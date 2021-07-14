/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Tpm2Lib;
#if WLK
using WEX.TestExecution;
using WEX.Logging.Interop;
#endif

namespace Tpm2Tester
{
    internal enum AbortReason
    {
        UnsupportedCommand,
        BlockedCommand
    }

    internal struct AbortedTestsInfo
    {
        internal TpmCc       command;
        internal AbortReason reason;
    }

    internal class CommandStats
    {
        internal int NumSuccess;
        internal int NumFailures;
        internal SortedSet<TpmRc> FailureResponses = new SortedSet<TpmRc>();
        internal SortedSet<string> CallerTests = new SortedSet<string>();
        internal TimeSpan SuccessExecutionTime;
        internal TimeSpan FailureExecutionTime;
    }

    internal class TestStats
    {
        internal int NumSuccess;
        internal int NumFailed;
        internal int NumAborted;
        internal int TotalExecutionTime;  // milliseconds
        internal SortedSet<TpmCc> Commands = new SortedSet<TpmCc>();
    }

    internal class TestCaseInfo
    {
        internal string TestCase;
        internal string Message;
        internal string Location;
        internal string StackTrace;
        internal string RngSeed;
        internal Object[] Parms;
        internal int RepeatedFailures;
    }

    internal struct TestExceptionInfo {
        internal string             message;
        internal string             fullStack;
#if !TSS_NO_STACK
        internal StackTrace         callerStack;
#endif
        internal TpmStructureBase   cmdParms;
    }

    internal delegate void Func();

    internal enum HtmlTextWriterAttribute
    {
        Border = 5,
        Cellpadding = 7,
    }

    internal enum HtmlTextWriterTag
    {
        Body = 12,
        H1 = 35,
        H2 = 36,
        H3 = 37,
        H4 = 38,
        Table = 82,
        Td = 84,
        Tr = 90,
    }

    internal class HtmlTextWriter
    {
        StringWriter    writer;
        string          attrs;
        Stack<string>   tags;

        public HtmlTextWriter(StringWriter sw)
        {
            writer = sw;
            attrs = "";
            tags = new Stack<string>();
        }

        public void AddAttribute(HtmlTextWriterAttribute attr, string val)
        {
            string attrName = null;
            switch (attr) {
                case HtmlTextWriterAttribute.Border: attrName = "border"; break;
                case HtmlTextWriterAttribute.Cellpadding: attrName = "cellpadding"; break;
                default: throw new Exception("Unknown HtmlTextWriterAttribute value");
            }
            attrs += " " + attrName + "=" + val;
        }

        public string GetTagName(HtmlTextWriterTag tag)
        {
            switch (tag) {
                case HtmlTextWriterTag.Body: return "body";
                case HtmlTextWriterTag.H1: return "h1";
                case HtmlTextWriterTag.H2: return "h2";
                case HtmlTextWriterTag.H3: return "h3";
                case HtmlTextWriterTag.H4: return "h4";
                case HtmlTextWriterTag.Table: return "table";
                case HtmlTextWriterTag.Td: return "td";
                case HtmlTextWriterTag.Tr: return "tr";
                default: throw new Exception("Unknown HtmlTextWriterTag value");
            }
        }

        public void RenderBeginTag(HtmlTextWriterTag tag)
        {
            string tagName = GetTagName(tag);
            writer.Write("<" + tagName + attrs + ">");
            tags.Push(tagName);
            attrs = "";
        }

        public void RenderEndTag()
        {
            string tagName = tags.Pop();
            writer.Write("</" + tagName + ">");
        }

        public void Write(string s)
        {
            writer.Write(s);
        }
    }

    internal class TestLogger
    {
        // Assembly implementing test methods being run by this framework instance
        internal Assembly TestAssembly;

        internal List<TestCaseInfo> CumulativeFailures = new List<TestCaseInfo>();

        internal List<TestCaseInfo> CumulativeWarnings = new List<TestCaseInfo>();

        internal Dictionary<string, AbortedTestsInfo> AbortedTests =
                                            new Dictionary<string, AbortedTestsInfo>();

        Dictionary<TpmCc, CommandStats> CumulativeCmdStats =
                                            new Dictionary<TpmCc, CommandStats>();

        Dictionary<string, TestStats> TestRoutinesStats =
                                            new Dictionary<string, TestStats>();

        // Number of TPM commands issued since the start of the test session
        int TotalNumCommands = 0;

        // Number of test assertions evaluated since the start of the test session
        int TotalNumAsserts = 0;

        internal DateTime TestSessStartTime = DateTime.Now;
        internal DateTime TestSessEndTime = DateTime.MinValue;

        // Total number of tests to execute. Is zero in case of a timed test session.
        internal int TestCount = 0;

        internal int MaxStatsLineLen = 0;

        int InstanceCount = 0;

        string TestLogFileName = null;
        internal bool LogTpmIo = false;
        internal string LogPath = null;

        internal const string LibTesterInfraName = "LibTesterInfra";

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="testAssembly">Assembly containing test methods. Used to cut off
        ///     framework stack frames when reporting test failure call stacks</param>
        internal TestLogger(Assembly testAssembly)
        {
            TestAssembly = testAssembly;
        }

        internal TestContext NewContext(bool validateTestAttributes = false,
                                        ICommandCallbacks callbacks = null)
        {
            int index = System.Threading.Interlocked.Increment(ref InstanceCount) - 1;
            var newCtx = new TestContext(this, index, validateTestAttributes, callbacks);

            // Mark the current TPM commands execution span as belonging to the
            // Tpm2Tester infrastructure
            newCtx.TestStarted(LibTesterInfraName);
            return newCtx;
        }

        internal static string FormatTimeSpan(TimeSpan span)
        {
            if(span < new TimeSpan())
            {
                span = new TimeSpan();
            }
            return span.ToString(@"dd\d\ hh\:mm\:ss");
        }

        internal string TimeToGo()
        {
            TimeSpan toGo = TestSessEndTime - DateTime.Now;
            if (TestSessEndTime == DateTime.MinValue)
                return null;

            return FormatTimeSpan(toGo);
        }

        internal void SetLogFileName(string logFileName)
        {
            TestLogFileName = logFileName;
        }

        internal void TestCompleted(TestContext ctx)
        {
            double testTime = (DateTime.Now - ctx.CurTestStartTime).TotalMilliseconds;
            string TestName = ctx.CurTestMethod;
            TestStatus status = ctx.CurTestStatus;
            Debug.Assert((status & ~(TestStatus.OK | TestStatus.Aborted
                                     | TestStatus.Failed)) == 0, "No test status set");

            lock (TestRoutinesStats)
            {
                if (!TestRoutinesStats.ContainsKey(TestName))
                {
                    TestRoutinesStats.Add(TestName, new TestStats());
                }
                TestStats s = TestRoutinesStats[TestName];
                s.TotalExecutionTime += (int)testTime;
                if (status == TestStatus.OK)
                {
                    s.NumSuccess++;
                }
                else
                {
                    // Multiple failure statuses are possible in case the test used
                    // restart feature.
                    if ((status & TestStatus.Failed) != 0)
                    {
                        s.NumFailed++;
                    }
                    if ((status & TestStatus.Aborted) != 0)
                    {
                        s.NumAborted++;
                    }
                }
            }
            lock (CumulativeCmdStats)
            {
                // Merge in statistics accumulated in the test context during this
                // test run.

                TotalNumCommands += ctx.NumCommands;
                TotalNumAsserts += ctx.NumAsserts;

                foreach (var kv in ctx.CmdStats)
                {
                    TpmCc cc = kv.Key;
                    CommandStats stat = kv.Value;
                    if (!CumulativeCmdStats.ContainsKey(cc))
                    {
                        Debug.Assert(stat.CallerTests.Count == 0);
                        stat.CallerTests.Add(ctx.CurTestMethod);
                        CumulativeCmdStats.Add(cc, stat);
                    }
                    else
                    {
                        CommandStats cumulStat = CumulativeCmdStats[cc];
                        cumulStat.NumSuccess += stat.NumSuccess;
                        cumulStat.NumFailures += stat.NumFailures;
                        cumulStat.FailureResponses = new SortedSet<TpmRc>(
                                cumulStat.FailureResponses.Union(stat.FailureResponses));
                        cumulStat.SuccessExecutionTime += stat.SuccessExecutionTime;
                        cumulStat.FailureExecutionTime += stat.FailureExecutionTime;
                        if (!cumulStat.CallerTests.Contains(ctx.CurTestMethod))
                        {
                            cumulStat.CallerTests.Add(ctx.CurTestMethod);
                        }
                    }
                }
            }
        }

        static string[] commandCodes = Enum.GetNames(typeof(TpmCc));

        internal static void SetForegroundColor (ref object[] parms,
                                                 ConsoleColor colorByDefault)
        {
            Console.ForegroundColor = colorByDefault;
            if (parms.Length > 0)
            {
                object last = parms[parms.Length - 1];
                if (last is ConsoleColor)
                {
                    Console.ForegroundColor = (ConsoleColor)last;
                    Array.Resize(ref parms, parms.Length - 1);
                }
            }
        }

        internal void WriteToLog(TextWriter console, string msgFormat,
                               params object[] msgParams)
        {
            string msg = msgParams.Length > 0 ? String.Format(msgFormat, msgParams)
                                              : msgFormat;
            ClearStatsLine();
            console.WriteLine(msg);
            if (TestLogFileName != null) lock (this)
            {
                File.AppendAllText(TestLogFileName, msg + "\n");
            }
        }

        internal void WriteToLog(string msgFormat, params object[] msgParams)
        {
            SetForegroundColor(ref msgParams, Console.ForegroundColor);
            WriteToLog(Console.Out, msgFormat, msgParams);
            Console.ResetColor();
        }

        internal void WriteErrorToLog(string msgFormat, params object[] msgParams)
        {
            SetForegroundColor(ref msgParams, ConsoleColor.Red);
            WriteToLog(Console.Error, msgFormat, msgParams);
            Console.ResetColor();
        }

        string ReadLine(string fileName, int lineNum)
        {
            string[] t = Globs.ReadAllLines(fileName);
            return t[lineNum - 1];
        }

        internal void ReportErrors(TestContext ctx)
        {
            foreach (var testCase in ctx.FailedTests)
            {
                if (ctx.FailedAssertions.ContainsKey(testCase.TestCase))
                {
                    testCase.RepeatedFailures = ctx.FailedAssertions[testCase.TestCase];
                    if (testCase.RepeatedFailures > 1)
                    {
                        ThreadSafePrint("Substrate.Assertion " + testCase.TestCase +
                                        " Repeatedly failed " + testCase.RepeatedFailures +
                                        " times", ConsoleColor.DarkRed);
                    }
                }
            }

            lock (CumulativeFailures)
            {
                CumulativeFailures.AddRange(ctx.FailedTests);
                CumulativeWarnings.AddRange(ctx.TestsWithWarnings);
            }
            ctx.FailedTests.Clear();
            ctx.TestsWithWarnings.Clear();
            ctx.FailedAssertions.Clear();
        }
        
        internal void ThreadSafePrint(string s, ConsoleColor color = 0)
        {
            lock (this)
            {
                ClearStatsLine();

                if (color != 0)
                    Console.ForegroundColor = color;

                WriteToLog(s);

                if (color != 0)
                    Console.ResetColor();
                Console.Out.Flush();
            }
        }

        internal string GetAbortReasonMessage (AbortedTestsInfo ati)
        {
            return "Command TpmRc." + Enum.GetName(typeof(TpmCc), ati.command) + " is "
                    + (ati.reason == AbortReason.UnsupportedCommand ?
                                "not implemented by the target TPM" : "blocked by OS");
        }

        internal static TestExceptionInfo ParseException(Exception e)
        {
            TestExceptionInfo ei = new TestExceptionInfo();

            while (e.InnerException != null)
            {
                e = e.InnerException;
            }

            ei.message = "";
            if (e is TssException)
            {
                TssException tssException = (TssException)e;
                if (e is TpmException)
                {
                    var tei = e as TpmException;
                    ei.message = "TPM Error: " + tei.ErrorString + ". ";
                    ei.cmdParms = tei.CmdParms;
                }
                else
                {
                    ei.message = "TSS Error: ";
                }
                ei.message += tssException.Message;
#if !TSS_NO_STACK
                ei.fullStack = tssException.StackTrace;
                ei.callerStack = tssException.CallerStack;
#endif
            }
            else
            {
                ei.message = "Exception " + e.GetType() + ": " + e.Message;
                ei.fullStack = e.StackTrace;
#if !TSS_NO_STACK
                ei.callerStack = null;
#endif
            }
            return ei;
        }

#if !TSS_NO_STACK
        internal static string GetLocationAsText(StackFrame[] frames, string delim)
        {
            string location = "> ";
            foreach (StackFrame frame in frames)
            {
                location += frame.GetMethod() + delim
                        + "@ " + Path.GetFileName(frame.GetFileName())
                        + " : " + frame.GetFileLineNumber() + ", "
                        + frame.GetFileColumnNumber() + delim;
            }
            return location;
        }
#endif
        internal void ClearStatsLine()
        {
            Console.Write(new string(' ', MaxStatsLineLen) + "\r");
        }

        internal void TestRunCompleted(string reportFileName)
        {
            ClearStatsLine();

            //
            // Print completion status
            //

            bool failed = CumulativeFailures.Count != 0;

            if (failed)
                WriteErrorToLog("Some tests FAILED.");
            else
                WriteToLog("All Tests PASSED.", ConsoleColor.Green);

            string conj = failed ? "And" : "But";
            if (AbortedTests.Count != 0)
            {
                WriteToLog(conj +
                           " some tests were ABORTED because of TPM or OS configuration.",
                           ConsoleColor.DarkMagenta);
                conj = "And";
            }

            if (CumulativeWarnings.Count != 0)
            {
                WriteToLog(conj + " there were WARNINGS.", ConsoleColor.Cyan);
            }

            //
            // Print final statistics
            //

            string time = FormatTimeSpan(DateTime.Now - TestSessStartTime);

            Console.WriteLine("Duration: " + time + "; " +
                          TotalNumCommands + " commands; " +
                          TotalNumAsserts + " asserts" +
                          "                          ");

            //
            // Generate detailed report
            //

            if (reportFileName != null)
            {
#if !WLK
                GenerateReport(reportFileName);
#endif
                try
                {
                    Process.Start(reportFileName);
                }
                catch (Exception) { }
                WriteToLog("Report {0} has been generated.", reportFileName);
            }
        }

        internal static string GetParamsList (object[] parms, string eol)
        {
            if (parms == null)
                return "";

            string parmsText = "";

            foreach (Object o in parms)
            {
                if (o is TestCaseInfo)
                {
                    // Formerly this parameter contained an exception object,
                    // information from which is now encapsulated in 'c'. 
                    continue;
                }
                else if (o is byte[])
                {
                    parmsText += Globs.HexFromByteArray((byte[])o);
                }
                else
                {
                    parmsText += o;
                }
                parmsText += eol;
            }

            return parmsText;
        }
#if !WLK
        void GenerateTestCasesTable(List<TestCaseInfo> testCases, string title,
                                    HtmlTextWriter w)
        {
            if (testCases.Count == 0)
                return;

            WriteLine(w, title, HtmlTextWriterTag.H2);

            BeginTable(w, "Test Case", "Details", "Stack Trace");

            foreach (TestCaseInfo c in testCases)
            {
                string parmsText = GetParamsList(c.Parms, "<br>");

                string details = c.Message + (c.RepeatedFailures > 1 ?
                                        " " + c.RepeatedFailures + " times" : "") + "<p>"
                        + c.Location + "<br>"
                        + (parmsText != "" ? "Parameters:<p>" + parmsText : "")
                        + (string.IsNullOrEmpty(c.RngSeed) ? ""
                            : "<br>To reproduce use option: -seed " + c.RngSeed + "<br>");

                details = details.Replace("\r\n", "<p>")
                                    .Replace("\r", "<br>").Replace("\n", "<br>");
                WriteTableRow(w, c.TestCase.Replace(":", " : "), details,
                            c.StackTrace != null ?
                                c.StackTrace.Replace("\r", "").Replace("\n", "<br>") : "");
            }
            EndTable(w); // table
        } // GenerateTestCasesTable

        internal void GenerateReport(string fileName)
        {
            TimeSpan testTimeSpan = DateTime.Now - TestSessStartTime;

            StringBuilder sb = new StringBuilder();
            StringWriter sw = new System.IO.StringWriter(sb);
            HtmlTextWriter w = new HtmlTextWriter(sw);

            w.RenderBeginTag(HtmlTextWriterTag.Body);

            WriteLine(w, "TPM Test Report", HtmlTextWriterTag.H1);
            WriteLine(w, "Start Time: " + TestSessStartTime.ToString("F"));
            WriteLine(w, "Duration: " + testTimeSpan.TotalMinutes.ToString("F2") + " min");

            bool failed = CumulativeFailures.Count != 0;
            bool aborted = AbortedTests.Count != 0;
            bool warnings = CumulativeWarnings.Count != 0;

            string title;

            if (failed)
            {
                title = "Some tests FAILED"
                      + (aborted ? " or were ABORTED" : "")
                      + (warnings ? " and there were WARNINGS" : "");
            }
            else
            {
                title = "All Tests PASSED"
                      + (warnings ? " with WARNINGS" : "")
                      + (aborted ? (warnings ? " and" : " but") + " some were ABORTED" : "");
            }
            WriteLine(w, title, HtmlTextWriterTag.H1);

            WriteLine(w, "Total Substrate.Assertions Checked = " + TotalNumAsserts);

            // ================  FAILING CASES SECTION ==========================
            GenerateTestCasesTable(CumulativeFailures, "Failing Cases", w);

            // ================  ABORTED CASES SECTION ==========================
            if (AbortedTests.Count != 0)
            {
                WriteLine(w, "Aborted Cases", HtmlTextWriterTag.H2);
                WriteLine(w, "Tests aborted because of commands not implemented by " +
                             "the target TPM, or blocked by OS.");

                BeginTable(w, "Test Case", "Abort Reason");
                foreach (var item in AbortedTests)
                {
                    WriteTableRow(w, item.Key, GetAbortReasonMessage(item.Value));
                }
                EndTable(w); // table
            }

            // ================  WARNINGS SECTION ==========================
            GenerateTestCasesTable(CumulativeWarnings, "Warnings", w);

            // ================  COMMAND STATS SECTION ==========================
            WriteLine(w, "Command Statistics", HtmlTextWriterTag.H2);
            WriteLine(w, "Total TPM Commands Executed = " + TotalNumCommands);

            BeginTable(w, "Command Code", "Successes", "Failures",
                          "Average<br>Success<br>Time, ms", "Average<br>Failure<br>Time, ms",
                          "Error Codes", "Calling Tests");

            var sortedStats = CumulativeCmdStats.OrderBy(item => item.Key.ToString()); // item.Value.NumSuccess
            //var sortedStats = CumulativeCmdStats;
            foreach (var item in sortedStats)
            {
                CommandStats stat = item.Value;
                string avgSuccessTime = stat.NumSuccess == 0 ? "-" : String.Format("{0:F1}",
                            stat.SuccessExecutionTime.TotalMilliseconds / stat.NumSuccess);
                string avgFailureTime = stat.NumFailures == 0 ? "-" : String.Format("{0:F2}",
                            stat.FailureExecutionTime.TotalMilliseconds / stat.NumFailures);
                WriteTableRow(w, item.Key, stat.NumSuccess, stat.NumFailures,
                                 avgSuccessTime, avgFailureTime,
                                 Globs.ToString(stat.FailureResponses, ", ", "-"),
                                 Globs.ToString(stat.CallerTests, ", ", "-"));
            }
            EndTable(w);

            // commands not executed -
            List<TpmCc> notExecuted = new List<TpmCc>();
            foreach (var c in CommandInformation.Info)
            {
                int num = sortedStats.Sum(y => (y.Key == c.CommandCode) ? 1 : 0);
                if (num == 0)
                {
                    Debug.WriteLine("Not executed:" + c.CommandCode.ToString());
                }
            }

            // ================  TEST ROUTINE STATS SECTION ==========================
            WriteLine(w, "Test Routine Statistics", HtmlTextWriterTag.H2);

            int totalTestRoutineCount = this.TestRoutinesStats.Sum(item =>
                    item.Value.NumAborted + item.Value.NumFailed + item.Value.NumSuccess);
            WriteLine(w, "Total Test Routines Executed = " + totalTestRoutineCount);

            BeginTable(w, "Test Name", "Succeeded", "Failed", "Aborted", "Average<BR>Time, s");

            var sortedTestStats = TestRoutinesStats.OrderBy(item => item.Key.ToString());
            foreach (var item in sortedTestStats)
            {
                TestStats stat = item.Value;
                int n = stat.NumSuccess + stat.NumFailed + stat.NumAborted;
                if (n == 0)
                {
                    continue;
                }
                string avgTime = String.Format("{0:F2}",
                                        (double)stat.TotalExecutionTime / n / 1000);
                WriteTableRow(w, item.Key, stat.NumSuccess, stat.NumFailed,
                              stat.NumAborted, avgTime);
            }
            EndTable(w);

            w.RenderEndTag(); // Body
            File.WriteAllText(fileName, sb.ToString());
        }

        int NumColumns = 0;

        void BeginTable(HtmlTextWriter w, params string[] columnHeaders)
        {
            // Our report does not contain nested tables 
            Debug.Assert(NumColumns == 0);

            w.AddAttribute(HtmlTextWriterAttribute.Border, "2");
            w.AddAttribute(HtmlTextWriterAttribute.Cellpadding, "3");
            w.RenderBeginTag(HtmlTextWriterTag.Table);

            // header row
            w.RenderBeginTag(HtmlTextWriterTag.Tr);
            foreach (string hdr in columnHeaders)
            {
                WriteLine(w, hdr, HtmlTextWriterTag.Td, HtmlTextWriterTag.H3);
            }
            w.RenderEndTag();

            NumColumns = columnHeaders.Length;
        }

        void WriteTableRow(HtmlTextWriter w, params object[] cellVals)
        {
            Debug.Assert(cellVals.Length == NumColumns);
            w.RenderBeginTag(HtmlTextWriterTag.Tr);
            foreach (object val in cellVals)
            {
                WriteLine(w, val.ToString(), HtmlTextWriterTag.Td);
            }
            w.RenderEndTag();
        }

        void EndTable(HtmlTextWriter w)
        {
            NumColumns = 0;
            w.RenderEndTag();
        }

        void WriteLine(HtmlTextWriter w, string t, params HtmlTextWriterTag[] tags)
        {
            if (tags.Length == 0)
            {
                tags = new HtmlTextWriterTag[] {HtmlTextWriterTag.H4};
            }
            foreach (var tag in tags)
            {
                w.RenderBeginTag(tag);
            }
            w.Write(t + "<p>");
            for (int i = 0; i < tags.Length; ++i)
            {
                w.RenderEndTag();
            }
        }

#else // WLK
        internal void GenerateWLKReport(ref int Run, ref int Fail, ref int Success, bool PassFailedTests)
        {
            foreach (TestCaseInfo c in CumulativeFailures)
            {
                string parmsText = "";

                // >>> write parms
                if (c.Parms != null)
                {
                    foreach (Object o in c.Parms)
                    {
                        if (o is TestCaseInfo)
                        {
                            // Formerly this parameter contained an exception object,
                            // information from which is now encapsulated in 'c'. 
                            continue;
                        }
                        else if (o is Enum)
                        {
                            parmsText += Enum.GetName(o.GetType(), o) + " : ";

                            bool    first = true;
                            Enum    e = o as Enum;
                            Array   values = Enum.GetValues(o.GetType());

                            foreach( Enum v in values )
                            {
                                if (e.HasFlag(v))
                                {
                                    if (!first)
                                    {
                                        parmsText += " | ";
                                    }
                                    else
                                    {
                                        first = false;
                                    }
                                    parmsText += Enum.GetName(o.GetType(), v);
                                }
                            }
                        }
                        else if (o is byte[])
                        {
                            parmsText += Globs.HexFromByteArray((byte[])o);
                        }
                        else
                        {
                            parmsText += o.ToString();
                        }
                        parmsText += "<p>";
                    }
                }
                else
                {
                    parmsText = "<br>";
                }

                string details = c.Message + "\n"
                                + c.Location + "\n"
                                + "Parameters:\n" + parmsText
                                + (string.IsNullOrEmpty(c.RngSeed) ? ""
                                    : "To reproduce use option: -seed " + c.RngSeed + "\n");
                details.Replace("\r", "");

                string errorText = c.TestCase.Replace(":", " : ") + ";\n" + details;
                // c.StackTrace.Replace("\r", "");

                WriteToWLKLog(errorText, TestResult.Failed, PassFailedTests);
            }

            // ================  ABORTED CASES SECTION ==========================
            foreach (var item in AbortedTests)
            {
                string errorText = "TestCaseInfo:" + item.Key + " aborted because: "
                                 + GetAbortReasonMessage(item.Value);
                if (item.Value.reason == AbortReason.BlockedCommand)
                {
                    WriteToWLKLog(errorText, TestResult.NotRun, PassFailedTests);
                }
                else
                {
                    WriteToWLKLog(errorText, TestResult.Failed, PassFailedTests);
                }
            }

            // ================  COMMAND STATS SECTION ==========================
            Log.Comment(string.Format("Total TPM command count: {0}", TotalNumCommands));

            string successfulCommands = "Commands executed: ";
            var sortedStats = CumulativeCmdStats.OrderBy(item => item.Key.ToString());
            //var sortedStats = CumulativeCmdStats;
            foreach (var item in sortedStats)
            {
                CommandStats stat = item.Value;
                successfulCommands += item.Key + " (" + stat.NumSuccess + ") ";
            }
            Log.Comment(successfulCommands);
            WriteToLog(successfulCommands);

            // commands not executed -
            List<TpmCc> notExecuted = new List<TpmCc>();
            foreach (var c in CommandInformation.Info)
            {
                int num = sortedStats.Sum(y => (y.Key == c.CommandCode) ? 1 : 0);
                if (num == 0  && TestCategorizer.CommandDefinedForMinTpm(c.CommandCode))
                {
                    Log.Comment("Command " + c.CommandCode + " not executed.");
                }
            }

            // ================  TEST ROUTINE STATS SECTION ==========================
            int totalTestRoutineCount = this.TestRoutinesStats.Sum(item =>
                    item.Value.NumAborted + item.Value.NumFailed + item.Value.NumSuccess);
            var sortedTestStats = TestRoutinesStats.OrderByDescending(item => item.Value.NumFailed);
            foreach (var item in sortedTestStats)
            {
                if (item.Value.NumFailed == 0)
                {
                    break;  // no more failures
                }
                WriteToWLKLog(string.Format("{0} failed.", item.Key),
                              TestResult.Failed, PassFailedTests);
                Fail++;
            }
            sortedTestStats = TestRoutinesStats.OrderByDescending(item => item.Value.NumSuccess);
            foreach (var item in sortedTestStats)
            {
                if (item.Value.NumSuccess == 0)
                {
                    break;  // no more failures
                }
                Verify.IsTrue(true, item.Key);
                WriteToLog("{0} passed.", item.Key);
                Success++;
            }
            foreach (var item in sortedTestStats)
            {
                TestStats stat = item.Value;
                if (stat.NumSuccess == 0 && stat.NumFailed == 0)
                {
                    Log.Result(TestResult.NotRun, string.Format("{0} not run.", item.Key));
                    Run++;
                }
            }
        }

        void WriteToWLKLog(string Msg, TestResult res, bool PassFailedTests)
        {
            if (PassFailedTests)
                Log.Warning(Msg);
            else
                Log.Result(res, Msg);
            WriteToLog(Msg);
        }
#endif

    } // class TestLogger

} // namespace Tpm2TestSuite

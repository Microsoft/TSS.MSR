/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Linq;
using System.IO;
using System.IO.Pipes;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Diagnostics;
using System.Text;
using Tpm2Lib;

namespace Tpm2Tester
{

    internal partial class TestFramework
    {
        //internal static TestProg MyTestProg;
        //internal TestCases TpmTester = null;

        const int MaxConcurrentInstances = 64;

        class ThreadTestContext
        {
            internal int testIndex;
            internal TestContext testCtx;
            internal TestLogger logger;
            internal Tbs tbs;
            internal DateTime endTime;
            internal List<MethodInfo> tests;
            internal Barrier barrier;
            internal bool aTestFailed;
        };

        // Part of the test infrastructure used by tests implemented in the client assemblies
        internal TestSubstrate Substrate;

        // Shortcut to the corresponding Substrate member
        internal TestConfig TestCfg;

        // Shortcut to the corresponding Substrate member
        internal TpmConfig TpmCfg;

        // The primary Tpm2 instance.
        internal Tpm2 MainTpm;

        // Primary test context 
        internal TestContext MainTestContext;

        // Primary logger
        internal TestLogger MainTestLogger;

        // Primary TPM device
        TpmPassThroughDevice MainTpmDevice;

        // Primary underlying TPM device
        Tpm2Device UnderlyingTpmDevice;

        // A TBS abstraction layer created on top of MainTpmDevice.
        Tbs Tbs;

        // TPM simulator process object created with '-tpm' option. See TestCfg.TpmPath.
        Process TpmProcess;

        static readonly AuthValue NullAuth = new AuthValue();

        private TesterCmdLine CmdLine;

        private delegate Tpm2Device MakeNewTpm(TestContext testCtx);
        private MakeNewTpm TpmFactory;
        private List<MethodInfo>    _AllTests;
        private List<string>        _AllTestNames;


        // Reference to an object in the client assembly that contains test methods to run.
        // This object must implement all non-static test methods in the assembly.
        // Static test methods can be spread across multiple classes. If the client
        // assembly only contains static test methods, TestContainer may reference any
        // object in the assembly.
        static object TestContainer = null;

        bool InitTPM;

        // State of the current test. Used to pass in the string of the '-params' option,
        // and/or to restart failing tests.
        // Restart can be useful when the same method tests multiple scenarios in order
        // to achieve better coverage during a single run in the presence of failures
        // that may happen only in a few cases out of the many.
        TestState TheTestState;

        // Set of handles that Tpm2Tester failed to delete during TPM cleanup.
        // This is normally NV indices in platform hierarchy that require a policy
        // for their deletion.
        static HashSet<uint> ToughHandles = new HashSet<uint>();

#if !TSS_NO_TCP
        // Output of the TPM simulator process to its stderr (with -tpm option).
        // Used to report simulator's crash dump. May be obsolete.
        internal string TpmStderr;
#endif

#if !WLK
        // Base of the report file name
        string StemFile = "TpmTests";
#endif

        internal string RemainingTestsFile = "RemainingTests";

        // Each tester assigns itself a separate instance to make it easier to run
        // more than one tester/TPM pair on a machine.
        internal int TesterInstance = 0;

        // Common prefix used to name InstanceAnchor objects.
        const string TesterMutexNamePrefix = "TPM_TESTER_MUTEX_";

        // An instance of a named kernel mode object used to uniquely number concurrent Tpm2Tester instances.
        static NamedPipeServerStream InstanceAnchor;

        string CheckinFileName = "";
        DateTime startTime;

        private TestFramework(TestSubstrate substrate)
        {
            Substrate = substrate;
            TestCfg = substrate.TestCfg;
            TpmCfg = substrate.TpmCfg;
        }

        /// <summary>Create a test framework instance with the test methods from the specified
        ///     containing object and given comamnd line options for the test session.</summary>
        /// <param name="testContainer">A reference to an object in the client assembly that
        ///     implements test methods (the ones with the Tpm2Tester.Test attribute). Such
        ///     methods are automatically enumerated, and then filtered and executed based
        ///     on the command line options.</param>
        internal static TestFramework Create(TestSubstrate substrate,
                                             string[] args, object testContainer)
        {
            var framework = new TestFramework(substrate);
            return framework.Init(args, testContainer) ? framework : null;
        }

        internal bool Init(string[] args, object testContainer)
        {
            Console.ResetColor();

            MainTestLogger = new TestLogger(testContainer.GetType().Assembly);

            TesterInstance = SetTesterInstance();
            if (TesterInstance < 0)
            {
                WriteErrorToLog("Too many tester instances running on this host. Aborting...");
                MainTestLogger = null;
                return false;
            }

            // So that multiple tester instances don't collide:
            RemainingTestsFile = RemainingTestsFile + "_" + TesterInstance + ".txt";

            TestContainer = testContainer;
            _AllTests = new List<MethodInfo>();
            MethodInfo[] methods = TestContainer.GetType()
                                        .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic);
            foreach (MethodInfo mi in methods)
            {
                TestAttribute attr = Globs.GetAttr<TestAttribute>(mi);
                if (attr == null || attr.CommProfile.HasFlag(Profile.Disabled))
                {
                    continue;
                }
                _AllTests.Add(mi);
            }
            _AllTestNames = Globs.ConvertAll(AllTests, item => item.Name);

            // By default (unless command line options intervene) all found test methods will be run.
            TestCfg.TestsToRun = AllTestNames;

            CmdLine = new TesterCmdLine(this, args);

            if (!CmdLine.Parse())
            {
                if (System.Diagnostics.Debugger.IsAttached)
                {
                    // give us a few seconds to see the error text.
                    Thread.Sleep(5000);
                }
                return false;
            }

            if (TestCfg.TestsToRun == null && !TestCfg.StopTpm && !TestCfg.DumpTpmInfo)
            {
                // Options "-list", "-help", etc.
                // Terminate without communicating with the TPM device.
                return false;
            }

            MainTestContext = MainTestLogger.NewContext(true);

            TestCategorizer.Init();

            return true;
        }

        internal bool RunTestSession()
        {
            Console.ResetColor();

            if (TesterInstance != 0 && TestCfg.Verbose)
            {
                WriteToLog("Tester Instance: " + TesterInstance);
            }

            TheTestState = new TestState(TestCfg.TestParams);

            // Instruct library to use deterministic "random" numbers for test
            // repeatability (at least in the case of single-threaded tests)
            if (TestCfg.SeededRng)
            {
                Globs.SetRngSeed(TestCfg.RngSeed);
            }

#if !TSS_NO_TCP
            if (TestCfg.TpmPath != "" && !StartTpm())
            {
                return false;
            }
#endif
            // Create a new device of class requested.  The object returned is a wrapper
            // of type TpmPassThruDevice, which allows callbacks to be installed.
            var tpmDevice = CreateTpmDevice(MainTestContext);

            if (tpmDevice == null)
                return false;

            int initialErrorCount = NumTestFailures();

            if (TestCfg.StopTpm)
                goto ExitProgram;

#if !TSS_NO_TCP
            if (TestCfg.TpmAutoRestart)
            {
                // Set the sockets to timeout so that we can propagate a failure to
                // the caller if the TPM seems to be busted.
                TestCfg.TheTcpTpmDevice.SetSocketTimeout((int)(TestConfig.NumMinsBeforeAutoRestart * 60));
            }

            if (TestCfg.TransportLogsDirectory != null)
            {
                if (!(UnderlyingTpmDevice is TcpTpmDevice))
                {
                    WriteErrorToLog("Can only log TCP TPM device");
                    return false;
                }
                if (TestCfg.StressMode == true)
                {
                    WriteErrorToLog("Cannot log in stress mode");
                    return false;
                }
                InitTransportLogger(TestCfg.TransportLogsDirectory,
                                              (TcpTpmDevice)UnderlyingTpmDevice);
            }
#endif
            if (TestCfg.DumpConsole)
            {
                string consoleLogFile;
                if (TestCfg.TransportLogsDirectory != null)
                {
                    consoleLogFile = System.IO.Path.Combine(TestCfg.TransportLogsDirectory,
                                                            "console.txt");
                }
                else
                {
#if TSS_MIN_API
                    consoleLogFile = "console.txt";
#else
                    string docsPath = Environment.GetFolderPath(
                                                Environment.SpecialFolder.MyDocuments);
                    consoleLogFile = System.IO.Path.Combine(docsPath, "console.txt");
#endif
                }
                MainTestLogger.SetLogFileName(consoleLogFile);
            }

#if false
            // Testing TPM with minimal Tpm2Tester infrastructure initialization

            tpmDevice.PowerCycle();
            tpmDevice.SignalNvOn();

            var tpm = new Tpm2(tpmDevice);
            tpm.Startup(Su.Clear);

            // Insert test code here

            return true;
#endif
            TestCfg.HasTRM = tpmDevice.HasRM();
            PowerUpTpm(tpmDevice);

            // "Stress-mode" creates threads that randomly execute TPM tests. If the
            // TPM is multi-context (like TBS) we open one context per stress thread.
            // If the device is not multi-context then Tpm2Tester uses its own emulated RM.
            if (TestCfg.HasTRM)
                TpmFactory = CreateTpmDevice;

            TestCfg.DoInit = TestCfg.DoInit && tpmDevice.PlatformAvailable();

            // Initialize the testCtx. It will try to communicate with the TPM.
            try
            {
                if (!InitTpmDevice(tpmDevice))
                    return false;
            }
            catch (Exception e)
            {
                var exceptionInfo = TestLogger.ParseException(e);
                WriteErrorToLog("Failed to communicate with the TPM during " +
                                          "initialization.\n" + exceptionInfo.message);
                return false;
            }

            if (TestCfg.DumpTpmInfo)
            {
                // -tpmInfo option was used. Quit after dumping TPM information.
                goto ExitProgram;
            }

            TestCfg.TestsToRun = CmdLine.GenerateTestSet(tpmDevice);

            if (TestCfg.TestsToRun.Count == 0)
                goto ExitProgram;

            // Ready to start tests...
            NotifyTestStartStop(true);

            // In the following we perform the requested test run with the requested
            // test routine set.

            // TestValidation tests that the test use the privileges that they state.
            // Test validation runs should be performed as new tests are added.
            if (FuzzMode)
            {
                if (TestCfg.Verbose)
                    WriteToLog("\nRunning TPM tests in fuzz mode\n");

                if (TestCfg.TestEndTime == DateTime.MinValue)
                {
                    if (TestCfg.Verbose)
                        WriteToLog("Test duration defaulting to 60 minutes");
                    TestCfg.TestEndTime = DateTime.Now + new TimeSpan(0, 60, 0);
                }
                RunFuzz(TestCfg.TestsToRun.ToArray(), TestCfg.TestEndTime);

#if !TSS_NO_TCP
                if (TestCfg.TpmPath != "")
                {
                    KillTpmProcess();
                }
#endif
            }
            else if (TestCfg.StressMode)
            {
                if (TestCfg.Verbose)
                    WriteToLog("\nRunning TPM tests in stress mode\n");

                if (TestCfg.TestEndTime == DateTime.MinValue)
                {
                    if (TestCfg.Verbose)
                        WriteToLog("Test duration defaulting to {0} minutes",
                                                TestConfig.DefaultStressModeDuration);
                    TestCfg.TestEndTime = DateTime.Now +
                                    new TimeSpan(0, TestConfig.DefaultStressModeDuration, 0);
                }

                double stateSaveProb = TestCfg.TestS3 ? TestConfig.StateSaveProbability : 0.0;
                RunStress(TestCfg.TestsToRun.ToArray(), TestCfg.NumThreads, TestCfg.TestEndTime,
                                    TestCfg.StopOnFirstError, stateSaveProb, TestCfg.TestNvAvailable);
            }
            else
            {
                if (TestCfg.Verbose)
                    WriteToLog("\nRunning TPM tests sequentially\n");

                RunTestsSerially(TestCfg.TestsToRun.ToArray(), TestCfg.TestEndTime);
            }

            // Tests completed
            string reportFileName = null;
#if !WLK
            if (TestCfg.ShowHTML)
                reportFileName = StemFile + "_" + TesterInstance.ToString() + ".Report.html";
#endif
            MainTestLogger.TestRunCompleted(reportFileName);

            ExitProgram:
            if (TestCfg.DoInit)
                MainTpm.Shutdown(Su.Clear);

            if (TestCfg.UseKeyCache)
                UnderlyingTpmDevice.SignalKeyCacheOff();

            tpmDevice.Dispose();

            if (!Debugger.IsAttached)
            {
                NotifyTestStartStop(false);
            }
            return initialErrorCount >= NumTestFailures();
        } // RunTestSession()

        public int NumTestFailures()
        {
            return MainTestLogger.CumulativeFailures.Count;
        }


        private int SetTesterInstance()
        {
            for (int j = 0; j < MaxConcurrentInstances; j++)
            {
                try
                {
                    InstanceAnchor = new NamedPipeServerStream(TesterMutexNamePrefix + j, PipeDirection.InOut, 1);
                }
                catch (IOException)
                {
                    continue;
                }
                return j;
            }
            return -1;
        }

        private int GetTesterInstance()
        {
            return TesterInstance;
        }

        // If instructed the tester will create a file in Crashes/Checkins to notify the world
        // that an instance has started
        private void NotifyTestStartStop(bool isStarting)
        {
            if (!TestCfg.GenerateStartupCheckin)
                return;

            string msg;

            if (isStarting)
            {
                startTime = DateTime.Now;
                string checkinFileDir = TestCfg.FuzzCrashesDirectory + "Checkins" + Path.DirectorySeparatorChar;

                string hostName = Process.GetCurrentProcess().MachineName;
                string dateTime = DateTime.Now.ToString("MMMM_dd_yyyy_HH_mm_ss_FFFF");

                string fileName = "checkin_" + hostName + "_" + TesterInstance.ToString() + "_" + dateTime + "_" + Guid.NewGuid().ToString() + ".txt";

                CheckinFileName = checkinFileDir + fileName;
                msg = "running...";
            }
            else
            {
                msg = "Test run " + (DateTime.Now - startTime).TotalHours + " hours";
            }
            try
            {
                File.WriteAllText(CheckinFileName, msg);
            }
            catch (Exception e)
            {
                WriteErrorToLog("Failed to create the checkin-file. Error: \n" + e.Message);
            }
        } // NotifyTestStartStop()

        // The warning appears to be a false positive, as the potentially leaked object is returned.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope")]
        // Make a device of the type specified on the command line.  A PassThroughDevice
        // is instantiated on top of the actual TPM device and necessary callbacks are installed
        // Note: in stress mode, and if TpmHasResourceManager=true, the test framework
        // will instantiate one device per thread.
        private TpmPassThroughDevice CreateTpmDevice(ICommandCallbacks callbacks)
        {
            Tpm2Device underlyingTpmDevice = null;
            try
            {
                switch (TestCfg.DeviceType)
                {
                    case TpmDeviceType.dll:
                        if (TestCfg.TpmDllPath == null)
                        {
                            WriteErrorToLog("-device dll requires -dllpath PathToDll");
                            return null;
                        }
                        if (!Directory.Exists(TestCfg.TpmDllPath))
                        {
                            WriteErrorToLog("dllpath does not exist:" + TestCfg.TpmDllPath);
                            return null;
                        }
                        underlyingTpmDevice = new InprocTpm(TestCfg.TpmDllPath);
                        break;
                    case TpmDeviceType.tbs:
                    case TpmDeviceType.tbsraw:
                        if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                            underlyingTpmDevice = new LinuxTpmDevice();
                        else
                        underlyingTpmDevice = new TbsDevice(TestCfg.DeviceType != TpmDeviceType.tbsraw);
                        break;
#if !TSS_NO_TCP
                    case TpmDeviceType.tcp:
                    case TpmDeviceType.rmsim:
                        {
                            var tcpDev = new TcpTpmDevice(TestCfg.TcpHostName, GetTcpServerPort(), TestCfg.StopTpm);
#if !DEBUG
                            tcpDev.SetSocketTimeout(2000);
#endif
                            underlyingTpmDevice = tcpDev;
                            if (TestCfg.DeviceType == TpmDeviceType.rmsim)
                            {
                                underlyingTpmDevice = new Tbs.TbsContext(new Tbs(underlyingTpmDevice, true));
                            }
                            break;
                        }
#endif
                            default:
                        throw new Exception("should not be here");
                }
#if !TSS_NO_TCP
                if (underlyingTpmDevice is TcpTpmDevice)
                {
                    TestCfg.TheTcpTpmDevice = (TcpTpmDevice)underlyingTpmDevice;
                }
#endif
            }
            catch (Exception)
            {
                if (underlyingTpmDevice != null)
                    underlyingTpmDevice.Dispose();
                throw;
            }
            try
            {
                underlyingTpmDevice.Connect();
            }
            catch (Exception e)
            {
                WriteErrorToLog("Failed to connect to the TPM. Error: " + e.Message);
                underlyingTpmDevice.Dispose();
                Thread.Sleep(3000);
                return null;
            }
            try
            {
                var tpmDevice = new TpmPassThroughDevice(underlyingTpmDevice);
                tpmDevice.SetCommandCallbacks(callbacks);

                UnderlyingTpmDevice = underlyingTpmDevice;
                if (TestCfg.UseKeyCache)
                    UnderlyingTpmDevice.SignalKeyCacheOn();
                return tpmDevice;
            }
            catch (Exception)
            {
                underlyingTpmDevice.Dispose();
                throw;
            }
        } // CreateTpmDevice()

        internal class BadRsaKeyException : Exception
        {
            internal byte[] PublicKey { get; set; }

            internal BadRsaKeyException(byte[] publicKey)
            {
                PublicKey = publicKey;
            }
        }

        private void ParamsTraceCallback(TpmCc ordinal, TpmStructureBase inParms,
                                           TpmStructureBase outParms)
        {
            TpmPublic pub = null;
            if (ordinal == TpmCc.Create)
            {
                pub = (outParms as Tpm2CreateResponse).outPublic;
            }
            else if (ordinal == TpmCc.CreatePrimary)
            {
                pub = (outParms as Tpm2CreatePrimaryResponse).outPublic;
            }
            if (pub != null)
            {
                if (pub.unique.GetUnionSelector() == TpmAlgId.Rsa)
                {
                    Tpm2bPublicKeyRsa rsaPub = (Tpm2bPublicKeyRsa)pub.unique;
                    if ((rsaPub.buffer[0] & 0x80) != 0x80)
                    {
                        WriteErrorToLog("RSA key was generated incorrectly: {0}",
                                        Globs.HexFromByteArray(rsaPub.buffer));
                        //throw new BadRsaKeyException(rsaPub.buffer);
                    }
                }
            }
        } // ParamsTraceCallback()

        private bool InitTpmDevice(TpmPassThroughDevice device)
        {
            MainTpmDevice = device;
#if WLK
            // the WHCK (WLK) is already clearing the TPM, no need to initialize here.
            InitTPM = false;
#else
            InitTPM = !TestCfg.RunAsStandardUser && TestCfg.DoInit;
#endif
            if (TestCfg.StressMode)
            {
                TpmCfg.PlatformDisabled = true;
                TpmCfg.PowerControl = TpmCfg.LocalityControl = false;
            }
            else
            {
                TpmCfg.PlatformDisabled = !device.PlatformAvailable();
                TpmCfg.PowerControl = device.PowerCtlAvailable();
                TpmCfg.LocalityControl = device.LocalityCtlAvailable();
                TpmCfg.NvControl = device.NvCtlAvailable();
            }

            MainTpm = new Tpm2(MainTpmDevice);

// To test TBS-like environment:
#if false
            TpmCfg.PlatformDisabled = true;
            MainTpm.LockoutAuth = new byte[] { 1 };
#endif

            //MainTpm._SetTraceCallback(RawCommandCallback);
            MainTpm._SetParamsTraceCallback(ParamsTraceCallback);

            // See whether the TPM is alive ...
            byte[] r = MainTpm._AllowErrors().GetRandom(1);
            if (MainTpm._GetLastResponseCode() != TpmRc.Success)
            {
                WriteErrorToLog("TPM failed to execute GetRandom command. Error {"
                                + MainTpm._GetLastResponseCode() + "}");
                return false;
            }

#if false
            // Test Tpm2Tester reaction on the presence of a policy-delete NV index.
            TpmHandle nvHandle = TpmHandle.NV((uint)0xC00002);
            byte[] nvPolicy = new TpmHash(TpmAlgId.Sha);
            nvPolicy[1] = 1;
            var nvPub = new NvPublic(nvHandle, TpmAlgId.Sha,
                                     TestConfig.DefaultNvAttrs
                                        | NvAttr.Platformcreate | NvAttr.PolicyDelete,
                                     nvPolicy, 8);

            MainTpm._ExpectResponses(TpmRc.Success, TpmRc.NvDefined)
                   .NvDefineSpace(TpmRh.Platform, null, nvPub);
            MainTpm.NvWrite(nvHandle, nvHandle, new byte[]{1,2,3,4}, 0);
#endif

            // ... and accessible to us
            ResetTpmDaLogic(MainTpm, true);

            if (TestCfg.TestNvAvailable)
            {
                MainTpm._DebugTestNvIsAvailable();
            }

            uint[] version = MainTpm.GetFirmwareVersionEx();
            if (TpmCfg.TpmVersion == 0)
            {
                TpmCfg.TpmVersion = version[2];
            }
            else if (TpmCfg.TpmVersion != version[2])
            {
                WriteErrorToLog("All TPM devices must be of same revision. "
                                + "Encountered revisions: {0}, {1}",
                                TpmCfg.TpmVersion / 100f, version[2] / 100f);
                return false;
            }
            if (TpmCfg.TpmVersion < 88)
            {
                WriteErrorToLog("Tpm2Tester does not support TPM revisions before 0.88. "
                                + "Aborting...");
                return false;
            }
            if (TpmCfg.TpmVersion > (uint)Spec.Version || TpmCfg.TpmVersion < 88)
            {
                WriteErrorToLog("This Tpm2Tester is only aware of TPM revisions up to {0}. "
                                + "Some test cases may fail.", (float)Spec.Version / 100);
            }

            // TPM version, spec date and manufacturer info
            string manufacturer;
            uint specYear, specDay;

            Tpm2.GetTpmInfo(MainTpm, out manufacturer, out specYear, out specDay);
            TpmCfg.TpmSpecDate = new DateTime((int)specYear, 1, 1);
            TpmCfg.TpmSpecDate = TpmCfg.TpmSpecDate.AddDays(specDay - 1);

            if (TestCfg.Verbose || TestCfg.DumpTpmInfo)
            {
                WriteToLog("TPM manufacturer: " + manufacturer);
                WriteToLog("TPM revision    : {0:F2}", TpmCfg.TpmVersion / 100f);
                WriteToLog("TPM Spec date   : " + TpmCfg.TpmSpecDate.ToString("MMMM dd, yyyy"));

                // NOTE: This is a convention in the reference implementation, that 
                // the FW version reports a build time. But this is not normative.
                string fwDateTime = "Date= " + Globs.HexFromValueType(version[0]) +
                                    ", Time=" + Globs.HexFromValueType(version[1]);
                WriteToLog("TPM Firmware Build Time Stamp: " + fwDateTime);
            }

            Tbs = new Tbs(MainTpmDevice, device.HasRM());


            // Clean up TPM
            try
            {
                if (!RecoverTpm(MainTpm) &&
                    (!PlatformCleanTpm(MainTpm) || !RecoverTpm(MainTpm)))
                {
                    WriteErrorToLog("Failed to completely clean up the TPM.\n" +
                                "Possibly one of the primary auth values is not known.\n" +
                                "Continuing, but some tests may fail or will be bypassed...");
                }
            }
            catch (Exception e)
            {
                WriteErrorToLog("Unknown error while cleaning up the TPM: " + e.Message);
                WriteErrorToLog("Will try to proceed, but some tests may fail...");
            }

            InitTpmParams(MainTpm);

            return true;
        } // InitTpmDevice()

        private void InitTpmParams(Tpm2 tpm)
        {
            if (TpmCfg.ImplementedAlgs != null)
                return;

            if (TestCfg.Verbose || TestCfg.DumpTpmInfo)
                WriteToLog("TPM configuration:");

            TpmCfg.Hierarchies = TpmCfg.PlatformDisabled
                        ? new TpmRh[] {TpmRh.Owner, TpmRh.Endorsement}
                        : new TpmRh[] {TpmRh.Owner, TpmRh.Endorsement, TpmRh.Platform};

            // Enumerate commands implemented by the target TPM instance.
            // If a test attempts to execute not implemented command, it will be reported
            // as "aborted" instead of "failed".
            uint totalCommands = Tpm2.GetProperty(MainTpm, Pt.TotalCommands);

            TpmCfg.FipsMode = (Tpm2.GetProperty(tpm, Pt.Modes) & (uint)ModesAttr.Fips1402) != 0;
            if (TpmCfg.FipsMode)
                WriteToLog("FIPS 140-2 compliant");

            ICapabilitiesUnion caps;
            byte more = tpm.GetCapability(Cap.Commands, (uint)TpmCc.First,
                                          totalCommands, out caps);
            TpmCfg.SupportedCommands = Globs.ConvertAll((caps as CcaArray).commandAttributes,
                    cmdAttr => (TpmCc)(cmdAttr & (CcAttr.commandIndexBitMask | CcAttr.V)))
                    .ToArray();
            Substrate.Assert(totalCommands == TpmCfg.SupportedCommands.Length);

            TpmCfg.ResettablePcrs = Tpm2.GetPcrProperty(tpm, PtPcr.ResetL0);
            TpmCfg.ExtendablePcrs = Tpm2.GetPcrProperty(tpm, PtPcr.ExtendL0);

            TpmCfg.ContextHashAlg = (TpmAlgId)Tpm2.GetProperty(tpm, Pt.ContextHash);

            ushort ctxDigestSize = TpmHash.DigestSize(TpmCfg.ContextHashAlg);
            
            var hashAlgs = new List<TpmAlgId>();
            var symAlgs = new List<TpmAlgId>();
            var blockModes = new List<TpmAlgId>();
            more = tpm.GetCapability(Cap.Algs, (uint)TpmAlgId.First,
                                     (uint)TpmAlgId.Last - (uint)TpmAlgId.First + 1,
                                     out caps);
            TpmCfg.ImplementedAlgs = Globs.ConvertAll(
                    (caps as AlgPropertyArray).algProperties,
                    algProp =>
                    {
                        if (algProp.algProperties == AlgorithmAttr.Hash)
                        {
                            if (CryptoLib.IsHashAlgorithm(algProp.alg))
                            {
                                hashAlgs.Add(algProp.alg);
                                if (TpmHash.DigestSize(algProp.alg) > ctxDigestSize)
                                {
                                    WriteErrorToLog("Warning: {0} has larger digest " +
                                            "than that of the context integrity {1}",
                                            algProp.alg, TpmCfg.ContextHashAlg, ConsoleColor.Cyan);
                                }
                            }
                            else
                            {
                                WriteErrorToLog("Warning: Tpm2Tester's software crypto " +
                                                "layer does not support {0}",
                                                algProp.alg, ConsoleColor.Cyan);
                            }
                        }
                        else if (algProp.algProperties.HasFlag(AlgorithmAttr.Symmetric))
                        {
                            if (algProp.algProperties.HasFlag(AlgorithmAttr.Encrypting))
                            {
                                blockModes.Add(algProp.alg);
                            }
                            else
                            {
                                symAlgs.Add(algProp.alg);
                            }
                        }
                        return algProp.alg;
                    })
                .ToArray();
            TpmCfg.HashAlgs = hashAlgs.ToArray();
            TpmCfg.HashAlgsEx = Array.CreateInstance(typeof(TpmAlgId), TpmCfg.HashAlgs.Length + 1)
                             as TpmAlgId[];
            TpmCfg.HashAlgsEx[0] = TpmAlgId.Null;
            Array.Copy(TpmCfg.HashAlgs, 0, TpmCfg.HashAlgsEx, 1, TpmCfg.HashAlgs.Length);
            LogListOfValues("Hash algorithms: ", hashAlgs);

            TpmCfg.EccCurves = new Dictionary<EccCurve, AlgorithmDetailEcc>();
            var swEccCurves = new List<EccCurve>();
            int maxEccKeyBits = 0;
            more = tpm._AllowErrors()
                      .GetCapability(Cap.EccCurves, (uint)0, (uint)0xFFFF, out caps);
            if (MainTpm._LastCommandSucceeded())
            {
                foreach (var curve in (caps as EccCurveArray).eccCurves)
                {
                    AlgorithmDetailEcc curveDetail = tpm.EccParameters(curve);
                    maxEccKeyBits = Math.Max(maxEccKeyBits, curveDetail.keySize);
                    var coordBytes = curveDetail.gX.Length;
                    if (!TpmCfg.Tpm_115_Errata_13() && coordBytes > 32)
                    {
                        continue;
                    }
                    TpmCfg.EccCurves.Add(curve, curveDetail);
                    if (AsymCryptoSystem.IsCurveSupported(curve))
                    {
                        swEccCurves.Add(curve);
                    }
                }
            }
            else
            {
                TestCfg.DisabledTests.Category |= Category.Ecc;
            }
            LogListOfValues("ECC curves: ", TpmCfg.EccCurves.Keys);
            TpmCfg.SwEccCurves = swEccCurves.ToArray();
            TpmCfg.MaxEccKeySize = (maxEccKeyBits + 7) / 8;

            TpmCfg.MaxDigestSize = (ushort)Tpm2.GetProperty(MainTpm, Pt.MaxDigest);
            TpmCfg.MaxInputBuffer = (ushort)Tpm2.GetProperty(tpm, Pt.InputBuffer);
            TpmCfg.MaxNvIndexSize = (ushort)Tpm2.GetProperty(tpm, Pt.NvIndexMax);
            TpmCfg.MaxNvOpSize = (ushort)Tpm2.GetProperty(tpm, Pt.NvBufferMax);
            TpmCfg.MaxLabelSize = Math.Min(32, (Math.Min(TpmCfg.MaxEccKeySize, TpmCfg.MaxDigestSize)));


            // Some TPMs allow NV index to take most of the NV. This would break some
            // tests. Thus, force the decreased limit.
            TpmHandle nvHandle1 = TpmHandle.NV(TestConfig.MaxNvIndex + 1);
            TpmHandle nvHandle2 = TpmHandle.NV(TestConfig.MaxNvIndex + 2);
            while (true)
            {
                var nvPub = new NvPublic(nvHandle1, TpmCfg.HashAlgs[0], TestConfig.DefaultNvAttrs,
                                         null, TpmCfg.MaxNvIndexSize);
                tpm._ExpectResponses(TpmRc.Success, TpmRc.NvSpace, TpmRc.BadAuth, TpmRc.NvDefined)
                   .NvDefineSpace(TpmRh.Owner, null, nvPub);

                if (tpm._GetLastResponseCode() == TpmRc.NvDefined)
                {
                    nvHandle1.handle++;
                    nvHandle2.handle++;
                    continue;
                }

                // OwnerAuth value recovery
                // NOTE: Similar code is used by CleanNv(). Update in sync.
                if (tpm._GetLastResponseCode() == TpmRc.BadAuth)
                {
                    // Owner auth may have been changed by a previously failed test
                    tpm[TestConfig.TempAuth]._ExpectResponses(TpmRc.Success, TpmRc.NvSpace, TpmRc.BadAuth)
                       .NvDefineSpace(TpmRh.Owner, null, nvPub);
                    if (tpm._LastCommandSucceeded())
                    {
                        tpm.OwnerAuth = TestConfig.TempAuth;
                    }
                    else if (!Globs.IsZeroBuffer(tpm.OwnerAuth))
                    {
                        tpm[NullAuth]._ExpectResponses(TpmRc.Success, TpmRc.NvSpace)
                           .NvDefineSpace(TpmRh.Owner, null, nvPub);
                        if (tpm._LastCommandSucceeded())
                        {
                            tpm.OwnerAuth = NullAuth;
                        }
                    }
                }
                if (tpm._LastCommandSucceeded())
                {
                    nvPub.nvIndex = nvHandle2;
                    tpm._ExpectResponses(TpmRc.Success, TpmRc.NvSpace)
                       .NvDefineSpace(TpmRh.Owner, null, nvPub);
                    bool secondIndexAllocated = tpm._LastCommandSucceeded();
                    tpm.NvUndefineSpace(TpmRh.Owner, nvHandle1);
                    if (secondIndexAllocated)
                    {
                        tpm.NvUndefineSpace(TpmRh.Owner, nvHandle2);
                        break;
                    }
                }
                if (TpmCfg.MaxNvIndexSize / 2 < 2048)
                {
                    TpmCfg.MaxNvIndexSize = 2048;
                    break;
                }
                else
                    TpmCfg.MaxNvIndexSize /= 2;
            }

            // Workaround for TPMs incorrectly reporting TPM_PT_NV_BUFFER_MAX property
            if (TpmCfg.MaxNvOpSize == 0)
            {
                TpmCfg.MaxNvOpSize = TpmCfg.MaxDigestSize;
            }
            TpmCfg.SafeNvIndexSize = Math.Min(TpmCfg.MaxNvIndexSize, TpmCfg.MaxNvOpSize);
            PcrSelection.MaxPcrs = (ushort)Tpm2.GetProperty(tpm, Pt.PcrCount);

            TpmCfg.MaxQualDataSize = (ushort)(TpmCfg.MaxDigestSize + sizeof(UInt16));

            TpmCfg.LargestHashAlg = TpmCfg.ShortestHashAlg = TpmAlgId.None;
            TpmCfg.MinDigestSize = ushort.MaxValue;
            TpmCfg.MaxDigestSize = 0;
            foreach (var alg in TpmCfg.HashAlgs)
            {
                var digestSize = TpmHash.DigestSize(alg);
                if (TpmCfg.MaxDigestSize < digestSize)
                {
                    TpmCfg.MaxDigestSize = digestSize;
                    TpmCfg.LargestHashAlg = alg;
                }
                if (TpmCfg.MinDigestSize > digestSize)
                {
                    TpmCfg.ShortestHashAlg = alg;
                    TpmCfg.MinDigestSize = digestSize;
                }
            }

            var keySizes = new List<ushort>();
            var symDef = new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb);
            var rsaParms = new RsaParms(symDef, null, 1024, 0);
            IPublicParmsUnion parms = null;

            if (TpmCfg.IsImplemented(TpmAlgId.Rsa))
            {
                // Find the smallest supported RSA size (currently checks only 1024 and 2048)
                tpm._AllowErrors().TestParms(rsaParms);
                if (!tpm._LastCommandSucceeded())
                {
                    rsaParms.keyBits = 2048;
                    tpm._AllowErrors().TestParms(rsaParms);
                    if (!tpm._LastCommandSucceeded())
                    {
                        symDef.KeyBits = 256;
                        tpm._AllowErrors().TestParms(rsaParms);
                        if (!tpm._LastCommandSucceeded())
                        {
                            WriteToLog("WARNING: Unrecognized TPM algorithm configuration.\n" +
                                       "         No standard RSA/AES combinations found.\n" +
                                       "         Attempting to continue...", ConsoleColor.Cyan);
                        }
                    }
                }
                parms = rsaParms;
            }
            else
            {
                var curve = TpmCfg.IsImplemented(EccCurve.NistP256) ? EccCurve.NistP256 : TpmCfg.EccCurves.Keys.First();
                parms = new EccParms(symDef, null, curve, new NullKdfScheme());
                tpm._AllowErrors().TestParms(parms);
                if (!tpm._LastCommandSucceeded())
                {
                    symDef.KeyBits = 256;
                    parms = new EccParms(symDef, null, curve, new NullKdfScheme());
                    tpm._AllowErrors().TestParms(parms);
                    if (!tpm._LastCommandSucceeded())
                    {
                        WriteToLog("WARNING: Unrecognized TPM algorithm configuration.\n" +
                                    "        No RSA is supported and, no working ECC/AES combination found.\n" +
                                    "        Attempting to continue...", ConsoleColor.Cyan);
                    }
                }
            }

            var allModes = new TpmAlgId[] { TpmAlgId.Cfb, TpmAlgId.Ctr,
                                            TpmAlgId.Ofb, TpmAlgId.Cbc, TpmAlgId.Ecb };
            var modes = new HashSet<TpmAlgId>();
            var symDefs = new List<SymDefObject>();
            var swSymDefs = new List<SymDefObject>();

            foreach (var alg in symAlgs)
            {
                if (alg == TpmAlgId.Xor)
                    continue;

                symDef.Algorithm = alg;
                for (ushort n = symDef.KeyBits; n <= 256; n += 64)
                {
                    symDef.KeyBits = n;
                    foreach (TpmAlgId mode in allModes)
                    {
                        symDef.Mode = mode;
                        tpm._AllowErrors().TestParms(parms);
                        if (tpm._LastCommandSucceeded())
                        {
                            if (mode == TpmAlgId.Cfb)
                            {
                                keySizes.Add(n);
                            }

                            var sd = symDef.Copy();
                            symDefs.Add(sd);
                            modes.Add(sd.Mode);

                            using (var sym = SymCipher.Create(sd))
                            {
                                if (sym != null && !sym.LimitedSupport)
                                {
                                    swSymDefs.Add(sd);
                                }
                            }
                        }
                    }
                }
                if (alg == TpmAlgId.Aes)
                {
                    TpmCfg.AesKeySizes = keySizes.ToArray();
                }
                else if (alg == TpmAlgId.Tdes)
                {
                    TpmCfg.DesKeySizes = keySizes.ToArray();
                }
                LogKeyParams(alg, keySizes);
                keySizes.Clear();
            }
            TpmCfg.SymDefs = symDefs.ToArray();
            TpmCfg.CfbSymDefs = TpmCfg.SymDefs.Where(sd => sd.Mode == TpmAlgId.Cfb).ToArray();
            TpmCfg.SwSymDefs = swSymDefs.ToArray();
            TpmCfg.SwCfbSymDefs = TpmCfg.SwSymDefs.Where(sd => sd.Mode == TpmAlgId.Cfb).ToArray();
            TpmCfg.SymModes = modes.ToArray();

            LogListOfValues("Block cipher modes: ", modes);

            if (TpmCfg.IsImplemented(TpmAlgId.Rsa))
            {
                rsaParms.symmetric = TpmCfg.SymDefs[0];
                for (ushort n = rsaParms.keyBits; n <= 4096; n += 1024)
                {
                    rsaParms.keyBits = n;
                    tpm._AllowErrors().TestParms(rsaParms);
                    if (tpm._LastCommandSucceeded())
                    {
                        keySizes.Add(n);
                    }
                }
                LogKeyParams(TpmAlgId.Rsa, keySizes);
            }
            TpmCfg.RsaKeySizes = keySizes.ToArray();

#if false
            // Test Tpm2Tester correctness in case not all PCR banks are allocated
            var allocatedPcrs = new uint[PcrSelection.MaxPcrs];
            for (uint i = 0; i < PcrSelection.MaxPcrs; ++i)
            {
                allocatedPcrs[i] = i;
            }
            var pcrBanks = new PcrSelection[TpmCfg.HashAlgs.Length];
            for (int i = 0; i < TpmCfg.HashAlgs.Length; ++i)
            {
                pcrBanks[i] = new PcrSelection(TpmCfg.HashAlgs[i],
                        TpmCfg.HashAlgs[i] != TpmAlgId.Sha256 ? allocatedPcrs : new uint[0]);
            }
            uint maxNum, sizeNeeded, sizeAvailable;
            uint success = tpm.PcrAllocate(TpmRh.Platform, pcrBanks, out maxNum,
                                           out sizeNeeded, out sizeAvailable);
            Substrate.Assert(success == 1 && tpm._LastCommandSucceeded());
            RecoveryResetTpm(tpm);
#endif

            more = tpm.GetCapability(Cap.Pcrs, 0, 64, out caps);
            Substrate.Assert(more == 0);
            PcrSelectionArray sa = caps as PcrSelectionArray;
            foreach (var sel in sa.pcrSelections)
            {
                if (sel.NumPcrsSelected() > 0)
                {
                    TpmCfg.PcrBanks.Add(sel);
                }
            }
        } // InitTpmParams()

        void LogListOfValues<V>(string label, IEnumerable<V> vals,
                                string separator = ", ")
        {
            string list = label;

            if (vals == null || vals.Count() == 0)
            {
                list += "<NONE>";
            }
            else
            {
                bool first = true;
                foreach (var v in vals)
                {
                    list += (first ? "" : separator) + v.ToString().ToUpper();
                    first = false;
                }
            }

            if (TestCfg.Verbose || TestCfg.DumpTpmInfo)
                WriteToLog(list);
        }

        void LogKeyParams<P>(TpmAlgId alg, IEnumerable<P> keyParams,
                            string separator = "/")
        {
            string label = "";
            if (alg != TpmAlgId.None)
            {
                label = alg == TpmAlgId.Rsa ? "RSA " : alg.ToString().ToUpper() + " ";
            }
            LogListOfValues(label, keyParams, separator);
        }

        // Ensures that (a) TPM primary seed auth values are set, and
        // (b) tries to clean all slots.
        internal bool RecoverTpm(Tpm2 tpm)
        {
            Substrate.ReactivateKeyCache(tpm);

            // Try to enable all hierarchies ...
            if (!TpmCfg.PlatformDisabled)
            {
                tpm._AllowErrors().HierarchyControl(TpmRh.Platform, TpmRh.Owner, 1);
                if (tpm._GetLastResponseCode() != TpmRc.Success)
                {
                    TpmCfg.PlatformAuthUnknown = true;
                }
                tpm._AllowErrors().HierarchyControl(TpmRh.Platform, TpmRh.Endorsement, 1);
                if (tpm._GetLastResponseCode() != TpmRc.Success)
                {
                    TpmCfg.PlatformAuthUnknown = true;
                }
            }

            // ... and then clean up the TPM
            return ResetTpmDaLogic(tpm) && CleanNv(tpm) && Substrate.CleanSlots(tpm);
        }

        internal bool CleanNv(Tpm2 tpm)
        {
            bool lostIndicesFound;
            return CleanNv(tpm, out lostIndicesFound);
        }

        private bool CleanNv(Tpm2 tpm, out bool lostIndicesFound)
        {
            lostIndicesFound = false;

            if (!TestCfg.ClearNv)
                return true;

            // Make sure that the owner hierarchy is enabled
            if (!TpmCfg.PlatformDisabled)
            {
                tpm._AllowErrors().HierarchyControl(TpmRh.Platform, TpmRh.Owner, 1);
                if (!tpm._LastCommandSucceeded())
                {
                    // Make sure that the owner and platform hierarchies are enabled
                    Substrate.RecoveryResetTpm(tpm);
                }
            }

            bool succeeded = true;
            byte moreData;
            do
            {
                ICapabilitiesUnion cap;
                uint maxHandles = UInt16.MaxValue;
                moreData = tpm.GetCapability(Cap.Handles, ((uint)Ht.NvIndex) << 24,
                                             maxHandles, out cap);
                HandleArray handles = (HandleArray)cap;
                foreach (TpmHandle hh in handles.handle)
                {
                    var h = hh.handle & 0x00FFFFFF;
                    // Tpm2Tester uses NV indices up to TestConfig.MaxNvIndex and KAT for policies
                    // (NiapPolicyTest) uses NV index 0x800000
                    if (!FuzzMode &&
                        h > (uint)TestConfig.MaxNvIndex && h != 0x800000)
                    {
                        // An NV index outside of Tpm2Tester's range. Leave it alone.
                        continue;
                    }

                    lostIndicesFound = true;

                    tpm._AllowErrors()
                       .NvUndefineSpace(TpmRh.Owner, hh);
                    TpmRc res = tpm._GetLastResponseCode();
                    if (res == TpmRc.Success)
                    {
                        continue;
                    }

                    // OwnerAuth value recovery
                    // NOTE: Similar code is used by InitTpmParams(). Update in sync.
                    if (res == TpmRc.BadAuth)
                    {
                        // Owner auth may have been changed by a previously failed test
                        tpm[TestConfig.TempAuth]._AllowErrors()
                           .NvUndefineSpace(TpmRh.Owner, hh);
                        res = tpm._GetLastResponseCode();
                        if (res == TpmRc.Success)
                        {
                            tpm.OwnerAuth = TestConfig.TempAuth;
                        }
                        else if (!Globs.IsZeroBuffer(tpm.OwnerAuth))
                        {
                            tpm[NullAuth]._AllowErrors()
                               .NvUndefineSpace(TpmRh.Owner, hh);
                            if (tpm._LastCommandSucceeded())
                            {
                                tpm.OwnerAuth = NullAuth;
                            }
                        }
                    }
                    if (!TpmCfg.PlatformDisabled)
                    {
                        if (res == TpmRc.Attributes)
                        {
                            // The index is created with the NvAttr.PolicyDelete attribute.
                            byte[] nvName;
                            var nvPub = tpm.NvReadPublic(hh, out nvName);
                            
                            // Enumerate algorithms supported by the TPM
                            InitTpmParams(tpm);

                            foreach (var HashAlg in TpmCfg.HashAlgs)
                            {
                                if (nvPub.authPolicy.Length != TpmHash.DigestSize(HashAlg))
                                {
                                    continue;
                                }
                                // Try the minimal policy
                                PolicyTree policy = new PolicyTree(HashAlg);
                                policy.SetPolicyRoot(new TpmPolicyCommand(
                                                        TpmCc.NvUndefineSpaceSpecial));
                                AuthSession sess = tpm.StartAuthSessionEx(TpmSe.Policy,
                                                                          HashAlg);
                                sess.RunPolicy(tpm, policy);
                                tpm[sess]._AssertPhysicalPresence()
                                         ._AllowErrors()
                                         .NvUndefineSpaceSpecial(hh, TpmRh.Platform);
                                res = tpm._GetLastResponseCode();
                                tpm.FlushContext(sess);
                                break;
                            }
                        }
                        else
                        {
                            tpm._AssertPhysicalPresence()
                               ._AllowErrors()
                               .NvUndefineSpace(TpmRh.Platform, hh);
                        }
                    }
                    else if (res == TpmRc.NvAuthorization)
                    {
                        // This is a platform NV index, and the platform hierarchy is disabled.
                    }

                    if (res != TpmRc.Success)
                    {
                        if (!ToughHandles.Contains(hh.handle))
                        {
                            WriteToLog("Unable to delete NV slot 0x{0:X}, error 0x{1:X}",
                                       hh.handle, res, ConsoleColor.DarkYellow);
                            succeeded = false;
                            if (res == TpmRc.BadAuth || res == TpmRc.AuthFail)
                            {
                                TpmCfg.PlatformAuthUnknown = true;  // TPM clear required
                            }
                            ToughHandles.Add(hh.handle);
                        }
                    }
                    else
                    {
                        WriteToLog("Deleted NV slot {0:X}", hh.handle, ConsoleColor.Green);
                    }
                }
            } while (moreData == 1);
            return succeeded;
        } // CleanNv()

        private static bool IsIoException(Exception e)
        {
            return e.InnerException is System.IO.IOException
#if !TSS_NO_TCP
                    || e.InnerException is System.Net.Sockets.SocketException
#endif
            ;
        }

        // Recover TPM to as clean a state as the platform can make it
        private bool PlatformCleanTpm(Tpm2 tpm)
        {
            if (TpmCfg.PlatformDisabled)
                return true;

            tpm._SetLocality(LocalityAttr.LocZero);
            // try a few times to get everything working
            for (int j = 0; j < 3; j++)
            {
                try
                {
                    bool cleanedOk = PlatformCleanTpmImpl(tpm);
                    if (MainTpmDevice.ImplementsPhysicalPresence())
                    {
                        MainTpmDevice.AssertPhysicalPresence(false);
                    }

                    if (!cleanedOk)
                        WriteErrorToLog("Platform failed to clean the TPM.");
                    return cleanedOk;
                }
                catch (Exception e)
                {
                    if (IsIoException(e))
                    {
                        MainTestContext.TpmSeemsToBeDead = true;
                        return false;
                    }

                    WriteToLog("Platform failed to clean the TPM. Trying again...");
                    WriteToLog(e.ToString());
                    WriteToLog(e.StackTrace);
                }
                Thread.Sleep(3000);
            }
            WriteToLog("Platform failed to clean the TPM. Giving up...");
            return false;
        } // PlatformCleanTpm()

        private bool PlatformCleanTpmImpl(Tpm2 tpm)
        {
            Substrate.Assert(!TpmCfg.PlatformDisabled);

            tpm._GetUnderlyingDevice().SignalNvOn();

            // Successful call to RecoveryResetTpm also resets tpm.PlatformAuth value
            Substrate.RecoveryResetTpm(tpm);

            //
            // Reset the seeds if necesssary
            //
            if (MainTpmDevice.ImplementsPhysicalPresence())
            {
                MainTpmDevice.AssertPhysicalPresence(true);
            }
            tpm.ClearControl(TpmRh.Platform, 0);

            if (TpmCfg.PlatformAuthUnknown)
            {
                TpmCfg.PlatformAuthUnknown = false;
                // tpm.Clear() also resets OwnerAuth, EndorsementAuth, and LockoutAuth
                tpm.Clear(TpmRh.Platform);
                tpm.ChangePPS(TpmRh.Platform);
                tpm.ChangeEPS(TpmRh.Platform);
            }

            ResetTpmDaLogic(tpm);

            // Set the PP-required list back to minimum
            ICapabilitiesUnion cap;
            byte more = tpm.GetCapability(Cap.PpCommands, 0, 255, out cap);
            if (more == 1)
            {
                WriteToLog("Tester error -- too many PP commands to reset.  Try again");
                return false;
            }
            CcArray capx = ((CcArray)cap);
            int count = capx.commandCodes.Length;
            tpm.PpCommands(TpmRh.Platform, new TpmCc[0], capx.commandCodes);

            MainTpmDevice.AssertPhysicalPresence(false);

            return CleanNv(tpm) && Substrate.CleanSlots(tpm);
        } // PlatformCleanTpmImpl()

        private bool ClearTpm(Tpm2 tpm, string logMessage = null)
        {
            Substrate.Assert(!TpmCfg.PlatformDisabled);

            if (logMessage != null)
            {
                WriteToLog(logMessage);
            }

            tpm._AssertPhysicalPresence()
               ._AllowErrors()
               .ClearControl(TpmRh.Platform, 0);
            if (!tpm._LastCommandSucceeded())
            {
                // Platform hierarchy is disabled or its auth value is unknown
                // Try LockoutAuth to clear TPM
                tpm._AssertPhysicalPresence()
                   ._AllowErrors()
                   .Clear(TpmRh.Lockout);
            }
            else
            {
                // Platform hierarchy is accessible, so use it to clear the TPM.
                tpm._AssertPhysicalPresence()
                   .Clear(TpmRh.Platform);
            }

            return tpm._LastCommandSucceeded();
        } // ClearTpm()

        private bool ResetTpmDaLogic(Tpm2 tpm, bool startup = false)
        {
            if (TpmCfg.LockoutAuthUnknown)
                return true;

            tpm._SetLocality(LocalityAttr.LocZero);

            if (TpmCfg.PowerControl)
                tpm._GetUnderlyingDevice().SignalNvOn();

            tpm[Auth.Pw]._AllowErrors()
               .DictionaryAttackLockReset(TpmRh.Lockout);

            var res = tpm._GetLastResponseCode();
            bool reboot = false;
            string reason = null;
            if (res == TpmRc.AuthFail || res == TpmRc.BadAuth)
            {
                if (!Globs.IsZeroBuffer(tpm.LockoutAuth))
                {
                    tpm[NullAuth]._AllowErrors()
                       .DictionaryAttackLockReset(TpmRh.Lockout);
                    if (tpm._LastCommandSucceeded())
                    {
                        tpm.LockoutAuth = NullAuth;
                    }
                }
                if (!tpm._LastCommandSucceeded())
                {
                    reboot = true;
                    reason = ">>> Lockout auth is unknown: tried " + Globs.HexFromByteArray(tpm.LockoutAuth);
                }
            }
            else if (res == TpmRc.Lockout)
            {
                reason = ">>> Lockout auth is locked out";
                reboot = true;
                if (Tpm2.GetProperty(tpm, Pt.LockoutRecovery) != 0)
                {
                    WriteToLog(reason, ConsoleColor.Cyan);
                    int timeout = 1000; // ms
                    while (timeout < 5000)
                    {
                        WriteToLog(">>> Waiting " + timeout + " ms ...");
                        Thread.Sleep(timeout);
                        tpm[Auth.Pw]._AllowErrors()
                           .DictionaryAttackLockReset(TpmRh.Lockout);
                        if (tpm._LastCommandSucceeded())
                        {
                            reboot = false;
                            break;
                        }
                        timeout *= 2;
                    }
                }
            }
            else if (!tpm._LastCommandSucceeded())
            {
                reboot = true;
                reason = ">>> Unexpected error {" + tpm._GetLastResponseCode() + 
                         "} returned by DictionaryAttackLockReset";
            }

            if (reboot)
            {
                bool failed = true;
                if (!TpmCfg.PlatformDisabled)
                {
                    WriteToLog(reason, ConsoleColor.Cyan);
                    WriteToLog(">>> Resetting TPM ...");

                    Substrate.RecoveryResetTpm(tpm);
                    tpm[Auth.Pw]._AllowErrors()
                       .DictionaryAttackLockReset(TpmRh.Lockout);

                    if (tpm._LastCommandSucceeded() || ClearTpm(tpm, ">>> Clearing TPM ..."))
                    {
                        failed = false;
                    }
                    else if (!startup)
                    {
                        WriteToLog(">>> Failed to reset DA logic. Error {" + 
                                   tpm._GetLastResponseCode() + "}", ConsoleColor.Cyan);
                    }
                }
                else
                {
                    WriteErrorToLog(reason);
                }

                if (!failed)
                {
                    tpm[Auth.Pw]._AllowErrors()
                       .DictionaryAttackLockReset(TpmRh.Lockout);
                    if (!tpm._LastCommandSucceeded())
                    {
                        if (!startup)
                        {
                            WriteToLog(">>> Last resort attempt to reset TPM DA logic " +
                                       "failed. Error {" + tpm._GetLastResponseCode() + "}",
                                       ConsoleColor.Cyan);
                        }
                        failed = true;
                    }
                }
                if (failed)
                {
                    if (startup)
                    {
                        WriteToLog(">>> Unable to reset TPM's DA protection logic. \n" +
                                    "Some tests will be bypassed...", ConsoleColor.Cyan);
                    }
                    else
                    {
                        WriteToLog(">>> LockoutAuth is unknown. Some tests will be bypassed. \n" +
                                   ">>> To run the complete test suite: \n" +
                                   "  - disable TPM auto-provisioning by OS, \n" +
                                   "  - clear TPM, \n" +
                                   "  - reboot the machine.", ConsoleColor.Cyan);
                    }
                    TpmCfg.LockoutAuthUnknown = true;
                    return false;
                }
            }
            tpm.DictionaryAttackParameters(TpmRh.Lockout, 10000, 1, 1);
            return true;
        } // ResetTpmDaLogic()

        private void PrepareStressPhase(Tpm2 tpm, string phaseHeadline,
                              double stateSaveProbability, DateTime endTime)
        {
            if (!RecoverTpm(tpm))
            {
                WriteToLog("Failed to prepare the TPM for the next test phase " +
                            "(tests will continue)");
            }
            else if (Tbs != null && InitTPM == true)
                Tbs.DebugAssertTpmIsEmpty();

            if (Tbs != null)
                Tbs.SetS3Probability(stateSaveProbability);

            var remainingTime = endTime - DateTime.Now;
            string minutesToGo = ((int)(remainingTime.TotalMinutes)).ToString();
            WriteToLog("\n" + phaseHeadline + ". " + minutesToGo + " minutes remaining.",
                       ConsoleColor.DarkGreen);
        }

        private void StresssPhaseCompleted(string phaseType, bool success, ref bool testsFailed)
        {
            if (InitTPM)
            {
                if (Tbs.NumActiveContexts() != 0)
                {
                    WriteToLog("WARNING: {0} tests leave dangling TBS contexts",
                               phaseType, ConsoleColor.Yellow);
                }
                if (Tbs.NumEntitiesInTpm() != 0)
                {
                    WriteToLog("WARNING: {0} ests leave dangling entities in TPM",
                               phaseType, ConsoleColor.Yellow);
                }
            }

            Tbs.SetS3Probability(0.0);
            if (!success)
                testsFailed = true;
        }

        // Stress runs in two phases. User tests in parallel on the requested number
        // of threads, followed by  the system tests run serially.  
        // Return false if any test failed
        private bool RunStress(string[] testNames, int numThreads, DateTime endTime,
                               bool stopOnError, double stateSaveProbability,
                               bool TestNvIsAvailable)
        {
            // Decrease probability of premature NV depletion in parallel mode
            TpmCfg.MaxNvOpSize = Math.Max(TpmCfg.MaxDigestSize, (ushort)(TpmCfg.MaxNvOpSize / numThreads));

            // Preallocate at least one persistent object fot the Tpm2Tester infra to
            // avoid unexpected failures caused by depleted NV during parallel phase.
            Substrate.LoadRsaPrimary(MainTpm);

            List<string> threadSafeTests = new List<string>();
            List<string> threadUnsafeTests = new List<string>();

            foreach( string testName in testNames )
            {
                if (GetTestAttribute(testName).SpecialNeeds.HasFlag(Special.NotThreadSafe))
                {
                    threadUnsafeTests.Add(testName);
                }
                else
                    threadSafeTests.Add(testName);
            }
            
            List<MethodInfo> parallelTests = MethodInfoFromNames(threadSafeTests);
            List<MethodInfo> sequentialTests = MethodInfoFromNames(threadUnsafeTests);
            TestContext seqCtx = MainTestLogger.NewContext();
            var parPhaseEndTime = sequentialTests.Count > 0 ? DateTime.Now : endTime;
            var seqPhaseEndTime = parallelTests.Count > 0 ? DateTime.Now : endTime;

            if (TestNvIsAvailable)
                Tbs.GetUnderlyingTpm()._DebugTestNvIsAvailable();

            bool success = true;
            bool testsFailed = false;
            bool aborted = false;

            while (!aborted && DateTime.Now < endTime)
            {
                // phase 1 is user tests in parallel
                if (parallelTests.Count > 0)
                {
                    PrepareStressPhase(MainTpm, "Parallel phase (" + numThreads
                                         + " threads, " + parallelTests.Count + " tests)",
                                       stateSaveProbability, endTime);
                    success = RunTestsInParallel(parallelTests, Tbs, MainTestLogger,
                                                 numThreads, parPhaseEndTime, out aborted);
                    StresssPhaseCompleted("Parallel", success, ref testsFailed);
                }
                
                if (!aborted && sequentialTests.Count > 0)
                {
                    PrepareStressPhase(MainTpm, "Sequential phase ("
                                             + sequentialTests.Count + " tests)",
                                       stateSaveProbability, endTime);

                    success = RunTestsSerially(Shuffle(sequentialTests),
                                               MainTpm, seqCtx, seqPhaseEndTime,
                                               false, null, out aborted);
                    StresssPhaseCompleted("Sequential", success, ref testsFailed);
                }
            }
            return !testsFailed;
        } // RunStress()

        // Run the provided test sets in parallel on the specified number of threads
        // for the indicated time. Note that the caller must make sure that the tests
        // are thread safe.
        private bool RunTestsInParallel(List<MethodInfo> tests, Tbs tbs, TestLogger logger,
                                        int numThreads, DateTime endTime, out bool aborted)
        {
            var thrCtx = new ThreadTestContext[numThreads];
            Barrier finishedBarrier = new Barrier(numThreads + 1);
            for (int j = 0; j < numThreads; j++)
            {
                thrCtx[j] = new ThreadTestContext
                {
                    testIndex = j,
                    testCtx = logger.NewContext(),
                    tbs = tbs,
                    logger = logger,
                    endTime = endTime,
                    tests = Shuffle(tests),
                    barrier = finishedBarrier,
                    aTestFailed = false
                };

                new Thread(TesterThreadProc).Start(thrCtx[j]);
            }
            finishedBarrier.SignalAndWait();

            // Check if the test run in any of the threads was aborted because of
            // either test infra failure or TPM getting into the failure mode.
            aborted = thrCtx.Any(elt => elt.testCtx == null);
            return !thrCtx.Any(elt => elt.aTestFailed);
        } // RunTestsInParallel()

        private void TesterThreadProc(Object o)
        {
            ThreadTestContext context = (ThreadTestContext)o;
            do
            {
                Tpm2Device dev;
                if (TpmFactory == null)
                {
                    dev = context.tbs.CreateTbsContext();
                }
                else
                {
                    dev = TpmFactory(context.testCtx);
                }
        
                // the TPM has its own RM so just create a new device
                using (dev)
                {
                    Tpm2 tpm = new Tpm2(dev);

                    bool aborted;
                    bool success = RunTestsSerially(Shuffle(context.tests), tpm,
                                                    context.testCtx, context.endTime,
                                                    true, null, out aborted);
                    if (!success)
                        context.aTestFailed = true;
                    if (aborted)
                    {
                        // Indicate that the test run was aborted because of either
                        // test infra failure or TPM getting into the failure mode
                        context.testCtx = null;
                        break;
                    }
                }
            } while (DateTime.Now < context.endTime);

            context.barrier.SignalAndWait();
        } // TesterThreadProc()

        // Main routine for running tests serially called from Main()
        private void RunTestsSerially(string[] testNames, DateTime endTime)
        {
            Substrate.Assert(!TestCfg.StressMode);

            List<MethodInfo> testsToRun = MethodInfoFromNames(testNames.ToList());
            if (testsToRun.Count == 0)
                return;

            MainTestLogger.TestCount = testsToRun.Count;
            MainTestLogger.TestSessEndTime = endTime;

            if (!TestCfg.StressMode && !RecoverTpm(MainTpm))
                WriteToLog("Failed to prepare TPM for the test run (tests will proceed)");

            bool aborted;
            RunTestsSerially(testsToRun, MainTpm, MainTestContext, endTime, false,
                             RemainingTestsFile, out aborted);
        } // RunTestsSerially()

        // Run tests either in listed or randomized order. Also either run tests once,
        // or if not once then until the time given. Note that this routine is called
        // simultaneously from multiple threads in a stress run.
        private bool RunTestsSerially(List<MethodInfo> tests, Tpm2 tpm, TestContext testCtx,
                                      DateTime endTime, bool parallel, string remainingTestsFile,
                                      out bool aborted)
        {
            aborted = false;
            if (tests.Count == 0)
                return true;

            bool testsFailed = false,
                 sharpDeadline = DateTime.Now <= endTime;
            do {
                if (TestCfg.Shuffle)
                    tests = Shuffle(tests);
                for (int j = 0; j < tests.Count; j++)
                {
                    // get remaining tests and print them out if requests
                    if (remainingTestsFile != null)
                    {
                        string testsLeft = "";
                        for (int k = j; k < tests.Count; k++)
                            testsLeft += tests[k].Name + " ";
                        try
                        {
                            File.WriteAllText(remainingTestsFile, testsLeft, Encoding.ASCII);
                        }
                        catch (Exception)
                        {
                            WriteErrorToLog("Failed to write remaining tests file");
                        }
                    }
                    if (TestCfg.TestValidationRun)
                    {
                        testCtx.ResetAttributeCollection(tpm);
                    }

                    MethodInfo test = tests[j];
#if !TSS_NO_TCP
                    TheTransportLogger.NotifyTestStart(test.Name);

                    if (TheTransportLogger.IsLogging())
                    {
                        // we want the log files to be standalone, so restart the TPM
                        if (TpmProcess == null)
                        {
                            WriteErrorToLog("TPM must be started using -tpm flag");
                        }
                        else
                        {
                            KillTpmProcess();
                            Thread.Sleep(1000);
                            StartTpm();
                            Thread.Sleep(1000);
                        }

                        Tpm2Device tpmDevice = tpm._GetUnderlyingDevice();
                        tpmDevice.Connect();

                        if (!PowerUpTpm(tpmDevice))
                        {
                            WriteErrorToLog("Failed to power-up the TPM");
                            return false;
                        }
                        if (!TpmCfg.PlatformDisabled)
                        {
                            // set the seed to a deterministic value
                            tpm.Clear(TpmRh.Platform);
                        }
                    }
#endif //!TSS_NO_TCP

                    bool succeeded = RunTest(test, tpm, testCtx, !parallel);

                    if (testCtx.ClearWasExecuted && parallel)
                    {
                        throw new Exception("Test case error: Clear() called in stress mode");
                    }

                    if (!succeeded)
                        testsFailed = true;

                    try
                    {
                        if (parallel)
                        {
                            ResetTpmDaLogic(tpm);
                        }
                        else
                        {
                            if (!succeeded)
                                RecoverTpm(tpm);
                            else
                            {
                                ResetTpmDaLogic(tpm);
                                if (InitTPM)
                                {
                                    if (TpmHelper.AreAnySlotsFull(tpm))
                                    {
                                        WriteErrorToLog("Test {0} leaks object handles\n", test.Name);
                                        Substrate.CleanSlots(tpm);
                                    }

                                    bool lostIndicesFound;
                                    CleanNv(tpm, out lostIndicesFound);
                                    if (lostIndicesFound)
                                        WriteErrorToLog("Test {0} leaks NV indices\n", test.Name);
                                }
                            }

                            if (TestCfg.TestValidationRun)
                                testCtx.ValidateTestAttributeCollection(test, tpm);
                        }
                    } catch (Exception e)
                    {
                        // Test run was aborted because of either test infra failure
                        // or TPM getting into the failure mode.
                        ProcessException(e);
                        aborted = true;
                        break;
                    }
#if !TSS_NO_TCP
                    TheTransportLogger.NotifyTestComplete();
#endif
                    if (sharpDeadline && DateTime.Now > endTime)
                        break;
                }
            } while (!aborted && DateTime.Now < endTime);

            return !testsFailed;
        } // RunTestsSerially()

        private List<MethodInfo> Shuffle(List<MethodInfo> tests)
        {
            int numTests = tests.Count;
            List<MethodInfo> shuffle = new List<MethodInfo>();
            if (numTests == 0) return shuffle;
            bool[] picked = new bool[numTests];
            // todo - more efficient shuffle
            int numPicked = 0;
            do
            {
                int pos = Substrate.RandomInt(numTests);
                if (picked[pos]) continue;
                picked[pos] = true;
                shuffle.Add(tests[pos]);
                numPicked++;
            } while (numPicked < numTests);
            return shuffle;
        }

        // Set DebugExceptions = TRUE if you want to invoke the debugger immediately
        // when an exception is thrown (this is useful for debugging test case errors).
        // Otherwise it will be swallowed by the tester and reported at the end
        // of the test run.
        private bool DebugExceptions = false;

        // Run named test.  Return whether the test succeeded or failed.  If the test
        // fails the caller should check that the TPM is in a suitable state for other
        // tests to proceed.  The actions the caller will take will probably depend on
        // whether the test is "user" or "system."
        private bool RunTest(MethodInfo testMethod, Tpm2 tpm, TestContext testCtx,
                             bool retryEnabled = false)
        {
            bool        retry = false;
            int         curPhase = 0;

            //NewTest = true;

            var attrs = Globs.GetAttr<TestAttribute>(testMethod);
            if (   TpmCfg.PlatformDisabled && attrs.SpecialNeeds.HasFlag(Special.Platform)
                || !TpmCfg.PowerControl && attrs.SpecialNeeds.HasFlag(Special.PowerControl)
                || !TpmCfg.LocalityControl && attrs.SpecialNeeds.HasFlag(Special.Locality)
                || !TpmCfg.NvControl && attrs.SpecialNeeds.HasFlag(Special.NvControl)
                || TpmCfg.LockoutAuthUnknown && attrs.SpecialNeeds.HasFlag(Special.Lockout)
                || TestCfg.HasTRM && attrs.SpecialNeeds.HasFlag(Special.NoTRM))
            {
                WriteToLog(testMethod.Name + " skipped", ConsoleColor.DarkCyan);
                return true;
            }

            // Mark transition of the statistics domain from Tpm2Tester infra to the test
            testCtx.TestStarted(testMethod.Name, Substrate.ReseedRng());

            if (FuzzMode)
                WriteToLog("-seed " + testCtx.CurRngSeed, ConsoleColor.Gray);
            else
                tpm._SetWarningHandler(testCtx.ReportWarning);

            if (DebugExceptions)
            {
                // If you are developing test cases it is useful for the debugger to 
                // be invoked at the point the exception is thrown. Set DebugExceptions
                // to enable this behavior. Note that this will disable error reporting
                // and test restart functionality.
                // A better alternative is to request the debugger to break whenever
                // a particular exception happens by means of
                //     Visual Studio Debug | Exceptions
                // dialog. This allows to continue with usual exception processing
                // after it is inspected in the debugger, leaving all Tpm2Tester
                // functionality intact. 
                testMethod.Invoke(TestContainer, new object[] {tpm, testCtx});
            }
            else do try
            {
                retry = false;
                int numArgs = testMethod.GetParameters().Length;
                if (numArgs == 2)
                {
                    retryEnabled = false;
                    testMethod.Invoke(TestContainer, new object[] {tpm, testCtx});
                }
                else
                {
                    // Only test methods with 2- or 3-argument are supported.
                    Substrate.Assert(numArgs == 3);
                    curPhase = TheTestState.TestPhase;
                    testMethod.Invoke(TestContainer, new object[] {tpm, testCtx, TheTestState});
                }
                tpm._SetInjectCmdCallback(null);
            }
            catch (Exception e)
            {
                if (!(e is EscapeException))
                    Debug.WriteLine($"Unexpected exception {e}");

                tpm._SetInjectCmdCallback(null);

                retry =  retryEnabled
                      && TheTestState.TestPhase != TestState.NullPhase
                      && curPhase != TheTestState.TestPhase;

                if (!(e is TssAssertException ||
                      (e.InnerException != null && e.InnerException is TssAssertException)))
                {
                    ProcessException(tpm, testCtx, e, testMethod);
                }
                if (retry)
                {
                    // Mark transition of the statistics domain to the Tpm2Tester infra...
                    testCtx.TestCompleted();
                    Substrate.CleanSlots(tpm);
                    // ... and back to the test
                    testCtx.TestStarted(testMethod.Name, Substrate.ReseedRng());
                }
            } while (retry);

            bool result = testCtx.CurTestStatus == TestStatus.OK;

            // Reset the test state
            TheTestState.TestPhase = TestState.NullPhase;
            TheTestState.TestParams = null;
            testCtx.TestCompleted();

            if (TpmCfg.PowerControl)
            {
                foreach (var kv in testCtx.CmdStats)
                {
                    TpmCc cc = kv.Key;
                    if (cc == TpmCc.PcrAllocate)
                    {
                        uint maxNum, sizeNeeded, sizeAvailable;
                        tpm.PcrAllocate(TpmRh.Platform, TpmCfg.PcrBanks.ToArray(),
                                        out maxNum, out sizeNeeded, out sizeAvailable);
                        Substrate.ResetTpm(tpm);
                        break;
                    }
                }
            }

            MainTpm._SetWarningHandler(null);
            return result;
        } // RunTest()

        private bool PowerUpTpm(Tpm2Device tpmDevice)
        {
            if (TestCfg.RunAsStandardUser)
                return true;
            if (tpmDevice.PlatformAvailable())
            {
                tpmDevice.PowerCycle();
                tpmDevice.SignalNvOn();
            }

            var tempTpm = new Tpm2(tpmDevice);
            string exceptionMessage = "";
            if (tpmDevice.PlatformAvailable() && !tpmDevice.UsesTbs())
            {
                try
                {
                    if (!TestCfg.DoInit)
                    {
                        // Attempt to initialize simulator in "TPM Resume" mode
                        tempTpm._AllowErrors().Startup(Su.State);
                        if (!tempTpm._LastCommandSucceeded())
                            tempTpm._AllowErrors().Startup(Su.Clear);
                    }
                    else
                        tempTpm._AllowErrors().Startup(Su.Clear);
                }
                catch (Exception e)
                {
                    exceptionMessage = e.Message;
                }
            }
            if (exceptionMessage != "" || tempTpm._GetLastResponseCode() != TpmRc.Success)
            {
                WriteErrorToLog(
                    "Warning: TPM device returned error from Startup(Su.Clear). " +
                    "Tests will continue.\nError was: " + exceptionMessage + "\n" +
                    tempTpm._GetLastResponseCode().ToString(), ConsoleColor.Cyan);
            }
            return true;
        } // PowerUpTpm()

        private void ProcessException(Exception e)
        {
            ProcessException(MainTpm, MainTestContext, e);
        }

        private void ProcessException(Tpm2 tpm, TestContext testCtx,
                                      Exception e, MethodInfo testMethod = null)
        {
            bool reportException = true;
            if (e.InnerException is TpmException)
            {
                TpmException ee = (TpmException)e.InnerException;
                // Check if the test failed because of a command that is not
                // supported by this TPM instance or is blocked by the OS
                // (TBS_E_BLOCKED returned).
                if (   testMethod != null
                    && (   !TpmCfg.IsImplemented(tpm.LastCommand)
                        || (uint)ee.RawResponse == 0x80280400))
                {
                    testCtx.CurTestStatus = TestStatus.Aborted;
                    AbortedTestsInfo testInfo = new AbortedTestsInfo
                        {
                            command = tpm.LastCommand,
                            reason = ((uint)ee.RawResponse == 0x80280400
                                   && TpmCfg.SupportedCommands.Contains(tpm.LastCommand))
                                                ? AbortReason.BlockedCommand
                                                : AbortReason.UnsupportedCommand
                        };
                    lock (MainTestLogger)
                    {
                        if (!MainTestLogger.AbortedTests.ContainsKey(testMethod.Name))
                        {
                            MainTestLogger.AbortedTests.Add(testMethod.Name, testInfo);
                        }
                    }
                    reportException = false;
                    WriteToLog("{0} - {1} was aborted",
                                MainTestLogger.GetAbortReasonMessage(testInfo),
                                testMethod.Name, ConsoleColor.DarkMagenta);
                }
                else
                {
                    testCtx.CurTestStatus = TestStatus.Failed;
                }
            }
            else
            {
                testCtx.CurTestStatus = TestStatus.Failed;
            }

            if (reportException)
            {
                testCtx.ReportTestException(e);
            }
            if (IsIoException(e))
            {
                testCtx.TpmSeemsToBeDead = true;
            }
        } // ProcessException()

        internal List<MethodInfo> AllTests
        {
            get { return _AllTests; }
        }

        internal List<string> AllTestNames
        {
            get { return _AllTestNames; }
        }

        internal TestAttribute GetTestAttribute(string TestName)
        {
            MethodInfo test = AllTests.Find(item => TestName == item.Name);
            return Globs.GetAttr<TestAttribute>(test);
        }

#if !TSS_NO_TCP
        TransportLogger TheTransportLogger = new TransportLogger();

        internal void InitTransportLogger(string logDir, Tpm2Device device)
        {
            TheTransportLogger = new TransportLogger(logDir, device);
            if (!TheTransportLogger.IsLogging())
            {
                WriteErrorToLog("Log directory " + logDir + " cannot be created");
            }
            else
            {
                MainTestLogger.LogPath = logDir;
            }
        }
#endif //!TSS_NO_TCP

        private void WriteToLog(TextWriter console, string msgFormat, params object[] msgParams)
        {
            if (MainTestLogger == null)
            {
                console.WriteLine(msgFormat, msgParams);
            }
            else
            {
                MainTestLogger.WriteToLog(console, msgFormat, msgParams);
            }
        }

        internal void WriteToLog(string msgFormat, params object[] msgParams)
        {
            TestLogger.SetForegroundColor(ref msgParams, Console.ForegroundColor);
            WriteToLog(Console.Out, msgFormat, msgParams);
            Console.ResetColor();
        }

        internal void WriteErrorToLog(string msgFormat, params object[] msgParams)
        {
            TestLogger.SetForegroundColor(ref msgParams, ConsoleColor.Red);
            WriteToLog(Console.Error, msgFormat, msgParams);
            Console.ResetColor();
        }

#if !TSS_NO_TCP
        private Barrier startTpmBarrier;
        private volatile bool TpmStartedOk;

        // Start the TPM with the path set in the command line parameter. The TPM
        // command line should specify
        // 
        //     base TPM port + 2 * the tester instance
        //
        // to allow multiple tester/TPM pairs.
        private bool StartTpm()
        {
            // first create the directory for the instance
            string dir = GetTpmWorkingDir();
            if (dir == null) return false;

            TpmStartedOk = false;
            var t = new Thread(StartTpmThread);
            startTpmBarrier = new Barrier(2);
            t.Start();
            // wait for the TPM to start
            startTpmBarrier.SignalAndWait();
            if (TpmStartedOk)
            {
                // wait a little while for the TPM to start listening
                Thread.Sleep(5000);
            }
            else
            {
                WriteErrorToLog("Failed to start the TPM at " + TestCfg.TpmPath);
            }
            return TpmStartedOk;
        } // StartTpm()

        private void StartTpmThread()
        {
            var p = new Process();
            TpmProcess = p;
            try
            {
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.FileName = TestCfg.TpmPath;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.WorkingDirectory = GetTpmWorkingDir();

                WriteToLog("Starting TPM:" + GetTpmWorkingDir() + ":" + TestCfg.TpmPath);

                //p.StartInfo.CreateNoWindow = false;
                p.StartInfo.Arguments = (this.TestCfg.TcpServerPort + 2 * TesterInstance).ToString();
                // try to start...
                bool started = p.Start();

                TpmStartedOk = started;

                WriteToLog("TPM started: " + started.ToString());
                startTpmBarrier.SignalAndWait();
                this.TpmStderr = p.StandardError.ReadToEnd();
                p.WaitForExit();
                WriteToLog("TPM exited: " + TpmStderr);
            }
            catch (Exception e)
            {
                WriteErrorToLog("Failed to start the TPM. Exception was: " + e.Message);
                TpmStartedOk = false;
                TpmProcess = null;
                startTpmBarrier.SignalAndWait();
            }
        } // StartTpmThread()

        // Each TPM has to start in its own directory so that NVCHIPs don't collide.
        // If this is not instance zero, the tester will try to create a new "/instance_n"
        // directory as the starting directory of additional instances
        private string GetTpmWorkingDir()
        {
            int instance = GetTesterInstance();
            if (instance == 0) return "";
            string instanceDirName = "Instance_" + instance.ToString();
            if (Directory.Exists(instanceDirName)) return instanceDirName;
            try
            {
                Directory.CreateDirectory(instanceDirName);
                return instanceDirName;
            }
            catch (Exception)
            {
                WriteErrorToLog("Failed to create the directory " + instanceDirName);
                return null;
            }
        }

        // The TPM listens on two consecutive ports. This function returns the lower
        // one. This is either a default, set by the "address" function on the command
        // line, or, if the tester is starting the TPM on this host, is set to the
        //
        //     default/command-line-parm + 2 * the tester instance number
        //
        // This allows to run more than one tester/TPM pair on a host.
        private int GetTcpServerPort()
        {
            if (TesterInstance == 0)
                return TestCfg.TcpServerPort;
            if (TestCfg.TpmPath == "")
                return TestCfg.TcpServerPort;

            // Return a non-colliding port range
            return TestCfg.TcpServerPort + 2 * TesterInstance;
        }

        private bool KillTpmProcess()
        {
            try
            {
                TpmProcess.Kill();
            }
            catch (Exception)
            {
            }
            TpmProcess = null;
            return true;
        }
#endif //!TSS_NO_TCP

    } // class TestFramework

} // namespace Tpm2TestSuite

/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Collections.Generic;
using Tpm2Lib;

namespace Tpm2Tester
{
    // Represents the kind of the TPM device being tested
    enum TpmDeviceType
    {
        // Use dynamically loaded TPM simulator DLL (make sure that Tpm2Tester and
        // simulator DLL are compiled for the same type of architecture)
        dll,

        // Use local OS TPM (TBS on Windows, and /dev/tpmrm0 or /dev/tpm0 on Linux)
        tbs,

        // The local Windows TBS is in raw mode (that has been manually enabled)
        tbsraw,

#if !TSS_NO_TCP
        // Use TCP connection to the simulator or remote proxy
        tcp,

        // Use TCP connection to the simulator or remote proxy, and access it via Tpm2Tester's Resource Manager emulator
        rmsim
#endif
    }

    // Contains hardcoded and configurable (obtained from the command line) parameters
    // of a test session.
    public class TestConfig
    {
        // Byte buffer to be used by tests changing the Owner hierarchy's auth value,
        // so that in case of test failure the framework could recover.
        public static readonly byte[] TempAuth = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1 };

        //
        // Test limits & constants
        //

        // Tests should only create NV slots in the range 0 to TestConfig.MaxNvIndex
        public const int MaxNvIndex = 0x1000;

        // TODO: initialize dynamically with the actual value from the TPM
        public const ushort MaxSymData = (ushort)Implementation.MaxSymData;

        public const ObjectAttr DefaultAttrs = ObjectAttr.FixedParent | ObjectAttr.FixedTPM
                                             | ObjectAttr.UserWithAuth;

        public const NvAttr DefaultNvAttrs = NvAttr.Authread | NvAttr.Authwrite;

        // Maximally acceptable TPM clock imprecision (according to the TPM 2.0 Spec)
        public const double MaxClockError = 0.15;

        //
        // Computational intensity, and run time duration controls
        //

        // Recommended number of iterations in simple loops repeating their actions
        // in order to put minor stress on the TPM data processing code.
        public const int NumIters = 10;

        // Recommended number of itertaions in nested loops 
        public const int NumItersNested = 4;

        // Number of failed authentication attempts before the TPM goes into lockout
        public const uint DA_MaxFailedTries = 5;

        // Max number of retries in case OS or concurrently running apps interpose
        // their TPM commands during the execution of tests relying on TPM audit.
        public const int MaxRetriesUponInterference = 5;


        //
        // Test parameters controlled by command line options
        //

        // Dictionary attack self-healing time in seconds (-daTime option).
        public uint DA_RecoveryTime = 3;

        // Stress mode runs user tests in parallel on several threads (-stress)
        public bool StressMode = false;

        // Number of threads for the stress mode (-threads)
        public int NumThreads = 3;

        // The seed to be used to seed PRNG in the beginning of the Tpm2Tester run
        // AND before the first test execution (-seed)
        public string RngSeed = null;

        // Path to look for the TPM dll (-device dll)
        public string TpmDllPath = null;

        // Specifies that the current TPM device has Resource Management enabled
        public bool HasTRM = false;

        // Allows execution of test that are not reliable (-bleed).
        public bool Bleeding = false;

        // Verbose output (-quiet to disable)
        public bool Verbose = true;

        //
        // Test parameters that are intended to be used by the framework only
        //

        // Type of the TPM device to use (-device)
        // By deafault, when TCP is not disabled, the TPM simulator is used.
        // Otherwise, the TPM provided by the OS.
#if !TSS_NO_TCP
        internal TpmDeviceType DeviceType = TpmDeviceType.tcp;

        // Address of the host running TPM Simulator or TPM Proxy (-address).
        internal string TcpHostName = "127.0.0.1";

        // Primary port, on which the TPM Simulator or TPM Proxy listens (-address).
        // Used only when a TCP device is selected. Tpm2Tester assumes that the TPM
        // is listening on two ports:
        // 
        // {TestCfg.TcpServerPort + 2 * TesterInstance, TestCfg.TcpServerPort + 1 + 2 * TesterInstance}
        //
        internal int TcpServerPort = 2321;

        // Only used with a TCP TPM device (TPM Simulator or TPM Proxy)
        internal TcpTpmDevice TheTcpTpmDevice = null;
#else
        internal TpmDeviceType DeviceType = TpmDeviceType.tbs;
#endif

        // Duration of the stresss mode session (with -tpm option).
        internal const int DefaultStressModeDuration = 60;

        // Time to run the tests, repeating the sequence of tests as many times as
        // necessary (-mins)
        internal DateTime TestEndTime = DateTime.MinValue;

        // An arbitrary string without spaces passed to the first executed test (-params).
        internal string TestParams = null;

        // Allow debugger to be attached on first error (not implemented)
        internal bool StopOnFirstError = false;

        // Shuffle the order of individual test cases execution (-shuffle)
        internal bool Shuffle = false;

        // Seed deterministically the PRNG used by Tpm2Tester (-randSeed to suppress).
        // Works together with TestCfg.RngSeed
        internal bool SeededRng = true;

        // Test switch to S3 power state (-S3).
        // Supported only with emulated Resource Manager. May be unreliable.
        internal bool TestS3 = false;

        // Parameter for the -S3 mode (no command line option).
        internal const double StateSaveProbability = 0.1;

        // Generate HTML log with detailed test run results and statistics (-nohtml
        // to disable).
#if !WLK
        internal bool ShowHTML = true;
#endif

        // Allows TPM initialization and failure recovery actions (-noinit' to disable).
        internal bool DoInit = true;

        // Controls if NV memory is cleaned up during Tpm2Tester startup and upon each
        // unit test completion (-noinit' to disable).
        internal bool ClearNv = true;

        // Signal TPM simulator process to exit upon Tpm2Tester session completion (-stopTpm).
        // Has effect only when used with TPM simulator. Useful when doing performance
        // or coverage measurements.
        internal bool StopTpm = false;

        // Enables RSA keys cache in the user mode TPM simulator (-fast).
        internal bool UseKeyCache = false;

        // Dump console output into the log file console.txt (-dumpConsole).
        internal bool DumpConsole = false;

        // Directory to store logs (-log)
        internal string TransportLogsDirectory = null;

        // Test mode when each command is first attempted with TPM's NV memory disabled
        // (-debugNv). Works with the TPM simulator only.
        internal bool TestNvAvailable = false;

        // Runs Tpm2Tester with limited functionality (-stdUser).
        internal bool RunAsStandardUser = false;

        // Dump TPM info (-tpmInfo)
        internal bool DumpTpmInfo = false;

        // Validate tests obey threading (and other) rules (-validate).
        // May be outdated.
        internal bool TestValidationRun = false;

        // Final list of tests to execute (based on command line arguments)
        // Note that some of these tests may be skipped at run time depending on the
        // actual TPM capabilities.
        internal List<string> TestsToRun = new List<string>();

        // Final list of tests to skip (based on command line arguments)
        // Note that more tests may be skipped at run time depending on the actual TPM capabilities.
        internal TestAttribute DisabledTests =
                        new TestAttribute(Profile.None, Privileges.None,
                                          Category.Hidden | Category.Slow);

#if !TSS_NO_TCP
        // Restart TPM if it dies or becomes unresponsive (-restart).
        // Works with the TPM simulator only. See TestConfig.NumMinsBeforeAutoRestart.
        internal bool TpmAutoRestart = false;

        // Timeout before the TPM is restarted (with -restart option);
        internal const double NumMinsBeforeAutoRestart = 2;

        // Path to the TPM simulator executable (.exe) file (-tpm).
        internal string TpmPath = "";
#endif

        // A directory to receive fuzz crash reports (-crashReports). May be outdated.
        internal string FuzzCrashesDirectory = ".";

        // Upon start, create a file in TestCfg.FuzzCrashesDirectory (-helloworld).
        // (Good for headless stress runs)
        internal bool GenerateStartupCheckin = false;

        public bool IsDisabled(Category cat)
        {
            return DisabledTests.Category.HasFlag(cat);
        }

        public bool IsDisabled(Special special)
        {
            return DisabledTests.SpecialNeeds.HasFlag(special);
        }

    } // class TestConfig
}

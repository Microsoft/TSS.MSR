/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Threading;
using Tpm2Lib;

/*
 * This file contains support data and routines for the test cases
 */

namespace Tpm2Tester
{
    
    public class TestState
    {
        public static readonly int NullPhase = 0;

        // Initially this field is NullPhase. The test accepting TestState parameter
        // (passed as the third by-ref argument) may set this field if it wants the
        // framework to restart it in case of failure.
        // If this field remains set to the same value after the restarted test failed,
        // the framework won't restart the test again.
        public int TestPhase;

        // The value of the '-params' option. An arbitrary string w/o spaces passed
        // to a single test specified with '-tests' option.
        // Alternatively the test may set this field when it requests restart (by setting
        // the TestPhase member).
        // The string is reset upon each test completion (i.e. if no restart is requested).
        public string TestParams;

        internal TestState(string testParams = null)
        {
            TestPhase = NullPhase;
            TestParams = testParams;
        }
    }; // class TestState

    // Represents Tpm2Tester execution environment for the 
    public class TestSubstrate
    {
        // 
        public TestConfig   TestCfg;
        public TpmConfig    TpmCfg;

        internal TestFramework Framework;

        public class TpmCommandCaller
        {
            Tpm2 tpm;

            public TpmCommandCaller(Tpm2 _tpm)
            {
                tpm = _tpm;
            }

            public void PcrEvent(uint pcr)
            {
                tpm.PcrEvent(TpmHandle.Pcr(pcr), Globs.GetRandomBytes(Globs.GetRandomInt(1024)));
            }

            public void Clear()
            {
                tpm.Clear(TpmRh.Platform);
            }

            public void ChangePPS()
            {
                tpm.ChangePPS(TpmRh.Platform);
            }

            public void ChangeEPS()
            {
                tpm.ChangeEPS(TpmRh.Platform);
            }
        } // class TpmCommandCaller

        private TestSubstrate()
        {
            TestCfg = new TestConfig();
            TpmCfg = new TpmConfig();
        }

        /// <summary>Create a test substrate instance with the test methods from the specified
        ///     containing object and given comamnd line options for the test session.</summary>
        /// <param name="testContainer">A reference to an object in the client assembly that
        ///     implements test methods (the ones with the Tpm2Tester.Test attribute). Such
        ///     methods are automatically enumerated, and then filtered and executed based
        ///     on the command line options.</param>
        public static TestSubstrate Create(string[] args, object testContainer)
        {
            var substrate = new TestSubstrate();
            substrate.Framework = TestFramework.Create(substrate, args, testContainer);
            return substrate.Framework != null ? substrate : null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public bool RunTestSession()
        {
            return Framework.RunTestSession();
        }

        public void WriteToLog(string msgFormat, params object[] msgParams)
        {
            Framework.WriteToLog(msgFormat, msgParams);
        }

        public void WriteErrorToLog(string msgFormat, params object[] msgParams)
        {
            Framework.WriteErrorToLog(msgFormat, msgParams);
        }

        public void SimpleFuzzer(byte[] x)
        {
            Framework.SimpleFuzzer(x);
        }

        public void DisableKeyCache(Tpm2 tpm)
        {
            if (TestCfg.UseKeyCache)
                tpm._GetUnderlyingDevice().SignalKeyCacheOff();
        }

        public void ReactivateKeyCache(Tpm2 tpm)
        {
            if (TestCfg.UseKeyCache)
                tpm._GetUnderlyingDevice().SignalKeyCacheOn();
        }

        public void SimpleInterferenceCallback(Tpm2 tpm, TpmCc nextCmd)
        {
            tpm.GetRandom(16);
        }

        int retryCount = 0;

        public void SimulateConcurrentInterference(Tpm2 tpm, Tpm2.InjectCmdCallback cb)
        {
            tpm._SetInjectCmdCallback(cb);
            retryCount = 0;
        }

        public void SimulateConcurrentInterference(Tpm2 tpm)
        {
            SimulateConcurrentInterference(tpm, SimpleInterferenceCallback);
        }

        // returns true if the test should repeat the failed audited command sequence 
        public bool RetryAfterConcurrentTpmCommandInterference(Tpm2 tpm)
        {
            bool simulated = tpm._GetInjectCmdCallback() != null;

            tpm._SetInjectCmdCallback(null);

            if (++retryCount > TestConfig.MaxRetriesUponInterference)
            {
                WriteErrorToLog("Either TPM audit logic is faulty or a concurrent process " + 
                                "keeps interposing its TPM commands. Aborting the test...");
                return false;
            }

            // If the the first intervention was simulated, no random pause is necessary
            if (retryCount > (simulated ? 1 : 0))
            {
                int pause = 3000 + RandomInt(7000);
                WriteErrorToLog("Possible interference by a concurrent process detected. " + 
                                "Retrying the test after {0} ms...", pause, System.ConsoleColor.Cyan);
                // Sleep for a while to decrease the probability of being intervened
                // again by continued concurrent TPM activity
                Thread.Sleep(pause);
            }
            return true;
        }

        public void AssertConcurrentTpmCommandInterferenceDetected(TestContext testCtx)
        {
            testCtx.Assert("Interposed.Cmds.Detection", retryCount > 0);
        }

        // Production TPM 1.16 in normal (non-bleeding) mode
        public bool ProdTpm_116()
        {
            return !TpmCfg.RefactoredTpm() && !TestCfg.Bleeding;
        }

        internal void Assert(bool cond)
        {
            if (Framework.MainTestContext.ReportErrors && !Framework.FuzzMode)
                Debug.Assert(cond);
        }

        // Returns the number of persistent keys allocated by the Tpm2Tester's infra
        public int NumPersistentKeys()
        {
            return  (PersRsaPrimOwner == null ? 0 : 1) +
                    (PersRsaPrimEndors == null ? 0 : 1) + 
                    (PersRsaPrimPlatform == null ? 0 : 1);
        }

        internal void RecoveryResetTpm(Tpm2 tpm)
        {
            if (TpmCfg.PowerControl)
                TpmHelper.PowerCycle(tpm, Su.Clear, Su.Clear);
        }

        private bool TpmStateTransition(Tpm2 tpm, Su shutdownMode, Su startupMode)
        {
            if (TpmCfg.PowerControl)
                TpmHelper.PowerCycle(tpm, shutdownMode, startupMode);
            return TpmCfg.PowerControl;
        }

        public bool ResetTpm(Tpm2 tpm)
        {
            return TpmStateTransition(tpm, Su.Clear, Su.Clear);
        }

        public bool RestartTpm(Tpm2 tpm)
        {
            return TpmStateTransition(tpm, Su.State, Su.Clear);
        }

        public bool ResumeTpm(Tpm2 tpm)
        {
            return TpmStateTransition(tpm, Su.State, Su.State);
        }

        public string ReseedRng()
        {
            string newSeed = TestCfg.RngSeed;
            TestCfg.RngSeed = null;
            byte[] newSeedBytes;
            if (newSeed == null)
            {
                newSeedBytes = Globs.GetRandomBytes(8);
                newSeed = Globs.HexFromByteArray(newSeedBytes);
            }
            else
            {
                newSeedBytes = Globs.ByteArrayFromHex(newSeed);
            }
            Globs.SetRngSeed(newSeed);
            return newSeed;
        }

        public byte[] RandomBytes(int numBytes)
        {
            return Globs.GetRandomBytes(numBytes);
        }

        public byte[] RandBytes(int minBytes, int maxBytes)
        {
            if (maxBytes < minBytes)
                return null;
            return RandomBytes(RandomInt(maxBytes - minBytes) + minBytes);
        }

        public int RandomInt(int max)
        {
            return Globs.GetRandomInt(max);
        }

        // Generates a non-zero random number up to the max value and different from excludedSize.
        public ushort RandomSize(int max, ushort excludedSize = 0)
        {
            if (max <= 0)
                return 0;

            ushort res = 0;
            do {
                res = (ushort)(Globs.GetRandomInt(max-1) + 1);
            } while (res == excludedSize);
            return res;
        }

        public TpmHandle RandomNvHandle(TpmHandle exclude = null)
        {
            TpmHandle h = null;
            do
            {
                h = TpmHandle.NV(RandomInt(TestConfig.MaxNvIndex));
            } while (exclude != null && h.handle == exclude.handle);

            return h;
        }

        public byte[] RandomAuth(TpmAlgId associatedHash = TpmAlgId.None, int minSize = 1)
        {
            int maxSize = 0;
            if (associatedHash == TpmAlgId.Null || associatedHash == TpmAlgId.None)
            {
                maxSize = TpmCfg.MaxDigestSize;
            }
            else
                maxSize = TpmHash.DigestSize(associatedHash);

            byte[] authVal = null;
            Debug.Assert(minSize <= maxSize);

            if (!TpmCfg.Tpm_115_Errata_13())
            {
                authVal = RandBytes(16, maxSize);
                authVal[0] |= 0x80;
                authVal[authVal.Length - 1] |= 0x80;
            }
            // Make sure that an auth value with trailing zeros is generated sometimes
            else if (RandomInt(10) != 0)
            {
                authVal = RandBytes(minSize, maxSize);
            }
            else
            {
                int trailingZeros = RandomInt(maxSize - minSize);

                authVal = Globs.Concatenate(RandBytes(minSize, maxSize - trailingZeros),
                                            Globs.ByteArray(trailingZeros, 0));
            }

            if (Globs.IsZeroBuffer(authVal))
            {
                authVal[0] = (byte)(RandomInt(254) + 1);
            }

            return authVal;
        }

        public byte[] RandomNonce(TpmAlgId associatedHash = TpmAlgId.None)
        {
            return RandomAuth(associatedHash, 16);
        }

        public byte[] RandomBlob(TpmAlgId associatedAlg = TpmAlgId.None)
        {
            int maxSize = TestConfig.MaxSymData;

            if (associatedAlg != TpmAlgId.None)
            {
                maxSize = CryptoLib.BlockSize(associatedAlg);
            }
            return RandBytes(1, maxSize);
        }

        public byte[] RandomDerivationLabel()
        {
            return RandBytes(0, TpmCfg.MaxLabelSize);
        }

        public byte[] RandomDerivationContext()
        {
            return RandomDerivationLabel();
        }

        public TpmDerive RandomTpmDerive()
        {
            return new TpmDerive(RandomDerivationLabel(), RandomDerivationContext());
        }

        public E Random<E>(IEnumerable<E> coll)
        {
            return coll.ElementAt(Globs.GetRandomInt(coll.Count()));            
        }

        public E Random<E>(IEnumerable<E> coll, E valueIfEmpty)
        {
            return coll == null || coll.Count() == 0 ? valueIfEmpty : Random(coll);
        }

        public EccCurve RandomCurve(TpmAlgId scheme = TpmAlgId.Null, bool swCompat = false)
        {
            if (TpmCfg.EccCurves == null || TpmCfg.EccCurves.Count == 0)
            {
                return EccCurve.None;
            }
            return Random(TpmCfg.CurvesForScheme(scheme, swCompat));
        }

        public ushort RandomRsaKeySize (TpmAlgId nameAlg)
        {
            return TpmHash.DigestSize(nameAlg) < 0x30
                        ? Random(TpmCfg.RsaKeySizes)
                        : Random(TpmCfg.RsaKeySizes.Where(size => size > 1536));
        }

        // Retuns a supported hash algorithm with the digest of the given size
        public TpmAlgId RandomHashAlg(int digestSize)
        {
            if (digestSize == 0)
                return Random(TpmCfg.HashAlgs);

            var candidateAlgs = new List<TpmAlgId>();
            for (int i = 0; i < TpmCfg.HashAlgs.Length; ++i)
            {
                if (TpmHash.DigestSize(TpmCfg.HashAlgs[i]) == digestSize)
                {
                    candidateAlgs.Add(TpmCfg.HashAlgs[i]);
                }
            }
            return Random(candidateAlgs, TpmAlgId.Null);
        }

        // Returns two hash algorithms of different size
        public TpmAlgId[] TwoRandomHashAlgs(int digestSize = 0)
        {
            if (TpmCfg.HashAlgs.Length <= 2)
                return TpmCfg.HashAlgs;

            TpmAlgId hashAlg = RandomHashAlg(digestSize);
            return new TpmAlgId[2] { hashAlg, AltHashAlg(hashAlg) };
        }

        public TpmAlgId[] RandomHashAlgs(int numAlgs)
        {
            if (TpmCfg.HashAlgs.Length <= numAlgs)
                return TpmCfg.HashAlgs;

            var hashAlgs = new TpmAlgId[numAlgs];

            int selected = 0;
            for (int i = 0;
                 selected < numAlgs && selected < TpmCfg.HashAlgs.Length - i;
                 ++i )
            {
                if (Globs.GetRandomInt(TpmCfg.HashAlgs.Length) < numAlgs )
                {
                    hashAlgs[selected++] = TpmCfg.HashAlgs[i];
                }
            }
            while (selected < numAlgs)
            {
                hashAlgs[selected] = hashAlgs[TpmCfg.HashAlgs.Length - (numAlgs - selected)];
                ++selected;
            }

            return hashAlgs;
        }

        // Returns a hash algorithm with the digest size different from that of baseAlg.
        // If all implemented hash algorithms besides baseAlg have the same digest size,
        // returns one of them. If only one hash algorithms is implemented, returns it.
        public TpmAlgId AltHashAlg(TpmAlgId baseAlg, bool onlyDiffSize = false)
        {
            ushort      baseSize = TpmHash.DigestSize(baseAlg);
            int         numDiffs = 0;
            TpmAlgId    altAlg = baseAlg;

            for (int i = 0; i < TpmCfg.HashAlgs.Length; ++i)
            {
                if (TpmCfg.HashAlgs[i] == baseAlg)
                {
                    continue;
                }
                if (TpmHash.DigestSize(TpmCfg.HashAlgs[i]) == baseSize)
                {
                    if (altAlg == baseAlg)
                    {
                        altAlg = TpmCfg.HashAlgs[i];
                    }
                    continue;
                }
                // Ensure equal probability of all of the suitable candidates selection.
                // The first suitable candidate is selected unconditionally, as RandInt(0)
                // always returns 0.
                if (RandomInt(++numDiffs) == 0)
                {
                    altAlg = TpmCfg.HashAlgs[i];
                    onlyDiffSize = false;
                }
            }
            return onlyDiffSize ? TpmAlgId.Null : altAlg;
        }

        public static void
            RandomApply(Action<uint /*index*/> f,
                        int numItemsToPick, int sequenceLength,
                        PcrSelection templateBank)
        {
            uint index = 0;
            while (numItemsToPick > 0)
            {
                if (templateBank.IsPcrSelected(index))
                {
                    if (Globs.GetRandomInt(sequenceLength) < numItemsToPick)
                    {
                        f(index);
                        --numItemsToPick;
                    }
                    --sequenceLength;
                    Debug.Assert(sequenceLength >= 0);
                }
                ++index;
            }
        }

        public void RandomizeSinglePcr(Tpm2 tpm, PcrSelection sel)
        {
            var selected = sel.GetSelectedPcrs();
            Assert(selected.Length > 0);
            tpm.PcrEvent(TpmHandle.Pcr(selected[RandomInt(selected.Length)]),
                         RandBytes(1, TpmCfg.MaxDigestSize));
        }

        public void RandomizePcrs(Tpm2 tpm, PcrSelection sel)
        {
            int maxPcrs = sel.NumPcrsSelected();
            var caller = new TpmCommandCaller(tpm);
            RandomApply(caller.PcrEvent, RandomInt(maxPcrs) + 1, maxPcrs, sel);
        }

        // Returns randomly selected non-empty PCR bank
        public PcrSelection RandomPcrBank()
        {
            PcrSelection bank = TpmCfg.PcrBanks[RandomInt(TpmCfg.PcrBanks.Count)];
            if (!CryptoLib.IsSupported(bank.hash))
            {
                // The TPM implements hash algorithms unsupported by Tpm2Tester
                // Make sure that we find a supported one
                foreach(var b in TpmCfg.PcrBanks)
                {
                    if (CryptoLib.IsSupported(b.hash))
                    {
                        bank = b;
                        break;
                    }
                }
            }
            return bank;
        }

        public int RandomPcr(TpmAlgId hashAlg)
        {
            return (int)Random(TpmCfg.PcrBank(hashAlg).GetSelectedPcrs());
        }

        // Generates a random subset of a non-empty PCR bank for the specified hashAlg
        // or randomly selected one by default. The size of subset is either numPcrs,
        // if specified, or randomly selected by default.
        public PcrSelection RandomPcrSel(TpmAlgId hashAlg = TpmAlgId.None, int numPcrs = 0)
        {
            int maxPcrs = Math.Min((ushort)16, PcrSelection.MaxPcrs);
            if (numPcrs == 0)
            {
                numPcrs = Globs.GetRandomInt(maxPcrs - 2) + 1;
            }
            Assert(numPcrs < maxPcrs - 1);

            PcrSelection tpmBank = hashAlg != TpmAlgId.None ? TpmCfg.PcrBank(hashAlg)
                                                            : RandomPcrBank();
            var sel = new PcrSelection(tpmBank.hash);
            RandomApply(sel.SelectPcr, numPcrs, maxPcrs, tpmBank);
            return sel;
        }

        public PcrSelection[] RandomSinglePcrSelArr()
        {
            return new PcrSelection[] { RandomPcrSel(TpmAlgId.None, 1) };
        }

        public EccPoint RandomEccPoint(Tpm2 tpm, EccCurve curveID)
        {
            int ptSize = tpm.EccParameters(curveID).gX.Length;
            return new EccPoint(RandomBytes(ptSize), RandomBytes(ptSize));
        }

        // Generates a random unique value for a key with the given template
        public IPublicIdUnion RandomUnique(Tpm2 tpm, TpmPublic pub)
        {
            IPublicIdUnion unique = null;
            switch (pub.type)
            {
                case TpmAlgId.Rsa:
                    unique = new Tpm2bPublicKeyRsa(
                                    RandomBytes(((pub.parameters as RsaParms).keyBits + 7) / 8));
                    break;
                case TpmAlgId.Ecc:
                    unique = RandomEccPoint(tpm, (pub.parameters as EccParms).curveID);
                    break;
                case TpmAlgId.Symcipher:
                    unique = new Tpm2bDigestSymcipher(TpmHash.FromRandom(pub.nameAlg));
                    break;
                case TpmAlgId.Keyedhash:
                    unique = new Tpm2bDigestKeyedhash(TpmHash.FromRandom(pub.nameAlg));
                    break;
            }
            return unique;
        }

        public void ForAllInvalidHandles(Tpm2 tpm, Action<TpmHandle, bool /*freshlyFlushed*/> action)
        {
            if (!TestCfg.StressMode && !TestCfg.HasTRM)
            {
                TpmHandle h = CreateDataObject(tpm);
                tpm.FlushContext(h);
                action(h, true);
            }

            var handleTypes = new Ht[] { Ht.Transient, Ht.Persistent, Ht.Permanent,
                                         Ht.NvIndex, Ht.Pcr, (Ht)0x88};
            foreach (var handleType in handleTypes)
            {
                TpmHandle h = RandomInvalidHandle(tpm, handleType);
                action(h, false);
            }
        }

        public void ExpectBadHandleError(Tpm2 tpm, TpmHandle h)
        {
            if (TestCfg.StressMode)
                tpm._ExpectResponses(TpmRc.Handle, TpmRc.Value);
            else if (Globs.IsOneOf(h.GetType(), Ht.Persistent, Ht.NvIndex) ||
            // TBS intercepts out of range transient handles and returns RC_HANDLE,
            // even though the correct reply is RC_VALUE.
                     (TestCfg.HasTRM && h.GetType() == Ht.Transient))
                tpm._ExpectError(TpmRc.Handle);
            else
                tpm._ExpectError(TpmRc.Value);
        }

        public void ExpectBadNvHandleError(Tpm2 tpm, TpmHandle h)
        {
            if (TestCfg.StressMode)
                tpm._ExpectResponses(TpmRc.Handle, TpmRc.Value);
            else if (h.GetType() == Ht.NvIndex ||
            // TBS intercepts transient handles and returns RC_HANDLE,
            // even though the correct reply is RC_VALUE.
                     (TestCfg.HasTRM && h.GetType() == Ht.Transient))
                tpm._ExpectError(TpmRc.Handle);
            else
                tpm._ExpectError(TpmRc.Value);
        }

        public TpmHandle RandomInvalidHandle(Tpm2 tpm, Ht handleType)
        {
            TpmHandle h = null;
            do
            {
                h = new TpmHandle(handleType, RandomInt(0x00100000 - 0x100) + 0x100);
                // Preclude TSS.Net from failing in an attempt to use ReadPublic
                // in order to get the nonexistent handle name
                h.Name = new byte[0];
                if (!Globs.IsOneOf(handleType, Ht.Persistent, Ht.Transient, Ht.Permanent, Ht.NvIndex))
                    return h;
                ExpectBadHandleError(tpm, h);
                if (handleType == Ht.NvIndex)
                    TpmHelper.NvReadPublic(tpm, h);
                else
                    TpmHelper.ReadPublic(tpm, h);
            } while (tpm._LastCommandSucceeded());
            return h;
        } // RandomInvalidHandle()

        // Allocate randomly configured NV index (in a thread-safe manner, if necessary)
        public NvPublic SafeDefineRandomNvIndex (Tpm2 tpm, ushort dataSize = 0, NvAttr attr = TestConfig.DefaultNvAttrs,
                                          TpmAlgId nameAlg = TpmAlgId.Null, byte[] auth = null)
        {
            bool randomSize = dataSize == 0;
            if (nameAlg == TpmAlgId.Null)
                nameAlg = Random(TpmCfg.HashAlgs);
            if (auth == null)
                auth = RandomAuth(nameAlg);

            NvPublic nvPub = new NvPublic(RandomNvHandle(), nameAlg, attr, null, 0);
            nvPub.dataSize = randomSize ? (ushort)RandomInt(TpmCfg.MaxNvOpSize) : dataSize;

            var expectedResp = tpm._GetExpectedResponses() ?? new TpmRc[] { TpmRc.Success };

            // Wait no more than 10 sec for parallel threads to free NV
            int i = 0;
            while (i++ < 20)
            {
                if (TestCfg.StressMode)
                    tpm._ExpectMoreResponses(TpmRc.NvSpace, TpmRc.NvDefined);
                tpm.NvDefineSpace(TpmRh.Owner, auth, nvPub);

                TpmRc res = tpm._GetLastResponseCode();
                if (res == TpmRc.Success || expectedResp.Contains(res))
                    break;

                tpm._ExpectResponses(expectedResp);
                if (res == TpmRc.NvDefined)
                {
                    nvPub.nvIndex = RandomNvHandle();
                }
                else if (randomSize && nvPub.dataSize > 8)
                {
                    nvPub.dataSize = (ushort)RandomInt(nvPub.dataSize);
                }
                else
                {
                    // Wait for other threads to free NV resources
                    Thread.Sleep(500);
                }
            }
            return i < 20 ? nvPub : null;
        }

        // Persist an object in a thread-safe manner.
        // Can return false only in stress mode.
        public bool StressSafeEvictControl(Tpm2 tpm, TpmHandle hObj, TpmHandle hPers,
                                    TpmRh hierarchy = TpmRh.Owner)
        {
            if (!TestCfg.StressMode)
            {
                tpm.EvictControl(hierarchy, hObj, hPers);
                return true;
            }

            // Wait no more than 10 sec for parallel threads to free NV
            for (int i = 0; i < 20; ++i)
            {
                tpm._ExpectResponses(TpmRc.Success, TpmRc.NvSpace);
                // Use lock to avoid interference with the creation of persistent
                // primary objects used by Tpm2Tester infra.
                lock (persKeysLock)
                    tpm.EvictControl(hierarchy, hObj, hPers);
                if (tpm._LastCommandSucceeded())
                    return true;
                // Wait until tests in parallel threads free NV
                Thread.Sleep(500);
            }
            return false;
        }

        // This is a test callback function to help the owner-evict RSA primary
        // semantics.  Note that if you return true then the library will not send
        // the command to the TPM.
        bool AlternateActionCallback(TpmCc ordinal, TpmStructureBase inParms,
                                     Type expectedResponseType,
                                     out TpmStructureBase outParms,
                                     out bool desiredResponse)
        {
            outParms = null;
            desiredResponse = true;
            if (ordinal == TpmCc.Clear)
            {
                // persistent Owner keys will be invalidated by the command
                PersRsaPrimOwner = null;
                RsaPrimOwnerPub = null;
                PersRsaPrimEndors = null;
                return false;
            }
            if (ordinal == TpmCc.ChangeEPS)
            {
                // persistent Endorsement keys will be invalidated by the command
                PersRsaPrimEndors = null;
                return false;
            }
            if (ordinal == TpmCc.ChangePPS)
            {
                // persistent Platform keys will be invalidated by the command
                PersRsaPrimPlatform = null;
                return false;
            }
            if (ordinal != TpmCc.FlushContext)
                return false;

            // TODO: replace the condition with a more general check for persistent handles 
            Tpm2FlushContextRequest req = (Tpm2FlushContextRequest)inParms;
            if (req.flushHandle == PersRsaPrimOwner ||
                req.flushHandle == PersRsaPrimEndors ||
                req.flushHandle == PersRsaPrimPlatform)
            {
                string errMsg = "Use TPM2_EvictControl() to relinquish persistent handles";
                WriteToLog(errMsg);
                throw new Exception(errMsg);
            }
            return false;
        }

        Object persKeysLock = new Object();
 
        uint NextPersHandle = (uint)TpmHc.PersistentFirst;
        uint NextPlatformPersHandle = (uint)TpmHc.PlatformPersistent;

        internal TpmHandle PersRsaPrimOwner = null;
        internal TpmHandle PersRsaPrimPlatform = null;
        internal TpmHandle PersRsaPrimEndors = null;

        TpmPublic RsaPrimOwnerPub = null;

        public TpmPublic GetRsaPrimOwnerPub(Tpm2 tpm)
        {
            if (RsaPrimOwnerPub == null)
                LoadRsaPrimary(tpm);
            return RsaPrimOwnerPub;
        }

        private int OneIfExists(object o)
        {
            return o == null ? 0 : 1;
        }

        // returns the number of persistent objects allocated by the Tpm2Tester infra.
        public int NumPersistentHandles()
        {
            return  OneIfExists(PersRsaPrimOwner) + 
                    OneIfExists(PersRsaPrimPlatform) +
                    OneIfExists(PersRsaPrimEndors);
        }

        private TpmHandle GeneratePersistentHandle(ref uint nextHandle,
                                                   TpmHc first, TpmHc last,
                                                   TpmHandle pers1,
                                                   TpmHandle pers2 = null)
        {
            if (nextHandle == (uint)last)
                nextHandle = (uint)first;

            while (pers1 != null && nextHandle == pers1.handle ||
                   pers2 != null && nextHandle == pers2.handle)
            {
                ++nextHandle;
            }
            return new TpmHandle(nextHandle++);
        }

        public TpmHandle NextPersistentHandle(TpmRh hierarchy = TpmRh.Owner)
        {
            lock (persKeysLock)
            {
                if (hierarchy == TpmRh.Owner || hierarchy == TpmRh.Endorsement)
                {
                    return GeneratePersistentHandle(ref NextPersHandle,
                                        TpmHc.PersistentFirst, TpmHc.PlatformPersistent - 1,
                                        PersRsaPrimOwner, PersRsaPrimEndors);
                }
                else if (hierarchy == TpmRh.Platform)
                {
                    return GeneratePersistentHandle(ref NextPlatformPersHandle,
                                        TpmHc.PlatformPersistent, TpmHc.PersistentLast,
                                        PersRsaPrimPlatform);
                }
            }
            Globs.Throw("Handle " + hierarchy + "is not a hierarchy");
            return null;
        }

        private bool ClearPersistent(Tpm2 tpm, TpmRh hierarchy,
                                     ref TpmHandle hPersistent)
        {
            if (hPersistent != null)
            {
                tpm.EvictControl(hierarchy, hPersistent, hPersistent);
                hPersistent = null;
                return true;
            }
            return false;
        }

        private ushort GetSupportedPrimaryRsaKeySize(Tpm2 tpm, ushort keySize, TpmRh hierarchy)
        {
            if (!TpmCfg.RsaKeySizes.Contains(keySize))
                return keySize;

            bool owner = hierarchy == TpmRh.Owner;
            var supportedSizes = owner ? TpmCfg.PrimaryRsaKeySizes : TpmCfg.PrimaryEndorsRsaKeySizes;
            if (supportedSizes == null)
            {
                var keySizes = new List<ushort>();
                var scheme = owner ? (IAsymSchemeUnion)new SchemeOaep(TpmCfg.HashAlgs[0])
                                   : (IAsymSchemeUnion)new SchemeRsassa(TpmCfg.HashAlgs[0]);
                var rsaParams = new RsaParms(new SymDef(), scheme, 0, 0);
                var inPub = new TpmPublic(AltHashAlg(TpmAlgId.Sha1),
                    (owner ? ObjectAttr.Decrypt : ObjectAttr.Sign)
                        | ObjectAttr.FixedTPM | ObjectAttr.FixedParent
                        | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
                    null,
                    rsaParams,
                    new Tpm2bPublicKeyRsa());
                foreach (var size in TpmCfg.RsaKeySizes)
                {
                    rsaParams.keyBits = size;
                    tpm._ExpectResponses(TpmRc.Success, TpmRc.Asymmetric, TpmRc.Value);

                    var sensCreate = new SensitiveCreate(null, null);
                    TpmPublic pub;
                    CreationData creationData;
                    byte[] creationHash;
                    TkCreation creationTicket;

                    TpmHandle h = tpm.CreatePrimary(hierarchy, sensCreate,
                                                    inPub, null, null,
                                                    out pub, out creationData,
                                                    out creationHash, out creationTicket);
                    if (tpm._LastCommandSucceeded())
                    {
                        keySizes.Add(size);
                        tpm.FlushContext(h);
                    }
                }

                if (owner)
                {
                    supportedSizes = TpmCfg.PrimaryRsaKeySizes = keySizes.ToArray();
                    if (   supportedSizes.Length != TpmCfg.RsaKeySizes.Length
                        && !TpmCfg.FipsMode)
                    {
                        WriteErrorToLog("CreatePrimary supports not all RSA key sizes, " +
                                        "but FIPS compliance is not indicated",
                                        ConsoleColor.Magenta);
                    }
                }
                else
                    supportedSizes = TpmCfg.PrimaryEndorsRsaKeySizes = keySizes.ToArray();
            }
            return supportedSizes.Contains(keySize) ? keySize : supportedSizes[0];
        }

        private EccCurve GetSupportedPrimaryEccCurve(Tpm2 tpm, EccCurve curveId, TpmRh hierarchy)
        {
            if (!TpmCfg.EccCurves.ContainsKey(curveId))
                return curveId;

            bool owner = hierarchy == TpmRh.Owner;
            var supportedCurves = owner ? TpmCfg.PrimaryCurves : TpmCfg.PrimaryEndorsmentCurves;
            if (supportedCurves == null)
            {
                var curves = new List<EccCurve>();
                var scheme = owner ? (IAsymSchemeUnion)new SchemeEcdh(TpmCfg.HashAlgs[0])
                                   : (IAsymSchemeUnion)new SchemeEcdsa(TpmCfg.HashAlgs[0]);
                var eccParams = new EccParms(new SymDef(), scheme, EccCurve.None,
                                             new NullKdfScheme());
                var inPub = new TpmPublic(AltHashAlg(TpmAlgId.Sha1),
                    (owner ? ObjectAttr.Decrypt : ObjectAttr.Sign)
                        | ObjectAttr.FixedTPM | ObjectAttr.FixedParent
                        | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
                    null,
                    eccParams,
                    new EccPoint());

                int numNonEcdhCurves = 0;
                foreach (var curve in TpmCfg.EccCurves)
                {
                    if (!TpmCfg.CurveSupportsScheme(curve.Key, TpmAlgId.Ecdh))
                    {
                        ++numNonEcdhCurves;
                        continue;
                    }

                    eccParams.curveID = curve.Key;
                    tpm._ExpectResponses(TpmRc.Success, TpmRc.Asymmetric, TpmRc.Value);

                    var sensCreate = new SensitiveCreate(null, null);
                    TpmPublic pub;
                    CreationData creationData;
                    byte[] creationHash;
                    TkCreation creationTicket;

                    TpmHandle h = tpm.CreatePrimary(hierarchy, sensCreate,
                                                    inPub, null, null,
                                                    out pub, out creationData,
                                                    out creationHash, out creationTicket);
                    if (tpm._LastCommandSucceeded())
                    {
                        curves.Add(curve.Key);
                        tpm.FlushContext(h);
                    }
                }

                if (owner)
                {
                    supportedCurves = TpmCfg.PrimaryCurves = curves.ToArray();
                    if (   supportedCurves.Length != TpmCfg.EccCurves.Count - numNonEcdhCurves
                        && !TpmCfg.FipsMode)
                    {
                        WriteErrorToLog("CreatePrimary supports not all ECC curves, " +
                                        "but FIPS compliance is not indicated");
                    }
                }
                else
                    supportedCurves = TpmCfg.PrimaryEndorsmentCurves = curves.ToArray();
            }
            return supportedCurves.Contains(curveId) ? curveId : supportedCurves[0];
        }

        public TpmHandle CreatePrimary(Tpm2 tpm, TpmPublic inPub, out TpmPublic pub,
                                       out byte[] creationHash, out TkCreation creationTicket,
                                       SensitiveCreate sensCreate = null,
                                       TpmRh hierarchy = TpmRh.Owner,
                                       PcrSelection[] inPcrSel = null,
                                       byte[] outsideInfo = null)
        {
            inPcrSel = inPcrSel ?? new PcrSelection[] { RandomPcrSel() };
            outsideInfo = outsideInfo ?? RandBytes(0, 20);
            if (sensCreate == null)
                sensCreate = new SensitiveCreate(RandomAuth(inPub.nameAlg), null);
            CreationData creationData;

            //
            // Some TPMs only allow primary keys of no lower than a particular strength.
            // Sometimes the restriction is applied only to the endorsement hierarchy,
            // and sometimes to both the owner and endorsement hierarchies.
            //

            // But a test may supply intentionally invalid parameters and expect a failure
            var expectedResponses = tpm._GetExpectedResponses();
            if (expectedResponses != null)
            {
                tpm._ExpectMoreResponses(TpmRc.Asymmetric, TpmRc.Value);
                TpmHandle h = tpm.CreatePrimary(hierarchy, sensCreate,
                                                inPub, null, null,
                                                out pub, out creationData,
                                                out creationHash, out creationTicket);
                if (expectedResponses.Contains(tpm._GetLastResponseCode()))
                {
                    return h;
                }
                // else vet the key size/curve
            }
            if (inPub.type == TpmAlgId.Rsa)
            {
                var rsaParams = inPub.parameters as RsaParms;
                rsaParams.keyBits = GetSupportedPrimaryRsaKeySize(tpm, rsaParams.keyBits,
                                                                  hierarchy);
            }
            else if (inPub.type == TpmAlgId.Ecc)
            {
                var eccParams = inPub.parameters as EccParms;
                eccParams.curveID = GetSupportedPrimaryEccCurve(tpm, eccParams.curveID,
                                                                hierarchy);
            }
            tpm._ExpectResponses(expectedResponses);

            return tpm.CreatePrimary(hierarchy, sensCreate, inPub,
                                            outsideInfo, inPcrSel,
                                            out pub, out creationData,
                                            out creationHash, out creationTicket);
        }

        public TpmHandle CreatePrimary(Tpm2 tpm, TpmPublic inPub, out TpmPublic pub,
                                       byte[] sensData = null, TpmRh hierarchy = TpmRh.Owner,
                                       PcrSelection[] creationPcrs = null,
                                       byte[] outsideInfo = null)
        {
            byte[]      creationHash;
            TkCreation  creationTicket;
            var sensCreate = new SensitiveCreate(RandomAuth(inPub.nameAlg), sensData);

            return CreatePrimary(tpm, inPub, out pub,
                                 out creationHash, out creationTicket,
                                 sensCreate, hierarchy, creationPcrs, outsideInfo);
        }

        public TpmHandle CreatePrimary(Tpm2 tpm, TpmPublic inPub, TpmRh hierarchy = TpmRh.Owner)
        {
            TpmPublic pub;

            return CreatePrimary(tpm, inPub, out pub, null, hierarchy);
        }

        public TpmHandle CreatePrimary(Tpm2 tpm, out TpmPublic primPub,
                                TpmRh hierarchy = TpmRh.Owner)
        {
            return CreateRsaPrimary(tpm, out primPub, null, hierarchy);
        }

        public TpmHandle CreatePrimary(Tpm2 tpm, TpmRh hierarchy = TpmRh.Owner)
        {
            TpmPublic primPub;
            return CreateRsaPrimary(tpm, out primPub, null, hierarchy);
        }

        public TpmPrivate Create(Tpm2 tpm, TpmHandle hParent, TpmPublic inPub, out TpmPublic pub,
                                 out byte[] creationHash, out TkCreation creationTicket,
                                 byte[] sensData = null, PcrSelection[] creationPcrs = null,
                                 byte[] outsideInfo = null, byte[] authVal = null)
        {
            if (hParent == null)
                hParent = LoadRsaPrimary(tpm);

            var sensCreate = new SensitiveCreate(authVal ?? RandomAuth(inPub.nameAlg),
                                                 sensData ?? null);
            CreationData creationData;
            var priv = tpm.Create(hParent, sensCreate, inPub,
                                  outsideInfo ?? RandBytes(1, TpmHash.DigestSize(
                                                                        inPub.nameAlg)),
                                  creationPcrs ?? new PcrSelection[] { RandomPcrSel() },
                                  out pub,
                                  out creationData, out creationHash, out creationTicket);
            return priv;
        }

        public TpmPrivate Create(Tpm2 tpm, TpmHandle hParent, TpmPublic inPub,
                                 out TpmPublic pub,
                                 byte[] sensData = null, PcrSelection[] creationPcrs = null,
                                 byte[] outsideInfo = null, byte[] authVal = null)
        {
            byte[]      creationHash;
            TkCreation  creationTicket;

            return Create(tpm, hParent, inPub, out pub,
                          out creationHash, out creationTicket,
                          sensData, creationPcrs, outsideInfo, authVal);
        }

        public TpmPrivate Create(Tpm2 tpm, TpmHandle hParent, TpmPublic inPub, byte[] sensData)
        {
            TpmPublic pub;
            return Create(tpm, hParent, inPub, out pub, sensData);
        }

        public TpmPrivate Create(Tpm2 tpm, TpmHandle hParent, TpmPublic parms)
        {
            TpmPublic pub;

            return Create(tpm, hParent, parms, out pub);
        }

        // Creates an RSA primary storage key, makes it persistent, and stores the
        // handle in a class member (one for each hierarchy).
        //
        // NOTE - this function should not use RNG. This ensures reproducibility of
        // test failures using the -seed option.
        private TpmHandle CreateRsaPrimaryAndCacheInternal(Tpm2 tpm, TpmRh hierarchy = TpmRh.Owner)
        {
            Assert(   hierarchy == TpmRh.Owner || hierarchy == TpmRh.Endorsement
                   || hierarchy == TpmRh.Platform);

            var rng = TestCfg.StressMode ? Globs.Rng : Globs.Rng.Clone();

            // Preserve response assertions possibly established by the caller of
            // a Tpm2Tester object creation helper that uses a default parent key
            var expectedResponses = tpm._GetExpectedResponses();

            // This helper should never be expected to fail by the caller
            tpm._ExpectResponses(TpmRc.Success);

            TpmPublic pub;
            var symDef = new SymDefObject(TpmAlgId.Aes, TpmCfg.AesKeySizes[0], TpmAlgId.Cfb);
            // If supported, use RSA-2048 as the default primary key. Otherwise use
            // the largest available RSA key size.
            var keySize = Enumerable.Contains<ushort>(TpmCfg.RsaKeySizes, 2048)
                        ? (ushort)2048 : TpmCfg.RsaKeySizes[TpmCfg.RsaKeySizes.Count() - 1];
            TpmHandle hPrim = null;
            bool cleanupAttempted = TestCfg.StressMode;

            while (true)
            {
                hPrim = CreateRsaPrimary(tpm, hierarchy, TpmCfg.HashAlgs[0], out pub,
                                         keySize, symDef,
                                         new AuthValue(), new byte[0],
                                         new PcrSelection(TpmCfg.HashAlgs[0], new uint[0]));

                if (hPrim.handle != 0)
                    break;
                if (cleanupAttempted)
                {
                    if (!TestCfg.StressMode)
                    {
                        WriteErrorToLog("Cleaning TPM had no effect on CreateRsaPrimary",
                                        ConsoleColor.Cyan);
                    }
                    break;
                }
                Framework.CleanNv(tpm);
                CleanSlots(tpm);
                cleanupAttempted = true;
            }

            // Make the new primary NV-resident so it does not have to be recreated
            // every time.
            TpmHandle hPers = NextPersistentHandle(hierarchy);
            tpm._ExpectResponses(TpmRc.Success, TpmRc.NvSpace, TpmRc.NvDefined)
               .EvictControl(hierarchy == TpmRh.Endorsement ? TpmRh.Owner : hierarchy,
                             hPrim, hPers);

            // If it failed and a primary from the previous session is not still in NV
            if (!tpm._LastCommandSucceeded() &&
                tpm._GetLastResponseCode() != TpmRc.NvDefined)
            {
                // There is no place to persist the key.
                // If there is a persistent primary in other hierarchy, flush it.
                bool nvCleared = false;
                if (hierarchy == TpmRh.Owner)
                {
                    nvCleared = ClearPersistent(tpm, TpmRh.Platform,
                                                ref PersRsaPrimPlatform)
                            ||  ClearPersistent(tpm, TpmRh.Owner,
                                                ref PersRsaPrimEndors);
                }
                else if (hierarchy == TpmRh.Platform)
                {
                    nvCleared = ClearPersistent(tpm, TpmRh.Owner,
                                                ref PersRsaPrimOwner)
                            ||  ClearPersistent(tpm, TpmRh.Owner,
                                                ref PersRsaPrimEndors);
                }
                else if (hierarchy == TpmRh.Endorsement)
                {
                    nvCleared = ClearPersistent(tpm, TpmRh.Owner,
                                                ref PersRsaPrimOwner)
                            ||  ClearPersistent(tpm, TpmRh.Platform,
                                                ref PersRsaPrimPlatform);
                }

                if (!nvCleared)
                    Globs.Throw("Not enough NV to make a primary key persistent");

                // Try to persist the new primary one more time
                tpm.EvictControl(hierarchy, hPrim, hPers);
            }

            if (hPers != null)
                hPers.Auth = hPrim.Auth;

            if (hierarchy == TpmRh.Owner)
            {
                PersRsaPrimOwner = hPers;
                RsaPrimOwnerPub = pub;
            }
            else if (hierarchy == TpmRh.Endorsement)
                PersRsaPrimEndors = hPers;
            else
                PersRsaPrimPlatform = hPers;

            // Delete the original transient key.
            // Prevent the tester framework from complaining that we are trying to 
            // evict something that we should not (behavior in the tester to make
            // it easier to  write compliant tests).
            tpm._SetAlternateActionCallback(null);
            tpm.FlushContext(hPrim);
            tpm._SetAlternateActionCallback(AlternateActionCallback);

            // Restore response assertions
            tpm._ExpectResponses(expectedResponses);

            if (!TestCfg.StressMode)
            {
                // Restore RNG used by Tpm2Tester to the state it was in before this
                // method was invoked.
                Globs.Rng = rng;
            }

            return new TpmHandle(hPers);
        } // CreateRsaPrimaryAndCacheInternal

        // Return a handle of the cached (persistent) RSA primary, creating it if necessary.
        public TpmHandle LoadRsaPrimary(Tpm2 tpm, TpmRh hierarchy = TpmRh.Owner)
        {
            Assert(   hierarchy == TpmRh.Owner || hierarchy == TpmRh.Endorsement
                   || hierarchy == TpmRh.Platform);

            lock (persKeysLock)
            {
                TpmHandle h;
                if (hierarchy == TpmRh.Owner)
                    h = PersRsaPrimOwner;
                else if (hierarchy == TpmRh.Endorsement)
                    h = PersRsaPrimEndors;
                else
                    h = PersRsaPrimPlatform;

                return h != null ? new TpmHandle(h)
                                 : CreateRsaPrimaryAndCacheInternal(tpm, hierarchy);
            }
        }

        // Creates an RSA primary storage key.
        TpmHandle CreatePrimary(Tpm2 tpm, TpmRh hierarchy, TpmHash policyOrNameAlg,
                                IPublicParmsUnion pubParams, IPublicIdUnion unique,
                                out TpmPublic pub,
                                byte[] auth = null, byte[] outsideInfo = null,
                                PcrSelection pcrSel = null)
        {
            if (policyOrNameAlg == null)
                policyOrNameAlg = new TpmHash(Random(TpmCfg.HashAlgs));
            var inPub = new TpmPublic(policyOrNameAlg.HashAlg,
                ObjectAttr.Restricted | ObjectAttr.Decrypt
                    | ObjectAttr.FixedParent | ObjectAttr.FixedTPM
                    | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
                policyOrNameAlg,
                pubParams,
                unique);
            var inPcrSel = new PcrSelection[] { pcrSel ?? RandomPcrSel() };
            outsideInfo = outsideInfo ?? RandBytes(0, 20);

            var sensCreate = new SensitiveCreate(auth ?? RandomAuth(inPub.nameAlg), null);
            byte[] creationHash;
            TkCreation creationTicket;

            return CreatePrimary(tpm, inPub, out pub,
                                out creationHash, out creationTicket,
                                sensCreate, hierarchy,
                                inPcrSel,
                                outsideInfo);
        }

        public TpmHandle CreateRsaPrimary(Tpm2 tpm, TpmRh hierarchy, TpmHash policyOrNameAlg,
                                          out TpmPublic pub,
                                          ushort keyBits = 0, SymDefObject symDef = null,
                                          byte[] auth = null, byte[] outsideInfo = null,
                                          PcrSelection pcrSel = null)
        {
            if (keyBits == 0)
            {
                keyBits = RandomRsaKeySize(policyOrNameAlg.HashAlg);
            }

            return  CreatePrimary(tpm, hierarchy, policyOrNameAlg,
                                  new RsaParms(symDef ?? Random(TpmCfg.SwCfbSymDefs),
                                               null, keyBits, 0),
                                  new Tpm2bPublicKeyRsa(),
                                  out pub, auth, outsideInfo, pcrSel);
        }

        public TpmHandle CreateRsaPrimary(Tpm2 tpm, out TpmPublic primPub,
                                          TpmHash policy = null, TpmRh hierarchy = TpmRh.Owner)
        {
            return CreateRsaPrimary(tpm, hierarchy,
                                    policy ?? new TpmHash(Random(TpmCfg.HashAlgs)), out primPub);
        }

        public TpmHandle CreateRsaPrimary(Tpm2 tpm, TpmHash policy = null,
                                                    TpmRh hierarchy = TpmRh.Owner)
        {
            TpmPublic primPub;
            return CreateRsaPrimary(tpm, out primPub, policy, hierarchy);
        }

        public TpmHandle CreateEccPrimary(Tpm2 tpm, out TpmPublic primPub,
                                          TpmHash policy = null, TpmRh hierarchy = TpmRh.Owner)
        {
            return CreatePrimary(tpm, hierarchy, policy,
                                 new EccParms(Random(TpmCfg.SwCfbSymDefs), null,
                                              Random(TpmCfg.SwEccCurves), new NullKdfScheme()),
                                 new EccPoint(),
                                 out primPub);
        }

        public TpmHandle CreateEccPrimary(Tpm2 tpm, 
                                   TpmHash policy = null, TpmRh hierarchy = TpmRh.Owner)
        {
            TpmPublic primPub;
            return CreateEccPrimary(tpm, out primPub, policy, hierarchy);
        }

        public TpmHandle CreateDataObject(Tpm2 tpm, byte[] data, TpmRh hierarchy,
                                   out TpmPublic pub,
                                   ObjectAttr attrs = TestConfig.DefaultAttrs,
                                   TpmAlgId nameAlg = TpmAlgId.None,
                                   byte[] auth = null,
                                   byte[] policy = null)
        {
            TpmHandle hPrim = LoadRsaPrimary(tpm, hierarchy);

            var inPub = new TpmPublic(
                nameAlg == TpmAlgId.None ? Random(TpmCfg.HashAlgs) : nameAlg,
                attrs,
                policy,
                new KeyedhashParms(),
                new Tpm2bDigestKeyedhash());

            TpmPrivate priv = Create(tpm, hPrim, inPub, out pub,
                                     data ?? RandomBlob(),
                                     null, null, auth);
            return tpm.Load(hPrim, priv, pub);
        }

        public TpmHandle CreateDataObject(Tpm2 tpm, byte[] data = null,
                                          TpmRh hierarchy = TpmRh.Owner,
                                          ObjectAttr attrs = TestConfig.DefaultAttrs)
        {
            TpmPublic pub;
            return CreateDataObject(tpm, data, hierarchy, out pub, attrs);
        }

        public TpmHandle CreateDataObject(Tpm2 tpm, TpmAlgId nameAlg, byte[] auth = null,
                                          byte[] data = null, TpmRh hierarchy = TpmRh.Owner,
                                          ObjectAttr attrs = TestConfig.DefaultAttrs)
        {
            TpmPublic pub;
            return CreateDataObject(tpm, data, hierarchy, out pub, attrs, nameAlg, auth);
        }

        public TpmHandle CreateDataObjectWithPolicy(Tpm2 tpm, TpmHash policy, out TpmPublic pub,
                                                    byte[] data = null)
        {
            return CreateDataObject(tpm, data, TpmRh.Owner, out pub,
                                    TestConfig.DefaultAttrs | ObjectAttr.AdminWithPolicy,
                                    policy.HashAlg, null, policy);
        }

        public TpmHandle CreateDataObjectWithPolicy(Tpm2 tpm, TpmHash policy, byte[] data = null)
        {
            TpmPublic pub;
            return CreateDataObjectWithPolicy(tpm, policy, out pub, data);
        }

        public TpmHandle CreateSignKey(Tpm2 tpm, out TpmPublic pub,
                                       TpmHash policy = null,
                                       TpmAlgId sigHashAlg = TpmAlgId.None,
                                       ObjectAttr extraAttrs = ObjectAttr.None)
        {
            if (sigHashAlg == TpmAlgId.None)
                sigHashAlg = Random(TpmCfg.HashAlgs);

            var inPub = new TpmPublic(
                policy == null ? Random(TpmCfg.HashAlgs) : policy.HashAlg,
                extraAttrs | ObjectAttr.Sign
                    | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
                policy,
                new RsaParms(new SymDefObject(),
                             new SchemeRsassa(sigHashAlg),
                             Random(TpmCfg.RsaKeySizes), 0),
                new Tpm2bPublicKeyRsa());

            return CreateAndLoad(tpm, inPub, out pub);
        }

        public TpmHandle CreateSignKey(Tpm2 tpm, TpmAlgId sigHashAlg = TpmAlgId.None,
                                       ObjectAttr extraAttrs = ObjectAttr.None)
        {
            TpmPublic pub;
            return CreateSignKey(tpm, out pub, null, sigHashAlg, extraAttrs);
        }

        public TpmHandle CreateAndLoad(Tpm2 tpm, TpmPublic inPub, out TpmPublic pub,
                                       TpmHandle hParent = null, byte[] sensData = null,
                                       PcrSelection[] creationPcrs = null)
        {
            if (hParent == null)
                hParent = LoadRsaPrimary(tpm);

            TpmPrivate priv = Create(tpm, hParent, inPub, out pub, sensData, creationPcrs);
            return tpm.Load(hParent, priv, pub);
        }

        public TpmHandle CreateAndLoad(Tpm2 tpm, TpmPublic inPub,
                                       TpmHandle hParent = null, byte[] sensData = null)
        {
            TpmPublic pub;
            return CreateAndLoad(tpm, inPub, out pub, hParent, sensData);
        }

        public AuthSession CreateSaltedAuthSession(Tpm2 tpm, TpmSe sessType, TpmAlgId authHashAlg)
        {
            TpmHandle hPrim = LoadRsaPrimary(tpm);

            TpmPublic primPub = TpmHelper.ReadPublic(tpm, hPrim);
            byte[] seed = RandomNonce(primPub.nameAlg);
            byte[] salt = primPub.EncryptOaep(seed, TssObject.SecretEncodingParms);
            byte[] nonceTpm;
            return tpm.StartAuthSession(hPrim, TpmRh.Null, RandomNonce(authHashAlg),
                                        salt, sessType,
                                        new SymDef(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                                        authHashAlg, out nonceTpm)
                      + seed + SessionAttr.ContinueSession;
        }

        public AuthSession CreateDecryptSession(Tpm2 tpm, out TpmHandle saltKey, SessionAttr decAttr)
        {
            TpmAlgId saltNameAlg = Random(TpmCfg.HashAlgs);
            byte[] seed = RandomNonce(saltNameAlg);
            byte[] salt = null;
            saltKey = EncryptBlob(tpm, seed, out salt, saltNameAlg);

            TpmAlgId authHashAlg = Random(TpmCfg.HashAlgs);
            byte[] nonceTpm;
            return tpm.StartAuthSession(saltKey, TpmRh.Null, RandomNonce(authHashAlg),
                                        salt, TpmSe.Hmac,
                                        new SymDef(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                                        authHashAlg, out nonceTpm)
                      + seed + (SessionAttr.ContinueSession | decAttr);
        }

        public TpmHandle EncryptBlob(Tpm2 tpm, byte[] blob, out byte[] encBlob,
                                     TpmAlgId nameAlg = TpmAlgId.Null,
                                     TpmRh hierarchy = TpmRh.Owner)
        {
            if (nameAlg == TpmAlgId.Null)
                nameAlg = Random(TpmCfg.HashAlgs);

            var inPub = new TpmPublic(nameAlg,
                ObjectAttr.Decrypt | ObjectAttr.UserWithAuth | ObjectAttr.AdminWithPolicy
                     | ObjectAttr.SensitiveDataOrigin,
                null,
                new RsaParms(new SymDefObject(), new SchemeOaep(nameAlg), TpmCfg.RsaKeySizes.Last(), 0),
                new Tpm2bPublicKeyRsa());

            TpmPublic pub;
            TpmHandle sealHandle = CreateAndLoad(tpm, inPub, out pub,
                                                 LoadRsaPrimary(tpm, hierarchy));

            var pubKey = AsymCryptoSystem.CreateFrom(pub);
            encBlob = pubKey.EncryptOaep(blob, TssObject.SecretEncodingParms);
            return sealHandle;
        }

        public TssObject CreateSealWithPolicyAndAuth(Tpm2 tpm, TpmHash policy, out byte[] sealedData)
        {
            TpmHandle hPrim = LoadRsaPrimary(tpm);
            var inPub = new TpmPublic(policy.HashAlg,
                ObjectAttr.FixedParent | ObjectAttr.FixedTPM
                    | ObjectAttr.UserWithAuth | ObjectAttr.UserWithAuth,
                policy,
                new KeyedhashParms(new NullSchemeKeyedhash()),
                new Tpm2bDigestKeyedhash()
            );
            sealedData = RandomNonce();

            TpmPublic pub;
            TpmPrivate priv;
            priv = Create(tpm, hPrim, inPub, out pub, sealedData);

            return new TssObject(pub, priv);
        }

        public bool CleanSlots(Tpm2 tpm, bool cleanSubstrate = false)
        {
            if (cleanSubstrate)
            {
                PersRsaPrimOwner = PersRsaPrimEndors = PersRsaPrimPlatform = null;
                RsaPrimOwnerPub = null;
            }

            TpmHandle[] handles = TpmHelper.GetLoadedEntities(tpm, Ht.Persistent);
            foreach (TpmHandle h in handles)
            {
                // Skip persistent handles allocated by this tester instance
                if (h == PersRsaPrimOwner || h == PersRsaPrimEndors || h == PersRsaPrimPlatform)
                {
                    continue;
                }
                tpm._AllowErrors()
                   .EvictControl(TpmRh.Owner, h, h);
                if (!tpm._LastCommandSucceeded() && !TpmCfg.PlatformDisabled)
                {
                    tpm._AllowErrors().EvictControl(TpmRh.Platform, h, h);
                }
            }

            bool loadedObjects = false;
            TpmHandle[] transient = TpmHelper.GetLoadedEntities(tpm, Ht.Transient);
            loadedObjects = loadedObjects || transient.Length != 0;
            TpmHelper.FlushEntities(tpm, transient);

            TpmHandle[] loadedSessions = TpmHelper.GetLoadedEntities(tpm, Ht.HmacSession);
            loadedObjects = loadedObjects || loadedSessions.Length != 0;
            TpmHelper.FlushEntities(tpm, loadedSessions);

            TpmHandle[] savedSessions = TpmHelper.GetLoadedEntities(tpm, Ht.PolicySession);
            loadedObjects = loadedObjects || savedSessions.Length != 0;
            TpmHelper.FlushEntities(tpm, savedSessions);

            if (loadedObjects)
            {
                // check we really have cleaned up
                int fullSlots = TpmHelper.GetLoadedEntities(tpm, Ht.Transient).Length +
                                TpmHelper.GetLoadedEntities(tpm, Ht.HmacSession).Length +
                                TpmHelper.GetLoadedEntities(tpm, Ht.PolicySession).Length;
                if (fullSlots != 0)
                {
                    WriteToLog("TPM still has loaded entities after flushing");
                }
                loadedObjects = fullSlots != 0;
            }
            return !loadedObjects;
        }

        public byte[] FlipABit(byte[] x, int startPos = 0)
        {
            if (x.Length == 0)
                return x;
            int pos = startPos + RandomInt(x.Length - startPos);
            int bit = RandomInt(8);
            byte theBit = (byte)(1 << bit);
            x[pos] ^= theBit;
            return x;
        }
    } // class TestSubstrate
}

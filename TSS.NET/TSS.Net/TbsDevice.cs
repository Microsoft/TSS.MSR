/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Diagnostics;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Tpm2Lib
{
    public sealed class TbsDevice : Tpm2Device
    {
        private UIntPtr TbsHandle;
        private UIntPtr OriginalHandle;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public TbsDevice(bool hasRM = true)
        {
            NeedsHMAC = false;
            _HasRM = hasRM;
        }

        public override UIntPtr GetHandle(UIntPtr h)
        {
            if (h != UIntPtr.Zero)
            {
                TbsHandle = h;
            }
            return TbsHandle;
        }

        public override void Connect()
        {
            TbsWrapper.TBS_CONTEXT_PARAMS contextParams;

            UIntPtr tbsContext = UIntPtr.Zero;
            contextParams.Version = TbsWrapper.TBS_CONTEXT_VERSION.TWO;
            contextParams.Flags = TbsWrapper.TBS_CONTEXT_CREATE_FLAGS.IncludeTpm20;
            TbsWrapper.TBS_RESULT result = TbsWrapper.NativeMethods
                                    .Tbsi_Context_Create(ref contextParams, ref tbsContext);
            Debug.WriteLine(Globs.GetResourceString("TbsHandle:") + tbsContext.ToUInt32());

            if (result != TbsWrapper.TBS_RESULT.SUCCESS)
            {
                throw new Exception("Failed to create TBS context: Error {" + result + "}");
            }

            TbsHandle = tbsContext;
            OriginalHandle = tbsContext;
        }

        public override void Close()
        {
            if (OriginalHandle != UIntPtr.Zero)
            {
                TbsWrapper.NativeMethods.Tbsip_Context_Close(OriginalHandle);
                OriginalHandle = UIntPtr.Zero;
            }
        }

        public override void PowerCycle()
        {
            throw new Exception("TbsDevice does not implement PowerCycle()");
        }

        public override void AssertPhysicalPresence(bool assertPhysicalPresence)
        {
            throw new NotImplementedException("Device does not support PP");
        }

        public override bool PlatformAvailable()
        {
            return false;
        }

        public override bool PowerCtlAvailable()
        {
            return false;
        }

        public override bool LocalityCtlAvailable()
        {
            return false;
        }

        public override bool NvCtlAvailable()
        {
            return false;
        }

        public override bool UsesTbs()
        {
            return true;
        }

        public override bool HasRM()
        {
            // TODO: detect raw mode during class initialization
            return _HasRM;
        }

        public override void DispatchCommand(CommandModifier active, byte[] inBuf, out byte[] outBuf)
        {
            if (TbsHandle == UIntPtr.Zero)
            {
                throw new Exception("TBS context not created.");
            }

            var resultBuf = new byte[4096];
            uint resultByteCount = (uint)resultBuf.Length;
            TpmRc result = TpmRc.Success;
            TbsWrapper.TBS_RESULT tbsRes = TbsWrapper.NativeMethods.
                Tbsip_Submit_Command(TbsHandle,
                                     (TbsWrapper.TBS_COMMAND_LOCALITY)active.ActiveLocality,
                                     active.ActivePriority,
                                     inBuf,
                                     (uint)inBuf.Length,
                                     resultBuf,
                                     ref resultByteCount);
            if (tbsRes == TbsWrapper.TBS_RESULT.SUCCESS)
            {
                if (resultByteCount != 0)
                {
                    outBuf = new byte[resultByteCount];
                    Array.Copy(resultBuf, outBuf, (int)resultByteCount);
                    return;
                }
                result = TpmRc.TbsUnknownError;
            }
            else
            { 
                result = (TpmRc)tbsRes;
            }

            outBuf = TpmErrorHelpers.BuildErrorResponseBuffer(result);
        } // TbsDevice.DispatchCommand

        protected override void Dispose(bool disposing)
        {
            Close();
        }

        public override bool ImplementsCancel()
        {
            return true;
        }

        public override void SignalCancelOn()
        {
            CancelContext();
        }

        public override void SignalCancelOff()
        {
        }

        public override void CancelContext()
        {
            TbsWrapper.TBS_RESULT result = TbsWrapper.NativeMethods.Tbsip_Cancel_Commands(TbsHandle);
            if (result != TbsWrapper.TBS_RESULT.SUCCESS)
            {
                Debug.WriteLine("TbsStubs.Tbsip_Cancel_Command error 0x{0:x}", result);
                throw new Exception("Tbsip_Cancel_Command() failed. Error {" + result + "}");
            }
        }
        private byte[] GetTpmAuth(TBS_AUTH_TYPE authType)
        {
#if false
            return new byte[0];
#else
            if (TbsHandle == UIntPtr.Zero)
            {
                throw new Exception("TBS context not created.");
            }

            //Console.WriteLine("GetTpmAuth: Retrieving auth value {0}", authType);
            var resultBuf = new byte[256];
            uint resultByteCount = (uint)resultBuf.Length;
            TbsWrapper.TBS_RESULT result = TbsWrapper.NativeMethods.
                Tbsi_Get_OwnerAuth(TbsHandle,
                                   (uint)authType,
                                   resultBuf,
                                   ref resultByteCount);
            if (result != TbsWrapper.TBS_RESULT.SUCCESS)
            {
#if false
                Console.WriteLine($"Trying to read LockoutAuth from the registry...");
                try
                {
                    string lockoutAuthBase64 = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM\WMI\Admin", "LockoutHash", null);
                    if (lockoutAuthBase64 != null)
                    {
                        resultBuf = Convert.FromBase64String(lockoutAuthBase64);
                        Console.WriteLine($"LockoutAuth: {lockoutAuthBase64} | len {resultBuf.Length} bytes | {Globs.HexFromByteArray(resultBuf)}");
                        return resultBuf;
                    }
                }
                catch (Exception e) {
                    Console.WriteLine($"Exception: {e}");
                }
#endif
#if !WINDOWS_UWP
                Console.WriteLine("GetTpmAuth({0}): Windows TBS returned 0x{1:X} {2}", authType, result,
                                    result == TbsWrapper.TBS_RESULT.OWNERAUTH_NOT_FOUND ? " (OWNERAUTH_NOT_FOUND)" :
                                    result == TbsWrapper.TBS_RESULT.BAD_PARAMETER ? " (BAD_PARAMETER)" : "");
#endif
                return new byte[0];
            }

            return Globs.CopyData(resultBuf, 0, (int)resultByteCount);
#endif
            }

        public override byte[] GetLockoutAuth()
        {
            return GetTpmAuth(TBS_AUTH_TYPE.LOCKOUT);
        }

        public override byte[] GetOwnerAuth()
        {
            return GetTpmAuth(TBS_AUTH_TYPE.OWNER);
        }

        public override byte[] GetEndorsementAuth()
        {
            return GetTpmAuth(TBS_AUTH_TYPE.ENDORSEMENT);
        }
    } // class TbsDevice

    [SuppressMessageAttribute("Microsoft.Design", "CA1008:EnumsShouldHaveZeroValue")]
    public enum TBS_COMMAND_PRIORITY : uint
    {
        LOW = 100,
        NORMAL = 200,
        HIGH = 300,
        SYSTEM = 400,
        MAX = 0x80000000
    }

    public enum TBS_AUTH_TYPE : uint
    {
        LOCKOUT = 1,        // TBS_OWNERAUTH_TYPE_FULL
        ENDORSEMENT = 12,   // TBS_OWNERAUTH_TYPE_ENDORSEMENT_20
        OWNER = 13          // TBS_OWNERAUTH_TYPE_STORAGE_20
    }

    internal class TbsWrapper
    {
        public class NativeMethods
        {
            // Note that code gen adds error code than can be returned by TBS API
            // to the TpmRc enum.

            [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
            internal static extern TBS_RESULT
            Tbsi_Context_Create(
                ref TBS_CONTEXT_PARAMS  ContextParams,
                ref UIntPtr             Context
            );

            [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
            internal static extern TBS_RESULT
            Tbsi_Get_OwnerAuth(
                UIntPtr                 hContext,
                uint                    ownerAuthType,
                [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), Out]
                byte[]                  OutBuf,
                ref uint                OutBufLen
                );

            [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
            internal static extern TBS_RESULT
            Tbsip_Context_Close(
                UIntPtr                 Context
            );

            [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
            internal static extern TBS_RESULT
            Tbsip_Submit_Command(
                UIntPtr                 Context,
                TBS_COMMAND_LOCALITY    Locality,
                TBS_COMMAND_PRIORITY Priority,
                [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4), In]
                byte[]                  InBuffer,
                uint                    InBufferSize,
                [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6), Out]
                byte[]                  OutBuf,
                ref uint                OutBufLen
            );

            [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
            internal static extern TBS_RESULT
            Tbsip_Cancel_Commands(
                UIntPtr                 Context
            );

        }

        public enum TBS_RESULT : uint
        {
            SUCCESS = 0,
            OWNERAUTH_NOT_FOUND = 0x80284015,
            BAD_PARAMETER = 0x80284002
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TBS_CONTEXT_PARAMS
        {
            public TBS_CONTEXT_VERSION Version;
            public TBS_CONTEXT_CREATE_FLAGS Flags;
        }

        public enum TBS_COMMAND_LOCALITY : uint
        {
            ZERO = 0,
            ONE = 1,
            TWO = 2,
            THREE = 3,
            FOUR = 4
        }

        public enum TBS_CONTEXT_VERSION : uint
        {
            ONE = 1,
            TWO = 2
        }

        public enum TBS_TPM_VERSION : uint
        {
            Invalid = 0,
            V1_2 = 1,
            V2 = 2
        }

        public enum TBS_CONTEXT_CREATE_FLAGS : uint
        {
            RequestRaw = 0x00000001,
            IncludeTpm12 = 0x00000002,
            IncludeTpm20 = 0x00000004
        }
    } // class TbsWrapper

#if !WINDOWS_UWP
    internal class TpmDllWrapper
    {
        public class NativeMethods
        {
            // helper to find the TPM
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool SetDllDirectory(string lpPathName);

#region TpmExports

            [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void _TPM_Init();

            [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void TPM_Manufacture();

            [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void ExecuteCommand(
                uint requestSize,
                [In] byte[] request,
                ref uint responseSize,
                ref IntPtr response);

            [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void Signal_Hash_Start();

            [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void Signal_Hash_Data(uint size, byte[] buffer);

            [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void Signal_Hash_End();

#endregion

#region PlatformExports
            const string platform = "tpm.dll"; // "platform.dll";

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__Signal_PhysicalPresenceOn();

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__Signal_PhysicalPresenceOff();

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__Signal_PowerOn();

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__Signal_PowerOff();

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__SetCancel();

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__ClearCancel();

            [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__NVEnable(IntPtr platParm);

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__NVDisable();

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__RsaKeyCacheControl(int state);

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__LocalitySet(byte locality);

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__SetNvAvail();

            [DllImport(platform, CallingConvention = CallingConvention.Cdecl)]
            public static extern void _plat__ClearNvAvail();

#endregion
        }
    } // class TpmDllWrapper

    /// <summary>
    /// The InprocTpm loads/runs TPM.dll (and ancillary libraries) in the TPM tester process.
    /// </summary>
    public sealed class InprocTpm : Tpm2Device
    {
        private IntPtr ResponseBuf;
        private uint ResponseBufSize = 4096;

        /// <summary>
        /// Specify the path to TPM.dll.  Note: any TPM in the current directory takes precedence
        /// </summary>
        /// <param name="tpmDllPath"></param>
        public InprocTpm(string tpmDllPath)
        {
            TpmDllWrapper.NativeMethods.SetDllDirectory(tpmDllPath);
            try
            {
                TpmDllWrapper.NativeMethods._plat__NVEnable(IntPtr.Zero);
            }
            catch (Exception)
            {
                //Console.Error.WriteLine("Can't load the TPM dll (or a dependency) at " + tpmDllPath);
                throw;
            }
            NeedsHMAC = false;
            ResponseBuf = Marshal.AllocHGlobal((int)ResponseBufSize);
        }

        public override void Connect()
        {
            TpmDllWrapper.NativeMethods._plat__NVEnable(IntPtr.Zero);
            TpmDllWrapper.NativeMethods.TPM_Manufacture();
            TpmDllWrapper.NativeMethods._plat__NVDisable();
        }

        public override void Close()
        {
        }

        public override void PowerCycle()
        {
            PowerOff();
            PowerOn();
        }

        private bool PowerIsOn;

        public void PowerOff()
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods._plat__Signal_PowerOff();
            PowerIsOn = false;
        }

        public void PowerOn()
        {
            if (PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods._plat__Signal_PowerOn();
            TpmDllWrapper.NativeMethods._TPM_Init();
            TpmDllWrapper.NativeMethods._plat__SetNvAvail();
            PowerIsOn = true;
        }

        public override bool PlatformAvailable()
        {
            return true;
        }

        public override bool PowerCtlAvailable()
        {
            return true;
        }

        public override bool LocalityCtlAvailable()
        {
            return true;
        }

        public override bool NvCtlAvailable()
        {
            return true;
        }

        public override bool HasRM()
        {
            return _HasRM;
        }

        public override bool ImplementsPhysicalPresence()
        {
            return true;
        }

        public override void AssertPhysicalPresence(bool assertPhysicalPresence)
        {
            if (!PowerIsOn)
            {
                return;
            }
            if (assertPhysicalPresence)
            {
                TpmDllWrapper.NativeMethods._plat__Signal_PhysicalPresenceOn();
            }
            else
            {
                TpmDllWrapper.NativeMethods._plat__Signal_PhysicalPresenceOff();

            }
        }

        public override bool ImplementsCancel()
        {
            return true;
        }

        public override void SignalCancelOn()
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods._plat__SetCancel();
        }

        public override void SignalCancelOff()
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods._plat__ClearCancel();
        }

        public override void SignalNvOn()
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods._plat__NVEnable(IntPtr.Zero);
        }

        public override void SignalNvOff()
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods._plat__NVDisable();
        }

        public override void SignalKeyCacheOn()
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods._plat__RsaKeyCacheControl(1);
        }

        public override void SignalKeyCacheOff()
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods._plat__RsaKeyCacheControl(0);
        }

        public override void SignalHashStart()
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods.Signal_Hash_Start();
        }

        public override void SignalHashData(byte[] data)
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods.Signal_Hash_Data((uint)data.Length, data);
        }

        public override void SignalHashEnd()
        {
            if (!PowerIsOn)
            {
                return;
            }
            TpmDllWrapper.NativeMethods.Signal_Hash_End();
        }

        public override void TestFailureMode()
        {
            throw new NotImplementedException("Signal TestFailureMode is supported only by TPM simulator");
        }

        public override void DispatchCommand(CommandModifier active, byte[] inBuf, out byte[] outBuf)
        {
            if (!PowerIsOn)
            {
                outBuf = new byte[0];
                return;
            }
            uint respSize = ResponseBufSize;
            IntPtr respBuf = ResponseBuf;

            TpmDllWrapper.NativeMethods._plat__LocalitySet(active.ActiveLocality);
            TpmDllWrapper.NativeMethods.ExecuteCommand((uint)inBuf.Length,
                                                       inBuf,
                                                       ref respSize,
                                                       ref respBuf);
            outBuf = new byte[respSize];
            Marshal.Copy(respBuf, outBuf, 0, (int)respSize);
        }

        protected override void Dispose(bool disposing)
        {
            Close();
        }
    } // class InprocTpm
#endif //WINDOWS_UWP
}

/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;

using Interop = System.Runtime.InteropServices;

namespace Tpm2Lib
{

    public abstract class BCryptObject
    {
        internal protected UIntPtr Handle = UIntPtr.Zero;

        public int LastError = 0;

        public BCryptObject() { }

        public BCryptObject(UIntPtr keyHandle)
        {
            Handle = keyHandle;
        }

        public static implicit operator UIntPtr (BCryptObject key)
        {
            return key.Handle;
        }

        /// <summary>
        /// Obtain the value of an NCrypt property from the platform provider.
        /// </summary>
        /// <param name="property">The name of the property.</param>
        /// <returns>Byte array containing the property value or null.</returns>
        public byte[] GetPropertyBytes(string propName)
        {
            uint propSize = 0;
            LastError = Native.BCryptGetProperty(Handle, propName, null, 0, out propSize, 0);
            if (LastError == 0)
            {
                var propValue = new byte[propSize];
                LastError = Native.BCryptGetProperty(Handle, propName, propValue, propSize, out propSize, 0);
                if (LastError == 0)
                {
                    return propValue;
                }
            }
            return null;
        }

        public uint GetProperty(string propName)
        {
            byte[] prop = GetPropertyBytes(propName);
            if (prop == null)
                return 0;
            Debug.Assert(prop.Length == 4);
            return (((uint)prop[3] & 0xff) << 24) +
                   (((uint)prop[2] & 0xff) << 16) +
                   (((uint)prop[1] & 0xff) << 8) +
                   ((uint)prop[0] & 0xff);
        }

        public void SetProperty(string propName, byte[] value)
        {
            LastError = Native.BCryptSetProperty(Handle, propName, value, (uint)value.Length, 0);
        }

        public void SetProperty(string propName, string value)
        {
            SetProperty(propName, Globs.BytesFromString(value));
        }

        public void SetProperty(string propName, uint value)
        {
            var buf = new byte[sizeof(uint)];
            buf[3] = (byte)((value >> 24) & 0xff);
            buf[2] = (byte)((value >> 16) & 0xff);
            buf[1] = (byte)((value >> 8) & 0xff);
            buf[0] = (byte)(value & 0xff);
            SetProperty(propName, buf);
        }
    } // class BCryptObject

    public class BCryptKey : BCryptObject, IDisposable
    {
        public BCryptKey(UIntPtr keyHandle)
            : base(keyHandle)
        {
        }

        public static implicit operator BCryptKey(UIntPtr keyHandle)
        {
            return new BCryptKey(keyHandle);
        }

        ~BCryptKey()
        {
            Dispose();
        }

        public void Dispose()
        {
            Destroy();
        }

        /// <summary>
        /// Free all native resources.
        /// </summary>
        public void Destroy()
        {
            if (Handle != UIntPtr.Zero)
            {
                LastError = Native.BCryptDestroyKey(Handle);
                Handle = UIntPtr.Zero;
            }
        }

        public byte[] Export(string blobType)
        {
            var blobSize = UIntPtr.Zero;
            LastError = Native.BCryptExportKey(Handle, UIntPtr.Zero, blobType,
                                               null, 0, out blobSize, 0);
            if (LastError == 0)
            {
                uint blobCapacity = (uint)blobSize;
                var keyBlob = new byte[blobCapacity];
                LastError = Native.BCryptExportKey(Handle, UIntPtr.Zero, blobType,
                                                   keyBlob, (uint)blobSize, out blobSize, 0);
                if (LastError == 0)
                {
                    Debug.Assert(blobCapacity == (uint)blobSize);
                    return keyBlob;
                }
            }
            return null;
        }

        public byte[] ExportSymKey(UIntPtr keyHandle)
        {
            byte[] keyBlob = Export(Native.BCRYPT_KEY_DATA_BLOB);

            // 12 is sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)
            if (keyBlob != null && keyBlob.Length > 12)
            {
                uint keySize = GetProperty(Native.BCRYPT_KEY_LENGTH) / 8;
                uint exportedKeySize = BitConverter.ToUInt32(keyBlob, 8);
                if (keyBlob.Length == 12 + keySize && keySize == exportedKeySize)
                {
                    return Globs.CopyData(keyBlob, 12);
                }
            }
            Globs.Throw("ExportSymKey(): " + (keyBlob != null ? "Invalid" : "No") + " symmetric key blob returned");
            return null;
        }

        public byte[] Encrypt(byte[] input, BCryptOaepPaddingInfo paddingInfo = null,
                              byte[] iv = null, uint flags = 0)
        {
            IntPtr padding = IntPtr.Zero;
            if (paddingInfo != null)
            {
                padding = Marshal.AllocHGlobal(Marshal.SizeOf(paddingInfo));
                Marshal.StructureToPtr(paddingInfo, padding, false);
                flags |= Native.BCRYPT_PAD_OAEP;
            }

            uint ivSize = 0;
            if (iv != null)
            {
                if (iv.Length == 0)
                {
                    iv = null;
                }
                else
                {
                    uint blockLen = GetProperty(Native.BCRYPT_BLOCK_LENGTH);
                    if (blockLen == 0)
                        return null;    // unsupported block cypher mode
                    Debug.Assert(blockLen > 0);
                    if (blockLen != iv.Length)
                    {
                        Globs.Throw<ArgumentException>("Encrypt(): Invalid IV size " + iv.Length);
                        return null;
                    }
                    // BCRYPT_BLOCK_PADDING causes gratuitous padding for block-aligned data buffers
                    //flags |= BCRYPT_BLOCK_PADDING;
                    ivSize = (uint)iv.Length;
                }
            }
            uint bytesReturned;
            LastError = Native.BCryptEncrypt(Handle, input, (uint)input.Length,
                                             padding, iv, ivSize,
                                             null, 0, out bytesReturned, flags);

            byte[] outBuf = null;
            if (LastError == 0)
            {
                outBuf = new byte[bytesReturned];
                LastError = Native.BCryptEncrypt(Handle, input, (uint)input.Length,
                                                 padding, iv, ivSize,
                                                 outBuf, bytesReturned, out bytesReturned, flags);
            }
            Marshal.FreeHGlobal(padding);
            return outBuf;
        }

        public byte[] Decrypt(byte[] input, BCryptOaepPaddingInfo paddingInfo = null,
                              byte[] iv = null, uint flags = 0)
        {
            IntPtr padding = IntPtr.Zero;
            if (paddingInfo != null)
            {
                padding = Marshal.AllocHGlobal(Marshal.SizeOf(paddingInfo));
                Marshal.StructureToPtr(paddingInfo, padding, false);
                flags |= Native.BCRYPT_PAD_OAEP;
            }

            uint ivSize = 0;
            if (iv != null)
            {
                if (iv.Length == 0)
                {
                    iv = null;
                }
                else
                {
                    uint blockLen = GetProperty(Native.BCRYPT_BLOCK_LENGTH);
                    Debug.Assert(blockLen > 0);
                    if (blockLen != iv.Length)
                    {
                        Globs.Throw<ArgumentException>("Encrypt(): Invalid IV size ("
                                        + iv.Length + " instead of " + blockLen + ")");
                        return null;
                    }
                    // BCRYPT_BLOCK_PADDING causes gratuitous padding for block-aligned data buffers
                    //flags |= Native.BCRYPT_BLOCK_PADDING;
                    ivSize = (uint)iv.Length;
                }
            }

            uint bytesReturned;
            LastError = Native.BCryptDecrypt(Handle, input, (uint)input.Length,
                                             padding, iv, ivSize,
                                             null, 0, out bytesReturned, flags);

            byte[] outBuf = null;
            if (LastError == 0)
            {
                outBuf = new byte[bytesReturned];
                LastError = Native.BCryptDecrypt(Handle, input, (uint)input.Length,
                                                 padding, iv, ivSize,
                                                 outBuf, bytesReturned, out bytesReturned, flags);
            }
            Marshal.FreeHGlobal(padding);
            return outBuf;
        }

        public byte[] SignHash(byte[] digest, BcryptScheme scheme, TpmAlgId schemeHash = TpmAlgId.None)
        {
            uint flags = 0;
            IntPtr padding = IntPtr.Zero;
            if (schemeHash != TpmAlgId.None)
            {
                if (scheme == BcryptScheme.Rsassa)
                {
                    var paddingInfo = new BCryptPkcs1PaddingInfo(schemeHash);
                    padding = Marshal.AllocHGlobal(Marshal.SizeOf(paddingInfo));
                    Marshal.StructureToPtr(paddingInfo, padding, false);
                    flags |= Native.BCRYPT_PAD_PKCS1;
                }
                else if (scheme == BcryptScheme.Pss)
                {
                    var paddingInfo = new BCryptPssPaddingInfo(schemeHash, 0);
                    padding = Marshal.AllocHGlobal(Marshal.SizeOf(paddingInfo));
                    Marshal.StructureToPtr(paddingInfo, padding, false);
                    flags |= Native.BCRYPT_PAD_PSS;
                }
                else //if (scheme == BcryptScheme.Ecdsa)
                {
                    padding = IntPtr.Zero;
                }
            }

            uint bytesReturned;
            LastError = Native.BCryptSignHash(Handle, padding, digest, (uint)digest.Length,
                                              null, 0, out bytesReturned, flags);

            byte[] outBuf = null;
            if (LastError == 0)
            {
                outBuf = new byte[bytesReturned];
                LastError = Native.BCryptSignHash(Handle, padding, digest, (uint)digest.Length,
                                                  outBuf, bytesReturned, out bytesReturned, flags);

            }
            Marshal.FreeHGlobal(padding);
            return LastError == 0 ? outBuf : null;
        }

        public bool VerifySignature(byte[] digest, byte[] signature,
                                    TpmAlgId schemeHash = TpmAlgId.None, bool Rsassa = true)
        {
            uint flags = 0;
            IntPtr padding = IntPtr.Zero;
            if (schemeHash != TpmAlgId.None)
            {
                if (Rsassa)
                {
                    var paddingInfo = new BCryptPkcs1PaddingInfo(schemeHash);
                    padding = Marshal.AllocHGlobal(Marshal.SizeOf(paddingInfo));
                    Marshal.StructureToPtr(paddingInfo, padding, false);
                    flags |= Native.BCRYPT_PAD_PKCS1;
                }
                else
                {
                    var paddingInfo = new BCryptPssPaddingInfo(schemeHash, 0);
                    padding = Marshal.AllocHGlobal(Marshal.SizeOf(paddingInfo));
                    Marshal.StructureToPtr(paddingInfo, padding, false);
                    flags |= Native.BCRYPT_PAD_PSS;
                }
            }

            LastError = Native.BCryptVerifySignature(Handle, padding, digest, (uint)digest.Length,
                                                     signature, (uint)signature.Length, flags);
            Marshal.FreeHGlobal(padding);
            return LastError == 0;
        }

        public byte[] DeriveKey(BCryptKey pubKey, TpmAlgId hashAlg, byte[] secretPrepend, byte[] secretAppend)
        {
            UIntPtr secretHandle;
            LastError = Native.BCryptSecretAgreement(Handle, pubKey, out secretHandle, 0);
            if (LastError != 0)
            {
                return null;
            }

            var hashAlgName = Globs.BytesFromString(Native.BCryptHashAlgName(hashAlg));

#if false
            var bufferDesc = new byte[0];   // BCryptBufferDesc
            var buffers = new byte[0];      // BCryptBuffer[]
            int offset = 0;

            WriteToBuffer(ref bufferDesc, ref offset, KDF_HASH_ALGORITHM);
            Marshal.StringToHGlobalUni();

            offset = 0;
            WriteToBuffer(ref bufferDesc, ref offset, BCRYPTBUFFER_VERSION);
            WriteToBuffer(ref bufferDesc, ref offset, 3);    // number of parameter buffers
            WriteToBuffer(ref bufferDesc, ref offset, KDF_HASH_ALGORITHM);

            IntPtr paramListPtr = Marshal.AllocHGlobal(bufferDesc.Length);
            Marshal.Copy(bufferDesc, 0, paramListPtr, bufferDesc.Length);
#endif
            var buffers = new BCryptBuffer[] {
                    new BCryptBuffer(hashAlgName.Length, Native.KDF_HASH_ALGORITHM, hashAlgName),
                    new BCryptBuffer(secretPrepend.Length, Native.KDF_SECRET_PREPEND, secretPrepend),
                    new BCryptBuffer(secretAppend.Length, Native.KDF_SECRET_APPEND, secretAppend)
                };
            var bufDesc = new BCryptBufferDesc(Native.BCRYPTBUFFER_VERSION, 3, buffers);

            IntPtr paramListPtr = Marshal.AllocHGlobal(Marshal.SizeOf(bufDesc));
            Marshal.StructureToPtr(bufDesc, paramListPtr, false);

            byte[] derivedKey = null;
            uint derivedKeySize = 0;
            LastError = Native.BCryptDeriveKey(secretHandle, Native.BCRYPT_KDF_HASH, paramListPtr,
                                               null, 0, out derivedKeySize, 0);
            if (LastError == 0)
            {
                derivedKey = new byte[derivedKeySize];
                LastError = Native.BCryptDeriveKey(secretHandle, Native.BCRYPT_KDF_HASH, paramListPtr,
                                                   derivedKey, derivedKeySize, out derivedKeySize, 0);
                if (LastError != 0)
                {
                    derivedKey = null;
                }
            }

            Native.BCryptDestroySecret(secretHandle);
            Marshal.FreeHGlobal(paramListPtr);
            return derivedKey;
        }
    } // class BCryptKey

    internal class BCryptAlgorithm : BCryptObject, IDisposable
    {
        private UIntPtr HashHandle = UIntPtr.Zero;
        private uint DigestSize = 0;

        public BCryptAlgorithm(string algName, uint flags = 0)
        {
            Open(algName, flags);
        }

        public void Open(string algName, uint flags = 0)
        {
            if (Handle != UIntPtr.Zero)
            {
                Globs.Throw("BCryptInterface.Open(): Already opened.");
                return;
            }
            LastError = Native.BCryptOpenAlgorithmProvider(out Handle, algName,
                                                           Native.MS_PRIMITIVE_PROVIDER, flags);
        }

        public void Close()
        {
            if (Handle != UIntPtr.Zero)
            {
                if (HashHandle != UIntPtr.Zero)
                {
                    Native.BCryptDestroyHash(HashHandle);
                    HashHandle = UIntPtr.Zero;
                }
                LastError = Native.BCryptCloseAlgorithmProvider(Handle, 0);
                Handle = UIntPtr.Zero;
            }
            else
            {
                Debug.Assert(HashHandle == UIntPtr.Zero);
                LastError = 0;
            }
        }

        public void Dispose()
        {
            Close();
        }

        ~BCryptAlgorithm()
        {
            Dispose();
        }

        public BCryptKey ImportKey(String blobType, byte[] keyBlob)
        {
            UIntPtr keyHandle = UIntPtr.Zero;
            LastError = Native.BCryptImportKey(Handle, UIntPtr.Zero, blobType,
                                                      out keyHandle, UIntPtr.Zero, 0,
                                                      keyBlob, (uint)keyBlob.Length, 0);
            return keyHandle;
        }

        public BCryptKey GenerateKeyPair(uint keyLen)
        {
            UIntPtr keyHandle;
            LastError = Native.BCryptGenerateKeyPair(Handle, out keyHandle, keyLen, 0);
            if (LastError == 0)
            {
                LastError = Native.BCryptFinalizeKeyPair(keyHandle, 0);
                if (LastError == 0)
                {
                    return keyHandle;
                }
                Native.BCryptDestroyKey(keyHandle);
            }
            return UIntPtr.Zero;
        }

        /// <summary>
        /// Import a key pair into the BCrypt library.
        /// </summary>
        /// <returns>An object encapsulating a handle to the imported key.</returns>
        public BCryptKey ImportKeyPair(String blobType, byte[] keyBlob)
        {
            UIntPtr keyHandle = UIntPtr.Zero;
            LastError = Native.BCryptImportKeyPair(Handle, UIntPtr.Zero, blobType,
                                                          out keyHandle, keyBlob, (uint)keyBlob.Length, 0);
            return keyHandle;
        }

        private static void WriteToBuffer(ref byte[] buffer, ref int offset, uint value)
        {
            buffer[offset + 3] = (byte)((value >> 24) & 0xff);
            buffer[offset + 2] = (byte)((value >> 16) & 0xff);
            buffer[offset + 1] = (byte)((value >> 8) & 0xff);
            buffer[offset + 0] = (byte)(value & 0xff);
            offset += 4;
        }

        private static void WriteToBuffer(ref byte[] buffer, ref int offset, byte[] value)
        {
            if (value.Length <= buffer.Length - offset)
            {
                Array.Copy(value, 0, buffer, offset, value.Length);
                offset += value.Length;
            }
        }

        /// <summary>
        /// Load an RSA key into the BCrypt provider. This method creates the necessary data structures and
        /// calls the BCrypt APIs required to create a RSA key.
        /// </summary>
        /// <param name="exponent">The key's exponent.</param>
        /// <param name="modulus">The key's modulus.</param>
        /// <param name="prime1">The key's first prime number.</param>
        /// <param name="prime2">The key's second prime number.</param>
        /// <returns>An object encapsulating a handle to the loaded key.</returns>
        public BCryptKey LoadRSAKey(byte[] exponent, byte[] modulus,
                                    byte[] prime1 = null, byte[] prime2 = null)
        {
            uint primeLen1 = 0,
                 primeLen2 = 0;
            // Compute the size of BCRYPT_RSAKEY_BLOB
            int rsaKeySize = exponent.Length + modulus.Length + 24;
            if (prime1 != null && prime1.Length > 0)
            {
                if (prime2 == null || prime2.Length == 0)
                {
                    Globs.Throw<ArgumentException>("LoadRSAKey(): The second prime is missing");
                    return UIntPtr.Zero;
                }
                primeLen1 = (uint)prime1.Length;
                primeLen2 = (uint)prime2.Length;
                rsaKeySize += prime1.Length + prime2.Length;
            }
            else if (prime2 != null && prime2.Length > 0)
            {
                Globs.Throw<ArgumentException>("LoadRSAKey(): The first prime is missing");
                return UIntPtr.Zero;
            }

            var rsaKey = new byte[rsaKeySize];

            // Initialize BCRYPT_RSAKEY_BLOB
            int offset = 0;
            WriteToBuffer(ref rsaKey, ref offset, primeLen1 == 0 ?
                            Native.BCRYPT_RSAPUBLIC_MAGIC : Native.BCRYPT_RSAPRIVATE_MAGIC);
            WriteToBuffer(ref rsaKey, ref offset, (uint)modulus.Length * 8);
            WriteToBuffer(ref rsaKey, ref offset, (uint)exponent.Length);
            WriteToBuffer(ref rsaKey, ref offset, (uint)modulus.Length);
            WriteToBuffer(ref rsaKey, ref offset, primeLen1);
            WriteToBuffer(ref rsaKey, ref offset, primeLen1);
            WriteToBuffer(ref rsaKey, ref offset, exponent);
            WriteToBuffer(ref rsaKey, ref offset, modulus);
            if (primeLen1 != 0)
            {
                WriteToBuffer(ref rsaKey, ref offset, prime1);
                WriteToBuffer(ref rsaKey, ref offset, prime2);
            }

            return ImportKeyPair(primeLen1 == 0 ? Native.BCRYPT_RSAPUBLIC_BLOB
                                                : Native.BCRYPT_RSAPRIVATE_BLOB, rsaKey);
        }

        /// <summary>
        /// Load a symmetric key into the BCrypt provider.
        /// </summary>
        /// <param name="keyData">Key bits.</param>
        /// <param name="symDef">Key params.</param>
        /// <param name="blockSize">Block size for CFB mode.</param>
        /// <returns>An object encapsulating a handle to the loaded key.</returns>
        public BCryptKey LoadSymKey(byte[] keyData, SymDefObject symDef, int blockSize = 0)
        {
            string modeName = Native.BCryptChainingMode(symDef.Mode);
            if (string.IsNullOrEmpty(modeName))
            {
                Globs.Throw<ArgumentException>("LoadSymKey(): Unsupported chaining mode " + symDef.Mode);
                return UIntPtr.Zero;
            }

            // Create key blob for import
            // 12 is sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)
            var keyBlob = new byte[12 + keyData.Length];
            int offset = 0;
            WriteToBuffer(ref keyBlob, ref offset, Native.BCRYPT_KEY_DATA_BLOB_MAGIC);
            WriteToBuffer(ref keyBlob, ref offset, Native.BCRYPT_KEY_DATA_BLOB_VERSION1);
            WriteToBuffer(ref keyBlob, ref offset, (uint)keyData.Length);
            WriteToBuffer(ref keyBlob, ref offset, keyData);

            uint blockSizeAlg = GetProperty(Native.BCRYPT_BLOCK_LENGTH);
            if (blockSize != 0 && blockSize != blockSizeAlg)
            {
                SetProperty(Native.BCRYPT_BLOCK_LENGTH, (uint)blockSize);
                blockSizeAlg = GetProperty(Native.BCRYPT_BLOCK_LENGTH);
            }
            //  Import symmetric key
            var key = ImportKey(Native.BCRYPT_KEY_DATA_BLOB, keyBlob);
            key.SetProperty(Native.BCRYPT_CHAINING_MODE, modeName);
            uint blockSizeKey = key.GetProperty(Native.BCRYPT_BLOCK_LENGTH);
            Debug.Assert(blockSizeAlg == blockSizeKey);
            uint KeyLen = key.GetProperty(Native.BCRYPT_KEY_LENGTH);
            Debug.Assert(KeyLen == symDef.KeyBits);
            if (symDef.Mode == TpmAlgId.Cfb)
            {
                key.SetProperty(Native.BCRYPT_MESSAGE_BLOCK_LENGTH, (uint)blockSize);
            }
            Debug.Assert(key.GetProperty(Native.BCRYPT_MESSAGE_BLOCK_LENGTH) == blockSizeKey);
            return key;
        }

        public BCryptKey GenerateSymKey(SymDefObject symDef, byte[] keyData = null, int blockSize = 0)
        {
            string modeName = Native.BCryptChainingMode(symDef.Mode);
            if (string.IsNullOrEmpty(modeName))
            {
                Globs.Throw<ArgumentException>("GenerateSymKey(): Unsupported chaining mode " + symDef.Mode);
                return null;
            }
            UIntPtr keyHandle = UIntPtr.Zero;
            int keySize = symDef.KeyBits / 8;
            //SetProperty(BCRYPT_KEY_LENGTH, symDef.KeyBits);   // not supported
            SetProperty(Native.BCRYPT_CHAINING_MODE, modeName);
            uint blockSizeAlg = GetProperty(Native.BCRYPT_BLOCK_LENGTH);
            if (blockSize != 0 && blockSize != blockSizeAlg)
            {
                SetProperty(Native.BCRYPT_BLOCK_LENGTH, (uint)blockSize);
                blockSizeAlg = GetProperty(Native.BCRYPT_BLOCK_LENGTH);
            }
            if (keyData != null && keyData.Length != keySize)
            {
                Globs.Throw<ArgumentException>("GenerateSymKey(): Invalid key length");
                return UIntPtr.Zero;
            }
            LastError = Native.BCryptGenerateSymmetricKey(Handle, out keyHandle, UIntPtr.Zero, 0,
                                                          keyData ?? Globs.GetRandomBytes(keySize),
                                                          (uint)keySize, 0);
            if (LastError != 0)
                return null;
            BCryptKey key = keyHandle;
            key.SetProperty(Native.BCRYPT_CHAINING_MODE, modeName);
            uint blockSizeKey = key.GetProperty(Native.BCRYPT_BLOCK_LENGTH);
            Debug.Assert(blockSizeAlg == blockSizeKey);
            uint KeyLen = key.GetProperty(Native.BCRYPT_KEY_LENGTH);
            Debug.Assert(KeyLen == symDef.KeyBits);
            if (symDef.Mode == TpmAlgId.Cfb)
            {
                key.SetProperty(Native.BCRYPT_MESSAGE_BLOCK_LENGTH, (uint)blockSize);
            }
            Debug.Assert(key.GetProperty(Native.BCRYPT_MESSAGE_BLOCK_LENGTH) == blockSizeKey);
            return key;
        }

        public byte[] HashData(byte[] data)
        {
            if (HashHandle == UIntPtr.Zero)
            {
                LastError = Native.BCryptCreateHash(Handle, out HashHandle,
                                                    UIntPtr.Zero, 0, null, 0,
                                                    Native.BCRYPT_HASH_REUSABLE_FLAG);
                if (LastError != 0)
                {
                    Debug.Assert(HashHandle == UIntPtr.Zero);
                    return null;
                }
                DigestSize = GetProperty(Native.BCRYPT_HASH_LENGTH);
            }
            LastError = Native.BCryptHashData(HashHandle, data, (uint)data.Length, 0);
            if (LastError != 0)
            {
                return null;
            }

            var digest = new byte[DigestSize];
            LastError = Native.BCryptFinishHash(HashHandle, digest, DigestSize, 0);
            if (LastError != 0)
            {
                return null;
            }
            return digest;
        }

        public byte[] HmacData(byte[] key, byte[] data)
        {
            if (HashHandle == UIntPtr.Zero)
            {
                LastError = Native.BCryptCreateHash(Handle, out HashHandle,
                                                    UIntPtr.Zero, 0,
                                                    key, (uint)key.Length,
                                                    Native.BCRYPT_HASH_REUSABLE_FLAG);
                if (LastError != 0)
                {
                    Debug.Assert(HashHandle == UIntPtr.Zero);
                    return null;
                }
                DigestSize = GetProperty(Native.BCRYPT_HASH_LENGTH);
            }
            LastError = Native.BCryptHashData(HashHandle, data, (uint)data.Length, 0);
            if (LastError != 0)
            {
                return null;
            }

            var digest = new byte[DigestSize];
            LastError = Native.BCryptFinishHash(HashHandle, digest, DigestSize, 0);
            if (LastError != 0)
            {
                return null;
            }
            return digest;
        }

    } // class BCryptAlgorithm

    public partial class Native
    {
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptOpenAlgorithmProvider(
            out UIntPtr AlgProvider,
            [Interop.MarshalAs(UnmanagedType.LPWStr), In]
                 String AlgId,
            [Interop.MarshalAs(UnmanagedType.LPWStr), In]
                 String Implementation,
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptCloseAlgorithmProvider(
            UIntPtr AlgProvider,
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptGetProperty(
            UIntPtr ObjectHandle,
            [Interop.MarshalAs(UnmanagedType.LPWStr), In]
                 String Property,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), Out]
                 byte[] Buffer,
            uint BufferSize,
            out uint ResultSize,
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptSetProperty(
            UIntPtr ObjectHandle,
            [Interop.MarshalAs(UnmanagedType.LPWStr), In]
                 String Property,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In]
                 byte[] Buffer,
            uint BufferSize,
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptCreateHash(
            // _Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
            UIntPtr AlgProvider,
            // _Out_    BCRYPT_HASH_HANDLE *phHash,
            out UIntPtr HashHandle,
            // _Out_    PUCHAR pbHashObject,
            UIntPtr HashObject,     // Must be UIntPtr.Zero
            // _In_opt_ ULONG cbHashObject,
            uint HashObjectSize,  // Must be 0
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5), In]
                byte[] Secret,
            // _In_     ULONG cbSecret,
            uint SecretSize,      // Must be 0
            // _In_     ULONG dwFlags
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptHashData(
            // _Inout_  BCRYPT_HASH_HANDLE hHash,
            UIntPtr HashHandle,
            // _In_     PUCHAR pbInput,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2), In]
                 byte[] DataBuffer,
            // _In_     ULONG cbInput,
            uint BufferSize,
            // _In_     ULONG dwFlags
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptFinishHash(
            // _Inout_  BCRYPT_HASH_HANDLE hHash,
            UIntPtr HashHandle,
            // _Out_    PUCHAR pbOutput,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2), Out]
                byte[] Digest,
            // _In_     ULONG cbOutput,
            uint DigestSize,
            // _In_     ULONG dwFlags
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptDestroyHash(
            // _Inout_  BCRYPT_HASH_HANDLE hHash,
            UIntPtr HashHandle);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptImportKey(
            UIntPtr AlgProvider,
            UIntPtr ImportKeyHandle,
            [Interop.MarshalAs(UnmanagedType.LPWStr), In]
                 String BlobType,
            out UIntPtr KeyHandle,
            UIntPtr KeyObject,      // must be UIntPtr.Zero
            uint KeyObjectSize,   // must be 0
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7), In]
                 byte[] Input,
            uint InputSize,
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
        BCryptGenerateKeyPair(
            // _Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
            UIntPtr AlgProvider,
            // _Out_    BCRYPT_KEY_HANDLE *phKey,
            out UIntPtr KeyHandle,
            // _In_     ULONG dwLength,
            uint KeyLength,
            // _In_     ULONG dwFlags
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptFinalizeKeyPair(
            // _Inout_  BCRYPT_KEY_HANDLE hKey,
            UIntPtr KeyHandle,
            // _In_     ULONG dwFlags
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptGenerateSymmetricKey(
            // _Inout_    BCRYPT_ALG_HANDLE hAlgorithm,
            UIntPtr AlgProvider,
            // _Out_      BCRYPT_KEY_HANDLE *phKey,
            out UIntPtr KeyHandle,
            // _Out_opt_  PUCHAR pbKeyObject,
            UIntPtr KeyObject,      // must be UIntPtr.Zero
            // _In_       ULONG cbKeyObject,
            uint KeyObjectSize,   // must be 0
            // _In_       PUCHAR pbSecret,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5), In]
                 byte[] Secret,
            // _In_       ULONG cbSecret,
            uint SecretSize,
            // _In_       ULONG dwFlags
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptExportKey(
            UIntPtr Key,
            UIntPtr WrapperKey, // must be NULL on Vista & WinSvr2008
            [Interop.MarshalAs(UnmanagedType.LPWStr), In]
                 String BlobType,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5), Out]
                byte[] Output,
            uint OutputCapacity,
            out UIntPtr OutputSize,
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptImportKeyPair(
            UIntPtr AlgProvider,
            UIntPtr WrapperKey, // must be NULL on Vista & WinSvr2008
            [Interop.MarshalAs(UnmanagedType.LPWStr), In]
                 String BlobType,
            out UIntPtr KeyHandle,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5), In]
                 byte[] Input,
            uint InputSize,
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptDestroyKey(
            UIntPtr Key);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptEncrypt(
            UIntPtr Key,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2), In]
                 byte[] Input,
            uint InputSize,
            IntPtr PaddingInfo,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5), In, Out]
                 byte[] IV,
            uint IVSize,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7), Out]
                 byte[] Output,
            uint OutputSize,
            out uint ResultOuputSize,
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptDecrypt(
            UIntPtr Key,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2), In]
                 byte[] Input,
            uint InputSize,
            IntPtr PaddingInfo,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5), In, Out]
                 byte[] IV,
            uint IVSize,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 7), Out]
                 byte[] Output,
            uint OutputCapacity,
            out uint ResultOuputSize,
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptSignHash(
            // _In_      BCRYPT_KEY_HANDLE hKey,
            UIntPtr KeyHandle,
            // _In_opt_  VOID *pPaddingInfo,
            IntPtr PaddingInfo,
            // _In_      PBYTE pbInput,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In]
                 byte[] Input,
            // _In_      DWORD cbInput,
            uint InputSize,
            // _Out_     PBYTE pbOutput,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5), Out]
                 byte[] Output,
            // _In_      DWORD cbOutput,
            uint OutputCapacity,
            // _Out_     DWORD *pcbResult,
            out uint ResultOuputSize,
            // _In_      ULONG dwFlags
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptVerifySignature(
            // _In_      BCRYPT_KEY_HANDLE hKey,
            UIntPtr KeyHandle,
            // _In_opt_  VOID *pPaddingInfo,
            IntPtr PaddingInfo,
            // _In_      PUCHAR pbHash,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), In]
                 byte[] Digest,
            // _In_      ULONG cbHash,
            uint DigestSize,
            // _In_      PUCHAR pbSignature,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5), In]
                 byte[] Signature,
            // _In_      ULONG cbSignature,
            uint SignatureSize,
            // _In_      ULONG dwFlags
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptSecretAgreement(
            // _In_   BCRYPT_KEY_HANDLE hPrivKey,
            UIntPtr PrivKeyHandle,
            // _In_   BCRYPT_KEY_HANDLE hPubKey,
            UIntPtr PubKeyHandle,
            // _Out_  BCRYPT_SECRET_HANDLE *phSecret,
            out UIntPtr SecretHandle,
            // _In_   ULONG dwFlags
            uint Flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptDestroySecret(
            // _In_  BCRYPT_SECRET_HANDLE hSecret
            UIntPtr SecretHandle
        );

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int
            BCryptDeriveKey(
            // _In_       BCRYPT_SECRET_HANDLE hSharedSecret,
            UIntPtr SecretHandle,
            // _In_       LPCWSTR pwszKDF,
            [Interop.MarshalAs(UnmanagedType.LPWStr), In]
                 String KDF,
            // _In_opt_   BCryptBufferDesc *pParameterList,
            IntPtr ParameterList,
            // _Out_opt_  PUCHAR pbDerivedKey,
            [Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4), Out]
                 byte[] DerivedKey,
            // _In_       ULONG cbDerivedKey,
            uint DerivedKeyCapacity,
            // _Out_      ULONG *pcbResult,
            out uint DerivedKeySize,
            // _In_       ULONG dwFlags
            uint Flags);

#if false
        public static string BCryptAlgName(TpmAlgId algId, EccCurve curveID = EccCurve.None, bool signing = false)
        {
            switch (algId)
            {
                case TpmAlgId.Rsa:
                    return BCRYPT_RSA_ALGORITHM;
                case TpmAlgId.Ecc:
                    switch (curveID)
                    {
                        case EccCurve.NistP256:
                            return signing ? BCRYPT_ECDSA_P256_ALGORITHM : BCRYPT_ECDH_P256_ALGORITHM;
                        case EccCurve.NistP384:
                            return signing ? BCRYPT_ECDSA_P384_ALGORITHM : BCRYPT_ECDH_P384_ALGORITHM;
                        case EccCurve.NistP521:
                            return signing ? BCRYPT_ECDSA_P521_ALGORITHM : BCRYPT_ECDH_P521_ALGORITHM;
                    }
                    Globs.Throw<ArgumentException>("Unsupported ECC curve");
                    return null;
                case TpmAlgId.Aes:
                    return BCRYPT_AES_ALGORITHM;
                case TpmAlgId.Sha512:
                    return BCRYPT_SHA512_ALGORITHM;
            }
            Globs.Throw<ArgumentException>("Unsupported algorithm");
            return null;
        }
#endif

        public static string BCryptHashAlgName(TpmAlgId hashAlgId)
        {
            switch (hashAlgId)
            {
                case TpmAlgId.Sha1:
                    return BCRYPT_SHA1_ALGORITHM;
                case TpmAlgId.Sha256:
                    return BCRYPT_SHA256_ALGORITHM;
                case TpmAlgId.Sha384:
                    return BCRYPT_SHA384_ALGORITHM;
                case TpmAlgId.Sha512:
                    return BCRYPT_SHA512_ALGORITHM;
                default:
                    return null;
            }
        }

        public static string BCryptChainingMode(TpmAlgId modeId)
        {
            switch (modeId)
            {
                case TpmAlgId.Cfb:
                    return BCRYPT_CHAIN_MODE_CFB;
                case TpmAlgId.Cbc:
                    return BCRYPT_CHAIN_MODE_CBC;
                case TpmAlgId.Ecb:
                    return BCRYPT_CHAIN_MODE_ECB;
                default:
                    return null;
            }
            // BCRYPT_CHAIN_MODE_CCM, BCRYPT_CHAIN_MODE_GCM
        }

        public const string BCRYPT_RNG_ALGORITHM = "RNG";
        public const string BCRYPT_RSA_ALGORITHM = "RSA";
        public const string BCRYPT_AES_ALGORITHM = "AES";
        public const string BCRYPT_AES_CMAC_ALGORITHM = "AES-CMAC";
        public const string BCRYPT_3DES_ALGORITHM = "3DES";
        public const string BCRYPT_SHA1_ALGORITHM = "SHA1";
        public const string BCRYPT_SHA256_ALGORITHM = "SHA256";
        public const string BCRYPT_SHA384_ALGORITHM = "SHA384";
        public const string BCRYPT_SHA512_ALGORITHM = "SHA512";
        public const string BCRYPT_ECDSA_P256_ALGORITHM = "ECDSA_P256";
        public const string BCRYPT_ECDSA_P384_ALGORITHM = "ECDSA_P384";
        public const string BCRYPT_ECDSA_P521_ALGORITHM = "ECDSA_P521";
        public const string BCRYPT_ECDH_P256_ALGORITHM = "ECDH_P256";
        public const string BCRYPT_ECDH_P384_ALGORITHM = "ECDH_P384";
        public const string BCRYPT_ECDH_P521_ALGORITHM = "ECDH_P521";

        public const string BCRYPT_KDF_HASH = "HASH";

        public const string BCRYPT_KEY_DATA_BLOB = "KeyDataBlob";
        //public const string BCRYPT_PUBLIC_KEY_BLOB = "PUBLICBLOB";
        public const string BCRYPT_RSAPUBLIC_BLOB = "RSAPUBLICBLOB";
        public const string BCRYPT_RSAPRIVATE_BLOB = "RSAPRIVATEBLOB";
        public const string BCRYPT_RSAFULLPRIVATE_BLOB = "RSAFULLPRIVATEBLOB";
        public const string BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB";
        public const string BCRYPT_ECCPRIVATE_BLOB = "ECCPRIVATEBLOB";
        public const string LEGACY_RSAPRIVATE_BLOB = "CAPIPRIVATEBLOB";

        public const string MS_PRIMITIVE_PROVIDER = "Microsoft Primitive Provider";

        // Generic algorithm properties
        public const string BCRYPT_OBJECT_LENGTH = "ObjectLength";

        // Hash algorithm properties
        public const string BCRYPT_HASH_LENGTH = "HashDigestLength";

        // Symmetric algorithm properties
        public const string BCRYPT_KEY_LENGTH = "KeyLength";            // bits
        public const string BCRYPT_BLOCK_LENGTH = "BlockLength";        // bytes (algs & keys)
        public const string BCRYPT_CHAINING_MODE = "ChainingMode";
        public const string BCRYPT_CHAIN_MODE_CFB = "ChainingModeCFB";
        public const string BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC";
        public const string BCRYPT_CHAIN_MODE_ECB = "ChainingModeECB";
        //public const string BCRYPT_CHAIN_MODE_CCM = "ChainingModeCCM";
        //public const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";

        // Symmetric key properties
        public const string BCRYPT_MESSAGE_BLOCK_LENGTH = "MessageBlockLength"; // CFB only
        public const string BCRYPT_INITIALIZATION_VECTOR = "IV";

        public const uint BCRYPT_RSAPUBLIC_MAGIC = 0x31415352;      // RSA1
        public const uint BCRYPT_RSAPRIVATE_MAGIC = 0x32415352;     // RSA2
        public const uint BCRYPT_KEY_DATA_BLOB_MAGIC = 0x4d42444b;  //Key Data Blob Magic (KDBM)

        public const uint BCRYPT_HASH_REUSABLE_FLAG = 0x00000020;

        public const uint BCRYPT_KEY_DATA_BLOB_VERSION1 = 1;
        public const uint BCRYPT_BLOCK_PADDING = 1;
        public const uint BCRYPT_PAD_PKCS1 = 2;
        public const uint BCRYPT_PAD_OAEP = 4;
        public const uint BCRYPT_PAD_PSS = 8;

        public const uint BCRYPTBUFFER_VERSION = 0;

        public const uint KDF_HASH_ALGORITHM = 0x0;
        public const uint KDF_SECRET_PREPEND = 0x1;
        public const uint KDF_SECRET_APPEND = 0x2;
        public const uint KDF_HMAC_KEY = 0x3;
        public const uint KDF_LABEL = 0xD;
        public const uint KDF_SALT = 0xF;
        public const uint KDF_ITERATION_COUNT = 0x10;

        public const uint BCRYPT_ALG_HANDLE_HMAC = 0x00000008;

    } // partial class NativeMethods

    // BCRYPT_RSAKEY_BLOB
    public class BCryptRsaKeyBlob : TpmStructureBase
    {
        [MarshalAs(0)]
        public uint Magic;
        [MarshalAs(1)]
        public uint BitLength;
        [MarshalAs(2)]
        public uint cbPublicExp;
        [MarshalAs(3)]
        public uint cbModulus;
        [MarshalAs(4)]
        public uint cbPrime1;
        [MarshalAs(5)]
        public uint cbPrime2;
    } // struct RsaPubKey

    // BCRYPT_OAEP_PADDING_INFO
    [StructLayout(LayoutKind.Sequential)]
    public sealed class BCryptOaepPaddingInfo : IDisposable
    {
        [Interop.MarshalAs(UnmanagedType.LPWStr)]
        string algId;    // IntPtr
        IntPtr label;    // byte[]
        uint labelSize;

        public BCryptOaepPaddingInfo(TpmAlgId hashAlg, byte[] _label)
        {
            algId = Native.BCryptHashAlgName(hashAlg);
            var l = RawRsa.GetLabel(_label);
            label = Marshal.AllocHGlobal(l.Length);
            Marshal.Copy(l, 0, label, l.Length);
            labelSize = (uint)l.Length;
        }

        ~BCryptOaepPaddingInfo()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void Dispose(bool disposing)
        {
            Globs.Free(ref label);
        }
    } // class BCryptOaepPaddingInfo

    // BCRYPT_PKCS1_PADDING_INFO
    [StructLayout(LayoutKind.Sequential)]
    public class BCryptPkcs1PaddingInfo
    {
        [Interop.MarshalAs(UnmanagedType.LPWStr)]
        public string HashAlg;    // IntPtr

        public BCryptPkcs1PaddingInfo(TpmAlgId hashAlg)
        {
            HashAlg = Native.BCryptHashAlgName(hashAlg);
        }
    };

    // BCRYPT_PSS_PADDING_INFO
    [StructLayout(LayoutKind.Sequential)]
    public class BCryptPssPaddingInfo
    {
        [Interop.MarshalAs(UnmanagedType.LPWStr)]
        public string HashAlg;    // IntPtr
        [Interop.MarshalAs(UnmanagedType.U4)]
        uint SaltSize;

        public BCryptPssPaddingInfo(TpmAlgId hashAlg, uint saltSize = 0)
        {
            HashAlg = Native.BCryptHashAlgName(hashAlg);
            SaltSize = saltSize;
        }
    };

    public enum BcryptScheme : uint
    {
        Rsassa,
        Pss,
        Ecdsa
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BCryptBuffer : IDisposable
    {
        public uint BufferSize;
        public uint BufferType;
        //[Interop.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)]
        //public byte[] Buffer;
        IntPtr Buffer;

        public BCryptBuffer(int bufferSize, uint bufferType, byte[] buffer)
        {
            BufferSize = (uint)bufferSize;
            BufferType = bufferType;
            //Buffer = buffer;
            Buffer = Marshal.AllocHGlobal(buffer.Length);
            Marshal.Copy(buffer, 0, Buffer, buffer.Length);
        }

        public void Dispose()
        {
            Globs.Free(ref Buffer);
        }
    } // struct BCryptBuffer

    [StructLayout(LayoutKind.Sequential)]
    public struct BCryptBufferDesc : IDisposable
    {
        uint Version;
        uint NumBuffers;
        IntPtr Buffers;

        public BCryptBufferDesc(uint version, uint numBuffers, BCryptBuffer[] buffers = null)
        {
            Version = version;
            NumBuffers = numBuffers;
            if (buffers == null)
            {
                Buffers = IntPtr.Zero;
                return;
            }

            int sizeOfBuffer = Marshal.SizeOf(buffers[0]);
            Buffers = Marshal.AllocHGlobal(sizeOfBuffer * buffers.Length);

            IntPtr ptr = new IntPtr(Buffers.ToInt64());
            foreach (var buf in buffers)
            {
                Debug.Assert(sizeOfBuffer == Marshal.SizeOf(buf));
                Marshal.StructureToPtr(buf, ptr, false);
                ptr = new IntPtr(ptr.ToInt64() + sizeOfBuffer);
            }
        }

        public void Dispose()
        {
            Globs.Free(ref Buffers);
        }
    } // struct BCryptBufferDesc

    public class Csp
    {
        public enum AlgId : uint
        {
            CAlgRsaKeyX = 0x0000a400,   // CALG_RSA_KEYX
            CAlgRsaSign = 0x00002400    // CALG_RSA_SIGN
        }

        // _PUBLICKEYSTRUC
        public class PublicKeyStruc : TpmStructureBase
        {
            [MarshalAs(0)]
            public byte bType;
            [MarshalAs(1)]
            public byte bVersion;
            [MarshalAs(2)]
            public ushort reserved;
            [MarshalAs(3)]
            public AlgId aiKeyAlg;
        } // struct PublicKeyStruc

        // _RSAPUBKEY
        public class RsaPubKey : TpmStructureBase
        {
            [MarshalAs(0)]
            public uint magic;
            [MarshalAs(1)]
            public uint bitlen;
            [MarshalAs(2)]
            public uint pubexp;
        } // struct RsaPubKey


        public class PrivateKeyBlob : TpmStructureBase
        {
            [MarshalAs(0)]
            public PublicKeyStruc publicKeyStruc;

            [MarshalAs(1)]
            public RsaPubKey rsaPubKey
            {
                get { return _rsaPubKey; }

                set
                {
                    _rsaPubKey = value;

                    int keyLen = (int)value.bitlen / 8;
                    modulus = new byte[keyLen];
                    prime1 = new byte[keyLen / 2];
                    prime2 = new byte[keyLen / 2];
                    exponent1 = new byte[keyLen / 2];
                    exponent2 = new byte[keyLen / 2];
                    coefficient = new byte[keyLen / 2];
                    privateExponent = new byte[keyLen / 2];
                }
            }
            RsaPubKey _rsaPubKey;

            [MarshalAs(2, MarshalType.FixedLengthArray)]
            public byte[] modulus;
            [MarshalAs(3, MarshalType.FixedLengthArray)]
            public byte[] prime1;
            [MarshalAs(4, MarshalType.FixedLengthArray)]
            public byte[] prime2;
            [MarshalAs(5, MarshalType.FixedLengthArray)]
            public byte[] exponent1;
            [MarshalAs(6, MarshalType.FixedLengthArray)]
            public byte[] exponent2;
            [MarshalAs(7, MarshalType.FixedLengthArray)]
            public byte[] coefficient;
            [MarshalAs(8, MarshalType.FixedLengthArray)]
            public byte[] privateExponent;
        } // class PrivateKeyBlob


        // Trailing parameters are used to populate TpmPublic generated for the key from the blob.
        public static TpmPrivate CspToTpm(byte[] cspPrivateBlob, out TpmPublic tpmPub,
                                          TpmAlgId nameAlg = TpmAlgId.Sha1,
                                          ObjectAttr keyAttrs = ObjectAttr.Decrypt | ObjectAttr.UserWithAuth,
                                          IAsymSchemeUnion scheme = null,
                                          SymDefObject symDef = null)
        {
            if (scheme == null)
            {
                scheme = new NullAsymScheme();
            }
            if (symDef == null)
            {
                symDef = new SymDefObject();
            }

            var m = new Marshaller(cspPrivateBlob, DataRepresentation.LittleEndian);
            var cspPrivate = m.Get<Csp.PrivateKeyBlob>();
            var keyAlg = cspPrivate.publicKeyStruc.aiKeyAlg;
            if (keyAlg != Csp.AlgId.CAlgRsaKeyX && keyAlg != Csp.AlgId.CAlgRsaSign)
            {
                Globs.Throw<NotSupportedException>("CSP blobs for keys of type " + keyAlg.ToString("X") + " are not supported");
                tpmPub = new TpmPublic();
                return new TpmPrivate();
            }

            var rsaPriv = new Tpm2bPrivateKeyRsa(Globs.ReverseByteOrder(cspPrivate.prime1));
            var sens = new Sensitive(new byte[0], new byte[0], rsaPriv);

            tpmPub = new TpmPublic(nameAlg, keyAttrs, new byte[0],
                                   new RsaParms(symDef,
                                                scheme,
                                                (ushort)cspPrivate.rsaPubKey.bitlen,
                                                cspPrivate.rsaPubKey.pubexp),
                                   new Tpm2bPublicKeyRsa(Globs.ReverseByteOrder(cspPrivate.modulus)));

            return new TpmPrivate(sens.GetTpm2BRepresentation());
        }
    } // class BCryptInterface
}
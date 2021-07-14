/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Diagnostics;
using System.IO;

namespace Tpm2Lib
{
    /// <summary>
    /// A helper class for doing symmetric cryptography based on 
    /// TPM structure definitions.
    /// </summary>
    public sealed class SymCipher : IDisposable
    {
        public bool LimitedSupport = false;

        private BCryptKey Key;
        private byte[] KeyBuffer;
        private byte[] IV;

        private SymCipher(BCryptKey key, byte[] keyData, byte[] iv, int blockSize)
        {
            Key = key;
            KeyBuffer = keyData;
            IV = Globs.CopyData(iv) ?? new byte[BlockSize];
            BlockSize = blockSize;
        }

        public byte[] KeyData { get { return KeyBuffer; } }

        public int BlockSize = 0;

        public int IVSize = 16;

        /// <summary>
        /// Block size in bytes.
        /// </summary>
        public static implicit operator byte[] (SymCipher sym)
        {
            return sym == null ? null : sym.KeyData;
        }

        public static int GetBlockSize(SymDefObject symDef)
        {
            if (symDef.Algorithm == TpmAlgId.Tdes)
            {
                return 8;
            }
            if (symDef.Algorithm != TpmAlgId.Aes)
            {
                Globs.Throw<ArgumentException>("Unsupported algorithm " + symDef.Algorithm);
                return 0;
            }
            return 16;
        }

        /// <summary>
        /// Create a new SymCipher object with a random key based on the alg and mode supplied.
        /// </summary>
        /// <param name="symDef"></param>
        /// <param name="keyData"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static SymCipher Create(SymDefObject symDef = null,
                                       byte[] keyData = null, byte[] iv = null)
        {
            if (symDef == null)
            {
                symDef = new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb);
            }

            BCryptAlgorithm alg = null;

            switch (symDef.Algorithm)
            {
                case TpmAlgId.Aes:
                    alg = new BCryptAlgorithm(Native.BCRYPT_AES_ALGORITHM);
                    break;
                case TpmAlgId.Tdes:
                    alg = new BCryptAlgorithm(Native.BCRYPT_3DES_ALGORITHM);
                    break;
                default:
                    Globs.Throw<ArgumentException>("Unsupported symmetric algorithm "
                                                   + symDef.Algorithm);
                    return null;
            }

            if (keyData == null)
            {
                keyData = Globs.GetRandomBytes(symDef.KeyBits / 8);
            }
            var key = alg.GenerateSymKey(symDef, keyData, GetBlockSize(symDef));
            //key = BCryptInterface.ExportSymKey(keyHandle);
            //keyHandle = alg.LoadSymKey(key, symDef, GetBlockSize(symDef));
            alg.Close();
            return key == null ? null : new SymCipher(key, keyData, iv, GetBlockSize(symDef));
        } // Create()

        public static SymCipher CreateFromPublicParms(IPublicParmsUnion parms)
        {
            switch (parms.GetUnionSelector())
            {
                case TpmAlgId.Rsa:
                    return Create((parms as RsaParms).symmetric);
                case TpmAlgId.Ecc:
                    return Create((parms as EccParms).symmetric);
                default:
                    Globs.Throw<ArgumentException>("CreateFromPublicParms: Unsupported algorithm");
                    return null;
            }
        }

        public static byte[] Encrypt(SymDefObject symDef, byte[] key, byte[] iv,
                                     byte[] dataToEncrypt)
        {
            using (SymCipher cipher = Create(symDef, key, iv))
            {
                return cipher.Encrypt(dataToEncrypt);
            }
        }

        public static byte[] Decrypt(SymDefObject symDef, byte[] key, byte[] iv,
                                     byte[] dataToDecrypt)
        {
            using (SymCipher cipher = Create(symDef, key, iv))
            {
                return cipher.Decrypt(dataToDecrypt);
            }
        }

        /// <summary>
        /// Performs the TPM-defined CFB encrypt using the associated algorithm.
        /// This routine assumes that the integrity value has been prepended.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] data, byte[] iv = null)
        {
            byte[] paddedData;
            int unpadded = data.Length % BlockSize;
            paddedData = unpadded == 0 ? data : Globs.AddZeroToEnd(data, BlockSize - unpadded);
            paddedData = Key.Encrypt(paddedData, null, iv ?? IV);
            return unpadded == 0 ? paddedData : Globs.CopyData(paddedData, 0, data.Length);
        }

        public byte[] Decrypt(byte[] data, byte[] iv = null)
        {
            byte[] paddedData;
            int unpadded = data.Length % BlockSize;
            paddedData = unpadded == 0 ? data : Globs.AddZeroToEnd(data, BlockSize - unpadded);
            paddedData = Key.Decrypt(paddedData, null, iv ?? IV);
            return Globs.CopyData(paddedData, 0, data.Length);
        }

        /// <summary>
        /// De-envelope inner-wrapped duplication blob.
        /// TODO: Move this to TpmPublic and make it fully general
        /// </summary>
        /// <param name="exportedPrivate"></param>
        /// <param name="encAlg"></param>
        /// <param name="encKey"></param>
        /// <param name="nameAlg"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        public static Sensitive SensitiveFromDupBlob(TpmPrivate exportedPrivate,
                                                     SymDefObject encAlg, byte[] encKey,
                                                     TpmAlgId nameAlg, byte[] name)
        {
            byte[] dupBlob = exportedPrivate.buffer;
            byte[] sensNoLen = null;
            using (SymCipher c = Create(encAlg, encKey))
            {
                byte[] innerObject = null;
                if (c == null)
                {
                    if (encAlg.Algorithm != TpmAlgId.Null)
                        return null;
                    else
                        return Marshaller.FromTpmRepresentation<Sensitive>(Marshaller.Tpm2BToBuffer(dupBlob));
                }
                innerObject = c.Decrypt(dupBlob);

                byte[] innerIntegrity, sensitive;
                KDF.Split(innerObject,
                          16 + CryptoLib.DigestSize(nameAlg) * 8,
                          out innerIntegrity,
                          8 * (innerObject.Length - CryptoLib.DigestSize(nameAlg) - 2),
                          out sensitive);

                byte[] expectedInnerIntegrity = Marshaller.ToTpm2B(
                                        CryptoLib.HashData(nameAlg, sensitive, name));

                if (!Globs.ArraysAreEqual(expectedInnerIntegrity, innerIntegrity))
                {
                    Globs.Throw("SensitiveFromDupBlob: Bad inner integrity");
                }

                sensNoLen = Marshaller.Tpm2BToBuffer(sensitive);
            }
            var sens = Marshaller.FromTpmRepresentation<Sensitive>(sensNoLen);
            return sens;
        }

        public void Dispose()
        {
            Key.Dispose();
        }
    }
}

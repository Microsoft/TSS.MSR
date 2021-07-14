/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Tpm2Lib
{
    /// <summary>
    /// A helper class for doing symmetric cryptography based on 
    /// TPM structure definitions.
    /// </summary>
    public sealed class SymCipher : IDisposable
    {
        public bool LimitedSupport = false;

        // .Net crypto object implementing the symmetric algorithm
        private readonly SymmetricAlgorithm Alg;

        // The block cipher mode requested by the user.
        // Since various .Net SDKs do not support some widely used block modes (e.g. CFB),
        // this class emulates them by using Alg in ECB mode. 
        private readonly CipherMode Mode;

        public byte[] KeyData { get { return Alg.Key; } }

        /// <summary>
        /// Block size in bytes.
        /// </summary>
        public int BlockSize { get { return Alg.BlockSize / 8; } }

        /// <summary>
        /// Initialization vector size in bytes.
        /// </summary>
        public int IVSize { get { return Alg.IV.Length; } }

        private SymCipher(SymmetricAlgorithm alg, CipherMode mode)
        {
            Alg = alg;
            Mode = mode;
        }

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

            if (symDef.Mode == TpmAlgId.Ofb)
                return null;

            var mode = GetCipherMode(symDef.Mode);
            if (mode == CipherMode_None)
                return null;

            SymmetricAlgorithm alg = null; // = new RijndaelManaged();
            bool limitedSupport = false;
            int feedbackSize = 0;

            switch (symDef.Algorithm) {
                case TpmAlgId.Aes:
                    alg = new RijndaelManaged();
                    alg.Mode = mode == CipherMode.CFB ? CipherMode.ECB : mode;
                    break;
                case TpmAlgId.Tdes:
                    // DES and __3DES are not supported in TPM 2.0 rev. < 1.32
                    alg = new TripleDESCryptoServiceProvider();
                    alg.Mode = mode;
                    if (mode == CipherMode.CFB)
                        feedbackSize = 8;
                    limitedSupport = true;
                    break;
                default:
                    //Globs.Throw<ArgumentException>("Unsupported symmetric algorithm " + symDef.Algorithm);
                    return null;
            }

            int blockSize = GetBlockSize(symDef);
            alg.KeySize = symDef.KeyBits;
            alg.BlockSize = blockSize * 8;
            alg.Padding = PaddingMode.None;
            alg.FeedbackSize = feedbackSize == 0 ? alg.BlockSize : feedbackSize;

            if (keyData == null)
            {
                // Generate random key
                alg.IV = Globs.GetZeroBytes(blockSize);
                try
                {
                    alg.GenerateKey();
                }
                catch (Exception)
                {
                    alg.Dispose();
                    throw;
                }
            }
            else
            {
                // Use supplied key bits
                alg.Key = keyData;
                if (iv == null)
                {
                    iv = Globs.GetZeroBytes(blockSize);
                }
                else if (iv.Length != blockSize)
                {
                    Array.Resize(ref iv, blockSize);
                }
                alg.IV = iv;
            }

            var symCipher = new SymCipher(alg, mode);
            symCipher.LimitedSupport = limitedSupport;
            return symCipher;
        } // Create()

        const CipherMode CipherMode_None = (CipherMode)0;

        public static CipherMode GetCipherMode(TpmAlgId cipherMode)
        {
            switch (cipherMode)
            {
                case TpmAlgId.Cfb:
                    return CipherMode.CFB;
                case TpmAlgId.Ofb:
                    return CipherMode.OFB;
                case TpmAlgId.Cbc:
                    return CipherMode.CBC;
                case TpmAlgId.Ecb:
                    return CipherMode.ECB;
                case TpmAlgId.Ctr:
                    // CTR in .NET requires you to manage your own counter.
                    return CipherMode_None;
                default:
                    Globs.Throw<ArgumentException>("GetCipherMode: Unsupported cipher mode");
                    return CipherMode_None;
            }
        }

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

        private static void EncryptCFB(byte[] paddedData, byte[] iv, ICryptoTransform enc)
        {
            for (int i = 0; i < paddedData.Length; i += iv.Length)
            {
                using (var outStream = new MemoryStream())
                using (var s = new CryptoStream(outStream, enc, CryptoStreamMode.Write))
                {
                    s.Write(iv, 0, iv.Length);
                    s.FlushFinalBlock();
                    outStream.ToArray().CopyTo(iv, 0);
                    for (int j = 0; j < iv.Length; ++j)
                        paddedData[i + j] = iv[j] ^= paddedData[i + j];
                }
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
            bool externalIV = iv != null && iv.Length > 0;
            if (externalIV)
                Alg.IV = iv;

            ICryptoTransform enc = Alg.CreateEncryptor();
            if (Alg.Mode == CipherMode.ECB && Mode == CipherMode.CFB)
            {
                EncryptCFB(paddedData, Alg.IV, enc);
            }
            else using (var outStream = new MemoryStream())
            {
                var s = new CryptoStream(outStream, enc, CryptoStreamMode.Write);
                s.Write(paddedData, 0, paddedData.Length);
                s.FlushFinalBlock();
                paddedData = outStream.ToArray();
            }

            if (externalIV)
            {
                var src = data;
                var res = paddedData;
                if (res.Length > iv.Length)
                {
                    src = Globs.CopyData(data, src.Length - iv.Length, iv.Length);
                    res = Globs.CopyData(paddedData, res.Length - iv.Length, iv.Length);
                }

                switch(Mode)
                {
                case CipherMode.CBC:
                case CipherMode.CFB:
                    res.CopyTo(iv, 0);
                    break;
                case CipherMode.OFB:
                    XorEngine.Xor(res, src).CopyTo(iv, 0);
                    break;
                case CipherMode.ECB:
                    break;
                case CipherMode.CTS:
                    Globs.Throw<ArgumentException>("Encrypt: Unsupported symmetric mode");
                    break;
                }
            }
            return unpadded == 0 ? paddedData : Globs.CopyData(paddedData, 0, data.Length);
        }

        private static void DecryptCFB(byte[] paddedData, byte[] iv, ICryptoTransform enc)
        {
            var tempOut = new byte[iv.Length];
            for (int i = 0; i < paddedData.Length; i += iv.Length)
            {
                using (var outStream = new MemoryStream())
                using (var s = new CryptoStream(outStream, enc, CryptoStreamMode.Write))
                {
                    s.Write(iv, 0, iv.Length);
                    s.FlushFinalBlock();
                    outStream.ToArray().CopyTo(tempOut, 0);
                    for (int j = 0; j < iv.Length; ++j)
                    {
                        iv[j] = paddedData[i + j];
                        paddedData[i + j] = (byte)((tempOut[j] ^ iv[j]) & 0x000000FF);
                    }
                }
            }
        }

        public byte[] Decrypt(byte[] data, byte[] iv = null)
        {
            byte[] paddedData;
            int unpadded = data.Length % BlockSize;
            paddedData = unpadded == 0 ? data : Globs.AddZeroToEnd(data, BlockSize - unpadded);
            bool externalIV = iv != null && iv.Length > 0;
            if (externalIV)
                Alg.IV = iv;

            byte[] tempOut = null;
            if (Alg.Mode == CipherMode.ECB && Mode == CipherMode.CFB)
            {
                DecryptCFB(paddedData, Alg.IV, Alg.CreateEncryptor());
                tempOut = unpadded == 0 ? paddedData : Globs.CopyData(paddedData, 0, data.Length);
            }
            else
            {
                ICryptoTransform dec = Alg.CreateDecryptor();
                tempOut = new byte[data.Length];
                using (var outStream = new MemoryStream(paddedData))
                {
                    var s = new CryptoStream(outStream, dec, CryptoStreamMode.Read);
                    int numPlaintextBytes = s.Read(tempOut, 0, data.Length);
                    Debug.Assert(numPlaintextBytes == data.Length);
                }
            }

            if (externalIV)
            {
                var src = data;
                var res = tempOut;
                if (res.Length > iv.Length)
                {
                    src = Globs.CopyData(paddedData, src.Length / iv.Length, iv.Length);
                    res = Globs.CopyData(tempOut, res.Length / iv.Length, iv.Length);
                }

                switch(Mode)
                {
                case CipherMode.CBC:
                case CipherMode.CFB:
                    src.CopyTo(iv, 0);
                    break;
                case CipherMode.OFB:
                    XorEngine.Xor(res, src).CopyTo(iv, 0);
                    break;
                case CipherMode.ECB:
                    break;
                case CipherMode.CTS:
                    Globs.Throw<ArgumentException>("Decrypt: Unsupported symmetric mode");
                    break;
                }
            }
            return tempOut;
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
            Alg.Dispose();
        }
    }
}

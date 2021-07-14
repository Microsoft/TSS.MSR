/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Tpm2Lib
{
    public static class CryptoLib
    {
        public static byte[] HashData(TpmAlgId algId, byte[] dataToHash)
        {
            if (dataToHash == null)
                dataToHash = new byte[0];

            string algName = Native.BCryptHashAlgName(algId);
            if (string.IsNullOrEmpty(algName))
            {
                Globs.Throw<ArgumentException>("HashData(): Unsupported hash algorithm " + algId);
                return null;
            }

            var alg = new BCryptAlgorithm(algName);
            var digest = alg.HashData(dataToHash);
            alg.Close();
            return digest;
        }

        static readonly TpmAlgId[] DefinedHashAlgorithms = {
            TpmAlgId.Sha1, TpmAlgId.Sha256, TpmAlgId.Sha384, TpmAlgId.Sha512
        };

        public static byte[] HashData(TpmAlgId alg, byte[][] dataToHash)
        {
            return HashData(alg, Globs.Concatenate(dataToHash));
        }

        public static bool IsHashAlgorithm(TpmAlgId alg)
        {
            return DefinedHashAlgorithms.Any(id => alg == id);
        }

        public static byte[] HashData(TpmAlgId alg, byte[] data1, byte[] data2)
        {
            return HashData(alg, Globs.Concatenate(data1, data2));
        }

        public static byte[] HashData(TpmAlgId alg, byte[] data1, byte[] data2, byte[] data3)
        {
            return HashData(alg, new[] {data1, data2, data3});
        }

        public static bool IsSupported(TpmAlgId algId)
        {
            switch (algId)
            {
                case TpmAlgId.Sha1:
                case TpmAlgId.Sha256:
                case TpmAlgId.Sha384:
                case TpmAlgId.Sha512:
                case TpmAlgId.Cmac:
                    return true;
            }
            return false;
        }

        public static int DigestSize(TpmAlgId hashAlgId)
        {
            switch (hashAlgId)
            {
                case TpmAlgId.Sha1:
                    return 20;
                case TpmAlgId.Sha256:
                    return 32;
                case TpmAlgId.Sha384:
                    return 48;
                case TpmAlgId.Sha512:
                    return 64;
                case TpmAlgId.Sm3256:
                    return 32;
                case TpmAlgId.Null:
                    return 0;
            }
            Globs.Throw<ArgumentException>("DigestSize(): Unsupported hash algorithm");
            return 0;
        }

        public static int BlockSize(TpmAlgId algId)
        {
            switch (algId)
            {
                case TpmAlgId.Sha1:
                    return 64;
                case TpmAlgId.Sha256:
                    return 64;
                case TpmAlgId.Sha384:
                    return 128;
                case TpmAlgId.Sha512:
                    return 128;
                case TpmAlgId.Sm3256:
                    return 64;
                case TpmAlgId.Cmac:
                    return 16;
                case TpmAlgId.Null:
                    return 0;
            }
            Globs.Throw<ArgumentException>("BlockSize{}: Unsupported hash or MAC  algorithm");
            return 0;
        }

        public static TpmAlgId SchemeHash (ISignatureUnion sig)
        {
            if (sig is SignatureRsa)
                return (sig as SignatureRsa).hash;
            if (sig is SignatureEcc)
                return (sig as SignatureEcc).hash;
            if (sig is TpmHash)
                return (sig as TpmHash).HashAlg;
            return TpmAlgId.Null;
        }

        public static byte[] Hmac(TpmAlgId hashAlgId, byte[] key, byte[] data)
        {
            string algName = Native.BCryptHashAlgName(hashAlgId);
            if (string.IsNullOrEmpty(algName))
            {
                Globs.Throw<ArgumentException>("CryptoLib.Hmac(): Unsupported hash algorithm " + hashAlgId);
                return null;
            }

            var alg = new BCryptAlgorithm(algName, Native.BCRYPT_ALG_HANDLE_HMAC);
            var digest = alg.HmacData(key, data);
            alg.Close();
            return digest;
        }

        public static byte[] Mac(TpmAlgId symAlg, TpmAlgId macScheme, byte[] key, byte[] data)
        {
            if (symAlg != TpmAlgId.Aes)
            {
                Globs.Throw<ArgumentException>("CryptoLib.Mac(): Unsupported symmetric algorithm" + symAlg);
                return null;
            }
            if (macScheme != TpmAlgId.Cmac)
            {
                Globs.Throw<ArgumentException>("CryptoLib.Mac(): Unsupported MAC scheme " + macScheme);
                return null;
            }

            var alg = new BCryptAlgorithm(Native.BCRYPT_AES_CMAC_ALGORITHM);
            var digest = alg.HmacData(key, data);
            alg.Close();
            return digest;
        }

        public static bool VerifyHmac(TpmAlgId hashAlg, byte[] key, byte[] data, byte[] sig)
        {
            return Globs.ArraysAreEqual(sig, Hmac(hashAlg, key, data));
        }

        public static byte[] I2Osp4(int x)
        {
            var osp = new byte[4];
            osp[0] = (byte)((x & 0xFF000000) >> 24);
            osp[1] = (byte)((x & 0x00FF0000) >> 16);
            osp[2] = (byte)((x & 0x0000FF00) >> 8);
            osp[3] = (byte)(x & 0x000000FF);
            return osp;
        }

        public static byte[] MGF(byte[] z, int length, TpmAlgId hashAlg)
        {
            var T = new byte[length];
            int pos = 0;
            for (int j = 0; pos < length; j++)
            {
                byte[] c = I2Osp4(j);
                byte[] tmp = HashData(hashAlg, new[]{z, c});

                foreach (byte t in tmp)
                {
                    T[pos++] = t;
                    if (pos >= length)
                    {
                        break;
                    }
                }
            }
            return T;
        }

        public static byte[] KdfThenXor(TpmAlgId hashAlg, byte[] key,
                                        byte[] contextU, byte[] contextV, byte[] data)
        {
            var mask = KDF.KDFa(hashAlg, key, "XOR", contextU, contextV, data.Length * 8);
            return XorEngine.Xor(data, mask);
        }
    }

    public class CryptoEncoders
    {
        /// <summary>
        /// EME-OAEP PKCS1.2, section 9.1.1.1.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="encodingParameters"></param>
        /// <param name="hashAlg"></param>
        /// <param name="modulusNumBytes"></param>
        /// <returns></returns>
        public static byte[] OaepEncode(byte[] message, byte[] encodingParameters,
                                        TpmAlgId hashAlg, int modulusNumBytes) 
        {
            int encodedMessageLength = modulusNumBytes - 1;
            int messageLength = message.Length;
            int hashLength = CryptoLib.DigestSize(hashAlg);

            // 1 (Step numbers from RSA labs spec.)
            // Ignore the ParametersLength limitation

            // 2
            if (messageLength > encodedMessageLength - 2 * hashLength - 1)
            {
                Globs.Throw<ArgumentException>("OaepEncode: Input message too long");
                return new byte[0];
            }
            int psLen = encodedMessageLength - messageLength - 2 * hashLength - 1;
            var ps = new byte[psLen];

            // 3 (Not needed.)
            for (int j = 0; j < psLen; j++)
                ps[j] = 0;

            // 4
            byte[] pHash = CryptoLib.HashData(hashAlg, encodingParameters);

            // 5
            var db = new byte[hashLength + psLen + 1 + messageLength];
            var one = new byte[1];

            one[0] = 1;
            pHash.CopyTo(db, 0);
            ps.CopyTo(db, pHash.Length);
            one.CopyTo(db, pHash.Length + ps.Length);
            message.CopyTo(db, pHash.Length + ps.Length + 1);

            // 6
            byte[] seed = Globs.GetRandomBytes(hashLength);

            // 7
            byte[] dbMask = CryptoLib.MGF(seed, encodedMessageLength - hashLength, hashAlg);

            // 8
            byte[] maskedDb = XorEngine.Xor(db, dbMask);

            // 9
            byte[] seedMask = CryptoLib.MGF(maskedDb, hashLength, hashAlg);

            // 10
            byte[] maskedSeed = XorEngine.Xor(seed, seedMask);

            //11
            var encodedMessage = new byte[maskedSeed.Length + maskedDb.Length];
            maskedSeed.CopyTo(encodedMessage, 0);
            maskedDb.CopyTo(encodedMessage, maskedSeed.Length);

            // 12
            return encodedMessage;
        }

        public static bool OaepDecode(byte[] eMx, byte[] encodingParms,
                                      TpmAlgId hashAlg, out byte[] decoded)
        {
            decoded = new byte[0];

            var em = new byte[eMx.Length + 1];
            Array.Copy(eMx, 0, em, 1, eMx.Length);

            int hLen = CryptoLib.DigestSize(hashAlg);
            int k = em.Length;

            // a.
            byte[] lHash = CryptoLib.HashData(hashAlg, encodingParms);

            // b.
            byte y = em[0];
            byte[] maskedSeed = Globs.CopyData(em, 1, hLen);
            byte[] maskedDB = Globs.CopyData(em, 1 + hLen);

            // c.
            byte[] seedMask = CryptoLib.MGF(maskedDB, hLen, hashAlg);

            // d.
            byte[] seed = XorEngine.Xor(maskedSeed, seedMask);

            // e.
            byte[] dbMask = CryptoLib.MGF(seed, k - hLen - 1, hashAlg);

            // f.
            byte[] db = XorEngine.Xor(maskedDB, dbMask);

            // g.
            byte[] lHashPrime = Globs.CopyData(db, 0, hLen);

            // Look for the zero..
            int j;

            for (j = hLen; j < db.Length; j++)
            {
                if (db[j] == 0)
                {
                    continue;
                }

                if (db[j] == 1)
                {
                    break;
                }

                return false;
            }

            if (j == db.Length - 1)
            {
                return false;
            }

            byte[] m = Globs.CopyData(db, j + 1);

            if (y != 0)
            {
                return false;
            }

            if (!Globs.ArraysAreEqual(lHash, lHashPrime))
            {
                return false;
            }

            decoded = m;
            return true;
        }

        public static byte[] PssEncode(byte[] m, TpmAlgId hashAlg, int sLen, int emBits)
        {
            var emLen = (int)Math.Ceiling(1.0 * emBits / 8);
            int hLen = CryptoLib.DigestSize(hashAlg);

            // 1 - Ignore
            // 2
            byte[] mHash = TpmHash.FromData(hashAlg, m);

            // 3
            if (emLen < hLen + sLen + 2)
            {
                Globs.Throw("PssEncode: Encoding error");
                return new byte[0];
            }

            // 4
            byte[] salt = Globs.GetRandomBytes(sLen);

            // 5
            byte[] mPrime = Globs.Concatenate(new[] { Globs.ByteArray(8, 0),
                                                      mHash,
                                                      salt});

            // 6
            byte[] h = CryptoLib.HashData(hashAlg, mPrime);

            // 7
            byte[] ps = Globs.GetZeroBytes(emLen - sLen - hLen - 2);

            // 8 
            byte[] db = Globs.Concatenate(new[] { ps,
                                                  new byte[] {0x01},
                                                  salt});

            // 9 
            byte[] dbMask = CryptoLib.MGF(h, emLen - hLen - 1, hashAlg);

            // 10
            byte[] maskedDb = XorEngine.Xor(db, dbMask);

            // 11
            int numZeroBits = 8 * emLen - emBits;
            byte mask = GetByteMask(numZeroBits);
            maskedDb[0] &= mask;

            // 12
            byte[] em = Globs.Concatenate(new[] { maskedDb,
                                                  h,
                                                  new byte[] {0xbc}});
            // 13 
            return em;
        }

        /// <summary>
        /// PSS verify.  Note: we expect the caller to do the hash.
        /// </summary>
        /// <param name="m"></param>
        /// <param name="em"></param>
        /// <param name="sLen"></param>
        /// <param name="emBits"></param>
        /// <param name="hashAlg"></param>
        /// <returns></returns>
        public static bool PssVerify(byte[] m, byte[] em, int sLen, int emBits, TpmAlgId hashAlg)
        {
            var emLen = (int)Math.Ceiling(1.0 * emBits / 8);
            int hLen = CryptoLib.DigestSize(hashAlg);
            // 1 - Skip
            // 2
            byte[] mHash = TpmHash.FromData(hashAlg, m);

            // 3
            if (emLen < hLen + sLen + 2)
            {
                return false;
            }

            // 4
            if (em[em.Length - 1] != 0xbc)
            {
                return false;
            }

            // 5
            byte[] maskedDB = Globs.CopyData(em, 0, emLen - hLen - 1);
            byte[] h = Globs.CopyData(em, emLen - hLen - 1, hLen);

            // 6
            int numZeroBits = 8 * emLen - emBits;
            // First numZero bits is zero in mask
            byte mask = GetByteMask(numZeroBits);
            if ((maskedDB[0] & mask) != maskedDB[0])
            {
                return false;
            }

            // 7
            byte[] dbMask = CryptoLib.MGF(h, emLen - hLen - 1, hashAlg);

            // 8
            byte[] db = XorEngine.Xor(maskedDB, dbMask);

            // 9
            int numZeroBits2 = 8 * emLen - emBits;
            byte mask2 = GetByteMask(numZeroBits2);
            db[0] &= mask2;

            // 10
            for (int j = 0; j < emLen - hLen - sLen - 2; j++)
            {
                if (db[j] != 0)
                {
                    return false;
                }

            }
            if (db[emLen - hLen - sLen - 1 - 1] != 1)
            {
                return false;
            }

            // 11
            byte[] salt = Globs.CopyData(db, db.Length - sLen);

            // 12
            byte[] mPrime = Globs.Concatenate(new[] { Globs.ByteArray(8, 0), mHash, salt});

            // 13
            byte[] hPrime = TpmHash.FromData(hashAlg, mPrime);

            // 14
            bool match = Globs.ArraysAreEqual(h, hPrime);
            if (match == false)
            {
                return false;
            }
            return true;
        }

        /// <summary>
        /// Gets a byte with the first (MSB) numBits =0;
        /// </summary>
        /// <param name="numBits"></param>
        /// <returns></returns>
        private static byte GetByteMask(int numBits)
        {
            Debug.Assert(numBits >= 0 && numBits <= 8);
            byte mask = 0xFF;
            for (int j = 1; j <= numBits; j++)
            {
                mask &= (byte)(0xff >> j);
            }
            return mask;
        }

        public static byte[] Pkcs15Encode(byte[] m, int emLen, TpmAlgId hashAlg)
        {
            byte[] prefix;
            switch (hashAlg)
            {
                case TpmAlgId.Sha1:
                    prefix = new byte[]
                    {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b,
                     0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
                    break;
                case TpmAlgId.Sha256:
                    prefix = new byte[] {
                        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
                    };
                    break;
                case TpmAlgId.Sha384:
                    prefix = new byte[] {
                        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                        0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
                    };
                    break;
                case TpmAlgId.Sha512:
                    prefix = new byte[] {
                        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                        0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
                    };
                    break;
                default:
                    Globs.Throw<ArgumentException>("Pkcs15Encode: Unsupported hashAlg");
                    return new byte[0];
            }
            byte[] messageHash = TpmHash.FromData(hashAlg, m);
            byte[] T = Globs.Concatenate(prefix, messageHash);
            int tLen = T.Length;

            if (emLen < tLen + 11)
            {
                Globs.Throw<ArgumentException>("Pkcs15Encode: Encoded message is too short");
                return new byte[0];
            }

            byte[] ps = Globs.ByteArray(emLen - tLen - 3, 0xff);
            byte[] em = Globs.Concatenate(new[] { new byte[] {0x00, 0x01}, ps,
                                                  new byte[] {0x00}, T});
            return em;
        }
    }

    public class XorEngine
    {
        public static byte[] Xor(byte[] p1, byte[] p2)
        {
            if (p1.Length != p2.Length)
            {
                Globs.Throw<ArgumentException>("XorEngine: Mismatched arguments length");
                return new byte[0];
            }
            var res = new byte[p1.Length];
            for (int j = 0; j < p1.Length; j++)
            {
                res[j] = (byte)(p1[j] ^ p2[j]);
            }
            return res;
        }

        /// <summary>
        /// XOR but arrays can be different length (output is lenghth of the shortest input)
        /// </summary>
        /// <param name="p1"></param>
        /// <param name="p2"></param>
        /// <returns></returns>
        public static byte[] XorPartial(byte[] p1, byte[] p2)
        {
            int len = Math.Min(p1.Length, p2.Length);
            var res = new byte[len];
            for (int j = 0; j < len; j++)
            {
                res[j] = (byte)(p1[j] ^ p2[j]);
            }
            return res;
        }

        public static byte[] Xor(byte[] data, TpmAlgId hashAlg, byte[] key,
                                 byte[] contextU, byte[] contextV)
        {
            byte[] mask = KDF.KDFa(hashAlg, key, "XOR", contextU, contextV, data.Length * 8);
            byte[] encData = Xor(mask, data);
            return encData;
        }
    }

    public class KDF
    {
        // ReSharper disable once InconsistentNaming
        public static byte[] KDFa(TpmAlgId hmacHash, byte[] hmacKey, string label,
                                  byte[] contextU, byte[] contextV, int numBitsRequired) 
        {
            int bitsPerLoop = CryptoLib.DigestSize(hmacHash) * 8;
            long numLoops = (numBitsRequired + bitsPerLoop - 1) / bitsPerLoop;
            var kdfStream = new byte[numLoops * bitsPerLoop / 8];
            for (int j = 0; j < numLoops; j++)
            {
                byte[] toHmac = Globs.Concatenate(new[] {
                    Globs.HostToNet(j + 1),
                    Encoding.UTF8.GetBytes(label), Globs.HostToNet((byte)0),
                    contextU,
                    contextV,
                    Globs.HostToNet(numBitsRequired)
                });
                byte[] fragment = CryptoLib.Hmac(hmacHash, hmacKey, toHmac);
                Array.Copy(fragment, 0, kdfStream, j * bitsPerLoop / 8, fragment.Length);
            }
            return Globs.ShiftRight(kdfStream, (int)(bitsPerLoop * numLoops - numBitsRequired));
        }

        /// <summary>
        /// split inData into two byte arrays.  The length of the arrays needed is given in bits
        /// </summary>
        /// <param name="inData"></param>
        /// <param name="numBits1"></param>
        /// <param name="a1"></param>
        /// <param name="numBits2"></param>
        /// <param name="a2"></param>
        public static void Split(byte[] inData, int numBits1, out byte[] a1, int numBits2, out byte[] a2)
        {
            if (numBits1 % 8 != 0 || numBits2 % 8 != 0)
            {
                Globs.Throw<NotImplementedException>("Split: Only byte-sized chunks are supported");
                a1 = a2 = new byte[0];
                return;
            }
            a1 = new byte[(numBits1 + 7) / 8];
            Array.Copy(inData, 0, a1, 0, (numBits1 + 7) / 8);
            a2 = new byte[(numBits2 + 7) / 8];
            Array.Copy(inData, (numBits1 + 7) / 8, a2, 0, (numBits2 + 7) / 8);
        }
    }
}

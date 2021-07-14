/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Linq;
using System.Numerics;
using System.Diagnostics;
using System.Text;

namespace Tpm2Lib
{
    /// <summary>
    /// AsymCryptoSystem is a helper class for doing asymmetric cryptography using TPM data
    /// structures. It currently does ECC and RSA signing, decryption and ECDH key exchange.
    /// 
    /// NOTE: The methods of this class do not attempt to replicate parameters validation
    ///       performed by the TPM.
    /// </summary>
    public sealed class AsymCryptoSystem : IDisposable
    {
        private TpmPublic PublicParms;
        private BCryptKey Key;

        internal static BCryptKey Generate(string algName, uint numBits)
        {
            var alg = new BCryptAlgorithm(algName);
            var key = alg.GenerateKeyPair(numBits);
            alg.Close();
            return key;
        }

        public AsymCryptoSystem()
        {
        }

        /// <summary>
        /// Create a new random software key (public and private) matching the parameters in keyParams.
        /// </summary>
        /// <param name="keyParams"></param>
        /// <returns></returns>
        public AsymCryptoSystem (TpmPublic keyParams)
        {
            TpmAlgId keyAlgId = keyParams.type;
            PublicParms = keyParams.Copy();

            switch (keyAlgId)
            {
                case TpmAlgId.Rsa:
                {
                    var rsaParams = keyParams.parameters as RsaParms;
                    Key = Generate(Native.BCRYPT_RSA_ALGORITHM, rsaParams.keyBits);
                    if (Key == UIntPtr.Zero)
                    {
                        Globs.Throw("Failed to generate RSA key");
                        return;
                    }
                    byte[] blob = Export(Native.BCRYPT_RSAPUBLIC_BLOB);
                    var m = new Marshaller(blob, DataRepresentation.LittleEndian);
                    var header = m.Get<BCryptRsaKeyBlob>();
                    /*var exponent = */m.GetArray<byte>((int)header.cbPublicExp);
                    var modulus = m.GetArray<byte>((int)header.cbModulus);

                    var pubId = new Tpm2bPublicKeyRsa(modulus);
                    PublicParms.unique = pubId;
                    break;
                }
                case TpmAlgId.Ecc:
                {
                    var eccParms = keyParams.parameters as EccParms;
                    var alg = RawEccKey.GetEccAlg(keyParams);
                    if (alg == null)
                    {
                        Globs.Throw<ArgumentException>("Unknown ECC curve");
                        return;
                    }

                    byte[] keyIs;
                    Key = Generate(alg, (uint)RawEccKey.GetKeyLength(eccParms.curveID));
                    //BCRYPT_ECCPRIVATE_BLOB;
                    keyIs = Key.Export(Native.BCRYPT_ECCPUBLIC_BLOB);

                    // Store the public key
                    const int offset = 8;
                    int keySize = 0;
                    switch (eccParms.curveID)
                    {
                        case EccCurve.NistP256:
                        case EccCurve.BnP256:
                        case EccCurve.Sm2P256:
                            keySize = 32;
                            break;
                        case EccCurve.NistP384:
                            keySize = 48;
                            break;
                        case EccCurve.NistP521:
                            keySize = 66;
                            break;
                        default:
                            throw new NotImplementedException();
                    }
                    var pubId = new EccPoint(
                        Globs.CopyData(keyIs, offset, keySize),
                        Globs.CopyData(keyIs, offset + keySize, keySize));
                    PublicParms.unique = pubId;
                    break;
                }
                default:
                    Globs.Throw<ArgumentException>("Algorithm not supported");
                    break;
            }
        }

        public static bool IsCurveSupported(EccCurve curve)
        {
            return RawEccKey.IsCurveSupported(curve);
        }

        /// <summary>
        /// Create a new AsymCryptoSystem from TPM public parameter. This can then
        /// be used to validate TPM signatures or encrypt data destined for a TPM.  
        /// </summary>
        /// <param name="pubKey"></param>
        /// <param name="privKey"></param>
        /// <returns></returns>
        public static AsymCryptoSystem CreateFrom(TpmPublic pubKey, TpmPrivate privKey = null)
        {
            var cs = new AsymCryptoSystem();

            TpmAlgId keyAlgId = pubKey.type;
            cs.PublicParms = pubKey.Copy();

            // Create an algorithm provider from the provided PubKey
            switch (keyAlgId)
            {
                case TpmAlgId.Rsa:
                {
                    RawRsa rr = null;
                    byte[] prime1 = null,
                            prime2 = null;
                    if (privKey != null)
                    {
                        rr = new RawRsa(pubKey, privKey);
                        prime1 = RawRsa.ToBigEndian(rr.P);
                        prime2 = RawRsa.ToBigEndian(rr.Q);
                    }
                    var rsaParams = (RsaParms)pubKey.parameters;
                    var exponent = rsaParams.exponent != 0
                                            ? Globs.HostToNet(rsaParams.exponent)
                                            : RsaParms.DefaultExponent;
                    var modulus = (pubKey.unique as Tpm2bPublicKeyRsa).buffer;
                    var alg = new BCryptAlgorithm(Native.BCRYPT_RSA_ALGORITHM);
                    cs.Key = alg.LoadRSAKey(exponent, modulus, prime1, prime2);
                    alg.Close();
                    break;
                }
                case TpmAlgId.Ecc:
                {
                    var eccParms = (EccParms)pubKey.parameters;
                    var eccPub = (EccPoint)pubKey.unique;
                    var algId = RawEccKey.GetEccAlg(pubKey);
                    if (algId == null)
                    {
                        return null;
                    }
                    bool isEcdsa = eccParms.scheme.GetUnionSelector() == TpmAlgId.Ecdsa;
                    byte[] keyBlob = RawEccKey.GetKeyBlob(eccPub.x, eccPub.y, keyAlgId,
                                                            !isEcdsa, eccParms.curveID);
                    var alg = new BCryptAlgorithm(algId);
                    cs.Key = alg.ImportKeyPair(Native.BCRYPT_ECCPUBLIC_BLOB, keyBlob);
                    alg.Close();
                    if (cs.Key == UIntPtr.Zero)
                    {
                        Globs.Throw("Failed to create new RSA key");
                        return null;
                    }
                    break;
                }
                default:
                    Globs.Throw<ArgumentException>("Algorithm not supported");
                    cs = null;
                    break;
            }
            return cs;
        }

        public byte[] Export(string bcryptBlobType)
        {
            //RSAParameters parms = RsaProvider.ExportParameters(bcryptBlobType == Native.BCRYPT_RSAPRIVATE_BLOB);
            //var alg = new BCryptAlgorithm(Native.BCRYPT_RSA_ALGORITHM);
            //var Key = alg.LoadRSAKey(parms.Exponent, parms.Modulus, parms.P, parms.Q);

            byte[] keyBlob = Key.Export(bcryptBlobType);

            //Key.Destroy();
            //alg.Close();

            return keyBlob;
        }

        public byte[] ExportLegacyBlob()
        {
            return Export(Native.LEGACY_RSAPRIVATE_BLOB);
        }

        public byte[] ExportCspBlob()
        {
            return ExportLegacyBlob();
        }

        /// <summary>
        /// Retrieves key template (containing public key bits).
        /// </summary>
        /// <returns></returns>
        public TpmPublic GetPublicParms()
        {
            return PublicParms;
        }

        public Sensitive GetSensitive()
        {
            TpmPublic fromCspPublic;
            TpmPrivate fromCspPrivate = Csp.CspToTpm(ExportCspBlob(), out fromCspPublic);
            var m = new Marshaller(fromCspPrivate.buffer);
            ushort privSize = m.Get<UInt16>();
            if (fromCspPrivate.buffer.Length != privSize + 2)
            {
                Globs.Throw("Invalid key blob");
            }
            return m.Get<Sensitive>();
        }

        /// <summary>
        /// Sign using the hash algorithm specified during object instantiation. 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public ISignatureUnion Sign(byte[] data)
        {
            return SignData(data, TpmAlgId.Null);
        }

        /// <summary>
        /// Sign using a non-default hash algorithm.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="sigHash"></param>
        /// <returns></returns>
        public ISignatureUnion SignData(byte[] data, TpmAlgId sigHash)
        {
            Debug.Assert(Key != UIntPtr.Zero);
            var rsaParams = PublicParms.parameters as RsaParms;
            if (rsaParams != null)
            {
                TpmAlgId sigScheme = rsaParams.scheme.GetUnionSelector();

                switch (sigScheme)
                {
                    case TpmAlgId.Rsassa:
                    {
                        if (sigHash == TpmAlgId.Null)
                        {
                            sigHash = (rsaParams.scheme as SigSchemeRsassa).hashAlg;
                        }
                        byte[] digest = CryptoLib.HashData(sigHash, data);
                        byte[] sig = Key.SignHash(digest, BcryptScheme.Rsassa, sigHash);
                        return new SignatureRsassa(sigHash, sig);
                    }
                    case TpmAlgId.Rsapss:
                    {
                        Globs.Throw<ArgumentException>("SignData(): PSS scheme is not supported");
                        return null;
                    }
                }
                Globs.Throw<ArgumentException>("Unsupported signature scheme");
                return null;
            }

            var eccParms = PublicParms.parameters as EccParms;
            if (eccParms != null)
            {
                if (eccParms.scheme.GetUnionSelector() != TpmAlgId.Ecdsa)
                {
                    Globs.Throw<ArgumentException>("Unsupported ECC sig scheme");
                    return null;
                }
                if (sigHash == TpmAlgId.Null)
                {
                    sigHash = (eccParms.scheme as SigSchemeEcdsa).hashAlg;
                }
                byte[] digest = CryptoLib.HashData(sigHash, data);
                //throw new NotImplementedException("ECC signing with BCrypt is not implemented");
                byte[] sig = Key.SignHash(digest, BcryptScheme.Ecdsa, sigHash);
                int len = sig.Length / 2;
                return new SignatureEcdsa(sigHash, Globs.CopyData(sig, 0, len), Globs.CopyData(sig, len, len));
            }

            // Should never be here
            Globs.Throw("VerifySignature: Unrecognized asymmetric algorithm");
            return null;
        } // SignData()

        /// <summary>
        /// Verifies the signature over a digest.
        /// The signing scheme is retrieved from the signature. The verification key
        /// shall have either compatible or null scheme.
        /// </summary>
        /// <param name="digest">Digest to check against the signature</param>
        /// <param name="signature">The signature</param>
        /// <returns>True if the verification succeeds.</returns>
        public bool VerifySignatureOverHash(byte[] digest, ISignatureUnion signature)
        {
            return VerifySignature(digest ?? new byte[0], true, signature);
        }

        /// <summary>
        /// Verifies the signature over data.
        /// The data will be hashed internall by the method using hash algorithm from
        /// the signing scheme digest computed from the specified data buffer.
        /// The signing scheme is retrieved from the signature. The verification key
        /// shall have either compatible or null scheme.
        /// </summary>
        /// <param name="signedData">Data buffer to check against the signature</param>
        /// <param name="signature">The signature</param>
        /// <returns>True if the verification succeeds.</returns>
        public bool VerifySignatureOverData(byte[] signedData, ISignatureUnion signature)
        {
            return VerifySignature(signedData, false, signature);
        }

        /// <summary>
        /// Verifies the signature over data or a digest.
        /// The data will be hashed internall by the method using hash algorithm from
        /// the signing scheme digest computed from the specified data buffer.
        /// The signing scheme is retrieved from the signature. The verification key
        /// shall have either compatible or null scheme.
        /// </summary>
        /// <param name="data">Byte buffer containing either digest or data to check against the signature</param>
        /// <param name="dataIsDigest">Specifies the type of 'data' parameter contents</param>
        /// <param name="signature">The signature</param>
        /// <returns>True if the verification succeeds.</returns>
        private bool VerifySignature(byte[] data, bool dataIsDigest, ISignatureUnion sig)
        {
            Debug.Assert(Key != UIntPtr.Zero);
            TpmAlgId sigScheme = sig.GetUnionSelector();
            TpmAlgId sigHash = CryptoLib.SchemeHash(sig);

            var rsaParams = PublicParms.parameters as RsaParms;
            if (rsaParams != null)
            {
                var s = sig as SignatureRsa;
                TpmAlgId keyScheme = rsaParams.scheme.GetUnionSelector();

                if (keyScheme != TpmAlgId.Null && keyScheme != sigScheme)
                {
                    Globs.Throw<ArgumentException>("Key scheme and signature scheme do not match");
                    return false;
                }

                byte[] digest = dataIsDigest ? data : CryptoLib.HashData(sigHash, data);

                if (sigScheme == TpmAlgId.Rsassa)
                {
                    return Key.VerifySignature(digest, s.sig, sigHash, true);
                }
                if (sigScheme == TpmAlgId.Rsapss)
                {
                    Globs.Throw<ArgumentException>("VerifySignature(): PSS scheme is not supported");
                    return false;
                }
                Globs.Throw<ArgumentException>("VerifySignature(): Unrecognized scheme");
                return false;
            }

            var eccParams = PublicParms.parameters as EccParms;
            if (eccParams != null)
            {
                if (eccParams.scheme.GetUnionSelector() != TpmAlgId.Ecdsa)
                {
                    Globs.Throw<ArgumentException>("Unsupported ECC sig scheme");
                    return false;
                }
                TpmAlgId keyScheme = eccParams.scheme.GetUnionSelector();

                if (keyScheme != TpmAlgId.Null && keyScheme != sigScheme)
                {
                    Globs.Throw<ArgumentException>("Key scheme and signature scheme do not match");
                    return false;
                }

                var s = sig as SignatureEcdsa;
                byte[] digest = dataIsDigest ? data : CryptoLib.HashData(sigHash, data);
                byte[] sigBlob = Globs.Concatenate(s.signatureR, s.signatureS);
                return Key.VerifySignature(digest, sigBlob);
            }

            // Should never be here
            Globs.Throw("VerifySignature: Unrecognized asymmetric algorithm");
            return false;
        } // VerifySignature()

        /// <summary>
        /// Generates the key exchange key and the public part of the ephemeral key
        /// using specified encoding parameters in the KDF (ECC only).
        /// </summary>
        /// <param name="encodingParms"></param>
        /// <param name="decryptKeyNameAlg"></param>
        /// <param name="ephemPub"></param>
        /// <returns>key exchange key blob</returns>
        public byte[] EcdhGetKeyExchangeKey(byte[] encodingParms, TpmAlgId decryptKeyNameAlg, out EccPoint ephemPub)
        {
            byte[] keyExchangeKey = null;
            ephemPub = null;

            var eccParms = (EccParms)PublicParms.parameters;
            int keyBits = RawEccKey.GetKeyLength(eccParms.curveID);

            // Make a new ephemeral key
            var ephKey = Generate(RawEccKey.GetEccAlg(PublicParms), (uint)keyBits);
            byte[] ephPub = ephKey.Export(Native.BCRYPT_ECCPUBLIC_BLOB);
            byte[] otherPub = Key.Export(Native.BCRYPT_ECCPUBLIC_BLOB);

            byte[] herPubX, herPubY;
            RawEccKey.KeyInfoFromPublicBlob(otherPub, out herPubX, out herPubY);

            byte[] myPubX, myPubY;
            RawEccKey.KeyInfoFromPublicBlob(ephPub, out myPubX, out myPubY);

            byte[] otherInfo = Globs.Concatenate(new[] { encodingParms, myPubX, herPubX });

            // The TPM uses the following number of bytes from the KDF
            int bytesNeeded = CryptoLib.DigestSize(decryptKeyNameAlg);
            keyExchangeKey = new byte[bytesNeeded];

            for (int pos = 0, count = 1, bytesToCopy = 0;
                 pos < bytesNeeded;
                 ++count, pos += bytesToCopy)
            {
                byte[] secretPrepend = Marshaller.GetTpmRepresentation((UInt32)count);
                byte[] fragment = ephKey.DeriveKey(Key, decryptKeyNameAlg, secretPrepend, otherInfo);
                bytesToCopy = Math.Min(bytesNeeded - pos, fragment.Length);
                Array.Copy(fragment, 0, keyExchangeKey, pos, bytesToCopy);
            }
            ephemPub = new EccPoint(myPubX, myPubY);
            return keyExchangeKey;
        }

        internal TpmAlgId OaepHash
        {
            get
            {
                var rsaParams = (RsaParms)PublicParms.parameters;
                var hashAlg = PublicParms.nameAlg;
                if (rsaParams.scheme is SchemeOaep)
                    hashAlg = (rsaParams.scheme as SchemeOaep).hashAlg;
                else if (rsaParams.scheme is EncSchemeOaep)
                    hashAlg = (rsaParams.scheme as EncSchemeOaep).hashAlg;
                return hashAlg;
            }
        }

        /// <summary>
        /// Encrypt dataToEncrypt using the specified encodingParams (RSA only).
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="label"></param>
        /// <returns></returns>
        public byte[] EncryptOaep(byte[] plainText, byte[] label)
        {
            if (plainText == null)
                plainText = new byte[0];
            if (label == null)
                label = new byte[0];
            var paddingInfo = new BCryptOaepPaddingInfo(OaepHash, label);
            byte[] cipherText = Key.Encrypt(plainText, paddingInfo);
            return cipherText;
        }

        public byte[] DecryptOaep(byte[] cipherText, byte[] label)
        {
            var paddingInfo = new BCryptOaepPaddingInfo(OaepHash, label);
            byte[] plainText = Key.Decrypt(cipherText, paddingInfo);
            return plainText;
        }


        public void Dispose()
        {
            Key.Dispose();
        }
    } // class AsymCryptoSystem

    public class RawRsa
    {
        internal int NumBits = 0;

        /// <summary>
        /// Modulus (internal key) = P * Q
        /// </summary>
        internal BigInteger N;

        /// <summary>
        /// Public (encryption) exponent (typically 65537)
        /// </summary>
        internal BigInteger E;

        /// <summary>
        ///  The first prime factor (private key)
        /// </summary>
        internal BigInteger P;

        /// <summary>
        ///  The second prime factor
        /// </summary>
        internal BigInteger Q;

        /// <summary>
        /// Private (decryption) exponent
        /// </summary>
        internal BigInteger D;

        internal BigInteger InverseQ;
        internal BigInteger DP;
        internal BigInteger DQ;

        internal int KeySize { get { return (NumBits + 7) / 8; } }

        /// <summary>
        /// Returns the public key in TPM-format
        /// </summary>
        /// <returns></returns>
        public byte[] Public { get { return ToBigEndian(N); } }

        /// <summary>
        /// Returns the RSA private key in TPM format (the first prime number)
        /// </summary>
        /// <returns></returns>
        public byte[] Private { get { return ToBigEndian(P); } }

        /// <summary>
        ///  Generates new key pair using OS CSP
        /// </summary>
        /// <param name="numBits"></param>
        /// <param name="publicExponent"></param>
        public RawRsa (int numBits, int publicExponent = 65537)
        {
            var key = AsymCryptoSystem.Generate(Native.BCRYPT_RSA_ALGORITHM, (uint)numBits);
            byte[] blob = key.Export(Native.BCRYPT_RSAFULLPRIVATE_BLOB);
            var m = new Marshaller(blob, DataRepresentation.LittleEndian);
            var header = m.Get<BCryptRsaKeyBlob>();
            E = FromBigEndian(m.GetArray<byte>((int)header.cbPublicExp));
            N = FromBigEndian(m.GetArray<byte>((int)header.cbModulus));
            P = FromBigEndian(m.GetArray<byte>((int)header.cbPrime1));
            Q = FromBigEndian(m.GetArray<byte>((int)header.cbPrime2));
            DP = FromBigEndian(m.GetArray<byte>((int)header.cbPrime1));
            DQ = FromBigEndian(m.GetArray<byte>((int)header.cbPrime2));
            InverseQ = FromBigEndian(m.GetArray<byte>((int)header.cbPrime1));
            D = FromBigEndian(m.GetArray<byte>((int)header.cbModulus));
        }

        /// <summary>
        /// Instantiates the object using a TPM generated key pair
        /// </summary>
        /// <param name="pub"></param>
        /// <param name="priv"></param>
        public RawRsa(TpmPublic pub, TpmPrivate priv)
        {
            var m = new Marshaller(priv.buffer);
            var privSize = m.Get<UInt16>();
            // Assert that the private key blob is in plain text 
            Debug.Assert(priv.buffer.Length == privSize + 2);
            var sens = m.Get<Sensitive>();
            Init(pub, sens.sensitive as Tpm2bPrivateKeyRsa);
        }

        void Init(TpmPublic pub, Tpm2bPrivateKeyRsa priv)
        {
            var parms = pub.parameters as RsaParms;

            NumBits = parms.keyBits;

            E = new BigInteger(parms.exponent == 0 ? RsaParms.DefaultExponent
                                                   : BitConverter.GetBytes(parms.exponent));
            N = FromBigEndian((pub.unique as Tpm2bPublicKeyRsa).buffer);
            P = FromBigEndian(priv.buffer);
            Q = N / P;
            Debug.Assert(N % P == BigInteger.Zero);

            BigInteger PHI = N - (P + Q - BigInteger.One);
            D = ModInverse(E, PHI);
            InverseQ = ModInverse(Q, P);
            DP = D % (P - BigInteger.One);
            DQ = D % (Q - BigInteger.One);
        }

        public static byte[] GetLabel(string label)
        {
            return GetLabel(Encoding.ASCII.GetBytes(label));
        }

        public static byte[] GetLabel(byte[] data)
        {
            if (data == null)
            {
                return new byte[0];
            }
            if (data.Length == 0)
            {
                return data;
            }
            int labelSize = 0;
            while (labelSize < data.Length && data[labelSize++] != 0)
            {
                continue;
            }
            var label = new byte[labelSize + (data[labelSize - 1] != 0 ? 1 : 0)];
            Array.Copy(data, label, labelSize);
            return label;
        }

        internal static BigInteger ModInverse(BigInteger a, BigInteger b)
        {
            BigInteger dividend = a % b;
            BigInteger divisor = b;

            BigInteger lastX = BigInteger.One;
            BigInteger currX = BigInteger.Zero;

            while (divisor.Sign > 0)
            {
                BigInteger quotient = dividend / divisor;
                BigInteger remainder = dividend % divisor;

                if (remainder.Sign <= 0)
                {
                    break;
                }

                BigInteger nextX = lastX - currX * quotient;

                lastX = currX;
                currX = nextX;

                dividend = divisor;
                divisor = remainder;
            }

            if (divisor != BigInteger.One)
            {
                throw new Exception("ModInverse(): Not coprime");
            }

            return (currX.Sign < 0 ? currX + b : currX);
        }

        /// <summary>
        /// Translate a byte array representing a big-endian (MSB first, possibly > 0x7F)
        /// TPM-style number to a BigInteger.
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        public static BigInteger FromBigEndian(byte[] b)
        {
            return new BigInteger(ToLittleEndian(b));
        }

        /// <summary>
        /// Translates a BigInt into a TPM-style big-endian byte array.
        /// By default removes MSB-zeros.
        /// If sizeWanted is specified, pads with MSB-zeros to desired length.
        /// </summary>
        /// <param name="b"></param>
        /// <param name="sizeWanted"></param>
        /// <returns></returns>
        public static byte[] ToBigEndian(BigInteger b, int sizeWanted = -1)
        {
            return ToBigEndian(b.ToByteArray());
        }

        /// <summary>
        /// Translate a byte array representing a big-endian (MSB first, possibly > 0x7F)
        /// TPM-style number to the little endian representation.
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        internal static byte[] ToLittleEndian(byte[] b)
        {
            int len = b.Length;
            var b2 = new byte[len + (b[0] > 0x7F ? 1 : 0)];

            for (int j = 0; j < len; j++)
            {
                b2[j] = b[len - 1 - j];
            }
            return b2;
        }

        /// <summary>
        /// Translates a little endian number represented as a byte array to TPM-style
        /// big-endian byte array. By default removes MSB-zeros.
        /// If sizeWanted is specified, pads with MSB-zeros to desired length.
        /// </summary>
        /// <param name="b"></param>
        /// <param name="sizeWanted"></param>
        /// <returns></returns>
        internal static byte[] ToBigEndian(byte[] b, int sizeWanted = -1)
        {
            int len = b.Length;

            // Count trailing zeros (MSB zeros to be removed)
            while (len > 0 && b[len - 1] == 0)
            {
                --len;
            }
            if (sizeWanted == -1)
            {
                sizeWanted = len;
            }

            int pad = sizeWanted - len;
            if (pad < 0)
            {
                Globs.Throw<ArgumentException>("ToBigEndian(): Too short size requested");
                return new byte[0];
            }

            var b2 = new byte[sizeWanted];

            for (int j = 0; j < len; j++)
            {
                b2[j + pad] = b[len - 1 - j];
            }
            return b2;
        }

        public byte[] RawEncrypt(byte[] plain)
        {
            BigInteger plainX = FromBigEndian(plain);
            BigInteger cipher = BigInteger.ModPow(plainX, E, N);
            byte[] cipherX = ToBigEndian(cipher, KeySize);
            return cipherX;
        }

        public byte[] RawDecrypt(byte[] cipher)
        {
            BigInteger cipherX = FromBigEndian(cipher);
            BigInteger plain = BigInteger.ModPow(cipherX, D, N);
            byte[] plainX = ToBigEndian(plain, KeySize);
            return plainX;
        }

        public byte[] OaepEncrypt(byte[] data, TpmAlgId hashAlg, byte[] encodingParms)
        {
            int encLen = NumBits / 8;
            byte[] zeroTermEncoding = GetLabel(encodingParms);
            byte[] encoded = CryptoEncoders.OaepEncode(data, zeroTermEncoding, hashAlg, encLen);
            BigInteger message = FromBigEndian(encoded);
            BigInteger cipher = BigInteger.ModPow(message, E, N);
            byte[] encMessageBigEnd = ToBigEndian(cipher, KeySize);
            if (encMessageBigEnd.Length < encLen)
                encMessageBigEnd = Globs.AddZeroToBeginning(encMessageBigEnd, encLen - encMessageBigEnd.Length);
            return encMessageBigEnd;
        }

        public byte[] OaepDecrypt(byte[] cipherText, TpmAlgId hashAlg, byte[] encodingParms)
        {
            byte[] zeroTermEncoding = GetLabel(encodingParms);
            BigInteger cipher = FromBigEndian(cipherText);
            BigInteger plain = BigInteger.ModPow(cipher, D, N);
            byte[] encMessage = ToBigEndian(plain, KeySize - 1);
            byte[] message;

            // Hack - be robust to leading zeros
            while (true)
            {
                bool decodeOk = CryptoEncoders.OaepDecode(encMessage, zeroTermEncoding, hashAlg, out message);
                if (decodeOk)
                {
                    break;
                }
                encMessage = Globs.AddZeroToBeginning(encMessage);
            }
            return message;
        }

        public byte[] PssSign(byte[] m, TpmAlgId hashAlg)
        {
            // The TPM uses the maximum salt length
            int defaultPssSaltLength = 0; // KeySize - CryptoLib.DigestSize(hashAlg) - 1 - 1;

            // Encode
            byte[] em = CryptoEncoders.PssEncode(m, hashAlg, defaultPssSaltLength, NumBits - 1);
            BigInteger message = FromBigEndian(em);

            // Sign
            BigInteger sig = BigInteger.ModPow(message, D, N);
            byte[] signature = ToBigEndian(sig, KeySize);
            return signature;
        }

        public bool PssVerify(byte[] m, byte[] signature, TpmAlgId hashAlg)
        {
            // The TPM uses the maximum salt length
            int defaultPssSaltLength = 0; //  KeySize - CryptoLib.DigestSize(hashAlg) - 1 - 1;
            BigInteger sig = FromBigEndian(signature);
            BigInteger emx = BigInteger.ModPow(sig, E, N);

            byte[] em = ToBigEndian(emx, KeySize);

            bool ok = CryptoEncoders.PssVerify(m, em, defaultPssSaltLength, NumBits - 1, hashAlg);
            return ok;
        }

        public byte[] PkcsSign(byte[] m, TpmAlgId hashAlg)
        {
            int k = KeySize;
            byte[] em = CryptoEncoders.Pkcs15Encode(m, k, hashAlg);
            BigInteger message = FromBigEndian(em);
            BigInteger sig = BigInteger.ModPow(message, D, N);
            byte[] signature = ToBigEndian(sig, KeySize);
            return signature;
        }

        public bool PkcsVerify(byte[] m, byte[] s, TpmAlgId hashAlg)
        {
            if (s.Length != KeySize)
            {
                Globs.Throw<ArgumentException>("PkcsVerify: Invalid signature");
                return false;
            }
            int k = KeySize;
            BigInteger sig = FromBigEndian(s);
            BigInteger emx = BigInteger.ModPow(sig, E, N);

            byte[] emDecrypted = ToBigEndian(emx, KeySize);

            byte[] emPrime = CryptoEncoders.Pkcs15Encode(m, k, hashAlg);
            if (!Globs.ArraysAreEqual(emPrime, emDecrypted))
            {
                return false;
            }
            return true;
        }
    }

    internal class RawEccKey
    {
        internal struct EccInfo
        {
            internal uint Magic;
            internal bool Public;   // Not private
            internal int KeyLength; // Bits
            internal bool Ecdh;     // Not ECDSA
        }

        internal static EccInfo[] AlgInfo = {

            //#define BCRYPT_ECDH_PUBLIC_P256_MAGIC   0x314B4345  // ECK1
            new EccInfo {Magic = 0x314B4345, KeyLength = 256, Ecdh = true, Public = true},
            //#define BCRYPT_ECDH_PRIVATE_P256_MAGIC  0x324B4345  // ECK2
            new EccInfo {Magic = 0x324B4345, KeyLength = 256, Ecdh = true, Public = false},
            //#define BCRYPT_ECDH_PUBLIC_P384_MAGIC   0x334B4345  // ECK3
            new EccInfo {Magic = 0x334B4345, KeyLength = 384, Ecdh = true, Public = true},
            //#define BCRYPT_ECDH_PRIVATE_P384_MAGIC  0x344B4345  // ECK4
            new EccInfo {Magic = 0x344B4345, KeyLength = 384, Ecdh = true, Public = false},
            //#define BCRYPT_ECDH_PUBLIC_P521_MAGIC   0x354B4345  // ECK5
            new EccInfo {Magic = 0x354B4345, KeyLength = 521, Ecdh = true, Public = true},
            //#define BCRYPT_ECDH_PRIVATE_P521_MAGIC  0x364B4345  // ECK6
            new EccInfo {Magic = 0x364B4345, KeyLength = 521, Ecdh = true, Public = false},

            //#define BCRYPT_ECDSA_PUBLIC_P256_MAGIC  0x31534345  // ECS1
            new EccInfo {Magic = 0x31534345, KeyLength = 256, Ecdh = false, Public = true},
            //#define BCRYPT_ECDSA_PRIVATE_P256_MAGIC 0x32534345  // ECS2
            new EccInfo {Magic = 0x32534345, KeyLength = 256, Ecdh = false, Public = false},
            //#define BCRYPT_ECDSA_PUBLIC_P384_MAGIC  0x33534345  // ECS3
            new EccInfo {Magic = 0x33534345, KeyLength = 384, Ecdh = false, Public = true},
            //#define BCRYPT_ECDSA_PRIVATE_P384_MAGIC 0x34534345  // ECS4
            new EccInfo {Magic = 0x34534345, KeyLength = 384, Ecdh = false, Public = false},
            //#define BCRYPT_ECDSA_PUBLIC_P521_MAGIC  0x35534345  // ECS5
            new EccInfo {Magic = 0x35534345, KeyLength = 521, Ecdh = false, Public = true},
            //#define BCRYPT_ECDSA_PRIVATE_P521_MAGIC 0x36534345  // ECS6
            new EccInfo {Magic = 0x36534345, KeyLength = 521, Ecdh = false, Public = false}
        };

        internal static int GetKeyLength(EccCurve curve)
        {
            switch (curve)
            {
                case EccCurve.NistP256:
                    return 256;
                case EccCurve.NistP384:
                    return 384;
                case EccCurve.NistP521:
                    return 521;
            }
            Globs.Throw<ArgumentException>("GetKeyLength(): Invalid ECC curve");
            return -1;
        }

        internal static uint MagicFromTpmAlgId(TpmAlgId algId, bool isEcdh, EccCurve curve, bool publicKey)
        {
            uint res = AlgInfo.FirstOrDefault(x => (x.Public == publicKey && 
                                                    x.KeyLength == GetKeyLength(curve) &&
                                                    x.Ecdh == isEcdh)).Magic;
            if (res == 0)
            {
                Globs.Throw("Unrecognized ECC parameter set");
            }
            return res;
        }

        internal static byte[] GetKeyBlob(byte[] x, byte[] y, TpmAlgId alg, bool isEcdh, EccCurve curve)
        {
            var m = new Marshaller();
            byte[] magic = BitConverter.GetBytes(MagicFromTpmAlgId(alg, isEcdh, curve, true));
            m.Put(magic, "");
            int keyBits = GetKeyLength(curve);
            int keySizeBytes = (keyBits + 7) / 8;

            if (x.Length != keySizeBytes || y.Length != keySizeBytes)
            {
                Globs.Throw<ArgumentException>("GetKeyBlob: Malformed ECC key");
                return new byte[0];
            }

            var size = Globs.ReverseByteOrder(Globs.HostToNet(keySizeBytes));
            m.Put(size, "len");
            m.Put(x, "x");
            m.Put(y, "y");
            var res = m.GetBytes();
            return res;
        }

        internal static void KeyInfoFromPublicBlob(byte[] blob, out byte[] x, out byte[] y)
        {
            x = null;
            y = null;
            var m = new Marshaller(blob);
            uint magic = BitConverter.ToUInt32(m.GetNBytes(4), 0);
            bool magicOk = AlgInfo.Any(xx => xx.Magic == magic);

            if (!magicOk)
            {
                Globs.Throw<ArgumentException>("KeyInfoFromPublicBlob: Public key blob magic not recognized");
            }

            uint cbKey = BitConverter.ToUInt32(m.GetNBytes(4), 0);

            x = m.GetNBytes((int)cbKey);
            y = m.GetNBytes((int)cbKey);
        }

        internal static bool IsCurveSupported(EccCurve curve)
        {
            int curveIndex = (int)curve;

            if (curveIndex < EcdsaCurveIDs.Length &&
                EcdsaCurveIDs[curveIndex] != null)
            {
                return true;
            }
            return false;
        }

        static string[] EcdsaCurveIDs = { null, null, null,
                            Native.BCRYPT_ECDSA_P256_ALGORITHM,
                            Native.BCRYPT_ECDSA_P384_ALGORITHM,
                            Native.BCRYPT_ECDSA_P521_ALGORITHM
                        };
        static string[] EcdhCurveIDs = { null, null, null,
                            Native.BCRYPT_ECDH_P256_ALGORITHM,
                            Native.BCRYPT_ECDH_P384_ALGORITHM,
                            Native.BCRYPT_ECDH_P521_ALGORITHM
                        };

        internal static string
        GetEccAlg(TpmPublic pub)
        {
            if (pub.unique.GetUnionSelector() != TpmAlgId.Ecc)
            {
                return null;
            }

            var eccParms = (EccParms)pub.parameters;

            bool signing = pub.objectAttributes.HasFlag(ObjectAttr.Sign);
            bool encrypting = pub.objectAttributes.HasFlag(ObjectAttr.Decrypt);
            if (!(signing ^ encrypting))
            {
                Globs.Throw<ArgumentException>("ECC Key must either sign or decrypt");
                return null;
            }
            var scheme = eccParms.scheme.GetUnionSelector();
            if (signing && scheme != TpmAlgId.Ecdsa && scheme != TpmAlgId.Null)
            {
                Globs.Throw<ArgumentException>("Unsupported ECC signing scheme");
                return null;
            }

            if (!IsCurveSupported(eccParms.curveID))
            {
                Globs.Throw<ArgumentException>("Unsupported ECC curve");
                return null;
            }
            int curveIndex = (int)eccParms.curveID;
            return signing ? EcdsaCurveIDs[curveIndex] : EcdhCurveIDs[curveIndex];
        }
    } // class CngEccKey
}

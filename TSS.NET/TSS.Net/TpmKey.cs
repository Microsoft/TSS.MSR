/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Diagnostics;
using System.Text;
using System.Security.Cryptography;


namespace Tpm2Lib
{
    public enum QuoteElt
    {
        None,
        Type,
        Magic,
        ExtraData,
        QualifiedSigner,
        PcrSelect,
        PcrDigest,
        Signature
    }

    public partial class NvPublic
    {
        /// <summary>
        /// Calculate and return the name of the entity. The name is an alg-prepended
        /// digest in a byte buffer
        /// </summary>
        /// <returns></returns>
        public byte[] GetName()
        {
            byte[] rawData = GetTpmRepresentation();
            TpmHash pubDigest = TpmHash.FromData(nameAlg, rawData);
            return Marshaller.GetTpmRepresentation(pubDigest);
        }
    }

    public partial class TpmPublic
    {
        /// <summary>
        // Calculate and return the name of the entity. The name is an alg-prepended
        // digest in a byte buffer
        /// </summary>
        /// <returns></returns>
        public byte[] GetName()
        {
            byte[] rawData = GetTpmRepresentation();
            TpmHash pubDigest = TpmHash.FromData(nameAlg, rawData);
            return Marshaller.GetTpmRepresentation(pubDigest);
        }

        public delegate void Transformer(byte[] x);

        internal Transformer TransformerCallback;

        /// <summary>
        // Install a transformer callback (for debugging). Transformer is called on several
        // code-paths in creating SW-generated keys, import blobs, and activation
        // blobs. Transformer can arbitrarily manipulate the byte array parameter and the
        // transformed value will be used (this allows a caller to transform parameters
        // that are hard to affect in the raw TPM command because they are protected by
        // crypto.
        // Note that the transformer callback should only work on a fraction (say 10%)
        // of the calls because the it is called several times during preparation of some
        // data structures and if one always modifies the first then it is possible that
        // the second is never processed by the TPM.
        /// </summary>
        /// <param name="transformer"></param>
        public void _SetTransformer(Transformer transformer)
        {
            TransformerCallback = transformer;
        }

        private void Transform(byte[] x)
        {
            if (TransformerCallback != null)
            {
                TransformerCallback(x);
            }
        }

        /// <summary>
        /// The TPM always signs hash-sized data. This version of the VerifySignature
        /// performs the necessary hashing operation over arbitrarily-length data and
        /// verifies that the hash is properly signed.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="sig"></param>
        /// <returns></returns>
        public bool VerifySignatureOverData(byte[] data, ISignatureUnion sig)
        {
            using (AsymCryptoSystem verifier = AsymCryptoSystem.CreateFrom(this))
            {
                return verifier == null ? false
                                        : verifier.VerifySignatureOverData(data, sig);
            }
        }

        /// <summary>
        /// Verify a TPM signature structure of the hash of some data (caller hashes
        /// the data that will be verified).
        /// </summary>
        public bool VerifySignatureOverHash(byte[] digest, ISignatureUnion sig)
        {
            using (AsymCryptoSystem verifier = AsymCryptoSystem.CreateFrom(this))
            {
                return verifier == null ? false
                                        : verifier.VerifySignatureOverHash(digest, sig);
            }
        }

        /// <summary>
        /// Verify that a TPM quote matches an expect PCR selection, is well formed,
        /// and is properly signed.
        /// </summary>
        /// <param name="pcrDigestAlg"></param>
        /// <param name="expectedSelectedPcr"></param>
        /// <param name="expectedPcrValues"></param>
        /// <param name="nonce"></param>
        /// <param name="quotedInfo"></param>
        /// <param name="signature"></param>
        /// <param name="qualifiedNameOfSigner"></param>
        /// <returns></returns>
        public bool VerifyQuote(TpmAlgId pcrDigestAlg,
                                PcrSelection[] expectedSelectedPcr,
                                Tpm2bDigest[] expectedPcrValues,
                                byte[] nonce,
                                Attest quotedInfo,
                                ISignatureUnion signature,
                                byte[] qualifiedNameOfSigner = null)
        {
            QuoteElt pointOfFailure;
            return VerifyQuote(pcrDigestAlg, expectedSelectedPcr, expectedPcrValues,
                               nonce, quotedInfo, signature, out pointOfFailure,
                               qualifiedNameOfSigner);
        }

        /// <summary>
        // Verify that a TPM quote matches an expect PCR selection, is well formed,
        // and is properly signed. In acse of failure this overload additionally
        // returns information about the specific check that failed.
        /// </summary>
        /// <param name="pcrDigestAlg"></param>
        /// <param name="expectedSelectedPcr"></param>
        /// <param name="expectedPcrValues"></param>
        /// <param name="nonce"></param>
        /// <param name="quotedInfo"></param>
        /// <param name="signature"></param>
        /// <param name="pointOfFailure"></param>
        /// <param name="qualifiedNameOfSigner"></param>
        /// <returns></returns>
        public bool VerifyQuote(TpmAlgId pcrDigestAlg,
                                PcrSelection[] expectedSelectedPcr,
                                Tpm2bDigest[] expectedPcrValues,
                                byte[] nonce,
                                Attest quotedInfo,
                                ISignatureUnion signature,
                                out QuoteElt pointOfFailure,
                                byte[] qualifiedNameOfSigner = null)
        {
            pointOfFailure = QuoteElt.None;

            if (!(quotedInfo.attested is QuoteInfo))
            {
                pointOfFailure = QuoteElt.Type;
                return false;
            }

            if (quotedInfo.magic != Generated.Value)
            {
                pointOfFailure = QuoteElt.Magic;
                return false;
            }

            if (!quotedInfo.extraData.IsEqual(nonce))
            {
                pointOfFailure = QuoteElt.ExtraData;
                return false;
            }

            // Check environment of signer (name) is expected
            if (qualifiedNameOfSigner != null &&
                !quotedInfo.qualifiedSigner.IsEqual(qualifiedNameOfSigner))
            {
                pointOfFailure = QuoteElt.QualifiedSigner;
                return false;
            }

            // Now check the quote-specific fields
            var quoted = (QuoteInfo)quotedInfo.attested;

            // Check values pcr indices are what we expect
            if (!Globs.ArraysAreEqual(quoted.pcrSelect, expectedSelectedPcr))
            {
                pointOfFailure = QuoteElt.PcrSelect;
                return false;
            }

            // Check that values in the indices above are what we expect
            // ReSharper disable once UnusedVariable
            var expected = new PcrValueCollection(expectedSelectedPcr, expectedPcrValues);
            var m = new Marshaller();

            foreach (Tpm2bDigest d in expectedPcrValues)
            {
                m.Put(d.buffer, "");
            }

            TpmHash expectedPcrHash = TpmHash.FromData(pcrDigestAlg, m.GetBytes());
            if (!Globs.ArraysAreEqual(expectedPcrHash, quoted.pcrDigest))
            {
                pointOfFailure = QuoteElt.PcrDigest;
                return false;
            }

            // And finally check the signature
            if (!VerifySignatureOverData(quotedInfo.GetTpmRepresentation(), signature))
            {
                pointOfFailure = QuoteElt.Signature;
                return false;
            }
            return true;
        }

        /// <summary>
        /// Verify that quotedInfo is properly signed by an associated private key
        /// holder, and that the quotedInfo.type, .extraData and .magic are correct.
        /// Also check that the certified name is what the caller expects.  The caller
        /// must check other fields (for instance the qualified name)
        /// </summary>
        /// <param name="name"></param>
        /// <param name="nonce"></param>
        /// <param name="quotedInfo"></param>
        /// <param name="expectedName"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        public bool VerifyCertify(TpmHash name, byte[] nonce, Attest quotedInfo,
                                  byte[] expectedName, ISignatureUnion signature)
        {
            // Check generic signature stuff
            if (quotedInfo.type != TpmSt.AttestCertify)
            {
                return false;
            }

            if (!Globs.ArraysAreEqual(quotedInfo.extraData, nonce))
            {
                return false;
            }

            if (quotedInfo.magic != Generated.Value)
            {
                return false;
            }

            // Check specific certify-signature stuff
            var certInfo = (CertifyInfo)quotedInfo.attested;
            if (!Globs.ArraysAreEqual(expectedName, certInfo.name))
            {
                return false;
            }
            // Check the actual signature
            TpmHash sigHash = TpmHash.FromData(TpmAlgId.Sha1, quotedInfo.GetTpmRepresentation());
            bool certifyOk = VerifySignatureOverHash(sigHash, signature);
            return certifyOk;
        }

        /// <summary>
        /// OEAP pad and encrypt the data using the specified encoding parameters (RSA only).
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        /// <param name="encodingParms"></param>
        /// <returns></returns>
        public byte[] EncryptOaep(byte[] dataToEncrypt, byte[] encodingParms)
        {
            using (AsymCryptoSystem encryptor = AsymCryptoSystem.CreateFrom(this))
            {
                return encryptor.EncryptOaep(dataToEncrypt, encodingParms);
            }
        }

        /// <summary>
        /// Get an ECDH key exchange key (one pass ephemeral) and the public key of
        /// the ephemeral key using ECDH with encodingParms as input to the KDF (ECC only).
        /// </summary>
        /// <param name="encodingParms"></param>
        /// <param name="pubEphem"></param>
        /// <returns></returns>
        public byte[] EcdhGetKeyExchangeKey(byte[] encodingParms, out EccPoint ephemPubPt)
        {
            using (AsymCryptoSystem encryptor = AsymCryptoSystem.CreateFrom(this))
            {
                if (encryptor == null)
                {
                    ephemPubPt = null;
                    return null;
                }
                return encryptor.EcdhGetKeyExchangeKey(encodingParms, nameAlg, out ephemPubPt);
            }
        }

        /// <summary>
        /// Create activation blobs that can be passed to ActivateCredential. Two
        /// blobs are returned:
        /// 1) encryptedSecret - symmetric key cfb-symmetrically encrypted with the 
        ///                      enveloping key;
        /// 2) credentialBlob -  the enveloping key OEAP (RSA) encrypted by the public
        ///                      part of this key. This is the return value of this
        ///                      function
        /// </summary>
        /// <param name="secret"></param>
        /// <param name="nameOfKeyToBeActivated"></param>
        /// <param name="encryptedSecret"></param>
        /// <returns>CredentialBlob (</returns>
        public IdObject CreateActivationCredentials(byte[] secret,
                                                    byte[] nameOfKeyToBeActivated,
                                                    out byte[] encryptedSecret)
        {
            byte[] seed, encSecret;

            switch (type)
            {
                case TpmAlgId.Rsa:
                    // The seed should be the same size as the name algorithmdigest
                    seed = Globs.GetRandomBytes(CryptoLib.DigestSize(nameAlg));
                    encSecret = EncryptOaep(seed, ActivateEncodingParms);
                    break;
                case TpmAlgId.Ecc:
                    EccPoint ephemPubPt;
                    seed = EcdhGetKeyExchangeKey(ActivateEncodingParms, out ephemPubPt);
                    if (seed == null)
                    {
                        encryptedSecret = null;
                        return null;
                    }
                    encSecret = Marshaller.GetTpmRepresentation(ephemPubPt);
                    break;
                default:
                    Globs.Throw<NotImplementedException>(
                                "CreateActivationCredentials: Unsupported algorithm");
                    encryptedSecret = new byte[0];
                    return null;
            }

            Transform(seed);
            Transform(encSecret);

            var cvx = new Tpm2bDigest(secret);
            byte[] cvTpm2B = Marshaller.GetTpmRepresentation(cvx);
            Transform(cvTpm2B);

            SymDefObject symDef = TssObject.GetSymDef(this);
            byte[] symKey = KDF.KDFa(nameAlg, seed, "STORAGE",
                                     nameOfKeyToBeActivated, new byte[0], symDef.KeyBits);
            Transform(symKey);

            byte[] encIdentity;
            // TPM only uses CFB mode in its command implementations
            var sd = symDef.Copy();
            sd.Mode = TpmAlgId.Cfb;
            using (var sym = SymCipher.Create(sd, symKey))
            {
                // Not all keys specs are supported by SW crypto
                if (sym == null)
                {
                    encryptedSecret = null;
                    return null;
                }
                encIdentity = sym.Encrypt(cvTpm2B);
            }
            Transform(encIdentity);

            var hmacKeyBits = CryptoLib.DigestSize(nameAlg);
            byte[] hmacKey = KDF.KDFa(nameAlg, seed, "INTEGRITY",
                                      new byte[0], new byte[0], hmacKeyBits * 8);
            Transform(hmacKey);
            byte[] outerHmac = CryptoLib.Hmac(nameAlg, hmacKey,
                                    Globs.Concatenate(encIdentity, nameOfKeyToBeActivated));
            Transform(outerHmac);


            encryptedSecret = encSecret;
            return new IdObject(outerHmac, encIdentity);
        }

        private static readonly byte[] ActivateEncodingParms = Encoding.UTF8.GetBytes("IDENTITY\0");
    } // class TpmPublic

    /// <summary>
    /// TssObject is a container wrapper for
    /// 1) A Public
    /// 2) A Public and a Sensitive
    /// 3) A public and a private
    /// 4) Optional use-authorization
    /// It (and methods on the contained public) provide support for many of the actions
    /// of the TPM (signing, quote verification, key creation, etc.)
    /// </summary>
    public partial class TssObject
    {
        public AuthValue UseAuth = new AuthValue();

        public TssObject(TpmPublic thePublicPart, TpmPrivate thePrivatePart)
        {
            Public = thePublicPart;
            Private = thePrivatePart;
        }

        public delegate void Transformer(byte[] x);

        private Transformer TransformerCallback;

        /// <summary>
        /// Install a transformer callback (for testing purposes). The callback is
        /// invoked on various code-paths in creating SW-generated keys, import blobs,
        /// and  activation blobs. Transformer can arbitrarily manipulate the byte
        /// array parameter and the transformed value will be used (this allows a
        /// caller to transform parameters that are hard to affect in the raw TPM
        /// command because they are protected by crypto.
        /// Note that the transformer callback should only work on a fraction (say 10%)
        /// of the calls because it is called several times during preparation of some
        /// data structures and if one always modifies the first one, then it is likely
        /// that the subsequent ones never reach the TPM.
        /// </summary>
        /// <param name="transformer"></param>
        public void _SetTransformer(Transformer transformer)
        {
            TransformerCallback = transformer;
        }

        private void Transform(byte[] x)
        {
            if (TransformerCallback != null)
            {
                TransformerCallback(x);
            }
        }

        public byte[] EncryptDecrypt (byte[] data, bool decrypt, ref byte[] ivIn, out byte[] ivOut)
        {
            ivOut = null;

            if (Public.type != TpmAlgId.Symcipher)
            {
                Globs.Throw<ArgumentException>("Only symmetric encryption/decryption is "
                                             + "supported by this overloaded version");
                return null;
            }

            var symDef = GetSymDef();
            using (var sym = SymCipher.Create(symDef,
                                        (Sensitive.sensitive as Tpm2bSymKey).buffer))
            {
                if (sym == null)
                {
                    Globs.Throw<ArgumentException>("Unsupported symmetric key configuration");
                    return null;
                }

                if (Globs.IsEmpty(ivIn))
                {
                    ivIn = (symDef.Mode == TpmAlgId.Ecb) ? new byte[0]
                        : Globs.GetRandomBytes(SymCipher.GetBlockSize(symDef));
                }
                ivOut = Globs.CopyData(ivIn);

                return decrypt ? sym.Decrypt(data, ivOut)
                                : sym.Encrypt(data, ivOut);
            }
        } // EncryptDecrypt

        public byte[] Encrypt(byte[] message, ref byte[] ivIn, out byte[] ivOut)
        {
            return EncryptDecrypt(message, false, ref ivIn, out ivOut);
        }

        public byte[] Decrypt(byte[] message, ref byte[] ivIn, out byte[] ivOut)
        {
            return EncryptDecrypt(message, true, ref ivIn, out ivOut);
        }

        public byte[] Encrypt(byte[] message, ref byte[] ivIn)
        {
            byte[] ivOut;
            return EncryptDecrypt(message, false, ref ivIn, out ivOut);
        }

        public byte[] Decrypt(byte[] message, ref byte[] ivIn)
        {
            byte[] ivOut;
            return EncryptDecrypt(message, true, ref ivIn, out ivOut);
        }

        /// <summary>
        /// Creates a *software* key.  The key will be random (not created from
        /// a seed).  The key can be used as the root of a software hierarchy that
        /// can be translated into a duplication blob ready for import into a TPM.
        /// Depending on the type of key, the software root key can be a parent for
        /// other root keys that can comprise a migration group.  The caller should
        /// specify necessary key parameters in Public.
        ///
        /// Parameter keyData is used only with symmetric or HMAC keys. If non-null
        /// on entry, it contains the key bytes supplied by the caller, otherwise the
        /// key will be randomly generated. For asymmetric keys keyData must be null.
        /// 
        /// Parameter authVal specifies the authorization value associated with the key.
        /// If it is null, then an random value will be used.
        /// </summary>
        /// <param name="pub"></param>
        /// <param name="authVal"></param>
        /// <param name="keyData"></param>
        /// <returns></returns>
        public static TssObject Create(TpmPublic pub,
                                       AuthValue authVal = null,
                                       byte[] keyData = null)
        {
            var newKey = new TssObject();

            // Create a new key from the supplied parameters
            IPublicIdUnion publicId;
            var sensData = CreateSensitiveComposite(pub, ref keyData, out publicId);

            var nameSize = CryptoLib.DigestSize(pub.nameAlg);

            // Create the associated seed value
            byte[] seed = Globs.GetRandomBytes(nameSize);

            // Fill in the fields for the symmetric private-part of the asymmetric key
            var sens = new Sensitive(authVal ?? AuthValue.FromRandom(nameSize),
                                     seed, sensData);
            newKey.Sensitive = sens;
            newKey.Private = new TpmPrivate(sens.GetTpm2BRepresentation());

            // fill in the public data
            newKey.Public = pub.Copy();

            if (pub.type == TpmAlgId.Keyedhash || pub.type == TpmAlgId.Symcipher)
            {
                byte[] unique = null;
                if (pub.objectAttributes.HasFlag(ObjectAttr.Restricted | ObjectAttr.Decrypt))
                {
                    unique = CryptoLib.Hmac(pub.nameAlg, seed, keyData);
                }
                else
                {
                    unique = CryptoLib.HashData(pub.nameAlg, seed, keyData);
                }
                newKey.Public.unique = pub.type == TpmAlgId.Keyedhash
                                     ? new Tpm2bDigestKeyedhash(unique) as IPublicIdUnion
                                     : new Tpm2bDigestSymcipher(unique);
            }
            else
            {
                newKey.Public.unique = publicId;
            }

            // And return the new key
            return newKey;
        }

        /// <summary>
        /// Creates a Private area for this key so that it can be loaded into a TPM by
        /// TPM2_Load() if the target TPM already has the storage key 'parent' loaded.
        /// This function lets an application to create key hierarchies in software
        /// that can be loaded into a TPM once the parent has been TPM2_Import'ed.
        /// TPM2_Import() supports plaintext import. To get this sort of import blob,
        /// set 'parent' to null.
        /// </summary>
        /// <param name="parent"></param>
        /// <returns></returns>
        public TpmPrivate GetPrivate(TssObject parent)
        {
            SymDefObject symDef = GetSymDef(parent.Public);

            // Figure out how many bits we will need from the KDF
            byte[] parentSymSeed = parent.Sensitive.seedValue;
            Transform(parentSymSeed);
            byte[] iv = (symDef.Mode == TpmAlgId.Ecb) ? new byte[0]
                                : Globs.GetRandomBytes(SymCipher.GetBlockSize(symDef));

            // The encryption key is calculated with a KDF
            byte[] symKey = KDF.KDFa(parent.Public.nameAlg,
                                     parentSymSeed,
                                     "STORAGE",
                                     GetName(),
                                     new byte[0],
                                     symDef.KeyBits);

            Transform(symKey);

            byte[] newPrivate = KeyWrapper.CreatePrivateFromSensitive(
                                                symDef,
                                                symKey,
                                                iv,
                                                Sensitive,
                                                Public.nameAlg,
                                                Public.GetName(),
                                                parent.Public.nameAlg,
                                                parent.Sensitive.seedValue,
                                                TransformerCallback);
            Transform(newPrivate);
            return new TpmPrivate(newPrivate);
        }

        /// <summary>
        /// Create a plaintext duplication blob that can be imported into a TPM
        /// </summary>
        /// <returns></returns>
        public TpmPrivate GetPlaintextDuplicationBlob()
        {
            return new TpmPrivate(Sensitive.GetTpm2BRepresentation());
        }

        public static byte[] LastSeed = new byte[0];

        /// <summary>
        /// Creates a duplication blob for the current key that can be Imported as a child
        /// of newParent. Three forms are possible. GetPlaintextDuplicationBlob() allows
        /// plaintext-import. This function enables duplication with and without an
        /// inner wrapper (depending on whether innerWrapper is null)
        /// </summary>
        /// <param name="newParent"></param>
        /// <param name="innerWrapper"></param>
        /// <param name="encSecret"></param>
        /// <returns></returns>
        public TpmPrivate GetDuplicationBlob(
            TpmPublic pubNewParent,
            SymCipher innerWrapper,
            out byte[] encSecret)
        {
            byte[] encSensitive;
            if (innerWrapper == null)
            {
                // No inner wrapper
                encSensitive = Marshaller.ToTpm2B(Sensitive.GetTpmRepresentation());
                Transform(encSensitive);
            }
            else
            {
                byte[] sens = Marshaller.ToTpm2B(Sensitive.GetTpmRepresentation());
                byte[] toHash = Globs.Concatenate(sens, GetName());
                Transform(toHash);
                byte[] innerIntegrity = Marshaller.ToTpm2B(CryptoLib.HashData(
                                                            Public.nameAlg, toHash));
                byte[] innerData = Globs.Concatenate(innerIntegrity, sens);
                Transform(innerData);
                encSensitive = innerWrapper.Encrypt(innerData);
                Transform(encSensitive);
            }

            byte[] seed;
            SymDefObject symDef = GetSymDef(pubNewParent).Copy();
            // TPM duplication procedures always use CFB mode
            symDef.Mode = TpmAlgId.Cfb;

            using (var swNewParent = AsymCryptoSystem.CreateFrom(pubNewParent))
            {
                switch (pubNewParent.type)
                {
                case TpmAlgId.Rsa:
                    // The seed should be the same size as the scheme hash
                    LastSeed =
                        seed = Globs.GetRandomBytes(
                                        CryptoLib.DigestSize(swNewParent.OaepHash));
                    encSecret = swNewParent.EncryptOaep(seed, DuplicateEncodingParms);
                    break;
                case TpmAlgId.Ecc:
                    EccPoint pubEphem;
                    if (swNewParent == null)
                    {
                        encSecret = null;
                        return null;
                    }
                    seed = swNewParent.EcdhGetKeyExchangeKey(DuplicateEncodingParms,
                                                             pubNewParent.nameAlg,
                                                             out pubEphem);
                    encSecret = Marshaller.GetTpmRepresentation(pubEphem);
                    break;
                default:
                    Globs.Throw<NotImplementedException>(
                                        "GetDuplicationBlob: Unsupported algorithm");
                    encSecret = new byte[0];
                    return new TpmPrivate();
                }
            }
            Transform(seed);
            Transform(encSecret);

            byte[] symKey = KDF.KDFa(pubNewParent.nameAlg, seed, "STORAGE",
                                     Public.GetName(), new byte[0], symDef.KeyBits);
            Transform(symKey);

            byte[] dupSensitive;
            using (SymCipher enc2 = SymCipher.Create(symDef, symKey))
            {
                if (enc2 == null)
                    return null;

                dupSensitive = enc2.Encrypt(encSensitive);
            }
            Transform(dupSensitive);

            var npNameNumBits = CryptoLib.DigestSize(pubNewParent.nameAlg) * 8;
            byte[] hmacKey = KDF.KDFa(pubNewParent.nameAlg, seed, "INTEGRITY",
                                      new byte[0], new byte[0], npNameNumBits);

            byte[] outerDataToHmac = Globs.Concatenate(dupSensitive, Public.GetName());
            Transform(outerDataToHmac);

            byte[] outerHmac = Marshaller.ToTpm2B(CryptoLib.Hmac(pubNewParent.nameAlg,
                                                                hmacKey, outerDataToHmac));
            Transform(outerHmac);

            byte[] dupBlob = Globs.Concatenate(outerHmac, dupSensitive);
            Transform(dupBlob);

            return new TpmPrivate(dupBlob);
        }

        /// <summary>
        /// Create a new asymmetric key based on the parameters in keyParms.
        ///
        /// Parameter keyData is used only with symmetric or HMAC keys. If non-null
        /// on entry, it contains the key bytes supplied by the caller, otherwise the
        /// key will be randomly generated, and returned via keyData. For asymmetric
        /// keys keyData must be null.
        ///
        /// The result data are returned in structures suitable for incorporation into
        /// </summary>
        /// <param name="pub"></param>
        /// <param name="keyData"></param>
        /// <param name="publicParms"></param>
        /// <returns></returns>
        internal static ISensitiveCompositeUnion
            CreateSensitiveComposite(TpmPublic pub,
                                     ref byte[] keyData,
                                     out IPublicIdUnion publicId)
        {
            ISensitiveCompositeUnion newSens = null;
            publicId = null;

            if (pub.type == TpmAlgId.Rsa)
            {
                if (keyData != null)
                {
                    newSens = new Tpm2bPrivateKeyRsa(keyData);
                    publicId = pub.unique;
                }
                else
                {
                    var newKeyPair = new RawRsa((pub.parameters as RsaParms).keyBits);

                    // Put the key bits into the required structure envelopes
                    newSens = new Tpm2bPrivateKeyRsa(newKeyPair.Private);
                    publicId = new Tpm2bPublicKeyRsa(newKeyPair.Public);
                }
            }
            else if (pub.type == TpmAlgId.Symcipher)
            {
                var symDef = (SymDefObject)pub.parameters;
                if (symDef.Algorithm != TpmAlgId.Aes)
                {
                    Globs.Throw<ArgumentException>("Unsupported symmetric algorithm");
                    return null;
                }

                int keySize = (symDef.KeyBits + 7) / 8;
                if (keyData == null)
                {
                    keyData = Globs.GetRandomBytes(keySize);
                }
                else if (keyData.Length != keySize)
                {
                    keyData = Globs.CopyData(keyData);
                }
                else
                {
                    Globs.Throw<ArgumentException>("Wrong symmetric key length");
                    return null;
                }
                newSens = new Tpm2bSymKey(keyData);
            }
            else if (pub.type == TpmAlgId.Keyedhash)
            {
                var scheme = (pub.parameters as KeyedhashParms).scheme;
                TpmAlgId hashAlg = scheme is SchemeHash ? (scheme as SchemeHash).hashAlg
                                 : scheme is SchemeXor  ? (scheme as SchemeXor).hashAlg
                                                        : pub.nameAlg;
                var digestSize = CryptoLib.DigestSize(hashAlg);

                if (keyData == null)
                {
                    keyData = Globs.GetRandomBytes(digestSize);
                }
                else if (keyData.Length <= CryptoLib.BlockSize(hashAlg))
                {
                    keyData = Globs.CopyData(keyData);
                }
                else
                {
                    Globs.Throw<ArgumentException>("HMAC key is too big");
                    return null;
                }
                newSens = new Tpm2bSensitiveData(keyData);
            }
            else
            {
                Globs.Throw<ArgumentException>("Unsupported key type");
            }

            return newSens;
        }

        /// <summary>
        /// Get the name of the associated public object
        /// </summary>
        /// <returns></returns>
        public byte[] GetName()
        {
            return Public.GetName();
        }

        /// <summary>
        /// Extract and return the SymDefObject that describes the symmetric
        /// algorithm used for key protection in storage keys.
        /// </summary>
        /// <returns></returns>
        public SymDefObject GetSymDef()
        {
            return TssObject.GetSymDef(Public);
        }

        /// <summary>
        /// Extract and return the SymDefObject that describes the associated symmetric
        /// algorithm that is used for key protection in storage keys.
        /// </summary>
        /// <param name="keyParms"></param>
        /// <returns></returns>
        internal static SymDefObject GetSymDef(TpmPublic keyParms)
        {
            TpmAlgId keyAlgId = keyParms.type;
            switch (keyAlgId)
            {
                case TpmAlgId.Rsa:
                    var rsaParms = (RsaParms)keyParms.parameters;
                    return rsaParms.symmetric;
                case TpmAlgId.Ecc:
                    var eccParms = (EccParms)keyParms.parameters;
                    return eccParms.symmetric;
                case TpmAlgId.Symcipher:
                    return keyParms.parameters is SymcipherParms
                                        ? (keyParms.parameters as SymcipherParms).sym
                                        : keyParms.parameters as SymDefObject;
                default:
                    Globs.Throw("Unsupported key type");
                    return new SymDefObject();
            }
        }

        /// <summary>
        /// The TPM always signs hash-sized data. This version of the VerifySignature
        /// performs the necessary hashing operation over arbitrarily-length data and
        /// verifies that the hash is properly signed.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="sig"></param>
        /// <returns></returns>
        public bool VerifySignatureOverData(byte[] data, ISignatureUnion sig)
        {
            byte[] digest = CryptoLib.HashData(CryptoLib.SchemeHash(sig), data);
            return VerifySignatureOverHash(digest, sig);
        }

        /// <summary>
        /// Verify a TPM signature structure of the hash of some data (caller hashes
        /// the data that will be verified).
        /// </summary>
        /// <param name="digest"></param>
        /// <param name="sig"></param>
        /// <returns></returns>
        public bool VerifySignatureOverHash(byte[] digest, ISignatureUnion sig)
        {
            if (Public.type == TpmAlgId.Keyedhash)
            {
                byte[] hmacKey = (Sensitive.sensitive as Tpm2bSensitiveData).buffer;
                return CryptoLib.VerifyHmac(CryptoLib.SchemeHash(sig),
                                            hmacKey, digest, (TpmHash)sig);
            }
            else
            {
                return Public.VerifySignatureOverHash(digest, sig);
            }
        }

        /// <summary>
        /// Encoding parameters for key duplication and import
        /// </summary>
        private static readonly byte[] DuplicateEncodingParms =
                                                Encoding.UTF8.GetBytes("DUPLICATE\0");

        /// <summary>
        /// Encoding parameters for objects in the storage hierarchy
        /// </summary>
        public static byte[] SecretEncodingParms = Encoding.UTF8.GetBytes("SECRET\0");
    } // class TssObject
}

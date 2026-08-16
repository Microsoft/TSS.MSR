use crate::crypto::{provider::CryptoProvider, Crypto, RsaKeyParts, RSA_DEFAULT_EXPONENT};
use crate::error::TpmError;
use crate::tpm2_helpers::int_to_tpm;
use crate::tpm_buffer::*;
use crate::tpm_structure::TpmEnum;
use crate::tpm_types::CertifyResponse;
use crate::tpm_types::*;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Activation data returned from create_activation
#[derive(Debug)]
pub struct ActivationData {
    pub credential_blob: TPMS_ID_OBJECT,
    pub secret: Vec<u8>, // Encrypted seed (ENCRYPTED_SECRET)
}

/// A [`TPMT_PUBLIC`] the caller has decided to trust, paired with its locally derived Name.
///
/// # What this type does and does not mean
///
/// `TrustedPublic` records a **caller-asserted** trust decision and nothing more. It exists so
/// that the decision is made once, in one greppable place, instead of being implied by whatever
/// public area happened to be in scope at the call site.
///
/// It is **not** a channel-authentication mechanism: nothing here authenticates the transport
/// the public area travelled over, and constructing one does not make a subsequent exchange
/// with the TPM authenticated.
///
/// It is **not** proof of TPM residency: nothing here shows that the private half of this key
/// is held by a TPM, or by *the* TPM you are talking to. A public area is just bytes, and the
/// Name is a digest over those same bytes, so an adversary who chooses the public area also
/// chooses its Name.
///
/// What it is worth depends entirely on where the expected Name came from:
///
/// * [`TrustedPublic::from_pinned_name`] is meaningful when the expected Name was obtained out
///   of band — burned into an image, shipped in a signed manifest, recorded at enrolment time
///   on a channel you trusted then. It rejects any public area that does not hash to that Name.
/// * [`TrustedPublic::assume_trusted`] asserts trust with no evidence at all. It is the right
///   call for a locally generated key you just created yourself, and the wrong call for
///   anything that arrived over a channel an adversary can reach.
#[derive(Clone, Debug)]
pub struct TrustedPublic {
    public: TPMT_PUBLIC,
    name: Vec<u8>,
}

impl TrustedPublic {
    /// Accept `public` only if it hashes to `expected_name`.
    ///
    /// The Name is recomputed locally with [`TPMT_PUBLIC::get_name`] and compared; a mismatch is
    /// an error. The strength of the result is exactly the strength of `expected_name`'s
    /// provenance — see the type-level documentation.
    pub fn from_pinned_name(
        public: TPMT_PUBLIC,
        expected_name: &[u8],
        crypto: &CryptoProvider,
    ) -> Result<Self, TpmError> {
        if expected_name.is_empty() {
            return Err(TpmError::InvalidParameter);
        }
        public.verify_name(expected_name, crypto)?;
        let name = public.get_name(crypto)?;
        Ok(Self { public, name })
    }

    /// Accept `public` on the caller's say-so, with nothing checked.
    ///
    /// Deliberately loud, and deliberately easy to grep for. Reach for this only when the public
    /// area cannot have been chosen by an adversary — a key this process just created, or one
    /// read back over a channel that is already authenticated by other means. If you cannot
    /// name the reason, use [`TrustedPublic::from_pinned_name`] instead.
    pub fn assume_trusted(public: TPMT_PUBLIC, crypto: &CryptoProvider) -> Result<Self, TpmError> {
        let name = public.get_name(crypto)?;
        Ok(Self { public, name })
    }

    /// Accept `public` on the strength of a credential a TPM could only have recovered by
    /// holding the named object.
    ///
    /// This is the `TPM2_MakeCredential` / `TPM2_ActivateCredential` exchange: a credential of
    /// the caller's choosing is encrypted to a storage key's public area — an endorsement key,
    /// normally — naming the object evidence is wanted for, and the TPM returns the credential
    /// only if it holds both that storage key and an object with that Name.
    ///
    /// `activated_name` is the Name given to [`TPMT_PUBLIC::create_activation`], and
    /// `recovered_credential` is what `TPM2_ActivateCredential` returned. Two things are
    /// checked: that `public` really is the public area of the object the credential was bound
    /// to, and that the credential came back intact. The first catches the easy mistake of
    /// naming one object and then trusting another's public area.
    ///
    /// What the result is worth rests on two things this function cannot see and the caller must
    /// get right:
    ///
    /// * **the storage key's own provenance.** Credential activation moves trust from the
    ///   storage key to the named object; it does not create any. If the endorsement key's
    ///   public area was itself taken on faith, so is everything derived here. Chain it to a
    ///   manufacturer's EK certificate.
    /// * **the credential's unpredictability.** Anyone who can guess it can answer without a
    ///   TPM, so use bytes freshly generated at random for this one exchange.
    pub fn from_activated_credential(
        public: TPMT_PUBLIC,
        activated_name: &[u8],
        credential: &[u8],
        recovered_credential: &[u8],
        crypto: &CryptoProvider,
    ) -> Result<Self, TpmError> {
        if credential.is_empty() {
            return Err(TpmError::InvalidParameter);
        }

        // Compared in constant time: the caller supplies the credential, and the TPM's answer
        // arrives from wherever the TPM is. Neither should be able to be recovered a byte at a
        // time by an adversary who can submit answers and watch how long the rejection takes.
        if !bool::from(credential.ct_eq(recovered_credential)) {
            return Err(TpmError::VerificationFailed(
                "Activation did not recover the credential it was made from".to_string(),
            ));
        }

        Self::from_pinned_name(public, activated_name, crypto)
    }

    /// The public area.
    pub fn public(&self) -> &TPMT_PUBLIC {
        &self.public
    }

    /// The Name derived from the public area, `nameAlg || H_nameAlg(publicArea)`.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Check a `TPM2_Certify` attestation this key signed over `certified_key`.
    ///
    /// # The signing key's provenance is a precondition, not a result
    ///
    /// The caller is responsible for establishing out of band that this signing key is the key
    /// it means, **before** calling this function. The two usual ways are credential activation
    /// against an endorsement key whose certificate chains to a manufacturer root — see
    /// [`TrustedPublic::from_activated_credential`] — and validating an attestation key
    /// certificate issued by a CA the caller already trusts, pinning the Name it carries with
    /// [`TrustedPublic::from_pinned_name`].
    ///
    /// Nothing here substitutes for that. Every value this function inspects reaches it from
    /// the same untrusted source: the attestation, the signature, and the signing key's own
    /// `objectAttributes` all travel together, so an adversary who fabricates a public area and
    /// an attestation to match satisfies all of these checks at once. This function does not
    /// authenticate a channel, does not defeat an adversary sitting on one, and does not show
    /// that the private half of the signing key lives in a TPM — let alone in the TPM you
    /// believe you are talking to.
    ///
    /// What it does establish, *given* that provenance: the key you already decided to trust
    /// signed this attestation, the attestation is bound to `nonce`, and it names
    /// `certified_key`. A zero-length `nonce` is accepted and carries no freshness — supply
    /// bytes you generated at random for this exchange if replay is a concern.
    ///
    /// # What is checked
    ///
    /// * the signing key's attributes are fit for attestation (defense in depth — see
    ///   [`TrustedPublic::check_attestation_key_attributes`]);
    /// * `magic` is `TPM_GENERATED_VALUE`;
    /// * `extraData` is `nonce`;
    /// * the attested body is a `certify`, and the Name it carries is `certified_key`'s;
    /// * the signature's hash algorithm is the one the signing key's scheme names;
    /// * the signature verifies over the marshalled attestation.
    ///
    /// Every failure is an `Err`: [`TpmError::VerificationFailed`] when a check did not pass and
    /// [`TpmError::NotSupported`] when the signature uses an algorithm this crate cannot verify.
    /// There is no success value to drop, so no caller can mistake a failed check for a pass.
    pub fn validate_certify(
        &self,
        crypto: &CryptoProvider,
        certified_key: &TPMT_PUBLIC,
        nonce: &[u8],
        certify_response: &CertifyResponse,
    ) -> Result<(), TpmError> {
        self.check_attestation_key_attributes()?;

        let attest = &certify_response.certifyInfo;

        // Everything from here to the algorithm dispatch below is deliberately hoisted above it.
        // These are the checks that give an attestation its meaning, and they are defined on the
        // attestation alone, so no signature algorithm has any business reaching a success path
        // without them. An earlier version dispatched first and delegated the non-RSASSA case to
        // the signature verifier with an empty digest, which skipped all of them; it was not
        // exploitable only because that verifier happened to reject the same cases for its own
        // reasons. Keep the order: structure first, then cryptography.
        if attest.magic != TPM_GENERATED::VALUE {
            return Err(TpmError::VerificationFailed(format!(
                "Certify: magic is 0x{:X}, not TPM_GENERATED_VALUE",
                attest.magic.0
            )));
        }

        if attest.extraData != nonce {
            return Err(TpmError::VerificationFailed(
                "Certify: extraData does not carry the nonce supplied".to_string(),
            ));
        }

        let Some(TPMU_ATTEST::certify(certify_info)) = &attest.attested else {
            return Err(TpmError::VerificationFailed(
                "Certify: the attested body is not a TPMS_CERTIFY_INFO".to_string(),
            ));
        };

        if certify_info.name != certified_key.get_name(crypto)? {
            return Err(TpmError::VerificationFailed(
                "Certify: the attestation names a different object than the key supplied"
                    .to_string(),
            ));
        }

        let Some(TPMU_SIGNATURE::rsassa(signature)) = &certify_response.signature else {
            return Err(TpmError::NotSupported(
                "Certify: only RSASSA signatures can be validated".to_string(),
            ));
        };

        if self.public.get_signing_hash_alg()? != signature.hash {
            return Err(TpmError::VerificationFailed(
                "Certify: the signature's hash algorithm is not the one the key's scheme names"
                    .to_string(),
            ));
        }

        let signed_blob = {
            let mut buffer = TpmBuffer::new(None);
            attest.toTpm(&mut buffer)?;
            buffer.trim().to_vec()
        };
        let signed_blob_hash = Crypto::hash(crypto, signature.hash, &signed_blob)?;

        if !Crypto::validate_signature(
            crypto,
            &self.public,
            signed_blob_hash,
            &certify_response.signature,
        )? {
            return Err(TpmError::VerificationFailed(
                "Certify: the signature over the attestation is invalid".to_string(),
            ));
        }

        Ok(())
    }

    /// Reject a signing key whose attributes make an attestation it signs worthless.
    ///
    /// **Defense in depth, and nothing more.** `objectAttributes` sits in the same public area
    /// as everything else the caller was handed, so an adversary who fabricates a public area
    /// simply sets these bits. Reading them proves nothing about provenance and cannot stand in
    /// for establishing it. These checks are meaningful only once the key's provenance has been
    /// settled out of band, and what they then catch is an honest mistake: a key that genuinely
    /// is the one that was pinned, but created from a template unfit for attestation.
    ///
    /// * `restricted` is the load-bearing one, because it is what gives the
    ///   `magic == TPM_GENERATED_VALUE` check any content. A TPM will not produce the hash
    ///   validation ticket that `TPM2_Sign` demands of a restricted key when the data hashed
    ///   begins with `TPM_GENERATED_VALUE` (TPM 2.0 Part 3, `TPM2_Hash` and
    ///   `TPM2_SequenceComplete`), so a restricted key signs no externally supplied structure
    ///   that could be mistaken for an attestation. An **unrestricted** key signs anything put
    ///   in front of it, hand-written `TPMS_ATTEST` included, and the magic check becomes a
    ///   check that the attacker remembered a constant.
    /// * `sign` because a key without it is not a signing key at all.
    /// * `fixedTPM` and `fixedParent` are what a TPM sets on a key that cannot be duplicated out
    ///   of its hierarchy. Requiring them rejects a key whose private half may lawfully have
    ///   been copied elsewhere — which would make an attestation say nothing about *which*
    ///   TPM produced it. Like the rest, this is the public area's own claim about itself.
    pub fn check_attestation_key_attributes(&self) -> Result<(), TpmError> {
        let attributes = self.public.objectAttributes;

        for (required, name) in [
            (TPMA_OBJECT::restricted, "restricted"),
            (TPMA_OBJECT::sign, "sign"),
            (TPMA_OBJECT::fixedTPM, "fixedTPM"),
            (TPMA_OBJECT::fixedParent, "fixedParent"),
        ] {
            if attributes.0 & required.0 == 0 {
                return Err(TpmError::VerificationFailed(format!(
                    "Certify: the signing key does not have {} set, so it is unfit to attest",
                    name
                )));
            }
        }

        Ok(())
    }
}

impl TPMS_RSA_PARMS {
    /// The public exponent as big-endian bytes with no leading zeros.
    ///
    /// The TPM encodes the default exponent of 2^16 + 1 as zero, so a stored zero is resolved
    /// here rather than by rewriting the field. That distinction matters: a key's Name is a
    /// digest over its whole public area, so normalising a stored zero to 65537 would change
    /// the Name of every key that uses the default and silently break every policy digest,
    /// `TPM2_ActivateCredential` and handle-to-Name comparison that depends on it. Resolve at
    /// the point of use, never in the structure.
    pub fn exponent_bytes(&self) -> Vec<u8> {
        if self.exponent == 0 {
            return RSA_DEFAULT_EXPONENT.to_vec();
        }

        // The exponent is non-zero, so at least one byte survives.
        self.exponent
            .to_be_bytes()
            .iter()
            .skip_while(|&&byte| byte == 0)
            .copied()
            .collect()
    }
}

impl TPMT_PUBLIC {
    pub fn get_name(&self, crypto: &CryptoProvider) -> Result<Vec<u8>, TpmError> {
        let mut buffer = TpmBuffer::new(None);
        self.toTpm(&mut buffer)?;

        let mut pub_hash = Crypto::hash(crypto, self.nameAlg, buffer.trim())?;
        let hash_alg = int_to_tpm(self.nameAlg.get_value());

        pub_hash.splice(0..0, hash_alg.iter().cloned());

        Ok(pub_hash)
    }

    /// Recompute this public area's Name and check it against `expected`.
    ///
    /// The Name of a TPM object is `nameAlg || H_nameAlg(publicArea)`, so it is a value the
    /// caller can derive locally from the public area alone. Verifying it proves only that the
    /// public area in hand is the one the expected Name commits to. It proves nothing about
    /// where that public area came from, and nothing about the channel it arrived over.
    ///
    /// A mismatch is [`TpmError::VerificationFailed`], the variant every other check on
    /// attacker-reachable data in this API uses, so a caller can tell an untrusted public area
    /// from an operational failure without reading the message.
    pub fn verify_name(&self, expected: &[u8], crypto: &CryptoProvider) -> Result<(), TpmError> {
        let actual = self.get_name(crypto)?;
        if actual != expected {
            return Err(TpmError::VerificationFailed(
                "TPMT_PUBLIC Name does not match the expected Name".to_string(),
            ));
        }
        Ok(())
    }

    pub fn get_signing_hash_alg(&self) -> Result<TPM_ALG_ID, TpmError> {
        let rsa_params = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(rsa_params)) = &self.parameters {
            rsa_params
        } else {
            return Err(TpmError::NotSupported(
                "Get signing hash algorithm is only supported for RSA".to_string(),
            ));
        };

        let scheme = if let Some(TPMU_ASYM_SCHEME::rsassa(scheme)) = &rsa_params.scheme {
            scheme
        } else {
            return Err(TpmError::NotSupported(
                "Get signing hash algorithm is only supported for RSA-SSA".to_string(),
            ));
        };

        Ok(scheme.hashAlg)
    }

    /// Implements the TPM2_MakeCredential command functionality:
    /// 1. Establish a seed and the secret that conveys it to the TPM
    /// 2. Derive symmetric key via KDFa
    /// 3. Encrypt credential + create integrity HMAC
    ///
    /// Both RSA and ECC storage keys are accepted. The two differ only in how the seed reaches the
    /// TPM, which [`Self::produce_seed`] handles; everything after that is defined on the seed
    /// alone and so is shared.
    pub fn create_activation(
        &self,
        crypto: &CryptoProvider,
        credential: &[u8],
        activated_name: &[u8],
    ) -> Result<ActivationData, TpmError> {
        // The wrapping scheme lives in the algorithm-specific parameters, but the constraint on it
        // is the same either way, so it is checked once here.
        let sym_def = match &self.parameters {
            Some(TPMU_PUBLIC_PARMS::rsaDetail(params)) => &params.symmetric,
            Some(TPMU_PUBLIC_PARMS::eccDetail(params)) => &params.symmetric,
            _ => {
                return Err(TpmError::NotSupported(
                    "Activation requires an RSA or ECC storage key".to_string(),
                ))
            }
        };

        if sym_def.algorithm != TPM_ALG_ID::AES
            || sym_def.keyBits != 128
            || sym_def.mode != TPM_ALG_ID::CFB
        {
            return Err(TpmError::NotSupported(
                "Unsupported wrapping scheme".to_string(),
            ));
        }

        // The seed is the same size as the nameAlg digest, per TPM 2.0 Part 1 "Credential
        // Protection". TSS.NET does the same in TpmKey.CreateActivationCredentials.
        let name_alg_size = Crypto::digest_size_checked(self.nameAlg)?;
        let (mut seed, secret) = self.produce_seed(crypto, name_alg_size)?;

        // Make the credential blob:

        // 1. Create the symmetric key via KDFa
        let mut sym_key = Crypto::kdfa(
            crypto,
            self.nameAlg,
            &seed,
            "STORAGE",
            activated_name,
            &[],
            128, // 128-bit AES key
        )?;

        // 2. Take credential and prepend size
        let mut credential_with_size = Vec::with_capacity(2 + credential.len());
        credential_with_size.extend_from_slice(&(credential.len() as u16).to_be_bytes());
        credential_with_size.extend_from_slice(credential);

        // 3. Encrypt the credential
        let enc_credential = Crypto::cfb_xcrypt(
            crypto,
            true,
            &sym_key,
            &[0u8; 16], // Zero IV
            &credential_with_size,
        )?;

        // 4. Generate the integrity HMAC key
        let mut hmac_key = Crypto::kdfa(
            crypto,
            self.nameAlg,
            &seed,
            "INTEGRITY",
            &[],
            &[],
            name_alg_size * 8,
        )?;

        // 5. Calculate outer HMAC
        let mut to_hmac = Vec::new();
        to_hmac.extend_from_slice(&enc_credential);
        to_hmac.extend_from_slice(activated_name);

        let integrity_hmac = Crypto::hmac(crypto, self.nameAlg, &hmac_key, &to_hmac)?;

        // Cleanup sensitive data
        seed.zeroize();
        hmac_key.zeroize();
        sym_key.zeroize();

        Ok(ActivationData {
            credential_blob: TPMS_ID_OBJECT::new(&integrity_hmac, &enc_credential),
            secret,
        })
    }

    /// Establishes the activation seed and the `secret` that lets this key's TPM recover it.
    ///
    /// This is the whole of the difference between an RSA and an ECC activation. With RSA the seed
    /// is chosen at random and the secret is that seed encrypted to the public key. With ECC no
    /// value is transported at all: both sides derive the seed from an ECDH agreement, and the
    /// secret is the ephemeral public point the TPM needs to repeat that agreement.
    ///
    /// Returns the seed and the secret, in that order.
    fn produce_seed(
        &self,
        crypto: &CryptoProvider,
        name_alg_size: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
        match (&self.parameters, &self.unique) {
            (Some(TPMU_PUBLIC_PARMS::rsaDetail(params)), Some(TPMU_PUBLIC_ID::rsa(unique))) => {
                let seed = Crypto::get_random(crypto, name_alg_size)?;

                // Encrypt seed with label "IDENTITY" using OAEP with the key's nameAlg
                let secret = Crypto::rsa_oaep_encrypt(
                    crypto,
                    &unique.buffer,
                    &params.exponent_bytes(),
                    self.nameAlg,
                    b"IDENTITY\0",
                    &seed,
                )?;

                Ok((seed, secret))
            }

            (Some(TPMU_PUBLIC_PARMS::eccDetail(params)), Some(TPMU_PUBLIC_ID::ecc(point))) => {
                let curve = params.curveID;
                let agreement = Crypto::ecc_ephemeral_agree(crypto, curve, &point.x, &point.y)?;

                // KDFe hashes this coordinate, so one the TPM marshalled without its leading zeroes
                // has to be restored to full width or the two sides hash different inputs and
                // derive different seeds.
                let width = Crypto::ecc_coordinate_size(curve)?;
                let party_v_info = Crypto::pad_ecc_coordinate(&point.x, width)?;

                // partyU is the initiator, which is this side, and partyV the key's owner. The TPM
                // makes the same assignment when it repeats the agreement, even though its own
                // role is the opposite one.
                let seed = Crypto::kdfe(
                    crypto,
                    self.nameAlg,
                    &agreement.z,
                    "IDENTITY",
                    &agreement.ephemeral_x,
                    &party_v_info,
                    name_alg_size * 8,
                )?;

                // The secret is the ephemeral point marshalled as a TPMS_ECC_POINT, so each
                // coordinate carries its own size. It is not a bare concatenation.
                let secret = TPMS_ECC_POINT::new(&agreement.ephemeral_x, &agreement.ephemeral_y)
                    .toBytes()?;

                Ok((seed, secret))
            }

            _ => Err(TpmError::NotSupported(format!(
                "Activation is not supported for a public area whose parameters are {:?} and \
                 whose unique field is {:?}",
                self.parameters.as_ref().map(std::mem::discriminant),
                self.unique.as_ref().map(std::mem::discriminant),
            ))),
        }
    }

    // Performs RSA encryption of the given data using the public key
    pub fn encrypt(&self, crypto: &CryptoProvider, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        // Verify we have an RSA key with correct parameters
        let rsa_params = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(params)) = &self.parameters {
            params
        } else {
            return Err(TpmError::NotSupported(
                "Only RSA encryption supported".to_string(),
            ));
        };

        // Check symmetric definition
        let sym_def = &rsa_params.symmetric;
        if sym_def.algorithm != TPM_ALG_ID::AES
            || sym_def.keyBits != 128
            || sym_def.mode != TPM_ALG_ID::CFB
        {
            return Err(TpmError::NotSupported(
                "Unsupported wrapping scheme".to_string(),
            ));
        }

        // Get RSA public key components
        let rsa_pub_n = if let Some(TPMU_PUBLIC_ID::rsa(unique)) = &self.unique {
            &unique.buffer
        } else {
            return Err(TpmError::NotSupported("Invalid RSA public key".to_string()));
        };

        // Encrypt the data using OAEP padding with the key's nameAlg
        Crypto::rsa_oaep_encrypt(
            crypto,
            rsa_pub_n,
            &rsa_params.exponent_bytes(),
            self.nameAlg,
            b"IDENTITY\0",
            data,
        )
    }

    /// Encrypt a session salt for use with salted auth sessions.
    /// Uses RSA-OAEP with the nameAlg hash and label "SECRET\0".
    pub fn encrypt_session_salt(
        &self,
        crypto: &CryptoProvider,
        salt: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let rsa_params = if let Some(TPMU_PUBLIC_PARMS::rsaDetail(params)) = &self.parameters {
            params
        } else {
            return Err(TpmError::NotSupported(
                "Only RSA keys can encrypt session salt".to_string(),
            ));
        };

        let rsa_pub_n = if let Some(TPMU_PUBLIC_ID::rsa(unique)) = &self.unique {
            &unique.buffer
        } else {
            return Err(TpmError::NotSupported(
                "Only RSA keys can encrypt session salt".to_string(),
            ));
        };

        Crypto::rsa_oaep_encrypt(
            crypto,
            rsa_pub_n,
            &rsa_params.exponent_bytes(),
            self.nameAlg,
            b"SECRET\0",
            salt,
        )
    }
}

impl TPMS_PCR_SELECTION {
    /// The smallest `pcrSelect` a valid selection carries, whatever it names.
    ///
    /// `PCR_SELECT_MIN` in the TPM 2.0 specification: three bytes, enough for the 24 PCRs a
    /// PC Client platform defines. A shorter selection is not a valid `TPMS_PCR_SELECTION`, so
    /// every selection built here is at least this long even when it names PCR 0.
    pub const MIN_PCR_SELECT_BYTES: usize = 3;

    /// The longest `pcrSelect` this structure can carry on the wire.
    ///
    /// `TPMS_PCR_SELECTION` marshals `pcrSelect` with a **one-byte** size prefix — see
    /// `buf.writeSizedByteBuf(&self.pcrSelect, 1)` in the generated `tpm_types.rs` — so a longer
    /// selection cannot be expressed. `TpmBuffer::writeSizedByteBuf` fails the marshal rather
    /// than truncating the length, so nothing is silently mis-sent, but a selection that cannot
    /// be marshalled is of no use to anyone and there is no reason to build one.
    pub const MAX_PCR_SELECT_BYTES: usize = u8::MAX as usize;

    /// The largest PCR index any `TPMS_PCR_SELECTION` can name: 2039.
    ///
    /// It follows from [`Self::MAX_PCR_SELECT_BYTES`]: the last representable bit is bit 7 of
    /// byte 254. Real TPMs implement far fewer PCRs — 24 on a PC Client platform — so this is a
    /// bound on what the wire format can express, not a promise that any TPM has that many.
    pub const MAX_PCR_INDEX: u32 = (Self::MAX_PCR_SELECT_BYTES as u32) * 8 - 1;

    /// The `pcrSelect` byte holding `pcr`'s bit, or an error if no selection can hold it.
    ///
    /// Checked **before** anything is allocated. Sizing the array from an unchecked `pcr` lets
    /// a caller that took the index from a configuration file or off the network ask for
    /// `u32::MAX / 8 + 1` bytes — half a gigabyte — and be met with an allocation failure abort
    /// rather than an error it can handle.
    fn select_byte_index(pcr: u32) -> Result<usize, TpmError> {
        if pcr > Self::MAX_PCR_INDEX {
            return Err(TpmError::InvalidArraySize(format!(
                "PCR {} needs a pcrSelect of {} bytes, but TPMS_PCR_SELECTION marshals \
                 pcrSelect behind a one-byte size prefix, so it holds at most {} bytes and \
                 PCR {} is the largest index it can name",
                pcr,
                pcr as usize / 8 + 1,
                Self::MAX_PCR_SELECT_BYTES,
                Self::MAX_PCR_INDEX
            )));
        }
        Ok(pcr as usize / 8)
    }

    /// Get a PCR-selection array naming exactly one PCR in one bank
    ///
    /// Errors when `pcr` is above [`Self::MAX_PCR_INDEX`] — see [`Self::new_from_pcr_u32`].
    pub fn get_selection_array(hash_alg: TPM_ALG_ID, pcr: u32) -> Result<Vec<Self>, TpmError> {
        Ok(vec![TPMS_PCR_SELECTION::new_from_pcr_u32(hash_alg, pcr)?])
    }

    /// Create a TPMS_PCR_SELECTION naming a single-PCR
    ///
    /// `pcr` above [`Self::MAX_PCR_INDEX`] is an error: the selection it would need is longer
    /// than the wire format can express, so building it would allocate a large buffer for a
    /// value that could never be sent.
    pub fn new_from_pcr_u32(hash_alg: TPM_ALG_ID, pcr: u32) -> Result<Self, TpmError> {
        let byte_index = Self::select_byte_index(pcr)?;

        // `byte_index` is already the byte holding `pcr`'s bit, so the array must grow whenever
        // that index does not fit in the minimum size. Dividing it by 8 again here compared the
        // wrong quantity and left the size at 3 for every PCR up to 191, so selecting PCR 24
        // (the first PCR outside the standard 0-23 range) indexed past the end of the vector.
        let size = std::cmp::max(Self::MIN_PCR_SELECT_BYTES, byte_index + 1);

        let mut pcr_select = vec![0u8; size];
        pcr_select[byte_index] = 1 << (pcr % 8);

        Ok(TPMS_PCR_SELECTION::new(hash_alg, &pcr_select))
    }

    /// Create a TPMS_PCR_SELECTION for a set of PCRs in a single bank
    ///
    /// Any PCR above [`Self::MAX_PCR_INDEX`] is an error, on the same grounds as
    /// [`Self::new_from_pcr_u32`]. Every index is checked before the array is allocated, so a
    /// single out-of-range entry cannot drive the allocation.
    pub fn new_from_pcrs_vec(hash_alg: TPM_ALG_ID, pcrs: &[u32]) -> Result<Self, TpmError> {
        let mut size = Self::MIN_PCR_SELECT_BYTES;
        for pcr in pcrs {
            size = std::cmp::max(size, Self::select_byte_index(*pcr)? + 1);
        }

        let mut pcr_select = vec![0u8; size];
        for pcr in pcrs {
            pcr_select[*pcr as usize / 8] |= 1 << (*pcr % 8);
        }

        Ok(TPMS_PCR_SELECTION::new(hash_alg, &pcr_select))
    }
}

#[cfg(test)]
mod pcr_selection_tests {
    use super::*;

    #[test]
    fn pcr_selection_is_unchanged_for_the_standard_pcr_range() -> Result<(), TpmError> {
        // PCRs 0-23 are the standard TPM range and must keep producing the historical 3-byte
        // wire format: it is part of every existing PCR policy, so any change here would
        // silently break policy digests computed against the old layout.
        for pcr in 0..24u32 {
            let selection = TPMS_PCR_SELECTION::new_from_pcr_u32(TPM_ALG_ID::SHA256, pcr)?;
            assert_eq!(selection.pcrSelect.len(), 3);

            let mut expected = vec![0u8; 3];
            expected[(pcr / 8) as usize] = 1 << (pcr % 8);
            assert_eq!(selection.pcrSelect, expected);

            // The same range through the vector-taking constructor, which shares the bound
            // check and must not have picked up a different size from it.
            let from_vec = TPMS_PCR_SELECTION::new_from_pcrs_vec(TPM_ALG_ID::SHA256, &[pcr])?;
            assert_eq!(from_vec.pcrSelect, expected);
        }

        Ok(())
    }

    #[test]
    fn pcr_selection_handles_a_pcr_beyond_the_first_three_bytes() -> Result<(), TpmError> {
        // PCR 24 is the first PCR outside the standard 0-23 range and previously panicked
        // because the growth check divided the byte index by 8 a second time.
        let selection = TPMS_PCR_SELECTION::new_from_pcr_u32(TPM_ALG_ID::SHA256, 24)?;

        assert_eq!(selection.pcrSelect.len(), 4);
        assert_eq!(selection.pcrSelect, vec![0, 0, 0, 1]);

        Ok(())
    }

    #[test]
    fn pcr_selection_handles_a_large_pcr_value() -> Result<(), TpmError> {
        let selection = TPMS_PCR_SELECTION::new_from_pcr_u32(TPM_ALG_ID::SHA256, 200)?;

        assert_eq!(selection.pcrSelect.len(), 26);
        assert_eq!(selection.pcrSelect[25], 1);
        assert!(selection.pcrSelect[..25].iter().all(|&b| b == 0));

        Ok(())
    }

    #[test]
    fn pcr_selection_sets_the_correct_bit() -> Result<(), TpmError> {
        let selection = TPMS_PCR_SELECTION::new_from_pcr_u32(TPM_ALG_ID::SHA256, 19)?;

        // PCR 19 is bit 3 (0b0000_1000) of byte 2 (19 / 8 == 2, 19 % 8 == 3).
        assert_eq!(selection.pcrSelect, vec![0, 0, 0b0000_1000]);

        Ok(())
    }

    /// The largest PCR the wire format can name still builds, and still marshals.
    ///
    /// The second half is what grounds `MAX_PCR_INDEX` in something other than a comment: the
    /// size prefix is one byte, so 255 bytes is the most that can be written, and the marshalled
    /// form is checked to begin with that length. Widening the bound by one PCR makes
    /// `select_byte_index` accept an index needing 256 bytes, which `writeSizedByteBuf` refuses
    /// -- see the test below.
    #[test]
    fn pcr_selection_accepts_the_largest_representable_pcr() -> Result<(), TpmError> {
        let selection = TPMS_PCR_SELECTION::new_from_pcr_u32(
            TPM_ALG_ID::SHA256,
            TPMS_PCR_SELECTION::MAX_PCR_INDEX,
        )?;

        assert_eq!(
            selection.pcrSelect.len(),
            TPMS_PCR_SELECTION::MAX_PCR_SELECT_BYTES
        );
        assert_eq!(selection.pcrSelect[254], 0b1000_0000);
        assert!(selection.pcrSelect[..254].iter().all(|&b| b == 0));

        // `toBytes` fails the marshal if the buffer went out of bounds, which is how
        // `writeSizedByteBuf` reports a payload too long for its size prefix.
        let marshalled = selection.toBytes()?;

        // hash (2 bytes) || size (1 byte) || pcrSelect
        assert_eq!(marshalled[2], 255);
        assert_eq!(marshalled.len(), 2 + 1 + 255);

        Ok(())
    }

    /// A `pcrSelect` one byte longer than the bound allows cannot be marshalled at all.
    ///
    /// This is the fact `MAX_PCR_SELECT_BYTES` is derived from, checked against the generated
    /// marshaller rather than assumed. If the generator ever moved `TPMS_PCR_SELECTION` to a
    /// wider size prefix this test would fail, which is the signal to widen the bound.
    #[test]
    fn a_pcr_select_over_the_bound_does_not_marshal() {
        let oversized = TPMS_PCR_SELECTION::new(
            TPM_ALG_ID::SHA256,
            &vec![0u8; TPMS_PCR_SELECTION::MAX_PCR_SELECT_BYTES + 1],
        );

        let mut buffer = TpmBuffer::new(None);
        let _ = oversized.toTpm(&mut buffer);
        assert!(
            !buffer.isOk(),
            "a 256-byte pcrSelect does not fit behind a one-byte size prefix"
        );
        assert!(
            oversized.toBytes().is_err(),
            "and the failure is reported to a caller that marshals the whole structure"
        );
    }

    /// An out-of-range PCR is rejected before anything is allocated.
    ///
    /// Reverting the bound check turns this into a request for `u32::MAX / 8 + 1` bytes -- half
    /// a gigabyte -- for a value that could never be sent. The test then fails on the `Ok` that
    /// comes back; when this was checked by hand, the run also stopped making progress under
    /// the memory it had asked for, which is the outcome the bound exists to prevent.
    #[test]
    fn pcr_selection_rejects_a_pcr_no_selection_can_name() {
        for pcr in [
            TPMS_PCR_SELECTION::MAX_PCR_INDEX + 1,
            u32::MAX / 2,
            u32::MAX,
        ] {
            let error = TPMS_PCR_SELECTION::new_from_pcr_u32(TPM_ALG_ID::SHA256, pcr)
                .expect_err("a PCR the wire format cannot name must not be allocated for");
            assert!(
                matches!(error, TpmError::InvalidArraySize(_)),
                "unexpected error for PCR {pcr}: {error}"
            );

            assert!(
                TPMS_PCR_SELECTION::get_selection_array(TPM_ALG_ID::SHA256, pcr).is_err(),
                "get_selection_array must carry the bound its element constructor applies"
            );
        }
    }

    /// The same bound on the vector-taking constructor, including when the out-of-range index is
    /// not the only one and not the first.
    ///
    /// Reverting `new_from_pcrs_vec` to sizing from `max(pcrs)` without a check reintroduces the
    /// same unbounded allocation, and this fails.
    #[test]
    fn pcr_selection_from_a_vec_rejects_a_pcr_no_selection_can_name() {
        let error = TPMS_PCR_SELECTION::new_from_pcrs_vec(
            TPM_ALG_ID::SHA256,
            &[0, 7, u32::MAX, TPMS_PCR_SELECTION::MAX_PCR_INDEX],
        )
        .expect_err("one out-of-range PCR is enough to reject the whole selection");
        assert!(
            matches!(error, TpmError::InvalidArraySize(_)),
            "unexpected error: {error}"
        );

        // The largest representable index is accepted in the same position, so the rejection
        // above is the bound and not the shape of the input.
        let selection = TPMS_PCR_SELECTION::new_from_pcrs_vec(
            TPM_ALG_ID::SHA256,
            &[0, 7, TPMS_PCR_SELECTION::MAX_PCR_INDEX],
        )
        .expect("the largest representable PCR is in range");
        assert_eq!(
            selection.pcrSelect.len(),
            TPMS_PCR_SELECTION::MAX_PCR_SELECT_BYTES
        );
        assert_eq!(selection.pcrSelect[0], 0b1000_0001);
        assert_eq!(selection.pcrSelect[254], 0b1000_0000);
    }
}

impl TPM_HANDLE {
    /// Creates a handle for a persistent object
    pub fn persistent(handle_offset: u32) -> Self {
        Self::new(((TPM_HT::PERSISTENT.get_value() as u32) << 24) + handle_offset)
    }

    /// Creates a handle for a PCR
    pub fn pcr(pcr_index: u32) -> Self {
        Self::new(pcr_index)
    }

    /// Creates a handle for an NV slot
    pub fn nv(nv_index: u32) -> Self {
        Self::new(((TPM_HT::NV_INDEX.get_value() as u32) << 24) + nv_index)
    }

    /// Set the authorization value for this TPM_HANDLE.  The default auth-value is NULL
    pub fn set_auth(&mut self, auth_val: &[u8]) {
        self.auth_value = auth_val.to_vec();
    }

    /// Returns this handle's type
    pub fn get_type(&self) -> TPM_HT {
        // The handle type is the top byte of the handle value
        unsafe { std::mem::transmute((self.handle >> 24) as u8) }
    }

    pub fn set_name(&mut self, name: &[u8]) -> Result<(), TpmError> {
        let handle_type = self.get_type();

        if (handle_type == TPM_HT::NV_INDEX
            || handle_type == TPM_HT::TRANSIENT
            || handle_type == TPM_HT::PERSISTENT)
        {
            self.name = name.to_vec();
            return Ok(());
        }

        if (name != self.get_name()?) {
            return Err(TpmError::GenericError(format!("Setting an invalid name of an entity with the name defined by the handle value, handle type: {}", handle_type)));
        }

        Ok(())
    }

    /// Get the TPM name of this handle
    pub fn get_name(&self) -> Result<Vec<u8>, TpmError> {
        let handle_type = self.get_type();

        // Per spec: handles of these types have their handle value as their name
        if handle_type == TPM_HT::PCR
            || handle_type == TPM_HT::HMAC_SESSION
            || handle_type == TPM_HT::POLICY_SESSION
            || handle_type == TPM_HT::PERMANENT
        {
            let mut name = Vec::with_capacity(4);
            name.extend_from_slice(&self.handle.to_be_bytes());
            return Ok(name);
        }

        if handle_type == TPM_HT::NV_INDEX
            || handle_type == TPM_HT::TRANSIENT
            || handle_type == TPM_HT::PERSISTENT
        {
            if (self.name.is_empty()) {
                return Err(TpmError::GenericError(format!(
                    "Name is not set for handle, handle type: {}",
                    handle_type
                )));
            }
            return Ok(self.name.clone());
        }

        Err(TpmError::GenericError(format!(
            "Unknown handle type, handle type: {}",
            handle_type
        )))
    }
}

impl std::fmt::Display for TPM_HANDLE {
    /// Get a string representation of this handle
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:0x{:x}", self.get_type(), self.handle)
    }
}

/// Wipes the private prime `TSS_KEY::privatePart` holds, so that a key that has gone out of scope
/// is not left in freed heap.
///
/// # Why this lives here
///
/// `TSS_KEY` is generated by TssCodeGen (`TSS.Rust/src/tpm_types.rs`) and generated files must not
/// be hand-edited, but `Drop` may be implemented anywhere in the defining crate, so the wipe can
/// be added from here. Every clone is wiped by this same implementation, exactly as for
/// [`RsaKeyParts`].
///
/// The printing half of the problem is closed too, by the `std::fmt::Debug` implementation
/// immediately below: the generator no longer derives `Debug` over this type, so `{:?}` renders
/// the prime as a byte count and nothing more.
///
/// One visible consequence, the same one `RsaKeyParts` already has: a type with a `Drop` cannot
/// have its fields moved out, so `TSS_KEY { publicPart, ..Default::default() }` no longer
/// compiles. Name both fields instead. The error is a compile error, not a surprise at runtime.
impl Drop for TSS_KEY {
    fn drop(&mut self) {
        self.privatePart.zeroize();
    }
}

/// Renders the public half of the key in full and the private prime not at all.
///
/// A derived `Debug` would print the RSA factor into any log line or error path that formats a
/// key, which is why `TSS_KEY` is listed in `CGenRust.StructsWithHandWrittenDebug` and the
/// generator emits no derive for it. The byte count is disclosed deliberately: it is already
/// implied by `publicPart.parameters.keyBits`, and without it the rendering says nothing about
/// whether a key was populated at all.
impl std::fmt::Debug for TSS_KEY {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TSS_KEY")
            .field("publicPart", &self.publicPart)
            .field(
                "privatePart",
                &format_args!("<{} bytes withheld>", self.privatePart.len()),
            )
            .finish()
    }
}

/// Renders what identifies a handle and none of what authorizes it.
///
/// `auth_value` is the caller's authorization value in the clear, and `TPM_HANDLE` is formatted
/// wherever a command is traced or an error names the object it failed on, so a derived `Debug`
/// would put that secret into ordinary log output. The handle and the Name are both public — the
/// Name is a digest over a public area — and are printed in full, so the rendering still says
/// which object this is.
///
/// Note what this does *not* do: unlike [`TSS_KEY`], `TPM_HANDLE` has no `Drop` that zeroizes
/// `auth_value`. A handle is constructed, copied and cloned on nearly every code path in the
/// crate, so a `Drop` would both cost more than it buys and, by blocking field moves, break a
/// large amount of existing construction. The auth value is therefore no longer *printable*, but
/// it is still left in freed heap when a handle is dropped.
impl std::fmt::Debug for TPM_HANDLE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TPM_HANDLE")
            .field("handle", &format_args!("0x{:08x}", self.handle))
            .field(
                "auth_value",
                &format_args!("<{} bytes withheld>", self.auth_value.len()),
            )
            .field("name", &self.name)
            .finish()
    }
}

/// Renders the sensitive area's type-independent structure and none of its secrets.
///
/// `authValue` is an authorization secret, `seedValue` is the protection seed a parent uses to
/// derive its children's protection keys, and `sensitive` is the private key itself. None of the
/// three has a non-secret use, so all three are withheld. The union selector is printed, because
/// which *kind* of key this is is public and is the one thing a reader needs to orient.
impl std::fmt::Debug for TPMT_SENSITIVE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sensitive_kind = match &self.sensitive {
            Some(s) => format!("{:?}", s.GetUnionSelector()),
            None => "none".to_string(),
        };
        f.debug_struct("TPMT_SENSITIVE")
            .field(
                "authValue",
                &format_args!("<{} bytes withheld>", self.authValue.len()),
            )
            .field(
                "seedValue",
                &format_args!("<{} bytes withheld>", self.seedValue.len()),
            )
            .field("sensitive", &format_args!("<{sensitive_kind} withheld>"))
            .finish()
    }
}

/// Renders neither the authorization value nor the data to be sealed.
///
/// Both fields of this structure are secrets the caller is handing to the TPM: `userAuth` becomes
/// the created object's authorization value, and `data` is the key or sealed blob itself.
impl std::fmt::Debug for TPMS_SENSITIVE_CREATE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TPMS_SENSITIVE_CREATE")
            .field(
                "userAuth",
                &format_args!("<{} bytes withheld>", self.userAuth.len()),
            )
            .field(
                "data",
                &format_args!("<{} bytes withheld>", self.data.len()),
            )
            .finish()
    }
}

/// Redacting `Debug` for the five `TPMU_SENSITIVE_COMPOSITE` members.
///
/// Each of these is a single buffer holding one form of private key material, and each is used
/// nowhere in the generated binding except as a member of that union, so there is no public value
/// this can hide. They are listed in `CGenRust.StructsWithHandWrittenDebug`, so the generator
/// emits no derived `Debug` and the assertion at the end of `tpm_types.rs` requires these.
macro_rules! debug_withholds_buffer {
    ($($ty:ident),+ $(,)?) => {
        $(
            impl std::fmt::Debug for $ty {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct(stringify!($ty))
                        .field(
                            "buffer",
                            &format_args!("<{} bytes withheld>", self.buffer.len()),
                        )
                        .finish()
                }
            }
        )+
    };
}

debug_withholds_buffer!(
    TPM2B_PRIVATE_KEY_RSA,
    TPM2B_ECC_PARAMETER,
    TPM2B_SENSITIVE_DATA,
    TPM2B_SYM_KEY,
    TPM2B_PRIVATE_VENDOR_SPECIFIC,
);

/// Not gated on `software-crypto`: none of this needs a crypto backend, and the redaction is
/// exactly as load bearing in a `--no-default-features` build.
#[cfg(test)]
mod secret_redaction_tests {
    use super::*;

    /// Bytes chosen so that neither their decimal nor their hexadecimal rendering is a substring
    /// of anything the redacted `Debug` legitimately prints.
    const SECRET: [u8; 6] = [0xA7, 0xB3, 0xC9, 0xD1, 0xE5, 0xF2];

    fn assert_withholds_secret(rendered: &str, secret: &[u8]) {
        for byte in secret {
            assert!(
                !rendered.contains(&byte.to_string()),
                "debug rendering {rendered} leaks byte {byte} in decimal"
            );
            assert!(
                !rendered.to_lowercase().contains(&format!("{byte:02x}")),
                "debug rendering {rendered} leaks byte {byte} in hex"
            );
        }
        assert!(
            !rendered.contains(&format!("{:?}", secret)),
            "debug rendering {rendered} leaks the secret verbatim"
        );
    }

    #[test]
    fn tss_key_debug_withholds_the_private_prime() {
        let key = TSS_KEY {
            publicPart: TPMT_PUBLIC {
                nameAlg: TPM_ALG_ID::SHA256,
                unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA {
                    buffer: vec![0x11, 0x22],
                })),
                ..Default::default()
            },
            privatePart: SECRET.to_vec(),
        };

        let rendered = format!("{:?}", key);

        assert_withholds_secret(&rendered, &SECRET);

        // The public half stays legible, which is the point of hand writing the rendering rather
        // than dropping `Debug` altogether.
        assert!(
            rendered.contains(&format!("{:?}", TPM_ALG_ID::SHA256)),
            "{rendered}"
        );
        assert!(rendered.contains("[17, 34]"), "{rendered}");
        assert!(
            rendered.contains("privatePart: <6 bytes withheld>"),
            "{rendered}"
        );
    }

    #[test]
    fn tpm_handle_debug_withholds_the_auth_value() {
        let mut handle = TPM_HANDLE::new(0x81000001);
        handle.auth_value = SECRET.to_vec();
        handle.name = vec![0x11, 0x22];

        let rendered = format!("{:?}", handle);

        assert_withholds_secret(&rendered, &SECRET);

        // The handle and the Name are both public, and are what makes a traced handle
        // identifiable at all.
        assert!(rendered.contains("0x81000001"), "{rendered}");
        assert!(rendered.contains("[17, 34]"), "{rendered}");
        assert!(
            rendered.contains("auth_value: <6 bytes withheld>"),
            "{rendered}"
        );
    }

    #[test]
    fn sensitive_area_debug_withholds_every_secret_it_carries() {
        let sensitive = TPMT_SENSITIVE {
            authValue: SECRET.to_vec(),
            seedValue: SECRET.to_vec(),
            sensitive: Some(TPMU_SENSITIVE_COMPOSITE::rsa(TPM2B_PRIVATE_KEY_RSA {
                buffer: SECRET.to_vec(),
            })),
        };

        let rendered = format!("{:?}", sensitive);

        assert_withholds_secret(&rendered, &SECRET);

        // Which kind of key this is is public, and is the one thing a reader needs to orient.
        assert!(
            rendered.contains(&format!("{:?}", TPM_ALG_ID::RSA)),
            "{rendered}"
        );
    }

    #[test]
    fn sensitive_composite_members_debug_withholds_their_buffers() {
        let rendered = format!(
            "{:?} {:?} {:?} {:?} {:?}",
            TPM2B_PRIVATE_KEY_RSA {
                buffer: SECRET.to_vec()
            },
            TPM2B_ECC_PARAMETER {
                buffer: SECRET.to_vec()
            },
            TPM2B_SENSITIVE_DATA {
                buffer: SECRET.to_vec()
            },
            TPM2B_SYM_KEY {
                buffer: SECRET.to_vec()
            },
            TPM2B_PRIVATE_VENDOR_SPECIFIC {
                buffer: SECRET.to_vec()
            },
        );

        assert_withholds_secret(&rendered, &SECRET);
        assert_eq!(
            rendered.matches("<6 bytes withheld>").count(),
            5,
            "{rendered}"
        );
    }

    #[test]
    fn sensitive_create_debug_withholds_the_auth_and_the_data() {
        let create = TPMS_SENSITIVE_CREATE::new(&SECRET.to_vec(), &SECRET.to_vec());

        let rendered = format!("{:?}", create);

        assert_withholds_secret(&rendered, &SECRET);
        assert!(
            rendered.contains("userAuth: <6 bytes withheld>"),
            "{rendered}"
        );
        assert!(rendered.contains("data: <6 bytes withheld>"), "{rendered}");
    }

    /// Pins that the zeroizing destructor is still present.
    ///
    /// A `T: Drop` bound is satisfied only by a type with an explicit `impl Drop`, so this fails
    /// the moment the implementation above is deleted. It does not, and cannot, observe the wipe
    /// itself: reading the buffer after a real drop would be a use after free, and `Drop::drop`
    /// cannot be called directly.
    #[test]
    fn tss_key_still_has_its_zeroizing_drop() {
        // `drop_bounds` warns because a `T: Drop` bound is almost never what a caller wants.
        // Here it is exactly what is wanted: the bound is satisfied only by a type carrying an
        // explicit `impl Drop`, which is the property under test.
        #[allow(drop_bounds)]
        fn assert_explicit_drop<T: Drop>() {}
        assert_explicit_drop::<TSS_KEY>();
    }

    #[test]
    fn withholding_debug_left_clone_and_default_alone() {
        let key = TSS_KEY {
            publicPart: TPMT_PUBLIC::default(),
            privatePart: SECRET.to_vec(),
        };
        assert_eq!(key.clone().privatePart, SECRET.to_vec());
        assert!(TSS_KEY::default().privatePart.is_empty());

        let mut handle = TPM_HANDLE::new(0x81000001);
        handle.auth_value = SECRET.to_vec();
        assert_eq!(handle.clone().auth_value, SECRET.to_vec());
        assert_eq!(handle.clone().handle, 0x81000001);
        assert_eq!(TPM_HANDLE::default().handle, u32::from(TPM_RH::NULL));
    }
}

impl TSS_KEY {
    /// Generate an RSA key pair in software.
    /// Populates publicPart.unique with the modulus and privatePart with the first prime (p).
    ///
    /// The prime moves out of the [`RsaKeyParts`] the provider returned and into `privatePart`,
    /// which is wiped on drop by the [`Drop`] implementation above and withheld from `{:?}` by
    /// the [`std::fmt::Debug`] implementation above.
    ///
    /// Calling this twice on the same key is safe for the prime it replaces: the store goes
    /// through [`TSS_KEY::set_private_part`], which wipes the old one before the allocation
    /// holding it is freed.
    pub fn create_key(&mut self, crypto: &CryptoProvider) -> Result<(), TpmError> {
        let (key_bits, exponent) =
            if let Some(TPMU_PUBLIC_PARMS::rsaDetail(ref params)) = self.publicPart.parameters {
                (params.keyBits as usize, params.exponent_bytes())
            } else {
                return Err(TpmError::GenericError(
                    "Only RSA key creation is supported".to_string(),
                ));
            };

        let mut key = Crypto::rsa_generate_keypair(crypto, key_bits, &exponent)?;

        // `RsaKeyParts` wipes its prime when dropped, so its fields cannot be moved out. Taking
        // them leaves nothing behind for the wipe to do, which is what is wanted here: the
        // material is moving into this key rather than being copied out of it.

        // Store modulus (n) in publicPart.unique. No wipe is needed for what this replaces: the
        // modulus is the public half of the key and is published in the Name of every object
        // derived from it.
        self.publicPart.unique = Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA {
            buffer: std::mem::take(&mut key.modulus),
        }));

        // Store first prime (p) as privatePart.
        self.set_private_part(std::mem::take(&mut key.prime));

        Ok(())
    }

    /// Store `prime` as the private half of this key, wiping the prime it replaces.
    ///
    /// Plain assignment would not do: it drops the previous `Vec`, and `Vec`'s own `Drop` only
    /// frees, it does not zeroize. The [`Drop`] implementation above runs only when the whole key
    /// goes out of scope, so calling [`TSS_KEY::create_key`] twice on the same key would leave
    /// the first prime sitting in freed heap for whatever allocates next.
    ///
    /// Every write to `privatePart` in this crate goes through here.
    pub fn set_private_part(&mut self, prime: Vec<u8>) {
        self.privatePart.zeroize();
        self.privatePart = prime;
    }

    /// Sign a digest using the software key (RSASSA-PKCS1-v1_5).
    /// `digest` should be the hash of the data to sign.
    /// Returns a TPMT_SIGNATURE with RSASSA scheme.
    pub fn sign(
        &self,
        crypto: &CryptoProvider,
        digest: &[u8],
        hash_alg: TPM_ALG_ID,
    ) -> Result<TPMT_SIGNATURE, TpmError> {
        let rsa_params =
            if let Some(TPMU_PUBLIC_PARMS::rsaDetail(ref params)) = self.publicPart.parameters {
                params
            } else {
                return Err(TpmError::GenericError(
                    "Only RSA signing is supported".to_string(),
                ));
            };

        let n_bytes = if let Some(TPMU_PUBLIC_ID::rsa(ref pub_key)) = self.publicPart.unique {
            pub_key.buffer.clone()
        } else {
            return Err(TpmError::GenericError(
                "No public key available".to_string(),
            ));
        };

        // Reconstruct RSA private key from modulus + prime p
        let key = RsaKeyParts {
            modulus: n_bytes,
            prime: self.privatePart.clone(),
            exponent: rsa_params.exponent_bytes(),
        };

        let sig_bytes = Crypto::rsa_pkcs1v15_sign(crypto, &key, hash_alg, digest)?;

        Ok(TPMT_SIGNATURE {
            signature: Some(TPMU_SIGNATURE::rsassa(TPMS_SIGNATURE_RSASSA {
                hash: hash_alg,
                sig: sig_bytes,
            })),
        })
    }
}

/// Observes that overwriting `TSS_KEY::privatePart` wipes the prime it replaces.
///
/// The claim is about memory that has been freed, and freed memory cannot be read afterwards
/// without reaching into it. It can be read at the *moment* of freeing, though: a `GlobalAlloc`
/// is handed a still-valid pointer to the block, so the wrapper below inspects it there and
/// records what it found before delegating to the system allocator.
///
/// Two things keep that read sound. Exactly one block is ever inspected — the one whose address
/// was armed, on this thread, while it was still owned by a live `Vec`, so no other allocation
/// can be sitting at that address — and only the bytes that `Vec` had initialized are read,
/// never its spare capacity.
///
/// A watched block that is *resized* rather than dropped escapes the check, because `realloc` is
/// forwarded to the system allocator untouched. That fails safe: the verdict stays `NOT_FREED`
/// and the assertions below reject it.
#[cfg(test)]
mod private_part_wipe_tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    /// The watched block was not released while it was being watched, so nothing was observed.
    const NOT_FREED: u8 = 0;
    /// It was released holding nothing but zeros.
    const FREED_WIPED: u8 = 1;
    /// It was released with its contents still in it.
    const FREED_INTACT: u8 = 2;

    thread_local! {
        /// Address of the block to inspect when it is released, or 0 for "not watching".
        static WATCHED_PTR: Cell<usize> = const { Cell::new(0) };
        /// How many bytes of that block were initialized. Only these are read.
        static WATCHED_LEN: Cell<usize> = const { Cell::new(0) };
        static VERDICT: Cell<u8> = const { Cell::new(NOT_FREED) };
    }

    struct WatchingAllocator;

    unsafe impl GlobalAlloc for WatchingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            System.alloc(layout)
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            System.alloc_zeroed(layout)
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            System.realloc(ptr, layout, new_size)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // `try_with` because thread-local storage may already have been torn down when a
            // thread's last allocations are released. The cells are `const`-initialized, so
            // reading them never allocates and this cannot re-enter the allocator.
            let watched = WATCHED_PTR.try_with(|w| w.get()).unwrap_or(0);
            if watched != 0 && watched == ptr as usize {
                let len = WATCHED_LEN.try_with(|w| w.get()).unwrap_or(0);
                let initialized = std::slice::from_raw_parts(ptr, len.min(layout.size()));
                let verdict = if initialized.iter().all(|&byte| byte == 0) {
                    FREED_WIPED
                } else {
                    FREED_INTACT
                };
                let _ = WATCHED_PTR.try_with(|w| w.set(0));
                let _ = VERDICT.try_with(|v| v.set(verdict));
            }
            System.dealloc(ptr, layout)
        }
    }

    #[global_allocator]
    static ALLOCATOR: WatchingAllocator = WatchingAllocator;

    /// Start watching the block `secret` currently owns.
    fn watch(secret: &[u8]) {
        VERDICT.with(|v| v.set(NOT_FREED));
        WATCHED_LEN.with(|w| w.set(secret.len()));
        WATCHED_PTR.with(|w| w.set(secret.as_ptr() as usize));
    }

    /// Stop watching, and report what the allocator saw.
    fn verdict() -> u8 {
        WATCHED_PTR.with(|w| w.set(0));
        VERDICT.with(|v| v.get())
    }

    fn assert_wiped(verdict: u8) {
        assert_ne!(
            verdict, NOT_FREED,
            "the watched block was never released, so this test observed nothing at all"
        );
        assert_eq!(
            verdict, FREED_WIPED,
            "the block holding the replaced prime was released with the prime still in it"
        );
    }

    /// Deleting the `zeroize` in [`TSS_KEY::set_private_part`] fails this: the block is then
    /// released still holding `0xA7`, and the verdict is `FREED_INTACT`.
    #[test]
    fn overwriting_the_private_part_wipes_the_prime_it_replaces() {
        let mut key = TSS_KEY {
            publicPart: TPMT_PUBLIC::default(),
            privatePart: vec![0xA7u8; 64],
        };

        watch(&key.privatePart);
        key.set_private_part(vec![0x11; 64]);

        assert_wiped(verdict());
        assert_eq!(key.privatePart, vec![0x11; 64]);
    }

    /// The same property for [`TSS_KEY::create_key`], which is where the defect was reported.
    ///
    /// The test above would stay green if `create_key` went back to assigning to the field
    /// directly, so this one pins that the store still goes through the wiping path. 1024 bits
    /// because two keys are generated and the modulus size is irrelevant to what is observed.
    #[test]
    #[cfg(feature = "software-crypto")]
    fn a_second_create_key_wipes_the_prime_the_first_left() -> Result<(), TpmError> {
        use crate::crypto::software_provider::SOFTWARE_PROVIDER;

        let mut key = TSS_KEY {
            publicPart: TPMT_PUBLIC {
                nameAlg: TPM_ALG_ID::SHA256,
                parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
                    &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
                    &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
                    1024,
                    65537,
                ))),
                ..Default::default()
            },
            privatePart: Vec::new(),
        };

        key.create_key(&SOFTWARE_PROVIDER)?;
        let first_prime = key.privatePart.clone();
        assert!(!first_prime.is_empty(), "the first key produced no prime");

        watch(&key.privatePart);
        key.create_key(&SOFTWARE_PROVIDER)?;

        assert_wiped(verdict());
        assert_ne!(
            key.privatePart, first_prime,
            "the second call must have produced a different key for this to mean anything"
        );

        Ok(())
    }
}

// The activation round trip is checked against a software endorsement key built with the `rsa`
// crate, so these tests only apply when the software provider is compiled in.
#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;
    use elliptic_curve::ecdh::diffie_hellman;
    use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint};
    use elliptic_curve::{
        AffinePoint, CurveArithmetic, FieldBytes, FieldBytesSize, PublicKey, SecretKey,
    };
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{Oaep, RsaPrivateKey};
    use sha1::Sha1;
    use sha2::Sha256;

    /// Build a software stand-in for an endorsement key, along with its public area.
    fn endorsement_key(name_alg: TPM_ALG_ID) -> Result<(RsaPrivateKey, TPMT_PUBLIC), TpmError> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| TpmError::GenericError(format!("RSA key generation failed: {e}")))?;

        let parameters = TPMS_RSA_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            2048,
            65537,
        );

        let public_area = TPMT_PUBLIC {
            nameAlg: name_alg,
            parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(parameters)),
            unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA {
                buffer: private_key.n().to_bytes_be(),
            })),
            ..Default::default()
        };

        Ok((private_key, public_area))
    }

    /// A Name is a two byte algorithm identifier followed by a digest. `create_activation`
    /// treats it as opaque input to KDFa and the integrity HMAC, so the contents do not matter
    /// as long as both sides agree on them.
    fn activated_name(name_alg: TPM_ALG_ID) -> Vec<u8> {
        vec![0xab; 2 + Crypto::digestSize(name_alg)]
    }

    /// Play the part of `TPM2_ActivateCredential` once the seed has been recovered.
    ///
    /// Everything here is defined on the seed alone, so it serves an RSA and an ECC activation
    /// alike. Only the step that produces the seed differs between them.
    fn activate_credential(
        seed: &[u8],
        name_alg: TPM_ALG_ID,
        activated_name: &[u8],
        activation: &ActivationData,
    ) -> Result<Vec<u8>, TpmError> {
        // A TPM rejects a seed whose size is not the nameAlg digest size: TPM 2.0 Part 4,
        // CryptSecretDecrypt, returns TPM_RC_VALUE. Modelling that check here is what makes
        // this test able to catch a wrongly sized seed, because the seed itself travels inside
        // the blob and would otherwise round trip at any length.
        let expected_seed_size = Crypto::digestSize(name_alg);
        if seed.len() != expected_seed_size {
            return Err(TpmError::InvalidArraySize(format!(
                "Seed is {} bytes, but {:?} requires {}",
                seed.len(),
                name_alg,
                expected_seed_size
            )));
        }

        let sym_key = Crypto::kdfa(
            &SOFTWARE_PROVIDER,
            name_alg,
            seed,
            "STORAGE",
            activated_name,
            &[],
            128,
        )?;
        let hmac_key = Crypto::kdfa(
            &SOFTWARE_PROVIDER,
            name_alg,
            seed,
            "INTEGRITY",
            &[],
            &[],
            expected_seed_size * 8,
        )?;

        let mut to_hmac = activation.credential_blob.encIdentity.clone();
        to_hmac.extend_from_slice(activated_name);
        if Crypto::hmac(&SOFTWARE_PROVIDER, name_alg, &hmac_key, &to_hmac)?
            != activation.credential_blob.integrityHMAC
        {
            return Err(TpmError::GenericError(
                "Integrity HMAC mismatch".to_string(),
            ));
        }

        let plaintext = Crypto::cfb_xcrypt(
            &SOFTWARE_PROVIDER,
            false,
            &sym_key,
            &[0u8; 16],
            &activation.credential_blob.encIdentity,
        )?;

        let Some(size_bytes) = plaintext.get(..2) else {
            return Err(TpmError::InvalidArraySize(
                "Credential is missing its size prefix".to_string(),
            ));
        };
        let size = u16::from_be_bytes([size_bytes[0], size_bytes[1]]) as usize;

        plaintext
            .get(2..2 + size)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                TpmError::InvalidArraySize("Credential size overruns the blob".to_string())
            })
    }

    /// Recover an RSA activation's seed the way a TPM would, by decrypting it.
    fn rsa_recover_seed(
        endorsement_private: &RsaPrivateKey,
        name_alg: TPM_ALG_ID,
        secret: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let padding = match name_alg {
            TPM_ALG_ID::SHA1 => Oaep::new_with_label::<Sha1, _>("IDENTITY\0"),
            TPM_ALG_ID::SHA256 => Oaep::new_with_label::<Sha256, _>("IDENTITY\0"),
            _ => {
                return Err(TpmError::NotSupported(format!(
                    "Unsupported nameAlg for OAEP: {:?}",
                    name_alg
                )))
            }
        };

        endorsement_private
            .decrypt(padding, secret)
            .map_err(|e| TpmError::GenericError(format!("Seed decryption failed: {e}")))
    }

    /// A software stand-in for an ECC storage key, along with its public area.
    fn ecc_endorsement_key<C>(
        curve: TPM_ECC_CURVE,
        name_alg: TPM_ALG_ID,
    ) -> Result<(SecretKey<C>, TPMT_PUBLIC), TpmError>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        let private_key = SecretKey::<C>::random(&mut OsRng);
        let public_area = ecc_public_area(&private_key, curve, name_alg)?;

        Ok((private_key, public_area))
    }

    /// The public area a TPM would report for an ECC key it already holds.
    fn ecc_public_area<C>(
        private_key: &SecretKey<C>,
        curve: TPM_ECC_CURVE,
        name_alg: TPM_ALG_ID,
    ) -> Result<TPMT_PUBLIC, TpmError>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        let point = private_key.public_key().to_encoded_point(false);
        let missing =
            || TpmError::GenericError("The generated point has no coordinates".to_string());

        let parameters = TPMS_ECC_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            curve,
            &Some(TPMU_KDF_SCHEME::null(TPMS_NULL_KDF_SCHEME::default())),
        );

        Ok(TPMT_PUBLIC {
            nameAlg: name_alg,
            parameters: Some(TPMU_PUBLIC_PARMS::eccDetail(parameters)),
            unique: Some(TPMU_PUBLIC_ID::ecc(TPMS_ECC_POINT::new(
                &point.x().ok_or_else(missing)?.to_vec(),
                &point.y().ok_or_else(missing)?.to_vec(),
            ))),
            ..Default::default()
        })
    }

    /// A P-256 endorsement key whose public X coordinate is encoded short.
    ///
    /// A TPM is free to drop the leading zero octets of a coordinate it marshals into a `TPM2B`,
    /// and restoring them is what [`Crypto::pad_ecc_coordinate`] exists for. A point built from a
    /// SEC1 encoding always carries its coordinates at full width, so no generated fixture
    /// exercises the restoration.
    ///
    /// The scalar is fixed rather than searched for. Only one key in 256 has a leading zero octet,
    /// and generating that many keys costs more in an unoptimised test build than the rest of this
    /// suite put together.
    fn ecc_endorsement_key_with_a_short_x(
        name_alg: TPM_ALG_ID,
    ) -> Result<(SecretKey<p256::NistP256>, TPMT_PUBLIC), TpmError> {
        // Public X is 001de71052742cda097122e99b7d6e10e60ed5452c8a6de03f0ca1455b7ba892.
        const SCALAR: [u8; 32] = [
            0xad, 0x56, 0xea, 0xd1, 0xd6, 0x29, 0x0c, 0xf6, 0x9f, 0x18, 0x71, 0x82, 0xd2, 0x70,
            0xd6, 0x2f, 0xd4, 0x09, 0x2b, 0xa1, 0xda, 0x80, 0x5a, 0x64, 0x13, 0xcf, 0xfe, 0x42,
            0x8f, 0xa7, 0x34, 0xbf,
        ];

        let private_key = SecretKey::<p256::NistP256>::from_slice(&SCALAR)
            .map_err(|e| TpmError::GenericError(format!("The fixture scalar is invalid: {e}")))?;
        let mut public_area = ecc_public_area(&private_key, TPM_ECC_CURVE::NIST_P256, name_alg)?;

        let Some(TPMU_PUBLIC_ID::ecc(point)) = &mut public_area.unique else {
            return Err(TpmError::GenericError(
                "The fixture is not an ECC key".to_string(),
            ));
        };

        // Drop the leading zeroes, the way a TPM marshalling a TPM2B is entitled to.
        let leading_zeroes = point
            .x
            .iter()
            .position(|octet| *octet != 0)
            .unwrap_or(point.x.len());
        point.x.drain(..leading_zeroes);

        Ok((private_key, public_area))
    }

    /// Recover an ECC activation's seed the way a TPM would, by repeating the agreement.
    ///
    /// Nothing is decrypted here, because nothing was transported. The TPM agrees its own private
    /// key with the ephemeral point it was handed and derives the same seed the caller did.
    fn ecc_recover_seed<C>(
        private_key: &SecretKey<C>,
        name_alg: TPM_ALG_ID,
        secret: &[u8],
    ) -> Result<Vec<u8>, TpmError>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        // The secret is a marshalled TPMS_ECC_POINT, so each coordinate arrives sized.
        let mut ephemeral_point = TPMS_ECC_POINT::default();
        ephemeral_point.initFromTpm(&mut TpmBuffer::from(secret))?;

        let width = FieldBytes::<C>::default().len();
        let ephemeral_x = Crypto::pad_ecc_coordinate(&ephemeral_point.x, width)?;
        let ephemeral_y = Crypto::pad_ecc_coordinate(&ephemeral_point.y, width)?;

        let encoded = EncodedPoint::<C>::from_affine_coordinates(
            FieldBytes::<C>::from_slice(&ephemeral_x),
            FieldBytes::<C>::from_slice(&ephemeral_y),
            false,
        );
        let ephemeral_public: PublicKey<C> =
            Option::from(PublicKey::<C>::from_encoded_point(&encoded)).ok_or_else(|| {
                TpmError::GenericError("The ephemeral point is not on the curve".to_string())
            })?;

        let z = diffie_hellman(
            private_key.to_nonzero_scalar(),
            ephemeral_public.as_affine(),
        );

        // The TPM is the responder, yet it still names the originator's point as partyU. Deriving
        // with the roles reversed would produce a different seed in silence, which is why this
        // assignment is written the same way on both sides.
        let own_point = private_key.public_key().to_encoded_point(false);
        let own_x = own_point
            .x()
            .ok_or_else(|| TpmError::GenericError("The key has no X coordinate".to_string()))?
            .to_vec();

        Crypto::kdfe(
            &SOFTWARE_PROVIDER,
            name_alg,
            z.raw_secret_bytes(),
            "IDENTITY",
            &ephemeral_x,
            &own_x,
            Crypto::digestSize(name_alg) * 8,
        )
    }

    #[test]
    fn create_activation_round_trips_through_a_software_activate() -> Result<(), TpmError> {
        for name_alg in [TPM_ALG_ID::SHA1, TPM_ALG_ID::SHA256] {
            let (endorsement_private, endorsement_public) = endorsement_key(name_alg)?;
            let activated_name = activated_name(name_alg);
            let credential = b"credential to activate".to_vec();

            let activation = endorsement_public.create_activation(
                &SOFTWARE_PROVIDER,
                &credential,
                &activated_name,
            )?;
            let seed = rsa_recover_seed(&endorsement_private, name_alg, &activation.secret)?;
            let recovered = activate_credential(&seed, name_alg, &activated_name, &activation)?;

            assert_eq!(recovered, credential, "nameAlg {:?}", name_alg);
        }

        Ok(())
    }

    /// The whole ECC activation, exercised against a stand-in that repeats the agreement.
    ///
    /// A curve is passed both as a `TPM_ECC_CURVE` and as its Rust type, so a mismatch between the
    /// two would show up as a failed round trip rather than passing unnoticed.
    fn ecc_round_trip<C>(curve: TPM_ECC_CURVE, name_alg: TPM_ALG_ID) -> Result<(), TpmError>
    where
        C: CurveArithmetic,
        FieldBytesSize<C>: ModulusSize,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    {
        let (private_key, public_area) = ecc_endorsement_key::<C>(curve, name_alg)?;
        let activated_name = activated_name(name_alg);
        let credential = b"credential to activate".to_vec();

        let activation =
            public_area.create_activation(&SOFTWARE_PROVIDER, &credential, &activated_name)?;
        let seed = ecc_recover_seed::<C>(&private_key, name_alg, &activation.secret)?;
        let recovered = activate_credential(&seed, name_alg, &activated_name, &activation)?;

        assert_eq!(
            recovered, credential,
            "curve {:?}, nameAlg {:?}",
            curve, name_alg
        );
        Ok(())
    }

    #[test]
    fn ecc_activation_round_trips_on_every_supported_curve() -> Result<(), TpmError> {
        for name_alg in [TPM_ALG_ID::SHA1, TPM_ALG_ID::SHA256, TPM_ALG_ID::SHA384] {
            ecc_round_trip::<p256::NistP256>(TPM_ECC_CURVE::NIST_P256, name_alg)?;
            ecc_round_trip::<p384::NistP384>(TPM_ECC_CURVE::NIST_P384, name_alg)?;
            ecc_round_trip::<p521::NistP521>(TPM_ECC_CURVE::NIST_P521, name_alg)?;
        }

        Ok(())
    }

    #[test]
    fn ecc_activation_restores_a_coordinate_the_tpm_marshalled_short() -> Result<(), TpmError> {
        let name_alg = TPM_ALG_ID::SHA256;
        let (private_key, public_area) = ecc_endorsement_key_with_a_short_x(name_alg)?;

        let Some(TPMU_PUBLIC_ID::ecc(point)) = &public_area.unique else {
            return Err(TpmError::GenericError(
                "The fixture is not an ECC key".to_string(),
            ));
        };
        assert!(
            point.x.len() < 32,
            "the fixture is only meaningful if its X coordinate is short, got {} octets",
            point.x.len()
        );

        let activated_name = activated_name(name_alg);
        let credential = b"credential to activate".to_vec();

        let activation =
            public_area.create_activation(&SOFTWARE_PROVIDER, &credential, &activated_name)?;
        let seed = ecc_recover_seed::<p256::NistP256>(&private_key, name_alg, &activation.secret)?;
        let recovered = activate_credential(&seed, name_alg, &activated_name, &activation)?;

        // KDFe hashes this coordinate, and the key's owner hashes it at its curve's full width.
        // Hashing it as it arrived would derive a different seed on each side, and the credential
        // would not come back.
        assert_eq!(recovered, credential);
        Ok(())
    }

    #[test]
    fn ecc_activation_rejects_a_coordinate_wider_than_its_curve() -> Result<(), TpmError> {
        let (_, mut public_area) =
            ecc_endorsement_key::<p256::NistP256>(TPM_ECC_CURVE::NIST_P256, TPM_ALG_ID::SHA256)?;

        if let Some(TPMU_PUBLIC_ID::ecc(point)) = &mut public_area.unique {
            point.x.insert(0, 0);
        }

        // A 33 octet X does not belong to P-256. Quietly trimming it to fit would agree with a
        // point the key's owner never held, and the failure would only appear at the TPM.
        assert!(
            public_area
                .create_activation(
                    &SOFTWARE_PROVIDER,
                    b"credential",
                    &activated_name(TPM_ALG_ID::SHA256)
                )
                .is_err(),
            "an oversized coordinate should be rejected"
        );
        Ok(())
    }

    #[test]
    fn ecc_activation_secret_is_a_marshalled_point() -> Result<(), TpmError> {
        // Two sized coordinates, not a bare concatenation. A TPM parses this field as a
        // TPMS_ECC_POINT, so a concatenation would be read as a single overlong X.
        let (_, public_area) =
            ecc_endorsement_key::<p256::NistP256>(TPM_ECC_CURVE::NIST_P256, TPM_ALG_ID::SHA256)?;
        let activation = public_area.create_activation(
            &SOFTWARE_PROVIDER,
            b"credential",
            &activated_name(TPM_ALG_ID::SHA256),
        )?;

        assert_eq!(
            activation.secret.len(),
            2 + 32 + 2 + 32,
            "P-256 point should be two sized 32 byte coordinates"
        );

        let mut point = TPMS_ECC_POINT::default();
        point.initFromTpm(&mut TpmBuffer::from(&activation.secret))?;
        assert_eq!(point.x.len(), 32);
        assert_eq!(point.y.len(), 32);
        Ok(())
    }

    #[test]
    fn ecc_activation_rejects_a_curve_without_an_implementation() -> Result<(), TpmError> {
        // The registry defines these, so their coordinate width is known, but no agreement is
        // available for them. Silently substituting a NIST curve would derive an unusable seed.
        for curve in [TPM_ECC_CURVE::BN_P256, TPM_ECC_CURVE::SM2_P256] {
            let (_, mut public_area) = ecc_endorsement_key::<p256::NistP256>(
                TPM_ECC_CURVE::NIST_P256,
                TPM_ALG_ID::SHA256,
            )?;

            if let Some(TPMU_PUBLIC_PARMS::eccDetail(params)) = &mut public_area.parameters {
                params.curveID = curve;
            }

            assert!(
                public_area
                    .create_activation(
                        &SOFTWARE_PROVIDER,
                        b"credential",
                        &activated_name(TPM_ALG_ID::SHA256)
                    )
                    .is_err(),
                "curve {:?} should be rejected",
                curve
            );
        }

        Ok(())
    }

    #[test]
    fn ecc_coordinate_size_agrees_with_the_curve_implementations() -> Result<(), TpmError> {
        // The provider pads with the width its curve crate reports, while create_activation pads
        // the peer's coordinate with the width from the registry table. The two feed the same
        // KDFe, so a disagreement between them would derive mismatched seeds.
        assert_eq!(
            Crypto::ecc_coordinate_size(TPM_ECC_CURVE::NIST_P256)?,
            FieldBytes::<p256::NistP256>::default().len()
        );
        assert_eq!(
            Crypto::ecc_coordinate_size(TPM_ECC_CURVE::NIST_P384)?,
            FieldBytes::<p384::NistP384>::default().len()
        );
        assert_eq!(
            Crypto::ecc_coordinate_size(TPM_ECC_CURVE::NIST_P521)?,
            FieldBytes::<p521::NistP521>::default().len()
        );
        Ok(())
    }

    #[test]
    fn exponent_bytes_resolves_the_specification_default() {
        // The TPM encodes 2^16 + 1 as zero on the wire.
        let mut parms = TPMS_RSA_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            2048,
            0,
        );
        assert_eq!(parms.exponent_bytes(), vec![0x01, 0x00, 0x01]);

        // An explicit 65537 encodes to the same bytes as the default.
        parms.exponent = 65537;
        assert_eq!(parms.exponent_bytes(), vec![0x01, 0x00, 0x01]);

        // A non default exponent is returned big-endian with leading zeros stripped.
        parms.exponent = 3;
        assert_eq!(parms.exponent_bytes(), vec![0x03]);

        parms.exponent = u32::MAX;
        assert_eq!(parms.exponent_bytes(), vec![0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn create_activation_rejects_a_non_storage_wrapping_scheme() -> Result<(), TpmError> {
        let (_, mut endorsement_public) = endorsement_key(TPM_ALG_ID::SHA256)?;

        let parameters = TPMS_RSA_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 256, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            2048,
            65537,
        );
        endorsement_public.parameters = Some(TPMU_PUBLIC_PARMS::rsaDetail(parameters));

        assert!(endorsement_public
            .create_activation(
                &SOFTWARE_PROVIDER,
                b"credential",
                &activated_name(TPM_ALG_ID::SHA256)
            )
            .is_err());

        Ok(())
    }

    #[test]
    fn create_activation_rejects_a_name_alg_that_is_not_a_hash() -> Result<(), TpmError> {
        // A behaviour lock, not a regression test: OAEP already rejects a non-hash nameAlg a few
        // lines further on, so this held before the seed sizing was made checked. It pins the
        // property itself so that reordering or relaxing either check cannot let a zero length
        // seed through unnoticed.
        let (_, mut endorsement_public) = endorsement_key(TPM_ALG_ID::SHA256)?;
        endorsement_public.nameAlg = TPM_ALG_ID::NULL;

        assert!(endorsement_public
            .create_activation(
                &SOFTWARE_PROVIDER,
                b"credential",
                &activated_name(TPM_ALG_ID::SHA256)
            )
            .is_err());

        Ok(())
    }

    /// The attributes a TPM gives a key created to sign attestations.
    const ATTESTATION_ATTRIBUTES: TPMA_OBJECT = TPMA_OBJECT(
        TPMA_OBJECT::restricted.0
            | TPMA_OBJECT::sign.0
            | TPMA_OBJECT::fixedTPM.0
            | TPMA_OBJECT::fixedParent.0
            | TPMA_OBJECT::sensitiveDataOrigin.0
            | TPMA_OBJECT::userWithAuth.0,
    );

    /// The public area of an RSASSA-SHA256 signing key, with `attributes` and `modulus`.
    ///
    /// Nothing but the genuine-certification test needs the modulus to be a real one: every
    /// other check `validate_certify` makes is defined on the attestation or on the attributes,
    /// so filler bytes keep those tests off the key generator.
    fn signing_key_public(attributes: TPMA_OBJECT, modulus: Vec<u8>) -> TPMT_PUBLIC {
        TPMT_PUBLIC {
            nameAlg: TPM_ALG_ID::SHA256,
            objectAttributes: attributes,
            parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
                &TPMT_SYM_DEF_OBJECT::default(),
                &Some(TPMU_ASYM_SCHEME::rsassa(TPMS_SIG_SCHEME_RSASSA {
                    hashAlg: TPM_ALG_ID::SHA256,
                })),
                2048,
                65537,
            ))),
            unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA {
                buffer: modulus,
            })),
            ..Default::default()
        }
    }

    /// An attestation key whose private half this test can actually sign with.
    fn attestation_key() -> Result<TSS_KEY, TpmError> {
        let mut key = TSS_KEY {
            publicPart: signing_key_public(ATTESTATION_ATTRIBUTES, Vec::new()),
            privatePart: Vec::new(),
        };
        key.create_key(&SOFTWARE_PROVIDER)?;
        Ok(key)
    }

    /// The public area of the object being certified. Its contents are immaterial: only its Name
    /// is compared, and that is derived from whatever is here.
    fn certified_key_public() -> TPMT_PUBLIC {
        signing_key_public(
            TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent,
            vec![0x11; 256],
        )
    }

    /// A well formed `TPMS_ATTEST` of a certify, as a TPM would produce it.
    fn certify_attestation(
        certified_key: &TPMT_PUBLIC,
        nonce: &[u8],
    ) -> Result<TPMS_ATTEST, TpmError> {
        Ok(TPMS_ATTEST {
            magic: TPM_GENERATED::VALUE,
            qualifiedSigner: vec![0x0a; 34],
            extraData: nonce.to_vec(),
            clockInfo: TPMS_CLOCK_INFO::new(1234, 5, 6, 1),
            firmwareVersion: 0x2024_0101,
            attested: Some(TPMU_ATTEST::certify(TPMS_CERTIFY_INFO {
                name: certified_key.get_name(&SOFTWARE_PROVIDER)?,
                qualifiedName: vec![0x0b; 34],
            })),
        })
    }

    /// Sign an attestation the way a TPM signs one, with RSASSA over its marshalled form, under
    /// `hash_alg`.
    ///
    /// The hash is a parameter because one test needs a signature that genuinely verifies under
    /// an algorithm the key's *scheme* does not name — a garbage signature would be rejected by
    /// `validate_signature` with the same error variant, and would pass whether or not the check
    /// under test exists.
    fn sign_attestation_with(
        key: &TSS_KEY,
        attest: &TPMS_ATTEST,
        hash_alg: TPM_ALG_ID,
    ) -> Result<CertifyResponse, TpmError> {
        let mut buffer = TpmBuffer::new(None);
        attest.toTpm(&mut buffer)?;
        let digest = Crypto::hash(&SOFTWARE_PROVIDER, hash_alg, buffer.trim())?;
        let signature = key.sign(&SOFTWARE_PROVIDER, &digest, hash_alg)?;

        Ok(CertifyResponse {
            certifyInfo: attest.clone(),
            signature: signature.signature,
        })
    }

    /// Sign an attestation the way a TPM signs one, with RSASSA over its marshalled form.
    fn sign_attestation(key: &TSS_KEY, attest: &TPMS_ATTEST) -> Result<CertifyResponse, TpmError> {
        sign_attestation_with(key, attest, TPM_ALG_ID::SHA256)
    }

    /// A signature in an algorithm this crate cannot verify.
    ///
    /// Pairing one with an otherwise flawed attestation is what shows that the checks on the
    /// attestation run before the signature algorithm is dispatched on: if any of them could be
    /// reached only through the RSASSA arm, these tests would report `NotSupported` instead.
    fn unverifiable_signature() -> Option<TPMU_SIGNATURE> {
        Some(TPMU_SIGNATURE::ecdsa(TPMS_SIGNATURE_ECDSA {
            hash: TPM_ALG_ID::SHA256,
            signatureR: vec![0x03; 32],
            signatureS: vec![0x04; 32],
        }))
    }

    /// The signing key as `validate_certify` wants it. These tests build the public area
    /// themselves, so there is no channel to distrust and nothing to pin against.
    fn trusted(public: TPMT_PUBLIC) -> Result<TrustedPublic, TpmError> {
        TrustedPublic::assume_trusted(public, &SOFTWARE_PROVIDER)
    }

    fn assert_verification_failed(error: TpmError) {
        assert!(
            matches!(error, TpmError::VerificationFailed(_)),
            "expected a verification failure, got {error}"
        );
    }

    #[test]
    fn validate_certify_accepts_a_genuine_certification() -> Result<(), TpmError> {
        let key = attestation_key()?;
        let certified_key = certified_key_public();
        let nonce = vec![9, 8, 7, 6, 5];
        let response = sign_attestation(&key, &certify_attestation(&certified_key, &nonce)?)?;

        trusted(key.publicPart.clone())?.validate_certify(
            &SOFTWARE_PROVIDER,
            &certified_key,
            &nonce,
            &response,
        )?;

        Ok(())
    }

    #[test]
    fn validate_certify_rejects_a_signature_over_something_else() -> Result<(), TpmError> {
        let key = attestation_key()?;
        let certified_key = certified_key_public();
        let nonce = vec![9, 8, 7, 6, 5];
        let mut response = sign_attestation(&key, &certify_attestation(&certified_key, &nonce)?)?;

        // A field the checks above the signature do not look at, so only the signature can catch
        // it: the attestation now differs from the one that was signed.
        response.certifyInfo.firmwareVersion += 1;

        let error = trusted(key.publicPart.clone())?
            .validate_certify(&SOFTWARE_PROVIDER, &certified_key, &nonce, &response)
            .expect_err("a signature over a different attestation must not verify");
        assert_verification_failed(error);

        Ok(())
    }

    #[test]
    fn validate_certify_rejects_an_unrestricted_signing_key() -> Result<(), TpmError> {
        // Everything else about this attestation is genuine, so each attribute is the only
        // reason left for the rejection.
        let key = attestation_key()?;
        let certified_key = certified_key_public();
        let nonce = vec![4, 4, 2];
        let response = sign_attestation(&key, &certify_attestation(&certified_key, &nonce)?)?;

        for missing in [
            TPMA_OBJECT::restricted,
            TPMA_OBJECT::sign,
            TPMA_OBJECT::fixedTPM,
            TPMA_OBJECT::fixedParent,
        ] {
            let mut public = key.publicPart.clone();
            public.objectAttributes = TPMA_OBJECT(public.objectAttributes.0 & !missing.0);

            let error = trusted(public)?
                .validate_certify(&SOFTWARE_PROVIDER, &certified_key, &nonce, &response)
                .expect_err("a signing key unfit to attest must be rejected");
            assert_verification_failed(error);
        }

        Ok(())
    }

    #[test]
    fn validate_certify_rejects_a_non_rsassa_signature() -> Result<(), TpmError> {
        let signing_key = signing_key_public(ATTESTATION_ATTRIBUTES, vec![0xcd; 256]);
        let certified_key = certified_key_public();
        let nonce = vec![1, 2, 3];

        // Nothing else is wrong with this attestation: the only thing standing between it and a
        // success is the signature algorithm.
        let response = CertifyResponse {
            certifyInfo: certify_attestation(&certified_key, &nonce)?,
            signature: unverifiable_signature(),
        };

        let error = trusted(signing_key)?
            .validate_certify(&SOFTWARE_PROVIDER, &certified_key, &nonce, &response)
            .expect_err("a signature this crate cannot verify must not reach a success path");
        assert!(
            matches!(error, TpmError::NotSupported(_)),
            "expected NotSupported, got {error}"
        );

        Ok(())
    }

    #[test]
    fn validate_certify_rejects_a_forged_magic_value() -> Result<(), TpmError> {
        let signing_key = signing_key_public(ATTESTATION_ATTRIBUTES, vec![0xcd; 256]);
        let certified_key = certified_key_public();
        let nonce = vec![1, 2, 3];

        let mut attest = certify_attestation(&certified_key, &nonce)?;
        attest.magic = TPM_GENERATED(0);

        let response = CertifyResponse {
            certifyInfo: attest,
            signature: unverifiable_signature(),
        };

        let error = trusted(signing_key)?
            .validate_certify(&SOFTWARE_PROVIDER, &certified_key, &nonce, &response)
            .expect_err("an attestation without TPM_GENERATED_VALUE must be rejected");
        assert_verification_failed(error);

        Ok(())
    }

    #[test]
    fn validate_certify_rejects_a_mismatched_nonce() -> Result<(), TpmError> {
        let signing_key = signing_key_public(ATTESTATION_ATTRIBUTES, vec![0xcd; 256]);
        let certified_key = certified_key_public();

        let response = CertifyResponse {
            certifyInfo: certify_attestation(&certified_key, &[1, 2, 3])?,
            signature: unverifiable_signature(),
        };

        let error = trusted(signing_key)?
            .validate_certify(&SOFTWARE_PROVIDER, &certified_key, &[1, 2, 4], &response)
            .expect_err("an attestation carrying another nonce must be rejected");
        assert_verification_failed(error);

        Ok(())
    }

    #[test]
    fn validate_certify_rejects_a_mismatched_certified_key_name() -> Result<(), TpmError> {
        let signing_key = signing_key_public(ATTESTATION_ATTRIBUTES, vec![0xcd; 256]);
        let certified_key = certified_key_public();
        let nonce = vec![1, 2, 3];

        let response = CertifyResponse {
            certifyInfo: certify_attestation(&certified_key, &nonce)?,
            signature: unverifiable_signature(),
        };

        let another_key = signing_key_public(TPMA_OBJECT::sign, vec![0x22; 256]);

        let error = trusted(signing_key)?
            .validate_certify(&SOFTWARE_PROVIDER, &another_key, &nonce, &response)
            .expect_err("an attestation naming another object must be rejected");
        assert_verification_failed(error);

        Ok(())
    }

    #[test]
    fn validate_certify_rejects_an_attestation_that_is_not_a_certify() -> Result<(), TpmError> {
        let signing_key = signing_key_public(ATTESTATION_ATTRIBUTES, vec![0xcd; 256]);
        let certified_key = certified_key_public();
        let nonce = vec![1, 2, 3];

        let mut attest = certify_attestation(&certified_key, &nonce)?;
        attest.attested = Some(TPMU_ATTEST::quote(TPMS_QUOTE_INFO {
            pcrSelect: Vec::new(),
            pcrDigest: vec![0x05; 32],
        }));

        let response = CertifyResponse {
            certifyInfo: attest,
            signature: unverifiable_signature(),
        };

        let error = trusted(signing_key)?
            .validate_certify(&SOFTWARE_PROVIDER, &certified_key, &nonce, &response)
            .expect_err("an attestation of another kind must be rejected");
        assert_verification_failed(error);

        Ok(())
    }

    #[test]
    fn validate_certify_rejects_a_signature_hash_the_key_scheme_does_not_name(
    ) -> Result<(), TpmError> {
        let key = attestation_key()?;
        let certified_key = certified_key_public();
        let nonce = vec![1, 2, 3];
        let attest = certify_attestation(&certified_key, &nonce)?;

        // The key's scheme is RSASSA-SHA256, so a SHA-1 signature is not one it makes — but this
        // one is otherwise impeccable: made with this very key, over this very attestation, and
        // it verifies. Feeding a garbage signature here instead would prove nothing, because
        // `validate_signature` rejects garbage with the same `VerificationFailed` variant and the
        // test would pass with the scheme check deleted.
        let response = sign_attestation_with(&key, &attest, TPM_ALG_ID::SHA1)?;

        // Stated as an assertion rather than left as a claim in a comment: without the check
        // under test, this flows through to `validate_signature` and `validate_certify` returns
        // `Ok(())`.
        let signed_blob = {
            let mut buffer = TpmBuffer::new(None);
            attest.toTpm(&mut buffer)?;
            buffer.trim().to_vec()
        };
        assert!(
            Crypto::validate_signature(
                &SOFTWARE_PROVIDER,
                &key.publicPart,
                Crypto::hash(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA1, &signed_blob)?,
                &response.signature,
            )?,
            "the SHA-1 signature must be genuine, or this test passes for the wrong reason"
        );

        let error = trusted(key.publicPart.clone())?
            .validate_certify(&SOFTWARE_PROVIDER, &certified_key, &nonce, &response)
            .expect_err("a signature hash the key's scheme does not name must be rejected");
        assert_verification_failed(error);

        Ok(())
    }

    #[test]
    fn from_activated_credential_rejects_what_the_activation_did_not_prove() -> Result<(), TpmError>
    {
        let public = certified_key_public();
        let name = public.get_name(&SOFTWARE_PROVIDER)?;
        let credential = vec![0x5a; 20];

        // The credential the TPM returned is the one that was made for this Name.
        let trusted = TrustedPublic::from_activated_credential(
            public.clone(),
            &name,
            &credential,
            &credential,
            &SOFTWARE_PROVIDER,
        )?;
        assert_eq!(trusted.name(), name.as_slice());

        // A TPM that could not recover the credential proves nothing.
        assert_verification_failed(
            TrustedPublic::from_activated_credential(
                public.clone(),
                &name,
                &credential,
                &[0x5b; 20],
                &SOFTWARE_PROVIDER,
            )
            .expect_err("a credential that did not come back is not evidence of anything"),
        );

        // Naming one object and then trusting another's public area proves nothing either.
        // This one arrives through `verify_name`, and it is a rejection of an untrusted public
        // area exactly as the credential comparison above is, so it reports the same variant.
        let another_key = signing_key_public(TPMA_OBJECT::sign, vec![0x22; 256]);
        assert_verification_failed(
            TrustedPublic::from_activated_credential(
                another_key,
                &name,
                &credential,
                &credential,
                &SOFTWARE_PROVIDER,
            )
            .expect_err("the activation named a different object than the public area supplied"),
        );

        Ok(())
    }

    /// Pins the variant a Name mismatch reports, which is what lets a caller tell an untrusted
    /// public area from an operational failure without matching on the message.
    ///
    /// Reverting `verify_name` to `GenericError` fails this test and the
    /// `from_activated_credential` case above.
    #[test]
    fn a_name_mismatch_is_a_verification_failure() -> Result<(), TpmError> {
        let public = certified_key_public();
        let name = public.get_name(&SOFTWARE_PROVIDER)?;

        public.verify_name(&name, &SOFTWARE_PROVIDER)?;

        let other_name =
            signing_key_public(TPMA_OBJECT::sign, vec![0x22; 256]).get_name(&SOFTWARE_PROVIDER)?;
        assert_verification_failed(
            public
                .verify_name(&other_name, &SOFTWARE_PROVIDER)
                .expect_err("a public area that does not hash to the expected Name is untrusted"),
        );
        assert_verification_failed(
            TrustedPublic::from_pinned_name(public, &other_name, &SOFTWARE_PROVIDER)
                .expect_err("from_pinned_name rejects on the same grounds"),
        );

        Ok(())
    }
}

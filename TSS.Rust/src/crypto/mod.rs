//! Cryptography used to build and check TPM structures on the host.
//!
//! This module is split into two layers. [`provider`] defines the primitives TSS.Rust needs from
//! a crypto backend, and two implementations are supplied: [`software_provider`], built on the
//! pure-Rust RustCrypto crates and available everywhere, and [`cng_provider`], built on Windows
//! CNG and adding no crates at all.
//! [`Crypto`] sits on top and adds the logic that the TPM 2.0 specification defines in terms of
//! those primitives — digest sizes, KDFa, signature validation — which is the same regardless of
//! which backend is in use.
//!
//! There is no ambient default backend. Every operation that needs one takes a
//! [`CryptoProvider`](provider::CryptoProvider) from its caller, so which backend runs is always
//! visible at the call site. [`Tpm2`](crate::tpm2_impl::Tpm2) holds the provider it was built with
//! and supplies it to the command dispatch path on the caller's behalf.

#[cfg(all(feature = "cng-crypto", windows))]
pub mod cng_provider;
pub mod provider;
#[cfg(feature = "software-crypto")]
pub mod software_provider;

use crate::{error::TpmError, tpm_types::*};
use provider::{CryptoProvider, EccEphemeralAgreement};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// The RSA public exponent the TPM 2.0 specification defines as the default (65537, "F4").
///
/// `TPMS_RSA_PARMS::exponent` encodes this value as zero, so it never travels on the wire.
/// Resolve a stored zero with `TPMS_RSA_PARMS::exponent_bytes` rather than reaching for this
/// constant directly, so that a key declaring a different exponent is honoured.
pub const RSA_DEFAULT_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// RSA private key material in the form `TSS_KEY` persists it: the modulus and the first prime,
/// plus the public exponent needed to reconstruct the key.
///
/// The second prime is recovered by dividing the modulus by the first, so it is not stored.
#[derive(Clone)]
pub struct RsaKeyParts {
    /// The modulus, which is public.
    pub modulus: Vec<u8>,

    /// The first prime factor, which is the whole of the private key.
    ///
    /// It sits beside the modulus, so the second prime, and from it the private exponent, follow
    /// from a single division. It is therefore wiped when dropped, and withheld from the [`Debug`]
    /// rendering below. Because the wipe is a `Drop`, this field cannot be moved out of the
    /// struct: take it with [`std::mem::take`] instead.
    pub prime: Vec<u8>,

    /// The public exponent, big-endian and without leading zeros. Callers holding a
    /// `TPMS_RSA_PARMS` should populate this with `TPMS_RSA_PARMS::exponent_bytes`, which
    /// resolves the specification's zero-means-65537 encoding.
    pub exponent: Vec<u8>,
}

/// Renders the public parts of the key in full and the prime not at all.
///
/// A derived `Debug` would put the private key into any log line that formats a generated or
/// reconstructed key, which includes every error path that reports the key it was working on.
impl fmt::Debug for RsaKeyParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKeyParts")
            .field("modulus", &self.modulus)
            .field("prime", &format_args!("<redacted>"))
            .field("exponent", &self.exponent)
            .finish()
    }
}

/// Wipes the prime, so that a key that has gone out of scope is not left in freed heap.
///
/// `Clone` copies the prime, and every copy is wiped by this same implementation.
impl Drop for RsaKeyParts {
    fn drop(&mut self) {
        self.prime.zeroize();
    }
}

#[cfg(test)]
mod secret_redaction_tests {
    use super::*;

    #[test]
    fn rsa_key_parts_debug_withholds_the_private_prime() {
        // Bytes chosen so that neither their decimal nor their hexadecimal rendering is a
        // substring of anything the redacted `Debug` legitimately prints.
        let prime = vec![0xA7u8, 0xB3, 0xC9, 0xD1, 0xE5, 0xF2];
        let key = RsaKeyParts {
            modulus: vec![0x11, 0x22],
            prime: prime.clone(),
            exponent: RSA_DEFAULT_EXPONENT.to_vec(),
        };

        let rendered = format!("{:?}", key);

        for byte in &prime {
            assert!(
                !rendered.contains(&byte.to_string()),
                "debug rendering {rendered} leaks prime byte {byte} in decimal"
            );
            assert!(
                !rendered.to_lowercase().contains(&format!("{byte:02x}")),
                "debug rendering {rendered} leaks prime byte {byte} in hex"
            );
        }
        assert!(
            !rendered.contains(&format!("{:?}", prime)),
            "debug rendering {rendered} leaks the prime verbatim"
        );

        // The public parts stay legible, which is the point of hand writing the rendering rather
        // than dropping `Debug` altogether.
        assert!(rendered.contains(&format!("{:?}", key.modulus)));
        assert!(rendered.contains(&format!("{:?}", key.exponent)));
    }

    #[test]
    fn rsa_key_parts_still_clones() {
        let key = RsaKeyParts {
            modulus: vec![0x11, 0x22],
            prime: vec![0xA7, 0xB3],
            exponent: RSA_DEFAULT_EXPONENT.to_vec(),
        };

        let copy = key.clone();

        assert_eq!(copy.modulus, key.modulus);
        assert_eq!(copy.prime, key.prime);
        assert_eq!(copy.exponent, key.exponent);
    }
}

pub struct Crypto;

impl Crypto {
    /// The length in bytes of a digest produced by `alg`, or zero if `alg` is not a hash.
    ///
    /// This is fixed by the TPM 2.0 specification, so it does not depend on the backend.
    ///
    /// Returning zero rather than an error is deliberate, and there are two reasons not to
    /// "fix" it. `TPMT_HA` unmarshalling calls this to decide how many digest bytes to read,
    /// and a `TPMT_HA` selected by `TPM_ALG_NULL` carries no digest at all, so zero is the
    /// correct answer there rather than a failure. That call site also lives in a generated
    /// file, which cannot be hand edited, and it has no error path to return one through.
    ///
    /// Every other caller wants `digest_size_checked`, which turns the zero into an error.
    // The function is called from an auto-generated file that expects this specific (non snake_cased) name
    #[allow(non_snake_case)]
    pub fn digestSize(alg: TPM_ALG_ID) -> usize {
        match alg {
            TPM_ALG_ID::SHA1 => 20,
            TPM_ALG_ID::SHA256 => 32,
            TPM_ALG_ID::SHA384 => 48,
            TPM_ALG_ID::SHA512 => 64,
            TPM_ALG_ID::SM3_256 => 32,
            _ => 0,
        }
    }

    /// The length in bytes of a digest produced by `alg`, or an error if `alg` is not a hash.
    ///
    /// This is the variant to reach for by default. `digestSize` answers zero for a non-hash
    /// algorithm, which silently produces an empty seed, key or nonce wherever the result sizes
    /// a buffer. Use `digestSize` only where a zero length is a legitimate answer, which in
    /// practice means `TPMT_HA` unmarshalling.
    pub fn digest_size_checked(alg: TPM_ALG_ID) -> Result<usize, TpmError> {
        match Self::digestSize(alg) {
            0 => Err(TpmError::NotSupported(format!(
                "Not a hash algorithm: {alg:?}"
            ))),
            size => Ok(size),
        }
    }

    // Hash a byte buffer using the specified algorithm
    pub fn hash(
        provider: &CryptoProvider,
        alg: TPM_ALG_ID,
        data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.hash)(alg, data)
    }

    pub fn hmac(
        provider: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        key: &[u8],
        to_hash: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.hmac)(hash_alg, key, to_hash)
    }

    /// RSA-OAEP encrypt `data` under the public key given by its big-endian components.
    ///
    /// `label` is used verbatim, so callers must include the trailing NUL that the TPM
    /// specification puts in labels such as `b"IDENTITY\0"`.
    pub fn rsa_oaep_encrypt(
        provider: &CryptoProvider,
        modulus: &[u8],
        exponent: &[u8],
        hash_alg: TPM_ALG_ID,
        label: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.rsa.oaep_encrypt)(modulus, exponent, hash_alg, label, data)
    }

    /// Verify an RSASSA-PKCS1-v1_5 signature over an already computed digest.
    pub fn rsa_pkcs1v15_verify(
        provider: &CryptoProvider,
        modulus: &[u8],
        exponent: &[u8],
        hash_alg: TPM_ALG_ID,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<bool, TpmError> {
        (provider.rsa.pkcs1v15_verify)(modulus, exponent, hash_alg, digest, signature)
    }

    /// Generate an RSA key pair with the given public exponent, returning the modulus and the
    /// first prime.
    ///
    /// `exponent` is big-endian. Callers holding a `TPMS_RSA_PARMS` should pass
    /// `TPMS_RSA_PARMS::exponent_bytes`, which resolves the zero-means-65537 encoding. A backend
    /// that cannot honour an arbitrary exponent must reject it rather than substitute its own.
    pub fn rsa_generate_keypair(
        provider: &CryptoProvider,
        key_bits: usize,
        exponent: &[u8],
    ) -> Result<RsaKeyParts, TpmError> {
        (provider.rsa.generate_keypair)(key_bits, exponent)
    }

    /// Sign an already computed digest with RSASSA-PKCS1-v1_5.
    pub fn rsa_pkcs1v15_sign(
        provider: &CryptoProvider,
        key: &RsaKeyParts,
        hash_alg: TPM_ALG_ID,
        digest: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.rsa.pkcs1v15_sign)(key, hash_alg, digest)
    }

    /// The width in bytes of one coordinate on `curve`.
    ///
    /// This is a property of the curve as the TCG registry defines it, not of the backend, so it
    /// is answered here and every provider agrees on it. It matters because a TPM may drop leading
    /// zero bytes from a coordinate it marshals into a `TPM2B`, while the key derivation hashes
    /// coordinates at their full width. Padding a short coordinate back out before it reaches
    /// [`Crypto::kdfe`] is what keeps both sides deriving the same value.
    ///
    /// A curve outside the registry is an error rather than a guess, because guessing a width
    /// produces a plausible-looking key that simply does not match the peer's.
    pub fn ecc_coordinate_size(curve: TPM_ECC_CURVE) -> Result<usize, TpmError> {
        match curve {
            TPM_ECC_CURVE::NIST_P192 => Ok(24),
            TPM_ECC_CURVE::NIST_P224 => Ok(28),
            TPM_ECC_CURVE::NIST_P256 => Ok(32),
            TPM_ECC_CURVE::NIST_P384 => Ok(48),
            // P-521's order is 521 bits, which occupies 66 bytes with the top 7 bits unused.
            TPM_ECC_CURVE::NIST_P521 => Ok(66),
            TPM_ECC_CURVE::BN_P256 => Ok(32),
            TPM_ECC_CURVE::BN_P638 => Ok(80),
            TPM_ECC_CURVE::SM2_P256 => Ok(32),
            // The registry's test curve, which is a 192 bit curve distinct from NIST P-192. Its
            // width is answered like any other because this is a registry lookup; whether a
            // backend will agree over it is a separate question that the backend answers.
            TPM_ECC_CURVE::TEST_P192 => Ok(24),
            other => Err(TpmError::NotSupported(format!(
                "Unknown ECC curve {other}, so its coordinate width is unknown"
            ))),
        }
    }

    /// Left pads an ECC coordinate to a fixed width.
    ///
    /// A TPM is free to drop leading zero bytes when it marshals a coordinate into a `TPM2B`, so a
    /// coordinate arriving short is normal and is restored here. One arriving long belongs to a
    /// different curve than the caller believes, which is an error rather than something to
    /// truncate.
    pub fn pad_ecc_coordinate(value: &[u8], width: usize) -> Result<Vec<u8>, TpmError> {
        if value.len() > width {
            return Err(TpmError::InvalidArraySize(format!(
                "A {} byte coordinate does not fit a {} byte curve",
                value.len(),
                width
            )));
        }

        let mut padded = vec![0u8; width - value.len()];
        padded.extend_from_slice(value);
        Ok(padded)
    }

    /// Generate an ephemeral key on `curve` and agree with the public point `(peer_x, peer_y)`.
    ///
    /// The agreed value is returned raw. Callers wanting key material run [`Crypto::kdfe`] over
    /// it, which is where the TPM's derivation is defined.
    pub fn ecc_ephemeral_agree(
        provider: &CryptoProvider,
        curve: TPM_ECC_CURVE,
        peer_x: &[u8],
        peer_y: &[u8],
    ) -> Result<EccEphemeralAgreement, TpmError> {
        (provider.ecc.ephemeral_agree)(curve, peer_x, peer_y)
    }

    pub fn validate_signature(
        provider: &CryptoProvider,
        public_key: &TPMT_PUBLIC,
        signed_blob_hash: Vec<u8>,
        signature: &Option<TPMU_SIGNATURE>,
    ) -> Result<bool, TpmError> {
        let rsa_params =
            if let Some(TPMU_PUBLIC_PARMS::rsaDetail(params)) = &public_key.parameters {
                params
            } else {
                return Err(TpmError::NotSupported(
                    "ValidateSignature: Only RSA is supported".to_string(),
                ));
            };

        let signature = if let Some(TPMU_SIGNATURE::rsassa(signature)) = &signature {
            signature
        } else {
            return Err(TpmError::NotSupported(
                "ValidateSignature: Only RSASSA scheme is supported".to_string(),
            ));
        };

        let rsa_pub_key = if let Some(TPMU_PUBLIC_ID::rsa(unique)) = &public_key.unique {
            &unique.buffer
        } else {
            return Err(TpmError::NotSupported(
                "ValidateSignature: Only RSA public key is supported".to_string(),
            ));
        };

        let expected_digest_size = Self::digest_size_checked(signature.hash)?;
        if signed_blob_hash.len() != expected_digest_size {
            return Err(TpmError::InvalidArraySize(format!(
                "ValidateSignature: digest length {} does not match {:?} length {}",
                signed_blob_hash.len(),
                signature.hash,
                expected_digest_size
            )));
        }

        Self::rsa_pkcs1v15_verify(
            provider,
            rsa_pub_key,
            &rsa_params.exponent_bytes(),
            signature.hash,
            &signed_blob_hash,
            &signature.sig,
        )
    }

    /// Reduce a generated KDF stream to `bits` bits, as TPM 2.0 Part 1 section 11.4.10 requires.
    ///
    /// Both KDFs generate whole digests, so the stream is normally longer than the request. The
    /// bits kept are the leftmost ones, and they come back right aligned in the fewest octets that
    /// hold them: a request that is not a whole number of octets leaves the unused bits of the
    /// leading octet zero rather than handing back extra significant bits. Simply truncating to
    /// whole octets would return a different value, which is why TSS.NET and TSS.CPP both shift
    /// their stream instead (`CryptoLib.KDFa` and `Crypto::KDFa` respectively).
    ///
    /// Every KDF call the TPM 2.0 protocol makes of itself asks for a digest or symmetric key
    /// size, all of which are whole octets, and for those this is exactly a truncation. The shift
    /// matters only to a caller using these KDFs for something the TPM does not.
    ///
    /// `stream` must hold at least `bits` bits, which both callers guarantee by generating whole
    /// digests until it does.
    fn truncate_kdf_stream(stream: &[u8], bits: usize) -> Vec<u8> {
        debug_assert!(
            stream.len() * 8 >= bits,
            "KDF stream is shorter than the request"
        );

        let octets_needed = bits.div_ceil(8);
        let bit_shift = (stream.len() * 8 - bits) % 8;
        let mut result = stream[..octets_needed].to_vec();

        if bit_shift != 0 {
            // A big endian right shift: every octet takes the bits falling out of the one above it.
            let mut carry = 0u8;
            for octet in result.iter_mut() {
                let fell_out = *octet << (8 - bit_shift);
                *octet = (*octet >> bit_shift) | carry;
                carry = fell_out;
            }
        }

        result
    }

    /// A buffer for a KDF stream, sized so that filling it never reallocates.
    ///
    /// Both KDFs append whole digests until the stream covers the request, so one digest beyond
    /// `bytes_needed` is the most that can ever be generated. Reserving that up front is not an
    /// optimisation: the buffer accumulates the derived key, and growing a `Vec` frees the old
    /// allocation without wiping it, which would leave a copy of that key behind and defeat the
    /// `Zeroizing` wrapper.
    fn kdf_stream_buffer(hash_alg: TPM_ALG_ID, bytes_needed: usize) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(Vec::with_capacity(
            bytes_needed + Self::digestSize(hash_alg),
        ))
    }

    // KDFa implementation as specified in TPM 2.0 Part 1
    pub fn kdfa(
        provider: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        key: &[u8],
        label: &str,
        context_u: &[u8],
        context_v: &[u8],
        bits: usize,
    ) -> Result<Vec<u8>, TpmError> {
        // Zero bits would make the loop below exit immediately and hand back an empty key, which
        // every caller would then use as if it were real key material.
        if bits == 0 {
            return Err(TpmError::InvalidArraySize(
                "KDFa was asked to produce zero bits of key material".to_string(),
            ));
        }

        let bytes_needed = bits.div_ceil(8);
        let mut result = Self::kdf_stream_buffer(hash_alg, bytes_needed);
        let mut counter = 1u32;

        while result.len() < bytes_needed {
            let mut to_hash = Vec::new();

            // Counter in big-endian
            to_hash.extend_from_slice(&counter.to_be_bytes());

            // Label
            to_hash.extend_from_slice(label.as_bytes());

            // 00 byte separator
            to_hash.push(0u8);

            // contextU
            to_hash.extend_from_slice(context_u);

            // contextV
            to_hash.extend_from_slice(context_v);

            // Number of bits in big-endian
            to_hash.extend_from_slice(&(bits as u32).to_be_bytes());

            // Perform HMAC. The digest is key material, so it is wiped once appended; `to_hash`
            // is not, because everything in it is public and the key travels separately.
            let hmac_result = Zeroizing::new(Self::hmac(provider, hash_alg, key, &to_hash)?);
            result.extend_from_slice(&hmac_result);

            counter = counter.checked_add(1).ok_or_else(|| {
                TpmError::InvalidArraySize("Counter overflow in KDFa".to_string())
            })?;
        }

        // Truncate to exact size needed
        Ok(Self::truncate_kdf_stream(&result, bits))
    }

    /// KDFe, the derivation TPM 2.0 Part 1 section 11.4.10.3 defines for ECDH secret sharing.
    ///
    /// This is the SP800-56A concatenation KDF. Each iteration hashes a big endian counter, the
    /// agreed value, the label and both parties' contributions; the iterations are concatenated
    /// and truncated to the requested length.
    ///
    /// It differs from [`Crypto::kdfa`] in two ways that are easy to conflate. It hashes rather
    /// than HMACs, so the agreed value is part of the hashed input instead of being a key. And the
    /// requested length is not itself hashed, where KDFa appends it to every iteration. Using one
    /// where the other is meant yields output of the right shape and the wrong value.
    ///
    /// `party_u_info` is the initiator's X coordinate and `party_v_info` the responder's. Both
    /// ends have to make the same assignment regardless of which role they are playing, so a
    /// party reproducing an agreement keeps the originator's point as U even though it is the one
    /// receiving. Swapping them derives a different value in silence.
    ///
    /// Coordinates must arrive at the curve's full width; see [`Crypto::ecc_coordinate_size`].
    pub fn kdfe(
        provider: &CryptoProvider,
        hash_alg: TPM_ALG_ID,
        z: &[u8],
        label: &str,
        party_u_info: &[u8],
        party_v_info: &[u8],
        bits: usize,
    ) -> Result<Vec<u8>, TpmError> {
        // As in KDFa, zero bits would exit the loop immediately and hand back an empty key that
        // every caller would then treat as real key material.
        if bits == 0 {
            return Err(TpmError::InvalidArraySize(
                "KDFe was asked to produce zero bits of key material".to_string(),
            ));
        }

        // An agreement that produced nothing cannot key anything, and hashing an empty Z would
        // still yield plausible-looking output.
        if z.is_empty() {
            return Err(TpmError::InvalidArraySize(
                "KDFe was given an empty agreed value".to_string(),
            ));
        }

        let bytes_needed = bits.div_ceil(8);
        let mut result = Self::kdf_stream_buffer(hash_alg, bytes_needed);
        let mut counter = 1u32;

        // Unlike KDFa, the hashed input contains the agreed value itself, so the buffer holding it
        // is as sensitive as `z` and is wiped on the same terms. Its length is the same on every
        // iteration, so reserving it exactly means the one allocation is the only copy made.
        let hashed_len = std::mem::size_of_val(&counter)
            + z.len()
            + label.len()
            + 1
            + party_u_info.len()
            + party_v_info.len();

        while result.len() < bytes_needed {
            let mut to_hash = Zeroizing::new(Vec::with_capacity(hashed_len));

            // Counter in big-endian
            to_hash.extend_from_slice(&counter.to_be_bytes());

            // The agreed value
            to_hash.extend_from_slice(z);

            // Label, with the terminating NUL the specification includes in the hash
            to_hash.extend_from_slice(label.as_bytes());
            to_hash.push(0u8);

            // Each party's contribution
            to_hash.extend_from_slice(party_u_info);
            to_hash.extend_from_slice(party_v_info);

            let digest = Zeroizing::new(Self::hash(provider, hash_alg, &to_hash)?);
            result.extend_from_slice(&digest);

            counter = counter.checked_add(1).ok_or_else(|| {
                TpmError::InvalidArraySize("Counter overflow in KDFe".to_string())
            })?;
        }

        Ok(Self::truncate_kdf_stream(&result, bits))
    }

    // AES CFB encryption/decryption
    pub fn cfb_xcrypt(
        provider: &CryptoProvider,
        encrypt: bool,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        (provider.aes_cfb)(encrypt, key, iv, data)
    }

    /// Return `num_bytes` of cryptographically secure random data.
    pub fn get_random(provider: &CryptoProvider, num_bytes: usize) -> Result<Vec<u8>, TpmError> {
        let mut result = vec![0u8; num_bytes];
        (provider.random)(&mut result)?;
        Ok(result)
    }
}

// These tests exercise the software provider directly -- they verify against the `rsa` crate --
// so they only apply when that backend is compiled in.
#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{Oaep, Pkcs1v15Sign, RsaPrivateKey};
    use sha2::{Digest as Sha2Digest, Sha256};
    use software_provider::SOFTWARE_PROVIDER;

    #[test]
    fn validate_signature_uses_signature_hash_algorithm() -> Result<(), TpmError> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| TpmError::GenericError(format!("RSA key generation failed: {e}")))?;
        let public_key = TPMT_PUBLIC {
            parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::default())),
            unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA {
                buffer: private_key.n().to_bytes_be(),
            })),
            ..Default::default()
        };

        let message = b"digest dispatch regression";
        let digest = Sha256::digest(message).to_vec();
        let sig = private_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|e| TpmError::GenericError(format!("RSA signing failed: {e}")))?;
        let signature = Some(TPMU_SIGNATURE::rsassa(TPMS_SIGNATURE_RSASSA {
            hash: TPM_ALG_ID::SHA256,
            sig,
        }));

        assert!(Crypto::validate_signature(
            &SOFTWARE_PROVIDER,
            &public_key,
            digest,
            &signature
        )?);
        Ok(())
    }

    #[test]
    fn rsa_oaep_encrypt_round_trips_and_binds_the_label() -> Result<(), TpmError> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| TpmError::GenericError(format!("RSA key generation failed: {e}")))?;
        let modulus = private_key.n().to_bytes_be();

        let plaintext = b"seed material";
        let ciphertext = Crypto::rsa_oaep_encrypt(
            &SOFTWARE_PROVIDER,
            &modulus,
            &RSA_DEFAULT_EXPONENT,
            TPM_ALG_ID::SHA256,
            b"IDENTITY\0",
            plaintext,
        )?;

        let decrypted = private_key
            .decrypt(Oaep::new_with_label::<Sha256, _>("IDENTITY\0"), &ciphertext)
            .map_err(|e| TpmError::GenericError(format!("OAEP decryption failed: {e}")))?;
        assert_eq!(decrypted, plaintext);

        // A different label must not recover the plaintext. This is what keeps the "IDENTITY\0"
        // and "SECRET\0" call sites distinct now that they share one implementation.
        assert!(private_key
            .decrypt(Oaep::new_with_label::<Sha256, _>("SECRET\0"), &ciphertext)
            .is_err());

        Ok(())
    }

    #[test]
    fn rsa_sign_round_trips_through_verify() -> Result<(), TpmError> {
        let key = Crypto::rsa_generate_keypair(&SOFTWARE_PROVIDER, 2048, &RSA_DEFAULT_EXPONENT)?;
        let digest = Sha256::digest(b"software key signing regression").to_vec();

        let signature =
            Crypto::rsa_pkcs1v15_sign(&SOFTWARE_PROVIDER, &key, TPM_ALG_ID::SHA256, &digest)?;

        assert!(Crypto::rsa_pkcs1v15_verify(
            &SOFTWARE_PROVIDER,
            &key.modulus,
            &RSA_DEFAULT_EXPONENT,
            TPM_ALG_ID::SHA256,
            &digest,
            &signature,
        )?);
        Ok(())
    }

    #[test]
    fn rsa_verify_rejects_a_malformed_signature_rather_than_failing() -> Result<(), TpmError> {
        let key = Crypto::rsa_generate_keypair(&SOFTWARE_PROVIDER, 2048, &RSA_DEFAULT_EXPONENT)?;
        let digest = Sha256::digest(b"malformed signature rejection").to_vec();

        // A signature that cannot verify is an answer rather than a failure, so each of these is
        // `Ok(false)` and none of them is `Err`. None is reachable only by mistake either: a
        // signature arrives from whoever sent it, and nothing stops it being short or numerically
        // at or above the modulus. The CNG provider is held to the same by
        // `pkcs1v15_verification_agrees_with_the_software_provider`, and the two backends are
        // interchangeable only while both answer this way.
        let not_below_modulus = vec![0xffu8; key.modulus.len()];
        let one_byte_short = vec![0x01u8; key.modulus.len() - 1];
        let one_byte_long = vec![0x01u8; key.modulus.len() + 1];

        let candidates: [(&str, Vec<u8>); 4] = [
            ("a signature not below the modulus", not_below_modulus),
            ("a signature one byte short", one_byte_short),
            ("a signature one byte long", one_byte_long),
            ("an empty signature", Vec::new()),
        ];

        for (description, candidate) in candidates {
            let verified = Crypto::rsa_pkcs1v15_verify(
                &SOFTWARE_PROVIDER,
                &key.modulus,
                &RSA_DEFAULT_EXPONENT,
                TPM_ALG_ID::SHA256,
                &digest,
                &candidate,
            )?;
            assert!(!verified, "the software provider accepted {description}");
        }

        Ok(())
    }

    #[test]
    fn rsa_sign_rejects_a_zero_prime_instead_of_dividing_by_it() {
        let key = RsaKeyParts {
            modulus: vec![0xff; 256],
            prime: vec![0u8; 128],
            exponent: RSA_DEFAULT_EXPONENT.to_vec(),
        };

        assert!(Crypto::rsa_pkcs1v15_sign(
            &SOFTWARE_PROVIDER,
            &key,
            TPM_ALG_ID::SHA256,
            &[0u8; 32]
        )
        .is_err());
    }

    #[test]
    fn rsa_sign_rejects_a_prime_that_does_not_divide_the_modulus() {
        // `from_p_q` recomputes the modulus as `p * q` rather than checking it against the one
        // supplied, so a prime that does not divide the modulus exactly would otherwise yield a
        // key with a silently different modulus whose signatures could never verify.
        let key = RsaKeyParts {
            modulus: vec![0xff; 256],
            prime: vec![0xfe; 128],
            exponent: RSA_DEFAULT_EXPONENT.to_vec(),
        };

        assert!(Crypto::rsa_pkcs1v15_sign(
            &SOFTWARE_PROVIDER,
            &key,
            TPM_ALG_ID::SHA256,
            &[0u8; 32]
        )
        .is_err());
    }

    #[test]
    fn rsa_round_trips_with_a_non_default_exponent() -> Result<(), TpmError> {
        // Generating with an exponent other than the default proves that generation, signing and
        // verification all read the caller's exponent instead of assuming 65537.
        let exponent: [u8; 3] = [0x00, 0x00, 0x03];
        let key = Crypto::rsa_generate_keypair(&SOFTWARE_PROVIDER, 2048, &exponent)?;
        assert_eq!(key.exponent, vec![0x03]);

        let digest = Sha256::digest(b"non default exponent").to_vec();
        let signature =
            Crypto::rsa_pkcs1v15_sign(&SOFTWARE_PROVIDER, &key, TPM_ALG_ID::SHA256, &digest)?;

        assert!(Crypto::rsa_pkcs1v15_verify(
            &SOFTWARE_PROVIDER,
            &key.modulus,
            &key.exponent,
            TPM_ALG_ID::SHA256,
            &digest,
            &signature,
        )?);

        // The default exponent must not verify a signature made with this key.
        assert!(!Crypto::rsa_pkcs1v15_verify(
            &SOFTWARE_PROVIDER,
            &key.modulus,
            &RSA_DEFAULT_EXPONENT,
            TPM_ALG_ID::SHA256,
            &digest,
            &signature,
        )?);
        Ok(())
    }

    #[test]
    fn hash_of_empty_input_is_the_real_digest() -> Result<(), TpmError> {
        // The empty string has a well known SHA-256 digest. Returning zeros of the right length
        // instead looks plausible but never matches what a TPM computes.
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(
            Crypto::hash(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &[])?,
            expected
        );
        Ok(())
    }

    #[test]
    fn hash_of_empty_input_still_rejects_an_unsupported_algorithm() {
        assert!(Crypto::hash(&SOFTWARE_PROVIDER, TPM_ALG_ID::NULL, &[]).is_err());
    }

    #[test]
    fn digest_size_checked_rejects_a_non_hash_algorithm() {
        assert_eq!(
            Crypto::digest_size_checked(TPM_ALG_ID::SHA256).ok(),
            Some(32)
        );
        assert!(Crypto::digest_size_checked(TPM_ALG_ID::NULL).is_err());
        assert!(Crypto::digest_size_checked(TPM_ALG_ID::RSA).is_err());
    }

    #[test]
    fn every_registry_curve_reports_a_coordinate_size() {
        // The generated `try_from` accepts exactly the curves the TCG registry names, so sweeping
        // it enumerates them without this test carrying a second list that could drift from the
        // first. A curve that is in the registry has a defined width, and answering "unsupported"
        // for one of them is the bug this guards against: it is a registry lookup, so it must not
        // depend on which curves a backend happens to implement. `NONE` is the absence of a curve
        // rather than a curve, so it has no width and is expected to fail.
        let mut curves_seen = 0;

        for raw in 0..=u16::MAX {
            let Ok(curve) = TPM_ECC_CURVE::try_from(raw) else {
                continue;
            };
            curves_seen += 1;

            if raw == 0 {
                assert!(
                    Crypto::ecc_coordinate_size(curve).is_err(),
                    "TPM_ECC_CURVE::NONE is not a curve and must not report a width"
                );
                continue;
            }

            let size = Crypto::ecc_coordinate_size(curve).unwrap_or_else(|e| {
                panic!("registry curve {raw:#06x} has no coordinate size: {e:?}")
            });
            assert!(size > 0, "curve {raw:#06x} reported a zero width");
        }

        // Guards the sweep itself: if `try_from` ever stopped accepting anything, every assertion
        // above would be skipped and the test would pass while checking nothing.
        assert!(
            curves_seen > 1,
            "the curve sweep found nothing to check, so it proved nothing"
        );
    }

    #[test]
    fn ecc_coordinate_sizes_match_the_curve_widths() {
        // Spot checks against the registry, so that a wrong-but-non-zero width cannot pass the
        // sweep above. P-521 is the one worth stating outright: 521 bits occupies 66 octets, with
        // the top seven bits of the leading octet unused.
        for (curve, expected) in [
            (TPM_ECC_CURVE::NIST_P192, 24),
            (TPM_ECC_CURVE::NIST_P224, 28),
            (TPM_ECC_CURVE::NIST_P256, 32),
            (TPM_ECC_CURVE::NIST_P384, 48),
            (TPM_ECC_CURVE::NIST_P521, 66),
        ] {
            assert_eq!(Crypto::ecc_coordinate_size(curve).ok(), Some(expected));
        }
    }

    #[test]
    fn kdfa_rejects_a_request_for_zero_bits() {
        // Sizing a KDFa request from `digestSize` of a non-hash algorithm used to ask for zero
        // bits, and KDFa answered with an empty key instead of failing.
        assert!(Crypto::kdfa(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            b"key",
            "ATH",
            &[],
            &[],
            0
        )
        .is_err());
    }

    #[test]
    fn kdfa_produces_the_requested_length() -> Result<(), TpmError> {
        let derived = Crypto::kdfa(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            b"key",
            "ATH",
            &[],
            &[],
            256,
        )?;
        assert_eq!(derived.len(), 32);
        Ok(())
    }

    /// KDFe against a value computed outside this crate.
    ///
    /// The round trip in `tpm_type_extensions` runs both ends of an activation through this same
    /// function, so it would agree with itself even if the construction were wrong. This pins the
    /// construction to an independently derived answer instead.
    #[test]
    fn kdfe_matches_an_independently_computed_vector() -> Result<(), TpmError> {
        let z = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        let party_u = [0xaau8; 32];
        let party_v = [0xbbu8; 32];

        // SHA256(BE32(1) || Z || "IDENTITY" || 0x00 || partyU || partyV).
        let one_block =
            hex_to_bytes("32721732041999b0cde95bc6f0702059883b6ddf7ba7635ffc3e3c09f4914cd4");

        let derived = Crypto::kdfe(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &z,
            "IDENTITY",
            &party_u,
            &party_v,
            256,
        )?;
        assert_eq!(
            derived, one_block,
            "KDFe should hash the counter, Z, the NUL terminated label and both parties, and \
             nothing else. In particular the requested length is not hashed, which is where it \
             differs from KDFa."
        );

        // A second block continues with counter 2 rather than restarting.
        let two_blocks = hex_to_bytes(
            "32721732041999b0cde95bc6f0702059883b6ddf7ba7635ffc3e3c09f4914cd4\
             b2f1a09b1730caf33fea691a5aac61ac2a064c64c0688fd3588776ed5cd6e5ec",
        );
        assert_eq!(
            Crypto::kdfe(
                &SOFTWARE_PROVIDER,
                TPM_ALG_ID::SHA256,
                &z,
                "IDENTITY",
                &party_u,
                &party_v,
                512
            )?,
            two_blocks
        );

        // A length that is not a whole number of digests is truncated, not rounded up.
        assert_eq!(
            Crypto::kdfe(
                &SOFTWARE_PROVIDER,
                TPM_ALG_ID::SHA256,
                &z,
                "IDENTITY",
                &party_u,
                &party_v,
                200
            )?,
            one_block[..25]
        );

        Ok(())
    }

    /// A request that is not a whole number of octets, which the TPM never makes but a caller can.
    ///
    /// The bits kept are the leftmost ones and they come back right aligned, so the answer is the
    /// stream shifted right, not the stream with its tail chopped off. TSS.NET and TSS.CPP both
    /// shift, and disagreeing with them would put this library on the wrong side of an interop
    /// boundary the moment anyone drove a KDF from one of the other stacks.
    #[test]
    fn kdf_right_aligns_a_request_that_is_not_a_whole_number_of_octets() -> Result<(), TpmError> {
        let z = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        let party_u = [0xaau8; 32];
        let party_v = [0xbbu8; 32];

        // The same inputs as the vector above, so the stream being reduced is already pinned to an
        // independently computed digest. 250 bits still occupy 32 octets, holding that digest
        // shifted right by the 6 bits that were not asked for.
        let shifted =
            hex_to_bytes("00c9c85cc8106666c337a56f1bc1c0816620edb77dee9d8d7ff0f8f027d24533");
        let derived = Crypto::kdfe(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &z,
            "IDENTITY",
            &party_u,
            &party_v,
            250,
        )?;

        assert_eq!(derived, shifted);
        assert_eq!(
            derived[0] >> 2,
            0,
            "the 6 octet bits that were not requested should be zero"
        );

        // KDFa reduces its stream the same way. Its own answer has to be pinned separately rather
        // than compared against a 256 bit call, because KDFa hashes the requested length into
        // every iteration, so asking for 250 bits changes the stream instead of just shortening it.
        let kdfa_shifted =
            hex_to_bytes("020f0ff8ba4b653c0586d60a3a3e7c772a74a26b11f8d9304124f2b5dee29068");
        let kdfa_derived = Crypto::kdfa(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            b"key",
            "ATH",
            &[],
            &[],
            250,
        )?;
        assert_eq!(
            kdfa_derived, kdfa_shifted,
            "KDFa should shift its stream rather than truncate it"
        );

        Ok(())
    }

    #[test]
    fn kdfe_rejects_inputs_that_would_yield_unusable_key_material() {
        let z = [0x01u8; 32];

        // Zero bits would leave the loop immediately and return an empty key that callers would
        // treat as real, which is the same trap KDFa had.
        assert!(Crypto::kdfe(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &z,
            "IDENTITY",
            &[],
            &[],
            0
        )
        .is_err());

        // An agreement that produced nothing cannot key anything, but hashing it would still
        // yield output that looks like a key.
        assert!(Crypto::kdfe(
            &SOFTWARE_PROVIDER,
            TPM_ALG_ID::SHA256,
            &[],
            "IDENTITY",
            &[],
            &[],
            256
        )
        .is_err());
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let digits: Vec<u8> = hex
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .map(|b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("test vector is not hexadecimal"),
            })
            .collect();

        digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
    }

    #[test]
    fn aes_cfb_round_trips_at_every_key_size() -> Result<(), TpmError> {
        // AES-192 and AES-256 keys used to be handed to an AES-128 cipher, which panicked.
        let iv = [0x5au8; 16];
        // Deliberately not a multiple of the block size, to cover the trailing partial block.
        let plaintext = b"CFB spans partial blocks too";

        for key_size in [16usize, 24, 32] {
            let key = vec![0xa5u8; key_size];
            let ciphertext = Crypto::cfb_xcrypt(&SOFTWARE_PROVIDER, true, &key, &iv, plaintext)?;
            assert_eq!(ciphertext.len(), plaintext.len());
            assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

            let recovered = Crypto::cfb_xcrypt(&SOFTWARE_PROVIDER, false, &key, &iv, &ciphertext)?;
            assert_eq!(recovered.as_slice(), plaintext.as_slice());
        }
        Ok(())
    }

    #[test]
    fn aes_cfb_rejects_an_unsupported_key_size() {
        assert!(
            Crypto::cfb_xcrypt(&SOFTWARE_PROVIDER, true, &[0u8; 20], &[0u8; 16], b"data").is_err()
        );
    }
}

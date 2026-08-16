//! A [`CryptoProvider`] built on Windows CNG.
//!
//! This backend adds no crates at all. Everything below is a call into `bcrypt.dll` through the
//! bindings the crate already depends on, so a Windows host can drop the `software-crypto`
//! feature and stop linking a second implementation of primitives the operating system already
//! ships, in FIPS validated form and under its own servicing.
//!
//! It does not replace [`software_provider`](super::software_provider) outright. Two of the nine
//! primitives are left unimplemented, for the reason recorded on
//! [`RsaOps`](super::provider::RsaOps): signing here needs the second prime recovered by dividing
//! the modulus by the first, and CNG exposes no big-integer division. A host that needs those two
//! keeps the software provider for them.
//!
//! Three things about this backend are worth knowing before reading it, because each is a place
//! where the obvious CNG call is the wrong one:
//!
//! * **No algorithm provider is ever opened.** Windows 8 introduced pseudo-handles, constants that
//!   stand in for an already-open provider, and the bindings expose one for every algorithm needed
//!   here. There is therefore no `BCryptOpenAlgorithmProvider`, no matching close, and no lifetime
//!   to manage for them.
//! * **AES-CFB is built on ECB rather than on `BCRYPT_CHAIN_MODE_CFB`.** See [`aes_cfb`].
//! * **The agreed ECDH value comes back byte reversed.** See [`raw_secret`].

use super::provider::{CryptoProvider, EccEphemeralAgreement, EccOps, RsaOps};
use super::Crypto;
use crate::{
    error::TpmError,
    tpm_types::{TPM_ALG_ID, TPM_ECC_CURVE},
};

use std::ffi::c_void;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_INVALID_SIGNATURE};
use windows::Win32::Security::Cryptography::{
    BCryptDeriveKey, BCryptDestroyKey, BCryptDestroySecret, BCryptEncrypt, BCryptExportKey,
    BCryptFinalizeKeyPair, BCryptGenRandom, BCryptGenerateKeyPair, BCryptGenerateSymmetricKey,
    BCryptHash, BCryptImportKeyPair, BCryptSecretAgreement, BCryptVerifySignature,
    BCRYPTGENRANDOM_FLAGS, BCRYPT_AES_ECB_ALG_HANDLE, BCRYPT_ALG_HANDLE, BCRYPT_ECCKEY_BLOB,
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDH_P256_ALG_HANDLE, BCRYPT_ECDH_P384_ALG_HANDLE,
    BCRYPT_ECDH_P521_ALG_HANDLE, BCRYPT_ECDH_PUBLIC_P256_MAGIC, BCRYPT_ECDH_PUBLIC_P384_MAGIC,
    BCRYPT_ECDH_PUBLIC_P521_MAGIC, BCRYPT_FLAGS, BCRYPT_HMAC_SHA1_ALG_HANDLE,
    BCRYPT_HMAC_SHA256_ALG_HANDLE, BCRYPT_HMAC_SHA384_ALG_HANDLE, BCRYPT_HMAC_SHA512_ALG_HANDLE,
    BCRYPT_KDF_RAW_SECRET, BCRYPT_KEY_HANDLE, BCRYPT_OAEP_PADDING_INFO, BCRYPT_PAD_OAEP,
    BCRYPT_PAD_PKCS1, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_RNG_ALG_HANDLE, BCRYPT_RSAKEY_BLOB,
    BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSAPUBLIC_MAGIC, BCRYPT_RSA_ALG_HANDLE, BCRYPT_SECRET_HANDLE,
    BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA1_ALG_HANDLE, BCRYPT_SHA256_ALGORITHM,
    BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA384_ALG_HANDLE,
    BCRYPT_SHA512_ALGORITHM, BCRYPT_SHA512_ALG_HANDLE,
};
use zeroize::Zeroizing;

/// The CNG-backed provider.
///
/// `generate_keypair` and `pkcs1v15_sign` are absent deliberately and report
/// [`TpmError::NotSupported`]; see the module documentation.
pub static CNG_PROVIDER: CryptoProvider = CryptoProvider {
    hash,
    hmac,
    aes_cfb,
    random,
    rsa: RsaOps {
        oaep_encrypt: rsa_oaep_encrypt,
        pkcs1v15_verify: rsa_pkcs1v15_verify,
        ..RsaOps::new_unimplemented()
    },
    ecc: EccOps {
        ephemeral_agree: ecc_ephemeral_agree,
    },
};

/// The AES block size, which is also the CFB segment width the TPM specification requires.
const AES_BLOCK_LEN: usize = 16;

/// Turns a failed `NTSTATUS` into an error naming both the operation and the raw status.
///
/// The status is reported rather than the `HRESULT` the bindings would convert it to, because the
/// `NTSTATUS` is the value CNG documents and the one worth searching for. `0xC000A000` says
/// "invalid signature"; the translated `HRESULT` says considerably less.
fn check(status: NTSTATUS, operation: &str) -> Result<(), TpmError> {
    if status.is_ok() {
        return Ok(());
    }

    Err(TpmError::GenericError(format!(
        "CNG {operation} failed with NTSTATUS 0x{:08X}",
        status.0 as u32
    )))
}

/// Owns a `BCRYPT_KEY_HANDLE` so that every exit path destroys it.
struct KeyHandle(BCRYPT_KEY_HANDLE);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        // Nothing useful can be done if this fails, and it runs on the unwind path too, so the
        // status is deliberately discarded rather than panicking a second time.
        unsafe {
            let _ = BCryptDestroyKey(self.0);
        }
    }
}

/// Owns a `BCRYPT_SECRET_HANDLE` so that every exit path destroys it.
///
/// The handle refers to an agreed value held inside CNG, so releasing it is what discards that
/// value rather than merely tidying up a bookkeeping slot.
struct SecretHandle(BCRYPT_SECRET_HANDLE);

impl Drop for SecretHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = BCryptDestroySecret(self.0);
        }
    }
}

/// The already-open provider for a hash algorithm.
///
/// SM3 has no entry because CNG does not implement it. A TPM may nominate it, so this is a real
/// gap rather than an oversight, and it is reported as one instead of being approximated.
fn hash_alg_handle(alg: TPM_ALG_ID) -> Result<BCRYPT_ALG_HANDLE, TpmError> {
    match alg {
        TPM_ALG_ID::SHA1 => Ok(BCRYPT_SHA1_ALG_HANDLE),
        TPM_ALG_ID::SHA256 => Ok(BCRYPT_SHA256_ALG_HANDLE),
        TPM_ALG_ID::SHA384 => Ok(BCRYPT_SHA384_ALG_HANDLE),
        TPM_ALG_ID::SHA512 => Ok(BCRYPT_SHA512_ALG_HANDLE),
        other => Err(TpmError::NotSupported(format!(
            "CNG does not offer hash algorithm {other}"
        ))),
    }
}

/// The already-open provider for an HMAC over a hash algorithm.
///
/// These are separate pseudo-handles rather than the hash ones with a flag set, so the usual
/// `BCRYPT_ALG_HANDLE_HMAC_FLAG` dance at open time does not arise.
fn hmac_alg_handle(alg: TPM_ALG_ID) -> Result<BCRYPT_ALG_HANDLE, TpmError> {
    match alg {
        TPM_ALG_ID::SHA1 => Ok(BCRYPT_HMAC_SHA1_ALG_HANDLE),
        TPM_ALG_ID::SHA256 => Ok(BCRYPT_HMAC_SHA256_ALG_HANDLE),
        TPM_ALG_ID::SHA384 => Ok(BCRYPT_HMAC_SHA384_ALG_HANDLE),
        TPM_ALG_ID::SHA512 => Ok(BCRYPT_HMAC_SHA512_ALG_HANDLE),
        other => Err(TpmError::NotSupported(format!(
            "CNG does not offer HMAC over hash algorithm {other}"
        ))),
    }
}

/// The name CNG knows a hash algorithm by, for the padding structures that take one by string.
fn hash_alg_name(alg: TPM_ALG_ID) -> Result<PCWSTR, TpmError> {
    match alg {
        TPM_ALG_ID::SHA1 => Ok(BCRYPT_SHA1_ALGORITHM),
        TPM_ALG_ID::SHA256 => Ok(BCRYPT_SHA256_ALGORITHM),
        TPM_ALG_ID::SHA384 => Ok(BCRYPT_SHA384_ALGORITHM),
        TPM_ALG_ID::SHA512 => Ok(BCRYPT_SHA512_ALGORITHM),
        other => Err(TpmError::NotSupported(format!(
            "CNG does not offer hash algorithm {other}"
        ))),
    }
}

/// One-shot hashing, which is what `BCryptHash` is for.
///
/// The create, update, finish and destroy sequence would be needed only to hash data arriving in
/// pieces, and the provider contract hands over one slice.
fn hash(alg: TPM_ALG_ID, data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let handle = hash_alg_handle(alg)?;
    let mut digest = vec![0u8; Crypto::digest_size_checked(alg)?];

    check(
        unsafe { BCryptHash(handle, None, data, &mut digest) },
        "hashing",
    )?;

    Ok(digest)
}

/// HMAC, which is the same one-shot call with the key supplied as the secret.
fn hmac(alg: TPM_ALG_ID, key: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let handle = hmac_alg_handle(alg)?;
    let mut mac = vec![0u8; Crypto::digest_size_checked(alg)?];

    check(
        unsafe { BCryptHash(handle, Some(key), data, &mut mac) },
        "HMAC",
    )?;

    Ok(mac)
}

fn random(out: &mut [u8]) -> Result<(), TpmError> {
    check(
        unsafe { BCryptGenRandom(Some(BCRYPT_RNG_ALG_HANDLE), out, BCRYPTGENRANDOM_FLAGS(0)) },
        "random number generation",
    )
}

/// AES in cipher feedback mode over a full block segment, built on the ECB primitive.
///
/// CNG does offer `BCRYPT_CHAIN_MODE_CFB`, and it is the wrong call twice over. Its segment
/// defaults to eight bits rather than a full block, which produces a completely different cipher
/// under a name that looks right; and it rejects input whose length is not a multiple of the block
/// size, which a TPM credential never satisfies, being a digest behind a two byte size. Driving
/// the block cipher directly avoids both. CFB is a stream mode, so consuming only the leading
/// bytes of the key stream for a trailing partial block is exactly what the mode calls for.
///
/// Only the block *encryption* is ever needed, in both directions, because CFB encrypts its
/// feedback value rather than the data.
fn aes_cfb(encrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError> {
    if iv.len() != AES_BLOCK_LEN {
        return Err(TpmError::InvalidArraySize(format!(
            "An AES-CFB IV must be {AES_BLOCK_LEN} bytes, not {}",
            iv.len()
        )));
    }

    // Rejected here rather than left to CNG, so the error names the length that was wrong.
    if !matches!(key.len(), 16 | 24 | 32) {
        return Err(TpmError::InvalidArraySize(format!(
            "An AES key must be 16, 24 or 32 bytes, not {}",
            key.len()
        )));
    }

    let mut handle = BCRYPT_KEY_HANDLE::default();
    check(
        unsafe { BCryptGenerateSymmetricKey(BCRYPT_AES_ECB_ALG_HANDLE, &mut handle, None, key, 0) },
        "AES key import",
    )?;
    let key_handle = KeyHandle(handle);

    let mut feedback = [0u8; AES_BLOCK_LEN];
    feedback.copy_from_slice(iv);

    let mut result = Vec::with_capacity(data.len());

    for chunk in data.chunks(AES_BLOCK_LEN) {
        let keystream = encrypt_block(&key_handle, &feedback)?;

        // The next feedback value is the ciphertext in both directions: when encrypting that is
        // the block just produced, when decrypting it is the block just consumed. A trailing
        // partial block is never fed forward, because nothing follows it.
        let mut next_feedback = [0u8; AES_BLOCK_LEN];

        for (index, &byte) in chunk.iter().enumerate() {
            let out = byte ^ keystream[index];
            next_feedback[index] = if encrypt { out } else { byte };
            result.push(out);
        }

        feedback = next_feedback;
    }

    Ok(result)
}

/// One raw AES block encryption.
fn encrypt_block(
    key: &KeyHandle,
    block: &[u8; AES_BLOCK_LEN],
) -> Result<[u8; AES_BLOCK_LEN], TpmError> {
    let mut out = [0u8; AES_BLOCK_LEN];
    let mut written = 0u32;

    // No padding flag, and a whole block in, so ECB returns exactly one block.
    check(
        unsafe {
            BCryptEncrypt(
                key.0,
                Some(block),
                None,
                None,
                Some(&mut out),
                &mut written,
                BCRYPT_FLAGS(0),
            )
        },
        "AES block encryption",
    )?;

    if written as usize != AES_BLOCK_LEN {
        return Err(TpmError::InvalidArraySize(format!(
            "An AES block encryption returned {written} bytes rather than {AES_BLOCK_LEN}"
        )));
    }

    Ok(out)
}

/// What CNG needs to know about a curve, beyond the width the registry already defines.
///
/// The magic is part of the key blob and identifies the curve to the provider the blob is imported
/// into, so it has to match the pseudo-handle beside it.
struct CurveParams {
    provider: BCRYPT_ALG_HANDLE,
    public_magic: u32,
    key_bits: u32,
}

/// Only the NIST prime curves appear, because they are the only ones CNG names a provider for.
///
/// A Barreto-Naehrig or SM2 curve is rejected rather than approximated with a curve of similar
/// width: agreeing over the wrong curve derives a key the peer cannot reproduce, and nothing about
/// the resulting failure would point back here.
fn curve_params(curve: TPM_ECC_CURVE) -> Result<CurveParams, TpmError> {
    match curve {
        TPM_ECC_CURVE::NIST_P256 => Ok(CurveParams {
            provider: BCRYPT_ECDH_P256_ALG_HANDLE,
            public_magic: BCRYPT_ECDH_PUBLIC_P256_MAGIC,
            key_bits: 256,
        }),
        TPM_ECC_CURVE::NIST_P384 => Ok(CurveParams {
            provider: BCRYPT_ECDH_P384_ALG_HANDLE,
            public_magic: BCRYPT_ECDH_PUBLIC_P384_MAGIC,
            key_bits: 384,
        }),
        // 521 rather than 528: the key length is the curve's order in bits, while the coordinate
        // width rounds that up to whole octets.
        TPM_ECC_CURVE::NIST_P521 => Ok(CurveParams {
            provider: BCRYPT_ECDH_P521_ALG_HANDLE,
            public_magic: BCRYPT_ECDH_PUBLIC_P521_MAGIC,
            key_bits: 521,
        }),
        other => Err(TpmError::NotSupported(format!(
            "CNG cannot perform ECDH over curve {other}"
        ))),
    }
}

/// The fixed part of a `BCRYPT_ECCKEY_BLOB`, which the coordinates follow immediately.
const ECC_BLOB_HEADER_LEN: usize = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();

fn ecc_ephemeral_agree(
    curve: TPM_ECC_CURVE,
    peer_x: &[u8],
    peer_y: &[u8],
) -> Result<EccEphemeralAgreement, TpmError> {
    let params = curve_params(curve)?;
    let width = Crypto::ecc_coordinate_size(curve)?;

    // CNG reads a fixed width coordinate pair out of the blob, so a short encoding would be read
    // as a differently valued point rather than rejected.
    let x = Crypto::pad_ecc_coordinate(peer_x, width)?;
    let y = Crypto::pad_ecc_coordinate(peer_y, width)?;

    // An off-curve point is rejected by the import, which is the only validation performed on the
    // peer's point and the reason it happens before anything is agreed.
    let peer = import_public(&params, width, &x, &y)?;
    let ephemeral = generate_ephemeral(&params)?;
    let (ephemeral_x, ephemeral_y) = export_public_coordinates(&ephemeral, width)?;

    let mut secret = BCRYPT_SECRET_HANDLE::default();
    check(
        unsafe { BCryptSecretAgreement(ephemeral.0, peer.0, &mut secret, 0) },
        "ECDH secret agreement",
    )?;
    let secret = SecretHandle(secret);

    let z = raw_secret(&secret, width)?;

    Ok(EccEphemeralAgreement {
        z,
        ephemeral_x,
        ephemeral_y,
    })
}

/// Imports a public point that is already padded to the curve's width.
fn import_public(
    params: &CurveParams,
    width: usize,
    x: &[u8],
    y: &[u8],
) -> Result<KeyHandle, TpmError> {
    let mut blob = Vec::with_capacity(ECC_BLOB_HEADER_LEN + x.len() + y.len());
    blob.extend_from_slice(&params.public_magic.to_le_bytes());
    blob.extend_from_slice(&(width as u32).to_le_bytes());
    blob.extend_from_slice(x);
    blob.extend_from_slice(y);

    let mut handle = BCRYPT_KEY_HANDLE::default();
    check(
        unsafe {
            BCryptImportKeyPair(
                params.provider,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                &mut handle,
                &blob,
                0,
            )
        },
        "ECC public key import",
    )?;

    Ok(KeyHandle(handle))
}

/// Generates a throwaway key on the peer's curve.
fn generate_ephemeral(params: &CurveParams) -> Result<KeyHandle, TpmError> {
    let mut handle = BCRYPT_KEY_HANDLE::default();
    check(
        unsafe { BCryptGenerateKeyPair(params.provider, &mut handle, params.key_bits, 0) },
        "ECC key generation",
    )?;

    // The handle is owned from here on, so a failure to finalize still destroys it.
    let key = KeyHandle(handle);
    check(
        unsafe { BCryptFinalizeKeyPair(key.0, 0) },
        "ECC key finalization",
    )?;

    Ok(key)
}

/// Reads a key's public point back out of CNG.
fn export_public_coordinates(
    key: &KeyHandle,
    width: usize,
) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
    let mut required = 0u32;
    check(
        unsafe { BCryptExportKey(key.0, None, BCRYPT_ECCPUBLIC_BLOB, None, &mut required, 0) },
        "ECC public key export sizing",
    )?;

    let mut blob = vec![0u8; required as usize];
    check(
        unsafe {
            BCryptExportKey(
                key.0,
                None,
                BCRYPT_ECCPUBLIC_BLOB,
                Some(&mut blob),
                &mut required,
                0,
            )
        },
        "ECC public key export",
    )?;

    let coordinates = blob
        .get(ECC_BLOB_HEADER_LEN..ECC_BLOB_HEADER_LEN + 2 * width)
        .ok_or_else(|| {
            TpmError::InvalidArraySize(format!(
                "An exported ECC key blob of {} bytes is too short for two {width} byte coordinates",
                blob.len()
            ))
        })?;

    let (x, y) = coordinates.split_at(width);
    Ok((x.to_vec(), y.to_vec()))
}

/// The agreed value itself, in the big-endian order every caller expects it in.
///
/// Two things about this call are easy to get wrong and silent when wrong, since both produce a
/// well formed value of the right length that simply disagrees with the peer.
///
/// The first is the KDF. CNG offers to run the SP800-56A concatenation itself, and at least one
/// Windows release ignores the hash algorithm it is handed and always uses SHA-256. The
/// derivation the TPM defines belongs to [`Crypto::kdfe`](super::Crypto::kdfe) in any case, so
/// `BCRYPT_KDF_RAW_SECRET` is used to ask for the agreed value untouched.
///
/// The second is the byte order. That one export hands the value back least significant byte
/// first, unlike every other value CNG exports, so it is reversed here. Left padding afterwards
/// matters for the same reason the input coordinates are padded: the value is hashed at the
/// curve's full width, and a short encoding hashes to something else entirely.
fn raw_secret(secret: &SecretHandle, width: usize) -> Result<Zeroizing<Vec<u8>>, TpmError> {
    let mut agreed = Zeroizing::new(vec![0u8; width]);
    let mut written = 0u32;

    check(
        unsafe {
            BCryptDeriveKey(
                secret.0,
                BCRYPT_KDF_RAW_SECRET,
                None,
                Some(&mut agreed),
                &mut written,
                0,
            )
        },
        "ECDH raw secret export",
    )?;

    let written = written as usize;
    if written == 0 || written > width {
        return Err(TpmError::InvalidArraySize(format!(
            "An ECDH agreement over a {width} byte curve returned {written} bytes"
        )));
    }

    agreed.truncate(written);
    agreed.reverse();

    if written == width {
        return Ok(agreed);
    }

    // `Zeroizing<Vec<u8>>` wipes the whole allocation rather than the live length, so the shorter
    // buffer is still cleared when it drops at the end of this function.
    let mut padded = Zeroizing::new(vec![0u8; width]);
    padded[width - written..].copy_from_slice(&agreed);
    Ok(padded)
}

/// Imports an RSA public key given its big-endian components.
///
/// The blob is a fixed header followed by the exponent and then the modulus, in that order. Both
/// prime lengths are zero, which is what marks the blob as carrying only the public half.
fn import_rsa_public(modulus: &[u8], exponent: &[u8]) -> Result<KeyHandle, TpmError> {
    if modulus.is_empty() || exponent.is_empty() {
        return Err(TpmError::InvalidArraySize(
            "An RSA public key needs both a modulus and an exponent".to_string(),
        ));
    }

    let header = BCRYPT_RSAKEY_BLOB {
        Magic: BCRYPT_RSAPUBLIC_MAGIC,
        BitLength: (modulus.len() * 8) as u32,
        cbPublicExp: exponent.len() as u32,
        cbModulus: modulus.len() as u32,
        cbPrime1: 0,
        cbPrime2: 0,
    };

    let header_len = std::mem::size_of::<BCRYPT_RSAKEY_BLOB>();
    let mut blob = Vec::with_capacity(header_len + exponent.len() + modulus.len());

    // The header is plain old data with no padding to reproduce by hand, so it is copied out
    // wholesale rather than field by field.
    let header_bytes =
        unsafe { std::slice::from_raw_parts(&header as *const _ as *const u8, header_len) };
    blob.extend_from_slice(header_bytes);
    blob.extend_from_slice(exponent);
    blob.extend_from_slice(modulus);

    let mut handle = BCRYPT_KEY_HANDLE::default();
    check(
        unsafe {
            BCryptImportKeyPair(
                BCRYPT_RSA_ALG_HANDLE,
                None,
                BCRYPT_RSAPUBLIC_BLOB,
                &mut handle,
                &blob,
                0,
            )
        },
        "RSA public key import",
    )?;

    Ok(KeyHandle(handle))
}

fn rsa_oaep_encrypt(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    label: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, TpmError> {
    let key = import_rsa_public(modulus, exponent)?;

    // CNG takes the label through a mutable pointer even though it only reads it, so it needs a
    // buffer of its own that outlives both calls below. The label is passed through byte for byte,
    // including the trailing NUL the TPM specification puts in it.
    let mut label = label.to_vec();
    let padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: hash_alg_name(hash_alg)?,
        pbLabel: label.as_mut_ptr(),
        cbLabel: label.len() as u32,
    };
    let padding_ptr = Some(&padding as *const _ as *const c_void);

    let mut required = 0u32;
    check(
        unsafe {
            BCryptEncrypt(
                key.0,
                Some(data),
                padding_ptr,
                None,
                None,
                &mut required,
                BCRYPT_PAD_OAEP,
            )
        },
        "RSA-OAEP encryption sizing",
    )?;

    let mut ciphertext = vec![0u8; required as usize];
    check(
        unsafe {
            BCryptEncrypt(
                key.0,
                Some(data),
                padding_ptr,
                None,
                Some(&mut ciphertext),
                &mut required,
                BCRYPT_PAD_OAEP,
            )
        },
        "RSA-OAEP encryption",
    )?;

    ciphertext.truncate(required as usize);
    Ok(ciphertext)
}

fn rsa_pkcs1v15_verify(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TpmError> {
    let key = import_rsa_public(modulus, exponent)?;

    let padding = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: hash_alg_name(hash_alg)?,
    };

    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            Some(&padding as *const _ as *const c_void),
            digest,
            signature,
            BCRYPT_PAD_PKCS1,
        )
    };

    // A signature that does not verify is an answer rather than a failure, so both of the statuses
    // that mean "no" are turned into one.
    //
    // `STATUS_INVALID_SIGNATURE` is the obvious one. `STATUS_INVALID_PARAMETER` is how CNG reports
    // a signature it will not even attempt, which for an attacker-supplied value mostly means one
    // numerically greater than the modulus or of the wrong length. Those are malformed signatures,
    // and a caller checking a signature off the wire wants to hear "invalid" rather than an error
    // it has to classify. Reporting them as failures would also disagree with every other backend:
    // the RustCrypto one answers `Ok(false)` for exactly these inputs, so a provider that did not
    // would make the two disagree on which signatures are acceptable.
    if status == STATUS_INVALID_SIGNATURE || status == STATUS_INVALID_PARAMETER {
        return Ok(false);
    }

    check(status, "RSA PKCS#1 v1.5 verification")?;
    Ok(true)
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;

    use elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{Oaep, RsaPrivateKey};
    use sha2::Sha256;

    /// The hash algorithms both providers implement.
    ///
    /// SM3 is absent because CNG has none, which the last case below states outright rather than
    /// leaving to be inferred from its absence here.
    const SHARED_HASHES: [TPM_ALG_ID; 4] = [
        TPM_ALG_ID::SHA1,
        TPM_ALG_ID::SHA256,
        TPM_ALG_ID::SHA384,
        TPM_ALG_ID::SHA512,
    ];

    #[test]
    fn hashes_agree_with_the_software_provider() {
        for alg in SHARED_HASHES {
            for data in [b"".as_slice(), b"abc".as_slice(), &[0x5au8; 1000]] {
                let theirs = (SOFTWARE_PROVIDER.hash)(alg, data).unwrap();
                let ours = (CNG_PROVIDER.hash)(alg, data).unwrap();
                assert_eq!(
                    ours,
                    theirs,
                    "hash mismatch for {alg:?} over {} bytes",
                    data.len()
                );
                assert_eq!(ours.len(), Crypto::digestSize(alg));
            }
        }
    }

    #[test]
    fn hmacs_agree_with_the_software_provider() {
        // The empty key and the over-long key are the two cases HMAC defines specially: one is
        // padded out to the block size, the other is hashed down to it. A backend that delegated
        // either differently would disagree here rather than in some later derivation.
        let keys: [&[u8]; 4] = [b"", b"key", &[0xa5; 64], &[0x3c; 200]];

        for alg in SHARED_HASHES {
            for key in keys {
                let theirs = (SOFTWARE_PROVIDER.hmac)(alg, key, b"message").unwrap();
                let ours = (CNG_PROVIDER.hmac)(alg, key, b"message").unwrap();
                assert_eq!(
                    ours,
                    theirs,
                    "HMAC mismatch for {alg:?} under a {} byte key",
                    key.len()
                );
            }
        }
    }

    #[test]
    fn sm3_is_reported_as_unsupported_rather_than_approximated() {
        assert!(matches!(
            (CNG_PROVIDER.hash)(TPM_ALG_ID::SM3_256, b"abc"),
            Err(TpmError::NotSupported(_))
        ));
    }

    #[test]
    fn aes_cfb_agrees_with_the_software_provider() {
        let iv = [0x42u8; AES_BLOCK_LEN];

        for key_len in [16usize, 24, 32] {
            let key = vec![0x11u8; key_len];

            // 34 bytes is the length that matters: a TPM credential is a digest behind a two byte
            // size, so it is never block aligned, and the trailing partial block is where a
            // backend that reached for CNG's own CFB mode would diverge.
            for len in [0usize, 1, 15, 16, 17, 34, 64] {
                let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();

                let theirs = (SOFTWARE_PROVIDER.aes_cfb)(true, &key, &iv, &plaintext).unwrap();
                let ours = (CNG_PROVIDER.aes_cfb)(true, &key, &iv, &plaintext).unwrap();
                assert_eq!(
                    ours,
                    theirs,
                    "AES-{}-CFB encrypt mismatch at {len} bytes",
                    key_len * 8
                );

                let round_trip = (CNG_PROVIDER.aes_cfb)(false, &key, &iv, &ours).unwrap();
                assert_eq!(
                    round_trip, plaintext,
                    "AES-CFB round trip failed at {len} bytes"
                );
            }
        }
    }

    #[test]
    fn aes_cfb_rejects_a_wrong_sized_key_or_iv() {
        let good_key = [0u8; 16];
        let good_iv = [0u8; AES_BLOCK_LEN];

        assert!((CNG_PROVIDER.aes_cfb)(true, &[0u8; 20], &good_iv, b"data").is_err());
        assert!((CNG_PROVIDER.aes_cfb)(true, &good_key, &[0u8; 8], b"data").is_err());
    }

    #[test]
    fn random_fills_the_whole_buffer() {
        let mut buffer = [0u8; 64];
        (CNG_PROVIDER.random)(&mut buffer).unwrap();
        assert!(
            buffer.iter().any(|&b| b != 0),
            "the random buffer came back untouched"
        );

        // A zero length request is legal and must not be turned into an error.
        (CNG_PROVIDER.random)(&mut []).unwrap();
    }

    /// Agrees with CNG against a peer key this test owns, then reproduces the agreed value
    /// independently.
    ///
    /// This is the test that earns its keep. Two providers cannot simply be compared on ECDH,
    /// because each generates its own ephemeral key, so instead the peer's private half is kept
    /// here and used to recompute the same value from the ephemeral point CNG returned. That
    /// covers the byte reversal in `raw_secret`, which is otherwise invisible: a value that is
    /// reversed, or padded to the wrong width, is still the right length and still looks like a
    /// secret.
    #[test]
    fn ecdh_agrees_with_a_peer_holding_the_private_half() {
        let peer_secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let peer_point = peer_secret.public_key().to_encoded_point(false);

        let agreement = (CNG_PROVIDER.ecc.ephemeral_agree)(
            TPM_ECC_CURVE::NIST_P256,
            peer_point.x().unwrap(),
            peer_point.y().unwrap(),
        )
        .unwrap();

        assert_eq!(agreement.z.len(), 32);
        assert_eq!(agreement.ephemeral_x.len(), 32);
        assert_eq!(agreement.ephemeral_y.len(), 32);

        let ephemeral_point = p256::EncodedPoint::from_affine_coordinates(
            p256::FieldBytes::from_slice(&agreement.ephemeral_x),
            p256::FieldBytes::from_slice(&agreement.ephemeral_y),
            false,
        );
        let ephemeral_public =
            p256::PublicKey::from_sec1_bytes(ephemeral_point.as_bytes()).unwrap();

        let expected = peer_secret.diffie_hellman(&ephemeral_public);
        assert_eq!(
            agreement.z.as_slice(),
            expected.raw_secret_bytes().as_slice(),
            "the agreed value disagrees with the peer, so the export is being mishandled"
        );
    }

    #[test]
    fn ecdh_rejects_a_curve_cng_cannot_agree_over() {
        assert!(matches!(
            (CNG_PROVIDER.ecc.ephemeral_agree)(TPM_ECC_CURVE::SM2_P256, &[1u8; 32], &[2u8; 32]),
            Err(TpmError::NotSupported(_))
        ));
    }

    #[test]
    fn ecdh_rejects_a_point_that_is_not_on_the_curve() {
        // Coordinates picked arbitrarily are overwhelmingly unlikely to satisfy the curve
        // equation, and CNG checks that on import rather than agreeing with nonsense.
        assert!((CNG_PROVIDER.ecc.ephemeral_agree)(
            TPM_ECC_CURVE::NIST_P256,
            &[0x11u8; 32],
            &[0x22u8; 32]
        )
        .is_err());
    }

    #[test]
    fn oaep_ciphertext_decrypts_under_the_matching_private_key() {
        // OAEP is randomized, so the two providers cannot be compared on their output. Decrypting
        // is the check that matters anyway, since it is what the TPM will do with this blob.
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let modulus = private.n().to_bytes_be();
        let exponent = private.e().to_bytes_be();

        let label = b"IDENTITY\0";
        let secret = b"the seed the credential protects";

        let ciphertext =
            (CNG_PROVIDER.rsa.oaep_encrypt)(&modulus, &exponent, TPM_ALG_ID::SHA256, label, secret)
                .unwrap();
        assert_eq!(ciphertext.len(), modulus.len());

        // The `rsa` crate models the label as a string, and takes it without the trailing NUL
        // that CNG and the TPM specification both include in the hashed label.
        let padding = Oaep::new_with_label::<Sha256, _>("IDENTITY\0");
        let recovered = private.decrypt(padding, &ciphertext).unwrap();
        assert_eq!(recovered, secret);
    }

    /// A 2048-bit RSA modulus that never changes between runs.
    ///
    /// It is a real generated modulus rather than an invented number, because CNG imports it as a
    /// public key and a value that is not a plausible key would be rejected on import rather than
    /// on the signature. Its only job is to make the rejection shapes below the same bytes every
    /// time; nothing here needs the private half.
    const FIXED_MODULUS: [u8; 256] = [
        0xc0, 0x79, 0x3f, 0xce, 0x4e, 0x17, 0xf3, 0xee, 0x11, 0xfd, 0x1b, 0x27, 0xfb, 0xf9, 0x28,
        0xd7, 0xee, 0x96, 0xe8, 0x4a, 0x5a, 0x15, 0x09, 0x4f, 0xba, 0xf9, 0x4b, 0x73, 0x4f, 0x73,
        0xcb, 0x0f, 0x4b, 0x23, 0x8a, 0x05, 0x25, 0x07, 0xb2, 0x9f, 0x0b, 0xf4, 0xf7, 0x35, 0x3c,
        0xe9, 0xa4, 0xab, 0x77, 0x2a, 0x8b, 0x80, 0x70, 0xaf, 0x9b, 0xa6, 0x38, 0x98, 0x3a, 0xee,
        0xd1, 0xcf, 0xf0, 0x99, 0x16, 0xdc, 0x7c, 0xcd, 0x42, 0x86, 0xd0, 0x5d, 0x2c, 0xa6, 0x98,
        0xc1, 0x8b, 0xff, 0xd2, 0x0f, 0x2d, 0x1a, 0x04, 0x15, 0x93, 0xd2, 0xb6, 0xab, 0x68, 0x60,
        0xe8, 0x3c, 0xa3, 0xb7, 0x6c, 0x5b, 0xf2, 0x09, 0x92, 0xf8, 0xed, 0x67, 0xf8, 0x18, 0xb5,
        0xee, 0x71, 0x62, 0x66, 0x93, 0xdb, 0xd5, 0xfc, 0x8f, 0xa6, 0xce, 0x1b, 0x1e, 0x63, 0xe6,
        0x79, 0xcf, 0xa8, 0xe7, 0xf9, 0x29, 0xf9, 0xf5, 0xcb, 0x51, 0xa0, 0xc4, 0x41, 0xfd, 0xd8,
        0xd0, 0xcb, 0x2e, 0xc2, 0x83, 0x8b, 0xda, 0x9b, 0xfb, 0x1f, 0x38, 0x4b, 0x46, 0x14, 0xe1,
        0x54, 0xbd, 0x82, 0xc1, 0x67, 0xe5, 0x94, 0x4a, 0xdb, 0xf3, 0x88, 0x94, 0xe7, 0x45, 0xa4,
        0x42, 0xbc, 0x7c, 0xed, 0x33, 0x45, 0xa5, 0xf9, 0x54, 0xe4, 0x9f, 0x7c, 0x6d, 0xf4, 0x8d,
        0x1e, 0x91, 0x7e, 0x35, 0x96, 0x3e, 0xfa, 0xbb, 0x85, 0xb7, 0x58, 0x3f, 0xa7, 0x10, 0x17,
        0x0d, 0x4a, 0xbc, 0xf2, 0x1f, 0x25, 0xae, 0xe0, 0x7e, 0x9c, 0x8c, 0x5d, 0xcf, 0x30, 0xfd,
        0x27, 0x62, 0xb7, 0x66, 0xc6, 0x97, 0x16, 0x30, 0x68, 0x33, 0x79, 0x79, 0xc2, 0xfe, 0xa1,
        0xbb, 0x5b, 0x92, 0x86, 0x56, 0x02, 0xe9, 0x31, 0x48, 0x08, 0x22, 0x82, 0x36, 0x27, 0x5e,
        0x84, 0x17, 0x37, 0x06, 0xc5, 0xa5, 0xac, 0x91, 0xe8, 0x40, 0x74, 0x76, 0x23, 0x4d, 0xd4,
        0x9b,
    ];

    /// The public exponent the fixed-input RSA cases use.
    const EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

    /// Both backends, so a shape is asserted against each in turn.
    fn providers() -> [(&'static str, &'static CryptoProvider); 2] {
        [
            ("the software provider", &SOFTWARE_PROVIDER),
            ("CNG", &CNG_PROVIDER),
        ]
    }

    /// The signature shapes both backends must answer with `Ok(false)`.
    ///
    /// Listing them in one place is what makes a new case cheap. The two backends reach the same
    /// answer through entirely different code, which is the whole reason to check: the `rsa` crate
    /// folds every verification error into one, while CNG distinguishes a signature that does not
    /// verify from one it will not attempt at all, and this provider folds those two statuses back
    /// together itself.
    ///
    /// Every shape here must be certain to be rejected, for every modulus and signature that can
    /// reach it, or this becomes a test that fails once in a while for a reason that is not a
    /// defect. Each is argued below, and all of them rest on `modulus` being a real RSA modulus:
    /// full width with its top bit set, which [`FIXED_MODULUS`] is by construction and which a
    /// caller passing a generated modulus would have to check rather than assume.
    fn rejected_signatures(modulus: &[u8], signature: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
        assert_eq!(
            signature.len(),
            modulus.len(),
            "the shapes below are derived from a signature at the modulus width"
        );

        // Flipping the least significant byte moves the value by at most 255, so it stays below
        // the modulus, and it always changes the value. This is the case where CNG genuinely
        // answers STATUS_INVALID_SIGNATURE.
        let mut in_range = signature.to_vec();
        if let Some(last) = in_range.last_mut() {
            *last ^= 0xff;
        }

        // Changing the most significant byte has to leave a value that is both different from the
        // signature and still below the modulus, which clearing that byte unconditionally does
        // not: a signature is zero padded to the modulus width, so roughly one signature in 256
        // already begins with a zero byte, and clearing it would reproduce the signature exactly
        // and be accepted. Both branches below are distinct from the signature by construction,
        // and both are below the modulus, whose leading byte is at least 0x80: the result is under
        // two units of the leading byte's place value, and the modulus is at least 128 of them.
        let mut leading_byte_changed = signature.to_vec();
        leading_byte_changed[0] = if signature[0] == 0 { 1 } else { 0 };

        // Every byte set is the largest value of this width and so is at or above any modulus of
        // the same width. This is the case CNG reports as STATUS_INVALID_PARAMETER, and it is here
        // as fixed bytes because flipping the leading byte of a generated signature lands on it
        // only for some keys: how often depends on the leading byte of the modulus drawn, so a
        // test that relied on that alone would exercise this status on some runs and not others.
        let out_of_range = vec![0xffu8; modulus.len()];

        let one_byte_short = signature[1..].to_vec();
        let one_byte_long = [&[0u8][..], signature].concat();

        vec![
            ("a corrupted in-range signature", in_range),
            ("a changed leading byte", leading_byte_changed),
            ("a signature not below the modulus", out_of_range),
            ("a signature one byte short", one_byte_short),
            ("a signature one byte long", one_byte_long),
            ("an empty signature", Vec::new()),
        ]
    }

    /// Runs every rejection shape through both backends, reporting which backend and which shape.
    ///
    /// `digest` is the one the signature was made over, where there is one, so that the corrupted
    /// in-range shape is judged against a digest its uncorrupted form would verify under. A shape
    /// that were accidentally a no-op would otherwise still pass here.
    fn assert_every_shape_is_rejected(
        modulus: &[u8],
        exponent: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) {
        for (backend, provider) in providers() {
            for (description, candidate) in rejected_signatures(modulus, signature) {
                let verified = (provider.rsa.pkcs1v15_verify)(
                    modulus,
                    exponent,
                    TPM_ALG_ID::SHA256,
                    digest,
                    &candidate,
                )
                .unwrap_or_else(|e| {
                    panic!("{backend} reported {description} as a failure rather than rejecting it: {e}")
                });

                // A signature that will not verify is an answer rather than a failure, whichever
                // backend is answering. A backend that returns `Err` here diverts a caller such as
                // `validate_certify` from its `false` branch into error handling, on input a
                // remote party chooses.
                assert!(!verified, "{backend} accepted {description}");
            }
        }
    }

    /// The rejection shapes over bytes that are identical on every run.
    ///
    /// Nothing here is generated, so this test either always passes or always fails, and a failure
    /// is reproducible by running it again. That matters because the shapes are the regression
    /// test for a provider that answered some of them with `Err`, and a test that samples a fresh
    /// key each run can only ever say that today's key was fine.
    #[test]
    fn pkcs1v15_rejections_are_the_same_on_every_run() {
        // Halving the leading byte of the modulus gives a value of the right width that is
        // certainly below it, which is all a rejection shape needs. Standing one in for a real
        // signature is what lets this test fix every byte without holding a private key.
        let mut signature_shaped = FIXED_MODULUS.to_vec();
        signature_shaped[0] >>= 1;

        assert_every_shape_is_rejected(&FIXED_MODULUS, &EXPONENT, &[0x5au8; 32], &signature_shaped);
    }

    /// The boundary the status map leaves in place.
    ///
    /// `rsa_pkcs1v15_verify` answers both `STATUS_INVALID_SIGNATURE` and
    /// `STATUS_INVALID_PARAMETER` with `Ok(false)`, so no verdict on a signature comes back as an
    /// error. What is still an error is a verification that never reached the signature: the key
    /// has to import and the hash algorithm has to have a CNG name before `BCryptVerifySignature`
    /// is called at all, and both of those fail ahead of the status map rather than through it.
    /// That is the distinction `Err` still carries, and it is the order of the three steps in
    /// `rsa_pkcs1v15_verify` that carries it, so it is asserted rather than assumed.
    ///
    /// Nothing here claims that a signature CNG refuses to attempt is an error. Under the status
    /// map it is not, which is what `pkcs1v15_rejections_are_the_same_on_every_run` pins from the
    /// other side.
    #[test]
    fn verification_still_fails_rather_than_rejects_when_it_cannot_be_performed() {
        let signature = [0x01u8; 256];
        let digest = [0x5au8; 32];

        // The contrast the two cases below are read against: this call is a verdict on the
        // signature rather than an error, and each of them differs from it in one respect only.
        // Without it they would pass just as well against a provider that errored on everything.
        let verified = (CNG_PROVIDER.rsa.pkcs1v15_verify)(
            &FIXED_MODULUS,
            &EXPONENT,
            TPM_ALG_ID::SHA256,
            &digest,
            &signature,
        )
        .expect("a signature below the modulus is judged rather than refused");
        assert!(!verified, "a signature that cannot verify was accepted");

        assert!(
            (CNG_PROVIDER.rsa.pkcs1v15_verify)(
                &[],
                &EXPONENT,
                TPM_ALG_ID::SHA256,
                &digest,
                &signature
            )
            .is_err(),
            "a key CNG cannot import was reported as a bad signature"
        );
        assert!(
            (CNG_PROVIDER.rsa.pkcs1v15_verify)(
                &FIXED_MODULUS,
                &EXPONENT,
                TPM_ALG_ID::SM3_256,
                &digest,
                &signature
            )
            .is_err(),
            "a hash algorithm CNG does not offer was reported as a bad signature"
        );
    }

    #[test]
    fn pkcs1v15_verification_agrees_with_the_software_provider() {
        let key = (SOFTWARE_PROVIDER.rsa.generate_keypair)(2048, &[0x01, 0x00, 0x01]).unwrap();
        let digest = (SOFTWARE_PROVIDER.hash)(TPM_ALG_ID::SHA256, b"signed data").unwrap();
        let signature =
            (SOFTWARE_PROVIDER.rsa.pkcs1v15_sign)(&key, TPM_ALG_ID::SHA256, &digest).unwrap();

        let verified = (CNG_PROVIDER.rsa.pkcs1v15_verify)(
            &key.modulus,
            &key.exponent,
            TPM_ALG_ID::SHA256,
            &digest,
            &signature,
        )
        .unwrap();
        assert!(verified, "a good signature was rejected");

        // Every way a signature can be wrong has to come back as `Ok(false)` rather than as an
        // error, and has to agree with the other backend on that. The first two cases are not
        // interchangeable: corrupting the low byte leaves a value below the modulus, which CNG
        // rejects as an invalid signature, while corrupting the high byte can push it above the
        // modulus, which CNG rejects as an invalid *parameter*. Testing only one of them left the
        // outcome depending on which key was generated, and the test passed or failed by luck.
        let mut low_byte_flipped = signature.clone();
        *low_byte_flipped.last_mut().unwrap() ^= 0xff;

        let mut high_byte_flipped = signature.clone();
        high_byte_flipped[0] ^= 0xff;

        let truncated = signature[..signature.len() - 1].to_vec();
        let empty = Vec::new();

        for (description, bad) in [
            ("a flipped low byte", low_byte_flipped),
            ("a flipped high byte", high_byte_flipped),
            ("a truncated signature", truncated),
            ("an empty signature", empty),
        ] {
            let ours = (CNG_PROVIDER.rsa.pkcs1v15_verify)(
                &key.modulus,
                &key.exponent,
                TPM_ALG_ID::SHA256,
                &digest,
                &bad,
            )
            .unwrap_or_else(|e| panic!("{description} was reported as a failure rather than as an invalid signature: {e:?}"));
            assert!(!ours, "{description} was accepted");

            let theirs = (SOFTWARE_PROVIDER.rsa.pkcs1v15_verify)(
                &key.modulus,
                &key.exponent,
                TPM_ALG_ID::SHA256,
                &digest,
                &bad,
            )
            .unwrap();
            assert_eq!(ours, theirs, "the backends disagree about {description}");
        }
    }

    #[test]
    fn the_two_unimplemented_rsa_primitives_say_so() {
        assert!(matches!(
            (CNG_PROVIDER.rsa.generate_keypair)(2048, &[0x01, 0x00, 0x01]),
            Err(TpmError::NotSupported(_))
        ));

        let key = crate::crypto::RsaKeyParts {
            modulus: vec![0xff; 256],
            prime: vec![0xff; 128],
            exponent: vec![0x01, 0x00, 0x01],
        };
        assert!(matches!(
            (CNG_PROVIDER.rsa.pkcs1v15_sign)(&key, TPM_ALG_ID::SHA256, &[0u8; 32]),
            Err(TpmError::NotSupported(_))
        ));
    }

    /// The KDFs sit above the provider, so running one through both backends checks the whole
    /// stack rather than the primitives in isolation.
    #[test]
    fn the_kdfs_produce_the_same_stream_over_either_provider() {
        for alg in SHARED_HASHES {
            for bits in [128usize, 250, 256, 512] {
                let theirs =
                    Crypto::kdfa(&SOFTWARE_PROVIDER, alg, b"key", "ATH", &[], &[], bits).unwrap();
                let ours = Crypto::kdfa(&CNG_PROVIDER, alg, b"key", "ATH", &[], &[], bits).unwrap();
                assert_eq!(ours, theirs, "KDFa mismatch for {alg:?} at {bits} bits");

                let z = [0x77u8; 32];
                let theirs =
                    Crypto::kdfe(&SOFTWARE_PROVIDER, alg, &z, "IDENTITY", &[], &[], bits).unwrap();
                let ours =
                    Crypto::kdfe(&CNG_PROVIDER, alg, &z, "IDENTITY", &[], &[], bits).unwrap();
                assert_eq!(ours, theirs, "KDFe mismatch for {alg:?} at {bits} bits");
            }
        }
    }
}

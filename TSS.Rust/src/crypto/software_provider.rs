//! A [`CryptoProvider`] built on the pure-Rust RustCrypto crates.
//!
//! This is the default backend and needs no platform support, so it works the same on every
//! target. Hosts that would rather not link a second implementation of primitives their operating
//! system already provides can disable the `software-crypto` feature and supply their own
//! provider instead.

use super::provider::{CryptoProvider, EccEphemeralAgreement, EccOps, RsaOps};
use super::{Crypto, RsaKeyParts};
use crate::{
    error::TpmError,
    tpm_types::{TPM_ALG_ID, TPM_ECC_CURVE},
};

use aes::{Aes128, Aes192, Aes256};
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, BlockSizeUser, KeyInit};
use elliptic_curve::ecdh::EphemeralSecret;
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytes, FieldBytesSize, PublicKey};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};
use sm3::Sm3;
use zeroize::Zeroizing;

/// The RustCrypto-backed provider.
pub static SOFTWARE_PROVIDER: CryptoProvider = CryptoProvider {
    hash,
    hmac,
    aes_cfb,
    random,
    rsa: RsaOps {
        oaep_encrypt: rsa_oaep_encrypt,
        pkcs1v15_verify: rsa_pkcs1v15_verify,
        generate_keypair: rsa_generate_keypair,
        pkcs1v15_sign: rsa_pkcs1v15_sign,
    },
    ecc: EccOps {
        ephemeral_agree: ecc_ephemeral_agree,
    },
};

fn hash(alg: TPM_ALG_ID, data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let digest = match alg {
        TPM_ALG_ID::SHA1 => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        TPM_ALG_ID::SHA256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        TPM_ALG_ID::SHA384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        TPM_ALG_ID::SHA512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        TPM_ALG_ID::SM3_256 => {
            let mut hasher = Sm3::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        _ => {
            return Err(TpmError::NotSupported(format!(
                "Unsupported hash algorithm: {:?}",
                alg
            )))
        }
    };

    let expected_size = Crypto::digestSize(alg);
    if digest.len() != expected_size {
        return Err(TpmError::InvalidArraySize(format!(
            "Hash output length mismatch: expected {}, got {}",
            expected_size,
            digest.len()
        )));
    }

    Ok(digest)
}

fn hmac(hash_alg: TPM_ALG_ID, key: &[u8], to_hash: &[u8]) -> Result<Vec<u8>, TpmError> {
    // Choose the appropriate HMAC algorithm based on the hash algorithm
    match hash_alg {
        TPM_ALG_ID::SHA1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).map_err(|_| {
                TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
            })?;
            mac.update(to_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        TPM_ALG_ID::SHA256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| {
                TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
            })?;
            mac.update(to_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        TPM_ALG_ID::SHA384 => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).map_err(|_| {
                TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
            })?;
            mac.update(to_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        TPM_ALG_ID::SHA512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).map_err(|_| {
                TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
            })?;
            mac.update(to_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        TPM_ALG_ID::SM3_256 => {
            let mut mac = <Hmac<Sm3> as Mac>::new_from_slice(key).map_err(|_| {
                TpmError::InvalidArraySize("HMAC can take key of any size".to_string())
            })?;
            mac.update(to_hash);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(TpmError::NotSupported(format!(
            "Unsupported hash algorithm: {:?}",
            hash_alg
        ))),
    }
}

fn pkcs1v15_sign_scheme(hash_alg: TPM_ALG_ID) -> Result<Pkcs1v15Sign, TpmError> {
    match hash_alg {
        TPM_ALG_ID::SHA1 => Ok(Pkcs1v15Sign::new::<Sha1>()),
        TPM_ALG_ID::SHA256 => Ok(Pkcs1v15Sign::new::<Sha256>()),
        TPM_ALG_ID::SHA384 => Ok(Pkcs1v15Sign::new::<Sha384>()),
        TPM_ALG_ID::SHA512 => Ok(Pkcs1v15Sign::new::<Sha512>()),
        _ => Err(TpmError::NotSupported(format!(
            "Unsupported RSASSA hash algorithm: {:?}",
            hash_alg
        ))),
    }
}

/// Build an RSA public key from its big-endian components.
fn rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Result<RsaPublicKey, TpmError> {
    RsaPublicKey::new(
        BigUint::from_bytes_be(modulus),
        BigUint::from_bytes_be(exponent),
    )
    .map_err(|_| TpmError::InvalidArraySize("Invalid RSA public key".to_string()))
}

fn rsa_oaep_encrypt(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    label: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, TpmError> {
    let rsa_key = rsa_public_key(modulus, exponent)?;

    // The `rsa` crate models an OAEP label as a string rather than as bytes, so the label
    // has to be converted here. Callers work in bytes because that is what the TPM
    // specification and other crypto backends use.
    let label = std::str::from_utf8(label)
        .map_err(|_| TpmError::NotSupported("OAEP label must be valid UTF-8".to_string()))?;

    let padding = match hash_alg {
        TPM_ALG_ID::SHA1 => Oaep::new_with_label::<Sha1, _>(label),
        TPM_ALG_ID::SHA256 => Oaep::new_with_label::<Sha256, _>(label),
        _ => {
            return Err(TpmError::NotSupported(format!(
                "Unsupported nameAlg for OAEP: {:?}",
                hash_alg
            )))
        }
    };

    rsa_key
        .encrypt(&mut OsRng, padding, data)
        .map_err(|e| TpmError::GenericError(format!("RSA-OAEP encryption failed: {e}")))
}

fn rsa_pkcs1v15_verify(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TpmError> {
    let rsa_key = rsa_public_key(modulus, exponent)?;
    let scheme = pkcs1v15_sign_scheme(hash_alg)?;
    Ok(rsa_key.verify(scheme, digest, signature).is_ok())
}

fn rsa_generate_keypair(key_bits: usize, exponent: &[u8]) -> Result<RsaKeyParts, TpmError> {
    let exponent_value = BigUint::from_bytes_be(exponent);
    let priv_key = RsaPrivateKey::new_with_exp(&mut OsRng, key_bits, &exponent_value)
        .map_err(|e| TpmError::GenericError(format!("RSA key generation failed: {}", e)))?;

    let prime = priv_key
        .primes()
        .first()
        .ok_or_else(|| TpmError::GenericError("Generated RSA key exposes no primes".to_string()))?;

    Ok(RsaKeyParts {
        modulus: priv_key.n().to_bytes_be(),
        prime: prime.to_bytes_be(),
        exponent: priv_key.e().to_bytes_be(),
    })
}

/// Sign an already computed digest with RSASSA-PKCS1-v1_5.
///
/// The second prime is recovered as `modulus / prime`.
fn rsa_pkcs1v15_sign(
    key: &RsaKeyParts,
    hash_alg: TPM_ALG_ID,
    digest: &[u8],
) -> Result<Vec<u8>, TpmError> {
    // Recovering the second prime divides by the first, so reject a zero prime up front
    // instead of letting the big-integer division panic.
    if key.prime.iter().all(|&byte| byte == 0) {
        return Err(TpmError::InvalidArraySize(
            "RSA private key prime is zero".to_string(),
        ));
    }

    let modulus = BigUint::from_bytes_be(&key.modulus);
    let first_prime = BigUint::from_bytes_be(&key.prime);

    // Integer division truncates, and `from_p_q` recomputes the modulus as `p * q` rather than
    // checking it against the one supplied. Without this guard a prime that does not divide the
    // modulus exactly would silently produce a key with a different modulus, whose signatures
    // could never verify against the stored public key.
    if (&modulus % &first_prime) != BigUint::from(0u32) {
        return Err(TpmError::InvalidArraySize(
            "RSA private key prime does not divide the modulus".to_string(),
        ));
    }

    let second_prime = &modulus / &first_prime;
    let exponent = BigUint::from_bytes_be(&key.exponent);

    let priv_key = RsaPrivateKey::from_p_q(first_prime, second_prime, exponent)
        .map_err(|e| TpmError::GenericError(format!("Failed to reconstruct RSA key: {}", e)))?;

    priv_key
        .sign(pkcs1v15_sign_scheme(hash_alg)?, digest)
        .map_err(|e| TpmError::GenericError(format!("RSA signing failed: {}", e)))
}

fn aes_cfb(encrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // The key length selects the AES variant. All three share a 128 bit block, so the mode
    // itself is identical; only the cipher differs.
    match key.len() {
        16 => aes_cfb_with::<Aes128>(encrypt, key, iv, data),
        24 => aes_cfb_with::<Aes192>(encrypt, key, iv, data),
        32 => aes_cfb_with::<Aes256>(encrypt, key, iv, data),
        other => Err(TpmError::InvalidArraySize(format!(
            "Invalid AES key length: {other} bytes"
        ))),
    }
}

/// CFB mode over a full block width, built on `C`'s raw block encryption.
///
/// CFB encrypts the feedback value in both directions, so only the block encryption of `C` is
/// needed even when decrypting.
fn aes_cfb_with<C>(encrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError>
where
    C: BlockEncrypt + BlockSizeUser + KeyInit,
{
    let cipher = C::new_from_slice(key)
        .map_err(|_| TpmError::InvalidArraySize("Invalid AES key length".to_string()))?;

    let mut feedback = GenericArray::<u8, C::BlockSize>::default();
    let block_size = feedback.len();
    if iv.len() != block_size {
        return Err(TpmError::InvalidArraySize(format!(
            "IV must be {block_size} bytes"
        )));
    }
    feedback.copy_from_slice(iv);

    let mut result = Vec::with_capacity(data.len());

    for chunk in data.chunks(block_size) {
        // Encrypt the feedback (IV or previous ciphertext)
        let mut encrypted_feedback = feedback.clone();
        cipher.encrypt_block(&mut encrypted_feedback);

        // The next feedback value is the ciphertext either way: on encryption that is the
        // output, on decryption it is the input.
        let mut ct_block = GenericArray::<u8, C::BlockSize>::default();
        if encrypt {
            for (i, &b) in chunk.iter().enumerate() {
                ct_block[i] = b ^ encrypted_feedback[i];
                result.push(ct_block[i]);
            }
        } else {
            ct_block[..chunk.len()].copy_from_slice(chunk);
            for (i, &b) in chunk.iter().enumerate() {
                result.push(b ^ encrypted_feedback[i]);
            }
        }
        feedback = ct_block;
    }

    result.truncate(data.len());
    Ok(result)
}

fn random(out: &mut [u8]) -> Result<(), TpmError> {
    OsRng
        .try_fill_bytes(out)
        .map_err(|e| TpmError::GenericError(format!("Failed to obtain random bytes: {e}")))
}

/// Dispatches to the curve's own arithmetic, since each is a distinct type.
///
/// Only the NIST prime curves appear. A TPM may also nominate Barreto-Naehrig or SM2 curves, for
/// which RustCrypto offers no ECDH implementation; they are rejected rather than approximated,
/// because agreeing over the wrong curve would silently derive a key the peer cannot reproduce.
fn ecc_ephemeral_agree(
    curve: TPM_ECC_CURVE,
    peer_x: &[u8],
    peer_y: &[u8],
) -> Result<EccEphemeralAgreement, TpmError> {
    match curve {
        TPM_ECC_CURVE::NIST_P256 => agree_on::<p256::NistP256>(peer_x, peer_y),
        TPM_ECC_CURVE::NIST_P384 => agree_on::<p384::NistP384>(peer_x, peer_y),
        TPM_ECC_CURVE::NIST_P521 => agree_on::<p521::NistP521>(peer_x, peer_y),
        other => Err(TpmError::NotSupported(format!(
            "This provider cannot perform ECDH over curve {other}"
        ))),
    }
}

/// One ephemeral agreement over a single curve.
///
/// The curve's own field width is used rather than a looked-up constant, so the coordinates handed
/// to the curve implementation are of exactly the length it expects and no length mismatch can
/// arise between the two.
fn agree_on<C>(peer_x: &[u8], peer_y: &[u8]) -> Result<EccEphemeralAgreement, TpmError>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    let width = FieldBytes::<C>::default().len();
    let x = Crypto::pad_ecc_coordinate(peer_x, width)?;
    let y = Crypto::pad_ecc_coordinate(peer_y, width)?;

    let encoded = EncodedPoint::<C>::from_affine_coordinates(
        FieldBytes::<C>::from_slice(&x),
        FieldBytes::<C>::from_slice(&y),
        false,
    );

    // A point off the curve, or the point at infinity, is rejected here. Agreeing with it would
    // otherwise produce a value carrying no secret at all.
    let peer: PublicKey<C> = Option::from(PublicKey::<C>::from_encoded_point(&encoded))
        .ok_or_else(|| {
            TpmError::NotSupported(
                "The ECC public point is not a valid point on its curve".to_string(),
            )
        })?;

    let ephemeral = EphemeralSecret::<C>::random(&mut OsRng);
    let ephemeral_point = ephemeral.public_key().to_encoded_point(false);

    // Uncompressed encoding was requested above, so both coordinates are present unless the point
    // is the identity, which a freshly generated key cannot be.
    let missing =
        || TpmError::GenericError("The ephemeral public point has no coordinates".to_string());
    let ephemeral_x = ephemeral_point.x().ok_or_else(missing)?.to_vec();
    let ephemeral_y = ephemeral_point.y().ok_or_else(missing)?.to_vec();

    // The shared secret is the agreed point's X coordinate, already at the curve's full width.
    let z = Zeroizing::new(ephemeral.diffie_hellman(&peer).raw_secret_bytes().to_vec());

    Ok(EccEphemeralAgreement {
        z,
        ephemeral_x,
        ephemeral_y,
    })
}

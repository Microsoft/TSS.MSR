//! The pluggable crypto backend interface.
//!
//! TSS.Rust needs a handful of cryptographic primitives to build TPM structures on the host: to
//! hash a public area into a name, to derive session keys with KDFa, to wrap an activation
//! credential, and so on. Which library performs those primitives is a deployment decision, not a
//! protocol decision, so it is expressed here as a value the caller supplies.
//!
//! A provider is a plain struct of function pointers rather than a trait object. That keeps
//! [`CryptoProvider`] `Copy`, lets it be built in a `const` context, and means threading one
//! through a call chain costs no more than passing a pointer. This mirrors how `jsonwebtoken`
//! models its own pluggable backend.
//!
//! Deliberately, there is no process-wide default provider. A global has to be installed by
//! whoever gets to it first, and in a library that is not a decision any one caller owns: an
//! application and a dependency that both use TSS.Rust would race to set it, and the loser would
//! silently run against a backend it did not choose. Requiring the provider at the call site also
//! lets a single process use two backends at once, which is what makes cross-provider equivalence
//! testing possible.
//!
//! Only primitives belong here. Logic defined by the TPM 2.0 specification — digest sizes, KDFa,
//! signature validation — is built on top of these primitives by [`Crypto`](super::Crypto) and is
//! identical no matter which backend is in use.

use super::RsaKeyParts;
use crate::{
    error::TpmError,
    tpm_types::{TPM_ALG_ID, TPM_ECC_CURVE},
};
use std::fmt;
use zeroize::Zeroizing;

/// Signature of [`CryptoProvider::hash`].
pub type HashFn = fn(alg: TPM_ALG_ID, data: &[u8]) -> Result<Vec<u8>, TpmError>;

/// Signature of [`CryptoProvider::hmac`].
pub type HmacFn = fn(alg: TPM_ALG_ID, key: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError>;

/// Signature of [`CryptoProvider::aes_cfb`].
pub type AesCfbFn =
    fn(encrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmError>;

/// Signature of [`CryptoProvider::random`].
pub type RandomFn = fn(out: &mut [u8]) -> Result<(), TpmError>;

/// Signature of [`RsaOps::oaep_encrypt`].
pub type RsaOaepEncryptFn = fn(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    label: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, TpmError>;

/// Signature of [`RsaOps::pkcs1v15_verify`].
pub type RsaPkcs1v15VerifyFn = fn(
    modulus: &[u8],
    exponent: &[u8],
    hash_alg: TPM_ALG_ID,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, TpmError>;

/// Signature of [`RsaOps::generate_keypair`].
pub type RsaGenerateKeypairFn =
    fn(key_bits: usize, exponent: &[u8]) -> Result<RsaKeyParts, TpmError>;

/// Signature of [`RsaOps::pkcs1v15_sign`].
pub type RsaPkcs1v15SignFn =
    fn(key: &RsaKeyParts, hash_alg: TPM_ALG_ID, digest: &[u8]) -> Result<Vec<u8>, TpmError>;

/// What one ephemeral ECDH agreement produces.
///
/// An ECC key cannot be handed a secret the way an RSA key can be handed a ciphertext. The sender
/// instead generates a throwaway key on the peer's curve and agrees a value with it, and the peer
/// reproduces that value from its own private key. The ephemeral public point therefore travels in
/// place of a ciphertext, which is why it is returned alongside the agreed value rather than being
/// discarded with the private half.
///
/// Every field is big endian and zero padded on the left to the curve's coordinate width, and that
/// padding is load bearing in both cases, for different reasons.
/// [`Crypto::kdfe`](super::Crypto::kdfe) hashes `z` and `ephemeral_x`, so a short encoding of
/// either derives a different key from the one the peer derives. `ephemeral_y` is never hashed and
/// reaches the peer only inside the marshalled point, but it is padded alongside `ephemeral_x`
/// because a TPM is entitled to be handed a coordinate at its curve's width.
#[derive(Clone)]
pub struct EccEphemeralAgreement {
    /// The agreed value, which is the X coordinate of the agreed point.
    ///
    /// This is keying material rather than a public value: it is the sole input that distinguishes
    /// the derived seed from something an eavesdropper could compute. It is therefore wiped when
    /// dropped, and withheld from the [`Debug`] rendering below.
    pub z: Zeroizing<Vec<u8>>,

    /// The ephemeral public point's X coordinate.
    pub ephemeral_x: Vec<u8>,

    /// The ephemeral public point's Y coordinate.
    pub ephemeral_y: Vec<u8>,
}

/// Renders the public coordinates in full and the agreed value not at all.
///
/// The agreed value is as sensitive as the seed derived from it, and a derived `Debug` would put
/// it into any log line that formats a provider result.
impl fmt::Debug for EccEphemeralAgreement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EccEphemeralAgreement")
            .field("z", &format_args!("<{} bytes withheld>", self.z.len()))
            .field("ephemeral_x", &self.ephemeral_x)
            .field("ephemeral_y", &self.ephemeral_y)
            .finish()
    }
}

/// Signature of [`EccOps::ephemeral_agree`].
pub type EccEphemeralAgreeFn = fn(
    curve: TPM_ECC_CURVE,
    peer_x: &[u8],
    peer_y: &[u8],
) -> Result<EccEphemeralAgreement, TpmError>;

/// Returns the error reported by every primitive a provider leaves unimplemented.
fn unimplemented(operation: &str) -> TpmError {
    TpmError::NotSupported(format!(
        "The configured crypto provider does not implement {operation}"
    ))
}

/// The RSA primitives a provider supplies.
///
/// These are split out from [`CryptoProvider`] so that a backend able to offer only some of them
/// can start from [`RsaOps::new_unimplemented`] and fill in what it supports. That is not a
/// hypothetical: a provider built on Windows CNG cannot implement [`RsaOps::pkcs1v15_sign`],
/// because signing here has to recover the second prime by dividing the modulus by the first and
/// CNG exposes no big-integer division.
#[derive(Clone, Copy, Debug)]
pub struct RsaOps {
    /// RSA-OAEP encrypt `data` under the public key given by its big-endian components.
    ///
    /// `label` is passed through verbatim, so it must already include the trailing NUL that the
    /// TPM specification puts in labels such as `b"IDENTITY\0"`.
    pub oaep_encrypt: RsaOaepEncryptFn,

    /// Verify an RSASSA-PKCS1-v1_5 signature over an already computed digest.
    ///
    /// A `false` result means the signature did not verify. An `Err` means the verification could
    /// not be performed at all, for instance because the key or the hash algorithm was rejected.
    ///
    /// A signature that is not a candidate at all — one whose length differs from the modulus, or
    /// whose value is at or above it — is `false` rather than `Err`. This follows from the
    /// sentence above rather than adding to it: neither the key nor the hash algorithm is at
    /// fault in that case, and those are what `Err` is reserved for. Both shapes are chosen by
    /// whoever supplied the signature and say nothing about the caller, so a backend that
    /// reported them as failures would divert a caller such as
    /// [`TrustedPublic::validate_certify`](crate::tpm_type_extensions::TrustedPublic::validate_certify)
    /// out of its `false` branch on input a remote party controls. A backend layered on an API
    /// that distinguishes these from an ordinary bad signature has to fold them in itself.
    pub pkcs1v15_verify: RsaPkcs1v15VerifyFn,

    /// Generate an RSA key pair, returning the modulus and the first prime.
    pub generate_keypair: RsaGenerateKeypairFn,

    /// Sign an already computed digest with RSASSA-PKCS1-v1_5.
    pub pkcs1v15_sign: RsaPkcs1v15SignFn,
}

impl RsaOps {
    /// A set of RSA operations that all report [`TpmError::NotSupported`].
    ///
    /// Intended as a base for functional record update, so a backend states only what it provides:
    ///
    /// ```ignore
    /// RsaOps {
    ///     oaep_encrypt: my_oaep_encrypt,
    ///     ..RsaOps::new_unimplemented()
    /// }
    /// ```
    pub const fn new_unimplemented() -> Self {
        Self {
            oaep_encrypt: |_, _, _, _, _| Err(unimplemented("RSA-OAEP encryption")),
            pkcs1v15_verify: |_, _, _, _, _| Err(unimplemented("RSA PKCS#1 v1.5 verification")),
            generate_keypair: |_, _| Err(unimplemented("RSA key generation")),
            pkcs1v15_sign: |_, _, _| Err(unimplemented("RSA PKCS#1 v1.5 signing")),
        }
    }
}

/// The elliptic curve primitives a provider supplies.
///
/// Split out from [`CryptoProvider`] for the same reason as [`RsaOps`]: a backend that offers no
/// curve arithmetic at all, or only some of the curves a TPM may nominate, starts from
/// [`EccOps::new_unimplemented`].
#[derive(Clone, Copy, Debug)]
pub struct EccOps {
    /// Generate an ephemeral key on `curve`, agree with the public point `(peer_x, peer_y)`, and
    /// return the agreed value together with the ephemeral public point.
    ///
    /// Only the raw agreed value is returned. Deriving a key from it is defined by the TPM
    /// specification rather than by the backend, so it belongs to
    /// [`Crypto::kdfe`](super::Crypto::kdfe) and is deliberately not delegated here. Some platform
    /// APIs offer to perform the SP800-56A concatenation themselves; that shortcut is best
    /// avoided, because at least one of them silently ignores the requested hash algorithm and
    /// always uses SHA-256. The result is a wrong key that no interoperability failure would
    /// attribute to the KDF.
    ///
    /// A curve the backend cannot agree over must be reported as [`TpmError::NotSupported`]
    /// rather than approximated with another curve.
    pub ephemeral_agree: EccEphemeralAgreeFn,
}

impl EccOps {
    /// A set of ECC operations that all report [`TpmError::NotSupported`].
    pub const fn new_unimplemented() -> Self {
        Self {
            ephemeral_agree: |_, _, _| Err(unimplemented("ECDH ephemeral key agreement")),
        }
    }
}

/// The cryptographic primitives TSS.Rust needs from its host.
#[derive(Clone, Copy, Debug)]
pub struct CryptoProvider {
    /// Hash `data` with `alg`, returning a digest of exactly `Crypto::digestSize(alg)` bytes.
    pub hash: HashFn,

    /// HMAC `data` under `key` using `alg`. The key may be of any length.
    pub hmac: HmacFn,

    /// AES in CFB mode with a full 128-bit segment, as the TPM specification requires.
    ///
    /// `data` is not required to be a multiple of the block size; the final partial block is
    /// processed against a truncated key stream. Backends layered on an API whose CFB mode
    /// defaults to an 8-bit segment must not use that mode here.
    pub aes_cfb: AesCfbFn,

    /// Fill `out` with cryptographically secure random bytes.
    pub random: RandomFn,

    /// The RSA primitives.
    pub rsa: RsaOps,

    /// The elliptic curve primitives.
    pub ecc: EccOps,
}

impl CryptoProvider {
    /// A provider whose every primitive reports [`TpmError::NotSupported`].
    ///
    /// Intended as a base for functional record update, in the same way as
    /// [`RsaOps::new_unimplemented`].
    pub const fn new_unimplemented() -> Self {
        Self {
            hash: |_, _| Err(unimplemented("hashing")),
            hmac: |_, _, _| Err(unimplemented("HMAC")),
            aes_cfb: |_, _, _, _| Err(unimplemented("AES-CFB")),
            random: |_| Err(unimplemented("random number generation")),
            rsa: RsaOps::new_unimplemented(),
            ecc: EccOps::new_unimplemented(),
        }
    }
}

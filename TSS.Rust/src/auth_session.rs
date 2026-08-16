use crate::crypto::{provider::CryptoProvider, Crypto};
use crate::error::TpmError;
use crate::{tpm_structure::TpmEnum, tpm_types::*};
use std::fmt;
use zeroize::Zeroize;

/// Authentication session for TPM commands
#[derive(Default, Clone)]
pub struct Session {
    pub sess_in: TPMS_AUTH_COMMAND,
    pub sess_out: TPMS_AUTH_RESPONSE,

    // Additional session properties
    pub hash_alg: TPM_ALG_ID,
    pub session_type: TPM_SE,
    pub needs_hmac: bool,
    pub needs_password: bool,

    /// Derived session key (from KDFa with "ATH" label)
    ///
    /// This authorizes every command issued on the session and keys its parameter encryption, so
    /// it is wiped when dropped and withheld from the [`Debug`] rendering below.
    pub session_key: Vec<u8>,

    /// Whether `session_key` was derived from anything an eavesdropper does not already have.
    ///
    /// A session key is only worth something if the KDFa that produced it took a secret input:
    /// the salt, or the authValue of the bind entity. An unsalted session bound to an entity
    /// whose authValue is empty produces a perfectly non-empty `session_key` that is a pure
    /// function of the two nonces — both of which travel in the clear. Emptiness of
    /// `session_key` therefore is not the property that matters; this flag is.
    secret_key_material: bool,

    /// Symmetric algorithm for parameter encryption
    pub symmetric: TPMT_SYM_DEF,

    /// Handle of the entity this session is bound to (NULL if unbound)
    pub bind_handle: u32,
}

/// Renders what identifies a session and none of what authorizes it.
///
/// A derived `Debug` would print `session_key`, and for a password session `sess_in.hmac`, which
/// holds the caller's auth value verbatim. A session is formatted wherever a command is traced or
/// an error reports the session it was issued on, so a derived implementation would put both into
/// ordinary log output.
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field(
                "session_handle",
                &format_args!("0x{:08x}", self.sess_in.sessionHandle.handle),
            )
            .field("session_type", &self.session_type)
            .field("hash_alg", &self.hash_alg)
            .field("attributes", &self.sess_in.sessionAttributes)
            .field("symmetric", &self.symmetric)
            .field("needs_hmac", &self.needs_hmac)
            .field("needs_password", &self.needs_password)
            .field("bind_handle", &format_args!("0x{:08x}", self.bind_handle))
            .field("nonce_caller", &self.sess_in.nonce)
            .field("nonce_tpm", &self.sess_out.nonce)
            .field("session_key", &format_args!("<redacted>"))
            .field("auth", &format_args!("<redacted>"))
            .finish()
    }
}

/// Wipes the session key and the auth value, so that a session that has gone out of scope is not
/// left in freed heap.
///
/// The session is cloned on essentially every command, so the copies matter as much as the
/// original; each one is wiped by this same implementation. `sess_in.hmac` is wiped here rather
/// than by its own type because `TPMS_AUTH_COMMAND` is generated from the TPM 2.0 specification
/// and cannot carry hand-written behaviour.
impl Drop for Session {
    fn drop(&mut self) {
        self.session_key.zeroize();
        self.sess_in.hmac.zeroize();
    }
}

impl Session {
    pub fn new(
        session_handle: TPM_HANDLE,
        nonce_tpm: &[u8],
        session_attributes: TPMA_SESSION,
        nonce_caller: &[u8],
    ) -> Self {
        Session {
            sess_in: TPMS_AUTH_COMMAND::new(
                &session_handle,
                &nonce_caller.to_vec(),
                session_attributes,
                &Vec::new(),
            ),
            sess_out: TPMS_AUTH_RESPONSE::new(&nonce_tpm.to_vec(), session_attributes, &Vec::new()),
            hash_alg: TPM_ALG_ID::SHA256,
            session_type: TPM_SE::HMAC,
            needs_hmac: true,
            needs_password: false,
            session_key: Vec::new(),
            secret_key_material: false,
            symmetric: TPMT_SYM_DEF::default(),
            bind_handle: TPM_RH::NULL.get_value(),
        }
    }

    /// Create a password authorization session (PWAP)
    pub fn pw(auth_value: Option<Vec<u8>>) -> Self {
        let mut s = Session::default();
        s.sess_in.sessionHandle = TPM_HANDLE::new(TPM_RH::PW.get_value());
        s.sess_in.nonce = Vec::new();
        s.sess_in.sessionAttributes = TPMA_SESSION::continueSession;
        let auth_value = auth_value.unwrap_or_default();
        s.sess_in.hmac = auth_value;
        s.sess_out.sessionAttributes = TPMA_SESSION::continueSession;
        s.session_type = TPM_SE::HMAC;
        s.needs_hmac = false;
        s.needs_password = true;
        s.bind_handle = TPM_RH::NULL.get_value();

        s
    }

    /// Create a fully initialized HMAC or policy session from a TPM StartAuthSession response.
    // The parameter list mirrors the TPM2_StartAuthSession response fields; grouping them into a
    // struct would just move the same values behind another type.
    #[allow(clippy::too_many_arguments)]
    pub fn from_tpm_response(
        crypto: &CryptoProvider,
        session_handle: TPM_HANDLE,
        session_type: TPM_SE,
        hash_alg: TPM_ALG_ID,
        nonce_caller: Vec<u8>,
        nonce_tpm: Vec<u8>,
        attributes: TPMA_SESSION,
        symmetric: TPMT_SYM_DEF,
        salt: &[u8],
        bind_object: &TPM_HANDLE,
    ) -> Result<Self, TpmError> {
        let mut sess = Session {
            sess_in: TPMS_AUTH_COMMAND::new(
                &session_handle,
                &nonce_caller,
                attributes,
                &Vec::new(),
            ),
            sess_out: TPMS_AUTH_RESPONSE::new(&nonce_tpm, attributes, &Vec::new()),
            hash_alg,
            session_type,
            needs_hmac: session_type == TPM_SE::HMAC,
            needs_password: false,
            session_key: Vec::new(),
            secret_key_material: false,
            symmetric,
            bind_handle: bind_object.handle,
        };

        sess.calc_session_key(crypto, salt, bind_object)?;
        sess.reject_vacuous_param_encryption(attributes)?;
        Ok(sess)
    }

    /// Refuse `TPMA_SESSION::encrypt` / `decrypt` on a session with no secret key material.
    ///
    /// Parameter encryption derives its AES-CFB key with
    /// `KDFa(hashAlg, sessionKey, "CFB", nonceNewer, nonceOlder)`. On an unsalted *and* unbound
    /// session `sessionKey` is empty, so every input to that derivation — both nonces — travels
    /// over the wire in the clear. Anyone who sees the exchange derives the same key and reads
    /// the "encrypted" parameter. It is not weak encryption, it is no encryption, and it is
    /// worse than none because the caller believes the parameter is protected.
    ///
    /// The same is true, less obviously, of a session bound to an entity with an empty
    /// authValue: `sessionKey` is then non-empty but is still a deterministic function of the
    /// two public nonces. `secret_key_material` is what distinguishes the two cases.
    ///
    /// Salt the session ([`crate::tpm2_impl::Tpm2::start_salted_auth_session`]) or bind it to an
    /// entity with a non-empty authValue, and the derivation gains an input an observer does not
    /// have.
    fn reject_vacuous_param_encryption(&self, attributes: TPMA_SESSION) -> Result<(), TpmError> {
        let xcrypt = TPMA_SESSION::encrypt.get_value() | TPMA_SESSION::decrypt.get_value();
        if (attributes.get_value() & xcrypt) != 0 && !self.secret_key_material {
            return Err(TpmError::GenericError(
                "Parameter encryption was requested on a session with no secret key material. \
                 An unsalted session that is unbound (or bound to an entity with an empty \
                 authValue) derives its encryption key entirely from nonces that travel in the \
                 clear, so the encryption protects nothing. Salt the session or bind it to an \
                 entity with a non-empty authValue."
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Derive the session key using KDFa with label "ATH".
    /// SessionKey = KDFa(hashAlg, bindAuth || salt, "ATH", nonceTPM, nonceCaller, hashBits)
    fn calc_session_key(
        &mut self,
        crypto: &CryptoProvider,
        salt: &[u8],
        bind_object: &TPM_HANDLE,
    ) -> Result<(), TpmError> {
        let null_handle = TPM_HANDLE::new(TPM_RH::NULL.get_value());
        let has_salt = !salt.is_empty();
        let is_bound = bind_object.handle != null_handle.handle;

        if !has_salt && !is_bound {
            // No key derivation needed for unbound, unsalted sessions
            return Ok(());
        }

        // hmacKey = bindAuth || salt
        let mut hmac_key = Vec::new();
        if is_bound {
            let bind_auth = trim_trailing_zeros(&bind_object.auth_value);
            hmac_key.extend_from_slice(&bind_auth);
        }
        hmac_key.extend_from_slice(salt);

        // The KDFa below runs regardless, because the TPM runs it too and the two keys must
        // agree. What it produces is only *secret* if something secret went into it.
        self.secret_key_material = !hmac_key.is_empty();

        let hash_bits = Crypto::digest_size_checked(self.hash_alg)? * 8;
        // Wipe before overwriting. `Drop for Session` runs only when the session goes out of
        // scope, so a key this method replaces would otherwise be dropped unwiped. Today the
        // only caller derives into a session it has just built, so there is nothing to wipe;
        // the wipe is here so that stays true of any later caller.
        self.session_key.zeroize();
        self.session_key = Crypto::kdfa(
            crypto,
            self.hash_alg,
            &hmac_key,
            "ATH",
            &self.sess_out.nonce, // nonceTPM
            &self.sess_in.nonce,  // nonceCaller
            hash_bits,
        )?;

        Ok(())
    }

    /// Check if this is a password authorization session
    pub fn is_pwap(&self) -> bool {
        self.sess_in.sessionHandle.handle == TPM_RH::PW.get_value()
    }

    /// Whether the TPM reported this session's context as closed in the last response it
    /// appeared in.
    ///
    /// `continueSession` CLEAR in a response is the TPM saying it closed the session and freed
    /// the context when the command completed (TPM 2.0 Part 2, `TPMA_SESSION.continueSession`,
    /// which also warns that "a session created after another session is ended may have the same
    /// handle but logically is not the same session"). The reference implementation flushes on
    /// exactly this condition — `SessionFlush` in `BuildResponseSession`, ms-tpm-20-ref
    /// `SessionProcess.c` — so the handle is dead and may later belong to someone else.
    ///
    /// A password authorization has no context to close: the TPM SETs the attribute in the
    /// response whatever the command asked for, and this client never reads a PWAP session's
    /// response attributes, so one is never reported closed.
    ///
    /// This reflects the last response, so it is only meaningful once the session has been used;
    /// on a session that has not been through a command it merely restates the attributes it was
    /// constructed with.
    pub fn is_terminated(&self) -> bool {
        !self.is_pwap()
            && (self.sess_out.sessionAttributes.get_value()
                & TPMA_SESSION::continueSession.get_value())
                == 0
    }

    /// Set authorization value for HMAC calculation
    ///
    /// The value it replaces is wiped first. `sess_in.hmac` on a password session is the
    /// caller's authorization value verbatim, and `Drop for Session` only wipes it when the
    /// whole session goes out of scope, so a second call would otherwise leave the first auth
    /// value in freed heap.
    pub fn set_auth_value(&mut self, auth_value: Vec<u8>) {
        if self.is_pwap() {
            self.sess_in.hmac.zeroize();
            self.sess_in.hmac = auth_value;
        }
    }

    /// Get the hash algorithm used by this session
    pub fn get_hash_alg(&self) -> TPM_ALG_ID {
        self.hash_alg
    }

    /// Whether the authValue of the entity being authorized is folded into the HMAC key.
    ///
    /// This mirrors `session->attributes.includeAuth` in the TPM reference implementation
    /// (`SessionProcess.c`, `CheckAuthSession`):
    ///
    /// * policy session — include only when `TPM2_PolicyAuthValue` or `TPM2_PolicyPassword` has
    ///   run, i.e. when the TPM's `isAuthValueNeeded` / `isPasswordNeeded` is SET;
    /// * HMAC session — include unless the session is bound to this very entity, in which case
    ///   the authValue is already inside `sessionKey`.
    fn includes_auth_value(&self, associated_handle: Option<&TPM_HANDLE>) -> bool {
        if self.session_type == TPM_SE::POLICY {
            return self.needs_hmac || self.needs_password;
        }

        match associated_handle {
            None => false,
            Some(handle) => {
                let bound_to_this_entity = self.bind_handle != TPM_RH::NULL.get_value()
                    && self.bind_handle != 0
                    && handle.handle == self.bind_handle;
                !bound_to_this_entity
            }
        }
    }

    /// `hmacKey = sessionKey || authValue`, the key both the command and the response HMAC use.
    fn auth_hmac_key(&self, associated_handle: Option<&TPM_HANDLE>) -> Vec<u8> {
        let mut key = self.session_key.clone();
        if self.includes_auth_value(associated_handle) {
            if let Some(handle) = associated_handle {
                key.extend_from_slice(&trim_trailing_zeros(&handle.auth_value));
            }
        }
        key
    }

    /// Whether this session's key was derived from a secret (salt, or a non-empty bind
    /// authValue). Sessions without it cannot be used for parameter encryption.
    pub fn has_secret_key_material(&self) -> bool {
        self.secret_key_material
    }

    /// Whether the TPM will place an authorization HMAC in the response for this session.
    ///
    /// The TPM's rule, from `BuildSingleResponseAuth` in the reference implementation:
    /// a password session carries no response auth, and neither does a policy session on which
    /// `TPM2_PolicyPassword` has run — in both cases the TPM returns an empty `hmac` field.
    /// Every other session gets one, and this client checks it rather than ignoring it.
    ///
    /// What that check is worth depends on the session, and the difference is worth stating
    /// plainly rather than glossing. The response tag is
    /// `HMAC(hashAlg, sessionKey ‖ authValue, ...)`, so it authenticates the response only when
    /// one of those two parts is secret:
    ///
    /// * a salted session, or one bound to an entity with a non-empty authValue, has a
    ///   `sessionKey` derived from something an observer does not have — see
    ///   [`Session::has_secret_key_material`];
    /// * a session that folds in an authValue — an HMAC session authorizing an entity it is not
    ///   bound to, or a policy session on which `TPM2_PolicyAuthValue` has run — is keyed on
    ///   that authValue.
    ///
    /// A policy session that is unsalted, unbound and has run neither `PolicyAuthValue` nor
    /// `PolicyPassword` has neither: `calc_session_key` returns before deriving anything, so
    /// `session_key` is empty, and `includes_auth_value` is false. Its HMAC key is the empty
    /// string, which anyone watching the exchange can key an HMAC with. Verifying that tag is a
    /// corruption check, not authentication, and no amount of checking makes it more than that
    /// — only salting or binding the session does.
    ///
    /// The rule is the same for all of them, because it has to be: which sessions carry a tag is
    /// the TPM's decision, and a client that skipped the check for the cases above would also
    /// skip it for every salted or `PolicyAuthValue` policy session, where the tag is the only
    /// thing standing behind the response parameters.
    ///
    /// (The TPM has one further shortcut, observed on hardware rather than read out of the
    /// reference implementation: an empty field also comes back when the HMAC key is empty *and*
    /// the command's auth field was empty. This client never sends an empty auth field for such
    /// a session, so the shortcut is not taken and there is always a tag to check.)
    pub fn expects_response_auth(&self) -> bool {
        !self.is_pwap() && !self.needs_password
    }

    /// Whether a command using this session carries a computed HMAC rather than a password.
    pub fn sends_command_hmac(&self) -> bool {
        !self.is_pwap() && !self.needs_password
    }

    /// Generate an HMAC for authorization.
    /// hmacKey = sessionKey || authValue
    /// hmac = HMAC(hashAlg, hmacKey, parmHash || nonceNewer || nonceOlder || nonceDec || nonceEnc || sessionAttrs)
    pub fn get_auth_hmac(
        &self,
        crypto: &CryptoProvider,
        cp_hash: Vec<u8>,
        is_command: bool,
        nonce_tpm_dec: &[u8],
        nonce_tpm_enc: &[u8],
        associated_handle: Option<&TPM_HANDLE>,
    ) -> Result<Vec<u8>, TpmError> {
        // PWAP: return the auth value directly
        if self.is_pwap() {
            return Ok(self.sess_in.hmac.clone());
        }

        // PolicyPassword: return auth value directly
        if self.needs_password {
            return Ok(self.sess_in.hmac.clone());
        }

        // Determine nonce order based on direction
        let (nonce_newer, nonce_older) = if is_command {
            (&self.sess_in.nonce, &self.sess_out.nonce)
        } else {
            (&self.sess_out.nonce, &self.sess_in.nonce)
        };

        // Session attributes: use command attrs for commands, response attrs for responses
        let session_attrs = if is_command {
            vec![self.sess_in.sessionAttributes.get_value()]
        } else {
            vec![self.sess_out.sessionAttributes.get_value()]
        };

        let hmac_key = self.auth_hmac_key(associated_handle);

        // Buffer to HMAC: parmHash || nonceNewer || nonceOlder || nonceDec || nonceEnc || sessionAttrs
        let mut buf_to_hmac = Vec::new();
        buf_to_hmac.extend_from_slice(&cp_hash);
        buf_to_hmac.extend_from_slice(nonce_newer);
        buf_to_hmac.extend_from_slice(nonce_older);
        buf_to_hmac.extend_from_slice(nonce_tpm_dec);
        buf_to_hmac.extend_from_slice(nonce_tpm_enc);
        buf_to_hmac.extend_from_slice(&session_attrs);

        Crypto::hmac(crypto, self.hash_alg, &hmac_key, &buf_to_hmac)
    }

    /// Process parameter encryption/decryption using AES-CFB.
    /// Key derivation: KDFa(hashAlg, sessionKey, "CFB", nonceNewer, nonceOlder, 256)
    /// First keyBits/8 bytes = AES key, next 16 bytes = IV
    pub fn param_xcrypt(
        &self,
        crypto: &CryptoProvider,
        data: &[u8],
        is_command: bool,
    ) -> Result<Vec<u8>, TpmError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Refuse to derive an encryption key from public values alone. See
        // `reject_vacuous_param_encryption`: this is the second gate, so that a `Session`
        // assembled by hand rather than by `from_tpm_response` cannot slip past the first.
        if !self.secret_key_material {
            return Err(TpmError::GenericError(
                "Refusing parameter encryption on a session with no secret key material: the \
                 AES-CFB key would be derived entirely from nonces that travel in the clear."
                    .to_string(),
            ));
        }

        // Only AES-128/256 CFB is supported
        if self.symmetric.algorithm != TPM_ALG_ID::AES || self.symmetric.mode != TPM_ALG_ID::CFB {
            return Err(TpmError::GenericError(
                "Only AES in CFB mode is supported for parameter encryption".to_string(),
            ));
        }

        let key_bits = self.symmetric.keyBits as usize;
        if key_bits != 128 && key_bits != 256 {
            return Err(TpmError::GenericError(format!(
                "Unsupported AES key size: {} bits",
                key_bits
            )));
        }

        let key_size = key_bits / 8;

        // Determine nonce order: for requests, nonceNewer=nonceCaller, nonceOlder=nonceTPM
        // For responses, nonceNewer=nonceTPM, nonceOlder=nonceCaller
        let (nonce_newer, nonce_older) = if is_command {
            (&self.sess_in.nonce, &self.sess_out.nonce)
        } else {
            (&self.sess_out.nonce, &self.sess_in.nonce)
        };

        // Derive key material: KDFa(hashAlg, sessionKey, "CFB", nonceNewer, nonceOlder, 256)
        // Produces key_size + 16 bytes (key + IV)
        let num_bits = (key_size + CFB_IV_SIZE) * 8;
        let key_info = Crypto::kdfa(
            crypto,
            self.hash_alg,
            &self.session_key,
            "CFB",
            nonce_newer,
            nonce_older,
            num_bits,
        )?;

        let (aes_key, iv) = split_cfb_key_material(&key_info, key_size)?;

        // For requests: encrypt (TPM will decrypt)
        // For responses: decrypt (TPM encrypted it)
        Crypto::cfb_xcrypt(crypto, is_command, aes_key, iv, data)
    }
}

/// Trim trailing zero bytes from a byte vector
fn trim_trailing_zeros(data: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    while result.last() == Some(&0) {
        result.pop();
    }
    result
}

/// The AES-CFB initialisation vector is one AES block, whatever the key size.
const CFB_IV_SIZE: usize = 16;

/// Split the KDFa stream that keys parameter encryption into the AES key and the CFB
/// initialisation vector.
///
/// The split is checked rather than sliced outright. KDFa is asked for exactly
/// `key_size + CFB_IV_SIZE` octets and the in-crate implementation returns exactly that, so with
/// the providers bundled here this can never come up short. [`CryptoProvider`] is a public struct
/// of function pointers, though: KDFa is built on a caller-supplied HMAC, and a backend that
/// returned fewer octets than it should would turn these two slices into a panic in a library
/// whose every other failure is a [`TpmError`].
fn split_cfb_key_material(key_info: &[u8], key_size: usize) -> Result<(&[u8], &[u8]), TpmError> {
    let needed = key_size + CFB_IV_SIZE;
    if key_info.len() < needed {
        return Err(TpmError::GenericError(format!(
            "Key derivation produced {} B of parameter encryption key material, but {} B are \
             needed for an AES-{} key and its initialization vector. The configured crypto \
             provider is not returning full length HMACs.",
            key_info.len(),
            needed,
            key_size * 8
        )));
    }
    Ok((&key_info[..key_size], &key_info[key_size..needed]))
}

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
    fn session_debug_withholds_the_session_key() {
        let mut session = Session::default();
        session.session_key = SECRET.to_vec();

        let rendered = format!("{:?}", session);

        assert_withholds_secret(&rendered, &SECRET);

        // The fields that identify the session stay legible, which is the point of hand writing
        // the rendering rather than dropping `Debug` altogether.
        assert!(rendered.contains("session_handle"));
        assert!(rendered.contains("session_type"));
        assert!(rendered.contains("hash_alg"));
        assert!(rendered.contains("attributes"));
        assert!(rendered.contains("session_key: <redacted>"));
    }

    #[test]
    fn session_debug_withholds_the_password_auth_value() {
        // A PWAP session carries the caller's auth value in `sess_in.hmac`, in the clear.
        let session = Session::pw(Some(SECRET.to_vec()));

        let rendered = format!("{:?}", session);

        assert_withholds_secret(&rendered, &SECRET);
        assert!(rendered.contains("auth: <redacted>"));
    }

    #[test]
    fn session_still_defaults_and_clones() {
        let mut session = Session::default();
        assert!(session.session_key.is_empty());

        session.session_key = SECRET.to_vec();
        let copy = session.clone();

        assert_eq!(copy.session_key, session.session_key);
        assert_eq!(
            copy.sess_in.sessionHandle.handle,
            session.sess_in.sessionHandle.handle
        );
        assert_eq!(copy.hash_alg, session.hash_alg);
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;

    const SALT: &[u8] = b"a thirty-two byte session salt..";

    fn start(
        attributes: TPMA_SESSION,
        salt: &[u8],
        bind: &TPM_HANDLE,
    ) -> Result<Session, TpmError> {
        Session::from_tpm_response(
            &SOFTWARE_PROVIDER,
            TPM_HANDLE::new(0x02000000),
            TPM_SE::HMAC,
            TPM_ALG_ID::SHA256,
            vec![0xAA; 32],
            vec![0xBB; 32],
            attributes,
            TPMT_SYM_DEF::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            salt,
            bind,
        )
    }

    fn null_handle() -> TPM_HANDLE {
        TPM_HANDLE::new(TPM_RH::NULL.get_value())
    }

    #[test]
    fn unsalted_unbound_session_rejects_parameter_encryption() {
        // KDFa(hash, <empty>, "CFB", nonceNewer, nonceOlder) is a function of two values that
        // both travelled in the clear. Anyone who saw the exchange derives the same AES-CFB key.
        let err = start(
            TPMA_SESSION::continueSession | TPMA_SESSION::decrypt,
            &[],
            &null_handle(),
        )
        .expect_err("parameter encryption with no key material must be refused");
        assert!(
            format!("{}", err).contains("no secret key material"),
            "unexpected error: {}",
            err
        );

        let err = start(
            TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
            &[],
            &null_handle(),
        )
        .expect_err("the encrypt direction is no better than the decrypt direction");
        assert!(format!("{}", err).contains("no secret key material"));
    }

    #[test]
    fn session_bound_to_an_entity_with_an_empty_auth_rejects_parameter_encryption() {
        // Less obvious than the unbound case and just as vacuous: KDFa runs, so `session_key` is
        // non-empty, but its only inputs are the two public nonces.
        let mut bound = TPM_HANDLE::new(0x81000001);
        bound.set_auth(&[]);

        let err = start(
            TPMA_SESSION::continueSession | TPMA_SESSION::decrypt,
            &[],
            &bound,
        )
        .expect_err("an empty bind authValue contributes no secret");
        assert!(format!("{}", err).contains("no secret key material"));
    }

    #[test]
    fn an_unencrypted_unsalted_session_is_still_allowed() {
        // The rejection is scoped to parameter encryption. Plain authorization over an unsalted,
        // unbound session remains legitimate and is what most callers use.
        let sess = start(TPMA_SESSION::continueSession, &[], &null_handle()).unwrap();
        assert!(sess.session_key.is_empty());
        assert!(!sess.has_secret_key_material());
    }

    #[test]
    fn a_salted_session_allows_parameter_encryption() {
        let sess = start(
            TPMA_SESSION::continueSession | TPMA_SESSION::decrypt,
            SALT,
            &null_handle(),
        )
        .expect("a salted session has a secret input and may encrypt parameters");
        assert!(sess.has_secret_key_material());
        assert_eq!(sess.session_key.len(), 32);
        assert!(sess
            .param_xcrypt(&SOFTWARE_PROVIDER, &[1, 2, 3, 4], true)
            .is_ok());
    }

    #[test]
    fn a_session_bound_to_a_non_empty_auth_allows_parameter_encryption() {
        let mut bound = TPM_HANDLE::new(0x81000001);
        bound.set_auth(b"bind-auth");

        let sess = start(
            TPMA_SESSION::continueSession | TPMA_SESSION::decrypt,
            &[],
            &bound,
        )
        .expect("a non-empty bind authValue is a secret an observer does not have");
        assert!(sess.has_secret_key_material());
    }

    #[test]
    fn param_xcrypt_refuses_a_session_without_secret_key_material() {
        // The second gate: a `Session` assembled by hand rather than through
        // `from_tpm_response` must not be able to reach the vacuous derivation either.
        let mut sess = Session::new(
            TPM_HANDLE::new(0x02000000),
            &[0xBB; 32],
            TPMA_SESSION::continueSession,
            &[0xAA; 32],
        );
        sess.symmetric = TPMT_SYM_DEF::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB);

        let err = sess
            .param_xcrypt(&SOFTWARE_PROVIDER, &[1, 2, 3, 4], true)
            .expect_err("no key material means no encryption");
        assert!(format!("{}", err).contains("no secret key material"));
    }

    #[test]
    fn a_password_session_expects_no_response_auth() {
        let sess = Session::pw(Some(b"auth".to_vec()));
        assert!(sess.is_pwap());
        assert!(!sess.expects_response_auth());
    }

    #[test]
    fn a_policy_session_without_policy_password_expects_a_response_auth() {
        // The rule is `!is_pwap && !needs_password`, not "HMAC session or PolicyAuthValue ran".
        // A policy session driven by PolicyPCR alone still gets an authenticated response.
        let mut sess = start(TPMA_SESSION::continueSession, SALT, &null_handle()).unwrap();
        sess.session_type = TPM_SE::POLICY;
        sess.needs_hmac = false;
        sess.needs_password = false;
        assert!(sess.expects_response_auth());
    }

    #[test]
    fn an_unsalted_unbound_policy_session_authenticates_nothing() {
        // What `expects_response_auth` documents, stated as an assertion. This session gets a
        // response tag and this client checks it, but the key it checks with is the empty
        // string: `calc_session_key` returned before deriving anything, and no authValue is
        // folded in because neither PolicyAuthValue nor PolicyPassword has run. Anyone on the
        // wire can produce a tag that verifies, so the check finds corruption, not forgery.
        let mut sess = start(TPMA_SESSION::continueSession, &[], &null_handle()).unwrap();
        sess.session_type = TPM_SE::POLICY;
        sess.needs_hmac = false;
        sess.needs_password = false;

        let mut authorized = TPM_HANDLE::new(0x81000001);
        authorized.set_auth(b"object-auth");

        assert!(sess.expects_response_auth());
        assert!(!sess.has_secret_key_material());
        assert!(!sess.includes_auth_value(Some(&authorized)));
        assert!(
            sess.auth_hmac_key(Some(&authorized)).is_empty(),
            "an unsalted, unbound policy session keys its HMAC on nothing at all"
        );

        // The contrast, so that this does not read as a claim about policy sessions in general:
        // salt the same session and the key is a secret an observer does not have.
        let salted = start(TPMA_SESSION::continueSession, SALT, &null_handle()).unwrap();
        assert!(salted.has_secret_key_material());
        assert!(!salted.auth_hmac_key(Some(&authorized)).is_empty());
    }

    /// Two bytes of hex per octet, for the vectors below.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// The session key against values computed outside this crate.
    ///
    /// Every other HMAC assertion in this repository keys itself on `session.session_key`, which
    /// comes from `calc_session_key` — the code under test. Those tests agree with the client no
    /// matter what it derives: swap the two nonces, or change the label, and they all still
    /// pass. These vectors were produced independently from the formula in TPM 2.0 Part 1,
    /// §11.4.10.2 and §19.6.8:
    ///
    /// ```text
    ///   sessionKey := KDFa(hashAlg, bindAuth ‖ salt, "ATH", nonceTPM, nonceCaller, bits)
    ///   KDFa(alg, key, label, contextU, contextV, bits) :=
    ///       HMAC_alg(key, BE32(counter) ‖ label ‖ 0x00 ‖ contextU ‖ contextV ‖ BE32(bits))
    /// ```
    ///
    /// so they pin the KDFa construction itself: the nonce *order* (nonceTPM is contextU, the
    /// caller's nonce contextV), the label, its NUL terminator, and the trailing bit count.
    #[test]
    fn the_session_key_matches_an_independently_computed_kdfa_vector() {
        // KDFa(SHA256, SALT, "ATH", [0xBB; 32], [0xAA; 32], 256), where the two nonces are the
        // ones `start` hands to `Session::from_tpm_response`.
        let salted = start(TPMA_SESSION::continueSession, SALT, &null_handle()).unwrap();
        assert_eq!(
            salted.session_key,
            hex("39a0d74e4c4cc9d54088ec9565944c5e3332594b4a98c35be52ae224c86ab367")
        );

        // The same derivation with the nonces the other way round. It is here to show what the
        // vector above rules out: a client that fed nonceCaller as contextU would agree with
        // every HMAC test in this repository and with no TPM at all.
        assert_ne!(
            salted.session_key,
            hex("12ed2216d596138fe107ef74730c868bbfd2b6e0d25c8801e60688585668c62e"),
            "nonceTPM is contextU and nonceCaller is contextV, not the other way round"
        );

        // And with the "CFB" label, which is what parameter encryption derives with. A session
        // key derived under the wrong label is the same length and useless.
        assert_ne!(
            salted.session_key,
            hex("ad195ab7d2e025c8e96aa8b9e961ab0d8ee3b8f7650def7dec93427ec5d56772"),
            "the session key is derived under the \"ATH\" label"
        );

        // bindAuth ‖ salt, with the bind entity's authValue first:
        // KDFa(SHA256, b"bind-auth" ‖ SALT, "ATH", [0xBB; 32], [0xAA; 32], 256).
        let mut bound = TPM_HANDLE::new(0x81000001);
        bound.set_auth(b"bind-auth");
        let bound = start(TPMA_SESSION::continueSession, SALT, &bound).unwrap();
        assert_eq!(
            bound.session_key,
            hex("8ac20ea98b54559b4697be91175c84851ef430023f264e87c379bf6d6301edd9")
        );
    }
}

#[cfg(test)]
mod cfb_key_material_tests {
    use super::*;

    #[test]
    fn key_material_shorter_than_the_key_and_iv_is_an_error_not_a_panic() {
        // Unreachable through the KDFa in this crate, which always returns exactly the number of
        // octets it was asked for. It is reachable through a `CryptoProvider` supplied by
        // someone else, and the answer there has to be an error rather than a panicking slice.
        let err = split_cfb_key_material(&[0u8; 31], 16)
            .expect_err("16 B of key and 16 B of IV do not fit in 31 B");
        assert!(
            format!("{}", err).contains("parameter encryption key material"),
            "unexpected error: {}",
            err
        );

        assert!(split_cfb_key_material(&[0u8; 47], 32).is_err());
    }

    #[test]
    fn key_material_is_split_into_the_key_and_then_the_iv() {
        let stream: Vec<u8> = (0..48u8).collect();

        let (key, iv) = split_cfb_key_material(&stream, 16).unwrap();
        assert_eq!(key, &stream[..16]);
        assert_eq!(iv, &stream[16..32]);

        let (key, iv) = split_cfb_key_material(&stream, 32).unwrap();
        assert_eq!(key, &stream[..32]);
        assert_eq!(iv, &stream[32..48]);
    }
}

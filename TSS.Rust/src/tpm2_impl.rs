/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

use crate::auth_session::Session;
use crate::crypto::{provider::CryptoProvider, Crypto};
use crate::device::TpmDevice;
use crate::error::TpmError;
use crate::tpm_buffer::{TpmBuffer, TpmMarshaller};
use crate::tpm_structure::{CmdStructure, ReqStructure, RespStructure, TpmEnum};
use crate::tpm_type_extensions::TrustedPublic;
use crate::tpm_types::{
    CreateLoadedResponse, CreatePrimaryResponse, TPM2_LoadExternal_REQUEST, TPM2_Load_REQUEST,
    TPMA_SESSION, TPMS_AUTH_COMMAND, TPMS_AUTH_RESPONSE, TPMT_HA, TPMT_PUBLIC, TPMT_SYM_DEF,
    TPM_ALG_ID, TPM_CC, TPM_HANDLE, TPM_HT, TPM_RC, TPM_RH, TPM_SE, TPM_ST,
};
use std::any::Any;
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The command element that a format-1 response code blames.
///
/// TPM 2.0 Part 1, §39.4: a format-1 code carries a 4-bit number in bits 8-11 alongside the
/// error itself. `RC_P` (bit 6) makes that number a parameter index; otherwise it is a handle
/// index, or a session index when `RC_S` (bit 11) is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RcIndex {
    /// A format-0 code, or a format-1 code that blames nothing in particular.
    #[default]
    Unspecified,
    /// Index of the command handle at fault.
    Handle(u32),
    /// Index of the command parameter at fault, counting from 1.
    Parameter(u32),
    /// Index of the authorization session at fault.
    Session(u32),
}

impl std::fmt::Display for RcIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RcIndex::Unspecified => write!(f, "no particular command element"),
            RcIndex::Handle(index) => write!(f, "handle {}", index),
            RcIndex::Parameter(index) => write!(f, "parameter {}", index),
            RcIndex::Session(index) => write!(f, "session {}", index),
        }
    }
}

/// A TPM response code as it arrives on the wire, split into the error it names and the command
/// element it blames.
///
/// Response codes come in two shapes (TPM 2.0 Part 1, §39.4). A format-0 code is a bare value.
/// A format-1 code — bit 7 set — folds a parameter, handle or session index into bits 6 and
/// 8-11, so what arrives is not a member of the `TPM_RC` enumeration at all: `TPM_RC_SIZE`
/// blamed on the first parameter arrives as `0x1D5`, not `0x095`. Those bits have to be
/// stripped before the value means anything, which is why a raw response code must never be fed
/// straight to `TPM_RC::try_from` — most of the errors a TPM actually returns are absent from
/// the generated match and would decode as "Invalid enum value", discarding the real error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCode {
    raw: u32,
    code: TPM_RC,
    index: RcIndex,
}

impl ResponseCode {
    /// Bit 7, set on a format-1 code.
    const RC_FMT1: u32 = 0x080;
    /// Bit 6 of a format-1 code: the number field is a parameter index.
    const RC_P: u32 = 0x040;
    /// Bit 11 of a format-1 code: the number field is a session index, not a handle index.
    const RC_S: u32 = 0x800;
    /// Bits 8-11 of a format-1 code: the parameter, handle or session number.
    const RC_N_MASK: u32 = 0xF00;
    const RC_N_SHIFT: u32 = 8;
    /// What survives masking a format-1 code: the F bit and the 6-bit error number.
    const FMT1_ERROR_MASK: u32 = 0x0BF;
    /// What survives masking a format-0 code: the error number, the V bit and the S bit.
    const FMT0_ERROR_MASK: u32 = 0x97F;

    /// Decode a response code straight off the wire.
    pub fn decode(raw: u32) -> Self {
        if Self::is_comm_medium_error(raw) {
            // Not a TPM response code at all — the TSS communication layer generated it, so
            // none of the TPM's bit assignments apply and there is nothing to strip.
            return Self {
                raw,
                code: TPM_RC(raw),
                index: RcIndex::Unspecified,
            };
        }

        if raw & Self::RC_FMT1 == 0 {
            return Self {
                raw,
                code: TPM_RC(raw & Self::FMT0_ERROR_MASK),
                index: RcIndex::Unspecified,
            };
        }

        let number = (raw & Self::RC_N_MASK) >> Self::RC_N_SHIFT;
        let index = if raw & Self::RC_P != 0 {
            if number == 0 {
                RcIndex::Unspecified
            } else {
                RcIndex::Parameter(number)
            }
        } else if raw & Self::RC_S != 0 {
            // The RC_S marker occupies the top bit of the number field; the session number is
            // what is left of it.
            RcIndex::Session(number & 0x7)
        } else if number == 0 {
            RcIndex::Unspecified
        } else {
            RcIndex::Handle(number)
        };

        Self {
            raw,
            code: TPM_RC(raw & Self::FMT1_ERROR_MASK),
            index,
        }
    }

    /// Whether the response code was generated by the TSS.Rust implementation rather than by
    /// the TPM.
    fn is_comm_medium_error(raw: u32) -> bool {
        raw & 0xFFFF0000 == 0x80280000
    }

    /// The code exactly as it arrived, index bits included.
    pub fn raw(&self) -> u32 {
        self.raw
    }

    /// The error itself, with any format-1 index bits masked off.
    pub fn code(&self) -> TPM_RC {
        self.code
    }

    /// The command element the TPM blamed for the error.
    pub fn index(&self) -> RcIndex {
        self.index
    }

    /// Whether the TPM reported success.
    pub fn is_success(&self) -> bool {
        self.code == TPM_RC::SUCCESS
    }
}

impl std::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.index {
            RcIndex::Unspecified => write!(f, "raw response code 0x{:03X}", self.raw),
            index => write!(f, "raw response code 0x{:03X}, {}", self.raw, index),
        }
    }
}

/// A TPM error with associated command and context information
#[derive(Debug, Clone)]
pub struct TpmCommandError {
    /// Response code returned by the TPM, with any format-1 index bits masked off
    pub response_code: TPM_RC,
    /// The response code exactly as it arrived, index bits included
    pub raw_response_code: u32,
    /// The command element the TPM blamed, for a format-1 response code
    pub index: RcIndex,
    /// Command code that triggered the error
    pub command_code: TPM_CC,
    /// Description of the error
    pub message: String,
}

impl TpmCommandError {
    /// The error for a command the TPM answered with a failure code.
    fn from_response(command_code: TPM_CC, response: ResponseCode) -> Self {
        TpmCommandError {
            response_code: response.code(),
            raw_response_code: response.raw(),
            index: response.index(),
            command_code,
            message: response.to_string(),
        }
    }
}

impl std::fmt::Display for TpmCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TPM command {} failed with TPM_RC::{}: {}",
            self.command_code, self.response_code, self.message
        )
    }
}

impl std::error::Error for TpmCommandError {}

impl From<TpmCommandError> for TpmError {
    fn from(err: TpmCommandError) -> Self {
        TpmError::GenericError(err.to_string())
    }
}

/// Base implementation for TPM operations
pub struct Tpm2 {
    /// The TPM device used for communication
    device: Box<dyn TpmDevice>,

    /// The crypto backend used for the host-side work a TPM session requires: deriving session
    /// keys, computing command parameter hashes, and encrypting command parameters.
    ///
    /// This is held rather than passed per call because the generated command methods dispatch
    /// through `&mut self` and have no parameter to carry it.
    crypto: CryptoProvider,

    /// Response code returned by the last executed command
    last_response_code: TPM_RC,

    /// Error object (may be None) generated during the last TPM command execution
    last_error: Option<TpmCommandError>,

    /// TPM sessions associated with the next command
    sessions: Option<Vec<Session>>,

    /// Controls whether exceptions are enabled
    exceptions_enabled: bool,

    /// Suppresses exceptions in response to the next command failure, when exceptions are enabled
    errors_allowed: bool,

    /// Command code for the current operation (for error reporting)
    current_cmd_code: Option<TPM_CC>,

    /// Session tag for the current operation
    current_session_tag: Option<TPM_ST>,

    /// Handle for pending TPM commands
    pending_command: Option<TPM_CC>,

    /// Input handles for current command
    in_handles: Vec<TPM_HANDLE>,

    /// How many of `in_handles` the current command authorizes, which is not always all of them:
    /// `TPM2_Duplicate` names a new parent it does not authorize, `TPM2_PolicyNV` an NV index and
    /// a policy session it does not authorize. Session *i* authorizes handle *i* only while *i*
    /// is below this count (TPM 2.0 Part 1, §19.6.4), and both the command and the response HMAC
    /// have to agree on that or they fold in different authValues.
    num_auth_handles: u16,

    /// Auth value for objects
    object_in_auth: Vec<u8>,

    /// Name for objects
    object_in_name: Vec<u8>,

    /// The public area the current command supplies for the object it creates, for the commands
    /// that take one as an input rather than returning it (`TPM2_Load`, `TPM2_LoadExternal`).
    /// Kept so that the Name the TPM reports for the new object can be checked against it.
    command_object_public: Option<TPMT_PUBLIC>,

    /// Admin authorization handles with auth values
    admin_platform: TPM_HANDLE,
    admin_owner: TPM_HANDLE,
    admin_endorsement: TPM_HANDLE,
    admin_lockout: TPM_HANDLE,

    /// CpHash for parameter encryption
    cp_hash: Option<TPMT_HA>,

    /// Command audit hash
    command_audit_hash: TPMT_HA,

    /// Audit command flag
    audit_command: bool,

    /// Audit CpHash
    audit_cp_hash: TPMT_HA,

    /// Encryption session
    enc_session: Option<Session>,

    /// Decryption session
    dec_session: Option<Session>,

    /// Nonces for TPM parameter encryption/decryption
    nonce_tpm_dec: Vec<u8>,
    nonce_tpm_enc: Vec<u8>,

    /// Command buffer for last command
    last_command_buf: Vec<u8>,

    /// Last command's serialized parameters (before handles)
    last_cmd_params: Vec<u8>,

    /// Sessions updated after the last command (preserved for continueSession)
    completed_sessions: Option<Vec<Session>>,
}

impl Tpm2 {
    /// Creates a new Tpm2 that performs its host-side crypto with `crypto`.
    pub fn new(device: Box<dyn TpmDevice>, crypto: CryptoProvider) -> Self {
        Tpm2 {
            device,
            crypto,
            last_response_code: TPM_RC::SUCCESS,
            last_error: None,
            sessions: None,
            exceptions_enabled: false,
            errors_allowed: true,
            current_cmd_code: None,
            current_session_tag: None,
            pending_command: None,
            in_handles: Vec::new(),
            num_auth_handles: 0,
            object_in_auth: Vec::new(),
            object_in_name: Vec::new(),
            command_object_public: None,
            admin_platform: TPM_HANDLE::new(0),
            admin_owner: TPM_HANDLE::new(0),
            admin_endorsement: TPM_HANDLE::new(0),
            admin_lockout: TPM_HANDLE::new(0),
            cp_hash: None,
            command_audit_hash: TPMT_HA::default(),
            audit_command: false,
            audit_cp_hash: TPMT_HA::default(),
            enc_session: None,
            dec_session: None,
            nonce_tpm_dec: Vec::new(),
            nonce_tpm_enc: Vec::new(),
            last_command_buf: Vec::new(),
            last_cmd_params: Vec::new(),
            completed_sessions: None,
        }
    }

    /// Creates a new Tpm2 that performs its host-side crypto with the built-in software backend.
    #[cfg(feature = "software-crypto")]
    pub fn with_software_crypto(device: Box<dyn TpmDevice>) -> Self {
        Self::new(device, crate::crypto::software_provider::SOFTWARE_PROVIDER)
    }

    /// The crypto backend this instance was built with.
    ///
    /// Callers that need to compute a policy digest or a key name alongside a live TPM can pass
    /// this to the corresponding `Crypto` entry point, so both agree on one backend.
    pub fn crypto(&self) -> &CryptoProvider {
        &self.crypto
    }

    /// How many times [`Tpm2::dispatch`] resends a command the TPM answered with `TPM_RC_RETRY`
    /// before giving up on it.
    ///
    /// Public because [`Tpm2::dispatch`] documents its own behaviour in terms of it: a caller
    /// budgeting for the worst case a command can cost needs the bound, not a promise that one
    /// exists.
    pub const MAX_RETRIES: u32 = 8;

    /// How long to wait before resending a command the TPM answered with `TPM_RC_RETRY`. It
    /// doubles on each further resend, up to [`Tpm2::RETRY_MAX_DELAY`], so the whole sequence
    /// costs well under a second rather than the flat second per attempt it used to.
    const RETRY_INITIAL_DELAY: Duration = Duration::from_millis(2);
    const RETRY_MAX_DELAY: Duration = Duration::from_millis(200);

    /// Send a TPM command to the underlying TPM device.
    ///
    /// `TPM_RC_RETRY` means the TPM was busy and did not act on the command, so the command is
    /// resent — up to [`Tpm2::MAX_RETRIES`] times, after which a TPM that never stops saying
    /// "retry" produces an error instead of an unbounded loop.
    pub fn dispatch<R: ReqStructure + 'static, S: RespStructure + 'static>(
        &mut self,
        cmd_code: TPM_CC,
        req: R,
        resp: &mut S,
    ) -> Result<(), TpmError> {
        let mut retries = 0u32;
        let mut delay = Self::RETRY_INITIAL_DELAY;

        loop {
            let dispatched = match self.dispatch_command(cmd_code, &req) {
                Ok(v) => v,
                Err(e) => {
                    self.clear_invocation_state();
                    return Err(e);
                }
            };

            if !dispatched {
                // Nothing was sent to the TPM: this invocation only computed a cpHash for the
                // caller, and there is no response to process.
                return Ok(());
            }

            match self.process_response(cmd_code, resp) {
                Ok(true) => return Ok(()),
                // TPM_RC_RETRY. The TPM did not act on the command, so resending it is both safe
                // and the only way to make progress. `process_response` has cleared the
                // invocation state, without which `dispatch_command` would refuse to run again.
                Ok(false) => {}
                Err(e) => {
                    self.clear_invocation_state();
                    return Err(e);
                }
            }

            retries += 1;
            if retries > Self::MAX_RETRIES {
                self.clear_invocation_state();
                self.sessions = None;
                return Err(TpmError::GenericError(format!(
                    "TPM answered {} with TPM_RC::RETRY {} times running; giving up",
                    cmd_code,
                    Self::MAX_RETRIES + 1
                )));
            }

            std::thread::sleep(delay);
            delay = (delay * 2).min(Self::RETRY_MAX_DELAY);
        }
    }

    /// Internal method to dispatch a command to the TPM
    pub fn dispatch_command<R: ReqStructure + 'static>(
        &mut self,
        cmd_code: TPM_CC,
        req: &R,
    ) -> Result<(bool), TpmError> {
        if self.current_cmd_code.is_some() {
            return Err(TpmError::GenericError(
                "Pending async command must be completed before issuing the next command."
                    .to_string(),
            ));
        }

        if self.audit_command && self.command_audit_hash.hashAlg == TPM_ALG_ID::NULL {
            return Err(TpmError::GenericError(
                "Command audit is not enabled".to_string(),
            ));
        }

        self.current_cmd_code = Some(cmd_code);

        // Determine session tag based on whether we need authorization
        let num_auth_handles = req.num_auth_handles();
        self.num_auth_handles = num_auth_handles;
        let has_sessions = num_auth_handles > 0 || self.sessions.is_some();
        self.current_session_tag = if has_sessions {
            Some(TPM_ST::SESSIONS)
        } else {
            Some(TPM_ST::NO_SESSIONS)
        };

        let mut cmd_buf = TpmBuffer::new(None);

        // Create command buffer header
        cmd_buf.writeShort(self.current_session_tag.unwrap().get_value());
        cmd_buf.writeInt(0); // to be filled in later
        cmd_buf.writeInt(cmd_code.get_value());

        // Marshal handles
        self.in_handles = req.get_handles();
        // Set auth values for well-known admin handles (OWNER, LOCKOUT, ENDORSEMENT, PLATFORM)
        for h in self.in_handles.iter_mut() {
            Self::set_rh_auth_value_static(
                h,
                &self.admin_owner,
                &self.admin_endorsement,
                &self.admin_platform,
                &self.admin_lockout,
            );
        }
        for handle in self.in_handles.iter() {
            handle.toTpm(&mut cmd_buf)?;
        }

        // Marshal command parameters to a separate buffer
        let mut param_buf = TpmBuffer::new(None);
        req.toTpm(&mut param_buf)?;
        param_buf.trim();
        self.last_cmd_params = param_buf.buffer().clone();

        // The public area of the object this command loads, for the commands that take one as an
        // input. It does not come back in the response, so it is kept here for the Name check in
        // `update_resp_handle`.
        self.command_object_public = Self::request_object_public(cmd_code, req);

        // Process authorization sessions if present
        let mut cp_hash_data = Vec::new();

        if has_sessions {
            // We do not know the size of the authorization area yet.
            // Remember the place to marshal it, ...
            let auth_size_pos = cmd_buf.current_pos();
            // ... and marshal a placeholder 0 value for now.
            cmd_buf.writeInt(0);

            // If not all required sessions were provided explicitly, create the necessary
            // number of password sessions with auth values from the corresponding TPM_HANDLE objects.
            if let Some(ref mut sessions) = self.sessions {
                // Ensure we have enough sessions
                if sessions.len() < num_auth_handles as usize {
                    for _ in sessions.len()..(num_auth_handles as usize) {
                        sessions.push(Session::pw(None));
                    }
                }

                // Roll nonces
                self.roll_nonces()?;

                // Prepare parameter encryption sessions
                self.prepare_param_encryption_sessions();

                // Do parameter encryption if needed
                self.do_param_encryption(req, &mut param_buf, 0, true)?;

                // Process authorization sessions and get cpHash data
                cp_hash_data = self.process_auth_sessions(
                    &mut cmd_buf,
                    cmd_code,
                    num_auth_handles,
                    param_buf.buffer(),
                )?;
            } else {
                // Create all password sessions with auth from the corresponding handles
                let mut new_sessions = Vec::with_capacity(num_auth_handles as usize);
                for i in 0..num_auth_handles as usize {
                    let auth = if i < self.in_handles.len() {
                        Some(self.in_handles[i].auth_value.clone())
                    } else {
                        None
                    };
                    new_sessions.push(Session::pw(auth));
                }

                // Marshal sessions to command buffer
                for sess in new_sessions.iter() {
                    sess.sess_in.toTpm(&mut cmd_buf)?;
                }

                self.sessions = Some(new_sessions);
            }

            // Update the auth area size
            cmd_buf.write_num_at_pos(
                (cmd_buf.current_pos() - auth_size_pos - 4) as u64,
                auth_size_pos,
                4,
            );
        }

        // Write marshaled command params to the command buffer
        cmd_buf.writeByteBuf(param_buf.buffer());

        // Fill in command buffer size in the command header
        cmd_buf.write_num_at_pos(cmd_buf.current_pos() as u64, 2, 4);
        cmd_buf.trim();

        // Handle CpHash and Audit processing
        if self.cp_hash.is_some() || self.audit_command {
            if cp_hash_data.is_empty() {
                cp_hash_data = self.get_cp_hash_data(cmd_code, param_buf.buffer())?;
            }

            if let Some(ref mut cp_hash) = self.cp_hash {
                cp_hash.digest = Crypto::hash(&self.crypto, cp_hash.hashAlg, &cp_hash_data)?;
                self.clear_invocation_state();
                self.sessions = None;
                self.cp_hash = None;
                return Ok(false);
            }

            if self.audit_command {
                self.audit_cp_hash.digest =
                    Crypto::hash(&self.crypto, self.command_audit_hash.hashAlg, &cp_hash_data)?;
            }
        }

        // Dispatch command to the device
        self.last_command_buf = cmd_buf.trim().to_vec();
        self.device.dispatch_command(&self.last_command_buf)?;

        // Update request handles based on command
        self.update_request_handles(cmd_code)?;

        // Set pending command
        self.pending_command = Some(cmd_code);

        Ok(true)
    }

    /// Process the TPM response and update the response structure
    ///
    /// Returns `true` when the command completed, and `false` when the TPM answered
    /// `TPM_RC_RETRY` and the command has to be resent — in which case the invocation state is
    /// cleared so that the caller can do exactly that.
    pub fn process_response<T: RespStructure + 'static>(
        &mut self,
        cmd_code: TPM_CC,
        resp_struct: &mut T,
    ) -> Result<(bool), TpmError> {
        if self.pending_command.is_none() {
            return Err(TpmError::GenericError(
                "Async command completion with no outstanding command".to_string(),
            ));
        }

        if self.pending_command.unwrap() != cmd_code {
            return Err(TpmError::GenericError(
                "Async command completion does not match command being processed".to_string(),
            ));
        }

        if self.audit_command && self.command_audit_hash.hashAlg == TPM_ALG_ID::NULL {
            return Err(TpmError::GenericError(
                "Command audit is not enabled".to_string(),
            ));
        }

        self.pending_command = None;

        // Get response from the TPM device
        let raw_resp_buf = self.device.get_response()?;

        if raw_resp_buf.len() < 10 {
            return Err(TpmError::GenericError(format!(
                "Too short TPM response of {} B received",
                raw_resp_buf.len()
            )));
        }

        let mut resp_buf = TpmBuffer::from(&raw_resp_buf);

        // Read the response header
        let resp_tag = TPM_ST::try_from(resp_buf.readShort())?;
        let resp_size = resp_buf.readInt();
        // The response code is decoded rather than converted. A format-1 code carries a
        // parameter, handle or session index in bits that belong to no TPM_RC enumerator, so
        // `TPM_RC::try_from` would reject the majority of the errors a TPM actually returns and
        // report "Invalid enum value" in place of the real one.
        let resp_code = ResponseCode::decode(resp_buf.readInt());
        self.last_response_code = resp_code.code();
        self.last_error = None;

        let act_resp_size = resp_buf.size();
        if resp_size as usize != act_resp_size {
            return Err(TpmError::GenericError(format!(
                "Inconsistent TPM response buffer: {} B reported, {} B received",
                resp_size, act_resp_size
            )));
        }

        if resp_code.code() == TPM_RC::RETRY {
            // The TPM was busy and did not act on the command. Clear the invocation state so
            // that the command can be dispatched again: leaving `current_cmd_code` set made
            // every resend fail with "Pending async command must be completed", which meant the
            // retry path could never succeed.
            self.clear_invocation_state();
            return Ok(false);
        }

        // Figure out our reaction to the received response. This logic depends on:
        //   errors_allowed - no exception, regardless of success or failure

        // Store a copy of audit command flag before clearing invocation state
        let audit_command = self.audit_command;

        // Handle errors and clean up invocation state
        if !resp_code.is_success() {
            self.clear_invocation_state();
            self.sessions = None;

            let error = TpmCommandError::from_response(cmd_code, resp_code);
            self.last_error = Some(error.clone());
            return Err(error.into());
        }

        // A check for the session tag consistency across the command invocation
        let sess_tag = self.current_session_tag.unwrap_or(TPM_ST::NULL);
        if resp_tag != sess_tag {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(TpmError::GenericError(
                "Wrong response session tag".to_string(),
            ));
        }

        //
        // The command succeeded, so we can process the response buffer
        //

        // Get the handles if any
        if resp_struct.num_handles() > 0 {
            let handle_val = resp_buf.readInt();
            resp_struct.set_handle(&TPM_HANDLE::new(handle_val));
        }

        let resp_params_pos: usize;
        let resp_params_size: usize;
        let mut rp_ready = false;

        // If there are no sessions then response parameters take up the remaining part
        // of the response buffer. Otherwise the response parameters area is preceded with
        // its size, and followed by the session area.
        if sess_tag == TPM_ST::SESSIONS {
            resp_params_size = resp_buf.readInt() as usize;
            resp_params_pos = resp_buf.current_pos();

            // Process response sessions, including verification of response HMACs
            rp_ready = match self.process_resp_sessions(
                &mut resp_buf,
                cmd_code,
                resp_params_pos,
                resp_params_size,
            ) {
                Ok(ready) => ready,
                Err(e) => {
                    self.clear_invocation_state();
                    self.sessions = None;
                    return Err(e);
                }
            };
        } else {
            resp_params_pos = resp_buf.current_pos();
            resp_params_size = resp_buf.size() - resp_params_pos;
        }

        // Update enc_session/dec_session nonces from the processed sessions
        if let Some(ref sessions) = self.sessions {
            if let Some(ref mut enc) = self.enc_session {
                for s in sessions.iter() {
                    if s.sess_in.sessionHandle.handle == enc.sess_in.sessionHandle.handle {
                        enc.sess_out.nonce = s.sess_out.nonce.clone();
                        enc.sess_in.nonce = s.sess_in.nonce.clone();
                        break;
                    }
                }
            }
            if let Some(ref mut dec) = self.dec_session {
                for s in sessions.iter() {
                    if s.sess_in.sessionHandle.handle == dec.sess_in.sessionHandle.handle {
                        dec.sess_out.nonce = s.sess_out.nonce.clone();
                        dec.sess_in.nonce = s.sess_in.nonce.clone();
                        break;
                    }
                }
            }
        }

        // Handle audit processing
        if audit_command {
            let rp_hash = self.get_rp_hash(
                self.command_audit_hash.hashAlg,
                &mut resp_buf,
                cmd_code,
                resp_params_pos,
                resp_params_size,
                rp_ready,
            )?;

            // Extend audit digest: CommandAuditHash = H(CommandAuditHash || cpHash || rpHash)
            let hash_alg = self.command_audit_hash.hashAlg;
            let mut extend_data = Vec::new();
            extend_data.extend_from_slice(&self.command_audit_hash.digest);
            extend_data.extend_from_slice(&self.audit_cp_hash.digest);
            extend_data.extend_from_slice(&rp_hash);
            if let Ok(new_digest) = Crypto::hash(&self.crypto, hash_alg, &extend_data) {
                self.command_audit_hash.digest = new_digest;
            }
        }

        // Parameter decryption (if necessary)
        if let Err(e) = self.do_param_encryption(resp_struct, &mut resp_buf, resp_params_pos, false)
        {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(e);
        }
        // Clear encryption session state after use
        self.enc_session = None;
        self.dec_session = None;

        // Reset position to start of parameters area and unmarshall
        resp_buf.set_current_pos(resp_params_pos);
        resp_struct.initFromTpm(&mut resp_buf)?;
        resp_buf.check_status()?;

        // Validate that we read the exact number of bytes expected
        if resp_buf.current_pos() != resp_params_pos + resp_params_size {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(TpmError::GenericError(
                "Bad response parameters area".to_string(),
            ));
        }

        // Update response handle with name and auth value
        if let Err(e) = self.update_resp_handle(cmd_code, resp_struct) {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(e);
        }

        // Complete post-command handle updates (e.g., HierarchyChangeAuth auth tracking)
        if let Err(e) = self.complete_update_request_handles(cmd_code) {
            self.clear_invocation_state();
            self.sessions = None;
            return Err(e);
        }

        // Offer the sessions back for reuse -- except any the TPM reported closed, which is
        // what the comment here has always said and what the code did not do. A response with
        // `continueSession` CLEAR means the TPM flushed the session when the command completed
        // (TPM 2.0 Part 2, `TPMA_SESSION.continueSession`), whether because the caller asked for
        // a one-shot session or because the TPM ended it. Its handle is dead and the TPM may
        // hand the same one to an unrelated session later, so handing the session object back
        // through `last_session()` would invite the caller to authorize a command with it.
        // Dropping it here also wipes its session key, by `Drop for Session`.
        self.completed_sessions = self
            .sessions
            .take()
            .map(|sessions| {
                sessions
                    .into_iter()
                    .filter(|session| !session.is_terminated())
                    .collect::<Vec<_>>()
            })
            .filter(|sessions| !sessions.is_empty());
        self.clear_invocation_state();

        Ok(true)
    }
}

impl Tpm2 {
    pub fn last_response_code(&self) -> TPM_RC {
        self.last_response_code
    }

    pub fn last_error(&self) -> Option<TpmCommandError> {
        self.last_error.clone()
    }

    pub fn allow_errors(&mut self) -> &mut Self {
        self.errors_allowed = true;
        self
    }

    pub fn enable_exceptions(&mut self, enable: bool) {
        self.exceptions_enabled = enable;
        self.errors_allowed = !enable;
    }

    pub fn with_session(&mut self, session: Session) -> &mut Self {
        self.sessions = Some(vec![session]);
        self
    }

    pub fn with_sessions(&mut self, sessions: Vec<Session>) -> &mut Self {
        self.sessions = Some(sessions);
        self
    }

    /// Get the updated session after the last command completed.
    /// This is needed when reusing HMAC/policy sessions across commands,
    /// since the TPM updates nonces after each command.
    ///
    /// Sessions the TPM reported as closed (`continueSession` CLEAR in the response) are not
    /// included: their contexts are gone, so there is nothing to reuse. That means the sessions
    /// here do not necessarily line up one for one with the ones handed to
    /// [`Tpm2::with_sessions`] — match on `sess_in.sessionHandle` rather than on position.
    pub fn last_sessions(&self) -> Option<&Vec<Session>> {
        self.completed_sessions.as_ref()
    }

    /// Get the first updated session from the last completed command.
    /// Convenience method for the common single-session case.
    ///
    /// `None` if the TPM closed the session, so a session that has been flushed is never handed
    /// back for another command.
    pub fn last_session(&self) -> Option<Session> {
        self.completed_sessions
            .as_ref()
            .and_then(|s| s.first().cloned())
    }

    pub fn connect(&mut self) -> Result<(), TpmError> {
        self.device.connect()?;
        self.last_response_code = TPM_RC::SUCCESS;
        self.last_error = None;
        Ok(())
    }

    pub fn close(&mut self) {
        self.device.close();
    }
}

/// High-level convenience methods for session management and common patterns.
impl Tpm2 {
    /// Start a simple HMAC or policy auth session (no salt, no binding).
    pub fn start_auth_session(
        &mut self,
        session_type: TPM_SE,
        auth_hash: TPM_ALG_ID,
    ) -> Result<Session, TpmError> {
        self.start_auth_session_full(
            session_type,
            auth_hash,
            TPMA_SESSION::continueSession,
            TPMT_SYM_DEF::default(),
        )
    }

    /// Start an auth session with explicit attributes and symmetric definition.
    ///
    /// The session is neither salted nor bound, so it has no secret key material. It cannot be
    /// used for parameter encryption — see [`Tpm2::start_salted_auth_session`] for that.
    pub fn start_auth_session_full(
        &mut self,
        session_type: TPM_SE,
        auth_hash: TPM_ALG_ID,
        attributes: TPMA_SESSION,
        symmetric: TPMT_SYM_DEF,
    ) -> Result<Session, TpmError> {
        let null_handle = TPM_HANDLE::new(TPM_RH::NULL.get_value());

        self.start_auth_session_ex(
            None, // no salt key
            &null_handle,
            session_type,
            auth_hash,
            attributes,
            symmetric,
        )
    }

    /// Start a session salted to `salt_key`, the straightforward way to get a session that can
    /// carry parameter encryption.
    ///
    /// `salt_key_public` must be the public area of `salt_key` as a [`TrustedPublic`] — see
    /// [`Tpm2::start_auth_session_ex`] for why this client will not fetch it for you.
    pub fn start_salted_auth_session(
        &mut self,
        salt_key: &TPM_HANDLE,
        salt_key_public: &TrustedPublic,
        session_type: TPM_SE,
        auth_hash: TPM_ALG_ID,
        attributes: TPMA_SESSION,
        symmetric: TPMT_SYM_DEF,
    ) -> Result<Session, TpmError> {
        let null_handle = TPM_HANDLE::new(TPM_RH::NULL.get_value());

        self.start_auth_session_ex(
            Some((salt_key, salt_key_public)),
            &null_handle,
            session_type,
            auth_hash,
            attributes,
            symmetric,
        )
    }

    /// Start an auth session with full control over salting and binding.
    ///
    /// # Salting
    ///
    /// Pass `Some((handle, public))` to salt the session. The salt is generated here, at the
    /// digest size of the salt key's `nameAlg` — the size the TPM requires — and encrypted to
    /// `public`, which the caller supplies as a
    /// [`TrustedPublic`], having already decided that this public area is the one it means.
    ///
    /// This function deliberately does **not** call `TPM2_ReadPublic` on the salt key. Doing so
    /// would encrypt the salt to whatever public area came back over the very channel the salt
    /// exists to protect: an adversary in the middle answers the `ReadPublic` with a key it
    /// holds the private half of, learns the salt, derives the session key, and from then on
    /// produces and verifies both command and response HMACs. Nothing downstream would notice,
    /// because every check would use the adversary's key. The trust decision has to be made from
    /// something other than the channel, so it is the caller's to make.
    ///
    /// Note also what salting does *not* buy you. It gives the session key an input an
    /// eavesdropper does not have, which is what parameter encryption and HMAC integrity need.
    /// It does not authenticate the peer. If the pinned Name came from the same untrusted
    /// channel — or if [`TrustedPublic::assume_trusted`] was used on a public area read over
    /// it — the session is salted and still unauthenticated.
    // The parameter list mirrors the TPM2_StartAuthSession command parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn start_auth_session_ex(
        &mut self,
        salt_key: Option<(&TPM_HANDLE, &TrustedPublic)>,
        bind: &TPM_HANDLE,
        session_type: TPM_SE,
        auth_hash: TPM_ALG_ID,
        attributes: TPMA_SESSION,
        symmetric: TPMT_SYM_DEF,
    ) -> Result<Session, TpmError> {
        let nonce_size = Crypto::digest_size_checked(auth_hash)?;
        let nonce_caller = Crypto::get_random(&self.crypto, nonce_size)?;

        let null_handle = TPM_HANDLE::new(TPM_RH::NULL.get_value());
        let (tpm_key, salt, encrypted_salt) = match salt_key {
            Some((handle, trusted)) => {
                // The salt must be exactly the digest size of the salt key's *nameAlg*, not of
                // the session hash. The TPM recovers the salt with OAEP under the key's nameAlg
                // and then rejects anything whose length does not match that digest size
                // (TPM_RC_VALUE on `encryptedSalt`), so a SHA-256 session salted to a SHA-1 key
                // fails outright if the session hash is used to size it.
                let salt = Zeroizing::new(Crypto::get_random(
                    &self.crypto,
                    Crypto::digest_size_checked(trusted.public().nameAlg)?,
                )?);
                let encrypted = trusted.public().encrypt_session_salt(&self.crypto, &salt)?;
                (handle.clone(), salt, encrypted)
            }
            None => (null_handle, Zeroizing::new(Vec::new()), Vec::new()),
        };

        let resp = self.StartAuthSession(
            &tpm_key,
            bind,
            &nonce_caller,
            &encrypted_salt,
            session_type,
            &symmetric,
            auth_hash,
        )?;

        // From here on the TPM holds a loaded session, so every exit has to account for it.
        // `Session::from_tpm_response` still has two ways to fail — `calc_session_key` rejects a
        // hash algorithm with no digest size, and the constructor refuses parameter encryption
        // on a session with no secret key material — and both leave the session occupying one of
        // the two or three slots a TPM typically has for loaded sessions, with no handle left
        // anywhere for the caller to flush. That refusal is not hypothetical: the sample in
        // `examples/tpm_samples.rs` provokes it deliberately on every run and then loads two
        // more sessions.
        let handle = resp.handle;
        match Session::from_tpm_response(
            &self.crypto,
            handle.clone(),
            session_type,
            auth_hash,
            nonce_caller,
            resp.nonceTPM,
            attributes,
            symmetric,
            &salt,
            bind,
        ) {
            Ok(session) => Ok(session),
            Err(err) => {
                self.flush_orphaned_handle(&handle);
                Err(err)
            }
        }
    }

    /// Set a session on this Tpm2 for the next command.
    pub fn set_sessions(&mut self, sessions: Vec<Session>) {
        self.sessions = Some(sessions);
    }
}

impl Tpm2 {
    // Additional helper methods to support the dispatch_command and process_response implementations

    /// Roll nonces for all non-PWAP sessions
    fn roll_nonces(&mut self) -> Result<(), TpmError> {
        if let Some(ref mut sessions) = self.sessions {
            for session in sessions.iter_mut() {
                if !session.is_pwap() {
                    let nonce_size = session.sess_out.nonce.len();
                    session.sess_in.nonce = Crypto::get_random(&self.crypto, nonce_size.max(16))?;
                }
            }
        }
        Ok(())
    }

    /// Clear the current invocation state
    fn clear_invocation_state(&mut self) {
        self.current_cmd_code = None;
        self.current_session_tag = None;
        self.command_object_public = None;
        self.num_auth_handles = 0;
        // Clear other command-specific state
    }

    /// Flush an object or session the TPM has loaded but this client is about to lose the handle
    /// to, on a path that is failing for some other reason.
    ///
    /// A TPM has room for only a handful of loaded sessions and transient objects, and nothing
    /// reclaims one whose handle no caller ever sees: it occupies its slot until the TPM is
    /// reset. Two paths here can produce exactly that — a `TPM2_StartAuthSession` whose response
    /// this client then refuses to build a `Session` from, and a `TPM2_Load` or
    /// `TPM2_CreatePrimary` whose reported Name fails the consistency check — and in both the
    /// command itself succeeded, so the TPM has already done the loading.
    ///
    /// The flush is best effort. It is issued for its side effect on the TPM, and its outcome
    /// must not displace the failure that is on its way to the caller, so the invocation state
    /// it needs is cleared first and the error reporting it would otherwise overwrite is put
    /// back afterwards.
    fn flush_orphaned_handle(&mut self, handle: &TPM_HANDLE) {
        let response_code = self.last_response_code;
        let error = self.last_error.take();

        // `FlushContext` dispatches a command of its own, which refuses to run while another
        // command is still marked as in flight.
        self.clear_invocation_state();
        self.sessions = None;
        let _ = self.FlushContext(handle);

        self.last_response_code = response_code;
        self.last_error = error;
    }

    /// Set the auth value for an admin hierarchy handle.
    /// Use this when the TPM's hierarchy auth was set externally (e.g., recovering from a
    /// previous run that changed auth but failed to reset it).
    pub fn set_admin_auth(&mut self, hierarchy: TPM_RH, auth: &[u8]) {
        let val = hierarchy.get_value();
        if val == TPM_RH::OWNER.get_value() {
            self.admin_owner.set_auth(auth);
        } else if val == TPM_RH::ENDORSEMENT.get_value() {
            self.admin_endorsement.set_auth(auth);
        } else if val == TPM_RH::PLATFORM.get_value() {
            self.admin_platform.set_auth(auth);
        } else if val == TPM_RH::LOCKOUT.get_value() {
            self.admin_lockout.set_auth(auth);
        }
    }

    /// Set auth values for well-known admin handles (avoids borrow issues)
    fn set_rh_auth_value_static(
        h: &mut TPM_HANDLE,
        admin_owner: &TPM_HANDLE,
        admin_endorsement: &TPM_HANDLE,
        admin_platform: &TPM_HANDLE,
        admin_lockout: &TPM_HANDLE,
    ) {
        match h.handle {
            val if val == TPM_RH::OWNER.get_value() => h.set_auth(&admin_owner.auth_value),
            val if val == TPM_RH::ENDORSEMENT.get_value() => {
                h.set_auth(&admin_endorsement.auth_value)
            }
            val if val == TPM_RH::PLATFORM.get_value() => h.set_auth(&admin_platform.auth_value),
            val if val == TPM_RH::LOCKOUT.get_value() => h.set_auth(&admin_lockout.auth_value),
            _ => {} // No auth value change needed
        }
    }

    /// The handle whose authValue session `index` folds into its HMAC key, if any.
    ///
    /// A command's handle area starts with the handles it authorizes and may continue with
    /// handles it does not: `TPM2_Duplicate`'s `newParentHandle`, `TPM2_PolicyNV`'s `nvIndex`
    /// and `policySession`. Session *i* is the authorization for handle *i* only while *i* is
    /// below `num_auth_handles`; a session past that point authorizes nothing and folds in no
    /// authValue, whatever handle happens to sit at its index.
    ///
    /// The command HMAC and the response HMAC are keyed identically, so both sides call this.
    /// They used not to: the response side asked only whether index *i* named some handle, so a
    /// command with more handles than authorizations, driven with a session per handle, produced
    /// a response HMAC key with an authValue in it that the command's did not have. The
    /// verification then failed on a response that was perfectly correct.
    fn authorized_handle(
        handles: &[TPM_HANDLE],
        num_auth_handles: u16,
        index: usize,
    ) -> Option<&TPM_HANDLE> {
        if index < num_auth_handles as usize {
            handles.get(index)
        } else {
            None
        }
    }

    /// Get CpHash data for parameter encryption
    fn get_cp_hash_data(&self, cmd_code: TPM_CC, cmd_params: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut buf = TpmBuffer::new(None);
        buf.writeInt(cmd_code.get_value());

        for h in self.in_handles.iter() {
            let name = h.get_name()?;
            buf.writeByteBuf(&name);
        }

        buf.writeByteBuf(cmd_params);
        Ok(buf.buffer().clone())
    }

    /// Process authorization sessions for a command
    fn process_auth_sessions(
        &mut self,
        cmd_buf: &mut TpmBuffer,
        cmd_code: TPM_CC,
        num_auth_handles: u16,
        cmd_params: &[u8],
    ) -> Result<Vec<u8>, TpmError> {
        let mut needs_hmac = false;

        if let Some(ref sessions) = self.sessions {
            for session in sessions.iter() {
                if !session.is_pwap() {
                    needs_hmac = true;
                    break;
                }
            }
        }

        // Compute CpHash if needed for HMAC sessions
        let cp_hash_data = if needs_hmac {
            self.get_cp_hash_data(cmd_code, cmd_params)?
        } else {
            Vec::new()
        };

        if let Some(ref mut sessions) = self.sessions {
            for (i, session) in sessions.iter().enumerate() {
                let mut auth_cmd = TPMS_AUTH_COMMAND::default();

                // If it's a PWAP session, handling is simple
                if session.is_pwap() {
                    auth_cmd.sessionHandle = TPM_HANDLE::new(TPM_RH::PW.get_value());
                    auth_cmd.nonce = Vec::new();

                    if i < self.in_handles.len() {
                        auth_cmd.hmac = self.in_handles[i].auth_value.clone();
                    }

                    auth_cmd.sessionAttributes = TPMA_SESSION::continueSession;
                    auth_cmd.toTpm(cmd_buf)?;
                    continue;
                }

                // For non-PWAP sessions, we need more complex processing
                let h_copy =
                    Self::authorized_handle(&self.in_handles, num_auth_handles, i).cloned();

                auth_cmd.nonce = session.sess_in.nonce.clone();
                auth_cmd.sessionHandle = session.sess_in.sessionHandle.clone();
                auth_cmd.sessionAttributes = session.sess_in.sessionAttributes;

                // Mirrors the TPM's own dispatch rule (`SessionProcess.c`: `if (PWAP ||
                // isPasswordNeeded) CheckPWAuthSession else CheckSessionHMAC`). Note the order:
                // a policy session on which TPM2_PolicyPassword ran sends the authValue in the
                // clear, every other non-PWAP session sends a computed HMAC — including a policy
                // session that has run no PolicyAuthValue, which used to send an empty field and
                // so could not be salted or bound at all.
                if session.needs_password {
                    if i < self.in_handles.len() {
                        auth_cmd.hmac = self.in_handles[i].auth_value.clone();
                    }
                } else {
                    // Calculate HMAC based on CpHash
                    let cp_hash =
                        Crypto::hash(&self.crypto, session.get_hash_alg(), &cp_hash_data)?;
                    auth_cmd.hmac = session.get_auth_hmac(
                        &self.crypto,
                        cp_hash,
                        true,
                        &self.nonce_tpm_dec,
                        &self.nonce_tpm_enc,
                        h_copy.as_ref(),
                    )?;
                }

                auth_cmd.toTpm(cmd_buf)?;
            }
        }

        Ok(cp_hash_data)
    }

    /// Prepare parameter encryption sessions
    fn prepare_param_encryption_sessions(&mut self) {
        self.enc_session = None;
        self.dec_session = None;
        self.nonce_tpm_dec.clear();
        self.nonce_tpm_enc.clear();

        if let Some(ref sessions) = self.sessions {
            for session in sessions.iter() {
                if session.is_pwap() {
                    continue;
                }

                // Check for decrypt attribute
                if (session.sess_in.sessionAttributes.get_value()
                    & TPMA_SESSION::decrypt.get_value())
                    != 0
                {
                    self.dec_session = Some(session.clone());
                }

                // Check for encrypt attribute
                if (session.sess_in.sessionAttributes.get_value()
                    & TPMA_SESSION::encrypt.get_value())
                    != 0
                {
                    self.enc_session = Some(session.clone());
                }
            }

            // Store nonces for the first session to prevent tampering
            if let Some(ref sessions_vec) = self.sessions {
                if !sessions_vec.is_empty() {
                    let first_session = &sessions_vec[0];

                    // If first session is followed by decrypt session
                    if let Some(ref dec) = self.dec_session {
                        if dec.sess_in.sessionHandle.handle
                            != first_session.sess_in.sessionHandle.handle
                        {
                            self.nonce_tpm_dec = dec.sess_out.nonce.clone();
                        }
                    }

                    // If first session is followed by encrypt session (and it's not the decrypt session)
                    if let Some(ref enc) = self.enc_session {
                        if enc.sess_in.sessionHandle.handle
                            != first_session.sess_in.sessionHandle.handle
                            && (self.dec_session.is_none()
                                || enc.sess_in.sessionHandle.handle
                                    != self
                                        .dec_session
                                        .as_ref()
                                        .unwrap()
                                        .sess_in
                                        .sessionHandle
                                        .handle)
                        {
                            self.nonce_tpm_enc = enc.sess_out.nonce.clone();
                        }
                    }
                }
            }
        }
    }

    /// Process parameter encryption/decryption
    fn do_param_encryption<T: CmdStructure>(
        &self,
        cmd: &T,
        param_buf: &mut TpmBuffer,
        start_pos: usize,
        is_request: bool,
    ) -> Result<(), TpmError> {
        let xcrypt_sess = if is_request {
            if self.dec_session.is_none() {
                return Ok(());
            }
            self.dec_session.as_ref()
        } else {
            if self.enc_session.is_none() {
                return Ok(());
            }
            self.enc_session.as_ref()
        };

        let sess = xcrypt_sess.unwrap();
        let sei = cmd.sess_enc_info();
        if sei.size_len == 0 || sei.val_len == 0 {
            return Ok(());
        }

        let orig_cur_pos = param_buf.current_pos();
        param_buf.set_current_pos(start_pos);

        // Read the size of the first parameter (TPM2B prefix)
        let arr_size = param_buf.read_num(sei.size_len as usize) as usize;
        param_buf.check_status()?;
        let arr_pos = param_buf.current_pos();

        if arr_size == 0 {
            param_buf.set_current_pos(orig_cur_pos);
            return Ok(());
        }

        // Read the data to encrypt/decrypt
        let xcrypt_size = arr_size
            .checked_mul(sei.val_len as usize)
            .ok_or(TpmError::BufferUnderflow)?;
        let to_xcrypt = param_buf.readByteBuf(xcrypt_size);
        param_buf.check_status()?;

        // Perform encryption/decryption
        let result = sess.param_xcrypt(&self.crypto, &to_xcrypt, is_request)?;

        // Write the result back into the buffer
        param_buf.set_current_pos(arr_pos);
        param_buf.writeByteBuf(&result);

        param_buf.set_current_pos(orig_cur_pos);

        Ok(())
    }

    /// Get RP hash (response parameter hash)
    fn get_rp_hash(
        &self,
        hash_alg: TPM_ALG_ID,
        resp_buf: &mut TpmBuffer,
        cmd_code: TPM_CC,
        resp_params_pos: usize,
        resp_params_size: usize,
        rp_ready: bool,
    ) -> Result<Vec<u8>, TpmError> {
        let rp_header_size = 8;
        let rp_hash_data_pos = resp_params_pos - rp_header_size;

        if !rp_ready {
            // Create a continuous data area required by rpHash
            let orig_cur_pos = resp_buf.current_pos();
            resp_buf.set_current_pos(rp_hash_data_pos);
            resp_buf.writeInt(TPM_RC::SUCCESS.get_value());
            resp_buf.writeInt(cmd_code.get_value());
            resp_buf.set_current_pos(orig_cur_pos);
        }

        let data_to_hash = &resp_buf.buffer()
            [rp_hash_data_pos..(rp_hash_data_pos + rp_header_size + resp_params_size)];
        Crypto::hash(&self.crypto, hash_alg, data_to_hash)
    }

    /// The session attributes to carry into the next command on a session, given what the caller
    /// asked for and what the TPM answered.
    ///
    /// This is decided bit by bit, because `TPMA_SESSION` (TPM 2.0 Part 2, §8.4) is not one
    /// decision:
    ///
    /// * `encrypt` (0x40), `decrypt` (0x20) and `audit` (0x80) say how the caller intends to use
    ///   the session, and hold until the caller says otherwise. They are kept exactly as
    ///   requested and are never sourced from the response, which is attacker-reachable where
    ///   the request is not: a response that cleared `encrypt`/`decrypt` would otherwise have
    ///   this client send the next command's first parameter in the clear, and one that cleared
    ///   `audit` would silently stop a session audit that the caller believes is running.
    ///   Part 2 has the TPM echo all three ("in a response, the attribute is copied from the
    ///   request", "if SET in the command, then this attribute will be SET in the response"), so
    ///   the response is at most a confirmation; for `encrypt`/`decrypt` the caller checks it
    ///   above and refuses to continue if it disagrees.
    ///
    /// * `auditReset` (0x4) and `auditExclusive` (0x2) are conditions on the single command that
    ///   carried them, not properties of the session. `auditReset` tells the TPM to initialize
    ///   the session's audit digest, so resending it would re-initialize that digest before
    ///   every later command and the session audit would only ever cover the most recent one
    ///   instead of accumulating over the session (TPM 2.0 Part 1, §21, audit; ms-tpm-20-ref
    ///   `SessionProcess.c`, `UpdateAuditSessionStatus`, calls `InitAuditSession` whenever the
    ///   bit is set).
    ///   `auditExclusive` asks the TPM to run the command only if the session is exclusive at
    ///   its start, and resending it turns a one-off precondition into a standing one that fails
    ///   with TPM_RC_EXCLUSIVE as soon as another audited command intervenes. Both are cleared
    ///   here.
    ///
    ///   They cannot be consumed by taking the response's byte instead. `auditExclusive` in a
    ///   response is the TPM's report of whether the session *is* exclusive and is normally SET
    ///   there, and `auditReset`, which Part 2 says "is always CLEAR in a response", is in fact
    ///   echoed back verbatim by the reference implementation (ms-tpm-20-ref rewrites only
    ///   `auditExclusive` before marshaling the response attributes) — that is, by the simulator
    ///   this client is tested against. Consuming them here does not depend on either.
    ///
    /// * `continueSession` (0x1) is the one bit the TPM answers rather than echoes: CLEAR in a
    ///   response means it closed the session and freed the context when the command completed.
    ///   Keeping it SET would claim a session that no longer exists, so the response decides it.
    ///   See also [`Session::is_terminated`], which is what keeps such a session from being
    ///   handed back for reuse.
    fn next_command_attributes(requested: TPMA_SESSION, returned: TPMA_SESSION) -> TPMA_SESSION {
        let one_shot =
            TPMA_SESSION::auditReset.get_value() | TPMA_SESSION::auditExclusive.get_value();
        let continue_session = TPMA_SESSION::continueSession.get_value();

        let mut next = requested.get_value() & !one_shot;
        if (returned.get_value() & continue_session) == 0 {
            next &= !continue_session;
        }
        TPMA_SESSION(next)
    }

    /// Process response sessions
    fn process_resp_sessions(
        &mut self,
        resp_buf: &mut TpmBuffer,
        cmd_code: TPM_CC,
        resp_params_pos: usize,
        resp_params_size: usize,
    ) -> Result<bool, TpmError> {
        let mut rp_ready = false;
        // The size came off the wire as a `u32`. On a 32-bit target the sum can wrap, and a
        // wrapped position looks in bounds to `set_current_pos` and then panics the raw slice
        // that computes rpHash further down.
        let resp_params_end = resp_params_pos
            .checked_add(resp_params_size)
            .ok_or_else(|| {
                TpmError::GenericError(format!(
                "TPM response claims a {} B parameter area at offset {}, which is not a position \
                 in any buffer",
                resp_params_size, resp_params_pos
            ))
            })?;
        resp_buf.set_current_pos(resp_params_end);
        resp_buf.check_status()?;

        // Pre-compute values needed for HMAC verification to avoid borrow conflicts
        let nonce_tpm_dec = self.nonce_tpm_dec.clone();
        let nonce_tpm_enc = self.nonce_tpm_enc.clone();
        let in_handles = self.in_handles.clone();
        let num_auth_handles = self.num_auth_handles;

        if let Some(ref mut sessions) = self.sessions {
            for (j, session) in sessions.iter_mut().enumerate() {
                let mut auth_response = TPMS_AUTH_RESPONSE::default();
                auth_response.initFromTpm(resp_buf)?;
                resp_buf.check_status()?;

                if session.is_pwap() {
                    // PWAP sessions should have empty nonce and hmac
                    if !auth_response.nonce.is_empty() || !auth_response.hmac.is_empty() {
                        return Err(TpmError::GenericError(
                            "Bad value in PWAP session response".to_string(),
                        ));
                    }
                    continue;
                }

                // Non-PWAP session handling. The predicate is the command side's, because the
                // two HMAC keys have to be identical -- see `Tpm2::authorized_handle`.
                let associated_handle = Self::authorized_handle(&in_handles, num_auth_handles, j);

                // Update session data based on what the TPM just told us.
                //
                // The response nonce and the response attributes are both inputs to the response
                // HMAC, so they have to be in place before it is checked; if either was tampered
                // with, the HMAC verification below is what catches it.
                session.sess_out.nonce = auth_response.nonce.clone();
                session.sess_out.sessionAttributes = auth_response.sessionAttributes;

                // What is NOT done here is copying the response attributes into `sess_in` for
                // the next command. The response is attacker-reachable; the caller's requested
                // attributes are not. Sourcing the next command's attributes from the response
                // lets an adversary clear `encrypt`/`decrypt` and have this client send the next
                // command's first parameter in the clear, while the calling code goes on
                // believing the session encrypts. The caller's request stays authoritative.
                //
                // The TPM echoes `encrypt`/`decrypt` verbatim, so a differing echo means either
                // tampering or a TPM that is not doing what was asked. Either way, stop.
                let xcrypt_mask =
                    TPMA_SESSION::encrypt.get_value() | TPMA_SESSION::decrypt.get_value();
                let requested_xcrypt = session.sess_in.sessionAttributes.get_value() & xcrypt_mask;
                let echoed_xcrypt = auth_response.sessionAttributes.get_value() & xcrypt_mask;
                if requested_xcrypt != echoed_xcrypt {
                    return Err(TpmError::GenericError(format!(
                        "Session {} response echoed encrypt/decrypt attributes 0x{:02x} but \
                         0x{:02x} was requested",
                        j, echoed_xcrypt, requested_xcrypt
                    )));
                }

                // Not every bit is the caller's to keep, though: `TPMA_SESSION` is a byte of
                // separate decisions, and only some of them describe the session rather than the
                // one command that has just been answered.
                session.sess_in.sessionAttributes = Self::next_command_attributes(
                    session.sess_in.sessionAttributes,
                    auth_response.sessionAttributes,
                );

                // The TPM returns an authorization HMAC for every session except a password
                // session and a policy session on which TPM2_PolicyPassword has run; for those
                // two it returns an empty field (`BuildSingleResponseAuth`). Everything else —
                // an HMAC session, and equally a policy session driven by PolicyAuthValue,
                // PolicyPCR, PolicySecret or nothing at all — is authenticated and must be
                // verified. Skipping the policy cases left every response parameter they carried
                // unauthenticated. This mirrors the command-side rule above.
                if !session.expects_response_auth() {
                    if !auth_response.hmac.is_empty() {
                        return Err(TpmError::GenericError(format!(
                            "Session {} returned an authorization HMAC where none was expected",
                            j
                        )));
                    }
                    continue;
                }

                // Compute rpHash inline to avoid borrow conflict with self
                let rp_hash = {
                    let rp_header_size = 8;
                    let rp_hash_data_pos = resp_params_pos - rp_header_size;

                    if !rp_ready {
                        let orig_cur_pos = resp_buf.current_pos();
                        resp_buf.set_current_pos(rp_hash_data_pos);
                        resp_buf.writeInt(TPM_RC::SUCCESS.get_value());
                        resp_buf.writeInt(cmd_code.get_value());
                        resp_buf.set_current_pos(orig_cur_pos);
                    }

                    let data_to_hash = &resp_buf.buffer()
                        [rp_hash_data_pos..(rp_hash_data_pos + rp_header_size + resp_params_size)];
                    Crypto::hash(&self.crypto, session.get_hash_alg(), data_to_hash)?
                };
                rp_ready = true;

                let expected_hmac = session.get_auth_hmac(
                    &self.crypto,
                    rp_hash,
                    false,
                    &nonce_tpm_dec,
                    &nonce_tpm_enc,
                    associated_handle,
                )?;

                if auth_response.hmac.is_empty() {
                    return Err(TpmError::GenericError(format!(
                        "Session {} returned no authorization HMAC where one was expected",
                        j
                    )));
                }

                // Length first, because `ct_eq` is only defined for equal-length slices, and
                // then a constant-time compare so that a wrong tag leaks nothing about how much
                // of it was right.
                let tag_ok = expected_hmac.len() == auth_response.hmac.len()
                    && bool::from(expected_hmac.ct_eq(&auth_response.hmac));
                if !tag_ok {
                    return Err(TpmError::GenericError(format!(
                        "Invalid TPM response HMAC (session {})",
                        j
                    )));
                }
            }
        }

        if resp_buf.size() - resp_buf.current_pos() != 0 {
            return Err(TpmError::GenericError(
                "Invalid response buffer: Data beyond the authorization area".to_string(),
            ));
        }

        Ok(rp_ready)
    }

    /// Update request handles based on command
    fn update_request_handles(&mut self, cmd_code: TPM_CC) -> Result<(), TpmError> {
        // Reset state
        self.object_in_name.clear();

        // This function handles updates to handles based on specific commands
        match cmd_code {
            TPM_CC::HierarchyChangeAuth => {
                // Extract newAuth from the serialized parameters (TPM2B: 2-byte size + data)
                if self.last_cmd_params.len() >= 2 {
                    let size =
                        u16::from_be_bytes([self.last_cmd_params[0], self.last_cmd_params[1]])
                            as usize;
                    if self.last_cmd_params.len() >= 2 + size {
                        self.object_in_auth = self.last_cmd_params[2..2 + size].to_vec();
                    }
                }
                Ok(())
            }
            TPM_CC::LoadExternal => {
                // Store the name for later use
                // In a real implementation, calculate the name from the public area
                self.object_in_name = vec![]; // Calculate from req
                Ok(())
            }
            TPM_CC::Load => {
                // Store the name for later use
                // In a real implementation, calculate the name from the public area
                self.object_in_name = vec![]; // Calculate from req
                Ok(())
            }
            TPM_CC::NV_ChangeAuth => {
                // Extract newAuth from the serialized parameters (TPM2B: 2-byte size + data)
                if self.last_cmd_params.len() >= 2 {
                    let size =
                        u16::from_be_bytes([self.last_cmd_params[0], self.last_cmd_params[1]])
                            as usize;
                    if self.last_cmd_params.len() >= 2 + size {
                        self.object_in_auth = self.last_cmd_params[2..2 + size].to_vec();
                    }
                }
                Ok(())
            }
            TPM_CC::ObjectChangeAuth => {
                // Extract newAuth from the serialized parameters (TPM2B: 2-byte size + data)
                if self.last_cmd_params.len() >= 2 {
                    let size =
                        u16::from_be_bytes([self.last_cmd_params[0], self.last_cmd_params[1]])
                            as usize;
                    if self.last_cmd_params.len() >= 2 + size {
                        self.object_in_auth = self.last_cmd_params[2..2 + size].to_vec();
                    }
                }
                Ok(())
            }
            TPM_CC::PCR_SetAuthValue => {
                // Store auth value for later use
                // In a real implementation, extract the new auth value from the request
                self.object_in_auth = vec![]; // Extract from req
                Ok(())
            }
            TPM_CC::EvictControl => {
                // Store name and auth value for later use
                if (!self.in_handles.is_empty()
                    && self.in_handles[1].get_type() != TPM_HT::PERSISTENT)
                {
                    let handle = &self.in_handles[1];
                    self.object_in_auth = handle.auth_value.clone();
                    self.object_in_name = handle.get_name()?;
                }
                Ok(())
            }
            TPM_CC::Clear => {
                // Reset admin auth values
                if !self.in_handles.is_empty() {
                    let mut handle = self.in_handles[0].clone();
                    handle.set_auth(&[]);
                }
                Ok(())
            }
            TPM_CC::HashSequenceStart => {
                // Extract auth from the serialized parameters (TPM2B: 2-byte size + data)
                if self.last_cmd_params.len() >= 2 {
                    let size =
                        u16::from_be_bytes([self.last_cmd_params[0], self.last_cmd_params[1]])
                            as usize;
                    if self.last_cmd_params.len() >= 2 + size {
                        self.object_in_auth = self.last_cmd_params[2..2 + size].to_vec();
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Complete update of request handles after command success
    fn complete_update_request_handles(&mut self, cmd_code: TPM_CC) -> Result<(), TpmError> {
        match cmd_code {
            TPM_CC::HierarchyChangeAuth => {
                // Update the appropriate hierarchy auth value
                if !self.in_handles.is_empty() {
                    match self.in_handles[0].handle {
                        val if val == TPM_RH::OWNER.get_value() => {
                            self.admin_owner.set_auth(&self.object_in_auth)
                        }
                        val if val == TPM_RH::ENDORSEMENT.get_value() => {
                            self.admin_endorsement.set_auth(&self.object_in_auth)
                        }
                        val if val == TPM_RH::PLATFORM.get_value() => {
                            self.admin_platform.set_auth(&self.object_in_auth)
                        }
                        val if val == TPM_RH::LOCKOUT.get_value() => {
                            self.admin_lockout.set_auth(&self.object_in_auth)
                        }
                        _ => {}
                    }

                    // Update handle auth
                    self.in_handles[0].set_auth(&self.object_in_auth);
                }
                Ok(())
            }
            TPM_CC::NV_ChangeAuth => {
                if !self.in_handles.is_empty() {
                    self.in_handles[0].set_auth(&self.object_in_auth);
                }
                Ok(())
            }
            TPM_CC::PCR_SetAuthValue => {
                if !self.in_handles.is_empty() {
                    self.in_handles[0].set_auth(&self.object_in_auth);
                }
                Ok(())
            }
            TPM_CC::EvictControl => {
                // Update handle auth and name
                if self.in_handles.len() >= 2 && self.in_handles[1].get_type() != TPM_HT::PERSISTENT
                {
                    self.in_handles[1].set_auth(&self.object_in_auth);
                    let _ = self.in_handles[1].set_name(&self.object_in_name.clone());
                }
                Ok(())
            }
            TPM_CC::Clear => {
                // Reset all hierarchy auth values
                self.admin_lockout.set_auth(&[]);
                self.admin_owner.set_auth(&[]);
                self.admin_endorsement.set_auth(&[]);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// The public area a command supplies for the object it loads.
    ///
    /// `TPM2_Load` and `TPM2_LoadExternal` take the public area as an input and return only the
    /// handle and the Name, so this is the only place it can be had from.
    fn request_object_public<R: ReqStructure + 'static>(
        cmd_code: TPM_CC,
        req: &R,
    ) -> Option<TPMT_PUBLIC> {
        let req = req as &dyn Any;
        match cmd_code {
            TPM_CC::Load => req
                .downcast_ref::<TPM2_Load_REQUEST>()
                .map(|r| r.inPublic.clone()),
            TPM_CC::LoadExternal => req
                .downcast_ref::<TPM2_LoadExternal_REQUEST>()
                .map(|r| r.inPublic.clone()),
            _ => None,
        }
    }

    /// The public area a response carries for the object the command created.
    fn response_object_public<T: RespStructure + 'static>(
        cmd_code: TPM_CC,
        resp: &T,
    ) -> Option<&TPMT_PUBLIC> {
        let resp = resp as &dyn Any;
        match cmd_code {
            TPM_CC::CreatePrimary => resp
                .downcast_ref::<CreatePrimaryResponse>()
                .map(|r| &r.outPublic),
            TPM_CC::CreateLoaded => resp
                .downcast_ref::<CreateLoadedResponse>()
                .map(|r| &r.outPublic),
            _ => None,
        }
    }

    /// Bind the response handle to the new object's Name, recomputing that Name wherever this
    /// client holds the public area it is derived from.
    ///
    /// The Name of a TPM object is `nameAlg || H_nameAlg(publicArea)` (TPM 2.0 Part 1, §16), so
    /// it is a value this client can derive for itself instead of taking the TPM's word for it.
    /// Recomputing it is a **consistency check**: it catches a TPM, resource manager or
    /// transport that reports a Name which does not belong to the public area it reported
    /// alongside it, and it stops that inconsistent Name from being written into the handle and
    /// silently folded into every later cpHash, policy digest and Name comparison.
    ///
    /// It is **not** authentication, **not** a defence against an active man in the middle, and
    /// **not** evidence that the object lives in a TPM. An adversary who supplies the public
    /// area supplies the Name that matches it and the check passes: the Name is a digest over
    /// bytes the adversary chose. Its worth beyond catching malfunctions is as a building block
    /// for a caller who knows which Name to expect — pinned out of band, from an enrolment
    /// record or a signed manifest — and [`TrustedPublic::from_pinned_name`] is where that
    /// comparison belongs.
    ///
    /// The check runs after the command has succeeded, so a failure means the TPM has loaded an
    /// object this client is about to refuse to hand back. `flush_orphaned_handle` flushes it,
    /// rather than leaving a transient slot occupied by an object no caller can name.
    ///
    /// What is available to check against differs by command, and the difference is not
    /// cosmetic:
    ///
    /// * `TPM2_CreatePrimary` and `TPM2_CreateLoaded` return `outPublic`, so the Name is checked
    ///   against the response's own public area.
    /// * `TPM2_Load` and `TPM2_LoadExternal` do not: the public area is a command *input*, and
    ///   the response carries only the handle and the Name. Those two are checked against the
    ///   `inPublic` the caller passed, captured at dispatch time — a stronger check than the
    ///   first two, since the public area it compares against is the caller's own.
    /// * A caller that reaches [`Tpm2::dispatch`] with its own request or response type, rather
    ///   than the generated one, gets no check: there is nothing to recover the public area
    ///   from, and the Name is then taken on the TPM's word.
    /// * `TPM2_HashSequenceStart` and `TPM2_HMAC_Start` return handles to objects that have no
    ///   public area and no Name, so there is nothing to check.
    fn update_resp_handle<T: RespStructure + 'static>(
        &mut self,
        cmd_code: TPM_CC,
        resp: &mut T,
    ) -> Result<(), TpmError> {
        match cmd_code {
            TPM_CC::Load | TPM_CC::CreatePrimary | TPM_CC::LoadExternal | TPM_CC::CreateLoaded => {
                let name = resp.get_resp_name();

                let public = match cmd_code {
                    TPM_CC::CreatePrimary | TPM_CC::CreateLoaded => {
                        Self::response_object_public(cmd_code, resp).cloned()
                    }
                    _ => self.command_object_public.take(),
                };

                if let Some(public) = public {
                    // An object loaded with a nameAlg of TPM_ALG_NULL has no digest-based Name;
                    // TPM2_LoadExternal permits exactly that, and there is nothing to recompute.
                    if public.nameAlg != TPM_ALG_ID::NULL {
                        if let Err(err) = public.verify_name(&name, &self.crypto) {
                            // The command succeeded, so the object is loaded and occupying a
                            // transient slot. The caller is about to be handed an error instead
                            // of the handle, so this is the last point at which anything can
                            // flush it — and a TPM that reports a Name inconsistent with its own
                            // public area is not one to leave holding an unreachable object.
                            let handle = resp.get_handle();
                            self.flush_orphaned_handle(&handle);

                            return Err(TpmError::VerificationFailed(format!(
                                "{} returned an object Name that fails the consistency check \
                                 against its public area: {}",
                                cmd_code, err
                            )));
                        }
                    }
                }

                if !name.is_empty() {
                    let mut handle = resp.get_handle();
                    handle.set_name(&name)?;
                    resp.set_handle(&handle);
                }
                Ok(())
            }
            TPM_CC::HashSequenceStart | TPM_CC::HMAC_Start => Ok(()),
            _ => Ok(()),
        }
    }
}

/// Factory function to create a new TPM implementation based on the available platform,
/// performing its host-side crypto with `crypto`.
///
/// The platform is [`TpmTbsDevice`](crate::device::TpmTbsDevice)'s own concern — TBS on Windows,
/// `/dev/tpm*` or a resource manager socket on Linux, and elsewhere a stub that reports at
/// `connect` time that there is no TPM to talk to — so there is nothing to select between here.
pub fn create_tpm_with_crypto(crypto: CryptoProvider) -> Tpm2 {
    use crate::device::TpmTbsDevice;
    Tpm2::new(Box::new(TpmTbsDevice::new()), crypto)
}

/// Factory function to create a new TPM implementation based on the available platform, using
/// the built-in software crypto backend.
#[cfg(feature = "software-crypto")]
pub fn create_tpm() -> Tpm2 {
    create_tpm_with_crypto(crate::crypto::software_provider::SOFTWARE_PROVIDER)
}

/// Factory function to create a TPM implementation with a custom device, using the built-in
/// software crypto backend.
///
/// To supply a different backend, call [`Tpm2::new`] directly.
#[cfg(feature = "software-crypto")]
pub fn create_tpm_with_device(device: Box<dyn TpmDevice>) -> Tpm2 {
    Tpm2::with_software_crypto(device)
}

/// An in-memory [`TpmDevice`] that replays canned response bytes.
///
/// Without it nothing in this module is reachable from a test: the only real `TpmDevice` talks to
/// Windows TBS, so every session and authorization path here has historically been exercised only
/// by hand against hardware.
///
/// Note what a mock device can and cannot establish. It can show that this client *reacts*
/// correctly to a given response — verifies what it should verify, refuses what it should refuse.
/// It cannot establish that a digest this client computes is the digest the TPM computes, because
/// the canned bytes are ours too. Tests of the second kind have to pin their expectations to
/// something outside this crate; see the `spec_*` helpers below, which are transcribed from the
/// TPM 2.0 specification rather than obtained from the code under test.
#[cfg(test)]
pub(crate) mod mock_device {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// The bytes a [`MockTpmDevice`] returns for one response, derived from the command that was
    /// just dispatched.
    pub type Responder = Box<dyn Fn(&[u8]) -> Vec<u8> + Send>;

    /// Where a [`MockTpmDevice`] gets the bytes for one response.
    pub enum MockResponse {
        /// Fixed bytes, returned verbatim.
        Canned(Vec<u8>),
        /// Bytes derived from the command just dispatched. Needed whenever the response has to
        /// be well formed with respect to values the client picked at random — the nonceCaller,
        /// and the authorization HMAC computed over it.
        Computed(Responder),
    }

    pub struct MockTpmDevice {
        responses: VecDeque<MockResponse>,
        commands: Arc<Mutex<Vec<Vec<u8>>>>,
        pending: Option<Vec<u8>>,
    }

    impl MockTpmDevice {
        pub fn new(responses: Vec<MockResponse>) -> Self {
            MockTpmDevice {
                responses: responses.into_iter().collect(),
                commands: Arc::new(Mutex::new(Vec::new())),
                pending: None,
            }
        }

        /// A handle on the commands this device is sent, live for as long as the device is.
        pub fn command_log(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
            Arc::clone(&self.commands)
        }
    }

    impl TpmDevice for MockTpmDevice {
        fn connect(&mut self) -> Result<bool, TpmError> {
            Ok(true)
        }

        fn close(&mut self) {}

        fn dispatch_command(&mut self, cmd_buf: &[u8]) -> Result<(), TpmError> {
            self.commands.lock().unwrap().push(cmd_buf.to_vec());
            let response = self.responses.pop_front().ok_or_else(|| {
                TpmError::GenericError("MockTpmDevice: no queued response".to_string())
            })?;
            self.pending = Some(match response {
                MockResponse::Canned(bytes) => bytes,
                MockResponse::Computed(f) => f(cmd_buf),
            });
            Ok(())
        }

        fn get_response(&mut self) -> Result<Vec<u8>, TpmError> {
            self.pending.take().ok_or_else(|| {
                TpmError::GenericError("MockTpmDevice: no response pending".to_string())
            })
        }

        fn response_is_ready(&self) -> Result<bool, TpmError> {
            Ok(self.pending.is_some())
        }

        fn has_flag(&self, _flag: u32) -> bool {
            false
        }

        fn get_tpm_info(&self) -> u32 {
            0
        }
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::mock_device::{MockResponse, MockTpmDevice};
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;
    use crate::tpm_types::*;
    use rand::rngs::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{Oaep, RsaPrivateKey};
    use sha1::Sha1;
    use std::sync::{Arc, Mutex};

    const LOCKOUT_AUTH: &[u8] = b"lockout-auth";
    const SALT: &[u8] = b"a thirty-two byte session salt..";

    fn be16(buf: &[u8], pos: usize) -> u16 {
        u16::from_be_bytes([buf[pos], buf[pos + 1]])
    }

    fn be32(buf: &[u8], pos: usize) -> u32 {
        u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
    }

    /// The first authorization area of a command. Layout from TPM 2.0 Part 1, §18.2:
    /// `tag ‖ commandSize ‖ commandCode ‖ handles ‖ authorizationSize ‖ authorizationArea`.
    struct CommandAuth {
        nonce_caller: Vec<u8>,
        attributes: u8,
        hmac: Vec<u8>,
        /// Offset just past the authorization area, which is where the command parameters start.
        area_end: usize,
    }

    /// Parse the single authorization area of a command with `num_handles` handles.
    fn parse_command_auth(cmd: &[u8], num_handles: usize) -> CommandAuth {
        let mut p = 2 + 4 + 4 + 4 * num_handles; // tag, commandSize, commandCode, handles
        let auth_size = be32(cmd, p) as usize;
        p += 4;
        let auth_end = p + auth_size;

        p += 4; // sessionHandle
        let nonce_len = be16(cmd, p) as usize;
        p += 2;
        let nonce_caller = cmd[p..p + nonce_len].to_vec();
        p += nonce_len;
        let attributes = cmd[p];
        p += 1;
        let hmac_len = be16(cmd, p) as usize;
        p += 2;
        let hmac = cmd[p..p + hmac_len].to_vec();
        p += hmac_len;

        assert_eq!(
            p, auth_end,
            "authorization area size does not match its contents"
        );

        CommandAuth {
            nonce_caller,
            attributes,
            hmac,
            area_end: auth_end,
        }
    }

    /// The authorization area of a `TPM2_Clear`, which has a single handle and no parameters.
    fn parse_clear_command_auth(cmd: &[u8]) -> CommandAuth {
        let auth = parse_command_auth(cmd, 1);
        assert_eq!(
            auth.area_end,
            cmd.len(),
            "TPM2_Clear should have no parameters"
        );
        auth
    }

    /// A `TPM_ST_SESSIONS` response for a command with no response handles, carrying `params` as
    /// its response parameters and exactly one authorization area.
    fn build_response_with_params(
        params: &[u8],
        nonce_tpm: &[u8],
        attributes: u8,
        hmac: &[u8],
    ) -> Vec<u8> {
        let mut auth = Vec::new();
        auth.extend_from_slice(&(nonce_tpm.len() as u16).to_be_bytes());
        auth.extend_from_slice(nonce_tpm);
        auth.push(attributes);
        auth.extend_from_slice(&(hmac.len() as u16).to_be_bytes());
        auth.extend_from_slice(hmac);

        let mut resp = Vec::new();
        resp.extend_from_slice(&TPM_ST::SESSIONS.get_value().to_be_bytes());
        resp.extend_from_slice(&((2 + 4 + 4 + 4 + params.len() + auth.len()) as u32).to_be_bytes());
        resp.extend_from_slice(&TPM_RC::SUCCESS.get_value().to_be_bytes()); // responseCode
        resp.extend_from_slice(&(params.len() as u32).to_be_bytes()); // parameterSize
        resp.extend_from_slice(params);
        resp.extend_from_slice(&auth);
        resp
    }

    /// A `TPM_ST_SESSIONS` response for a command with no response handles and no response
    /// parameters, carrying exactly one authorization area.
    fn build_response(nonce_tpm: &[u8], attributes: u8, hmac: &[u8]) -> Vec<u8> {
        build_response_with_params(&[], nonce_tpm, attributes, hmac)
    }

    /// TPM 2.0 Part 1, §19.6.5 and §19.6.6:
    /// ```text
    ///   rpHash   := H_sessionAlg(responseCode ‖ commandCode ‖ parameters)
    ///   authHMAC := HMAC_sessionAlg(sessionKey ‖ authValue,
    ///                               rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes)
    /// ```
    /// (`nonceTPM` is the newer nonce on the response side, `nonceCaller` the older.)
    fn spec_response_hmac_over(
        key: &[u8],
        cmd_code: TPM_CC,
        params: &[u8],
        nonce_tpm: &[u8],
        nonce_caller: &[u8],
        attributes: u8,
    ) -> Vec<u8> {
        let mut rp = Vec::new();
        rp.extend_from_slice(&TPM_RC::SUCCESS.get_value().to_be_bytes());
        rp.extend_from_slice(&cmd_code.get_value().to_be_bytes());
        rp.extend_from_slice(params);
        let rp_hash = Crypto::hash(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &rp).unwrap();

        let mut buf = Vec::new();
        buf.extend_from_slice(&rp_hash);
        buf.extend_from_slice(nonce_tpm);
        buf.extend_from_slice(nonce_caller);
        buf.push(attributes);
        Crypto::hmac(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, key, &buf).unwrap()
    }

    /// The TPM 2.0 response authorization HMAC, transcribed from the specification rather than
    /// obtained from the code under test, for a response with no parameters.
    fn spec_response_hmac(
        key: &[u8],
        cmd_code: TPM_CC,
        nonce_tpm: &[u8],
        nonce_caller: &[u8],
        attributes: u8,
    ) -> Vec<u8> {
        spec_response_hmac_over(key, cmd_code, &[], nonce_tpm, nonce_caller, attributes)
    }

    /// The TPM 2.0 command authorization HMAC, likewise transcribed from the specification.
    ///
    /// TPM 2.0 Part 1, §19.6.5, for a command with no parameters and no separate
    /// encrypt/decrypt sessions:
    /// ```text
    ///   cpHash   := H_sessionAlg(commandCode ‖ name(s) ‖ parameters)
    ///   authHMAC := HMAC_sessionAlg(sessionKey ‖ authValue,
    ///                               cpHash ‖ nonceCaller ‖ nonceTPM ‖ sessionAttributes)
    /// ```
    fn spec_command_hmac(
        key: &[u8],
        cmd_code: TPM_CC,
        handle_names: &[Vec<u8>],
        nonce_caller: &[u8],
        nonce_tpm: &[u8],
        attributes: u8,
    ) -> Vec<u8> {
        let mut cp = Vec::new();
        cp.extend_from_slice(&cmd_code.get_value().to_be_bytes());
        for name in handle_names {
            cp.extend_from_slice(name);
        }
        let cp_hash = Crypto::hash(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, &cp).unwrap();

        let mut buf = Vec::new();
        buf.extend_from_slice(&cp_hash);
        buf.extend_from_slice(nonce_caller);
        buf.extend_from_slice(nonce_tpm);
        buf.push(attributes);
        Crypto::hmac(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256, key, &buf).unwrap()
    }

    /// A session as `TPM2_StartAuthSession` would have left it, built directly so that the test
    /// knows the salt and therefore the session key.
    fn make_session(session_type: TPM_SE, salt: &[u8]) -> Session {
        Session::from_tpm_response(
            &SOFTWARE_PROVIDER,
            TPM_HANDLE::new(0x03000000),
            session_type,
            TPM_ALG_ID::SHA256,
            vec![0xAA; 32],
            vec![0xBB; 32],
            TPMA_SESSION::continueSession,
            TPMT_SYM_DEF::default(),
            salt,
            &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        )
        .unwrap()
    }

    /// A `Tpm2` over a mock device, with the lockout authValue set so that `TPM2_Clear` has a
    /// non-empty authValue to fold into its HMAC key.
    fn tpm_with(responses: Vec<MockResponse>) -> (Tpm2, Arc<Mutex<Vec<Vec<u8>>>>) {
        let device = MockTpmDevice::new(responses);
        let log = device.command_log();
        let mut tpm = Tpm2::with_software_crypto(Box::new(device));
        tpm.set_admin_auth(TPM_RH::LOCKOUT, LOCKOUT_AUTH);
        (tpm, log)
    }

    /// A responder that answers a `TPM2_Clear` with a correctly authenticated response.
    ///
    /// `key_for` turns the parsed command into the HMAC key the TPM would have used, so each
    /// test states for itself what it believes the key is.
    fn correct_responder(
        nonce_tpm: Vec<u8>,
        resp_attributes_of: fn(u8) -> u8,
        key: Vec<u8>,
    ) -> MockResponse {
        MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            let resp_attrs = resp_attributes_of(auth.attributes);
            let hmac = spec_response_hmac(
                &key,
                TPM_CC::Clear,
                &nonce_tpm,
                &auth.nonce_caller,
                resp_attrs,
            );
            build_response(&nonce_tpm, resp_attrs, &hmac)
        }))
    }

    fn echo(attrs: u8) -> u8 {
        attrs
    }

    // ---------------------------------------------------------------------------------------
    // Item 7(a): which sessions carry a response authorization, and whether it is verified.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn response_auth_is_verified_for_a_policy_session_without_policy_password() {
        // A policy session that has run no PolicyAuthValue and no PolicyPassword. The TPM still
        // authenticates the response with the session key, and this client used to skip the
        // check entirely for exactly this case.
        let session = make_session(TPM_SE::POLICY, SALT);
        let key = session.session_key.clone();
        assert!(!key.is_empty(), "the salted session should have a key");
        assert!(
            session.expects_response_auth(),
            "the TPM authenticates this response, so the client has to check it"
        );

        let (mut tpm, _log) = tpm_with(vec![correct_responder(vec![0xC1; 32], echo, key.clone())]);
        tpm.with_session(session.clone());

        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("a correctly authenticated response should be accepted");

        // The same session against a response whose tag is well formed, the right length, and
        // keyed on the right session key -- but computed over a different nonceTPM from the one
        // the response carries. Only a verifier that actually consumes nonceTPM rejects this,
        // and a verifier that skips policy sessions altogether accepts it.
        let sent_nonce = vec![0xC2; 32];
        let hmac_nonce = vec![0xC3; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            let hmac = spec_response_hmac(
                &key,
                TPM_CC::Clear,
                &hmac_nonce,
                &auth.nonce_caller,
                auth.attributes,
            );
            build_response(&sent_nonce, auth.attributes, &hmac)
        }));
        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("a tag computed over a nonce the response does not carry is not valid");
        assert!(
            format!("{}", err).contains("Invalid TPM response HMAC"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn tampered_response_hmac_is_rejected() {
        // The same exchange as above with one bit flipped in the tag. If verification were
        // skipped — as it was — this would pass silently.
        let session = make_session(TPM_SE::POLICY, SALT);
        let key = session.session_key.clone();
        let nonce_tpm = vec![0xC1; 32];

        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            let mut hmac = spec_response_hmac(
                &key,
                TPM_CC::Clear,
                &nonce_tpm,
                &auth.nonce_caller,
                auth.attributes,
            );
            hmac[31] ^= 0x01;
            build_response(&nonce_tpm, auth.attributes, &hmac)
        }));

        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("a tampered response HMAC must be rejected");
        assert!(
            format!("{:?}", err).contains("Invalid TPM response HMAC"),
            "unexpected error: {:?}",
            err
        );
    }

    #[test]
    fn response_auth_is_not_expected_after_policy_password() {
        // TPM2_PolicyPassword makes the TPM authenticate the command with the authValue in the
        // clear and return an empty response authorization (`BuildSingleResponseAuth`). Demanding
        // one here would break every legitimate PolicyPassword session.
        let mut session = make_session(TPM_SE::POLICY, SALT);
        session.needs_password = true;
        session.needs_hmac = false;

        let nonce_tpm = vec![0xC2; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            build_response(&nonce_tpm, auth.attributes, &[])
        }));

        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("an empty response auth is correct after TPM2_PolicyPassword");
    }

    #[test]
    fn unexpected_response_auth_after_policy_password_is_rejected() {
        let mut session = make_session(TPM_SE::POLICY, SALT);
        session.needs_password = true;
        session.needs_hmac = false;

        let nonce_tpm = vec![0xC3; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            build_response(&nonce_tpm, auth.attributes, &[0x00; 32])
        }));

        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("an authorization the TPM cannot have produced must be rejected");
        assert!(
            format!("{:?}", err).contains("where none was expected"),
            "unexpected error: {:?}",
            err
        );
    }

    #[test]
    fn missing_response_auth_is_rejected_for_an_hmac_session() {
        let session = make_session(TPM_SE::HMAC, SALT);
        let nonce_tpm = vec![0xC4; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            build_response(&nonce_tpm, auth.attributes, &[])
        }));

        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("stripping the response authorization must not go unnoticed");
        assert!(
            format!("{:?}", err).contains("no authorization HMAC where one was expected"),
            "unexpected error: {:?}",
            err
        );
    }

    // ---------------------------------------------------------------------------------------
    // Item 7(b): which session attributes the next command inherits, and from where.
    // ---------------------------------------------------------------------------------------

    /// Run two `TPM2_Clear` commands on one session, the second on whatever `last_session()`
    /// hands back, and return the session attribute byte each command carried.
    ///
    /// `resp_attributes_of` is what the TPM does to the request's attribute byte on the way
    /// back, so a test can model a TPM that echoes a bit as readily as one that rewrites it.
    fn attributes_of_two_commands(
        requested: TPMA_SESSION,
        resp_attributes_of: fn(u8) -> u8,
    ) -> (u8, u8) {
        let mut session = make_session(TPM_SE::HMAC, SALT);
        session.sess_in.sessionAttributes = requested;
        let key = {
            let mut k = session.session_key.clone();
            k.extend_from_slice(LOCKOUT_AUTH);
            k
        };
        // `TPM2_Clear` sets lockoutAuth to the Empty Buffer, and this client follows the TPM in
        // that (`complete_update_request_handles`), so the second command folds no authValue
        // into its HMAC key and the key is the session key alone.
        let key_after_clear = session.session_key.clone();

        let (mut tpm, log) = tpm_with(vec![
            correct_responder(vec![0xD1; 32], resp_attributes_of, key),
            correct_responder(vec![0xD2; 32], resp_attributes_of, key_after_clear),
        ]);

        tpm.with_session(session);
        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("the first command should be accepted");

        let reused = tpm
            .last_session()
            .expect("the TPM left the session open, so it should come back for reuse");
        tpm.with_session(reused);
        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("the second command should be accepted");

        let commands = log.lock().unwrap();
        assert_eq!(commands.len(), 2, "both commands should have been sent");
        (
            parse_clear_command_auth(&commands[0]).attributes,
            parse_clear_command_auth(&commands[1]).attributes,
        )
    }

    #[test]
    fn the_per_bit_attribute_policy_keeps_what_is_the_callers_and_consumes_what_is_not() {
        let attrs = |bits: u8| TPMA_SESSION(bits);
        let next = |requested: u8, returned: u8| {
            Tpm2::next_command_attributes(attrs(requested), attrs(returned)).get_value()
        };

        let continue_session = TPMA_SESSION::continueSession.get_value();
        let audit_exclusive = TPMA_SESSION::auditExclusive.get_value();
        let audit_reset = TPMA_SESSION::auditReset.get_value();
        let decrypt = TPMA_SESSION::decrypt.get_value();
        let encrypt = TPMA_SESSION::encrypt.get_value();
        let audit = TPMA_SESSION::audit.get_value();

        // How the caller means to use the session holds across commands.
        let persistent = continue_session | decrypt | encrypt | audit;
        assert_eq!(next(persistent, persistent), persistent);

        // The one-shot bits are consumed by the command that carried them, even when the TPM
        // hands them straight back -- which is what the reference implementation does.
        assert_eq!(
            next(
                continue_session | audit | audit_reset | audit_exclusive,
                continue_session | audit | audit_reset | audit_exclusive,
            ),
            continue_session | audit,
        );

        // continueSession is the TPM's answer: CLEAR means it closed the session.
        assert_eq!(next(continue_session | encrypt, encrypt), encrypt);

        // And nothing the response says can add an attribute to the next command.
        assert_eq!(next(continue_session, 0xFF), continue_session);
    }

    #[test]
    fn session_attributes_are_not_taken_from_the_response() {
        // The response is attacker-reachable and the request is not, so the caller's request
        // decides the bits that describe the session. Here the TPM answers with auditExclusive
        // SET -- its report that the session is exclusive, which is exactly what a TPM returns
        // for an audit session that holds exclusivity (TPM 2.0 Part 2: "in a response, it
        // indicates that the session is exclusive"). That report must not become the next
        // command's "execute only if exclusive" precondition.
        let mut session = make_session(TPM_SE::HMAC, SALT);
        session.sess_in.sessionAttributes = TPMA_SESSION::continueSession | TPMA_SESSION::audit;
        let requested = session.sess_in.sessionAttributes.get_value();
        let key = {
            let mut k = session.session_key.clone();
            k.extend_from_slice(LOCKOUT_AUTH);
            k
        };
        let returned = requested | TPMA_SESSION::auditExclusive.get_value();

        let (mut tpm, _log) = tpm_with(vec![correct_responder(
            vec![0xC5; 32],
            |attrs| attrs | TPMA_SESSION::auditExclusive.get_value(),
            key,
        )]);
        tpm.with_session(session);

        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("a session the TPM reports as exclusive is still a usable session");

        let after = tpm.last_session().expect("session should be retained");
        assert_eq!(
            after.sess_in.sessionAttributes.get_value(),
            requested,
            "the next command's attributes must come from the caller, not the response"
        );
        assert_eq!(
            after.sess_out.sessionAttributes.get_value(),
            returned,
            "what the TPM actually returned should still be observable"
        );
    }

    #[test]
    fn audit_reset_is_not_resent_on_the_following_command() {
        // auditReset tells the TPM to initialize the session's audit digest. It belongs to the
        // one command that asked for it: resending it would re-initialize the digest before
        // every later command, so the audit would only ever cover the most recent one instead of
        // accumulating over the session.
        //
        // The TPM here echoes the bit back, which is what the reference implementation does
        // (ms-tpm-20-ref rewrites only auditExclusive before marshaling the response
        // attributes) even though Part 2 says the bit is always CLEAR in a response. So the
        // client cannot rely on the response to consume it, and this test would pass for the
        // wrong reason against a TPM that did clear it.
        let requested =
            TPMA_SESSION::continueSession | TPMA_SESSION::audit | TPMA_SESSION::auditReset;

        let (first, second) = attributes_of_two_commands(requested, echo);

        assert_eq!(
            first,
            requested.get_value(),
            "the first command carries what the caller asked for"
        );
        assert_eq!(
            second,
            (TPMA_SESSION::continueSession | TPMA_SESSION::audit).get_value(),
            "auditReset is consumed by the command that carried it; audit and continueSession \
             are the caller's and stay"
        );
    }

    #[test]
    fn audit_exclusive_is_not_resent_on_the_following_command() {
        // auditExclusive asks the TPM to run this one command only if the session is exclusive
        // at its start. Carried forward it becomes a standing precondition the caller never
        // asked for, and one that fails with TPM_RC_EXCLUSIVE the moment another audited
        // command intervenes. The TPM here reports the session as exclusive, i.e. it answers
        // with the bit SET, so consuming it cannot come from the response either.
        let requested =
            TPMA_SESSION::continueSession | TPMA_SESSION::audit | TPMA_SESSION::auditExclusive;

        let (first, second) = attributes_of_two_commands(requested, |attrs| {
            attrs | TPMA_SESSION::auditExclusive.get_value()
        });

        assert_eq!(
            first,
            requested.get_value(),
            "the first command carries what the caller asked for"
        );
        assert_eq!(
            second,
            (TPMA_SESSION::continueSession | TPMA_SESSION::audit).get_value(),
            "auditExclusive is a condition on one command, not a property of the session"
        );
    }

    #[test]
    fn encrypt_and_decrypt_survive_into_the_following_command() {
        // The counterpart to the one-shot bits: parameter encryption is a standing decision of
        // the caller's, and consuming or dropping it would silently send the next command's
        // first parameter in the clear.
        let requested =
            TPMA_SESSION::continueSession | TPMA_SESSION::encrypt | TPMA_SESSION::decrypt;

        let (first, second) = attributes_of_two_commands(requested, echo);

        assert_eq!(first, requested.get_value());
        assert_eq!(
            second,
            requested.get_value(),
            "encrypt/decrypt must still be set on the second command"
        );
    }

    #[test]
    fn a_session_the_tpm_closed_is_not_handed_back_for_reuse() {
        // continueSession CLEAR in a response is the TPM saying it flushed the session when the
        // command completed. The context is gone and the handle may later belong to an
        // unrelated session, so there is nothing left to reuse and the client must not offer it.
        let session = make_session(TPM_SE::HMAC, SALT);
        let key = {
            let mut k = session.session_key.clone();
            k.extend_from_slice(LOCKOUT_AUTH);
            k
        };

        let (mut tpm, log) = tpm_with(vec![correct_responder(vec![0xC5; 32], |_| 0x00, key)]);
        tpm.with_session(session);

        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("a TPM closing the session is a well formed response, not an error");

        assert!(
            tpm.last_session().is_none(),
            "a session the TPM flushed must not come back for another command"
        );
        assert!(
            tpm.last_sessions().is_none(),
            "and it must not come back through the plural accessor either"
        );

        // And take the reuse path a caller would take, so the assertion lands on the wire and
        // not only on the accessor: with nothing handed back there is no second command, and
        // the device's log would record one if there were -- it logs a command before it looks
        // for a response to it, so this holds even with no second response queued.
        if let Some(stale) = tpm.last_session() {
            tpm.with_session(stale);
            let _ = tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()));
        }
        let commands = log.lock().unwrap();
        assert_eq!(
            commands.len(),
            1,
            "no command may go out on a session handle the TPM has flushed"
        );
    }

    #[test]
    fn a_response_that_adds_an_encrypt_attribute_is_rejected() {
        // The echo check is not only about bits going missing. A response that claims the TPM
        // encrypted a response parameter the caller never asked it to encrypt disagrees with
        // the request just as much, and a client that took its attributes from the response
        // would go on to encrypt the next command's first parameter on a session the caller
        // never nominated for it.
        let mut session = make_session(TPM_SE::HMAC, SALT);
        session.sess_in.sessionAttributes = TPMA_SESSION::continueSession;
        let key = {
            let mut k = session.session_key.clone();
            k.extend_from_slice(LOCKOUT_AUTH);
            k
        };

        let (mut tpm, _log) = tpm_with(vec![correct_responder(
            vec![0xC7; 32],
            |attrs| attrs | TPMA_SESSION::encrypt.get_value(),
            key,
        )]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("an encrypt/decrypt echo that disagrees with the request is rejected");
        assert!(
            format!("{:?}", err).contains("echoed encrypt/decrypt attributes"),
            "unexpected error: {:?}",
            err
        );
    }

    #[test]
    fn a_response_that_drops_the_encrypt_attribute_is_rejected() {
        // Stripping `encrypt` from the echo is how an adversary would try to talk this client
        // out of encrypting the next command's first parameter.
        let mut session = make_session(TPM_SE::HMAC, SALT);
        session.sess_in.sessionAttributes = TPMA_SESSION::continueSession | TPMA_SESSION::encrypt;
        let key = {
            let mut k = session.session_key.clone();
            k.extend_from_slice(LOCKOUT_AUTH);
            k
        };

        let (mut tpm, _log) = tpm_with(vec![correct_responder(
            vec![0xC6; 32],
            |attrs| attrs & !TPMA_SESSION::encrypt.get_value(),
            key,
        )]);
        tpm.with_session(session);

        let err = tpm
            .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect_err("a downgraded encrypt/decrypt echo must be rejected");
        assert!(
            format!("{:?}", err).contains("echoed encrypt/decrypt attributes"),
            "unexpected error: {:?}",
            err
        );
    }

    // ---------------------------------------------------------------------------------------
    // Command side: the rule the response side mirrors.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_policy_session_without_policy_password_sends_a_command_hmac() {
        // Previously this sent an empty authorization field, which is why a salted or bound
        // policy session could not be used at all: the TPM computed an HMAC over its session key
        // and got nothing to compare it with.
        let session = make_session(TPM_SE::POLICY, SALT);
        let key = session.session_key.clone();
        let expected_key = key.clone();

        let (mut tpm, log) = tpm_with(vec![correct_responder(vec![0xC7; 32], echo, key)]);
        tpm.with_session(session);
        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .unwrap();

        let cmd = log.lock().unwrap()[0].clone();
        let auth = parse_clear_command_auth(&cmd);
        // TPM2_Clear's one handle is TPM_RH_LOCKOUT, whose Name is the four-byte handle value
        // (TPM 2.0 Part 1, §16: for a permanent handle the Name is the handle).
        let name = TPM_RH::LOCKOUT.get_value().to_be_bytes().to_vec();
        assert_eq!(
            auth.hmac,
            spec_command_hmac(
                &expected_key,
                TPM_CC::Clear,
                &[name],
                &auth.nonce_caller,
                &[0xBB; 32],
                auth.attributes,
            ),
            "a policy session with no PolicyAuthValue keys its command HMAC on the session key \
             alone, with no authValue folded in"
        );
    }

    #[test]
    fn a_policy_password_session_sends_the_auth_value_in_the_command() {
        let mut session = make_session(TPM_SE::POLICY, SALT);
        session.needs_password = true;
        session.needs_hmac = false;

        let nonce_tpm = vec![0xC8; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_clear_command_auth(cmd);
            build_response(&nonce_tpm, auth.attributes, &[])
        }));

        let (mut tpm, log) = tpm_with(vec![responder]);
        tpm.with_session(session);
        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .unwrap();

        let cmd = log.lock().unwrap()[0].clone();
        let auth = parse_clear_command_auth(&cmd);
        assert_eq!(
            auth.hmac, LOCKOUT_AUTH,
            "after TPM2_PolicyPassword the authValue is sent in the clear, not HMAC'd"
        );
    }

    #[test]
    fn an_hmac_session_folds_the_auth_value_into_its_command_key() {
        let session = make_session(TPM_SE::HMAC, SALT);
        let mut key = session.session_key.clone();
        key.extend_from_slice(LOCKOUT_AUTH);
        let responder_key = key.clone();

        let (mut tpm, log) = tpm_with(vec![correct_responder(vec![0xC9; 32], echo, responder_key)]);
        tpm.with_session(session);
        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .unwrap();

        let cmd = log.lock().unwrap()[0].clone();
        let auth = parse_clear_command_auth(&cmd);
        let name = TPM_RH::LOCKOUT.get_value().to_be_bytes().to_vec();
        assert_eq!(
            auth.hmac,
            spec_command_hmac(
                &key,
                TPM_CC::Clear,
                &[name],
                &auth.nonce_caller,
                &[0xBB; 32],
                auth.attributes,
            )
        );
    }

    #[test]
    fn a_non_empty_password_session_response_auth_is_rejected() {
        // A password session's response authorization is fixed: empty nonce, empty HMAC. There
        // is no key to check anything else with, so a response that fills either field did not
        // come from a TPM applying the rules, and the only answer available is to refuse it.
        // `a_password_session_expects_no_response_auth` in `auth_session` pins the flag; this
        // pins what dispatch does when the flag says "nothing to check" and something arrives.
        let cases: [(&[u8], &[u8]); 3] = [
            (&[], &[0x11; 32]),         // an HMAC where none can exist
            (&[0x22; 16], &[]),         // a nonce a password session never has
            (&[0x22; 16], &[0x11; 32]), // both
        ];

        for (nonce, hmac) in cases {
            let (mut tpm, _log) = tpm_with(vec![MockResponse::Canned(build_response(
                nonce,
                TPMA_SESSION::continueSession.get_value(),
                hmac,
            ))]);

            let err = tpm
                .Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
                .expect_err("a password session's response carries no authorization to check");
            assert!(
                format!("{}", err).contains("Bad value in PWAP session response"),
                "unexpected error for nonce {:?} hmac {:?}: {}",
                nonce,
                hmac,
                err
            );
        }
    }

    #[test]
    fn a_handle_the_command_does_not_authorize_is_absent_from_the_response_hmac_key() {
        // TPM2_ContextSave names one handle and authorizes none: saving a context needs no
        // authorization, so a session attached to it is there for auditing or parameter
        // encryption, not to authorize `saveHandle`. Its HMAC key is the session key alone, even
        // though the handle beside it carries an authValue -- the caller set one because the
        // object needs it for every *other* command.
        //
        // The command side has always applied that rule. The response side keyed on whichever
        // handle sat at the session's index, authorized or not, so it folded in an authValue the
        // command's key did not have and rejected a correct response. The same disagreement is
        // reachable with a second session on TPM2_Duplicate, whose newParentHandle the command
        // does not authorize.
        let session = make_session(TPM_SE::HMAC, SALT);
        let key = session.session_key.clone();

        let mut save_handle = TPM_HANDLE::new(OBJECT_HANDLE);
        save_handle
            .set_name(&name_of(&sample_public(0x88)))
            .unwrap();
        save_handle.set_auth(b"object-auth");

        let params = ContextSaveResponse {
            context: TPMS_CONTEXT::new(
                7,
                &TPM_HANDLE::new(OBJECT_HANDLE),
                &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
                &TPMS_CONTEXT_DATA::default(),
            ),
        }
        .toBytes()
        .unwrap();

        let nonce_tpm = vec![0xCB; 32];
        let responder = MockResponse::Computed(Box::new(move |cmd: &[u8]| {
            let auth = parse_command_auth(cmd, 1);
            let hmac = spec_response_hmac_over(
                &key,
                TPM_CC::ContextSave,
                &params,
                &nonce_tpm,
                &auth.nonce_caller,
                auth.attributes,
            );
            build_response_with_params(&params, &nonce_tpm, auth.attributes, &hmac)
        }));

        let (mut tpm, _log) = tpm_with(vec![responder]);
        tpm.with_session(session);

        tpm.ContextSave(&save_handle)
            .expect("the response HMAC key must be the one the command's HMAC was keyed on");
    }

    // ---------------------------------------------------------------------------------------
    // Response code decoding: the shape of an ordinary TPM failure.
    // ---------------------------------------------------------------------------------------
    /// A response with the given code and body. `TPM_ST_NO_SESSIONS` is the tag a TPM uses for
    /// an error response, and for any command dispatched without an authorization session.
    fn response(tag: TPM_ST, response_code: u32, body: &[u8]) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&tag.get_value().to_be_bytes());
        resp.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        resp.extend_from_slice(&response_code.to_be_bytes());
        resp.extend_from_slice(body);
        resp
    }

    fn error_response(response_code: u32) -> MockResponse {
        MockResponse::Canned(response(TPM_ST::NO_SESSIONS, response_code, &[]))
    }

    /// A `TPM2_GetRandom` response carrying `bytes`.
    fn get_random_response(bytes: &[u8]) -> MockResponse {
        let mut body = Vec::new();
        body.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(bytes);
        MockResponse::Canned(response(TPM_ST::NO_SESSIONS, 0, &body))
    }

    #[test]
    fn format_one_response_codes_decode_to_their_base_error_and_index() {
        // Every one of these is a value a TPM puts on the wire, and none of them is a member of
        // the generated TPM_RC enumeration: a format-1 code folds a parameter, handle or session
        // number into the value, so running it through `TPM_RC::try_from` reports "Invalid enum
        // value" and throws the real error away.
        for raw in [0x1D5u32, 0x1C5, 0x18B, 0x98E, 0xD5, 0xC4] {
            assert!(
                TPM_RC::try_from(raw).is_err(),
                "0x{:X} is deliberately absent from the generated TPM_RC match",
                raw
            );
        }

        // TPM_RC_SIZE (0x095) against parameter 1: RC_FMT1 | RC_P | RC_1.
        let size_of_parm_1 = ResponseCode::decode(0x1D5);
        assert_eq!(size_of_parm_1.raw(), 0x1D5);
        assert_eq!(size_of_parm_1.code(), TPM_RC::SIZE);
        assert_eq!(size_of_parm_1.index(), RcIndex::Parameter(1));

        // TPM_RC_HIERARCHY (0x085) against parameter 1.
        let hierarchy_of_parm_1 = ResponseCode::decode(0x1C5);
        assert_eq!(hierarchy_of_parm_1.code(), TPM_RC::HIERARCHY);
        assert_eq!(hierarchy_of_parm_1.index(), RcIndex::Parameter(1));

        // TPM_RC_HANDLE (0x08B) against handle 1: RC_FMT1 | RC_1, with RC_P clear.
        let handle_1 = ResponseCode::decode(0x18B);
        assert_eq!(handle_1.code(), TPM_RC::HANDLE);
        assert_eq!(handle_1.index(), RcIndex::Handle(1));

        // TPM_RC_AUTH_FAIL (0x08E) against session 1: RC_FMT1 | RC_S | RC_1.
        let auth_fail_of_session_1 = ResponseCode::decode(0x98E);
        assert_eq!(auth_fail_of_session_1.code(), TPM_RC::AUTH_FAIL);
        assert_eq!(auth_fail_of_session_1.index(), RcIndex::Session(1));

        // A format-1 code with no number field names no particular element.
        assert_eq!(ResponseCode::decode(0xD5).code(), TPM_RC::SIZE);
        assert_eq!(ResponseCode::decode(0xD5).index(), RcIndex::Unspecified);
    }

    #[test]
    fn format_zero_response_codes_are_left_alone() {
        // Format-0 codes carry no index, and must survive decoding unchanged.
        for (raw, expected) in [
            (0x000u32, TPM_RC::SUCCESS),
            (0x101, TPM_RC::FAILURE),
            (0x921, TPM_RC::LOCKOUT),
            (0x922, TPM_RC::RETRY),
        ] {
            let decoded = ResponseCode::decode(raw);
            assert_eq!(decoded.code(), expected, "0x{:X}", raw);
            assert_eq!(decoded.index(), RcIndex::Unspecified, "0x{:X}", raw);
            assert_eq!(decoded.raw(), raw);
        }
        assert!(ResponseCode::decode(0).is_success());

        // A code the TSS communication layer generated is not a TPM response code and none of
        // the TPM's bit assignments apply to it.
        let comm_error = ResponseCode::decode(0x80280002);
        assert_eq!(comm_error.code(), TPM_RC(0x80280002));
        assert_eq!(comm_error.index(), RcIndex::Unspecified);
    }

    #[test]
    fn a_format_one_error_surfaces_as_the_error_the_tpm_reported() {
        let (mut tpm, _log) = tpm_with(vec![error_response(0x1D5)]);

        let err = tpm
            .GetRandom(20)
            .expect_err("the TPM reported a failure code");
        let text = format!("{}", err);
        assert!(
            !text.contains("Invalid enum value"),
            "the real response code must not be discarded: {}",
            text
        );
        assert!(text.contains("SIZE"), "unexpected error: {}", text);
        assert!(text.contains("parameter 1"), "unexpected error: {}", text);

        assert_eq!(tpm.last_response_code(), TPM_RC::SIZE);

        let last = tpm
            .last_error()
            .expect("last_error() must be populated for a TPM failure");
        assert_eq!(last.response_code, TPM_RC::SIZE);
        assert_eq!(
            last.raw_response_code, 0x1D5,
            "the code as it arrived must be preserved, not just its masked form"
        );
        assert_eq!(last.index, RcIndex::Parameter(1));
        assert_eq!(last.command_code, TPM_CC::GetRandom);
    }

    #[test]
    fn last_error_is_cleared_by_a_command_that_succeeds() {
        let (mut tpm, _log) =
            tpm_with(vec![error_response(0x1D5), get_random_response(&[0xAB; 8])]);

        assert!(tpm.GetRandom(20).is_err());
        assert!(tpm.last_error().is_some());

        assert_eq!(tpm.GetRandom(8).unwrap(), vec![0xAB; 8]);
        assert_eq!(tpm.last_response_code(), TPM_RC::SUCCESS);
        assert!(
            tpm.last_error().is_none(),
            "a successful command must not leave the previous failure behind"
        );
    }

    // ---------------------------------------------------------------------------------------
    // TPM_RC_RETRY: the TPM was busy and did not act on the command.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn a_command_the_tpm_asks_to_retry_is_resent_and_can_succeed() {
        let (mut tpm, log) = tpm_with(vec![
            error_response(TPM_RC::RETRY.get_value()),
            get_random_response(&[0xAB; 8]),
        ]);

        // This used to be impossible: the retry path left `current_cmd_code` set, so the resend
        // failed with "Pending async command must be completed before issuing the next command."
        let out = tpm
            .GetRandom(8)
            .expect("a command the TPM asked to retry should be able to complete");
        assert_eq!(out, vec![0xAB; 8]);

        let commands = log.lock().unwrap();
        assert_eq!(
            commands.len(),
            2,
            "the command should have been resent once"
        );
        assert_eq!(
            commands[0], commands[1],
            "the resend should be the same command, byte for byte"
        );
    }

    #[test]
    fn a_tpm_that_never_stops_retrying_terminates_with_an_error() {
        let responses = (0..64)
            .map(|_| error_response(TPM_RC::RETRY.get_value()))
            .collect();
        let (mut tpm, log) = tpm_with(responses);

        let start = std::time::Instant::now();
        let err = tpm
            .GetRandom(8)
            .expect_err("an unending retry must not loop forever");
        let elapsed = start.elapsed();

        assert!(
            format!("{}", err).contains("RETRY"),
            "the caller should be told why: {}",
            err
        );
        assert_eq!(
            log.lock().unwrap().len() as u32,
            Tpm2::MAX_RETRIES + 1,
            "the command should be sent once and then retried a bounded number of times"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "a bounded backoff, not a flat second of blocking per attempt: {:?}",
            elapsed
        );
    }

    #[test]
    fn a_retried_command_with_a_password_session_is_resent_unchanged() {
        // The resend re-marshals the request, including the authorization area. A password
        // session has no nonce to roll and no HMAC to recompute, so its authorization area is a
        // constant and the second command is byte for byte the first. That is a property of
        // password sessions specifically -- see the HMAC session case below.
        let public = sample_public(0x77);
        let name = name_of(&public);
        let (mut tpm, log) = tpm_with(vec![
            error_response(TPM_RC::RETRY.get_value()),
            create_primary_response(&public, &name),
        ]);

        create_primary(&mut tpm, &public).expect("the resend should carry a valid authorization");

        let commands = log.lock().unwrap();
        assert_eq!(
            commands.len(),
            2,
            "the command should have been resent once"
        );
        assert_eq!(
            commands[0], commands[1],
            "the resend should be the same command, authorization area included"
        );
    }

    #[test]
    fn a_retried_command_with_an_hmac_session_rerolls_its_nonce_and_still_verifies() {
        // `dispatch_command` calls `roll_nonces` on every attempt, so a session with a real
        // nonce does not resend the same bytes: nonceCaller is fresh and the command HMAC is
        // recomputed over it. What has to survive the retry is not the encoding but the
        // authorization -- the second attempt must be one the TPM accepts, and its response must
        // still verify against the nonce that attempt actually sent.
        let session = make_session(TPM_SE::HMAC, SALT);
        let mut key = session.session_key.clone();
        key.extend_from_slice(LOCKOUT_AUTH);

        let (mut tpm, log) = tpm_with(vec![
            error_response(TPM_RC::RETRY.get_value()),
            correct_responder(vec![0xCC; 32], echo, key.clone()),
        ]);
        tpm.with_session(session);

        tpm.Clear(&TPM_HANDLE::new(TPM_RH::LOCKOUT.get_value()))
            .expect("the resent command and its response authorization must agree");

        let commands = log.lock().unwrap();
        assert_eq!(
            commands.len(),
            2,
            "the command should have been resent once"
        );
        assert_ne!(
            commands[0], commands[1],
            "a session with a nonce cannot resend the same bytes"
        );

        let first = parse_clear_command_auth(&commands[0]);
        let second = parse_clear_command_auth(&commands[1]);
        assert_ne!(
            first.nonce_caller, second.nonce_caller,
            "each attempt gets a fresh nonceCaller"
        );
        let name = TPM_RH::LOCKOUT.get_value().to_be_bytes().to_vec();
        assert_eq!(
            second.hmac,
            spec_command_hmac(
                &key,
                TPM_CC::Clear,
                &[name],
                &second.nonce_caller,
                &[0xBB; 32],
                second.attributes,
            ),
            "the retry's HMAC must be over the nonce the retry sent"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Object Names: a consistency check between the Name a command reports and the public area
    // that Name is a digest over. Not authentication, and no defence against an adversary who
    // supplies both -- see `Tpm2::update_resp_handle`.
    // ---------------------------------------------------------------------------------------

    /// A minimal keyed-hash public area, distinguished by its `unique` field so that two of them
    /// have different Names.
    fn sample_public(unique: u8) -> TPMT_PUBLIC {
        let parameters = TPMU_PUBLIC_PARMS::keyedHashDetail(TPMS_KEYEDHASH_PARMS::new(&Some(
            TPMU_SCHEME_KEYEDHASH::hmac(TPMS_SCHEME_HMAC {
                hashAlg: TPM_ALG_ID::SHA256,
            }),
        )));
        let unique = TPMU_PUBLIC_ID::keyedHash(TPM2B_DIGEST_KEYEDHASH {
            buffer: vec![unique; 32],
        });
        TPMT_PUBLIC::new(
            TPM_ALG_ID::SHA256,
            TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth,
            &Vec::new(),
            &Some(parameters),
            &Some(unique),
        )
    }

    fn name_of(public: &TPMT_PUBLIC) -> Vec<u8> {
        public.get_name(&SOFTWARE_PROVIDER).unwrap()
    }

    const OBJECT_HANDLE: u32 = 0x80000001;

    /// A `TPM2_LoadExternal` response: a transient object handle and the object's Name.
    fn load_external_response(name: &[u8]) -> MockResponse {
        let mut body = Vec::new();
        body.extend_from_slice(&OBJECT_HANDLE.to_be_bytes());
        body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        body.extend_from_slice(name);
        MockResponse::Canned(response(TPM_ST::NO_SESSIONS, 0, &body))
    }

    fn load_external(tpm: &mut Tpm2, public: &TPMT_PUBLIC) -> Result<TPM_HANDLE, TpmError> {
        tpm.LoadExternal(
            &TPMT_SENSITIVE::default(),
            public,
            &TPM_HANDLE::new(TPM_RH::NULL.get_value()),
        )
    }

    /// A `TPM2_CreatePrimary` response, authorized by the password session the client creates
    /// for the one auth handle: empty nonce, empty HMAC.
    fn create_primary_response(public: &TPMT_PUBLIC, name: &[u8]) -> MockResponse {
        let params = CreatePrimaryResponse {
            outPublic: public.clone(),
            creationHash: vec![0u8; 32],
            creationTicket: TPMT_TK_CREATION::new(
                &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
                &vec![0u8; 32],
            ),
            name: name.to_vec(),
            ..Default::default()
        };
        let params = params.toBytes().unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(&OBJECT_HANDLE.to_be_bytes());
        body.extend_from_slice(&(params.len() as u32).to_be_bytes());
        body.extend_from_slice(&params);
        body.extend_from_slice(&0u16.to_be_bytes()); // nonce
        body.push(TPMA_SESSION::continueSession.get_value());
        body.extend_from_slice(&0u16.to_be_bytes()); // hmac
        MockResponse::Canned(response(TPM_ST::SESSIONS, 0, &body))
    }

    fn create_primary(tpm: &mut Tpm2, public: &TPMT_PUBLIC) -> Result<TPM_HANDLE, TpmError> {
        tpm.CreatePrimary(
            &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
            &TPMS_SENSITIVE_CREATE::new(&Vec::new(), &Vec::new()),
            public,
            &Vec::new(),
            &Vec::new(),
        )
        .map(|resp| resp.handle)
    }

    #[test]
    fn create_primary_accepts_a_name_that_matches_the_public_area_it_returned() {
        let public = sample_public(0x11);
        let name = name_of(&public);
        let (mut tpm, _log) = tpm_with(vec![create_primary_response(&public, &name)]);

        let handle = create_primary(&mut tpm, &public)
            .expect("a Name consistent with outPublic must be accepted");
        assert_eq!(handle.get_name().unwrap(), name);
    }

    #[test]
    fn create_primary_rejects_a_name_that_disagrees_with_the_public_area_it_returned() {
        // The Name of a different public area: the inconsistency a malfunctioning TPM or
        // resource manager produces, and which used to be copied into the handle unexamined.
        let public = sample_public(0x11);
        let wrong_name = name_of(&sample_public(0x22));
        let (mut tpm, _log) = tpm_with(vec![create_primary_response(&public, &wrong_name)]);

        let err = create_primary(&mut tpm, &public)
            .expect_err("a Name that is not a digest over the returned public area is bogus");
        assert!(
            format!("{}", err).contains("consistency check"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn load_external_accepts_a_name_that_matches_the_public_area_it_was_given() {
        // TPM2_LoadExternal returns only a handle and a Name -- the public area was a command
        // input -- so the Name is checked against the caller's own `inPublic`.
        let public = sample_public(0x33);
        let name = name_of(&public);
        let (mut tpm, _log) = tpm_with(vec![load_external_response(&name)]);

        let handle = load_external(&mut tpm, &public).expect("a consistent Name must be accepted");
        assert_eq!(handle.get_name().unwrap(), name);
    }

    #[test]
    fn load_external_rejects_a_name_that_disagrees_with_the_public_area_it_was_given() {
        let public = sample_public(0x33);
        let wrong_name = name_of(&sample_public(0x44));
        let (mut tpm, _log) = tpm_with(vec![load_external_response(&wrong_name)]);

        let err = load_external(&mut tpm, &public)
            .expect_err("the TPM's Name must agree with the public area it was handed");
        assert!(
            format!("{}", err).contains("consistency check"),
            "unexpected error: {}",
            err
        );
    }

    /// A `TPM2_FlushContext` response: no handles, no parameters, no sessions.
    fn flush_context_response() -> MockResponse {
        MockResponse::Canned(response(TPM_ST::NO_SESSIONS, 0, &[]))
    }

    /// Assert that `cmd` is a `TPM2_FlushContext` for `handle`.
    ///
    /// `flushHandle` is a *parameter* of TPM2_FlushContext rather than a handle-area handle, so
    /// it follows the header directly: `tag ‖ commandSize ‖ commandCode ‖ flushHandle`.
    fn assert_flush_of(cmd: &[u8], handle: u32) {
        assert_eq!(
            be32(cmd, 6),
            TPM_CC::FlushContext.get_value(),
            "expected a TPM2_FlushContext"
        );
        assert_eq!(be32(cmd, 10), handle, "flushed the wrong handle");
        assert_eq!(cmd.len(), 14, "TPM2_FlushContext takes one handle value");
    }

    #[test]
    fn a_create_primary_name_is_checked_against_its_own_public_area() {
        // Two commands supply the public area a Name is checked against in opposite ways:
        // TPM2_LoadExternal takes it as an input, which the client captures at dispatch, while
        // TPM2_CreatePrimary returns it in the response. A CreatePrimary must be checked
        // against its own `outPublic` and never against a public area some earlier command
        // captured.
        //
        // The sequence below is the one that would expose the confusion: a LoadExternal that
        // captures `first`, then a command that supplies no public area at all, then a
        // CreatePrimary that returns `second` but reports the Name of `first`. If the captured
        // input area were what CreatePrimary compared the Name against, that response would be
        // accepted. Today `dispatch_command` overwrites the captured area on every command, so
        // this pins the rule rather than catching a live leak -- but the rule is what keeps a
        // Name check meaningful, and both halves of it (per-command capture, and the choice of
        // which area to compare against) have to hold for it to stay that way.
        let first = sample_public(0x55);
        let second = sample_public(0x66);
        let (mut tpm, log) = tpm_with(vec![
            load_external_response(&name_of(&first)),
            get_random_response(&[0xAB; 8]),
            create_primary_response(&second, &name_of(&first)),
            flush_context_response(),
        ]);

        load_external(&mut tpm, &first).expect("the load is consistent with its own public area");
        assert!(
            tpm.command_object_public.is_none(),
            "a captured input public area belongs to the command that supplied it and must not \
             outlive it"
        );

        tpm.GetRandom(8)
            .expect("a command that supplies no public area at all");
        assert!(
            tpm.command_object_public.is_none(),
            "a command that supplies no public area must leave none behind either"
        );

        let err = create_primary(&mut tpm, &second).expect_err(
            "the Name belongs to a public area this response did not return, so it is bogus",
        );
        assert!(
            format!("{}", err).contains("consistency check"),
            "unexpected error: {}",
            err
        );

        let commands = log.lock().unwrap();
        assert_eq!(commands.len(), 4, "the rejected object should be flushed");
        assert_flush_of(&commands[3], OBJECT_HANDLE);
    }

    #[test]
    fn an_object_whose_name_fails_the_consistency_check_is_flushed() {
        // TPM2_LoadExternal has already succeeded, so the TPM holds a transient object. Its
        // handle reaches no caller -- the Name check rejects the response -- so unless it is
        // flushed here it occupies a transient slot until the TPM is reset. A TPM reporting a
        // Name inconsistent with the public area it was handed is the last one to leave holding
        // an object nobody can name.
        let public = sample_public(0x33);
        let wrong_name = name_of(&sample_public(0x44));
        let (mut tpm, log) = tpm_with(vec![
            load_external_response(&wrong_name),
            flush_context_response(),
        ]);

        load_external(&mut tpm, &public).expect_err("the Name does not match the public area");

        let commands = log.lock().unwrap();
        assert_eq!(
            commands.len(),
            2,
            "the loaded object must be flushed, not abandoned"
        );
        assert_flush_of(&commands[1], OBJECT_HANDLE);
    }

    // ---------------------------------------------------------------------------------------
    // Sessions the TPM has loaded: what happens when the client will not use them.
    // ---------------------------------------------------------------------------------------

    const SESSION_HANDLE: u32 = 0x02000000;

    /// A `TPM2_StartAuthSession` response: the session handle and the TPM's nonce.
    fn start_auth_session_response(handle: u32, nonce_tpm: &[u8]) -> MockResponse {
        let mut body = Vec::new();
        body.extend_from_slice(&handle.to_be_bytes());
        body.extend_from_slice(&(nonce_tpm.len() as u16).to_be_bytes());
        body.extend_from_slice(nonce_tpm);
        MockResponse::Canned(response(TPM_ST::NO_SESSIONS, 0, &body))
    }

    #[test]
    fn a_session_the_client_refuses_to_build_is_flushed() {
        // TPM2_StartAuthSession has returned, so the TPM has allocated and loaded a session.
        // Only then does this client decide it will not build a `Session` from it: parameter
        // encryption was asked for on a session with no secret key material to key it with.
        // The handle is in the response and nowhere else, and a TPM typically has room for about
        // three loaded sessions, so dropping it here costs a slot until the next TPM reset.
        //
        // This is not a hypothetical path: `examples/tpm_samples.rs` provokes exactly this
        // refusal on every run to demonstrate it, and then loads two more sessions.
        let (mut tpm, log) = tpm_with(vec![
            start_auth_session_response(SESSION_HANDLE, &[0xBB; 32]),
            flush_context_response(),
        ]);

        let err = tpm
            .start_auth_session_full(
                TPM_SE::HMAC,
                TPM_ALG_ID::SHA256,
                TPMA_SESSION::continueSession | TPMA_SESSION::decrypt,
                TPMT_SYM_DEF::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            )
            .expect_err("an unsalted, unbound session cannot carry parameter encryption");
        assert!(
            format!("{}", err).contains("no secret key material"),
            "unexpected error: {}",
            err
        );

        let commands = log.lock().unwrap();
        assert_eq!(
            commands.len(),
            2,
            "the session the TPM loaded must be flushed, not abandoned"
        );
        assert_flush_of(&commands[1], SESSION_HANDLE);
    }

    #[test]
    fn a_flush_on_the_error_path_does_not_displace_the_error_that_caused_it() {
        // The flush is best effort and issued for its side effect on the TPM. Here the device
        // has no response left for it, so `FlushContext` fails -- and the caller must still be
        // told why the session was refused, not why the cleanup was.
        let (mut tpm, log) = tpm_with(vec![start_auth_session_response(
            SESSION_HANDLE,
            &[0xBB; 32],
        )]);

        let err = tpm
            .start_auth_session_full(
                TPM_SE::HMAC,
                TPM_ALG_ID::SHA256,
                TPMA_SESSION::continueSession | TPMA_SESSION::encrypt,
                TPMT_SYM_DEF::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            )
            .expect_err("the refusal stands whatever the cleanup does");
        assert!(
            format!("{}", err).contains("no secret key material"),
            "unexpected error: {}",
            err
        );
        assert_eq!(
            log.lock().unwrap().len(),
            2,
            "the flush should still have been attempted"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Session salt: sized by the salt key, not by the session.
    // ---------------------------------------------------------------------------------------

    /// A software stand-in for an RSA salt key: the private half, so the test can decrypt what
    /// the client encrypts, and a public area whose `nameAlg` the caller chooses.
    fn salt_key(name_alg: TPM_ALG_ID) -> (RsaPrivateKey, TrustedPublic) {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let parameters = TPMS_RSA_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            2048,
            65537,
        );
        let public = TPMT_PUBLIC {
            nameAlg: name_alg,
            parameters: Some(TPMU_PUBLIC_PARMS::rsaDetail(parameters)),
            unique: Some(TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA {
                buffer: private_key.n().to_bytes_be(),
            })),
            ..Default::default()
        };
        let trusted = TrustedPublic::assume_trusted(public, &SOFTWARE_PROVIDER).unwrap();
        (private_key, trusted)
    }

    /// The `encryptedSalt` parameter of a logged `TPM2_StartAuthSession`:
    /// `tag ‖ commandSize ‖ commandCode ‖ tpmKey ‖ bind ‖ nonceCaller ‖ encryptedSalt ‖ ...`
    fn encrypted_salt_of(cmd: &[u8]) -> Vec<u8> {
        let mut p = 2 + 4 + 4 + 4 + 4;
        let nonce_len = be16(cmd, p) as usize;
        p += 2 + nonce_len;
        let salt_len = be16(cmd, p) as usize;
        p += 2;
        cmd[p..p + salt_len].to_vec()
    }

    #[test]
    fn the_session_salt_is_sized_by_the_salt_keys_name_alg_not_by_the_session_hash() {
        // The TPM recovers the salt with OAEP under the salt *key's* nameAlg and then requires
        // what it recovered to be exactly that hash's digest size (TPM 2.0 Part 4,
        // `CryptSecretDecrypt`, which answers TPM_RC_VALUE on `encryptedSalt` otherwise). Sizing
        // the salt by the session hash instead is right only while the two happen to agree; a
        // SHA-1 salt key with a SHA-256 session sends 32 bytes where the TPM demands 20, and
        // every salted session against that key fails outright.
        //
        // The client cannot see the TPM's side of that check, so this test does what the TPM
        // does: decrypt the salt with the key's own private half and measure it.
        let (private_key, trusted) = salt_key(TPM_ALG_ID::SHA1);

        let (mut tpm, log) = tpm_with(vec![start_auth_session_response(
            SESSION_HANDLE,
            &[0xBB; 32],
        )]);
        tpm.start_salted_auth_session(
            &TPM_HANDLE::new(0x81000001),
            &trusted,
            TPM_SE::HMAC,
            TPM_ALG_ID::SHA256,
            TPMA_SESSION::continueSession,
            TPMT_SYM_DEF::default(),
        )
        .expect("a salted session over the mock device");

        let cmd = log.lock().unwrap()[0].clone();
        let salt = private_key
            .decrypt(
                Oaep::new_with_label::<Sha1, _>("SECRET\0"),
                &encrypted_salt_of(&cmd),
            )
            .expect("the salt is encrypted under the salt key's own nameAlg");

        assert_eq!(
            salt.len(),
            Crypto::digest_size_checked(TPM_ALG_ID::SHA1).unwrap(),
            "the salt must be the digest size of the salt key's nameAlg (SHA-1, 20 bytes), not \
             of the session hash (SHA-256, 32 bytes)"
        );
        assert_ne!(
            salt.len(),
            Crypto::digest_size_checked(TPM_ALG_ID::SHA256).unwrap(),
            "sizing the salt by the session hash is the regression this pins"
        );
    }
}

/// Round trips against the machine's own TPM, one per session category.
///
/// **These require hardware and are not CI coverage.** They are `#[ignore]`d and only run when
/// asked for by name, for example
/// `cargo test --locked hardware -- --ignored --test-threads=1`.
/// They use the local TBS device, create and flush transient objects under the owner hierarchy,
/// and will fail on a TPM whose owner hierarchy has a non-empty authValue.
///
/// Their purpose is the one thing a mock cannot serve: confirming that the command and response
/// authorization rules in this module agree with a real TPM's, for every session category those
/// rules distinguish between.
#[cfg(all(test, target_os = "windows", feature = "software-crypto"))]
mod hardware_tests {
    use super::*;
    use crate::crypto::software_provider::SOFTWARE_PROVIDER;
    use crate::device::TpmTbsDevice;
    use crate::policy::{PolicyAuthValue, PolicyPassword, PolicyPcr, PolicyTree};
    use crate::tpm_type_extensions::TrustedPublic;
    use crate::tpm_types::*;

    const OBJ_AUTH: &[u8] = b"object-auth";

    fn open_tpm() -> Tpm2 {
        let mut tpm = Tpm2::with_software_crypto(Box::new(TpmTbsDevice::new()));
        tpm.connect().expect("no local TPM available");
        tpm
    }

    /// A keyed-hash primary under the owner hierarchy carrying `policy`, with `userWithAuth` so
    /// that the authValue paths are exercised too.
    fn make_primary(tpm: &mut Tpm2, policy: &[u8]) -> Result<TPM_HANDLE, TpmError> {
        let attrs = TPMA_OBJECT::sign
            | TPMA_OBJECT::fixedParent
            | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::userWithAuth;
        let parameters = TPMU_PUBLIC_PARMS::keyedHashDetail(TPMS_KEYEDHASH_PARMS::new(&Some(
            TPMU_SCHEME_KEYEDHASH::hmac(TPMS_SCHEME_HMAC {
                hashAlg: TPM_ALG_ID::SHA256,
            }),
        )));
        let unique = TPMU_PUBLIC_ID::keyedHash(TPM2B_DIGEST_KEYEDHASH::default());
        let templ = TPMT_PUBLIC::new(
            TPM_ALG_ID::SHA256,
            attrs,
            &policy.to_vec(),
            &Some(parameters),
            &Some(unique),
        );
        let sens = TPMS_SENSITIVE_CREATE::new(&OBJ_AUTH.to_vec(), &vec![5, 4, 3, 2, 1, 0]);
        let resp = tpm.CreatePrimary(
            &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
            &sens,
            &templ,
            &Default::default(),
            &Default::default(),
        )?;
        let mut handle = resp.handle;
        handle.set_auth(OBJ_AUTH);
        Ok(handle)
    }

    /// An RSA storage primary, used where a salt key is needed.
    fn make_storage_primary(tpm: &mut Tpm2) -> Result<TPM_HANDLE, TpmError> {
        let attrs = TPMA_OBJECT::decrypt
            | TPMA_OBJECT::restricted
            | TPMA_OBJECT::fixedParent
            | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::sensitiveDataOrigin
            | TPMA_OBJECT::userWithAuth;
        let parameters = TPMU_PUBLIC_PARMS::rsaDetail(TPMS_RSA_PARMS::new(
            &TPMT_SYM_DEF_OBJECT::new(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
            // A restricted decryption key must carry the NULL asymmetric scheme; an RSASSA
            // scheme here is rejected by the TPM.
            &Some(TPMU_ASYM_SCHEME::null(TPMS_NULL_ASYM_SCHEME::default())),
            2048,
            65537,
        ));
        let unique = TPMU_PUBLIC_ID::rsa(TPM2B_PUBLIC_KEY_RSA::default());
        let templ = TPMT_PUBLIC::new(
            TPM_ALG_ID::SHA256,
            attrs,
            &Vec::new(),
            &Some(parameters),
            &Some(unique),
        );
        let resp = tpm.CreatePrimary(
            &TPM_HANDLE::new(TPM_RH::OWNER.get_value()),
            &TPMS_SENSITIVE_CREATE::new(&Vec::new(), &Vec::new()),
            &templ,
            &Default::default(),
            &Default::default(),
        )?;
        Ok(resp.handle)
    }

    /// The exchange every case below runs: one authorized command, so that both the command and
    /// the response authorization for this session category are exercised end to end.
    fn authorized_round_trip(tpm: &mut Tpm2, handle: &TPM_HANDLE, session: Session) {
        let out = tpm
            .with_session(session)
            .HMAC(handle, &vec![1, 2, 3, 4], TPM_ALG_ID::SHA256)
            .expect("authorized command should succeed and its response should verify");
        assert_eq!(out.len(), 32);
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_pwap_session_round_trip() {
        let mut tpm = open_tpm();
        let handle = make_primary(&mut tpm, &[]).unwrap();
        authorized_round_trip(&mut tpm, &handle, Session::pw(Some(OBJ_AUTH.to_vec())));
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_salted_hmac_session_round_trip() {
        let mut tpm = open_tpm();
        let handle = make_primary(&mut tpm, &[]).unwrap();
        let salt_key = make_storage_primary(&mut tpm).unwrap();

        // The salt key is one this process just created, so `assume_trusted` is the honest
        // constructor: there is no channel between us and it for anyone to be in the middle of.
        let public = tpm.ReadPublic(&salt_key).unwrap().outPublic;
        let trusted = TrustedPublic::assume_trusted(public, &SOFTWARE_PROVIDER).unwrap();

        let session = tpm
            .start_salted_auth_session(
                &salt_key,
                &trusted,
                TPM_SE::HMAC,
                TPM_ALG_ID::SHA256,
                TPMA_SESSION::continueSession,
                TPMT_SYM_DEF::default(),
            )
            .unwrap();
        assert!(session.has_secret_key_material());
        let sess_handle = session.sess_in.sessionHandle.clone();
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&salt_key).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_bound_hmac_session_round_trip() {
        let mut tpm = open_tpm();
        let handle = make_primary(&mut tpm, &[]).unwrap();

        let session = tpm
            .start_auth_session_ex(
                None,
                &handle,
                TPM_SE::HMAC,
                TPM_ALG_ID::SHA256,
                TPMA_SESSION::continueSession,
                TPMT_SYM_DEF::default(),
            )
            .unwrap();
        assert!(
            session.has_secret_key_material(),
            "binding to an entity with a non-empty authValue does give the session a secret"
        );
        let sess_handle = session.sess_in.sessionHandle.clone();
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_policy_auth_value_session_round_trip() {
        let mut tpm = open_tpm();
        let tree = PolicyTree::new().add(PolicyAuthValue::new());
        let digest = tree
            .get_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256)
            .unwrap();

        let handle = make_primary(&mut tpm, &digest).unwrap();
        let session = tpm
            .start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)
            .unwrap();
        let sess_handle = session.sess_in.sessionHandle.clone();
        let session = tree.execute(&mut tpm, session).unwrap();
        assert!(session.expects_response_auth());
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_policy_password_session_round_trip() {
        let mut tpm = open_tpm();
        let tree = PolicyTree::new().add(PolicyPassword::new());
        let digest = tree
            .get_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256)
            .unwrap();

        let handle = make_primary(&mut tpm, &digest).unwrap();
        let session = tpm
            .start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)
            .unwrap();
        let sess_handle = session.sess_in.sessionHandle.clone();
        let session = tree.execute(&mut tpm, session).unwrap();
        // The one category that must NOT expect a response authorization.
        assert!(!session.expects_response_auth());
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }

    #[test]
    #[ignore = "requires a local TPM"]
    fn hardware_policy_pcr_session_round_trip() {
        let mut tpm = open_tpm();
        // `pcrSelect` is a bitmap and must be at least PCR_SELECT_MIN (3) bytes; a one-byte,
        // all-zero selection both undersizes the field and names no PCR at all.
        let selection = TPMS_PCR_SELECTION::new_from_pcr_u32(TPM_ALG_ID::SHA256, 0).unwrap();
        let read = tpm.PCR_Read(&vec![selection.clone()]).unwrap();

        let tree = PolicyTree::new().add(PolicyPcr::new(read.pcrValues.clone(), vec![selection]));
        let digest = tree
            .get_policy_digest(&SOFTWARE_PROVIDER, TPM_ALG_ID::SHA256)
            .unwrap();

        let handle = make_primary(&mut tpm, &digest).unwrap();
        let session = tpm
            .start_auth_session(TPM_SE::POLICY, TPM_ALG_ID::SHA256)
            .unwrap();
        let sess_handle = session.sess_in.sessionHandle.clone();
        let session = tree.execute(&mut tpm, session).unwrap();
        // A policy session with neither PolicyAuthValue nor PolicyPassword: the TPM still
        // authenticates the response, and this client must check it. This is the category the
        // old rule skipped.
        assert!(session.expects_response_auth());
        authorized_round_trip(&mut tpm, &handle, session);

        tpm.FlushContext(&sess_handle).unwrap();
        tpm.FlushContext(&handle).unwrap();
    }
}

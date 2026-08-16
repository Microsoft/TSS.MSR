/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

//! TPM device communication implementations

use crate::error::TpmError;

#[cfg(target_os = "windows")]
use std::os::raw::c_void;
#[cfg(target_os = "windows")]
use std::ptr;
// The `Win32_System_TpmBaseServices` feature of the `windows` crate is only requested for Windows
// targets, so this module does not exist anywhere else.
#[cfg(target_os = "windows")]
use windows::Win32::System::TpmBaseServices::*;

#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::net::TcpStream;
#[cfg(target_os = "linux")]
use std::time::Duration;

/// Defines the TPM connection information flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TpmConnInfo {
    /// Platform hierarchy is enabled, and hardware platform functionality is available
    TpmPlatformAvailable = 0x01,
    /// Connection represents a TPM Resource Manager (TRM)
    TpmUsesTrm = 0x02,
    /// The TRM is in raw mode
    TpmInRawMode = 0x04,
    /// Physical presence signals are supported
    TpmSupportsPP = 0x08,
    /// System and TPM power control signals are not supported
    TpmNoPowerCtl = 0x10,
    /// TPM locality cannot be changed
    TpmNoLocalityCtl = 0x20,
    /// Connection medium is socket
    TpmSocketConn = 0x1000,
    /// Connection medium is OS/platform specific handle
    TpmTbsConn = 0x2000,
    /// Socket connection to old version of Intel's user mode TRM on Linux
    TpmLinuxOldUserModeTrm = 0x4000,
    /// Connection via TCG compliant TCTI connection interface
    TpmTctiConn = 0x8000,
}

/// Commands for TCP communication with TPM simulator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TcpTpmCommand {
    SignalPowerOn = 1,
    SignalPowerOff = 2,
    SignalPPOn = 3,
    SignalPPOff = 4,
    SignalHashStart = 5,
    SignalHashData = 6,
    SignalHashEnd = 7,
    SendCommand = 8,
    SignalCancelOn = 9,
    SignalCancelOff = 10,
    SignalNvOn = 11,
    SignalNvOff = 12,
    SignalKeyCacheOn = 13,
    SignalKeyCacheOff = 14,
    RemoteHandshake = 15,
    SetAlternativeResult = 16,
    SessionEnd = 20,
    Stop = 21,
    TestFailureMode = 30,
}

/// Main trait for TPM devices
pub trait TpmDevice {
    /// Connect to the TPM device
    fn connect(&mut self) -> Result<bool, TpmError>;

    /// Close the connection to the TPM device
    fn close(&mut self);

    /// Dispatch a command to the TPM
    fn dispatch_command(&mut self, cmd_buf: &[u8]) -> Result<(), TpmError>;

    /// Get a response from the TPM
    fn get_response(&mut self) -> Result<Vec<u8>, TpmError>;

    /// Check if a response is ready
    fn response_is_ready(&self) -> Result<bool, TpmError>;

    /// Power control
    fn power_ctl(&mut self, _on: bool) -> Result<(), TpmError> {
        Err(TpmError::NotSupported("power_ctl".to_string()))
    }

    /// Assert physical presence
    fn assert_physical_presence(&mut self, _on: bool) -> Result<(), TpmError> {
        Err(TpmError::NotSupported(
            "assert_physical_presence".to_string(),
        ))
    }

    /// Set locality for subsequent commands
    fn set_locality(&mut self, _locality: u32) -> Result<(), TpmError> {
        Err(TpmError::NotSupported("set_locality".to_string()))
    }

    /// Check if platform is available
    fn platform_available(&self) -> bool {
        false
    }

    /// Check if power control is available
    fn power_ctl_available(&self) -> bool {
        self.platform_available() && !self.has_flag(TpmConnInfo::TpmNoPowerCtl as u32)
    }

    /// Check if locality control is available
    fn locality_ctl_available(&self) -> bool {
        self.platform_available() && !self.has_flag(TpmConnInfo::TpmNoLocalityCtl as u32)
    }

    /// Check if physical presence can be asserted
    fn implements_physical_presence(&self) -> bool {
        self.has_flag(TpmConnInfo::TpmSupportsPP as u32)
    }

    /// Power on convenience method
    fn power_on(&mut self) -> Result<(), TpmError> {
        self.power_ctl(true)
    }

    /// Power off convenience method
    fn power_off(&mut self) -> Result<(), TpmError> {
        self.power_ctl(false)
    }

    /// Power cycle convenience method
    fn power_cycle(&mut self) -> Result<(), TpmError> {
        self.power_ctl(false)?;
        self.power_ctl(true)
    }

    /// Physical presence on convenience method
    fn pp_on(&mut self) -> Result<(), TpmError> {
        self.assert_physical_presence(true)
    }

    /// Physical presence off convenience method
    fn pp_off(&mut self) -> Result<(), TpmError> {
        self.assert_physical_presence(false)
    }

    /// Check if a specific flag is set in TpmInfo
    fn has_flag(&self, flag: u32) -> bool;

    /// Get the TpmInfo flags
    fn get_tpm_info(&self) -> u32;
}

/// How a [`TbsContext`] closes the handle it owns.
///
/// The close is reached through a function pointer rather than called directly so that the unit
/// tests, which wrap handles TBS has never issued, can substitute a recorder for that one handle
/// instead of compiling the close out of the whole build. Every context TBS did issue carries
/// [`tbs_context_close`] and is therefore closed for real, in test builds as well as in
/// production ones.
#[cfg(target_os = "windows")]
type TbsCloseFn = unsafe fn(*mut c_void) -> u32;

/// Closes a TBS context. The default [`TbsCloseFn`] of every [`TbsContext`].
///
/// # Safety
///
/// `handle` must be a context returned by a successful `Tbsi_Context_Create` that has not been
/// closed already.
#[cfg(target_os = "windows")]
unsafe fn tbs_context_close(handle: *mut c_void) -> u32 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { Tbsip_Context_Close(handle) }
}

/// A TBS (TPM Base Services) context handle together with its ownership.
///
/// Keeping the handle and the ownership flag in one type means the two cannot drift apart, and it
/// gives the handle a [`Drop`] of its own: an owned context is closed as soon as the value holding
/// it goes away, including on an early return or an unwind. A borrowed context is never closed.
#[cfg(target_os = "windows")]
struct TbsContext {
    handle: *mut c_void,
    owned: bool,
    /// Applied to `handle` on drop when `owned`. Both constructors set the real TBS close; only a
    /// unit test, hand-building a context over a handle of its own, substitutes anything else.
    close: TbsCloseFn,
}

#[cfg(target_os = "windows")]
impl TbsContext {
    /// Opens a new TBS context. The returned value owns it and closes it on drop.
    fn create() -> Result<Self, TpmError> {
        let mut params = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            ..Default::default()
        };
        params.Anonymous.Anonymous._bitfield = 4;
        params.Anonymous.asUINT32 = 4;

        let mut handle: *mut c_void = ptr::null_mut();
        // SAFETY: `params` is a fully initialized TBS_CONTEXT_PARAMS2 whose `version` field marks
        // it as the version-two layout TBS expects behind the TBS_CONTEXT_PARAMS pointer, and
        // `handle` is a live local that TBS only writes to. Both pointers outlive the call.
        let res = unsafe {
            Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                &mut handle,
            )
        };

        if res != TBS_SUCCESS {
            return Err(TpmError::TbsError(format!(
                "Failed to connect to TBS: {:?}",
                res
            )));
        }
        if handle.is_null() {
            return Err(TpmError::TbsError(
                "TBS reported success but returned no context".to_string(),
            ));
        }

        Ok(Self {
            handle,
            owned: true,
            close: tbs_context_close,
        })
    }

    /// Wraps a context owned by the caller. The returned value never closes it.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid TBS context that outlives the returned value.
    unsafe fn borrowed(handle: *mut c_void) -> Result<Self, TpmError> {
        if handle.is_null() {
            return Err(TpmError::InvalidParameter);
        }

        Ok(Self {
            handle,
            owned: false,
            close: tbs_context_close,
        })
    }

    fn handle(&self) -> *mut c_void {
        self.handle
    }
}

#[cfg(target_os = "windows")]
impl Drop for TbsContext {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }

        // SAFETY: `handle` came from a successful `Tbsi_Context_Create` in `create`, the only
        // constructor that sets `owned` on a context carrying the real close; a context carrying
        // any other close came from a unit test that built it over a handle of its own.
        // `TbsContext` is neither `Clone` nor `Copy`, so this is the only value holding that
        // handle, and `Drop` runs at most once - meeting the TBS requirement of exactly one close
        // per created context.
        unsafe {
            (self.close)(self.handle);
        }
    }
}

/// The [`TbsCloseFn`] the unit tests substitute for handles TBS has never issued: it records the
/// close and touches nothing.
#[cfg(all(test, target_os = "windows"))]
mod tbs_close_log {
    use std::cell::Cell;
    use std::os::raw::c_void;

    thread_local! {
        static CLOSES: Cell<usize> = const { Cell::new(0) };
    }

    /// # Safety
    ///
    /// None: `handle` is never dereferenced, and no TBS call is made. The signature exists only
    /// to match [`super::TbsCloseFn`].
    pub(super) unsafe fn record_close(_handle: *mut c_void) -> u32 {
        CLOSES.with(|closes| closes.set(closes.get() + 1));
        super::TBS_SUCCESS
    }

    pub(super) fn count() -> usize {
        CLOSES.with(|closes| closes.get())
    }
}

// Windows TBS (TPM Base Services) implementation
#[cfg(target_os = "windows")]
pub struct TpmTbsDevice {
    context: Option<TbsContext>,
    result_buffer: [u8; 4096],
    res_size: u32,
    tpm_info: u32,
}

#[cfg(target_os = "windows")]
impl Default for TpmTbsDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
impl TpmTbsDevice {
    pub fn new() -> Self {
        TpmTbsDevice {
            context: None,
            result_buffer: [0; 4096],
            res_size: 0,
            tpm_info: 0,
        }
    }

    /// Creates a TPM device that submits commands through a caller-owned TBS context.
    ///
    /// The context is borrowed: it is closed neither by [`TpmDevice::close`] nor when the device
    /// is dropped. A context opened by [`TpmDevice::connect`], by contrast, is owned by the device
    /// and is closed by either.
    ///
    /// # Safety
    ///
    /// `context` must be a valid TBS context and must remain valid until this device is closed or
    /// dropped. The caller must synchronize any other use of the context.
    pub unsafe fn from_borrowed_context(context: *mut c_void) -> Result<Self, TpmError> {
        // SAFETY: forwarded from this function's own contract.
        let context = unsafe { TbsContext::borrowed(context) }?;

        Ok(Self {
            context: Some(context),
            result_buffer: [0; 4096],
            res_size: 0,
            tpm_info: TpmConnInfo::TpmTbsConn as u32,
        })
    }
}

#[cfg(target_os = "windows")]
impl TpmDevice for TpmTbsDevice {
    fn connect(&mut self) -> Result<bool, TpmError> {
        if self.context.is_some() {
            return Ok(true); // Already connected
        }

        // Held locally until the device is known to be usable: every early return below drops it,
        // which closes the context.
        let context = TbsContext::create()?;

        // Get device info to check if TPM 2.0 is available
        let mut info = TPM_DEVICE_INFO::default();
        // SAFETY: the size passed is the size of the very buffer being passed, `info` is live for
        // the duration of the call, and TBS only writes to it.
        let res = unsafe {
            Tbsi_GetDeviceInfo(
                std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
                &mut info as *mut _ as *mut c_void,
            )
        };

        if res != TBS_SUCCESS {
            return Err(TpmError::TbsError("Failed to get device info".to_string()));
        } else if info.tpmVersion != TPM_VERSION_20 {
            return Err(TpmError::TbsError(
                "Platform does not contain a TPM 2.0".to_string(),
            ));
        }

        self.context = Some(context);

        // Set appropriate flags
        self.tpm_info = TpmConnInfo::TpmTbsConn as u32;

        Ok(true)
    }

    fn close(&mut self) {
        // Dropping the context closes it, but only if this device owns it.
        self.context = None;
        self.res_size = 0;
        self.tpm_info = 0;
    }

    fn dispatch_command(&mut self, cmd_buf: &[u8]) -> Result<(), TpmError> {
        // Copied out so that the rest of the method can borrow `self` mutably.
        let context = match &self.context {
            Some(context) => context.handle(),
            None => return Err(TpmError::NotConnected),
        };

        // Reset result buffer size
        self.res_size = self.result_buffer.len() as u32;

        // Submit command to TBS
        // SAFETY: `context` is a live TBS context (dropping the device or calling `close` clears
        // `self.context`, so it cannot outlive its close). `result_buffer` and `res_size` are
        // fields of `self`, borrowed mutably here and so not aliased, and `res_size` is set to the
        // buffer's true length just above, which is what bounds what TBS writes.
        let res = unsafe {
            Tbsip_Submit_Command(
                context,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                cmd_buf,
                self.result_buffer.as_mut_ptr(),
                &mut self.res_size as *mut u32,
            )
        };

        if res != TBS_SUCCESS {
            return Err(TpmError::TbsError(format!(
                "TBS SubmitCommand error: 0x{:08x}",
                res
            )));
        }

        Ok(())
    }

    fn get_response(&mut self) -> Result<Vec<u8>, TpmError> {
        if self.res_size == 0 {
            return Err(TpmError::NoResponse);
        }

        // TBS wrote this length, and it is bounded by the buffer length handed to it, but the
        // clamp costs nothing and keeps a wrong length from panicking here.
        let res_size = (self.res_size as usize).min(self.result_buffer.len());
        let resp = self.result_buffer[0..res_size].to_vec();
        self.res_size = 0;

        Ok(resp)
    }

    fn response_is_ready(&self) -> Result<bool, TpmError> {
        if self.context.is_none() {
            return Err(TpmError::NotConnected);
        }

        if self.res_size == 0 {
            return Err(TpmError::UnexpectedState);
        }

        // For Windows TBS, the response is always ready after dispatch_command
        Ok(true)
    }

    fn has_flag(&self, flag: u32) -> bool {
        (self.tpm_info & flag) != 0
    }

    fn get_tpm_info(&self) -> u32 {
        self.tpm_info
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use std::ptr::NonNull;

    use super::*;

    /// A pointer that is never dereferenced: the tests below only ever check whether it is
    /// carried around and whether a close was attempted on it.
    fn fake_context() -> *mut c_void {
        NonNull::<c_void>::dangling().as_ptr()
    }

    fn owned_device(context: *mut c_void) -> TpmTbsDevice {
        TpmTbsDevice {
            context: Some(TbsContext {
                handle: context,
                owned: true,
                // The handle above is not a TBS context, so it must not reach TBS. This is the
                // only place that substitutes anything for the real close.
                close: tbs_close_log::record_close,
            }),
            result_buffer: [0; 4096],
            res_size: 0,
            tpm_info: TpmConnInfo::TpmTbsConn as u32,
        }
    }

    /// The substitution above is confined to contexts a test builds by hand: anything TBS itself
    /// issued goes through a constructor, and a constructor always installs the real close.
    #[test]
    fn constructed_contexts_close_through_tbs() {
        let context = unsafe { TbsContext::borrowed(fake_context()) }.unwrap();

        assert!(std::ptr::fn_addr_eq(
            context.close,
            tbs_context_close as TbsCloseFn
        ));
    }

    #[test]
    fn borrowed_context_rejects_null() {
        let result = unsafe { TpmTbsDevice::from_borrowed_context(ptr::null_mut()) };
        assert!(matches!(result, Err(TpmError::InvalidParameter)));
    }

    #[test]
    fn borrowed_context_is_not_owned() {
        let context = fake_context();
        let device = unsafe { TpmTbsDevice::from_borrowed_context(context) }.unwrap();

        let held = device.context.as_ref().unwrap();
        assert_eq!(held.handle(), context);
        assert!(!held.owned);
    }

    #[test]
    fn borrowed_context_is_not_closed_on_drop() {
        let closes = tbs_close_log::count();

        let device = unsafe { TpmTbsDevice::from_borrowed_context(fake_context()) }.unwrap();
        drop(device);

        assert_eq!(tbs_close_log::count(), closes);
    }

    #[test]
    fn borrowed_context_is_not_closed_by_close() {
        let closes = tbs_close_log::count();

        let mut device = unsafe { TpmTbsDevice::from_borrowed_context(fake_context()) }.unwrap();
        device.close();

        assert_eq!(tbs_close_log::count(), closes);
        assert!(device.context.is_none());
        assert_eq!(device.get_tpm_info(), 0);
    }

    #[test]
    fn owned_context_is_closed_on_drop() {
        let closes = tbs_close_log::count();

        let device = owned_device(fake_context());
        drop(device);

        assert_eq!(tbs_close_log::count(), closes + 1);
    }

    #[test]
    fn owned_context_is_closed_by_close() {
        let closes = tbs_close_log::count();

        let mut device = owned_device(fake_context());
        device.close();

        assert_eq!(tbs_close_log::count(), closes + 1);
        assert!(device.context.is_none());
        assert_eq!(device.get_tpm_info(), 0);

        // Dropping the already-closed device must not close a second time.
        drop(device);
        assert_eq!(tbs_close_log::count(), closes + 1);
    }

    #[test]
    fn disconnected_device_rejects_commands() {
        let mut device = TpmTbsDevice::new();

        assert!(matches!(
            device.dispatch_command(&[0u8; 12]),
            Err(TpmError::NotConnected)
        ));
        assert!(matches!(
            device.response_is_ready(),
            Err(TpmError::NotConnected)
        ));
    }
}

// Linux TPM device implementation
#[cfg(target_os = "linux")]
pub struct TpmTbsDevice {
    dev_tpm: Option<File>,
    socket: Option<TcpStream>,
    tpm_info: u32,
}

/// Upper bound on the size of a response frame accepted from a socket peer.
///
/// The length prefix of a socket response is attacker-controlled, so it is checked against this
/// bound before it is used to size an allocation. The value is the reference implementation's
/// `MAX_RESPONSE_SIZE`, which is also the fixed buffer the `/dev/tpm*` path reads into.
#[cfg(target_os = "linux")]
const MAX_SOCKET_RESPONSE_SIZE: usize =
    crate::tpm_types::Implementation::MAX_RESPONSE_SIZE.0 as usize;

/// How long a single socket read or write may block before it is failed.
///
/// Without this a wedged peer holds the calling thread forever.
#[cfg(target_os = "linux")]
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
impl Default for TpmTbsDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl TpmTbsDevice {
    pub fn new() -> Self {
        TpmTbsDevice {
            dev_tpm: None,
            socket: None,
            tpm_info: 0,
        }
    }

    fn connect_to_linux_user_mode_trm(&mut self) -> Result<bool, TpmError> {
        use std::path::Path;

        // Check if TRM libraries exist
        let old_trm = Path::new("/usr/lib/x86_64-linux-gnu/libtctisocket.so.0").exists()
            || Path::new("/usr/lib/i386-linux-gnu/libtctisocket.so.0").exists();

        let new_trm = Path::new("/usr/lib/x86_64-linux-gnu/libtcti-socket.so.0").exists()
            || Path::new("/usr/lib/i386-linux-gnu/libtcti-socket.so.0").exists()
            || Path::new("/usr/local/lib/libtss2-tcti-tabrmd.so.0").exists();

        if !(old_trm || new_trm) {
            return Ok(false);
        }

        // Connect to user mode TRM
        let socket = TcpStream::connect("127.0.0.1:2323")
            .map_err(|e| TpmError::IoError(format!("Failed to connect to user TRM: {}", e)))?;
        socket
            .set_read_timeout(Some(SOCKET_TIMEOUT))
            .map_err(|e| TpmError::IoError(format!("Failed to set read timeout: {}", e)))?;
        socket
            .set_write_timeout(Some(SOCKET_TIMEOUT))
            .map_err(|e| TpmError::IoError(format!("Failed to set write timeout: {}", e)))?;

        // No handshake needed with user mode TRM

        self.socket = Some(socket);
        self.tpm_info = TpmConnInfo::TpmSocketConn as u32
            | TpmConnInfo::TpmUsesTrm as u32
            | TpmConnInfo::TpmNoPowerCtl as u32
            | TpmConnInfo::TpmNoLocalityCtl as u32;

        if old_trm {
            self.tpm_info |= TpmConnInfo::TpmLinuxOldUserModeTrm as u32;
        }

        Ok(true)
    }
}

#[cfg(target_os = "linux")]
impl TpmDevice for TpmTbsDevice {
    fn connect(&mut self) -> Result<bool, TpmError> {
        // Connectedness is the presence of the handle commands travel over, which is the same
        // test the Windows implementation makes on its TBS context. `tpm_info` describes a
        // connection; it is not the connection itself.
        if self.dev_tpm.is_some() || self.socket.is_some() {
            return Ok(true); // Already connected
        }

        // Try to open the direct TPM device
        if let Ok(file) = OpenOptions::new().read(true).write(true).open("/dev/tpm0") {
            self.dev_tpm = Some(file);
            self.tpm_info = TpmConnInfo::TpmTbsConn as u32
                | TpmConnInfo::TpmNoPowerCtl as u32
                | TpmConnInfo::TpmNoLocalityCtl as u32;
            return Ok(true);
        }

        // Try TPM resource manager
        if let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tpmrm0")
        {
            self.dev_tpm = Some(file);
            self.tpm_info = TpmConnInfo::TpmTbsConn as u32
                | TpmConnInfo::TpmUsesTrm as u32
                | TpmConnInfo::TpmNoPowerCtl as u32
                | TpmConnInfo::TpmNoLocalityCtl as u32;
            return Ok(true);
        }

        // Try user mode TRM
        self.connect_to_linux_user_mode_trm()
    }

    fn close(&mut self) {
        self.dev_tpm = None;
        self.socket = None;
        self.tpm_info = 0;
    }

    fn dispatch_command(&mut self, cmd_buf: &[u8]) -> Result<(), TpmError> {
        if self.tpm_info & (TpmConnInfo::TpmSocketConn as u32) != 0 {
            // Socket-based communication
            if let Some(socket) = self.socket.as_mut() {
                // Send command to the TPM
                let mut buf = vec![];

                // Command header
                buf.extend_from_slice(&(TcpTpmCommand::SendCommand as u32).to_be_bytes());
                buf.push(0); // locality
                buf.extend_from_slice(&(cmd_buf.len() as u32).to_be_bytes());

                if self.tpm_info & (TpmConnInfo::TpmLinuxOldUserModeTrm as u32) != 0 {
                    buf.push(0); // debugMsgLevel
                    buf.push(1); // commandSent
                }

                // Send header and command buffer
                socket
                    .write_all(&buf)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;
                socket
                    .write_all(cmd_buf)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;

                Ok(())
            } else {
                Err(TpmError::NotConnected)
            }
        } else if self.tpm_info & (TpmConnInfo::TpmTbsConn as u32) != 0 {
            // TPM device file communication
            if let Some(dev) = self.dev_tpm.as_mut() {
                // Write command to TPM device
                match dev.write_all(cmd_buf) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(TpmError::IoError(format!(
                        "Failed to write TPM command: {}",
                        e
                    ))),
                }
            } else {
                Err(TpmError::NotConnected)
            }
        } else {
            Err(TpmError::InvalidTpmType)
        }
    }

    fn get_response(&mut self) -> Result<Vec<u8>, TpmError> {
        if self.tpm_info & (TpmConnInfo::TpmSocketConn as u32) != 0 {
            // Socket-based communication
            if let Some(socket) = self.socket.as_mut() {
                // Receive array length
                let mut len_buf = [0u8; 4];
                socket
                    .read_exact(&mut len_buf)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;
                let len = u32::from_be_bytes(len_buf) as usize;

                // The peer chooses this length, so refuse to allocate on its word alone.
                if len > MAX_SOCKET_RESPONSE_SIZE {
                    return Err(TpmError::IoError(format!(
                        "TPM response of {} bytes exceeds the {} byte maximum",
                        len, MAX_SOCKET_RESPONSE_SIZE
                    )));
                }

                // Read the response data
                let mut resp = vec![0u8; len];
                socket
                    .read_exact(&mut resp)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;

                // Get the terminating ACK
                let mut ack_buf = [0u8; 4];
                socket
                    .read_exact(&mut ack_buf)
                    .map_err(|e| TpmError::IoError(e.to_string()))?;
                let ack = u32::from_be_bytes(ack_buf);

                if ack != 0 {
                    return Err(TpmError::BadEndTag);
                }

                Ok(resp)
            } else {
                Err(TpmError::NotConnected)
            }
        } else if self.tpm_info & (TpmConnInfo::TpmTbsConn as u32) != 0 {
            // TPM device file communication
            if let Some(dev) = self.dev_tpm.as_mut() {
                // Buffer for response
                let mut resp_buf = [0u8; 4096];

                // Read from TPM device
                match dev.read(&mut resp_buf) {
                    Ok(bytes_read) => {
                        if bytes_read < 10 {
                            // 10 is the mandatory response header size
                            return Err(TpmError::IoError(format!(
                                "Failed to read sufficient data from TPM: got {} bytes",
                                bytes_read
                            )));
                        }

                        Ok(resp_buf[0..bytes_read].to_vec())
                    }
                    Err(e) => Err(TpmError::IoError(format!(
                        "Failed to read TPM response: {}",
                        e
                    ))),
                }
            } else {
                Err(TpmError::NotConnected)
            }
        } else {
            Err(TpmError::InvalidTpmType)
        }
    }

    fn response_is_ready(&self) -> Result<bool, TpmError> {
        // For Linux implementations, the response is typically ready after a blocking read
        Ok(true)
    }

    fn has_flag(&self, flag: u32) -> bool {
        (self.tpm_info & flag) != 0
    }

    fn get_tpm_info(&self) -> u32 {
        self.tpm_info
    }
}

// Placeholder implementation for platforms with no system TPM interface of their own.
//
// Windows reaches its TPM through TBS and Linux through `/dev/tpm*` or a user-mode resource
// manager; nothing equivalent is implemented for macOS or the BSDs. Rather than leave the crate
// without a `TpmTbsDevice` there - which fails to build with an error that points at the wrong
// place - the type exists everywhere and reports the platform as unsupported at run time. Callers
// on such a platform can still drive a TPM by passing their own [`TpmDevice`] to `Tpm2::new`.
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub struct TpmTbsDevice;

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
impl Default for TpmTbsDevice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
impl TpmTbsDevice {
    pub fn new() -> Self {
        TpmTbsDevice
    }

    fn unsupported<T>(operation: &str) -> Result<T, TpmError> {
        Err(TpmError::NotSupported(format!(
            "{}: this platform has no built-in TPM device; supply a TpmDevice implementation",
            operation
        )))
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
impl TpmDevice for TpmTbsDevice {
    fn connect(&mut self) -> Result<bool, TpmError> {
        Self::unsupported("connect")
    }

    fn close(&mut self) {}

    fn dispatch_command(&mut self, _cmd_buf: &[u8]) -> Result<(), TpmError> {
        Self::unsupported("dispatch_command")
    }

    fn get_response(&mut self) -> Result<Vec<u8>, TpmError> {
        Self::unsupported("get_response")
    }

    fn response_is_ready(&self) -> Result<bool, TpmError> {
        Self::unsupported("response_is_ready")
    }

    fn has_flag(&self, _flag: u32) -> bool {
        false
    }

    fn get_tpm_info(&self) -> u32 {
        0
    }
}

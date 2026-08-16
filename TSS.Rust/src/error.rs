//! Error types for TPM operations

use std::error::Error;
use std::fmt;

/// TPM Error types
#[derive(Debug)]
pub enum TpmError {
    /// Buffer underflow occurred during deserialization
    BufferUnderflow,

    /// Buffer overflow occurred during serialization
    BufferOverflow,

    /// Bytes remained after deserializing a complete TPM value
    TrailingData,

    /// Invalid array size
    InvalidArraySize(String),

    /// Invalid enum value
    InvalidEnumValue,

    /// Invalid union type
    InvalidUnion,

    /// Incorrect tag value
    IncorrectTag(u32, u32), // expected, actual

    /// I/O error
    IoError(String),

    /// Device communication error
    DeviceError(String),

    /// Generic TPM error
    GenericError(String),

    /// Operation not supported
    NotSupported(String),

    /// A cryptographic or structural check on attacker-reachable data did not pass
    VerificationFailed(String),

    /// TPM device not connected
    NotConnected,

    /// Bad end tag received from TPM
    BadEndTag,

    /// Command failed
    CommandFailed,

    /// Invalid parameter provided
    InvalidParameter,

    /// No response available
    NoResponse,

    /// Unexpected device state
    UnexpectedState,

    /// Incompatible TPM/proxy
    IncompatibleTpm,

    /// Invalid TPM device type
    InvalidTpmType,

    /// Windows TBS specific error
    #[cfg(target_os = "windows")]
    TbsError(String),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BufferUnderflow => write!(f, "Buffer underflow during deserialization"),
            Self::BufferOverflow => write!(f, "Buffer overflow during serialization"),
            Self::TrailingData => write!(f, "Trailing data after TPM value"),
            Self::InvalidArraySize(msg) => write!(f, "Invalid array size: {}", msg),
            Self::InvalidEnumValue => write!(f, "Invalid enum value"),
            Self::InvalidUnion => write!(f, "Invalid union type"),
            Self::IncorrectTag(expected, actual) => write!(
                f,
                "Incorrect tag: expected 0x{:X}, got 0x{:X}",
                expected, actual
            ),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::DeviceError(msg) => write!(f, "Device error: {}", msg),
            Self::GenericError(msg) => write!(f, "TPM error: {}", msg),
            Self::NotSupported(operation) => write!(f, "Operation not supported: {}", operation),
            Self::VerificationFailed(reason) => write!(f, "Verification failed: {}", reason),
            Self::NotConnected => write!(f, "TPM device not connected"),
            Self::BadEndTag => write!(f, "Bad end tag received from TPM"),
            Self::CommandFailed => write!(f, "TPM command failed"),
            Self::InvalidParameter => write!(f, "Invalid parameter provided"),
            Self::NoResponse => write!(f, "No TPM response available"),
            Self::UnexpectedState => write!(f, "TPM in unexpected state"),
            Self::IncompatibleTpm => write!(f, "Incompatible TPM/proxy"),
            Self::InvalidTpmType => write!(f, "Invalid TPM device type"),
            #[cfg(target_os = "windows")]
            Self::TbsError(msg) => write!(f, "TBS error: {}", msg),
        }
    }
}

impl Error for TpmError {}

impl From<std::io::Error> for TpmError {
    fn from(error: std::io::Error) -> Self {
        TpmError::IoError(error.to_string())
    }
}

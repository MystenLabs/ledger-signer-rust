use serde::{Deserialize, Serialize};
use std::fmt;

/// Custom error type for the Ledger Signer application
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum AppError {
    /// Ledger device connection errors
    DeviceConnection(String),

    /// Ledger device not found
    DeviceNotFound,

    /// Ledger app not open or wrong app
    WrongApp(String),

    /// Device communication timeout
    DeviceTimeout,

    /// User rejected operation on device
    UserRejected,

    /// Invalid derivation path format
    InvalidDerivationPath(String),

    /// Invalid transaction format
    InvalidTransaction(String),

    /// Signature operation failed
    SignatureFailed(String),

    /// Public key retrieval failed
    PublicKeyFailed(String),

    /// Device info retrieval failed
    DeviceInfoFailed(String),

    /// APDU communication error with status code
    ApduError { status: u16, message: String },

    /// Serialization/Deserialization errors
    SerializationError(String),

    /// Internal error (should be rare)
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::DeviceConnection(msg) => write!(f, "Device connection error: {msg}"),
            AppError::DeviceNotFound => write!(
                f,
                "No Ledger devices found. Please ensure your Ledger is connected and unlocked"
            ),
            AppError::WrongApp(msg) => write!(f, "Wrong Ledger app: {msg}"),
            AppError::DeviceTimeout => write!(
                f,
                "Device timeout - please ensure the Sui app is open and device is unlocked"
            ),
            AppError::UserRejected => write!(f, "Transaction rejected by user on Ledger device"),
            AppError::InvalidDerivationPath(path) => write!(
                f,
                "Invalid derivation path '{path}': must be in format like 44'/784'/0'/0'/0'",
            ),
            AppError::InvalidTransaction(msg) => write!(f, "Invalid transaction: {msg}"),
            AppError::SignatureFailed(msg) => write!(f, "Signature operation failed: {msg}"),
            AppError::PublicKeyFailed(msg) => write!(f, "Public key retrieval failed: {msg}"),
            AppError::DeviceInfoFailed(msg) => write!(f, "Device info retrieval failed: {msg}"),
            AppError::ApduError { status, message } => {
                write!(f, "Ledger device error 0x{status:04x}: {message}")
            }
            AppError::SerializationError(msg) => write!(f, "Serialization error: {msg}"),
            AppError::Internal(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl std::error::Error for AppError {}

/// Type alias for Results in this application
pub type AppResult<T> = Result<T, AppError>;

// Conversion implementations for common error types

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        // Try to downcast to our error type first
        if let Some(app_err) = err.downcast_ref::<AppError>() {
            return app_err.clone();
        }

        // Otherwise, convert to internal error
        AppError::Internal(err.to_string())
    }
}

impl From<ledger_lib::Error> for AppError {
    fn from(err: ledger_lib::Error) -> Self {
        match &err {
            ledger_lib::Error::Hid(_) => AppError::DeviceNotFound,
            ledger_lib::Error::Tcp(_) => AppError::DeviceConnection(err.to_string()),
            ledger_lib::Error::Ble(_) => AppError::DeviceConnection(err.to_string()),
            ledger_lib::Error::UnknownModel(model) => {
                AppError::Internal(format!("Unknown Ledger model: {model}"))
            }
            ledger_lib::Error::NoDevices => AppError::DeviceNotFound,
            ledger_lib::Error::InvalidDeviceIndex(index) => {
                AppError::Internal(format!("Invalid device index: {index}"))
            }
            ledger_lib::Error::Apdu(apdu_err) => {
                AppError::SerializationError(format!("APDU encode/decode error: {apdu_err}"))
            }
            ledger_lib::Error::Response(status, message) => AppError::ApduError {
                status: *status as u16,
                message: format!("Response error 0x{message:02x}"),
            },
            ledger_lib::Error::Timeout => AppError::DeviceTimeout,
            ledger_lib::Error::UnexpectedResponse => {
                AppError::DeviceConnection("Unexpected response from Ledger device".to_string())
            }
            ledger_lib::Error::DeviceInUse => {
                AppError::DeviceConnection("Device is already in use".to_string())
            }
            ledger_lib::Error::Unknown => AppError::Internal("Unknown Ledger error".to_string()),
        }
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(err: base64::DecodeError) -> Self {
        AppError::SerializationError(format!("Base64 decode error: {err}"))
    }
}

impl From<std::num::ParseIntError> for AppError {
    fn from(err: std::num::ParseIntError) -> Self {
        AppError::InvalidDerivationPath(format!("Invalid number in path: {err}"))
    }
}

// Helper function to convert APDU status codes to AppError
pub fn apdu_status_to_error(status: u16) -> AppError {
    let (status, message) = match status {
        0x9000 => return AppError::Internal("Success status passed as error".to_string()),
        0x6802 => (
            status,
            "Invalid command or parameters. Please ensure the Sui app is open and unlocked",
        ),
        0x6985 => return AppError::UserRejected,
        0x6986 => (status, "Command not allowed - ensure Ledger is unlocked"),
        0x6A80 => (status, "Incorrect data sent to Ledger device"),
        0x6A82 => (status, "File not found on Ledger device"),
        0x6A86 => (status, "Incorrect parameters sent to Ledger device"),
        0x6B00 => (status, "Incorrect parameters P1 or P2"),
        0x6D00 => (status, "Instruction not supported"),
        0x6E00 => (status, "Class not supported"),
        _ => (status, "Unknown error"),
    };

    AppError::ApduError {
        status,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_apdu_status_to_error() {
        // Test user rejection
        match apdu_status_to_error(0x6985) {
            AppError::UserRejected => (),
            _ => panic!("Expected UserRejected error"),
        }

        // Test device timeout related error
        match apdu_status_to_error(0x6802) {
            AppError::ApduError { status, message } => {
                assert_eq!(status, 0x6802);
                assert!(message.contains("Sui app"));
            }
            _ => panic!("Expected ApduError"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = AppError::DeviceNotFound;
        assert_eq!(
            err.to_string(),
            "No Ledger devices found. Please ensure your Ledger is connected and unlocked"
        );

        let err = AppError::InvalidDerivationPath("bad/path".to_string());
        assert!(err.to_string().contains("bad/path"));
        assert!(err.to_string().contains("44'/784'/0'/0'/0'"));
    }

    #[test]
    fn test_error_serialization() {
        let err = AppError::UserRejected;
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("UserRejected"));

        let err = AppError::ApduError {
            status: 0x6985,
            message: "Test message".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        // The JSON should contain the error type and details
        assert!(json.contains("ApduError"));
        assert!(json.contains("Test message"));
        // Status is serialized as decimal, not hex
        assert!(json.contains("27013")); // 0x6985 in decimal
    }

    #[test]
    fn test_error_conversions() {
        // Test base64 decode error conversion
        // Create an actual decode error by trying to decode invalid base64
        let decode_result = base64::engine::general_purpose::STANDARD.decode("invalid!@#$base64");
        let decode_err = decode_result.unwrap_err();
        let app_err: AppError = decode_err.into();
        match app_err {
            AppError::SerializationError(msg) => assert!(msg.contains("Base64")),
            _ => panic!("Expected SerializationError"),
        }

        // Test parse int error conversion
        let parse_err = "not_a_number".parse::<u32>().unwrap_err();
        let app_err: AppError = parse_err.into();
        match app_err {
            AppError::InvalidDerivationPath(msg) => assert!(msg.contains("Invalid number")),
            _ => panic!("Expected InvalidDerivationPath"),
        }
    }
}

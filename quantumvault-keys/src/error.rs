//! Error types for key management operations.

use thiserror::Error;

/// Result type for key management operations.
pub type KeyResult<T> = std::result::Result<T, KeyError>;

/// Errors that can occur during key management.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Key not found.
    #[error("Key not found: {0}")]
    NotFound(String),

    /// Key already exists.
    #[error("Key already exists: {0}")]
    AlreadyExists(String),

    /// Key has expired.
    #[error("Key has expired: {0}")]
    Expired(String),

    /// Key has been revoked.
    #[error("Key has been revoked: {0}")]
    Revoked(String),

    /// Key is not in a usable state.
    #[error("Key is not usable: {0} (status: {1:?})")]
    NotUsable(String, super::KeyStatus),

    /// Storage backend error.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Encryption/decryption error.
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Policy violation.
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// AWS error.
    #[error("AWS error: {0}")]
    Aws(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Core library error.
    #[error("Core error: {0}")]
    Core(#[from] quantumvault_core::Error),
}

impl From<serde_json::Error> for KeyError {
    fn from(err: serde_json::Error) -> Self {
        KeyError::Serialization(err.to_string())
    }
}

impl From<bincode::Error> for KeyError {
    fn from(err: bincode::Error) -> Self {
        KeyError::Serialization(err.to_string())
    }
}

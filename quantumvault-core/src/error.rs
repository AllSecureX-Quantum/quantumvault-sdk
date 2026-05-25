//! Error types for QuantumVault operations.

use thiserror::Error;

/// Result type alias for QuantumVault operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during QuantumVault operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid algorithm specified.
    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),

    /// Algorithm not supported for the operation.
    #[error("Algorithm {algorithm} not supported for {operation}")]
    UnsupportedAlgorithm {
        algorithm: String,
        operation: String,
    },

    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Encryption failed.
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed.
    #[error("Decryption failed: {0}")]
    Decryption(String),

    /// Signature generation failed.
    #[error("Signature generation failed: {0}")]
    SignatureGeneration(String),

    /// Signature verification failed.
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    /// Invalid key format or data.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid ciphertext format or data.
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Invalid signature format or data.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Security level mismatch.
    #[error("Security level mismatch: expected {expected}, got {actual}")]
    SecurityLevelMismatch { expected: u8, actual: u8 },

    /// Insufficient entropy for secure random generation.
    #[error("Insufficient entropy for secure random generation")]
    InsufficientEntropy,

    /// Key has expired.
    #[error("Key expired at {0}")]
    KeyExpired(String),

    /// Key has been revoked.
    #[error("Key has been revoked: {0}")]
    KeyRevoked(String),

    /// Operation not permitted by policy.
    #[error("Operation not permitted: {0}")]
    PolicyViolation(String),

    /// Compliance requirement not met.
    #[error("Compliance requirement not met: {0}")]
    ComplianceViolation(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error.
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Telemetry error.
    #[error("Telemetry error: {0}")]
    Telemetry(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Check if this error is a security-sensitive error that should be logged.
    pub fn is_security_event(&self) -> bool {
        matches!(
            self,
            Error::Decryption(_)
                | Error::SignatureVerification(_)
                | Error::InvalidKey(_)
                | Error::KeyExpired(_)
                | Error::KeyRevoked(_)
                | Error::PolicyViolation(_)
                | Error::ComplianceViolation(_)
        )
    }

    /// Get a sanitized error message safe for logging (no sensitive data).
    pub fn sanitized_message(&self) -> String {
        match self {
            Error::Decryption(_) => "Decryption operation failed".to_string(),
            Error::InvalidKey(_) => "Invalid key provided".to_string(),
            Error::InvalidCiphertext(_) => "Invalid ciphertext provided".to_string(),
            Error::InvalidSignature(_) => "Invalid signature provided".to_string(),
            _ => self.to_string(),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serialization(err.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Deserialization(err.to_string())
    }
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Error::Serialization(err.to_string())
    }
}

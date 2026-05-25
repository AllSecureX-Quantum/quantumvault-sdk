//! Errors produced by the ACME protocol library + client/server.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, AcmeError>;

/// Failure modes of ACME-PQC.
#[derive(Debug, Error)]
pub enum AcmeError {
    /// Inbound JSON body didn't parse.
    #[error("malformed request: {0}")]
    MalformedRequest(String),

    /// Account id not recognised by the server.
    #[error("unknown account: {0}")]
    UnknownAccount(String),

    /// Order id not recognised by the server.
    #[error("unknown order: {0}")]
    UnknownOrder(String),

    /// Order is not yet in a state that allows the requested operation.
    #[error("order in unexpected state: {0}")]
    OrderStateError(String),

    /// Request signature didn't verify against the account's stored key.
    #[error("invalid request signature")]
    SignatureInvalid,

    /// Algorithm in the signed request isn't one we accept.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Protocol version mismatch.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Server-side issuance failure (e.g. CA refused).
    #[error("issuance failed: {0}")]
    IssuanceFailed(String),

    /// JSON serialisation / deserialisation.
    #[error("JSON: {0}")]
    Json(String),

    /// Base64 decode failure.
    #[error("base64: {0}")]
    Base64(String),

    /// HTTP transport error (client side).
    #[error("HTTP: {0}")]
    Http(String),

    /// Underlying crypto failure.
    #[error("crypto: {0}")]
    Crypto(String),

    /// I/O error.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

impl From<serde_json::Error> for AcmeError {
    fn from(e: serde_json::Error) -> Self {
        AcmeError::Json(e.to_string())
    }
}

impl From<base64::DecodeError> for AcmeError {
    fn from(e: base64::DecodeError) -> Self {
        AcmeError::Base64(e.to_string())
    }
}

impl From<reqwest::Error> for AcmeError {
    fn from(e: reqwest::Error) -> Self {
        AcmeError::Http(e.to_string())
    }
}

impl From<quantumvault_core::Error> for AcmeError {
    fn from(e: quantumvault_core::Error) -> Self {
        AcmeError::Crypto(e.to_string())
    }
}

impl From<quantumvault_ca::CaError> for AcmeError {
    fn from(e: quantumvault_ca::CaError) -> Self {
        AcmeError::IssuanceFailed(e.to_string())
    }
}

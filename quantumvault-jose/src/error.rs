//! Errors produced by `quantumvault-jose`.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// All failure modes of JOSE encoding, decoding, and validation.
#[derive(Debug, Error)]
pub enum Error {
    /// The `alg` header is not one of the supported values.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The JWT does not have the expected `header.payload.signature` shape.
    #[error("malformed JWT: {0}")]
    Malformed(&'static str),

    /// Base64URL decoding failed.
    #[error("base64url decode error: {0}")]
    Base64(String),

    /// JSON serialisation or parsing failed.
    #[error("JSON error: {0}")]
    Json(String),

    /// The signature is cryptographically invalid for the supplied
    /// verifying key. May also indicate a tampered token.
    #[error("invalid signature")]
    InvalidSignature,

    /// The token's `exp` claim is in the past.
    #[error("token expired")]
    Expired,

    /// The token's `nbf` claim is in the future.
    #[error("token not yet valid")]
    NotYetValid,

    /// An `iss` claim was required by validation policy but didn't match.
    #[error("issuer mismatch")]
    IssuerMismatch,

    /// An `aud` claim was required by validation policy but didn't match.
    #[error("audience mismatch")]
    AudienceMismatch,

    /// The algorithm declared in the JWT header doesn't match the policy.
    #[error("algorithm not allowed: {0}")]
    AlgorithmNotAllowed(String),

    /// Underlying crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

impl From<quantumvault_core::Error> for Error {
    fn from(e: quantumvault_core::Error) -> Self {
        Error::Crypto(e.to_string())
    }
}

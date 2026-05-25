//! Errors produced by sign / verify operations.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, SmimeError>;

/// Failure modes of S/MIME-style sign / verify.
#[derive(Debug, Error)]
pub enum SmimeError {
    /// Message is not RFC 5322 (no header/body separator).
    #[error("not a valid RFC 5322 message: {0}")]
    InvalidMessage(&'static str),

    /// `Content-Type` doesn't claim `multipart/signed`.
    #[error("message is not multipart/signed (got Content-Type: {0:?})")]
    NotMultipartSigned(String),

    /// `multipart/signed` envelope is missing a required parameter.
    #[error("multipart/signed envelope malformed: {0}")]
    MultipartMalformed(&'static str),

    /// We expected exactly two MIME parts (body + signature). Found a
    /// different count.
    #[error("expected exactly 2 MIME parts (body + signature), found {0}")]
    WrongPartCount(usize),

    /// The second part is not the expected signature content-type.
    #[error("signature MIME part has unexpected Content-Type")]
    SignaturePartMissing,

    /// Signature envelope JSON didn't parse or had the wrong shape.
    #[error("signature envelope malformed: {0}")]
    EnvelopeMalformed(String),

    /// Signature envelope is a version this build does not support.
    #[error("unsupported signature envelope version: {0}")]
    UnsupportedEnvelopeVersion(u8),

    /// Body hash doesn't match the hash recorded in the signature.
    #[error("body hash mismatch — message was modified after signing")]
    HashMismatch,

    /// ML-DSA signature verification returned false.
    #[error("signature invalid for body")]
    SignatureInvalid,

    /// Manifest verifying key doesn't match what the caller pinned.
    #[error("verifying key mismatch — message was signed with a different key")]
    VerifyingKeyMismatch,

    /// I/O error reading or writing a file.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Base64 decode failure.
    #[error("base64: {0}")]
    Base64(String),

    /// JSON serialise / deserialise failure.
    #[error("JSON: {0}")]
    Json(String),

    /// Underlying crypto failure.
    #[error("crypto: {0}")]
    Crypto(String),
}

impl From<base64::DecodeError> for SmimeError {
    fn from(e: base64::DecodeError) -> Self {
        SmimeError::Base64(e.to_string())
    }
}

impl From<serde_json::Error> for SmimeError {
    fn from(e: serde_json::Error) -> Self {
        SmimeError::Json(e.to_string())
    }
}

impl From<quantumvault_core::Error> for SmimeError {
    fn from(e: quantumvault_core::Error) -> Self {
        SmimeError::Crypto(e.to_string())
    }
}

impl From<quantumvault_pkcs11::HsmError> for SmimeError {
    fn from(e: quantumvault_pkcs11::HsmError) -> Self {
        SmimeError::EnvelopeMalformed(format!("hsm: {e}"))
    }
}

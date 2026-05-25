//! Errors produced by the CA library.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, CaError>;

/// Failure modes of certificate issuance and verification.
#[derive(Debug, Error)]
pub enum CaError {
    /// The certificate JSON was malformed.
    #[error("malformed certificate: {0}")]
    MalformedCertificate(String),

    /// Format version not supported by this build.
    #[error("unsupported certificate version: {0}")]
    UnsupportedVersion(u8),

    /// The issuer in a child cert does not match the subject of its
    /// alleged parent CA cert.
    #[error("issuer/subject mismatch — cert was issued by a different CA than supplied")]
    IssuerMismatch,

    /// Certificate signature is cryptographically invalid.
    #[error("invalid certificate signature")]
    SignatureInvalid,

    /// Certificate is not yet valid (now < not_before).
    #[error("certificate not yet valid (becomes valid at {0})")]
    NotYetValid(String),

    /// Certificate has expired (now > not_after).
    #[error("certificate expired at {0}")]
    Expired(String),

    /// An intermediate certificate is not marked as a CA, so it can't
    /// sign other certs.
    #[error("alleged CA is not marked is_ca=true: {0}")]
    NotACa(String),

    /// Path length constraint exceeded.
    #[error("path-length constraint exceeded: {0}")]
    PathLengthExceeded(String),

    /// The trust root provided does not appear in the chain.
    #[error("chain does not terminate in the supplied trust anchor")]
    UntrustedChain,

    /// I/O failure.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// JSON failure.
    #[error("JSON: {0}")]
    Json(String),

    /// Base64 failure.
    #[error("base64: {0}")]
    Base64(String),

    /// Underlying crypto failure.
    #[error("crypto: {0}")]
    Crypto(String),

    /// An HSM/KEK operation failed, or a wrapped key was loaded without
    /// the `--hsm-kek` flag supplied.
    #[error("hsm: {0}")]
    Hsm(String),
}

impl From<quantumvault_pkcs11::HsmError> for CaError {
    fn from(e: quantumvault_pkcs11::HsmError) -> Self {
        CaError::Hsm(e.to_string())
    }
}

impl From<serde_json::Error> for CaError {
    fn from(e: serde_json::Error) -> Self {
        CaError::Json(e.to_string())
    }
}

impl From<base64::DecodeError> for CaError {
    fn from(e: base64::DecodeError) -> Self {
        CaError::Base64(e.to_string())
    }
}

impl From<quantumvault_core::Error> for CaError {
    fn from(e: quantumvault_core::Error) -> Self {
        CaError::Crypto(e.to_string())
    }
}

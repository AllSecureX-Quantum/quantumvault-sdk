//! Errors produced by the DNSSEC library.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, DnssecError>;

/// Failure modes of zone parsing, signing, and verification.
#[derive(Debug, Error)]
pub enum DnssecError {
    /// Zone file does not parse as RFC 1035-style records.
    #[error("malformed zone (line {line}): {message}")]
    MalformedZone {
        /// 1-indexed line number where the error was detected.
        line: usize,
        /// Human-readable description.
        message: String,
    },

    /// Manifest JSON is malformed.
    #[error("malformed manifest: {0}")]
    MalformedManifest(String),

    /// Unsupported manifest version.
    #[error("unsupported manifest version: {0}")]
    UnsupportedManifestVersion(u8),

    /// A signed RRSet on disk doesn't match the recomputed hash.
    #[error("RRSet hash mismatch for {0}")]
    RrsetHashMismatch(String),

    /// ML-DSA signature failed for a RRSet.
    #[error("RRSet signature invalid for {0}")]
    RrsetSignatureInvalid(String),

    /// KSK fingerprint pinned by the caller doesn't match the manifest.
    #[error("KSK fingerprint mismatch — manifest signed with a different KSK")]
    KskFingerprintMismatch,

    /// ZSK signature by the KSK failed.
    #[error("ZSK is not signed by the expected KSK")]
    ZskNotSignedByKsk,

    /// A record from the zone has no matching manifest entry.
    #[error("RRSet present in zone but not in manifest: {0}")]
    RrsetMissingInManifest(String),

    /// A manifest entry has no matching RRSet in the zone.
    #[error("RRSet present in manifest but not in zone: {0}")]
    RrsetMissingInZone(String),

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

    /// An HSM/KEK operation failed, or a wrapped key was loaded
    /// without the `--hsm-kek` flag supplied.
    #[error("hsm: {0}")]
    Hsm(String),
}

impl From<quantumvault_pkcs11::HsmError> for DnssecError {
    fn from(e: quantumvault_pkcs11::HsmError) -> Self {
        DnssecError::Hsm(e.to_string())
    }
}

impl From<serde_json::Error> for DnssecError {
    fn from(e: serde_json::Error) -> Self {
        DnssecError::Json(e.to_string())
    }
}

impl From<base64::DecodeError> for DnssecError {
    fn from(e: base64::DecodeError) -> Self {
        DnssecError::Base64(e.to_string())
    }
}

impl From<quantumvault_core::Error> for DnssecError {
    fn from(e: quantumvault_core::Error) -> Self {
        DnssecError::Crypto(e.to_string())
    }
}

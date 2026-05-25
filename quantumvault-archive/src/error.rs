//! Errors produced by the archive sealer.

use std::path::PathBuf;
use thiserror::Error;

/// Result type alias.
pub type Result<T> = std::result::Result<T, ArchiveError>;

/// Failures of seal / verify operations.
#[derive(Debug, Error)]
pub enum ArchiveError {
    /// I/O error reading or writing a file.
    #[error("I/O error at {path:?}: {source}")]
    Io {
        /// File the error was triggered on.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// I/O error not tied to a specific file (e.g. directory walk).
    #[error("I/O error: {0}")]
    GenericIo(#[from] std::io::Error),

    /// The archive directory does not exist.
    #[error("archive root does not exist: {0:?}")]
    ArchiveRootMissing(PathBuf),

    /// The archive root path is not a directory.
    #[error("archive root is not a directory: {0:?}")]
    ArchiveRootNotDirectory(PathBuf),

    /// Manifest file is missing where expected.
    #[error("manifest not found at {0:?} (have you sealed this directory yet?)")]
    ManifestMissing(PathBuf),

    /// Manifest file is malformed (not valid JSON or wrong shape).
    #[error("malformed manifest: {0}")]
    ManifestMalformed(String),

    /// Manifest format version is not supported by this build.
    #[error("unsupported manifest version: {0}")]
    UnsupportedManifestVersion(u8),

    /// A file present in the manifest is missing on disk.
    #[error("file referenced by manifest is missing: {0:?}")]
    SealedFileMissing(PathBuf),

    /// A file's bytes don't match the recorded hash.
    #[error("file content changed since seal: {0:?}")]
    HashMismatch(PathBuf),

    /// SLH-DSA signature verification failed for a file.
    #[error("signature invalid for file: {0:?}")]
    SignatureInvalid(PathBuf),

    /// The verifying key in the manifest doesn't match the one supplied
    /// out-of-band (potential key substitution attack).
    #[error("verifying key mismatch — manifest was sealed with a different key")]
    VerifyingKeyMismatch,

    /// Base64 decode failure (corrupted key file, malformed manifest, etc).
    #[error("base64 decode: {0}")]
    Base64(String),

    /// JSON serialise / deserialise failure.
    #[error("JSON: {0}")]
    Json(String),

    /// Underlying crypto operation failed.
    #[error("crypto: {0}")]
    Crypto(String),
}

impl From<base64::DecodeError> for ArchiveError {
    fn from(e: base64::DecodeError) -> Self {
        ArchiveError::Base64(e.to_string())
    }
}

impl From<serde_json::Error> for ArchiveError {
    fn from(e: serde_json::Error) -> Self {
        ArchiveError::Json(e.to_string())
    }
}

impl From<quantumvault_core::Error> for ArchiveError {
    fn from(e: quantumvault_core::Error) -> Self {
        ArchiveError::Crypto(e.to_string())
    }
}

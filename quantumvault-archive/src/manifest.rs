//! Manifest format — the audit artefact produced by sealing.

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{ArchiveError, Result};
use crate::keys::{wire_name, ArchiveVerifyingKey};

/// Manifest format version. Bump on breaking changes.
pub const MANIFEST_VERSION: u8 = 1;

/// On-disk file name for the manifest. Lives at the root of the sealed
/// directory.
pub const MANIFEST_FILE_NAME: &str = "qvarchive.manifest.json";

/// The audit artefact produced by [`crate::seal_directory`].
///
/// Contains:
/// - The verifying key (so a recipient can verify without out-of-band key
///   distribution — but they should still pin the key fingerprint they
///   expect)
/// - One [`ManifestEntry`] per file, sorted by path for deterministic
///   serialisation and stable diffs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Manifest format version.
    pub version: u8,
    /// Algorithm used for every entry's signature.
    pub algorithm: String,
    /// Base64-encoded verifying key bytes.
    pub verifying_key: String,
    /// Verifying key identifier.
    pub verifying_key_id: String,
    /// Timestamp (RFC 3339) when the manifest was sealed.
    pub sealed_at: DateTime<Utc>,
    /// File entries, sorted by path.
    pub entries: Vec<ManifestEntry>,
}

/// One file's audit entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Path relative to the archive root, with forward slashes for portability.
    pub path: String,
    /// File size in bytes at seal time.
    pub size: u64,
    /// Lowercase hex of SHA-3-256(file content).
    pub sha3_256: String,
    /// Base64-encoded SLH-DSA signature over the SHA-3-256 hash of the file.
    pub signature: String,
    /// Per-file timestamp (RFC 3339).
    pub sealed_at: DateTime<Utc>,
}

impl Manifest {
    /// Build a manifest skeleton with no entries.
    pub fn new_empty(verifying_key: &ArchiveVerifyingKey) -> Self {
        let vk = verifying_key.core();
        Self {
            version: MANIFEST_VERSION,
            algorithm: wire_name(vk.algorithm).into(),
            verifying_key: B64.encode(&vk.bytes),
            verifying_key_id: vk.key_id.clone(),
            sealed_at: Utc::now(),
            entries: Vec::new(),
        }
    }

    /// Load a manifest from disk and validate its version + shape.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(ArchiveError::ManifestMissing(path.to_path_buf()));
        }
        let s = std::fs::read_to_string(path).map_err(|e| ArchiveError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let m: Manifest = serde_json::from_str(&s)
            .map_err(|e| ArchiveError::ManifestMalformed(format!("parse error: {e}")))?;
        if m.version != MANIFEST_VERSION {
            return Err(ArchiveError::UnsupportedManifestVersion(m.version));
        }
        Ok(m)
    }

    /// Atomic save: write to `path.tmp`, fsync, rename. Survives a crash
    /// without leaving a half-written manifest in place.
    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        let mut tmp = path.to_path_buf();
        tmp.set_extension("tmp");
        let json = serde_json::to_vec_pretty(self)?;
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(|e| ArchiveError::Io {
                path: tmp.clone(),
                source: e,
            })?;
            f.write_all(&json).map_err(|e| ArchiveError::Io {
                path: tmp.clone(),
                source: e,
            })?;
            f.sync_all().map_err(|e| ArchiveError::Io {
                path: tmp.clone(),
                source: e,
            })?;
        }
        std::fs::rename(&tmp, path).map_err(|e| ArchiveError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }

    /// Decode the verifying-key bytes from the manifest's base64 field.
    pub fn verifying_key_bytes(&self) -> Result<Vec<u8>> {
        B64.decode(&self.verifying_key).map_err(Into::into)
    }
}

//! Seal: hash every file in a directory tree, sign each hash with SLH-DSA,
//! write the resulting manifest atomically.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use quantumvault_core::api::sign as core_sign;
use quantumvault_core::Config;
use walkdir::WalkDir;

use crate::error::{ArchiveError, Result};
use crate::hashing::{hash_file, to_hex};
use crate::keys::{ArchiveSigningKey, ArchiveVerifyingKey};
use crate::manifest::{Manifest, ManifestEntry, MANIFEST_FILE_NAME};

/// Options controlling what `seal_directory` walks.
#[derive(Debug, Clone)]
pub struct SealOptions {
    /// Skip files larger than this many bytes. `None` = no limit.
    pub max_file_size_bytes: Option<u64>,
    /// Skip hidden files (those whose path components start with '.').
    pub skip_hidden: bool,
    /// Follow symlinks. Default: false (avoids loops + symlink-substitution
    /// attacks on a sealed archive).
    pub follow_symlinks: bool,
}

impl Default for SealOptions {
    fn default() -> Self {
        Self {
            max_file_size_bytes: None,
            skip_hidden: true,
            follow_symlinks: false,
        }
    }
}

/// Summary of what was sealed.
#[derive(Debug, Clone)]
pub struct SealReport {
    /// Path to the manifest that was written.
    pub manifest_path: PathBuf,
    /// Number of files sealed.
    pub files_sealed: usize,
    /// Total bytes hashed.
    pub bytes_hashed: u64,
    /// Files skipped (hidden, too large, or the manifest file itself).
    pub files_skipped: usize,
}

/// Seal every file in `archive_root` (recursively) and write
/// `qvarchive.manifest.json` at the root.
///
/// The manifest carries the SLH-DSA verifying key, so verification later
/// only needs the manifest file plus the archive contents. (Customers
/// should still pin the verifying key fingerprint they expect — see
/// [`crate::verify_directory`].)
pub fn seal_directory(
    archive_root: &Path,
    signing_key: &ArchiveSigningKey,
    verifying_key: &ArchiveVerifyingKey,
    options: &SealOptions,
) -> Result<SealReport> {
    validate_root(archive_root)?;

    let manifest_path = archive_root.join(MANIFEST_FILE_NAME);
    let cfg = Config::builder()
        .security_level(quantumvault_core::SecurityLevel::Level5)
        .build()?;

    let mut entries = Vec::new();
    let mut files_skipped = 0usize;
    let mut bytes_hashed = 0u64;

    let walker = WalkDir::new(archive_root)
        .follow_links(options.follow_symlinks)
        .into_iter();

    for dir_entry in walker {
        let dir_entry = match dir_entry {
            Ok(e) => e,
            Err(e) => {
                return Err(ArchiveError::GenericIo(e.into_io_error().unwrap_or_else(
                    || std::io::Error::new(std::io::ErrorKind::Other, "walk error"),
                )));
            }
        };

        if !dir_entry.file_type().is_file() {
            continue;
        }
        let abs = dir_entry.path();

        // Skip the manifest itself if we encounter it during a re-seal.
        if abs
            .file_name()
            .map(|n| n == MANIFEST_FILE_NAME)
            .unwrap_or(false)
        {
            files_skipped += 1;
            continue;
        }

        let rel = abs
            .strip_prefix(archive_root)
            .map_err(|_| ArchiveError::ManifestMalformed("path strip_prefix failed".into()))?;

        if options.skip_hidden && rel_has_hidden_component(rel) {
            files_skipped += 1;
            continue;
        }

        let metadata = abs.metadata().map_err(|e| ArchiveError::Io {
            path: abs.to_path_buf(),
            source: e,
        })?;
        let size = metadata.len();
        if let Some(max) = options.max_file_size_bytes {
            if size > max {
                files_skipped += 1;
                continue;
            }
        }

        let hash = hash_file(abs)?;
        bytes_hashed += size;

        // Sign the hash. SLH-DSA-SHAKE-256s is what the default keygen produces.
        let signature = core_sign::sign_message(&hash, signing_key.core(), &cfg)?;
        let sig_b64 = B64.encode(&signature.bytes);

        entries.push(ManifestEntry {
            path: rel_to_portable_string(rel),
            size,
            sha3_256: to_hex(&hash),
            signature: sig_b64,
            sealed_at: Utc::now(),
        });
    }

    // Deterministic ordering — makes diffs across re-seals readable.
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let manifest = Manifest {
        entries,
        ..Manifest::new_empty(verifying_key)
    };
    manifest.save_atomic(&manifest_path)?;

    Ok(SealReport {
        files_sealed: manifest.entries.len(),
        manifest_path,
        bytes_hashed,
        files_skipped,
    })
}

fn validate_root(root: &Path) -> Result<()> {
    if !root.exists() {
        return Err(ArchiveError::ArchiveRootMissing(root.to_path_buf()));
    }
    if !root.is_dir() {
        return Err(ArchiveError::ArchiveRootNotDirectory(root.to_path_buf()));
    }
    Ok(())
}

fn rel_has_hidden_component(rel: &Path) -> bool {
    rel.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| s.starts_with('.'))
            .unwrap_or(false)
    })
}

/// Render a relative path using forward slashes regardless of OS. The
/// manifest is portable across Linux / macOS / Windows.
fn rel_to_portable_string(rel: &Path) -> String {
    rel.components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/")
}

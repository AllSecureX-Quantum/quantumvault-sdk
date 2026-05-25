//! Verify: re-hash each file and check its SLH-DSA signature.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::api::verify as core_verify;
use quantumvault_core::{Config, Signature, VerifyingKey};

use crate::error::{ArchiveError, Result};
use crate::hashing::{from_hex, hash_file};
use crate::keys::ArchiveVerifyingKey;
use crate::manifest::{Manifest, MANIFEST_FILE_NAME};

/// Summary of what was verified.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Files that verified cleanly.
    pub verified: Vec<PathBuf>,
    /// Files present in the manifest but missing on disk.
    pub missing: Vec<PathBuf>,
    /// Files whose content hash diverged (tampered or corrupted).
    pub hash_mismatch: Vec<PathBuf>,
    /// Files whose SLH-DSA signature failed verification.
    pub signature_invalid: Vec<PathBuf>,
    /// Files present on disk that are NOT in the manifest (additions
    /// after seal).
    pub extra_on_disk: Vec<PathBuf>,
}

impl VerifyReport {
    /// True if every manifest entry verified cleanly. Note: extra files
    /// on disk are *not* a hard failure — the manifest sealed what
    /// existed at seal time; additions are allowed but reported.
    pub fn all_sealed_files_pass(&self) -> bool {
        self.missing.is_empty()
            && self.hash_mismatch.is_empty()
            && self.signature_invalid.is_empty()
    }
}

/// Verify every file referenced in the manifest at `archive_root`.
///
/// If `expected_verifying_key` is supplied, it must match the key
/// embedded in the manifest. Pass `None` to skip this check (e.g. for
/// quick local verification).
///
/// In production deployments callers should always pass the expected
/// verifying key — otherwise an attacker who can replace both the manifest
/// and the files can substitute their own signing key and pass verification.
pub fn verify_directory(
    archive_root: &Path,
    expected_verifying_key: Option<&ArchiveVerifyingKey>,
) -> Result<VerifyReport> {
    let manifest_path = archive_root.join(MANIFEST_FILE_NAME);
    let manifest = Manifest::load(&manifest_path)?;

    // Reconstruct the verifying key from the manifest.
    let vk_bytes = manifest.verifying_key_bytes()?;
    let algo = parse_algorithm(&manifest.algorithm)?;
    let vk_inner = VerifyingKey::new(vk_bytes, algo, manifest.verifying_key_id.clone());

    if let Some(expected) = expected_verifying_key {
        let exp = expected.core();
        if exp.bytes != vk_inner.bytes || exp.algorithm != vk_inner.algorithm {
            return Err(ArchiveError::VerifyingKeyMismatch);
        }
    }

    let cfg = Config::builder()
        .security_level(quantumvault_core::SecurityLevel::Level5)
        .build()?;

    let mut report = VerifyReport {
        verified: Vec::new(),
        missing: Vec::new(),
        hash_mismatch: Vec::new(),
        signature_invalid: Vec::new(),
        extra_on_disk: Vec::new(),
    };

    // Sealed file → expected hash + signature.
    let mut sealed_paths: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in &manifest.entries {
        sealed_paths.insert(entry.path.clone());
        let abs = archive_root.join(&entry.path);

        if !abs.exists() {
            report.missing.push(abs);
            continue;
        }

        let computed = match hash_file(&abs) {
            Ok(h) => h,
            Err(_) => {
                report.missing.push(abs);
                continue;
            }
        };
        let expected = from_hex(&entry.sha3_256)?;
        if computed != expected {
            report.hash_mismatch.push(abs);
            continue;
        }

        let sig_bytes = B64.decode(&entry.signature)?;
        let signature = Signature {
            bytes: sig_bytes,
            algorithm: algo,
            key_id: manifest.verifying_key_id.clone(),
            signed_at: 0,
        };
        let ok = core_verify::verify_signature(&computed, &signature, &vk_inner, &cfg)?;
        if !ok {
            report.signature_invalid.push(abs);
            continue;
        }

        report.verified.push(abs);
    }

    // Find files present on disk but not in the manifest. Skip the
    // manifest itself + hidden files (matches sealer's default behaviour).
    for dir_entry in walkdir::WalkDir::new(archive_root).follow_links(false) {
        let dir_entry = match dir_entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !dir_entry.file_type().is_file() {
            continue;
        }
        let abs = dir_entry.path();
        if abs
            .file_name()
            .map(|n| n == MANIFEST_FILE_NAME)
            .unwrap_or(false)
        {
            continue;
        }
        let rel = match abs.strip_prefix(archive_root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rel_str = rel
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect::<Vec<_>>()
            .join("/");
        if rel.components().any(|c| {
            c.as_os_str()
                .to_str()
                .map(|s| s.starts_with('.'))
                .unwrap_or(false)
        }) {
            continue;
        }
        if !sealed_paths.contains(&rel_str) {
            report.extra_on_disk.push(abs.to_path_buf());
        }
    }

    Ok(report)
}

fn parse_algorithm(s: &str) -> Result<quantumvault_core::Algorithm> {
    use quantumvault_core::Algorithm;
    match s {
        "SLH-DSA-SHAKE-128s" => Ok(Algorithm::SlhDsaShake128s),
        "SLH-DSA-SHAKE-128f" => Ok(Algorithm::SlhDsaShake128f),
        "SLH-DSA-SHAKE-256s" => Ok(Algorithm::SlhDsaShake256s),
        "SLH-DSA-SHAKE-256f" => Ok(Algorithm::SlhDsaShake256f),
        other => Err(ArchiveError::ManifestMalformed(format!(
            "manifest algorithm must be SLH-DSA-SHAKE-*, got {other:?}"
        ))),
    }
}

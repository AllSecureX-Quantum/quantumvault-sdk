//! Long-lived archival signing keys (SLH-DSA-SHAKE-256s).
//!
//! The signing key is kept offline (USB stick, HSM, customer's PKCS#11 token)
//! and only loaded into memory at seal time. The verifying key ships
//! alongside the manifest so auditors can verify without holding any secret
//! material.
//!
//! We default to **SLH-DSA-SHAKE-256s** (the "small signature, slow signing"
//! variant). For archival workloads sealing happens once and verify happens
//! occasionally — small signatures matter more than fast signing.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::api::keygen as core_keygen;
use quantumvault_core::{Algorithm, Config, SecurityLevel};

use crate::error::{ArchiveError, Result};

/// Default algorithm used for archival signatures.
///
/// We use the **small / slow** variant intentionally: archive sealing
/// happens once at write time, but the resulting signature lives forever
/// in the manifest. Optimising for signature size keeps the manifest
/// readable and storage-efficient.
pub const DEFAULT_ALGORITHM: Algorithm = Algorithm::SlhDsaShake256s;

/// Signing key for sealing. Keep offline; never ship to the customer side
/// of a verification deployment.
pub struct ArchiveSigningKey {
    inner: quantumvault_core::SigningKey,
}

/// Verifying key for opening a sealed manifest. Safe to publish.
pub struct ArchiveVerifyingKey {
    inner: quantumvault_core::VerifyingKey,
}

/// Fresh SLH-DSA-SHAKE-256s key pair.
pub fn generate_keypair() -> Result<(ArchiveSigningKey, ArchiveVerifyingKey)> {
    let cfg = Config::builder()
        .security_level(SecurityLevel::Level5)
        .build()?;
    let kp = core_keygen::generate_signature_keypair(DEFAULT_ALGORITHM, &cfg)?;
    Ok((
        ArchiveSigningKey {
            inner: kp.signing_key,
        },
        ArchiveVerifyingKey {
            inner: kp.verifying_key,
        },
    ))
}

impl ArchiveSigningKey {
    /// Construct from raw bytes + algorithm.
    pub(crate) fn from_inner(inner: quantumvault_core::SigningKey) -> Self {
        Self { inner }
    }

    /// Borrow the core signing key (used internally by the sealer).
    pub(crate) fn core(&self) -> &quantumvault_core::SigningKey {
        &self.inner
    }

    /// Save the signing key to a path. Writes JSON containing the
    /// algorithm + base64-encoded key bytes. Set restrictive permissions on
    /// the resulting file — this is secret material.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&KeyFile::from_signing(&self.inner))?;
        let mut tmp_path = path.to_path_buf();
        tmp_path.set_extension("tmp");
        let mut f = fs::File::create(&tmp_path).map_err(|e| ArchiveError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        f.write_all(json.as_bytes()).map_err(|e| ArchiveError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        f.sync_all().map_err(|e| ArchiveError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        drop(f);

        // Restrict perms before rename on Unix (0600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms).map_err(|e| ArchiveError::Io {
                path: tmp_path.clone(),
                source: e,
            })?;
        }

        fs::rename(&tmp_path, path).map_err(|e| ArchiveError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }

    /// Load a signing key from a path previously written by
    /// [`ArchiveSigningKey::save_to_file`].
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path).map_err(|e| ArchiveError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let file: KeyFile = serde_json::from_str(&s)?;
        let bytes = B64.decode(&file.bytes)?;
        let algo = parse_algorithm(&file.algorithm)?;
        let inner = quantumvault_core::SigningKey::new(bytes, algo, file.key_id);
        Ok(Self { inner })
    }
}

impl ArchiveVerifyingKey {
    /// Construct from a core verifying key.
    pub(crate) fn from_inner(inner: quantumvault_core::VerifyingKey) -> Self {
        Self { inner }
    }

    /// Borrow the core verifying key.
    pub(crate) fn core(&self) -> &quantumvault_core::VerifyingKey {
        &self.inner
    }

    /// Raw bytes of the verifying key.
    pub fn bytes(&self) -> &[u8] {
        &self.inner.bytes
    }

    /// Algorithm string ("SLH-DSA-SHAKE-256s" etc).
    pub fn algorithm(&self) -> String {
        self.inner.algorithm.to_string()
    }

    /// Save the verifying key to a path (safe to share).
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&KeyFile::from_verifying(&self.inner))?;
        fs::write(path, json).map_err(|e| ArchiveError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Load a verifying key from a path previously written by
    /// [`ArchiveVerifyingKey::save_to_file`].
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path).map_err(|e| ArchiveError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let file: KeyFile = serde_json::from_str(&s)?;
        let bytes = B64.decode(&file.bytes)?;
        let algo = parse_algorithm(&file.algorithm)?;
        let inner = quantumvault_core::VerifyingKey::new(bytes, algo, file.key_id);
        Ok(Self { inner })
    }
}

// =====================================================================
// On-disk key-file format
// =====================================================================

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    /// Algorithm name (e.g. "SLH-DSA-SHAKE-256s").
    algorithm: String,
    /// Key identifier.
    key_id: String,
    /// Base64-encoded key bytes.
    bytes: String,
    /// Always "qvarchive-key:v1".
    format: String,
}

impl KeyFile {
    fn from_signing(sk: &quantumvault_core::SigningKey) -> Self {
        Self {
            algorithm: wire_name(sk.algorithm).into(),
            key_id: sk.key_id.clone(),
            bytes: B64.encode(sk.as_bytes()),
            format: "qvarchive-key:v1".into(),
        }
    }
    fn from_verifying(vk: &quantumvault_core::VerifyingKey) -> Self {
        Self {
            algorithm: wire_name(vk.algorithm).into(),
            key_id: vk.key_id.clone(),
            bytes: B64.encode(&vk.bytes),
            format: "qvarchive-key:v1".into(),
        }
    }
}

/// Wire-format name for an SLH-DSA algorithm — matches the serde rename in
/// `quantumvault_core::Algorithm`. We can't use `Display` because that
/// includes a "(SPHINCS+)" suffix for human-readable logs.
pub(crate) fn wire_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
        Algorithm::SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
        Algorithm::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
        Algorithm::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
        // ML-DSA / ML-KEM aren't valid for archive signing but we return a
        // best-effort name so logging doesn't lose information.
        Algorithm::MlDsa44 => "ML-DSA-44",
        Algorithm::MlDsa65 => "ML-DSA-65",
        Algorithm::MlDsa87 => "ML-DSA-87",
        Algorithm::MlKem512 => "ML-KEM-512",
        Algorithm::MlKem768 => "ML-KEM-768",
        Algorithm::MlKem1024 => "ML-KEM-1024",
        _ => "UNKNOWN",
    }
}

/// Parse an algorithm string from a key file back to the core enum.
/// We only accept the SLH-DSA variants for archive signing keys — anything
/// else is a misconfigured key file.
fn parse_algorithm(s: &str) -> Result<Algorithm> {
    match s {
        "SLH-DSA-SHAKE-128s" => Ok(Algorithm::SlhDsaShake128s),
        "SLH-DSA-SHAKE-128f" => Ok(Algorithm::SlhDsaShake128f),
        "SLH-DSA-SHAKE-256s" => Ok(Algorithm::SlhDsaShake256s),
        "SLH-DSA-SHAKE-256f" => Ok(Algorithm::SlhDsaShake256f),
        other => Err(ArchiveError::ManifestMalformed(format!(
            "key file algorithm must be SLH-DSA-SHAKE-*, got {other:?}"
        ))),
    }
}

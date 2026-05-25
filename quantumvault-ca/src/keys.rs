//! CA signing keys (ML-DSA-65 by default).
//!
//! On-disk JSON format with the same shape as the rest of the SDK
//! (`algorithm` + `key_id` + base64 `bytes` + a `format` tag).

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::api::keygen as core_keygen;
use quantumvault_core::{Algorithm, Config, SecurityLevel};
use quantumvault_pkcs11::{read_dev_kek_file, KekProvider, WrappedKey};

use crate::error::{CaError, Result};

/// AAD bound into HSM-wrapped CA signing keys. Constant — every qvca
/// wrapped key uses the same value, so callers don't have to manage it.
/// The KEK itself is the secret; the AAD just scopes the envelope to
/// the qvca key schema (catches "this was wrapped for a different
/// product / format version").
const QVCA_HSM_AAD: &[u8] = b"qvca-signing-key:v1";

/// CA signing key (ML-DSA, secret material — never publish).
pub struct CaSigningKey {
    inner: quantumvault_core::SigningKey,
}

/// CA verifying key (ML-DSA, safe to publish — distribute as a trust
/// anchor inside leaf certificates and root-cert bundles).
#[derive(Clone)]
pub struct CaVerifyingKey {
    inner: quantumvault_core::VerifyingKey,
}

/// Generate a fresh ML-DSA-65 keypair for CA use.
pub fn generate_keypair() -> Result<(CaSigningKey, CaVerifyingKey)> {
    let cfg = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()?;
    let kp = core_keygen::generate_signature_keypair(Algorithm::MlDsa65, &cfg)?;
    Ok((
        CaSigningKey {
            inner: kp.signing_key,
        },
        CaVerifyingKey {
            inner: kp.verifying_key,
        },
    ))
}

impl CaSigningKey {
    pub(crate) fn core(&self) -> &quantumvault_core::SigningKey {
        &self.inner
    }

    /// Persist with restrictive permissions (0o600 on Unix).
    ///
    /// If `kek_path` is `Some`, the on-disk file is a
    /// [`quantumvault_pkcs11::WrappedKey`] envelope: the
    /// [`KeyFile`] JSON is encrypted under an AES-256 KEK loaded from
    /// the supplied dev-KEK file (in production an HSM-resident KEK).
    /// If `kek_path` is `None`, the file is a plain [`KeyFile`].
    ///
    /// Both file shapes have the same on-disk extension; loaders
    /// auto-detect by parsing.
    pub fn save_to_file(&self, path: &Path, kek_path: Option<&Path>) -> Result<()> {
        let plain_json = serde_json::to_vec(&KeyFile::from_signing(&self.inner))?;
        let bytes_to_write = match kek_path {
            None => plain_json,
            Some(kek_path) => {
                let kek = read_dev_kek_file(kek_path)?;
                let env = kek.wrap(&plain_json, QVCA_HSM_AAD)?;
                serde_json::to_vec_pretty(&env)?
            }
        };
        atomic_write_secret(path, &bytes_to_write)
    }

    /// Load from disk. Auto-detects whether the file is a plain
    /// [`KeyFile`] or a wrapped envelope and routes appropriately. If
    /// the file is wrapped and `kek_path` is `None`, returns
    /// [`CaError::Hsm`] with a clear "this key file is wrapped; pass
    /// --hsm-kek" message.
    pub fn load_from_file(path: &Path, kek_path: Option<&Path>) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        if let Some(plain_json) = unwrap_if_wrapped(&s, kek_path)? {
            let f: KeyFile = serde_json::from_slice(&plain_json)?;
            return Self::from_keyfile(f);
        }
        let f: KeyFile = serde_json::from_str(&s)?;
        Self::from_keyfile(f)
    }

    fn from_keyfile(f: KeyFile) -> Result<Self> {
        let bytes = B64.decode(&f.bytes)?;
        let algo = parse_algorithm(&f.algorithm)?;
        Ok(Self {
            inner: quantumvault_core::SigningKey::new(bytes, algo, f.key_id),
        })
    }
}

/// If `s` parses as a [`WrappedKey`] envelope, unwrap and return the
/// plaintext bytes. Otherwise return `Ok(None)` — caller falls through
/// to the plain-file path.
fn unwrap_if_wrapped(s: &str, kek_path: Option<&Path>) -> Result<Option<Vec<u8>>> {
    // Heuristic: a wrapped envelope is JSON that has `algorithm: "AES-256-GCM"`.
    // Plain qvca keyfiles have `format: "qvca-key:v1"`. We try the envelope
    // shape first; if serde rejects it we fall through.
    let Ok(env): std::result::Result<WrappedKey, _> = serde_json::from_str(s) else {
        return Ok(None);
    };
    if env.algorithm != "AES-256-GCM" {
        return Ok(None);
    }
    let kek_path = kek_path.ok_or_else(|| {
        CaError::Hsm(
            "this signing key file is HSM-wrapped — pass --hsm-kek <dev-kek.json> to unwrap".into(),
        )
    })?;
    let kek = read_dev_kek_file(kek_path)?;
    let pt = kek.unwrap(&env, QVCA_HSM_AAD)?;
    Ok(Some(pt.to_vec()))
}

fn atomic_write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

impl CaVerifyingKey {
    pub(crate) fn core(&self) -> &quantumvault_core::VerifyingKey {
        &self.inner
    }

    /// Raw verifying-key bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.inner.bytes
    }

    /// Key identifier.
    pub fn key_id(&self) -> &str {
        &self.inner.key_id
    }

    /// Algorithm wire name ("ML-DSA-65").
    pub fn algorithm(&self) -> &'static str {
        wire_name(self.inner.algorithm)
    }

    /// Persist (safe to share publicly).
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&KeyFile::from_verifying(&self.inner))?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load from disk.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        let f: KeyFile = serde_json::from_str(&s)?;
        let bytes = B64.decode(&f.bytes)?;
        let algo = parse_algorithm(&f.algorithm)?;
        Ok(Self {
            inner: quantumvault_core::VerifyingKey::new(bytes, algo, f.key_id),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    algorithm: String,
    key_id: String,
    bytes: String,
    format: String,
}

impl KeyFile {
    fn from_signing(sk: &quantumvault_core::SigningKey) -> Self {
        Self {
            algorithm: wire_name(sk.algorithm).into(),
            key_id: sk.key_id.clone(),
            bytes: B64.encode(sk.as_bytes()),
            format: "qvca-key:v1".into(),
        }
    }
    fn from_verifying(vk: &quantumvault_core::VerifyingKey) -> Self {
        Self {
            algorithm: wire_name(vk.algorithm).into(),
            key_id: vk.key_id.clone(),
            bytes: B64.encode(&vk.bytes),
            format: "qvca-key:v1".into(),
        }
    }
}

pub(crate) fn wire_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::MlDsa44 => "ML-DSA-44",
        Algorithm::MlDsa65 => "ML-DSA-65",
        Algorithm::MlDsa87 => "ML-DSA-87",
        _ => "UNSUPPORTED",
    }
}

pub(crate) fn parse_algorithm(s: &str) -> Result<Algorithm> {
    match s {
        "ML-DSA-44" => Ok(Algorithm::MlDsa44),
        "ML-DSA-65" => Ok(Algorithm::MlDsa65),
        "ML-DSA-87" => Ok(Algorithm::MlDsa87),
        other => Err(CaError::MalformedCertificate(format!(
            "CA algorithm must be ML-DSA-*, got {other:?}"
        ))),
    }
}

pub(crate) fn security_level_for(alg: Algorithm) -> SecurityLevel {
    match alg {
        Algorithm::MlDsa44 => SecurityLevel::Level2,
        Algorithm::MlDsa65 => SecurityLevel::Level3,
        Algorithm::MlDsa87 => SecurityLevel::Level5,
        _ => SecurityLevel::Level3,
    }
}

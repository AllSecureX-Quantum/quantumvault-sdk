//! DNSSEC signing keys — ZSK + KSK pair, both ML-DSA-65.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::api::keygen as core_keygen;
use quantumvault_core::{Algorithm, Config, SecurityLevel};
use quantumvault_pkcs11::{read_dev_kek_file, KekProvider, WrappedKey};

use crate::error::{DnssecError, Result};

/// AAD bound into HSM-wrapped DNSSEC signing keys. Constant per
/// schema — scopes the envelope to qvdnssec so a key wrapped for
/// another product can't be unwrapped here even if the KEK matches.
const QVDNSSEC_HSM_AAD: &[u8] = b"qvdnssec-signing-key:v1";

/// DNSSEC signing key (secret material).
pub struct DnssecSigningKey {
    inner: quantumvault_core::SigningKey,
}

/// DNSSEC verifying key (public). The KSK's verifying key acts as the
/// trust anchor (analogous to a DS record in classical DNSSEC).
#[derive(Clone)]
pub struct DnssecVerifyingKey {
    inner: quantumvault_core::VerifyingKey,
}

/// Generate a fresh ML-DSA-65 keypair for DNSSEC use.
pub fn generate_keypair() -> Result<(DnssecSigningKey, DnssecVerifyingKey)> {
    let cfg = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()?;
    let kp = core_keygen::generate_signature_keypair(Algorithm::MlDsa65, &cfg)?;
    Ok((
        DnssecSigningKey {
            inner: kp.signing_key,
        },
        DnssecVerifyingKey {
            inner: kp.verifying_key,
        },
    ))
}

impl DnssecSigningKey {
    pub(crate) fn core(&self) -> &quantumvault_core::SigningKey {
        &self.inner
    }

    /// Save with 0o600 perms on Unix.
    ///
    /// If `kek_path` is `Some`, writes a [`quantumvault_pkcs11::WrappedKey`]
    /// envelope instead of a plaintext key file. The loader auto-detects.
    pub fn save_to_file(&self, path: &Path, kek_path: Option<&Path>) -> Result<()> {
        let plain_json = serde_json::to_vec(&KeyFile::from_signing(&self.inner))?;
        let bytes = match kek_path {
            None => plain_json,
            Some(kek_path) => {
                let kek = read_dev_kek_file(kek_path)?;
                let env = kek.wrap(&plain_json, QVDNSSEC_HSM_AAD)?;
                serde_json::to_vec_pretty(&env)?
            }
        };
        atomic_write_secret(path, &bytes)
    }

    /// Load from disk. Auto-detects plain vs wrapped. If wrapped and
    /// `kek_path` is `None`, returns a clear "pass --hsm-kek" error.
    pub fn load_from_file(path: &Path, kek_path: Option<&Path>) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        if let Some(plain) = unwrap_if_wrapped(&s, kek_path)? {
            let f: KeyFile = serde_json::from_slice(&plain)?;
            return Self::from_keyfile(f);
        }
        let f: KeyFile = serde_json::from_str(&s)?;
        Self::from_keyfile(f)
    }

    fn from_keyfile(f: KeyFile) -> Result<Self> {
        let bytes = B64.decode(&f.bytes)?;
        Ok(Self {
            inner: quantumvault_core::SigningKey::new(bytes, Algorithm::MlDsa65, f.key_id),
        })
    }
}

fn unwrap_if_wrapped(s: &str, kek_path: Option<&Path>) -> Result<Option<Vec<u8>>> {
    let Ok(env): std::result::Result<WrappedKey, _> = serde_json::from_str(s) else {
        return Ok(None);
    };
    if env.algorithm != "AES-256-GCM" {
        return Ok(None);
    }
    let kek_path = kek_path.ok_or_else(|| {
        DnssecError::Hsm(
            "this signing key file is HSM-wrapped — pass --hsm-kek <dev-kek.json> to unwrap".into(),
        )
    })?;
    let kek = read_dev_kek_file(kek_path)?;
    let pt = kek.unwrap(&env, QVDNSSEC_HSM_AAD)?;
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

impl DnssecVerifyingKey {
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

    /// SHA-3-256 fingerprint (hex). Used as the DNSSEC trust anchor.
    pub fn fingerprint(&self) -> String {
        crate::hashing::to_hex(&crate::hashing::hash_bytes(&self.inner.bytes))
    }

    /// Save (safe to share — this is the trust anchor).
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
        Ok(Self {
            inner: quantumvault_core::VerifyingKey::new(bytes, Algorithm::MlDsa65, f.key_id),
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
            algorithm: "ML-DSA-65".into(),
            key_id: sk.key_id.clone(),
            bytes: B64.encode(sk.as_bytes()),
            format: "qvdnssec-key:v1".into(),
        }
    }
    fn from_verifying(vk: &quantumvault_core::VerifyingKey) -> Self {
        Self {
            algorithm: "ML-DSA-65".into(),
            key_id: vk.key_id.clone(),
            bytes: B64.encode(&vk.bytes),
            format: "qvdnssec-key:v1".into(),
        }
    }
}

//! S/MIME signing keys (ML-DSA-65 by default).
//!
//! Re-uses the on-disk key-file format from `quantumvault-archive` so a
//! deployment can keep one key store and use the same keys for both
//! archival sealing (SLH-DSA) and S/MIME signing (ML-DSA-65). The
//! difference is the algorithm at keygen time.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::api::keygen as core_keygen;
use quantumvault_core::{Algorithm, Config, SecurityLevel};
use quantumvault_pkcs11::{read_dev_kek_file, KekProvider, WrappedKey};

use crate::error::{Result, SmimeError};

/// AAD bound into HSM-wrapped S/MIME signing keys.
const QVSMIME_HSM_AAD: &[u8] = b"qvsmime-signing-key:v1";

/// Default algorithm for S/MIME signing. ML-DSA-65 (FIPS 204, NIST Level 3)
/// is the right pick for per-message signing — small signatures, fast.
pub const DEFAULT_ALGORITHM: Algorithm = Algorithm::MlDsa65;

/// S/MIME signing key. Keep offline / in a KMS / HSM.
pub struct SmimeSigningKey {
    inner: quantumvault_core::SigningKey,
}

/// S/MIME verifying key. Safe to publish (e.g. in a DNS TXT record, a
/// public JWKS, or a company website footer).
#[derive(Clone)]
pub struct SmimeVerifyingKey {
    inner: quantumvault_core::VerifyingKey,
}

/// Generate a fresh ML-DSA-65 signing keypair for S/MIME use.
pub fn generate_keypair() -> Result<(SmimeSigningKey, SmimeVerifyingKey)> {
    let cfg = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()?;
    let kp = core_keygen::generate_signature_keypair(DEFAULT_ALGORITHM, &cfg)?;
    Ok((
        SmimeSigningKey {
            inner: kp.signing_key,
        },
        SmimeVerifyingKey {
            inner: kp.verifying_key,
        },
    ))
}

impl SmimeSigningKey {
    /// Borrow the underlying core signing key (internal use only).
    pub(crate) fn core(&self) -> &quantumvault_core::SigningKey {
        &self.inner
    }

    /// Save to a JSON file with the same format as the archive sealer.
    /// On Unix the file is written with 0600 permissions.
    ///
    /// If `kek_path` is `Some`, the on-disk file is a
    /// [`quantumvault_pkcs11::WrappedKey`] envelope and the signing
    /// key never sits on disk in cleartext.
    pub fn save_to_file(&self, path: &Path, kek_path: Option<&Path>) -> Result<()> {
        let plain = serde_json::to_vec(&KeyFile::from_signing(&self.inner))?;
        let bytes = match kek_path {
            None => plain,
            Some(p) => {
                let kek = read_dev_kek_file(p)?;
                let env = kek.wrap(&plain, QVSMIME_HSM_AAD)?;
                serde_json::to_vec_pretty(&env)?
            }
        };
        atomic_write_secret(path, &bytes)
    }

    /// Load from a file previously written by [`SmimeSigningKey::save_to_file`].
    /// Auto-detects plain vs wrapped. If wrapped and `kek_path` is `None`,
    /// returns a clear "pass --hsm-kek" error.
    pub fn load_from_file(path: &Path, kek_path: Option<&Path>) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        if let Some(plain) = unwrap_if_wrapped(&s, kek_path)? {
            let file: KeyFile = serde_json::from_slice(&plain)?;
            return Self::from_keyfile(file);
        }
        let file: KeyFile = serde_json::from_str(&s)?;
        Self::from_keyfile(file)
    }

    fn from_keyfile(file: KeyFile) -> Result<Self> {
        let bytes = B64.decode(&file.bytes)?;
        let algo = parse_algorithm(&file.algorithm)?;
        Ok(Self {
            inner: quantumvault_core::SigningKey::new(bytes, algo, file.key_id),
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
        SmimeError::EnvelopeMalformed(
            "this signing key file is HSM-wrapped — pass --hsm-kek <dev-kek.json> to unwrap".into(),
        )
    })?;
    let kek = read_dev_kek_file(kek_path)?;
    let pt = kek.unwrap(&env, QVSMIME_HSM_AAD)?;
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

impl SmimeVerifyingKey {
    /// Borrow the underlying core verifying key (internal use only).
    pub(crate) fn core(&self) -> &quantumvault_core::VerifyingKey {
        &self.inner
    }

    /// Raw bytes of the verifying key.
    pub fn bytes(&self) -> &[u8] {
        &self.inner.bytes
    }

    /// Key identifier.
    pub fn key_id(&self) -> &str {
        &self.inner.key_id
    }

    /// Algorithm name (e.g. `"ML-DSA-65"`).
    pub fn algorithm_name(&self) -> &'static str {
        wire_name(self.inner.algorithm)
    }

    /// Save to a JSON file (safe to share publicly).
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&KeyFile::from_verifying(&self.inner))?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load from a file previously written by [`SmimeVerifyingKey::save_to_file`].
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        let file: KeyFile = serde_json::from_str(&s)?;
        let bytes = B64.decode(&file.bytes)?;
        let algo = parse_algorithm(&file.algorithm)?;
        Ok(Self {
            inner: quantumvault_core::VerifyingKey::new(bytes, algo, file.key_id),
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
            format: "qvsmime-key:v1".into(),
        }
    }
    fn from_verifying(vk: &quantumvault_core::VerifyingKey) -> Self {
        Self {
            algorithm: wire_name(vk.algorithm).into(),
            key_id: vk.key_id.clone(),
            bytes: B64.encode(&vk.bytes),
            format: "qvsmime-key:v1".into(),
        }
    }
}

/// Wire-format name for ML-DSA / SLH-DSA algorithms (no Display suffix).
pub(crate) fn wire_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::MlDsa44 => "ML-DSA-44",
        Algorithm::MlDsa65 => "ML-DSA-65",
        Algorithm::MlDsa87 => "ML-DSA-87",
        Algorithm::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
        Algorithm::SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
        Algorithm::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
        Algorithm::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
        _ => "UNSUPPORTED",
    }
}

/// Map wire algorithm string to the core enum. We only accept ML-DSA
/// algorithms for S/MIME signing.
pub(crate) fn parse_algorithm(s: &str) -> Result<Algorithm> {
    match s {
        "ML-DSA-44" => Ok(Algorithm::MlDsa44),
        "ML-DSA-65" => Ok(Algorithm::MlDsa65),
        "ML-DSA-87" => Ok(Algorithm::MlDsa87),
        other => Err(SmimeError::EnvelopeMalformed(format!(
            "S/MIME algorithm must be ML-DSA-*, got {other:?}"
        ))),
    }
}

/// Security level for an algorithm (used internally to build a Config).
pub(crate) fn security_level_for(alg: Algorithm) -> SecurityLevel {
    match alg {
        Algorithm::MlDsa44 => SecurityLevel::Level2,
        Algorithm::MlDsa65 => SecurityLevel::Level3,
        Algorithm::MlDsa87 => SecurityLevel::Level5,
        _ => SecurityLevel::Level3,
    }
}

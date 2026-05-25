//! On-disk verifying-key format for the proxy.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::{Algorithm, VerifyingKey};
use serde::{Deserialize, Serialize};

/// JSON layout of `verifying.json`. Carries algorithm name, key id, and
/// base64-encoded raw verifying-key bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyingKeyFile {
    /// Algorithm wire name, e.g. `"ML-DSA-65"`.
    pub algorithm: String,
    /// Key identifier (matches the JWT header's `kid`, if present).
    pub key_id: String,
    /// Base64-encoded verifying-key bytes.
    pub bytes: String,
    /// Always `"qvjwt-vk:v1"` — identifies this file format.
    #[serde(default)]
    pub format: String,
}

impl VerifyingKeyFile {
    /// Load from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path)
            .with_context(|| format!("read verifying-key file {path:?}"))?;
        let f: Self = serde_json::from_str(&s)
            .with_context(|| format!("parse verifying-key JSON at {path:?}"))?;
        Ok(f)
    }

    /// Convert to a `quantumvault_core::VerifyingKey` we can hand to
    /// `quantumvault_jose`.
    pub fn into_core(self) -> Result<VerifyingKey> {
        let algo = parse_algorithm(&self.algorithm)?;
        let bytes = B64
            .decode(&self.bytes)
            .with_context(|| "base64-decode verifying-key bytes")?;
        Ok(VerifyingKey::new(bytes, algo, self.key_id))
    }
}

/// Convenience: read the file at `path` and convert in one call.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    VerifyingKeyFile::load(path)?.into_core()
}

fn parse_algorithm(s: &str) -> Result<Algorithm> {
    match s {
        "ML-DSA-44" => Ok(Algorithm::MlDsa44),
        "ML-DSA-65" => Ok(Algorithm::MlDsa65),
        "ML-DSA-87" => Ok(Algorithm::MlDsa87),
        other => Err(anyhow!(
            "unsupported JWT algorithm {other:?} — must be ML-DSA-44 / 65 / 87"
        )),
    }
}

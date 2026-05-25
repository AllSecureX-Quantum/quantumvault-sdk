//! On-disk manifest format.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{DnssecError, Result};

/// Current manifest format version.
pub const MANIFEST_VERSION: u8 = 1;

/// Label on the manifest's ZSK block.
pub const ZSK_LABEL: &str = "ZSK";
/// Label on the manifest's KSK block.
pub const KSK_LABEL: &str = "KSK";

/// One RRSet's signed entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RrsetEntry {
    /// `name|class|type` key.
    pub key: String,
    /// SHA-3-256 of canonical RRSet bytes (lowercase hex).
    pub sha3_256: String,
    /// Base64 ML-DSA signature by the ZSK over the hash bytes.
    pub signature: String,
}

/// Block describing a DNSSEC key inside the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyBlock {
    /// `"ZSK"` or `"KSK"`.
    pub label: String,
    /// Algorithm name (always `"ML-DSA-65"` in v1).
    pub algorithm: String,
    /// Verifying-key identifier.
    pub key_id: String,
    /// Base64 verifying-key bytes.
    pub bytes: String,
    /// SHA-3-256 fingerprint of the verifying-key bytes.
    pub fingerprint: String,
    /// Base64 signature by the KSK over the ZSK's verifying-key bytes.
    /// Only present on the ZSK block; `None` on the KSK (which is the
    /// self-anchoring trust root).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_by_ksk: Option<String>,
}

/// Manifest produced by `sign_zone` and consumed by `verify_zone`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZoneManifest {
    /// Format version.
    pub version: u8,
    /// Zone origin / apex (e.g. `"example.com."`).
    pub zone: String,
    /// Algorithm used throughout (always `"ML-DSA-65"` in v1).
    pub algorithm: String,
    /// Manifest creation timestamp (RFC 3339).
    pub signed_at: DateTime<Utc>,
    /// KSK block (trust anchor).
    pub ksk: KeyBlock,
    /// ZSK block (signed by the KSK).
    pub zsk: KeyBlock,
    /// One entry per RRSet, sorted by `key`.
    pub rrsets: Vec<RrsetEntry>,
}

impl ZoneManifest {
    /// Save with an atomic tmp+rename.
    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        let mut tmp = path.to_path_buf();
        tmp.set_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load from disk and validate the format version.
    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        let m: Self = serde_json::from_str(&s)
            .map_err(|e| DnssecError::MalformedManifest(format!("parse: {e}")))?;
        if m.version != MANIFEST_VERSION {
            return Err(DnssecError::UnsupportedManifestVersion(m.version));
        }
        Ok(m)
    }
}

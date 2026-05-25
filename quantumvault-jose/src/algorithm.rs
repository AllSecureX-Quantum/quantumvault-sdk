//! Supported JOSE `alg` header values.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// JWS signing algorithm.
///
/// These map onto NIST FIPS 204 ML-DSA at three security levels.
/// The `alg` header values shipped on the wire are exactly the strings
/// shown in the doc comments below; they're stable and form part of the
/// public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// `ML-DSA-44` — NIST Level 2. ~2 420-byte signatures.
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,
    /// `ML-DSA-65` — NIST Level 3 (default). ~3 309-byte signatures.
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    /// `ML-DSA-87` — NIST Level 5 (CNSA 2.0). ~4 627-byte signatures.
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
}

impl Algorithm {
    /// Return the `alg` string as it appears in JWS headers.
    pub fn as_str(&self) -> &'static str {
        match self {
            Algorithm::MlDsa44 => "ML-DSA-44",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Map to the core algorithm enum used by the underlying crypto crate.
    pub(crate) fn to_core(self) -> quantumvault_core::Algorithm {
        match self {
            Algorithm::MlDsa44 => quantumvault_core::Algorithm::MlDsa44,
            Algorithm::MlDsa65 => quantumvault_core::Algorithm::MlDsa65,
            Algorithm::MlDsa87 => quantumvault_core::Algorithm::MlDsa87,
        }
    }

    /// Map from a wire `alg` string back to an `Algorithm`.
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "ML-DSA-44" => Ok(Algorithm::MlDsa44),
            "ML-DSA-65" => Ok(Algorithm::MlDsa65),
            "ML-DSA-87" => Ok(Algorithm::MlDsa87),
            other => Err(Error::UnsupportedAlgorithm(other.to_string())),
        }
    }

    /// The NIST security level (2, 3 or 5).
    pub fn security_level(&self) -> u8 {
        match self {
            Algorithm::MlDsa44 => 2,
            Algorithm::MlDsa65 => 3,
            Algorithm::MlDsa87 => 5,
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::MlDsa65
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

//! NIST security level definitions and algorithm mappings.

use crate::error::{Error, Result};
use crate::primitives::Algorithm;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// NIST Post-Quantum Cryptography Security Levels.
///
/// These levels correspond to the security strength of classical algorithms:
/// - Level 1: At least as hard to break as AES-128
/// - Level 2: At least as hard to break as SHA-256
/// - Level 3: At least as hard to break as AES-192
/// - Level 4: At least as hard to break as SHA-384
/// - Level 5: At least as hard to break as AES-256
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// NIST Level 1 - Equivalent to AES-128 security.
    #[serde(rename = "level1")]
    Level1 = 1,
    /// NIST Level 2 - Equivalent to SHA-256 collision resistance.
    #[serde(rename = "level2")]
    Level2 = 2,
    /// NIST Level 3 - Equivalent to AES-192 security (recommended default).
    #[serde(rename = "level3")]
    Level3 = 3,
    /// NIST Level 4 - Equivalent to SHA-384 collision resistance.
    #[serde(rename = "level4")]
    Level4 = 4,
    /// NIST Level 5 - Equivalent to AES-256 security (highest).
    #[serde(rename = "level5")]
    Level5 = 5,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Level3
    }
}

impl SecurityLevel {
    /// Get the numeric value of the security level.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Get the recommended ML-KEM variant for this security level.
    pub fn recommended_kem(&self) -> Algorithm {
        match self {
            Self::Level1 | Self::Level2 => Algorithm::MlKem512,
            Self::Level3 | Self::Level4 => Algorithm::MlKem768,
            Self::Level5 => Algorithm::MlKem1024,
        }
    }

    /// Get the recommended ML-DSA variant for this security level.
    pub fn recommended_dsa(&self) -> Algorithm {
        match self {
            Self::Level1 | Self::Level2 => Algorithm::MlDsa44,
            Self::Level3 | Self::Level4 => Algorithm::MlDsa65,
            Self::Level5 => Algorithm::MlDsa87,
        }
    }

    /// Get the recommended hash-based signature for this security level.
    pub fn recommended_hash_signature(&self) -> Algorithm {
        match self {
            Self::Level1 | Self::Level2 | Self::Level3 => Algorithm::SlhDsaShake128s,
            Self::Level4 | Self::Level5 => Algorithm::SlhDsaShake256s,
        }
    }

    /// Check if an algorithm meets this security level.
    pub fn algorithm_meets_level(&self, algorithm: Algorithm) -> bool {
        algorithm.security_level() >= *self
    }

    /// Get a human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Level1 => "NIST Level 1 - AES-128 equivalent (basic security)",
            Self::Level2 => "NIST Level 2 - SHA-256 collision resistance",
            Self::Level3 => "NIST Level 3 - AES-192 equivalent (recommended)",
            Self::Level4 => "NIST Level 4 - SHA-384 collision resistance",
            Self::Level5 => "NIST Level 5 - AES-256 equivalent (highest security)",
        }
    }

    /// Get the equivalent classical security in bits.
    pub fn classical_security_bits(&self) -> u32 {
        match self {
            Self::Level1 => 128,
            Self::Level2 => 128,
            Self::Level3 => 192,
            Self::Level4 => 192,
            Self::Level5 => 256,
        }
    }
}

impl FromStr for SecurityLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "1" | "level1" | "l1" => Ok(Self::Level1),
            "2" | "level2" | "l2" => Ok(Self::Level2),
            "3" | "level3" | "l3" => Ok(Self::Level3),
            "4" | "level4" | "l4" => Ok(Self::Level4),
            "5" | "level5" | "l5" => Ok(Self::Level5),
            _ => Err(Error::Configuration(format!(
                "Invalid security level: {}. Valid values: 1-5, level1-level5",
                s
            ))),
        }
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Level {}", self.as_u8())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Level1 < SecurityLevel::Level3);
        assert!(SecurityLevel::Level5 > SecurityLevel::Level3);
    }

    #[test]
    fn test_from_str() {
        assert_eq!(SecurityLevel::from_str("3").unwrap(), SecurityLevel::Level3);
        assert_eq!(
            SecurityLevel::from_str("level5").unwrap(),
            SecurityLevel::Level5
        );
        assert!(SecurityLevel::from_str("invalid").is_err());
    }

    #[test]
    fn test_recommended_algorithms() {
        assert_eq!(SecurityLevel::Level3.recommended_kem(), Algorithm::MlKem768);
        assert_eq!(SecurityLevel::Level5.recommended_dsa(), Algorithm::MlDsa87);
    }
}

//! Compliance profile definitions for regulatory requirements.

use crate::config::SecurityLevel;
use crate::error::{Error, Result};
use crate::primitives::Algorithm;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Compliance profiles for different regulatory requirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceProfile {
    /// Standard profile - no specific compliance requirements.
    #[serde(rename = "standard")]
    Standard,
    /// CNSA 2.0 - NSA Commercial National Security Algorithm Suite.
    /// Required for US government classified systems.
    #[serde(rename = "cnsa2")]
    Cnsa2,
    /// FIPS 140-3 - Federal Information Processing Standard.
    /// Required for US government unclassified systems.
    #[serde(rename = "fips140")]
    Fips140,
    /// PCI-DSS - Payment Card Industry Data Security Standard.
    #[serde(rename = "pci_dss")]
    PciDss,
    /// HIPAA - Health Insurance Portability and Accountability Act.
    #[serde(rename = "hipaa")]
    Hipaa,
    /// SOC 2 - Service Organization Control Type 2.
    #[serde(rename = "soc2")]
    Soc2,
    /// Custom compliance profile.
    #[serde(rename = "custom")]
    Custom,
}

impl Default for ComplianceProfile {
    fn default() -> Self {
        Self::Standard
    }
}

impl ComplianceProfile {
    /// Get the minimum required security level for this compliance profile.
    pub fn minimum_security_level(&self) -> SecurityLevel {
        match self {
            Self::Standard => SecurityLevel::Level1,
            Self::Cnsa2 => SecurityLevel::Level5,
            Self::Fips140 => SecurityLevel::Level3,
            Self::PciDss => SecurityLevel::Level3,
            Self::Hipaa => SecurityLevel::Level3,
            Self::Soc2 => SecurityLevel::Level3,
            Self::Custom => SecurityLevel::Level1,
        }
    }

    /// Validate that a security level meets this compliance profile.
    pub fn validate_security_level(&self, level: SecurityLevel) -> Result<()> {
        let min = self.minimum_security_level();
        if level < min {
            return Err(Error::ComplianceViolation(format!(
                "{} compliance requires at least {} (got {})",
                self.name(),
                min,
                level
            )));
        }
        Ok(())
    }

    /// Check if an algorithm is approved for this compliance profile.
    pub fn is_algorithm_approved(&self, algorithm: Algorithm) -> bool {
        match self {
            Self::Standard => true,
            Self::Cnsa2 => self.cnsa2_approved(algorithm),
            Self::Fips140 => self.fips_approved(algorithm),
            Self::PciDss | Self::Hipaa | Self::Soc2 => {
                algorithm.security_level() >= SecurityLevel::Level3
            }
            Self::Custom => true,
        }
    }

    /// Get approved algorithms for CNSA 2.0.
    fn cnsa2_approved(&self, algorithm: Algorithm) -> bool {
        matches!(
            algorithm,
            Algorithm::MlKem1024
                | Algorithm::MlDsa87
                | Algorithm::SlhDsaShake256s
                | Algorithm::SlhDsaShake256f
                | Algorithm::Xmss
                | Algorithm::Lms
        )
    }

    /// Get approved algorithms for FIPS 140-3.
    fn fips_approved(&self, algorithm: Algorithm) -> bool {
        matches!(
            algorithm,
            Algorithm::MlKem512
                | Algorithm::MlKem768
                | Algorithm::MlKem1024
                | Algorithm::MlDsa44
                | Algorithm::MlDsa65
                | Algorithm::MlDsa87
                | Algorithm::SlhDsaShake128s
                | Algorithm::SlhDsaShake128f
                | Algorithm::SlhDsaShake256s
                | Algorithm::SlhDsaShake256f
        )
    }

    /// Get the human-readable name of this compliance profile.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Cnsa2 => "CNSA 2.0",
            Self::Fips140 => "FIPS 140-3",
            Self::PciDss => "PCI-DSS",
            Self::Hipaa => "HIPAA",
            Self::Soc2 => "SOC 2",
            Self::Custom => "Custom",
        }
    }

    /// Get a description of this compliance profile.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Standard => "No specific compliance requirements",
            Self::Cnsa2 => "NSA Commercial National Security Algorithm Suite 2.0 - Required for US government classified systems",
            Self::Fips140 => "Federal Information Processing Standard 140-3 - Required for US government unclassified systems",
            Self::PciDss => "Payment Card Industry Data Security Standard - Required for payment card processing",
            Self::Hipaa => "Health Insurance Portability and Accountability Act - Required for healthcare data",
            Self::Soc2 => "Service Organization Control Type 2 - Required for service providers",
            Self::Custom => "Custom compliance profile with user-defined requirements",
        }
    }

    /// Get required audit logging settings.
    pub fn audit_requirements(&self) -> AuditRequirements {
        match self {
            Self::Standard => AuditRequirements {
                log_all_operations: false,
                log_key_operations: true,
                log_failures: true,
                retention_days: 90,
                tamper_evident: false,
            },
            Self::Cnsa2 | Self::Fips140 => AuditRequirements {
                log_all_operations: true,
                log_key_operations: true,
                log_failures: true,
                retention_days: 365,
                tamper_evident: true,
            },
            Self::PciDss => AuditRequirements {
                log_all_operations: true,
                log_key_operations: true,
                log_failures: true,
                retention_days: 365,
                tamper_evident: true,
            },
            Self::Hipaa => AuditRequirements {
                log_all_operations: true,
                log_key_operations: true,
                log_failures: true,
                retention_days: 2190, // 6 years
                tamper_evident: true,
            },
            Self::Soc2 => AuditRequirements {
                log_all_operations: true,
                log_key_operations: true,
                log_failures: true,
                retention_days: 365,
                tamper_evident: false,
            },
            Self::Custom => AuditRequirements::default(),
        }
    }

    /// Get key management requirements.
    pub fn key_requirements(&self) -> KeyRequirements {
        match self {
            Self::Standard => KeyRequirements {
                max_key_age_days: 0, // No limit
                require_rotation: false,
                require_hsm: false,
                require_split_knowledge: false,
            },
            Self::Cnsa2 => KeyRequirements {
                max_key_age_days: 365,
                require_rotation: true,
                require_hsm: true,
                require_split_knowledge: true,
            },
            Self::Fips140 => KeyRequirements {
                max_key_age_days: 365,
                require_rotation: true,
                require_hsm: true,
                require_split_knowledge: false,
            },
            Self::PciDss => KeyRequirements {
                max_key_age_days: 365,
                require_rotation: true,
                require_hsm: false,
                require_split_knowledge: false,
            },
            Self::Hipaa | Self::Soc2 => KeyRequirements {
                max_key_age_days: 365,
                require_rotation: true,
                require_hsm: false,
                require_split_knowledge: false,
            },
            Self::Custom => KeyRequirements::default(),
        }
    }
}

impl FromStr for ComplianceProfile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "standard" | "none" => Ok(Self::Standard),
            "cnsa2" | "cnsa" | "cnsa_2.0" => Ok(Self::Cnsa2),
            "fips" | "fips140" | "fips_140" | "fips140-3" => Ok(Self::Fips140),
            "pci" | "pci_dss" | "pcidss" => Ok(Self::PciDss),
            "hipaa" => Ok(Self::Hipaa),
            "soc2" | "soc_2" => Ok(Self::Soc2),
            "custom" => Ok(Self::Custom),
            _ => Err(Error::Configuration(format!(
                "Invalid compliance profile: {}. Valid values: standard, cnsa2, fips140, pci_dss, hipaa, soc2, custom",
                s
            ))),
        }
    }
}

impl std::fmt::Display for ComplianceProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Audit logging requirements for compliance.
#[derive(Clone, Debug)]
pub struct AuditRequirements {
    /// Log all cryptographic operations.
    pub log_all_operations: bool,
    /// Log key management operations.
    pub log_key_operations: bool,
    /// Log failed operations.
    pub log_failures: bool,
    /// Retention period in days.
    pub retention_days: u32,
    /// Require tamper-evident logging.
    pub tamper_evident: bool,
}

impl Default for AuditRequirements {
    fn default() -> Self {
        Self {
            log_all_operations: false,
            log_key_operations: true,
            log_failures: true,
            retention_days: 90,
            tamper_evident: false,
        }
    }
}

/// Key management requirements for compliance.
#[derive(Clone, Debug, Default)]
pub struct KeyRequirements {
    /// Maximum key age in days (0 = no limit).
    pub max_key_age_days: u32,
    /// Require automatic key rotation.
    pub require_rotation: bool,
    /// Require HSM-backed keys.
    pub require_hsm: bool,
    /// Require split knowledge for key generation.
    pub require_split_knowledge: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cnsa2_security_level() {
        assert_eq!(
            ComplianceProfile::Cnsa2.minimum_security_level(),
            SecurityLevel::Level5
        );
    }

    #[test]
    fn test_compliance_validation() {
        assert!(ComplianceProfile::Cnsa2
            .validate_security_level(SecurityLevel::Level5)
            .is_ok());
        assert!(ComplianceProfile::Cnsa2
            .validate_security_level(SecurityLevel::Level3)
            .is_err());
    }

    #[test]
    fn test_algorithm_approval() {
        assert!(ComplianceProfile::Cnsa2.is_algorithm_approved(Algorithm::MlKem1024));
        assert!(!ComplianceProfile::Cnsa2.is_algorithm_approved(Algorithm::MlKem512));
    }
}

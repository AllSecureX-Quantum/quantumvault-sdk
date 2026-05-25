//! Key generation API.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::primitives::{dsa, kem, Algorithm, AlgorithmType};
use crate::types::{KeyMetadata, KeyPair, SignatureKeyPair};

/// Generate a key pair for the specified algorithm.
pub fn generate_keypair(algorithm: Algorithm, config: &Config) -> Result<KeyPair> {
    // Validate algorithm is approved for compliance profile
    if !config.compliance_profile.is_algorithm_approved(algorithm) {
        return Err(Error::ComplianceViolation(format!(
            "Algorithm {} is not approved for {} compliance profile",
            algorithm, config.compliance_profile
        )));
    }

    // Validate security level
    if algorithm.security_level() < config.security_level {
        return Err(Error::SecurityLevelMismatch {
            expected: config.security_level.as_u8(),
            actual: algorithm.security_level().as_u8(),
        });
    }

    match algorithm.algorithm_type() {
        AlgorithmType::Kem => kem::generate_keypair(algorithm),
        AlgorithmType::Dsa => {
            // For DSA, convert SignatureKeyPair to KeyPair format
            let sig_keypair = dsa::generate_keypair(algorithm)?;
            Ok(KeyPair {
                key_id: sig_keypair.key_id.clone(),
                public_key: crate::types::PublicKey::new(
                    sig_keypair.verifying_key.bytes.clone(),
                    algorithm,
                    sig_keypair.verifying_key.key_id.clone(),
                ),
                secret_key: crate::types::SecretKey::new(
                    sig_keypair.signing_key.as_bytes().to_vec(),
                    algorithm,
                    sig_keypair.signing_key.key_id.clone(),
                ),
                algorithm,
                created_at: sig_keypair.created_at,
                expires_at: sig_keypair.expires_at,
                metadata: sig_keypair.metadata.clone(),
            })
        }
        AlgorithmType::HybridKem => {
            #[cfg(feature = "hybrid")]
            {
                super::hybrid::generate_hybrid_kem_keypair(algorithm, config)
            }
            #[cfg(not(feature = "hybrid"))]
            {
                Err(Error::UnsupportedAlgorithm {
                    algorithm: algorithm.to_string(),
                    operation: "key generation (hybrid feature not enabled)".to_string(),
                })
            }
        }
        AlgorithmType::HybridDsa => {
            #[cfg(feature = "hybrid")]
            {
                super::hybrid::generate_hybrid_dsa_keypair(algorithm, config)
            }
            #[cfg(not(feature = "hybrid"))]
            {
                Err(Error::UnsupportedAlgorithm {
                    algorithm: algorithm.to_string(),
                    operation: "key generation (hybrid feature not enabled)".to_string(),
                })
            }
        }
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
            operation: "key generation".to_string(),
        }),
    }
}

/// Generate a signature key pair for the specified algorithm.
pub fn generate_signature_keypair(
    algorithm: Algorithm,
    config: &Config,
) -> Result<SignatureKeyPair> {
    // Validate algorithm is approved for compliance profile
    if !config.compliance_profile.is_algorithm_approved(algorithm) {
        return Err(Error::ComplianceViolation(format!(
            "Algorithm {} is not approved for {} compliance profile",
            algorithm, config.compliance_profile
        )));
    }

    // Validate security level
    if algorithm.security_level() < config.security_level {
        return Err(Error::SecurityLevelMismatch {
            expected: config.security_level.as_u8(),
            actual: algorithm.security_level().as_u8(),
        });
    }

    match algorithm.algorithm_type() {
        AlgorithmType::Dsa => dsa::generate_keypair(algorithm),
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
            operation: "signature key generation".to_string(),
        }),
    }
}

/// Generate a key pair with custom metadata.
pub fn generate_keypair_with_metadata(
    algorithm: Algorithm,
    metadata: KeyMetadata,
    config: &Config,
) -> Result<KeyPair> {
    let mut keypair = generate_keypair(algorithm, config)?;
    keypair.metadata = metadata;
    Ok(keypair)
}

/// Generate a key pair with expiration.
pub fn generate_keypair_with_expiration(
    algorithm: Algorithm,
    expires_in_seconds: i64,
    config: &Config,
) -> Result<KeyPair> {
    let mut keypair = generate_keypair(algorithm, config)?;
    keypair.expires_at = Some(chrono::Utc::now().timestamp() + expires_in_seconds);
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityLevel;

    #[test]
    fn test_generate_ml_kem_keypair() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = generate_keypair(Algorithm::MlKem768, &config).unwrap();
        assert_eq!(keypair.algorithm, Algorithm::MlKem768);
        assert!(!keypair.key_id.is_empty());
    }

    #[test]
    fn test_generate_ml_dsa_keypair() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = generate_signature_keypair(Algorithm::MlDsa65, &config).unwrap();
        assert_eq!(keypair.algorithm, Algorithm::MlDsa65);
    }

    #[test]
    fn test_security_level_enforcement() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level5)
            .build()
            .unwrap();

        // ML-KEM-512 is Level 1, should fail with Level 5 requirement
        let result = generate_keypair(Algorithm::MlKem512, &config);
        assert!(result.is_err());
    }
}

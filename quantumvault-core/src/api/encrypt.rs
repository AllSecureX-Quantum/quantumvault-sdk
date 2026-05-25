//! Encryption API using KEM + symmetric encryption.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::primitives::{hash, kem, symmetric};
use crate::types::{EncryptedData, PublicKey, SymmetricAlgorithm};

/// Encrypt data using the recipient's public key.
///
/// This uses a KEM-DEM (Key Encapsulation Mechanism + Data Encapsulation Mechanism)
/// approach:
/// 1. Generate a shared secret using the KEM with the recipient's public key
/// 2. Derive a symmetric key from the shared secret
/// 3. Encrypt the data using AES-256-GCM
pub fn encrypt_data(
    plaintext: &[u8],
    public_key: &PublicKey,
    config: &Config,
) -> Result<EncryptedData> {
    // Validate the public key's algorithm is approved
    if !config
        .compliance_profile
        .is_algorithm_approved(public_key.algorithm)
    {
        return Err(Error::ComplianceViolation(format!(
            "Algorithm {} is not approved for {} compliance profile",
            public_key.algorithm, config.compliance_profile
        )));
    }

    // Encapsulate to get shared secret and ciphertext
    let encap_result = kem::encapsulate(public_key)?;

    // Derive symmetric key from shared secret using HKDF
    let info = format!(
        "QuantumVault-Encrypt-v1-{}",
        public_key.algorithm.nist_standard()
    );
    let symmetric_key = hash::hkdf_expand(&encap_result.shared_secret, info.as_bytes(), 32)?;

    // Determine symmetric algorithm based on config
    let sym_algorithm = match config.default_symmetric_algorithm {
        crate::config::SymmetricAlgorithmConfig::Aes128Gcm => SymmetricAlgorithm::Aes128Gcm,
        crate::config::SymmetricAlgorithmConfig::Aes256Gcm => SymmetricAlgorithm::Aes256Gcm,
        crate::config::SymmetricAlgorithmConfig::ChaCha20Poly1305 => {
            SymmetricAlgorithm::ChaCha20Poly1305
        }
    };

    // Create AAD (Additional Authenticated Data) from key ID and algorithm
    let aad = create_aad(&public_key.key_id, public_key.algorithm);

    // Encrypt the plaintext
    let enc_result = symmetric::encrypt(plaintext, &symmetric_key, Some(&aad), sym_algorithm)?;

    let now = chrono::Utc::now().timestamp();

    Ok(EncryptedData {
        encapsulated_key: encap_result.ciphertext.clone(),
        ciphertext: enc_result.ciphertext,
        nonce: enc_result.nonce,
        tag: Vec::new(), // Tag is included in ciphertext for AEAD
        algorithm: public_key.algorithm,
        key_id: public_key.key_id.clone(),
        encrypted_at: now,
        version: EncryptedData::CURRENT_VERSION,
    })
}

/// Encrypt data with additional authenticated data (AAD).
pub fn encrypt_data_with_aad(
    plaintext: &[u8],
    public_key: &PublicKey,
    additional_data: &[u8],
    config: &Config,
) -> Result<EncryptedData> {
    // Validate the public key's algorithm is approved
    if !config
        .compliance_profile
        .is_algorithm_approved(public_key.algorithm)
    {
        return Err(Error::ComplianceViolation(format!(
            "Algorithm {} is not approved for {} compliance profile",
            public_key.algorithm, config.compliance_profile
        )));
    }

    // Encapsulate to get shared secret and ciphertext
    let encap_result = kem::encapsulate(public_key)?;

    // Derive symmetric key from shared secret
    let info = format!(
        "QuantumVault-Encrypt-v1-{}",
        public_key.algorithm.nist_standard()
    );
    let symmetric_key = hash::hkdf_expand(&encap_result.shared_secret, info.as_bytes(), 32)?;

    // Create combined AAD
    let mut aad = create_aad(&public_key.key_id, public_key.algorithm);
    aad.extend_from_slice(additional_data);

    // Encrypt the plaintext
    let enc_result = symmetric::encrypt(
        plaintext,
        &symmetric_key,
        Some(&aad),
        SymmetricAlgorithm::Aes256Gcm,
    )?;

    let now = chrono::Utc::now().timestamp();

    Ok(EncryptedData {
        encapsulated_key: encap_result.ciphertext.clone(),
        ciphertext: enc_result.ciphertext,
        nonce: enc_result.nonce,
        tag: Vec::new(),
        algorithm: public_key.algorithm,
        key_id: public_key.key_id.clone(),
        encrypted_at: now,
        version: EncryptedData::CURRENT_VERSION,
    })
}

/// Create Additional Authenticated Data from key ID and algorithm.
fn create_aad(key_id: &str, algorithm: crate::primitives::Algorithm) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"QV1"); // Version marker
    aad.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
    aad.extend_from_slice(key_id.as_bytes());
    aad.extend_from_slice(&[algorithm.security_level().as_u8()]);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::keygen;
    use crate::config::SecurityLevel;
    use crate::primitives::Algorithm;

    #[test]
    fn test_encrypt_data() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = keygen::generate_keypair(Algorithm::MlKem768, &config).unwrap();
        let plaintext = b"Hello, Quantum World!";

        let encrypted = encrypt_data(plaintext, &keypair.public_key, &config).unwrap();

        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.encapsulated_key.is_empty());
        assert!(!encrypted.nonce.is_empty());
        assert_eq!(encrypted.algorithm, Algorithm::MlKem768);
    }
}

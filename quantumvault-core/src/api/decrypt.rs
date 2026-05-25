//! Decryption API using KEM + symmetric decryption.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::primitives::{hash, kem, symmetric};
use crate::types::{EncryptedData, SecretKey, SymmetricAlgorithm};

/// Decrypt data using the recipient's secret key.
///
/// This reverses the KEM-DEM encryption:
/// 1. Decapsulate the shared secret using the secret key
/// 2. Derive the symmetric key from the shared secret
/// 3. Decrypt the ciphertext
pub fn decrypt_data(
    encrypted: &EncryptedData,
    secret_key: &SecretKey,
    config: &Config,
) -> Result<Vec<u8>> {
    // Validate version
    if encrypted.version > EncryptedData::CURRENT_VERSION {
        return Err(Error::Deserialization(format!(
            "Unsupported encrypted data version: {}. Maximum supported: {}",
            encrypted.version,
            EncryptedData::CURRENT_VERSION
        )));
    }

    // Validate algorithm match
    if encrypted.algorithm != secret_key.algorithm {
        return Err(Error::InvalidKey(format!(
            "Algorithm mismatch: encrypted with {:?}, key is {:?}",
            encrypted.algorithm, secret_key.algorithm
        )));
    }

    // Validate key ID match
    if encrypted.key_id != secret_key.key_id {
        return Err(Error::InvalidKey(format!(
            "Key ID mismatch: encrypted for {}, got key {}",
            encrypted.key_id, secret_key.key_id
        )));
    }

    // Decapsulate to recover shared secret
    let shared_secret = kem::decapsulate(&encrypted.encapsulated_key, secret_key)?;

    // Derive symmetric key from shared secret
    let info = format!(
        "QuantumVault-Encrypt-v1-{}",
        encrypted.algorithm.nist_standard()
    );
    let symmetric_key = hash::hkdf_expand(&shared_secret, info.as_bytes(), 32)?;

    // Determine symmetric algorithm based on config
    let sym_algorithm = match config.default_symmetric_algorithm {
        crate::config::SymmetricAlgorithmConfig::Aes128Gcm => SymmetricAlgorithm::Aes128Gcm,
        crate::config::SymmetricAlgorithmConfig::Aes256Gcm => SymmetricAlgorithm::Aes256Gcm,
        crate::config::SymmetricAlgorithmConfig::ChaCha20Poly1305 => {
            SymmetricAlgorithm::ChaCha20Poly1305
        }
    };

    // Recreate AAD for verification
    let aad = create_aad(&encrypted.key_id, encrypted.algorithm);

    // Decrypt the ciphertext
    let plaintext = symmetric::decrypt(
        &encrypted.ciphertext,
        &symmetric_key,
        &encrypted.nonce,
        Some(&aad),
        sym_algorithm,
    )?;

    Ok(plaintext)
}

/// Decrypt data with additional authenticated data (AAD).
pub fn decrypt_data_with_aad(
    encrypted: &EncryptedData,
    secret_key: &SecretKey,
    additional_data: &[u8],
    _config: &Config,
) -> Result<Vec<u8>> {
    // Validate version
    if encrypted.version > EncryptedData::CURRENT_VERSION {
        return Err(Error::Deserialization(format!(
            "Unsupported encrypted data version: {}",
            encrypted.version
        )));
    }

    // Validate algorithm match
    if encrypted.algorithm != secret_key.algorithm {
        return Err(Error::InvalidKey(format!(
            "Algorithm mismatch: encrypted with {:?}, key is {:?}",
            encrypted.algorithm, secret_key.algorithm
        )));
    }

    // Decapsulate to recover shared secret
    let shared_secret = kem::decapsulate(&encrypted.encapsulated_key, secret_key)?;

    // Derive symmetric key from shared secret
    let info = format!(
        "QuantumVault-Encrypt-v1-{}",
        encrypted.algorithm.nist_standard()
    );
    let symmetric_key = hash::hkdf_expand(&shared_secret, info.as_bytes(), 32)?;

    // Recreate combined AAD
    let mut aad = create_aad(&encrypted.key_id, encrypted.algorithm);
    aad.extend_from_slice(additional_data);

    // Decrypt the ciphertext
    let plaintext = symmetric::decrypt(
        &encrypted.ciphertext,
        &symmetric_key,
        &encrypted.nonce,
        Some(&aad),
        SymmetricAlgorithm::Aes256Gcm,
    )?;

    Ok(plaintext)
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
    use crate::api::{encrypt, keygen};
    use crate::config::SecurityLevel;
    use crate::primitives::Algorithm;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = keygen::generate_keypair(Algorithm::MlKem768, &config).unwrap();
        let plaintext = b"Hello, Quantum World!";

        let encrypted = encrypt::encrypt_data(plaintext, &keypair.public_key, &config).unwrap();
        let decrypted = decrypt_data(&encrypted, &keypair.secret_key, &config).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair1 = keygen::generate_keypair(Algorithm::MlKem768, &config).unwrap();
        let keypair2 = keygen::generate_keypair(Algorithm::MlKem768, &config).unwrap();
        let plaintext = b"Secret message";

        let encrypted = encrypt::encrypt_data(plaintext, &keypair1.public_key, &config).unwrap();
        let result = decrypt_data(&encrypted, &keypair2.secret_key, &config);

        // Should fail due to key ID mismatch
        assert!(result.is_err());
    }
}

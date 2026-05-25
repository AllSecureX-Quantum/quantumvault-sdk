//! Key generation utilities.

use crate::error::KeyResult;
use quantumvault_core::Algorithm;
use rand::{CryptoRng, RngCore};

/// Generate secure random bytes.
pub fn generate_random_bytes<R: RngCore + CryptoRng>(rng: &mut R, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a cryptographically secure key ID.
pub fn generate_key_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Entropy source for key generation.
pub struct EntropySource {
    additional_entropy: Vec<u8>,
}

impl EntropySource {
    /// Create a new entropy source.
    pub fn new() -> Self {
        Self {
            additional_entropy: Vec::new(),
        }
    }

    /// Add additional entropy (e.g., from user input, hardware RNG).
    pub fn add_entropy(&mut self, data: &[u8]) {
        self.additional_entropy.extend_from_slice(data);
    }

    /// Get entropy for key generation.
    pub fn get_entropy(&self, len: usize) -> KeyResult<Vec<u8>> {
        let mut entropy = vec![0u8; len];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| crate::error::KeyError::Crypto(format!("Failed to get entropy: {}", e)))?;

        // Mix in additional entropy if available
        if !self.additional_entropy.is_empty() {
            use sha3::{Digest, Sha3_256};
            let mut hasher = Sha3_256::new();
            hasher.update(&entropy);
            hasher.update(&self.additional_entropy);
            let mixed = hasher.finalize();

            // Use mixed entropy to seed output
            for (i, byte) in entropy.iter_mut().enumerate() {
                *byte ^= mixed[i % mixed.len()];
            }
        }

        Ok(entropy)
    }
}

impl Default for EntropySource {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that an algorithm is suitable for the intended purpose.
pub fn validate_algorithm_for_purpose(algorithm: Algorithm, purpose: KeyPurpose) -> KeyResult<()> {
    let valid = match purpose {
        KeyPurpose::Encryption => matches!(
            algorithm,
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024
        ),
        KeyPurpose::Signing => matches!(
            algorithm,
            Algorithm::MlDsa44
                | Algorithm::MlDsa65
                | Algorithm::MlDsa87
                | Algorithm::SlhDsaShake128s
                | Algorithm::SlhDsaShake128f
                | Algorithm::SlhDsaShake256s
                | Algorithm::SlhDsaShake256f
        ),
        KeyPurpose::KeyAgreement => matches!(
            algorithm,
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024
        ),
    };

    if valid {
        Ok(())
    } else {
        Err(crate::error::KeyError::InvalidConfig(format!(
            "Algorithm {} is not suitable for {:?}",
            algorithm, purpose
        )))
    }
}

/// Purpose for which a key will be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPurpose {
    /// Key for encryption/decryption.
    Encryption,
    /// Key for signing/verification.
    Signing,
    /// Key for key agreement (key exchange).
    KeyAgreement,
}

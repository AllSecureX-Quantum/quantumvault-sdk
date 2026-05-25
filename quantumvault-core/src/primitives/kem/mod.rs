//! Key Encapsulation Mechanism implementations.
//!
//! Provides ML-KEM (Kyber) implementations at various security levels
//! following FIPS 203 specifications.

mod ml_kem;

pub use ml_kem::{MlKem1024, MlKem512, MlKem768};

use crate::error::{Error, Result};
use crate::primitives::Algorithm;
use crate::types::{KeyPair, PublicKey, SecretKey};
use rand::RngCore;
use zeroize::Zeroize;

/// Trait for Key Encapsulation Mechanisms.
pub trait Kem: Sized {
    /// The algorithm identifier.
    const ALGORITHM: Algorithm;

    /// Public key size in bytes.
    const PUBLIC_KEY_SIZE: usize;

    /// Secret key size in bytes.
    const SECRET_KEY_SIZE: usize;

    /// Ciphertext (encapsulated key) size in bytes.
    const CIPHERTEXT_SIZE: usize;

    /// Shared secret size in bytes.
    const SHARED_SECRET_SIZE: usize;

    /// Generate a new key pair.
    fn generate_keypair<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Result<KeyPair>;

    /// Encapsulate a shared secret using a public key.
    fn encapsulate<R: RngCore + rand::CryptoRng>(
        rng: &mut R,
        public_key: &PublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate a shared secret using a secret key.
    fn decapsulate(ciphertext: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>>;
}

/// Encapsulation result containing ciphertext and shared secret.
pub struct EncapsulationResult {
    /// The encapsulated key (ciphertext).
    pub ciphertext: Vec<u8>,
    /// The shared secret (should be zeroized after use).
    pub shared_secret: Vec<u8>,
}

impl Drop for EncapsulationResult {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

/// Generate a KEM key pair for the specified algorithm.
pub fn generate_keypair(algorithm: Algorithm) -> Result<KeyPair> {
    let mut rng = rand::thread_rng();

    match algorithm {
        Algorithm::MlKem512 => MlKem512::generate_keypair(&mut rng),
        Algorithm::MlKem768 => MlKem768::generate_keypair(&mut rng),
        Algorithm::MlKem1024 => MlKem1024::generate_keypair(&mut rng),
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
            operation: "KEM key generation".to_string(),
        }),
    }
}

/// Encapsulate a shared secret using the given public key.
pub fn encapsulate(public_key: &PublicKey) -> Result<EncapsulationResult> {
    let mut rng = rand::thread_rng();

    let (ciphertext, shared_secret) = match public_key.algorithm {
        Algorithm::MlKem512 => MlKem512::encapsulate(&mut rng, public_key)?,
        Algorithm::MlKem768 => MlKem768::encapsulate(&mut rng, public_key)?,
        Algorithm::MlKem1024 => MlKem1024::encapsulate(&mut rng, public_key)?,
        _ => {
            return Err(Error::UnsupportedAlgorithm {
                algorithm: public_key.algorithm.to_string(),
                operation: "KEM encapsulation".to_string(),
            })
        }
    };

    Ok(EncapsulationResult {
        ciphertext,
        shared_secret,
    })
}

/// Decapsulate a shared secret using the given secret key.
pub fn decapsulate(ciphertext: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>> {
    match secret_key.algorithm {
        Algorithm::MlKem512 => MlKem512::decapsulate(ciphertext, secret_key),
        Algorithm::MlKem768 => MlKem768::decapsulate(ciphertext, secret_key),
        Algorithm::MlKem1024 => MlKem1024::decapsulate(ciphertext, secret_key),
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: secret_key.algorithm.to_string(),
            operation: "KEM decapsulation".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_roundtrip_ml_kem_768() {
        let keypair = generate_keypair(Algorithm::MlKem768).unwrap();
        let encap = encapsulate(&keypair.public_key).unwrap();
        let shared_secret = decapsulate(&encap.ciphertext, &keypair.secret_key).unwrap();
        assert_eq!(encap.shared_secret, shared_secret);
    }

    #[test]
    fn test_kem_all_variants() {
        for algorithm in [
            Algorithm::MlKem512,
            Algorithm::MlKem768,
            Algorithm::MlKem1024,
        ] {
            let keypair = generate_keypair(algorithm).unwrap();
            let encap = encapsulate(&keypair.public_key).unwrap();
            let shared_secret = decapsulate(&encap.ciphertext, &keypair.secret_key).unwrap();
            assert_eq!(encap.shared_secret, shared_secret);
            assert_eq!(shared_secret.len(), 32);
        }
    }
}

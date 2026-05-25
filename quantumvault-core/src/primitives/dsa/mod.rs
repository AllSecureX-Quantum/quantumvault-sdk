//! Digital Signature Algorithm implementations.
//!
//! Provides ML-DSA (Dilithium) and SLH-DSA (SPHINCS+) implementations
//! following FIPS 204 and FIPS 205 specifications.

mod ml_dsa;
mod slh_dsa;

pub use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
pub use slh_dsa::{SlhDsaShake128f, SlhDsaShake128s, SlhDsaShake256f, SlhDsaShake256s};

use crate::error::{Error, Result};
use crate::primitives::Algorithm;
use crate::types::{Signature, SignatureKeyPair, SigningKey, VerifyingKey};
use rand::RngCore;

/// Trait for Digital Signature Algorithms.
pub trait Dsa: Sized {
    /// The algorithm identifier.
    const ALGORITHM: Algorithm;

    /// Public key (verifying key) size in bytes.
    const VERIFYING_KEY_SIZE: usize;

    /// Secret key (signing key) size in bytes.
    const SIGNING_KEY_SIZE: usize;

    /// Signature size in bytes.
    const SIGNATURE_SIZE: usize;

    /// Generate a new signature key pair.
    fn generate_keypair<R: RngCore + rand::CryptoRng>(rng: &mut R) -> Result<SignatureKeyPair>;

    /// Sign a message.
    fn sign(message: &[u8], signing_key: &SigningKey) -> Result<Signature>;

    /// Verify a signature.
    fn verify(message: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<bool>;
}

/// Generate a DSA key pair for the specified algorithm.
pub fn generate_keypair(algorithm: Algorithm) -> Result<SignatureKeyPair> {
    let mut rng = rand::thread_rng();

    match algorithm {
        Algorithm::MlDsa44 => MlDsa44::generate_keypair(&mut rng),
        Algorithm::MlDsa65 => MlDsa65::generate_keypair(&mut rng),
        Algorithm::MlDsa87 => MlDsa87::generate_keypair(&mut rng),
        Algorithm::SlhDsaShake128s => SlhDsaShake128s::generate_keypair(&mut rng),
        Algorithm::SlhDsaShake128f => SlhDsaShake128f::generate_keypair(&mut rng),
        Algorithm::SlhDsaShake256s => SlhDsaShake256s::generate_keypair(&mut rng),
        Algorithm::SlhDsaShake256f => SlhDsaShake256f::generate_keypair(&mut rng),
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
            operation: "DSA key generation".to_string(),
        }),
    }
}

/// Sign a message using the given signing key.
pub fn sign(message: &[u8], signing_key: &SigningKey) -> Result<Signature> {
    match signing_key.algorithm {
        Algorithm::MlDsa44 => MlDsa44::sign(message, signing_key),
        Algorithm::MlDsa65 => MlDsa65::sign(message, signing_key),
        Algorithm::MlDsa87 => MlDsa87::sign(message, signing_key),
        Algorithm::SlhDsaShake128s => SlhDsaShake128s::sign(message, signing_key),
        Algorithm::SlhDsaShake128f => SlhDsaShake128f::sign(message, signing_key),
        Algorithm::SlhDsaShake256s => SlhDsaShake256s::sign(message, signing_key),
        Algorithm::SlhDsaShake256f => SlhDsaShake256f::sign(message, signing_key),
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: signing_key.algorithm.to_string(),
            operation: "signing".to_string(),
        }),
    }
}

/// Verify a signature using the given verifying key.
pub fn verify(message: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<bool> {
    match verifying_key.algorithm {
        Algorithm::MlDsa44 => MlDsa44::verify(message, signature, verifying_key),
        Algorithm::MlDsa65 => MlDsa65::verify(message, signature, verifying_key),
        Algorithm::MlDsa87 => MlDsa87::verify(message, signature, verifying_key),
        Algorithm::SlhDsaShake128s => SlhDsaShake128s::verify(message, signature, verifying_key),
        Algorithm::SlhDsaShake128f => SlhDsaShake128f::verify(message, signature, verifying_key),
        Algorithm::SlhDsaShake256s => SlhDsaShake256s::verify(message, signature, verifying_key),
        Algorithm::SlhDsaShake256f => SlhDsaShake256f::verify(message, signature, verifying_key),
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: verifying_key.algorithm.to_string(),
            operation: "verification".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsa_roundtrip_ml_dsa_65() {
        let keypair = generate_keypair(Algorithm::MlDsa65).unwrap();
        let message = b"Test message for signing";
        let signature = sign(message, &keypair.signing_key).unwrap();
        let valid = verify(message, &signature, &keypair.verifying_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_dsa_invalid_signature() {
        let keypair = generate_keypair(Algorithm::MlDsa65).unwrap();
        let message = b"Test message";
        let signature = sign(message, &keypair.signing_key).unwrap();
        let wrong_message = b"Wrong message";
        let valid = verify(wrong_message, &signature, &keypair.verifying_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_all_ml_dsa_variants() {
        for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
            let keypair = generate_keypair(algorithm).unwrap();
            let message = b"Test message";
            let signature = sign(message, &keypair.signing_key).unwrap();
            let valid = verify(message, &signature, &keypair.verifying_key).unwrap();
            assert!(valid, "Failed for algorithm {:?}", algorithm);
        }
    }
}

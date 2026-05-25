//! ML-DSA (Module Lattice Digital Signature Algorithm) implementations.
//!
//! Based on FIPS 204 (formerly CRYSTALS-Dilithium).

use crate::error::{Error, Result};
use crate::primitives::Algorithm;
use crate::types::{KeyMetadata, Signature, SignatureKeyPair, SigningKey, VerifyingKey};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _, SignedMessage};
use rand::RngCore;
use uuid::Uuid;

/// ML-DSA-44 (Dilithium-2) - NIST Level 2 security.
pub struct MlDsa44;

/// ML-DSA-65 (Dilithium-3) - NIST Level 3 security (recommended).
pub struct MlDsa65;

/// ML-DSA-87 (Dilithium-5) - NIST Level 5 security.
pub struct MlDsa87;

impl super::Dsa for MlDsa44 {
    const ALGORITHM: Algorithm = Algorithm::MlDsa44;
    const VERIFYING_KEY_SIZE: usize = 1312;
    const SIGNING_KEY_SIZE: usize = 2560;
    const SIGNATURE_SIZE: usize = 2420;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<SignatureKeyPair> {
        let (pk, sk) = dilithium2::keypair();
        let key_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        Ok(SignatureKeyPair {
            key_id: key_id.clone(),
            verifying_key: VerifyingKey::new(
                pk.as_bytes().to_vec(),
                Self::ALGORITHM,
                key_id.clone(),
            ),
            signing_key: SigningKey::new(sk.as_bytes().to_vec(), Self::ALGORITHM, key_id.clone()),
            algorithm: Self::ALGORITHM,
            created_at: now,
            expires_at: None,
            metadata: KeyMetadata::default(),
        })
    }

    fn sign(message: &[u8], signing_key: &SigningKey) -> Result<Signature> {
        if signing_key.as_bytes().len() != Self::SIGNING_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-DSA-44 signing key size: expected {}, got {}",
                Self::SIGNING_KEY_SIZE,
                signing_key.as_bytes().len()
            )));
        }

        let sk = dilithium2::SecretKey::from_bytes(signing_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-DSA-44 signing key: {:?}", e)))?;

        let sig = dilithium2::detached_sign(message, &sk);
        let now = chrono::Utc::now().timestamp();

        Ok(Signature {
            bytes: sig.as_bytes().to_vec(),
            algorithm: Self::ALGORITHM,
            key_id: signing_key.key_id.clone(),
            signed_at: now,
        })
    }

    fn verify(message: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<bool> {
        if verifying_key.bytes.len() != Self::VERIFYING_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-DSA-44 verifying key size: expected {}, got {}",
                Self::VERIFYING_KEY_SIZE,
                verifying_key.bytes.len()
            )));
        }

        let pk = dilithium2::PublicKey::from_bytes(&verifying_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-DSA-44 verifying key: {:?}", e)))?;

        let sig = dilithium2::DetachedSignature::from_bytes(&signature.bytes).map_err(|e| {
            Error::InvalidSignature(format!("Invalid ML-DSA-44 signature: {:?}", e))
        })?;

        Ok(dilithium2::verify_detached_signature(&sig, message, &pk).is_ok())
    }
}

impl super::Dsa for MlDsa65 {
    const ALGORITHM: Algorithm = Algorithm::MlDsa65;
    const VERIFYING_KEY_SIZE: usize = 1952;
    const SIGNING_KEY_SIZE: usize = 4032;
    const SIGNATURE_SIZE: usize = 3293;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<SignatureKeyPair> {
        let (pk, sk) = dilithium3::keypair();
        let key_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        Ok(SignatureKeyPair {
            key_id: key_id.clone(),
            verifying_key: VerifyingKey::new(
                pk.as_bytes().to_vec(),
                Self::ALGORITHM,
                key_id.clone(),
            ),
            signing_key: SigningKey::new(sk.as_bytes().to_vec(), Self::ALGORITHM, key_id.clone()),
            algorithm: Self::ALGORITHM,
            created_at: now,
            expires_at: None,
            metadata: KeyMetadata::default(),
        })
    }

    fn sign(message: &[u8], signing_key: &SigningKey) -> Result<Signature> {
        if signing_key.as_bytes().len() != Self::SIGNING_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-DSA-65 signing key size: expected {}, got {}",
                Self::SIGNING_KEY_SIZE,
                signing_key.as_bytes().len()
            )));
        }

        let sk = dilithium3::SecretKey::from_bytes(signing_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-DSA-65 signing key: {:?}", e)))?;

        let sig = dilithium3::detached_sign(message, &sk);
        let now = chrono::Utc::now().timestamp();

        Ok(Signature {
            bytes: sig.as_bytes().to_vec(),
            algorithm: Self::ALGORITHM,
            key_id: signing_key.key_id.clone(),
            signed_at: now,
        })
    }

    fn verify(message: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<bool> {
        if verifying_key.bytes.len() != Self::VERIFYING_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-DSA-65 verifying key size: expected {}, got {}",
                Self::VERIFYING_KEY_SIZE,
                verifying_key.bytes.len()
            )));
        }

        let pk = dilithium3::PublicKey::from_bytes(&verifying_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-DSA-65 verifying key: {:?}", e)))?;

        let sig = dilithium3::DetachedSignature::from_bytes(&signature.bytes).map_err(|e| {
            Error::InvalidSignature(format!("Invalid ML-DSA-65 signature: {:?}", e))
        })?;

        Ok(dilithium3::verify_detached_signature(&sig, message, &pk).is_ok())
    }
}

impl super::Dsa for MlDsa87 {
    const ALGORITHM: Algorithm = Algorithm::MlDsa87;
    const VERIFYING_KEY_SIZE: usize = 2592;
    const SIGNING_KEY_SIZE: usize = 4896;
    const SIGNATURE_SIZE: usize = 4627;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<SignatureKeyPair> {
        let (pk, sk) = dilithium5::keypair();
        let key_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        Ok(SignatureKeyPair {
            key_id: key_id.clone(),
            verifying_key: VerifyingKey::new(
                pk.as_bytes().to_vec(),
                Self::ALGORITHM,
                key_id.clone(),
            ),
            signing_key: SigningKey::new(sk.as_bytes().to_vec(), Self::ALGORITHM, key_id.clone()),
            algorithm: Self::ALGORITHM,
            created_at: now,
            expires_at: None,
            metadata: KeyMetadata::default(),
        })
    }

    fn sign(message: &[u8], signing_key: &SigningKey) -> Result<Signature> {
        if signing_key.as_bytes().len() != Self::SIGNING_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-DSA-87 signing key size: expected {}, got {}",
                Self::SIGNING_KEY_SIZE,
                signing_key.as_bytes().len()
            )));
        }

        let sk = dilithium5::SecretKey::from_bytes(signing_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-DSA-87 signing key: {:?}", e)))?;

        let sig = dilithium5::detached_sign(message, &sk);
        let now = chrono::Utc::now().timestamp();

        Ok(Signature {
            bytes: sig.as_bytes().to_vec(),
            algorithm: Self::ALGORITHM,
            key_id: signing_key.key_id.clone(),
            signed_at: now,
        })
    }

    fn verify(message: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<bool> {
        if verifying_key.bytes.len() != Self::VERIFYING_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-DSA-87 verifying key size: expected {}, got {}",
                Self::VERIFYING_KEY_SIZE,
                verifying_key.bytes.len()
            )));
        }

        let pk = dilithium5::PublicKey::from_bytes(&verifying_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-DSA-87 verifying key: {:?}", e)))?;

        let sig = dilithium5::DetachedSignature::from_bytes(&signature.bytes).map_err(|e| {
            Error::InvalidSignature(format!("Invalid ML-DSA-87 signature: {:?}", e))
        })?;

        Ok(dilithium5::verify_detached_signature(&sig, message, &pk).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::dsa::Dsa;

    #[test]
    fn test_ml_dsa_44_key_sizes() {
        let mut rng = rand::thread_rng();
        let keypair = MlDsa44::generate_keypair(&mut rng).unwrap();
        assert_eq!(
            keypair.verifying_key.bytes.len(),
            MlDsa44::VERIFYING_KEY_SIZE
        );
        assert_eq!(
            keypair.signing_key.as_bytes().len(),
            MlDsa44::SIGNING_KEY_SIZE
        );
    }

    #[test]
    fn test_ml_dsa_65_roundtrip() {
        let mut rng = rand::thread_rng();
        let keypair = MlDsa65::generate_keypair(&mut rng).unwrap();
        let message = b"Test message for ML-DSA-65";
        let signature = MlDsa65::sign(message, &keypair.signing_key).unwrap();
        assert!(MlDsa65::verify(message, &signature, &keypair.verifying_key).unwrap());
    }

    #[test]
    fn test_ml_dsa_87_signature_size() {
        let mut rng = rand::thread_rng();
        let keypair = MlDsa87::generate_keypair(&mut rng).unwrap();
        let message = b"Test message";
        let signature = MlDsa87::sign(message, &keypair.signing_key).unwrap();
        assert_eq!(signature.bytes.len(), MlDsa87::SIGNATURE_SIZE);
    }
}

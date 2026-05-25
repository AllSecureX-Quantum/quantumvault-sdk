//! ML-KEM (Module Lattice Key Encapsulation Mechanism) implementations.
//!
//! Based on FIPS 203 (formerly CRYSTALS-Kyber).

use crate::error::{Error, Result};
use crate::primitives::Algorithm;
use crate::types::{KeyMetadata, KeyPair, PublicKey, SecretKey};
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey as _, SecretKey as _, SharedSecret};
use rand::RngCore;
use uuid::Uuid;

/// ML-KEM-512 (Kyber-512) - NIST Level 1 security.
pub struct MlKem512;

/// ML-KEM-768 (Kyber-768) - NIST Level 3 security (recommended).
pub struct MlKem768;

/// ML-KEM-1024 (Kyber-1024) - NIST Level 5 security.
pub struct MlKem1024;

impl super::Kem for MlKem512 {
    const ALGORITHM: Algorithm = Algorithm::MlKem512;
    const PUBLIC_KEY_SIZE: usize = 800;
    const SECRET_KEY_SIZE: usize = 1632;
    const CIPHERTEXT_SIZE: usize = 768;
    const SHARED_SECRET_SIZE: usize = 32;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<KeyPair> {
        let (pk, sk) = kyber512::keypair();
        let key_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        Ok(KeyPair {
            key_id: key_id.clone(),
            public_key: PublicKey::new(pk.as_bytes().to_vec(), Self::ALGORITHM, key_id.clone()),
            secret_key: SecretKey::new(sk.as_bytes().to_vec(), Self::ALGORITHM, key_id.clone()),
            algorithm: Self::ALGORITHM,
            created_at: now,
            expires_at: None,
            metadata: KeyMetadata::default(),
        })
    }

    fn encapsulate<R: RngCore + rand::CryptoRng>(
        _rng: &mut R,
        public_key: &PublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if public_key.bytes.len() != Self::PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-KEM-512 public key size: expected {}, got {}",
                Self::PUBLIC_KEY_SIZE,
                public_key.bytes.len()
            )));
        }

        let pk = kyber512::PublicKey::from_bytes(&public_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-KEM-512 public key: {:?}", e)))?;

        let (ss, ct) = kyber512::encapsulate(&pk);

        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }

    fn decapsulate(ciphertext: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>> {
        if ciphertext.len() != Self::CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertext(format!(
                "Invalid ML-KEM-512 ciphertext size: expected {}, got {}",
                Self::CIPHERTEXT_SIZE,
                ciphertext.len()
            )));
        }

        if secret_key.as_bytes().len() != Self::SECRET_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-KEM-512 secret key size: expected {}, got {}",
                Self::SECRET_KEY_SIZE,
                secret_key.as_bytes().len()
            )));
        }

        let sk = kyber512::SecretKey::from_bytes(secret_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-KEM-512 secret key: {:?}", e)))?;

        let ct = kyber512::Ciphertext::from_bytes(ciphertext).map_err(|e| {
            Error::InvalidCiphertext(format!("Invalid ML-KEM-512 ciphertext: {:?}", e))
        })?;

        let ss = kyber512::decapsulate(&ct, &sk);

        Ok(ss.as_bytes().to_vec())
    }
}

impl super::Kem for MlKem768 {
    const ALGORITHM: Algorithm = Algorithm::MlKem768;
    const PUBLIC_KEY_SIZE: usize = 1184;
    const SECRET_KEY_SIZE: usize = 2400;
    const CIPHERTEXT_SIZE: usize = 1088;
    const SHARED_SECRET_SIZE: usize = 32;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<KeyPair> {
        let (pk, sk) = kyber768::keypair();
        let key_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        Ok(KeyPair {
            key_id: key_id.clone(),
            public_key: PublicKey::new(pk.as_bytes().to_vec(), Self::ALGORITHM, key_id.clone()),
            secret_key: SecretKey::new(sk.as_bytes().to_vec(), Self::ALGORITHM, key_id.clone()),
            algorithm: Self::ALGORITHM,
            created_at: now,
            expires_at: None,
            metadata: KeyMetadata::default(),
        })
    }

    fn encapsulate<R: RngCore + rand::CryptoRng>(
        _rng: &mut R,
        public_key: &PublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if public_key.bytes.len() != Self::PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-KEM-768 public key size: expected {}, got {}",
                Self::PUBLIC_KEY_SIZE,
                public_key.bytes.len()
            )));
        }

        let pk = kyber768::PublicKey::from_bytes(&public_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-KEM-768 public key: {:?}", e)))?;

        let (ss, ct) = kyber768::encapsulate(&pk);

        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }

    fn decapsulate(ciphertext: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>> {
        if ciphertext.len() != Self::CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertext(format!(
                "Invalid ML-KEM-768 ciphertext size: expected {}, got {}",
                Self::CIPHERTEXT_SIZE,
                ciphertext.len()
            )));
        }

        if secret_key.as_bytes().len() != Self::SECRET_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-KEM-768 secret key size: expected {}, got {}",
                Self::SECRET_KEY_SIZE,
                secret_key.as_bytes().len()
            )));
        }

        let sk = kyber768::SecretKey::from_bytes(secret_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-KEM-768 secret key: {:?}", e)))?;

        let ct = kyber768::Ciphertext::from_bytes(ciphertext).map_err(|e| {
            Error::InvalidCiphertext(format!("Invalid ML-KEM-768 ciphertext: {:?}", e))
        })?;

        let ss = kyber768::decapsulate(&ct, &sk);

        Ok(ss.as_bytes().to_vec())
    }
}

impl super::Kem for MlKem1024 {
    const ALGORITHM: Algorithm = Algorithm::MlKem1024;
    const PUBLIC_KEY_SIZE: usize = 1568;
    const SECRET_KEY_SIZE: usize = 3168;
    const CIPHERTEXT_SIZE: usize = 1568;
    const SHARED_SECRET_SIZE: usize = 32;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<KeyPair> {
        let (pk, sk) = kyber1024::keypair();
        let key_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();

        Ok(KeyPair {
            key_id: key_id.clone(),
            public_key: PublicKey::new(pk.as_bytes().to_vec(), Self::ALGORITHM, key_id.clone()),
            secret_key: SecretKey::new(sk.as_bytes().to_vec(), Self::ALGORITHM, key_id.clone()),
            algorithm: Self::ALGORITHM,
            created_at: now,
            expires_at: None,
            metadata: KeyMetadata::default(),
        })
    }

    fn encapsulate<R: RngCore + rand::CryptoRng>(
        _rng: &mut R,
        public_key: &PublicKey,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if public_key.bytes.len() != Self::PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-KEM-1024 public key size: expected {}, got {}",
                Self::PUBLIC_KEY_SIZE,
                public_key.bytes.len()
            )));
        }

        let pk = kyber1024::PublicKey::from_bytes(&public_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-KEM-1024 public key: {:?}", e)))?;

        let (ss, ct) = kyber1024::encapsulate(&pk);

        Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
    }

    fn decapsulate(ciphertext: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>> {
        if ciphertext.len() != Self::CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertext(format!(
                "Invalid ML-KEM-1024 ciphertext size: expected {}, got {}",
                Self::CIPHERTEXT_SIZE,
                ciphertext.len()
            )));
        }

        if secret_key.as_bytes().len() != Self::SECRET_KEY_SIZE {
            return Err(Error::InvalidKey(format!(
                "Invalid ML-KEM-1024 secret key size: expected {}, got {}",
                Self::SECRET_KEY_SIZE,
                secret_key.as_bytes().len()
            )));
        }

        let sk = kyber1024::SecretKey::from_bytes(secret_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid ML-KEM-1024 secret key: {:?}", e)))?;

        let ct = kyber1024::Ciphertext::from_bytes(ciphertext).map_err(|e| {
            Error::InvalidCiphertext(format!("Invalid ML-KEM-1024 ciphertext: {:?}", e))
        })?;

        let ss = kyber1024::decapsulate(&ct, &sk);

        Ok(ss.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::kem::Kem;

    #[test]
    fn test_ml_kem_512_key_sizes() {
        let mut rng = rand::thread_rng();
        let keypair = MlKem512::generate_keypair(&mut rng).unwrap();
        assert_eq!(keypair.public_key.bytes.len(), MlKem512::PUBLIC_KEY_SIZE);
        assert_eq!(
            keypair.secret_key.as_bytes().len(),
            MlKem512::SECRET_KEY_SIZE
        );
    }

    #[test]
    fn test_ml_kem_768_key_sizes() {
        let mut rng = rand::thread_rng();
        let keypair = MlKem768::generate_keypair(&mut rng).unwrap();
        assert_eq!(keypair.public_key.bytes.len(), MlKem768::PUBLIC_KEY_SIZE);
        assert_eq!(
            keypair.secret_key.as_bytes().len(),
            MlKem768::SECRET_KEY_SIZE
        );
    }

    #[test]
    fn test_ml_kem_1024_key_sizes() {
        let mut rng = rand::thread_rng();
        let keypair = MlKem1024::generate_keypair(&mut rng).unwrap();
        assert_eq!(keypair.public_key.bytes.len(), MlKem1024::PUBLIC_KEY_SIZE);
        assert_eq!(
            keypair.secret_key.as_bytes().len(),
            MlKem1024::SECRET_KEY_SIZE
        );
    }

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let mut rng = rand::thread_rng();
        let keypair = MlKem768::generate_keypair(&mut rng).unwrap();
        let (ct, ss1) = MlKem768::encapsulate(&mut rng, &keypair.public_key).unwrap();
        let ss2 = MlKem768::decapsulate(&ct, &keypair.secret_key).unwrap();
        assert_eq!(ss1, ss2);
        assert_eq!(ss1.len(), MlKem768::SHARED_SECRET_SIZE);
    }
}

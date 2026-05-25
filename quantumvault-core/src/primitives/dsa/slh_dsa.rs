//! SLH-DSA (Stateless Hash-based Digital Signature Algorithm) implementations.
//!
//! Based on FIPS 205 (formerly SPHINCS+).

use crate::error::{Error, Result};
use crate::primitives::Algorithm;
use crate::types::{KeyMetadata, Signature, SignatureKeyPair, SigningKey, VerifyingKey};
use pqcrypto_sphincsplus::{
    sphincsshake128fsimple, sphincsshake128ssimple, sphincsshake256fsimple, sphincsshake256ssimple,
};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
use rand::RngCore;
use uuid::Uuid;

/// SLH-DSA-SHAKE-128s - NIST Level 3, small signatures.
pub struct SlhDsaShake128s;

/// SLH-DSA-SHAKE-128f - NIST Level 3, fast signing.
pub struct SlhDsaShake128f;

/// SLH-DSA-SHAKE-256s - NIST Level 5, small signatures.
pub struct SlhDsaShake256s;

/// SLH-DSA-SHAKE-256f - NIST Level 5, fast signing.
pub struct SlhDsaShake256f;

impl super::Dsa for SlhDsaShake128s {
    const ALGORITHM: Algorithm = Algorithm::SlhDsaShake128s;
    const VERIFYING_KEY_SIZE: usize = 32;
    const SIGNING_KEY_SIZE: usize = 64;
    const SIGNATURE_SIZE: usize = 7856;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<SignatureKeyPair> {
        let (pk, sk) = sphincsshake128ssimple::keypair();
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
        let sk = sphincsshake128ssimple::SecretKey::from_bytes(signing_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA signing key: {:?}", e)))?;

        let sig = sphincsshake128ssimple::detached_sign(message, &sk);
        let now = chrono::Utc::now().timestamp();

        Ok(Signature {
            bytes: sig.as_bytes().to_vec(),
            algorithm: Self::ALGORITHM,
            key_id: signing_key.key_id.clone(),
            signed_at: now,
        })
    }

    fn verify(message: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<bool> {
        let pk = sphincsshake128ssimple::PublicKey::from_bytes(&verifying_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA verifying key: {:?}", e)))?;

        let sig = sphincsshake128ssimple::DetachedSignature::from_bytes(&signature.bytes)
            .map_err(|e| Error::InvalidSignature(format!("Invalid SLH-DSA signature: {:?}", e)))?;

        Ok(sphincsshake128ssimple::verify_detached_signature(&sig, message, &pk).is_ok())
    }
}

impl super::Dsa for SlhDsaShake128f {
    const ALGORITHM: Algorithm = Algorithm::SlhDsaShake128f;
    const VERIFYING_KEY_SIZE: usize = 32;
    const SIGNING_KEY_SIZE: usize = 64;
    const SIGNATURE_SIZE: usize = 17088;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<SignatureKeyPair> {
        let (pk, sk) = sphincsshake128fsimple::keypair();
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
        let sk = sphincsshake128fsimple::SecretKey::from_bytes(signing_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA signing key: {:?}", e)))?;

        let sig = sphincsshake128fsimple::detached_sign(message, &sk);
        let now = chrono::Utc::now().timestamp();

        Ok(Signature {
            bytes: sig.as_bytes().to_vec(),
            algorithm: Self::ALGORITHM,
            key_id: signing_key.key_id.clone(),
            signed_at: now,
        })
    }

    fn verify(message: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<bool> {
        let pk = sphincsshake128fsimple::PublicKey::from_bytes(&verifying_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA verifying key: {:?}", e)))?;

        let sig = sphincsshake128fsimple::DetachedSignature::from_bytes(&signature.bytes)
            .map_err(|e| Error::InvalidSignature(format!("Invalid SLH-DSA signature: {:?}", e)))?;

        Ok(sphincsshake128fsimple::verify_detached_signature(&sig, message, &pk).is_ok())
    }
}

impl super::Dsa for SlhDsaShake256s {
    const ALGORITHM: Algorithm = Algorithm::SlhDsaShake256s;
    const VERIFYING_KEY_SIZE: usize = 64;
    const SIGNING_KEY_SIZE: usize = 128;
    const SIGNATURE_SIZE: usize = 29792;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<SignatureKeyPair> {
        let (pk, sk) = sphincsshake256ssimple::keypair();
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
        let sk = sphincsshake256ssimple::SecretKey::from_bytes(signing_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA signing key: {:?}", e)))?;

        let sig = sphincsshake256ssimple::detached_sign(message, &sk);
        let now = chrono::Utc::now().timestamp();

        Ok(Signature {
            bytes: sig.as_bytes().to_vec(),
            algorithm: Self::ALGORITHM,
            key_id: signing_key.key_id.clone(),
            signed_at: now,
        })
    }

    fn verify(message: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<bool> {
        let pk = sphincsshake256ssimple::PublicKey::from_bytes(&verifying_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA verifying key: {:?}", e)))?;

        let sig = sphincsshake256ssimple::DetachedSignature::from_bytes(&signature.bytes)
            .map_err(|e| Error::InvalidSignature(format!("Invalid SLH-DSA signature: {:?}", e)))?;

        Ok(sphincsshake256ssimple::verify_detached_signature(&sig, message, &pk).is_ok())
    }
}

impl super::Dsa for SlhDsaShake256f {
    const ALGORITHM: Algorithm = Algorithm::SlhDsaShake256f;
    const VERIFYING_KEY_SIZE: usize = 64;
    const SIGNING_KEY_SIZE: usize = 128;
    const SIGNATURE_SIZE: usize = 49856;

    fn generate_keypair<R: RngCore + rand::CryptoRng>(_rng: &mut R) -> Result<SignatureKeyPair> {
        let (pk, sk) = sphincsshake256fsimple::keypair();
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
        let sk = sphincsshake256fsimple::SecretKey::from_bytes(signing_key.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA signing key: {:?}", e)))?;

        let sig = sphincsshake256fsimple::detached_sign(message, &sk);
        let now = chrono::Utc::now().timestamp();

        Ok(Signature {
            bytes: sig.as_bytes().to_vec(),
            algorithm: Self::ALGORITHM,
            key_id: signing_key.key_id.clone(),
            signed_at: now,
        })
    }

    fn verify(message: &[u8], signature: &Signature, verifying_key: &VerifyingKey) -> Result<bool> {
        let pk = sphincsshake256fsimple::PublicKey::from_bytes(&verifying_key.bytes)
            .map_err(|e| Error::InvalidKey(format!("Invalid SLH-DSA verifying key: {:?}", e)))?;

        let sig = sphincsshake256fsimple::DetachedSignature::from_bytes(&signature.bytes)
            .map_err(|e| Error::InvalidSignature(format!("Invalid SLH-DSA signature: {:?}", e)))?;

        Ok(sphincsshake256fsimple::verify_detached_signature(&sig, message, &pk).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::dsa::Dsa;

    #[test]
    fn test_slh_dsa_shake128s_roundtrip() {
        let mut rng = rand::thread_rng();
        let keypair = SlhDsaShake128s::generate_keypair(&mut rng).unwrap();
        let message = b"Test message for SLH-DSA";
        let signature = SlhDsaShake128s::sign(message, &keypair.signing_key).unwrap();
        assert!(SlhDsaShake128s::verify(message, &signature, &keypair.verifying_key).unwrap());
    }

    #[test]
    fn test_slh_dsa_shake256s_roundtrip() {
        let mut rng = rand::thread_rng();
        let keypair = SlhDsaShake256s::generate_keypair(&mut rng).unwrap();
        let message = b"Test message for SLH-DSA Level 5";
        let signature = SlhDsaShake256s::sign(message, &keypair.signing_key).unwrap();
        assert!(SlhDsaShake256s::verify(message, &signature, &keypair.verifying_key).unwrap());
    }
}

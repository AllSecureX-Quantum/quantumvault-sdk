//! Symmetric encryption implementations.
//!
//! Provides AES-GCM and ChaCha20-Poly1305 authenticated encryption.

use crate::error::{Error, Result};
use crate::types::SymmetricAlgorithm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce, XChaCha20Poly1305, XNonce};
use rand::RngCore;

/// Symmetric encryption result.
pub struct EncryptionResult {
    /// The ciphertext with authentication tag.
    pub ciphertext: Vec<u8>,
    /// The nonce/IV used.
    pub nonce: Vec<u8>,
}

/// Encrypt data using authenticated encryption.
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    aad: Option<&[u8]>,
    algorithm: SymmetricAlgorithm,
) -> Result<EncryptionResult> {
    let mut rng = rand::thread_rng();
    let nonce_size = algorithm.nonce_size();
    let mut nonce = vec![0u8; nonce_size];
    rng.fill_bytes(&mut nonce);

    let ciphertext = encrypt_with_nonce(plaintext, key, &nonce, aad, algorithm)?;

    Ok(EncryptionResult { ciphertext, nonce })
}

/// Encrypt data using authenticated encryption with a provided nonce.
pub fn encrypt_with_nonce(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: Option<&[u8]>,
    algorithm: SymmetricAlgorithm,
) -> Result<Vec<u8>> {
    validate_key_size(key, algorithm)?;
    validate_nonce_size(nonce, algorithm)?;

    let payload = match aad {
        Some(aad) => Payload {
            msg: plaintext,
            aad,
        },
        None => Payload {
            msg: plaintext,
            aad: &[],
        },
    };

    match algorithm {
        SymmetricAlgorithm::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::Encryption(format!("AES-128-GCM init failed: {}", e)))?;
            let nonce = GenericArray::from_slice(nonce);
            cipher
                .encrypt(nonce, payload)
                .map_err(|e| Error::Encryption(format!("AES-128-GCM encryption failed: {}", e)))
        }
        SymmetricAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::Encryption(format!("AES-256-GCM init failed: {}", e)))?;
            let nonce = GenericArray::from_slice(nonce);
            cipher
                .encrypt(nonce, payload)
                .map_err(|e| Error::Encryption(format!("AES-256-GCM encryption failed: {}", e)))
        }
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Encryption(format!("ChaCha20-Poly1305 init failed: {}", e)))?;
            let nonce = ChachaNonce::from_slice(nonce);
            cipher.encrypt(nonce, payload).map_err(|e| {
                Error::Encryption(format!("ChaCha20-Poly1305 encryption failed: {}", e))
            })
        }
        SymmetricAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Encryption(format!("XChaCha20-Poly1305 init failed: {}", e)))?;
            let nonce = XNonce::from_slice(nonce);
            cipher.encrypt(nonce, payload).map_err(|e| {
                Error::Encryption(format!("XChaCha20-Poly1305 encryption failed: {}", e))
            })
        }
    }
}

/// Decrypt data using authenticated encryption.
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: Option<&[u8]>,
    algorithm: SymmetricAlgorithm,
) -> Result<Vec<u8>> {
    validate_key_size(key, algorithm)?;
    validate_nonce_size(nonce, algorithm)?;

    let payload = match aad {
        Some(aad) => Payload {
            msg: ciphertext,
            aad,
        },
        None => Payload {
            msg: ciphertext,
            aad: &[],
        },
    };

    match algorithm {
        SymmetricAlgorithm::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::Decryption(format!("AES-128-GCM init failed: {}", e)))?;
            let nonce = GenericArray::from_slice(nonce);
            cipher.decrypt(nonce, payload).map_err(|_| {
                Error::Decryption(
                    "AES-128-GCM decryption failed: authentication tag mismatch".into(),
                )
            })
        }
        SymmetricAlgorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::Decryption(format!("AES-256-GCM init failed: {}", e)))?;
            let nonce = GenericArray::from_slice(nonce);
            cipher.decrypt(nonce, payload).map_err(|_| {
                Error::Decryption(
                    "AES-256-GCM decryption failed: authentication tag mismatch".into(),
                )
            })
        }
        SymmetricAlgorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Decryption(format!("ChaCha20-Poly1305 init failed: {}", e)))?;
            let nonce = ChachaNonce::from_slice(nonce);
            cipher.decrypt(nonce, payload).map_err(|_| {
                Error::Decryption(
                    "ChaCha20-Poly1305 decryption failed: authentication tag mismatch".into(),
                )
            })
        }
        SymmetricAlgorithm::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::Decryption(format!("XChaCha20-Poly1305 init failed: {}", e)))?;
            let nonce = XNonce::from_slice(nonce);
            cipher.decrypt(nonce, payload).map_err(|_| {
                Error::Decryption(
                    "XChaCha20-Poly1305 decryption failed: authentication tag mismatch".into(),
                )
            })
        }
    }
}

/// Generate a random symmetric key for the given algorithm.
pub fn generate_key(algorithm: SymmetricAlgorithm) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut key = vec![0u8; algorithm.key_size()];
    rng.fill_bytes(&mut key);
    key
}

/// Generate a random nonce for the given algorithm.
pub fn generate_nonce(algorithm: SymmetricAlgorithm) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut nonce = vec![0u8; algorithm.nonce_size()];
    rng.fill_bytes(&mut nonce);
    nonce
}

fn validate_key_size(key: &[u8], algorithm: SymmetricAlgorithm) -> Result<()> {
    let expected = algorithm.key_size();
    if key.len() != expected {
        return Err(Error::InvalidKey(format!(
            "Invalid key size for {:?}: expected {}, got {}",
            algorithm,
            expected,
            key.len()
        )));
    }
    Ok(())
}

fn validate_nonce_size(nonce: &[u8], algorithm: SymmetricAlgorithm) -> Result<()> {
    let expected = algorithm.nonce_size();
    if nonce.len() != expected {
        return Err(Error::Encryption(format!(
            "Invalid nonce size for {:?}: expected {}, got {}",
            algorithm,
            expected,
            nonce.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256gcm_roundtrip() {
        let key = generate_key(SymmetricAlgorithm::Aes256Gcm);
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let result = encrypt(plaintext, &key, Some(aad), SymmetricAlgorithm::Aes256Gcm).unwrap();
        let decrypted = decrypt(
            &result.ciphertext,
            &key,
            &result.nonce,
            Some(aad),
            SymmetricAlgorithm::Aes256Gcm,
        )
        .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = generate_key(SymmetricAlgorithm::ChaCha20Poly1305);
        let plaintext = b"Hello, World!";

        let result = encrypt(plaintext, &key, None, SymmetricAlgorithm::ChaCha20Poly1305).unwrap();
        let decrypted = decrypt(
            &result.ciphertext,
            &key,
            &result.nonce,
            None,
            SymmetricAlgorithm::ChaCha20Poly1305,
        )
        .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = generate_key(SymmetricAlgorithm::Aes256Gcm);
        let plaintext = b"Hello, World!";

        let mut result = encrypt(plaintext, &key, None, SymmetricAlgorithm::Aes256Gcm).unwrap();
        result.ciphertext[0] ^= 0xFF; // Tamper with ciphertext

        let decrypted = decrypt(
            &result.ciphertext,
            &key,
            &result.nonce,
            None,
            SymmetricAlgorithm::Aes256Gcm,
        );

        assert!(decrypted.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = generate_key(SymmetricAlgorithm::Aes256Gcm);
        let plaintext = b"Hello, World!";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let result = encrypt(plaintext, &key, Some(aad), SymmetricAlgorithm::Aes256Gcm).unwrap();
        let decrypted = decrypt(
            &result.ciphertext,
            &key,
            &result.nonce,
            Some(wrong_aad),
            SymmetricAlgorithm::Aes256Gcm,
        );

        assert!(decrypted.is_err());
    }
}

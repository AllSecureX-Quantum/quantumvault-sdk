//! Hybrid cryptography API combining PQC and classical algorithms.
//!
//! Hybrid mode provides defense-in-depth by combining post-quantum algorithms
//! with classical algorithms. The security depends on BOTH algorithms being secure.

#[cfg(feature = "hybrid")]
use crate::config::Config;
#[cfg(feature = "hybrid")]
use crate::error::{Error, Result};
#[cfg(feature = "hybrid")]
use crate::primitives::{hash, kem, Algorithm};
#[cfg(feature = "hybrid")]
use crate::types::{
    ClassicalAlgorithm, ClassicalEncryptedData, ClassicalPublicKey, EncryptedData,
    HybridEncryptedData, KeyMetadata, KeyPair, PublicKey, SecretKey,
};

#[cfg(feature = "hybrid")]
use rsa::{pkcs1v15::Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

#[cfg(feature = "hybrid")]
use rand::rngs::OsRng;

/// Encrypt data using hybrid mode (PQC + Classical).
///
/// This encrypts the plaintext with BOTH a PQC algorithm and a classical algorithm.
/// The symmetric key is derived from BOTH shared secrets, so an attacker must
/// break BOTH algorithms to decrypt the data.
#[cfg(feature = "hybrid")]
pub fn hybrid_encrypt(
    plaintext: &[u8],
    pqc_public_key: &PublicKey,
    classical_public_key: &ClassicalPublicKey,
    _config: &Config,
) -> Result<HybridEncryptedData> {
    // Generate PQC shared secret
    let pqc_encap = kem::encapsulate(pqc_public_key)?;

    // Generate classical shared secret and encrypt it
    let classical_shared_secret = generate_random_secret(32)?;
    let classical_encrypted =
        encrypt_with_classical(&classical_shared_secret, classical_public_key)?;

    // Combine shared secrets using HKDF
    let combined_secret = combine_secrets(
        &pqc_encap.shared_secret,
        &classical_shared_secret,
        b"QuantumVault-Hybrid-v1",
    )?;

    // Encrypt plaintext with combined key
    let info = b"hybrid-data-encryption";
    let symmetric_key = hash::hkdf_expand(&combined_secret, info, 32)?;

    let enc_result = crate::primitives::symmetric::encrypt(
        plaintext,
        &symmetric_key,
        None,
        crate::types::SymmetricAlgorithm::Aes256Gcm,
    )?;

    let now = chrono::Utc::now().timestamp();

    // Create key confirmation (hash of combined secret for verification)
    let key_confirmation = hash::hash(
        &combined_secret,
        crate::primitives::hash::HashAlgorithm::Sha3_256,
    );

    Ok(HybridEncryptedData {
        pqc_component: EncryptedData {
            encapsulated_key: pqc_encap.ciphertext.clone(),
            ciphertext: enc_result.ciphertext,
            nonce: enc_result.nonce,
            tag: Vec::new(),
            algorithm: pqc_public_key.algorithm,
            key_id: pqc_public_key.key_id.clone(),
            encrypted_at: now,
            version: 1,
        },
        classical_component: classical_encrypted,
        key_confirmation,
    })
}

/// Decrypt data using hybrid mode.
#[cfg(feature = "hybrid")]
pub fn hybrid_decrypt(
    encrypted: &HybridEncryptedData,
    pqc_secret_key: &SecretKey,
    classical_secret_key: &[u8],
    classical_algorithm: ClassicalAlgorithm,
    _config: &Config,
) -> Result<Vec<u8>> {
    // Recover PQC shared secret
    let pqc_shared_secret =
        kem::decapsulate(&encrypted.pqc_component.encapsulated_key, pqc_secret_key)?;

    // Recover classical shared secret
    let classical_shared_secret = decrypt_with_classical(
        &encrypted.classical_component.encrypted_key,
        classical_secret_key,
        classical_algorithm,
    )?;

    // Combine shared secrets
    let combined_secret = combine_secrets(
        &pqc_shared_secret,
        &classical_shared_secret,
        b"QuantumVault-Hybrid-v1",
    )?;

    // Verify key confirmation
    let expected_confirmation = hash::hash(
        &combined_secret,
        crate::primitives::hash::HashAlgorithm::Sha3_256,
    );
    if expected_confirmation != encrypted.key_confirmation {
        return Err(Error::Decryption("Key confirmation mismatch".into()));
    }

    // Derive symmetric key and decrypt
    let info = b"hybrid-data-encryption";
    let symmetric_key = hash::hkdf_expand(&combined_secret, info, 32)?;

    crate::primitives::symmetric::decrypt(
        &encrypted.pqc_component.ciphertext,
        &symmetric_key,
        &encrypted.pqc_component.nonce,
        None,
        crate::types::SymmetricAlgorithm::Aes256Gcm,
    )
}

/// Generate a hybrid KEM key pair.
#[cfg(feature = "hybrid")]
pub fn generate_hybrid_kem_keypair(algorithm: Algorithm, _config: &Config) -> Result<KeyPair> {
    match algorithm {
        Algorithm::HybridMlKemRsa => {
            // Generate ML-KEM-768 key pair
            let pqc_keypair = kem::generate_keypair(Algorithm::MlKem768)?;

            // Generate RSA-2048 key pair
            let rsa_private = RsaPrivateKey::new(&mut OsRng, 2048)
                .map_err(|e| Error::KeyGeneration(format!("RSA key generation failed: {}", e)))?;

            // Combine keys (simplified - in production you'd serialize both)
            let mut combined_public = pqc_keypair.public_key.bytes.clone();
            let rsa_public = RsaPublicKey::from(&rsa_private);
            let rsa_public_bytes = rsa_public_to_bytes(&rsa_public)?;
            combined_public.extend_from_slice(&rsa_public_bytes);

            let mut combined_secret = pqc_keypair.secret_key.as_bytes().to_vec();
            let rsa_private_bytes = rsa_private_to_bytes(&rsa_private)?;
            combined_secret.extend_from_slice(&rsa_private_bytes);

            Ok(KeyPair {
                key_id: pqc_keypair.key_id.clone(),
                public_key: PublicKey::new(
                    combined_public,
                    algorithm,
                    pqc_keypair.public_key.key_id.clone(),
                ),
                secret_key: SecretKey::new(
                    combined_secret,
                    algorithm,
                    pqc_keypair.secret_key.key_id.clone(),
                ),
                algorithm,
                created_at: pqc_keypair.created_at,
                expires_at: None,
                metadata: KeyMetadata::default(),
            })
        }
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
            operation: "hybrid KEM key generation".to_string(),
        }),
    }
}

/// Generate a hybrid DSA key pair.
#[cfg(feature = "hybrid")]
pub fn generate_hybrid_dsa_keypair(algorithm: Algorithm, _config: &Config) -> Result<KeyPair> {
    Err(Error::UnsupportedAlgorithm {
        algorithm: algorithm.to_string(),
        operation: "hybrid DSA key generation (not yet implemented)".to_string(),
    })
}

#[cfg(feature = "hybrid")]
fn generate_random_secret(len: usize) -> Result<Vec<u8>> {
    use rand::RngCore;
    let mut secret = vec![0u8; len];
    OsRng.fill_bytes(&mut secret);
    Ok(secret)
}

#[cfg(feature = "hybrid")]
fn combine_secrets(secret1: &[u8], secret2: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    // Combine secrets using HKDF with both as IKM
    let mut combined_ikm = Vec::with_capacity(secret1.len() + secret2.len());
    combined_ikm.extend_from_slice(secret1);
    combined_ikm.extend_from_slice(secret2);

    hash::hkdf_extract_expand(context, &combined_ikm, b"combined-secret", 32)
}

#[cfg(feature = "hybrid")]
fn encrypt_with_classical(
    plaintext: &[u8],
    public_key: &ClassicalPublicKey,
) -> Result<ClassicalEncryptedData> {
    match public_key.algorithm {
        ClassicalAlgorithm::RsaOaep2048 | ClassicalAlgorithm::RsaOaep4096 => {
            let rsa_public = rsa_public_from_bytes(&public_key.bytes)?;
            let encrypted = rsa_public
                .encrypt(&mut OsRng, Pkcs1v15Encrypt, plaintext)
                .map_err(|e| Error::Encryption(format!("RSA encryption failed: {}", e)))?;

            Ok(ClassicalEncryptedData {
                encrypted_key: encrypted,
                algorithm: public_key.algorithm,
            })
        }
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: format!("{:?}", public_key.algorithm),
            operation: "classical encryption".to_string(),
        }),
    }
}

#[cfg(feature = "hybrid")]
fn decrypt_with_classical(
    ciphertext: &[u8],
    secret_key: &[u8],
    algorithm: ClassicalAlgorithm,
) -> Result<Vec<u8>> {
    match algorithm {
        ClassicalAlgorithm::RsaOaep2048 | ClassicalAlgorithm::RsaOaep4096 => {
            let rsa_private = rsa_private_from_bytes(secret_key)?;
            rsa_private
                .decrypt(Pkcs1v15Encrypt, ciphertext)
                .map_err(|e| Error::Decryption(format!("RSA decryption failed: {}", e)))
        }
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: format!("{:?}", algorithm),
            operation: "classical decryption".to_string(),
        }),
    }
}

#[cfg(feature = "hybrid")]
fn rsa_public_to_bytes(key: &RsaPublicKey) -> Result<Vec<u8>> {
    use rsa::pkcs8::EncodePublicKey;
    key.to_public_key_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|e| Error::Serialization(format!("RSA public key serialization failed: {}", e)))
}

#[cfg(feature = "hybrid")]
fn rsa_private_to_bytes(key: &RsaPrivateKey) -> Result<Vec<u8>> {
    use rsa::pkcs8::EncodePrivateKey;
    key.to_pkcs8_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|e| Error::Serialization(format!("RSA private key serialization failed: {}", e)))
}

#[cfg(feature = "hybrid")]
fn rsa_public_from_bytes(bytes: &[u8]) -> Result<RsaPublicKey> {
    use rsa::pkcs8::DecodePublicKey;
    RsaPublicKey::from_public_key_der(bytes).map_err(|e| {
        Error::Deserialization(format!("RSA public key deserialization failed: {}", e))
    })
}

#[cfg(feature = "hybrid")]
fn rsa_private_from_bytes(bytes: &[u8]) -> Result<RsaPrivateKey> {
    use rsa::pkcs8::DecodePrivateKey;
    RsaPrivateKey::from_pkcs8_der(bytes).map_err(|e| {
        Error::Deserialization(format!("RSA private key deserialization failed: {}", e))
    })
}

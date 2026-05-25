//! Core types for QuantumVault cryptographic operations.

use crate::primitives::Algorithm;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A cryptographic key pair consisting of public and secret keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// Unique identifier for this key pair.
    pub key_id: String,
    /// The public key (can be shared).
    pub public_key: PublicKey,
    /// The secret key (must be kept private).
    pub secret_key: SecretKey,
    /// Algorithm used for this key pair.
    pub algorithm: Algorithm,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: i64,
    /// Optional expiration timestamp.
    pub expires_at: Option<i64>,
    /// Key metadata.
    #[serde(default)]
    pub metadata: KeyMetadata,
}

impl KeyPair {
    /// Check if the key pair has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            chrono::Utc::now().timestamp() > expires
        } else {
            false
        }
    }
}

/// Public key for encryption or signature verification.
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Raw key bytes.
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
    /// Algorithm this key is for.
    pub algorithm: Algorithm,
    /// Key identifier.
    pub key_id: String,
}

impl PublicKey {
    /// Create a new public key from raw bytes.
    pub fn new(bytes: Vec<u8>, algorithm: Algorithm, key_id: String) -> Self {
        Self {
            bytes,
            algorithm,
            key_id,
        }
    }

    /// Get the key size in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the key is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Secret key for decryption or signing (zeroized on drop).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// Raw key bytes (will be zeroized on drop).
    #[serde(with = "base64_bytes")]
    bytes: Vec<u8>,
    /// Algorithm this key is for.
    #[zeroize(skip)]
    pub algorithm: Algorithm,
    /// Key identifier.
    #[zeroize(skip)]
    pub key_id: String,
}

impl SecretKey {
    /// Create a new secret key from raw bytes.
    pub fn new(bytes: Vec<u8>, algorithm: Algorithm, key_id: String) -> Self {
        Self {
            bytes,
            algorithm,
            key_id,
        }
    }

    /// Get read-only access to the key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the key size in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the key is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Signing key for digital signatures (zeroized on drop).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    /// Raw key bytes (will be zeroized on drop).
    #[serde(with = "base64_bytes")]
    bytes: Vec<u8>,
    /// Algorithm this key is for.
    #[zeroize(skip)]
    pub algorithm: Algorithm,
    /// Key identifier.
    #[zeroize(skip)]
    pub key_id: String,
}

impl SigningKey {
    /// Create a new signing key from raw bytes.
    pub fn new(bytes: Vec<u8>, algorithm: Algorithm, key_id: String) -> Self {
        Self {
            bytes,
            algorithm,
            key_id,
        }
    }

    /// Get read-only access to the key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Verifying key for signature verification.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyingKey {
    /// Raw key bytes.
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
    /// Algorithm this key is for.
    pub algorithm: Algorithm,
    /// Key identifier.
    pub key_id: String,
}

impl VerifyingKey {
    /// Create a new verifying key from raw bytes.
    pub fn new(bytes: Vec<u8>, algorithm: Algorithm, key_id: String) -> Self {
        Self {
            bytes,
            algorithm,
            key_id,
        }
    }
}

/// Key pair for digital signatures.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignatureKeyPair {
    /// Unique identifier for this key pair.
    pub key_id: String,
    /// The verifying (public) key.
    pub verifying_key: VerifyingKey,
    /// The signing (private) key.
    pub signing_key: SigningKey,
    /// Algorithm used for this key pair.
    pub algorithm: Algorithm,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: i64,
    /// Optional expiration timestamp.
    pub expires_at: Option<i64>,
    /// Key metadata.
    #[serde(default)]
    pub metadata: KeyMetadata,
}

/// Encrypted data container.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encapsulated key (for KEM-based encryption).
    #[serde(with = "base64_bytes")]
    pub encapsulated_key: Vec<u8>,
    /// The ciphertext.
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
    /// Nonce/IV used for symmetric encryption.
    #[serde(with = "base64_bytes")]
    pub nonce: Vec<u8>,
    /// Authentication tag (for AEAD).
    #[serde(with = "base64_bytes")]
    pub tag: Vec<u8>,
    /// Algorithm used for encryption.
    pub algorithm: Algorithm,
    /// Key ID used for encryption.
    pub key_id: String,
    /// Encryption timestamp.
    pub encrypted_at: i64,
    /// Version for format compatibility.
    pub version: u8,
}

impl EncryptedData {
    /// Current version of the encrypted data format.
    pub const CURRENT_VERSION: u8 = 1;
}

/// Digital signature.
#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Raw signature bytes.
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
    /// Algorithm used for signing.
    pub algorithm: Algorithm,
    /// Key ID used for signing.
    pub key_id: String,
    /// Signing timestamp.
    pub signed_at: i64,
}

impl Signature {
    /// Get the signature size in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the signature is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Hybrid encrypted data (PQC + Classical).
#[cfg(feature = "hybrid")]
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridEncryptedData {
    /// PQC encrypted component.
    pub pqc_component: EncryptedData,
    /// Classical encrypted component.
    pub classical_component: ClassicalEncryptedData,
    /// Combined symmetric key hash for verification.
    #[serde(with = "base64_bytes")]
    pub key_confirmation: Vec<u8>,
}

/// Classical encryption data (for hybrid mode).
#[cfg(feature = "hybrid")]
#[derive(Clone, Serialize, Deserialize)]
pub struct ClassicalEncryptedData {
    /// Encrypted symmetric key.
    #[serde(with = "base64_bytes")]
    pub encrypted_key: Vec<u8>,
    /// Algorithm used (RSA, ECDH, etc.).
    pub algorithm: ClassicalAlgorithm,
}

/// Classical cryptographic algorithms (for hybrid mode).
#[cfg(feature = "hybrid")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassicalAlgorithm {
    /// RSA-OAEP with 2048-bit key.
    RsaOaep2048,
    /// RSA-OAEP with 4096-bit key.
    RsaOaep4096,
    /// ECDH with P-256 curve.
    EcdhP256,
    /// ECDH with P-384 curve.
    EcdhP384,
    /// X25519 key exchange.
    X25519,
}

/// Classical public key (for hybrid mode).
#[cfg(feature = "hybrid")]
#[derive(Clone, Serialize, Deserialize)]
pub struct ClassicalPublicKey {
    /// Raw key bytes.
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
    /// Algorithm this key is for.
    pub algorithm: ClassicalAlgorithm,
}

/// Key metadata for tracking and management.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Human-readable key name.
    #[serde(default)]
    pub name: Option<String>,
    /// Key description.
    #[serde(default)]
    pub description: Option<String>,
    /// Key tags for organization.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Custom attributes.
    #[serde(default)]
    pub attributes: std::collections::HashMap<String, String>,
    /// Key storage location.
    #[serde(default)]
    pub storage_type: KeyStorageType,
    /// Compliance tags.
    #[serde(default)]
    pub compliance_tags: Vec<String>,
}

/// Key storage type.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyStorageType {
    /// Stored in memory (ephemeral).
    #[default]
    Memory,
    /// Stored locally on disk.
    Local,
    /// Stored in AWS KMS.
    AwsKms,
    /// Stored in AWS Secrets Manager.
    AwsSecretsManager,
    /// Stored in AWS CloudHSM.
    AwsCloudHsm,
    /// Stored in HashiCorp Vault.
    HashiCorpVault,
    /// Custom storage provider.
    Custom(String),
}

/// Symmetric key for AES/ChaCha operations (zeroized on drop).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    pub algorithm: SymmetricAlgorithm,
}

impl SymmetricKey {
    /// Create a new symmetric key.
    pub fn new(bytes: Vec<u8>, algorithm: SymmetricAlgorithm) -> Self {
        Self { bytes, algorithm }
    }

    /// Get read-only access to the key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Symmetric encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymmetricAlgorithm {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305.
    XChaCha20Poly1305,
}

impl SymmetricAlgorithm {
    /// Get the key size in bytes for this algorithm.
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::XChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size in bytes for this algorithm.
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    /// Get the tag size in bytes for this algorithm.
    pub fn tag_size(&self) -> usize {
        16
    }
}

/// Custom serialization for binary data as base64.
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

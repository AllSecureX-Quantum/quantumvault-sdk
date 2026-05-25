//! # QuantumVault Keys
//!
//! Key management module providing secure key generation, storage,
//! lifecycle management, and policy enforcement.
//!
//! ## Features
//!
//! - **Secure Key Generation**: Cryptographically secure random key generation
//! - **Multiple Storage Backends**: Local, AWS KMS, AWS Secrets Manager, HashiCorp Vault
//! - **Key Lifecycle Management**: Rotation, expiration, revocation
//! - **Policy Enforcement**: Access control and usage restrictions
//! - **Audit Logging**: Complete audit trail for all key operations
//!
//! ## Example
//!
//! ```rust,ignore
//! use quantumvault_keys::{KeyManager, StorageBackend};
//! use quantumvault_core::{Algorithm, SecurityLevel};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let manager = KeyManager::builder()
//!         .storage(StorageBackend::Local { path: "./keys".into() })
//!         .build()
//!         .await?;
//!
//!     // Generate a new key
//!     let key_id = manager.generate_key(Algorithm::MlKem768).await?;
//!
//!     // Retrieve the key
//!     let keypair = manager.get_key(&key_id).await?;
//!
//!     Ok(())
//! }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod generation;
pub mod lifecycle;
pub mod policy;
pub mod storage;

mod error;
mod manager;

pub use error::{KeyError, KeyResult};
pub use manager::{KeyManager, KeyManagerBuilder};
pub use storage::{StorageBackend, StorageConfig};

use quantumvault_core::Algorithm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Key entry in the key store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Unique key identifier.
    pub key_id: String,
    /// Algorithm used for this key.
    pub algorithm: Algorithm,
    /// Key type (encryption or signing).
    pub key_type: KeyType,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last used timestamp.
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Expiration timestamp.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Key status.
    pub status: KeyStatus,
    /// Key metadata.
    pub metadata: KeyMetadata,
    /// Rotation policy.
    pub rotation_policy: Option<RotationPolicy>,
    /// Usage count.
    pub usage_count: u64,
}

/// Type of key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Key Encapsulation Mechanism key for encryption.
    Kem,
    /// Digital Signature Algorithm key for signing.
    Dsa,
    /// Symmetric key.
    Symmetric,
}

/// Status of a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStatus {
    /// Key is active and can be used.
    Active,
    /// Key is being rotated.
    Rotating,
    /// Key is disabled but not revoked.
    Disabled,
    /// Key has expired.
    Expired,
    /// Key has been revoked.
    Revoked,
    /// Key is pending deletion.
    PendingDeletion,
}

impl KeyStatus {
    /// Check if the key can be used for operations.
    pub fn is_usable(&self) -> bool {
        matches!(self, KeyStatus::Active)
    }
}

/// Key metadata.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Human-readable name.
    pub name: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Tags for organization.
    pub tags: Vec<String>,
    /// Custom attributes.
    pub attributes: HashMap<String, String>,
    /// Owner identifier.
    pub owner: Option<String>,
    /// Compliance tags.
    pub compliance_tags: Vec<String>,
}

/// Key rotation policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Enable automatic rotation.
    pub auto_rotate: bool,
    /// Rotation interval in days.
    pub rotation_interval_days: u32,
    /// Last rotation timestamp.
    pub last_rotated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Next scheduled rotation.
    pub next_rotation_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Keep old key versions.
    pub retain_versions: u32,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            auto_rotate: true,
            rotation_interval_days: 90,
            last_rotated_at: None,
            next_rotation_at: None,
            retain_versions: 3,
        }
    }
}

/// Key generation options.
#[derive(Clone, Debug, Default)]
pub struct KeyGenOptions {
    /// Key metadata.
    pub metadata: KeyMetadata,
    /// Key expiration (days from now).
    pub expires_in_days: Option<u32>,
    /// Rotation policy.
    pub rotation_policy: Option<RotationPolicy>,
    /// Tags.
    pub tags: Vec<String>,
}

impl KeyGenOptions {
    /// Create new options with a name.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            metadata: KeyMetadata {
                name: Some(name.into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Set expiration.
    pub fn expires_in(mut self, days: u32) -> Self {
        self.expires_in_days = Some(days);
        self
    }

    /// Set rotation policy.
    pub fn rotation(mut self, policy: RotationPolicy) -> Self {
        self.rotation_policy = Some(policy);
        self
    }

    /// Add a tag.
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

//! Key storage backends.

mod local;
// AWS KMS / Secrets Manager backends are deferred — see quantumvault-aws crate
// for the AWS integration surface. Module files were removed; re-add when the
// `aws-kms` / `aws-secrets` features are reinstated.

pub use local::LocalStorage;

use crate::error::KeyResult;
use crate::KeyEntry;
use async_trait::async_trait;
use quantumvault_core::KeyPair;
use std::path::PathBuf;
use std::sync::Arc;

/// Storage backend configuration.
#[derive(Clone, Debug)]
pub enum StorageBackend {
    /// Local file-based storage.
    Local {
        /// Path to the key storage directory.
        path: PathBuf,
        /// Encryption key for securing stored keys (optional).
        encryption_key: Option<Vec<u8>>,
    },
    /// In-memory storage (ephemeral, for testing).
    Memory,
    // NOTE: AWS KMS / Secrets Manager backends are provided by the dedicated
    // quantumvault-aws crate. The previously-gated variants here were dead
    // code (modules didn't exist, features were commented out) and were
    // removed during the foundation hardening pass.
}

/// Storage configuration.
#[derive(Clone, Debug, Default)]
pub struct StorageConfig {
    /// Enable encryption at rest.
    pub encrypt_at_rest: bool,
    /// Enable compression.
    pub compress: bool,
    /// Backup configuration.
    pub backup: Option<BackupConfig>,
}

/// Backup configuration.
#[derive(Clone, Debug)]
pub struct BackupConfig {
    /// Enable automatic backups.
    pub enabled: bool,
    /// Backup interval in hours.
    pub interval_hours: u32,
    /// Backup destination.
    pub destination: String,
    /// Number of backups to retain.
    pub retention_count: u32,
}

/// Trait for key storage implementations.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Store a key pair.
    async fn store_keypair(&self, keypair: &KeyPair, entry: &KeyEntry) -> KeyResult<()>;

    /// Retrieve a key pair.
    async fn get_keypair(&self, key_id: &str) -> KeyResult<KeyPair>;

    /// Get key entry (metadata only).
    async fn get_entry(&self, key_id: &str) -> KeyResult<KeyEntry>;

    /// List all key entries.
    async fn list_entries(&self) -> KeyResult<Vec<KeyEntry>>;

    /// Update key status.
    async fn update_status(&self, key_id: &str, status: crate::KeyStatus) -> KeyResult<()>;

    /// Update last used timestamp.
    async fn update_last_used(&self, key_id: &str) -> KeyResult<()>;

    /// Delete a key.
    async fn delete(&self, key_id: &str) -> KeyResult<()>;

    /// Check if a key exists.
    async fn exists(&self, key_id: &str) -> KeyResult<bool>;
}

/// Create a key store from a storage backend configuration.
pub async fn create_store(backend: StorageBackend) -> KeyResult<Arc<dyn KeyStore>> {
    match backend {
        StorageBackend::Local {
            path,
            encryption_key,
        } => {
            let store = LocalStorage::new(path, encryption_key).await?;
            Ok(Arc::new(store))
        }
        StorageBackend::Memory => {
            let store = local::MemoryStorage::new();
            Ok(Arc::new(store))
        }
    }
}

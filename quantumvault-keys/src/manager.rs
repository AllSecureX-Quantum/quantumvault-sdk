//! Key manager for coordinating key operations.

use crate::error::{KeyError, KeyResult};
use crate::storage::{KeyStore, StorageBackend};
use crate::{KeyEntry, KeyGenOptions, KeyStatus, KeyType, RotationPolicy};
use quantumvault_core::{Algorithm, Config as CoreConfig, KeyPair, SecurityLevel};
use std::sync::Arc;
use tracing::{info, warn};

/// Key manager for all key operations.
pub struct KeyManager {
    store: Arc<dyn KeyStore>,
    config: KeyManagerConfig,
    core_config: CoreConfig,
}

/// Configuration for the key manager.
#[derive(Clone, Debug)]
pub struct KeyManagerConfig {
    /// Default rotation policy.
    pub default_rotation_policy: RotationPolicy,
    /// Enable automatic key expiration checks.
    pub auto_expire_check: bool,
    /// Enable automatic rotation.
    pub auto_rotation: bool,
    /// Cache keys in memory.
    pub enable_cache: bool,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
}

impl Default for KeyManagerConfig {
    fn default() -> Self {
        Self {
            default_rotation_policy: RotationPolicy::default(),
            auto_expire_check: true,
            auto_rotation: true,
            enable_cache: true,
            cache_ttl_secs: 300,
        }
    }
}

impl KeyManager {
    /// Create a new key manager builder.
    pub fn builder() -> KeyManagerBuilder {
        KeyManagerBuilder::default()
    }

    /// Generate a new KEM key pair.
    pub async fn generate_kem_key(
        &self,
        algorithm: Algorithm,
        options: Option<KeyGenOptions>,
    ) -> KeyResult<String> {
        let options = options.unwrap_or_default();

        // Validate algorithm is KEM
        if !matches!(
            algorithm,
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024
        ) {
            return Err(KeyError::InvalidConfig(format!(
                "{} is not a KEM algorithm",
                algorithm
            )));
        }

        // Generate the key pair
        let keypair =
            quantumvault_core::api::keygen::generate_keypair(algorithm, &self.core_config)?;

        // Create key entry
        let now = chrono::Utc::now();
        let expires_at = options
            .expires_in_days
            .map(|days| now + chrono::Duration::days(days as i64));

        let entry = KeyEntry {
            key_id: keypair.key_id.clone(),
            algorithm,
            key_type: KeyType::Kem,
            created_at: now,
            last_used_at: None,
            expires_at,
            status: KeyStatus::Active,
            metadata: options.metadata,
            rotation_policy: options
                .rotation_policy
                .or(Some(self.config.default_rotation_policy.clone())),
            usage_count: 0,
        };

        // Store the key
        self.store.store_keypair(&keypair, &entry).await?;

        info!(key_id = %keypair.key_id, algorithm = %algorithm, "Generated new KEM key");

        Ok(keypair.key_id)
    }

    /// Generate a new DSA key pair.
    pub async fn generate_dsa_key(
        &self,
        algorithm: Algorithm,
        options: Option<KeyGenOptions>,
    ) -> KeyResult<String> {
        let options = options.unwrap_or_default();

        // Validate algorithm is DSA
        if !matches!(
            algorithm,
            Algorithm::MlDsa44
                | Algorithm::MlDsa65
                | Algorithm::MlDsa87
                | Algorithm::SlhDsaShake128s
                | Algorithm::SlhDsaShake128f
                | Algorithm::SlhDsaShake256s
                | Algorithm::SlhDsaShake256f
        ) {
            return Err(KeyError::InvalidConfig(format!(
                "{} is not a DSA algorithm",
                algorithm
            )));
        }

        // Generate the key pair
        let sig_keypair = quantumvault_core::api::keygen::generate_signature_keypair(
            algorithm,
            &self.core_config,
        )?;

        // Convert to KeyPair format for storage
        let keypair = KeyPair {
            key_id: sig_keypair.key_id.clone(),
            public_key: quantumvault_core::PublicKey::new(
                sig_keypair.verifying_key.bytes.clone(),
                algorithm,
                sig_keypair.verifying_key.key_id.clone(),
            ),
            secret_key: quantumvault_core::SecretKey::new(
                sig_keypair.signing_key.as_bytes().to_vec(),
                algorithm,
                sig_keypair.signing_key.key_id.clone(),
            ),
            algorithm,
            created_at: sig_keypair.created_at,
            expires_at: sig_keypair.expires_at,
            metadata: Default::default(),
        };

        let now = chrono::Utc::now();
        let expires_at = options
            .expires_in_days
            .map(|days| now + chrono::Duration::days(days as i64));

        let entry = KeyEntry {
            key_id: keypair.key_id.clone(),
            algorithm,
            key_type: KeyType::Dsa,
            created_at: now,
            last_used_at: None,
            expires_at,
            status: KeyStatus::Active,
            metadata: options.metadata,
            rotation_policy: options
                .rotation_policy
                .or(Some(self.config.default_rotation_policy.clone())),
            usage_count: 0,
        };

        self.store.store_keypair(&keypair, &entry).await?;

        info!(key_id = %keypair.key_id, algorithm = %algorithm, "Generated new DSA key");

        Ok(keypair.key_id)
    }

    /// Get a key by ID.
    pub async fn get_key(&self, key_id: &str) -> KeyResult<KeyPair> {
        let entry = self.store.get_entry(key_id).await?;

        // Check key status
        if !entry.status.is_usable() {
            return Err(KeyError::NotUsable(key_id.to_string(), entry.status));
        }

        // Check expiration
        if let Some(expires_at) = entry.expires_at {
            if chrono::Utc::now() > expires_at {
                return Err(KeyError::Expired(key_id.to_string()));
            }
        }

        // Update last used
        self.store.update_last_used(key_id).await?;

        self.store.get_keypair(key_id).await
    }

    /// Get key entry (metadata only).
    pub async fn get_key_entry(&self, key_id: &str) -> KeyResult<KeyEntry> {
        self.store.get_entry(key_id).await
    }

    /// List all keys.
    pub async fn list_keys(&self) -> KeyResult<Vec<KeyEntry>> {
        self.store.list_entries().await
    }

    /// List keys by status.
    pub async fn list_keys_by_status(&self, status: KeyStatus) -> KeyResult<Vec<KeyEntry>> {
        let all_keys = self.store.list_entries().await?;
        Ok(all_keys
            .into_iter()
            .filter(|k| k.status == status)
            .collect())
    }

    /// Rotate a key.
    pub async fn rotate_key(&self, key_id: &str) -> KeyResult<String> {
        let old_entry = self.store.get_entry(key_id).await?;

        // Generate new key with same algorithm
        let new_key_id = match old_entry.key_type {
            KeyType::Kem => {
                self.generate_kem_key(
                    old_entry.algorithm,
                    Some(KeyGenOptions {
                        metadata: old_entry.metadata.clone(),
                        rotation_policy: old_entry.rotation_policy.clone(),
                        ..Default::default()
                    }),
                )
                .await?
            }
            KeyType::Dsa => {
                self.generate_dsa_key(
                    old_entry.algorithm,
                    Some(KeyGenOptions {
                        metadata: old_entry.metadata.clone(),
                        rotation_policy: old_entry.rotation_policy.clone(),
                        ..Default::default()
                    }),
                )
                .await?
            }
            KeyType::Symmetric => {
                return Err(KeyError::InvalidConfig(
                    "Symmetric key rotation not yet implemented".into(),
                ));
            }
        };

        // Mark old key as rotating then disabled
        self.store
            .update_status(key_id, KeyStatus::Disabled)
            .await?;

        info!(old_key = %key_id, new_key = %new_key_id, "Rotated key");

        Ok(new_key_id)
    }

    /// Revoke a key.
    pub async fn revoke_key(&self, key_id: &str, reason: &str) -> KeyResult<()> {
        self.store.update_status(key_id, KeyStatus::Revoked).await?;
        warn!(key_id = %key_id, reason = %reason, "Key revoked");
        Ok(())
    }

    /// Delete a key.
    pub async fn delete_key(&self, key_id: &str) -> KeyResult<()> {
        // First mark as pending deletion
        self.store
            .update_status(key_id, KeyStatus::PendingDeletion)
            .await?;

        // Then actually delete
        self.store.delete(key_id).await?;

        info!(key_id = %key_id, "Key deleted");
        Ok(())
    }

    /// Check for expired keys and update their status.
    pub async fn check_expirations(&self) -> KeyResult<Vec<String>> {
        let all_keys = self.store.list_entries().await?;
        let now = chrono::Utc::now();
        let mut expired = Vec::new();

        for entry in all_keys {
            if entry.status == KeyStatus::Active {
                if let Some(expires_at) = entry.expires_at {
                    if now > expires_at {
                        self.store
                            .update_status(&entry.key_id, KeyStatus::Expired)
                            .await?;
                        expired.push(entry.key_id.clone());
                        warn!(key_id = %entry.key_id, "Key expired");
                    }
                }
            }
        }

        Ok(expired)
    }

    /// Get keys due for rotation.
    pub async fn get_keys_due_for_rotation(&self) -> KeyResult<Vec<KeyEntry>> {
        let all_keys = self.store.list_entries().await?;
        let now = chrono::Utc::now();

        Ok(all_keys
            .into_iter()
            .filter(|k| {
                if let Some(ref policy) = k.rotation_policy {
                    if policy.auto_rotate {
                        if let Some(next_rotation) = policy.next_rotation_at {
                            return now > next_rotation;
                        }
                    }
                }
                false
            })
            .collect())
    }
}

/// Builder for KeyManager.
#[derive(Default)]
pub struct KeyManagerBuilder {
    storage: Option<StorageBackend>,
    config: KeyManagerConfig,
    security_level: SecurityLevel,
}

impl KeyManagerBuilder {
    /// Set the storage backend.
    pub fn storage(mut self, backend: StorageBackend) -> Self {
        self.storage = Some(backend);
        self
    }

    /// Set the configuration.
    pub fn config(mut self, config: KeyManagerConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the security level.
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }

    /// Build the key manager.
    pub async fn build(self) -> KeyResult<KeyManager> {
        let storage = self
            .storage
            .ok_or_else(|| KeyError::InvalidConfig("Storage backend not configured".into()))?;

        let store = crate::storage::create_store(storage).await?;

        let core_config = CoreConfig::builder()
            .security_level(self.security_level)
            .build()
            .map_err(|e| KeyError::InvalidConfig(e.to_string()))?;

        Ok(KeyManager {
            store,
            config: self.config,
            core_config,
        })
    }
}

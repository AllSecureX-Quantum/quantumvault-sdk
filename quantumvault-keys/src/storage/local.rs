//! Local file-based key storage.

use crate::error::{KeyError, KeyResult};
use crate::storage::KeyStore;
use crate::{KeyEntry, KeyStatus};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use parking_lot::RwLock;
use quantumvault_core::KeyPair;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tracing::debug;

/// Local file-based storage for keys.
pub struct LocalStorage {
    path: PathBuf,
    encryption_key: Option<[u8; 32]>,
    index: RwLock<KeyIndex>,
}

/// In-memory storage for testing.
pub struct MemoryStorage {
    keys: RwLock<HashMap<String, StoredKey>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredKey {
    keypair: SerializableKeyPair,
    entry: KeyEntry,
}

#[derive(Clone, Serialize, Deserialize)]
struct SerializableKeyPair {
    key_id: String,
    algorithm: quantumvault_core::Algorithm,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    created_at: i64,
    expires_at: Option<i64>,
}

impl From<&KeyPair> for SerializableKeyPair {
    fn from(kp: &KeyPair) -> Self {
        Self {
            key_id: kp.key_id.clone(),
            algorithm: kp.algorithm,
            public_key: kp.public_key.bytes.clone(),
            secret_key: kp.secret_key.as_bytes().to_vec(),
            created_at: kp.created_at,
            expires_at: kp.expires_at,
        }
    }
}

impl From<SerializableKeyPair> for KeyPair {
    fn from(skp: SerializableKeyPair) -> Self {
        KeyPair {
            key_id: skp.key_id.clone(),
            public_key: quantumvault_core::PublicKey::new(
                skp.public_key,
                skp.algorithm,
                skp.key_id.clone(),
            ),
            secret_key: quantumvault_core::SecretKey::new(
                skp.secret_key,
                skp.algorithm,
                skp.key_id,
            ),
            algorithm: skp.algorithm,
            created_at: skp.created_at,
            expires_at: skp.expires_at,
            metadata: Default::default(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct KeyIndex {
    entries: HashMap<String, KeyEntry>,
}

impl LocalStorage {
    /// Create a new local storage.
    pub async fn new(path: PathBuf, encryption_key: Option<Vec<u8>>) -> KeyResult<Self> {
        // Create directory if it doesn't exist
        fs::create_dir_all(&path).await?;

        // Convert encryption key to fixed size array
        let key = encryption_key.map(|k| {
            let mut arr = [0u8; 32];
            let len = k.len().min(32);
            arr[..len].copy_from_slice(&k[..len]);
            arr
        });

        // Load existing index
        let index_path = path.join("index.json");
        let index = if index_path.exists() {
            let data = fs::read_to_string(&index_path).await?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            KeyIndex::default()
        };

        Ok(Self {
            path,
            encryption_key: key,
            index: RwLock::new(index),
        })
    }

    async fn save_index(&self) -> KeyResult<()> {
        let index_path = self.path.join("index.json");
        let data = {
            let index = self.index.read();
            serde_json::to_string_pretty(&*index)?
        };
        fs::write(index_path, data).await?;
        Ok(())
    }

    fn encrypt_data(&self, data: &[u8]) -> KeyResult<Vec<u8>> {
        match &self.encryption_key {
            Some(key) => {
                let cipher =
                    Aes256Gcm::new_from_slice(key).map_err(|e| KeyError::Crypto(e.to_string()))?;

                let mut nonce_bytes = [0u8; 12];
                getrandom::getrandom(&mut nonce_bytes)
                    .map_err(|e| KeyError::Crypto(e.to_string()))?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, data)
                    .map_err(|e| KeyError::Crypto(e.to_string()))?;

                // Prepend nonce to ciphertext
                let mut result = nonce_bytes.to_vec();
                result.extend(ciphertext);
                Ok(result)
            }
            None => Ok(data.to_vec()),
        }
    }

    fn decrypt_data(&self, data: &[u8]) -> KeyResult<Vec<u8>> {
        match &self.encryption_key {
            Some(key) => {
                if data.len() < 12 {
                    return Err(KeyError::Crypto("Invalid encrypted data".into()));
                }

                let cipher =
                    Aes256Gcm::new_from_slice(key).map_err(|e| KeyError::Crypto(e.to_string()))?;

                let nonce = Nonce::from_slice(&data[..12]);
                let ciphertext = &data[12..];

                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| KeyError::Crypto(e.to_string()))
            }
            None => Ok(data.to_vec()),
        }
    }

    fn key_file_path(&self, key_id: &str) -> PathBuf {
        self.path.join(format!("{}.key", key_id))
    }
}

#[async_trait]
impl KeyStore for LocalStorage {
    async fn store_keypair(&self, keypair: &KeyPair, entry: &KeyEntry) -> KeyResult<()> {
        let stored = StoredKey {
            keypair: keypair.into(),
            entry: entry.clone(),
        };

        // Serialize and encrypt
        let data = bincode::serialize(&stored)?;
        let encrypted = self.encrypt_data(&data)?;

        // Write to file
        let path = self.key_file_path(&keypair.key_id);
        fs::write(&path, encrypted).await?;

        // Update index
        {
            let mut index = self.index.write();
            index.entries.insert(keypair.key_id.clone(), entry.clone());
        }
        self.save_index().await?;

        debug!(key_id = %keypair.key_id, "Stored key");
        Ok(())
    }

    async fn get_keypair(&self, key_id: &str) -> KeyResult<KeyPair> {
        let path = self.key_file_path(key_id);
        if !path.exists() {
            return Err(KeyError::NotFound(key_id.to_string()));
        }

        let encrypted = fs::read(&path).await?;
        let data = self.decrypt_data(&encrypted)?;
        let stored: StoredKey = bincode::deserialize(&data)?;

        Ok(stored.keypair.into())
    }

    async fn get_entry(&self, key_id: &str) -> KeyResult<KeyEntry> {
        let index = self.index.read();
        index
            .entries
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyError::NotFound(key_id.to_string()))
    }

    async fn list_entries(&self) -> KeyResult<Vec<KeyEntry>> {
        let index = self.index.read();
        Ok(index.entries.values().cloned().collect())
    }

    async fn update_status(&self, key_id: &str, status: KeyStatus) -> KeyResult<()> {
        {
            let mut index = self.index.write();
            if let Some(entry) = index.entries.get_mut(key_id) {
                entry.status = status;
            } else {
                return Err(KeyError::NotFound(key_id.to_string()));
            }
        }
        self.save_index().await?;
        Ok(())
    }

    async fn update_last_used(&self, key_id: &str) -> KeyResult<()> {
        {
            let mut index = self.index.write();
            if let Some(entry) = index.entries.get_mut(key_id) {
                entry.last_used_at = Some(chrono::Utc::now());
                entry.usage_count += 1;
            } else {
                return Err(KeyError::NotFound(key_id.to_string()));
            }
        }
        self.save_index().await?;
        Ok(())
    }

    async fn delete(&self, key_id: &str) -> KeyResult<()> {
        let path = self.key_file_path(key_id);
        if path.exists() {
            fs::remove_file(&path).await?;
        }

        {
            let mut index = self.index.write();
            index.entries.remove(key_id);
        }
        self.save_index().await?;

        Ok(())
    }

    async fn exists(&self, key_id: &str) -> KeyResult<bool> {
        let index = self.index.read();
        Ok(index.entries.contains_key(key_id))
    }
}

impl MemoryStorage {
    /// Create a new in-memory storage.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl KeyStore for MemoryStorage {
    async fn store_keypair(&self, keypair: &KeyPair, entry: &KeyEntry) -> KeyResult<()> {
        let stored = StoredKey {
            keypair: keypair.into(),
            entry: entry.clone(),
        };
        self.keys.write().insert(keypair.key_id.clone(), stored);
        Ok(())
    }

    async fn get_keypair(&self, key_id: &str) -> KeyResult<KeyPair> {
        self.keys
            .read()
            .get(key_id)
            .map(|s| s.keypair.clone().into())
            .ok_or_else(|| KeyError::NotFound(key_id.to_string()))
    }

    async fn get_entry(&self, key_id: &str) -> KeyResult<KeyEntry> {
        self.keys
            .read()
            .get(key_id)
            .map(|s| s.entry.clone())
            .ok_or_else(|| KeyError::NotFound(key_id.to_string()))
    }

    async fn list_entries(&self) -> KeyResult<Vec<KeyEntry>> {
        Ok(self.keys.read().values().map(|s| s.entry.clone()).collect())
    }

    async fn update_status(&self, key_id: &str, status: KeyStatus) -> KeyResult<()> {
        if let Some(stored) = self.keys.write().get_mut(key_id) {
            stored.entry.status = status;
            Ok(())
        } else {
            Err(KeyError::NotFound(key_id.to_string()))
        }
    }

    async fn update_last_used(&self, key_id: &str) -> KeyResult<()> {
        if let Some(stored) = self.keys.write().get_mut(key_id) {
            stored.entry.last_used_at = Some(chrono::Utc::now());
            stored.entry.usage_count += 1;
            Ok(())
        } else {
            Err(KeyError::NotFound(key_id.to_string()))
        }
    }

    async fn delete(&self, key_id: &str) -> KeyResult<()> {
        self.keys.write().remove(key_id);
        Ok(())
    }

    async fn exists(&self, key_id: &str) -> KeyResult<bool> {
        Ok(self.keys.read().contains_key(key_id))
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

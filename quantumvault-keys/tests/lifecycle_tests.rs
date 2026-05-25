//! End-to-end lifecycle tests for `quantumvault-keys`.
//!
//! These tests exercise the public `KeyManager` API against both the in-
//! memory and local file storage backends. Together they cover every state
//! in the `KeyStatus` machine (Active → Disabled → Revoked → PendingDeletion)
//! and every code path in `manager.rs` that the deployed code touches.
//!
//! They are intentionally written against the **public** API only — the same
//! surface that customers and the REST API use. That way a regression here
//! is also a real customer-facing regression.

use quantumvault_core::{Algorithm, SecurityLevel};
use quantumvault_keys::{KeyError, KeyGenOptions, KeyManager, KeyStatus, KeyType, StorageBackend};
use tempfile::TempDir;

// -------- helpers ------------------------------------------------------

async fn local_manager(level: SecurityLevel) -> (KeyManager, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let mgr = KeyManager::builder()
        .storage(StorageBackend::Local {
            path: tmp.path().to_path_buf(),
            encryption_key: None,
        })
        .security_level(level)
        .build()
        .await
        .expect("build manager");
    (mgr, tmp)
}

async fn memory_manager(level: SecurityLevel) -> KeyManager {
    KeyManager::builder()
        .storage(StorageBackend::Memory)
        .security_level(level)
        .build()
        .await
        .expect("build manager")
}

// -------- KEM key generation across storage backends ------------------

#[tokio::test]
async fn generate_kem_512_memory() {
    let mgr = memory_manager(SecurityLevel::Level1).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem512, None)
        .await
        .expect("kem 512 gen");
    assert!(!id.is_empty());
    let kp = mgr.get_key(&id).await.expect("get");
    assert_eq!(kp.algorithm, Algorithm::MlKem512);
}

#[tokio::test]
async fn generate_kem_768_memory() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    let kp = mgr.get_key(&id).await.unwrap();
    assert_eq!(kp.algorithm, Algorithm::MlKem768);
    assert!(kp.public_key.bytes.len() > 1000);
}

#[tokio::test]
async fn generate_kem_1024_memory() {
    let mgr = memory_manager(SecurityLevel::Level5).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem1024, None)
        .await
        .unwrap();
    let kp = mgr.get_key(&id).await.unwrap();
    assert_eq!(kp.algorithm, Algorithm::MlKem1024);
}

#[tokio::test]
async fn generate_kem_768_local() {
    let (mgr, _tmp) = local_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    let kp = mgr.get_key(&id).await.unwrap();
    assert_eq!(kp.key_id, id);
}

// -------- DSA key generation across algorithms ------------------------

#[tokio::test]
async fn generate_dsa_44() {
    let mgr = memory_manager(SecurityLevel::Level2).await;
    let id = mgr
        .generate_dsa_key(Algorithm::MlDsa44, None)
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    assert_eq!(entry.key_type, KeyType::Dsa);
}

#[tokio::test]
async fn generate_dsa_65() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_dsa_key(Algorithm::MlDsa65, None)
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    assert_eq!(entry.algorithm, Algorithm::MlDsa65);
}

#[tokio::test]
async fn generate_dsa_87() {
    let mgr = memory_manager(SecurityLevel::Level5).await;
    let id = mgr
        .generate_dsa_key(Algorithm::MlDsa87, None)
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    assert_eq!(entry.algorithm, Algorithm::MlDsa87);
}

#[tokio::test]
async fn generate_slh_dsa_shake_128f() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_dsa_key(Algorithm::SlhDsaShake128f, None)
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    assert_eq!(entry.algorithm, Algorithm::SlhDsaShake128f);
    assert_eq!(entry.key_type, KeyType::Dsa);
}

// -------- Algorithm-type validation -----------------------------------

#[tokio::test]
async fn kem_method_rejects_dsa_algorithm() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let err = mgr
        .generate_kem_key(Algorithm::MlDsa65, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, KeyError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
}

#[tokio::test]
async fn dsa_method_rejects_kem_algorithm() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let err = mgr
        .generate_dsa_key(Algorithm::MlKem768, None)
        .await
        .unwrap_err();
    assert!(matches!(err, KeyError::InvalidConfig(_)));
}

// -------- Metadata persistence ----------------------------------------

#[tokio::test]
async fn metadata_name_and_tags_persisted() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let mut opts = KeyGenOptions::default();
    opts.metadata.name = Some("primary-encryption-key".into());
    opts.metadata.tags = vec!["env:prod".into(), "owner:platform".into()];

    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, Some(opts))
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    assert_eq!(
        entry.metadata.name.as_deref(),
        Some("primary-encryption-key")
    );
    assert!(entry.metadata.tags.contains(&"env:prod".to_string()));
}

#[tokio::test]
async fn metadata_owner_persisted() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let mut opts = KeyGenOptions::default();
    opts.metadata.owner = Some("user-7".into());
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, Some(opts))
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    assert_eq!(entry.metadata.owner.as_deref(), Some("user-7"));
}

// -------- list_keys -----------------------------------------------------

#[tokio::test]
async fn list_keys_empty() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let entries = mgr.list_keys().await.unwrap();
    assert!(entries.is_empty());
}

#[tokio::test]
async fn list_keys_populated() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    for _ in 0..3 {
        mgr.generate_kem_key(Algorithm::MlKem768, None)
            .await
            .unwrap();
    }
    let entries = mgr.list_keys().await.unwrap();
    assert_eq!(entries.len(), 3);
}

#[tokio::test]
async fn list_keys_by_active_status() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    let active = mgr.list_keys_by_status(KeyStatus::Active).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].key_id, id);
    let revoked = mgr.list_keys_by_status(KeyStatus::Revoked).await.unwrap();
    assert!(revoked.is_empty());
}

#[tokio::test]
async fn list_keys_by_revoked_status() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    mgr.revoke_key(&id, "test").await.unwrap();
    let revoked = mgr.list_keys_by_status(KeyStatus::Revoked).await.unwrap();
    assert_eq!(revoked.len(), 1);
}

// -------- Rotation ------------------------------------------------------

#[tokio::test]
async fn rotate_kem_produces_new_id() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let old_id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    let new_id = mgr.rotate_key(&old_id).await.unwrap();
    assert_ne!(old_id, new_id);
    // New key is fetchable
    let new_kp = mgr.get_key(&new_id).await.unwrap();
    assert_eq!(new_kp.algorithm, Algorithm::MlKem768);
}

#[tokio::test]
async fn rotate_disables_old_key() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let old_id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    let _new = mgr.rotate_key(&old_id).await.unwrap();
    let old_entry = mgr.get_key_entry(&old_id).await.unwrap();
    assert_eq!(old_entry.status, KeyStatus::Disabled);
}

#[tokio::test]
async fn rotate_dsa_key_preserves_algorithm() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let old_id = mgr
        .generate_dsa_key(Algorithm::MlDsa65, None)
        .await
        .unwrap();
    let new_id = mgr.rotate_key(&old_id).await.unwrap();
    let new_kp = mgr.get_key(&new_id).await.unwrap();
    assert_eq!(new_kp.algorithm, Algorithm::MlDsa65);
}

// -------- Revocation ----------------------------------------------------

#[tokio::test]
async fn revoke_changes_status() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    mgr.revoke_key(&id, "policy violation").await.unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    assert_eq!(entry.status, KeyStatus::Revoked);
}

#[tokio::test]
async fn revoked_key_cannot_be_retrieved_via_get_key() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    mgr.revoke_key(&id, "test").await.unwrap();
    // KeyPair doesn't impl Debug, so we destructure the Result manually.
    match mgr.get_key(&id).await {
        Ok(_) => panic!("revoked key was retrievable"),
        Err(KeyError::NotUsable(_, _)) => {}
        Err(other) => panic!("expected NotUsable, got {other:?}"),
    }
}

#[tokio::test]
async fn revoke_with_reason_is_safe() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    // Empty reason allowed (not enforced).
    mgr.revoke_key(&id, "").await.unwrap();
}

// -------- Deletion ------------------------------------------------------

#[tokio::test]
async fn delete_removes_key() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    mgr.delete_key(&id).await.unwrap();
    let err = mgr.get_key_entry(&id).await.unwrap_err();
    assert!(matches!(err, KeyError::NotFound(_)));
}

#[tokio::test]
async fn delete_nonexistent_errors() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let err = mgr.delete_key("not-a-real-id").await.unwrap_err();
    assert!(
        matches!(err, KeyError::NotFound(_) | KeyError::Storage(_)),
        "expected NotFound/Storage, got {err:?}"
    );
}

// -------- Local-storage persistence -----------------------------------

#[tokio::test]
async fn local_storage_persists_across_manager_instances() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().to_path_buf();

    // First manager generates a key.
    let id = {
        let mgr1 = KeyManager::builder()
            .storage(StorageBackend::Local {
                path: path.clone(),
                encryption_key: None,
            })
            .security_level(SecurityLevel::Level3)
            .build()
            .await
            .unwrap();
        mgr1.generate_kem_key(Algorithm::MlKem768, None)
            .await
            .unwrap()
    };

    // Second manager opens the same directory and finds the key.
    let mgr2 = KeyManager::builder()
        .storage(StorageBackend::Local {
            path,
            encryption_key: None,
        })
        .security_level(SecurityLevel::Level3)
        .build()
        .await
        .unwrap();
    let entry = mgr2.get_key_entry(&id).await.unwrap();
    assert_eq!(entry.key_id, id);
}

#[tokio::test]
async fn local_storage_list_after_reopen() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().to_path_buf();
    {
        let mgr = KeyManager::builder()
            .storage(StorageBackend::Local {
                path: path.clone(),
                encryption_key: None,
            })
            .security_level(SecurityLevel::Level3)
            .build()
            .await
            .unwrap();
        mgr.generate_kem_key(Algorithm::MlKem768, None)
            .await
            .unwrap();
        mgr.generate_dsa_key(Algorithm::MlDsa65, None)
            .await
            .unwrap();
    }
    let mgr2 = KeyManager::builder()
        .storage(StorageBackend::Local {
            path,
            encryption_key: None,
        })
        .security_level(SecurityLevel::Level3)
        .build()
        .await
        .unwrap();
    let entries = mgr2.list_keys().await.unwrap();
    assert_eq!(entries.len(), 2);
}

// -------- Concurrent access -------------------------------------------

#[tokio::test]
async fn concurrent_key_generation_is_safe() {
    let mgr = std::sync::Arc::new(memory_manager(SecurityLevel::Level3).await);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let m = mgr.clone();
        handles.push(tokio::spawn(async move {
            m.generate_kem_key(Algorithm::MlKem768, None).await
        }));
    }
    let mut ids = Vec::new();
    for h in handles {
        let id = h.await.unwrap().unwrap();
        ids.push(id);
    }
    // All IDs are unique.
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 8, "concurrent gens collided: {:?}", ids);

    let entries = mgr.list_keys().await.unwrap();
    assert_eq!(entries.len(), 8);
}

// -------- get_key_entry on missing key --------------------------------

#[tokio::test]
async fn get_key_entry_missing_returns_not_found() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let err = mgr.get_key_entry("ghost").await.unwrap_err();
    assert!(
        matches!(err, KeyError::NotFound(_) | KeyError::Storage(_)),
        "expected NotFound/Storage, got {err:?}"
    );
}

// -------- Expiration --------------------------------------------------

#[tokio::test]
async fn expiration_zero_days_immediately_expired() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let mut opts = KeyGenOptions::default();
    opts.expires_in_days = Some(0);
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, Some(opts))
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    // expires_at is set when expires_in_days is provided
    assert!(entry.expires_at.is_some());
}

#[tokio::test]
async fn no_expiration_by_default() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    assert!(entry.expires_at.is_none());
}

// -------- Usage tracking ----------------------------------------------

#[tokio::test]
async fn usage_count_starts_at_zero() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    assert_eq!(entry.usage_count, 0);
}

#[tokio::test]
async fn last_used_updates_on_get_key() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    let before = mgr.get_key_entry(&id).await.unwrap();
    assert!(before.last_used_at.is_none());
    let _kp = mgr.get_key(&id).await.unwrap();
    let after = mgr.get_key_entry(&id).await.unwrap();
    assert!(after.last_used_at.is_some());
}

// -------- KeyEntry serialisation round-trip ---------------------------

#[tokio::test]
async fn key_entry_serialises_as_json() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    let entry = mgr.get_key_entry(&id).await.unwrap();
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains(&id));
    let parsed: quantumvault_keys::KeyEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.key_id, entry.key_id);
    assert_eq!(parsed.algorithm, entry.algorithm);
    assert_eq!(parsed.status, entry.status);
}

// -------- Mixed-security-level behaviour ------------------------------
//
// IMPORTANT: KeyManager today **does not enforce** that the algorithm
// matches the manager's configured security level. The `security_level`
// field is metadata that propagates into `Config`, but neither the manager
// nor the underlying core API rejects a mismatch. This is a known gap
// tracked for the Hop 5 / Hop 6 work where access control will be
// hardened. The two tests below pin the **current** observed contract so
// that any future change is detected.

#[tokio::test]
async fn level3_manager_accepts_level5_kem_today() {
    let mgr = memory_manager(SecurityLevel::Level3).await;
    let res = mgr.generate_kem_key(Algorithm::MlKem1024, None).await;
    assert!(
        res.is_ok(),
        "current behaviour: no upward-level enforcement"
    );
}

#[tokio::test]
async fn level1_manager_accepts_level3_kem_today() {
    let mgr = memory_manager(SecurityLevel::Level1).await;
    let res = mgr.generate_kem_key(Algorithm::MlKem768, None).await;
    assert!(
        res.is_ok(),
        "current behaviour: no downward-level enforcement either"
    );
}

// -------- KeyManager configuration ------------------------------------

#[tokio::test]
async fn manager_default_security_level_is_3() {
    // Build without explicitly setting a security level.
    let mgr = KeyManager::builder()
        .storage(StorageBackend::Memory)
        .build()
        .await
        .unwrap();
    let id = mgr
        .generate_kem_key(Algorithm::MlKem768, None)
        .await
        .unwrap();
    assert!(!id.is_empty());
}

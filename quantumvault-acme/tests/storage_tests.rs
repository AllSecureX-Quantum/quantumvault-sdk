//! Tests for the Store trait + both backends.

use chrono::Utc;
use quantumvault_acme::{Account, InMemoryStore, OrderResource, OrderStatus, SqliteStore, Store};

fn sample_account(id: &str) -> Account {
    Account {
        id: id.to_string(),
        algorithm: "ML-DSA-65".to_string(),
        verifying_key: "abc==".to_string(),
        key_id: "vk-1".to_string(),
        created_at: Utc::now(),
        contact: Some("ops@example.com".to_string()),
    }
}

fn sample_order(id: &str, account_id: &str) -> OrderResource {
    OrderResource {
        id: id.to_string(),
        account_id: account_id.to_string(),
        subject_cn: "api.example.com".into(),
        sans: vec!["DNS:api.example.com".into()],
        validity_days: 90,
        status: OrderStatus::Pending,
        created_at: Utc::now(),
        issued_at: None,
        certificate: None,
    }
}

// -------- InMemoryStore -----------------------------------------------

#[tokio::test]
async fn memory_account_round_trip() {
    let store = InMemoryStore::new();
    let acc = sample_account("a-1");
    store.put_account(&acc).await.unwrap();
    let loaded = store.get_account("a-1").await.unwrap().unwrap();
    assert_eq!(loaded.id, "a-1");
    assert_eq!(loaded.key_id, "vk-1");
}

#[tokio::test]
async fn memory_returns_none_for_missing() {
    let store = InMemoryStore::new();
    assert!(store.get_account("nope").await.unwrap().is_none());
    assert!(store.get_order("nope").await.unwrap().is_none());
}

#[tokio::test]
async fn memory_order_with_certificate_round_trips() {
    let store = InMemoryStore::new();
    let mut order = sample_order("o-1", "a-1");
    order.status = OrderStatus::Issued;
    order.issued_at = Some(Utc::now());
    order.certificate = Some(serde_json::json!({"tbs": "...", "signature": "..."}));
    store.put_order(&order).await.unwrap();
    let loaded = store.get_order("o-1").await.unwrap().unwrap();
    assert_eq!(loaded.status, OrderStatus::Issued);
    assert!(loaded.certificate.is_some());
}

#[test]
fn memory_backend_label() {
    let store = InMemoryStore::new();
    assert_eq!(store.backend(), "memory");
}

// -------- SqliteStore -------------------------------------------------

#[tokio::test]
async fn sqlite_account_round_trip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SqliteStore::open(&tmp.path().join("acme.db")).unwrap();
    let acc = sample_account("a-1");
    store.put_account(&acc).await.unwrap();
    let loaded = store.get_account("a-1").await.unwrap().unwrap();
    assert_eq!(loaded.id, acc.id);
    assert_eq!(loaded.algorithm, acc.algorithm);
    assert_eq!(loaded.verifying_key, acc.verifying_key);
    assert_eq!(loaded.key_id, acc.key_id);
    assert_eq!(loaded.contact, acc.contact);
}

#[tokio::test]
async fn sqlite_order_round_trip_pending() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SqliteStore::open(&tmp.path().join("acme.db")).unwrap();
    // Orders carry a FOREIGN KEY → accounts(id); create the parent first.
    store.put_account(&sample_account("a-1")).await.unwrap();
    let order = sample_order("o-1", "a-1");
    store.put_order(&order).await.unwrap();
    let loaded = store.get_order("o-1").await.unwrap().unwrap();
    assert_eq!(loaded.status, OrderStatus::Pending);
    assert_eq!(loaded.subject_cn, "api.example.com");
    assert_eq!(loaded.sans, vec!["DNS:api.example.com".to_string()]);
}

#[tokio::test]
async fn sqlite_order_round_trip_issued_with_certificate() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SqliteStore::open(&tmp.path().join("acme.db")).unwrap();
    store.put_account(&sample_account("a-1")).await.unwrap();
    let mut order = sample_order("o-2", "a-1");
    order.status = OrderStatus::Issued;
    order.issued_at = Some(Utc::now());
    order.certificate = Some(serde_json::json!({
        "tbs": {"serial": "abc", "subject": {"cn": "api.example.com"}},
        "signature": {"algorithm": "ML-DSA-65", "bytes": "..."}
    }));
    store.put_order(&order).await.unwrap();
    let loaded = store.get_order("o-2").await.unwrap().unwrap();
    assert_eq!(loaded.status, OrderStatus::Issued);
    assert!(loaded.issued_at.is_some());
    assert!(loaded.certificate.is_some());
    assert_eq!(
        loaded.certificate.unwrap()["tbs"]["serial"],
        serde_json::json!("abc")
    );
}

#[tokio::test]
async fn sqlite_order_without_account_violates_foreign_key() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SqliteStore::open(&tmp.path().join("acme.db")).unwrap();
    // No account created — order insert MUST fail because of the FK.
    let order = sample_order("orphan", "missing-account");
    let result = store.put_order(&order).await;
    assert!(result.is_err(), "FK violation must error");
}

#[tokio::test]
async fn sqlite_state_survives_reopen() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("acme.db");

    // First open: write data.
    {
        let store = SqliteStore::open(&path).unwrap();
        store
            .put_account(&sample_account("persist-1"))
            .await
            .unwrap();
        store
            .put_order(&sample_order("persist-order-1", "persist-1"))
            .await
            .unwrap();
        // store dropped here.
    }
    // Second open against the same file: data must still be there.
    let store = SqliteStore::open(&path).unwrap();
    let acc = store.get_account("persist-1").await.unwrap();
    assert!(acc.is_some(), "account did not survive reopen");
    let order = store.get_order("persist-order-1").await.unwrap();
    assert!(order.is_some(), "order did not survive reopen");
}

#[tokio::test]
async fn sqlite_missing_returns_none() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SqliteStore::open(&tmp.path().join("acme.db")).unwrap();
    assert!(store.get_account("nope").await.unwrap().is_none());
    assert!(store.get_order("nope").await.unwrap().is_none());
}

#[tokio::test]
async fn sqlite_put_is_idempotent_replace() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SqliteStore::open(&tmp.path().join("acme.db")).unwrap();
    let mut acc = sample_account("a-1");
    store.put_account(&acc).await.unwrap();
    // Mutate and put again.
    acc.contact = Some("new@example.com".to_string());
    store.put_account(&acc).await.unwrap();
    let loaded = store.get_account("a-1").await.unwrap().unwrap();
    assert_eq!(loaded.contact.as_deref(), Some("new@example.com"));
}

#[test]
fn sqlite_backend_label() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SqliteStore::open(&tmp.path().join("acme.db")).unwrap();
    assert_eq!(store.backend(), "sqlite");
}

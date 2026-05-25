//! Account + order persistence.
//!
//! Two backends:
//! - [`InMemoryStore`] — single-process, lost on restart. Good for tests
//!   and ephemeral deployments.
//! - [`SqliteStore`] — single-file SQLite database. Survives restart.
//!   Open with [`SqliteStore::open`] and pass the resulting `Arc<dyn Store>`
//!   into the server.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use crate::error::{AcmeError, Result};
use crate::proto::{Account, OrderResource, OrderStatus};

/// Persistence trait for accounts + orders.
///
/// All methods are async to keep the call site uniform across the
/// (async) HTTP handler and the (sync, internally locked) backends.
#[async_trait::async_trait]
pub trait Store: Send + Sync {
    /// Insert a new account. Returns an error if the id already exists.
    async fn put_account(&self, account: &Account) -> Result<()>;
    /// Fetch an account by id, or `None`.
    async fn get_account(&self, id: &str) -> Result<Option<Account>>;

    /// Insert or replace an order.
    async fn put_order(&self, order: &OrderResource) -> Result<()>;
    /// Fetch an order by id, or `None`.
    async fn get_order(&self, id: &str) -> Result<Option<OrderResource>>;

    /// Human-readable backend label for logs.
    fn backend(&self) -> &'static str;
}

// =====================================================================
// In-memory backend
// =====================================================================

/// In-memory store. State is lost on process restart.
#[derive(Default)]
pub struct InMemoryStore {
    accounts: Mutex<HashMap<String, Account>>,
    orders: Mutex<HashMap<String, OrderResource>>,
}

impl InMemoryStore {
    /// Construct a new, empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl Store for InMemoryStore {
    async fn put_account(&self, account: &Account) -> Result<()> {
        self.accounts
            .lock()
            .await
            .insert(account.id.clone(), account.clone());
        Ok(())
    }
    async fn get_account(&self, id: &str) -> Result<Option<Account>> {
        Ok(self.accounts.lock().await.get(id).cloned())
    }
    async fn put_order(&self, order: &OrderResource) -> Result<()> {
        self.orders
            .lock()
            .await
            .insert(order.id.clone(), order.clone());
        Ok(())
    }
    async fn get_order(&self, id: &str) -> Result<Option<OrderResource>> {
        Ok(self.orders.lock().await.get(id).cloned())
    }
    fn backend(&self) -> &'static str {
        "memory"
    }
}

// =====================================================================
// SQLite backend
// =====================================================================

/// SQLite-backed persistent store. Schema is created idempotently on
/// open via `CREATE TABLE IF NOT EXISTS`.
pub struct SqliteStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SqliteStore {
    /// Open (or create) a SQLite database at `path`.
    pub fn open(path: &Path) -> Result<Arc<Self>> {
        let conn = rusqlite::Connection::open(path).map_err(sqlite_err)?;
        conn.execute_batch(SCHEMA).map_err(sqlite_err)?;
        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
        }))
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    id            TEXT PRIMARY KEY,
    algorithm     TEXT NOT NULL,
    verifying_key TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    contact       TEXT
);
CREATE TABLE IF NOT EXISTS orders (
    id               TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL,
    subject_cn       TEXT NOT NULL,
    sans_json        TEXT NOT NULL,
    validity_days    INTEGER NOT NULL,
    status           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    issued_at        TEXT,
    certificate_json TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);
"#;

fn sqlite_err(e: rusqlite::Error) -> AcmeError {
    AcmeError::IssuanceFailed(format!("sqlite: {e}"))
}

fn parse_dt(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| AcmeError::MalformedRequest(format!("bad RFC 3339 timestamp {s:?}: {e}")))
}

fn status_str(s: OrderStatus) -> &'static str {
    match s {
        OrderStatus::Pending => "pending",
        OrderStatus::Ready => "ready",
        OrderStatus::Issued => "issued",
        OrderStatus::Invalid => "invalid",
    }
}

fn parse_status(s: &str) -> Result<OrderStatus> {
    Ok(match s {
        "pending" => OrderStatus::Pending,
        "ready" => OrderStatus::Ready,
        "issued" => OrderStatus::Issued,
        "invalid" => OrderStatus::Invalid,
        other => {
            return Err(AcmeError::MalformedRequest(format!(
                "unknown order status: {other:?}"
            )))
        }
    })
}

#[async_trait::async_trait]
impl Store for SqliteStore {
    async fn put_account(&self, account: &Account) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO accounts \
             (id, algorithm, verifying_key, key_id, created_at, contact) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                account.id,
                account.algorithm,
                account.verifying_key,
                account.key_id,
                account.created_at.to_rfc3339(),
                account.contact,
            ],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    async fn get_account(&self, id: &str) -> Result<Option<Account>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT id, algorithm, verifying_key, key_id, created_at, contact \
                 FROM accounts WHERE id = ?1",
            )
            .map_err(sqlite_err)?;
        let result = stmt
            .query_row(rusqlite::params![id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .ok();
        match result {
            None => Ok(None),
            Some((id, algorithm, verifying_key, key_id, created_at, contact)) => {
                Ok(Some(Account {
                    id,
                    algorithm,
                    verifying_key,
                    key_id,
                    created_at: parse_dt(&created_at)?,
                    contact,
                }))
            }
        }
    }

    async fn put_order(&self, order: &OrderResource) -> Result<()> {
        let conn = self.conn.lock().await;
        let sans_json = serde_json::to_string(&order.sans)?;
        let cert_json = match &order.certificate {
            Some(v) => Some(serde_json::to_string(v)?),
            None => None,
        };
        conn.execute(
            "INSERT OR REPLACE INTO orders \
             (id, account_id, subject_cn, sans_json, validity_days, status, \
              created_at, issued_at, certificate_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                order.id,
                order.account_id,
                order.subject_cn,
                sans_json,
                order.validity_days,
                status_str(order.status),
                order.created_at.to_rfc3339(),
                order.issued_at.map(|d| d.to_rfc3339()),
                cert_json,
            ],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    async fn get_order(&self, id: &str) -> Result<Option<OrderResource>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT id, account_id, subject_cn, sans_json, validity_days, \
                        status, created_at, issued_at, certificate_json \
                 FROM orders WHERE id = ?1",
            )
            .map_err(sqlite_err)?;
        let row = stmt
            .query_row(rusqlite::params![id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                ))
            })
            .ok();
        match row {
            None => Ok(None),
            Some((
                id,
                account_id,
                subject_cn,
                sans_json,
                validity_days,
                status,
                created_at,
                issued_at,
                certificate_json,
            )) => {
                let sans: Vec<String> = serde_json::from_str(&sans_json)?;
                let certificate = match certificate_json {
                    Some(s) => Some(serde_json::from_str::<serde_json::Value>(&s)?),
                    None => None,
                };
                Ok(Some(OrderResource {
                    id,
                    account_id,
                    subject_cn,
                    sans,
                    validity_days,
                    status: parse_status(&status)?,
                    created_at: parse_dt(&created_at)?,
                    issued_at: match issued_at {
                        Some(s) => Some(parse_dt(&s)?),
                        None => None,
                    },
                    certificate,
                }))
            }
        }
    }

    fn backend(&self) -> &'static str {
        "sqlite"
    }
}

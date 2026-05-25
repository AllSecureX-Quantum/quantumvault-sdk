//! Protocol types — request/response bodies for the ACME-PQC wire.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current protocol version. Bump on breaking changes.
pub const PROTOCOL_VERSION: u8 = 1;

/// Server-side account record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    /// Account identifier (UUID).
    pub id: String,
    /// Algorithm wire name ("ML-DSA-65").
    pub algorithm: String,
    /// Base64-encoded verifying-key bytes.
    pub verifying_key: String,
    /// Verifying-key identifier.
    pub key_id: String,
    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Optional contact (email, etc.) — informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
}

/// Status of an issuance order through its lifecycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    /// Order accepted; awaiting validation.
    Pending,
    /// Validation passed; cert is being issued.
    Ready,
    /// Cert has been issued and is downloadable.
    Issued,
    /// Order has been rejected or has failed.
    Invalid,
}

/// Server-side order record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderResource {
    /// Order identifier (UUID).
    pub id: String,
    /// Account that owns this order.
    pub account_id: String,
    /// Subject CN being requested.
    pub subject_cn: String,
    /// Subject Alternative Names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
    /// Requested validity, in days.
    pub validity_days: i64,
    /// Order lifecycle state.
    pub status: OrderStatus,
    /// Order creation timestamp.
    pub created_at: DateTime<Utc>,
    /// When the cert was issued (set on `Issued`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    /// Issued certificate (set on `Issued`) — serialised as the JSON
    /// form produced by `quantumvault-ca`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<serde_json::Value>,
}

/// Body of `POST /v1/accounts`. Signed by the account's own key (the
/// only signature where the server doesn't yet know the verifying key —
/// it learns it from this very request, so this is a self-attest).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterAccountRequest {
    /// Protocol version (must equal [`PROTOCOL_VERSION`]).
    pub version: u8,
    /// Algorithm wire name.
    pub algorithm: String,
    /// Base64 verifying-key bytes.
    pub verifying_key: String,
    /// Verifying-key identifier (the client picks; server validates).
    pub key_id: String,
    /// Optional contact info (email).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
}

/// Body of `POST /v1/orders`. Signed by an already-registered account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssueOrderRequest {
    /// Protocol version.
    pub version: u8,
    /// Existing account id.
    pub account_id: String,
    /// Subject CN to be put on the cert.
    pub subject_cn: String,
    /// Subject Alternative Names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
    /// Subject's verifying-key (the key the cert binds to) — base64.
    pub subject_verifying_key: String,
    /// Subject's verifying-key identifier.
    pub subject_key_id: String,
    /// Requested validity, in days.
    pub validity_days: i64,
    /// Nonce — client picks a fresh UUID per order to make replay
    /// of a captured `SignedRequest` useless.
    pub nonce: String,
}

/// Envelope around any signed protocol request.
///
/// `payload` is the canonical JSON of the inner request (e.g.
/// `IssueOrderRequest`); `signature` is an ML-DSA signature over the
/// raw payload bytes by the account key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRequest {
    /// JSON-encoded inner request.
    pub payload: serde_json::Value,
    /// Algorithm wire name (must match the account's algorithm).
    pub algorithm: String,
    /// Verifying-key id (matches what the server has for the account,
    /// EXCEPT for `RegisterAccountRequest` where the server learns the
    /// key from the payload itself).
    pub verifying_key_id: String,
    /// Base64 ML-DSA signature over the canonical bytes of `payload`.
    pub signature: String,
}

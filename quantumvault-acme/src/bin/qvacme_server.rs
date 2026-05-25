//! `qvacme-server` — ACME-PQC HTTP server.
//!
//! Accepts ML-DSA-signed protocol requests, validates them, issues
//! certificates from a configured `quantumvault-ca` parent CA, and
//! serves the result back. State persists to SQLite when `--db` is
//! supplied; otherwise the server uses an in-memory store (good for
//! tests and ephemeral deployments).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use clap::Parser;
use quantumvault_ca::{
    CaSigningKey, CaVerifyingKey, Certificate, CertificateBuilder, DistinguishedName, KeyUsage,
};
use quantumvault_core::{Algorithm, VerifyingKey};
use serde::Serialize;
use tracing::{info, warn};
use uuid::Uuid;

use quantumvault_acme::{
    verify_request, AcmeError, InMemoryStore, IssueOrderRequest, OrderResource, OrderStatus,
    RegisterAccountRequest, SignedRequest, SqliteStore, Store, PROTOCOL_VERSION,
};

#[derive(Parser, Debug)]
#[command(
    name = "qvacme-server",
    about = "ACME-PQC server — auto-issue ML-DSA certificates from a quantumvault-ca parent"
)]
struct Cli {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// Path to the parent-CA directory (must contain
    /// `*.signing.json` + `*.cert.json` from `qvca init-root` or
    /// `qvca issue-intermediate`).
    #[arg(long)]
    parent: PathBuf,
    /// Auto-approve every order (otherwise orders sit at `pending`
    /// until an external trigger). Use only on trusted networks.
    #[arg(long)]
    auto_approve: bool,
    /// Path to a SQLite database file for persistent storage.
    /// If absent, the server uses an in-memory store that's wiped on
    /// restart.
    #[arg(long)]
    db: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    store: Arc<dyn Store>,
    parent_signing_key: Arc<CaSigningKey>,
    parent_cert: Arc<Certificate>,
    auto_approve: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    let (sk_path, cert_path) = find_parent_files(&cli.parent)?;
    let parent_signing_key =
        CaSigningKey::load_from_file(&sk_path, None).context("load parent signing key")?;
    let parent_cert = Certificate::load_from_file(&cert_path).context("load parent cert")?;
    if !parent_cert.tbs.is_ca {
        anyhow::bail!("parent cert is not a CA — qvacme-server requires a CA parent");
    }

    let store: Arc<dyn Store> = match &cli.db {
        Some(path) => SqliteStore::open(path).context("open sqlite store")?,
        None => Arc::new(InMemoryStore::new()),
    };

    let state = AppState {
        store: store.clone(),
        parent_signing_key: Arc::new(parent_signing_key),
        parent_cert: Arc::new(parent_cert),
        auto_approve: cli.auto_approve,
    };

    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/accounts", post(register_account))
        .route("/v1/orders", post(submit_order))
        .route("/v1/orders/:id", get(get_order))
        .route("/v1/orders/:id/certificate", get(get_certificate))
        .with_state(state);

    info!(
        listen = %cli.listen,
        parent = ?cli.parent,
        auto_approve = cli.auto_approve,
        store = store.backend(),
        db = ?cli.db,
        "qvacme-server starting"
    );

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// =====================================================================
// Handlers
// =====================================================================

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: String,
}

fn err(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> axum::response::Response {
    (
        status,
        Json(ErrorBody {
            error: code,
            message: message.into(),
        }),
    )
        .into_response()
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "protocol_version": PROTOCOL_VERSION,
        "service": "qvacme-server",
    }))
}

async fn register_account(
    State(st): State<AppState>,
    Json(signed): Json<SignedRequest>,
) -> axum::response::Response {
    // For register, the verifying key is inside the payload (the
    // applicant brings it). We extract it, verify the signature, then
    // record the account.
    let payload: RegisterAccountRequest = match serde_json::from_value(signed.payload.clone()) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, "malformed", e.to_string()),
    };
    if payload.version != PROTOCOL_VERSION {
        return err(
            StatusCode::BAD_REQUEST,
            "version_mismatch",
            format!("unsupported version {}", payload.version),
        );
    }
    if payload.algorithm != "ML-DSA-65" {
        return err(
            StatusCode::BAD_REQUEST,
            "alg_not_allowed",
            format!("only ML-DSA-65 is accepted; got {}", payload.algorithm),
        );
    }
    let vk_bytes = match B64.decode(&payload.verifying_key) {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_REQUEST, "bad_base64", e.to_string()),
    };
    let vk = VerifyingKey::new(vk_bytes, Algorithm::MlDsa65, payload.key_id.clone());
    let parsed: RegisterAccountRequest = match verify_request(&signed, &vk) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "register_account signature verification failed");
            return err(StatusCode::UNAUTHORIZED, "bad_signature", e.to_string());
        }
    };

    let id = Uuid::new_v4().to_string();
    let acc = quantumvault_acme::Account {
        id: id.clone(),
        algorithm: parsed.algorithm,
        verifying_key: parsed.verifying_key,
        key_id: parsed.key_id,
        created_at: Utc::now(),
        contact: parsed.contact,
    };
    if let Err(e) = st.store.put_account(&acc).await {
        warn!(error = %e, "put_account failed");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            e.to_string(),
        );
    }
    info!(account = %id, "account registered");
    (StatusCode::CREATED, Json(acc)).into_response()
}

async fn submit_order(
    State(st): State<AppState>,
    Json(signed): Json<SignedRequest>,
) -> axum::response::Response {
    // Pull account id from the payload first, then verify against the
    // account's stored verifying key.
    let payload_peek: IssueOrderRequest = match serde_json::from_value(signed.payload.clone()) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, "malformed", e.to_string()),
    };
    if payload_peek.version != PROTOCOL_VERSION {
        return err(
            StatusCode::BAD_REQUEST,
            "version_mismatch",
            format!("unsupported version {}", payload_peek.version),
        );
    }

    let account = match st.store.get_account(&payload_peek.account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return err(
                StatusCode::NOT_FOUND,
                "unknown_account",
                format!("account {} not found", payload_peek.account_id),
            )
        }
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                e.to_string(),
            )
        }
    };

    let acc_vk_bytes = match B64.decode(&account.verifying_key) {
        Ok(b) => b,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "corrupt_account",
                e.to_string(),
            )
        }
    };
    let acc_vk = VerifyingKey::new(acc_vk_bytes, Algorithm::MlDsa65, account.key_id.clone());

    let parsed: IssueOrderRequest = match verify_request(&signed, &acc_vk) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "submit_order signature verification failed");
            return err(StatusCode::UNAUTHORIZED, "bad_signature", e.to_string());
        }
    };

    // Build the order record.
    let order_id = Uuid::new_v4().to_string();
    let mut order = OrderResource {
        id: order_id.clone(),
        account_id: parsed.account_id,
        subject_cn: parsed.subject_cn.clone(),
        sans: parsed.sans.clone(),
        validity_days: parsed.validity_days,
        status: OrderStatus::Pending,
        created_at: Utc::now(),
        issued_at: None,
        certificate: None,
    };

    if st.auto_approve {
        // Issue immediately.
        let subject_vk_bytes = match B64.decode(&parsed.subject_verifying_key) {
            Ok(b) => b,
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "bad_base64",
                    format!("subject_verifying_key: {e}"),
                )
            }
        };
        let subject_vk = match build_ca_verifying_key(
            subject_vk_bytes,
            Algorithm::MlDsa65,
            &parsed.subject_key_id,
        ) {
            Ok(vk) => vk,
            Err(e) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "vk_construct_failed",
                    e.to_string(),
                )
            }
        };
        let mut b = CertificateBuilder::new(
            DistinguishedName::cn(parsed.subject_cn.clone()),
            &subject_vk,
        )
        .validity_days(parsed.validity_days)
        .with_key_usage(KeyUsage::DigitalSignature)
        .with_key_usage(KeyUsage::KeyEncipherment)
        .with_key_usage(KeyUsage::ServerAuth)
        .with_key_usage(KeyUsage::ClientAuth);
        for s in &parsed.sans {
            b = b.with_san(s.clone());
        }
        let cert = match b.sign_with(&st.parent_signing_key, &st.parent_cert) {
            Ok(c) => c,
            Err(e) => {
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "issuance_failed",
                    e.to_string(),
                )
            }
        };
        let cert_json = match serde_json::to_value(&cert) {
            Ok(v) => v,
            Err(e) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "json_failed",
                    e.to_string(),
                )
            }
        };
        order.status = OrderStatus::Issued;
        order.issued_at = Some(Utc::now());
        order.certificate = Some(cert_json);
        info!(order = %order_id, "order auto-approved + cert issued");
    } else {
        info!(order = %order_id, "order pending external approval");
    }

    if let Err(e) = st.store.put_order(&order).await {
        warn!(error = %e, "put_order failed");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            e.to_string(),
        );
    }
    (StatusCode::CREATED, Json(order)).into_response()
}

async fn get_order(State(st): State<AppState>, Path(id): Path<String>) -> axum::response::Response {
    match st.store.get_order(&id).await {
        Ok(Some(o)) => (StatusCode::OK, Json(o)).into_response(),
        Ok(None) => err(
            StatusCode::NOT_FOUND,
            "unknown_order",
            format!("order {id} not found"),
        ),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            e.to_string(),
        ),
    }
}

async fn get_certificate(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match st.store.get_order(&id).await {
        Ok(Some(o)) => match (&o.status, &o.certificate) {
            (OrderStatus::Issued, Some(cert)) => {
                (StatusCode::OK, Json(cert.clone())).into_response()
            }
            _ => err(
                StatusCode::CONFLICT,
                "not_yet_issued",
                format!("order {id} is in state {:?}; cert not available", o.status),
            ),
        },
        Ok(None) => err(
            StatusCode::NOT_FOUND,
            "unknown_order",
            format!("order {id} not found"),
        ),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "store_error",
            e.to_string(),
        ),
    }
}

// =====================================================================
// Internal helpers
// =====================================================================

fn find_parent_files(parent_dir: &std::path::Path) -> Result<(PathBuf, PathBuf)> {
    for (sk_pfx, cert_pfx) in [("root", "root"), ("intermediate", "intermediate")] {
        let sk = parent_dir.join(format!("{sk_pfx}.signing.json"));
        let cert = parent_dir.join(format!("{cert_pfx}.cert.json"));
        if sk.exists() && cert.exists() {
            return Ok((sk, cert));
        }
    }
    anyhow::bail!(
        "could not find a signing key + certificate pair in {:?} \
         (expected root.signing.json/root.cert.json or \
          intermediate.signing.json/intermediate.cert.json)",
        parent_dir
    )
}

/// Build a `CaVerifyingKey` from raw bytes by going through the on-disk
/// file format (saves us a public constructor we don't need anywhere else).
fn build_ca_verifying_key(
    bytes: Vec<u8>,
    alg: Algorithm,
    key_id: &str,
) -> Result<CaVerifyingKey, AcmeError> {
    let tmp = tempfile_path()?;
    let json = serde_json::json!({
        "algorithm": match alg {
            Algorithm::MlDsa44 => "ML-DSA-44",
            Algorithm::MlDsa65 => "ML-DSA-65",
            Algorithm::MlDsa87 => "ML-DSA-87",
            _ => "UNSUPPORTED",
        },
        "key_id": key_id,
        "bytes": B64.encode(&bytes),
        "format": "qvca-key:v1",
    });
    std::fs::write(&tmp, json.to_string())?;
    let vk = CaVerifyingKey::load_from_file(&tmp).map_err(AcmeError::from)?;
    let _ = std::fs::remove_file(&tmp);
    Ok(vk)
}

fn tempfile_path() -> Result<PathBuf, AcmeError> {
    let dir = std::env::temp_dir();
    let name = format!("qvacme-vk-{}.json", Uuid::new_v4());
    Ok(dir.join(name))
}

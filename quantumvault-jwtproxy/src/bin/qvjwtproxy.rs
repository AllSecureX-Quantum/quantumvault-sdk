//! `qvjwtproxy` — Envoy-style reverse HTTP proxy that verifies PQC JWTs
//! before forwarding to a backend service.
//!
//! Listens on `--listen`, forwards every request to `--backend`, but
//! returns `401` with a JSON error body for any request whose
//! `Authorization: Bearer <jwt>` is missing, malformed, expired, or
//! cryptographically invalid.
//!
//! Verifying key + validation policy are loaded once at start-up.
//!
//! Example:
//!
//! ```text
//! qvjwtproxy \
//!   --listen 127.0.0.1:8080 \
//!   --backend http://localhost:9000 \
//!   --verifying-key keys/jwt.verifying.json \
//!   --issuer https://auth.example.com \
//!   --audience payments-api \
//!   --leeway-seconds 5
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
    Json, Router,
};
use clap::Parser;
use quantumvault_core::VerifyingKey;
use quantumvault_jose::Validation;
use quantumvault_jwtproxy::{load_verifying_key, verify_jwt, JwtOutcome};
use serde::Serialize;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "qvjwtproxy",
    about = "Reverse proxy that verifies post-quantum JWTs (ML-DSA, NIST FIPS 204) before forwarding"
)]
struct Cli {
    /// Address to listen on, e.g. `127.0.0.1:8080`.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Backend URL to forward verified requests to, e.g. `http://localhost:9000`.
    /// The request's path + query string are appended.
    #[arg(long)]
    backend: String,

    /// Path to the verifying-key JSON file (algorithm + key_id + base64
    /// bytes).
    #[arg(long)]
    verifying_key: PathBuf,

    /// Expected `iss` claim. If set, tokens with a different issuer are
    /// rejected.
    #[arg(long)]
    issuer: Option<String>,

    /// Expected `aud` claim. If set, tokens whose audience doesn't
    /// include this value are rejected.
    #[arg(long)]
    audience: Option<String>,

    /// Clock-skew tolerance (seconds) applied to `exp` and `nbf`.
    #[arg(long, default_value_t = 0)]
    leeway_seconds: i64,

    /// Require the JWT to carry an `exp` claim.
    #[arg(long)]
    require_exp: bool,

    /// Paths that bypass verification (e.g. `/health`, `/metrics`).
    /// Match is by exact-prefix.
    #[arg(long, value_delimiter = ',')]
    public_path: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    verifying_key: Arc<VerifyingKey>,
    backend: Arc<String>,
    policy: Arc<Validation>,
    public_paths: Arc<Vec<String>>,
    http: reqwest::Client,
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
    let vk = load_verifying_key(&cli.verifying_key)
        .with_context(|| format!("load verifying key from {:?}", cli.verifying_key))?;

    let mut policy = Validation {
        leeway_seconds: cli.leeway_seconds,
        require_exp: cli.require_exp,
        ..Validation::default()
    };
    if let Some(iss) = cli.issuer.clone() {
        policy.expected_issuer = Some(iss);
    }
    if let Some(aud) = cli.audience.clone() {
        policy.expected_audience = Some(aud);
    }

    let state = AppState {
        verifying_key: Arc::new(vk),
        backend: Arc::new(cli.backend.clone()),
        policy: Arc::new(policy),
        public_paths: Arc::new(cli.public_path.clone()),
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("build reqwest client")?,
    };

    info!(
        listen = %cli.listen,
        backend = %cli.backend,
        issuer = ?cli.issuer,
        audience = ?cli.audience,
        public_paths = ?cli.public_path,
        "qvjwtproxy starting"
    );

    let app = Router::new().fallback(handler).with_state(state);
    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// =====================================================================
// HTTP handler
// =====================================================================

async fn handler(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> axum::response::Response {
    let path = uri.path().to_string();
    let bypass = st.public_paths.iter().any(|p| path.starts_with(p));

    if !bypass {
        let auth = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());
        match verify_jwt(auth, &st.verifying_key, &st.policy) {
            JwtOutcome::Ok(decoded) => {
                info!(
                    path = %path,
                    sub = ?decoded.claims.subject_str(),
                    iss = ?decoded.claims.issuer_str(),
                    "jwt verified"
                );
            }
            JwtOutcome::MissingBearer => {
                warn!(path = %path, "no Authorization: Bearer header");
                return reject(
                    StatusCode::UNAUTHORIZED,
                    "missing_bearer",
                    "Authorization header missing or not Bearer scheme",
                );
            }
            JwtOutcome::Rejected(e) => {
                warn!(path = %path, error = %e, "jwt rejected");
                return reject(StatusCode::UNAUTHORIZED, error_code_for(&e), &e.to_string());
            }
        }
    }

    // Forward to backend.
    let target = format!(
        "{}{}",
        st.backend.trim_end_matches('/'),
        uri.path_and_query()
            .map(|p| p.as_str())
            .unwrap_or(uri.path()),
    );
    let body_bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "failed to read request body");
            return reject(
                StatusCode::BAD_REQUEST,
                "bad_request_body",
                "could not read request body",
            );
        }
    };

    // Translate axum/http headers into reqwest's header map.
    let mut req_headers = reqwest::header::HeaderMap::new();
    for (k, v) in headers.iter() {
        // Hop-by-hop headers must NOT be forwarded.
        let name = k.as_str().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
                | "host"
                | "content-length"
        ) {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            req_headers.insert(name, val);
        }
    }

    let reqwest_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return reject(
                StatusCode::METHOD_NOT_ALLOWED,
                "bad_method",
                "unrecognised HTTP method",
            );
        }
    };

    let resp = match st
        .http
        .request(reqwest_method, &target)
        .headers(req_headers)
        .body(body_bytes.to_vec())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(target = %target, error = %e, "backend request failed");
            return reject(
                StatusCode::BAD_GATEWAY,
                "backend_unreachable",
                "could not reach backend",
            );
        }
    };

    let status = resp.status();
    let mut resp_headers = HeaderMap::new();
    for (k, v) in resp.headers() {
        let name = k.as_str().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "connection" | "keep-alive" | "transfer-encoding" | "content-length"
        ) {
            continue;
        }
        if let (Ok(name), Ok(val)) = (
            axum::http::HeaderName::from_bytes(k.as_str().as_bytes()),
            axum::http::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            resp_headers.insert(name, val);
        }
    }
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "failed to read backend response body");
            return reject(
                StatusCode::BAD_GATEWAY,
                "backend_read_failed",
                "could not read backend response",
            );
        }
    };

    let mut response = axum::response::Response::builder()
        .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    if let Some(hs) = response.headers_mut() {
        *hs = resp_headers;
    }
    response
        .body(Body::from(body_bytes.to_vec()))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "response build failed").into_response()
        })
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorPayload,
}
#[derive(Serialize)]
struct ErrorPayload {
    code: &'static str,
    message: String,
}

fn reject(status: StatusCode, code: &'static str, message: &str) -> axum::response::Response {
    (
        status,
        Json(ErrorBody {
            error: ErrorPayload {
                code,
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

fn error_code_for(e: &quantumvault_jose::Error) -> &'static str {
    use quantumvault_jose::Error::*;
    match e {
        Expired => "token_expired",
        NotYetValid => "token_not_yet_valid",
        InvalidSignature => "invalid_signature",
        IssuerMismatch => "issuer_mismatch",
        AudienceMismatch => "audience_mismatch",
        AlgorithmNotAllowed(_) | UnsupportedAlgorithm(_) => "alg_not_allowed",
        Malformed(_) | Base64(_) | Json(_) => "malformed_token",
        Crypto(_) => "crypto_error",
    }
}

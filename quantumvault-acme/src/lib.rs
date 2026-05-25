//! # QuantumVault ACME — PQC-flavoured automated certificate provisioning
//!
//! A minimal RFC 8555-style protocol that issues ML-DSA-65 certificates
//! from a `quantumvault-ca` intermediate. Each protocol request body is
//! signed with the applicant's ML-DSA-65 key — the same JWS-over-payload
//! pattern ACME uses.
//!
//! ## Wire flow (4 steps)
//!
//! 1. `POST /v1/accounts` — register a fresh account (server records the
//!    applicant's verifying key, returns an account id).
//! 2. `POST /v1/orders` — submit an order: subject CN + SANs +
//!    requested-validity. Body is signed by the account key.
//! 3. `GET /v1/orders/{id}` — poll status (`pending` → `issued`).
//! 4. `GET /v1/orders/{id}/certificate` — download the issued cert.
//!
//! ## What this is and is not
//!
//! - **This is** a working PQC automation surface in front of
//!   `quantumvault-ca`. End-to-end, no manual steps.
//! - **This is not** a literal RFC 8555 reimplementation. Real ACME
//!   carries challenges (HTTP-01 / DNS-01 / TLS-ALPN-01); we ship an
//!   `"out-of-band"` challenge type that the operator approves
//!   externally (or auto-approves when the server is run in
//!   `--auto-approve` mode for trusted-network deployments).
//! - **This will become** the foundation for full ACME-PQC once the
//!   IETF `draft-ietf-acme-pqc` finalises.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
mod error;
mod proto;
mod signing;
pub mod storage;

pub use client::Client;
pub use error::{AcmeError, Result};
pub use proto::{
    Account, IssueOrderRequest, OrderResource, OrderStatus, RegisterAccountRequest, SignedRequest,
    PROTOCOL_VERSION,
};
pub use signing::{sign_request, verify_request};
pub use storage::{InMemoryStore, SqliteStore, Store};

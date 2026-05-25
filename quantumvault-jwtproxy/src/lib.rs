//! # QuantumVault JWT Proxy
//!
//! Reverse HTTP proxy that **verifies post-quantum JWTs** (ML-DSA via
//! `quantumvault-jose`) on every request before forwarding to a backend.
//!
//! Intended deployment: as an Envoy-style sidecar in front of any HTTP
//! service. The service stays unaware of JWT semantics; this proxy is the
//! single chokepoint for token validation.
//!
//! ## Library surface
//!
//! - [`VerifyingKeyFile`] — on-disk JSON format for the verifying key the
//!   proxy needs to validate tokens.
//! - [`load_verifying_key`] — load the JSON file into a
//!   `quantumvault_jose::VerifyingKey`.
//! - [`verify_jwt`] — pure function that takes a token + verifying key +
//!   policy and returns an `Outcome`.
//!
//! The reverse-proxy binary (`qvjwtproxy`) builds on top of these.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod jwt;
mod keyfile;

pub use jwt::{verify_jwt, JwtOutcome};
pub use keyfile::{load_verifying_key, VerifyingKeyFile};

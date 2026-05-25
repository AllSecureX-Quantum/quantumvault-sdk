//! # QuantumVault CA — internal post-quantum certificate authority
//!
//! Issues and verifies certificates signed with **NIST FIPS 204 ML-DSA**.
//! Models the same trust-chain semantics as X.509 (root → intermediate →
//! leaf) but uses a versioned JSON certificate format so we can ship today
//! without an ASN.1 stack. A future revision will add a CMS / X.509 v3
//! profile once the IETF `pqc-x509` draft stabilises.
//!
//! ## Wire format
//!
//! A signed certificate is a JSON document with two top-level fields:
//!
//! ```text
//! {
//!   "tbs": { "version": 1, "serial": "...", "subject": {...},
//!            "issuer": {...}, "subject_public_key": {...},
//!            "not_before": "RFC3339", "not_after": "RFC3339",
//!            "is_ca": true|false, "path_length": <opt int>,
//!            "key_usage": [...], "san": [...] },
//!   "signature": { "algorithm": "ML-DSA-65", "issuer_key_id": "...",
//!                  "bytes": "<base64>" }
//! }
//! ```
//!
//! The `signature.bytes` field is `MlDsa(issuer_signing_key,
//! canonical_json(tbs))`. The `tbs` block is canonicalised by
//! `serde_json::to_vec_pretty` with sorted keys, so signing is
//! reproducible across runs and platforms.
//!
//! ## CLI
//!
//! The `qvca` binary exposes:
//!
//! ```text
//! qvca init-root          # bootstrap a self-signed root
//! qvca issue-intermediate # issue an intermediate from any CA
//! qvca issue-leaf         # issue a leaf certificate (non-CA)
//! qvca verify             # verify a chain against a trust anchor
//! qvca info               # print one certificate's contents
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod cert;
mod chain;
mod error;
mod keys;
mod name;

pub use cert::{
    Certificate, CertificateBuilder, KeyUsage, SignatureBlock, SubjectPublicKey, TbsCertificate,
    CERT_VERSION,
};
pub use chain::{verify_chain, ChainReport};
pub use error::{CaError, Result};
pub use keys::{generate_keypair, CaSigningKey, CaVerifyingKey};
pub use name::DistinguishedName;

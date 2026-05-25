//! # QuantumVault S/MIME-style PQC email signing
//!
//! Detached digital signatures over RFC 5322 email messages using
//! **NIST FIPS 204 ML-DSA-65** (lattice signatures, NIST Level 3) — fast
//! enough for per-message signing on the SMTP path.
//!
//! ## What it does
//!
//! `sign(message_bytes)` wraps a raw email in a `multipart/signed` MIME
//! envelope: the original message stays readable to any mail client, and a
//! second MIME part carries an ML-DSA signature over the body. `verify`
//! does the inverse — extracts the signature, recomputes the body hash,
//! and checks the signature against a supplied verifying key.
//!
//! ## Wire format
//!
//! ```text
//! From: alice@example.com
//! To:   bob@example.com
//! Subject: Q3 report
//! MIME-Version: 1.0
//! Content-Type: multipart/signed;
//!   protocol="application/pqc-signature";
//!   micalg="sha3-256";
//!   boundary="<random>"
//!
//! --<random>
//! Content-Type: text/plain; charset=utf-8
//!
//! (original body bytes — what gets signed)
//!
//! --<random>
//! Content-Type: application/pqc-signature; name="signature.pqc"
//! Content-Transfer-Encoding: base64
//! Content-Disposition: attachment; filename="signature.pqc"
//!
//! <base64 of a JSON `SignatureEnvelope`>
//!
//! --<random>--
//! ```
//!
//! ## What it does *not* do (yet)
//!
//! - **Encryption**: signing-only in v1. PQC mail encryption (via ML-KEM)
//!   lands in a future revision.
//! - **CMS / PKCS#7 ASN.1**: we use a JSON signature envelope, not the
//!   classical CMS binary. JSON is debuggable, the format is versioned,
//!   and we don't need an ASN.1 stack on day one. A CMS profile lands once
//!   the IETF `pqc-cms` draft stabilises.
//! - **Canonicalisation**: signed bytes are exactly the body bytes
//!   between the boundary markers. If an intermediate MTA rewrites line
//!   endings or transfer encoding, the signature breaks — by design.
//!   Use this at the message origin or over an SMTP path you control.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod hashing;
mod keys;
mod mime;
mod signer;
mod verifier;

pub use error::{Result, SmimeError};
pub use keys::{generate_keypair, SmimeSigningKey, SmimeVerifyingKey, DEFAULT_ALGORITHM};
pub use mime::{wrap_multipart_signed, MimePart, MimeSplit};
pub use signer::{sign_message, SignReport, SignedMessage};
pub use verifier::{verify_message, VerifyReport};

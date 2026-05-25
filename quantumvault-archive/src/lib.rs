//! # QuantumVault Archive Sealer
//!
//! Long-term integrity sealing for archival data using **NIST FIPS 205
//! SLH-DSA-SHAKE-256s** (formerly SPHINCS+), a hash-based post-quantum
//! signature scheme.
//!
//! Hash-based signatures rely only on the security of the underlying hash
//! function (SHA-3 / SHAKE in our case) — no mathematical assumption beyond
//! hash-function preimage and collision resistance. That makes them the
//! most conservative choice for archival data that must remain verifiable
//! decades from now, which is the regulatory case in BFSI (RBI 7-year
//! retention), defence (need-to-keep-forever), and healthcare (HIPAA 10
//! years).
//!
//! ## Use case
//!
//! 1. A customer has a directory of files that must be retained immutably
//!    for years (audit logs, contracts, scan PDFs, transaction journals).
//! 2. They run [`seal_directory`] once. It produces a single
//!    `qvarchive.manifest.json` file alongside the archive, signed with
//!    SLH-DSA against a long-lived archival signing key (kept offline).
//! 3. At any later point — even decades later — they run
//!    [`verify_directory`] to confirm every file still matches its
//!    signature. A tampered, truncated, or replaced file fails.
//!
//! IT Act §65B (India) and ISO 14641-1 admissibility: the manifest +
//! verifying key together constitute admissible evidence of file
//! authenticity at the moment of sealing.
//!
//! ## CLI
//!
//! The `qvarchive` binary in this crate exposes four subcommands:
//!
//! ```text
//! qvarchive keygen --out keys/         # fresh SLH-DSA-SHAKE-256s keypair
//! qvarchive seal   <dir> --key keys/   # seal every file in <dir>
//! qvarchive verify <dir> --key keys/   # verify the manifest
//! qvarchive status <dir>               # summary of what's sealed
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod hashing;
mod keys;
mod manifest;
mod sealer;
mod verifier;

pub use error::{ArchiveError, Result};
pub use keys::{generate_keypair, ArchiveSigningKey, ArchiveVerifyingKey};
pub use manifest::{Manifest, ManifestEntry, MANIFEST_FILE_NAME, MANIFEST_VERSION};
pub use sealer::{seal_directory, SealOptions, SealReport};
pub use verifier::{verify_directory, VerifyReport};

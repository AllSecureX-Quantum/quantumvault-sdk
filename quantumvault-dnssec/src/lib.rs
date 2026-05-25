//! # QuantumVault DNSSEC — post-quantum zone signing
//!
//! Sign and verify BIND-style DNS zones with **NIST FIPS 204 ML-DSA-65**.
//!
//! Today's classical DNSSEC uses RSA / ECDSA inside RRSIG records;
//! quantum-vulnerable. The IETF is drafting algorithm-number assignments
//! for PQC DNSSEC (draft-ietf-dnsop-dnssec-pqc-*) but the standard isn't
//! ratified. This crate ships a **parallel** PQC zone-signing format
//! that lives in a JSON manifest alongside the zone file. A resolver
//! or middleware that knows about the manifest can verify authenticity
//! cryptographically; standards-compliant interop will follow once the
//! IETF draft stabilises and IANA assigns ML-DSA an algorithm code.
//!
//! ## What the tool does
//!
//! 1. Parses a BIND-style zone file (subset of RFC 1035).
//! 2. Groups records into RRSets by `(owner, class, type)`.
//! 3. For each RRSet, computes a canonical SHA-3-256 hash.
//! 4. Signs each hash with the **Zone Signing Key** (ZSK).
//! 5. Signs the ZSK itself with the **Key Signing Key** (KSK).
//! 6. Writes a `<zone>.qvdnssec.manifest.json` next to the zone file.
//!
//! Verify reverses the flow against the manifest. The KSK fingerprint
//! acts as the trust anchor — analogous to the DS record in classical
//! DNSSEC.
//!
//! ## CLI
//!
//! The `qvdnssec` binary exposes:
//!
//! ```text
//! qvdnssec keygen      # generate ZSK + KSK ML-DSA-65 keypairs
//! qvdnssec sign-zone   # sign a BIND zone, produce manifest
//! qvdnssec verify-zone # verify a zone against its manifest
//! qvdnssec info        # show manifest contents
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod hashing;
mod keys;
mod manifest;
mod signer;
mod verifier;
mod zone;

pub use error::{DnssecError, Result};
pub use keys::{generate_keypair, DnssecSigningKey, DnssecVerifyingKey};
pub use manifest::{RrsetEntry, ZoneManifest, KSK_LABEL, MANIFEST_VERSION, ZSK_LABEL};
pub use signer::{sign_zone, SignZoneReport};
pub use verifier::{verify_zone, VerifyZoneReport};
pub use zone::{parse_zone, ResourceRecord, RrSet, Zone};

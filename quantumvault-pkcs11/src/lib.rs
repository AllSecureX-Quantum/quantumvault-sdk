//! `quantumvault-pkcs11` — PKCS#11 HSM bridge.
//!
//! # What this crate does
//!
//! It provides a single, file-format-compatible way to seal PQC private-key
//! material under an AES-256 Key-Encrypting-Key (KEK), where the KEK can
//! live either:
//!
//! * **in process** ([`InMemoryKek`]) — for development, CI, and any
//!   environment that doesn't have a PKCS#11-capable HSM available, or
//! * **inside a PKCS#11 HSM** ([`Pkcs11Kek`], gated behind the `pkcs11`
//!   feature) — for sovereign-deployment customers (BEL / ECIL / C-DAC /
//!   Thales Luna / Utimaco / Entrust nShield).
//!
//! The two paths produce byte-identical [`WrappedKey`] envelopes — so a
//! key sealed by a dev/test process can be unsealed by an HSM-backed
//! production process, and vice versa, *provided the same KEK is used*.
//!
//! # Why a KEK and not direct PQC operations on the HSM?
//!
//! PKCS#11 v3.1 (June 2024) standardised `CKM_ML_DSA` / `CKM_ML_KEM` but
//! virtually no HSM vendor has shipped firmware support yet. Building
//! against those mechanisms today would mean nothing to deploy with. The
//! KEK pattern needs only `CKM_AES_GCM`, which is a v2.40 mechanism
//! every certified HSM has supported for over a decade. When vendors
//! ship the v3.1 mechanisms we can add a `Pkcs11Signer` implementation
//! alongside this one without breaking the existing wire format.
//!
//! # Threat model
//!
//! * Attacker has read access to the wrapped key file on disk. → Cannot
//!   recover the plaintext PQC private key without (a) the AES-256 KEK
//!   or (b) live PIN-authenticated access to the HSM that holds it.
//! * Attacker tampers with the wrapped file. → AES-GCM AAD covers the
//!   version, KEK label, AEAD algorithm string, and any caller-supplied
//!   AAD (typically `key_id || algorithm`). Any change rejects.
//! * Attacker swaps the wrapped file with a different one that was
//!   sealed under the same KEK. → Caller-supplied AAD that names the
//!   exact key (e.g. `acme-account-7c3d`) defeats this.

mod envelope;
mod file;
mod kek;

pub use envelope::{WrappedKey, ENVELOPE_VERSION};
pub use file::{read_dev_kek_file, write_dev_kek_file, DEV_KEK_FILE_HEADER};
pub use kek::{InMemoryKek, KekProvider};

#[cfg(feature = "pkcs11")]
pub use kek::Pkcs11Kek;

use thiserror::Error;

/// Errors surfaced by this crate.
#[derive(Debug, Error)]
pub enum HsmError {
    /// The wrapped envelope's `version` field is not one this build understands.
    #[error(
        "unsupported wrapped-key envelope version: {0} (this build supports {ENVELOPE_VERSION})"
    )]
    UnsupportedVersion(u32),

    /// The AEAD algorithm string in the envelope is not one this build supports.
    #[error("unsupported AEAD algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Base64 decoding of a field in the envelope failed.
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),

    /// AEAD decryption failed — either the KEK is wrong, the ciphertext
    /// was tampered with, or the AAD doesn't match.
    #[error("AEAD decrypt failed — wrong KEK, tampered ciphertext, or AAD mismatch")]
    DecryptFailed,

    /// JSON (de)serialisation of the envelope failed.
    #[error("envelope serialisation failed: {0}")]
    Serde(#[from] serde_json::Error),

    /// I/O failure when reading or writing an envelope file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// PKCS#11 backend error (label not found, session denied, …).
    #[error("pkcs11 error: {0}")]
    Pkcs11(String),

    /// The caller supplied a KEK of the wrong length.
    #[error("kek must be exactly 32 bytes (AES-256), got {0}")]
    BadKekLength(usize),
}

/// Convenience [`Result`] alias.
pub type Result<T> = std::result::Result<T, HsmError>;

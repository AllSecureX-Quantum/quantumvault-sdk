//! On-disk envelope format for HSM-wrapped PQC key material.
//!
//! Versioned and human-readable so audit teams can `cat` a file and see
//! what KEK label was used to seal it (without leaking any plaintext).

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::HsmError;

/// On-disk envelope version. Bumped when the wire format gains new
/// fields. Old readers reject newer envelopes (forward-incompatible).
pub const ENVELOPE_VERSION: u32 = 1;

/// AEAD algorithm string written into the envelope. Hard-coded to
/// AES-256-GCM today — every PKCS#11 HSM supports this. If we ever
/// need ChaCha20-Poly1305 we'd add a separate algorithm string and
/// dispatch on it during decrypt.
pub const AEAD_AES_256_GCM: &str = "AES-256-GCM";

/// A sealed PQC private key file.
///
/// The envelope itself is non-secret — only the `ciphertext` is. The
/// envelope is JSON-encoded so auditors can inspect what KEK sealed
/// what file without invoking any crypto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Format version of this envelope.
    pub version: u32,

    /// AEAD algorithm string (currently always `"AES-256-GCM"`).
    pub algorithm: String,

    /// Opaque label identifying which KEK should be used to unwrap.
    /// For [`crate::Pkcs11Kek`] this is the CKA_LABEL of the AES key
    /// inside the HSM. For [`crate::InMemoryKek`] this is a free-form
    /// human-readable string.
    pub kek_label: String,

    /// Caller-supplied AAD that scopes this envelope to a specific
    /// purpose (e.g. `acme-account-7c3d::ML-DSA-65`). Base64-encoded.
    /// Bound into AES-GCM so any change to it rejects decryption.
    pub aad_b64: String,

    /// 12-byte AES-GCM nonce, base64-encoded. Fresh per wrap.
    pub nonce_b64: String,

    /// Ciphertext || GCM tag, base64-encoded.
    pub ciphertext_b64: String,
}

impl WrappedKey {
    /// Decode the base64 fields into their raw byte forms, validating
    /// the version and algorithm fields along the way.
    pub(crate) fn decode(&self) -> Result<DecodedEnvelope, HsmError> {
        if self.version != ENVELOPE_VERSION {
            return Err(HsmError::UnsupportedVersion(self.version));
        }
        if self.algorithm != AEAD_AES_256_GCM {
            return Err(HsmError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        Ok(DecodedEnvelope {
            aad: B64.decode(&self.aad_b64)?,
            nonce: B64.decode(&self.nonce_b64)?,
            ciphertext: B64.decode(&self.ciphertext_b64)?,
        })
    }

    /// Build a fresh envelope from raw byte fields.
    pub(crate) fn from_raw(
        kek_label: impl Into<String>,
        aad: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            algorithm: AEAD_AES_256_GCM.to_string(),
            kek_label: kek_label.into(),
            aad_b64: B64.encode(aad),
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(ciphertext),
        }
    }
}

pub(crate) struct DecodedEnvelope {
    pub aad: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

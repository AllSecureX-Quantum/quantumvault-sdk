//! Sign side — wrap an RFC 5322 message in a `multipart/signed` envelope
//! with an ML-DSA signature attachment.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use quantumvault_core::api::sign as core_sign;
use quantumvault_core::Config;
use serde::{Deserialize, Serialize};

use crate::error::{Result, SmimeError};
use crate::hashing::{hash_bytes, to_hex};
use crate::keys::{security_level_for, wire_name, SmimeSigningKey, SmimeVerifyingKey};
use crate::mime;

/// Format version for the signature envelope JSON. Bump on breaking
/// changes; older verifiers refuse to open unsupported versions.
pub const ENVELOPE_VERSION: u8 = 1;

/// JSON-serialised payload that lives inside the signature MIME part.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    /// Format version (currently always `1`).
    pub version: u8,
    /// Algorithm name (e.g. `"ML-DSA-65"`).
    pub algorithm: String,
    /// Lowercase hex of SHA-3-256(body bytes).
    pub sha3_256: String,
    /// Base64-encoded ML-DSA signature over the SHA-3-256 hash.
    pub signature: String,
    /// Verifying-key identifier (UUID by default).
    pub verifying_key_id: String,
    /// Base64-encoded verifying key bytes. The recipient can verify with
    /// only this envelope, but should pin the expected key fingerprint
    /// out-of-band.
    pub verifying_key: String,
    /// RFC 3339 timestamp when the message was signed.
    pub signed_at: DateTime<Utc>,
}

/// Output of [`sign_message`].
#[derive(Debug)]
pub struct SignedMessage {
    /// The new `multipart/signed` RFC 5322 message bytes — ready to send
    /// over SMTP.
    pub bytes: Vec<u8>,
    /// The signature envelope JSON for the part that was attached.
    pub envelope: SignatureEnvelope,
}

/// Summary of what was signed.
#[derive(Debug)]
pub struct SignReport {
    /// Length of the original body that was hashed and signed.
    pub body_bytes_signed: usize,
    /// Length of the resulting multipart/signed message.
    pub output_bytes: usize,
}

/// Sign an RFC 5322 message. The input is the full message (headers +
/// body). Output is a `multipart/signed` envelope with the original body
/// preserved verbatim and an ML-DSA signature attached as a second MIME
/// part.
pub fn sign_message(
    raw_message: &[u8],
    signing_key: &SmimeSigningKey,
    verifying_key: &SmimeVerifyingKey,
) -> Result<(SignedMessage, SignReport)> {
    let split = mime::split_headers_body(raw_message)?;

    // The signed input is the literal body bytes — NOT the MIME headers.
    // (See lib.rs docs for why; this is a deliberate v1 trade-off.)
    let hash = hash_bytes(&split.body);

    // Sign with the algorithm carried by the signing key.
    let core_alg = signing_key.core().algorithm;
    let cfg = Config::builder()
        .security_level(security_level_for(core_alg))
        .build()?;
    let core_sig = core_sign::sign_message(&hash, signing_key.core(), &cfg)?;

    let envelope = SignatureEnvelope {
        version: ENVELOPE_VERSION,
        algorithm: wire_name(core_alg).into(),
        sha3_256: to_hex(&hash),
        signature: B64.encode(&core_sig.bytes),
        verifying_key_id: verifying_key.key_id().to_string(),
        verifying_key: B64.encode(verifying_key.bytes()),
        signed_at: Utc::now(),
    };
    let envelope_json = serde_json::to_vec_pretty(&envelope)?;

    let output = mime::wrap_multipart_signed(raw_message, &envelope_json)?;
    let report = SignReport {
        body_bytes_signed: split.body.len(),
        output_bytes: output.len(),
    };
    Ok((
        SignedMessage {
            bytes: output,
            envelope,
        },
        report,
    ))
}

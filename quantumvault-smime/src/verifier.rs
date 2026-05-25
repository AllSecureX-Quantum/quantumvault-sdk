//! Verify side — extract the signature from a `multipart/signed`
//! envelope and check it against the body.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::api::verify as core_verify;
use quantumvault_core::{Config, Signature, VerifyingKey};

use crate::error::{Result, SmimeError};
use crate::hashing::{hash_bytes, to_hex};
use crate::keys::{parse_algorithm, security_level_for, SmimeVerifyingKey};
use crate::mime;
use crate::signer::{SignatureEnvelope, ENVELOPE_VERSION};

const SIGNATURE_CONTENT_TYPE_PREFIX: &str = "application/pqc-signature";

/// Result of verifying a `multipart/signed` message.
#[derive(Debug)]
pub struct VerifyReport {
    /// True when both the body hash matches and the ML-DSA signature
    /// verifies against the supplied (or embedded) verifying key.
    pub valid: bool,
    /// Original body bytes (as recovered from the envelope's first part).
    /// Caller may want to pass these on to downstream consumers.
    pub body: Vec<u8>,
    /// Parsed signature envelope.
    pub envelope: SignatureEnvelope,
}

/// Verify a `multipart/signed` message.
///
/// If `expected_verifying_key` is supplied, it must match the verifying
/// key embedded in the signature envelope — defends against an attacker
/// who can rewrite both the body and the envelope.
pub fn verify_message(
    raw_message: &[u8],
    expected_verifying_key: Option<&SmimeVerifyingKey>,
) -> Result<VerifyReport> {
    // 1. Confirm the outer Content-Type is multipart/signed.
    let outer = mime::split_headers_body(raw_message)?;
    let outer_ct = mime::header_value(&outer.headers, "Content-Type")
        .ok_or(SmimeError::InvalidMessage("missing outer Content-Type"))?;
    if !outer_ct
        .to_ascii_lowercase()
        .starts_with("multipart/signed")
    {
        return Err(SmimeError::NotMultipartSigned(outer_ct));
    }
    let boundary = mime::param_value(&outer_ct, "boundary")
        .ok_or(SmimeError::MultipartMalformed("missing boundary parameter"))?;

    // 2. Split into the body part and the signature part.
    let parts = mime::split_multipart(&outer.body, &boundary)?;
    if parts.len() != 2 {
        return Err(SmimeError::WrongPartCount(parts.len()));
    }
    let body_part = &parts[0];
    let sig_part = &parts[1];

    let sig_ct = mime::header_value(&sig_part.headers, "Content-Type")
        .ok_or(SmimeError::SignaturePartMissing)?;
    if !sig_ct
        .to_ascii_lowercase()
        .starts_with(SIGNATURE_CONTENT_TYPE_PREFIX)
    {
        return Err(SmimeError::SignaturePartMissing);
    }

    // 3. Decode the signature envelope.
    let envelope_json_text = std::str::from_utf8(&sig_part.body)
        .map_err(|_| SmimeError::EnvelopeMalformed("signature body is not UTF-8".into()))?;
    let envelope_bytes = mime::base64_decode_loose(envelope_json_text)?;
    let envelope: SignatureEnvelope = serde_json::from_slice(&envelope_bytes)?;
    if envelope.version != ENVELOPE_VERSION {
        return Err(SmimeError::UnsupportedEnvelopeVersion(envelope.version));
    }
    let algo = parse_algorithm(&envelope.algorithm)?;

    // 4. Check the verifying key matches what the caller expects (if any).
    let vk_bytes = B64
        .decode(&envelope.verifying_key)
        .map_err(|e| SmimeError::Base64(e.to_string()))?;
    if let Some(expected) = expected_verifying_key {
        if expected.bytes() != vk_bytes || expected.core().algorithm != algo {
            return Err(SmimeError::VerifyingKeyMismatch);
        }
    }
    let core_vk = VerifyingKey::new(vk_bytes, algo, envelope.verifying_key_id.clone());

    // 5. Recompute the body hash and check it matches.
    let computed = hash_bytes(&body_part.body);
    let expected_hex = envelope.sha3_256.clone();
    if to_hex(&computed) != expected_hex {
        return Ok(VerifyReport {
            valid: false,
            body: body_part.body.clone(),
            envelope,
        });
    }

    // 6. Verify the signature.
    let sig_bytes = B64
        .decode(&envelope.signature)
        .map_err(|e| SmimeError::Base64(e.to_string()))?;
    let cfg = Config::builder()
        .security_level(security_level_for(algo))
        .build()?;
    let core_sig = Signature {
        bytes: sig_bytes,
        algorithm: algo,
        key_id: envelope.verifying_key_id.clone(),
        signed_at: 0,
    };
    let ok = core_verify::verify_signature(&computed, &core_sig, &core_vk, &cfg)?;
    Ok(VerifyReport {
        valid: ok,
        body: body_part.body.clone(),
        envelope,
    })
}

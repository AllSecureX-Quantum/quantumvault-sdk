//! ML-DSA-65 signing and verification of protocol requests.
//!
//! Pattern matches ACME's JWS-over-payload: sign the canonical JSON
//! bytes of the inner request, encode the signature in a wrapper, send.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::{api::sign as core_sign, api::verify as core_verify};
use quantumvault_core::{Algorithm, Config, SecurityLevel, Signature, SigningKey, VerifyingKey};
use serde::Serialize;

use crate::error::{AcmeError, Result};
use crate::proto::SignedRequest;

/// Sign a request payload and produce a [`SignedRequest`] envelope.
pub fn sign_request<T: Serialize>(
    payload: &T,
    signing_key: &SigningKey,
    verifying_key_id: &str,
) -> Result<SignedRequest> {
    let payload_value = serde_json::to_value(payload)?;
    let canonical = serde_json::to_vec(&payload_value)?;
    let cfg = config_for(signing_key.algorithm);
    let sig = core_sign::sign_message(&canonical, signing_key, &cfg)?;
    Ok(SignedRequest {
        payload: payload_value,
        algorithm: alg_name(signing_key.algorithm).to_string(),
        verifying_key_id: verifying_key_id.to_string(),
        signature: B64.encode(&sig.bytes),
    })
}

/// Verify a [`SignedRequest`] against a known verifying key. Returns
/// the parsed inner payload on success.
pub fn verify_request<T: serde::de::DeserializeOwned>(
    req: &SignedRequest,
    verifying_key: &VerifyingKey,
) -> Result<T> {
    let expected_alg = alg_name(verifying_key.algorithm);
    if req.algorithm != expected_alg {
        return Err(AcmeError::UnsupportedAlgorithm(req.algorithm.clone()));
    }
    let canonical = serde_json::to_vec(&req.payload)?;
    let sig_bytes = B64.decode(&req.signature)?;
    let cfg = config_for(verifying_key.algorithm);
    let signature = Signature {
        bytes: sig_bytes,
        algorithm: verifying_key.algorithm,
        key_id: req.verifying_key_id.clone(),
        signed_at: 0,
    };
    let ok = core_verify::verify_signature(&canonical, &signature, verifying_key, &cfg)?;
    if !ok {
        return Err(AcmeError::SignatureInvalid);
    }
    let parsed: T = serde_json::from_value(req.payload.clone())?;
    Ok(parsed)
}

fn config_for(alg: Algorithm) -> Config {
    let lvl = match alg {
        Algorithm::MlDsa44 => SecurityLevel::Level2,
        Algorithm::MlDsa65 => SecurityLevel::Level3,
        Algorithm::MlDsa87 => SecurityLevel::Level5,
        _ => SecurityLevel::Level3,
    };
    Config::builder()
        .security_level(lvl)
        .build()
        .expect("config builder is infallible for these inputs")
}

fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::MlDsa44 => "ML-DSA-44",
        Algorithm::MlDsa65 => "ML-DSA-65",
        Algorithm::MlDsa87 => "ML-DSA-87",
        _ => "UNSUPPORTED",
    }
}

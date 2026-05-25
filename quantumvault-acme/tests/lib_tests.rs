//! Library tests for the ACME-PQC signing logic + protocol types.
//! No HTTP server is spun up here — pure logic verified in-process.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_acme::{
    sign_request, verify_request, AcmeError, IssueOrderRequest, RegisterAccountRequest,
    SignedRequest, PROTOCOL_VERSION,
};
use quantumvault_core::api::keygen as core_keygen;
use quantumvault_core::{Algorithm, Config, SecurityLevel};

fn fresh_kp() -> quantumvault_core::SignatureKeyPair {
    let cfg = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()
        .unwrap();
    core_keygen::generate_signature_keypair(Algorithm::MlDsa65, &cfg).unwrap()
}

// -------- sign / verify round-trip ------------------------------------

#[test]
fn signed_request_round_trips() {
    let kp = fresh_kp();
    let payload = RegisterAccountRequest {
        version: PROTOCOL_VERSION,
        algorithm: "ML-DSA-65".into(),
        verifying_key: B64.encode(&kp.verifying_key.bytes),
        key_id: kp.verifying_key.key_id.clone(),
        contact: Some("ops@example.com".into()),
    };
    let signed = sign_request(&payload, &kp.signing_key, &kp.signing_key.key_id).unwrap();
    let parsed: RegisterAccountRequest = verify_request(&signed, &kp.verifying_key).unwrap();
    assert_eq!(parsed, payload);
}

#[test]
fn tampered_payload_rejected() {
    let kp = fresh_kp();
    let payload = RegisterAccountRequest {
        version: PROTOCOL_VERSION,
        algorithm: "ML-DSA-65".into(),
        verifying_key: B64.encode(&kp.verifying_key.bytes),
        key_id: kp.verifying_key.key_id.clone(),
        contact: None,
    };
    let mut signed = sign_request(&payload, &kp.signing_key, &kp.signing_key.key_id).unwrap();
    // Change the contact field after signing.
    signed.payload["contact"] = serde_json::json!("attacker@evil.com");
    let err: Result<RegisterAccountRequest, _> = verify_request(&signed, &kp.verifying_key);
    let err = err.unwrap_err();
    assert!(matches!(err, AcmeError::SignatureInvalid), "got {err:?}");
}

#[test]
fn wrong_algorithm_in_envelope_rejected() {
    let kp = fresh_kp();
    let payload = RegisterAccountRequest {
        version: PROTOCOL_VERSION,
        algorithm: "ML-DSA-65".into(),
        verifying_key: B64.encode(&kp.verifying_key.bytes),
        key_id: kp.verifying_key.key_id.clone(),
        contact: None,
    };
    let mut signed = sign_request(&payload, &kp.signing_key, &kp.signing_key.key_id).unwrap();
    signed.algorithm = "RS256".into();
    let err: Result<RegisterAccountRequest, _> = verify_request(&signed, &kp.verifying_key);
    assert!(matches!(
        err.unwrap_err(),
        AcmeError::UnsupportedAlgorithm(_)
    ));
}

#[test]
fn foreign_key_rejected() {
    let kp_a = fresh_kp();
    let kp_b = fresh_kp();
    let payload = RegisterAccountRequest {
        version: PROTOCOL_VERSION,
        algorithm: "ML-DSA-65".into(),
        verifying_key: B64.encode(&kp_a.verifying_key.bytes),
        key_id: kp_a.verifying_key.key_id.clone(),
        contact: None,
    };
    let signed = sign_request(&payload, &kp_a.signing_key, &kp_a.signing_key.key_id).unwrap();
    let err: Result<RegisterAccountRequest, _> = verify_request(&signed, &kp_b.verifying_key);
    assert!(matches!(err.unwrap_err(), AcmeError::SignatureInvalid));
}

// -------- Issue-order envelope -----------------------------------------

#[test]
fn issue_order_request_signs_and_verifies() {
    let kp = fresh_kp();
    let payload = IssueOrderRequest {
        version: PROTOCOL_VERSION,
        account_id: "acc-123".into(),
        subject_cn: "api.example.com".into(),
        sans: vec!["DNS:api.example.com".into(), "DNS:www...".into()],
        subject_verifying_key: B64.encode([0u8; 32]),
        subject_key_id: "sub-1".into(),
        validity_days: 90,
        nonce: "nonce-1".into(),
    };
    let signed = sign_request(&payload, &kp.signing_key, &kp.signing_key.key_id).unwrap();
    let parsed: IssueOrderRequest = verify_request(&signed, &kp.verifying_key).unwrap();
    assert_eq!(parsed.subject_cn, "api.example.com");
    assert_eq!(parsed.sans.len(), 2);
    assert_eq!(parsed.validity_days, 90);
}

#[test]
fn signed_envelope_serialises_round_trip() {
    let kp = fresh_kp();
    let payload = RegisterAccountRequest {
        version: PROTOCOL_VERSION,
        algorithm: "ML-DSA-65".into(),
        verifying_key: B64.encode(&kp.verifying_key.bytes),
        key_id: kp.verifying_key.key_id.clone(),
        contact: None,
    };
    let signed = sign_request(&payload, &kp.signing_key, &kp.signing_key.key_id).unwrap();
    let json = serde_json::to_string(&signed).unwrap();
    let back: SignedRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, signed);
}

// -------- Tampered signature byte -------------------------------------

#[test]
fn flipping_signature_bit_breaks_verify() {
    let kp = fresh_kp();
    let payload = RegisterAccountRequest {
        version: PROTOCOL_VERSION,
        algorithm: "ML-DSA-65".into(),
        verifying_key: B64.encode(&kp.verifying_key.bytes),
        key_id: kp.verifying_key.key_id.clone(),
        contact: None,
    };
    let mut signed = sign_request(&payload, &kp.signing_key, &kp.signing_key.key_id).unwrap();
    let last = signed.signature.len() - 1;
    let new_char = if signed.signature.as_bytes()[last] == b'A' {
        'B'
    } else {
        'A'
    };
    signed
        .signature
        .replace_range(last..last + 1, &new_char.to_string());
    let err: Result<RegisterAccountRequest, _> = verify_request(&signed, &kp.verifying_key);
    assert!(matches!(
        err.unwrap_err(),
        AcmeError::SignatureInvalid | AcmeError::Base64(_)
    ));
}

// -------- Protocol invariants -----------------------------------------

#[test]
fn protocol_version_is_one() {
    assert_eq!(PROTOCOL_VERSION, 1);
}

#[test]
fn order_status_serde_is_snake_case() {
    use quantumvault_acme::OrderStatus;
    let json = serde_json::to_string(&OrderStatus::Pending).unwrap();
    assert_eq!(json, "\"pending\"");
    let json = serde_json::to_string(&OrderStatus::Issued).unwrap();
    assert_eq!(json, "\"issued\"");
}

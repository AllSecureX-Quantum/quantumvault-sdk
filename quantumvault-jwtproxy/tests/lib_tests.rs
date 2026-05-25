//! Library tests for the JWT-verification logic (no HTTP server spun up).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::api::keygen as core_keygen;
use quantumvault_core::{Algorithm, Config, SecurityLevel};
use quantumvault_jose::{encode, Claims, Validation};
use quantumvault_jwtproxy::{verify_jwt, JwtOutcome, VerifyingKeyFile};

fn fresh_keypair() -> quantumvault_core::SignatureKeyPair {
    let cfg = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()
        .unwrap();
    core_keygen::generate_signature_keypair(Algorithm::MlDsa65, &cfg).unwrap()
}

fn vk_file_for(kp: &quantumvault_core::SignatureKeyPair) -> VerifyingKeyFile {
    VerifyingKeyFile {
        algorithm: "ML-DSA-65".into(),
        key_id: kp.verifying_key.key_id.clone(),
        bytes: B64.encode(&kp.verifying_key.bytes),
        format: "qvjwt-vk:v1".into(),
    }
}

fn sign_token(kp: &quantumvault_core::SignatureKeyPair, claims: Claims) -> String {
    // Wrap into a PySigningKeyPair-equivalent via quantumvault-jose's encode.
    // jose::encode wants a SigningKeyPair object — we have one already.
    // Adapt by going through the public encode helper of jose.
    let sk_pair_for_jose = quantumvault_jose_signing_keypair(kp);
    encode(
        &claims,
        quantumvault_jose::Algorithm::MlDsa65,
        &sk_pair_for_jose,
    )
    .unwrap()
}

// The Rust quantumvault-jose `encode` takes a `&quantumvault_core::SigningKey`,
// not a SignatureKeyPair. Let's shadow with what it actually takes.
fn quantumvault_jose_signing_keypair(
    kp: &quantumvault_core::SignatureKeyPair,
) -> quantumvault_core::SigningKey {
    kp.signing_key.clone()
}

// -------- Happy path --------------------------------------------------

#[test]
fn valid_token_returns_ok() {
    let kp = fresh_keypair();
    let token = sign_token(
        &kp,
        Claims::new()
            .subject("user-42")
            .expiry_in(chrono::Duration::seconds(120)),
    );
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default();
    match verify_jwt(Some(&format!("Bearer {}", token)), &vk, &policy) {
        JwtOutcome::Ok(d) => assert_eq!(d.claims.subject_str(), Some("user-42")),
        other => panic!("expected Ok, got {other:?}"),
    }
}

// -------- Header parsing ----------------------------------------------

#[test]
fn missing_authorization_returns_missing_bearer() {
    let kp = fresh_keypair();
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default();
    matches!(verify_jwt(None, &vk, &policy), JwtOutcome::MissingBearer)
        .then_some(())
        .expect("expected MissingBearer");
}

#[test]
fn non_bearer_scheme_returns_missing_bearer() {
    let kp = fresh_keypair();
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default();
    let outcome = verify_jwt(Some("Basic abc==:def"), &vk, &policy);
    matches!(outcome, JwtOutcome::MissingBearer)
        .then_some(())
        .expect("expected MissingBearer");
}

#[test]
fn bearer_with_no_token_returns_missing_bearer() {
    let kp = fresh_keypair();
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default();
    let outcome = verify_jwt(Some("Bearer "), &vk, &policy);
    matches!(outcome, JwtOutcome::MissingBearer)
        .then_some(())
        .expect("expected MissingBearer");
}

#[test]
fn bearer_scheme_is_case_insensitive() {
    let kp = fresh_keypair();
    let token = sign_token(&kp, Claims::new().subject("u"));
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default();
    let outcome = verify_jwt(Some(&format!("bearer {}", token)), &vk, &policy);
    assert!(matches!(outcome, JwtOutcome::Ok(_)));
}

// -------- Token validation --------------------------------------------

#[test]
fn tampered_signature_rejected() {
    let kp = fresh_keypair();
    let token = sign_token(&kp, Claims::new().subject("alice"));
    let bad = format!("{}X", &token[..token.len() - 1]);
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default();
    matches!(
        verify_jwt(Some(&format!("Bearer {}", bad)), &vk, &policy),
        JwtOutcome::Rejected(_)
    )
    .then_some(())
    .expect("expected Rejected");
}

#[test]
fn expired_token_rejected() {
    let kp = fresh_keypair();
    let token = sign_token(
        &kp,
        Claims::new()
            .subject("u")
            .expiry(chrono::Utc::now() - chrono::Duration::seconds(60)),
    );
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default();
    let outcome = verify_jwt(Some(&format!("Bearer {}", token)), &vk, &policy);
    match outcome {
        JwtOutcome::Rejected(quantumvault_jose::Error::Expired) => {}
        other => panic!("expected Rejected(Expired), got {other:?}"),
    }
}

#[test]
fn foreign_verifying_key_rejected() {
    let kp_a = fresh_keypair();
    let kp_b = fresh_keypair();
    let token = sign_token(&kp_a, Claims::new().subject("u"));
    let vk_b = vk_file_for(&kp_b).into_core().unwrap();
    let policy = Validation::default();
    let outcome = verify_jwt(Some(&format!("Bearer {}", token)), &vk_b, &policy);
    matches!(outcome, JwtOutcome::Rejected(_))
        .then_some(())
        .expect("expected Rejected");
}

#[test]
fn issuer_mismatch_rejected() {
    let kp = fresh_keypair();
    let token = sign_token(&kp, Claims::new().issuer("https://other.example.com"));
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default().with_issuer("https://auth.example.com");
    let outcome = verify_jwt(Some(&format!("Bearer {}", token)), &vk, &policy);
    match outcome {
        JwtOutcome::Rejected(quantumvault_jose::Error::IssuerMismatch) => {}
        other => panic!("expected IssuerMismatch, got {other:?}"),
    }
}

#[test]
fn audience_mismatch_rejected() {
    let kp = fresh_keypair();
    let token = sign_token(&kp, Claims::new().audience("billing"));
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default().with_audience("payments-api");
    let outcome = verify_jwt(Some(&format!("Bearer {}", token)), &vk, &policy);
    match outcome {
        JwtOutcome::Rejected(quantumvault_jose::Error::AudienceMismatch) => {}
        other => panic!("expected AudienceMismatch, got {other:?}"),
    }
}

#[test]
fn malformed_token_rejected() {
    let kp = fresh_keypair();
    let vk = vk_file_for(&kp).into_core().unwrap();
    let policy = Validation::default();
    let outcome = verify_jwt(Some("Bearer not.a.valid.jwt"), &vk, &policy);
    matches!(outcome, JwtOutcome::Rejected(_))
        .then_some(())
        .expect("expected Rejected");
}

// -------- Verifying-key file format ----------------------------------

#[test]
fn verifying_key_file_roundtrips() {
    let kp = fresh_keypair();
    let f = vk_file_for(&kp);
    let json = serde_json::to_string_pretty(&f).unwrap();
    let parsed: VerifyingKeyFile = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.algorithm, "ML-DSA-65");
    assert_eq!(parsed.key_id, kp.verifying_key.key_id);
    let vk = parsed.into_core().unwrap();
    assert_eq!(vk.bytes, kp.verifying_key.bytes);
}

#[test]
fn verifying_key_file_rejects_unsupported_algorithm() {
    let f = VerifyingKeyFile {
        algorithm: "RS256".into(),
        key_id: "x".into(),
        bytes: B64.encode([0u8; 32]),
        format: "qvjwt-vk:v1".into(),
    };
    match f.into_core() {
        Ok(_) => panic!("expected RS256 to be rejected"),
        Err(e) => assert!(format!("{e}").contains("RS256")),
    }
}

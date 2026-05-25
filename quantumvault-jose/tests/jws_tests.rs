//! End-to-end tests for `quantumvault-jose`.
//!
//! These exercise the JOSE library against all three ML-DSA security levels,
//! along with negative paths (tampered token, wrong key, alg confusion,
//! expired/not-yet-valid, missing exp under strict mode, audience and issuer
//! enforcement).

use chrono::{Duration, Utc};
use quantumvault_core::api::keygen::generate_signature_keypair;
use quantumvault_core::{Algorithm as CoreAlg, Config, SecurityLevel};

use quantumvault_jose::{
    decode, decode_with_validation, encode, Algorithm, Audience, Claims, Error, Header, Validation,
};

fn signing_kp(alg: CoreAlg, lvl: SecurityLevel) -> quantumvault_core::SignatureKeyPair {
    let cfg = Config::builder().security_level(lvl).build().unwrap();
    generate_signature_keypair(alg, &cfg).unwrap()
}

// -------- Round-trip per algorithm -------------------------------------

#[test]
fn roundtrip_ml_dsa_44() {
    let kp = signing_kp(CoreAlg::MlDsa44, SecurityLevel::Level2);
    let claims = Claims::new().subject("u").issued_now();
    let token = encode(&claims, Algorithm::MlDsa44, &kp.signing_key).unwrap();
    let decoded = decode(&token, &kp.verifying_key).unwrap();
    assert_eq!(decoded.header.alg, Algorithm::MlDsa44);
    assert_eq!(decoded.claims.subject_str(), Some("u"));
}

#[test]
fn roundtrip_ml_dsa_65() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new()
        .issuer("https://auth.example.com")
        .subject("u-1")
        .audience("payments-api")
        .expiry_in(Duration::minutes(15));
    let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let decoded = decode(&token, &kp.verifying_key).unwrap();
    assert_eq!(decoded.claims.subject_str(), Some("u-1"));
    assert_eq!(
        decoded.claims.issuer_str(),
        Some("https://auth.example.com")
    );
}

#[test]
fn roundtrip_ml_dsa_87() {
    let kp = signing_kp(CoreAlg::MlDsa87, SecurityLevel::Level5);
    let claims = Claims::new().subject("u-87");
    let token = encode(&claims, Algorithm::MlDsa87, &kp.signing_key).unwrap();
    let decoded = decode(&token, &kp.verifying_key).unwrap();
    assert_eq!(decoded.header.alg, Algorithm::MlDsa87);
    assert_eq!(decoded.claims.subject_str(), Some("u-87"));
}

// -------- Token shape (RFC 7519 compact serialisation) -----------------

#[test]
fn token_has_three_dot_separated_segments() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let token = encode(&Claims::new(), Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    for p in &parts {
        assert!(!p.is_empty(), "segment must not be empty: '{p}'");
    }
}

#[test]
fn header_segment_is_base64url_json() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine;
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let token = encode(&Claims::new(), Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let header_b64 = token.split('.').next().unwrap();
    let header_bytes = B64URL.decode(header_b64).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(json["alg"], "ML-DSA-65");
    assert_eq!(json["typ"], "JWT");
}

// -------- Tamper detection ---------------------------------------------

#[test]
fn tampered_payload_rejected() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new().subject("alice");
    let mut token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();

    // Decode the middle segment, mutate, re-encode.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine;
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    let mut payload_bytes = B64URL.decode(&parts[1]).unwrap();
    // Replace alice with malice (same length).
    let s = std::str::from_utf8(&payload_bytes)
        .unwrap()
        .replace("alice", "malice");
    payload_bytes = s.into_bytes();
    parts[1] = B64URL.encode(&payload_bytes);
    token = parts.join(".");

    let err = decode(&token, &kp.verifying_key).unwrap_err();
    assert!(matches!(err, Error::InvalidSignature), "got {err:?}");
}

#[test]
fn tampered_signature_rejected() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let token = encode(&Claims::new(), Algorithm::MlDsa65, &kp.signing_key).unwrap();
    // Flip the last char of the signature.
    let mut chars: Vec<char> = token.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let mutated: String = chars.into_iter().collect();
    assert!(matches!(
        decode(&mutated, &kp.verifying_key),
        Err(Error::InvalidSignature) | Err(Error::Base64(_))
    ));
}

#[test]
fn foreign_verifying_key_rejected() {
    let kp_a = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let kp_b = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let token = encode(&Claims::new(), Algorithm::MlDsa65, &kp_a.signing_key).unwrap();
    let err = decode(&token, &kp_b.verifying_key).unwrap_err();
    assert!(matches!(err, Error::InvalidSignature));
}

// -------- alg / key mismatch (alg-confusion attack class) --------------

#[test]
fn alg_confusion_header_vs_verifying_key_mismatch_rejected() {
    let kp_65 = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let kp_87 = signing_kp(CoreAlg::MlDsa87, SecurityLevel::Level5);
    let token = encode(&Claims::new(), Algorithm::MlDsa65, &kp_65.signing_key).unwrap();
    // Try to verify a 65-signed token using an 87 verifying key — header
    // claims 65 but key is 87. Must reject.
    let err = decode(&token, &kp_87.verifying_key).unwrap_err();
    assert!(matches!(err, Error::AlgorithmNotAllowed(_)));
}

#[test]
fn encode_rejects_mismatched_alg_and_signing_key() {
    let kp_65 = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    // Try to sign with alg=ML-DSA-87 but a ML-DSA-65 signing key.
    let err = encode(&Claims::new(), Algorithm::MlDsa87, &kp_65.signing_key).unwrap_err();
    assert!(matches!(err, Error::AlgorithmNotAllowed(_)));
}

#[test]
fn allowed_algorithms_filter_rejects_excluded() {
    let kp = signing_kp(CoreAlg::MlDsa44, SecurityLevel::Level2);
    let token = encode(&Claims::new(), Algorithm::MlDsa44, &kp.signing_key).unwrap();
    let v = Validation::default().with_algorithms(vec![Algorithm::MlDsa65, Algorithm::MlDsa87]);
    let err = decode_with_validation(&token, &kp.verifying_key, &v).unwrap_err();
    assert!(matches!(err, Error::AlgorithmNotAllowed(_)));
}

// -------- Expiry / not-before ------------------------------------------

#[test]
fn expired_token_rejected() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new().expiry(Utc::now() - Duration::seconds(60));
    let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let err = decode(&token, &kp.verifying_key).unwrap_err();
    assert!(matches!(err, Error::Expired));
}

#[test]
fn expiry_with_leeway_accepted() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new().expiry(Utc::now() - Duration::seconds(30));
    let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let v = Validation::default().with_leeway_seconds(120);
    let ok = decode_with_validation(&token, &kp.verifying_key, &v).unwrap();
    assert!(ok.claims.exp.is_some());
}

#[test]
fn not_yet_valid_token_rejected() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new().not_before(Utc::now() + Duration::minutes(5));
    let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let err = decode(&token, &kp.verifying_key).unwrap_err();
    assert!(matches!(err, Error::NotYetValid));
}

#[test]
fn strict_validation_rejects_missing_exp() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let token = encode(&Claims::new(), Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let err = decode_with_validation(&token, &kp.verifying_key, &Validation::strict()).unwrap_err();
    assert!(matches!(err, Error::Expired));
}

// -------- Issuer / audience --------------------------------------------

#[test]
fn issuer_must_match() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new().issuer("https://other.example.com");
    let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let v = Validation::default().with_issuer("https://auth.example.com");
    let err = decode_with_validation(&token, &kp.verifying_key, &v).unwrap_err();
    assert!(matches!(err, Error::IssuerMismatch));
}

#[test]
fn issuer_match_succeeds() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new().issuer("https://auth.example.com");
    let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let v = Validation::default().with_issuer("https://auth.example.com");
    let decoded = decode_with_validation(&token, &kp.verifying_key, &v).unwrap();
    assert_eq!(
        decoded.claims.issuer_str(),
        Some("https://auth.example.com")
    );
}

#[test]
fn audience_must_match_for_single() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new().audience("billing-api");
    let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let v = Validation::default().with_audience("payments-api");
    let err = decode_with_validation(&token, &kp.verifying_key, &v).unwrap_err();
    assert!(matches!(err, Error::AudienceMismatch));
}

#[test]
fn audience_match_for_multi_succeeds() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new().audiences(["billing-api", "payments-api"]);
    let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let v = Validation::default().with_audience("payments-api");
    let decoded = decode_with_validation(&token, &kp.verifying_key, &v).unwrap();
    match decoded.claims.audience_ref() {
        Some(Audience::Multi(v)) => assert_eq!(v.len(), 2),
        other => panic!("expected multi-audience, got {other:?}"),
    }
}

#[test]
fn missing_audience_rejected_when_required() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let token = encode(&Claims::new(), Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let v = Validation::default().with_audience("any-api");
    let err = decode_with_validation(&token, &kp.verifying_key, &v).unwrap_err();
    assert!(matches!(err, Error::AudienceMismatch));
}

// -------- Malformed inputs ---------------------------------------------

#[test]
fn malformed_token_only_two_segments() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let err = decode("abc.def", &kp.verifying_key).unwrap_err();
    assert!(matches!(err, Error::Malformed(_)));
}

#[test]
fn malformed_token_four_segments() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    // splitn(3, '.') captures "c.d" as the third part. That isn't valid
    // base64url so it falls out at decode time. Either response is fine
    // — the contract is "rejected", not "rejected with a specific code".
    let err = decode("a.b.c.d", &kp.verifying_key).unwrap_err();
    assert!(
        matches!(err, Error::Malformed(_) | Error::Base64(_)),
        "got {err:?}"
    );
}

#[test]
fn empty_token_rejected() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let err = decode("", &kp.verifying_key).unwrap_err();
    // Empty string splits to a single segment.
    assert!(matches!(err, Error::Malformed(_)));
}

#[test]
fn header_with_unknown_alg_rejected() {
    // Construct a token with alg="RS256" — must fail at header parse time
    // because the Algorithm enum doesn't have an RS256 variant.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine;
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let bad_header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    let bad_header_b64 = B64URL.encode(serde_json::to_vec(&bad_header).unwrap());
    let bad_payload_b64 = B64URL.encode(b"{}");
    let token = format!("{}.{}.{}", bad_header_b64, bad_payload_b64, "AAAA");
    let err = decode(&token, &kp.verifying_key).unwrap_err();
    assert!(matches!(
        err,
        Error::Json(_) | Error::UnsupportedAlgorithm(_)
    ));
}

// -------- Custom claims --------------------------------------------------

#[test]
fn custom_claim_roundtrips() {
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let claims = Claims::new()
        .with_claim("role", serde_json::json!("admin"))
        .with_claim("scopes", serde_json::json!(["read", "write"]));
    let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key).unwrap();
    let decoded = decode(&token, &kp.verifying_key).unwrap();
    assert_eq!(
        decoded.claims.get("role").unwrap(),
        &serde_json::json!("admin")
    );
    assert_eq!(
        decoded.claims.get("scopes").unwrap(),
        &serde_json::json!(["read", "write"])
    );
}

// -------- Header kid round-trip ----------------------------------------

#[test]
fn header_kid_persists_through_roundtrip() {
    use quantumvault_jose::Header;
    let kp = signing_kp(CoreAlg::MlDsa65, SecurityLevel::Level3);
    let header = Header::new(Algorithm::MlDsa65).with_kid("kid-2026-05");
    let token = quantumvault_jose::encode_with_header(header, &Claims::new(), &kp.signing_key)
        .expect("encode_with_header");
    let decoded = decode(&token, &kp.verifying_key).unwrap();
    assert_eq!(decoded.header.kid.as_deref(), Some("kid-2026-05"));
}

// -------- Algorithm metadata -------------------------------------------

#[test]
fn algorithm_security_levels() {
    assert_eq!(Algorithm::MlDsa44.security_level(), 2);
    assert_eq!(Algorithm::MlDsa65.security_level(), 3);
    assert_eq!(Algorithm::MlDsa87.security_level(), 5);
}

#[test]
fn algorithm_default_is_ml_dsa_65() {
    assert_eq!(Algorithm::default(), Algorithm::MlDsa65);
}

#[test]
fn algorithm_from_str_roundtrip() {
    for alg in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let s = alg.as_str();
        assert_eq!(Algorithm::from_str(s).unwrap(), alg);
    }
}

#[test]
fn algorithm_from_str_rejects_unknown() {
    assert!(matches!(
        Algorithm::from_str("RS256"),
        Err(Error::UnsupportedAlgorithm(_))
    ));
}

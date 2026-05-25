//! Library-level tests for the S/MIME sign + verify path.

use quantumvault_smime::{
    generate_keypair, sign_message, verify_message, SmimeError, SmimeSigningKey, SmimeVerifyingKey,
};

fn sample_email() -> &'static [u8] {
    b"From: alice@example.com\r\n\
      To: bob@example.com\r\n\
      Subject: Q3 financial report\r\n\
      Date: Sat, 16 May 2026 14:00:00 +0530\r\n\
      MIME-Version: 1.0\r\n\
      Content-Type: text/plain; charset=utf-8\r\n\
      \r\n\
      Bob,\r\n\
      \r\n\
      Net revenue 12.4M INR.\r\n\
      \r\n\
      \xe2\x80\x94 Alice\r\n"
}

fn fresh_kp() -> (SmimeSigningKey, SmimeVerifyingKey) {
    generate_keypair().expect("generate_keypair")
}

// -------- Round-trip ---------------------------------------------------

#[test]
fn signed_message_is_valid_multipart() {
    let (sk, vk) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk, &vk).unwrap();
    // The output must start with the new headers.
    let s = std::str::from_utf8(&signed.bytes).unwrap();
    assert!(s.contains("Content-Type: multipart/signed"));
    assert!(s.contains("protocol=\"application/pqc-signature\""));
    assert!(s.contains("micalg=\"sha3-256\""));
}

#[test]
fn signed_message_preserves_original_headers() {
    let (sk, vk) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk, &vk).unwrap();
    let s = std::str::from_utf8(&signed.bytes).unwrap();
    assert!(s.contains("From: alice@example.com"));
    assert!(s.contains("Subject: Q3 financial report"));
}

#[test]
fn verify_returns_valid_for_unmodified_message() {
    let (sk, vk) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk, &vk).unwrap();
    let report = verify_message(&signed.bytes, Some(&vk)).unwrap();
    assert!(report.valid);
}

#[test]
fn verify_recovers_original_body() {
    let (sk, vk) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk, &vk).unwrap();
    let report = verify_message(&signed.bytes, Some(&vk)).unwrap();
    // The body recovered from the signed envelope must contain the
    // original message text.
    let s = std::str::from_utf8(&report.body).unwrap();
    assert!(s.contains("Net revenue 12.4M INR"));
}

#[test]
fn verify_succeeds_without_explicit_expected_key() {
    let (sk, vk) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk, &vk).unwrap();
    let report = verify_message(&signed.bytes, None).unwrap();
    assert!(report.valid);
}

// -------- Tamper detection ---------------------------------------------

#[test]
fn tampered_body_rejected() {
    let (sk, vk) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk, &vk).unwrap();
    let mut bytes = signed.bytes.clone();
    // Replace "12.4M" with "99.9M" (same length).
    let idx = bytes.windows(5).position(|w| w == b"12.4M").unwrap();
    bytes[idx..idx + 5].copy_from_slice(b"99.9M");
    let report = verify_message(&bytes, Some(&vk)).unwrap();
    assert!(!report.valid);
}

#[test]
fn foreign_verifying_key_rejected_at_pin() {
    let (sk_a, vk_a) = fresh_kp();
    let (_sk_b, vk_b) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk_a, &vk_a).unwrap();
    let err = verify_message(&signed.bytes, Some(&vk_b)).unwrap_err();
    assert!(matches!(err, SmimeError::VerifyingKeyMismatch));
}

// -------- Malformed inputs ---------------------------------------------

#[test]
fn sign_rejects_input_without_blank_line() {
    let (sk, vk) = fresh_kp();
    let bad = b"From: alice@example.com\r\nSubject: missing-blank-line\r\n";
    let err = sign_message(bad, &sk, &vk).unwrap_err();
    assert!(matches!(err, SmimeError::InvalidMessage(_)));
}

#[test]
fn verify_rejects_non_multipart_input() {
    let (_sk, vk) = fresh_kp();
    let plain = b"From: alice@example.com\r\n\
                 Content-Type: text/plain\r\n\
                 \r\n\
                 hello\r\n";
    let err = verify_message(plain, Some(&vk)).unwrap_err();
    assert!(matches!(err, SmimeError::NotMultipartSigned(_)));
}

#[test]
fn verify_rejects_multipart_without_signature_part() {
    let (_sk, vk) = fresh_kp();
    let bad = b"From: alice@example.com\r\n\
                Content-Type: multipart/signed; boundary=\"bd\"; protocol=\"application/pqc-signature\"\r\n\
                \r\n\
                preamble\r\n\
                --bd\r\n\
                Content-Type: text/plain\r\n\
                \r\n\
                only one part\r\n\
                --bd--\r\n";
    let err = verify_message(bad, Some(&vk)).unwrap_err();
    assert!(matches!(err, SmimeError::WrongPartCount(_)));
}

// -------- Multi-algorithm round-trip -----------------------------------

#[test]
fn ml_dsa_65_default_keygen_works() {
    // The default keygen returns ML-DSA-65; verify the algorithm string
    // appears in the resulting envelope.
    let (sk, vk) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk, &vk).unwrap();
    assert_eq!(signed.envelope.algorithm, "ML-DSA-65");
}

// -------- Body sizes ---------------------------------------------------

#[test]
fn one_mib_body_roundtrips() {
    let (sk, vk) = fresh_kp();
    // Build a message with a 1 MiB body.
    let mut msg = Vec::new();
    msg.extend_from_slice(b"From: alice@example.com\r\n");
    msg.extend_from_slice(b"To: bob@example.com\r\n");
    msg.extend_from_slice(b"Subject: large attachment\r\n");
    msg.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
    msg.extend_from_slice(b"\r\n");
    msg.extend(std::iter::repeat(0xABu8).take(1024 * 1024));
    let (signed, report) = sign_message(&msg, &sk, &vk).unwrap();
    assert_eq!(report.body_bytes_signed, 1024 * 1024);
    let v = verify_message(&signed.bytes, Some(&vk)).unwrap();
    assert!(v.valid);
}

#[test]
fn empty_body_roundtrips() {
    let (sk, vk) = fresh_kp();
    let msg = b"From: a@b\r\nContent-Type: text/plain\r\n\r\n";
    let (signed, _r) = sign_message(msg, &sk, &vk).unwrap();
    let v = verify_message(&signed.bytes, Some(&vk)).unwrap();
    assert!(v.valid);
}

// -------- Envelope schema ---------------------------------------------

#[test]
fn envelope_has_expected_top_level_fields() {
    let (sk, vk) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk, &vk).unwrap();
    let env = &signed.envelope;
    assert_eq!(env.version, 1);
    assert_eq!(env.algorithm, "ML-DSA-65");
    assert_eq!(env.sha3_256.len(), 64);
    assert!(!env.signature.is_empty());
    assert!(!env.verifying_key.is_empty());
    assert!(!env.verifying_key_id.is_empty());
}

#[test]
fn envelope_sha3_matches_body_hash() {
    use sha3::{Digest, Sha3_256};
    let (sk, vk) = fresh_kp();
    let (signed, _r) = sign_message(sample_email(), &sk, &vk).unwrap();
    let body = verify_message(&signed.bytes, Some(&vk)).unwrap().body;
    let mut h = Sha3_256::new();
    h.update(&body);
    let hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(hex, signed.envelope.sha3_256);
}

// -------- Key file round-trip -----------------------------------------

#[test]
fn keypair_save_load_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (sk, vk) = fresh_kp();
    let sk_path = tmp.path().join("smime.signing.json");
    let vk_path = tmp.path().join("smime.verifying.json");
    sk.save_to_file(&sk_path, None).unwrap();
    vk.save_to_file(&vk_path).unwrap();

    let sk2 = SmimeSigningKey::load_from_file(&sk_path, None).unwrap();
    let vk2 = SmimeVerifyingKey::load_from_file(&vk_path).unwrap();
    let (signed, _r) = sign_message(sample_email(), &sk2, &vk2).unwrap();
    let v = verify_message(&signed.bytes, Some(&vk2)).unwrap();
    assert!(v.valid);
}

// -------- LF-only line endings (RFC 822 §5.1 is CRLF; many tools use LF)
// We must still handle the looser input gracefully on the sign path.
// The output is always CRLF.

#[test]
fn sign_accepts_lf_only_input() {
    let (sk, vk) = fresh_kp();
    let bad = b"From: a@b\nContent-Type: text/plain\n\nbody only\n";
    let (signed, _r) = sign_message(bad, &sk, &vk).expect("lf-only input must be accepted");
    let v = verify_message(&signed.bytes, Some(&vk)).unwrap();
    assert!(v.valid);
}

// -------- Boundary obscurity ------------------------------------------

#[test]
fn each_signing_uses_a_fresh_boundary() {
    let (sk, vk) = fresh_kp();
    let (a, _) = sign_message(sample_email(), &sk, &vk).unwrap();
    let (b, _) = sign_message(sample_email(), &sk, &vk).unwrap();
    let a_s = std::str::from_utf8(&a.bytes).unwrap();
    let b_s = std::str::from_utf8(&b.bytes).unwrap();
    let extract_boundary = |s: &str| -> String {
        s.lines()
            .find(|l| l.starts_with("Content-Type: multipart/signed"))
            .and_then(|l| {
                l.split("boundary=\"")
                    .nth(1)
                    .and_then(|t| t.split('"').next())
            })
            .map(|s| s.to_string())
            .unwrap_or_default()
    };
    let a_b = extract_boundary(a_s);
    let b_b = extract_boundary(b_s);
    assert!(!a_b.is_empty());
    assert!(!b_b.is_empty());
    assert_ne!(a_b, b_b, "boundary should be random per-sign");
}

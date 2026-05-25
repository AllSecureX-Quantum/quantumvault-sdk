//! Round-trip + tamper tests for the in-memory KEK.

use quantumvault_pkcs11::{HsmError, InMemoryKek, KekProvider, WrappedKey, ENVELOPE_VERSION};

fn fresh() -> InMemoryKek {
    InMemoryKek::generate("test-kek")
}

#[test]
fn wrap_unwrap_recovers_original_plaintext() {
    let kek = fresh();
    let pt = b"my super-secret ML-DSA-65 signing key bytes";
    let aad = b"acme-account-7c3d::ML-DSA-65";

    let env = kek.wrap(pt, aad).unwrap();
    let recovered = kek.unwrap(&env, aad).unwrap();
    assert_eq!(recovered.as_slice(), pt);
}

#[test]
fn envelope_metadata_is_populated() {
    let kek = fresh();
    let env = kek.wrap(b"x", b"y").unwrap();
    assert_eq!(env.version, ENVELOPE_VERSION);
    assert_eq!(env.algorithm, "AES-256-GCM");
    assert_eq!(env.kek_label, "test-kek");
    assert!(!env.nonce_b64.is_empty());
    assert!(!env.ciphertext_b64.is_empty());
}

#[test]
fn fresh_nonce_per_wrap() {
    let kek = fresh();
    let a = kek.wrap(b"same plaintext", b"same aad").unwrap();
    let b = kek.wrap(b"same plaintext", b"same aad").unwrap();
    assert_ne!(a.nonce_b64, b.nonce_b64, "nonce must not repeat");
    assert_ne!(
        a.ciphertext_b64, b.ciphertext_b64,
        "AES-GCM determinism — different nonces should produce different ct"
    );
}

#[test]
fn wrong_aad_rejects() {
    let kek = fresh();
    let env = kek.wrap(b"plaintext", b"original-aad").unwrap();
    let err = kek.unwrap(&env, b"different-aad").unwrap_err();
    assert!(matches!(err, HsmError::DecryptFailed), "got {err:?}");
}

#[test]
fn different_kek_rejects() {
    let alice = fresh();
    let bob = fresh();
    let env = alice.wrap(b"plaintext", b"aad").unwrap();
    let err = bob.unwrap(&env, b"aad").unwrap_err();
    assert!(matches!(err, HsmError::DecryptFailed), "got {err:?}");
}

#[test]
fn tampered_ciphertext_rejects() {
    let kek = fresh();
    let mut env = kek.wrap(b"plaintext", b"aad").unwrap();
    // Flip a base64 character. AES-GCM authentication tag will catch it.
    let last = env.ciphertext_b64.len() - 1;
    let ch = env.ciphertext_b64.as_bytes()[last];
    let replacement = if ch == b'A' { 'B' } else { 'A' };
    env.ciphertext_b64
        .replace_range(last..last + 1, &replacement.to_string());
    let err = kek.unwrap(&env, b"aad").unwrap_err();
    // Either AEAD failure or base64 decode failure is acceptable here —
    // both are tamper rejections.
    assert!(
        matches!(err, HsmError::DecryptFailed | HsmError::Base64(_)),
        "got {err:?}"
    );
}

#[test]
fn unknown_version_rejected() {
    let kek = fresh();
    let mut env = kek.wrap(b"plaintext", b"aad").unwrap();
    env.version = 99;
    let err = kek.unwrap(&env, b"aad").unwrap_err();
    assert!(matches!(err, HsmError::UnsupportedVersion(99)), "got {err:?}");
}

#[test]
fn unknown_algorithm_rejected() {
    let kek = fresh();
    let mut env = kek.wrap(b"plaintext", b"aad").unwrap();
    env.algorithm = "XSalsa20".into();
    let err = kek.unwrap(&env, b"aad").unwrap_err();
    assert!(matches!(err, HsmError::UnsupportedAlgorithm(_)), "got {err:?}");
}

#[test]
fn envelope_serialises_round_trip() {
    let kek = fresh();
    let env = kek.wrap(b"plaintext", b"aad").unwrap();
    let json = serde_json::to_string(&env).unwrap();
    let back: WrappedKey = serde_json::from_str(&json).unwrap();
    assert_eq!(back, env);
    // And we can still unwrap after the round-trip.
    let pt = kek.unwrap(&back, b"aad").unwrap();
    assert_eq!(pt.as_slice(), b"plaintext");
}

#[test]
fn cross_kek_with_same_bytes_succeeds() {
    // Two KEK instances built from the same raw bytes must be
    // interchangeable — this is the contract that makes "seal in dev,
    // unseal in HSM" possible.
    let bytes = [42u8; 32];
    let kek_a = InMemoryKek::from_bytes("dev", bytes);
    let kek_b = InMemoryKek::from_bytes("prod", bytes);

    let env = kek_a.wrap(b"plaintext", b"aad").unwrap();
    let recovered = kek_b.unwrap(&env, b"aad").unwrap();
    assert_eq!(recovered.as_slice(), b"plaintext");
}

#[test]
fn empty_plaintext_round_trips() {
    let kek = fresh();
    let env = kek.wrap(b"", b"aad").unwrap();
    let pt = kek.unwrap(&env, b"aad").unwrap();
    assert!(pt.is_empty());
}

#[test]
fn large_plaintext_round_trips() {
    let kek = fresh();
    // Realistic ML-DSA-65 secret-key size is ~4KB; SLH-DSA secret key
    // is ~64 bytes. We use 32 KiB to exercise multi-block GCM.
    let pt = vec![0x5au8; 32 * 1024];
    let env = kek.wrap(&pt, b"aad").unwrap();
    let recovered = kek.unwrap(&env, b"aad").unwrap();
    assert_eq!(recovered.as_slice(), pt.as_slice());
}

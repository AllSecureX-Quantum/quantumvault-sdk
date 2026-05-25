//! Property-based round-trip tests for QuantumVault core.
//!
//! These tests fuzz the encrypt/decrypt and sign/verify code paths with
//! randomly-generated inputs. They're the foundation safety net: any
//! adversarial-looking byte string that survives the round-trip gives us
//! cheap confidence that the underlying NIST primitives are wired
//! correctly. Failures here mean a real bug in the API layer.
//!
//! Each property is run `cases` times (default 32, override via the
//! `PROPTEST_CASES` env var). Sticking with 32 by default keeps CI under a
//! second per property while still exercising thousands of total byte
//! patterns across the suite.

use proptest::prelude::*;
use quantumvault_core::api;
use quantumvault_core::{Algorithm, Config, QuantumVault, SecurityLevel};

fn config(level: SecurityLevel) -> Config {
    Config::builder().security_level(level).build().unwrap()
}

// -------- KEM: ML-KEM round-trip ----------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn ml_kem_768_roundtrip_arbitrary_plaintext(
        plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
        let kp = qv.keygen(Algorithm::MlKem768).unwrap();
        let enc = qv.encrypt(&plaintext, &kp.public_key).unwrap();
        let dec = qv.decrypt(&enc, &kp.secret_key).unwrap();
        prop_assert_eq!(dec, plaintext);
    }

    #[test]
    fn ml_kem_512_roundtrip_arbitrary_plaintext(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let qv = QuantumVault::new(SecurityLevel::Level1).unwrap();
        let kp = qv.keygen(Algorithm::MlKem512).unwrap();
        let enc = qv.encrypt(&plaintext, &kp.public_key).unwrap();
        let dec = qv.decrypt(&enc, &kp.secret_key).unwrap();
        prop_assert_eq!(dec, plaintext);
    }

    #[test]
    fn ml_kem_1024_roundtrip_arbitrary_plaintext(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let qv = QuantumVault::new(SecurityLevel::Level5).unwrap();
        let kp = qv.keygen(Algorithm::MlKem1024).unwrap();
        let enc = qv.encrypt(&plaintext, &kp.public_key).unwrap();
        let dec = qv.decrypt(&enc, &kp.secret_key).unwrap();
        prop_assert_eq!(dec, plaintext);
    }

    // Cross-key safety: decrypting with the wrong secret key must fail.
    #[test]
    fn ml_kem_768_wrong_key_fails(
        plaintext in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
        let kp_a = qv.keygen(Algorithm::MlKem768).unwrap();
        let kp_b = qv.keygen(Algorithm::MlKem768).unwrap();
        let enc = qv.encrypt(&plaintext, &kp_a.public_key).unwrap();
        let dec = qv.decrypt(&enc, &kp_b.secret_key);
        prop_assert!(dec.is_err(), "decrypt with foreign secret key must fail");
    }

    // Ciphertext malleability: flipping any single bit must break decryption.
    #[test]
    fn ml_kem_768_ciphertext_tamper_fails(
        plaintext in proptest::collection::vec(any::<u8>(), 1..256),
        flip_byte_idx in 0usize..16,
    ) {
        let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
        let kp = qv.keygen(Algorithm::MlKem768).unwrap();
        let mut enc = qv.encrypt(&plaintext, &kp.public_key).unwrap();
        if !enc.ciphertext.is_empty() {
            let idx = flip_byte_idx % enc.ciphertext.len();
            enc.ciphertext[idx] ^= 0x01;
            let dec = qv.decrypt(&enc, &kp.secret_key);
            prop_assert!(dec.is_err(), "tampered ciphertext must not decrypt cleanly");
        }
    }
}

// -------- Signatures: ML-DSA sign / verify ------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn ml_dsa_65_signature_roundtrip(
        message in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let cfg = config(SecurityLevel::Level3);
        let kp = api::keygen::generate_signature_keypair(Algorithm::MlDsa65, &cfg).unwrap();
        let sig = api::sign::sign_message(&message, &kp.signing_key, &cfg).unwrap();
        let ok = api::verify::verify_signature(&message, &sig, &kp.verifying_key, &cfg).unwrap();
        prop_assert!(ok, "signature must verify on the same message");
    }

    #[test]
    fn ml_dsa_44_signature_roundtrip(
        message in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let cfg = config(SecurityLevel::Level2);
        let kp = api::keygen::generate_signature_keypair(Algorithm::MlDsa44, &cfg).unwrap();
        let sig = api::sign::sign_message(&message, &kp.signing_key, &cfg).unwrap();
        let ok = api::verify::verify_signature(&message, &sig, &kp.verifying_key, &cfg).unwrap();
        prop_assert!(ok);
    }

    #[test]
    fn ml_dsa_87_signature_roundtrip(
        message in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let cfg = config(SecurityLevel::Level5);
        let kp = api::keygen::generate_signature_keypair(Algorithm::MlDsa87, &cfg).unwrap();
        let sig = api::sign::sign_message(&message, &kp.signing_key, &cfg).unwrap();
        let ok = api::verify::verify_signature(&message, &sig, &kp.verifying_key, &cfg).unwrap();
        prop_assert!(ok);
    }

    // Tampered message must not verify against a genuine signature.
    #[test]
    fn ml_dsa_65_tampered_message_rejected(
        message in proptest::collection::vec(any::<u8>(), 1..512),
        flip_byte_idx in 0usize..16,
    ) {
        let cfg = config(SecurityLevel::Level3);
        let kp = api::keygen::generate_signature_keypair(Algorithm::MlDsa65, &cfg).unwrap();
        let sig = api::sign::sign_message(&message, &kp.signing_key, &cfg).unwrap();
        let mut tampered = message.clone();
        let idx = flip_byte_idx % tampered.len();
        tampered[idx] ^= 0x01;
        let ok = api::verify::verify_signature(&tampered, &sig, &kp.verifying_key, &cfg).unwrap();
        prop_assert!(!ok, "tampered message must not verify");
    }

    // Foreign key must not verify.
    #[test]
    fn ml_dsa_65_foreign_key_rejected(
        message in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let cfg = config(SecurityLevel::Level3);
        let kp_a = api::keygen::generate_signature_keypair(Algorithm::MlDsa65, &cfg).unwrap();
        let kp_b = api::keygen::generate_signature_keypair(Algorithm::MlDsa65, &cfg).unwrap();
        let sig = api::sign::sign_message(&message, &kp_a.signing_key, &cfg).unwrap();
        let ok = api::verify::verify_signature(&message, &sig, &kp_b.verifying_key, &cfg).unwrap();
        prop_assert!(!ok);
    }
}

// -------- SLH-DSA (hash-based) round-trip -------------------------------
//
// SLH-DSA is slow — a single sign+verify can take ~100 ms in s-mode. Keep
// the case count low so the property still runs in CI without dominating
// the run time.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn slh_dsa_shake_128f_roundtrip(
        message in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let cfg = config(SecurityLevel::Level3);
        let kp = api::keygen::generate_signature_keypair(
            Algorithm::SlhDsaShake128f, &cfg,
        ).unwrap();
        let sig = api::sign::sign_message(&message, &kp.signing_key, &cfg).unwrap();
        let ok = api::verify::verify_signature(&message, &sig, &kp.verifying_key, &cfg).unwrap();
        prop_assert!(ok);
    }
}

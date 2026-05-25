//! Integration tests for QuantumVault Core.

use quantumvault_core::{Algorithm, Config, QuantumVault, SecurityLevel};

#[test]
fn test_keygen_mlkem768() {
    let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
    let keypair = qv.keygen(Algorithm::MlKem768).unwrap();

    assert!(!keypair.public_key.bytes.is_empty());
    assert!(keypair.public_key.bytes.len() > 1000); // ML-KEM-768 has ~1184 byte public key
}

#[test]
fn test_keygen_all_kem_algorithms() {
    // Test each algorithm with its corresponding minimum security level
    for (level, algo) in [
        (SecurityLevel::Level1, Algorithm::MlKem512),
        (SecurityLevel::Level3, Algorithm::MlKem768),
        (SecurityLevel::Level5, Algorithm::MlKem1024),
    ] {
        let qv = QuantumVault::new(level).unwrap();
        let keypair = qv.keygen(algo).unwrap();
        assert!(!keypair.public_key.bytes.is_empty());
        assert!(!keypair.key_id.is_empty());
    }
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
    let keypair = qv.keygen(Algorithm::MlKem768).unwrap();

    let plaintext = b"Hello, Post-Quantum World!";
    let encrypted = qv.encrypt(plaintext, &keypair.public_key).unwrap();

    assert!(!encrypted.ciphertext.is_empty());
    assert!(!encrypted.encapsulated_key.is_empty());

    let decrypted = qv.decrypt(&encrypted, &keypair.secret_key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_empty_message() {
    let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
    let keypair = qv.keygen(Algorithm::MlKem768).unwrap();

    let plaintext = b"";
    let encrypted = qv.encrypt(plaintext, &keypair.public_key).unwrap();
    let decrypted = qv.decrypt(&encrypted, &keypair.secret_key).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_large_message() {
    let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
    let keypair = qv.keygen(Algorithm::MlKem768).unwrap();

    // 1MB of data
    let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let encrypted = qv.encrypt(&plaintext, &keypair.public_key).unwrap();
    let decrypted = qv.decrypt(&encrypted, &keypair.secret_key).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_security_levels() {
    // Test that each security level can be used to create a QuantumVault instance
    // Each level must use an algorithm meeting its minimum security requirement
    for (level, algo) in [
        (SecurityLevel::Level1, Algorithm::MlKem512),
        (SecurityLevel::Level3, Algorithm::MlKem768),
        (SecurityLevel::Level5, Algorithm::MlKem1024),
    ] {
        let qv = QuantumVault::new(level).unwrap();
        // Verify keygen works with appropriate algorithm
        let keypair = qv.keygen(algo).unwrap();
        assert!(!keypair.key_id.is_empty());
    }
}

#[test]
fn test_sign_verify_mldsa65() {
    let config = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()
        .unwrap();

    let keypair =
        quantumvault_core::api::keygen::generate_signature_keypair(Algorithm::MlDsa65, &config)
            .unwrap();

    let message = b"Sign this message";
    let signature =
        quantumvault_core::api::sign::sign_message(message, &keypair.signing_key, &config).unwrap();

    assert!(!signature.bytes.is_empty());

    let valid = quantumvault_core::api::verify::verify_signature(
        message,
        &signature,
        &keypair.verifying_key,
        &config,
    )
    .unwrap();

    assert!(valid);
}

#[test]
fn test_signature_invalid_message() {
    let config = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()
        .unwrap();

    let keypair =
        quantumvault_core::api::keygen::generate_signature_keypair(Algorithm::MlDsa65, &config)
            .unwrap();

    let message = b"Original message";
    let signature =
        quantumvault_core::api::sign::sign_message(message, &keypair.signing_key, &config).unwrap();

    let wrong_message = b"Tampered message";
    let valid = quantumvault_core::api::verify::verify_signature(
        wrong_message,
        &signature,
        &keypair.verifying_key,
        &config,
    )
    .unwrap();

    assert!(!valid);
}

#[test]
fn test_config_builder() {
    let config = Config::builder()
        .security_level(SecurityLevel::Level5)
        .build()
        .unwrap();

    assert_eq!(config.security_level, SecurityLevel::Level5);
}

#[test]
fn test_keypair_serialization() {
    let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
    let keypair = qv.keygen(Algorithm::MlKem768).unwrap();

    // Serialize public key
    let pk_json = serde_json::to_string(&keypair.public_key).unwrap();
    let pk_restored: quantumvault_core::PublicKey = serde_json::from_str(&pk_json).unwrap();

    assert_eq!(keypair.public_key.bytes, pk_restored.bytes);
    assert_eq!(keypair.public_key.algorithm, pk_restored.algorithm);
}

#[test]
fn test_encrypted_data_serialization() {
    let qv = QuantumVault::new(SecurityLevel::Level3).unwrap();
    let keypair = qv.keygen(Algorithm::MlKem768).unwrap();

    let plaintext = b"Test serialization";
    let encrypted = qv.encrypt(plaintext, &keypair.public_key).unwrap();

    // Serialize
    let json = serde_json::to_string(&encrypted).unwrap();
    let restored: quantumvault_core::EncryptedData = serde_json::from_str(&json).unwrap();

    // Verify we can still decrypt
    let decrypted = qv.decrypt(&restored, &keypair.secret_key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_cnsa2_compliance() {
    // CNSA 2.0 requires Level 5 security
    let qv = QuantumVault::new(SecurityLevel::Level5).unwrap();

    // Use CNSA 2.0 approved algorithms
    let kem_keypair = qv.keygen(Algorithm::MlKem1024).unwrap();

    let config = Config::builder()
        .security_level(SecurityLevel::Level5)
        .build()
        .unwrap();

    let sig_keypair =
        quantumvault_core::api::keygen::generate_signature_keypair(Algorithm::MlDsa87, &config)
            .unwrap();

    // Verify we're using Level 5 algorithms
    assert_eq!(kem_keypair.algorithm, Algorithm::MlKem1024);
    assert_eq!(sig_keypair.signing_key.algorithm, Algorithm::MlDsa87);
}

// Hybrid encryption test is gated behind an unimplemented feature flag until
// the public hybrid API (generate_hybrid_keypair / hybrid_encrypt / hybrid_decrypt)
// is finalised. Enable manually once the API stabilises.
#[test]
#[cfg(feature = "hybrid-api-pending")]
fn test_hybrid_encryption() {
    let config = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()
        .unwrap();

    let hybrid_keypair = quantumvault_core::api::hybrid::generate_hybrid_keypair(&config).unwrap();

    let plaintext = b"Hybrid encryption test";
    let encrypted =
        quantumvault_core::api::hybrid::hybrid_encrypt(plaintext, &hybrid_keypair, &config)
            .unwrap();

    let decrypted =
        quantumvault_core::api::hybrid::hybrid_decrypt(&encrypted, &hybrid_keypair, &config)
            .unwrap();

    assert_eq!(decrypted, plaintext);
}

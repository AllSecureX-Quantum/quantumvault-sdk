//! Library tests for certificate issuance and chain verification.

use chrono::{Duration, Utc};
use quantumvault_ca::{
    generate_keypair, verify_chain, CaError, CaSigningKey, CaVerifyingKey, Certificate,
    CertificateBuilder, DistinguishedName, KeyUsage,
};

// -------- Builders shared across tests ----------------------------------

fn fresh_kp() -> (CaSigningKey, CaVerifyingKey) {
    generate_keypair().expect("generate_keypair")
}

fn root_ca(dn: DistinguishedName, sk: &CaSigningKey, vk: &CaVerifyingKey) -> Certificate {
    CertificateBuilder::new(dn, vk)
        .ca(Some(2))
        .validity_days(3650)
        .with_key_usage(KeyUsage::DigitalSignature)
        .with_key_usage(KeyUsage::KeyCertSign)
        .self_sign(sk)
        .expect("self-sign root")
}

fn issue_intermediate(
    parent_sk: &CaSigningKey,
    parent_cert: &Certificate,
    subject: DistinguishedName,
    int_vk: &CaVerifyingKey,
    path_length: Option<u8>,
) -> Certificate {
    CertificateBuilder::new(subject, int_vk)
        .ca(path_length)
        .validity_days(1825)
        .with_key_usage(KeyUsage::DigitalSignature)
        .with_key_usage(KeyUsage::KeyCertSign)
        .sign_with(parent_sk, parent_cert)
        .expect("sign intermediate")
}

fn issue_leaf(
    parent_sk: &CaSigningKey,
    parent_cert: &Certificate,
    subject: DistinguishedName,
    leaf_vk: &CaVerifyingKey,
) -> Certificate {
    CertificateBuilder::new(subject, leaf_vk)
        .validity_days(365)
        .with_key_usage(KeyUsage::DigitalSignature)
        .with_key_usage(KeyUsage::ServerAuth)
        .with_san("DNS:api.example.com")
        .sign_with(parent_sk, parent_cert)
        .expect("sign leaf")
}

// -------- Happy paths ---------------------------------------------------

#[test]
fn self_sign_root_verifies_against_own_key() {
    let (sk, vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root CA"), &sk, &vk);
    assert!(root.verify_signature_with(&vk).unwrap());
}

#[test]
fn three_level_chain_verifies() {
    let (root_sk, root_vk) = fresh_kp();
    let (int_sk, int_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();

    let root = root_ca(DistinguishedName::cn("Root"), &root_sk, &root_vk);
    let intermediate = issue_intermediate(
        &root_sk,
        &root,
        DistinguishedName::cn("Intermediate"),
        &int_vk,
        Some(0),
    );
    let leaf = issue_leaf(
        &int_sk,
        &intermediate,
        DistinguishedName::cn("api.example.com"),
        &leaf_vk,
    );

    let root_fp = root.fingerprint().unwrap();
    let report = verify_chain(&[leaf, intermediate, root], &[root_fp.clone()]).unwrap();
    assert_eq!(report.depth, 3);
    assert_eq!(report.root_fingerprint, root_fp);
    assert!(report.valid);
}

#[test]
fn two_level_chain_root_plus_leaf() {
    let (root_sk, root_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &root_sk, &root_vk);
    let leaf = issue_leaf(
        &root_sk,
        &root,
        DistinguishedName::cn("api.example.com"),
        &leaf_vk,
    );
    let root_fp = root.fingerprint().unwrap();
    let report = verify_chain(&[leaf, root], &[root_fp.clone()]).unwrap();
    assert_eq!(report.depth, 2);
    assert!(report.valid);
}

#[test]
fn root_self_signed_check_passes() {
    let (sk, vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &sk, &vk);
    // Issuer must equal Subject on a self-sign.
    assert_eq!(root.tbs.issuer, root.tbs.subject);
}

// -------- Adversarial paths --------------------------------------------

#[test]
fn tampered_leaf_subject_breaks_signature() {
    let (root_sk, root_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &root_sk, &root_vk);
    let mut leaf = issue_leaf(
        &root_sk,
        &root,
        DistinguishedName::cn("api.example.com"),
        &leaf_vk,
    );
    leaf.tbs.subject.cn = "attacker.evil.com".into();

    let err = verify_chain(&[leaf, root.clone()], &[root.fingerprint().unwrap()]).unwrap_err();
    assert!(matches!(err, CaError::SignatureInvalid), "got {err:?}");
}

#[test]
fn tampered_signature_bytes_break_chain() {
    let (root_sk, root_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &root_sk, &root_vk);
    let mut leaf = issue_leaf(
        &root_sk,
        &root,
        DistinguishedName::cn("api.example.com"),
        &leaf_vk,
    );
    // Replace last char of signature.
    let last = leaf.signature.bytes.len() - 1;
    let new_char = if leaf.signature.bytes.as_bytes()[last] == b'A' {
        'B'
    } else {
        'A'
    };
    leaf.signature
        .bytes
        .replace_range(last..last + 1, &new_char.to_string());

    let err = verify_chain(&[leaf, root.clone()], &[root.fingerprint().unwrap()]).unwrap_err();
    assert!(matches!(err, CaError::SignatureInvalid));
}

#[test]
fn expired_cert_rejected() {
    let (root_sk, root_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &root_sk, &root_vk);
    let leaf = CertificateBuilder::new(DistinguishedName::cn("expired"), &leaf_vk)
        .validity(
            Utc::now() - Duration::days(2),
            Utc::now() - Duration::days(1),
        )
        .sign_with(&root_sk, &root)
        .unwrap();
    let err = verify_chain(&[leaf, root.clone()], &[root.fingerprint().unwrap()]).unwrap_err();
    assert!(matches!(err, CaError::Expired(_)));
}

#[test]
fn not_yet_valid_cert_rejected() {
    let (root_sk, root_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &root_sk, &root_vk);
    let leaf = CertificateBuilder::new(DistinguishedName::cn("future"), &leaf_vk)
        .validity(
            Utc::now() + Duration::days(1),
            Utc::now() + Duration::days(30),
        )
        .sign_with(&root_sk, &root)
        .unwrap();
    let err = verify_chain(&[leaf, root.clone()], &[root.fingerprint().unwrap()]).unwrap_err();
    assert!(matches!(err, CaError::NotYetValid(_)));
}

#[test]
fn untrusted_root_rejected() {
    let (root_sk, root_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &root_sk, &root_vk);
    let leaf = issue_leaf(
        &root_sk,
        &root,
        DistinguishedName::cn("api.example.com"),
        &leaf_vk,
    );
    // Use a fingerprint that doesn't match.
    let bogus = "0".repeat(64);
    let err = verify_chain(&[leaf, root], &[bogus]).unwrap_err();
    assert!(matches!(err, CaError::UntrustedChain));
}

#[test]
fn empty_chain_errors() {
    let err = verify_chain(&[], &["anything".into()]).unwrap_err();
    assert!(matches!(err, CaError::MalformedCertificate(_)));
}

#[test]
fn leaf_cannot_act_as_ca() {
    let (root_sk, root_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();
    let (_grandchild_sk, gc_vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &root_sk, &root_vk);
    let leaf = issue_leaf(
        &root_sk,
        &root,
        DistinguishedName::cn("api.example.com"),
        &leaf_vk,
    );
    // Try to issue a grandchild from the leaf — must fail because leaf
    // is not a CA.
    let err = CertificateBuilder::new(DistinguishedName::cn("grand"), &gc_vk)
        .validity_days(30)
        .sign_with(&root_sk, &leaf)
        .unwrap_err();
    assert!(matches!(err, CaError::NotACa(_)));
}

#[test]
fn issuer_mismatch_in_chain_rejected() {
    // Build two independent trust trees, then try to verify a leaf from
    // tree-A using tree-B's root as the trust anchor in a chain that
    // doesn't actually match. The issuer DN inside the leaf won't match
    // tree-B's root subject DN.
    let (root_a_sk, root_a_vk) = fresh_kp();
    let (root_b_sk, root_b_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();
    let root_a = root_ca(DistinguishedName::cn("Root A"), &root_a_sk, &root_a_vk);
    let root_b = root_ca(DistinguishedName::cn("Root B"), &root_b_sk, &root_b_vk);
    let leaf_under_a = issue_leaf(&root_a_sk, &root_a, DistinguishedName::cn("api"), &leaf_vk);
    // Now present the chain as [leaf_under_a, root_b] — issuer doesn't match.
    let err = verify_chain(
        &[leaf_under_a, root_b.clone()],
        &[root_b.fingerprint().unwrap()],
    )
    .unwrap_err();
    assert!(matches!(err, CaError::IssuerMismatch), "got {err:?}");
}

#[test]
fn path_length_zero_blocks_grandchild_chain() {
    // Build root with path_length=0 → no intermediates allowed under it.
    let (root_sk, root_vk) = fresh_kp();
    let (int_sk, int_vk) = fresh_kp();
    let (_leaf_sk, leaf_vk) = fresh_kp();
    let root = CertificateBuilder::new(DistinguishedName::cn("Root"), &root_vk)
        .ca(Some(0))
        .validity_days(3650)
        .with_key_usage(KeyUsage::KeyCertSign)
        .self_sign(&root_sk)
        .unwrap();
    let intermediate = issue_intermediate(
        &root_sk,
        &root,
        DistinguishedName::cn("Int"),
        &int_vk,
        Some(0),
    );
    let leaf = issue_leaf(
        &int_sk,
        &intermediate,
        DistinguishedName::cn("api"),
        &leaf_vk,
    );
    let err = verify_chain(
        &[leaf, intermediate, root.clone()],
        &[root.fingerprint().unwrap()],
    )
    .unwrap_err();
    assert!(matches!(err, CaError::PathLengthExceeded(_)), "got {err:?}");
}

#[test]
fn serial_numbers_are_unique_per_cert() {
    // Issue two leafs from the same root, confirm serials differ.
    let (root_sk, root_vk) = fresh_kp();
    let (_a_sk, a_vk) = fresh_kp();
    let (_b_sk, b_vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &root_sk, &root_vk);
    let a = issue_leaf(&root_sk, &root, DistinguishedName::cn("a"), &a_vk);
    let b = issue_leaf(&root_sk, &root, DistinguishedName::cn("b"), &b_vk);
    assert_ne!(a.tbs.serial, b.tbs.serial);
}

#[test]
fn save_load_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (sk, vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &sk, &vk);
    let path = tmp.path().join("root.cert.json");
    root.save_to_file(&path).unwrap();
    let loaded = Certificate::load_from_file(&path).unwrap();
    assert_eq!(loaded, root);
}

#[test]
fn fingerprint_is_stable_for_unchanged_cert() {
    let (sk, vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &sk, &vk);
    let fp1 = root.fingerprint().unwrap();
    let fp2 = root.fingerprint().unwrap();
    assert_eq!(fp1, fp2);
    assert_eq!(fp1.len(), 64);
}

#[test]
fn key_usage_on_root_includes_keycertsign() {
    let (sk, vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &sk, &vk);
    assert!(root.tbs.key_usage.contains(&KeyUsage::KeyCertSign));
}

#[test]
fn signature_algorithm_is_ml_dsa_65() {
    let (sk, vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &sk, &vk);
    assert_eq!(root.signature.algorithm, "ML-DSA-65");
}

#[test]
fn distinguished_name_render_omits_empty_fields() {
    let dn = DistinguishedName::cn("api.example.com").with_o("Acme");
    let s = dn.to_display();
    assert!(s.contains("CN=api.example.com"));
    assert!(s.contains("O=Acme"));
    assert!(!s.contains("OU=")); // not set
}

#[test]
fn version_mismatch_rejected_on_load() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (sk, vk) = fresh_kp();
    let root = root_ca(DistinguishedName::cn("Root"), &sk, &vk);
    let path = tmp.path().join("root.cert.json");
    root.save_to_file(&path).unwrap();
    // Bump version to an unsupported value.
    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    json["tbs"]["version"] = serde_json::json!(99);
    std::fs::write(&path, json.to_string()).unwrap();
    let err = Certificate::load_from_file(&path).unwrap_err();
    assert!(
        matches!(err, CaError::UnsupportedVersion(99)),
        "got {err:?}"
    );
}

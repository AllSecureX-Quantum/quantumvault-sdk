//! End-to-end tests for the archive sealer + verifier.
//!
//! These exercise the public library API against a real on-disk archive
//! built in a per-test tempdir. All tests are offline and deterministic.

use std::fs;
use std::path::{Path, PathBuf};

use quantumvault_archive::{
    generate_keypair, seal_directory, verify_directory, ArchiveSigningKey, ArchiveVerifyingKey,
    Manifest, SealOptions, MANIFEST_FILE_NAME,
};
use tempfile::TempDir;

// -------- helpers ------------------------------------------------------

fn fresh_kp() -> (ArchiveSigningKey, ArchiveVerifyingKey) {
    generate_keypair().expect("generate_keypair")
}

fn write(root: &Path, rel: &str, content: &[u8]) -> PathBuf {
    let abs = root.join(rel);
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&abs, content).unwrap();
    abs
}

// -------- Round-trip ---------------------------------------------------

#[test]
fn seal_and_verify_single_file() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "report.pdf", b"the report bytes");
    let (sk, vk) = fresh_kp();

    let report = seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    assert_eq!(report.files_sealed, 1);
    assert!(report.manifest_path.exists());

    let v = verify_directory(tmp.path(), Some(&vk)).unwrap();
    assert!(v.all_sealed_files_pass());
    assert_eq!(v.verified.len(), 1);
    assert!(v.missing.is_empty());
}

#[test]
fn seal_and_verify_many_files() {
    let tmp = TempDir::new().unwrap();
    for i in 0..10 {
        write(
            tmp.path(),
            &format!("file-{i:02}.txt"),
            format!("content {i}").as_bytes(),
        );
    }
    let (sk, vk) = fresh_kp();
    let report = seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    assert_eq!(report.files_sealed, 10);
    let v = verify_directory(tmp.path(), Some(&vk)).unwrap();
    assert!(v.all_sealed_files_pass());
    assert_eq!(v.verified.len(), 10);
}

#[test]
fn seal_handles_nested_directories() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "a/b/c/deep.txt", b"deep");
    write(tmp.path(), "a/sibling.txt", b"sib");
    write(tmp.path(), "top.txt", b"top");
    let (sk, vk) = fresh_kp();
    let report = seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    assert_eq!(report.files_sealed, 3);
    let v = verify_directory(tmp.path(), Some(&vk)).unwrap();
    assert!(v.all_sealed_files_pass());
}

#[test]
fn seal_empty_directory() {
    let tmp = TempDir::new().unwrap();
    let (sk, vk) = fresh_kp();
    let report = seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    assert_eq!(report.files_sealed, 0);
    let v = verify_directory(tmp.path(), Some(&vk)).unwrap();
    assert!(v.all_sealed_files_pass());
}

#[test]
fn seal_skips_manifest_on_reseal() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "a.txt", b"alpha");
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    // Re-seal: the existing manifest must not be sealed into itself.
    let report = seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    assert_eq!(
        report.files_sealed, 1,
        "re-seal should ignore the manifest file"
    );
}

// -------- Tamper detection ---------------------------------------------

#[test]
fn tampered_file_content_detected() {
    let tmp = TempDir::new().unwrap();
    let f = write(tmp.path(), "data.bin", b"original");
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();

    // Tamper.
    fs::write(&f, b"tampered").unwrap();
    let v = verify_directory(tmp.path(), Some(&vk)).unwrap();
    assert!(!v.all_sealed_files_pass());
    assert_eq!(v.hash_mismatch.len(), 1);
    assert!(v.hash_mismatch[0].ends_with("data.bin"));
}

#[test]
fn file_deletion_detected() {
    let tmp = TempDir::new().unwrap();
    let f = write(tmp.path(), "secret.dat", b"x");
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();

    fs::remove_file(&f).unwrap();
    let v = verify_directory(tmp.path(), Some(&vk)).unwrap();
    assert!(!v.all_sealed_files_pass());
    assert_eq!(v.missing.len(), 1);
}

#[test]
fn manifest_signature_swap_detected() {
    // Swap the signature for one entry with the signature for another:
    // the per-file hashes won't match the swapped signature, so verify
    // should fail.
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "a.txt", b"alpha");
    write(tmp.path(), "b.txt", b"beta");
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();

    let manifest_path = tmp.path().join(MANIFEST_FILE_NAME);
    let mut manifest = Manifest::load(&manifest_path).unwrap();
    let (a, b) = manifest.entries.iter_mut().fold((None, None), |(a, b), e| {
        if e.path == "a.txt" {
            (Some(&mut e.signature), b)
        } else {
            (a, Some(&mut e.signature))
        }
    });
    // Swap the two signatures.
    if let (Some(a_sig), Some(b_sig)) = (a, b) {
        std::mem::swap(a_sig, b_sig);
    }
    manifest.save_atomic(&manifest_path).unwrap();

    let v = verify_directory(tmp.path(), Some(&vk)).unwrap();
    assert_eq!(v.signature_invalid.len(), 2, "swapped sigs must both fail");
}

#[test]
fn extra_file_on_disk_reported_but_not_failure() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "sealed.txt", b"sealed at time T");
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();

    // Add a new file AFTER seal — the manifest doesn't know about it.
    write(tmp.path(), "added-later.txt", b"snuck in");
    let v = verify_directory(tmp.path(), Some(&vk)).unwrap();
    assert!(v.all_sealed_files_pass(), "sealed files unchanged → pass");
    assert_eq!(v.extra_on_disk.len(), 1);
}

// -------- Key-substitution defence ------------------------------------

#[test]
fn verify_rejects_substituted_verifying_key() {
    // Attacker seals files with their OWN key, planting the matching
    // verifying key into the manifest. The caller passes the *expected*
    // verifying key; verify must refuse.
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "report.pdf", b"x");
    let (attacker_sk, attacker_vk) = fresh_kp();
    seal_directory(
        tmp.path(),
        &attacker_sk,
        &attacker_vk,
        &SealOptions::default(),
    )
    .unwrap();

    // The true verifying key the customer expects.
    let (_real_sk, real_vk) = fresh_kp();
    let err = verify_directory(tmp.path(), Some(&real_vk)).unwrap_err();
    assert!(matches!(
        err,
        quantumvault_archive::ArchiveError::VerifyingKeyMismatch
    ));
}

#[test]
fn verify_without_expected_key_uses_manifest_key() {
    // No expected key → use whatever the manifest claims. This is the
    // "no defence" mode, useful for local quick checks.
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "report.pdf", b"x");
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    let v = verify_directory(tmp.path(), None).unwrap();
    assert!(v.all_sealed_files_pass());
}

// -------- SealOptions filters -----------------------------------------

#[test]
fn skip_hidden_default_excludes_dotfiles() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), ".hidden", b"x");
    write(tmp.path(), "visible.txt", b"y");
    let (sk, vk) = fresh_kp();
    let report = seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    assert_eq!(report.files_sealed, 1);
    assert_eq!(report.files_skipped, 1);
}

#[test]
fn include_hidden_seals_dotfiles() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), ".hidden", b"x");
    write(tmp.path(), "visible.txt", b"y");
    let (sk, vk) = fresh_kp();
    let opts = SealOptions {
        skip_hidden: false,
        ..SealOptions::default()
    };
    let report = seal_directory(tmp.path(), &sk, &vk, &opts).unwrap();
    assert_eq!(report.files_sealed, 2);
}

#[test]
fn max_file_size_filter_works() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "small.txt", b"x");
    write(tmp.path(), "big.bin", &vec![0xABu8; 10_000]);
    let (sk, vk) = fresh_kp();
    let opts = SealOptions {
        max_file_size_bytes: Some(100),
        ..SealOptions::default()
    };
    let report = seal_directory(tmp.path(), &sk, &vk, &opts).unwrap();
    assert_eq!(report.files_sealed, 1, "big.bin filtered");
    assert_eq!(report.files_skipped, 1);
}

// -------- Manifest schema ---------------------------------------------

#[test]
fn manifest_entries_are_sorted_by_path() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "zebra.txt", b"z");
    write(tmp.path(), "apple.txt", b"a");
    write(tmp.path(), "mango.txt", b"m");
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    let manifest = Manifest::load(&tmp.path().join(MANIFEST_FILE_NAME)).unwrap();
    let paths: Vec<&str> = manifest.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, vec!["apple.txt", "mango.txt", "zebra.txt"]);
}

#[test]
fn manifest_has_expected_top_level_shape() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "a.txt", b"x");
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    let manifest_path = tmp.path().join(MANIFEST_FILE_NAME);
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["algorithm"], "SLH-DSA-SHAKE-256s");
    assert!(json["verifying_key"].is_string());
    assert!(json["entries"].is_array());
    assert!(json["entries"][0]["path"].is_string());
    assert!(json["entries"][0]["sha3_256"].is_string());
    assert!(json["entries"][0]["signature"].is_string());
}

#[test]
fn manifest_load_rejects_unsupported_version() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "a.txt", b"x");
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    let manifest_path = tmp.path().join(MANIFEST_FILE_NAME);
    let mut json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    json["version"] = serde_json::json!(99);
    fs::write(&manifest_path, json.to_string()).unwrap();
    let err = Manifest::load(&manifest_path).unwrap_err();
    assert!(matches!(
        err,
        quantumvault_archive::ArchiveError::UnsupportedManifestVersion(99)
    ));
}

// -------- Key file round-trip -----------------------------------------

#[test]
fn keypair_save_load_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let (sk, vk) = fresh_kp();
    let sk_path = tmp.path().join("sk.json");
    let vk_path = tmp.path().join("vk.json");
    sk.save_to_file(&sk_path).unwrap();
    vk.save_to_file(&vk_path).unwrap();

    // Load back, use to seal, verify with original.
    let sk2 = ArchiveSigningKey::load_from_file(&sk_path).unwrap();
    let vk2 = ArchiveVerifyingKey::load_from_file(&vk_path).unwrap();

    let archive = TempDir::new().unwrap();
    write(archive.path(), "x.txt", b"data");
    seal_directory(archive.path(), &sk2, &vk2, &SealOptions::default()).unwrap();
    let v = verify_directory(archive.path(), Some(&vk2)).unwrap();
    assert!(v.all_sealed_files_pass());
}

// -------- Verify on missing/never-sealed dir --------------------------

#[test]
fn verify_unsealed_directory_errors() {
    let tmp = TempDir::new().unwrap();
    write(tmp.path(), "a.txt", b"x");
    let err = verify_directory(tmp.path(), None).unwrap_err();
    assert!(matches!(
        err,
        quantumvault_archive::ArchiveError::ManifestMissing(_)
    ));
}

#[test]
fn seal_missing_directory_errors() {
    let missing = std::path::Path::new("/this/should/never/exist/anywhere-42");
    let (sk, vk) = fresh_kp();
    let err = seal_directory(missing, &sk, &vk, &SealOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        quantumvault_archive::ArchiveError::ArchiveRootMissing(_)
    ));
}

#[test]
fn seal_when_root_is_a_file_errors() {
    let tmp = TempDir::new().unwrap();
    let f = tmp.path().join("a.txt");
    fs::write(&f, b"x").unwrap();
    let (sk, vk) = fresh_kp();
    let err = seal_directory(&f, &sk, &vk, &SealOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        quantumvault_archive::ArchiveError::ArchiveRootNotDirectory(_)
    ));
}

// -------- Large file --------------------------------------------------

#[test]
fn one_mib_file_roundtrips() {
    let tmp = TempDir::new().unwrap();
    let payload = vec![0x5Au8; 1024 * 1024];
    write(tmp.path(), "big.dat", &payload);
    let (sk, vk) = fresh_kp();
    seal_directory(tmp.path(), &sk, &vk, &SealOptions::default()).unwrap();
    let v = verify_directory(tmp.path(), Some(&vk)).unwrap();
    assert!(v.all_sealed_files_pass());
    assert_eq!(v.verified.len(), 1);
}

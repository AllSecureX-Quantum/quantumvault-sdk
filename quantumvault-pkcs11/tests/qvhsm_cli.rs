//! End-to-end smoke for the `qvhsm` binary.
//!
//! Runs the real built binary against a temp dir. Goal: prove the
//! golden path (init-master -> wrap -> unwrap) works as documented
//! and that tamper / wrong-AAD cases produce non-zero exits.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn bin() -> PathBuf {
    // CARGO_BIN_EXE_qvhsm is set by Cargo for integration tests of
    // this crate — points at the freshly built `qvhsm` binary.
    PathBuf::from(env!("CARGO_BIN_EXE_qvhsm"))
}

#[test]
fn golden_path_init_wrap_unwrap() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    let plaintext = tmp.path().join("pqc.sk");
    let wrapped = tmp.path().join("pqc.sk.wrapped.json");
    let recovered = tmp.path().join("pqc.sk.recovered");

    std::fs::write(&plaintext, b"pretend this is an ML-DSA-65 secret key").unwrap();

    // init-master
    let st = Command::new(bin())
        .args(["init-master", "--label", "dev-master", "--out"])
        .arg(&kek)
        .status()
        .expect("init-master");
    assert!(st.success(), "init-master failed");
    assert!(kek.exists());

    // wrap
    let st = Command::new(bin())
        .args(["wrap", "--kek"])
        .arg(&kek)
        .args(["--in"])
        .arg(&plaintext)
        .args(["--out"])
        .arg(&wrapped)
        .args(["--aad", "acme-account-7c3d::ML-DSA-65"])
        .status()
        .expect("wrap");
    assert!(st.success(), "wrap failed");
    assert!(wrapped.exists());

    // unwrap
    let st = Command::new(bin())
        .args(["unwrap", "--kek"])
        .arg(&kek)
        .args(["--in"])
        .arg(&wrapped)
        .args(["--out"])
        .arg(&recovered)
        .args(["--aad", "acme-account-7c3d::ML-DSA-65"])
        .status()
        .expect("unwrap");
    assert!(st.success(), "unwrap failed");

    let original = std::fs::read(&plaintext).unwrap();
    let after = std::fs::read(&recovered).unwrap();
    assert_eq!(original, after, "recovered plaintext mismatch");
}

#[test]
fn wrong_aad_exits_nonzero() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    let plaintext = tmp.path().join("pqc.sk");
    let wrapped = tmp.path().join("pqc.sk.wrapped.json");
    let recovered = tmp.path().join("pqc.sk.recovered");

    std::fs::write(&plaintext, b"sk").unwrap();
    assert!(Command::new(bin())
        .args(["init-master", "--label", "k", "--out"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());
    assert!(Command::new(bin())
        .args(["wrap", "--kek"])
        .arg(&kek)
        .args(["--in"])
        .arg(&plaintext)
        .args(["--out"])
        .arg(&wrapped)
        .args(["--aad", "intended-purpose"])
        .status()
        .unwrap()
        .success());

    // Try to unwrap with a different AAD — should fail.
    let st = Command::new(bin())
        .args(["unwrap", "--kek"])
        .arg(&kek)
        .args(["--in"])
        .arg(&wrapped)
        .args(["--out"])
        .arg(&recovered)
        .args(["--aad", "WRONG-purpose"])
        .status()
        .unwrap();
    assert!(!st.success(), "unwrap with wrong AAD should fail");
}

#[test]
fn init_master_refuses_to_overwrite() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    assert!(Command::new(bin())
        .args(["init-master", "--label", "k", "--out"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());
    let st = Command::new(bin())
        .args(["init-master", "--label", "k", "--out"])
        .arg(&kek)
        .status()
        .unwrap();
    assert!(
        !st.success(),
        "init-master must refuse to overwrite an existing KEK file"
    );
}

#[test]
fn inspect_prints_metadata_without_decryption() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    let plaintext = tmp.path().join("pqc.sk");
    let wrapped = tmp.path().join("pqc.sk.wrapped.json");

    std::fs::write(&plaintext, b"sk").unwrap();
    assert!(Command::new(bin())
        .args(["init-master", "--label", "k", "--out"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());
    assert!(Command::new(bin())
        .args(["wrap", "--kek"])
        .arg(&kek)
        .args(["--in"])
        .arg(&plaintext)
        .args(["--out"])
        .arg(&wrapped)
        .args(["--aad", "scope-A"])
        .status()
        .unwrap()
        .success());

    let out = Command::new(bin())
        .args(["inspect", "--in"])
        .arg(&wrapped)
        .output()
        .unwrap();
    assert!(out.status.success(), "inspect failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("AES-256-GCM"), "{stdout}");
    assert!(stdout.contains("scope-A"), "AAD should be visible: {stdout}");
}

#[test]
fn info_shows_backend() {
    let out = Command::new(bin()).arg("info").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("backend"), "{s}");
    assert!(s.contains("envelope"), "{s}");
}

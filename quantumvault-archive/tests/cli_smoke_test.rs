//! Smoke tests for the `qvarchive` binary.
//!
//! We invoke the binary the way a user actually would, against a fresh
//! tempdir, and check exit codes + stdout shape. This is the
//! customer-facing path — if any of these break, the CLI is broken.

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

fn qvarchive() -> Command {
    Command::cargo_bin("qvarchive").expect("qvarchive bin")
}

#[test]
fn keygen_writes_two_files() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    qvarchive()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    assert!(keys.join("archive.signing.json").exists());
    assert!(keys.join("archive.verifying.json").exists());
}

#[test]
fn end_to_end_seal_and_verify_clean() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let archive = tmp.path().join("archive");
    fs::create_dir_all(&archive).unwrap();
    fs::write(archive.join("a.txt"), b"alpha").unwrap();
    fs::write(archive.join("b.txt"), b"beta").unwrap();

    qvarchive()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();

    qvarchive()
        .args(["seal"])
        .arg(&archive)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success()
        .stdout(predicates::str::contains("sealed 2 files"));

    qvarchive()
        .args(["verify"])
        .arg(&archive)
        .args(["--key"])
        .arg(keys.join("archive.verifying.json"))
        .assert()
        .success()
        .stdout(predicates::str::contains("all sealed files verified"));
}

#[test]
fn verify_exits_nonzero_when_tampered() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let archive = tmp.path().join("archive");
    fs::create_dir_all(&archive).unwrap();
    fs::write(archive.join("doc.pdf"), b"original").unwrap();

    qvarchive()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    qvarchive()
        .args(["seal"])
        .arg(&archive)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success();

    // Tamper.
    fs::write(archive.join("doc.pdf"), b"tampered!").unwrap();

    qvarchive()
        .args(["verify"])
        .arg(&archive)
        .args(["--key"])
        .arg(keys.join("archive.verifying.json"))
        .assert()
        .failure() // exit code != 0
        .stdout(predicates::str::contains("verification FAILED"));
}

#[test]
fn status_on_unsealed_dir_exits_nonzero() {
    let tmp = TempDir::new().unwrap();
    let archive = tmp.path().join("archive");
    fs::create_dir_all(&archive).unwrap();
    fs::write(archive.join("a.txt"), b"x").unwrap();

    qvarchive()
        .args(["status"])
        .arg(&archive)
        .assert()
        .failure()
        .stdout(predicates::str::contains("unsealed"));
}

#[test]
fn status_after_seal_reports_file_count() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let archive = tmp.path().join("archive");
    fs::create_dir_all(&archive).unwrap();
    fs::write(archive.join("a.txt"), b"x").unwrap();
    fs::write(archive.join("b.txt"), b"y").unwrap();
    fs::write(archive.join("c.txt"), b"z").unwrap();

    qvarchive()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    qvarchive()
        .args(["seal"])
        .arg(&archive)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success();

    qvarchive()
        .args(["status"])
        .arg(&archive)
        .assert()
        .success()
        .stdout(predicates::str::contains("Entries      : 3"));
}

#[test]
fn verify_with_substituted_verifying_key_fails() {
    let tmp = TempDir::new().unwrap();
    let attacker_keys = tmp.path().join("attacker");
    let real_keys = tmp.path().join("real");
    let archive = tmp.path().join("archive");
    fs::create_dir_all(&archive).unwrap();
    fs::write(archive.join("doc.pdf"), b"data").unwrap();

    // Attacker generates their own keys and seals.
    qvarchive()
        .args(["keygen", "--out"])
        .arg(&attacker_keys)
        .assert()
        .success();
    qvarchive()
        .args(["seal"])
        .arg(&archive)
        .args(["--key"])
        .arg(&attacker_keys)
        .assert()
        .success();

    // Customer generated a different key out-of-band.
    qvarchive()
        .args(["keygen", "--out"])
        .arg(&real_keys)
        .assert()
        .success();

    // Customer verifies against the REAL key — must reject the swap.
    qvarchive()
        .args(["verify"])
        .arg(&archive)
        .args(["--key"])
        .arg(real_keys.join("archive.verifying.json"))
        .assert()
        .failure(); // verifying-key-mismatch error
}

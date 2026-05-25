//! CLI smoke tests against the real `qvca` binary.

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

fn qvca() -> Command {
    Command::cargo_bin("qvca").expect("qvca bin")
}

#[test]
fn init_root_creates_three_files() {
    let tmp = TempDir::new().unwrap();
    let root_dir = tmp.path().join("root");
    qvca()
        .args(["init-root", "--out"])
        .arg(&root_dir)
        .args(["--cn", "Root CA", "--validity-years", "1"])
        .assert()
        .success();
    assert!(root_dir.join("root.signing.json").exists());
    assert!(root_dir.join("root.verifying.json").exists());
    assert!(root_dir.join("root.cert.json").exists());
}

#[test]
fn end_to_end_three_level_chain_verifies() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    let intermediate = tmp.path().join("int");
    let leaf = tmp.path().join("leaf");

    qvca()
        .args(["init-root", "--out"])
        .arg(&root)
        .args([
            "--cn",
            "Root",
            "--validity-years",
            "5",
            "--path-length",
            "1",
        ])
        .assert()
        .success();

    qvca()
        .args(["issue-intermediate", "--parent"])
        .arg(&root)
        .args(["--out"])
        .arg(&intermediate)
        .args([
            "--cn",
            "Intermediate",
            "--validity-years",
            "2",
            "--path-length",
            "0",
        ])
        .assert()
        .success();

    qvca()
        .args(["issue-leaf", "--parent"])
        .arg(&intermediate)
        .args(["--out"])
        .arg(&leaf)
        .args(["--cn", "api.example.com", "--validity-days", "90"])
        .assert()
        .success();

    qvca()
        .args(["verify", "--leaf"])
        .arg(leaf.join("leaf.cert.json"))
        .args(["--intermediate"])
        .arg(intermediate.join("intermediate.cert.json"))
        .args(["--trust-root"])
        .arg(root.join("root.cert.json"))
        .assert()
        .success()
        .stdout(predicates::str::contains("chain verified"));
}

#[test]
fn verify_fails_when_leaf_subject_tampered() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    let leaf = tmp.path().join("leaf");
    qvca()
        .args(["init-root", "--out"])
        .arg(&root)
        .args(["--cn", "Root", "--validity-years", "5"])
        .assert()
        .success();
    qvca()
        .args(["issue-leaf", "--parent"])
        .arg(&root)
        .args(["--out"])
        .arg(&leaf)
        .args(["--cn", "api.example.com"])
        .assert()
        .success();

    // Tamper.
    let leaf_path = leaf.join("leaf.cert.json");
    let mut json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&leaf_path).unwrap()).unwrap();
    json["tbs"]["subject"]["cn"] = serde_json::json!("attacker.evil.com");
    fs::write(&leaf_path, json.to_string()).unwrap();

    qvca()
        .args(["verify", "--leaf"])
        .arg(&leaf_path)
        .args(["--trust-root"])
        .arg(root.join("root.cert.json"))
        .assert()
        .failure()
        .stdout(predicates::str::contains("CHAIN VERIFICATION FAILED"));
}

#[test]
fn verify_fails_when_trust_root_swapped() {
    let tmp = TempDir::new().unwrap();
    let real_root = tmp.path().join("real_root");
    let fake_root = tmp.path().join("fake_root");
    let leaf = tmp.path().join("leaf");
    qvca()
        .args(["init-root", "--out"])
        .arg(&real_root)
        .args(["--cn", "Real Root"])
        .assert()
        .success();
    qvca()
        .args(["init-root", "--out"])
        .arg(&fake_root)
        .args(["--cn", "Fake Root"])
        .assert()
        .success();
    qvca()
        .args(["issue-leaf", "--parent"])
        .arg(&real_root)
        .args(["--out"])
        .arg(&leaf)
        .args(["--cn", "api"])
        .assert()
        .success();

    // Try to verify with the fake root as trust anchor — must fail.
    qvca()
        .args(["verify", "--leaf"])
        .arg(leaf.join("leaf.cert.json"))
        .args(["--trust-root"])
        .arg(fake_root.join("root.cert.json"))
        .assert()
        .failure();
}

#[test]
fn info_prints_expected_fields() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    qvca()
        .args(["init-root", "--out"])
        .arg(&root)
        .args(["--cn", "Root", "--o", "Test Org", "--c", "IN"])
        .assert()
        .success();
    qvca()
        .args(["info", "--cert"])
        .arg(root.join("root.cert.json"))
        .assert()
        .success()
        .stdout(predicates::str::contains("Algorithm        : ML-DSA-65"))
        .stdout(predicates::str::contains("Is CA            : true"))
        .stdout(predicates::str::contains("Test Org"));
}

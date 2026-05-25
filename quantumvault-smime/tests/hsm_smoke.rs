//! HSM-wrapped key flow for qvsmime.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn bin(name: &str) -> PathBuf {
    let qvsmime = PathBuf::from(env!("CARGO_BIN_EXE_qvsmime"));
    let dir = qvsmime.parent().expect("exe parent");
    dir.join(name)
}

const RAW_EMAIL: &str = "\
From: alice@example.com\r\n\
To: bob@example.com\r\n\
Subject: HSM smoke\r\n\
\r\n\
Body content for HSM-wrapped S/MIME signing test.\r\n";

#[test]
fn hsm_wrapped_keygen_then_sign_verify() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    let keys = tmp.path().join("keys");
    let raw = tmp.path().join("in.eml");
    let signed = tmp.path().join("out.eml");
    fs::write(&raw, RAW_EMAIL).unwrap();

    assert!(Command::new(bin("qvhsm"))
        .args(["init-master", "--label", "smime-smoke", "--out"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());

    // keygen --hsm-kek
    assert!(Command::new(bin("qvsmime"))
        .args(["keygen", "--out"])
        .arg(&keys)
        .args(["--hsm-kek"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());

    let sk_blob = fs::read_to_string(keys.join("smime.signing.json")).unwrap();
    assert!(sk_blob.contains("AES-256-GCM"), "signing key should be wrapped");
    let vk_blob = fs::read_to_string(keys.join("smime.verifying.json")).unwrap();
    assert!(vk_blob.contains("qvsmime-key:v1"));

    // sign --hsm-kek
    assert!(Command::new(bin("qvsmime"))
        .args(["sign", "-i"])
        .arg(&raw)
        .args(["-o"])
        .arg(&signed)
        .args(["--key"])
        .arg(&keys)
        .args(["--hsm-kek"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());

    // verify needs no --hsm-kek (only verifying key is used).
    assert!(Command::new(bin("qvsmime"))
        .args(["verify", "-i"])
        .arg(&signed)
        .args(["--key"])
        .arg(keys.join("smime.verifying.json"))
        .status()
        .unwrap()
        .success());
}

#[test]
fn sign_without_hsm_kek_errors_when_key_wrapped() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    let keys = tmp.path().join("keys");
    let raw = tmp.path().join("in.eml");
    let signed = tmp.path().join("out.eml");
    fs::write(&raw, RAW_EMAIL).unwrap();

    assert!(Command::new(bin("qvhsm"))
        .args(["init-master", "--label", "k", "--out"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());
    assert!(Command::new(bin("qvsmime"))
        .args(["keygen", "--out"])
        .arg(&keys)
        .args(["--hsm-kek"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());

    let out = Command::new(bin("qvsmime"))
        .args(["sign", "-i"])
        .arg(&raw)
        .args(["-o"])
        .arg(&signed)
        .args(["--key"])
        .arg(&keys)
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected sign to fail without --hsm-kek");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("HSM-wrapped") || stderr.contains("--hsm-kek"),
        "expected clear missing-KEK hint, got: {stderr}"
    );
}

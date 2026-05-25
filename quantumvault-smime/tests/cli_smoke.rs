//! End-to-end CLI smoke tests using `assert_cmd` against the real `qvsmime`
//! binary.

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

fn qvsmime() -> Command {
    Command::cargo_bin("qvsmime").expect("qvsmime bin")
}

const SAMPLE_EMAIL: &[u8] = b"From: alice@example.com\r\n\
                              To: bob@example.com\r\n\
                              Subject: hello\r\n\
                              Content-Type: text/plain; charset=utf-8\r\n\
                              \r\n\
                              the payload bytes that get signed\r\n";

#[test]
fn keygen_writes_two_files() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    qvsmime()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    assert!(keys.join("smime.signing.json").exists());
    assert!(keys.join("smime.verifying.json").exists());
}

#[test]
fn end_to_end_sign_and_verify() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let input = tmp.path().join("input.eml");
    let signed = tmp.path().join("signed.eml");
    fs::write(&input, SAMPLE_EMAIL).unwrap();

    qvsmime()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    qvsmime()
        .args(["sign", "-i"])
        .arg(&input)
        .args(["-o"])
        .arg(&signed)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success();

    qvsmime()
        .args(["verify", "-i"])
        .arg(&signed)
        .args(["--key"])
        .arg(keys.join("smime.verifying.json"))
        .assert()
        .success()
        .stdout(predicates::str::contains("signature verified"));
}

#[test]
fn verify_exits_nonzero_when_body_tampered() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let input = tmp.path().join("input.eml");
    let signed = tmp.path().join("signed.eml");
    fs::write(&input, SAMPLE_EMAIL).unwrap();

    qvsmime()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    qvsmime()
        .args(["sign", "-i"])
        .arg(&input)
        .args(["-o"])
        .arg(&signed)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success();

    // Tamper: change one byte in the signed file's body.
    let mut bytes = fs::read(&signed).unwrap();
    let idx = bytes
        .windows(b"the payload bytes".len())
        .position(|w| w == b"the payload bytes")
        .unwrap();
    bytes[idx] = b'X';
    fs::write(&signed, &bytes).unwrap();

    qvsmime()
        .args(["verify", "-i"])
        .arg(&signed)
        .args(["--key"])
        .arg(keys.join("smime.verifying.json"))
        .assert()
        .failure()
        .stdout(predicates::str::contains("VERIFICATION FAILED"));
}

#[test]
fn verify_with_substituted_key_fails() {
    let tmp = TempDir::new().unwrap();
    let attacker = tmp.path().join("attacker");
    let real = tmp.path().join("real");
    let input = tmp.path().join("input.eml");
    let signed = tmp.path().join("signed.eml");
    fs::write(&input, SAMPLE_EMAIL).unwrap();

    qvsmime()
        .args(["keygen", "--out"])
        .arg(&attacker)
        .assert()
        .success();
    qvsmime()
        .args(["sign", "-i"])
        .arg(&input)
        .args(["-o"])
        .arg(&signed)
        .args(["--key"])
        .arg(&attacker)
        .assert()
        .success();
    qvsmime()
        .args(["keygen", "--out"])
        .arg(&real)
        .assert()
        .success();

    qvsmime()
        .args(["verify", "-i"])
        .arg(&signed)
        .args(["--key"])
        .arg(real.join("smime.verifying.json"))
        .assert()
        .failure();
}

#[test]
fn info_prints_envelope_metadata() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let input = tmp.path().join("input.eml");
    let signed = tmp.path().join("signed.eml");
    fs::write(&input, SAMPLE_EMAIL).unwrap();
    qvsmime()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    qvsmime()
        .args(["sign", "-i"])
        .arg(&input)
        .args(["-o"])
        .arg(&signed)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success();

    qvsmime()
        .args(["info", "-i"])
        .arg(&signed)
        .assert()
        .success()
        .stdout(predicates::str::contains("Algorithm    : ML-DSA-65"))
        .stdout(predicates::str::contains("Body sha3_256:"));
}

#[test]
fn body_out_writes_recovered_body() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let input = tmp.path().join("input.eml");
    let signed = tmp.path().join("signed.eml");
    let body = tmp.path().join("body.txt");
    fs::write(&input, SAMPLE_EMAIL).unwrap();
    qvsmime()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    qvsmime()
        .args(["sign", "-i"])
        .arg(&input)
        .args(["-o"])
        .arg(&signed)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success();

    qvsmime()
        .args(["verify", "-i"])
        .arg(&signed)
        .args(["--key"])
        .arg(keys.join("smime.verifying.json"))
        .args(["--body-out"])
        .arg(&body)
        .assert()
        .success();

    let recovered = fs::read(&body).unwrap();
    assert!(recovered.windows(20).any(|w| w == b"the payload bytes th"));
}

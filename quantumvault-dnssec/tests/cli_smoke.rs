//! CLI smoke tests against the real `qvdnssec` binary.

use std::fs;

use assert_cmd::Command;
use tempfile::TempDir;

fn qvdnssec() -> Command {
    Command::cargo_bin("qvdnssec").expect("qvdnssec bin")
}

const ZONE_TEXT: &str = "$ORIGIN example.com.\n\
$TTL 3600\n\
@   IN  SOA  ns1.example.com. admin.example.com. ( 1 3600 600 604800 3600 )\n\
@   IN  NS   ns1.example.com.\n\
@   IN  A    1.2.3.4\n\
api IN  A    1.2.3.5\n";

#[test]
fn keygen_writes_four_files() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    qvdnssec()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    assert!(keys.join("ksk.signing.json").exists());
    assert!(keys.join("ksk.verifying.json").exists());
    assert!(keys.join("zsk.signing.json").exists());
    assert!(keys.join("zsk.verifying.json").exists());
}

#[test]
fn end_to_end_sign_and_verify_passes() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let zone = tmp.path().join("example.com.zone");
    fs::write(&zone, ZONE_TEXT).unwrap();
    qvdnssec()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    qvdnssec()
        .args(["sign-zone", "--zone"])
        .arg(&zone)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success();
    qvdnssec()
        .args(["verify-zone", "--zone"])
        .arg(&zone)
        .args(["--trust-ksk"])
        .arg(keys.join("ksk.verifying.json"))
        .assert()
        .success()
        .stdout(predicates::str::contains("zone verified"));
}

#[test]
fn verify_fails_when_a_record_tampered() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let zone = tmp.path().join("example.com.zone");
    fs::write(&zone, ZONE_TEXT).unwrap();
    qvdnssec()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    qvdnssec()
        .args(["sign-zone", "--zone"])
        .arg(&zone)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success();
    let text = fs::read_to_string(&zone)
        .unwrap()
        .replace("1.2.3.5", "9.9.9.9");
    fs::write(&zone, &text).unwrap();
    qvdnssec()
        .args(["verify-zone", "--zone"])
        .arg(&zone)
        .args(["--trust-ksk"])
        .arg(keys.join("ksk.verifying.json"))
        .assert()
        .failure()
        .stdout(predicates::str::contains("ZONE VERIFICATION FAILED"));
}

#[test]
fn verify_with_wrong_ksk_fails() {
    let tmp = TempDir::new().unwrap();
    let real = tmp.path().join("real_keys");
    let fake = tmp.path().join("fake_keys");
    let zone = tmp.path().join("example.com.zone");
    fs::write(&zone, ZONE_TEXT).unwrap();
    qvdnssec()
        .args(["keygen", "--out"])
        .arg(&real)
        .assert()
        .success();
    qvdnssec()
        .args(["keygen", "--out"])
        .arg(&fake)
        .assert()
        .success();
    qvdnssec()
        .args(["sign-zone", "--zone"])
        .arg(&zone)
        .args(["--key"])
        .arg(&real)
        .assert()
        .success();
    qvdnssec()
        .args(["verify-zone", "--zone"])
        .arg(&zone)
        .args(["--trust-ksk"])
        .arg(fake.join("ksk.verifying.json"))
        .assert()
        .failure()
        .stdout(predicates::str::contains("KSK fingerprint mismatch"));
}

#[test]
fn info_prints_manifest_metadata() {
    let tmp = TempDir::new().unwrap();
    let keys = tmp.path().join("keys");
    let zone = tmp.path().join("example.com.zone");
    fs::write(&zone, ZONE_TEXT).unwrap();
    qvdnssec()
        .args(["keygen", "--out"])
        .arg(&keys)
        .assert()
        .success();
    qvdnssec()
        .args(["sign-zone", "--zone"])
        .arg(&zone)
        .args(["--key"])
        .arg(&keys)
        .assert()
        .success();
    let manifest = zone.with_extension("zone.qvdnssec.manifest.json");
    qvdnssec()
        .args(["info", "--manifest"])
        .arg(&manifest)
        .assert()
        .success()
        .stdout(predicates::str::contains("Zone           : example.com."))
        .stdout(predicates::str::contains("Algorithm      : ML-DSA-65"))
        .stdout(predicates::str::contains("KSK fingerprint"));
}

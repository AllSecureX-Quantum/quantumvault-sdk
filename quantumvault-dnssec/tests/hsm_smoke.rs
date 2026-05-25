//! HSM-wrapped key flow for qvdnssec.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn bin(name: &str) -> PathBuf {
    let qvdnssec = PathBuf::from(env!("CARGO_BIN_EXE_qvdnssec"));
    let dir = qvdnssec.parent().expect("exe parent");
    dir.join(name)
}

const ZONE_TEXT: &str = "$ORIGIN example.com.\n\
$TTL 3600\n\
@   IN  SOA  ns1.example.com. admin.example.com. ( 1 3600 600 604800 3600 )\n\
@   IN  NS   ns1.example.com.\n\
@   IN  A    1.2.3.4\n\
api IN  A    1.2.3.5\n";

#[test]
fn hsm_wrapped_keygen_then_sign_verify() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    let keys = tmp.path().join("keys");
    let zone = tmp.path().join("example.com.zone");
    fs::write(&zone, ZONE_TEXT).unwrap();

    assert!(Command::new(bin("qvhsm"))
        .args(["init-master", "--label", "dnssec-smoke", "--out"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());

    // keygen with --hsm-kek
    assert!(Command::new(bin("qvdnssec"))
        .args(["keygen", "--out"])
        .arg(&keys)
        .args(["--hsm-kek"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());

    // The signing keys on disk should be wrapped envelopes; verifying
    // keys remain plaintext (they're the trust anchors).
    let ksk_sk = fs::read_to_string(keys.join("ksk.signing.json")).unwrap();
    let zsk_sk = fs::read_to_string(keys.join("zsk.signing.json")).unwrap();
    assert!(ksk_sk.contains("AES-256-GCM"), "KSK should be wrapped: {ksk_sk}");
    assert!(zsk_sk.contains("AES-256-GCM"), "ZSK should be wrapped: {zsk_sk}");
    let ksk_vk = fs::read_to_string(keys.join("ksk.verifying.json")).unwrap();
    assert!(
        ksk_vk.contains("qvdnssec-key:v1"),
        "verifying key should NOT be wrapped: {ksk_vk}"
    );

    // sign-zone with --hsm-kek
    assert!(Command::new(bin("qvdnssec"))
        .args(["sign-zone", "--zone"])
        .arg(&zone)
        .args(["--key"])
        .arg(&keys)
        .args(["--hsm-kek"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());

    // verify-zone needs no --hsm-kek (only verifying keys are used).
    let out = Command::new(bin("qvdnssec"))
        .args(["verify-zone", "--zone"])
        .arg(&zone)
        .args(["--trust-ksk"])
        .arg(keys.join("ksk.verifying.json"))
        .output()
        .unwrap();
    assert!(out.status.success(), "verify failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("zone verified"));
}

#[test]
fn sign_zone_without_hsm_kek_errors_when_keys_wrapped() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    let keys = tmp.path().join("keys");
    let zone = tmp.path().join("example.com.zone");
    fs::write(&zone, ZONE_TEXT).unwrap();

    assert!(Command::new(bin("qvhsm"))
        .args(["init-master", "--label", "k", "--out"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());
    assert!(Command::new(bin("qvdnssec"))
        .args(["keygen", "--out"])
        .arg(&keys)
        .args(["--hsm-kek"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());

    let out = Command::new(bin("qvdnssec"))
        .args(["sign-zone", "--zone"])
        .arg(&zone)
        .args(["--key"])
        .arg(&keys)
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected sign-zone to fail without --hsm-kek");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("HSM-wrapped") || stderr.contains("--hsm-kek"),
        "expected clear missing-KEK hint, got: {stderr}"
    );
}

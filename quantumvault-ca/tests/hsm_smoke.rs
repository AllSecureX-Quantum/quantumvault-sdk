//! Integration smoke for the `--hsm-kek` flow on `qvca`.
//!
//! Goal: prove the operator can issue a full chain whose signing keys
//! never sit on disk in cleartext. Spawns the real `qvhsm` to mint a
//! dev KEK, then the real `qvca` to bootstrap a root, issue an
//! intermediate, and issue a leaf — all with `--hsm-kek`. Verifies
//! chain validity against the trust anchor at the end.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn bin(name: &str) -> PathBuf {
    // CARGO_BIN_EXE_<bin> is only set for the *current* crate's bins,
    // so qvhsm (which lives in quantumvault-pkcs11) isn't directly
    // available. Resolve it relative to the current qvca executable —
    // both binaries end up in the same target/debug/ directory.
    let qvca = PathBuf::from(env!("CARGO_BIN_EXE_qvca"));
    let dir = qvca.parent().expect("qvca exe has a parent");
    dir.join(name)
}

#[test]
fn end_to_end_hsm_wrapped_chain() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    let root = tmp.path().join("root");
    let intermediate = tmp.path().join("intermediate");
    let leaf = tmp.path().join("leaf");

    // 1. Mint a dev KEK.
    let st = Command::new(bin("qvhsm"))
        .args(["init-master", "--label", "qvca-hsm-smoke", "--out"])
        .arg(&kek)
        .status()
        .expect("qvhsm init-master");
    assert!(st.success(), "qvhsm init-master failed");

    // 2. Bootstrap a root CA with --hsm-kek. Root signing key on disk
    //    must be a wrapped envelope, not a plaintext qvca-key.
    let st = Command::new(bin("qvca"))
        .args(["init-root", "--out"])
        .arg(&root)
        .args([
            "--cn",
            "Smoke HSM Root",
            "--validity-years",
            "2",
            "--hsm-kek",
        ])
        .arg(&kek)
        .status()
        .expect("qvca init-root");
    assert!(st.success(), "qvca init-root --hsm-kek failed");

    let root_sk_path = root.join("root.signing.json");
    assert!(root_sk_path.exists());
    let sk_blob = std::fs::read_to_string(&root_sk_path).unwrap();
    assert!(
        sk_blob.contains("AES-256-GCM"),
        "root signing key should be wrapped, got: {sk_blob}"
    );
    assert!(
        !sk_blob.contains("qvca-key:v1"),
        "wrapped file must not contain plaintext qvca-key format tag"
    );

    // 3. Issue an intermediate from that wrapped root. --hsm-kek both
    //    unwraps the parent and wraps the new intermediate.
    let st = Command::new(bin("qvca"))
        .args(["issue-intermediate", "--parent"])
        .arg(&root)
        .args(["--out"])
        .arg(&intermediate)
        .args(["--cn", "Smoke HSM Intermediate", "--hsm-kek"])
        .arg(&kek)
        .status()
        .expect("issue-intermediate");
    assert!(st.success(), "qvca issue-intermediate --hsm-kek failed");

    let intermediate_sk = intermediate.join("intermediate.signing.json");
    let intermediate_blob = std::fs::read_to_string(&intermediate_sk).unwrap();
    assert!(
        intermediate_blob.contains("AES-256-GCM"),
        "intermediate signing key should also be wrapped"
    );

    // 4. Issue a leaf from the intermediate.
    let st = Command::new(bin("qvca"))
        .args(["issue-leaf", "--parent"])
        .arg(&intermediate)
        .args(["--out"])
        .arg(&leaf)
        .args([
            "--cn",
            "api.smoke.test",
            "--san",
            "DNS:api.smoke.test",
            "--validity-days",
            "30",
            "--hsm-kek",
        ])
        .arg(&kek)
        .status()
        .expect("issue-leaf");
    assert!(st.success(), "qvca issue-leaf --hsm-kek failed");

    // 5. Verify the chain. Verification only needs verifying keys +
    //    certs, which are NOT wrapped — so no --hsm-kek is needed
    //    here. This proves the wrapped signing keys produced a valid
    //    cryptographic chain end-to-end.
    let st = Command::new(bin("qvca"))
        .args(["verify", "--leaf"])
        .arg(leaf.join("leaf.cert.json"))
        .args(["--intermediate"])
        .arg(intermediate.join("intermediate.cert.json"))
        .args(["--trust-root"])
        .arg(root.join("root.cert.json"))
        .status()
        .expect("qvca verify");
    assert!(st.success(), "chain verify failed");
}

#[test]
fn loading_wrapped_signing_key_without_hsm_kek_errors_clearly() {
    let tmp = TempDir::new().unwrap();
    let kek = tmp.path().join("dev.kek.json");
    let root = tmp.path().join("root");
    let intermediate = tmp.path().join("intermediate");

    assert!(Command::new(bin("qvhsm"))
        .args(["init-master", "--label", "k", "--out"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());
    assert!(Command::new(bin("qvca"))
        .args(["init-root", "--out"])
        .arg(&root)
        .args(["--cn", "Wrapped Root", "--validity-years", "1", "--hsm-kek"])
        .arg(&kek)
        .status()
        .unwrap()
        .success());

    // Now try to issue an intermediate WITHOUT passing --hsm-kek.
    // The parent signing key on disk is wrapped; the loader must
    // refuse and tell the operator to pass --hsm-kek.
    let out = Command::new(bin("qvca"))
        .args(["issue-intermediate", "--parent"])
        .arg(&root)
        .args(["--out"])
        .arg(&intermediate)
        .args(["--cn", "Should-Fail"])
        .output()
        .expect("issue-intermediate");
    assert!(!out.status.success(), "expected non-zero exit, got success");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("HSM-wrapped") || stderr.contains("--hsm-kek"),
        "expected clear missing-KEK hint, got stderr: {stderr}"
    );
}

#[test]
fn wrong_kek_rejects_with_clear_error() {
    let tmp = TempDir::new().unwrap();
    let kek_a = tmp.path().join("a.kek.json");
    let kek_b = tmp.path().join("b.kek.json");
    let root = tmp.path().join("root");
    let intermediate = tmp.path().join("intermediate");

    for (k, label) in [(&kek_a, "a"), (&kek_b, "b")] {
        assert!(Command::new(bin("qvhsm"))
            .args(["init-master", "--label", label, "--out"])
            .arg(k)
            .status()
            .unwrap()
            .success());
    }
    // Bootstrap under KEK a.
    assert!(Command::new(bin("qvca"))
        .args(["init-root", "--out"])
        .arg(&root)
        .args([
            "--cn",
            "Wrong KEK Root",
            "--validity-years",
            "1",
            "--hsm-kek"
        ])
        .arg(&kek_a)
        .status()
        .unwrap()
        .success());

    // Try to unwrap under KEK b.
    let out = Command::new(bin("qvca"))
        .args(["issue-intermediate", "--parent"])
        .arg(&root)
        .args(["--out"])
        .arg(&intermediate)
        .args(["--cn", "Wrong-KEK-Test", "--hsm-kek"])
        .arg(&kek_b)
        .output()
        .expect("issue-intermediate");
    assert!(!out.status.success(), "wrong KEK should fail unwrap");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("hsm:")
            || stderr.contains("AEAD")
            || stderr.contains("tampered")
            || stderr.contains("decrypt"),
        "expected AEAD-failure stderr, got: {stderr}"
    );
}

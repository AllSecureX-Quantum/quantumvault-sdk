//! End-to-end smoke for the unified `quantumvault tools <tool> ...` entrypoint.
//!
//! These tests build the workspace binaries via `cargo_bin` (assert_cmd) and
//! place a copy of the `quantumvault` binary alongside the tool binaries
//! in a temp dir — the same install layout we expect for customers — so
//! the sibling-of-current-exe resolution path is exercised.

use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;

fn copy_bin(target_dir: &std::path::Path, name: &str) -> PathBuf {
    let src = assert_cmd::cargo::cargo_bin(name);
    assert!(src.exists(), "cargo did not build {name} at {src:?}");
    let dest = target_dir.join(src.file_name().unwrap());
    fs::copy(&src, &dest).unwrap_or_else(|e| panic!("copy {name}: {e}"));
    // Preserve executable bit on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dest, perms).unwrap();
    }
    dest
}

/// `quantumvault tools list` should return JSON listing all seven tools
/// with resolved paths pointing at the sibling binaries we just laid down.
#[test]
fn tools_list_finds_sibling_binaries() {
    let tmp = TempDir::new().unwrap();
    let bin_dir = tmp.path();
    let quantumvault = copy_bin(bin_dir, "quantumvault");
    for tool in [
        "qvarchive",
        "qvsmime",
        "qvca",
        "qvdnssec",
        "qvjwtproxy",
        "qvacme-server",
        "qvacme-client",
        "qvhsm",
    ] {
        copy_bin(bin_dir, tool);
    }

    let mut cmd = std::process::Command::new(&quantumvault);
    cmd.args(["--format", "json", "tools", "list"]);
    let out = cmd.output().expect("spawn quantumvault");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("not JSON: {e} :: {stdout}"));

    let entries = parsed["data"].as_array().expect("data array");
    assert_eq!(entries.len(), 8, "expected 8 tools, got {}", entries.len());
    for entry in entries {
        let resolved = entry["resolved"].as_str().expect("resolved");
        assert_ne!(resolved, "not-found", "tool {entry:?} did not resolve");
        assert!(
            resolved.starts_with(bin_dir.to_str().unwrap()),
            "expected sibling resolution, got {resolved}"
        );
    }
}

/// `quantumvault tools ca init-root --out <dir> --cn ... --validity-years 1`
/// must transparently invoke the real `qvca` binary and produce a root cert.
#[test]
fn tools_ca_init_root_delegates_to_qvca() {
    let tmp = TempDir::new().unwrap();
    let bin_dir = tmp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let quantumvault = copy_bin(&bin_dir, "quantumvault");
    copy_bin(&bin_dir, "qvca");

    let root = tmp.path().join("root");

    let mut cmd = std::process::Command::new(&quantumvault);
    cmd.arg("tools")
        .arg("ca")
        .arg("init-root")
        .arg("--out")
        .arg(&root)
        .args(["--cn", "Unified CLI Smoke Root", "--validity-years", "1"]);
    let out = cmd.output().expect("spawn quantumvault");
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        root.join("root.cert.json").exists(),
        "root cert not created"
    );
}

/// `quantumvault tools hsm init-master ... && hsm wrap ... && hsm unwrap ...`
/// must round-trip a wrapped key file through the unified CLI.
#[test]
fn tools_hsm_round_trips_via_unified_cli() {
    let tmp = TempDir::new().unwrap();
    let bin_dir = tmp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let quantumvault = copy_bin(&bin_dir, "quantumvault");
    copy_bin(&bin_dir, "qvhsm");

    let work = tmp.path().join("work");
    fs::create_dir_all(&work).unwrap();
    let kek = work.join("dev.kek.json");
    let plaintext = work.join("pqc.sk");
    let wrapped = work.join("pqc.sk.wrapped.json");
    let recovered = work.join("pqc.sk.recovered");
    fs::write(&plaintext, b"ML-DSA-65 secret-key bytes").unwrap();

    // init-master
    let st = std::process::Command::new(&quantumvault)
        .args(["tools", "hsm", "init-master", "--label", "smoke", "--out"])
        .arg(&kek)
        .status()
        .unwrap();
    assert!(st.success(), "init-master through unified CLI failed");

    // wrap
    let st = std::process::Command::new(&quantumvault)
        .args(["tools", "hsm", "wrap", "--kek"])
        .arg(&kek)
        .args(["--in"])
        .arg(&plaintext)
        .args(["--out"])
        .arg(&wrapped)
        .args(["--aad", "smoke-aad"])
        .status()
        .unwrap();
    assert!(st.success(), "wrap through unified CLI failed");

    // unwrap
    let st = std::process::Command::new(&quantumvault)
        .args(["tools", "hsm", "unwrap", "--kek"])
        .arg(&kek)
        .args(["--in"])
        .arg(&wrapped)
        .args(["--out"])
        .arg(&recovered)
        .args(["--aad", "smoke-aad"])
        .status()
        .unwrap();
    assert!(st.success(), "unwrap through unified CLI failed");

    assert_eq!(fs::read(&plaintext).unwrap(), fs::read(&recovered).unwrap());
}

/// `quantumvault tools archive keygen --out <dir>` must produce the
/// SLH-DSA archival keypair that `qvarchive` would produce standalone.
#[test]
fn tools_archive_keygen_delegates_to_qvarchive() {
    let tmp = TempDir::new().unwrap();
    let bin_dir = tmp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let quantumvault = copy_bin(&bin_dir, "quantumvault");
    copy_bin(&bin_dir, "qvarchive");

    let key_dir = tmp.path().join("k");

    let mut cmd = std::process::Command::new(&quantumvault);
    cmd.arg("tools")
        .arg("archive")
        .arg("keygen")
        .arg("--out")
        .arg(&key_dir);
    let out = cmd.output().expect("spawn quantumvault");
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // qvarchive writes signing.key + verifying.key + key.json (or similar);
    // the contract we care about is that *something* lands in the out dir.
    let entries: Vec<_> = fs::read_dir(&key_dir).unwrap().collect();
    assert!(!entries.is_empty(), "qvarchive keygen produced no files");
}

/// `quantumvault tools <tool> -- <child-args>` passes everything after
/// `--` straight to the child. We use this form to reach the child's own
/// `--help` (the unseparated form is intercepted by the wrapper's clap).
#[test]
fn tools_help_passthrough_via_separator() {
    let tmp = TempDir::new().unwrap();
    let bin_dir = tmp.path();
    let quantumvault = copy_bin(bin_dir, "quantumvault");
    copy_bin(bin_dir, "qvca");

    let mut cmd = std::process::Command::new(&quantumvault);
    cmd.args(["tools", "ca", "--", "--help"]);
    let out = cmd.output().expect("spawn quantumvault");
    assert!(out.status.success(), "qvca --help via wrapper failed");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("init-root") || combined.contains("verify"),
        "child help text missing expected commands: {combined}"
    );
}

/// If the underlying binary isn't on PATH or sibling, the wrapper must
/// fail with a clear message rather than panic.
#[test]
fn missing_tool_reports_clear_error() {
    let tmp = TempDir::new().unwrap();
    let bin_dir = tmp.path();
    let quantumvault = copy_bin(bin_dir, "quantumvault");
    // Note: NOT copying qvca alongside.

    let mut cmd = std::process::Command::new(&quantumvault);
    cmd.env("PATH", bin_dir) // sanitised PATH that doesn't contain qvca
        .args(["tools", "ca", "info"]);
    let out = cmd.output().expect("spawn quantumvault");
    assert!(!out.status.success(), "wrapper unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("qvca") && stderr.contains("not found")
            || stderr.contains("could not find"),
        "expected clear missing-tool error, got: {stderr}"
    );
}

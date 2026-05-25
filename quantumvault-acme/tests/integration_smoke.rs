//! End-to-end integration smoke: bootstrap a CA with qvca, start
//! qvacme-server in the background, run qvacme-client through the full
//! provisioning flow, verify the issued cert with qvca.

use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::TempDir;

fn bin(name: &str) -> Command {
    Command::cargo_bin(name).expect("bin")
}

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn next_port() -> u16 {
    // Bind to an ephemeral port, then close — kernel won't immediately
    // reuse, so it's almost-certainly free for the next bind. Avoids
    // the "two tests pick the same hard-coded port" footgun.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

#[test]
fn end_to_end_register_issue_verify() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    let account = tmp.path().join("account");
    let cert_out = tmp.path().join("cert");
    std::fs::create_dir_all(&account).unwrap();
    std::fs::create_dir_all(&cert_out).unwrap();

    // 1. Bootstrap a root CA.
    let st = bin("qvca")
        .args(["init-root", "--out"])
        .arg(&root)
        .args(["--cn", "Test Root", "--validity-years", "5"])
        .status()
        .expect("qvca init-root");
    assert!(st.success(), "qvca init-root failed");

    // 2. Start qvacme-server in the background.
    let port = next_port();
    let url = format!("http://127.0.0.1:{port}");
    let mut server = bin("qvacme-server");
    server
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--auto-approve",
            "--parent",
        ])
        .arg(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = server.spawn().expect("spawn qvacme-server");
    let _guard = ServerGuard(child);

    // Wait for the server to come up — poll /v1/health.
    let mut up = false;
    for _ in 0..30 {
        sleep(Duration::from_millis(200));
        let ok = bin("qvacme-client")
            .args(["ping", "--server", &url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            up = true;
            break;
        }
    }
    assert!(up, "qvacme-server did not become healthy");

    // 3. Account keygen + register.
    let st = bin("qvacme-client")
        .args(["account-keygen", "--out"])
        .arg(&account)
        .status()
        .expect("account-keygen");
    assert!(st.success());

    let record_path = account.join("record.json");
    let st = bin("qvacme-client")
        .args(["register", "--server", &url, "--account"])
        .arg(&account)
        .args(["--out"])
        .arg(&record_path)
        .status()
        .expect("register");
    assert!(st.success(), "register failed");
    assert!(record_path.exists());

    // 4. Issue.
    let st = bin("qvacme-client")
        .args(["issue", "--server", &url, "--account"])
        .arg(&account)
        .args(["--account-record"])
        .arg(&record_path)
        .args([
            "--cn",
            "api.example.com",
            "--san",
            "DNS:api.example.com",
            "--validity-days",
            "60",
            "--out",
        ])
        .arg(&cert_out)
        .args(["--max-polls", "10", "--poll-ms", "200"])
        .status()
        .expect("issue");
    assert!(st.success(), "issue failed");
    let cert_path = cert_out.join("certificate.json");
    assert!(cert_path.exists());

    // 5. Verify the cert with qvca against the trust root.
    let st = bin("qvca")
        .args(["verify", "--leaf"])
        .arg(&cert_path)
        .args(["--trust-root"])
        .arg(root.join("root.cert.json"))
        .status()
        .expect("qvca verify");
    assert!(st.success(), "qvca verify failed on ACME-issued cert");
}

/// Server runs with `--db <sqlite>`; we register an account, kill the
/// server, restart against the same db file, and re-use the same
/// account record to issue a second cert. If state didn't survive, the
/// second issue would fail with `unknown_account`.
#[test]
fn sqlite_state_survives_server_restart() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    let account = tmp.path().join("account");
    let db = tmp.path().join("acme.db");
    let cert_a = tmp.path().join("cert-a");
    let cert_b = tmp.path().join("cert-b");
    std::fs::create_dir_all(&account).unwrap();
    std::fs::create_dir_all(&cert_a).unwrap();
    std::fs::create_dir_all(&cert_b).unwrap();

    // Bootstrap root CA.
    assert!(bin("qvca")
        .args(["init-root", "--out"])
        .arg(&root)
        .args(["--cn", "PersistRoot", "--validity-years", "5"])
        .status()
        .unwrap()
        .success());

    // Account keypair.
    assert!(bin("qvacme-client")
        .args(["account-keygen", "--out"])
        .arg(&account)
        .status()
        .unwrap()
        .success());

    let port = next_port();
    let url = format!("http://127.0.0.1:{port}");
    let listen = format!("127.0.0.1:{port}");

    // First server lifecycle: register + first issue.
    {
        let mut server = bin("qvacme-server");
        server
            .args(["--listen", &listen, "--auto-approve", "--parent"])
            .arg(&root)
            .args(["--db"])
            .arg(&db)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = server.spawn().expect("spawn server #1");
        let _g = ServerGuard(child);

        wait_for_ping(&url);

        let record_path = account.join("record.json");
        assert!(bin("qvacme-client")
            .args(["register", "--server", &url, "--account"])
            .arg(&account)
            .args(["--out"])
            .arg(&record_path)
            .status()
            .unwrap()
            .success());

        assert!(bin("qvacme-client")
            .args(["issue", "--server", &url, "--account"])
            .arg(&account)
            .args(["--account-record"])
            .arg(&record_path)
            .args([
                "--cn",
                "first.persist.test",
                "--validity-days",
                "30",
                "--out"
            ])
            .arg(&cert_a)
            .args(["--max-polls", "10", "--poll-ms", "200"])
            .status()
            .unwrap()
            .success());
        // ServerGuard kills + waits on drop.
    }

    // Tiny pause to make sure the OS releases the port.
    sleep(Duration::from_millis(300));

    // Second server lifecycle: same --db; the existing account_id must
    // still exist on disk and allow a new order.
    {
        let mut server = bin("qvacme-server");
        server
            .args(["--listen", &listen, "--auto-approve", "--parent"])
            .arg(&root)
            .args(["--db"])
            .arg(&db)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = server.spawn().expect("spawn server #2");
        let _g = ServerGuard(child);

        wait_for_ping(&url);

        // Re-use the SAME record from before — proves the account
        // survived the restart.
        let record_path = account.join("record.json");
        let st = bin("qvacme-client")
            .args(["issue", "--server", &url, "--account"])
            .arg(&account)
            .args(["--account-record"])
            .arg(&record_path)
            .args([
                "--cn",
                "second.persist.test",
                "--validity-days",
                "30",
                "--out",
            ])
            .arg(&cert_b)
            .args(["--max-polls", "10", "--poll-ms", "200"])
            .status()
            .unwrap();
        assert!(
            st.success(),
            "second issue failed — SQLite state did not survive restart"
        );
        assert!(cert_b.join("certificate.json").exists());
    }
}

fn wait_for_ping(url: &str) {
    for _ in 0..30 {
        sleep(Duration::from_millis(200));
        let ok = bin("qvacme-client")
            .args(["ping", "--server", url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return;
        }
    }
    panic!("server did not become healthy at {url}");
}

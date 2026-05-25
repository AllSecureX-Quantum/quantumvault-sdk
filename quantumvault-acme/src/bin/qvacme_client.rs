//! `qvacme-client` — talks to a `qvacme-server` to obtain a PQC cert.
//!
//! Walks the full flow: generate a fresh account keypair, register
//! the account, generate a subject keypair (the key the cert will
//! bind to), submit the order, download the cert.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use quantumvault_ca::{generate_keypair as ca_keygen, Certificate};
use quantumvault_core::api::keygen as core_keygen;
use quantumvault_core::{Algorithm, Config, SecurityLevel, SigningKey, VerifyingKey};
use serde::Serialize;

use quantumvault_acme::Client;

#[derive(Parser, Debug)]
#[command(
    name = "qvacme-client",
    about = "ACME-PQC client — register an account, request an ML-DSA cert from a qvacme-server"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a fresh account signing keypair and write it to disk.
    AccountKeygen {
        /// Where to write account.signing.json + account.verifying.json.
        #[arg(long)]
        out: PathBuf,
    },

    /// Register an account with the server.
    Register {
        /// `qvacme-server` base URL (e.g. http://127.0.0.1:8443).
        #[arg(long)]
        server: String,
        /// Directory holding the account keypair.
        #[arg(long)]
        account: PathBuf,
        /// Optional contact (email).
        #[arg(long)]
        contact: Option<String>,
        /// Where to write the returned account record JSON.
        #[arg(long)]
        out: PathBuf,
    },

    /// Submit an order and download the certificate when ready.
    Issue {
        /// Server URL.
        #[arg(long)]
        server: String,
        /// Account directory.
        #[arg(long)]
        account: PathBuf,
        /// Account record JSON (output of `register`).
        #[arg(long)]
        account_record: PathBuf,
        /// CN the cert should carry.
        #[arg(long)]
        cn: String,
        /// SANs (comma-separated, e.g. `DNS:api.example.com,DNS:www...`).
        #[arg(long, value_delimiter = ',')]
        san: Vec<String>,
        /// Validity in days.
        #[arg(long, default_value_t = 90)]
        validity_days: i64,
        /// Output directory: subject.signing.json + subject.verifying.json
        /// + certificate.json.
        #[arg(long)]
        out: PathBuf,
        /// Poll interval in milliseconds.
        #[arg(long, default_value_t = 500)]
        poll_ms: u64,
        /// Maximum poll attempts.
        #[arg(long, default_value_t = 30)]
        max_polls: u32,
    },

    /// Probe server health.
    Ping {
        /// Server URL.
        #[arg(long)]
        server: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("qvacme-client: error: build runtime: {e}");
            return ExitCode::from(2);
        }
    };
    match rt.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("qvacme-client: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Command::AccountKeygen { out } => cmd_account_keygen(&out).await,
        Command::Register {
            server,
            account,
            contact,
            out,
        } => cmd_register(&server, &account, contact, &out).await,
        Command::Issue {
            server,
            account,
            account_record,
            cn,
            san,
            validity_days,
            out,
            poll_ms,
            max_polls,
        } => {
            cmd_issue(
                &server,
                &account,
                &account_record,
                &cn,
                &san,
                validity_days,
                &out,
                poll_ms,
                max_polls,
            )
            .await
        }
        Command::Ping { server } => cmd_ping(&server).await,
    }
}

async fn cmd_account_keygen(out_dir: &std::path::Path) -> Result<ExitCode> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {out_dir:?}"))?;
    let cfg = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()
        .context("config")?;
    let kp = core_keygen::generate_signature_keypair(Algorithm::MlDsa65, &cfg)?;
    write_key_pair(out_dir, "account", &kp.signing_key, &kp.verifying_key)?;
    println!("✓ wrote account keypair → {}", out_dir.display());
    println!("  algorithm: ML-DSA-65");
    println!("  key_id   : {}", kp.signing_key.key_id);
    Ok(ExitCode::SUCCESS)
}

async fn cmd_register(
    server: &str,
    account_dir: &std::path::Path,
    contact: Option<String>,
    out_record: &std::path::Path,
) -> Result<ExitCode> {
    let (sk, vk) = load_key_pair(account_dir, "account")?;
    let client = Client::new(server)?;
    let acc = client
        .register_account(&sk, &vk.bytes, &sk.key_id, contact)
        .await
        .context("register account")?;
    std::fs::write(out_record, serde_json::to_vec_pretty(&acc)?)?;
    println!("✓ account registered");
    println!("  account_id : {}", acc.id);
    println!("  record at  : {}", out_record.display());
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_arguments)]
async fn cmd_issue(
    server: &str,
    account_dir: &std::path::Path,
    account_record_path: &std::path::Path,
    cn: &str,
    san: &[String],
    validity_days: i64,
    out_dir: &std::path::Path,
    poll_ms: u64,
    max_polls: u32,
) -> Result<ExitCode> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {out_dir:?}"))?;
    let (account_sk, _account_vk) = load_key_pair(account_dir, "account")?;
    let account_record: quantumvault_acme::Account =
        serde_json::from_slice(&std::fs::read(account_record_path)?)?;

    // Generate a fresh subject keypair (the key the cert binds to).
    let (subj_sk, subj_vk) = ca_keygen()?;
    // CaVerifyingKey doesn't expose raw bytes via a public ctor we can
    // round-trip from. We save and reload from disk.
    save_ca_kp_to(&out_dir.join("subject"), &subj_sk, &subj_vk)?;

    let subj_vk_bytes = std::fs::read(out_dir.join("subject.verifying.json"))?;
    // The on-disk vk JSON has a "bytes" field — pull the raw bytes back
    // out for the wire request.
    let subj_vk_json: serde_json::Value = serde_json::from_slice(&subj_vk_bytes)?;
    let vk_b64 = subj_vk_json["bytes"]
        .as_str()
        .ok_or_else(|| anyhow!("subject vk file missing 'bytes' field"))?;
    let subj_vk_raw = B64.decode(vk_b64).context("decode subject vk")?;
    let subj_key_id = subj_vk_json["key_id"].as_str().unwrap_or("").to_string();

    let client = Client::new(server)?;
    let order = client
        .submit_order(
            &account_sk,
            &account_record.id,
            cn,
            san.to_vec(),
            &subj_vk_raw,
            &subj_key_id,
            validity_days,
        )
        .await
        .context("submit order")?;
    println!(
        "✓ order submitted: {} (status={:?})",
        order.id, order.status
    );

    let mut order = order;
    let mut attempts = 0u32;
    while order.status != quantumvault_acme::OrderStatus::Issued && attempts < max_polls {
        tokio::time::sleep(std::time::Duration::from_millis(poll_ms)).await;
        order = client.get_order(&order.id).await?;
        attempts += 1;
    }
    if order.status != quantumvault_acme::OrderStatus::Issued {
        eprintln!(
            "✗ order did not reach Issued after {} polls (status={:?})",
            max_polls, order.status
        );
        return Ok(ExitCode::FAILURE);
    }
    let cert_value = client.get_certificate(&order.id).await?;
    let cert_path = out_dir.join("certificate.json");
    std::fs::write(&cert_path, serde_json::to_vec_pretty(&cert_value)?)?;

    // Decode + summarise.
    let cert: Certificate = serde_json::from_value(cert_value)?;
    println!("✓ certificate issued");
    println!("  cert path : {}", cert_path.display());
    println!("  serial    : {}", cert.tbs.serial);
    println!("  subject   : {}", cert.tbs.subject.to_display());
    println!("  issuer    : {}", cert.tbs.issuer.to_display());
    println!("  expires   : {}", cert.tbs.not_after.to_rfc3339());
    Ok(ExitCode::SUCCESS)
}

async fn cmd_ping(server: &str) -> Result<ExitCode> {
    let client = Client::new(server)?;
    let v = client.health().await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(ExitCode::SUCCESS)
}

// =====================================================================
// Key file helpers
// =====================================================================

#[derive(Serialize)]
struct KeyFile<'a> {
    algorithm: &'a str,
    key_id: &'a str,
    bytes: &'a str,
    format: &'a str,
}

fn write_key_pair(
    dir: &std::path::Path,
    prefix: &str,
    sk: &SigningKey,
    vk: &VerifyingKey,
) -> Result<()> {
    let sk_b64 = B64.encode(sk.as_bytes());
    let vk_b64 = B64.encode(&vk.bytes);
    let sk_path = dir.join(format!("{prefix}.signing.json"));
    let vk_path = dir.join(format!("{prefix}.verifying.json"));
    std::fs::write(
        &sk_path,
        serde_json::to_vec_pretty(&KeyFile {
            algorithm: "ML-DSA-65",
            key_id: &sk.key_id,
            bytes: &sk_b64,
            format: "qvacme-key:v1",
        })?,
    )?;
    std::fs::write(
        &vk_path,
        serde_json::to_vec_pretty(&KeyFile {
            algorithm: "ML-DSA-65",
            key_id: &vk.key_id,
            bytes: &vk_b64,
            format: "qvacme-key:v1",
        })?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_key_pair(dir: &std::path::Path, prefix: &str) -> Result<(SigningKey, VerifyingKey)> {
    let sk_v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join(format!("{prefix}.signing.json")))?)?;
    let vk_v: serde_json::Value = serde_json::from_slice(&std::fs::read(
        dir.join(format!("{prefix}.verifying.json")),
    )?)?;
    let sk = SigningKey::new(
        B64.decode(sk_v["bytes"].as_str().unwrap_or(""))?,
        Algorithm::MlDsa65,
        sk_v["key_id"].as_str().unwrap_or("").to_string(),
    );
    let vk = VerifyingKey::new(
        B64.decode(vk_v["bytes"].as_str().unwrap_or(""))?,
        Algorithm::MlDsa65,
        vk_v["key_id"].as_str().unwrap_or("").to_string(),
    );
    Ok((sk, vk))
}

fn save_ca_kp_to(
    base: &std::path::Path,
    sk: &quantumvault_ca::CaSigningKey,
    vk: &quantumvault_ca::CaVerifyingKey,
) -> Result<()> {
    let sk_path = base.with_extension("signing.json");
    let vk_path = base.with_extension("verifying.json");
    sk.save_to_file(&sk_path, None)?;
    vk.save_to_file(&vk_path)?;
    Ok(())
}

//! `qvsmime` — CLI for QuantumVault S/MIME-style email signing.
//!
//! Subcommands:
//! - `keygen` — generate an ML-DSA-65 signing keypair
//! - `sign`   — wrap an RFC 5322 message in a `multipart/signed` envelope
//! - `verify` — extract + verify the signature; exit 1 if invalid
//! - `info`   — show envelope metadata without verifying

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use quantumvault_smime::{
    generate_keypair, sign_message, verify_message, SmimeSigningKey, SmimeVerifyingKey,
};

#[derive(Parser, Debug)]
#[command(
    name = "qvsmime",
    about = "QuantumVault S/MIME — post-quantum email signing (ML-DSA-65, NIST FIPS 204)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a fresh ML-DSA-65 signing keypair.
    Keygen {
        /// Output directory. Writes `<out>/smime.signing.json` (secret) and
        /// `<out>/smime.verifying.json` (publishable).
        #[arg(long)]
        out: PathBuf,
        /// Dev KEK file (from `qvhsm init-master`). When supplied, the
        /// signing key is written as an HSM-wrapped envelope.
        #[arg(long)]
        hsm_kek: Option<PathBuf>,
    },

    /// Sign an RFC 5322 message.
    Sign {
        /// Path to the input message. Use `-` for stdin.
        #[arg(long, short = 'i')]
        input: PathBuf,
        /// Path to write the signed output. Use `-` for stdout.
        #[arg(long, short = 'o')]
        output: PathBuf,
        /// Directory holding `smime.signing.json` and `smime.verifying.json`.
        #[arg(long)]
        key: PathBuf,
        /// Dev KEK file. Required when the signing key in `key/` is
        /// HSM-wrapped.
        #[arg(long)]
        hsm_kek: Option<PathBuf>,
    },

    /// Verify a `multipart/signed` message. Exits 1 if invalid.
    Verify {
        /// Path to the signed message. Use `-` for stdin.
        #[arg(long, short = 'i')]
        input: PathBuf,
        /// Optional verifying-key file to pin against the envelope.
        #[arg(long)]
        key: Option<PathBuf>,
        /// Write the recovered body bytes to this path on a successful verify.
        #[arg(long)]
        body_out: Option<PathBuf>,
    },

    /// Show the signature envelope metadata without verifying.
    Info {
        /// Path to the signed message. Use `-` for stdin.
        #[arg(long, short = 'i')]
        input: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("qvsmime: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Command::Keygen { out, hsm_kek } => cmd_keygen(&out, hsm_kek.as_deref()),
        Command::Sign {
            input,
            output,
            key,
            hsm_kek,
        } => cmd_sign(&input, &output, &key, hsm_kek.as_deref()),
        Command::Verify {
            input,
            key,
            body_out,
        } => cmd_verify(&input, key.as_deref(), body_out.as_deref()),
        Command::Info { input } => cmd_info(&input),
    }
}

fn cmd_keygen(
    out_dir: &std::path::Path,
    hsm_kek: Option<&std::path::Path>,
) -> Result<ExitCode> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {out_dir:?}"))?;
    let (sk, vk) = generate_keypair().context("generate_keypair")?;
    let sk_path = out_dir.join("smime.signing.json");
    let vk_path = out_dir.join("smime.verifying.json");
    sk.save_to_file(&sk_path, hsm_kek).context("save signing key")?;
    vk.save_to_file(&vk_path).context("save verifying key")?;
    println!("✓ wrote signing key   → {}", sk_path.display());
    println!("✓ wrote verifying key → {}", vk_path.display());
    println!();
    println!("Algorithm: ML-DSA-65 (NIST FIPS 204, Level 3)");
    if let Some(p) = hsm_kek {
        println!("Signing key is HSM-wrapped under KEK at {}.", p.display());
    } else {
        println!("Keep the signing key OFFLINE; the verifying key can be published.");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_sign(
    input: &std::path::Path,
    output: &std::path::Path,
    key_dir: &std::path::Path,
    hsm_kek: Option<&std::path::Path>,
) -> Result<ExitCode> {
    let sk_path = key_dir.join("smime.signing.json");
    let vk_path = key_dir.join("smime.verifying.json");
    let sk = SmimeSigningKey::load_from_file(&sk_path, hsm_kek)
        .with_context(|| format!("load signing key from {sk_path:?}"))?;
    let vk = SmimeVerifyingKey::load_from_file(&vk_path)
        .with_context(|| format!("load verifying key from {vk_path:?}"))?;

    let raw = read_input(input).context("read input message")?;
    let (signed, report) = sign_message(&raw, &sk, &vk).context("sign_message")?;
    write_output(output, &signed.bytes).context("write output message")?;

    eprintln!(
        "✓ signed {} bytes → {} bytes ({})",
        report.body_bytes_signed,
        report.output_bytes,
        output.display(),
    );
    eprintln!(
        "  algorithm: {} · sha3_256: {}…",
        signed.envelope.algorithm,
        &signed.envelope.sha3_256[..16]
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(
    input: &std::path::Path,
    key_path: Option<&std::path::Path>,
    body_out: Option<&std::path::Path>,
) -> Result<ExitCode> {
    let expected = match key_path {
        Some(p) => Some(
            SmimeVerifyingKey::load_from_file(p)
                .with_context(|| format!("load verifying key from {p:?}"))?,
        ),
        None => None,
    };
    let raw = read_input(input).context("read signed message")?;
    let report = verify_message(&raw, expected.as_ref()).context("verify_message")?;

    println!("Algorithm    : {}", report.envelope.algorithm);
    println!("Signed at    : {}", report.envelope.signed_at.to_rfc3339());
    println!("Key id       : {}", report.envelope.verifying_key_id);
    println!("Body sha3_256: {}", report.envelope.sha3_256);
    println!("Body bytes   : {}", report.body.len());

    if !report.valid {
        println!("\n✗ VERIFICATION FAILED — body hash or signature is invalid.");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n✓ signature verified");

    if let Some(p) = body_out {
        write_output(p, &report.body).context("write body output")?;
        println!("  body bytes written → {}", p.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_info(input: &std::path::Path) -> Result<ExitCode> {
    let raw = read_input(input).context("read signed message")?;
    let report = verify_message(&raw, None).context("verify_message")?;
    println!("Algorithm    : {}", report.envelope.algorithm);
    println!("Signed at    : {}", report.envelope.signed_at.to_rfc3339());
    println!("Key id       : {}", report.envelope.verifying_key_id);
    println!("Body sha3_256: {}", report.envelope.sha3_256);
    println!("Body bytes   : {}", report.body.len());
    println!("Signature OK : {}", report.valid);
    Ok(if report.valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

// =====================================================================
// I/O helpers
// =====================================================================

fn read_input(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    if path.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read(path)
    }
}

fn write_output(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    if path.as_os_str() == "-" {
        use std::io::Write;
        std::io::stdout().write_all(data)?;
        Ok(())
    } else {
        std::fs::write(path, data)
    }
}

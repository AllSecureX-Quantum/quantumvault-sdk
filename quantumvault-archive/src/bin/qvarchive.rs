//! `qvarchive` — CLI for the QuantumVault Archive Sealer (Hop 6.6).
//!
//! Four subcommands:
//! - `keygen`  generate a fresh SLH-DSA archival keypair
//! - `seal`    seal every file under a directory and write a manifest
//! - `verify`  verify every file matches its signature
//! - `status`  summary of what's sealed in a directory

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use quantumvault_archive::{
    generate_keypair, seal_directory, verify_directory, ArchiveSigningKey, ArchiveVerifyingKey,
    Manifest, SealOptions, MANIFEST_FILE_NAME,
};

#[derive(Parser, Debug)]
#[command(
    name = "qvarchive",
    about = "QuantumVault Archive Sealer — long-term integrity via SLH-DSA (FIPS 205)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a fresh SLH-DSA-SHAKE-256s archival keypair.
    Keygen {
        /// Where to write the keypair. Two files land here:
        /// `<out>/archive.signing.json` and `<out>/archive.verifying.json`.
        #[arg(long)]
        out: PathBuf,
    },

    /// Seal every file in a directory and write `qvarchive.manifest.json`.
    Seal {
        /// Directory to seal. Must exist.
        archive_root: PathBuf,
        /// Directory holding `archive.signing.json` and `archive.verifying.json`.
        #[arg(long)]
        key: PathBuf,
        /// Skip files larger than this many bytes.
        #[arg(long)]
        max_file_size: Option<u64>,
        /// Include hidden files.
        #[arg(long)]
        include_hidden: bool,
        /// Follow symlinks (off by default).
        #[arg(long)]
        follow_symlinks: bool,
    },

    /// Verify every file in a sealed directory still matches its signature.
    Verify {
        /// Directory previously sealed.
        archive_root: PathBuf,
        /// Optional path to a verifying key. If supplied, it must match the
        /// one stored in the manifest (defends against manifest-key
        /// substitution attacks).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Print verbose per-file status.
        #[arg(long, short = 'v')]
        verbose: bool,
    },

    /// Show a one-line summary of the seal state of a directory.
    Status {
        /// Directory to inspect.
        archive_root: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("qvarchive: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Command::Keygen { out } => cmd_keygen(&out),
        Command::Seal {
            archive_root,
            key,
            max_file_size,
            include_hidden,
            follow_symlinks,
        } => cmd_seal(
            &archive_root,
            &key,
            max_file_size,
            include_hidden,
            follow_symlinks,
        ),
        Command::Verify {
            archive_root,
            key,
            verbose,
        } => cmd_verify(&archive_root, key.as_deref(), verbose),
        Command::Status { archive_root } => cmd_status(&archive_root),
    }
}

fn cmd_keygen(out_dir: &std::path::Path) -> Result<ExitCode> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create_dir_all {out_dir:?}"))?;
    let (sk, vk) = generate_keypair().context("generate_keypair")?;
    let sk_path = out_dir.join("archive.signing.json");
    let vk_path = out_dir.join("archive.verifying.json");
    sk.save_to_file(&sk_path).context("save signing key")?;
    vk.save_to_file(&vk_path).context("save verifying key")?;
    println!("✓ wrote signing key   → {}", sk_path.display());
    println!("✓ wrote verifying key → {}", vk_path.display());
    println!();
    println!("Algorithm: SLH-DSA-SHAKE-256s (NIST FIPS 205)");
    println!("Keep the signing key OFFLINE; the verifying key can be published.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_seal(
    archive_root: &std::path::Path,
    key_dir: &std::path::Path,
    max_file_size: Option<u64>,
    include_hidden: bool,
    follow_symlinks: bool,
) -> Result<ExitCode> {
    let sk_path = key_dir.join("archive.signing.json");
    let vk_path = key_dir.join("archive.verifying.json");
    let sk = ArchiveSigningKey::load_from_file(&sk_path)
        .with_context(|| format!("load signing key from {sk_path:?}"))?;
    let vk = ArchiveVerifyingKey::load_from_file(&vk_path)
        .with_context(|| format!("load verifying key from {vk_path:?}"))?;

    let opts = SealOptions {
        max_file_size_bytes: max_file_size,
        skip_hidden: !include_hidden,
        follow_symlinks,
    };
    let report = seal_directory(archive_root, &sk, &vk, &opts).context("seal_directory")?;

    println!(
        "✓ sealed {} files ({} bytes hashed)",
        report.files_sealed, report.bytes_hashed
    );
    if report.files_skipped > 0 {
        println!(
            "  ({} files skipped: hidden / oversized / manifest itself)",
            report.files_skipped
        );
    }
    println!("  manifest: {}", report.manifest_path.display());
    println!();
    println!("Algorithm: SLH-DSA-SHAKE-256s · NIST Level 5 (CNSA 2.0)");
    println!(
        "Verify later with: qvarchive verify {}",
        archive_root.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(
    archive_root: &std::path::Path,
    key_path: Option<&std::path::Path>,
    verbose: bool,
) -> Result<ExitCode> {
    let expected = match key_path {
        Some(p) => Some(
            ArchiveVerifyingKey::load_from_file(p)
                .with_context(|| format!("load verifying key from {p:?}"))?,
        ),
        None => None,
    };
    let report = verify_directory(archive_root, expected.as_ref()).context("verify_directory")?;

    let total = report.verified.len()
        + report.missing.len()
        + report.hash_mismatch.len()
        + report.signature_invalid.len();
    println!("Sealed files in manifest : {}", total);
    println!("  Verified OK            : {}", report.verified.len());
    println!("  Missing on disk        : {}", report.missing.len());
    println!("  Hash mismatch          : {}", report.hash_mismatch.len());
    println!(
        "  Signature invalid      : {}",
        report.signature_invalid.len()
    );
    println!(
        "Extra files on disk      : {} (not in manifest)",
        report.extra_on_disk.len()
    );

    if verbose {
        for p in &report.verified {
            println!("  ok        : {}", p.display());
        }
        for p in &report.missing {
            println!("  MISSING   : {}", p.display());
        }
        for p in &report.hash_mismatch {
            println!("  HASH BAD  : {}", p.display());
        }
        for p in &report.signature_invalid {
            println!("  SIG BAD   : {}", p.display());
        }
        for p in &report.extra_on_disk {
            println!("  unsealed  : {}", p.display());
        }
    }

    if report.all_sealed_files_pass() {
        println!("\n✓ all sealed files verified");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("\n✗ verification FAILED — some sealed files diverged");
        Ok(ExitCode::FAILURE)
    }
}

fn cmd_status(archive_root: &std::path::Path) -> Result<ExitCode> {
    let manifest_path = archive_root.join(MANIFEST_FILE_NAME);
    if !manifest_path.exists() {
        println!(
            "unsealed: {} has no qvarchive.manifest.json",
            archive_root.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    let manifest = Manifest::load(&manifest_path).context("load manifest")?;
    println!("Archive      : {}", archive_root.display());
    println!("Sealed at    : {}", manifest.sealed_at.to_rfc3339());
    println!("Algorithm    : {}", manifest.algorithm);
    println!("Key id       : {}", manifest.verifying_key_id);
    println!("Entries      : {}", manifest.entries.len());
    println!(
        "Total bytes  : {}",
        manifest.entries.iter().map(|e| e.size).sum::<u64>()
    );
    Ok(ExitCode::SUCCESS)
}

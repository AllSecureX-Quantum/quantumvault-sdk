//! `qvdnssec` — CLI for QuantumVault PQC DNSSEC.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use quantumvault_dnssec::{
    generate_keypair, parse_zone, sign_zone, verify_zone, DnssecSigningKey, DnssecVerifyingKey,
    ZoneManifest,
};

#[derive(Parser, Debug)]
#[command(
    name = "qvdnssec",
    about = "QuantumVault PQC DNSSEC — sign and verify DNS zones with ML-DSA-65"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate fresh ZSK + KSK ML-DSA-65 keypairs.
    Keygen {
        /// Output directory. Writes
        ///   zsk.signing.json / zsk.verifying.json
        ///   ksk.signing.json / ksk.verifying.json.
        #[arg(long)]
        out: PathBuf,
        /// Dev KEK file (from `qvhsm init-master`). When set, both
        /// signing keys are written as HSM-wrapped envelopes instead
        /// of plaintext keys. Verifying keys (the trust anchors) are
        /// never wrapped.
        #[arg(long)]
        hsm_kek: Option<PathBuf>,
    },

    /// Sign a BIND-format zone file. Writes
    /// `<zone>.qvdnssec.manifest.json` next to the zone.
    SignZone {
        /// Zone file (BIND-format).
        #[arg(long)]
        zone: PathBuf,
        /// Directory with `zsk.*.json` and `ksk.*.json` files.
        #[arg(long)]
        key: PathBuf,
        /// Dev KEK file. Required when the signing keys in `key/`
        /// are HSM-wrapped.
        #[arg(long)]
        hsm_kek: Option<PathBuf>,
    },

    /// Verify a signed zone against the KSK trust anchor.
    VerifyZone {
        /// Zone file.
        #[arg(long)]
        zone: PathBuf,
        /// Manifest (defaults to `<zone>.qvdnssec.manifest.json`).
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Trust-anchor KSK verifying-key file
        /// (e.g. `keys/ksk.verifying.json`).
        #[arg(long = "trust-ksk")]
        trust_ksk: PathBuf,
    },

    /// Print one manifest's contents.
    Info {
        /// Manifest path.
        #[arg(long)]
        manifest: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("qvdnssec: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Command::Keygen { out, hsm_kek } => cmd_keygen(&out, hsm_kek.as_deref()),
        Command::SignZone { zone, key, hsm_kek } => cmd_sign_zone(&zone, &key, hsm_kek.as_deref()),
        Command::VerifyZone {
            zone,
            manifest,
            trust_ksk,
        } => cmd_verify_zone(&zone, manifest.as_deref(), &trust_ksk),
        Command::Info { manifest } => cmd_info(&manifest),
    }
}

fn cmd_keygen(out: &std::path::Path, hsm_kek: Option<&std::path::Path>) -> Result<ExitCode> {
    std::fs::create_dir_all(out).with_context(|| format!("create {out:?}"))?;
    let (ksk_sk, ksk_vk) = generate_keypair().context("generate KSK")?;
    let (zsk_sk, zsk_vk) = generate_keypair().context("generate ZSK")?;
    ksk_sk.save_to_file(&out.join("ksk.signing.json"), hsm_kek)?;
    ksk_vk.save_to_file(&out.join("ksk.verifying.json"))?;
    zsk_sk.save_to_file(&out.join("zsk.signing.json"), hsm_kek)?;
    zsk_vk.save_to_file(&out.join("zsk.verifying.json"))?;
    if let Some(p) = hsm_kek {
        println!(
            "✓ wrote keypair files in {} (signing keys HSM-wrapped under {})",
            out.display(),
            p.display()
        );
    } else {
        println!("✓ wrote keypair files in {}", out.display());
    }
    println!();
    println!("KSK fingerprint (publish as the trust anchor):");
    println!("  {}", ksk_vk.fingerprint());
    println!();
    println!("ZSK fingerprint:");
    println!("  {}", zsk_vk.fingerprint());
    println!();
    println!("Algorithm: ML-DSA-65 (NIST FIPS 204, Level 3)");
    println!("KEEP THE SIGNING KEYS OFFLINE. Publish only the .verifying.json files.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_sign_zone(
    zone_path: &std::path::Path,
    key_dir: &std::path::Path,
    hsm_kek: Option<&std::path::Path>,
) -> Result<ExitCode> {
    let zone_text =
        std::fs::read_to_string(zone_path).with_context(|| format!("read zone {zone_path:?}"))?;
    let zone = parse_zone(&zone_text).context("parse zone")?;

    let ksk_sk = DnssecSigningKey::load_from_file(&key_dir.join("ksk.signing.json"), hsm_kek)?;
    let ksk_vk = DnssecVerifyingKey::load_from_file(&key_dir.join("ksk.verifying.json"))?;
    let zsk_sk = DnssecSigningKey::load_from_file(&key_dir.join("zsk.signing.json"), hsm_kek)?;
    let zsk_vk = DnssecVerifyingKey::load_from_file(&key_dir.join("zsk.verifying.json"))?;

    let manifest_path = derive_manifest_path(zone_path);
    let report = sign_zone(&zone, &ksk_sk, &ksk_vk, &zsk_sk, &zsk_vk, &manifest_path)
        .context("sign_zone")?;

    println!("✓ signed zone");
    println!("  zone     : {}", zone_path.display());
    println!("  records  : {}", report.records_seen);
    println!("  RRSets   : {}", report.rrsets_signed);
    println!("  manifest : {}", manifest_path.display());
    println!();
    println!("Trust anchor (KSK fingerprint, publish in your parent zone / DS record):");
    println!("  {}", ksk_vk.fingerprint());
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify_zone(
    zone_path: &std::path::Path,
    manifest_path_opt: Option<&std::path::Path>,
    trust_ksk_path: &std::path::Path,
) -> Result<ExitCode> {
    let zone_text =
        std::fs::read_to_string(zone_path).with_context(|| format!("read zone {zone_path:?}"))?;
    let zone = parse_zone(&zone_text).context("parse zone")?;

    let manifest_path: PathBuf = match manifest_path_opt {
        Some(p) => p.to_path_buf(),
        None => derive_manifest_path(zone_path),
    };
    let manifest = ZoneManifest::load(&manifest_path).context("load manifest")?;
    let expected_ksk =
        DnssecVerifyingKey::load_from_file(trust_ksk_path).context("load trust-anchor KSK")?;

    match verify_zone(&zone, &manifest, &expected_ksk) {
        Ok(report) => {
            println!("✓ zone verified");
            println!("  zone             : {}", manifest.zone);
            println!("  RRSets checked   : {}", report.rrsets_checked);
            println!("  KSK fingerprint  : {}", report.ksk_fingerprint);
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            println!("✗ ZONE VERIFICATION FAILED: {e}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_info(manifest_path: &std::path::Path) -> Result<ExitCode> {
    let m = ZoneManifest::load(manifest_path).context("load manifest")?;
    println!("Zone           : {}", m.zone);
    println!("Algorithm      : {}", m.algorithm);
    println!("Signed at      : {}", m.signed_at.to_rfc3339());
    println!("Manifest ver   : {}", m.version);
    println!("KSK fingerprint: {}", m.ksk.fingerprint);
    println!("ZSK fingerprint: {}", m.zsk.fingerprint);
    println!("RRSets         : {}", m.rrsets.len());
    Ok(ExitCode::SUCCESS)
}

fn derive_manifest_path(zone: &std::path::Path) -> PathBuf {
    let mut p = zone.to_path_buf();
    let new_name = match zone.file_name().and_then(|n| n.to_str()) {
        Some(name) => format!("{name}.qvdnssec.manifest.json"),
        None => "qvdnssec.manifest.json".to_string(),
    };
    p.set_file_name(new_name);
    p
}

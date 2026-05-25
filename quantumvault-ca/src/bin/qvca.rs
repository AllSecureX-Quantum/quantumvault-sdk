//! `qvca` — internal post-quantum Certificate Authority CLI.
//!
//! Five subcommands:
//! - `init-root`           bootstrap a self-signed root CA
//! - `issue-intermediate`  issue an intermediate CA from any parent CA
//! - `issue-leaf`          issue a leaf (non-CA) certificate
//! - `verify`              verify a chain against a trust anchor
//! - `info`                pretty-print one certificate

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use quantumvault_ca::{
    generate_keypair, verify_chain, CaSigningKey, CaVerifyingKey, Certificate, CertificateBuilder,
    DistinguishedName, KeyUsage,
};

#[derive(Parser, Debug)]
#[command(
    name = "qvca",
    about = "QuantumVault internal Certificate Authority — ML-DSA-65 signed (NIST FIPS 204)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Bootstrap a self-signed root CA.
    InitRoot {
        /// Output directory. Writes `root.signing.json`,
        /// `root.verifying.json`, `root.cert.json`.
        #[arg(long)]
        out: PathBuf,
        /// Common Name for the root CA.
        #[arg(long)]
        cn: String,
        /// Organisation (optional).
        #[arg(long)]
        o: Option<String>,
        /// Country code, ISO 3166 two-letter (optional).
        #[arg(long)]
        c: Option<String>,
        /// Validity in years. Default: 10.
        #[arg(long, default_value_t = 10)]
        validity_years: u32,
        /// Maximum chain depth beneath this root. Default: 2.
        #[arg(long, default_value_t = 2u8)]
        path_length: u8,
        /// Path to a dev KEK file (from `qvhsm init-master`) or a
        /// PKCS#11-fronted KEK identifier. When supplied, the root
        /// signing key is written as an HSM-wrapped envelope instead
        /// of a plaintext key file.
        #[arg(long)]
        hsm_kek: Option<PathBuf>,
    },

    /// Issue an intermediate CA from a parent CA.
    IssueIntermediate {
        /// Directory of the parent CA (must contain `*.signing.json`
        /// and `*.cert.json`).
        #[arg(long)]
        parent: PathBuf,
        /// Output directory for the new intermediate.
        #[arg(long)]
        out: PathBuf,
        /// Common Name for the intermediate.
        #[arg(long)]
        cn: String,
        /// Organisation (optional).
        #[arg(long)]
        o: Option<String>,
        /// Validity in years. Default: 5.
        #[arg(long, default_value_t = 5)]
        validity_years: u32,
        /// Max chain depth beneath this intermediate. Default: 1.
        #[arg(long, default_value_t = 1u8)]
        path_length: u8,
        /// Dev KEK file. Used to (a) unwrap the parent's HSM-wrapped
        /// signing key on load, and (b) wrap the new intermediate's
        /// signing key on save.
        #[arg(long)]
        hsm_kek: Option<PathBuf>,
    },

    /// Issue a leaf certificate from any CA (root or intermediate).
    IssueLeaf {
        /// Directory of the issuing CA.
        #[arg(long)]
        parent: PathBuf,
        /// Output directory for the new leaf.
        #[arg(long)]
        out: PathBuf,
        /// Common Name for the leaf (e.g. `api.example.com`).
        #[arg(long)]
        cn: String,
        /// Subject Alternative Names, comma separated
        /// (e.g. `DNS:api.example.com,DNS:www.api.example.com`).
        #[arg(long, value_delimiter = ',')]
        san: Vec<String>,
        /// Validity in days. Default: 365.
        #[arg(long, default_value_t = 365)]
        validity_days: i64,
        /// Dev KEK file. Used to (a) unwrap the parent CA's signing key
        /// on load, and (b) wrap the new leaf's signing key on save.
        #[arg(long)]
        hsm_kek: Option<PathBuf>,
    },

    /// Verify a chain. Pass the leaf, intermediates (if any), and the
    /// trust-anchor root cert.
    Verify {
        /// Leaf certificate.
        #[arg(long)]
        leaf: PathBuf,
        /// Intermediate certificates (may be empty), in order from
        /// closest-to-leaf to closest-to-root.
        #[arg(long = "intermediate", value_delimiter = ',')]
        intermediates: Vec<PathBuf>,
        /// Trust-anchor root certificate.
        #[arg(long)]
        trust_root: PathBuf,
    },

    /// Print one certificate's contents.
    Info {
        #[arg(long)]
        cert: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("qvca: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Command::InitRoot {
            out,
            cn,
            o,
            c,
            validity_years,
            path_length,
            hsm_kek,
        } => cmd_init_root(
            &out,
            &cn,
            o.as_deref(),
            c.as_deref(),
            validity_years,
            path_length,
            hsm_kek.as_deref(),
        ),
        Command::IssueIntermediate {
            parent,
            out,
            cn,
            o,
            validity_years,
            path_length,
            hsm_kek,
        } => cmd_issue_intermediate(
            &parent,
            &out,
            &cn,
            o.as_deref(),
            validity_years,
            path_length,
            hsm_kek.as_deref(),
        ),
        Command::IssueLeaf {
            parent,
            out,
            cn,
            san,
            validity_days,
            hsm_kek,
        } => cmd_issue_leaf(&parent, &out, &cn, &san, validity_days, hsm_kek.as_deref()),
        Command::Verify {
            leaf,
            intermediates,
            trust_root,
        } => cmd_verify(&leaf, &intermediates, &trust_root),
        Command::Info { cert } => cmd_info(&cert),
    }
}

fn build_dn(cn: &str, o: Option<&str>, c: Option<&str>) -> DistinguishedName {
    let mut dn = DistinguishedName::cn(cn);
    if let Some(o) = o {
        dn = dn.with_o(o);
    }
    if let Some(c) = c {
        dn = dn.with_c(c);
    }
    dn
}

fn cmd_init_root(
    out_dir: &std::path::Path,
    cn: &str,
    o: Option<&str>,
    c: Option<&str>,
    validity_years: u32,
    path_length: u8,
    hsm_kek: Option<&std::path::Path>,
) -> Result<ExitCode> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {out_dir:?}"))?;
    let (sk, vk) = generate_keypair().context("generate root keypair")?;
    let dn = build_dn(cn, o, c);

    let validity_days = (validity_years as i64) * 365;
    let cert = CertificateBuilder::new(dn.clone(), &vk)
        .ca(Some(path_length))
        .validity_days(validity_days)
        .with_key_usage(KeyUsage::DigitalSignature)
        .with_key_usage(KeyUsage::KeyCertSign)
        .with_key_usage(KeyUsage::CrlSign)
        .self_sign(&sk)
        .context("self-sign root")?;

    sk.save_to_file(&out_dir.join("root.signing.json"), hsm_kek)?;
    vk.save_to_file(&out_dir.join("root.verifying.json"))?;
    cert.save_to_file(&out_dir.join("root.cert.json"))?;

    println!("✓ root CA created");
    println!("  subject     : {}", cert.tbs.subject.to_display());
    println!("  serial      : {}", cert.tbs.serial);
    println!("  fingerprint : {}", cert.fingerprint()?);
    println!("  not_before  : {}", cert.tbs.not_before.to_rfc3339());
    println!("  not_after   : {}", cert.tbs.not_after.to_rfc3339());
    if hsm_kek.is_some() {
        println!("  signing key : HSM-wrapped under KEK at {}", hsm_kek.unwrap().display());
    }
    println!("  files in    : {}", out_dir.display());
    Ok(ExitCode::SUCCESS)
}

fn cmd_issue_intermediate(
    parent_dir: &std::path::Path,
    out_dir: &std::path::Path,
    cn: &str,
    o: Option<&str>,
    validity_years: u32,
    path_length: u8,
    hsm_kek: Option<&std::path::Path>,
) -> Result<ExitCode> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {out_dir:?}"))?;
    let (parent_sk_path, parent_cert_path) = find_parent_files(parent_dir)?;
    let parent_sk = CaSigningKey::load_from_file(&parent_sk_path, hsm_kek)?;
    let parent_cert = Certificate::load_from_file(&parent_cert_path)?;

    let (sk, vk) = generate_keypair().context("generate intermediate keypair")?;
    let dn = build_dn(cn, o, parent_cert.tbs.subject.c.as_deref());
    let validity_days = (validity_years as i64) * 365;

    let cert = CertificateBuilder::new(dn, &vk)
        .ca(Some(path_length))
        .validity_days(validity_days)
        .with_key_usage(KeyUsage::DigitalSignature)
        .with_key_usage(KeyUsage::KeyCertSign)
        .with_key_usage(KeyUsage::CrlSign)
        .sign_with(&parent_sk, &parent_cert)
        .context("sign intermediate with parent")?;

    sk.save_to_file(&out_dir.join("intermediate.signing.json"), hsm_kek)?;
    vk.save_to_file(&out_dir.join("intermediate.verifying.json"))?;
    cert.save_to_file(&out_dir.join("intermediate.cert.json"))?;

    println!("✓ intermediate CA created");
    println!("  subject     : {}", cert.tbs.subject.to_display());
    println!("  issuer      : {}", cert.tbs.issuer.to_display());
    println!("  serial      : {}", cert.tbs.serial);
    println!("  fingerprint : {}", cert.fingerprint()?);
    println!("  files in    : {}", out_dir.display());
    Ok(ExitCode::SUCCESS)
}

fn cmd_issue_leaf(
    parent_dir: &std::path::Path,
    out_dir: &std::path::Path,
    cn: &str,
    san: &[String],
    validity_days: i64,
    hsm_kek: Option<&std::path::Path>,
) -> Result<ExitCode> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {out_dir:?}"))?;
    let (parent_sk_path, parent_cert_path) = find_parent_files(parent_dir)?;
    let parent_sk = CaSigningKey::load_from_file(&parent_sk_path, hsm_kek)?;
    let parent_cert = Certificate::load_from_file(&parent_cert_path)?;

    let (sk, vk) = generate_keypair().context("generate leaf keypair")?;
    let dn = build_dn(
        cn,
        parent_cert.tbs.subject.o.as_deref(),
        parent_cert.tbs.subject.c.as_deref(),
    );

    let mut b = CertificateBuilder::new(dn, &vk)
        .validity_days(validity_days)
        .with_key_usage(KeyUsage::DigitalSignature)
        .with_key_usage(KeyUsage::KeyEncipherment)
        .with_key_usage(KeyUsage::ServerAuth)
        .with_key_usage(KeyUsage::ClientAuth);
    for s in san {
        b = b.with_san(s);
    }

    let cert = b
        .sign_with(&parent_sk, &parent_cert)
        .context("sign leaf with parent")?;

    sk.save_to_file(&out_dir.join("leaf.signing.json"), hsm_kek)?;
    vk.save_to_file(&out_dir.join("leaf.verifying.json"))?;
    cert.save_to_file(&out_dir.join("leaf.cert.json"))?;

    println!("✓ leaf certificate issued");
    println!("  subject     : {}", cert.tbs.subject.to_display());
    println!("  issuer      : {}", cert.tbs.issuer.to_display());
    println!("  serial      : {}", cert.tbs.serial);
    println!("  fingerprint : {}", cert.fingerprint()?);
    if !cert.tbs.san.is_empty() {
        println!("  SANs        : {}", cert.tbs.san.join(", "));
    }
    println!("  files in    : {}", out_dir.display());
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(
    leaf: &std::path::Path,
    intermediates: &[PathBuf],
    trust_root: &std::path::Path,
) -> Result<ExitCode> {
    let leaf_cert = Certificate::load_from_file(leaf)?;
    let mut chain: Vec<Certificate> = Vec::with_capacity(intermediates.len() + 2);
    chain.push(leaf_cert);
    for p in intermediates {
        chain.push(Certificate::load_from_file(p)?);
    }
    let root = Certificate::load_from_file(trust_root)?;
    let root_fp = root.fingerprint()?;
    chain.push(root);

    let trust_anchors = vec![root_fp.clone()];
    match verify_chain(&chain, &trust_anchors) {
        Ok(report) => {
            println!("✓ chain verified");
            println!("  depth            : {}", report.depth);
            println!("  leaf subject     : {}", report.leaf_subject);
            println!("  root fingerprint : {}", report.root_fingerprint);
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            println!("✗ CHAIN VERIFICATION FAILED: {e}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_info(path: &std::path::Path) -> Result<ExitCode> {
    let cert = Certificate::load_from_file(path)?;
    println!("Version          : {}", cert.tbs.version);
    println!("Serial           : {}", cert.tbs.serial);
    println!("Subject          : {}", cert.tbs.subject.to_display());
    println!("Issuer           : {}", cert.tbs.issuer.to_display());
    println!("Algorithm        : {}", cert.signature.algorithm);
    println!("Not before       : {}", cert.tbs.not_before.to_rfc3339());
    println!("Not after        : {}", cert.tbs.not_after.to_rfc3339());
    println!("Is CA            : {}", cert.tbs.is_ca);
    if let Some(p) = cert.tbs.path_length {
        println!("Path length      : {p}");
    }
    if !cert.tbs.key_usage.is_empty() {
        let usages: Vec<String> = cert
            .tbs
            .key_usage
            .iter()
            .map(|u| format!("{u:?}"))
            .collect();
        println!("Key usage        : {}", usages.join(", "));
    }
    if !cert.tbs.san.is_empty() {
        println!("SANs             : {}", cert.tbs.san.join(", "));
    }
    println!("Fingerprint      : {}", cert.fingerprint()?);
    Ok(ExitCode::SUCCESS)
}

fn find_parent_files(parent_dir: &std::path::Path) -> Result<(PathBuf, PathBuf)> {
    // Try root.* first, then intermediate.*.
    let candidates = [("root", "root"), ("intermediate", "intermediate")];
    for (sk_pfx, cert_pfx) in candidates {
        let sk = parent_dir.join(format!("{sk_pfx}.signing.json"));
        let cert = parent_dir.join(format!("{cert_pfx}.cert.json"));
        if sk.exists() && cert.exists() {
            return Ok((sk, cert));
        }
    }
    Err(anyhow!(
        "could not find a signing key + certificate pair in {:?} \
         (expected root.signing.json / root.cert.json OR \
          intermediate.signing.json / intermediate.cert.json)",
        parent_dir
    ))
}

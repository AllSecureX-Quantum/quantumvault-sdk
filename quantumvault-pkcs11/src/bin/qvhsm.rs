//! `qvhsm` — operator CLI for the PKCS#11 HSM bridge.
//!
//! Five subcommands:
//!
//!   init-master   Generate a fresh AES-256 KEK and write it to disk
//!                 (for dev / CI; production uses an HSM-resident KEK).
//!   wrap          Seal a file under the KEK, producing a `.wrapped.json`
//!                 envelope. Bind a caller-supplied label as AAD.
//!   unwrap        Reverse `wrap`. Writes the recovered plaintext to a
//!                 file with permissions 0o600.
//!   inspect       Pretty-print an envelope's non-secret metadata
//!                 (version, KEK label, algorithm).
//!   info          Print which KEK backend this build was compiled with.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use quantumvault_pkcs11::{
    read_dev_kek_file, write_dev_kek_file, InMemoryKek, KekProvider, WrappedKey,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let rest: Vec<&str> = args.iter().skip(2).map(String::as_str).collect();

    let cmd = args.get(1).map(String::as_str);
    let result: Result<(), String> = match cmd {
        Some("init-master") => cmd_init_master(&rest),
        Some("wrap") => cmd_wrap(&rest),
        Some("unwrap") => cmd_unwrap(&rest),
        Some("inspect") => cmd_inspect(&rest),
        Some("info") => cmd_info(),
        Some("--help") | Some("-h") | Some("help") | None => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!("unknown subcommand `{other}`. Try `qvhsm --help`.")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("qvhsm: {msg}");
            ExitCode::from(1)
        }
    }
}

fn print_help() {
    println!(
        "qvhsm — PKCS#11 HSM bridge for QuantumVault\n\
         \n\
         USAGE:\n  \
           qvhsm <COMMAND> [OPTIONS]\n\
         \n\
         COMMANDS:\n  \
           init-master --label <L> --out <FILE>        Generate a dev KEK file.\n  \
           wrap        --kek <FILE> --in <FILE> --out <FILE> --aad <STRING>\n  \
           unwrap      --kek <FILE> --in <FILE> --out <FILE> --aad <STRING>\n  \
           inspect     --in <FILE>                     Print envelope metadata.\n  \
           info                                        Show build / backend info.\n"
    );
}

// -----------------------------------------------------------------------
// init-master
// -----------------------------------------------------------------------

fn cmd_init_master(args: &[&str]) -> Result<(), String> {
    let label = required_flag(args, "--label")?;
    let out = required_flag(args, "--out")?;
    let path = PathBuf::from(out);

    if path.exists() {
        return Err(format!(
            "{} already exists — refusing to overwrite a KEK file",
            path.display()
        ));
    }

    let kek = InMemoryKek::generate(&label);
    write_dev_kek_file(&path, &kek).map_err(|e| format!("write KEK: {e}"))?;

    println!("✓ wrote dev KEK to {}", path.display());
    println!("  label: {label}");
    println!("  algorithm: AES-256 (intended for AES-256-GCM wrap)");
    println!();
    println!("  WARNING: a plaintext KEK on disk is dev-only. In production");
    println!("  generate the KEK *inside* the HSM (cryptoki C_GenerateKey,");
    println!("  CKM_AES_KEY_GEN, CKA_EXTRACTABLE=false) and use the PKCS#11");
    println!("  backend (cargo build --features pkcs11).");
    Ok(())
}

// -----------------------------------------------------------------------
// wrap
// -----------------------------------------------------------------------

fn cmd_wrap(args: &[&str]) -> Result<(), String> {
    let kek_path = required_flag(args, "--kek")?;
    let in_path = required_flag(args, "--in")?;
    let out_path = required_flag(args, "--out")?;
    let aad = required_flag(args, "--aad")?;

    let kek = load_dev_kek(Path::new(&kek_path))?;
    let plaintext = fs::read(&in_path).map_err(|e| format!("read {in_path}: {e}"))?;
    let env = kek
        .wrap(&plaintext, aad.as_bytes())
        .map_err(|e| format!("wrap failed: {e}"))?;
    let serialised = serde_json::to_string_pretty(&env).map_err(|e| e.to_string())?;
    atomic_write(Path::new(&out_path), serialised.as_bytes())?;

    println!(
        "✓ wrapped {} ({} bytes) -> {}",
        in_path,
        plaintext.len(),
        out_path
    );
    println!("  kek label : {}", env.kek_label);
    println!("  aad       : {aad}");
    println!("  algorithm : {}", env.algorithm);
    Ok(())
}

// -----------------------------------------------------------------------
// unwrap
// -----------------------------------------------------------------------

fn cmd_unwrap(args: &[&str]) -> Result<(), String> {
    let kek_path = required_flag(args, "--kek")?;
    let in_path = required_flag(args, "--in")?;
    let out_path = required_flag(args, "--out")?;
    let aad = required_flag(args, "--aad")?;

    let kek = load_dev_kek(Path::new(&kek_path))?;
    let env_bytes = fs::read(&in_path).map_err(|e| format!("read {in_path}: {e}"))?;
    let env: WrappedKey =
        serde_json::from_slice(&env_bytes).map_err(|e| format!("parse envelope: {e}"))?;
    let pt = kek
        .unwrap(&env, aad.as_bytes())
        .map_err(|e| format!("unwrap failed: {e}"))?;
    atomic_write_secret(Path::new(&out_path), &pt)?;

    println!(
        "✓ unwrapped {} -> {} ({} bytes)",
        in_path,
        out_path,
        pt.len()
    );
    Ok(())
}

// -----------------------------------------------------------------------
// inspect
// -----------------------------------------------------------------------

fn cmd_inspect(args: &[&str]) -> Result<(), String> {
    let in_path = required_flag(args, "--in")?;
    let bytes = fs::read(&in_path).map_err(|e| format!("read {in_path}: {e}"))?;
    let env: WrappedKey =
        serde_json::from_slice(&bytes).map_err(|e| format!("parse envelope: {e}"))?;
    let aad = B64
        .decode(&env.aad_b64)
        .map_err(|e| format!("aad decode: {e}"))?;
    let aad_str = std::str::from_utf8(&aad)
        .map(|s| s.to_string())
        .unwrap_or_else(|_| {
            let mut s = String::from("(binary) ");
            s.push_str(&hex(&aad));
            s
        });

    println!("envelope   : {in_path}");
    println!("  version  : {}", env.version);
    println!("  algorithm: {}", env.algorithm);
    println!("  kek label: {}", env.kek_label);
    println!("  aad      : {aad_str}");
    println!("  ct bytes : {}", env.ciphertext_b64.len());
    Ok(())
}

// -----------------------------------------------------------------------
// info
// -----------------------------------------------------------------------

fn cmd_info() -> Result<(), String> {
    let backend = if cfg!(feature = "pkcs11") {
        "in-memory + PKCS#11 (cryptoki)"
    } else {
        "in-memory only (build with --features pkcs11 to enable HSM backend)"
    };
    println!("qvhsm  ·  QuantumVault PKCS#11 HSM bridge");
    println!("backend  : {backend}");
    println!("envelope : v1 (AES-256-GCM, AAD-bound, base64 JSON)");
    Ok(())
}

// -----------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------

fn required_flag(args: &[&str], name: &str) -> Result<String, String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            return args
                .get(i + 1)
                .map(|s| s.to_string())
                .ok_or_else(|| format!("flag {name} expects a value"));
        }
        i += 1;
    }
    Err(format!("missing required flag {name}"))
}

fn load_dev_kek(path: &Path) -> Result<InMemoryKek, String> {
    read_dev_kek_file(path).map_err(|e| format!("load KEK from {}: {e}", path.display()))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent dir", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))?;
    Ok(())
}

fn atomic_write_secret(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|e| format!("stat {}: {e}", path.display()))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

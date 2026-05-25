//! Wrappers that route `quantumvault tools <tool> ...` to the matching
//! standalone PQC binary (`qvarchive`, `qvsmime`, `qvca`, `qvdnssec`,
//! `qvjwtproxy`, `qvacme-server`, `qvacme-client`).
//!
//! Why this exists: customers should only need to install / discover one
//! entrypoint (`quantumvault`). The standalone binaries are kept (so
//! existing scripts, systemd units, and Docker images don't break) but
//! the unified CLI is the supported product surface going forward.
//!
//! Binary resolution: first try a sibling of the currently-running
//! `quantumvault` binary (the common install layout), then fall back to
//! `PATH`. If neither hit, error out with a clear "install …" message.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;

use crate::output::CommandOutput;

#[derive(Subcommand)]
pub enum ToolCommands {
    /// Long-term archival sealer (SLH-DSA-signed manifests).
    Archive {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// S/MIME-style PQC email signing.
    Smime {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Internal PQC Certificate Authority (ML-DSA-65 chains).
    Ca {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// PQC DNSSEC zone signing (ZSK + KSK).
    Dnssec {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// PQC JWT verifying reverse-proxy sidecar.
    #[command(name = "jwt-proxy")]
    JwtProxy {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// ACME-PQC issuance server.
    #[command(name = "acme-server")]
    AcmeServer {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// ACME-PQC client.
    #[command(name = "acme-client")]
    AcmeClient {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// PKCS#11 HSM bridge — wrap/unwrap PQC keys under an HSM-held KEK.
    Hsm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// List the bundled tools and where they resolve to.
    List,
}

const TOOLS: &[(&str, &str)] = &[
    ("archive", "qvarchive"),
    ("smime", "qvsmime"),
    ("ca", "qvca"),
    ("dnssec", "qvdnssec"),
    ("jwt-proxy", "qvjwtproxy"),
    ("acme-server", "qvacme-server"),
    ("acme-client", "qvacme-client"),
    ("hsm", "qvhsm"),
];

pub async fn run(cmd: ToolCommands) -> Result<CommandOutput> {
    match cmd {
        ToolCommands::Archive { args } => dispatch("qvarchive", args),
        ToolCommands::Smime { args } => dispatch("qvsmime", args),
        ToolCommands::Ca { args } => dispatch("qvca", args),
        ToolCommands::Dnssec { args } => dispatch("qvdnssec", args),
        ToolCommands::JwtProxy { args } => dispatch("qvjwtproxy", args),
        ToolCommands::AcmeServer { args } => dispatch("qvacme-server", args),
        ToolCommands::AcmeClient { args } => dispatch("qvacme-client", args),
        ToolCommands::Hsm { args } => dispatch("qvhsm", args),
        ToolCommands::List => Ok(CommandOutput::success_with_data(
            "bundled tools",
            list_entries(),
        )),
    }
}

fn list_entries() -> Vec<serde_json::Value> {
    TOOLS
        .iter()
        .map(|(alias, bin)| {
            let resolved = resolve_binary(bin)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| String::from("not-found"));
            serde_json::json!({
                "alias": alias,
                "binary": bin,
                "resolved": resolved,
            })
        })
        .collect()
}

fn dispatch(binary: &str, args: Vec<OsString>) -> Result<CommandOutput> {
    let path = resolve_binary(binary).with_context(|| {
        format!(
            "could not find `{binary}`. Install it from the QuantumVault \
             release bundle, or ensure it is on PATH or beside the `quantumvault` binary."
        )
    })?;

    let status = Command::new(&path)
        .args(&args)
        .status()
        .with_context(|| format!("failed to spawn {}", path.display()))?;

    if status.success() {
        // Child has already printed its own output; return an empty success
        // marker so the outer formatter doesn't add a duplicate banner.
        Ok(CommandOutput::success(""))
    } else {
        let code = status.code().unwrap_or(1);
        // Propagate the child's exit code so cron / systemd / CI see the failure.
        std::process::exit(code);
    }
}

/// Find a tool binary, preferring a sibling of the current executable
/// (the typical install layout) and falling back to `PATH`.
fn resolve_binary(name: &str) -> Result<PathBuf> {
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join(exe_name(name));
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    which_on_path(name).ok_or_else(|| anyhow!("`{name}` not found"))
}

fn exe_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let needle = exe_name(name);
    for entry in std::env::split_paths(&path_var) {
        let candidate = entry.join(&needle);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_name_appends_extension_on_windows_only() {
        if cfg!(windows) {
            assert_eq!(exe_name("qvca"), "qvca.exe");
        } else {
            assert_eq!(exe_name("qvca"), "qvca");
        }
    }

    #[test]
    fn list_entries_cover_each_tool() {
        let entries = list_entries();
        assert_eq!(entries.len(), TOOLS.len());
        for (alias, bin) in TOOLS {
            let hit = entries.iter().find(|e| e["alias"] == *alias);
            let hit = hit.unwrap_or_else(|| panic!("missing alias {alias}"));
            assert_eq!(hit["binary"], *bin);
        }
    }

    #[test]
    fn resolve_unknown_binary_errors() {
        let err = resolve_binary("definitely-not-a-real-binary-xyz").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "expected not-found error, got: {msg}"
        );
    }
}

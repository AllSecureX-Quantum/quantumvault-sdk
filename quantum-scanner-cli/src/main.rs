//! AllSecureX Quantum Scanner CLI
//!
//! A production-ready CLI tool for scanning codebases for quantum-vulnerable
//! cryptographic implementations. Compiled binary keeps detection algorithms private.
//!
//! Copyright (c) 2025-2026 AllSecureX. All rights reserved.

mod api;
mod auth;
mod config;
mod patterns;
mod scanner;
mod ui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

/// AllSecureX Quantum Scanner - Post-Quantum Cryptography Assessment Tool
#[derive(Parser)]
#[command(name = "quantum-scanner")]
#[command(author = "AllSecureX <engineering@allsecurex.com>")]
#[command(version)]
#[command(about = "Scan your codebase for quantum-vulnerable cryptography", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Use a specific config file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Output format (text, json, sarif)
    #[arg(short, long, global = true, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with AllSecureX platform
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },

    /// Scan a directory or repository for crypto vulnerabilities
    Scan {
        /// Path to scan (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Scan type: full, quick, or dependency
        #[arg(short = 't', long, default_value = "full")]
        scan_type: String,

        /// Include patterns (glob)
        #[arg(short, long)]
        include: Option<Vec<String>>,

        /// Exclude patterns (glob)
        #[arg(short, long)]
        exclude: Option<Vec<String>>,

        /// Sync results to AllSecureX platform
        #[arg(long, default_value = "true")]
        sync: bool,

        /// Generate executive summary (requires Professional tier)
        #[arg(long)]
        executive: bool,

        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// CI/CD mode (no interactive prompts)
        #[arg(long)]
        ci: bool,
    },

    /// View scan history and reports (local or cloud)
    Report {
        /// Scan ID to view (optional, shows latest if not specified)
        scan_id: Option<String>,

        /// List all local scans
        #[arg(short, long)]
        list: bool,

        /// Open report in default viewer/browser
        #[arg(long)]
        open: bool,

        /// Use local reports (default: true for faster access)
        #[arg(long, default_value = "true")]
        local: bool,

        /// Export format: json, html
        #[arg(short, long)]
        export: Option<String>,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// View scan history
    History {
        /// Number of recent scans to show
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Check quota and subscription status
    Quota,

    /// Configure scanner settings
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },

    /// Check for updates
    Upgrade,
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Login with API key
    Login {
        /// API key (or set ALLSECUREX_API_KEY env var)
        #[arg(short, long, env = "ALLSECUREX_API_KEY")]
        key: Option<String>,
    },

    /// Logout and clear credentials
    Logout,

    /// Show current authentication status
    Status,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Set a configuration value
    Set { key: String, value: String },

    /// Reset configuration to defaults
    Reset,
}

fn print_banner() {
    println!();
    println!(
        "{}",
        r#"
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║      ◆ AllSecureX Quantum Scanner                                ║
    ║      Post-Quantum Cryptography Assessment Tool                   ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    "#
        .cyan()
    );
}

fn print_footer() {
    println!();
    println!(
        "{}",
        "    ─────────────────────────────────────────────────────────────────".dimmed()
    );
    println!(
        "    {} {}",
        "Website:".dimmed(),
        "https://allsecurex.com".blue()
    );
    println!(
        "    {} {}",
        "QuantumVault SDK:".dimmed(),
        "https://quantumvault.allsecurex.com".blue()
    );
    println!(
        "    {} {}",
        "Documentation:".dimmed(),
        "https://allsecurex.com/api-docs".blue()
    );
    println!();
    println!("    {}", format!("© {} AllSecureX. All rights reserved.", chrono::Utc::now().format("%Y")).dimmed());
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("quantum_scanner=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // Load configuration
    let config = config::Config::load(cli.config.as_ref())?;

    match cli.command {
        Commands::Auth { action } => match action {
            AuthCommands::Login { key } => {
                print_banner();
                auth::login(key).await?;
                print_footer();
            }
            AuthCommands::Logout => {
                auth::logout()?;
                println!("{}", "✓ Logged out successfully".green());
            }
            AuthCommands::Status => {
                print_banner();
                auth::status().await?;
                print_footer();
            }
        },

        Commands::Scan {
            path,
            scan_type,
            include,
            exclude,
            sync,
            executive,
            output,
            ci,
        } => {
            if !ci {
                print_banner();
            }

            // Check authentication
            let api_key = auth::get_stored_api_key()?;
            if api_key.is_none() {
                eprintln!(
                    "{}",
                    "Error: Not authenticated. Run 'quantum-scanner auth login' first.".red()
                );
                std::process::exit(1);
            }

            // Run scan
            let result = scanner::run_scan(
                &path,
                &scan_type,
                include,
                exclude,
                sync,
                executive,
                output.as_ref(),
                ci,
                &config,
            )
            .await?;

            if cli.format == "json" {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                // Text output is handled by scanner module
            }

            if !ci {
                print_footer();
            }
        }

        Commands::Report {
            scan_id,
            list,
            open,
            local,
            export,
            output,
        } => {
            print_banner();

            if list {
                // List local scans
                api::list_local_scans()?;
            } else if local {
                // View local report (faster, full details)
                api::view_local_report(
                    scan_id.as_deref(),
                    open,
                    export.as_deref(),
                    output.as_ref(),
                )?;
            } else {
                // Cloud report (requires auth)
                let api_key = auth::get_stored_api_key()?;
                if api_key.is_none() {
                    eprintln!(
                        "{}",
                        "Error: Not authenticated. Run 'quantum-scanner auth login' first.".red()
                    );
                    std::process::exit(1);
                }
                api::get_report(scan_id.as_deref(), export.as_deref(), output.as_ref()).await?;
            }
            print_footer();
        }

        Commands::History { limit } => {
            print_banner();
            let api_key = auth::get_stored_api_key()?;
            if api_key.is_none() {
                eprintln!(
                    "{}",
                    "Error: Not authenticated. Run 'quantum-scanner auth login' first.".red()
                );
                std::process::exit(1);
            }

            api::get_history(limit).await?;
            print_footer();
        }

        Commands::Quota => {
            print_banner();
            let api_key = auth::get_stored_api_key()?;
            if api_key.is_none() {
                eprintln!(
                    "{}",
                    "Error: Not authenticated. Run 'quantum-scanner auth login' first.".red()
                );
                std::process::exit(1);
            }

            api::get_quota().await?;
            print_footer();
        }

        Commands::Config { action } => match action {
            ConfigCommands::Show => {
                config::show(&config)?;
            }
            ConfigCommands::Set { key, value } => {
                config::set(&key, &value)?;
                println!("{}", format!("✓ Set {} = {}", key, value).green());
            }
            ConfigCommands::Reset => {
                config::reset()?;
                println!("{}", "✓ Configuration reset to defaults".green());
            }
        },

        Commands::Upgrade => {
            print_banner();
            println!("Checking for updates...");
            // Check current version against latest
            let latest = api::check_version().await?;
            if latest.is_some() {
                println!(
                    "{}",
                    format!("New version available: {}", latest.unwrap()).yellow()
                );
                println!("Download: https://scanner.allsecurex.com/install");
            } else {
                println!("{}", "✓ You're running the latest version!".green());
            }
            print_footer();
        }
    }

    Ok(())
}

//! QuantumVault CLI - Command-line interface for post-quantum cryptography.

mod commands;
mod config;
mod output;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// QuantumVault SDK - Post-Quantum Cryptography CLI
#[derive(Parser)]
#[command(name = "quantumvault")]
#[command(author = "AllSecureX <security@allsecurex.com>")]
#[command(version)]
#[command(about = "Post-quantum cryptography CLI for enterprise applications", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<String>,

    /// Output format (text, json, yaml)
    #[arg(short, long, global = true, default_value = "text")]
    format: String,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize QuantumVault configuration
    Init {
        /// API key for AllSecureX platform
        #[arg(long)]
        api_key: Option<String>,

        /// AWS region
        #[arg(long, default_value = "us-east-1")]
        region: String,

        /// Force overwrite existing configuration
        #[arg(short, long)]
        force: bool,
    },

    /// Key management commands
    #[command(subcommand)]
    Key(KeyCommands),

    /// Encryption and decryption commands
    #[command(subcommand)]
    Crypto(CryptoCommands),

    /// Digital signature commands
    #[command(subcommand)]
    Sign(SignCommands),

    /// Migration commands
    #[command(subcommand)]
    Migrate(MigrateCommands),

    /// Wrappers around the standalone PQC tool binaries
    /// (archive, smime, ca, dnssec, jwt-proxy, acme-server, acme-client).
    #[command(subcommand)]
    Tools(commands::tools::ToolCommands),

    /// Test the configuration and connection
    Test,

    /// Show current configuration
    Config,

    /// Display information about supported algorithms
    Algorithms,
}

#[derive(Subcommand)]
pub enum KeyCommands {
    /// Generate a new key pair
    Generate {
        /// Algorithm to use (ml-kem-768, ml-dsa-65, etc.)
        #[arg(short, long, default_value = "ml-kem-768")]
        algorithm: String,

        /// Key name/label
        #[arg(short, long)]
        name: Option<String>,

        /// Key expiration in days (0 = no expiration)
        #[arg(short, long, default_value = "0")]
        expires: u32,

        /// Output file for public key
        #[arg(long)]
        output_public: Option<String>,

        /// Output file for secret key
        #[arg(long)]
        output_secret: Option<String>,
    },

    /// List all keys
    List {
        /// Show only keys with this status
        #[arg(long)]
        status: Option<String>,

        /// Show detailed output
        #[arg(short, long)]
        detailed: bool,
    },

    /// Show key details
    Show {
        /// Key ID
        key_id: String,
    },

    /// Export a public key
    Export {
        /// Key ID
        key_id: String,

        /// Output file
        #[arg(short, long)]
        output: Option<String>,

        /// Export format (pem, der, raw)
        #[arg(long, default_value = "pem")]
        format: String,
    },

    /// Rotate a key
    Rotate {
        /// Key ID to rotate
        key_id: String,
    },

    /// Revoke a key
    Revoke {
        /// Key ID to revoke
        key_id: String,

        /// Reason for revocation
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Delete a key
    Delete {
        /// Key ID to delete
        key_id: String,

        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum CryptoCommands {
    /// Encrypt data
    Encrypt {
        /// Input file (or - for stdin)
        input: String,

        /// Output file (or - for stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Key ID or key file to use
        #[arg(short, long)]
        key: String,
    },

    /// Decrypt data
    Decrypt {
        /// Input file (or - for stdin)
        input: String,

        /// Output file (or - for stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Key ID or key file to use
        #[arg(short, long)]
        key: String,
    },
}

#[derive(Subcommand)]
pub enum SignCommands {
    /// Sign a file or message
    Create {
        /// Input file (or - for stdin)
        input: String,

        /// Output signature file
        #[arg(short, long)]
        output: Option<String>,

        /// Key ID to use for signing
        #[arg(short, long)]
        key: String,

        /// Detached signature (don't include message)
        #[arg(short, long)]
        detached: bool,
    },

    /// Verify a signature
    Verify {
        /// Input file (signed or original)
        input: String,

        /// Signature file (for detached signatures)
        #[arg(short, long)]
        signature: Option<String>,

        /// Key ID or public key file
        #[arg(short, long)]
        key: String,
    },
}

#[derive(Subcommand)]
pub enum MigrateCommands {
    /// Scan codebase for crypto usage
    Scan {
        /// Path to scan
        #[arg(default_value = ".")]
        path: String,

        /// Output report file
        #[arg(short, long)]
        output: Option<String>,

        /// File patterns to include
        #[arg(long)]
        include: Option<Vec<String>>,

        /// File patterns to exclude
        #[arg(long)]
        exclude: Option<Vec<String>>,
    },

    /// Generate migration plan
    Plan {
        /// Scan report file
        report: String,

        /// Migration strategy (direct, hybrid, parallel)
        #[arg(long, default_value = "hybrid")]
        strategy: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(filter)
        .init();

    // Handle color settings
    if cli.no_color {
        colored::control::set_override(false);
    }

    // Load configuration
    let app_config = config::load_config(cli.config.as_deref())?;

    // Execute command
    let result = match cli.command {
        Commands::Init {
            api_key,
            region,
            force,
        } => commands::init::run(api_key, region, force).await,
        Commands::Key(cmd) => commands::key::run(cmd, &app_config).await,
        Commands::Crypto(cmd) => commands::crypto::run(cmd, &app_config).await,
        Commands::Sign(cmd) => commands::sign::run(cmd, &app_config).await,
        Commands::Migrate(cmd) => commands::migrate::run(cmd, &app_config).await,
        Commands::Tools(cmd) => commands::tools::run(cmd).await,
        Commands::Test => commands::test::run(&app_config).await,
        Commands::Config => commands::config::run(&app_config).await,
        Commands::Algorithms => commands::algorithms::run().await,
    };

    // Handle result
    match result {
        Ok(output) => {
            output::print_output(&output, &cli.format)?;
            Ok(())
        }
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            std::process::exit(1);
        }
    }
}

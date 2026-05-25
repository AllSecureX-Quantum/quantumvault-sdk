//! Initialize command for QuantumVault CLI.

use crate::config::CliConfig;
use crate::output::CommandOutput;
use anyhow::Result;
use colored::Colorize;
use dialoguer::{Input, Select};

/// Run the init command.
pub async fn run(api_key: Option<String>, region: String, force: bool) -> Result<CommandOutput> {
    let config_path = CliConfig::config_path();

    // Check if config already exists
    if config_path.exists() && !force {
        println!(
            "{} Configuration already exists at {}",
            "Warning:".yellow(),
            config_path.display()
        );
        println!("Use --force to overwrite");
        return Ok(CommandOutput::error("Configuration already exists"));
    }

    println!();
    println!("{}", "QuantumVault SDK Initialization".bold().cyan());
    println!("{}", "=".repeat(40));
    println!();

    // Get API key if not provided
    let api_key = if let Some(key) = api_key {
        key
    } else {
        Input::new()
            .with_prompt("AllSecureX API Key (optional, press Enter to skip)")
            .allow_empty(true)
            .interact_text()?
    };

    // Get default algorithm
    let algorithms = vec![
        "ml-kem-768 (recommended)",
        "ml-kem-512",
        "ml-kem-1024",
        "ml-dsa-65 (recommended for signing)",
        "ml-dsa-44",
        "ml-dsa-87",
    ];

    let algorithm_idx = Select::new()
        .with_prompt("Select default algorithm")
        .items(&algorithms)
        .default(0)
        .interact()?;

    let default_algorithm = match algorithm_idx {
        0 => "ml-kem-768",
        1 => "ml-kem-512",
        2 => "ml-kem-1024",
        3 => "ml-dsa-65",
        4 => "ml-dsa-44",
        5 => "ml-dsa-87",
        _ => "ml-kem-768",
    }
    .to_string();

    // Get security level
    let levels = vec![
        "Level 3 - AES-192 equivalent (recommended)",
        "Level 1 - AES-128 equivalent",
        "Level 5 - AES-256 equivalent (highest)",
    ];

    let level_idx = Select::new()
        .with_prompt("Select security level")
        .items(&levels)
        .default(0)
        .interact()?;

    let security_level = match level_idx {
        0 => "level3",
        1 => "level1",
        2 => "level5",
        _ => "level3",
    }
    .to_string();

    // Create configuration
    let config = CliConfig {
        api_key: if api_key.is_empty() {
            None
        } else {
            Some(api_key)
        },
        region,
        default_algorithm,
        security_level,
        enable_telemetry: false,
        ..Default::default()
    };

    // Create key storage directory
    std::fs::create_dir_all(&config.key_storage_path)?;

    // Save configuration
    config.save()?;

    println!();
    println!(
        "{} Configuration saved to {}",
        "✓".green(),
        config_path.display()
    );
    println!(
        "{} Key storage directory: {}",
        "✓".green(),
        config.key_storage_path.display()
    );
    println!();
    println!("{}", "Quick Start:".bold());
    println!("  quantumvault key generate --name my-first-key");
    println!("  quantumvault key list");
    println!("  quantumvault test");
    println!();

    Ok(CommandOutput::success_with_data(
        "Configuration initialized successfully",
        serde_json::json!({
            "config_path": config_path.to_string_lossy(),
            "key_storage_path": config.key_storage_path.to_string_lossy(),
        }),
    ))
}

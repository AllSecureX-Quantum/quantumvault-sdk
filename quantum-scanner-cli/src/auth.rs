//! Authentication module for AllSecureX Quantum Scanner
//!
//! Handles API key storage using a local config file (~/.quantum-scanner/config.json).
//! This approach is similar to AWS CLI, GitHub CLI, and other popular tools.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthInfo {
    pub org_id: String,
    pub org_name: String,
    pub tier: String,
    pub email: Option<String>,
    pub scans_used: i32,
    pub scans_limit: i32,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ConfigFile {
    api_key: Option<String>,
}

/// Get the config directory path (~/.quantum-scanner)
fn get_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not find home directory")?;
    Ok(home.join(".quantum-scanner"))
}

/// Get the config file path (~/.quantum-scanner/config.json)
fn get_config_path() -> Result<PathBuf> {
    Ok(get_config_dir()?.join("config.json"))
}

/// Get the stored API key from config file or env var
pub fn get_stored_api_key() -> Result<Option<String>> {
    // First check environment variable
    if let Ok(key) = std::env::var("ALLSECUREX_API_KEY") {
        return Ok(Some(key));
    }

    // Then check config file
    let config_path = get_config_path()?;
    if config_path.exists() {
        let content = fs::read_to_string(&config_path)?;
        let config: ConfigFile = serde_json::from_str(&content).unwrap_or_default();
        return Ok(config.api_key);
    }

    Ok(None)
}

/// Store API key in config file
fn store_api_key(key: &str) -> Result<()> {
    let config_dir = get_config_dir()?;
    fs::create_dir_all(&config_dir)?;

    let config = ConfigFile {
        api_key: Some(key.to_string()),
    };

    let config_path = get_config_path()?;
    let content = serde_json::to_string_pretty(&config)?;
    fs::write(&config_path, content)?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&config_path)?.permissions();
        perms.set_mode(0o600); // Only owner can read/write
        fs::set_permissions(&config_path, perms)?;
    }

    Ok(())
}

/// Delete stored API key
fn delete_api_key() -> Result<()> {
    let config_path = get_config_path()?;
    if config_path.exists() {
        fs::remove_file(&config_path)?;
    }
    Ok(())
}

/// Login with API key
pub async fn login(key: Option<String>) -> Result<()> {
    let api_key = if let Some(k) = key {
        k
    } else {
        // Interactive prompt
        println!("Enter your AllSecureX API key:");
        print!("  > ");
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        input.trim().to_string()
    };

    if api_key.is_empty() {
        anyhow::bail!("API key cannot be empty");
    }

    if !api_key.starts_with("qv_") {
        anyhow::bail!("Invalid API key format. Keys should start with 'qv_'");
    }

    println!();
    println!("  {} Verifying API key...", "⠋".cyan());

    // Verify with API
    let auth_info = verify_api_key(&api_key).await?;

    // Store in keyring
    store_api_key(&api_key).context("Failed to store API key securely")?;

    println!("  {} API key verified", "✓".green());
    println!(
        "  {} Account linked: {}",
        "✓".green(),
        auth_info.org_name.cyan()
    );
    println!(
        "  {} Plan: {} ({} scans/month)",
        "✓".green(),
        auth_info.tier.to_uppercase().yellow(),
        if auth_info.scans_limit < 0 {
            "Unlimited".to_string()
        } else {
            auth_info.scans_limit.to_string()
        }
    );
    println!();
    println!(
        "  {}",
        "You're ready to scan! Run: quantum-scanner scan".green()
    );

    Ok(())
}

/// Logout and clear credentials
pub fn logout() -> Result<()> {
    delete_api_key()?;
    Ok(())
}

/// Show authentication status
pub async fn status() -> Result<()> {
    let api_key = get_stored_api_key()?;

    if let Some(key) = api_key {
        println!("  {} Checking authentication...", "⠋".cyan());

        match verify_api_key(&key).await {
            Ok(auth_info) => {
                println!();
                println!("  {} Authenticated", "✓".green());
                println!();
                println!("  ┌─────────────────────────────────────────────────────────┐");
                println!(
                    "  │ {} {:<47} │",
                    "Organization:".dimmed(),
                    auth_info.org_name
                );
                println!(
                    "  │ {} {:<47} │",
                    "Tier:        ".dimmed(),
                    auth_info.tier.to_uppercase()
                );
                if let Some(email) = &auth_info.email {
                    println!("  │ {} {:<47} │", "Email:       ".dimmed(), email);
                }
                println!(
                    "  │ {} {:<47} │",
                    "Scans Used:  ".dimmed(),
                    format!(
                        "{}/{}",
                        auth_info.scans_used,
                        if auth_info.scans_limit < 0 {
                            "∞".to_string()
                        } else {
                            auth_info.scans_limit.to_string()
                        }
                    )
                );
                println!(
                    "  │ {} {:<47} │",
                    "API Key:     ".dimmed(),
                    mask_api_key(&key)
                );
                println!("  └─────────────────────────────────────────────────────────┘");
            }
            Err(e) => {
                println!("  {} Authentication failed: {}", "✗".red(), e);
                println!("  Run 'quantum-scanner auth login' to re-authenticate.");
            }
        }
    } else {
        println!("  {} Not authenticated", "✗".red());
        println!();
        println!("  Run 'quantum-scanner auth login' to authenticate.");
    }

    Ok(())
}

/// Verify API key with AllSecureX API
async fn verify_api_key(key: &str) -> Result<AuthInfo> {
    let client = reqwest::Client::new();

    let response = client
        .get("https://scanner-api.quantumvault.allsecurex.com/scanner/quota")
        .header("X-API-Key", key)
        .header("User-Agent", "AllSecureX-Quantum-Scanner/1.0.0")
        .send()
        .await
        .context("Failed to connect to AllSecureX API")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("API authentication failed ({}): {}", status, body);
    }

    #[derive(Deserialize)]
    struct ApiResponse {
        success: bool,
        data: QuotaData,
    }

    #[derive(Deserialize)]
    struct QuotaData {
        tier: String,
        used: i32,
        limit: i32,
        #[serde(default)]
        org_name: Option<String>,
        #[serde(default)]
        org_id: Option<String>,
        #[serde(default)]
        email: Option<String>,
    }

    let api_response: ApiResponse = response
        .json()
        .await
        .context("Failed to parse API response")?;

    Ok(AuthInfo {
        org_id: api_response.data.org_id.unwrap_or_default(),
        org_name: api_response
            .data
            .org_name
            .unwrap_or_else(|| "Your Organization".to_string()),
        tier: api_response.data.tier,
        email: api_response.data.email,
        scans_used: api_response.data.used,
        scans_limit: api_response.data.limit,
    })
}

fn mask_api_key(key: &str) -> String {
    if key.len() <= 8 {
        "****".to_string()
    } else {
        format!("{}****{}", &key[..7], &key[key.len() - 4..])
    }
}

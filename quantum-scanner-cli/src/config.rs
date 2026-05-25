//! Configuration module for AllSecureX Quantum Scanner

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const CONFIG_FILE_NAME: &str = "quantum-scanner.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// AllSecureX API endpoint
    #[serde(default = "default_api_endpoint")]
    pub api_endpoint: String,

    /// Default scan type
    #[serde(default = "default_scan_type")]
    pub default_scan_type: String,

    /// Default exclude patterns
    #[serde(default = "default_exclude_patterns")]
    pub exclude_patterns: Vec<String>,

    /// Auto-sync results to cloud
    #[serde(default = "default_true")]
    pub auto_sync: bool,

    /// Show progress bar
    #[serde(default = "default_true")]
    pub show_progress: bool,

    /// Minimum severity to report (info, low, medium, high, critical)
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Maximum file size to scan (in KB)
    #[serde(default = "default_max_file_size")]
    pub max_file_size_kb: u64,

    /// Number of parallel workers
    #[serde(default = "default_workers")]
    pub parallel_workers: usize,
}

fn default_api_endpoint() -> String {
    "https://api.allsecurex.com".to_string()
}

fn default_scan_type() -> String {
    "full".to_string()
}

fn default_exclude_patterns() -> Vec<String> {
    vec![
        "node_modules/**".to_string(),
        ".git/**".to_string(),
        "vendor/**".to_string(),
        "dist/**".to_string(),
        "build/**".to_string(),
        "target/**".to_string(),
        "__pycache__/**".to_string(),
        "*.lock".to_string(),
        "*.min.js".to_string(),
        "*.bundle.js".to_string(),
    ]
}

fn default_true() -> bool {
    true
}

fn default_min_severity() -> String {
    "low".to_string()
}

fn default_max_file_size() -> u64 {
    1024 // 1 MB
}

fn default_workers() -> usize {
    num_cpus::get().max(4)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_endpoint: default_api_endpoint(),
            default_scan_type: default_scan_type(),
            exclude_patterns: default_exclude_patterns(),
            auto_sync: default_true(),
            show_progress: default_true(),
            min_severity: default_min_severity(),
            max_file_size_kb: default_max_file_size(),
            parallel_workers: default_workers(),
        }
    }
}

impl Config {
    /// Load configuration from file or defaults
    pub fn load(custom_path: Option<&PathBuf>) -> Result<Self> {
        let config_path = if let Some(path) = custom_path {
            path.clone()
        } else {
            get_config_path()?
        };

        if config_path.exists() {
            let content =
                std::fs::read_to_string(&config_path).context("Failed to read config file")?;
            let config: Config = toml::from_str(&content).context("Failed to parse config file")?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<()> {
        let config_path = get_config_path()?;

        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        std::fs::write(&config_path, content)?;
        Ok(())
    }
}

/// Get the configuration file path
fn get_config_path() -> Result<PathBuf> {
    let config_dir = dirs::config_dir()
        .context("Could not determine config directory")?
        .join("allsecurex");

    Ok(config_dir.join(CONFIG_FILE_NAME))
}

/// Show current configuration
pub fn show(config: &Config) -> Result<()> {
    println!("Current Configuration:");
    println!("  API Endpoint:      {}", config.api_endpoint);
    println!("  Default Scan Type: {}", config.default_scan_type);
    println!("  Auto Sync:         {}", config.auto_sync);
    println!("  Show Progress:     {}", config.show_progress);
    println!("  Min Severity:      {}", config.min_severity);
    println!("  Max File Size:     {} KB", config.max_file_size_kb);
    println!("  Parallel Workers:  {}", config.parallel_workers);
    println!("  Exclude Patterns:");
    for pattern in &config.exclude_patterns {
        println!("    - {}", pattern);
    }
    Ok(())
}

/// Set a configuration value
pub fn set(key: &str, value: &str) -> Result<()> {
    let config_path = get_config_path()?;
    let mut config = if config_path.exists() {
        Config::load(Some(&config_path))?
    } else {
        Config::default()
    };

    match key {
        "api_endpoint" => config.api_endpoint = value.to_string(),
        "default_scan_type" => config.default_scan_type = value.to_string(),
        "auto_sync" => config.auto_sync = value.parse()?,
        "show_progress" => config.show_progress = value.parse()?,
        "min_severity" => config.min_severity = value.to_string(),
        "max_file_size_kb" => config.max_file_size_kb = value.parse()?,
        "parallel_workers" => config.parallel_workers = value.parse()?,
        _ => anyhow::bail!("Unknown configuration key: {}", key),
    }

    config.save()?;
    Ok(())
}

/// Reset configuration to defaults
pub fn reset() -> Result<()> {
    let config = Config::default();
    config.save()?;
    Ok(())
}

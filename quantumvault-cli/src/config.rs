//! CLI configuration management.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// CLI configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// AllSecureX API key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// AWS region.
    #[serde(default = "default_region")]
    pub region: String,

    /// Default algorithm for key generation.
    #[serde(default = "default_algorithm")]
    pub default_algorithm: String,

    /// Default security level.
    #[serde(default = "default_security_level")]
    pub security_level: String,

    /// Key storage path.
    #[serde(default = "default_key_storage_path")]
    pub key_storage_path: PathBuf,

    /// Enable telemetry.
    #[serde(default)]
    pub enable_telemetry: bool,

    /// Project ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_algorithm() -> String {
    "ml-kem-768".to_string()
}

fn default_security_level() -> String {
    "level3".to_string()
}

fn default_key_storage_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("quantumvault")
        .join("keys")
}

impl CliConfig {
    /// Get the configuration file path.
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("quantumvault")
            .join("config.yaml")
    }

    /// Save configuration to file.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();

        // Create parent directories
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_yaml::to_string(self)?;
        std::fs::write(&path, content)?;

        Ok(())
    }
}

/// Load configuration from file or environment.
pub fn load_config(config_path: Option<&str>) -> Result<CliConfig> {
    let path = config_path
        .map(PathBuf::from)
        .unwrap_or_else(CliConfig::config_path);

    // Try to load from file
    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let mut config: CliConfig =
            serde_yaml::from_str(&content).with_context(|| "Failed to parse config file")?;

        // Override with environment variables
        override_from_env(&mut config);

        return Ok(config);
    }

    // Create default config with environment overrides
    let mut config = CliConfig::default();
    override_from_env(&mut config);

    Ok(config)
}

/// Override configuration from environment variables.
fn override_from_env(config: &mut CliConfig) {
    if let Ok(api_key) = std::env::var("QUANTUMVAULT_API_KEY") {
        config.api_key = Some(api_key);
    }

    if let Ok(region) = std::env::var("QUANTUMVAULT_REGION") {
        config.region = region;
    }

    if let Ok(algorithm) = std::env::var("QUANTUMVAULT_DEFAULT_ALGORITHM") {
        config.default_algorithm = algorithm;
    }

    if let Ok(level) = std::env::var("QUANTUMVAULT_SECURITY_LEVEL") {
        config.security_level = level;
    }

    if let Ok(path) = std::env::var("QUANTUMVAULT_KEY_STORAGE") {
        config.key_storage_path = PathBuf::from(path);
    }

    if std::env::var("QUANTUMVAULT_ENABLE_TELEMETRY").is_ok() {
        config.enable_telemetry = true;
    }

    if let Ok(project_id) = std::env::var("QUANTUMVAULT_PROJECT_ID") {
        config.project_id = Some(project_id);
    }
}

//! Configuration management for QuantumVault.

mod compliance;
mod performance;
mod security_levels;

pub use compliance::ComplianceProfile;
pub use performance::PerformanceProfile;
pub use security_levels::SecurityLevel;

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// QuantumVault configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// NIST security level (1-5).
    pub security_level: SecurityLevel,
    /// Compliance profile (CNSA 2.0, FIPS, etc.).
    pub compliance_profile: ComplianceProfile,
    /// Performance profile.
    pub performance_profile: PerformanceProfile,
    /// Enable telemetry reporting.
    pub enable_telemetry: bool,
    /// AllSecureX API key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// AWS region.
    #[serde(default = "default_region")]
    pub region: String,
    /// Project ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Organization ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    /// Default symmetric algorithm.
    pub default_symmetric_algorithm: SymmetricAlgorithmConfig,
    /// Enable strict mode (fail on any warning).
    #[serde(default)]
    pub strict_mode: bool,
    /// Maximum key age in seconds (0 = no limit).
    #[serde(default)]
    pub max_key_age_seconds: u64,
    /// Enable key rotation reminders.
    #[serde(default = "default_true")]
    pub key_rotation_reminders: bool,
    /// Key rotation reminder threshold in days.
    #[serde(default = "default_rotation_days")]
    pub key_rotation_reminder_days: u32,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_true() -> bool {
    true
}

fn default_rotation_days() -> u32 {
    30
}

impl Default for Config {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Level3,
            compliance_profile: ComplianceProfile::Standard,
            performance_profile: PerformanceProfile::Balanced,
            enable_telemetry: false,
            api_key: None,
            region: default_region(),
            project_id: None,
            organization_id: None,
            default_symmetric_algorithm: SymmetricAlgorithmConfig::Aes256Gcm,
            strict_mode: false,
            max_key_age_seconds: 0,
            key_rotation_reminders: true,
            key_rotation_reminder_days: 30,
        }
    }
}

impl Config {
    /// Create a new configuration builder.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// Load configuration from a file.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let ext = path.extension().and_then(|e| e.to_str());

        match ext {
            Some("yaml") | Some("yml") => {
                serde_yaml::from_str(&contents).map_err(|e| Error::Configuration(e.to_string()))
            }
            Some("json") => {
                serde_json::from_str(&contents).map_err(|e| Error::Configuration(e.to_string()))
            }
            _ => Err(Error::Configuration(
                "Unsupported config file format".into(),
            )),
        }
    }

    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        if let Ok(level) = std::env::var("QUANTUMVAULT_SECURITY_LEVEL") {
            config.security_level = level.parse()?;
        }

        if let Ok(profile) = std::env::var("QUANTUMVAULT_COMPLIANCE_PROFILE") {
            config.compliance_profile = profile.parse()?;
        }

        if let Ok(api_key) = std::env::var("QUANTUMVAULT_API_KEY") {
            config.api_key = Some(api_key);
        }

        if let Ok(region) = std::env::var("QUANTUMVAULT_REGION") {
            config.region = region;
        }

        if let Ok(project_id) = std::env::var("QUANTUMVAULT_PROJECT_ID") {
            config.project_id = Some(project_id);
        }

        if std::env::var("QUANTUMVAULT_ENABLE_TELEMETRY").is_ok() {
            config.enable_telemetry = true;
        }

        Ok(config)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate compliance requirements
        self.compliance_profile
            .validate_security_level(self.security_level)?;

        // Validate API key if telemetry is enabled
        if self.enable_telemetry && self.api_key.is_none() {
            return Err(Error::Configuration(
                "API key required when telemetry is enabled".into(),
            ));
        }

        Ok(())
    }
}

/// Configuration builder.
#[derive(Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Set the security level.
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.config.security_level = level;
        self
    }

    /// Set the compliance profile.
    pub fn compliance_profile(mut self, profile: ComplianceProfile) -> Self {
        self.config.compliance_profile = profile;
        self
    }

    /// Set the performance profile.
    pub fn performance_profile(mut self, profile: PerformanceProfile) -> Self {
        self.config.performance_profile = profile;
        self
    }

    /// Enable or disable telemetry.
    pub fn enable_telemetry(mut self, enable: bool) -> Self {
        self.config.enable_telemetry = enable;
        self
    }

    /// Set the API key.
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.config.api_key = Some(key.into());
        self
    }

    /// Set the AWS region.
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.config.region = region.into();
        self
    }

    /// Set the project ID.
    pub fn project_id(mut self, id: impl Into<String>) -> Self {
        self.config.project_id = Some(id.into());
        self
    }

    /// Set the organization ID.
    pub fn organization_id(mut self, id: impl Into<String>) -> Self {
        self.config.organization_id = Some(id.into());
        self
    }

    /// Enable strict mode.
    pub fn strict_mode(mut self, strict: bool) -> Self {
        self.config.strict_mode = strict;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Result<Config> {
        self.config.validate()?;
        Ok(self.config)
    }
}

/// Symmetric algorithm configuration.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SymmetricAlgorithmConfig {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM (default, recommended).
    #[default]
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

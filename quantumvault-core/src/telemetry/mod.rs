//! Telemetry collection for AllSecureX integration.
//!
//! Collects cryptographic operation metrics for monitoring and compliance.

mod collector;
mod events;
mod exporter;
mod metrics;

pub use collector::TelemetryCollector;
pub use events::{CryptoEvent, EventSeverity};
pub use metrics::Metrics;

use crate::config::Config;
use crate::primitives::Algorithm;
use std::time::Duration;

/// Telemetry configuration.
#[derive(Clone, Debug)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled.
    pub enabled: bool,
    /// AllSecureX API endpoint.
    pub endpoint: String,
    /// API key for authentication.
    pub api_key: Option<String>,
    /// Batch size for sending events.
    pub batch_size: usize,
    /// Flush interval in seconds.
    pub flush_interval_secs: u64,
    /// Whether to include detailed operation data.
    pub include_details: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "https://api.allsecurex.com/v1/telemetry".to_string(),
            api_key: None,
            batch_size: 100,
            flush_interval_secs: 60,
            include_details: false,
        }
    }
}

impl From<&Config> for TelemetryConfig {
    fn from(config: &Config) -> Self {
        Self {
            enabled: config.enable_telemetry,
            endpoint: "https://api.allsecurex.com/v1/telemetry".to_string(),
            api_key: config.api_key.clone(),
            batch_size: 100,
            flush_interval_secs: 60,
            include_details: false,
        }
    }
}

/// Operation type for telemetry tracking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperationType {
    /// Key generation operation.
    KeyGen,
    /// Encryption operation.
    Encrypt,
    /// Decryption operation.
    Decrypt,
    /// Signing operation.
    Sign,
    /// Verification operation.
    Verify,
    /// Key rotation operation.
    KeyRotation,
    /// Key import operation.
    KeyImport,
    /// Key export operation.
    KeyExport,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGen => write!(f, "keygen"),
            Self::Encrypt => write!(f, "encrypt"),
            Self::Decrypt => write!(f, "decrypt"),
            Self::Sign => write!(f, "sign"),
            Self::Verify => write!(f, "verify"),
            Self::KeyRotation => write!(f, "key_rotation"),
            Self::KeyImport => write!(f, "key_import"),
            Self::KeyExport => write!(f, "key_export"),
        }
    }
}

/// Operation result for telemetry.
#[derive(Clone, Debug)]
pub struct OperationRecord {
    /// Type of operation.
    pub operation: OperationType,
    /// Algorithm used.
    pub algorithm: Algorithm,
    /// Operation duration.
    pub duration: Duration,
    /// Whether operation succeeded.
    pub success: bool,
    /// Data size in bytes (if applicable).
    pub data_size: Option<usize>,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Timestamp of operation.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl OperationRecord {
    /// Create a new successful operation record.
    pub fn success(operation: OperationType, algorithm: Algorithm, duration: Duration) -> Self {
        Self {
            operation,
            algorithm,
            duration,
            success: true,
            data_size: None,
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a new failed operation record.
    pub fn failure(
        operation: OperationType,
        algorithm: Algorithm,
        duration: Duration,
        error: String,
    ) -> Self {
        Self {
            operation,
            algorithm,
            duration,
            success: false,
            data_size: None,
            error: Some(error),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Add data size to the record.
    pub fn with_data_size(mut self, size: usize) -> Self {
        self.data_size = Some(size);
        self
    }
}

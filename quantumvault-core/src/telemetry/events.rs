//! Security and audit events.

use crate::primitives::Algorithm;
use serde::{Deserialize, Serialize};

/// Severity level for crypto events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventSeverity {
    /// Informational event.
    Info,
    /// Warning - potential issue.
    Warning,
    /// Error - operation failed.
    Error,
    /// Critical - security concern.
    Critical,
}

/// A cryptographic security event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoEvent {
    /// Event ID.
    pub id: String,
    /// Event type.
    pub event_type: CryptoEventType,
    /// Event severity.
    pub severity: EventSeverity,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Related algorithm (if applicable).
    pub algorithm: Option<Algorithm>,
    /// Related key ID (if applicable).
    pub key_id: Option<String>,
    /// Human-readable message.
    pub message: String,
    /// Additional metadata.
    pub metadata: std::collections::HashMap<String, String>,
}

/// Types of cryptographic events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CryptoEventType {
    /// New key generated.
    KeyGenerated,
    /// Key is about to expire.
    KeyExpiringsSoon,
    /// Key has expired.
    KeyExpired,
    /// Key was rotated.
    KeyRotated,
    /// Key was revoked.
    KeyRevoked,
    /// Key was accessed.
    KeyAccessed,
    /// Encryption operation performed.
    EncryptionPerformed,
    /// Decryption operation performed.
    DecryptionPerformed,
    /// Decryption failed (potential attack).
    DecryptionFailed,
    /// Signature created.
    SignatureCreated,
    /// Signature verified.
    SignatureVerified,
    /// Signature verification failed.
    SignatureVerificationFailed,
    /// Legacy algorithm usage detected.
    LegacyAlgorithmUsed,
    /// Compliance violation detected.
    ComplianceViolation,
    /// Security policy violation.
    PolicyViolation,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Anomalous usage pattern detected.
    AnomalyDetected,
    /// Configuration changed.
    ConfigurationChanged,
}

impl CryptoEvent {
    /// Create a new event.
    pub fn new(
        event_type: CryptoEventType,
        severity: EventSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            event_type,
            severity,
            timestamp: chrono::Utc::now(),
            algorithm: None,
            key_id: None,
            message: message.into(),
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Set the algorithm.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Set the key ID.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Check if this is a security-critical event.
    pub fn is_security_critical(&self) -> bool {
        matches!(
            self.event_type,
            CryptoEventType::DecryptionFailed
                | CryptoEventType::SignatureVerificationFailed
                | CryptoEventType::PolicyViolation
                | CryptoEventType::ComplianceViolation
                | CryptoEventType::AnomalyDetected
        )
    }
}

/// Event builder for common events.
pub struct EventBuilder;

impl EventBuilder {
    /// Create a key generated event.
    pub fn key_generated(algorithm: Algorithm, key_id: &str) -> CryptoEvent {
        CryptoEvent::new(
            CryptoEventType::KeyGenerated,
            EventSeverity::Info,
            format!("New {} key generated", algorithm),
        )
        .with_algorithm(algorithm)
        .with_key_id(key_id)
    }

    /// Create a key expiring soon event.
    pub fn key_expiring_soon(key_id: &str, days_remaining: u32) -> CryptoEvent {
        CryptoEvent::new(
            CryptoEventType::KeyExpiringsSoon,
            EventSeverity::Warning,
            format!("Key {} expires in {} days", key_id, days_remaining),
        )
        .with_key_id(key_id)
        .with_metadata("days_remaining", days_remaining.to_string())
    }

    /// Create a decryption failed event.
    pub fn decryption_failed(key_id: &str, reason: &str) -> CryptoEvent {
        CryptoEvent::new(
            CryptoEventType::DecryptionFailed,
            EventSeverity::Warning,
            format!("Decryption failed for key {}: {}", key_id, reason),
        )
        .with_key_id(key_id)
        .with_metadata("reason", reason)
    }

    /// Create a legacy algorithm usage event.
    pub fn legacy_algorithm_used(algorithm: &str, location: &str) -> CryptoEvent {
        CryptoEvent::new(
            CryptoEventType::LegacyAlgorithmUsed,
            EventSeverity::Warning,
            format!("Legacy algorithm {} used in {}", algorithm, location),
        )
        .with_metadata("legacy_algorithm", algorithm)
        .with_metadata("location", location)
    }

    /// Create a compliance violation event.
    pub fn compliance_violation(profile: &str, reason: &str) -> CryptoEvent {
        CryptoEvent::new(
            CryptoEventType::ComplianceViolation,
            EventSeverity::Critical,
            format!("{} compliance violation: {}", profile, reason),
        )
        .with_metadata("compliance_profile", profile)
        .with_metadata("reason", reason)
    }
}

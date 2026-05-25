//! Metrics structures for telemetry.

use crate::primitives::Algorithm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Aggregated metrics for cryptographic operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    /// Total number of operations performed.
    pub total_operations: u64,
    /// Operations per second (average).
    pub operations_per_second: f64,
    /// Number of key generation operations.
    pub keygen_count: u64,
    /// Number of encryption operations.
    pub encrypt_count: u64,
    /// Number of decryption operations.
    pub decrypt_count: u64,
    /// Number of signing operations.
    pub sign_count: u64,
    /// Number of verification operations.
    pub verify_count: u64,
    /// Number of failed operations.
    pub failure_count: u64,
    /// Usage count per algorithm.
    pub algorithm_usage: HashMap<Algorithm, u64>,
    /// Average latency in microseconds.
    pub avg_latency_us: u64,
    /// 50th percentile latency in microseconds.
    pub p50_latency_us: u64,
    /// 95th percentile latency in microseconds.
    pub p95_latency_us: u64,
    /// 99th percentile latency in microseconds.
    pub p99_latency_us: u64,
    /// Uptime in seconds.
    pub uptime_secs: u64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            total_operations: 0,
            operations_per_second: 0.0,
            keygen_count: 0,
            encrypt_count: 0,
            decrypt_count: 0,
            sign_count: 0,
            verify_count: 0,
            failure_count: 0,
            algorithm_usage: HashMap::new(),
            avg_latency_us: 0,
            p50_latency_us: 0,
            p95_latency_us: 0,
            p99_latency_us: 0,
            uptime_secs: 0,
        }
    }
}

impl Metrics {
    /// Calculate success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        if self.total_operations == 0 {
            return 100.0;
        }
        let successes = self.total_operations - self.failure_count;
        (successes as f64 / self.total_operations as f64) * 100.0
    }

    /// Get the most used algorithm.
    pub fn most_used_algorithm(&self) -> Option<(Algorithm, u64)> {
        self.algorithm_usage
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(alg, count)| (*alg, *count))
    }

    /// Get algorithm usage as percentages.
    pub fn algorithm_usage_percentages(&self) -> HashMap<Algorithm, f64> {
        let total: u64 = self.algorithm_usage.values().sum();
        if total == 0 {
            return HashMap::new();
        }
        self.algorithm_usage
            .iter()
            .map(|(alg, count)| (*alg, (*count as f64 / total as f64) * 100.0))
            .collect()
    }
}

/// Real-time metrics for dashboard display.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RealtimeMetrics {
    /// Current operations per second.
    pub current_ops_per_sec: f64,
    /// Current average latency in milliseconds.
    pub current_avg_latency_ms: f64,
    /// Active connections/sessions.
    pub active_sessions: u32,
    /// Queue depth (pending operations).
    pub queue_depth: u32,
    /// Memory usage in bytes.
    pub memory_usage_bytes: u64,
}

/// Health status for the service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall health score (0-100).
    pub score: u8,
    /// Whether the service is healthy.
    pub healthy: bool,
    /// Individual component status.
    pub components: HashMap<String, ComponentHealth>,
    /// Warnings (non-critical issues).
    pub warnings: Vec<String>,
    /// Errors (critical issues).
    pub errors: Vec<String>,
}

/// Health status for a component.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name.
    pub name: String,
    /// Whether the component is healthy.
    pub healthy: bool,
    /// Component-specific message.
    pub message: String,
    /// Last check timestamp.
    pub last_check: chrono::DateTime<chrono::Utc>,
}

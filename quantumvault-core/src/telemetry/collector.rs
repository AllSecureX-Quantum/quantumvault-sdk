//! Telemetry collector for aggregating metrics.

use super::{Metrics, OperationRecord, OperationType, TelemetryConfig};
use crate::config::Config;
use crate::error::Result;
use crate::primitives::Algorithm;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Telemetry collector that aggregates cryptographic operation metrics.
pub struct TelemetryCollector {
    config: TelemetryConfig,
    counters: RwLock<OperationCounters>,
    latencies: RwLock<LatencyTracker>,
    algorithm_usage: RwLock<HashMap<Algorithm, u64>>,
    errors: RwLock<Vec<ErrorRecord>>,
    start_time: std::time::Instant,
}

#[derive(Default)]
struct OperationCounters {
    keygen: AtomicU64,
    encrypt: AtomicU64,
    decrypt: AtomicU64,
    sign: AtomicU64,
    verify: AtomicU64,
    failures: AtomicU64,
}

struct LatencyTracker {
    samples: HashMap<OperationType, Vec<u64>>,
    max_samples: usize,
}

impl Default for LatencyTracker {
    fn default() -> Self {
        Self {
            samples: HashMap::new(),
            max_samples: 10000,
        }
    }
}

#[derive(Clone, Debug)]
struct ErrorRecord {
    operation: OperationType,
    algorithm: Algorithm,
    message: String,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl TelemetryCollector {
    /// Create a new telemetry collector.
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            config: TelemetryConfig::from(config),
            counters: RwLock::new(OperationCounters::default()),
            latencies: RwLock::new(LatencyTracker::default()),
            algorithm_usage: RwLock::new(HashMap::new()),
            errors: RwLock::new(Vec::new()),
            start_time: std::time::Instant::now(),
        })
    }

    /// Record a cryptographic operation.
    pub fn record_operation(
        &self,
        operation: &str,
        algorithm: Algorithm,
        duration: Duration,
        success: bool,
    ) {
        if !self.config.enabled {
            return;
        }

        let op_type = match operation {
            "keygen" => OperationType::KeyGen,
            "encrypt" => OperationType::Encrypt,
            "decrypt" => OperationType::Decrypt,
            "sign" => OperationType::Sign,
            "verify" => OperationType::Verify,
            "hybrid_encrypt" => OperationType::Encrypt,
            "hybrid_decrypt" => OperationType::Decrypt,
            _ => return,
        };

        // Update counters
        {
            let counters = self.counters.read();
            match op_type {
                OperationType::KeyGen => counters.keygen.fetch_add(1, Ordering::Relaxed),
                OperationType::Encrypt => counters.encrypt.fetch_add(1, Ordering::Relaxed),
                OperationType::Decrypt => counters.decrypt.fetch_add(1, Ordering::Relaxed),
                OperationType::Sign => counters.sign.fetch_add(1, Ordering::Relaxed),
                OperationType::Verify => counters.verify.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
            if !success {
                counters.failures.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Track algorithm usage
        {
            let mut usage = self.algorithm_usage.write();
            *usage.entry(algorithm).or_insert(0) += 1;
        }

        // Track latency
        {
            let mut latencies = self.latencies.write();
            let max_samples = latencies.max_samples;
            let samples = latencies.samples.entry(op_type).or_insert_with(Vec::new);
            if samples.len() < max_samples {
                samples.push(duration.as_micros() as u64);
            }
        }
    }

    /// Record an operation with full details.
    pub fn record_operation_detailed(&self, record: OperationRecord) {
        self.record_operation(
            &record.operation.to_string(),
            record.algorithm,
            record.duration,
            record.success,
        );

        if !record.success {
            if let Some(error) = record.error {
                let mut errors = self.errors.write();
                if errors.len() < 1000 {
                    errors.push(ErrorRecord {
                        operation: record.operation,
                        algorithm: record.algorithm,
                        message: error,
                        timestamp: record.timestamp,
                    });
                }
            }
        }
    }

    /// Get current metrics snapshot.
    pub fn get_metrics(&self) -> Metrics {
        let counters = self.counters.read();
        let latencies = self.latencies.read();
        let usage = self.algorithm_usage.read();

        let total_operations = counters.keygen.load(Ordering::Relaxed)
            + counters.encrypt.load(Ordering::Relaxed)
            + counters.decrypt.load(Ordering::Relaxed)
            + counters.sign.load(Ordering::Relaxed)
            + counters.verify.load(Ordering::Relaxed);

        let uptime = self.start_time.elapsed();

        Metrics {
            total_operations,
            operations_per_second: if uptime.as_secs() > 0 {
                total_operations as f64 / uptime.as_secs() as f64
            } else {
                0.0
            },
            keygen_count: counters.keygen.load(Ordering::Relaxed),
            encrypt_count: counters.encrypt.load(Ordering::Relaxed),
            decrypt_count: counters.decrypt.load(Ordering::Relaxed),
            sign_count: counters.sign.load(Ordering::Relaxed),
            verify_count: counters.verify.load(Ordering::Relaxed),
            failure_count: counters.failures.load(Ordering::Relaxed),
            algorithm_usage: usage.clone(),
            avg_latency_us: calculate_avg_latency(&latencies),
            p50_latency_us: calculate_percentile_latency(&latencies, 50),
            p95_latency_us: calculate_percentile_latency(&latencies, 95),
            p99_latency_us: calculate_percentile_latency(&latencies, 99),
            uptime_secs: uptime.as_secs(),
        }
    }

    /// Reset all metrics.
    pub fn reset(&self) {
        let counters = self.counters.write();
        counters.keygen.store(0, Ordering::Relaxed);
        counters.encrypt.store(0, Ordering::Relaxed);
        counters.decrypt.store(0, Ordering::Relaxed);
        counters.sign.store(0, Ordering::Relaxed);
        counters.verify.store(0, Ordering::Relaxed);
        counters.failures.store(0, Ordering::Relaxed);

        self.latencies.write().samples.clear();
        self.algorithm_usage.write().clear();
        self.errors.write().clear();
    }
}

fn calculate_avg_latency(tracker: &LatencyTracker) -> u64 {
    let mut total: u64 = 0;
    let mut count: u64 = 0;
    for samples in tracker.samples.values() {
        total += samples.iter().sum::<u64>();
        count += samples.len() as u64;
    }
    if count > 0 {
        total / count
    } else {
        0
    }
}

fn calculate_percentile_latency(tracker: &LatencyTracker, percentile: u8) -> u64 {
    let mut all_samples: Vec<u64> = tracker
        .samples
        .values()
        .flat_map(|v| v.iter().copied())
        .collect();

    if all_samples.is_empty() {
        return 0;
    }

    all_samples.sort_unstable();
    let index = (all_samples.len() as f64 * (percentile as f64 / 100.0)) as usize;
    let index = index.min(all_samples.len() - 1);
    all_samples[index]
}

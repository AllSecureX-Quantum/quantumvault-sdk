//! Performance profile configuration for speed vs security tradeoffs.

use serde::{Deserialize, Serialize};

/// Performance profiles for different use cases.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PerformanceProfile {
    /// Optimize for lowest latency (smaller keys, faster algorithms).
    #[serde(rename = "speed")]
    Speed,
    /// Balanced performance and security (default).
    #[default]
    #[serde(rename = "balanced")]
    Balanced,
    /// Optimize for maximum security (larger keys, more conservative).
    #[serde(rename = "security")]
    Security,
    /// Optimize for batch operations (higher throughput).
    #[serde(rename = "throughput")]
    Throughput,
    /// Memory-constrained environments (smaller memory footprint).
    #[serde(rename = "memory_optimized")]
    MemoryOptimized,
}

impl PerformanceProfile {
    /// Get the description of this performance profile.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Speed => "Optimized for lowest latency with smaller keys",
            Self::Balanced => "Balanced performance and security (recommended)",
            Self::Security => "Maximum security with larger keys and conservative parameters",
            Self::Throughput => "Optimized for batch operations and high throughput",
            Self::MemoryOptimized => "Optimized for memory-constrained environments",
        }
    }

    /// Get batch size recommendation for this profile.
    pub fn recommended_batch_size(&self) -> usize {
        match self {
            Self::Speed => 1,
            Self::Balanced => 16,
            Self::Security => 1,
            Self::Throughput => 128,
            Self::MemoryOptimized => 4,
        }
    }

    /// Whether to use parallelization for operations.
    pub fn use_parallelization(&self) -> bool {
        matches!(self, Self::Throughput | Self::Balanced)
    }

    /// Get the number of threads to use for parallel operations.
    pub fn parallel_threads(&self) -> usize {
        match self {
            Self::Speed => 1,
            Self::Balanced => num_cpus::get().min(4),
            Self::Security => 1,
            Self::Throughput => num_cpus::get(),
            Self::MemoryOptimized => 1,
        }
    }

    /// Whether to cache derived keys.
    pub fn cache_derived_keys(&self) -> bool {
        matches!(self, Self::Speed | Self::Throughput)
    }

    /// Maximum cache size in bytes.
    pub fn max_cache_size(&self) -> usize {
        match self {
            Self::Speed => 64 * 1024 * 1024,          // 64 MB
            Self::Balanced => 16 * 1024 * 1024,       // 16 MB
            Self::Security => 0,                      // No caching
            Self::Throughput => 128 * 1024 * 1024,    // 128 MB
            Self::MemoryOptimized => 1 * 1024 * 1024, // 1 MB
        }
    }

    /// Whether to precompute values for faster operations.
    pub fn use_precomputation(&self) -> bool {
        matches!(self, Self::Speed | Self::Throughput | Self::Balanced)
    }
}

impl std::fmt::Display for PerformanceProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Speed => "Speed",
            Self::Balanced => "Balanced",
            Self::Security => "Security",
            Self::Throughput => "Throughput",
            Self::MemoryOptimized => "Memory Optimized",
        };
        write!(f, "{}", name)
    }
}

/// Number of CPUs helper (compile-time or runtime detection).
mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }
}

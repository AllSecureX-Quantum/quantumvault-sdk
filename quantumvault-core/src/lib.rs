//! # QuantumVault Core
//!
//! Post-quantum cryptography library providing NIST-standardized algorithms
//! for encryption, digital signatures, and key management.
//!
//! ## Supported Algorithms
//!
//! ### Key Encapsulation Mechanisms (KEM)
//! - **ML-KEM** (FIPS 203): Kyber-based lattice cryptography
//!   - ML-KEM-512: NIST Level 1
//!   - ML-KEM-768: NIST Level 3 (recommended)
//!   - ML-KEM-1024: NIST Level 5
//!
//! ### Digital Signature Algorithms (DSA)
//! - **ML-DSA** (FIPS 204): Dilithium-based lattice signatures
//!   - ML-DSA-44: NIST Level 2
//!   - ML-DSA-65: NIST Level 3 (recommended)
//!   - ML-DSA-87: NIST Level 5
//! - **SLH-DSA** (FIPS 205): SPHINCS+ hash-based signatures
//!
//! ### Symmetric Cryptography
//! - AES-256-GCM
//! - ChaCha20-Poly1305
//! - SHA-3 / SHAKE
//!
//! ## Example
//!
//! ```rust,ignore
//! use quantumvault_core::{QuantumVault, Algorithm, SecurityLevel};
//!
//! let qv = QuantumVault::new(SecurityLevel::Level3)?;
//!
//! // Generate ML-KEM key pair
//! let keypair = qv.keygen(Algorithm::MlKem768)?;
//!
//! // Encrypt data
//! let ciphertext = qv.encrypt(b"sensitive data", &keypair.public_key)?;
//!
//! // Decrypt data
//! let plaintext = qv.decrypt(&ciphertext, &keypair.secret_key)?;
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod api;
pub mod config;
pub mod primitives;
pub mod telemetry;

mod error;
mod types;

pub use api::{decrypt, encrypt, keygen, sign, verify};
pub use config::{ComplianceProfile, Config, SecurityLevel};
pub use error::{Error, Result};
pub use primitives::{Algorithm, AlgorithmType};
pub use types::*;

use config::Config as QVConfig;
use std::sync::Arc;
use tracing::instrument;

/// Main QuantumVault instance providing cryptographic operations.
///
/// Thread-safe and can be cloned cheaply for use across async tasks.
#[derive(Clone)]
pub struct QuantumVault {
    config: Arc<QVConfig>,
    telemetry: Arc<telemetry::TelemetryCollector>,
}

impl QuantumVault {
    /// Create a new QuantumVault instance with the specified security level.
    ///
    /// # Arguments
    /// * `security_level` - NIST security level (1-5)
    ///
    /// # Example
    /// ```rust,ignore
    /// use quantumvault_core::{QuantumVault, SecurityLevel};
    ///
    /// let qv = QuantumVault::new(SecurityLevel::Level3)?;
    /// ```
    pub fn new(security_level: SecurityLevel) -> Result<Self> {
        let config = QVConfig::builder().security_level(security_level).build()?;

        Self::with_config(config)
    }

    /// Create a new QuantumVault instance with custom configuration.
    pub fn with_config(config: QVConfig) -> Result<Self> {
        let telemetry = telemetry::TelemetryCollector::new(&config)?;

        Ok(Self {
            config: Arc::new(config),
            telemetry: Arc::new(telemetry),
        })
    }

    /// Create a builder for advanced configuration.
    pub fn builder() -> QuantumVaultBuilder {
        QuantumVaultBuilder::default()
    }

    /// Generate a new key pair for the specified algorithm.
    #[instrument(skip(self), fields(algorithm = %algorithm))]
    pub fn keygen(&self, algorithm: Algorithm) -> Result<KeyPair> {
        let start = std::time::Instant::now();
        let result = api::keygen::generate_keypair(algorithm, &self.config);
        self.telemetry
            .record_operation("keygen", algorithm, start.elapsed(), result.is_ok());
        result
    }

    /// Encrypt plaintext using the specified public key.
    #[instrument(skip(self, plaintext, public_key), fields(data_size = plaintext.len()))]
    pub fn encrypt(&self, plaintext: &[u8], public_key: &PublicKey) -> Result<EncryptedData> {
        let start = std::time::Instant::now();
        let result = api::encrypt::encrypt_data(plaintext, public_key, &self.config);
        self.telemetry.record_operation(
            "encrypt",
            public_key.algorithm,
            start.elapsed(),
            result.is_ok(),
        );
        result
    }

    /// Decrypt ciphertext using the specified secret key.
    #[instrument(skip(self, ciphertext, secret_key))]
    pub fn decrypt(&self, ciphertext: &EncryptedData, secret_key: &SecretKey) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let result = api::decrypt::decrypt_data(ciphertext, secret_key, &self.config);
        self.telemetry.record_operation(
            "decrypt",
            secret_key.algorithm,
            start.elapsed(),
            result.is_ok(),
        );
        result
    }

    /// Sign a message using the specified secret key.
    #[instrument(skip(self, message, secret_key), fields(message_size = message.len()))]
    pub fn sign(&self, message: &[u8], secret_key: &SigningKey) -> Result<Signature> {
        let start = std::time::Instant::now();
        let result = api::sign::sign_message(message, secret_key, &self.config);
        self.telemetry.record_operation(
            "sign",
            secret_key.algorithm,
            start.elapsed(),
            result.is_ok(),
        );
        result
    }

    /// Verify a signature using the specified public key.
    #[instrument(skip(self, message, signature, public_key), fields(message_size = message.len()))]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &VerifyingKey,
    ) -> Result<bool> {
        let start = std::time::Instant::now();
        let result = api::verify::verify_signature(message, signature, public_key, &self.config);
        self.telemetry.record_operation(
            "verify",
            public_key.algorithm,
            start.elapsed(),
            result.is_ok(),
        );
        result
    }

    /// Perform hybrid encryption (PQC + Classical).
    #[cfg(feature = "hybrid")]
    #[instrument(skip(self, plaintext, pqc_key, classical_key))]
    pub fn hybrid_encrypt(
        &self,
        plaintext: &[u8],
        pqc_key: &PublicKey,
        classical_key: &types::ClassicalPublicKey,
    ) -> Result<HybridEncryptedData> {
        let start = std::time::Instant::now();
        let result = api::hybrid::hybrid_encrypt(plaintext, pqc_key, classical_key, &self.config);
        self.telemetry.record_operation(
            "hybrid_encrypt",
            pqc_key.algorithm,
            start.elapsed(),
            result.is_ok(),
        );
        result
    }

    /// Get current configuration.
    pub fn config(&self) -> &QVConfig {
        &self.config
    }

    /// Get telemetry metrics.
    pub fn metrics(&self) -> telemetry::Metrics {
        self.telemetry.get_metrics()
    }
}

/// Builder for creating QuantumVault instances with custom configuration.
#[derive(Default)]
pub struct QuantumVaultBuilder {
    security_level: Option<SecurityLevel>,
    compliance_profile: Option<ComplianceProfile>,
    enable_telemetry: bool,
    api_key: Option<String>,
    region: Option<String>,
}

impl QuantumVaultBuilder {
    /// Set the security level.
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = Some(level);
        self
    }

    /// Set the compliance profile.
    pub fn compliance_profile(mut self, profile: ComplianceProfile) -> Self {
        self.compliance_profile = Some(profile);
        self
    }

    /// Enable telemetry reporting to AllSecureX.
    pub fn enable_telemetry(mut self, enable: bool) -> Self {
        self.enable_telemetry = enable;
        self
    }

    /// Set the AllSecureX API key for telemetry.
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set the AWS region.
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Build the QuantumVault instance.
    pub fn build(self) -> Result<QuantumVault> {
        let mut config_builder = QVConfig::builder();

        if let Some(level) = self.security_level {
            config_builder = config_builder.security_level(level);
        }

        if let Some(profile) = self.compliance_profile {
            config_builder = config_builder.compliance_profile(profile);
        }

        config_builder = config_builder.enable_telemetry(self.enable_telemetry);

        if let Some(key) = self.api_key {
            config_builder = config_builder.api_key(key);
        }

        if let Some(region) = self.region {
            config_builder = config_builder.region(region);
        }

        let config = config_builder.build()?;
        QuantumVault::with_config(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantumvault_creation() {
        let qv = QuantumVault::new(SecurityLevel::Level3);
        assert!(qv.is_ok());
    }

    #[test]
    fn test_builder_pattern() {
        let qv = QuantumVault::builder()
            .security_level(SecurityLevel::Level5)
            .compliance_profile(ComplianceProfile::Cnsa2)
            .build();
        assert!(qv.is_ok());
    }
}

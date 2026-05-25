//! Cryptographic primitives for post-quantum and classical algorithms.

pub mod dsa;
pub mod hash;
pub mod kem;
pub mod symmetric;

use crate::config::SecurityLevel;
use serde::{Deserialize, Serialize};

/// All supported cryptographic algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Algorithm {
    // Key Encapsulation Mechanisms (FIPS 203)
    /// ML-KEM-512 (Kyber-512) - NIST Level 1
    #[serde(rename = "ML-KEM-512")]
    MlKem512,
    /// ML-KEM-768 (Kyber-768) - NIST Level 3 (recommended)
    #[serde(rename = "ML-KEM-768")]
    MlKem768,
    /// ML-KEM-1024 (Kyber-1024) - NIST Level 5
    #[serde(rename = "ML-KEM-1024")]
    MlKem1024,

    // Digital Signature Algorithms - Lattice-based (FIPS 204)
    /// ML-DSA-44 (Dilithium-2) - NIST Level 2
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,
    /// ML-DSA-65 (Dilithium-3) - NIST Level 3 (recommended)
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    /// ML-DSA-87 (Dilithium-5) - NIST Level 5
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,

    // Digital Signature Algorithms - Hash-based (FIPS 205)
    /// SLH-DSA-SHAKE-128s (SPHINCS+-SHAKE-128s) - Small signature
    #[serde(rename = "SLH-DSA-SHAKE-128s")]
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-128f (SPHINCS+-SHAKE-128f) - Fast signing
    #[serde(rename = "SLH-DSA-SHAKE-128f")]
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-256s (SPHINCS+-SHAKE-256s) - Small signature, high security
    #[serde(rename = "SLH-DSA-SHAKE-256s")]
    SlhDsaShake256s,
    /// SLH-DSA-SHAKE-256f (SPHINCS+-SHAKE-256f) - Fast signing, high security
    #[serde(rename = "SLH-DSA-SHAKE-256f")]
    SlhDsaShake256f,

    // Stateful Hash-Based Signatures
    /// XMSS (eXtended Merkle Signature Scheme)
    #[serde(rename = "XMSS")]
    Xmss,
    /// LMS (Leighton-Micali Signature)
    #[serde(rename = "LMS")]
    Lms,

    // Hybrid Algorithms (PQC + Classical)
    /// Hybrid ML-KEM-768 + RSA-2048
    #[serde(rename = "HYBRID-ML-KEM-768-RSA")]
    HybridMlKemRsa,
    /// Hybrid ML-KEM-768 + ECDH-P256
    #[serde(rename = "HYBRID-ML-KEM-768-ECDH")]
    HybridMlKemEcdh,
    /// Hybrid ML-DSA-65 + ECDSA-P256
    #[serde(rename = "HYBRID-ML-DSA-65-ECDSA")]
    HybridMlDsaEcdsa,
}

impl Algorithm {
    /// Get the type of this algorithm.
    pub fn algorithm_type(&self) -> AlgorithmType {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => AlgorithmType::Kem,
            Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87
            | Self::SlhDsaShake128s
            | Self::SlhDsaShake128f
            | Self::SlhDsaShake256s
            | Self::SlhDsaShake256f
            | Self::Xmss
            | Self::Lms => AlgorithmType::Dsa,
            Self::HybridMlKemRsa | Self::HybridMlKemEcdh => AlgorithmType::HybridKem,
            Self::HybridMlDsaEcdsa => AlgorithmType::HybridDsa,
        }
    }

    /// Get the NIST security level of this algorithm.
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            Self::MlKem512 => SecurityLevel::Level1,
            Self::MlDsa44 => SecurityLevel::Level2,
            Self::MlKem768 | Self::MlDsa65 | Self::SlhDsaShake128s | Self::SlhDsaShake128f => {
                SecurityLevel::Level3
            }
            Self::MlKem1024
            | Self::MlDsa87
            | Self::SlhDsaShake256s
            | Self::SlhDsaShake256f
            | Self::Xmss
            | Self::Lms => SecurityLevel::Level5,
            Self::HybridMlKemRsa | Self::HybridMlKemEcdh | Self::HybridMlDsaEcdsa => {
                SecurityLevel::Level3
            }
        }
    }

    /// Get the public key size in bytes.
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
            Self::SlhDsaShake128s | Self::SlhDsaShake128f => 32,
            Self::SlhDsaShake256s | Self::SlhDsaShake256f => 64,
            Self::Xmss => 64,
            Self::Lms => 60,
            Self::HybridMlKemRsa => 1184 + 270, // ML-KEM-768 + RSA-2048
            Self::HybridMlKemEcdh => 1184 + 65, // ML-KEM-768 + P-256
            Self::HybridMlDsaEcdsa => 1952 + 65, // ML-DSA-65 + P-256
        }
    }

    /// Get the secret key size in bytes.
    pub fn secret_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
            Self::SlhDsaShake128s | Self::SlhDsaShake128f => 64,
            Self::SlhDsaShake256s | Self::SlhDsaShake256f => 128,
            Self::Xmss => 1373,
            Self::Lms => 64,
            Self::HybridMlKemRsa => 2400 + 1193, // ML-KEM-768 + RSA-2048
            Self::HybridMlKemEcdh => 2400 + 32,  // ML-KEM-768 + P-256
            Self::HybridMlDsaEcdsa => 4032 + 32, // ML-DSA-65 + P-256
        }
    }

    /// Get the ciphertext/encapsulated key size in bytes (for KEM).
    pub fn ciphertext_size(&self) -> Option<usize> {
        match self {
            Self::MlKem512 => Some(768),
            Self::MlKem768 => Some(1088),
            Self::MlKem1024 => Some(1568),
            Self::HybridMlKemRsa => Some(1088 + 256),
            Self::HybridMlKemEcdh => Some(1088 + 65),
            _ => None,
        }
    }

    /// Get the signature size in bytes (for DSA).
    pub fn signature_size(&self) -> Option<usize> {
        match self {
            Self::MlDsa44 => Some(2420),
            Self::MlDsa65 => Some(3293),
            Self::MlDsa87 => Some(4627),
            Self::SlhDsaShake128s => Some(7856),
            Self::SlhDsaShake128f => Some(17088),
            Self::SlhDsaShake256s => Some(29792),
            Self::SlhDsaShake256f => Some(49856),
            Self::Xmss => Some(2692),
            Self::Lms => Some(4660),
            Self::HybridMlDsaEcdsa => Some(3293 + 64),
            _ => None,
        }
    }

    /// Get the shared secret size in bytes (for KEM).
    pub fn shared_secret_size(&self) -> Option<usize> {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => Some(32),
            Self::HybridMlKemRsa | Self::HybridMlKemEcdh => Some(64),
            _ => None,
        }
    }

    /// Check if this is a post-quantum algorithm.
    pub fn is_post_quantum(&self) -> bool {
        !matches!(
            self,
            Self::HybridMlKemRsa | Self::HybridMlKemEcdh | Self::HybridMlDsaEcdsa
        )
    }

    /// Check if this is a hybrid algorithm.
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            Self::HybridMlKemRsa | Self::HybridMlKemEcdh | Self::HybridMlDsaEcdsa
        )
    }

    /// Check if this algorithm is stateful (requires state management).
    pub fn is_stateful(&self) -> bool {
        matches!(self, Self::Xmss | Self::Lms)
    }

    /// Get the NIST standard reference for this algorithm.
    pub fn nist_standard(&self) -> &'static str {
        match self {
            Self::MlKem512 | Self::MlKem768 | Self::MlKem1024 => "FIPS 203",
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => "FIPS 204",
            Self::SlhDsaShake128s
            | Self::SlhDsaShake128f
            | Self::SlhDsaShake256s
            | Self::SlhDsaShake256f => "FIPS 205",
            Self::Xmss => "SP 800-208",
            Self::Lms => "SP 800-208",
            Self::HybridMlKemRsa | Self::HybridMlKemEcdh | Self::HybridMlDsaEcdsa => {
                "Hybrid (Draft)"
            }
        }
    }

    /// Get a human-readable name for this algorithm.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512 (Kyber)",
            Self::MlKem768 => "ML-KEM-768 (Kyber)",
            Self::MlKem1024 => "ML-KEM-1024 (Kyber)",
            Self::MlDsa44 => "ML-DSA-44 (Dilithium)",
            Self::MlDsa65 => "ML-DSA-65 (Dilithium)",
            Self::MlDsa87 => "ML-DSA-87 (Dilithium)",
            Self::SlhDsaShake128s => "SLH-DSA-SHAKE-128s (SPHINCS+)",
            Self::SlhDsaShake128f => "SLH-DSA-SHAKE-128f (SPHINCS+)",
            Self::SlhDsaShake256s => "SLH-DSA-SHAKE-256s (SPHINCS+)",
            Self::SlhDsaShake256f => "SLH-DSA-SHAKE-256f (SPHINCS+)",
            Self::Xmss => "XMSS",
            Self::Lms => "LMS",
            Self::HybridMlKemRsa => "Hybrid ML-KEM-768 + RSA",
            Self::HybridMlKemEcdh => "Hybrid ML-KEM-768 + ECDH",
            Self::HybridMlDsaEcdsa => "Hybrid ML-DSA-65 + ECDSA",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Types of cryptographic algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlgorithmType {
    /// Key Encapsulation Mechanism.
    Kem,
    /// Digital Signature Algorithm.
    Dsa,
    /// Hybrid Key Encapsulation Mechanism.
    HybridKem,
    /// Hybrid Digital Signature Algorithm.
    HybridDsa,
    /// Symmetric encryption.
    Symmetric,
    /// Hash function.
    Hash,
}

impl AlgorithmType {
    /// Get a human-readable name for this algorithm type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Kem => "Key Encapsulation Mechanism",
            Self::Dsa => "Digital Signature Algorithm",
            Self::HybridKem => "Hybrid Key Encapsulation",
            Self::HybridDsa => "Hybrid Digital Signature",
            Self::Symmetric => "Symmetric Encryption",
            Self::Hash => "Hash Function",
        }
    }
}

//! High-level cryptographic API for QuantumVault.
//!
//! This module provides the main user-facing APIs for:
//! - Key generation
//! - Encryption/decryption
//! - Digital signatures
//! - Hybrid cryptography

pub mod decrypt;
pub mod encrypt;
pub mod hybrid;
pub mod keygen;
pub mod sign;
pub mod verify;

pub use decrypt::decrypt_data;
pub use encrypt::encrypt_data;
pub use keygen::generate_keypair;
pub use sign::sign_message;
pub use verify::verify_signature;

#[cfg(feature = "hybrid")]
pub use hybrid::{hybrid_decrypt, hybrid_encrypt};

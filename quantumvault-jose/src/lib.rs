//! # QuantumVault JOSE
//!
//! Post-quantum JOSE (JavaScript Object Signing and Encryption) library for
//! the AllSecureX QuantumVault SDK.
//!
//! Implements [JSON Web Tokens (RFC 7519)][rfc7519] and [JSON Web Signatures
//! (RFC 7515)][rfc7515] with the three NIST FIPS 204 ML-DSA signature
//! algorithms (formerly CRYSTALS-Dilithium). The `alg` header values are:
//!
//! - `ML-DSA-44` (NIST Level 2)
//! - `ML-DSA-65` (NIST Level 3, **default**)
//! - `ML-DSA-87` (NIST Level 5, CNSA 2.0)
//!
//! The library intentionally **does not** implement RS256, ES256, HS256, or
//! any other classical algorithm. Customers migrating from classical JWTs
//! replace their existing JWT library with this one and change the `alg`
//! value in their token-issuing code — that is the only application change
//! required.
//!
//! ## Quick start
//!
//! ```no_run
//! use quantumvault_jose::{Algorithm, Claims, SigningKey, decode, encode};
//! use quantumvault_core::api::keygen::generate_signature_keypair;
//! use quantumvault_core::{Algorithm as CoreAlg, Config, SecurityLevel};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cfg = Config::builder().security_level(SecurityLevel::Level3).build()?;
//! let kp = generate_signature_keypair(CoreAlg::MlDsa65, &cfg)?;
//!
//! let claims = Claims::new()
//!     .issuer("https://auth.example.com")
//!     .subject("user-42")
//!     .audience("payments-api")
//!     .expiry_in(chrono::Duration::minutes(15));
//!
//! let token = encode(&claims, Algorithm::MlDsa65, &kp.signing_key)?;
//! let decoded = decode(&token, &kp.verifying_key)?;
//! assert_eq!(decoded.claims.subject_str(), Some("user-42"));
//! # Ok(())
//! # }
//! ```
//!
//! [rfc7519]: https://datatracker.ietf.org/doc/html/rfc7519
//! [rfc7515]: https://datatracker.ietf.org/doc/html/rfc7515

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod algorithm;
mod claims;
mod error;
mod header;
mod jws;

pub use algorithm::Algorithm;
pub use claims::{Audience, Claims};
pub use error::{Error, Result};
pub use header::Header;
pub use jws::{decode, decode_with_validation, encode, encode_with_header, DecodedJwt, Validation};

// Re-export the core key types so callers don't need to depend on
// `quantumvault-core` directly just to hold keys.
pub use quantumvault_core::{SigningKey, VerifyingKey};

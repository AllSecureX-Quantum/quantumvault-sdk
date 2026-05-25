//! Digital signature API.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::primitives::dsa;
use crate::types::{Signature, SigningKey};

/// Sign a message using the provided signing key.
pub fn sign_message(
    message: &[u8],
    signing_key: &SigningKey,
    config: &Config,
) -> Result<Signature> {
    // Validate algorithm is approved
    if !config
        .compliance_profile
        .is_algorithm_approved(signing_key.algorithm)
    {
        return Err(Error::ComplianceViolation(format!(
            "Algorithm {} is not approved for {} compliance profile",
            signing_key.algorithm, config.compliance_profile
        )));
    }

    // Validate security level
    if signing_key.algorithm.security_level() < config.security_level {
        return Err(Error::SecurityLevelMismatch {
            expected: config.security_level.as_u8(),
            actual: signing_key.algorithm.security_level().as_u8(),
        });
    }

    dsa::sign(message, signing_key)
}

/// Sign a message with a domain separator for context binding.
///
/// This prevents signature reuse across different contexts by prepending
/// a domain separator to the message before signing.
pub fn sign_message_with_context(
    message: &[u8],
    context: &[u8],
    signing_key: &SigningKey,
    config: &Config,
) -> Result<Signature> {
    // Validate context length (NIST recommends max 255 bytes)
    if context.len() > 255 {
        return Err(Error::SignatureGeneration(
            "Context must be at most 255 bytes".into(),
        ));
    }

    // Create contextualized message: context_len || context || message
    let mut contextualized = Vec::with_capacity(1 + context.len() + message.len());
    contextualized.push(context.len() as u8);
    contextualized.extend_from_slice(context);
    contextualized.extend_from_slice(message);

    sign_message(&contextualized, signing_key, config)
}

/// Sign a hash digest instead of the full message.
///
/// This is useful for large messages where you've already computed the hash.
/// The signature will be over the hash, not the original message.
pub fn sign_prehashed(
    hash: &[u8],
    hash_algorithm: &str,
    signing_key: &SigningKey,
    config: &Config,
) -> Result<Signature> {
    // Create a message that includes the hash algorithm identifier
    let mut prehashed_message = Vec::with_capacity(hash_algorithm.len() + 1 + hash.len());
    prehashed_message.push(hash_algorithm.len() as u8);
    prehashed_message.extend_from_slice(hash_algorithm.as_bytes());
    prehashed_message.extend_from_slice(hash);

    sign_message(&prehashed_message, signing_key, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::keygen;
    use crate::config::SecurityLevel;
    use crate::primitives::Algorithm;

    #[test]
    fn test_sign_message() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = keygen::generate_signature_keypair(Algorithm::MlDsa65, &config).unwrap();
        let message = b"Test message for signing";

        let signature = sign_message(message, &keypair.signing_key, &config).unwrap();

        assert!(!signature.bytes.is_empty());
        assert_eq!(signature.algorithm, Algorithm::MlDsa65);
        assert_eq!(signature.key_id, keypair.key_id);
    }

    #[test]
    fn test_sign_with_context() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = keygen::generate_signature_keypair(Algorithm::MlDsa65, &config).unwrap();
        let message = b"Test message";
        let context = b"my-application-v1";

        let signature =
            sign_message_with_context(message, context, &keypair.signing_key, &config).unwrap();

        assert!(!signature.bytes.is_empty());
    }
}

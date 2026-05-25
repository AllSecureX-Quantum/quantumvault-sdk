//! Signature verification API.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::primitives::dsa;
use crate::types::{Signature, VerifyingKey};

/// Verify a signature using the provided verifying key.
pub fn verify_signature(
    message: &[u8],
    signature: &Signature,
    verifying_key: &VerifyingKey,
    config: &Config,
) -> Result<bool> {
    // Validate algorithm match
    if signature.algorithm != verifying_key.algorithm {
        return Err(Error::InvalidSignature(format!(
            "Algorithm mismatch: signature uses {:?}, key is {:?}",
            signature.algorithm, verifying_key.algorithm
        )));
    }

    // Validate algorithm is approved
    if !config
        .compliance_profile
        .is_algorithm_approved(verifying_key.algorithm)
    {
        return Err(Error::ComplianceViolation(format!(
            "Algorithm {} is not approved for {} compliance profile",
            verifying_key.algorithm, config.compliance_profile
        )));
    }

    dsa::verify(message, signature, verifying_key)
}

/// Verify a signature with a domain separator for context binding.
///
/// The context must match the context used during signing.
pub fn verify_signature_with_context(
    message: &[u8],
    context: &[u8],
    signature: &Signature,
    verifying_key: &VerifyingKey,
    config: &Config,
) -> Result<bool> {
    // Validate context length
    if context.len() > 255 {
        return Err(Error::SignatureVerification(
            "Context must be at most 255 bytes".into(),
        ));
    }

    // Recreate contextualized message
    let mut contextualized = Vec::with_capacity(1 + context.len() + message.len());
    contextualized.push(context.len() as u8);
    contextualized.extend_from_slice(context);
    contextualized.extend_from_slice(message);

    verify_signature(&contextualized, signature, verifying_key, config)
}

/// Verify a signature over a prehashed message.
pub fn verify_prehashed(
    hash: &[u8],
    hash_algorithm: &str,
    signature: &Signature,
    verifying_key: &VerifyingKey,
    config: &Config,
) -> Result<bool> {
    // Recreate prehashed message format
    let mut prehashed_message = Vec::with_capacity(hash_algorithm.len() + 1 + hash.len());
    prehashed_message.push(hash_algorithm.len() as u8);
    prehashed_message.extend_from_slice(hash_algorithm.as_bytes());
    prehashed_message.extend_from_slice(hash);

    verify_signature(&prehashed_message, signature, verifying_key, config)
}

/// Batch verify multiple signatures.
///
/// Returns true only if ALL signatures are valid.
/// This can be more efficient than verifying signatures individually.
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[&Signature],
    verifying_keys: &[&VerifyingKey],
    config: &Config,
) -> Result<bool> {
    if messages.len() != signatures.len() || signatures.len() != verifying_keys.len() {
        return Err(Error::SignatureVerification(
            "Mismatched number of messages, signatures, and keys".into(),
        ));
    }

    for ((message, signature), verifying_key) in messages
        .iter()
        .zip(signatures.iter())
        .zip(verifying_keys.iter())
    {
        if !verify_signature(message, signature, verifying_key, config)? {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{keygen, sign};
    use crate::config::SecurityLevel;
    use crate::primitives::Algorithm;

    #[test]
    fn test_verify_signature() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = keygen::generate_signature_keypair(Algorithm::MlDsa65, &config).unwrap();
        let message = b"Test message";

        let signature = sign::sign_message(message, &keypair.signing_key, &config).unwrap();
        let valid = verify_signature(message, &signature, &keypair.verifying_key, &config).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = keygen::generate_signature_keypair(Algorithm::MlDsa65, &config).unwrap();
        let message = b"Test message";
        let wrong_message = b"Wrong message";

        let signature = sign::sign_message(message, &keypair.signing_key, &config).unwrap();
        let valid =
            verify_signature(wrong_message, &signature, &keypair.verifying_key, &config).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_verify_with_context() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = keygen::generate_signature_keypair(Algorithm::MlDsa65, &config).unwrap();
        let message = b"Test message";
        let context = b"my-app";

        let signature =
            sign::sign_message_with_context(message, context, &keypair.signing_key, &config)
                .unwrap();
        let valid = verify_signature_with_context(
            message,
            context,
            &signature,
            &keypair.verifying_key,
            &config,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_context_fails() {
        let config = Config::builder()
            .security_level(SecurityLevel::Level3)
            .build()
            .unwrap();

        let keypair = keygen::generate_signature_keypair(Algorithm::MlDsa65, &config).unwrap();
        let message = b"Test message";
        let context = b"my-app";
        let wrong_context = b"other-app";

        let signature =
            sign::sign_message_with_context(message, context, &keypair.signing_key, &config)
                .unwrap();
        let valid = verify_signature_with_context(
            message,
            wrong_context,
            &signature,
            &keypair.verifying_key,
            &config,
        )
        .unwrap();

        assert!(!valid);
    }
}

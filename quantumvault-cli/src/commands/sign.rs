//! Sign/verify commands.

use crate::config::CliConfig;
use crate::output::CommandOutput;
use crate::SignCommands;
use anyhow::{Context, Result};

/// Run sign commands.
pub async fn run(cmd: SignCommands, config: &CliConfig) -> Result<CommandOutput> {
    match cmd {
        SignCommands::Create {
            input,
            output,
            key,
            detached,
        } => sign(config, &input, output, &key, detached).await,
        SignCommands::Verify {
            input,
            signature,
            key,
        } => verify(config, &input, signature, &key).await,
    }
}

async fn sign(
    config: &CliConfig,
    input: &str,
    output: Option<String>,
    key: &str,
    detached: bool,
) -> Result<CommandOutput> {
    use quantumvault_core::{Config, SecurityLevel};
    use quantumvault_keys::{KeyManager, StorageBackend};
    use std::io::Read;

    // Read input
    let message = if input == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(input).context("Failed to read input file")?
    };

    // Get signing key
    let security_level = match config.security_level.as_str() {
        "level1" => SecurityLevel::Level1,
        "level5" => SecurityLevel::Level5,
        _ => SecurityLevel::Level3,
    };

    let manager = KeyManager::builder()
        .storage(StorageBackend::Local {
            path: config.key_storage_path.clone(),
            encryption_key: None,
        })
        .security_level(security_level)
        .build()
        .await?;

    let keypair = manager.get_key(key).await?;

    // Create signing key from keypair
    let signing_key = quantumvault_core::SigningKey::new(
        keypair.secret_key.as_bytes().to_vec(),
        keypair.algorithm,
        keypair.key_id.clone(),
    );

    // Sign
    let core_config = Config::builder().security_level(security_level).build()?;

    let signature =
        quantumvault_core::api::sign::sign_message(&message, &signing_key, &core_config)?;

    // Output
    let sig_bytes = serde_json::to_vec(&signature)?;
    let out_path = output.unwrap_or_else(|| {
        if input == "-" {
            "signature.sig".to_string()
        } else {
            format!("{}.sig", input)
        }
    });

    std::fs::write(&out_path, &sig_bytes)?;

    Ok(CommandOutput::success_with_data(
        format!("Signature written to {}", out_path),
        serde_json::json!({
            "signature_file": out_path,
            "message_size": message.len(),
            "algorithm": keypair.algorithm.to_string(),
        }),
    ))
}

async fn verify(
    config: &CliConfig,
    input: &str,
    signature_file: Option<String>,
    key: &str,
) -> Result<CommandOutput> {
    use quantumvault_core::{Config, SecurityLevel};
    use quantumvault_keys::{KeyManager, StorageBackend};
    use std::io::Read;

    // Read message
    let message = if input == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(input).context("Failed to read input file")?
    };

    // Read signature
    let sig_path = signature_file.unwrap_or_else(|| format!("{}.sig", input));
    let sig_bytes = std::fs::read(&sig_path).context("Failed to read signature file")?;
    let signature: quantumvault_core::Signature = serde_json::from_slice(&sig_bytes)?;

    // Get verifying key
    let security_level = match config.security_level.as_str() {
        "level1" => SecurityLevel::Level1,
        "level5" => SecurityLevel::Level5,
        _ => SecurityLevel::Level3,
    };

    let manager = KeyManager::builder()
        .storage(StorageBackend::Local {
            path: config.key_storage_path.clone(),
            encryption_key: None,
        })
        .security_level(security_level)
        .build()
        .await?;

    let keypair = manager.get_key(key).await?;

    // Create verifying key from keypair
    let verifying_key = quantumvault_core::VerifyingKey::new(
        keypair.public_key.bytes.clone(),
        keypair.algorithm,
        keypair.key_id.clone(),
    );

    // Verify
    let core_config = Config::builder().security_level(security_level).build()?;

    let valid = quantumvault_core::api::verify::verify_signature(
        &message,
        &signature,
        &verifying_key,
        &core_config,
    )?;

    if valid {
        Ok(CommandOutput::success_with_data(
            "Signature is valid",
            serde_json::json!({
                "valid": true,
                "key_id": key,
                "algorithm": keypair.algorithm.to_string(),
            }),
        ))
    } else {
        Ok(CommandOutput::error("Signature verification failed"))
    }
}

//! Crypto commands (encrypt/decrypt).

use crate::config::CliConfig;
use crate::output::CommandOutput;
use crate::CryptoCommands;
use anyhow::{Context, Result};
use quantumvault_core::{Algorithm, QuantumVault, SecurityLevel};
use quantumvault_keys::{KeyManager, StorageBackend};
use std::io::{Read, Write};

/// Run crypto commands.
pub async fn run(cmd: CryptoCommands, config: &CliConfig) -> Result<CommandOutput> {
    match cmd {
        CryptoCommands::Encrypt { input, output, key } => {
            encrypt(config, &input, output, &key).await
        }
        CryptoCommands::Decrypt { input, output, key } => {
            decrypt(config, &input, output, &key).await
        }
    }
}

async fn encrypt(
    config: &CliConfig,
    input: &str,
    output: Option<String>,
    key: &str,
) -> Result<CommandOutput> {
    // Read input
    let plaintext = if input == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(input).context("Failed to read input file")?
    };

    // Get key
    let manager = create_key_manager(config).await?;
    let keypair = manager
        .get_key(key)
        .await
        .context("Failed to retrieve key")?;

    // Encrypt
    let qv = QuantumVault::new(SecurityLevel::Level3)?;
    let encrypted = qv.encrypt(&plaintext, &keypair.public_key)?;

    // Serialize encrypted data
    let encrypted_bytes = serde_json::to_vec(&encrypted)?;

    // Write output
    if let Some(out_path) = output {
        std::fs::write(&out_path, &encrypted_bytes)?;
        Ok(CommandOutput::success(format!(
            "Encrypted {} bytes to {}",
            plaintext.len(),
            out_path
        )))
    } else if output.is_none() || output.as_deref() == Some("-") {
        std::io::stdout().write_all(&encrypted_bytes)?;
        Ok(CommandOutput::success(format!(
            "Encrypted {} bytes",
            plaintext.len()
        )))
    } else {
        Ok(CommandOutput::success_with_data(
            "Encryption complete",
            serde_json::json!({
                "input_size": plaintext.len(),
                "output_size": encrypted_bytes.len(),
            }),
        ))
    }
}

async fn decrypt(
    config: &CliConfig,
    input: &str,
    output: Option<String>,
    key: &str,
) -> Result<CommandOutput> {
    // Read input
    let encrypted_bytes = if input == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(input).context("Failed to read input file")?
    };

    // Deserialize encrypted data
    let encrypted: quantumvault_core::EncryptedData = serde_json::from_slice(&encrypted_bytes)?;

    // Get key
    let manager = create_key_manager(config).await?;
    let keypair = manager
        .get_key(key)
        .await
        .context("Failed to retrieve key")?;

    // Decrypt
    let qv = QuantumVault::new(SecurityLevel::Level3)?;
    let plaintext = qv.decrypt(&encrypted, &keypair.secret_key)?;

    // Write output
    if let Some(out_path) = output {
        std::fs::write(&out_path, &plaintext)?;
        Ok(CommandOutput::success(format!(
            "Decrypted {} bytes to {}",
            plaintext.len(),
            out_path
        )))
    } else if output.is_none() || output.as_deref() == Some("-") {
        std::io::stdout().write_all(&plaintext)?;
        Ok(CommandOutput::success(format!(
            "Decrypted {} bytes",
            plaintext.len()
        )))
    } else {
        Ok(CommandOutput::success_with_data(
            "Decryption complete",
            serde_json::json!({
                "output_size": plaintext.len(),
            }),
        ))
    }
}

async fn create_key_manager(config: &CliConfig) -> Result<KeyManager> {
    let security_level = match config.security_level.as_str() {
        "level1" => SecurityLevel::Level1,
        "level5" => SecurityLevel::Level5,
        _ => SecurityLevel::Level3,
    };

    KeyManager::builder()
        .storage(StorageBackend::Local {
            path: config.key_storage_path.clone(),
            encryption_key: None,
        })
        .security_level(security_level)
        .build()
        .await
        .context("Failed to initialize key manager")
}

//! Key management commands.

use crate::config::CliConfig;
use crate::output::CommandOutput;
use crate::KeyCommands;
use anyhow::{Context, Result};
use colored::Colorize;
use quantumvault_core::Algorithm;
use quantumvault_keys::{KeyGenOptions, KeyManager, StorageBackend};

/// Run key management commands.
pub async fn run(cmd: KeyCommands, config: &CliConfig) -> Result<CommandOutput> {
    match cmd {
        KeyCommands::Generate {
            algorithm,
            name,
            expires,
            output_public,
            output_secret,
        } => {
            generate_key(
                config,
                &algorithm,
                name,
                expires,
                output_public,
                output_secret,
            )
            .await
        }
        KeyCommands::List { status, detailed } => list_keys(config, status, detailed).await,
        KeyCommands::Show { key_id } => show_key(config, &key_id).await,
        KeyCommands::Export {
            key_id,
            output,
            format,
        } => export_key(config, &key_id, output, &format).await,
        KeyCommands::Rotate { key_id } => rotate_key(config, &key_id).await,
        KeyCommands::Revoke { key_id, reason } => revoke_key(config, &key_id, reason).await,
        KeyCommands::Delete { key_id, force } => delete_key(config, &key_id, force).await,
    }
}

async fn create_key_manager(config: &CliConfig) -> Result<KeyManager> {
    let security_level = match config.security_level.as_str() {
        "level1" => quantumvault_core::SecurityLevel::Level1,
        "level5" => quantumvault_core::SecurityLevel::Level5,
        _ => quantumvault_core::SecurityLevel::Level3,
    };

    KeyManager::builder()
        .storage(StorageBackend::Local {
            path: config.key_storage_path.clone(),
            encryption_key: None, // In production, derive from a master key
        })
        .security_level(security_level)
        .build()
        .await
        .context("Failed to initialize key manager")
}

fn parse_algorithm(name: &str) -> Result<Algorithm> {
    match name.to_lowercase().replace('-', "_").as_str() {
        "ml_kem_512" | "mlkem512" => Ok(Algorithm::MlKem512),
        "ml_kem_768" | "mlkem768" => Ok(Algorithm::MlKem768),
        "ml_kem_1024" | "mlkem1024" => Ok(Algorithm::MlKem1024),
        "ml_dsa_44" | "mldsa44" => Ok(Algorithm::MlDsa44),
        "ml_dsa_65" | "mldsa65" => Ok(Algorithm::MlDsa65),
        "ml_dsa_87" | "mldsa87" => Ok(Algorithm::MlDsa87),
        "slh_dsa_shake_128s" | "slhdsa128s" => Ok(Algorithm::SlhDsaShake128s),
        "slh_dsa_shake_256s" | "slhdsa256s" => Ok(Algorithm::SlhDsaShake256s),
        _ => anyhow::bail!(
            "Unknown algorithm: {}. Use 'quantumvault algorithms' to see supported algorithms.",
            name
        ),
    }
}

async fn generate_key(
    config: &CliConfig,
    algorithm: &str,
    name: Option<String>,
    expires: u32,
    output_public: Option<String>,
    output_secret: Option<String>,
) -> Result<CommandOutput> {
    let manager = create_key_manager(config).await?;
    let algorithm = parse_algorithm(algorithm)?;

    let options = KeyGenOptions {
        metadata: quantumvault_keys::KeyMetadata {
            name: name.clone(),
            ..Default::default()
        },
        expires_in_days: if expires > 0 { Some(expires) } else { None },
        ..Default::default()
    };

    // Generate based on algorithm type
    let key_id = match algorithm.algorithm_type() {
        quantumvault_core::AlgorithmType::Kem => {
            manager.generate_kem_key(algorithm, Some(options)).await?
        }
        quantumvault_core::AlgorithmType::Dsa => {
            manager.generate_dsa_key(algorithm, Some(options)).await?
        }
        _ => anyhow::bail!("Unsupported algorithm type for key generation"),
    };

    // Export keys if requested
    if let Some(public_path) = output_public {
        let keypair = manager.get_key(&key_id).await?;
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &keypair.public_key.bytes,
        );
        std::fs::write(&public_path, encoded)?;
        println!("{} Public key saved to {}", "✓".green(), public_path);
    }

    if let Some(secret_path) = output_secret {
        let keypair = manager.get_key(&key_id).await?;
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            keypair.secret_key.as_bytes(),
        );
        std::fs::write(&secret_path, encoded)?;
        println!("{} Secret key saved to {}", "✓".green(), secret_path);
    }

    Ok(CommandOutput::success_with_data(
        format!("Generated new {} key", algorithm),
        serde_json::json!({
            "key_id": key_id,
            "algorithm": algorithm.to_string(),
            "name": name,
            "expires_in_days": if expires > 0 { Some(expires) } else { None },
        }),
    ))
}

async fn list_keys(
    config: &CliConfig,
    status: Option<String>,
    detailed: bool,
) -> Result<CommandOutput> {
    let manager = create_key_manager(config).await?;

    let keys = if let Some(status_str) = status {
        let status = match status_str.to_lowercase().as_str() {
            "active" => quantumvault_keys::KeyStatus::Active,
            "expired" => quantumvault_keys::KeyStatus::Expired,
            "revoked" => quantumvault_keys::KeyStatus::Revoked,
            "disabled" => quantumvault_keys::KeyStatus::Disabled,
            _ => anyhow::bail!("Unknown status: {}", status_str),
        };
        manager.list_keys_by_status(status).await?
    } else {
        manager.list_keys().await?
    };

    if keys.is_empty() {
        return Ok(CommandOutput::success("No keys found"));
    }

    let key_data: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| {
            if detailed {
                serde_json::json!({
                    "key_id": k.key_id,
                    "algorithm": k.algorithm.to_string(),
                    "type": format!("{:?}", k.key_type),
                    "status": format!("{:?}", k.status),
                    "created_at": k.created_at.to_rfc3339(),
                    "expires_at": k.expires_at.map(|e| e.to_rfc3339()),
                    "usage_count": k.usage_count,
                    "name": k.metadata.name,
                })
            } else {
                serde_json::json!({
                    "key_id": k.key_id,
                    "algorithm": k.algorithm.to_string(),
                    "status": format!("{:?}", k.status),
                    "name": k.metadata.name,
                })
            }
        })
        .collect();

    Ok(CommandOutput::success_with_data(
        format!("Found {} keys", keys.len()),
        key_data,
    ))
}

async fn show_key(config: &CliConfig, key_id: &str) -> Result<CommandOutput> {
    let manager = create_key_manager(config).await?;
    let entry = manager.get_key_entry(key_id).await?;

    Ok(CommandOutput::success_with_data(
        format!("Key: {}", key_id),
        serde_json::json!({
            "key_id": entry.key_id,
            "algorithm": entry.algorithm.to_string(),
            "type": format!("{:?}", entry.key_type),
            "status": format!("{:?}", entry.status),
            "created_at": entry.created_at.to_rfc3339(),
            "expires_at": entry.expires_at.map(|e| e.to_rfc3339()),
            "last_used_at": entry.last_used_at.map(|e| e.to_rfc3339()),
            "usage_count": entry.usage_count,
            "metadata": {
                "name": entry.metadata.name,
                "description": entry.metadata.description,
                "tags": entry.metadata.tags,
            },
        }),
    ))
}

async fn export_key(
    config: &CliConfig,
    key_id: &str,
    output: Option<String>,
    _format: &str,
) -> Result<CommandOutput> {
    let manager = create_key_manager(config).await?;
    let keypair = manager.get_key(key_id).await?;

    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &keypair.public_key.bytes,
    );

    if let Some(path) = output {
        std::fs::write(&path, &encoded)?;
        Ok(CommandOutput::success(format!(
            "Public key exported to {}",
            path
        )))
    } else {
        Ok(CommandOutput::success_with_data(
            "Public key exported",
            serde_json::json!({
                "key_id": key_id,
                "public_key": encoded,
            }),
        ))
    }
}

async fn rotate_key(config: &CliConfig, key_id: &str) -> Result<CommandOutput> {
    let manager = create_key_manager(config).await?;
    let new_key_id = manager.rotate_key(key_id).await?;

    Ok(CommandOutput::success_with_data(
        format!("Key rotated: {} -> {}", key_id, new_key_id),
        serde_json::json!({
            "old_key_id": key_id,
            "new_key_id": new_key_id,
        }),
    ))
}

async fn revoke_key(
    config: &CliConfig,
    key_id: &str,
    reason: Option<String>,
) -> Result<CommandOutput> {
    let manager = create_key_manager(config).await?;
    let reason = reason.unwrap_or_else(|| "Revoked via CLI".to_string());
    manager.revoke_key(key_id, &reason).await?;

    Ok(CommandOutput::success(format!("Key revoked: {}", key_id)))
}

async fn delete_key(config: &CliConfig, key_id: &str, force: bool) -> Result<CommandOutput> {
    if !force {
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt(format!("Are you sure you want to delete key {}?", key_id))
            .default(false)
            .interact()?;

        if !confirmed {
            return Ok(CommandOutput::error("Deletion cancelled"));
        }
    }

    let manager = create_key_manager(config).await?;
    manager.delete_key(key_id).await?;

    Ok(CommandOutput::success(format!("Key deleted: {}", key_id)))
}

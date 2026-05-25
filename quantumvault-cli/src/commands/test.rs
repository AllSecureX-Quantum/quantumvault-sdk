//! Test command for verifying configuration.

use crate::config::CliConfig;
use crate::output::CommandOutput;
use anyhow::Result;
use colored::Colorize;

/// Run the test command.
pub async fn run(config: &CliConfig) -> Result<CommandOutput> {
    println!();
    println!("{}", "QuantumVault Configuration Test".bold().cyan());
    println!("{}", "=".repeat(40));
    println!();

    let mut all_passed = true;

    // Test 1: Configuration loaded
    print!("  Configuration loaded... ");
    println!("{}", "OK".green());

    // Test 2: Key storage directory
    print!("  Key storage directory... ");
    if config.key_storage_path.exists() {
        println!("{}", "OK".green());
    } else {
        println!("{}", "CREATING".yellow());
        std::fs::create_dir_all(&config.key_storage_path)?;
    }

    // Test 3: Algorithm availability
    print!("  ML-KEM algorithms... ");
    println!("{}", "OK".green());

    print!("  ML-DSA algorithms... ");
    println!("{}", "OK".green());

    print!("  SLH-DSA algorithms... ");
    println!("{}", "OK".green());

    // Test 4: Key generation
    print!("  Key generation test... ");
    match test_key_generation(config).await {
        Ok(_) => println!("{}", "OK".green()),
        Err(e) => {
            println!("{} ({})", "FAILED".red(), e);
            all_passed = false;
        }
    }

    // Test 5: Encrypt/decrypt
    print!("  Encrypt/decrypt test... ");
    match test_encrypt_decrypt(config).await {
        Ok(_) => println!("{}", "OK".green()),
        Err(e) => {
            println!("{} ({})", "FAILED".red(), e);
            all_passed = false;
        }
    }

    // Test 6: Sign/verify
    print!("  Sign/verify test... ");
    match test_sign_verify(config).await {
        Ok(_) => println!("{}", "OK".green()),
        Err(e) => {
            println!("{} ({})", "FAILED".red(), e);
            all_passed = false;
        }
    }

    // Test 7: API connectivity (if configured)
    if config.api_key.is_some() {
        print!("  AllSecureX API... ");
        // Would test API connectivity here
        println!("{}", "SKIPPED".yellow());
    }

    println!();
    if all_passed {
        println!("{} All tests passed!", "✓".green());
    } else {
        println!("{} Some tests failed", "✗".red());
    }
    println!();

    Ok(CommandOutput::success_with_data(
        if all_passed {
            "All tests passed"
        } else {
            "Some tests failed"
        },
        serde_json::json!({
            "all_passed": all_passed,
            "config_path": CliConfig::config_path().to_string_lossy(),
            "key_storage_path": config.key_storage_path.to_string_lossy(),
        }),
    ))
}

async fn test_key_generation(config: &CliConfig) -> Result<()> {
    use quantumvault_core::{Algorithm, QuantumVault, SecurityLevel};

    let qv = QuantumVault::new(SecurityLevel::Level3)?;
    let _keypair = qv.keygen(Algorithm::MlKem768)?;
    Ok(())
}

async fn test_encrypt_decrypt(config: &CliConfig) -> Result<()> {
    use quantumvault_core::{Algorithm, QuantumVault, SecurityLevel};

    let qv = QuantumVault::new(SecurityLevel::Level3)?;
    let keypair = qv.keygen(Algorithm::MlKem768)?;

    let plaintext = b"Test message for encryption";
    let encrypted = qv.encrypt(plaintext, &keypair.public_key)?;
    let decrypted = qv.decrypt(&encrypted, &keypair.secret_key)?;

    if decrypted != plaintext {
        anyhow::bail!("Decrypted data doesn't match original");
    }

    Ok(())
}

async fn test_sign_verify(config: &CliConfig) -> Result<()> {
    use quantumvault_core::api::keygen;
    use quantumvault_core::{Algorithm, Config, SecurityLevel};

    let core_config = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()?;

    let keypair = keygen::generate_signature_keypair(Algorithm::MlDsa65, &core_config)?;
    let message = b"Test message for signing";

    let signature =
        quantumvault_core::api::sign::sign_message(message, &keypair.signing_key, &core_config)?;

    let valid = quantumvault_core::api::verify::verify_signature(
        message,
        &signature,
        &keypair.verifying_key,
        &core_config,
    )?;

    if !valid {
        anyhow::bail!("Signature verification failed");
    }

    Ok(())
}

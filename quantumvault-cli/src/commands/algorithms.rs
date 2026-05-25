//! Algorithms information command.

use crate::output::CommandOutput;
use anyhow::Result;
use colored::Colorize;

/// Run the algorithms command.
pub async fn run() -> Result<CommandOutput> {
    println!();
    println!("{}", "Supported Algorithms".bold().cyan());
    println!("{}", "=".repeat(60));
    println!();

    println!("{}", "Key Encapsulation Mechanisms (KEM) - FIPS 203".bold());
    println!();
    print_algorithm(
        "ML-KEM-512",
        "Level 1",
        "800 bytes",
        "1632 bytes",
        "Basic security, fastest",
    );
    print_algorithm(
        "ML-KEM-768",
        "Level 3",
        "1184 bytes",
        "2400 bytes",
        "Recommended for most uses",
    );
    print_algorithm(
        "ML-KEM-1024",
        "Level 5",
        "1568 bytes",
        "3168 bytes",
        "Highest security, CNSA 2.0",
    );
    println!();

    println!("{}", "Digital Signature Algorithms (DSA) - FIPS 204".bold());
    println!();
    print_algorithm(
        "ML-DSA-44",
        "Level 2",
        "1312 bytes",
        "2560 bytes",
        "Basic security, smallest",
    );
    print_algorithm(
        "ML-DSA-65",
        "Level 3",
        "1952 bytes",
        "4032 bytes",
        "Recommended for most uses",
    );
    print_algorithm(
        "ML-DSA-87",
        "Level 5",
        "2592 bytes",
        "4896 bytes",
        "Highest security, CNSA 2.0",
    );
    println!();

    println!("{}", "Hash-Based Signatures (SLH-DSA) - FIPS 205".bold());
    println!();
    print_algorithm(
        "SLH-DSA-SHAKE-128s",
        "Level 3",
        "32 bytes",
        "64 bytes",
        "Small signature (~8 KB)",
    );
    print_algorithm(
        "SLH-DSA-SHAKE-128f",
        "Level 3",
        "32 bytes",
        "64 bytes",
        "Fast signing (~17 KB sig)",
    );
    print_algorithm(
        "SLH-DSA-SHAKE-256s",
        "Level 5",
        "64 bytes",
        "128 bytes",
        "Highest security, small sig",
    );
    print_algorithm(
        "SLH-DSA-SHAKE-256f",
        "Level 5",
        "64 bytes",
        "128 bytes",
        "Highest security, fast",
    );
    println!();

    println!("{}", "Security Levels".bold());
    println!();
    println!(
        "  {} - Equivalent to AES-128 (128-bit security)",
        "Level 1".yellow()
    );
    println!(
        "  {} - Equivalent to SHA-256 collision resistance",
        "Level 2".yellow()
    );
    println!(
        "  {} - Equivalent to AES-192 (192-bit security) {}",
        "Level 3".yellow(),
        "[Recommended]".green()
    );
    println!(
        "  {} - Equivalent to SHA-384 collision resistance",
        "Level 4".yellow()
    );
    println!(
        "  {} - Equivalent to AES-256 (256-bit security) {}",
        "Level 5".yellow(),
        "[CNSA 2.0]".cyan()
    );
    println!();

    println!("{}", "Compliance Profiles".bold());
    println!();
    println!("  {} - No specific requirements", "Standard".white());
    println!(
        "  {} - US Government classified systems (Level 5 required)",
        "CNSA 2.0".cyan()
    );
    println!(
        "  {} - US Government unclassified systems (Level 3+)",
        "FIPS 140-3".cyan()
    );
    println!(
        "  {} - Payment card processing (Level 3+)",
        "PCI-DSS".cyan()
    );
    println!("  {} - Healthcare data (Level 3+)", "HIPAA".cyan());
    println!();

    Ok(CommandOutput::success_with_data(
        "Algorithm information displayed",
        serde_json::json!({
            "kem_algorithms": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
            "dsa_algorithms": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
            "hash_signatures": ["SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"],
            "recommended": {
                "kem": "ML-KEM-768",
                "dsa": "ML-DSA-65",
                "cnsa2": ["ML-KEM-1024", "ML-DSA-87"],
            }
        }),
    ))
}

fn print_algorithm(name: &str, level: &str, pk_size: &str, sk_size: &str, notes: &str) {
    println!(
        "  {:<25} {} | PK: {} | SK: {}",
        name.green(),
        level.yellow(),
        pk_size,
        sk_size
    );
    println!("  {:<25} {}", "", notes.dimmed());
}

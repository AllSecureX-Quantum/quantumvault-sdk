//! Migration commands for crypto discovery and transformation.

use crate::config::CliConfig;
use crate::output::CommandOutput;
use crate::MigrateCommands;
use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Run migration commands.
pub async fn run(cmd: MigrateCommands, config: &CliConfig) -> Result<CommandOutput> {
    match cmd {
        MigrateCommands::Scan {
            path,
            output,
            include: _,
            exclude: _,
        } => scan(config, path.into(), output, true).await,
        MigrateCommands::Plan {
            report,
            strategy: _,
        } => plan(config, report, None).await,
    }
}

/// Crypto usage finding from scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFinding {
    pub file_path: String,
    pub line_number: usize,
    pub finding_type: FindingType,
    pub algorithm: String,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingType {
    WeakAlgorithm,
    DeprecatedApi,
    HardcodedKey,
    InsecureRandom,
    VulnerableLibrary,
    ClassicalCrypto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Scan report structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_timestamp: String,
    pub scanned_path: String,
    pub total_files_scanned: usize,
    pub findings: Vec<CryptoFinding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub quantum_vulnerable_algorithms: Vec<String>,
}

/// Migration plan structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub plan_id: String,
    pub created_at: String,
    pub findings_addressed: usize,
    pub steps: Vec<MigrationStep>,
    pub estimated_impact: ImpactAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStep {
    pub step_number: usize,
    pub description: String,
    pub file_path: String,
    pub current_algorithm: String,
    pub recommended_algorithm: String,
    pub code_changes: Vec<CodeChange>,
    pub testing_requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeChange {
    pub line_number: usize,
    pub original: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    pub performance_impact: String,
    pub key_size_change: String,
    pub compatibility_notes: Vec<String>,
}

// Patterns for detecting classical/weak cryptography
const WEAK_CRYPTO_PATTERNS: &[(&str, &str, &str)] = &[
    // RSA patterns
    (
        r"RSA",
        "RSA",
        "Replace with ML-KEM for encryption or ML-DSA for signatures",
    ),
    (
        r"rsa\.generate",
        "RSA Key Generation",
        "Use quantumvault.keygen() with ML-KEM/ML-DSA",
    ),
    // ECDSA/ECDH patterns
    (r"ECDSA", "ECDSA", "Replace with ML-DSA or SLH-DSA"),
    (r"ECDH", "ECDH", "Replace with ML-KEM key encapsulation"),
    (
        r"secp256k1|secp384r1|P-256|P-384",
        "Elliptic Curve",
        "Replace with post-quantum algorithm",
    ),
    // DSA patterns
    (r"DSA(?!-)", "DSA", "Replace with ML-DSA"),
    // DH patterns
    (
        r"DiffieHellman|diffie-hellman",
        "Diffie-Hellman",
        "Replace with ML-KEM",
    ),
    // Weak hash patterns
    (r"MD5|md5", "MD5", "Use SHA-3 or SHAKE"),
    (r"SHA1|sha1|SHA-1", "SHA-1", "Use SHA-256 or SHA-3"),
    // Weak symmetric
    (r"DES(?!A)|3DES|TripleDES", "DES/3DES", "Use AES-256-GCM"),
    (
        r"RC4|rc4|arcfour",
        "RC4",
        "Use AES-256-GCM or ChaCha20-Poly1305",
    ),
    (r"Blowfish|blowfish", "Blowfish", "Use AES-256-GCM"),
    // Hardcoded keys
    (
        r#"['"](-----BEGIN.*KEY-----)"#,
        "Hardcoded Key",
        "Use secure key storage",
    ),
    (
        r#"api[_-]?key\s*=\s*['"]"#,
        "Hardcoded API Key",
        "Use environment variables or secrets manager",
    ),
];

async fn scan(
    _config: &CliConfig,
    path: PathBuf,
    output: Option<String>,
    recursive: bool,
) -> Result<CommandOutput> {
    use chrono::Utc;
    use regex::Regex;
    use std::fs;
    use walkdir::WalkDir;

    println!();
    println!("{}", "QuantumVault Crypto Scanner".bold().cyan());
    println!("{}", "=".repeat(50));
    println!();
    println!("Scanning: {}", path.display().to_string().yellow());
    println!("Recursive: {}", if recursive { "Yes" } else { "No" });
    println!();

    let mut findings = Vec::new();
    let mut files_scanned = 0;

    // Build walker
    let walker = if recursive {
        WalkDir::new(&path).follow_links(true)
    } else {
        WalkDir::new(&path).max_depth(1)
    };

    // Supported file extensions
    let code_extensions = [
        "rs", "py", "js", "ts", "go", "java", "c", "cpp", "h", "hpp", "cs", "rb", "php",
    ];

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let file_path = entry.path();

        // Skip non-files
        if !file_path.is_file() {
            continue;
        }

        // Check extension
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !code_extensions.contains(&ext) {
            continue;
        }

        files_scanned += 1;

        // Read file content
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue, // Skip binary/unreadable files
        };

        // Check for patterns
        for (pattern, algorithm, recommendation) in WEAK_CRYPTO_PATTERNS {
            let re = match Regex::new(pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for (line_num, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    let severity = determine_severity(algorithm);
                    let finding_type = determine_finding_type(algorithm);

                    findings.push(CryptoFinding {
                        file_path: file_path.display().to_string(),
                        line_number: line_num + 1,
                        finding_type,
                        algorithm: algorithm.to_string(),
                        severity,
                        description: format!(
                            "Found usage of {} which is vulnerable to quantum attacks",
                            algorithm
                        ),
                        recommendation: recommendation.to_string(),
                    });
                }
            }
        }

        // Progress indicator
        if files_scanned % 100 == 0 {
            print!("\r  Scanned {} files...", files_scanned);
        }
    }

    println!("\r  Scanned {} files          ", files_scanned);
    println!();

    // Build summary
    let summary = ScanSummary {
        critical_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count(),
        high_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .count(),
        medium_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Medium))
            .count(),
        low_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Low))
            .count(),
        info_count: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Info))
            .count(),
        quantum_vulnerable_algorithms: findings
            .iter()
            .map(|f| f.algorithm.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect(),
    };

    let report = ScanReport {
        scan_timestamp: Utc::now().to_rfc3339(),
        scanned_path: path.display().to_string(),
        total_files_scanned: files_scanned,
        findings: findings.clone(),
        summary: summary.clone(),
    };

    // Print summary
    println!("{}", "Scan Results".bold());
    println!("{}", "-".repeat(30));
    println!("  {} Critical", format_count(summary.critical_count, "red"));
    println!("  {} High", format_count(summary.high_count, "red"));
    println!("  {} Medium", format_count(summary.medium_count, "yellow"));
    println!("  {} Low", format_count(summary.low_count, "blue"));
    println!("  {} Info", format_count(summary.info_count, "white"));
    println!();

    if !summary.quantum_vulnerable_algorithms.is_empty() {
        println!("{}", "Quantum-Vulnerable Algorithms Found:".bold().red());
        for alg in &summary.quantum_vulnerable_algorithms {
            println!("  - {}", alg.yellow());
        }
        println!();
    }

    // Print top findings
    if !findings.is_empty() {
        println!("{}", "Top Findings:".bold());
        for finding in findings.iter().take(10) {
            let severity_color = match finding.severity {
                Severity::Critical => "red",
                Severity::High => "red",
                Severity::Medium => "yellow",
                Severity::Low => "blue",
                Severity::Info => "white",
            };
            println!(
                "  [{}] {}:{} - {}",
                format_severity(&finding.severity, severity_color),
                finding.file_path,
                finding.line_number,
                finding.algorithm
            );
        }
        if findings.len() > 10 {
            println!("  ... and {} more findings", findings.len() - 10);
        }
        println!();
    }

    // Write report
    let report_path = output.unwrap_or_else(|| "quantumvault-scan-report.json".to_string());
    let report_json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&report_path, &report_json)?;
    println!("Report written to: {}", report_path.green());
    println!();

    Ok(CommandOutput::success_with_data(
        format!(
            "Scan complete. Found {} findings in {} files",
            findings.len(),
            files_scanned
        ),
        serde_json::json!({
            "files_scanned": files_scanned,
            "total_findings": findings.len(),
            "critical": summary.critical_count,
            "high": summary.high_count,
            "medium": summary.medium_count,
            "low": summary.low_count,
            "report_path": report_path,
        }),
    ))
}

async fn plan(
    _config: &CliConfig,
    scan_report: String,
    output: Option<String>,
) -> Result<CommandOutput> {
    use chrono::Utc;
    use uuid::Uuid;

    println!();
    println!("{}", "QuantumVault Migration Planner".bold().cyan());
    println!("{}", "=".repeat(50));
    println!();

    // Load scan report
    let report_content =
        std::fs::read_to_string(&scan_report).context("Failed to read scan report")?;
    let report: ScanReport =
        serde_json::from_str(&report_content).context("Failed to parse scan report")?;

    println!("Loaded scan report from: {}", scan_report.yellow());
    println!("Findings to address: {}", report.findings.len());
    println!();

    // Generate migration steps
    let mut steps = Vec::new();
    let mut step_num = 1;

    for finding in &report.findings {
        let recommended = get_recommended_algorithm(&finding.algorithm);

        steps.push(MigrationStep {
            step_number: step_num,
            description: format!(
                "Replace {} with {} in {}",
                finding.algorithm, recommended, finding.file_path
            ),
            file_path: finding.file_path.clone(),
            current_algorithm: finding.algorithm.clone(),
            recommended_algorithm: recommended.to_string(),
            code_changes: vec![CodeChange {
                line_number: finding.line_number,
                original: format!("// Current: {}", finding.algorithm),
                replacement: format!("// Use: quantumvault with {}", recommended),
            }],
            testing_requirements: vec![
                "Verify encryption/decryption roundtrip".to_string(),
                "Check key sizes match expected values".to_string(),
                "Run performance benchmarks".to_string(),
                "Verify backward compatibility if needed".to_string(),
            ],
        });
        step_num += 1;
    }

    let plan = MigrationPlan {
        plan_id: Uuid::new_v4().to_string(),
        created_at: Utc::now().to_rfc3339(),
        findings_addressed: report.findings.len(),
        steps,
        estimated_impact: ImpactAssessment {
            performance_impact: "ML-KEM/ML-DSA operations are ~10-100x slower than classical RSA/ECDSA for signing, but comparable for encryption".to_string(),
            key_size_change: "Public keys increase from ~256 bytes (ECDSA) to ~1952 bytes (ML-DSA-65) or ~1184 bytes (ML-KEM-768)".to_string(),
            compatibility_notes: vec![
                "Post-quantum algorithms are not backward compatible with classical systems".to_string(),
                "Consider hybrid mode for transition period".to_string(),
                "Update key storage to accommodate larger keys".to_string(),
                "Review network protocols for larger signature/key sizes".to_string(),
            ],
        },
    };

    // Print plan summary
    println!("{}", "Migration Plan Summary".bold());
    println!("{}", "-".repeat(30));
    println!("  Plan ID: {}", plan.plan_id);
    println!("  Steps: {}", plan.steps.len());
    println!();

    println!("{}", "Recommended Migrations:".bold());
    let mut algo_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for step in &plan.steps {
        *algo_counts
            .entry(format!(
                "{} -> {}",
                step.current_algorithm, step.recommended_algorithm
            ))
            .or_insert(0) += 1;
    }
    for (migration, count) in &algo_counts {
        println!("  {} ({} occurrences)", migration.yellow(), count);
    }
    println!();

    println!("{}", "Impact Assessment:".bold());
    println!(
        "  Performance: {}",
        plan.estimated_impact.performance_impact
    );
    println!("  Key Sizes: {}", plan.estimated_impact.key_size_change);
    println!();

    println!("{}", "Compatibility Notes:".bold());
    for note in &plan.estimated_impact.compatibility_notes {
        println!("  - {}", note);
    }
    println!();

    // Write plan
    let plan_path = output.unwrap_or_else(|| "quantumvault-migration-plan.json".to_string());
    let plan_json = serde_json::to_string_pretty(&plan)?;
    std::fs::write(&plan_path, &plan_json)?;
    println!("Migration plan written to: {}", plan_path.green());
    println!();

    Ok(CommandOutput::success_with_data(
        format!("Migration plan created with {} steps", plan.steps.len()),
        serde_json::json!({
            "plan_id": plan.plan_id,
            "total_steps": plan.steps.len(),
            "plan_path": plan_path,
        }),
    ))
}

fn determine_severity(algorithm: &str) -> Severity {
    match algorithm {
        "Hardcoded Key" | "Hardcoded API Key" => Severity::Critical,
        "MD5" | "SHA-1" | "DES/3DES" | "RC4" => Severity::High,
        "RSA" | "ECDSA" | "ECDH" | "DSA" | "Diffie-Hellman" => Severity::High, // Quantum vulnerable
        "Elliptic Curve" => Severity::Medium,
        "Blowfish" => Severity::Medium,
        _ => Severity::Info,
    }
}

fn determine_finding_type(algorithm: &str) -> FindingType {
    match algorithm {
        "Hardcoded Key" | "Hardcoded API Key" => FindingType::HardcodedKey,
        "MD5" | "SHA-1" => FindingType::WeakAlgorithm,
        "DES/3DES" | "RC4" | "Blowfish" => FindingType::WeakAlgorithm,
        "RSA" | "ECDSA" | "ECDH" | "DSA" | "Diffie-Hellman" | "Elliptic Curve" => {
            FindingType::ClassicalCrypto
        }
        _ => FindingType::DeprecatedApi,
    }
}

fn get_recommended_algorithm(current: &str) -> &'static str {
    match current {
        "RSA" => "ML-KEM-768 (encryption) or ML-DSA-65 (signatures)",
        "ECDSA" | "DSA" => "ML-DSA-65 or SLH-DSA-SHAKE-128s",
        "ECDH" | "Diffie-Hellman" | "Elliptic Curve" => "ML-KEM-768",
        "MD5" | "SHA-1" => "SHA-3-256 or SHAKE256",
        "DES/3DES" | "RC4" | "Blowfish" => "AES-256-GCM",
        "Hardcoded Key" | "Hardcoded API Key" => "AWS Secrets Manager or QuantumVault Key Storage",
        _ => "ML-KEM-768 / ML-DSA-65",
    }
}

fn format_count(count: usize, color: &str) -> String {
    let s = format!("{:>3}", count);
    match color {
        "red" => s.red().to_string(),
        "yellow" => s.yellow().to_string(),
        "blue" => s.blue().to_string(),
        _ => s.white().to_string(),
    }
}

fn format_severity(severity: &Severity, color: &str) -> String {
    let label = match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED ",
        Severity::Low => "LOW ",
        Severity::Info => "INFO",
    };
    match color {
        "red" => label.red().to_string(),
        "yellow" => label.yellow().to_string(),
        "blue" => label.blue().to_string(),
        _ => label.white().to_string(),
    }
}

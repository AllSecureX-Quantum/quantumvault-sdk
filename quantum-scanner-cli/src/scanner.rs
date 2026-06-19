//! Local file scanner module
//!
//! Scans files locally for cryptographic patterns. Only findings
//! are sent to the API - source code never leaves the machine.

use crate::api;
use crate::auth;
use crate::config::Config;
use crate::patterns::{self, Finding, QuantumRisk, Severity};
use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: Option<String>,
    pub crypto_agility_score: u32,
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
    pub synced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_coverage: Option<ScanCoverage>,
}

/// Scan summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub by_severity: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub by_quantum_risk: HashMap<String, usize>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    /// Count of vulnerable (non-quantum-safe) findings - what risk score is calculated from
    pub vulnerable_count: usize,
    /// Count of quantum-safe / modern primitives detected (Info, QuantumSafe)
    pub quantum_safe_count: usize,
    pub estimated_hours: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub libraries_detected: Option<Vec<String>>,
    /// Distinct quantum-safe algorithms detected (e.g. ["ML-KEM", "AES-256", "SHA-256"])
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantum_safe_algorithms: Option<Vec<String>>,
}

/// Scan coverage and blind spots — "Known Unknowns"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCoverage {
    pub total_files_discovered: usize,
    pub files_scanned: usize,
    pub files_skipped_minified: usize,
    pub files_skipped_too_large: usize,
    pub files_skipped_binary: usize,
    pub files_skipped_lock: usize,
    pub directories_excluded: Vec<String>,
    pub languages_covered: Vec<String>,
    pub blind_spots: Vec<String>,
}

// File extensions to scan
const SCANNABLE_EXTENSIONS: &[&str] = &[
    "js", "jsx", "mjs", "cjs", "ts", "tsx", "py", "pyw", "java", "kt", "kts", "go", "rs", "c",
    "cpp", "cc", "cxx", "h", "hpp", "cs", "rb", "php", "swift", "scala", "sh", "bash", "yaml",
    "yml", "json", "xml", "conf", "cfg", "ini", "pem", "crt", "cer", "key",
];

// Directories to skip (build outputs, dependencies, caches)
const SKIP_DIRS: &[&str] = &[
    // Package managers & dependencies
    "node_modules",
    "vendor",
    "bower_components",
    // Version control
    ".git",
    ".svn",
    ".hg",
    // Build outputs
    "dist",
    "build",
    "out",
    "target",
    "bin",
    "obj",
    "cdk.out",
    ".cdk.staging",
    ".serverless",
    ".next",
    ".nuxt",
    ".output",
    ".vercel",
    // Python
    "__pycache__",
    ".pytest_cache",
    ".tox",
    ".mypy_cache",
    "venv",
    "env",
    ".venv",
    ".env",
    "virtualenv",
    "site-packages",
    ".eggs",
    "*.egg-info",
    // Test & coverage
    "coverage",
    ".nyc_output",
    ".coverage",
    // IDE
    ".idea",
    ".vscode",
    ".vs",
    // Terraform/IaC
    ".terraform",
    "terraform.tfstate.d",
];

// Files to skip
const SKIP_FILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile.lock",
    "composer.lock",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "go.sum",
];

const MAX_FILE_SIZE: u64 = 1024 * 1024; // 1 MB

/// Run a scan on the specified path
pub async fn run_scan(
    path: &Path,
    scan_type: &str,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    sync: bool,
    _executive: bool,
    output: Option<&PathBuf>,
    ci: bool,
    config: &Config,
) -> Result<ScanResult> {
    let start_time = std::time::Instant::now();

    // Resolve path
    let scan_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    if !scan_path.exists() {
        anyhow::bail!("Path does not exist: {}", scan_path.display());
    }

    if !ci {
        println!();
        println!(
            "  {} Scanning: {}",
            "◆".cyan(),
            scan_path.display().to_string().blue()
        );
        println!("  {} Type: {}", "◆".cyan(), scan_type.yellow());
        println!();
    }

    // Collect files to scan
    let files = collect_files(&scan_path, &include, &exclude)?;
    let total_files = files.len();

    if !ci {
        println!("  {} Discovered {} files", "✓".green(), total_files);
    }

    // Progress bar
    let progress = if !ci && config.show_progress {
        let pb = ProgressBar::new(total_files as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.cyan} [{bar:40.cyan/white}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("█▓░"),
        );
        Some(pb)
    } else {
        None
    };

    // Scan files with coverage tracking
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut files_scanned = 0;
    let mut files_skipped_minified = 0;
    let mut files_skipped_binary = 0;
    let mut languages_seen = std::collections::HashSet::new();
    let mut libraries_seen = std::collections::HashSet::new();

    for file_path in &files {
        if let Some(pb) = &progress {
            let file_name = file_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            pb.set_message(format!("Scanning {}", file_name));
            pb.inc(1);
        }

        // Read file
        match fs::read_to_string(file_path) {
            Ok(content) => {
                // Skip minified files
                if is_minified_file(&content) {
                    files_skipped_minified += 1;
                    continue;
                }

                let rel_path = file_path
                    .strip_prefix(&scan_path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();

                let language = patterns::detect_language(&rel_path);
                if language != "unknown" {
                    languages_seen.insert(language.to_string());
                }

                let findings = patterns::scan_content(&content, &rel_path, language);

                // Track detected libraries
                for f in &findings {
                    if let Some(ref lib) = f.library_name {
                        libraries_seen.insert(lib.clone());
                    }
                }

                all_findings.extend(findings);
                files_scanned += 1;
            }
            Err(_) => {
                // Binary file or encoding issue
                files_skipped_binary += 1;
            }
        }
    }

    if let Some(pb) = progress {
        pb.finish_with_message("Scan complete");
    }

    // Deduplicate findings (same file + line + pattern)
    all_findings = deduplicate_findings(all_findings);

    // Calculate score and summary
    let crypto_agility_score = patterns::calculate_crypto_agility_score(&all_findings);
    let summary = calculate_summary(&all_findings);

    // Build scan coverage / blind spots
    let mut blind_spots = Vec::new();
    if files_skipped_minified > 0 {
        blind_spots.push(format!(
            "{} minified/bundled files were skipped (may contain crypto)",
            files_skipped_minified
        ));
    }
    if files_skipped_binary > 0 {
        blind_spots.push(format!(
            "{} binary/unreadable files were skipped",
            files_skipped_binary
        ));
    }
    blind_spots
        .push("Vendor-managed services and black-box appliances are not scanned".to_string());
    blind_spots.push("Runtime-negotiated TLS cipher suites are not captured (use QERA for outside-in assessment)".to_string());

    let dirs_excluded: Vec<String> = SKIP_DIRS.iter().map(|d| d.to_string()).collect();

    let scan_coverage = ScanCoverage {
        total_files_discovered: total_files,
        files_scanned,
        files_skipped_minified,
        files_skipped_too_large: 0,
        files_skipped_binary,
        files_skipped_lock: 0,
        directories_excluded: dirs_excluded,
        languages_covered: languages_seen.into_iter().collect(),
        blind_spots,
    };

    // Add detected libraries to summary
    let mut summary_with_libs = summary.clone();
    let libs: Vec<String> = libraries_seen.into_iter().collect();
    if !libs.is_empty() {
        summary_with_libs.libraries_detected = Some(libs);
    }

    let duration = start_time.elapsed();

    // Print results
    if !ci {
        print_results(
            &all_findings,
            &summary,
            crypto_agility_score,
            files_scanned,
            duration,
        );
    }

    // Sync to API if requested
    let mut scan_id = None;
    let mut synced = false;

    if sync {
        if let Ok(Some(_api_key)) = auth::get_stored_api_key() {
            match api::sync_scan(&all_findings, &summary, crypto_agility_score, files_scanned).await
            {
                Ok(id) => {
                    scan_id = Some(id.clone());
                    synced = true;
                    if !ci {
                        println!();
                        println!("  {} Results synced to AllSecureX platform", "✓".green());
                        println!(
                            "    View report: {}",
                            format!("https://quantumvault.allsecurex.com/scanner/{}", id).blue()
                        );
                        println!();
                        println!("  {} Quick Actions:", "◆".cyan());
                        println!(
                            "    {} View summary:   {}",
                            "→".dimmed(),
                            format!("quantum-scanner report {}", id).blue()
                        );
                        println!(
                            "    {} Open in browser: {}",
                            "→".dimmed(),
                            format!("quantum-scanner report {} --open", id).blue()
                        );
                        println!(
                            "    {} Export HTML:     {}",
                            "→".dimmed(),
                            format!("quantum-scanner report {} --export html", id).blue()
                        );
                        println!(
                            "    {} List all scans:  {}",
                            "→".dimmed(),
                            "quantum-scanner report --list".blue()
                        );
                    }
                }
                Err(e) => {
                    if !ci {
                        eprintln!("  {} Failed to sync results: {}", "⚠".yellow(), e);
                    }
                }
            }
        }
    }

    // Save to file if requested
    if let Some(output_path) = output {
        let result = ScanResult {
            scan_id: scan_id.clone(),
            crypto_agility_score,
            files_scanned,
            findings: all_findings.clone(),
            summary: summary_with_libs.clone(),
            synced,
            scan_coverage: Some(scan_coverage.clone()),
        };
        let json = serde_json::to_string_pretty(&result)?;
        fs::write(output_path, json)?;
        if !ci {
            println!(
                "  {} Report saved to: {}",
                "✓".green(),
                output_path.display()
            );
        }
    }

    Ok(ScanResult {
        scan_id,
        crypto_agility_score,
        files_scanned,
        findings: all_findings,
        summary: summary_with_libs,
        synced,
        scan_coverage: Some(scan_coverage),
    })
}

fn collect_files(
    path: &Path,
    include: &Option<Vec<String>>,
    exclude: &Option<Vec<String>>,
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !should_skip_dir(e.file_name().to_str().unwrap_or("")))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let file_path = entry.path();
        let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Skip certain files
        if SKIP_FILES.contains(&file_name) {
            continue;
        }

        // Check extension
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !SCANNABLE_EXTENSIONS.contains(&ext) {
            continue;
        }

        // Check file size
        if let Ok(metadata) = fs::metadata(file_path) {
            if metadata.len() > MAX_FILE_SIZE {
                continue;
            }
        }

        // Apply include patterns
        if let Some(patterns) = include {
            let rel_path = file_path.to_string_lossy();
            let matches = patterns.iter().any(|p| {
                glob::Pattern::new(p)
                    .map(|pat| pat.matches(&rel_path))
                    .unwrap_or(false)
            });
            if !matches {
                continue;
            }
        }

        // Apply exclude patterns
        if let Some(patterns) = exclude {
            let rel_path = file_path.to_string_lossy();
            let excluded = patterns.iter().any(|p| {
                glob::Pattern::new(p)
                    .map(|pat| pat.matches(&rel_path))
                    .unwrap_or(false)
            });
            if excluded {
                continue;
            }
        }

        files.push(file_path.to_path_buf());
    }

    Ok(files)
}

fn should_skip_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name)
}

/// Check if a file appears to be minified/bundled (very long lines, no meaningful structure)
fn is_minified_file(content: &str) -> bool {
    let lines: Vec<&str> = content.lines().take(20).collect();
    if lines.is_empty() {
        return false;
    }

    // If any of the first 20 lines is over 1000 chars, likely minified
    let has_very_long_line = lines.iter().any(|line| line.len() > 1000);

    // Calculate average line length
    let total_len: usize = lines.iter().map(|l| l.len()).sum();
    let avg_len = total_len / lines.len();

    // If avg line length > 500, likely minified
    has_very_long_line || avg_len > 500
}

/// Deduplicate findings - keep only unique file+line+pattern combinations
fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    use std::collections::HashSet;

    let mut seen: HashSet<(String, usize, String)> = HashSet::new();
    let mut unique_findings: Vec<Finding> = Vec::new();

    for finding in findings {
        let key = (
            finding.file_path.clone(),
            finding.line,
            finding.pattern_id.clone(),
        );

        if !seen.contains(&key) {
            seen.insert(key);
            unique_findings.push(finding);
        }
    }

    // Sort by severity (critical first), then by file path
    unique_findings.sort_by(|a, b| {
        let severity_order = |s: &Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };

        severity_order(&a.severity)
            .cmp(&severity_order(&b.severity))
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line.cmp(&b.line))
    });

    unique_findings
}

fn calculate_summary(findings: &[Finding]) -> ScanSummary {
    let mut by_severity: HashMap<String, usize> = HashMap::new();
    let mut by_category: HashMap<String, usize> = HashMap::new();
    let mut by_quantum_risk: HashMap<String, usize> = HashMap::new();

    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut info_count = 0;
    let mut quantum_safe_count = 0;
    let mut vulnerable_count = 0;
    let mut safe_algos: std::collections::HashSet<String> = std::collections::HashSet::new();

    for finding in findings {
        *by_severity
            .entry(finding.severity.as_str().to_string())
            .or_insert(0) += 1;
        *by_category
            .entry(format!("{:?}", finding.category))
            .or_insert(0) += 1;
        *by_quantum_risk
            .entry(finding.quantum_risk.as_str().to_string())
            .or_insert(0) += 1;

        match finding.severity {
            Severity::Critical => critical_count += 1,
            Severity::High => high_count += 1,
            Severity::Medium => medium_count += 1,
            Severity::Low => low_count += 1,
            Severity::Info => info_count += 1,
        }

        if finding.quantum_risk == QuantumRisk::QuantumSafe {
            quantum_safe_count += 1;
            safe_algos.insert(finding.algorithm.clone());
        } else {
            vulnerable_count += 1;
        }
    }

    // Estimate migration hours, but only for vulnerable findings - safe findings are 0
    let estimated_hours = findings
        .iter()
        .filter(|f| f.quantum_risk != QuantumRisk::QuantumSafe)
        .map(|f| match f.migration_effort.as_str() {
            "trivial" => 0.5,
            "easy" => 2.0,
            "moderate" => 8.0,
            "complex" => 24.0,
            "requires_redesign" => 80.0,
            _ => 4.0,
        })
        .sum();

    let quantum_safe_algorithms = if safe_algos.is_empty() {
        None
    } else {
        let mut v: Vec<String> = safe_algos.into_iter().collect();
        v.sort();
        Some(v)
    };

    ScanSummary {
        by_severity,
        by_category,
        by_quantum_risk,
        total_findings: findings.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        vulnerable_count,
        quantum_safe_count,
        estimated_hours,
        libraries_detected: None,
        quantum_safe_algorithms,
    }
}

fn print_results(
    findings: &[Finding],
    summary: &ScanSummary,
    score: u32,
    files_scanned: usize,
    duration: std::time::Duration,
) {
    println!();
    println!(
        "  {}",
        "═══════════════════════════════════════════════════════════════".dimmed()
    );
    println!();

    // Crypto Agility Score
    println!("  ┌───────────────────────────────────────────────────────────┐");
    println!("  │                   CRYPTO AGILITY SCORE                    │");
    println!("  │                                                           │");

    let score_color = if score >= 80 {
        "green"
    } else if score >= 50 {
        "yellow"
    } else {
        "red"
    };

    let score_bar = "█".repeat((score as usize) / 5);
    let empty_bar = "░".repeat(20 - (score as usize) / 5);

    println!(
        "  │                          {}/100                          │",
        match score_color {
            "green" => score.to_string().green(),
            "yellow" => score.to_string().yellow(),
            _ => score.to_string().red(),
        }
    );
    println!(
        "  │                    {}{}                    │",
        match score_color {
            "green" => score_bar.green(),
            "yellow" => score_bar.yellow(),
            _ => score_bar.red(),
        },
        empty_bar.dimmed()
    );
    println!("  │                                                           │");

    let status = if score >= 80 {
        "✓ QUANTUM READY".green()
    } else if score >= 50 {
        "⚠ NEEDS ATTENTION".yellow()
    } else {
        "✗ ACTION REQUIRED".red()
    };
    println!("  │                     {}                      │", status);
    println!("  │                                                           │");
    println!("  └───────────────────────────────────────────────────────────┘");
    println!();

    // Findings Summary
    println!("  ┌───────────────────────────────────────────────────────────┐");
    println!("  │ FINDINGS SUMMARY                                          │");
    println!("  ├───────────────────────────────────────────────────────────┤");
    println!(
        "  │  {} CRITICAL    {:>4}    Broken or highly vulnerable       │",
        "🔴".to_string(),
        summary.critical_count
    );
    println!(
        "  │  {} HIGH        {:>4}    Quantum-vulnerable by 2030        │",
        "🟠".to_string(),
        summary.high_count
    );
    println!(
        "  │  {} MEDIUM      {:>4}    Needs assessment                  │",
        "🟡".to_string(),
        summary.medium_count
    );
    println!(
        "  │  {} LOW         {:>4}    Minor issues                      │",
        "🔵".to_string(),
        summary.low_count
    );
    println!(
        "  │  {} INFO        {:>4}    Informational                     │",
        "⚪".to_string(),
        summary.info_count
    );
    println!(
        "  │  {} QUANTUM-SAFE{:>4}    Already PQC / modern               │",
        "✅".to_string(),
        summary.quantum_safe_count
    );
    println!("  │                                                           │");
    println!(
        "  │  Vulnerable:    {:>6}    (drives risk score)              │",
        summary.vulnerable_count
    );
    println!(
        "  │  Files Scanned: {:>6}                                     │",
        files_scanned
    );
    println!(
        "  │  Scan Duration: {:>5.1}s                                     │",
        duration.as_secs_f32()
    );
    println!(
        "  │  Est. Migration: {:>4.0} hours                               │",
        summary.estimated_hours
    );
    println!("  └───────────────────────────────────────────────────────────┘");

    // Quantum-safe primitives panel (positive signal)
    if let Some(ref safe_algos) = summary.quantum_safe_algorithms {
        if !safe_algos.is_empty() {
            println!();
            println!("  {} Quantum-safe primitives detected:", "✓".green());
            for algo in safe_algos.iter().take(8) {
                println!("    {} {}", "✓".green(), algo.green());
            }
            if safe_algos.len() > 8 {
                println!(
                    "    {}",
                    format!("... and {} more", safe_algos.len() - 8).dimmed()
                );
            }
        }
    }

    // Top findings
    if !findings.is_empty() {
        println!();
        println!("  {} Top Findings:", "◆".cyan());
        println!();

        for (i, finding) in findings.iter().take(5).enumerate() {
            let severity_icon = match finding.severity {
                Severity::Critical => "🔴",
                Severity::High => "🟠",
                Severity::Medium => "🟡",
                Severity::Low => "🔵",
                Severity::Info => "⚪",
            };

            println!(
                "    {} {} {} at {}:{}",
                severity_icon,
                finding.algorithm.yellow(),
                format!("({})", finding.quantum_risk.as_str()).dimmed(),
                finding.file_path.blue(),
                finding.line
            );
            println!(
                "       → Migrate to: {}",
                finding.recommended_replacement.green()
            );
            if i < 4 {
                println!();
            }
        }

        if findings.len() > 5 {
            println!();
            println!(
                "    ... and {} more findings",
                (findings.len() - 5).to_string().dimmed()
            );
        }
    }

    println!();
}

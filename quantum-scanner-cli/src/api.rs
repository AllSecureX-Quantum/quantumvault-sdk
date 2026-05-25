//! API client module for AllSecureX platform
//!
//! Handles communication with the AllSecureX API for syncing
//! scan results and retrieving reports.
//!
//! Full scan results are stored locally, while only essential
//! summary data is sent to the API to avoid payload size limits.

use crate::auth;
use crate::patterns::{Category, Finding, QuantumRisk, Severity};
use crate::scanner::ScanSummary;
use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const API_BASE_URL: &str = "https://scanner-api.quantumvault.allsecurex.com";
const USER_AGENT: &str = concat!("AllSecureX-Quantum-Scanner/", env!("CARGO_PKG_VERSION"));

/// Lightweight finding for API upload (no context/code snippets)
#[derive(Serialize)]
struct LightFinding {
    algorithm: String,
    category: Category,
    severity: Severity,
    quantum_risk: QuantumRisk,
    file_path: String,
    line: usize,
    pattern_id: String,
}

impl From<&Finding> for LightFinding {
    fn from(f: &Finding) -> Self {
        LightFinding {
            algorithm: f.algorithm.clone(),
            category: f.category.clone(),
            severity: f.severity.clone(),
            quantum_risk: f.quantum_risk.clone(),
            file_path: f.file_path.clone(),
            line: f.line,
            pattern_id: f.pattern_id.clone(),
        }
    }
}

/// Full local scan report
#[derive(Serialize)]
struct LocalScanReport<'a> {
    scan_id: String,
    timestamp: String,
    findings: &'a [Finding],
    summary: &'a ScanSummary,
    crypto_agility_score: u32,
    files_scanned: usize,
    cli_version: &'static str,
}

/// Get the scans directory path
fn get_scans_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    Ok(home.join(".quantum-scanner").join("scans"))
}

/// Save full scan results locally
fn save_local_report(
    scan_id: &str,
    findings: &[Finding],
    summary: &ScanSummary,
    score: u32,
    files_scanned: usize,
) -> Result<PathBuf> {
    let scans_dir = get_scans_dir()?;
    fs::create_dir_all(&scans_dir)?;

    let report = LocalScanReport {
        scan_id: scan_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        findings,
        summary,
        crypto_agility_score: score,
        files_scanned,
        cli_version: env!("CARGO_PKG_VERSION"),
    };

    let report_path = scans_dir.join(format!("{}.json", scan_id));
    let content = serde_json::to_string_pretty(&report)?;
    fs::write(&report_path, content)?;

    Ok(report_path)
}

/// Get HTTP client with auth
fn get_client() -> Result<(reqwest::Client, String)> {
    let api_key =
        auth::get_stored_api_key()?.ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

    let client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;

    Ok((client, api_key))
}

/// Sync scan results to AllSecureX platform
/// Full results are uploaded to S3 via the API
pub async fn sync_scan(
    findings: &[Finding],
    summary: &ScanSummary,
    score: u32,
    files_scanned: usize,
) -> Result<String> {
    let (client, api_key) = get_client()?;

    #[derive(Serialize)]
    struct SyncRequest<'a> {
        name: String,
        config: ScanConfig,
        findings: &'a [Finding],
        summary: SyncSummary,
        crypto_agility_score: u32,
        files_scanned: usize,
        total_findings: usize,
        cli_version: &'static str,
    }

    #[derive(Serialize)]
    struct ScanConfig {
        target_type: &'static str,
        scan_depth: &'static str,
    }

    #[derive(Serialize)]
    struct SyncSummary {
        critical_count: usize,
        high_count: usize,
        medium_count: usize,
        low_count: usize,
        info_count: usize,
        by_category: std::collections::HashMap<String, usize>,
        estimated_effort_hours: u32,
    }

    let total_findings = findings.len();

    // Build category map
    let mut by_category = std::collections::HashMap::new();
    for (cat, count) in &summary.by_category {
        by_category.insert(cat.clone(), *count);
    }

    let request = SyncRequest {
        name: format!(
            "CLI Scan - {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
        ),
        config: ScanConfig {
            target_type: "local_directory",
            scan_depth: "full",
        },
        findings, // Send ALL findings now
        summary: SyncSummary {
            critical_count: summary.critical_count,
            high_count: summary.high_count,
            medium_count: summary.medium_count,
            low_count: summary.low_count,
            info_count: summary.info_count,
            by_category,
            estimated_effort_hours: summary.estimated_hours as u32,
        },
        crypto_agility_score: score,
        files_scanned,
        total_findings,
        cli_version: env!("CARGO_PKG_VERSION"),
    };

    let response = client
        .post(format!("{}/scanner/scans/upload", API_BASE_URL))
        .header("X-API-Key", &api_key)
        .json(&request)
        .send()
        .await
        .context("Failed to connect to AllSecureX API")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        // Check for quota exceeded
        if status.as_u16() == 429 {
            anyhow::bail!("Monthly scan limit reached. Upgrade at https://allsecurex.com/pricing");
        }

        anyhow::bail!("API error ({}): {}", status, body);
    }

    #[derive(Deserialize)]
    struct ApiResponse {
        success: bool,
        data: ScanData,
    }

    #[derive(Deserialize)]
    struct ScanData {
        scan_id: String,
    }

    let api_response: ApiResponse = response
        .json()
        .await
        .context("Failed to parse API response")?;

    let scan_id = api_response.data.scan_id;

    // Save full results locally
    match save_local_report(&scan_id, findings, summary, score, files_scanned) {
        Ok(path) => {
            println!("    Local report: {}", path.display().to_string().dimmed());
        }
        Err(e) => {
            eprintln!("    {} Failed to save local report: {}", "⚠".yellow(), e);
        }
    }

    Ok(scan_id)
}

/// Get report for a scan
pub async fn get_report(
    scan_id: Option<&str>,
    export: Option<&str>,
    output: Option<&PathBuf>,
) -> Result<()> {
    let (client, api_key) = get_client()?;

    // Get scan list if no ID provided
    let scan_id = if let Some(id) = scan_id {
        id.to_string()
    } else {
        // Get latest scan
        let response = client
            .get(format!("{}/scanner/scans", API_BASE_URL))
            .header("X-API-Key", &api_key)
            .query(&[("limit", "1")])
            .send()
            .await?;

        #[derive(Deserialize)]
        struct ListResponse {
            data: Vec<ScanItem>,
        }

        #[derive(Deserialize)]
        struct ScanItem {
            scan_id: String,
        }

        let list: ListResponse = response.json().await?;
        list.data
            .first()
            .map(|s| s.scan_id.clone())
            .ok_or_else(|| anyhow::anyhow!("No scans found"))?
    };

    // Get report
    let response = client
        .get(format!("{}/scanner/scans/{}/report", API_BASE_URL, scan_id))
        .header("X-API-Key", &api_key)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to get report: {}", response.status());
    }

    let report: serde_json::Value = response.json().await?;

    // Export if requested
    if let Some(format) = export {
        match format {
            "json" => {
                let json = serde_json::to_string_pretty(&report)?;
                if let Some(path) = output {
                    std::fs::write(path, &json)?;
                    println!("  {} Report exported to: {}", "✓".green(), path.display());
                } else {
                    println!("{}", json);
                }
            }
            "pdf" | "html" | "sarif" => {
                println!(
                    "  {} {} export is available in Professional tier",
                    "⚠".yellow(),
                    format.to_uppercase()
                );
                println!("    Upgrade at: https://allsecurex.com/pricing");
            }
            _ => anyhow::bail!("Unknown export format: {}", format),
        }
    } else {
        // Print summary
        if let Some(data) = report.get("data") {
            println!();
            println!("  {} Scan Report: {}", "◆".cyan(), scan_id.blue());
            println!();

            if let Some(summary) = data.get("summary") {
                println!("  ┌─────────────────────────────────────────────────────────┐");
                println!("  │ Summary                                                 │");
                println!("  ├─────────────────────────────────────────────────────────┤");

                if let Some(by_severity) = summary.get("by_severity") {
                    let critical = by_severity
                        .get("critical")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let high = by_severity
                        .get("high")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let medium = by_severity
                        .get("medium")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let low = by_severity.get("low").and_then(|v| v.as_u64()).unwrap_or(0);

                    println!(
                        "  │  Critical: {:>4}  High: {:>4}  Medium: {:>4}  Low: {:>4}  │",
                        critical, high, medium, low
                    );
                }

                println!("  └─────────────────────────────────────────────────────────┘");
            }

            println!();
            println!(
                "    Full report: {}",
                format!("https://quantumvault.allsecurex.com/scanner/{}", scan_id).blue()
            );
        }
    }

    Ok(())
}

/// Get scan history
pub async fn get_history(limit: usize) -> Result<()> {
    let (client, api_key) = get_client()?;

    let response = client
        .get(format!("{}/scanner/scans", API_BASE_URL))
        .header("X-API-Key", &api_key)
        .query(&[("limit", limit.to_string())])
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to get history: {}", response.status());
    }

    #[derive(Deserialize)]
    struct ListResponse {
        data: Vec<ScanItem>,
    }

    #[derive(Deserialize)]
    struct ScanItem {
        scan_id: String,
        name: Option<String>,
        status: String,
        created_at: String,
        #[serde(default)]
        summary: Option<ScanSummaryData>,
    }

    #[derive(Deserialize, Default)]
    struct ScanSummaryData {
        risk_score: Option<u32>,
        #[serde(default)]
        by_severity: std::collections::HashMap<String, u64>,
    }

    let list: ListResponse = response.json().await?;

    println!();
    println!("  {} Recent Scans", "◆".cyan());
    println!();
    println!(
        "  {:<20} {:<12} {:<8} {:<8} {:<8} {}",
        "Scan ID".dimmed(),
        "Status".dimmed(),
        "Critical".dimmed(),
        "High".dimmed(),
        "Score".dimmed(),
        "Date".dimmed()
    );
    println!(
        "  {}",
        "─────────────────────────────────────────────────────────────────────────".dimmed()
    );

    for scan in list.data {
        let critical = scan
            .summary
            .as_ref()
            .and_then(|s| s.by_severity.get("critical"))
            .unwrap_or(&0);
        let high = scan
            .summary
            .as_ref()
            .and_then(|s| s.by_severity.get("high"))
            .unwrap_or(&0);
        let score = scan
            .summary
            .as_ref()
            .and_then(|s| s.risk_score)
            .map(|s| 100 - s)
            .unwrap_or(0);

        let status_colored = match scan.status.as_str() {
            "completed" => scan.status.green(),
            "running" => scan.status.yellow(),
            "failed" => scan.status.red(),
            _ => scan.status.normal(),
        };

        println!(
            "  {:<20} {:<12} {:>8} {:>8} {:>7}% {}",
            &scan.scan_id[..20.min(scan.scan_id.len())],
            status_colored,
            critical,
            high,
            score,
            &scan.created_at[..10]
        );
    }

    println!();
    Ok(())
}

/// Get quota information
pub async fn get_quota() -> Result<()> {
    let (client, api_key) = get_client()?;

    let response = client
        .get(format!("{}/scanner/quota", API_BASE_URL))
        .header("X-API-Key", &api_key)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to get quota: {}", response.status());
    }

    #[derive(Deserialize)]
    struct QuotaResponse {
        data: QuotaData,
    }

    #[derive(Deserialize)]
    struct QuotaData {
        tier: String,
        used: i32,
        limit: i32,
        remaining: i32,
        month: String,
        reset_date: String,
    }

    let quota: QuotaResponse = response.json().await?;
    let data = quota.data;

    println!();
    println!("  {} Scan Quota", "◆".cyan());
    println!();
    println!("  ┌─────────────────────────────────────────────────────────┐");
    println!("  │ Plan: {:<50} │", data.tier.to_uppercase().yellow());
    println!("  │                                                         │");

    if data.limit < 0 {
        println!(
            "  │ Scans: {} / {} (Unlimited)                       │",
            data.used.to_string().green(),
            "∞".green()
        );
    } else {
        let usage_pct = (data.used as f32 / data.limit as f32 * 100.0) as u32;
        let bar_len = 30;
        let filled = (usage_pct as usize * bar_len / 100).min(bar_len);
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(bar_len - filled));

        let bar_colored = if usage_pct >= 90 {
            bar.red()
        } else if usage_pct >= 70 {
            bar.yellow()
        } else {
            bar.green()
        };

        println!(
            "  │ Scans: {} / {}                                         │",
            data.used, data.limit
        );
        println!("  │ {}  {}%               │", bar_colored, usage_pct);
        println!("  │                                                         │");
        println!(
            "  │ Remaining: {:>4} scans                                   │",
            data.remaining
        );
    }

    println!("  │                                                         │");
    println!(
        "  │ Period: {}                                        │",
        data.month
    );
    println!(
        "  │ Resets: {}                                        │",
        data.reset_date
    );
    println!("  └─────────────────────────────────────────────────────────┘");

    if data.limit > 0 && data.remaining <= 0 {
        println!();
        println!("  {} Monthly limit reached! Upgrade at:", "⚠".yellow());
        println!("    {}", "https://allsecurex.com/pricing".blue());
    }

    println!();
    Ok(())
}

/// Check for CLI updates
pub async fn check_version() -> Result<Option<String>> {
    let client = reqwest::Client::builder().user_agent(USER_AGENT).build()?;

    let response = client
        .get(format!("{}/scanner/version", API_BASE_URL))
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            #[derive(Deserialize)]
            struct VersionResponse {
                latest: String,
            }

            let version: VersionResponse = resp.json().await?;
            let current = env!("CARGO_PKG_VERSION");

            if version.latest != current {
                Ok(Some(version.latest))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

// ============================================================================
// LOCAL REPORT FUNCTIONS
// ============================================================================

/// List all local scan reports
pub fn list_local_scans() -> Result<()> {
    let scans_dir = get_scans_dir()?;

    if !scans_dir.exists() {
        println!();
        println!("  {} No local scans found", "◆".cyan());
        println!();
        println!("    Run a scan first: {}", "quantum-scanner scan .".blue());
        println!();
        return Ok(());
    }

    let mut scans: Vec<_> = fs::read_dir(&scans_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|e| e == "json")
                .unwrap_or(false)
        })
        .collect();

    // Sort by modification time (newest first)
    scans.sort_by(|a, b| {
        let a_time = a.metadata().and_then(|m| m.modified()).ok();
        let b_time = b.metadata().and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    if scans.is_empty() {
        println!();
        println!("  {} No local scans found", "◆".cyan());
        println!();
        return Ok(());
    }

    println!();
    println!("  {} Local Scan Reports", "◆".cyan());
    println!();
    println!(
        "  {:<30} {:<10} {:<10} {:<10} {}",
        "Scan ID".dimmed(),
        "Critical".dimmed(),
        "High".dimmed(),
        "Score".dimmed(),
        "Date".dimmed()
    );
    println!(
        "  {}",
        "─────────────────────────────────────────────────────────────────────────────".dimmed()
    );

    for entry in scans.iter().take(20) {
        let path = entry.path();
        let scan_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        // Try to read and parse the scan file
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(report) = serde_json::from_str::<serde_json::Value>(&content) {
                let summary = report.get("summary");
                let critical = summary
                    .and_then(|s| s.get("by_severity"))
                    .and_then(|b| b.get("critical"))
                    .and_then(|v| v.as_u64())
                    .or_else(|| {
                        summary
                            .and_then(|s| s.get("critical_count"))
                            .and_then(|v| v.as_u64())
                    })
                    .unwrap_or(0);
                let high = summary
                    .and_then(|s| s.get("by_severity"))
                    .and_then(|b| b.get("high"))
                    .and_then(|v| v.as_u64())
                    .or_else(|| {
                        summary
                            .and_then(|s| s.get("high_count"))
                            .and_then(|v| v.as_u64())
                    })
                    .unwrap_or(0);
                let score = report
                    .get("crypto_agility_score")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let timestamp = report
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .map(|s| &s[..10])
                    .unwrap_or("unknown");

                let critical_str = if critical > 0 {
                    critical.to_string().red().to_string()
                } else {
                    critical.to_string()
                };
                let high_str = if high > 0 {
                    high.to_string().yellow().to_string()
                } else {
                    high.to_string()
                };

                println!(
                    "  {:<30} {:>10} {:>10} {:>9}% {}",
                    &scan_id[..30.min(scan_id.len())],
                    critical_str,
                    high_str,
                    score,
                    timestamp
                );
            }
        }
    }

    println!();
    println!(
        "  {} View details: {}",
        "→".dimmed(),
        "quantum-scanner report <scan-id>".blue()
    );
    println!(
        "  {} Open report:  {}",
        "→".dimmed(),
        "quantum-scanner report <scan-id> --open".blue()
    );
    println!();

    Ok(())
}

/// View a local scan report
pub fn view_local_report(
    scan_id: Option<&str>,
    open: bool,
    export: Option<&str>,
    output: Option<&PathBuf>,
) -> Result<()> {
    let scans_dir = get_scans_dir()?;

    // Find the report file
    let report_path = if let Some(id) = scan_id {
        scans_dir.join(format!("{}.json", id))
    } else {
        // Get the latest scan
        let mut scans: Vec<_> = fs::read_dir(&scans_dir)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .map(|e| e == "json")
                    .unwrap_or(false)
            })
            .collect();

        scans.sort_by(|a, b| {
            let a_time = a.metadata().and_then(|m| m.modified()).ok();
            let b_time = b.metadata().and_then(|m| m.modified()).ok();
            b_time.cmp(&a_time)
        });

        scans.first().map(|e| e.path()).ok_or_else(|| {
            anyhow::anyhow!("No local scans found. Run 'quantum-scanner scan .' first.")
        })?
    };

    if !report_path.exists() {
        anyhow::bail!(
            "Scan not found: {}. Run 'quantum-scanner report --list' to see available scans.",
            scan_id.unwrap_or("latest")
        );
    }

    let content = fs::read_to_string(&report_path)?;
    let report: serde_json::Value = serde_json::from_str(&content)?;

    let scan_id = report_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    // Handle --open flag
    if open {
        // Export to HTML and open in browser
        let html_path = export_to_html(&report, scan_id)?;
        println!("  {} Opening report in browser...", "◆".cyan());
        open_in_browser(&html_path)?;
        return Ok(());
    }

    // Handle --export flag
    if let Some(format) = export {
        match format {
            "json" => {
                let json = serde_json::to_string_pretty(&report)?;
                if let Some(path) = output {
                    fs::write(path, &json)?;
                    println!("  {} Report exported to: {}", "✓".green(), path.display());
                } else {
                    println!("{}", json);
                }
            }
            "html" => {
                let html_path = if let Some(path) = output {
                    export_to_html_path(&report, scan_id, path)?
                } else {
                    export_to_html(&report, scan_id)?
                };
                println!(
                    "  {} HTML report exported to: {}",
                    "✓".green(),
                    html_path.display()
                );
            }
            _ => anyhow::bail!("Unknown export format: {}. Supported: json, html", format),
        }
        return Ok(());
    }

    // Display report summary
    println!();
    println!("  {} Local Scan Report: {}", "◆".cyan(), scan_id.blue());
    println!();

    // Summary section
    let summary = report.get("summary");
    let critical = summary
        .and_then(|s| s.get("by_severity"))
        .and_then(|b| b.get("critical"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            summary
                .and_then(|s| s.get("critical_count"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);
    let high = summary
        .and_then(|s| s.get("by_severity"))
        .and_then(|b| b.get("high"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            summary
                .and_then(|s| s.get("high_count"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);
    let medium = summary
        .and_then(|s| s.get("by_severity"))
        .and_then(|b| b.get("medium"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            summary
                .and_then(|s| s.get("medium_count"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);
    let low = summary
        .and_then(|s| s.get("by_severity"))
        .and_then(|b| b.get("low"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            summary
                .and_then(|s| s.get("low_count"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);

    let score = report
        .get("crypto_agility_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let files_scanned = report
        .get("files_scanned")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total_findings = report
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    println!("  ┌───────────────────────────────────────────────────────────┐");
    println!("  │                    FINDINGS SUMMARY                       │");
    println!("  ├───────────────────────────────────────────────────────────┤");
    println!(
        "  │  🔴 Critical:   {:>5}                                     │",
        critical
    );
    println!(
        "  │  🟠 High:       {:>5}                                     │",
        high
    );
    println!(
        "  │  🟡 Medium:     {:>5}                                     │",
        medium
    );
    println!(
        "  │  🔵 Low:        {:>5}                                     │",
        low
    );
    println!("  │                                                           │");
    println!(
        "  │  Files Scanned: {:>5}                                     │",
        files_scanned
    );
    println!(
        "  │  Total Findings: {:>4}                                     │",
        total_findings
    );
    println!(
        "  │  Agility Score: {:>4}/100                                  │",
        score
    );
    println!("  └───────────────────────────────────────────────────────────┘");

    // Show top 10 findings
    if let Some(findings) = report.get("findings").and_then(|f| f.as_array()) {
        println!();
        println!("  {} Top Findings:", "◆".cyan());
        println!();

        for (i, finding) in findings.iter().take(10).enumerate() {
            let severity = finding
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let algorithm = finding
                .get("algorithm")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let file_path = finding
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let line = finding.get("line").and_then(|v| v.as_u64()).unwrap_or(0);

            let icon = match severity {
                "critical" => "🔴",
                "high" => "🟠",
                "medium" => "🟡",
                "low" => "🔵",
                _ => "⚪",
            };

            println!(
                "    {}. {} {} at {}:{}",
                i + 1,
                icon,
                algorithm,
                file_path,
                line
            );
        }

        if findings.len() > 10 {
            println!();
            println!("    ... and {} more findings", findings.len() - 10);
        }
    }

    println!();
    println!(
        "  {} Open in browser: {}",
        "→".dimmed(),
        format!("quantum-scanner report {} --open", scan_id).blue()
    );
    println!(
        "  {} Export to HTML:  {}",
        "→".dimmed(),
        format!("quantum-scanner report {} --export html", scan_id).blue()
    );
    println!(
        "  {} Raw JSON file:   {}",
        "→".dimmed(),
        report_path.display().to_string().dimmed()
    );
    println!();

    Ok(())
}

/// Export report to HTML format
fn export_to_html(report: &serde_json::Value, scan_id: &str) -> Result<PathBuf> {
    let scans_dir = get_scans_dir()?;
    let html_path = scans_dir.join(format!("{}.html", scan_id));
    export_to_html_path(report, scan_id, &html_path)?;
    Ok(html_path)
}

fn export_to_html_path(
    report: &serde_json::Value,
    scan_id: &str,
    path: &PathBuf,
) -> Result<PathBuf> {
    let summary = report.get("summary");
    let critical = summary
        .and_then(|s| s.get("by_severity"))
        .and_then(|b| b.get("critical"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            summary
                .and_then(|s| s.get("critical_count"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);
    let high = summary
        .and_then(|s| s.get("by_severity"))
        .and_then(|b| b.get("high"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            summary
                .and_then(|s| s.get("high_count"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);
    let medium = summary
        .and_then(|s| s.get("by_severity"))
        .and_then(|b| b.get("medium"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            summary
                .and_then(|s| s.get("medium_count"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);
    let low = summary
        .and_then(|s| s.get("by_severity"))
        .and_then(|b| b.get("low"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            summary
                .and_then(|s| s.get("low_count"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0);

    let score = report
        .get("crypto_agility_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let files_scanned = report
        .get("files_scanned")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let timestamp = report
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let findings = report.get("findings").and_then(|f| f.as_array());

    let mut findings_html = String::new();
    if let Some(findings) = findings {
        for finding in findings {
            let severity = finding
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let algorithm = finding
                .get("algorithm")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let file_path = finding
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let line = finding.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
            let context = finding
                .get("context")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let recommendation = finding
                .get("recommended_replacement")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let severity_class = match severity {
                "critical" => "critical",
                "high" => "high",
                "medium" => "medium",
                "low" => "low",
                _ => "info",
            };

            findings_html.push_str(&format!(
                r#"
                <div class="finding {severity_class}">
                    <div class="finding-header">
                        <span class="severity-badge {severity_class}">{severity}</span>
                        <span class="algorithm">{algorithm}</span>
                    </div>
                    <div class="location">{file_path}:{line}</div>
                    {context_html}
                    {recommendation_html}
                </div>
            "#,
                severity_class = severity_class,
                severity = severity.to_uppercase(),
                algorithm = algorithm,
                file_path = file_path,
                line = line,
                context_html = if !context.is_empty() {
                    format!("<pre class=\"context\">{}</pre>", html_escape(context))
                } else {
                    String::new()
                },
                recommendation_html = if !recommendation.is_empty() {
                    format!(
                        "<div class=\"recommendation\">→ {}</div>",
                        html_escape(recommendation)
                    )
                } else {
                    String::new()
                },
            ));
        }
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum Scanner Report - {scan_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{ text-align: center; margin-bottom: 3rem; }}
        h1 {{ color: #38bdf8; font-size: 2rem; margin-bottom: 0.5rem; }}
        .timestamp {{ color: #64748b; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: #1e293b; border-radius: 0.5rem; padding: 1.5rem; text-align: center; }}
        .stat-value {{ font-size: 2.5rem; font-weight: bold; }}
        .stat-label {{ color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
        .stat-card.critical .stat-value {{ color: #ef4444; }}
        .stat-card.high .stat-value {{ color: #f97316; }}
        .stat-card.medium .stat-value {{ color: #eab308; }}
        .stat-card.low .stat-value {{ color: #3b82f6; }}
        .stat-card.score .stat-value {{ color: #22c55e; }}
        .findings {{ margin-top: 2rem; }}
        h2 {{ color: #38bdf8; margin-bottom: 1rem; }}
        .finding {{ background: #1e293b; border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; border-left: 4px solid #64748b; }}
        .finding.critical {{ border-left-color: #ef4444; }}
        .finding.high {{ border-left-color: #f97316; }}
        .finding.medium {{ border-left-color: #eab308; }}
        .finding.low {{ border-left-color: #3b82f6; }}
        .finding-header {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }}
        .severity-badge {{ padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: bold; }}
        .severity-badge.critical {{ background: #ef4444; color: white; }}
        .severity-badge.high {{ background: #f97316; color: white; }}
        .severity-badge.medium {{ background: #eab308; color: black; }}
        .severity-badge.low {{ background: #3b82f6; color: white; }}
        .algorithm {{ font-weight: bold; }}
        .location {{ color: #94a3b8; font-family: monospace; font-size: 0.875rem; }}
        .context {{ background: #0f172a; padding: 0.75rem; border-radius: 0.25rem; margin-top: 0.5rem; overflow-x: auto; font-size: 0.875rem; }}
        .recommendation {{ color: #22c55e; margin-top: 0.5rem; font-size: 0.875rem; }}
        .footer {{ text-align: center; margin-top: 3rem; padding-top: 2rem; border-top: 1px solid #334155; color: #64748b; }}
        .footer a {{ color: #38bdf8; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>◆ AllSecureX Quantum Scanner Report</h1>
            <p class="timestamp">Scan ID: {scan_id} | Generated: {timestamp}</p>
        </header>

        <div class="summary">
            <div class="stat-card score">
                <div class="stat-value">{score}</div>
                <div class="stat-label">Crypto Agility Score</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-value">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{low}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{files_scanned}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
        </div>

        <div class="findings">
            <h2>Findings ({total_findings})</h2>
            {findings_html}
        </div>

        <footer class="footer">
            <p>Generated by <a href="https://allsecurex.com">AllSecureX Quantum Scanner</a></p>
            <p>© 2025 AllSecureX. All rights reserved.</p>
        </footer>
    </div>
</body>
</html>"#,
        scan_id = scan_id,
        timestamp = timestamp,
        score = score,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        files_scanned = files_scanned,
        total_findings = findings.map(|f| f.len()).unwrap_or(0),
        findings_html = findings_html,
    );

    fs::write(path, html)?;
    Ok(path.clone())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Open a file in the default browser/application
fn open_in_browser(path: &PathBuf) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(path).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(path).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", "", path.to_str().unwrap_or("")])
            .spawn()?;
    }
    Ok(())
}

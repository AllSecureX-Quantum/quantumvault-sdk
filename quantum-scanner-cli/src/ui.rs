//! Terminal UI module for AllSecureX Quantum Scanner
//!
//! Provides rich terminal output and interactive elements using ratatui.

use crate::patterns::{Finding, QuantumRisk, Severity};
use crate::scanner::ScanSummary;
use colored::Colorize;

/// Format severity with color
pub fn format_severity(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH".bright_red().to_string(),
        Severity::Medium => "MEDIUM".yellow().to_string(),
        Severity::Low => "LOW".blue().to_string(),
        Severity::Info => "INFO".dimmed().to_string(),
    }
}

/// Format quantum risk level with color
pub fn format_quantum_risk(risk: &QuantumRisk) -> String {
    match risk {
        QuantumRisk::BrokenNow => "BROKEN NOW".red().bold().to_string(),
        QuantumRisk::BrokenBy2030 => "BROKEN BY 2030".bright_red().to_string(),
        QuantumRisk::Uncertain => "UNCERTAIN".yellow().to_string(),
        QuantumRisk::QuantumSafe => "QUANTUM SAFE".green().to_string(),
    }
}

/// Get severity icon
pub fn get_severity_icon(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "⚪",
    }
}

/// Get quantum risk icon
pub fn get_quantum_risk_icon(risk: &QuantumRisk) -> &'static str {
    match risk {
        QuantumRisk::BrokenNow => "💀",
        QuantumRisk::BrokenBy2030 => "🚨",
        QuantumRisk::Uncertain => "⚡",
        QuantumRisk::QuantumSafe => "✓",
    }
}

/// Print a boxed header
pub fn print_box_header(title: &str, width: usize) {
    let padding = width.saturating_sub(title.len() + 4);
    let left_pad = padding / 2;
    let right_pad = padding - left_pad;

    println!("  ┌{}┐", "─".repeat(width));
    println!(
        "  │{}{}{}│",
        " ".repeat(left_pad + 2),
        title,
        " ".repeat(right_pad + 2)
    );
    println!("  └{}┘", "─".repeat(width));
}

/// Print a divider line
pub fn print_divider(width: usize) {
    println!("  {}", "─".repeat(width).dimmed());
}

/// Print the crypto agility score gauge
pub fn print_score_gauge(score: u32) {
    let width = 40;
    let filled = ((score as f32 / 100.0) * width as f32) as usize;
    let empty = width - filled;

    let (color, status) = if score >= 80 {
        ("green", "QUANTUM READY")
    } else if score >= 50 {
        ("yellow", "NEEDS ATTENTION")
    } else {
        ("red", "ACTION REQUIRED")
    };

    println!();
    println!("  ┌────────────────────────────────────────────────┐");
    println!("  │           CRYPTO AGILITY SCORE                 │");
    println!("  │                                                │");

    let score_str = format!("{}/100", score);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));

    let colored_bar = match color {
        "green" => bar.green(),
        "yellow" => bar.yellow(),
        _ => bar.red(),
    };

    let colored_score = match color {
        "green" => score_str.green(),
        "yellow" => score_str.yellow(),
        _ => score_str.red(),
    };

    println!(
        "  │                    {}                      │",
        colored_score
    );
    println!("  │    {}    │", colored_bar);
    println!("  │                                                │");

    let status_display = match color {
        "green" => format!("✓ {}", status).green(),
        "yellow" => format!("⚠ {}", status).yellow(),
        _ => format!("✗ {}", status).red(),
    };
    println!("  │               {}                │", status_display);
    println!("  │                                                │");
    println!("  └────────────────────────────────────────────────┘");
}

/// Print findings table
pub fn print_findings_table(findings: &[Finding], max_items: usize) {
    if findings.is_empty() {
        println!();
        println!(
            "  {} No quantum-vulnerable cryptography detected!",
            "✓".green()
        );
        println!();
        return;
    }

    println!();
    println!("  {} Findings ({} total):", "◆".cyan(), findings.len());
    println!();

    // Sort by severity
    let mut sorted_findings = findings.to_vec();
    sorted_findings.sort_by_key(|f| match f.severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    });

    // Print header
    println!(
        "  {:<6} {:<12} {:<20} {:<30} {}",
        "".dimmed(),
        "Severity".dimmed(),
        "Algorithm".dimmed(),
        "Quantum Risk".dimmed(),
        "Location".dimmed()
    );
    print_divider(85);

    // Print findings
    for finding in sorted_findings.iter().take(max_items) {
        let icon = get_severity_icon(&finding.severity);
        let severity = format_severity(&finding.severity);
        let algorithm = finding.algorithm.yellow();
        let risk = format!("{}", finding.quantum_risk.as_str().to_string());
        let location = format!("{}:{}", finding.file_path, finding.line);

        println!(
            "  {:<6} {:<12} {:<20} {:<30} {}",
            icon,
            severity,
            algorithm,
            risk,
            location.blue()
        );
    }

    if findings.len() > max_items {
        println!();
        println!(
            "    ... and {} more findings",
            (findings.len() - max_items).to_string().dimmed()
        );
    }

    println!();
}

/// Print summary statistics
pub fn print_summary_stats(summary: &ScanSummary, files_scanned: usize, duration_secs: f32) {
    println!();
    println!("  ┌────────────────────────────────────────────────┐");
    println!("  │ SCAN SUMMARY                                   │");
    println!("  ├────────────────────────────────────────────────┤");
    println!(
        "  │  🔴 Critical    {:>4}                            │",
        summary.critical_count
    );
    println!(
        "  │  🟠 High        {:>4}                            │",
        summary.high_count
    );
    println!(
        "  │  🟡 Medium      {:>4}                            │",
        summary.medium_count
    );
    println!(
        "  │  🔵 Low         {:>4}                            │",
        summary.low_count
    );
    println!(
        "  │  ⚪ Info        {:>4}                            │",
        summary.info_count
    );
    println!("  │                                                │");
    println!(
        "  │  Files Scanned: {:>6}                          │",
        files_scanned
    );
    println!(
        "  │  Scan Duration: {:>5.1}s                          │",
        duration_secs
    );
    println!(
        "  │  Est. Migration: {:>4.0} hours                     │",
        summary.estimated_hours
    );
    println!("  └────────────────────────────────────────────────┘");
}

/// Print migration recommendations
pub fn print_migration_recommendations(findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }

    println!();
    println!("  {} Migration Recommendations:", "◆".cyan());
    println!();

    // Group by recommended replacement
    let mut recommendations: std::collections::HashMap<String, Vec<&Finding>> =
        std::collections::HashMap::new();

    for finding in findings {
        recommendations
            .entry(finding.recommended_replacement.clone())
            .or_default()
            .push(finding);
    }

    for (replacement, related_findings) in recommendations.iter().take(5) {
        let count = related_findings.len();
        let severity = related_findings
            .iter()
            .map(|f| match f.severity {
                Severity::Critical => 0,
                Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
                Severity::Info => 4,
            })
            .min()
            .unwrap_or(4);

        let icon = match severity {
            0 => "🔴",
            1 => "🟠",
            2 => "🟡",
            3 => "🔵",
            _ => "⚪",
        };

        println!(
            "    {} Migrate to {} ({} occurrences)",
            icon,
            replacement.green(),
            count
        );

        // Show first affected file
        if let Some(first) = related_findings.first() {
            println!(
                "       → Example: {}:{}",
                first.file_path.blue(),
                first.line
            );
        }
        println!();
    }
}

/// Print tier upgrade prompt
pub fn print_upgrade_prompt(feature: &str) {
    println!();
    println!("  {} {} requires Professional tier", "⚠".yellow(), feature);
    println!();
    println!(
        "    Upgrade at: {}",
        "https://allsecurex.com/pricing".blue()
    );
    println!();
    println!("    Professional features include:");
    println!("      • Unlimited scans per month");
    println!("      • PDF/HTML/SARIF export");
    println!("      • Executive summary reports");
    println!("      • CI/CD integrations");
    println!("      • Priority support");
    println!();
}

/// Print quota warning
pub fn print_quota_warning(remaining: i32, limit: i32) {
    if limit < 0 {
        return; // Unlimited
    }

    let percentage = ((limit - remaining) as f32 / limit as f32 * 100.0) as u32;

    if percentage >= 90 {
        println!();
        println!(
            "  {} Scan quota almost exhausted: {} of {} used",
            "⚠".yellow(),
            (limit - remaining),
            limit
        );
        println!(
            "    Upgrade for more scans: {}",
            "https://allsecurex.com/pricing".blue()
        );
        println!();
    } else if percentage >= 70 {
        println!(
            "  {} Scan quota: {} of {} used",
            "ℹ".dimmed(),
            (limit - remaining),
            limit
        );
    }
}

/// Print sync success message
pub fn print_sync_success(scan_id: &str) {
    println!();
    println!("  {} Results synced to AllSecureX platform", "✓".green());
    println!(
        "    View report: {}",
        format!("https://quantumvault.allsecurex.com/scanner/{}", scan_id).blue()
    );
}

/// Print error message
pub fn print_error(message: &str) {
    eprintln!("  {} {}", "✗".red(), message.red());
}

/// Print warning message
pub fn print_warning(message: &str) {
    println!("  {} {}", "⚠".yellow(), message.yellow());
}

/// Print success message
pub fn print_success(message: &str) {
    println!("  {} {}", "✓".green(), message.green());
}

/// Print info message
pub fn print_info(message: &str) {
    println!("  {} {}", "ℹ".cyan(), message);
}

/// Print the spinner animation (for async operations)
pub fn spinner_frames() -> &'static [&'static str] {
    &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_severity() {
        // Just ensure no panics
        format_severity(&Severity::Critical);
        format_severity(&Severity::High);
        format_severity(&Severity::Medium);
        format_severity(&Severity::Low);
        format_severity(&Severity::Info);
    }

    #[test]
    fn test_format_quantum_risk() {
        format_quantum_risk(&QuantumRisk::BrokenNow);
        format_quantum_risk(&QuantumRisk::BrokenBy2030);
        format_quantum_risk(&QuantumRisk::Uncertain);
        format_quantum_risk(&QuantumRisk::QuantumSafe);
    }
}

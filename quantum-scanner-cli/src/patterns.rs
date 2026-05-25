//! Cryptographic pattern detection module
//!
//! Contains patterns for detecting quantum-vulnerable cryptography.
//! This code is compiled into the binary - source is not visible to users.
//!
//! Copyright (c) 2025 AllSecureX. All rights reserved. PROPRIETARY.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn weight(&self) -> u32 {
        match self {
            Severity::Critical => 25,
            Severity::High => 15,
            Severity::Medium => 8,
            Severity::Low => 3,
            Severity::Info => 1,
        }
    }
}

/// Quantum risk levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumRisk {
    BrokenNow,
    #[serde(rename = "broken_by_2030", alias = "broken_by2030")]
    BrokenBy2030,
    Uncertain,
    QuantumSafe,
}

impl QuantumRisk {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuantumRisk::BrokenNow => "broken_now",
            QuantumRisk::BrokenBy2030 => "broken_by_2030",
            QuantumRisk::Uncertain => "uncertain",
            QuantumRisk::QuantumSafe => "quantum_safe",
        }
    }

    pub fn weight(&self) -> u32 {
        match self {
            QuantumRisk::BrokenNow => 20,
            QuantumRisk::BrokenBy2030 => 10,
            QuantumRisk::Uncertain => 3,
            QuantumRisk::QuantumSafe => 0,
        }
    }
}

/// Crypto category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    AsymmetricEncryption,
    SymmetricEncryption,
    DigitalSignature,
    KeyExchange,
    HashFunction,
    RandomNumberGenerator,
    Certificate,
    TlsCipherSuite,
}

/// A detected crypto finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub algorithm: String,
    pub category: Category,
    pub severity: Severity,
    pub quantum_risk: QuantumRisk,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub context: String,
    pub recommended_replacement: String,
    pub migration_effort: String,
    pub pattern_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
}

/// A compiled crypto detection pattern
pub struct CryptoPattern {
    pub id: &'static str,
    pub name: &'static str,
    pub algorithm: &'static str,
    pub category: Category,
    pub severity: Severity,
    pub quantum_risk: QuantumRisk,
    pub regex: Regex,
    pub recommended_replacement: &'static str,
    pub migration_effort: &'static str,
    pub languages: &'static [&'static str],
}

// ============================================================================
// PROPRIETARY DETECTION PATTERNS
// These patterns are compiled into the binary and not visible to end users.
// ============================================================================

/// Get all compiled crypto patterns
pub fn get_patterns() -> &'static [CryptoPattern] {
    static PATTERNS: Lazy<Vec<CryptoPattern>> = Lazy::new(|| {
        vec![
            // RSA Detection
            CryptoPattern {
                id: "rsa-key-generation",
                name: "RSA Key Generation",
                algorithm: "RSA",
                category: Category::AsymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r#"(?i)(RSA\.generate|generateKeyPair\s*\(\s*['"]?rsa|crypto\.generateKeyPairSync\s*\(\s*['"]rsa|RSA\.generate_private_key|rsa_generate_key|RSAKeyPairGenerator|KeyPairGenerator\.getInstance\s*\(\s*['"]RSA)"#).unwrap(),
                recommended_replacement: "ML-KEM-768 (FIPS 203) or ML-DSA-65 (FIPS 204)",
                migration_effort: "complex",
                languages: &["python", "javascript", "java", "go", "rust", "csharp"],
            },

            // ECDSA/ECDH Detection
            CryptoPattern {
                id: "ecdsa-signature",
                name: "ECDSA/ECDH Elliptic Curve",
                algorithm: "ECDSA/ECDH",
                category: Category::DigitalSignature,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"(?i)(ECDSA|ECDH|secp256k1|prime256v1|secp384r1|P-256|P-384|P-521|ec\.SECP|EllipticCurve|EC2PrivateKey|ECPublicKey|NIST\s*P-)").unwrap(),
                recommended_replacement: "ML-DSA-65 (FIPS 204) or SLH-DSA-192f (FIPS 205)",
                migration_effort: "complex",
                languages: &["python", "javascript", "java", "go", "rust", "csharp"],
            },

            // Diffie-Hellman Detection
            CryptoPattern {
                id: "diffie-hellman",
                name: "Diffie-Hellman Key Exchange",
                algorithm: "Diffie-Hellman",
                category: Category::KeyExchange,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r#"(?i)(DiffieHellman|createDiffieHellman|DH\.generate|dh\.generate_parameters|DHParameterSpec|KeyAgreement\.getInstance\s*\(\s*['"]DH)"#).unwrap(),
                recommended_replacement: "ML-KEM-768 (FIPS 203)",
                migration_effort: "complex",
                languages: &["python", "javascript", "java", "go", "rust", "csharp"],
            },

            // DSA Detection
            CryptoPattern {
                id: "dsa-signature",
                name: "DSA Digital Signature",
                algorithm: "DSA",
                category: Category::DigitalSignature,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r#"(?i)(DSA\.generate|KeyPairGenerator\.getInstance\s*\(\s*['"]DSA|dsa_generate_key|DSAParameterSpec)"#).unwrap(),
                recommended_replacement: "ML-DSA-65 (FIPS 204)",
                migration_effort: "complex",
                languages: &["python", "javascript", "java", "go"],
            },

            // MD5 Detection (Broken Now)
            CryptoPattern {
                id: "md5-hash",
                name: "MD5 Hash Function",
                algorithm: "MD5",
                category: Category::HashFunction,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(createHash\s*\(\s*['"]md5|hashlib\.md5|MD5\.Create|DigestUtils\.md5|md5_hash|Digest::MD5|MessageDigest\.getInstance\s*\(\s*['"]MD5)"#).unwrap(),
                recommended_replacement: "SHA-256 or SHA-3-256",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "ruby", "php"],
            },

            // SHA-1 Detection (Broken Now)
            CryptoPattern {
                id: "sha1-hash",
                name: "SHA-1 Hash Function",
                algorithm: "SHA-1",
                category: Category::HashFunction,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(createHash\s*\(\s*['"]sha1|hashlib\.sha1|SHA1\.Create|DigestUtils\.sha1|sha1_hash|Digest::SHA1|MessageDigest\.getInstance\s*\(\s*['"]SHA-?1)"#).unwrap(),
                recommended_replacement: "SHA-256 or SHA-3-256",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "ruby", "php"],
            },

            // AES-128 Detection (Uncertain)
            CryptoPattern {
                id: "aes-128",
                name: "AES-128 Encryption",
                algorithm: "AES-128",
                category: Category::SymmetricEncryption,
                severity: Severity::Medium,
                quantum_risk: QuantumRisk::Uncertain,
                regex: Regex::new(r"(?i)(aes-128|aes128|AES/128|key_size\s*=\s*128|keySize\s*=\s*128|\.AES\(.*?128)").unwrap(),
                recommended_replacement: "AES-256-GCM",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp"],
            },

            // 3DES Detection (Deprecated)
            CryptoPattern {
                id: "triple-des",
                name: "Triple DES (3DES)",
                algorithm: "3DES",
                category: Category::SymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"(?i)(3des|triple-?des|des-?ede|DESede|TripleDES)").unwrap(),
                recommended_replacement: "AES-256-GCM",
                migration_effort: "moderate",
                languages: &["python", "javascript", "java", "go", "csharp"],
            },

            // Blowfish Detection (Weak)
            CryptoPattern {
                id: "blowfish",
                name: "Blowfish Encryption",
                algorithm: "Blowfish",
                category: Category::SymmetricEncryption,
                severity: Severity::Medium,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"(?i)(blowfish|bf-cbc|Blowfish\.new)").unwrap(),
                recommended_replacement: "AES-256-GCM or ChaCha20-Poly1305",
                migration_effort: "moderate",
                languages: &["python", "javascript", "java", "php"],
            },

            // RC4 Detection (Broken)
            CryptoPattern {
                id: "rc4-stream",
                name: "RC4 Stream Cipher",
                algorithm: "RC4",
                category: Category::SymmetricEncryption,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"(?i)(rc4|arcfour|ARC4\.new)").unwrap(),
                recommended_replacement: "ChaCha20-Poly1305 or AES-256-GCM",
                migration_effort: "moderate",
                languages: &["python", "javascript", "java", "php"],
            },

            // Legacy TLS Detection
            CryptoPattern {
                id: "tls-legacy",
                name: "Legacy TLS (1.0/1.1)",
                algorithm: "TLS 1.0/1.1",
                category: Category::TlsCipherSuite,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"(?i)(TLSv1[._]?[01]|ssl\.PROTOCOL_TLSv1|TLS_1_0|TLS_1_1|SSLv3|SSLv2|ssl_protocols\s+[^;]*TLSv1[^.2-3])").unwrap(),
                recommended_replacement: "TLS 1.3 with post-quantum cipher suites",
                migration_effort: "moderate",
                languages: &["python", "javascript", "java", "go", "nginx", "apache"],
            },

            // Weak Random Detection
            CryptoPattern {
                id: "weak-random",
                name: "Weak Random Number Generator",
                algorithm: "Insecure PRNG",
                category: Category::RandomNumberGenerator,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"(?i)(Math\.random|random\.random\(\)|rand\(\)|srand\(|java\.util\.Random[^S]|System\.Random)").unwrap(),
                recommended_replacement: "crypto.getRandomValues() or secrets module",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "c", "cpp", "csharp"],
            },

            // Hardcoded Key Detection
            CryptoPattern {
                id: "hardcoded-key",
                name: "Hardcoded Cryptographic Key",
                algorithm: "Hardcoded Secret",
                category: Category::SymmetricEncryption,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(secret[_-]?key|api[_-]?key|private[_-]?key|encryption[_-]?key)\s*[:=]\s*["'][a-zA-Z0-9+/=]{16,}["']"#).unwrap(),
                recommended_replacement: "Use secure key management (AWS KMS, HashiCorp Vault, QuantumVault)",
                migration_effort: "moderate",
                languages: &["python", "javascript", "java", "go", "rust", "csharp"],
            },

            // X.509 RSA Certificate
            CryptoPattern {
                id: "rsa-certificate",
                name: "RSA Certificate",
                algorithm: "RSA Certificate",
                category: Category::Certificate,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"(?i)(BEGIN\s+RSA\s+PRIVATE|rsaEncryption|sha256WithRSAEncryption|sha384WithRSAEncryption)").unwrap(),
                recommended_replacement: "Post-quantum hybrid certificates (ML-DSA + RSA)",
                migration_effort: "complex",
                languages: &["pem", "crt", "cert"],
            },

            // ElGamal Detection
            CryptoPattern {
                id: "elgamal",
                name: "ElGamal Encryption",
                algorithm: "ElGamal",
                category: Category::AsymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"(?i)(elgamal|ElGamal)").unwrap(),
                recommended_replacement: "ML-KEM-768 (FIPS 203)",
                migration_effort: "complex",
                languages: &["python", "java"],
            },
        ]
    });

    &PATTERNS
}

/// Scan content for crypto patterns
pub fn scan_content(content: &str, file_path: &str, language: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let patterns = get_patterns();

    // Detect crypto library used in this file
    let library = detect_crypto_library(content, language);

    for pattern in patterns {
        // Check if pattern applies to this language
        if !pattern.languages.is_empty() && !pattern.languages.iter().any(|l| language.contains(l))
        {
            continue;
        }

        // Find all matches
        for mat in pattern.regex.find_iter(content) {
            // Calculate line and column
            let (line, column) = get_line_column(content, mat.start());

            // Get context (surrounding lines)
            let context = get_context(content, mat.start());

            // Extract key size from matched content if possible
            let matched_text = mat.as_str();
            let key_size = extract_key_size(matched_text, &context);

            findings.push(Finding {
                algorithm: pattern.algorithm.to_string(),
                category: pattern.category,
                severity: pattern.severity,
                quantum_risk: pattern.quantum_risk,
                file_path: file_path.to_string(),
                line,
                column,
                context,
                recommended_replacement: pattern.recommended_replacement.to_string(),
                migration_effort: pattern.migration_effort.to_string(),
                pattern_id: pattern.id.to_string(),
                library_name: library.clone(),
                library_version: None,
                key_size,
            });
        }
    }

    // Deduplicate by location
    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    findings
        .dedup_by(|a, b| a.file_path == b.file_path && a.line == b.line && a.column == b.column);

    findings
}

/// Get line and column from byte offset
fn get_line_column(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;

    for (i, ch) in content.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }

    (line, column)
}

/// Get context around match
fn get_context(content: &str, start: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let (line_num, _) = get_line_column(content, start);

    let start_line = line_num.saturating_sub(2);
    let end_line = (line_num + 1).min(lines.len());

    lines[start_line..end_line].join("\n")
}

/// Calculate risk score from findings
pub fn calculate_risk_score(findings: &[Finding]) -> u32 {
    if findings.is_empty() {
        return 0;
    }

    let total_weight: u32 = findings
        .iter()
        .map(|f| f.severity.weight() + f.quantum_risk.weight())
        .sum();

    // Normalize to 0-100 scale
    (total_weight.min(500) * 100 / 500).min(100)
}

/// Get severity breakdown
pub fn get_severity_breakdown(findings: &[Finding]) -> SeverityBreakdown {
    let mut breakdown = SeverityBreakdown::default();

    for finding in findings {
        match finding.severity {
            Severity::Critical => breakdown.critical += 1,
            Severity::High => breakdown.high += 1,
            Severity::Medium => breakdown.medium += 1,
            Severity::Low => breakdown.low += 1,
            Severity::Info => breakdown.info += 1,
        }
    }

    breakdown
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

/// Detect language from file extension
pub fn detect_language(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext.to_lowercase().as_str() {
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "ts" | "tsx" => "javascript",
        "py" | "pyw" => "python",
        "java" => "java",
        "go" => "go",
        "rs" => "rust",
        "cs" => "csharp",
        "rb" => "ruby",
        "php" => "php",
        "c" | "h" => "c",
        "cpp" | "cc" | "cxx" | "hpp" => "cpp",
        "pem" | "crt" | "cer" | "key" => "cert",
        "conf" | "cfg" => "config",
        "yaml" | "yml" => "yaml",
        "json" => "json",
        "xml" => "xml",
        "sh" | "bash" => "shell",
        "dockerfile" => "docker",
        _ => "unknown",
    }
}

/// Detect the crypto library used in a file based on import/require patterns
fn detect_crypto_library(content: &str, _language: &str) -> Option<String> {
    static LIB_PATTERNS: Lazy<Vec<(&str, Regex)>> = Lazy::new(|| {
        vec![
            // Python
            ("PyCryptodome", Regex::new(r"(?i)from\s+Crypto(dome)?\.|import\s+Crypto(dome)?\.").unwrap()),
            ("cryptography (pyca)", Regex::new(r"from\s+cryptography\.|import\s+cryptography").unwrap()),
            ("hashlib (stdlib)", Regex::new(r"import\s+hashlib|from\s+hashlib").unwrap()),
            ("PyNaCl", Regex::new(r"from\s+nacl\.|import\s+nacl").unwrap()),
            // JavaScript / TypeScript
            ("Node.js crypto (stdlib)", Regex::new(r#"require\s*\(\s*['"]crypto['"]\)|from\s+['"]crypto['"]\s|from\s+['"]node:crypto['"]\s"#).unwrap()),
            ("Web Crypto API", Regex::new(r"crypto\.subtle\.|SubtleCrypto|window\.crypto").unwrap()),
            ("tweetnacl", Regex::new(r#"require\s*\(\s*['"]tweetnacl['"]\)|from\s+['"]tweetnacl['"]\s"#).unwrap()),
            ("jose (JWT)", Regex::new(r#"require\s*\(\s*['"]jose['"]\)|from\s+['"]jose['"]\s"#).unwrap()),
            ("jsonwebtoken", Regex::new(r#"require\s*\(\s*['"]jsonwebtoken['"]\)|from\s+['"]jsonwebtoken['"]\s"#).unwrap()),
            ("bcrypt", Regex::new(r#"require\s*\(\s*['"]bcrypt['"]\)|from\s+['"]bcrypt['"]\s"#).unwrap()),
            // Java / Kotlin
            ("JCA/JCE (stdlib)", Regex::new(r"javax\.crypto\.|java\.security\.|KeyPairGenerator|Cipher\.getInstance|MessageDigest\.getInstance").unwrap()),
            ("Bouncy Castle", Regex::new(r"org\.bouncycastle\.|BouncyCastle|BCrypt").unwrap()),
            // Go
            ("crypto (stdlib)", Regex::new(r#""crypto/|crypto\.SHA|crypto\.MD5"#).unwrap()),
            ("golang.org/x/crypto", Regex::new(r"golang\.org/x/crypto").unwrap()),
            // Rust
            ("ring", Regex::new(r"use\s+ring::|ring::").unwrap()),
            ("RustCrypto", Regex::new(r"use\s+(sha2|aes|rsa|hmac|pbkdf2)::|sha2::|aes::").unwrap()),
            ("openssl (rust)", Regex::new(r"use\s+openssl::|openssl::").unwrap()),
            // C#
            ("System.Security.Cryptography", Regex::new(r"System\.Security\.Cryptography|using\s+System\.Security\.Cryptography").unwrap()),
            ("Bouncy Castle (.NET)", Regex::new(r"Org\.BouncyCastle|BouncyCastle\.Crypto").unwrap()),
            // C/C++
            ("OpenSSL", Regex::new(r#"#include\s*[<"]openssl/|EVP_|SSL_CTX_|BIO_|RSA_generate_key"#).unwrap()),
            ("libsodium", Regex::new(r#"#include\s*[<"]sodium\.h|crypto_secretbox|crypto_box_keypair"#).unwrap()),
            ("wolfSSL", Regex::new(r#"#include\s*[<"]wolfssl/|wolfSSL_|wc_"#).unwrap()),
            ("mbedTLS", Regex::new(r#"#include\s*[<"]mbedtls/|mbedtls_"#).unwrap()),
            // PHP
            ("openssl (PHP)", Regex::new(r"openssl_encrypt|openssl_decrypt|openssl_sign|openssl_pkey_new").unwrap()),
            // Ruby
            ("OpenSSL (Ruby)", Regex::new(r#"require\s+['"]openssl['"]|OpenSSL::"#).unwrap()),
            // Config / Server
            ("Nginx", Regex::new(r"ssl_protocols|ssl_ciphers|ssl_certificate").unwrap()),
            ("Apache", Regex::new(r"SSLProtocol|SSLCipherSuite|SSLCertificateFile").unwrap()),
        ]
    });

    for (name, regex) in LIB_PATTERNS.iter() {
        if regex.is_match(content) {
            return Some(name.to_string());
        }
    }

    None
}

/// Extract key size from matched text or surrounding context
fn extract_key_size(matched_text: &str, context: &str) -> Option<u32> {
    static KEY_SIZE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)(?:modulus[_\s]*(?:length|len|size)|key[_\s]*(?:size|length|len|bits)|(?:128|192|256|512|1024|2048|3072|4096)[\s\-_]?(?:bit)?)\s*[=:,\(]\s*(\d{3,4})|(?:aes[\-_]?)(128|192|256)|(\d{3,4})[\s\-_]?(?:bit)").unwrap()
    });

    // Try to find key size in matched text first, then context
    for text in [matched_text, context] {
        if let Some(cap) = KEY_SIZE_RE.captures(text) {
            let size_str = cap.get(1).or(cap.get(2)).or(cap.get(3));
            if let Some(s) = size_str {
                if let Ok(size) = s.as_str().parse::<u32>() {
                    if [128, 192, 256, 512, 1024, 2048, 3072, 4096].contains(&size) {
                        return Some(size);
                    }
                }
            }
        }
    }

    // Check for common patterns in context
    if context.contains("2048") {
        return Some(2048);
    }
    if context.contains("4096") {
        return Some(4096);
    }
    if context.contains("3072") {
        return Some(3072);
    }
    if context.contains("aes-256") || context.contains("AES-256") || context.contains("aes256") {
        return Some(256);
    }
    if context.contains("aes-128") || context.contains("AES-128") || context.contains("aes128") {
        return Some(128);
    }

    None
}

/// Calculate crypto agility score (inverse of risk score)
pub fn calculate_crypto_agility_score(findings: &[Finding]) -> u32 {
    100 - calculate_risk_score(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_detection() {
        let code = r#"const keypair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });"#;
        let findings = scan_content(code, "test.js", "javascript");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].algorithm, "RSA");
    }

    #[test]
    fn test_md5_detection() {
        let code = r#"const hash = crypto.createHash('md5').update(data).digest('hex');"#;
        let findings = scan_content(code, "test.js", "javascript");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].algorithm, "MD5");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_risk_score() {
        let findings = vec![Finding {
            algorithm: "RSA".to_string(),
            category: Category::AsymmetricEncryption,
            severity: Severity::High,
            quantum_risk: QuantumRisk::BrokenBy2030,
            file_path: "test.js".to_string(),
            line: 1,
            column: 1,
            context: String::new(),
            recommended_replacement: String::new(),
            migration_effort: String::new(),
            pattern_id: "rsa-key-generation".to_string(),
            library_name: None,
            library_version: None,
            key_size: Some(2048),
        }];

        let score = calculate_risk_score(&findings);
        assert!(score > 0);
        assert!(score <= 100);
    }
}

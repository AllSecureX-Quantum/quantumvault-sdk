//! Cryptographic pattern detection module
//!
//! Contains patterns for detecting quantum-vulnerable cryptography.
//! This code is compiled into the binary - source is not visible to users.
//!
//! Copyright (c) 2025-2026 AllSecureX. All rights reserved. PROPRIETARY.

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
    PostQuantum,
    PasswordHashing,
    InsecureConfiguration,
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

            // ================================================================
            // v1.2: C/C++ SOURCE-LEVEL PATTERNS
            // Reference: NIST FIPS 203/204/205 (Aug 2024), NIST SP 800-131A Rev 3,
            // CNSA 2.0 (Sep 2022), Mosca's Theorem, NIST IR 8413, RFC 7465.
            // ================================================================

            // OpenSSL/libcrypto - RSA
            CryptoPattern {
                id: "c-openssl-rsa",
                name: "OpenSSL RSA",
                algorithm: "RSA (OpenSSL)",
                category: Category::AsymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"\b(RSA_generate_key|RSA_generate_key_ex|RSA_new|RSA_padding_add|RSA_public_encrypt|RSA_private_decrypt|RSA_sign|RSA_verify|PEM_read_RSAPrivateKey|EVP_PKEY_CTX_set_rsa_keygen_bits|EVP_PKEY_RSA)\b").unwrap(),
                recommended_replacement: "ML-KEM-768 (FIPS 203) for KEM, ML-DSA-65 (FIPS 204) for signatures. Use OpenSSL 3.2+ with oqs-provider.",
                migration_effort: "complex",
                languages: &["c", "cpp"],
            },

            // OpenSSL - ECDSA / ECDH / EC keys
            CryptoPattern {
                id: "c-openssl-ec",
                name: "OpenSSL Elliptic Curve",
                algorithm: "ECDSA/ECDH (OpenSSL)",
                category: Category::DigitalSignature,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"\b(EC_KEY_new|EC_KEY_generate_key|ECDSA_sign|ECDSA_verify|ECDH_compute_key|EVP_PKEY_EC|EC_GROUP_new_by_curve_name|NID_X9_62_prime256v1|NID_secp384r1|NID_secp521r1|NID_secp256k1)\b").unwrap(),
                recommended_replacement: "ML-DSA-65 (FIPS 204) for signing, ML-KEM-768 (FIPS 203) for KEM",
                migration_effort: "complex",
                languages: &["c", "cpp"],
            },

            // OpenSSL - Diffie-Hellman
            CryptoPattern {
                id: "c-openssl-dh",
                name: "OpenSSL Diffie-Hellman",
                algorithm: "DH (OpenSSL)",
                category: Category::KeyExchange,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"\b(DH_new|DH_generate_key|DH_generate_parameters_ex|DH_compute_key|EVP_PKEY_DH|EVP_PKEY_DHX|PEM_read_DHparams)\b").unwrap(),
                recommended_replacement: "ML-KEM-768 (FIPS 203)",
                migration_effort: "complex",
                languages: &["c", "cpp"],
            },

            // OpenSSL - DSA
            CryptoPattern {
                id: "c-openssl-dsa",
                name: "OpenSSL DSA",
                algorithm: "DSA (OpenSSL)",
                category: Category::DigitalSignature,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"\b(DSA_new|DSA_generate_key|DSA_generate_parameters_ex|DSA_sign|DSA_verify|EVP_PKEY_DSA|PEM_read_DSAPrivateKey)\b").unwrap(),
                recommended_replacement: "ML-DSA-65 (FIPS 204)",
                migration_effort: "complex",
                languages: &["c", "cpp"],
            },

            // OpenSSL - MD5
            CryptoPattern {
                id: "c-openssl-md5",
                name: "OpenSSL MD5",
                algorithm: "MD5 (OpenSSL)",
                category: Category::HashFunction,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(MD5_Init|MD5_Update|MD5_Final|EVP_md5|NID_md5|EVP_PKEY_HMAC[A-Za-z0-9_ ,()]{0,40}md5)\b").unwrap(),
                recommended_replacement: "EVP_sha256 (SHA-256) or EVP_sha3_256 (SHA-3-256). MD5 collision-broken (Wang & Yu, 2004).",
                migration_effort: "easy",
                languages: &["c", "cpp"],
            },

            // OpenSSL - SHA-1
            CryptoPattern {
                id: "c-openssl-sha1",
                name: "OpenSSL SHA-1",
                algorithm: "SHA-1 (OpenSSL)",
                category: Category::HashFunction,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(SHA1_Init|SHA1_Update|SHA1_Final|EVP_sha1|NID_sha1)\b").unwrap(),
                recommended_replacement: "EVP_sha256 or EVP_sha3_256. SHA-1 collision-broken (SHAttered, Google 2017).",
                migration_effort: "easy",
                languages: &["c", "cpp"],
            },

            // OpenSSL - AES-128
            CryptoPattern {
                id: "c-openssl-aes-128",
                name: "OpenSSL AES-128",
                algorithm: "AES-128 (OpenSSL)",
                category: Category::SymmetricEncryption,
                severity: Severity::Medium,
                quantum_risk: QuantumRisk::Uncertain,
                regex: Regex::new(r"\b(EVP_aes_128_(ecb|cbc|cfb|cfb1|cfb8|cfb128|ofb|ctr|gcm|ccm|wrap|xts))\b").unwrap(),
                recommended_replacement: "EVP_aes_256_gcm. AES-128 post-quantum security is 64 bits (Grover); AES-256 retains 128-bit PQ security (NIST IR 8413).",
                migration_effort: "trivial",
                languages: &["c", "cpp"],
            },

            // OpenSSL - 3DES / DES
            CryptoPattern {
                id: "c-openssl-3des",
                name: "OpenSSL 3DES/DES",
                algorithm: "3DES (OpenSSL)",
                category: Category::SymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(EVP_des_ede3_cbc|EVP_des_ede3_ecb|EVP_des_ede3|EVP_des_cbc|EVP_des_ecb|DES_ede3_cbc_encrypt|DES_set_key|DES_ecb_encrypt|EVP_des_ede)\b").unwrap(),
                recommended_replacement: "EVP_aes_256_gcm. 3DES disallowed after 2023 per NIST SP 800-131A Rev 3.",
                migration_effort: "moderate",
                languages: &["c", "cpp"],
            },

            // OpenSSL - RC4
            CryptoPattern {
                id: "c-openssl-rc4",
                name: "OpenSSL RC4",
                algorithm: "RC4 (OpenSSL)",
                category: Category::SymmetricEncryption,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(RC4_set_key|EVP_rc4)\b").unwrap(),
                recommended_replacement: "EVP_chacha20_poly1305 or EVP_aes_256_gcm. RC4 prohibited per RFC 7465 (Feb 2015).",
                migration_effort: "moderate",
                languages: &["c", "cpp"],
            },

            // OpenSSL - Blowfish / IDEA / CAST
            CryptoPattern {
                id: "c-openssl-legacy-block",
                name: "OpenSSL Legacy Block Ciphers",
                algorithm: "Blowfish/IDEA/CAST (OpenSSL)",
                category: Category::SymmetricEncryption,
                severity: Severity::Medium,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(BF_set_key|BF_encrypt|EVP_bf_(cbc|ecb|cfb|ofb)|IDEA_set_encrypt_key|EVP_idea_cbc|CAST_set_key|EVP_cast5_cbc)\b").unwrap(),
                recommended_replacement: "EVP_aes_256_gcm or EVP_chacha20_poly1305",
                migration_effort: "moderate",
                languages: &["c", "cpp"],
            },

            // OpenSSL - Legacy TLS
            CryptoPattern {
                id: "c-openssl-tls-legacy",
                name: "OpenSSL Legacy TLS Methods",
                algorithm: "TLS 1.0/1.1 (OpenSSL)",
                category: Category::TlsCipherSuite,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(SSLv2_method|SSLv2_client_method|SSLv2_server_method|SSLv3_method|SSLv3_client_method|SSLv3_server_method|TLSv1_method|TLSv1_client_method|TLSv1_server_method|TLSv1_1_method|TLSv1_1_client_method|TLSv1_1_server_method|SSLv23_method)\b").unwrap(),
                recommended_replacement: "TLS_method() with SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION). RFC 8996 deprecates TLS 1.0/1.1.",
                migration_effort: "moderate",
                languages: &["c", "cpp"],
            },

            // OpenSSL - Hostname verification disabled
            CryptoPattern {
                id: "c-openssl-verify-none",
                name: "OpenSSL Certificate Verification Disabled",
                algorithm: "SSL_VERIFY_NONE",
                category: Category::InsecureConfiguration,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\bSSL_(CTX_)?set_verify\s*\([^,]+,\s*SSL_VERIFY_NONE\b").unwrap(),
                recommended_replacement: "SSL_VERIFY_PEER with X509_VERIFY_PARAM hostname check. Pin trust anchors.",
                migration_effort: "easy",
                languages: &["c", "cpp"],
            },

            // mbedTLS - RSA
            CryptoPattern {
                id: "c-mbedtls-rsa",
                name: "mbedTLS RSA",
                algorithm: "RSA (mbedTLS)",
                category: Category::AsymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"\b(mbedtls_rsa_init|mbedtls_rsa_gen_key|mbedtls_rsa_public|mbedtls_rsa_private|mbedtls_rsa_pkcs1_sign|mbedtls_rsa_pkcs1_verify|mbedtls_rsa_rsassa_pss_sign|MBEDTLS_PK_RSA)\b").unwrap(),
                recommended_replacement: "ML-KEM-768 / ML-DSA-65. mbedTLS 3.5+ has experimental PQ via PSA Crypto API.",
                migration_effort: "complex",
                languages: &["c", "cpp"],
            },

            // mbedTLS - ECDSA / ECDH
            CryptoPattern {
                id: "c-mbedtls-ec",
                name: "mbedTLS Elliptic Curve",
                algorithm: "ECDSA/ECDH (mbedTLS)",
                category: Category::DigitalSignature,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"\b(mbedtls_ecdsa_(init|sign|verify|genkey)|mbedtls_ecdh_(init|gen_public|compute_shared|make_params)|MBEDTLS_ECP_DP_SECP256R1|MBEDTLS_ECP_DP_SECP384R1|MBEDTLS_ECP_DP_SECP521R1|MBEDTLS_PK_ECDSA|MBEDTLS_PK_ECKEY)\b").unwrap(),
                recommended_replacement: "ML-DSA-65 / ML-KEM-768",
                migration_effort: "complex",
                languages: &["c", "cpp"],
            },

            // mbedTLS - MD5
            CryptoPattern {
                id: "c-mbedtls-md5",
                name: "mbedTLS MD5",
                algorithm: "MD5 (mbedTLS)",
                category: Category::HashFunction,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(mbedtls_md5_init|mbedtls_md5_starts|mbedtls_md5_starts_ret|mbedtls_md5_update|mbedtls_md5_update_ret|mbedtls_md5_finish|mbedtls_md5_finish_ret|mbedtls_md5_ret|MBEDTLS_MD_MD5)\b").unwrap(),
                recommended_replacement: "mbedtls_sha256 / MBEDTLS_MD_SHA256",
                migration_effort: "easy",
                languages: &["c", "cpp"],
            },

            // mbedTLS - SHA-1
            CryptoPattern {
                id: "c-mbedtls-sha1",
                name: "mbedTLS SHA-1",
                algorithm: "SHA-1 (mbedTLS)",
                category: Category::HashFunction,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(mbedtls_sha1_init|mbedtls_sha1_starts|mbedtls_sha1_starts_ret|mbedtls_sha1_update|mbedtls_sha1_update_ret|mbedtls_sha1_finish|mbedtls_sha1_ret|MBEDTLS_MD_SHA1)\b").unwrap(),
                recommended_replacement: "mbedtls_sha256 / MBEDTLS_MD_SHA256",
                migration_effort: "easy",
                languages: &["c", "cpp"],
            },

            // mbedTLS - DES / 3DES
            CryptoPattern {
                id: "c-mbedtls-des",
                name: "mbedTLS DES/3DES",
                algorithm: "DES/3DES (mbedTLS)",
                category: Category::SymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(mbedtls_des_setkey|mbedtls_des3_set2key|mbedtls_des3_set3key|mbedtls_des_crypt|mbedtls_des3_crypt|MBEDTLS_CIPHER_DES_CBC|MBEDTLS_CIPHER_DES_EDE3_CBC)\b").unwrap(),
                recommended_replacement: "mbedtls_gcm_* with AES-256",
                migration_effort: "moderate",
                languages: &["c", "cpp"],
            },

            // mbedTLS - Legacy TLS / SSL versions
            CryptoPattern {
                id: "c-mbedtls-tls-legacy",
                name: "mbedTLS Legacy TLS",
                algorithm: "TLS 1.0/1.1 (mbedTLS)",
                category: Category::TlsCipherSuite,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(MBEDTLS_SSL_MINOR_VERSION_[012]|MBEDTLS_SSL_VERSION_TLS1_0|MBEDTLS_SSL_VERSION_TLS1_1|MBEDTLS_SSL_VERIFY_NONE|mbedtls_ssl_conf_authmode\s*\([^,]+,\s*MBEDTLS_SSL_VERIFY_NONE)\b").unwrap(),
                recommended_replacement: "MBEDTLS_SSL_VERSION_TLS1_3 + MBEDTLS_SSL_VERIFY_REQUIRED",
                migration_effort: "moderate",
                languages: &["c", "cpp"],
            },

            // wolfSSL - RSA
            CryptoPattern {
                id: "c-wolfssl-rsa",
                name: "wolfSSL RSA",
                algorithm: "RSA (wolfSSL)",
                category: Category::AsymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"\b(wc_RsaPublicKeyDecode|wc_RsaPrivateKeyDecode|wc_InitRsaKey|wc_MakeRsaKey|wc_RsaSSL_Sign|wc_RsaSSL_Verify|wc_RsaPublicEncrypt|wc_RsaPrivateDecrypt)\b").unwrap(),
                recommended_replacement: "ML-KEM/ML-DSA via wolfCrypt PQ (wolfSSL 5.7+).",
                migration_effort: "complex",
                languages: &["c", "cpp"],
            },

            // wolfSSL - ECC
            CryptoPattern {
                id: "c-wolfssl-ec",
                name: "wolfSSL ECC",
                algorithm: "ECDSA/ECDH (wolfSSL)",
                category: Category::DigitalSignature,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"\b(wc_ecc_init|wc_ecc_make_key|wc_ecc_sign_hash|wc_ecc_verify_hash|wc_ecc_shared_secret|ECC_SECP256R1|ECC_SECP384R1)\b").unwrap(),
                recommended_replacement: "ML-DSA-65 / ML-KEM-768 via wolfCrypt PQ",
                migration_effort: "complex",
                languages: &["c", "cpp"],
            },

            // wolfSSL - MD5
            CryptoPattern {
                id: "c-wolfssl-md5",
                name: "wolfSSL MD5",
                algorithm: "MD5 (wolfSSL)",
                category: Category::HashFunction,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(wc_InitMd5|wc_Md5Update|wc_Md5Final|wc_Md5Hash)\b").unwrap(),
                recommended_replacement: "wc_Sha256",
                migration_effort: "easy",
                languages: &["c", "cpp"],
            },

            // wolfSSL - SHA-1
            CryptoPattern {
                id: "c-wolfssl-sha1",
                name: "wolfSSL SHA-1",
                algorithm: "SHA-1 (wolfSSL)",
                category: Category::HashFunction,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(wc_InitSha|wc_ShaUpdate|wc_ShaFinal|wc_ShaHash)\b").unwrap(),
                recommended_replacement: "wc_Sha256",
                migration_effort: "easy",
                languages: &["c", "cpp"],
            },

            // Apple CommonCrypto
            CryptoPattern {
                id: "c-cc-md5-sha1",
                name: "CommonCrypto MD5/SHA-1",
                algorithm: "MD5/SHA-1 (CommonCrypto)",
                category: Category::HashFunction,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(CC_MD5|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_SHA1|CC_SHA1_Init|CC_SHA1_Update|CC_SHA1_Final|kCCHmacAlgMD5|kCCHmacAlgSHA1)\b").unwrap(),
                recommended_replacement: "CC_SHA256 / CC_SHA512",
                migration_effort: "easy",
                languages: &["c", "cpp", "swift"],
            },

            // Apple CommonCrypto - Legacy block ciphers
            CryptoPattern {
                id: "c-cc-legacy-ciphers",
                name: "CommonCrypto Legacy Ciphers",
                algorithm: "DES/3DES/RC4 (CommonCrypto)",
                category: Category::SymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC4|kCCAlgorithmRC2|kCCAlgorithmBlowfish)\b").unwrap(),
                recommended_replacement: "kCCAlgorithmAES with kCCKeySizeAES256 + kCCModeGCM",
                migration_effort: "moderate",
                languages: &["c", "cpp", "swift"],
            },

            // Windows CNG / BCrypt - Legacy hash/cipher
            CryptoPattern {
                id: "c-cng-legacy",
                name: "Windows CNG Legacy Algorithms",
                algorithm: "Legacy Algos (CNG)",
                category: Category::HashFunction,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\b(CALG_MD5|CALG_SHA1|CALG_DES|CALG_3DES|CALG_RC4|CALG_RC2|BCRYPT_MD5_ALGORITHM|BCRYPT_SHA1_ALGORITHM|BCRYPT_DES_ALGORITHM|BCRYPT_3DES_ALGORITHM|BCRYPT_RC4_ALGORITHM)\b").unwrap(),
                recommended_replacement: "BCRYPT_SHA256_ALGORITHM or BCRYPT_AES_ALGORITHM with BCRYPT_CHAIN_MODE_GCM",
                migration_effort: "moderate",
                languages: &["c", "cpp", "csharp"],
            },

            // Windows CNG / BCrypt - RSA / ECC
            CryptoPattern {
                id: "c-cng-rsa-ec",
                name: "Windows CNG RSA / ECC",
                algorithm: "RSA/ECC (CNG)",
                category: Category::AsymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"\b(BCRYPT_RSA_ALGORITHM|BCRYPT_RSA_SIGN_ALGORITHM|BCRYPT_ECDSA_P256_ALGORITHM|BCRYPT_ECDSA_P384_ALGORITHM|BCRYPT_ECDSA_P521_ALGORITHM|BCRYPT_ECDH_P256_ALGORITHM|BCRYPT_ECDH_P384_ALGORITHM|BCRYPT_ECDH_P521_ALGORITHM|BCRYPT_DH_ALGORITHM|BCRYPT_DSA_ALGORITHM)\b").unwrap(),
                recommended_replacement: "Migrate when Windows ships ML-KEM/ML-DSA. Windows 11 24H2 has experimental BCRYPT_MLKEM_ALGORITHM.",
                migration_effort: "complex",
                languages: &["c", "cpp", "csharp"],
            },

            // Hardcoded crypto key buffer in C/C++
            CryptoPattern {
                id: "c-hardcoded-key-buffer",
                name: "Hardcoded Key Buffer (C/C++)",
                algorithm: "Hardcoded Secret",
                category: Category::InsecureConfiguration,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(unsigned\s+char|static\s+const|const\s+unsigned\s+char|uint8_t|BYTE)\s+\w*(key|secret|passwd|password|iv|nonce|salt)\w*\s*\[\s*\d*\s*\]\s*=\s*\{\s*0x"#).unwrap(),
                recommended_replacement: "Use a KMS/HSM (AWS KMS, Azure Key Vault, HashiCorp Vault, AllSecureX Key Vault). Inject keys at runtime.",
                migration_effort: "moderate",
                languages: &["c", "cpp"],
            },

            // CURL insecure flags (C/C++)
            CryptoPattern {
                id: "c-curl-insecure",
                name: "CURL TLS Verification Disabled",
                algorithm: "Insecure CURL",
                category: Category::InsecureConfiguration,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\bcurl_easy_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*0L?\b").unwrap(),
                recommended_replacement: "Set CURLOPT_SSL_VERIFYPEER=1 and CURLOPT_SSL_VERIFYHOST=2. Pin CA bundle via CURLOPT_CAINFO.",
                migration_effort: "easy",
                languages: &["c", "cpp"],
            },

            // ================================================================
            // v1.2: SAFE / POST-QUANTUM ALGORITHM DETECTION
            // Reported as Info / QuantumSafe so users see what is already correct.
            // ================================================================

            // ML-KEM (FIPS 203, Aug 2024)
            CryptoPattern {
                id: "safe-ml-kem",
                name: "ML-KEM (Kyber) Post-Quantum KEM",
                algorithm: "ML-KEM",
                category: Category::PostQuantum,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(ML[-_]?KEM[-_]?(?:512|768|1024)|\bML[-_]?KEM\b|Kyber(?:512|768|1024)|\bKyber\b|OQS_KEM_(?:alg_)?(?:kyber|ml_kem)|mlkem|crypto_kem_kyber|EVP_PKEY_ML_KEM|BCRYPT_MLKEM_ALGORITHM)").unwrap(),
                recommended_replacement: "Maintain. Already aligned with NIST FIPS 203 (August 2024).",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "swift", "kotlin"],
            },

            // ML-DSA (FIPS 204, Aug 2024)
            // v1.2.1: word-boundary fix - matches MLDSA inside ECDSA_MLDSA, DILITHIUM
            // inside RSA3072_DILITHIUM, etc. PQC algorithm names are distinctive
            // enough that loose matching does not produce false positives.
            CryptoPattern {
                id: "safe-ml-dsa",
                name: "ML-DSA (Dilithium) Post-Quantum Signature",
                algorithm: "ML-DSA",
                category: Category::PostQuantum,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(ML[-_]?DSA[-_]?(?:44|65|87)|ML[-_]?DSA|MLDSA|Dilithium[235]?|OQS_SIG_(?:alg_)?(?:dilithium|ml_dsa)|crypto_sign_dilithium|EVP_PKEY_ML_DSA|BCRYPT_MLDSA_ALGORITHM)").unwrap(),
                recommended_replacement: "Maintain. Already aligned with NIST FIPS 204 (August 2024).",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "swift", "kotlin"],
            },

            // SLH-DSA (FIPS 205, Aug 2024)
            // v1.2.1: word-boundary fix - matches SLHDSA / SLH-DSA / SLH_DSA inside
            // compound identifiers; SPHINCS is whitelisted standalone or with + suffix.
            CryptoPattern {
                id: "safe-slh-dsa",
                name: "SLH-DSA (SPHINCS+) Hash-Based Signature",
                algorithm: "SLH-DSA",
                category: Category::PostQuantum,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(SLH[-_]?DSA|SLHDSA|SPHINCS\+?|sphincsplus|OQS_SIG_(?:alg_)?(?:sphincs|slh_dsa)|EVP_PKEY_SLH_DSA)").unwrap(),
                recommended_replacement: "Maintain. NIST FIPS 205. Stateless hash-based, conservative design.",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // liboqs / Open Quantum Safe
            CryptoPattern {
                id: "safe-liboqs",
                name: "liboqs (Open Quantum Safe)",
                algorithm: "liboqs",
                category: Category::PostQuantum,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"\b(OQS_(?:KEM|SIG|RAND|MEM|init|destroy)_|oqsprovider|liboqs|oqs-provider)\b").unwrap(),
                recommended_replacement: "Maintain. Open Quantum Safe is the NIST PQC reference implementation.",
                migration_effort: "trivial",
                languages: &["c", "cpp", "python", "rust", "go", "java"],
            },

            // PQ Hybrid TLS key exchange
            CryptoPattern {
                id: "safe-pq-hybrid-kx",
                name: "Hybrid Post-Quantum TLS Key Exchange",
                algorithm: "Hybrid PQ KX",
                category: Category::PostQuantum,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)\b(X25519MLKEM768|x25519_kyber768|p256_kyber768|secp256r1_kyber768|x25519_mlkem|p384_mlkem)\b").unwrap(),
                recommended_replacement: "Maintain. RFC draft-kwiatkowski-tls-ecdhe-mlkem. Deployed by Cloudflare and Chrome.",
                migration_effort: "trivial",
                languages: &["c", "cpp", "python", "rust", "go", "java", "javascript", "csharp"],
            },

            // AES-256
            // v1.2.1: word-boundary fix - the algorithm name AES-256 is distinctive
            // enough that dropping the leading \b does not introduce false positives.
            CryptoPattern {
                id: "safe-aes-256",
                name: "AES-256 Symmetric Encryption",
                algorithm: "AES-256",
                category: Category::SymmetricEncryption,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(AES[-_/]?256[-_]?(?:GCM|CCM|CTR|CBC|OFB|XTS|WRAP)|AES[-_/]?256\b|EVP_aes_256_(?:gcm|ccm|ctr|cbc|wrap|xts|ofb)|mbedtls_aes_256|wc_Aes(?:Gcm|Ccm)?Init|kCCKeySizeAES256|AES_256_KEY_SIZE|aes256gcm|aes256_gcm)").unwrap(),
                recommended_replacement: "Maintain. AES-256 retains 128-bit post-quantum security against Grover (NIST IR 8413).",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "swift", "kotlin", "ruby", "php"],
            },

            // ChaCha20-Poly1305
            CryptoPattern {
                id: "safe-chacha20-poly1305",
                name: "ChaCha20-Poly1305 AEAD",
                algorithm: "ChaCha20-Poly1305",
                category: Category::SymmetricEncryption,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(ChaCha20[-_]?Poly1305|XChaCha20[-_]?Poly1305|EVP_chacha20_poly1305|crypto_aead_chacha20poly1305|crypto_aead_xchacha20poly1305|TLS_CHACHA20_POLY1305_SHA256|chacha20poly1305)").unwrap(),
                recommended_replacement: "Maintain. RFC 8439 AEAD. Strong against Grover (256-bit key, 128-bit PQ security).",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "swift", "kotlin", "ruby", "php"],
            },

            // SHA-256
            // v1.2.1: drop leading boundary, match SHA-256 in compound identifiers.
            CryptoPattern {
                id: "safe-sha256",
                name: "SHA-256 Hash",
                algorithm: "SHA-256",
                category: Category::HashFunction,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r#"(?i)(SHA[-_]?256|sha2_256|EVP_sha256|mbedtls_sha256|wc_Sha256|CC_SHA256|BCRYPT_SHA256_ALGORITHM|hashlib\.sha256|createHash\s*\(\s*['"]sha256|MessageDigest\.getInstance\s*\(\s*['"]SHA[-_]?256)"#).unwrap(),
                recommended_replacement: "Maintain. 128-bit collision resistance vs Grover; preferred general-purpose hash.",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "swift", "kotlin", "ruby", "php"],
            },

            // SHA-384 / SHA-512
            CryptoPattern {
                id: "safe-sha-large",
                name: "SHA-384 / SHA-512 Hash",
                algorithm: "SHA-384/512",
                category: Category::HashFunction,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r#"(?i)(SHA[-_]?(?:384|512)|sha2_(?:384|512)|EVP_sha(?:384|512)|mbedtls_sha512|wc_Sha(?:384|512)|CC_SHA(?:384|512)|hashlib\.sha(?:384|512)|BCRYPT_SHA(?:384|512)_ALGORITHM)"#).unwrap(),
                recommended_replacement: "Maintain. Required for TLS 1.3 cipher suite TLS_AES_256_GCM_SHA384.",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "swift", "kotlin"],
            },

            // SHA-3 / SHAKE
            CryptoPattern {
                id: "safe-sha3",
                name: "SHA-3 / SHAKE Hash",
                algorithm: "SHA-3",
                category: Category::HashFunction,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(SHA[-_]?3(?:[-_]?(?:224|256|384|512))?|sha3_(?:224|256|384|512)|EVP_sha3_(?:224|256|384|512)|Keccak|SHAKE128|SHAKE256|cSHAKE)").unwrap(),
                recommended_replacement: "Maintain. NIST FIPS 202. Sponge construction provides design diversity vs SHA-2.",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // HKDF
            CryptoPattern {
                id: "safe-hkdf",
                name: "HKDF Key Derivation",
                algorithm: "HKDF",
                category: Category::KeyExchange,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(HKDF[-_]?(?:Extract|Expand|SHA256|SHA512)|\bHKDF\b|hkdf_extract|hkdf_expand|EVP_PKEY_HKDF|mbedtls_hkdf|wc_HKDF)").unwrap(),
                recommended_replacement: "Maintain. RFC 5869. Underpins TLS 1.3 key schedule.",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // Argon2 - distinctive name, no boundary needed
            CryptoPattern {
                id: "safe-argon2",
                name: "Argon2 Password Hashing",
                algorithm: "Argon2",
                category: Category::PasswordHashing,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(Argon2(?:i|d|id)?|argon2_hash|crypto_pwhash_argon2|PHC_ARGON2)").unwrap(),
                recommended_replacement: "Maintain. PHC password-hashing competition winner (2015). OWASP-recommended.",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "php", "ruby"],
            },

            // bcrypt / scrypt
            CryptoPattern {
                id: "safe-bcrypt-scrypt",
                name: "bcrypt / scrypt Password Hashing",
                algorithm: "bcrypt/scrypt",
                category: Category::PasswordHashing,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)\b(bcrypt(?:_hashpw|_checkpw|\.hash|\.compare)?|scrypt(?:_kdf|_pwhash|Sync)?|crypto_pwhash_scrypt|EVP_PBE_scrypt|BCryptPasswordHasher)").unwrap(),
                recommended_replacement: "Maintain. OWASP-recommended password hashes (verify bcrypt cost >= 12, scrypt N >= 2^17).",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "php", "ruby"],
            },

            // BLAKE2 / BLAKE3
            CryptoPattern {
                id: "safe-blake",
                name: "BLAKE2 / BLAKE3 Hash",
                algorithm: "BLAKE2/3",
                category: Category::HashFunction,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(BLAKE2[bs]|BLAKE3|blake2b_(?:init|update|final)|blake3_(?:hasher|update|finalize)|crypto_generichash)").unwrap(),
                recommended_replacement: "Maintain. RFC 7693 (BLAKE2). Used by WireGuard, Signal, IPFS.",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // TLS 1.3 (modern; PQ-ready)
            CryptoPattern {
                id: "safe-tls-1-3",
                name: "TLS 1.3",
                algorithm: "TLS 1.3",
                category: Category::TlsCipherSuite,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::Uncertain,
                regex: Regex::new(r"(?i)\b(TLS[v_]?1[._]?3\b|TLS1_3_VERSION|TLS_AES_256_GCM_SHA384|TLS_AES_128_GCM_SHA256|MBEDTLS_SSL_VERSION_TLS1_3)\b").unwrap(),
                recommended_replacement: "Enable hybrid PQ key exchange (X25519MLKEM768) on OpenSSL 3.5+, BoringSSL, or Cloudflare for full quantum safety.",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // ================================================================
            // v1.2: ADDITIONAL DEEP-DIVE CRYPTO ISSUES (all languages)
            // ================================================================

            // ECB mode (cross-language)
            CryptoPattern {
                id: "ecb-mode-multilang",
                name: "ECB Mode (Pattern Leakage)",
                algorithm: "ECB Mode",
                category: Category::InsecureConfiguration,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(AES[/_-]?(?:128|192|256)?[/_-]?ECB|AES\.MODE_ECB|MODE_ECB|Cipher\.getInstance\s*\(\s*['"]AES/ECB|EVP_aes_(?:128|192|256)_ecb|BCRYPT_CHAIN_MODE_ECB)"#).unwrap(),
                recommended_replacement: "Use GCM (authenticated). ECB leaks data patterns - the ECB Penguin demonstrates this.",
                migration_effort: "moderate",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // PBKDF2 with weak iteration count
            CryptoPattern {
                id: "pbkdf2-weak-iter",
                name: "PBKDF2 with Low Iteration Count",
                algorithm: "PBKDF2 (weak)",
                category: Category::PasswordHashing,
                severity: Severity::High,
                quantum_risk: QuantumRisk::Uncertain,
                regex: Regex::new(r"(?i)PBKDF2[^,)\n]{0,80}[,(]\s*(?:iterations\s*=\s*)?(?:1000|10000|100000|[1-9]\d{0,3}|[1-9]\d{4})\s*[,)]").unwrap(),
                recommended_replacement: "PBKDF2 iter >= 600,000 (OWASP 2023) or migrate to Argon2id.",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp"],
            },

            // TLS verification disabled (cross-language)
            CryptoPattern {
                id: "tls-verify-disabled",
                name: "TLS Certificate Verification Disabled",
                algorithm: "Insecure TLS",
                category: Category::InsecureConfiguration,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r##"(?i)(InsecureSkipVerify\s*[:=]\s*true|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|VERIFY_NONE|trust_all_certs|allowAllHostnameVerifier|disable_ssl_verification)"##).unwrap(),
                recommended_replacement: "Enable certificate verification + hostname check. Pin trust anchors.",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "php", "ruby"],
            },

            // JWT none algorithm
            CryptoPattern {
                id: "jwt-none-alg",
                name: "JWT 'none' Algorithm",
                algorithm: "JWT none",
                category: Category::DigitalSignature,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(['"]alg['"]\s*:\s*['"]none['"]|algorithm\s*[:=]\s*['"]none['"]|algorithms\s*[:=]\s*\[\s*['"]none['"])"#).unwrap(),
                recommended_replacement: "Use HS256 (shared secret) or RS256/ES256 (asymmetric). Plan migration to ML-DSA-65 for post-quantum.",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "ruby", "php", "json", "yaml", "config"],
            },

            // Static IV / nonce (heuristic)
            CryptoPattern {
                id: "static-iv-nonce",
                name: "Static IV / Nonce",
                algorithm: "Static IV",
                category: Category::InsecureConfiguration,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(iv|nonce)\s*[:=]\s*['"](?:0+|[01]{8,}|[a-fA-F0-9]{16,32})['"]"#).unwrap(),
                recommended_replacement: "Generate IV/nonce per-message via CSPRNG. GCM reuses nonce = catastrophic break.",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // ================================================================
            // v1.2.1: COMPETITIVE-DEPTH PATTERNS
            // Beats Snyk / SonarQube / CodeQL / CryptoSense on cryptographic
            // primitive depth. Adds modern-classical curve detection, HSM/KMS
            // signals, JWS/JWE algorithm parsing, PKCS#1 v1.5 padding flagging,
            // and managed-key-custody inventory.
            // ================================================================

            // Ed25519 (signing curve) - modern classical, quantum-vulnerable
            // Reference: RFC 8032 (EdDSA), Bernstein 2011. Discrete-log scheme,
            // breakable by Shor's algorithm same as ECDSA.
            CryptoPattern {
                id: "modern-classical-ed25519",
                name: "Ed25519 Signature (EdDSA)",
                algorithm: "Ed25519",
                category: Category::DigitalSignature,
                severity: Severity::Medium,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"(?i)(Ed25519|EdDSA|ed25519_sign|ed25519_verify|crypto_sign_ed25519|EVP_PKEY_ED25519|NID_ED25519|ssh-ed25519)").unwrap(),
                recommended_replacement: "Modern classical signature, well-engineered but Shor-vulnerable. Plan migration to ML-DSA-65 (FIPS 204). Hybrid Ed25519+ML-DSA-65 is a sound interim.",
                migration_effort: "complex",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "swift", "kotlin", "ruby", "php"],
            },

            // X25519 / Curve25519 (key exchange) - modern classical
            // Reference: RFC 7748. Also discrete-log, Shor-vulnerable.
            CryptoPattern {
                id: "modern-classical-x25519",
                name: "X25519 / Curve25519 Key Exchange",
                algorithm: "X25519",
                category: Category::KeyExchange,
                severity: Severity::Medium,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"(?i)(X25519|Curve25519|x25519_keypair|crypto_box_curve25519|EVP_PKEY_X25519|NID_X25519|curve25519_donna)").unwrap(),
                recommended_replacement: "Modern classical KEX, Shor-vulnerable. Migrate to ML-KEM-768 (FIPS 203). Hybrid X25519+ML-KEM-768 (X25519MLKEM768, draft-kwiatkowski-tls-ecdhe-mlkem) is the right interim posture.",
                migration_effort: "complex",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "swift", "kotlin", "ruby", "php"],
            },

            // X448 / Ed448 - same family
            CryptoPattern {
                id: "modern-classical-curve448",
                name: "Ed448 / X448 (Curve448)",
                algorithm: "Curve448",
                category: Category::KeyExchange,
                severity: Severity::Medium,
                quantum_risk: QuantumRisk::BrokenBy2030,
                regex: Regex::new(r"(?i)(Ed448|X448|Curve448|EVP_PKEY_(?:ED448|X448)|NID_(?:ED448|X448))").unwrap(),
                recommended_replacement: "Modern classical curve, Shor-vulnerable. Plan ML-KEM-1024 / ML-DSA-87 for migration.",
                migration_effort: "complex",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // PKCS#11 / HSM detection (informational - identifies HSM usage)
            // Strong positive signal: keys live in HSM, not in process memory.
            CryptoPattern {
                id: "safe-pkcs11-hsm",
                name: "PKCS#11 / HSM",
                algorithm: "PKCS#11 HSM",
                category: Category::PostQuantum,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(PKCS#?11|C_Initialize|C_OpenSession|C_GenerateKey|C_Sign|CK_FUNCTION_LIST|softhsm|YubiHSM|CloudHSM|nCipher|nshield|Luna(?:HSM|SA)|Utimaco|safenet)").unwrap(),
                recommended_replacement: "HSM-managed keys are inherently better protected. Verify the HSM firmware supports ML-KEM/ML-DSA when migration window opens (Thales, Entrust, AWS CloudHSM all have PQ roadmaps).",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // Cloud KMS (managed key custody - positive)
            CryptoPattern {
                id: "safe-cloud-kms",
                name: "Cloud KMS (Managed Key Custody)",
                algorithm: "Cloud KMS",
                category: Category::PostQuantum,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::QuantumSafe,
                regex: Regex::new(r"(?i)(AWS[._]?KMS|aws-?sdk[/-]?kms|KMSClient|kms\.Encrypt|kms\.Decrypt|kms\.GenerateDataKey|AzureKeyVault|Azure\.Security\.KeyVault|google\.cloud\.kms|google-cloud-kms|gcp_kms|HashiCorp\s*Vault|vault\.read\b|vault_client|VaultClient|/v1/transit/encrypt|HVAC)").unwrap(),
                recommended_replacement: "Managed key custody is the right pattern. AWS KMS / Azure Key Vault / GCP KMS / HashiCorp Vault roadmaps include PQ algorithms; track vendor announcements.",
                migration_effort: "trivial",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // JWS / JWT modern algorithms (safe)
            CryptoPattern {
                id: "safe-jws-modern",
                name: "JWS Modern Algorithm (ES256/EdDSA/PS256/RS256)",
                algorithm: "JWS Modern",
                category: Category::DigitalSignature,
                severity: Severity::Info,
                quantum_risk: QuantumRisk::Uncertain,
                regex: Regex::new(r#"(?i)(['"]alg['"]\s*:\s*['"](?:RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES384|ES512|EdDSA|HS256|HS384|HS512)['"]|algorithm\s*[:=]\s*['"](?:RS256|PS256|ES256|EdDSA|HS256)['"]?)"#).unwrap(),
                recommended_replacement: "Modern JWS algorithm. Asymmetric variants (RS/PS/ES/EdDSA) are quantum-vulnerable; plan ML-DSA-65 migration. HS256 with rotated secret is OK long-term (symmetric, Grover-tolerant with 256-bit key).",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "ruby", "php", "json", "yaml", "config"],
            },

            // JWS HS256 weak secret heuristic
            CryptoPattern {
                id: "jws-weak-secret",
                name: "JWS HS256 with Short Secret",
                algorithm: "JWS Weak Secret",
                category: Category::DigitalSignature,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(jwt\.sign|jsonwebtoken|sign_jwt)[^,)]*['"](?:secret|password|test|hello|key|jwt)['"]"#).unwrap(),
                recommended_replacement: "Use a 256-bit random secret from a KMS. Short / dictionary secrets are brute-forceable in seconds.",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "ruby", "php"],
            },

            // PKCS#1 v1.5 RSA padding (Bleichenbacher-vulnerable)
            // Reference: Bleichenbacher 1998. Padding oracle attack.
            CryptoPattern {
                id: "rsa-pkcs1-v15",
                name: "RSA PKCS#1 v1.5 Padding (Bleichenbacher)",
                algorithm: "RSA PKCS1v1.5",
                category: Category::AsymmetricEncryption,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"(?i)(RSA[/_-]?ECB[/_-]?PKCS1Padding|PKCS1_v1_5|RSA_PKCS1_PADDING|MBEDTLS_RSA_PKCS_V15|padding\s*=\s*PKCS1v15)").unwrap(),
                recommended_replacement: "Switch to RSA-OAEP (RSA_PKCS1_OAEP_PADDING / RSA-OAEP-SHA256) for encryption or RSA-PSS for signing. PKCS#1 v1.5 padding is Bleichenbacher-vulnerable (CVE-2018-12404, ROBOT). Then plan ML-KEM migration.",
                migration_effort: "moderate",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // Java KeyStore JKS (uses MD5 + SHA-1 + custom XOR)
            CryptoPattern {
                id: "java-keystore-jks",
                name: "Java Legacy KeyStore (JKS / JCEKS)",
                algorithm: "JKS",
                category: Category::InsecureConfiguration,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(KeyStore\.getInstance\s*\(\s*['"](?:JKS|JCEKS)['"]|\.jks\b|\.jceks\b|storetype\s*=\s*JKS)"#).unwrap(),
                recommended_replacement: "Migrate to PKCS12 (KeyStore.getInstance(\"PKCS12\")). JKS uses MD5+SHA1+custom XOR for password protection (CVE-2017-10356).",
                migration_effort: "easy",
                languages: &["java", "kotlin", "scala", "config", "yaml"],
            },

            // Self-rolled crypto - XOR encryption heuristic
            CryptoPattern {
                id: "self-rolled-xor",
                name: "Self-Rolled XOR Encryption",
                algorithm: "XOR Cipher",
                category: Category::SymmetricEncryption,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"(?i)(\w*encrypt\w*|\w*cipher\w*|\w*obfusc\w*)[^{]*\{[^}]{0,200}\bx?or\s*=|(?:plaintext|ciphertext|cleartext)\s*\^\s*key|key\s*\^\s*(?:plaintext|ciphertext|data)").unwrap(),
                recommended_replacement: "Never roll your own crypto. Use AES-256-GCM or ChaCha20-Poly1305 from a vetted library (libsodium, RustCrypto, BoringSSL).",
                migration_effort: "complex",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // Deterministic / seeded CSPRNG (catastrophic)
            CryptoPattern {
                id: "seeded-csprng",
                name: "Seeded / Deterministic Random",
                algorithm: "Deterministic RNG",
                category: Category::RandomNumberGenerator,
                severity: Severity::Critical,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"(?i)(SecureRandom\.setSeed|Random\s*\(\s*\d+\s*\)|random\.seed\s*\(\s*\d+|np\.random\.seed\s*\(\s*\d+|srand\s*\(\s*(?:0|1|42|time\s*\(\s*0\s*\)\s*)?\)|prng\s*=\s*new\s+Random\s*\(\s*\d+)").unwrap(),
                recommended_replacement: "Never seed a CSPRNG with a constant or time(). Use SecureRandom() with no seed, secrets.token_bytes(), crypto.randomBytes(), os.urandom(), or getentropy().",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp"],
            },

            // TLS_RSA cipher suites (vulnerable to ROBOT, no forward secrecy)
            CryptoPattern {
                id: "tls-rsa-cipher-suite",
                name: "TLS_RSA Cipher Suite (No Forward Secrecy)",
                algorithm: "TLS_RSA",
                category: Category::TlsCipherSuite,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"\bTLS_RSA_WITH_[A-Z_0-9]+\b").unwrap(),
                recommended_replacement: "Replace with TLS_ECDHE_* (forward secrecy) or TLS 1.3 cipher suite. TLS_RSA suites are CVE-2017-13099 (ROBOT) vulnerable and provide no forward secrecy.",
                migration_effort: "moderate",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "config", "yaml", "nginx", "apache"],
            },

            // SSLv3 / Heartbleed-vulnerable OpenSSL versions
            CryptoPattern {
                id: "tls-cbc-mac-then-encrypt",
                name: "TLS CBC Cipher Suite (Lucky13 / BEAST)",
                algorithm: "TLS CBC",
                category: Category::TlsCipherSuite,
                severity: Severity::Medium,
                quantum_risk: QuantumRisk::Uncertain,
                regex: Regex::new(r"\bTLS_(?:ECDHE_RSA|ECDHE_ECDSA|DHE_RSA|RSA)_WITH_(?:AES_(?:128|256)_CBC|3DES_EDE_CBC)_SHA(?:256)?\b").unwrap(),
                recommended_replacement: "Prefer GCM or CHACHA20-POLY1305 cipher suites. CBC suites are Lucky13 (CVE-2013-0169) and BEAST-susceptible without rigorous countermeasures.",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp", "c", "cpp", "config", "yaml", "nginx", "apache"],
            },

            // PBKDF2 with MD5 / SHA-1 (vs SHA-256+)
            CryptoPattern {
                id: "pbkdf2-weak-prf",
                name: "PBKDF2 with Weak PRF (MD5 / SHA-1)",
                algorithm: "PBKDF2 (MD5/SHA-1)",
                category: Category::PasswordHashing,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r#"(?i)(PBKDF2[^,)\n]{0,80}(?:HmacMD5|HmacSHA1|MD5|SHA-?1)|PBKDF2WithHmacSHA1|PBKDF2_HMAC.*['"](?:md5|sha1)['"])"#).unwrap(),
                recommended_replacement: "Use PBKDF2WithHmacSHA256 (or SHA512), iter >= 600,000. Better: migrate to Argon2id.",
                migration_effort: "easy",
                languages: &["python", "javascript", "java", "go", "rust", "csharp"],
            },

            // Hardcoded TLS / cert pinning bypass
            CryptoPattern {
                id: "cert-pin-bypass",
                name: "Certificate Pinning Bypass",
                algorithm: "Pin Bypass",
                category: Category::InsecureConfiguration,
                severity: Severity::High,
                quantum_risk: QuantumRisk::BrokenNow,
                regex: Regex::new(r"(?i)(TrustManager.*\{\s*public\s+void\s+check(?:Client|Server)Trusted[^}]*\{\s*\}|HostnameVerifier.*return\s+true|TrustAll(?:Hostnames|Certificates)?|trustAllCerts)").unwrap(),
                recommended_replacement: "Implement proper certificate validation with hostname checking. Pin the issuing CA, not the leaf, to allow rotation.",
                migration_effort: "moderate",
                languages: &["java", "kotlin", "scala", "csharp"],
            },
        ]
    });

    &PATTERNS
}

/// Comment/string syntax for a language: (line comments, block comments,
/// string literals as (delimiter, escapes_allowed, multiline)).
type LangSyntax = (
    &'static [&'static str],
    &'static [(&'static str, &'static str)],
    &'static [(&'static str, bool, bool)],
);

fn syntax_for(language: &str) -> LangSyntax {
    const CLIKE: LangSyntax = (
        &["//"],
        &[("/*", "*/")],
        &[("\"", true, false), ("'", true, false), ("`", false, true)],
    );
    match language {
        "python" => (
            &["#"],
            &[],
            &[
                ("\"\"\"", false, true),
                ("'''", false, true),
                ("\"", true, false),
                ("'", true, false),
            ],
        ),
        "ruby" | "shell" | "docker" | "config" | "yaml" => {
            (&["#"], &[], &[("\"", true, false), ("'", false, false)])
        }
        "xml" => (&[], &[("<!--", "-->")], &[("\"", false, false), ("'", false, false)]),
        // No comments: certificates/keys and strict JSON. Mask nothing so PEM
        // headers and JSON string values remain fully visible.
        "cert" | "json" | "unknown" => (&[], &[], &[]),
        // javascript, java, go, rust, csharp, php, c, cpp and anything else.
        _ => CLIKE,
    }
}

/// Build two masked views of `content`, byte for byte (newlines and offsets
/// preserved so match offsets map back to the original):
///
/// * `code_view` - comments AND all string-literal interiors blanked. Used for
///   symbol/call patterns (e.g. `MD5_Init`, `EVP_md5`, `hashlib.md5`). A crypto
///   symbol that appears inside a string, such as a log message
///   `LOG("Error in MD5_Init")`, can therefore NEVER produce a finding, while a
///   real call `MD5_Init(&ctx)` in code still matches. This is the exact class
///   of false positive reported by NSE.
///
/// * `arg_view` - comments blanked; a string interior is blanked only if it is a
///   multi-line string or contains whitespace (i.e. prose); a whitespace-free
///   token such as `"md5"`, `"AES/CBC/PKCS5Padding"` or `"SHA-256"` is kept.
///   Used for patterns that read the algorithm out of a string argument, e.g.
///   `getInstance("MD5")` or `createHash('md5')`. Algorithm identifiers never
///   contain whitespace, so real arguments are always preserved while free-text
///   mentions are removed.
fn mask_views(content: &str, language: &str) -> (String, String) {
    let (line_cmts, block_cmts, strings) = syntax_for(language);
    if line_cmts.is_empty() && block_cmts.is_empty() && strings.is_empty() {
        return (content.to_string(), content.to_string());
    }
    let bytes = content.as_bytes();
    let n = bytes.len();
    let mut code = bytes.to_vec();
    let mut arg = bytes.to_vec();
    let sw = |i: usize, tok: &str| -> bool {
        let t = tok.as_bytes();
        i + t.len() <= n && &bytes[i..i + t.len()] == t
    };
    let blank = |v: &mut [u8], a: usize, b: usize| {
        for k in a..b {
            if v[k] != b'\n' {
                v[k] = b' ';
            }
        }
    };
    #[derive(Clone, Copy)]
    enum St {
        Code,
        Block(usize),
    }
    let mut state = St::Code;
    let mut i = 0;
    while i < n {
        match state {
            St::Code => {
                if line_cmts.iter().any(|t| sw(i, t)) {
                    let start = i;
                    while i < n && bytes[i] != b'\n' {
                        i += 1;
                    }
                    blank(&mut code, start, i);
                    blank(&mut arg, start, i);
                    continue;
                }
                if let Some(idx) = block_cmts.iter().position(|(o, _)| sw(i, o)) {
                    let o = block_cmts[idx].0;
                    blank(&mut code, i, i + o.len());
                    blank(&mut arg, i, i + o.len());
                    i += o.len();
                    state = St::Block(idx);
                    continue;
                }
                if let Some(idx) = strings.iter().position(|(d, _, _)| sw(i, d)) {
                    let (d, esc, ml) = strings[idx];
                    let start = i + d.len();
                    let mut j = start;
                    let mut closed = false;
                    while j < n {
                        if esc && bytes[j] == b'\\' {
                            j += 2;
                            continue;
                        }
                        if !ml && bytes[j] == b'\n' {
                            break;
                        }
                        if sw(j, d) {
                            closed = true;
                            break;
                        }
                        j += 1;
                    }
                    let end = j.min(n);
                    let has_ws = bytes[start..end].iter().any(|b| *b == b' ' || *b == b'\t');
                    blank(&mut code, start, end); // code view: always blank string body
                    if ml || has_ws {
                        blank(&mut arg, start, end); // arg view: blank prose only
                    }
                    i = if closed { j + d.len() } else { end };
                    continue;
                }
                i += 1;
            }
            St::Block(idx) => {
                let c = block_cmts[idx].1;
                if sw(i, c) {
                    blank(&mut code, i, i + c.len());
                    blank(&mut arg, i, i + c.len());
                    i += c.len();
                    state = St::Code;
                } else {
                    blank(&mut code, i, i + 1);
                    blank(&mut arg, i, i + 1);
                    i += 1;
                }
            }
        }
    }
    // SAFETY: only ASCII bytes were replaced with ASCII spaces; still valid UTF-8.
    (
        String::from_utf8(code).unwrap_or_else(|_| content.to_string()),
        String::from_utf8(arg).unwrap_or_else(|_| content.to_string()),
    )
}

/// C/C++ source-level rules (id prefix "c-") detect bare function symbols such
/// as MD5_Init / EVP_md5, which must never match inside a string literal (e.g. a
/// log message `"Error in MD5_Init"`). They use the code view, where every string
/// interior is blanked. All other rules use the arg view, which preserves
/// whitespace-free algorithm tokens (including compound identifiers such as
/// 'ECDSA_MLDSA') so cryptographic inventory stays complete.
fn uses_code_view(pattern_id: &str) -> bool {
    pattern_id.starts_with("c-")
}

/// Scan content for crypto patterns
pub fn scan_content(content: &str, file_path: &str, language: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let patterns = get_patterns();

    // Detect crypto library used in this file
    let library = detect_crypto_library(content, language);

    // Comment/string-masked views (offsets map back to `content`). Symbol rules
    // match on code_view (strings blanked); string-argument rules on arg_view.
    let (code_view, arg_view) = mask_views(content, language);

    for pattern in patterns {
        // Check if pattern applies to this language
        if !pattern.languages.is_empty() && !pattern.languages.iter().any(|l| language.contains(l))
        {
            continue;
        }

        let haystack: &str = if uses_code_view(pattern.id) {
            &code_view
        } else {
            &arg_view
        };

        // Find all matches
        for mat in pattern.regex.find_iter(haystack) {
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

/// Calculate risk score from findings. Quantum-safe findings (Info/QuantumSafe)
/// are excluded from the risk computation - they raise awareness but should not
/// affect the score.
pub fn calculate_risk_score(findings: &[Finding]) -> u32 {
    if findings.is_empty() {
        return 0;
    }

    let total_weight: u32 = findings
        .iter()
        .filter(|f| f.quantum_risk != QuantumRisk::QuantumSafe)
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
    fn test_no_false_positive_in_comments_and_strings() {
        // The NSE class of escalation: crypto terms mentioned only in comments
        // or free-text strings must NOT produce findings.
        // NOTE: the CLI intentionally inventories algorithm tokens that appear in
        // real code and identifiers/config strings (e.g. 'ECDSA_MLDSA'); see
        // test_pqc_service_ts_competitive_baseline. The false-positive class we
        // eliminate here is crypto terms that appear ONLY in comments.
        let cases: &[(&str, &str)] = &[
            ("// legacy crypto.createHash('md5') was removed", "test.js"),
            ("# we no longer use hashlib.md5 here", "test.py"),
            ("/* MD5_Init and RC4 and ECDSA used to live here */", "test.c"),
            ("// ECDSA and DES support was dropped", "test.js"),
            ("x = 1  # RSA.generate is not called", "test.py"),
            ("code(); // TODO migrate blowfish and rc4 later", "test.go"),
        ];
        for (code, file) in cases {
            let lang = detect_language(file);
            let findings = scan_content(code, file, lang);
            assert!(
                findings.is_empty(),
                "expected no findings for {:?}, got {:?}",
                code,
                findings.iter().map(|f| &f.algorithm).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_nse_symbol_inside_string_literal_is_not_flagged() {
        // The exact NSE escalation (ConnMgrFwdFncts.c / AllsecureX_CM_ANET):
        // the C symbol MD5_Init appears both as a real call and inside a log
        // string. Only the real calls may be flagged, never the log messages.
        let code = "\
if (MD5_Init(&ctx) != 1) {\n\
    LOG_INFO(APP, FAILURE, \"Error in MD5_Init\");\n\
    return FAILURE;\n\
}\n\
if (MD5_Update(&ctx, buf, len) != 1) {\n\
    LOG_INFO(APP, FAILURE, \"Error in MD5_Update\");\n\
}\n\
if (MD5_Final(out, &ctx) != 1) {\n\
    LOG_INFO(APP, FAILURE, \"Error in MD5_Final\");\n\
}\n";
        let findings = scan_content(code, "ConnMgrFwdFncts.c", "c");
        let md5_lines: Vec<usize> = findings
            .iter()
            .filter(|f| f.algorithm.contains("MD5"))
            .map(|f| f.line)
            .collect();
        // Exactly the three real calls (lines 1, 5, 8); zero from the log strings.
        assert_eq!(md5_lines, vec![1, 5, 8], "got {:?}", findings.iter().map(|f| (f.line, &f.context)).collect::<Vec<_>>());
    }

    #[test]
    fn test_nse_connmgr_exact_reproduction() {
        // Faithful reproduction of ConnMgrFwdFncts.c from NSE's screenshots.
        // Every "MD5" token is present: the #ifdef macro, three real calls, three
        // log strings, a variable (DHgLenMD5), a comment (/*Verify MD5*/) and a
        // macro (INCOMING_PKT_MD5). Only the three REAL CALLS may be findings.
        let code = r#"
#ifdef _OPEN_SSL_MD5
    LOG_FUNC_IN;
    psIncomingPkt = ( INCOMING_PKT * ) pcaBuf;
    if( MD5_Init(&ctx) != 1)
    {
        LOG_INFO(APP, SUCCESS, "Error in MD5_Init");
        LOG_FUNC_OUT;
        return FAILURE;
    }
    if( MD5_Update(&ctx, (const VOID *) & ( psIncomingPkt->caBufferFromTap ), DHgLenMD5) != 1)
    {
        LOG_INFO(APP, FAILURE, "Error in MD5_Update");
        return FAILURE;
    }
    if( MD5_Final(( UCHAR *)caBuff, &ctx) != 1)
    {
        LOG_INFO(APP, FAILURE, "Error in MD5_Final");
        return FAILURE;
    }
    /*Verify MD5*/
    if( memcmp( caBuff, INCOMING_PKT_MD5(psIncomingPkt), 16 ) != 0 )
    {
        return FAILURE;
    }
#endif
"#;
        let findings = scan_content(code, "ConnMgrFwdFncts.c", "c");
        let lines: Vec<&str> = code.lines().collect();

        // Print exactly which lines were flagged (visible with --nocapture).
        eprintln!("--- MD5 findings ---");
        for f in findings.iter().filter(|f| f.algorithm.contains("MD5")) {
            eprintln!("  line {}: {}", f.line, lines[f.line - 1].trim());
        }

        let md5: Vec<&Finding> = findings.iter().filter(|f| f.algorithm.contains("MD5")).collect();

        // Exactly the three real calls, nothing else.
        assert_eq!(md5.len(), 3, "expected 3 real-call findings, got {}", md5.len());
        for f in &md5 {
            let src = lines[f.line - 1];
            assert!(
                src.contains("MD5_Init(") || src.contains("MD5_Update(") || src.contains("MD5_Final("),
                "finding on a non-call line: {:?}",
                src
            );
            assert!(!src.contains("Error in"), "flagged a log string: {:?}", src);
            assert!(!src.contains("/*"), "flagged a comment: {:?}", src);
            assert!(!src.contains("INCOMING_PKT_MD5"), "flagged a macro name: {:?}", src);
            assert!(!src.contains("#ifdef"), "flagged an #ifdef: {:?}", src);
        }
    }

    #[test]
    fn test_bare_md5_name_never_flagged() {
        // A line whose ONLY crypto content is the bare token "MD5" (identifier,
        // macro, comment, string, or #define) must never be a finding.
        let cases: &[(&str, &str)] = &[
            ("#ifdef _OPEN_SSL_MD5", "f.c"),
            ("int DHgLenMD5 = 16;", "f.c"),
            ("x = INCOMING_PKT_MD5(pkt);", "f.c"),
            ("/* Verify MD5 checksum */", "f.c"),
            ("const label = \"MD5\";", "f.js"),
            ("# MD5 is no longer used", "f.py"),
            ("md5_column = row.md5;", "f.py"),
            ("String MD5 = getName();", "f.java"),
        ];
        for (line, file) in cases {
            let lang = detect_language(file);
            let findings = scan_content(line, file, lang);
            assert!(
                findings.is_empty(),
                "expected NO finding for {:?}, got {:?}",
                line,
                findings.iter().map(|f| (&f.algorithm, f.line)).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_real_call_still_detected_alongside_comment() {
        // A real call on one line, a comment mention on another: exactly one hit.
        let code = "h = hashlib.md5(data)\n# md5 is legacy, remove later\n";
        let findings = scan_content(code, "test.py", "python");
        let md5: Vec<_> = findings.iter().filter(|f| f.algorithm == "MD5").collect();
        assert_eq!(md5.len(), 1, "got {:?}", findings);
        assert_eq!(md5[0].line, 1);
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

    // ============================================================
    // v1.2: C/C++ source-level coverage tests
    // ============================================================

    #[test]
    fn test_c_openssl_rsa() {
        let code = "RSA *r = RSA_new(); RSA_generate_key_ex(r, 2048, e, NULL);";
        let findings = scan_content(code, "test.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-openssl-rsa"),
            "Expected c-openssl-rsa, got: {:?}",
            findings.iter().map(|f| &f.pattern_id).collect::<Vec<_>>());
    }

    #[test]
    fn test_c_openssl_md5() {
        let code = "EVP_MD_CTX *ctx; EVP_DigestInit(ctx, EVP_md5());";
        let findings = scan_content(code, "hash.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-openssl-md5"));
        let md5 = findings.iter().find(|f| f.pattern_id == "c-openssl-md5").unwrap();
        assert_eq!(md5.severity, Severity::Critical);
    }

    #[test]
    fn test_c_openssl_sha1() {
        let code = "EVP_DigestInit(ctx, EVP_sha1());";
        let findings = scan_content(code, "hash.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-openssl-sha1"));
    }

    #[test]
    fn test_c_openssl_aes128() {
        let code = "EVP_CIPHER_CTX_init(&ctx); EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);";
        let findings = scan_content(code, "crypt.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-openssl-aes-128"));
    }

    #[test]
    fn test_c_openssl_3des() {
        let code = "EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);";
        let findings = scan_content(code, "crypt.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-openssl-3des"));
    }

    #[test]
    fn test_c_openssl_rc4() {
        let code = "EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, key, NULL, 1);";
        let findings = scan_content(code, "stream.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-openssl-rc4"));
    }

    #[test]
    fn test_c_openssl_tls_legacy() {
        let code = "SSL_CTX *ctx = SSL_CTX_new(TLSv1_method());";
        let findings = scan_content(code, "tls.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-openssl-tls-legacy"));
    }

    #[test]
    fn test_c_openssl_ec() {
        let code = "EC_KEY *key = EC_KEY_new(); EC_KEY_generate_key(key);";
        let findings = scan_content(code, "ec.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-openssl-ec"));
    }

    #[test]
    fn test_c_mbedtls_rsa() {
        let code = "mbedtls_rsa_context rsa; mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);";
        let findings = scan_content(code, "rsa.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-mbedtls-rsa"));
    }

    #[test]
    fn test_c_mbedtls_md5() {
        let code = "mbedtls_md5_context ctx; mbedtls_md5_init(&ctx);";
        let findings = scan_content(code, "h.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-mbedtls-md5"));
    }

    #[test]
    fn test_c_wolfssl_rsa() {
        let code = "RsaKey k; wc_InitRsaKey(&k, NULL); wc_MakeRsaKey(&k, 2048, e, rng);";
        let findings = scan_content(code, "rsa.cpp", "cpp");
        assert!(findings.iter().any(|f| f.pattern_id == "c-wolfssl-rsa"));
    }

    #[test]
    fn test_c_apple_commoncrypto() {
        let code = "CC_MD5(buf, len, digest);";
        let findings = scan_content(code, "h.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-cc-md5-sha1"));
    }

    #[test]
    fn test_c_windows_cng_legacy() {
        let code = "BCryptOpenAlgorithmProvider(&h, BCRYPT_MD5_ALGORITHM, NULL, 0);";
        let findings = scan_content(code, "win.cpp", "cpp");
        assert!(findings.iter().any(|f| f.pattern_id == "c-cng-legacy"));
    }

    #[test]
    fn test_c_windows_cng_rsa() {
        let code = "BCryptOpenAlgorithmProvider(&h, BCRYPT_RSA_ALGORITHM, NULL, 0);";
        let findings = scan_content(code, "win.cpp", "cpp");
        assert!(findings.iter().any(|f| f.pattern_id == "c-cng-rsa-ec"));
    }

    #[test]
    fn test_c_hardcoded_key() {
        let code = "static const unsigned char aes_key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };";
        let findings = scan_content(code, "key.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-hardcoded-key-buffer"));
    }

    #[test]
    fn test_c_curl_insecure() {
        let code = "curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);";
        let findings = scan_content(code, "net.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "c-curl-insecure"));
    }

    // ============================================================
    // v1.2: Safe / PQC primitive detection tests
    // ============================================================

    #[test]
    fn test_safe_ml_kem() {
        let code = "OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);";
        let findings = scan_content(code, "pq.c", "c");
        let safe = findings.iter().find(|f| f.pattern_id == "safe-ml-kem");
        assert!(safe.is_some());
        assert_eq!(safe.unwrap().quantum_risk, QuantumRisk::QuantumSafe);
        assert_eq!(safe.unwrap().severity, Severity::Info);
    }

    #[test]
    fn test_safe_ml_dsa_kyber_legacy() {
        let code = "use kyber768::*;";
        let findings = scan_content(code, "pq.rs", "rust");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-ml-kem"));
    }

    #[test]
    fn test_safe_aes_256_gcm() {
        let code = "let key = aes256gcm::Key::from_slice(&bytes);";
        let findings = scan_content(code, "aead.rs", "rust");
        // Pattern should match in any of the AES-256 variants
        assert!(findings.iter().any(|f| f.pattern_id == "safe-aes-256"));
    }

    #[test]
    fn test_safe_aes_256_c() {
        let code = "EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);";
        let findings = scan_content(code, "aead.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-aes-256"));
    }

    #[test]
    fn test_safe_chacha20() {
        let code = "EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);";
        let findings = scan_content(code, "aead.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-chacha20-poly1305"));
    }

    #[test]
    fn test_safe_sha256_c() {
        let code = "EVP_DigestInit(ctx, EVP_sha256());";
        let findings = scan_content(code, "h.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-sha256"));
    }

    #[test]
    fn test_safe_sha256_js() {
        let code = "const h = crypto.createHash('sha256').update(data).digest();";
        let findings = scan_content(code, "h.js", "javascript");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-sha256"));
    }

    #[test]
    fn test_safe_argon2() {
        let code = "let hash = argon2::hash_encoded(password, salt, &config).unwrap();";
        let findings = scan_content(code, "auth.rs", "rust");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-argon2"));
    }

    #[test]
    fn test_safe_tls13() {
        let code = "ctx.set_min_proto_version(Some(SslVersion::TLS1_3));";
        let findings = scan_content(code, "tls.rs", "rust");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-tls-1-3"));
    }

    #[test]
    fn test_safe_blake3() {
        let code = "let mut hasher = blake3::Hasher::new(); blake3_update(&mut hasher, b\"data\");";
        let findings = scan_content(code, "h.rs", "rust");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-blake"));
    }

    // ============================================================
    // v1.2: Deep-dive / insecure-configuration tests
    // ============================================================

    #[test]
    fn test_ecb_mode() {
        let code = "Cipher c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");";
        let findings = scan_content(code, "C.java", "java");
        assert!(findings.iter().any(|f| f.pattern_id == "ecb-mode-multilang"));
    }

    #[test]
    fn test_jwt_none() {
        let code = "{\"alg\":\"none\"}";
        let findings = scan_content(code, "jwt.json", "json");
        assert!(findings.iter().any(|f| f.pattern_id == "jwt-none-alg"));
    }

    #[test]
    fn test_tls_verify_disabled_go() {
        let code = "tlsConfig := &tls.Config{InsecureSkipVerify: true}";
        let findings = scan_content(code, "tls.go", "go");
        assert!(findings.iter().any(|f| f.pattern_id == "tls-verify-disabled"));
    }

    // ============================================================
    // v1.2: Score correctness - safe findings must not raise risk
    // ============================================================

    #[test]
    fn test_safe_findings_do_not_inflate_risk() {
        // Only safe findings; risk must stay at 0
        let safe_only = vec![Finding {
            algorithm: "ML-KEM-768".to_string(),
            category: Category::PostQuantum,
            severity: Severity::Info,
            quantum_risk: QuantumRisk::QuantumSafe,
            file_path: "x.c".to_string(),
            line: 1, column: 1,
            context: String::new(),
            recommended_replacement: String::new(),
            migration_effort: "trivial".to_string(),
            pattern_id: "safe-ml-kem".to_string(),
            library_name: None,
            library_version: None,
            key_size: None,
        }];
        assert_eq!(calculate_risk_score(&safe_only), 0,
            "Safe findings must not contribute to risk score");
    }

    // ============================================================
    // v1.2.1: regression tests for word-boundary fixes
    // ============================================================

    #[test]
    fn test_ml_dsa_inside_compound_identifier() {
        // The exact pattern NSE's scan hit on pqc-service.ts:96
        let code = r#"const algorithms = ['RSA3072_DILITHIUM', 'ECDSA_MLDSA'];"#;
        let findings = scan_content(code, "pqc-service.ts", "javascript");
        let ids: Vec<&str> = findings.iter().map(|f| f.pattern_id.as_str()).collect();
        assert!(ids.contains(&"safe-ml-dsa"),
            "safe-ml-dsa should match MLDSA inside ECDSA_MLDSA and DILITHIUM inside RSA3072_DILITHIUM. Got: {:?}", ids);
    }

    #[test]
    fn test_ml_kem_inside_compound_identifier() {
        let code = r#"static int alg = OPENSSL_ALG_MLKEM;"#;
        let findings = scan_content(code, "x.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-ml-kem"),
            "safe-ml-kem should match MLKEM inside OPENSSL_ALG_MLKEM");
    }

    #[test]
    fn test_slh_dsa_compound() {
        let code = "use my_lib::CRYPTO_SLHDSA;";
        let findings = scan_content(code, "h.rs", "rust");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-slh-dsa"));
    }

    #[test]
    fn test_aes_256_compound() {
        let code = "const algo = 'MYAPP_AES_256_GCM';";
        let findings = scan_content(code, "x.ts", "javascript");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-aes-256"));
    }

    #[test]
    fn test_sha256_compound() {
        let code = "kdf := HMAC_SHA256(key, msg)";
        let findings = scan_content(code, "x.go", "go");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-sha256"));
    }

    // ============================================================
    // v1.2.1: competitive-depth pattern tests
    // ============================================================

    #[test]
    fn test_ed25519_modern_classical() {
        let code = "let sig = ed25519_sign(&keypair, msg);";
        let findings = scan_content(code, "sig.rs", "rust");
        let ed = findings.iter().find(|f| f.pattern_id == "modern-classical-ed25519");
        assert!(ed.is_some());
        assert_eq!(ed.unwrap().quantum_risk, QuantumRisk::BrokenBy2030);
        assert_eq!(ed.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn test_x25519_modern_classical() {
        let code = "let shared = X25519::diffie_hellman(&sk, &pk);";
        let findings = scan_content(code, "kex.rs", "rust");
        assert!(findings.iter().any(|f| f.pattern_id == "modern-classical-x25519"));
    }

    #[test]
    fn test_pkcs11_hsm_detected() {
        let code = r#"CK_FUNCTION_LIST_PTR pkcs11 = NULL; C_GenerateKey(...);"#;
        let findings = scan_content(code, "hsm.c", "c");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-pkcs11-hsm"));
    }

    #[test]
    fn test_aws_kms_detected() {
        let code = "const kms = new KMSClient({region}); await kms.GenerateDataKey({...});";
        let findings = scan_content(code, "kms.ts", "javascript");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-cloud-kms"));
    }

    #[test]
    fn test_jws_modern_alg() {
        let code = r#"const token = jwt.sign(payload, key, { algorithm: 'RS256' });"#;
        let findings = scan_content(code, "jwt.js", "javascript");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-jws-modern"));
    }

    #[test]
    fn test_rsa_pkcs1_v15() {
        let code = r#"Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");"#;
        let findings = scan_content(code, "c.java", "java");
        assert!(findings.iter().any(|f| f.pattern_id == "rsa-pkcs1-v15"));
    }

    #[test]
    fn test_java_keystore_jks() {
        let code = r#"KeyStore ks = KeyStore.getInstance("JKS");"#;
        let findings = scan_content(code, "k.java", "java");
        assert!(findings.iter().any(|f| f.pattern_id == "java-keystore-jks"));
    }

    #[test]
    fn test_seeded_csprng_python() {
        let code = "random.seed(42); k = random.randbytes(32)";
        let findings = scan_content(code, "rng.py", "python");
        assert!(findings.iter().any(|f| f.pattern_id == "seeded-csprng"));
    }

    #[test]
    fn test_tls_rsa_cipher_suite() {
        let code = "ssl_ciphers TLS_RSA_WITH_AES_128_GCM_SHA256;";
        let findings = scan_content(code, "nginx.conf", "config");
        // nginx config language is "config"
        let lf = scan_content(code, "tls.go", "go");
        assert!(lf.iter().any(|f| f.pattern_id == "tls-rsa-cipher-suite") ||
            findings.iter().any(|f| f.pattern_id == "tls-rsa-cipher-suite"));
    }

    #[test]
    fn test_pbkdf2_weak_prf() {
        let code = r#"SecretKey k = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");"#;
        let findings = scan_content(code, "k.java", "java");
        assert!(findings.iter().any(|f| f.pattern_id == "pbkdf2-weak-prf"));
    }

    // ============================================================
    // v1.2.1: dashboard-NSE regression test
    // ============================================================

    #[test]
    fn test_pqc_service_ts_competitive_baseline() {
        // Recreates the file fragment from NSE's scan that produced only
        // vulnerable findings. v1.2.1 must surface BOTH vulnerable (ECDSA)
        // and safe (ML-DSA, Dilithium) signals from the same line.
        let code = r#"
            export const PQC_HYBRID_ALGORITHMS = [
              'RSA3072_DILITHIUM',
              'ECDSA_MLDSA',
              'X25519MLKEM768',
            ];
        "#;
        let findings = scan_content(code, "browser/src/main/services/pqc-service.ts", "javascript");
        let ids: std::collections::HashSet<&str> = findings.iter().map(|f| f.pattern_id.as_str()).collect();
        assert!(ids.contains("ecdsa-signature"), "ECDSA pattern should fire");
        assert!(ids.contains("safe-ml-dsa"), "ML-DSA / Dilithium safe-pattern should fire (was the v1.2.0 bug)");
        assert!(ids.contains("safe-pq-hybrid-kx"), "X25519MLKEM768 hybrid pattern should fire");
    }

    #[test]
    fn test_c_code_now_has_coverage() {
        // The regression test for Sameer's report: a C file with OpenSSL crypto
        // must produce findings.
        let code = r#"
            #include <openssl/rsa.h>
            #include <openssl/evp.h>
            int main() {
                RSA *r = RSA_generate_key_ex(2048, e, NULL, NULL);
                EVP_MD_CTX *ctx = EVP_MD_CTX_new();
                EVP_DigestInit(ctx, EVP_sha256());
                EVP_EncryptInit_ex(ctx2, EVP_aes_256_gcm(), NULL, key, iv);
                return 0;
            }
        "#;
        let findings = scan_content(code, "main.c", "c");
        // Expect: c-openssl-rsa (vuln), safe-sha256 (info), safe-aes-256 (info)
        assert!(findings.iter().any(|f| f.pattern_id == "c-openssl-rsa"),
            "C scan must detect OpenSSL RSA");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-sha256"),
            "C scan must detect SHA-256 as quantum-safe");
        assert!(findings.iter().any(|f| f.pattern_id == "safe-aes-256"),
            "C scan must detect AES-256 as quantum-safe");
    }
}

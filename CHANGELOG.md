# Changelog

All notable changes to the AllSecureX Quantum Scanner are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-06-19

### Fixed
- **Word-boundary bug in safe-algorithm patterns.** `safe-ml-dsa`, `safe-ml-kem`,
  `safe-slh-dsa`, `safe-aes-256`, `safe-sha256`, and related patterns no longer
  miss matches inside compound identifiers like `ECDSA_MLDSA`, `OPENSSL_ALG_MLKEM`,
  `MYORG_AES_256_GCM`, or `HMAC_SHA256`. The previous `\b` anchor failed when the
  algorithm token was joined to surrounding text by an underscore (`_` is a word
  character in regex). Reported on NSE's source-code scan of `pqc-service.ts`.

### Added
- **Modern-classical curve detection** (`modern-classical-ed25519`,
  `modern-classical-x25519`, `modern-classical-curve448`). Ed25519, X25519,
  and Curve448 are well-engineered modern primitives but vulnerable to Shor's
  algorithm. Reported as Medium severity, `BrokenBy2030`, with migration paths
  to ML-DSA / ML-KEM and hybrid posture guidance (X25519MLKEM768).
- **HSM / PKCS#11 detection** (`safe-pkcs11-hsm`). Recognises PKCS#11 C API
  calls and major HSM brands (SoftHSM, YubiHSM, AWS CloudHSM, nCipher / nShield,
  Thales Luna, Utimaco, SafeNet). Reported as Info / quantum-safe.
- **Cloud KMS detection** (`safe-cloud-kms`). AWS KMS, Azure Key Vault, GCP KMS,
  HashiCorp Vault.
- **JWS modern algorithm detection** (`safe-jws-modern`). RS256/RS384/RS512,
  PS256/PS384/PS512, ES256/ES384/ES512, EdDSA, HS256/HS384/HS512.
- **JWS weak-secret heuristic** (`jws-weak-secret`). Flags `jwt.sign(payload, "secret")`
  and similar dictionary-secret patterns.
- **RSA PKCS#1 v1.5 padding** (`rsa-pkcs1-v15`). Bleichenbacher / ROBOT
  attack surface (CVE-2018-12404).
- **Java legacy KeyStore** (`java-keystore-jks`). JKS / JCEKS use MD5 + SHA-1 +
  custom XOR (CVE-2017-10356); migration to PKCS12.
- **Self-rolled XOR encryption** (`self-rolled-xor`). Heuristic for homebrew
  XOR-based "encryption" patterns.
- **Seeded / deterministic CSPRNG** (`seeded-csprng`). `random.seed(42)`,
  `SecureRandom.setSeed`, `srand(time(0))`, `new Random(42)`.
- **TLS_RSA cipher suite detection** (`tls-rsa-cipher-suite`). No forward secrecy,
  ROBOT-vulnerable.
- **TLS CBC cipher suite detection** (`tls-cbc-mac-then-encrypt`). Lucky13
  (CVE-2013-0169) and BEAST.
- **PBKDF2 with weak PRF** (`pbkdf2-weak-prf`). PBKDF2WithHmacSHA1, etc.
- **Certificate pinning bypass** (`cert-pin-bypass`). Empty `checkServerTrusted`,
  always-true hostname verifiers.

### Changed
- **CHANGELOG.md** added to the public repository. Versions 1.0.0 onward are
  reconstructed from git tag annotations.
- **52 unit tests** (up from 36 in v1.2.0). Regression test
  `test_pqc_service_ts_competitive_baseline` covers the exact NSE finding.

### Backend
- Lambda `scanner-api` now persists `quantum_safe_count`, `vulnerable_count`,
  and `quantum_safe_algorithms[]` to the report.json in S3. Backwards-compatible
  for v1.1.x and v1.2.0 clients (derives missing fields from findings array).
  Audit-ledger entries include safe-finding counts.

## [1.2.0] - 2026-06-19

### Added
- **C / C++ source-level coverage** across OpenSSL / libcrypto, mbedTLS, wolfSSL,
  Apple CommonCrypto, and Windows CNG / BCrypt. 28 new patterns covering RSA,
  ECDSA / ECDH, DH, DSA, MD5, SHA-1, 3DES / DES, RC4, Blowfish / IDEA / CAST,
  AES-128, ECB mode, legacy TLS methods, certificate verification disabled,
  hardcoded key buffers, CURL insecure verify.
- **Quantum-safe / PQC primitive reporting.** 13 patterns reported as Info /
  QuantumSafe: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205),
  liboqs, hybrid PQ TLS KX, AES-256, ChaCha20-Poly1305, SHA-256 / 384 / 512,
  SHA-3, HKDF, Argon2, bcrypt / scrypt, BLAKE2 / 3, TLS 1.3.
- **Deep-dive cross-language patterns:** ECB mode, weak PBKDF2 iteration count
  (OWASP 2023), `InsecureSkipVerify` / `rejectUnauthorized:false`, JWT
  `alg:none`, static IV / nonce.
- **Schema additions** (backward compatible): `summary.vulnerable_count`,
  `summary.quantum_safe_count`, `summary.quantum_safe_algorithms[]`.

### Changed
- Crypto Agility Score excludes safe findings from risk math.
- CLI output: new `QUANTUM-SAFE` line in summary box, green "Quantum-safe
  primitives detected" panel listing distinct safe algorithms.

### Citations
- NIST FIPS 203 / 204 / 205 (Aug 2024)
- NIST SP 800-131A Rev 3, NIST IR 8413
- RFC 7465 (RC4), RFC 8996 (TLS 1.0 / 1.1)
- Wang & Yu 2004 (MD5), SHAttered 2017 (SHA-1)
- OWASP 2023 (PBKDF2 iter), Mosca's theorem, CNSA 2.0

## [1.1.4] - 2026-06-14

### Fixed
- Banner copyright year now uses `chrono::Utc::now()` so the next calendar year
  does not require a release just to fix the printed year (customer reported
  "2025" after the rollover).

## [1.1.3] - 2026-05-26

### Added
- Initial production-ready C / C++ file extension scanning (file walker level;
  pattern-level coverage was narrow).
- Local report cache at `~/.quantum-scanner/scans/`.
- Auditor Evidence Pack scaffolding.

## [1.0.3] - 2026-05-26

### Fixed
- Dockerfile ENTRYPOINT and Homebrew formula `bin.install` paths.

## [1.0.2] - 2026-05-26

### Changed
- Initial cross-platform binary release pipeline (Linux x86_64, macOS arm64,
  Windows x86_64).

## [1.0.1] - 2026-05-25

### Added
- Homebrew tap formula template (`homebrew/quantumvault.rb.tmpl`).

## [1.0.0] - 2026-05-25

### Added
- Initial public release of `quantum-scanner` CLI.
- Pattern library covering RSA, ECDSA / ECDH, DH, DSA, MD5, SHA-1, AES-128,
  3DES, RC4, Blowfish, weak random, hardcoded keys, RSA certificates, ElGamal,
  TLS legacy versions across Python, JavaScript / TypeScript, Java, Go, Rust,
  C#, Ruby, PHP.
- Cloud sync to AllSecureX QuantumVault dashboard.
- npm distribution as `allsecurex-quantum-scanner`.
- Homebrew distribution as `allsecurex/tap/quantum-scanner`.

[1.2.1]: https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/tag/v1.2.1
[1.2.0]: https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/tag/v1.2.0
[1.1.4]: https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/tag/v1.1.4
[1.1.3]: https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/tag/v1.1.3
[1.0.3]: https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/tag/v1.0.3
[1.0.2]: https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/tag/v1.0.2
[1.0.1]: https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/tag/v1.0.1
[1.0.0]: https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/tag/v1.0.0

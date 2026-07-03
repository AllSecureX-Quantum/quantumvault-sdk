//! Comprehensive cryptographic detection corpus.
//!
//! Executable, exhaustive test corpus covering every algorithm family the
//! scanner knows about, across multiple languages and native libraries. It
//! exists to guarantee two properties at once:
//!
//!   1. REAL cryptographic usage is detected (recall).
//!   2. Crypto terms that appear only in COMMENTS, in free-text/log STRINGS, in
//!      unrelated identifiers, or as safe algorithms are NEVER flagged as a
//!      vulnerability (precision / zero false positives).
//!
//! Buckets:
//!   * MUST_DETECT      - real calls, one or more per family/language/library.
//!   * MUST_BE_SILENT   - comments, prose strings, unrelated words, macros and
//!                        anchored-family identifiers: expect ZERO findings.
//!   * SAFE_NOT_WEAK    - modern/PQC algorithms: must produce NO broken/vulnerable
//!                        finding (safe informational findings are fine).
//!
//! Note on intended inventory behaviour: for the broad "generic" rules
//! (ECDSA, RC4, Blowfish, ElGamal, Ed25519, X25519) the scanner deliberately
//! inventories the algorithm token when it appears as a code identifier or a
//! whitespace-free config value (e.g. the compound identifier 'ECDSA_MLDSA').
//! Those are NOT false positives, so the SILENT bucket uses only the genuine
//! false-positive shapes: comments and whitespace-bearing prose strings (plus
//! identifiers for the strictly anchored families such as MD5/SHA-1/RSA).

#![cfg(test)]

use crate::patterns::{detect_language, scan_content, Finding, QuantumRisk};

fn scan(code: &str, file: &str) -> Vec<Finding> {
    scan_content(code, file, detect_language(file))
}

fn vulnerable(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| matches!(f.quantum_risk, QuantumRisk::BrokenNow | QuantumRisk::BrokenBy2030))
        .collect()
}

// ===========================================================================
// BUCKET A - MUST DETECT (real usage): (code, file, expected algorithm substr)
// ===========================================================================
const MUST_DETECT: &[(&str, &str, &str)] = &[
    // ---- RSA (quantum-vulnerable) ----
    ("priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "a.py", "RSA"),
    ("const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });", "a.js", "RSA"),
    ("KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");", "a.java", "RSA"),
    ("RSA_generate_key_ex(rsa, 2048, bne, NULL);", "a.c", "RSA"),
    ("mbedtls_rsa_gen_key(&rsa, f_rng, p_rng, 2048, 65537);", "a.c", "RSA"),
    ("ret = wc_MakeRsaKey(&key, 2048, 65537, &rng);", "a.c", "RSA"),
    ("BCryptOpenAlgorithmProvider(&h, BCRYPT_RSA_ALGORITHM, NULL, 0);", "a.c", "RSA"),
    // ---- ECC / ECDSA / ECDH (quantum-vulnerable) ----
    ("sk = ec.generate_private_key(ec.SECP256R1())", "a.py", "ECDSA"),
    ("Signature s = Signature.getInstance(\"SHA256withECDSA\");", "a.java", "ECDSA"),
    ("EC_KEY_generate_key(eckey);", "a.c", "ECDSA"),
    ("mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, hlen, rng, p);", "a.c", "ECDSA"),
    ("ECDH_compute_key(secret, len, peer, key, NULL);", "a.c", "ECDSA"),
    // ---- Finite-field Diffie-Hellman (quantum-vulnerable) ----
    ("KeyAgreement ka = KeyAgreement.getInstance(\"DH\");", "a.java", "Diffie-Hellman"),
    ("DH_generate_key(dh);", "a.c", "DH"),
    // ---- DSA (quantum-vulnerable) ----
    ("KeyPairGenerator.getInstance(\"DSA\");", "a.java", "DSA"),
    ("DSA_generate_key(dsa);", "a.c", "DSA"),
    // ---- ElGamal (quantum-vulnerable) ----
    ("cipher = ElGamal.new(key)", "a.py", "ElGamal"),
    // ---- Ed25519 / X25519 (classically strong, quantum-vulnerable) ----
    ("sig = ed25519.sign(sk, message)", "a.py", "Ed25519"),
    ("let shared = X25519::diffie_hellman(&sk, &pk);", "a.rs", "X25519"),
    // ---- MD5 (broken) ----
    ("h = hashlib.md5(payload).hexdigest()", "a.py", "MD5"),
    ("const hash = crypto.createHash('md5').update(d).digest('hex');", "a.js", "MD5"),
    ("MessageDigest md = MessageDigest.getInstance(\"MD5\");", "a.java", "MD5"),
    ("if (MD5_Init(&ctx) != 1) return -1;", "a.c", "MD5"),
    ("mbedtls_md5_starts(&ctx);", "a.c", "MD5"),
    ("CC_MD5(data, (CC_LONG)len, digest);", "a.c", "MD5"),
    // ---- SHA-1 (broken for signatures) ----
    ("h = hashlib.sha1(data).digest()", "a.py", "SHA-1"),
    ("SHA1_Update(&c, buf, n);", "a.c", "SHA-1"),
    // ---- 3DES / DES (broken) ----
    ("Cipher c = Cipher.getInstance(\"DESede/CBC/PKCS5Padding\");", "a.java", "3DES"),
    ("EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);", "a.c", "3DES"),
    // ---- RC4 (broken) ----
    ("cipher = ARC4.new(key)", "a.py", "RC4"),
    ("EVP_CipherInit_ex(ctx, EVP_rc4(), NULL, key, NULL, 1);", "a.c", "RC4"),
    // ---- Blowfish (weak) ----
    ("c = Blowfish.new(key, Blowfish.MODE_CBC, iv)", "a.py", "Blowfish"),
    // ---- ECB mode (broken construction) ----
    ("Cipher c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");", "a.java", "ECB"),
    ("cipher = AES.new(key, AES.MODE_ECB)", "a.py", "ECB"),
    // ---- Legacy TLS (broken protocol) ----
    ("ctx = SSL.Context(SSL.SSLv3_METHOD)", "a.py", "TLS"),
    ("ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)", "a.py", "TLS"),
    // ---- Weak PRNG for security ----
    ("token = str(Math.random())", "a.js", "PRNG"),
    ("int r = rand();", "a.c", "PRNG"),
    // ---- Hardcoded secret ----
    ("secret_key = \"aB3xY7zK9pQ2mN5rT8wL\"", "a.py", "Hardcoded"),
    // ---- RSA legacy certificate ----
    ("-----BEGIN RSA PRIVATE KEY-----", "a.pem", "RSA"),
];

// ===========================================================================
// BUCKET B - MUST BE SILENT (false-positive shapes): expect ZERO findings
// ===========================================================================
const MUST_BE_SILENT: &[(&str, &str)] = &[
    // ---- Line / block comments mentioning algorithms ----
    ("// TODO: remove MD5 and SHA1 and migrate RSA someday", "a.js"),
    ("# switched from 3DES to AES; dropped RC4 and Blowfish", "a.py"),
    ("/* This module historically used ECDSA, DH and DSA */", "a.c"),
    ("<!-- legacy: MD5 checksum of payload -->", "a.html"),
    ("-- old DES-encrypted column, now AES", "a.sql"),
    (";; uses RSA and ElGamal historically", "a.clj"),
    ("/// Doc: this replaces the old Blowfish cipher", "a.rs"),
    // ---- The NSE class: crypto SYMBOL inside a free-text / log STRING ----
    ("LOG_INFO(APP, FAILURE, \"Error in MD5_Init\");", "a.c"),
    ("printf(\"MD5_Update failed for the buffer\\n\");", "a.c"),
    ("fprintf(stderr, \"SHA1_Final returned error\\n\");", "a.c"),
    ("throw new Error(\"RSA key generation failed\");", "a.js"),
    ("return \"ECDSA signature verification failed\";", "a.java"),
    ("log.info(\"disabled SHA1 and MD5 hashing everywhere\")", "a.py"),
    ("const msg = \"we no longer support Blowfish or DES here\";", "a.js"),
    ("panic!(\"DH_generate_key failed at startup\");", "a.rs"),
    ("System.out.println(\"Falling back from RC4 to AES-256\");", "a.java"),
    // ---- Unrelated English words that merely contain algorithm letters ----
    ("int candidates = countNodes();", "a.c"),
    ("String description = user.getDisplayName();", "a.java"),
    ("let designation = role.title;", "a.js"),
    ("desktop_mode = True", "a.py"),
    ("addresses = fetch_all()", "a.py"),
    // ---- Identifiers for STRICTLY anchored families (MD5/SHA-1/RSA/DES-symbol)
    ("int DHgLenMD5 = 16;", "a.c"),
    ("x = INCOMING_PKT_MD5(pkt);", "a.c"),
    ("#ifdef _OPEN_SSL_MD5", "a.c"),
    ("record.md5sum = compute_checksum();", "a.py"),
    ("int sha1Count = table.size();", "a.java"),
    ("rsaWrapperFactory.init();", "a.java"),
    ("var desiredCount = 3;", "a.js"),
    // ---- Placeholders must not be treated as hardcoded secrets ----
    ("api_key = \"YOUR_API_KEY_HERE\"", "a.py"),
    ("secret_key = \"changeme\"", "a.py"),
    ("private_key = \"<insert-key-here>\"", "a.py"),
];

// ===========================================================================
// BUCKET C - SAFE / PQC: must produce NO broken-or-vulnerable finding
// ===========================================================================
const SAFE_NOT_WEAK: &[(&str, &str)] = &[
    ("digest = hashlib.sha256(data).hexdigest()", "a.py"),
    ("const h = crypto.createHash('sha512').update(d).digest();", "a.js"),
    ("MessageDigest md = MessageDigest.getInstance(\"SHA-256\");", "a.java"),
    ("EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);", "a.c"),
    ("out = EVP_sha3_256();", "a.c"),
    ("c = crypto.createCipheriv('aes-256-gcm', key, iv)", "a.js"),
    ("EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);", "a.c"),
    ("cipher = ChaCha20Poly1305(key)", "a.py"),
    ("h = argon2.PasswordHasher().hash(password)", "a.py"),
    ("hashed = bcrypt.hashpw(pw, bcrypt.gensalt())", "a.py"),
    ("key = HKDF(algorithm=hashes.SHA256(), length=32).derive(ikm)", "a.py"),
    ("kem = ML_KEM_768.keygen()", "a.py"),
    ("sig = ML_DSA_65.sign(sk, msg)", "a.py"),
    ("s = SLH_DSA_SHA2_128s.sign(sk, msg)", "a.py"),
    ("OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);", "a.c"),
    ("suite = \"TLS_AES_256_GCM_SHA384\"", "a.py"),
    ("let group = \"X25519MLKEM768\";", "a.rs"),
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn corpus_must_detect_real_usage() {
    let mut failures = Vec::new();
    for (code, file, expect) in MUST_DETECT {
        let findings = scan(code, file);
        let hit = findings
            .iter()
            .any(|f| f.algorithm.to_lowercase().contains(&expect.to_lowercase()));
        if !hit {
            failures.push(format!(
                "  MISS  [{}] expected {:?} in {:?}; got {:?}",
                file,
                expect,
                code,
                findings.iter().map(|f| f.algorithm.as_str()).collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} MUST_DETECT case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn corpus_must_be_silent_zero_false_positives() {
    let mut failures = Vec::new();
    for (code, file) in MUST_BE_SILENT {
        let findings = scan(code, file);
        if !findings.is_empty() {
            failures.push(format!(
                "  FALSE POSITIVE [{}] {:?} -> {:?}",
                file,
                code,
                findings
                    .iter()
                    .map(|f| format!("{}@{}", f.algorithm, f.pattern_id))
                    .collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} false positive(s) detected:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn corpus_safe_algorithms_not_flagged_vulnerable() {
    let mut failures = Vec::new();
    for (code, file) in SAFE_NOT_WEAK {
        let findings = scan(code, file);
        let vulns = vulnerable(&findings);
        if !vulns.is_empty() {
            failures.push(format!(
                "  WRONGLY FLAGGED [{}] {:?} -> {:?}",
                file,
                code,
                vulns.iter().map(|f| format!("{}@{}", f.algorithm, f.pattern_id)).collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} safe case(s) flagged as vulnerable:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Coverage summary (visible with --nocapture).
#[test]
fn corpus_summary() {
    eprintln!(
        "crypto corpus: {} must-detect, {} must-be-silent, {} safe-not-weak = {} total cases",
        MUST_DETECT.len(),
        MUST_BE_SILENT.len(),
        SAFE_NOT_WEAK.len(),
        MUST_DETECT.len() + MUST_BE_SILENT.len() + SAFE_NOT_WEAK.len()
    );
}

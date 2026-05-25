//! Certificate types — TbsCertificate (the unsigned body), Certificate
//! (TBS + signature), and a fluent builder for issuance.

use std::fs;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Duration, Utc};
use quantumvault_core::api::sign as core_sign;
use quantumvault_core::Config;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{CaError, Result};
use crate::keys::{parse_algorithm, security_level_for, wire_name, CaSigningKey, CaVerifyingKey};
use crate::name::DistinguishedName;

/// On-disk format version of certificate JSON files.
pub const CERT_VERSION: u8 = 1;

/// Standard key usage flags (RFC 5280 §4.2.1.3, subset).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyUsage {
    /// `digitalSignature` — sign data / authenticate.
    DigitalSignature,
    /// `keyEncipherment` — wrap symmetric keys.
    KeyEncipherment,
    /// `keyAgreement` — KEM / key-exchange.
    KeyAgreement,
    /// `keyCertSign` — sign other certificates (CA only).
    KeyCertSign,
    /// `cRLSign` — sign certificate revocation lists.
    CrlSign,
    /// Server authentication (extended-key-usage style).
    ServerAuth,
    /// Client authentication.
    ClientAuth,
    /// Code signing.
    CodeSigning,
    /// Email protection.
    EmailProtection,
}

/// Subject public key carried by the certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubjectPublicKey {
    /// Algorithm name (e.g. `"ML-DSA-65"`).
    pub algorithm: String,
    /// Base64-encoded raw verifying-key bytes.
    pub bytes: String,
    /// Subject's key identifier (UUID).
    pub key_id: String,
}

/// The TBS ("to-be-signed") portion of a certificate — everything that
/// the issuer's ML-DSA signature covers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TbsCertificate {
    /// Format version.
    pub version: u8,
    /// Serial number (16 hex chars, 64 random bits).
    pub serial: String,
    /// Subject Distinguished Name.
    pub subject: DistinguishedName,
    /// Issuer Distinguished Name (matches some CA's subject).
    pub issuer: DistinguishedName,
    /// Subject's public key.
    pub subject_public_key: SubjectPublicKey,
    /// Validity window — not-before (inclusive).
    pub not_before: DateTime<Utc>,
    /// Validity window — not-after (inclusive).
    pub not_after: DateTime<Utc>,
    /// True if this cert is allowed to sign other certs.
    pub is_ca: bool,
    /// Maximum number of intermediate CAs allowed beneath this one.
    /// `None` for non-CA or for unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_length: Option<u8>,
    /// Key-usage extensions (`digital_signature`, `key_cert_sign`, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_usage: Vec<KeyUsage>,
    /// Subject Alternative Names (DNS, IP, URI, email).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub san: Vec<String>,
    /// Authority key identifier — the issuer's verifying-key id.
    pub authority_key_id: String,
    /// Subject key identifier — same as `subject_public_key.key_id`.
    pub subject_key_id: String,
}

/// Issuer's signature block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureBlock {
    /// Algorithm used (`"ML-DSA-65"`).
    pub algorithm: String,
    /// Base64-encoded ML-DSA signature over `tbs` (canonical JSON).
    pub bytes: String,
}

/// A signed certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Certificate {
    /// The TBS body.
    pub tbs: TbsCertificate,
    /// Issuer's signature.
    pub signature: SignatureBlock,
}

impl Certificate {
    /// Persist to a file as pretty-printed JSON.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load from a file.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path)?;
        let c: Self = serde_json::from_str(&s)?;
        if c.tbs.version != CERT_VERSION {
            return Err(CaError::UnsupportedVersion(c.tbs.version));
        }
        Ok(c)
    }

    /// Verify the signature on this certificate against a supplied
    /// issuer verifying key. Does NOT check chain / expiry — see
    /// [`crate::verify_chain`] for full chain verification.
    pub fn verify_signature_with(&self, issuer_vk: &CaVerifyingKey) -> Result<bool> {
        let algo = parse_algorithm(&self.signature.algorithm)?;
        let signed_input = canonical_tbs_bytes(&self.tbs)?;
        let sig_bytes = B64.decode(&self.signature.bytes)?;
        let core_sig = quantumvault_core::Signature {
            bytes: sig_bytes,
            algorithm: algo,
            key_id: self.tbs.authority_key_id.clone(),
            signed_at: 0,
        };
        let cfg = Config::builder()
            .security_level(security_level_for(algo))
            .build()?;
        Ok(quantumvault_core::api::verify::verify_signature(
            &signed_input,
            &core_sig,
            issuer_vk.core(),
            &cfg,
        )?)
    }

    /// Return the SHA-3-256 fingerprint of the certificate (as hex).
    /// Useful for trust-anchor pinning.
    pub fn fingerprint(&self) -> Result<String> {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(serde_json::to_vec(self)?);
        let mut out = String::with_capacity(64);
        for b in h.finalize() {
            use std::fmt::Write;
            write!(&mut out, "{:02x}", b).expect("write to string");
        }
        Ok(out)
    }
}

/// Fluent builder for unsigned certificates. Call `.self_sign()` to
/// produce a self-signed root, or `.sign_with(parent_sk, parent_cert)`
/// to issue a child cert from a CA's signing key.
pub struct CertificateBuilder {
    subject: DistinguishedName,
    subject_public_key: SubjectPublicKey,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    is_ca: bool,
    path_length: Option<u8>,
    key_usage: Vec<KeyUsage>,
    san: Vec<String>,
}

impl CertificateBuilder {
    /// Start building a new certificate for `subject`, binding to
    /// `subject_verifying_key`.
    pub fn new(subject: DistinguishedName, subject_verifying_key: &CaVerifyingKey) -> Self {
        Self {
            subject,
            subject_public_key: SubjectPublicKey {
                algorithm: subject_verifying_key.algorithm().to_string(),
                bytes: B64.encode(subject_verifying_key.bytes()),
                key_id: subject_verifying_key.key_id().to_string(),
            },
            not_before: Utc::now(),
            not_after: Utc::now() + Duration::days(365),
            is_ca: false,
            path_length: None,
            key_usage: Vec::new(),
            san: Vec::new(),
        }
    }

    /// Mark this certificate as a CA. The path-length parameter is the
    /// maximum chain depth beneath it (None = unlimited).
    pub fn ca(mut self, path_length: Option<u8>) -> Self {
        self.is_ca = true;
        self.path_length = path_length;
        // CAs MUST have key_cert_sign in their key-usage block.
        if !self.key_usage.contains(&KeyUsage::KeyCertSign) {
            self.key_usage.push(KeyUsage::KeyCertSign);
        }
        self
    }

    /// Set the validity window.
    pub fn validity(mut self, not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }

    /// Validity window: from now to `now + days`.
    pub fn validity_days(self, days: i64) -> Self {
        let now = Utc::now();
        self.validity(now, now + Duration::days(days))
    }

    /// Append a key-usage flag.
    pub fn with_key_usage(mut self, u: KeyUsage) -> Self {
        if !self.key_usage.contains(&u) {
            self.key_usage.push(u);
        }
        self
    }

    /// Append a SAN entry (e.g. `"DNS:api.example.com"` or
    /// `"IP:10.0.0.1"`).
    pub fn with_san(mut self, san: impl Into<String>) -> Self {
        self.san.push(san.into());
        self
    }

    /// Issue as a self-signed certificate (root CA case).
    pub fn self_sign(self, signing_key: &CaSigningKey) -> Result<Certificate> {
        // The signer's verifying-key id must match the subject_public_key
        // for a self-sign to make sense.
        let key_id = signing_key.core().key_id.clone();
        let tbs = TbsCertificate {
            version: CERT_VERSION,
            serial: random_serial(),
            subject: self.subject.clone(),
            issuer: self.subject.clone(), // self-issued
            subject_public_key: self.subject_public_key.clone(),
            not_before: self.not_before,
            not_after: self.not_after,
            is_ca: self.is_ca,
            path_length: self.path_length,
            key_usage: self.key_usage,
            san: self.san,
            authority_key_id: key_id.clone(),
            subject_key_id: self.subject_public_key.key_id.clone(),
        };
        sign_tbs(tbs, signing_key)
    }

    /// Issue as a child certificate signed by `parent_signing_key` whose
    /// matching CA cert is `parent_cert`.
    ///
    /// The parent must be a CA and the parent's signature must verify
    /// with the supplied signing key's *paired* verifying key — that's
    /// the caller's responsibility (we don't have access to the
    /// verifying key here; the safer path is via the CLI which loads
    /// both).
    pub fn sign_with(
        self,
        parent_signing_key: &CaSigningKey,
        parent_cert: &Certificate,
    ) -> Result<Certificate> {
        if !parent_cert.tbs.is_ca {
            return Err(CaError::NotACa(parent_cert.tbs.subject.to_display()));
        }
        let tbs = TbsCertificate {
            version: CERT_VERSION,
            serial: random_serial(),
            subject: self.subject,
            issuer: parent_cert.tbs.subject.clone(),
            subject_public_key: self.subject_public_key.clone(),
            not_before: self.not_before,
            not_after: self.not_after,
            is_ca: self.is_ca,
            path_length: self.path_length,
            key_usage: self.key_usage,
            san: self.san,
            authority_key_id: parent_signing_key.core().key_id.clone(),
            subject_key_id: self.subject_public_key.key_id.clone(),
        };
        sign_tbs(tbs, parent_signing_key)
    }
}

// =====================================================================
// Internal: TBS canonicalisation + sign
// =====================================================================

fn sign_tbs(tbs: TbsCertificate, signing_key: &CaSigningKey) -> Result<Certificate> {
    let signed_input = canonical_tbs_bytes(&tbs)?;
    let core_alg = signing_key.core().algorithm;
    let cfg = Config::builder()
        .security_level(security_level_for(core_alg))
        .build()?;
    let core_sig = core_sign::sign_message(&signed_input, signing_key.core(), &cfg)?;
    Ok(Certificate {
        tbs,
        signature: SignatureBlock {
            algorithm: wire_name(core_alg).into(),
            bytes: B64.encode(&core_sig.bytes),
        },
    })
}

/// Canonical-JSON encoding of a TBS for signing. Uses pretty + sorted
/// key ordering via `serde_json::to_vec_pretty` (which preserves serde
/// struct field order, and is stable across runs).
pub(crate) fn canonical_tbs_bytes(tbs: &TbsCertificate) -> Result<Vec<u8>> {
    serde_json::to_vec(tbs).map_err(Into::into)
}

fn random_serial() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(16);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).expect("write to string");
    }
    s
}

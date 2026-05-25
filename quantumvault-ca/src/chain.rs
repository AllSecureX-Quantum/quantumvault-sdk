//! Chain-verification — walks leaf → intermediate(s) → root, verifying
//! each link's signature and the entire chain's time bounds.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use quantumvault_core::Config;

use crate::cert::{canonical_tbs_bytes, Certificate};
use crate::error::{CaError, Result};
use crate::keys::{parse_algorithm, security_level_for};

/// Report from a successful chain verification.
#[derive(Debug, Clone)]
pub struct ChainReport {
    /// True if every link in the chain checked out.
    pub valid: bool,
    /// Number of certificates inspected (leaf + intermediates + root).
    pub depth: usize,
    /// SHA-3-256 fingerprint of the root that anchored the chain.
    pub root_fingerprint: String,
    /// Subject DN of the leaf.
    pub leaf_subject: String,
}

/// Verify a certificate chain.
///
/// `chain` must be ordered **leaf first**, ending in a CA whose
/// fingerprint matches one of the `trust_anchors` (typically a single
/// self-signed root).
///
/// Each step checks:
/// 1. The cert's signature against the issuer's `subject_public_key`.
/// 2. The cert is within its validity window (with no leeway).
/// 3. Intermediate certs are flagged `is_ca=true`.
/// 4. Path-length constraints are honoured.
/// 5. The chain terminates in an entry whose fingerprint appears in
///    `trust_anchors` — that's the trust anchor.
pub fn verify_chain(chain: &[Certificate], trust_anchors: &[String]) -> Result<ChainReport> {
    if chain.is_empty() {
        return Err(CaError::MalformedCertificate("chain is empty".into()));
    }
    let now = Utc::now();

    for cert in chain {
        if cert.tbs.version != crate::CERT_VERSION {
            return Err(CaError::UnsupportedVersion(cert.tbs.version));
        }
        if now < cert.tbs.not_before {
            return Err(CaError::NotYetValid(cert.tbs.not_before.to_rfc3339()));
        }
        if now > cert.tbs.not_after {
            return Err(CaError::Expired(cert.tbs.not_after.to_rfc3339()));
        }
    }

    // Walk pairs: chain[i] is signed by chain[i+1]'s subject key.
    let mut intermediates_seen: u32 = 0;
    for i in 0..chain.len() - 1 {
        let child = &chain[i];
        let parent = &chain[i + 1];

        // The parent must be a CA.
        if !parent.tbs.is_ca {
            return Err(CaError::NotACa(parent.tbs.subject.to_display()));
        }
        // The child's issuer DN must match the parent's subject DN.
        if child.tbs.issuer != parent.tbs.subject {
            return Err(CaError::IssuerMismatch);
        }
        // Path-length constraint: parent.path_length is the max number
        // of intermediates between parent and a leaf. Each intermediate
        // we've seen below `parent` consumes one. (parent's own slot is
        // free.)
        if let Some(max) = parent.tbs.path_length {
            if i as u32 > max as u32 {
                return Err(CaError::PathLengthExceeded(parent.tbs.subject.to_display()));
            }
        }
        if child.tbs.is_ca {
            intermediates_seen += 1;
        }

        // Verify the child's signature using the parent's subject_public_key.
        let algo = parse_algorithm(&child.signature.algorithm)?;
        let parent_pk_bytes = B64.decode(&parent.tbs.subject_public_key.bytes)?;
        let parent_vk = quantumvault_core::VerifyingKey::new(
            parent_pk_bytes,
            algo,
            parent.tbs.subject_public_key.key_id.clone(),
        );
        let sig_bytes = B64.decode(&child.signature.bytes)?;
        let core_sig = quantumvault_core::Signature {
            bytes: sig_bytes,
            algorithm: algo,
            key_id: child.tbs.authority_key_id.clone(),
            signed_at: 0,
        };
        let cfg = Config::builder()
            .security_level(security_level_for(algo))
            .build()?;
        let signed_input = canonical_tbs_bytes(&child.tbs)?;
        let ok = quantumvault_core::api::verify::verify_signature(
            &signed_input,
            &core_sig,
            &parent_vk,
            &cfg,
        )?;
        if !ok {
            return Err(CaError::SignatureInvalid);
        }
    }

    // Verify the root is self-signed AND its fingerprint is a trust anchor.
    let root = chain.last().unwrap();
    if root.tbs.issuer != root.tbs.subject {
        return Err(CaError::MalformedCertificate(
            "final chain element is not a self-signed root".into(),
        ));
    }
    {
        // Verify the root's own signature against its embedded
        // subject_public_key (self-sign check).
        let algo = parse_algorithm(&root.signature.algorithm)?;
        let pk_bytes = B64.decode(&root.tbs.subject_public_key.bytes)?;
        let vk = quantumvault_core::VerifyingKey::new(
            pk_bytes,
            algo,
            root.tbs.subject_public_key.key_id.clone(),
        );
        let sig_bytes = B64.decode(&root.signature.bytes)?;
        let core_sig = quantumvault_core::Signature {
            bytes: sig_bytes,
            algorithm: algo,
            key_id: root.tbs.authority_key_id.clone(),
            signed_at: 0,
        };
        let cfg = Config::builder()
            .security_level(security_level_for(algo))
            .build()?;
        let signed_input = canonical_tbs_bytes(&root.tbs)?;
        let ok =
            quantumvault_core::api::verify::verify_signature(&signed_input, &core_sig, &vk, &cfg)?;
        if !ok {
            return Err(CaError::SignatureInvalid);
        }
    }
    let root_fp = root.fingerprint()?;
    if !trust_anchors.contains(&root_fp) {
        return Err(CaError::UntrustedChain);
    }

    let _ = intermediates_seen; // currently informational
    Ok(ChainReport {
        valid: true,
        depth: chain.len(),
        root_fingerprint: root_fp,
        leaf_subject: chain[0].tbs.subject.to_display(),
    })
}

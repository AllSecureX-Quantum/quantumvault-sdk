//! Verify-zone path — re-hash each RRSet, check signatures against the
//! KSK pinned by the caller.

use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use quantumvault_core::{Algorithm, Config, SecurityLevel, Signature, VerifyingKey};

use crate::error::{DnssecError, Result};
use crate::hashing::{hash_bytes, to_hex};
use crate::keys::DnssecVerifyingKey;
use crate::manifest::ZoneManifest;
use crate::zone::Zone;

/// Summary of what was verified.
#[derive(Debug, Clone)]
pub struct VerifyZoneReport {
    /// Did every check pass?
    pub valid: bool,
    /// Number of RRSets in the zone (= number checked).
    pub rrsets_checked: usize,
    /// KSK fingerprint that anchored the trust chain.
    pub ksk_fingerprint: String,
}

/// Verify a zone against its manifest, with the caller pinning the
/// expected KSK fingerprint (the trust anchor).
pub fn verify_zone(
    zone: &Zone,
    manifest: &ZoneManifest,
    expected_ksk: &DnssecVerifyingKey,
) -> Result<VerifyZoneReport> {
    // 1. KSK fingerprint must match the caller's expectation.
    let exp_fp = expected_ksk.fingerprint();
    if manifest.ksk.fingerprint != exp_fp {
        return Err(DnssecError::KskFingerprintMismatch);
    }

    let cfg = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()?;

    // 2. Verify the ZSK was signed by the KSK.
    let zsk_bytes = B64.decode(&manifest.zsk.bytes)?;
    let zsk_sig = manifest
        .zsk
        .signature_by_ksk
        .as_ref()
        .ok_or(DnssecError::ZskNotSignedByKsk)?;
    let zsk_sig_bytes = B64.decode(zsk_sig)?;
    let ksk_bytes = B64.decode(&manifest.ksk.bytes)?;
    let ksk_vk = VerifyingKey::new(ksk_bytes, Algorithm::MlDsa65, manifest.ksk.key_id.clone());
    let zsk_sig_core = Signature {
        bytes: zsk_sig_bytes,
        algorithm: Algorithm::MlDsa65,
        key_id: manifest.ksk.key_id.clone(),
        signed_at: 0,
    };
    let ok =
        quantumvault_core::api::verify::verify_signature(&zsk_bytes, &zsk_sig_core, &ksk_vk, &cfg)?;
    if !ok {
        return Err(DnssecError::ZskNotSignedByKsk);
    }
    let zsk_vk = VerifyingKey::new(
        zsk_bytes.clone(),
        Algorithm::MlDsa65,
        manifest.zsk.key_id.clone(),
    );

    // 3. Verify each RRSet's signature against the ZSK and check that
    //    the on-disk RRSet matches the manifest's recorded hash.
    let mut by_key: HashMap<String, &crate::zone::RrSet> = HashMap::new();
    for r in &zone.rrsets {
        by_key.insert(r.key(), r);
    }
    let mut keys_in_manifest: HashSet<String> = HashSet::new();

    for entry in &manifest.rrsets {
        keys_in_manifest.insert(entry.key.clone());
        let rr = by_key
            .get(&entry.key)
            .ok_or_else(|| DnssecError::RrsetMissingInZone(entry.key.clone()))?;
        let computed_hash = hash_bytes(&rr.canonical_bytes());
        if to_hex(&computed_hash) != entry.sha3_256 {
            return Err(DnssecError::RrsetHashMismatch(entry.key.clone()));
        }
        let sig_bytes = B64.decode(&entry.signature)?;
        let sig = Signature {
            bytes: sig_bytes,
            algorithm: Algorithm::MlDsa65,
            key_id: manifest.zsk.key_id.clone(),
            signed_at: 0,
        };
        let ok =
            quantumvault_core::api::verify::verify_signature(&computed_hash, &sig, &zsk_vk, &cfg)?;
        if !ok {
            return Err(DnssecError::RrsetSignatureInvalid(entry.key.clone()));
        }
    }

    // 4. Any zone RRSet not in the manifest is a (possibly malicious)
    //    addition — reject.
    for rr in &zone.rrsets {
        if !keys_in_manifest.contains(&rr.key()) {
            return Err(DnssecError::RrsetMissingInManifest(rr.key()));
        }
    }

    Ok(VerifyZoneReport {
        valid: true,
        rrsets_checked: manifest.rrsets.len(),
        ksk_fingerprint: manifest.ksk.fingerprint.clone(),
    })
}

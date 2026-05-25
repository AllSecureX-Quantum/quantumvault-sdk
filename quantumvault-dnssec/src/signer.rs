//! Sign-zone path — produce a manifest from a parsed zone + (KSK, ZSK).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use quantumvault_core::api::sign as core_sign;
use quantumvault_core::{Config, SecurityLevel};

use crate::error::Result;
use crate::hashing::{hash_bytes, to_hex};
use crate::keys::{DnssecSigningKey, DnssecVerifyingKey};
use crate::manifest::{KeyBlock, RrsetEntry, ZoneManifest, KSK_LABEL, MANIFEST_VERSION, ZSK_LABEL};
use crate::zone::Zone;

/// Summary of what was signed.
#[derive(Debug, Clone)]
pub struct SignZoneReport {
    /// Number of RRSets signed.
    pub rrsets_signed: usize,
    /// Number of records that fed into those RRSets.
    pub records_seen: usize,
    /// Manifest path that was written.
    pub manifest_path: std::path::PathBuf,
}

/// Sign every RRSet with the ZSK; sign the ZSK with the KSK; write a
/// manifest beside the zone.
pub fn sign_zone(
    zone: &Zone,
    ksk_sk: &DnssecSigningKey,
    ksk_vk: &DnssecVerifyingKey,
    zsk_sk: &DnssecSigningKey,
    zsk_vk: &DnssecVerifyingKey,
    manifest_path: &std::path::Path,
) -> Result<SignZoneReport> {
    let cfg = Config::builder()
        .security_level(SecurityLevel::Level3)
        .build()?;

    // 1. Sign each RRSet with the ZSK.
    let mut entries: Vec<RrsetEntry> = Vec::with_capacity(zone.rrsets.len());
    for rr in &zone.rrsets {
        let canonical = rr.canonical_bytes();
        let hash = hash_bytes(&canonical);
        let sig = core_sign::sign_message(&hash, zsk_sk.core(), &cfg)?;
        entries.push(RrsetEntry {
            key: rr.key(),
            sha3_256: to_hex(&hash),
            signature: B64.encode(&sig.bytes),
        });
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));

    // 2. Sign the ZSK's verifying-key bytes with the KSK (the
    //    DNSSEC-equivalent of "KSK signs DNSKEY RRSet").
    let zsk_sig_by_ksk = core_sign::sign_message(zsk_vk.bytes(), ksk_sk.core(), &cfg)?;

    let ksk_block = KeyBlock {
        label: KSK_LABEL.into(),
        algorithm: "ML-DSA-65".into(),
        key_id: ksk_vk.key_id().to_string(),
        bytes: B64.encode(ksk_vk.bytes()),
        fingerprint: ksk_vk.fingerprint(),
        signature_by_ksk: None,
    };
    let zsk_block = KeyBlock {
        label: ZSK_LABEL.into(),
        algorithm: "ML-DSA-65".into(),
        key_id: zsk_vk.key_id().to_string(),
        bytes: B64.encode(zsk_vk.bytes()),
        fingerprint: zsk_vk.fingerprint(),
        signature_by_ksk: Some(B64.encode(&zsk_sig_by_ksk.bytes)),
    };

    let manifest = ZoneManifest {
        version: MANIFEST_VERSION,
        zone: zone.origin.clone(),
        algorithm: "ML-DSA-65".into(),
        signed_at: Utc::now(),
        ksk: ksk_block,
        zsk: zsk_block,
        rrsets: entries.clone(),
    };
    manifest.save_atomic(manifest_path)?;

    Ok(SignZoneReport {
        rrsets_signed: entries.len(),
        records_seen: zone.records.len(),
        manifest_path: manifest_path.to_path_buf(),
    })
}

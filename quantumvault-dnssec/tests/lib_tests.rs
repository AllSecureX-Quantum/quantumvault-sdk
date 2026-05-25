//! Library tests for the DNSSEC zone-signing path.

use quantumvault_dnssec::{
    generate_keypair, parse_zone, sign_zone, verify_zone, DnssecError, ZoneManifest,
};

const SIMPLE_ZONE: &str = "$ORIGIN example.com.\n\
$TTL 3600\n\
@   IN  SOA  ns1.example.com. admin.example.com. ( 1 3600 600 604800 3600 )\n\
@   IN  NS   ns1.example.com.\n\
@   IN  A    1.2.3.4\n\
www IN  A    1.2.3.4\n\
api IN  A    1.2.3.5\n\
api IN  AAAA 2606:2800:220:1::1\n\
@   IN  TXT  \"v=spf1 -all\"\n";

fn sign_simple(
    tmp_dir: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf, ZoneManifest) {
    let zone_path = tmp_dir.join("example.com.zone");
    std::fs::write(&zone_path, SIMPLE_ZONE).unwrap();
    let manifest_path = tmp_dir.join("example.com.zone.qvdnssec.manifest.json");

    let zone = parse_zone(SIMPLE_ZONE).unwrap();
    let (ksk_sk, ksk_vk) = generate_keypair().unwrap();
    let (zsk_sk, zsk_vk) = generate_keypair().unwrap();
    sign_zone(&zone, &ksk_sk, &ksk_vk, &zsk_sk, &zsk_vk, &manifest_path).unwrap();

    let manifest = ZoneManifest::load(&manifest_path).unwrap();
    // Save the KSK alongside so tests can pin against it.
    let ksk_path = tmp_dir.join("ksk.verifying.json");
    ksk_vk.save_to_file(&ksk_path).unwrap();

    (zone_path, ksk_path, manifest)
}

// -------- Parser -------------------------------------------------------

#[test]
fn parses_simple_zone() {
    let z = parse_zone(SIMPLE_ZONE).unwrap();
    assert_eq!(z.origin, "example.com.");
    // 7 records (SOA + NS + apex A + www A + api A + api AAAA + TXT)
    assert_eq!(z.records.len(), 7);
    // Each RRSet key is "name|class|type" — multiple records under
    // the same key collapse, so we expect 7 unique RRSets.
    let keys: Vec<String> = z.rrsets.iter().map(|r| r.key()).collect();
    assert!(keys.contains(&"example.com.|IN|SOA".to_string()));
    assert!(keys.contains(&"api.example.com.|IN|A".to_string()));
    assert!(keys.contains(&"api.example.com.|IN|AAAA".to_string()));
}

#[test]
fn fqdn_completion_uses_origin() {
    let z = parse_zone(SIMPLE_ZONE).unwrap();
    assert!(z.records.iter().any(|r| r.name == "api.example.com."));
    assert!(z.records.iter().any(|r| r.name == "www.example.com."));
}

#[test]
fn at_owner_becomes_origin() {
    let z = parse_zone(SIMPLE_ZONE).unwrap();
    // The first record (SOA) has @ owner.
    assert_eq!(z.records[0].name, "example.com.");
}

#[test]
fn parses_parenthesised_soa() {
    let z = parse_zone(SIMPLE_ZONE).unwrap();
    let soa = z.records.iter().find(|r| r.rtype == "SOA").unwrap();
    // SOA rdata should contain all five serial-and-timer numbers as
    // ordinary tokens — the parser folded the parens into spaces.
    assert!(soa.rdata.contains("604800"));
    assert!(soa.rdata.contains("ns1.example.com."));
}

#[test]
fn missing_blank_separator_or_unmatched_paren_errors() {
    let bad = "$ORIGIN ex.com.\n$TTL 60\n@ IN SOA ns admin ( 1 2 3";
    let err = parse_zone(bad).unwrap_err();
    assert!(matches!(err, DnssecError::MalformedZone { .. }));
}

#[test]
fn unknown_record_type_errors() {
    let bad = "$ORIGIN ex.com.\n$TTL 60\n@ IN FOOBAR somerdata\n";
    let err = parse_zone(bad).unwrap_err();
    assert!(matches!(err, DnssecError::MalformedZone { .. }));
}

// -------- Round-trip --------------------------------------------------

#[test]
fn sign_then_verify_passes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (zone_path, ksk_path, _m) = sign_simple(tmp.path());
    let text = std::fs::read_to_string(&zone_path).unwrap();
    let z = parse_zone(&text).unwrap();
    let manifest =
        ZoneManifest::load(&zone_path.with_extension("zone.qvdnssec.manifest.json")).unwrap();
    let ksk = quantumvault_dnssec::DnssecVerifyingKey::load_from_file(&ksk_path).unwrap();
    let report = verify_zone(&z, &manifest, &ksk).unwrap();
    assert!(report.valid);
    assert_eq!(report.rrsets_checked, z.rrsets.len());
}

#[test]
fn signed_manifest_has_expected_shape() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (_zone_path, _ksk_path, m) = sign_simple(tmp.path());
    assert_eq!(m.version, 1);
    assert_eq!(m.algorithm, "ML-DSA-65");
    assert_eq!(m.zone, "example.com.");
    assert!(m.ksk.signature_by_ksk.is_none(), "KSK is the trust root");
    assert!(
        m.zsk.signature_by_ksk.is_some(),
        "ZSK must be signed by KSK"
    );
    assert_eq!(m.ksk.fingerprint.len(), 64);
    assert_eq!(m.zsk.fingerprint.len(), 64);
}

// -------- Tamper / attack paths ---------------------------------------

#[test]
fn rrset_hash_mismatch_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (zone_path, ksk_path, _m) = sign_simple(tmp.path());
    // Change an A record in the zone after signing.
    let mut text = std::fs::read_to_string(&zone_path).unwrap();
    text = text.replace("1.2.3.5", "9.9.9.9");
    std::fs::write(&zone_path, &text).unwrap();
    let z = parse_zone(&text).unwrap();
    let manifest =
        ZoneManifest::load(&zone_path.with_extension("zone.qvdnssec.manifest.json")).unwrap();
    let ksk = quantumvault_dnssec::DnssecVerifyingKey::load_from_file(&ksk_path).unwrap();
    let err = verify_zone(&z, &manifest, &ksk).unwrap_err();
    assert!(
        matches!(err, DnssecError::RrsetHashMismatch(_)),
        "got {err:?}"
    );
}

#[test]
fn added_rrset_after_signing_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (zone_path, ksk_path, _m) = sign_simple(tmp.path());
    // Add a new RRSet that the manifest doesn't know about.
    let mut text = std::fs::read_to_string(&zone_path).unwrap();
    text.push_str("evil   IN  A  6.6.6.6\n");
    std::fs::write(&zone_path, &text).unwrap();
    let z = parse_zone(&text).unwrap();
    let manifest =
        ZoneManifest::load(&zone_path.with_extension("zone.qvdnssec.manifest.json")).unwrap();
    let ksk = quantumvault_dnssec::DnssecVerifyingKey::load_from_file(&ksk_path).unwrap();
    let err = verify_zone(&z, &manifest, &ksk).unwrap_err();
    assert!(matches!(err, DnssecError::RrsetMissingInManifest(_)));
}

#[test]
fn removed_rrset_after_signing_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (zone_path, ksk_path, _m) = sign_simple(tmp.path());
    // Remove the api A record.
    let text: String = std::fs::read_to_string(&zone_path)
        .unwrap()
        .lines()
        .filter(|l| !l.contains("api ") || !l.contains("1.2.3.5"))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&zone_path, &text).unwrap();
    let z = parse_zone(&text).unwrap();
    let manifest =
        ZoneManifest::load(&zone_path.with_extension("zone.qvdnssec.manifest.json")).unwrap();
    let ksk = quantumvault_dnssec::DnssecVerifyingKey::load_from_file(&ksk_path).unwrap();
    let err = verify_zone(&z, &manifest, &ksk).unwrap_err();
    assert!(matches!(err, DnssecError::RrsetMissingInZone(_)));
}

#[test]
fn wrong_ksk_pinning_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (zone_path, _real_ksk, _m) = sign_simple(tmp.path());
    // Generate a different KSK and pin it.
    let (_x_sk, fake_ksk) = generate_keypair().unwrap();
    let text = std::fs::read_to_string(&zone_path).unwrap();
    let z = parse_zone(&text).unwrap();
    let manifest =
        ZoneManifest::load(&zone_path.with_extension("zone.qvdnssec.manifest.json")).unwrap();
    let err = verify_zone(&z, &manifest, &fake_ksk).unwrap_err();
    assert!(matches!(err, DnssecError::KskFingerprintMismatch));
}

#[test]
fn rrset_signature_tampering_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (zone_path, ksk_path, mut m) = sign_simple(tmp.path());
    // Flip the last char of the first RRSet's signature.
    let sig = &mut m.rrsets[0].signature;
    let last = sig.len() - 1;
    let new = if sig.as_bytes()[last] == b'A' {
        'B'
    } else {
        'A'
    };
    sig.replace_range(last..last + 1, &new.to_string());
    let manifest_path = zone_path.with_extension("zone.qvdnssec.manifest.json");
    m.save_atomic(&manifest_path).unwrap();
    let text = std::fs::read_to_string(&zone_path).unwrap();
    let z = parse_zone(&text).unwrap();
    let reloaded = ZoneManifest::load(&manifest_path).unwrap();
    let ksk = quantumvault_dnssec::DnssecVerifyingKey::load_from_file(&ksk_path).unwrap();
    let err = verify_zone(&z, &reloaded, &ksk).unwrap_err();
    assert!(matches!(err, DnssecError::RrsetSignatureInvalid(_)));
}

#[test]
fn missing_zsk_signature_by_ksk_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (zone_path, ksk_path, mut m) = sign_simple(tmp.path());
    // Strip the ZSK-by-KSK signature.
    m.zsk.signature_by_ksk = None;
    let manifest_path = zone_path.with_extension("zone.qvdnssec.manifest.json");
    m.save_atomic(&manifest_path).unwrap();
    let text = std::fs::read_to_string(&zone_path).unwrap();
    let z = parse_zone(&text).unwrap();
    let reloaded = ZoneManifest::load(&manifest_path).unwrap();
    let ksk = quantumvault_dnssec::DnssecVerifyingKey::load_from_file(&ksk_path).unwrap();
    let err = verify_zone(&z, &reloaded, &ksk).unwrap_err();
    assert!(matches!(err, DnssecError::ZskNotSignedByKsk));
}

// -------- Manifest version --------------------------------------------

#[test]
fn manifest_load_rejects_unknown_version() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (zone_path, _ksk_path, _m) = sign_simple(tmp.path());
    let manifest_path = zone_path.with_extension("zone.qvdnssec.manifest.json");
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    v["version"] = serde_json::json!(99);
    std::fs::write(&manifest_path, v.to_string()).unwrap();
    let err = ZoneManifest::load(&manifest_path).unwrap_err();
    assert!(matches!(err, DnssecError::UnsupportedManifestVersion(99)));
}

// -------- Key file round-trip -----------------------------------------

#[test]
fn keys_save_load_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (sk, vk) = generate_keypair().unwrap();
    let sk_path = tmp.path().join("sk.json");
    let vk_path = tmp.path().join("vk.json");
    sk.save_to_file(&sk_path, None).unwrap();
    vk.save_to_file(&vk_path).unwrap();
    let _sk2 =
        quantumvault_dnssec::DnssecSigningKey::load_from_file(&sk_path, None).unwrap();
    let vk2 = quantumvault_dnssec::DnssecVerifyingKey::load_from_file(&vk_path).unwrap();
    assert_eq!(vk2.fingerprint(), vk.fingerprint());
}

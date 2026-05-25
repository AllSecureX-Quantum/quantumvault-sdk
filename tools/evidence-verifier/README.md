# AllSecureX Auditor Evidence Pack — Independent Verifier

A standalone bash script that **independently verifies** an AllSecureX QERA
Auditor Evidence Pack — no AllSecureX dependency at verification time, no API
calls, no SDK install. Audit, internal audit, statutory audit and supervisory
inspection teams run it offline to confirm that:

1. **Every entry's SHA-256 hash** matches the manifest claim (byte-for-byte
   integrity of the four artefacts inside the ZIP).
2. **The manifest's HMAC-SHA-256 signature** is valid against the shared key
   you receive from AllSecureX at engagement onboarding.

If any byte has changed since issuance — in any file, in the manifest itself —
the verifier exits non-zero with a precise reason.

## Files in a real Evidence Pack

```
qera-evidence-{assessmentId}.aep.zip
├── assessment.json    full QERA AssessmentResult
├── findings.csv       flat findings, spreadsheet-ready
├── findings.cef       SIEM-format (Splunk, QRadar, ArcSight, LogRhythm)
├── findings.jsonl     line-delimited JSON for Elastic / Logstash / Sentinel
└── manifest.json      SHA-256 per entry + HMAC-SHA-256 over manifest body
```

## Verifying an Evidence Pack

```bash
# 1. Receive the HMAC key from your AllSecureX engagement contact
#    (issued once at onboarding, rotated quarterly, held in your KMS / vault).
export EVIDENCE_HMAC_KEY=f62dc59500…a1361b70

# 2. Run the verifier — accepts either the .zip or an already-extracted folder
./verify-evidence-pack.sh qera-evidence-2026Q2.aep.zip

# 3. Inspect exit code
#    0 = all checks pass
#    1 = pack structure invalid (missing files, bad JSON, key missing)
#    2 = one or more SHA-256 hashes mismatch
#    3 = HMAC signature mismatch
#    4 = signature.algorithm = dev-unsigned-hmac (refuse to accept)
```

## What "verified" actually proves

| Check | What it tells your auditor |
|---|---|
| All four entries pass SHA-256 | Every byte of `assessment.json`, `findings.csv`, `findings.cef`, `findings.jsonl` matches what AllSecureX hashed at issuance. No tampering of the underlying findings. |
| Manifest HMAC-SHA-256 valid | The manifest itself (including the SHA-256 list) has not been edited. Re-signing requires the customer's HMAC key, held outside AllSecureX after issuance. |
| Signature algorithm `hmac-sha256` | Not the `dev-unsigned-hmac` fallback. Production pack, regulator-defensible. |

## Algorithm details (for cryptographic review)

The HMAC is computed by the QERA Lambda using Node.js `crypto.createHmac('sha256', key).update(body).digest('hex')`,
where `body` is `JSON.stringify(manifest)` with the `signature` field omitted
and **no whitespace** between tokens (default compact `JSON.stringify`).

The verifier re-creates the same body via Python:

```python
json.dumps(manifest_without_signature, separators=(",", ":"), ensure_ascii=False)
```

Both produce byte-identical UTF-8 input to the HMAC, by design.

## Dependencies

- `bash` (>= 4 — macOS users with Bash 3 should `brew install bash` or use zsh)
- `unzip`
- `sha256sum` (Linux) **or** `shasum -a 256` (macOS) — both supported automatically
- `openssl` (for HMAC-SHA-256)
- `jq` (manifest parsing)
- `python3` (JSON body reconstruction)

All are present by default on Linux and macOS.

## Key rotation

Your HMAC key is rotated quarterly. Old packs remain verifiable with the key
that issued them — keep the old keys in your KMS history (`AWSCURRENT` →
`AWSPREVIOUS` is the recommended Secrets Manager pattern). The verifier
accepts a key per invocation; you can match key to pack by inspecting
`manifest.generatedAt` against your rotation log.

## What this tool does NOT do

- It does not validate the **content correctness** of the findings inside
  `assessment.json` — those are the QERA engine's responsibility.
- It does not check whether the **HMAC key is fresh or revoked** — that is
  the customer's KMS / Secrets Manager responsibility.
- It does not perform **transport authentication** — it operates on a pack
  that has already been received.

## Pinning the verifier

This script ships as part of the AllSecureX engagement. The intended pinning
pattern is for the customer to mirror it into their own ISMS evidence vault
alongside the HMAC key history, so the verification capability survives
independently of AllSecureX availability.

---

**Contact:** himanshu@allsecurex.com  ·  allsecurex.com

#!/usr/bin/env bash
#
# verify-evidence-pack.sh
#
# Independently verify an AllSecureX QERA Auditor Evidence Pack.
# Performs:
#   1. SHA-256 of every entry compared against manifest.entries[].sha256
#   2. HMAC-SHA-256 of the manifest body (signature object stripped)
#      compared against manifest.signature.value, using the shared key
#      passed in via $EVIDENCE_HMAC_KEY (env var) or --key on the CLI.
#
# Exit codes:
#   0  all checks pass
#   1  pack structure invalid (missing files, bad JSON)
#   2  one or more SHA-256 hashes mismatch
#   3  HMAC signature mismatch
#   4  signature algorithm is dev-unsigned-hmac (not regulator-defensible)
#
# Usage:
#   ./verify-evidence-pack.sh path/to/qera-evidence-*.aep.zip [--key HEXKEY]
#   ./verify-evidence-pack.sh path/to/extracted-folder/      [--key HEXKEY]
#
# Dependencies: bash, unzip, sha256sum (or shasum -a 256), openssl, jq, python3
# Works on Linux and macOS out of the box.
set -euo pipefail

usage() {
  cat <<EOF
verify-evidence-pack.sh — Independently verify an AllSecureX Auditor Evidence Pack

USAGE
  $(basename "$0") <pack.zip|extracted-dir> [--key HEXKEY]

ENVIRONMENT
  EVIDENCE_HMAC_KEY    Hex-encoded HMAC-SHA-256 key shared by AllSecureX at engagement onboarding
                       (can also be passed via --key)

EXAMPLES
  EVIDENCE_HMAC_KEY=\$(cat ~/.config/allsecurex/evidence-key) \\
    $(basename "$0") qera-evidence-2026Q2.aep.zip

  $(basename "$0") ./extracted-evidence-folder --key f62dc59500…a1361b70

DEPENDENCIES
  bash >= 4, unzip, sha256sum or shasum, openssl, jq, python3
EOF
}

if [[ $# -lt 1 ]] || [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
  usage; exit 0
fi

# ── Parse args ──────────────────────────────────────────────────────────────
TARGET="$1"; shift
HMAC_KEY="${EVIDENCE_HMAC_KEY:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key) HMAC_KEY="$2"; shift 2;;
    *) echo "[err] unknown flag: $1"; usage; exit 1;;
  esac
done

# ── Resolve the pack directory ──────────────────────────────────────────────
TMP_DIR=""
cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
  return 0
}
trap cleanup EXIT

if [[ -f "$TARGET" ]]; then
  TMP_DIR="$(mktemp -d -t aep-verify-XXXX)"
  echo "[info] extracting $TARGET → $TMP_DIR"
  unzip -q "$TARGET" -d "$TMP_DIR"
  PACK_DIR="$TMP_DIR"
elif [[ -d "$TARGET" ]]; then
  PACK_DIR="$TARGET"
else
  echo "[err] not a file or directory: $TARGET" >&2
  exit 1
fi

# ── Locate manifest ─────────────────────────────────────────────────────────
MANIFEST="$PACK_DIR/manifest.json"
if [[ ! -f "$MANIFEST" ]]; then
  echo "[err] manifest.json missing in pack" >&2
  exit 1
fi
if ! jq empty "$MANIFEST" 2>/dev/null; then
  echo "[err] manifest.json is not valid JSON" >&2
  exit 1
fi

PACK_ID=$(jq -r '.packId' "$MANIFEST")
SPEC=$(jq -r '.specVersion' "$MANIFEST")
ASSESSMENT_ID=$(jq -r '.assessmentId' "$MANIFEST")
ORG=$(jq -r '.organizationName' "$MANIFEST")
SIG_ALG=$(jq -r '.signature.algorithm' "$MANIFEST")
SIG_VAL=$(jq -r '.signature.value' "$MANIFEST")

echo "[info] pack       : $PACK_ID"
echo "[info] spec       : $SPEC"
echo "[info] assessment : $ASSESSMENT_ID"
echo "[info] organisation: $ORG"
echo "[info] signature  : $SIG_ALG"

# ── 1. Verify SHA-256 of each entry ─────────────────────────────────────────
echo
echo "── 1. SHA-256 entry integrity ──────────────────────────────────────"
HAS_BAD=0
N=$(jq '.entries | length' "$MANIFEST")
for i in $(seq 0 $((N-1))); do
  FILE=$(jq -r ".entries[$i].filename" "$MANIFEST")
  EXPECTED=$(jq -r ".entries[$i].sha256" "$MANIFEST")
  EXPECTED_BYTES=$(jq -r ".entries[$i].bytes" "$MANIFEST")
  PATH_TO="$PACK_DIR/$FILE"

  if [[ ! -f "$PATH_TO" ]]; then
    echo "  ❌ $FILE — file missing"
    HAS_BAD=1
    continue
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$PATH_TO" | awk '{print $1}')
  else
    ACTUAL=$(shasum -a 256 "$PATH_TO" | awk '{print $1}')
  fi
  ACTUAL_BYTES=$(wc -c < "$PATH_TO" | tr -d ' ')

  if [[ "$ACTUAL" == "$EXPECTED" && "$ACTUAL_BYTES" == "$EXPECTED_BYTES" ]]; then
    echo "  ✓ $FILE — $EXPECTED_BYTES bytes, hash match"
  else
    echo "  ❌ $FILE"
    echo "       expected sha256 = $EXPECTED   bytes = $EXPECTED_BYTES"
    echo "       actual   sha256 = $ACTUAL     bytes = $ACTUAL_BYTES"
    HAS_BAD=1
  fi
done
if [[ $HAS_BAD -eq 1 ]]; then
  echo "[fail] one or more entries failed SHA-256 verification" >&2
  exit 2
fi

# ── 2. Verify HMAC-SHA-256 over the manifest body ───────────────────────────
echo
echo "── 2. HMAC-SHA-256 manifest signature ──────────────────────────────"

if [[ "$SIG_ALG" == "dev-unsigned-hmac" ]]; then
  echo "  ⚠ signature.algorithm = dev-unsigned-hmac"
  echo "       this is a development fallback (SHA-256 over manifest body)."
  echo "       it is traceable but NOT a real HMAC. Refuse to accept for regulator-defensible audit."
  exit 4
fi

if [[ -z "$HMAC_KEY" ]]; then
  echo "[err] HMAC key not provided. Pass via --key HEX or set EVIDENCE_HMAC_KEY env var." >&2
  exit 1
fi

# Compute HMAC over the manifest body — same shape the Lambda signs:
#   stringify(JSON_without_signature_field) → HMAC-SHA-256(key, .) → hex
BODY=$(python3 - "$MANIFEST" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as fh:
    obj = json.load(fh)
obj.pop("signature", None)
# Match JS `JSON.stringify(obj)` exactly:
#   - no whitespace separators
#   - keys in insertion order (Python 3.7+ json preserves this)
sys.stdout.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))
PYEOF
)

COMPUTED=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$HMAC_KEY" -hex | awk '{print $NF}')

if [[ "$COMPUTED" == "$SIG_VAL" ]]; then
  echo "  ✓ HMAC signature matches — manifest body integrity verified"
else
  echo "  ❌ HMAC signature MISMATCH"
  echo "       expected: $SIG_VAL"
  echo "       computed: $COMPUTED"
  exit 3
fi

echo
echo "── VERIFIED ────────────────────────────────────────────────────────"
echo "  All entries pass SHA-256 integrity."
echo "  Manifest HMAC-SHA-256 signature is valid."
echo "  This Auditor Evidence Pack is byte-for-byte unmodified since issuance."
echo
exit 0

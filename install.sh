#!/bin/sh
# install.sh — QuantumVault SDK one-line installer.
#
# Usage (interactive — pinned to latest release):
#   curl -fsSL https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/latest/download/install.sh | sh
#
# Usage (CI / scripted — pinned to a specific version):
#   curl -fsSL https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/download/v1.2.3/install.sh \
#     | sh -s -- --version v1.2.3
#
# A short vanity URL (e.g. install.quantumvault.allsecurex.com) may be
# added later as a redirect to the latest release; until then the
# canonical install path is via github.com directly.
#
# What this script does:
#   1. Detects host OS + architecture.
#   2. Downloads the matching release archive from GitHub Releases.
#   3. Verifies the SHA-256 checksum against CHECKSUMS.txt.
#   4. Extracts every PQC binary (quantumvault, qvca, qvdnssec, qvsmime,
#      qvarchive, qvjwtproxy, qvacme-server, qvacme-client, qvhsm,
#      quantum-scanner) into a destination directory.
#   5. Defaults: /usr/local/bin if writable, else $HOME/.local/bin.
#
# Exit codes:
#   0 success
#   1 unsupported platform
#   2 download / verification failure
#   3 install / extract failure
#
# The script is POSIX-sh portable. Tested against bash, dash, ash, zsh.

set -eu

REPO="${QV_REPO:-AllSecureX-Quantum/quantumvault-sdk}"
VERSION="${QV_VERSION:-}"
DEST="${QV_DEST:-}"
SKIP_VERIFY=0
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version)  VERSION="$2"; shift 2 ;;
    --dest)     DEST="$2"; shift 2 ;;
    --repo)     REPO="$2"; shift 2 ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    --quiet|-q) QUIET=1; shift ;;
    --help|-h)
      cat <<EOF
QuantumVault installer

Options:
  --version <vX.Y.Z>   Version tag to install (default: latest)
  --dest    <dir>      Install directory (default: /usr/local/bin or ~/.local/bin)
  --repo    <owner/repo>  Override release repo
  --skip-verify        Skip SHA-256 checksum verification (NOT recommended)
  --quiet              Suppress progress output

Environment overrides: QV_VERSION, QV_DEST, QV_REPO.
EOF
      exit 0
      ;;
    *)
      echo "qvinstall: unknown flag $1" >&2
      exit 1
      ;;
  esac
done

log() {
  [ "$QUIET" -eq 1 ] && return 0
  printf '%s\n' "==> $*" >&2
}

err() {
  printf '%s\n' "error: $*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "missing required command: $1"
    exit 1
  }
}

require_cmd uname
require_cmd tar
require_cmd mkdir
# curl OR wget — we detect which is present.
if command -v curl >/dev/null 2>&1; then
  DL_CMD='curl -fsSL'
elif command -v wget >/dev/null 2>&1; then
  DL_CMD='wget -qO-'
else
  err "neither curl nor wget found on PATH"
  exit 1
fi

# ----- Detect host platform ----------------------------------------------
OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"
case "$OS_RAW" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *)      err "unsupported OS: $OS_RAW"; exit 1 ;;
esac

case "$ARCH_RAW" in
  x86_64|amd64)  ARCH=x86_64 ;;
  arm64|aarch64) ARCH=aarch64 ;;
  *)             err "unsupported architecture: $ARCH_RAW"; exit 1 ;;
esac

# Map (OS, ARCH) -> Rust target triple used in the release artefact name.
case "$OS-$ARCH" in
  linux-x86_64)   TARGET=x86_64-unknown-linux-gnu ;;
  darwin-aarch64) TARGET=aarch64-apple-darwin ;;
  darwin-x86_64)
    err "macOS Intel binaries are not yet released — please build from source"
    exit 1
    ;;
  linux-aarch64)
    err "Linux arm64 binaries are not yet released — please build from source"
    exit 1
    ;;
  *) err "no published binary for $OS-$ARCH"; exit 1 ;;
esac

# ----- Resolve version ---------------------------------------------------
if [ -z "$VERSION" ]; then
  log "resolving latest release tag from github.com/$REPO ..."
  VERSION="$($DL_CMD "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
    | head -n1)"
  if [ -z "$VERSION" ]; then
    err "could not resolve latest release tag"
    exit 2
  fi
fi
log "installing $VERSION for $OS/$ARCH ($TARGET)"

# ----- Pick install destination -----------------------------------------
if [ -z "$DEST" ]; then
  if [ -w /usr/local/bin ]; then
    DEST=/usr/local/bin
  else
    DEST="$HOME/.local/bin"
    mkdir -p "$DEST"
  fi
fi
log "install destination: $DEST"

# ----- Download archive + checksum --------------------------------------
ARCHIVE="quantumvault-${VERSION}-${TARGET}.tar.gz"
BASE="https://github.com/$REPO/releases/download/${VERSION}"
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t qvinstall)"
trap 'rm -rf "$TMP"' EXIT

log "downloading $ARCHIVE ..."
$DL_CMD "$BASE/$ARCHIVE" > "$TMP/$ARCHIVE" || {
  err "archive download failed: $BASE/$ARCHIVE"
  exit 2
}

if [ "$SKIP_VERIFY" -eq 0 ]; then
  log "fetching CHECKSUMS.txt ..."
  $DL_CMD "$BASE/CHECKSUMS.txt" > "$TMP/CHECKSUMS.txt" || {
    err "checksums file download failed"
    exit 2
  }
  # Extract the line for our archive, then verify.
  EXPECTED="$(grep " $ARCHIVE\$" "$TMP/CHECKSUMS.txt" | awk '{print $1}')"
  if [ -z "$EXPECTED" ]; then
    err "no checksum entry for $ARCHIVE in CHECKSUMS.txt"
    exit 2
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "$TMP/$ARCHIVE" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}')"
  else
    err "no sha256sum or shasum on PATH — re-run with --skip-verify if you accept the risk"
    exit 2
  fi
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    err "checksum mismatch! expected=$EXPECTED actual=$ACTUAL"
    err "DO NOT trust the downloaded archive."
    exit 2
  fi
  log "checksum verified ($ACTUAL)"
else
  log "checksum verification skipped (--skip-verify)"
fi

# ----- Extract + install ------------------------------------------------
log "extracting ..."
tar -xzf "$TMP/$ARCHIVE" -C "$TMP" || { err "extract failed"; exit 3; }

STAGE_DIR="$TMP/quantumvault-${VERSION}-${TARGET}"
[ -d "$STAGE_DIR" ] || { err "expected directory $STAGE_DIR after extract"; exit 3; }

INSTALLED=""
for bin in quantumvault qvca qvdnssec qvsmime qvarchive qvjwtproxy \
           qvacme-server qvacme-client qvhsm quantum-scanner; do
  if [ -f "$STAGE_DIR/$bin" ]; then
    install -m 0755 "$STAGE_DIR/$bin" "$DEST/$bin" \
      || cp "$STAGE_DIR/$bin" "$DEST/$bin"
    chmod +x "$DEST/$bin"
    INSTALLED="$INSTALLED $bin"
  fi
done

if [ -z "$INSTALLED" ]; then
  err "no binaries were installed — archive layout unexpected"
  exit 3
fi

log "installed:$INSTALLED"
log "destination: $DEST"

# Final hint: warn if dest isn't on PATH.
case ":$PATH:" in
  *":$DEST:"*) : ;;
  *)
    cat <<EOF >&2

Note: $DEST is not on your PATH. Add it to your shell profile:

    echo 'export PATH="$DEST:\$PATH"' >> ~/.profile

EOF
    ;;
esac

log "done. Try:  quantumvault tools list"

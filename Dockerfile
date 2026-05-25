# Dockerfile — QuantumVault SDK unified image.
#
# Produces a single image containing every customer-facing PQC binary:
# the unified `quantumvault` CLI plus every standalone tool it wraps.
# After `docker run` the unified entrypoint resolves sibling binaries
# inside /usr/local/bin and routes `quantumvault tools <name>` to them.
#
# Distribution channel: pushed to ghcr.io/<org>/quantumvault on each
# `v*.*.*` tag by .github/workflows/docker-publish.yml. Tagged
# `:vX.Y.Z`, `:vX.Y`, `:vX`, and `:latest`.
#
# Image size target: < 80 MB. We use a debian:bookworm-slim final stage
# rather than distroless / alpine because (a) the pqcrypto C deps link
# against glibc, so musl is out; (b) several PQC binaries open
# arbitrary user-supplied files at runtime so a shell + coreutils
# stay useful for debugging.

# Rust 1.85+ required: transitive dep `base64ct` uses edition2024.
ARG RUST_VERSION=1.86
ARG DEBIAN_VERSION=bookworm

# -----------------------------------------------------------------------
# Stage 1: builder
# -----------------------------------------------------------------------
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

WORKDIR /src

# Install build deps the pqcrypto C sources + sqlite need. Keep this
# list minimal so the apt cache layer stays small.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      pkg-config \
      cmake \
      libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# Bring in the full workspace. Each tool needs to see its sibling
# crates via the workspace path deps.
COPY Cargo.toml Cargo.lock* ./
COPY quantumvault-core      quantumvault-core
COPY quantumvault-keys      quantumvault-keys
COPY quantumvault-jose      quantumvault-jose
COPY quantumvault-cli       quantumvault-cli
COPY quantumvault-archive   quantumvault-archive
COPY quantumvault-smime     quantumvault-smime
COPY quantumvault-jwtproxy  quantumvault-jwtproxy
COPY quantumvault-ca        quantumvault-ca
COPY quantumvault-dnssec    quantumvault-dnssec
COPY quantumvault-acme      quantumvault-acme
COPY quantumvault-pkcs11    quantumvault-pkcs11
COPY quantum-scanner-cli    quantum-scanner-cli

# Single cargo build invocation produces every customer-facing binary
# in /src/target/release/.
RUN cargo build --release \
      -p quantumvault-cli \
      -p quantum-scanner \
      -p quantumvault-archive \
      -p quantumvault-smime \
      -p quantumvault-jwtproxy \
      -p quantumvault-ca \
      -p quantumvault-dnssec \
      -p quantumvault-acme \
      -p quantumvault-pkcs11

# -----------------------------------------------------------------------
# Stage 2: runtime
# -----------------------------------------------------------------------
FROM debian:${DEBIAN_VERSION}-slim AS runtime

# ca-certificates so qvacme-client and any HTTPS-speaking tool finds a
# trust store.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 65532 qv \
 && useradd --system --uid 65532 --gid qv --home /home/qv --create-home qv

# Copy the binaries into /usr/local/bin so they sit in the standard
# location AND so the unified CLI's sibling-of-current-exe resolution
# finds them at runtime.
COPY --from=builder \
  /src/target/release/quantumvault \
  /src/target/release/quantum-scanner \
  /src/target/release/qvarchive \
  /src/target/release/qvsmime \
  /src/target/release/qvjwtproxy \
  /src/target/release/qvca \
  /src/target/release/qvdnssec \
  /src/target/release/qvacme-server \
  /src/target/release/qvacme-client \
  /src/target/release/qvhsm \
  /usr/local/bin/

# Drop privileges. Mount a customer data volume at /work as a non-root
# user — keys generated here will land in /work/, not on the read-only
# image FS.
USER qv
WORKDIR /work

# Image metadata. Versioning is driven by the docker-publish workflow.
LABEL org.opencontainers.image.title="QuantumVault SDK"
LABEL org.opencontainers.image.description="Post-quantum cryptography toolkit (ML-KEM, ML-DSA, SLH-DSA) — CA, DNSSEC, S/MIME, archival, ACME, JWT, HSM bridge."
LABEL org.opencontainers.image.source="https://github.com/AllSecureX-Quantum/quantumvault-sdk"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="AllSecureX"

# Default to the unified CLI's help screen. Override with a specific
# tool: `docker run … quantumvault tools ca init-root …`.
ENTRYPOINT ["quantumvault"]
CMD ["--help"]

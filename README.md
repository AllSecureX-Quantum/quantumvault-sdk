# QuantumVault SDK

Post-quantum cryptography toolkit for production systems. NIST FIPS 203 (ML-KEM),
FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) across a coherent set of CLI binaries
that drop into existing infrastructure.

> Built and maintained by [AllSecureX](https://allsecurex.com) for BFSI,
> defence and Indian critical-infrastructure operators preparing for the
> NSA CNSA 2.0 (2033) migration deadline.

## What's in the box

| Binary | Purpose | Standard |
|---|---|---|
| `quantumvault` | Unified CLI wrapping every tool below | — |
| `qvca` | Internal certificate authority | ML-DSA (FIPS 204) |
| `qvdnssec` | DNSSEC zone signing | ML-DSA |
| `qvacme-server` / `qvacme-client` | ACME-style cert provisioning | RFC 8555-style |
| `qvjwtproxy` | JWT verifier sidecar | ML-DSA |
| `qvsmime` | S/MIME-style email signing | ML-DSA-65 |
| `qvarchive` | Long-term archive sealing | SLH-DSA (FIPS 205) |
| `qvhsm` | PKCS#11 HSM bridge | PKCS#11 v2.40 |
| `quantum-scanner` | Source-code crypto inventory + CryptoBOM export | CycloneDX 1.6 |

## Install

```bash
# Universal one-liner (Linux + macOS)
curl -fsSL https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases/latest/download/install.sh | sh

# Homebrew (macOS arm64 + Linux x86_64)
brew tap allsecurex-quantum/tap
brew install quantumvault

# Docker (multi-arch image with every binary)
docker run --rm ghcr.io/allsecurex-quantum/quantumvault-sdk:latest quantumvault --help

# Scanner alone, via npm
npm install -g allsecurex-quantum-scanner
```

Direct archives for `linux-x86_64`, `macos-arm64` and `windows-x86_64` are
attached to every [GitHub Release](https://github.com/AllSecureX-Quantum/quantumvault-sdk/releases),
each accompanied by a `CHECKSUMS.txt` for SHA-256 verification.

## Standards alignment

- NIST FIPS 203 — Module-Lattice Key Encapsulation (ML-KEM)
- NIST FIPS 204 — Module-Lattice Digital Signatures (ML-DSA)
- NIST FIPS 205 — Stateless Hash-Based Digital Signatures (SLH-DSA)
- NSA CNSA 2.0 — quantum-safe trajectory to 2033
- CycloneDX 1.6 — Cryptographic Bill of Materials with `cryptoProperties`
- RFC 8555 — ACME (PQC-extended)
- PKCS#11 v2.40 — HSM mechanism set

## Language bindings

Idiomatic wrappers around the same Rust core ship in dedicated repos:

- Go — [`AllSecureX-Quantum/quantumvault-go`](https://github.com/AllSecureX-Quantum/quantumvault-go)
- Java — [`AllSecureX-Quantum/quantumvault-java`](https://github.com/AllSecureX-Quantum/quantumvault-java)
- Python — [`AllSecureX-Quantum/quantumvault-python`](https://github.com/AllSecureX-Quantum/quantumvault-python)
- Node.js — [`AllSecureX-Quantum/-crypto-shim-nodejs-`](https://github.com/AllSecureX-Quantum/-crypto-shim-nodejs-)

## Build from source

```bash
git clone https://github.com/AllSecureX-Quantum/quantumvault-sdk
cd quantumvault-sdk
cargo build --release --workspace
```

Rust 1.75 or newer.

## Auditor evidence verification

`tools/evidence-verifier/` ships the standalone bash verifier auditors use to
independently confirm tamper-evident QERA Evidence Packs. No QuantumVault
dependency at verification time — just `bash`, `unzip`, `openssl`, `jq`,
`python3`.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contact

[himanshu@allsecurex.com](mailto:himanshu@allsecurex.com) · [allsecurex.com](https://allsecurex.com)

//! SHA-3-256 hashing for file content.
//!
//! The hash is what we actually sign — it pins each file's exact byte
//! content at seal time. Any later change (tampering, truncation, file
//! swap) is detected when verifying because the recomputed hash diverges.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use sha3::{Digest, Sha3_256};

use crate::error::{ArchiveError, Result};

/// Streaming hash of a file — reads in 64 KiB chunks so files larger than
/// memory are handled fine. Returns the 32-byte SHA-3-256 digest.
pub fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let file = File::open(path).map_err(|e| ArchiveError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha3_256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|e| ArchiveError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Hash arbitrary in-memory bytes (handy for tests + the message we sign).
pub fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Encode a hash as lowercase hex for human-readable manifests.
pub fn to_hex(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).expect("write to string is infallible");
    }
    s
}

/// Parse a hex hash. Caller passes a 64-character lowercase hex string.
pub fn from_hex(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        return Err(ArchiveError::ManifestMalformed(format!(
            "hash field must be 64 hex chars, got {}",
            s.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[i * 2])?;
        let lo = hex_nibble(s.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ArchiveError::ManifestMalformed(format!(
            "invalid hex char: {:?}",
            c as char
        ))),
    }
}

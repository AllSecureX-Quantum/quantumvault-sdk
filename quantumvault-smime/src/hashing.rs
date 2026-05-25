//! SHA-3-256 hashing of email bodies.

use sha3::{Digest, Sha3_256};

/// 32-byte SHA-3-256 digest of arbitrary bytes.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

/// Lowercase hex encoding of a 32-byte digest.
pub fn to_hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).expect("write to string is infallible");
    }
    s
}

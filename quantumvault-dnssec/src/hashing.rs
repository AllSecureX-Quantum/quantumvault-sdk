//! SHA-3-256 hashing for canonical RRSet bytes.

use sha3::{Digest, Sha3_256};

/// 32-byte SHA-3-256 digest.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

/// Lowercase hex encoding.
pub fn to_hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).expect("write to string");
    }
    s
}

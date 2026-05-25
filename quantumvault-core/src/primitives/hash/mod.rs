//! Hash function implementations.

use crate::error::Result;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

/// Hash algorithm variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (SHA-2 family).
    Sha256,
    /// SHA-384 (SHA-2 family).
    Sha384,
    /// SHA-512 (SHA-2 family).
    Sha512,
    /// SHA3-256 (SHA-3 family, recommended).
    Sha3_256,
    /// SHA3-384 (SHA-3 family).
    Sha3_384,
    /// SHA3-512 (SHA-3 family).
    Sha3_512,
}

impl HashAlgorithm {
    /// Get the output size in bytes.
    pub fn output_size(&self) -> usize {
        match self {
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }

    /// Check if this is a SHA-3 family algorithm.
    pub fn is_sha3(&self) -> bool {
        matches!(self, Self::Sha3_256 | Self::Sha3_384 | Self::Sha3_512)
    }
}

/// Compute a hash of the input data.
pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        HashAlgorithm::Sha3_256 => Sha3_256::digest(data).to_vec(),
        HashAlgorithm::Sha3_384 => Sha3_384::digest(data).to_vec(),
        HashAlgorithm::Sha3_512 => Sha3_512::digest(data).to_vec(),
    }
}

/// SHAKE128 extendable output function.
pub fn shake128(data: &[u8], output_len: usize) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut hasher = Shake128::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// SHAKE256 extendable output function.
pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// HMAC-based Key Derivation Function (HKDF).
pub fn hkdf_expand(secret: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha3_256>::new(None, secret);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|_| crate::error::Error::Internal("HKDF expansion failed".into()))?;
    Ok(okm)
}

/// Key Derivation Function with salt.
pub fn hkdf_extract_expand(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha3_256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|_| crate::error::Error::Internal("HKDF expansion failed".into()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"test data";
        let hash_result = hash(data, HashAlgorithm::Sha256);
        assert_eq!(hash_result.len(), 32);
    }

    #[test]
    fn test_sha3_256() {
        let data = b"test data";
        let hash_result = hash(data, HashAlgorithm::Sha3_256);
        assert_eq!(hash_result.len(), 32);
    }

    #[test]
    fn test_shake256() {
        let data = b"test data";
        let output = shake256(data, 64);
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_hkdf() {
        let secret = b"shared secret";
        let info = b"encryption key";
        let derived = hkdf_expand(secret, info, 32).unwrap();
        assert_eq!(derived.len(), 32);
    }
}

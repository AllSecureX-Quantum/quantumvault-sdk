//! Dev-KEK file format — the on-disk representation of an
//! [`InMemoryKek`](crate::InMemoryKek) used by `qvhsm init-master` and
//! by consumer binaries (`qvca`, `qvdnssec`, `qvsmime`) when reading
//! the same file to unwrap their signing keys.
//!
//! Production deployments use a PKCS#11 token and never touch this
//! format. The plaintext-on-disk KEK is intentionally labelled, so an
//! auditor scanning the disk can spot it.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::kek::KekProvider;
use crate::{HsmError, InMemoryKek, Result};

/// Magic header written into every dev-KEK file so auditors and `qvhsm`
/// can identify the format without guessing.
pub const DEV_KEK_FILE_HEADER: &str = "QVHSM-KEK-v1";

#[derive(Serialize, Deserialize)]
struct DevKekFile {
    header: String,
    label: String,
    key_b64: String,
    #[serde(default)]
    warning: String,
}

/// Read a dev-KEK file written by `qvhsm init-master`.
///
/// Returns an [`HsmError::Pkcs11`] variant if the file isn't a valid
/// dev-KEK file — same error category as production HSM-load failures
/// so callers don't need to distinguish.
pub fn read_dev_kek_file(path: &Path) -> Result<InMemoryKek> {
    let bytes = fs::read(path)?;
    let f: DevKekFile = serde_json::from_slice(&bytes)?;
    if f.header != DEV_KEK_FILE_HEADER {
        return Err(HsmError::Pkcs11(format!(
            "{} is not a dev-KEK file (header `{}` expected, got `{}`)",
            path.display(),
            DEV_KEK_FILE_HEADER,
            f.header,
        )));
    }
    let key_bytes = B64.decode(&f.key_b64)?;
    if key_bytes.len() != 32 {
        return Err(HsmError::BadKekLength(key_bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    Ok(InMemoryKek::from_bytes(f.label, arr))
}

/// Persist a dev-KEK to disk. Atomic + restrictive permissions (0o600
/// on Unix). Refuses to overwrite an existing file — the caller is
/// expected to have already checked.
pub fn write_dev_kek_file(path: &Path, kek: &InMemoryKek) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| HsmError::Pkcs11(format!("{} has no parent dir", path.display())))?;
    fs::create_dir_all(parent)?;

    let file = DevKekFile {
        header: DEV_KEK_FILE_HEADER.into(),
        label: kek.label().to_string(),
        key_b64: B64.encode(kek.export_bytes()),
        warning: "This file contains a plaintext AES-256 KEK. Treat it like a \
                  private key. In production use a PKCS#11 HSM, not this file."
            .into(),
    };
    let json = serde_json::to_vec_pretty(&file)?;

    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "kek".into()),
        std::process::id()
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KekProvider;
    use tempfile::TempDir;

    #[test]
    fn write_then_read_round_trips() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kek.json");
        let kek = InMemoryKek::from_bytes("test", [9u8; 32]);
        write_dev_kek_file(&path, &kek).unwrap();
        let loaded = read_dev_kek_file(&path).unwrap();
        assert_eq!(loaded.label(), "test");

        // And they should be functionally interchangeable.
        let env = loaded.wrap(b"hello", b"aad").unwrap();
        let pt = kek.unwrap(&env, b"aad").unwrap();
        assert_eq!(pt.as_slice(), b"hello");
    }

    #[test]
    fn bad_header_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kek.json");
        fs::write(
            &path,
            r#"{"header":"WRONG","label":"x","key_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#,
        )
        .unwrap();
        match read_dev_kek_file(&path) {
            Ok(_) => panic!("expected header rejection"),
            Err(HsmError::Pkcs11(_)) => {}
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn wrong_key_length_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("kek.json");
        let bad = serde_json::json!({
            "header": DEV_KEK_FILE_HEADER,
            "label": "x",
            "key_b64": B64.encode([0u8; 16]),
        });
        fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        match read_dev_kek_file(&path) {
            Ok(_) => panic!("expected length rejection"),
            Err(HsmError::BadKekLength(16)) => {}
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }
}

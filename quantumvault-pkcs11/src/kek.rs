//! Key-Encrypting-Key (KEK) providers.
//!
//! The same wrap/unwrap contract is satisfied by:
//!
//! * [`InMemoryKek`] — process-local AES-256-GCM. Used by tests, CI,
//!   and anywhere an HSM isn't present.
//! * [`Pkcs11Kek`] — feature `pkcs11`. Routes the AEAD operation to a
//!   PKCS#11 token via `cryptoki`, so the AES-256 key bytes never
//!   leave the HSM in plaintext.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::envelope::WrappedKey;
use crate::{HsmError, Result};

/// Anything that can seal and unseal byte slices under a named KEK.
///
/// Implementations MUST:
/// * Generate a fresh 12-byte nonce per `wrap()` call (never reuse).
/// * Bind the supplied AAD into AES-GCM so tampering rejects.
/// * Produce envelopes that are byte-identical regardless of backend
///   (so a file sealed in dev can be unsealed in production and
///   vice-versa, given the same KEK material).
pub trait KekProvider {
    /// Seal `plaintext` under this KEK, binding `aad` into the AEAD tag.
    fn wrap(&self, plaintext: &[u8], aad: &[u8]) -> Result<WrappedKey>;

    /// Reverse [`Self::wrap`]. Returns the original plaintext on success.
    fn unwrap(&self, env: &WrappedKey, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>>;

    /// Human-readable label this KEK identifies as on disk. For the
    /// in-memory KEK this is operator-chosen; for the PKCS#11 KEK this
    /// is the CKA_LABEL of the AES object inside the token.
    fn label(&self) -> &str;
}

// -----------------------------------------------------------------------
// In-memory KEK
// -----------------------------------------------------------------------

/// An AES-256-GCM KEK held in process memory.
///
/// Use this in:
/// * unit / integration tests,
/// * CI pipelines where no HSM is available,
/// * customer dev environments before they cut over to PKCS#11.
///
/// The key bytes are zeroised on drop.
pub struct InMemoryKek {
    label: String,
    key: Zeroizing<[u8; 32]>,
}

impl InMemoryKek {
    /// Build a new KEK from raw 32 bytes (AES-256).
    pub fn from_bytes(label: impl Into<String>, key: [u8; 32]) -> Self {
        Self {
            label: label.into(),
            key: Zeroizing::new(key),
        }
    }

    /// Generate a brand-new random KEK. Useful for `qvhsm init-master`.
    pub fn generate(label: impl Into<String>) -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self::from_bytes(label, key)
    }

    /// Expose the raw key bytes. Only intended for `qvhsm init-master`
    /// to persist a freshly generated dev KEK to disk — never call this
    /// from production paths.
    pub fn export_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl KekProvider for InMemoryKek {
    fn wrap(&self, plaintext: &[u8], aad: &[u8]) -> Result<WrappedKey> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| HsmError::BadKekLength(self.key.len()))?;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .map_err(|_| HsmError::DecryptFailed)?;
        Ok(WrappedKey::from_raw(&self.label, aad, &nonce, &ct))
    }

    fn unwrap(&self, env: &WrappedKey, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let decoded = env.decode()?;
        // AAD-in-envelope must match the AAD the caller supplies.
        if decoded.aad != aad {
            return Err(HsmError::DecryptFailed);
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| HsmError::BadKekLength(self.key.len()))?;
        let nonce = Nonce::from_slice(&decoded.nonce);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &decoded.ciphertext,
                    aad: &decoded.aad,
                },
            )
            .map_err(|_| HsmError::DecryptFailed)?;
        Ok(Zeroizing::new(pt))
    }

    fn label(&self) -> &str {
        &self.label
    }
}

// -----------------------------------------------------------------------
// PKCS#11 KEK (feature-gated)
// -----------------------------------------------------------------------

#[cfg(feature = "pkcs11")]
pub use pkcs11_impl::Pkcs11Kek;

#[cfg(feature = "pkcs11")]
mod pkcs11_impl {
    use cryptoki::context::{CInitializeArgs, Pkcs11};
    use cryptoki::mechanism::{aead::GcmParams, Mechanism};
    use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
    use cryptoki::session::{Session, UserType};
    use cryptoki::slot::Slot;
    use cryptoki::types::AuthPin;
    use rand::RngCore;
    use std::path::Path;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    use super::KekProvider;
    use crate::envelope::WrappedKey;
    use crate::{HsmError, Result};

    /// A KEK that lives inside a PKCS#11 token.
    ///
    /// The AES-256 key bytes never leave the HSM. We hold a logged-in
    /// session for the lifetime of this struct and dispatch every
    /// wrap/unwrap to the token via `CKM_AES_GCM`.
    pub struct Pkcs11Kek {
        label: String,
        // The cryptoki session and handle. Mutex because cryptoki's
        // Session methods take &mut self.
        inner: Mutex<Inner>,
    }

    struct Inner {
        session: Session,
        kek_handle: ObjectHandle,
    }

    impl Pkcs11Kek {
        /// Open the supplied PKCS#11 module, log in as `User` to the
        /// given slot with `pin`, and locate the AES KEK whose
        /// `CKA_LABEL` matches `key_label`.
        pub fn open(
            module_path: impl AsRef<Path>,
            slot_id: u64,
            pin: &str,
            key_label: &str,
        ) -> Result<Self> {
            let pkcs11 = Pkcs11::new(module_path.as_ref())
                .map_err(|e| HsmError::Pkcs11(format!("load module: {e}")))?;
            pkcs11
                .initialize(CInitializeArgs::OsThreads)
                .map_err(|e| HsmError::Pkcs11(format!("initialize: {e}")))?;
            let slot = Slot::try_from(slot_id)
                .map_err(|e| HsmError::Pkcs11(format!("invalid slot id: {e}")))?;
            let session = pkcs11
                .open_rw_session(slot)
                .map_err(|e| HsmError::Pkcs11(format!("open session: {e}")))?;
            session
                .login(UserType::User, Some(&AuthPin::new(pin.into())))
                .map_err(|e| HsmError::Pkcs11(format!("login: {e}")))?;

            let kek_handle = find_aes_kek(&session, key_label)?;
            Ok(Self {
                label: key_label.to_string(),
                inner: Mutex::new(Inner { session, kek_handle }),
            })
        }
    }

    fn find_aes_kek(session: &Session, label: &str) -> Result<ObjectHandle> {
        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let handles = session
            .find_objects(&template)
            .map_err(|e| HsmError::Pkcs11(format!("find_objects: {e}")))?;
        handles
            .into_iter()
            .next()
            .ok_or_else(|| HsmError::Pkcs11(format!("no AES key with label `{label}` on token")))
    }

    impl KekProvider for Pkcs11Kek {
        fn wrap(&self, plaintext: &[u8], aad: &[u8]) -> Result<WrappedKey> {
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);

            let guard = self
                .inner
                .lock()
                .map_err(|_| HsmError::Pkcs11("session mutex poisoned".into()))?;

            let params = GcmParams::new(&nonce, aad, 128.into());
            let mech = Mechanism::AesGcm(params);
            let ct = guard
                .session
                .encrypt(&mech, guard.kek_handle, plaintext)
                .map_err(|e| HsmError::Pkcs11(format!("encrypt: {e}")))?;

            Ok(WrappedKey::from_raw(&self.label, aad, &nonce, &ct))
        }

        fn unwrap(&self, env: &WrappedKey, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            let decoded = env.decode()?;
            if decoded.aad != aad {
                return Err(HsmError::DecryptFailed);
            }

            let guard = self
                .inner
                .lock()
                .map_err(|_| HsmError::Pkcs11("session mutex poisoned".into()))?;

            let params = GcmParams::new(&decoded.nonce, aad, 128.into());
            let mech = Mechanism::AesGcm(params);
            let pt = guard
                .session
                .decrypt(&mech, guard.kek_handle, &decoded.ciphertext)
                .map_err(|_| HsmError::DecryptFailed)?;
            Ok(Zeroizing::new(pt))
        }

        fn label(&self) -> &str {
            &self.label
        }
    }

    // Silence an unused-import warning on the `Attribute` re-exports that
    // aren't all referenced in the path above.
    #[allow(dead_code)]
    fn _attribute_type_marker() -> AttributeType {
        AttributeType::Class
    }
}

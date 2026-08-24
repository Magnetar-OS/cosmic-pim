// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// Ported from `src-tauri/src/secrets.rs` in the Meltemi project
// (https://github.com/entro314-labs/meltemi). See NOTICE and LICENSING.md.
//
// Restructured from module-level statics into a struct so that the backend can
// be pointed at a temporary directory in tests, and so the app and the sync
// daemon can hold independent stores without fighting over a `OnceLock`.

//! Credential storage: the OS keychain when it works, an encrypted local
//! envelope when it does not.
//!
//! # Why there is a fallback at all
//!
//! On Linux the "OS keychain" is whatever implements the freedesktop Secret
//! Service — GNOME Keyring, KWallet, or nothing. Headless sessions, minimal
//! window managers, containers, and CI have no such service, and a calendar
//! that refuses to sync because `gnome-keyring-daemon` is not running is not
//! acceptable.
//!
//! So the backend is **probed** with a real set/get/delete round trip, not
//! merely constructed. `keyring::Entry::new` succeeds on hosts where the
//! actual read or write then prompts or fails, so anything less than a full
//! round trip mis-detects.
//!
//! # What the envelope fallback is and is not
//!
//! XChaCha20-Poly1305 under a per-install 32-byte master key written `0600`.
//! That protects secrets from *other users* and from casual file scraping. It
//! does **not** protect them from an attacker already running as this UID —
//! but neither does GNOME Keyring once the session is unlocked, so the fallback
//! is not the weaker link people assume.
//!
//! [`SecretStore::backend`] reports which one is live, so the UI can say so
//! rather than silently downgrading.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::aead::Aead as _;
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use crate::error::{Error, Result};

const KEY_FILE: &str = "secrets.key";
const STORE_FILE: &str = "secrets.enc.json";
const PROBE_SLOT: &str = "__cosmic-pim-backend-probe";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    OsKeychain,
    LocalEnvelope,
}

pub struct SecretStore {
    service: String,
    backend: Backend,
    /// Why the keychain was skipped, when it was. Surfaced in the UI.
    fallback_reason: Option<String>,
    dir: PathBuf,
    /// Serialises envelope read-modify-write cycles, which are not atomic
    /// across separate load/store calls.
    envelope_lock: Mutex<()>,
}

impl SecretStore {
    /// Opens a store, probing the OS keychain to decide the backend.
    ///
    /// `dir` is only used by the envelope fallback; nothing is written there
    /// when the keychain works.
    #[must_use]
    pub fn open(service: &str, dir: &Path) -> Self {
        let (backend, fallback_reason) = match Self::probe(service) {
            Ok(()) => (Backend::OsKeychain, None),
            Err(why) => {
                tracing::warn!(%why, "OS keychain unusable; falling back to a local envelope");
                (Backend::LocalEnvelope, Some(why.to_string()))
            }
        };

        Self {
            service: service.to_owned(),
            backend,
            fallback_reason,
            dir: dir.to_path_buf(),
            envelope_lock: Mutex::new(()),
        }
    }

    /// Opens a store that never touches the OS keychain.
    ///
    /// For tests, and for the `--no-keyring` escape hatch a user needs when
    /// their keyring daemon is present but broken (which happens, and is
    /// otherwise unrecoverable because the probe succeeds).
    #[must_use]
    pub fn open_envelope_only(service: &str, dir: &Path) -> Self {
        Self {
            service: service.to_owned(),
            backend: Backend::LocalEnvelope,
            fallback_reason: Some("explicitly requested".to_owned()),
            dir: dir.to_path_buf(),
            envelope_lock: Mutex::new(()),
        }
    }

    /// A real round trip. `Entry::new` alone proves nothing.
    fn probe(service: &str) -> std::result::Result<(), keyring::Error> {
        let entry = keyring::Entry::new(service, PROBE_SLOT)?;
        entry.set_password("probe")?;
        let read = entry.get_password()?;
        let _ = entry.delete_credential();
        if read == "probe" {
            Ok(())
        } else {
            Err(keyring::Error::Invalid("probe".into(), "mismatch".into()))
        }
    }

    #[must_use]
    pub fn backend(&self) -> Backend {
        self.backend
    }

    #[must_use]
    pub fn fallback_reason(&self) -> Option<&str> {
        self.fallback_reason.as_deref()
    }

    pub fn load(&self, slot: &str) -> Result<Option<String>> {
        match self.backend {
            Backend::OsKeychain => {
                match keyring::Entry::new(&self.service, slot)
                    .map_err(Error::keychain)?
                    .get_password()
                {
                    Ok(v) => Ok(Some(v)),
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(e) => Err(Error::keychain(e)),
                }
            }
            Backend::LocalEnvelope => self.envelope_load(slot),
        }
    }

    pub fn store(&self, slot: &str, value: &str) -> Result<()> {
        match self.backend {
            Backend::OsKeychain => keyring::Entry::new(&self.service, slot)
                .map_err(Error::keychain)?
                .set_password(value)
                .map_err(Error::keychain),
            Backend::LocalEnvelope => self.envelope_store(slot, value),
        }
    }

    /// Best-effort delete. A missing entry is success and anything else is
    /// logged rather than returned: removing an account must not fail because
    /// its password was already gone.
    pub fn forget(&self, slot: &str) {
        let outcome = match self.backend {
            Backend::OsKeychain => keyring::Entry::new(&self.service, slot)
                .map_err(Error::keychain)
                .and_then(|entry| match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                    Err(e) => Err(Error::keychain(e)),
                }),
            Backend::LocalEnvelope => self.envelope_forget(slot),
        };
        if let Err(why) = outcome {
            tracing::warn!(slot, %why, "could not delete secret");
        }
    }

    /* ---------------- envelope fallback ---------------- */

    fn master_key(&self) -> Result<[u8; 32]> {
        let path = self.dir.join(KEY_FILE);

        if let Ok(mut bytes) = std::fs::read(&path) {
            let key: std::result::Result<[u8; 32], _> = bytes.as_slice().try_into();
            // The heap copy must not outlive this read.
            bytes.zeroize();
            return key.map_err(|_| Error::keychain("secrets.key is corrupt (wrong length)"));
        }

        let key: [u8; 32] = rand::random();
        std::fs::create_dir_all(&self.dir).ok();

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            // 0600 before a single byte is written. Creating world-readable and
            // chmod-ing after leaves a window in which the key is exposed.
            opts.mode(0o600);
        }

        let mut file = opts
            .open(&path)
            .map_err(|e| Error::keychain(format!("cannot create secrets.key: {e}")))?;
        file.write_all(&key)
            .map_err(|e| Error::keychain(format!("cannot write secrets.key: {e}")))?;
        file.sync_all()
            .map_err(|e| Error::keychain(format!("cannot flush secrets.key: {e}")))?;
        Ok(key)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        let mut key = self.master_key()?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        key.zeroize();
        Ok(cipher)
    }

    fn read_envelope(&self) -> Envelope {
        std::fs::read(self.dir.join(STORE_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn write_envelope(&self, envelope: &Envelope) -> Result<()> {
        let json = serde_json::to_string(envelope)
            .map_err(|e| Error::keychain(format!("cannot serialise the secret store: {e}")))?;
        // Atomic and fsynced, via the same writer the vdir uses. A torn secret
        // store loses every credential at once.
        cosmic_pim_core::atomic::write(&self.dir.join(STORE_FILE), &json, None)
            .map(|_| ())
            .map_err(|e| Error::keychain(format!("cannot write the secret store: {e}")))
    }

    fn envelope_load(&self, slot: &str) -> Result<Option<String>> {
        let _guard = self.envelope_lock.lock().map_err(|_| Error::poisoned())?;

        let envelope = self.read_envelope();
        let Some(entry) = envelope.entries.get(slot) else {
            return Ok(None);
        };

        let nonce: [u8; 24] = B64
            .decode(&entry.nonce)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| Error::keychain("corrupt secret nonce"))?;
        let ciphertext = B64
            .decode(&entry.ciphertext)
            .map_err(|_| Error::keychain("corrupt secret ciphertext"))?;

        let mut plain = self
            .cipher()?
            .decrypt(&XNonce::from(nonce), ciphertext.as_slice())
            .map_err(|_| Error::keychain("secret decryption failed (master key changed?)"))?;
        let out = String::from_utf8(plain.clone())
            .map_err(|_| Error::keychain("stored secret is not valid UTF-8"));
        plain.zeroize();
        out.map(Some)
    }

    fn envelope_store(&self, slot: &str, value: &str) -> Result<()> {
        let _guard = self.envelope_lock.lock().map_err(|_| Error::poisoned())?;

        let nonce_bytes: [u8; 24] = rand::random();
        let ciphertext = self
            .cipher()?
            .encrypt(&XNonce::from(nonce_bytes), value.as_bytes())
            .map_err(|_| Error::keychain("secret encryption failed"))?;

        let mut envelope = self.read_envelope();
        envelope.entries.insert(
            slot.to_owned(),
            EnvelopeEntry {
                nonce: B64.encode(nonce_bytes),
                ciphertext: B64.encode(ciphertext),
            },
        );
        self.write_envelope(&envelope)
    }

    fn envelope_forget(&self, slot: &str) -> Result<()> {
        let _guard = self.envelope_lock.lock().map_err(|_| Error::poisoned())?;

        let mut envelope = self.read_envelope();
        if envelope.entries.remove(slot).is_some() {
            self.write_envelope(&envelope)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Envelope {
    entries: HashMap<String, EnvelopeEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EnvelopeEntry {
    nonce: String,
    ciphertext: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, SecretStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        // Never probe the real keychain in tests: it would prompt on a
        // developer's desktop and behave differently in CI.
        let store = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        (dir, store)
    }

    #[test]
    fn a_secret_round_trips() {
        let (_dir, store) = store();
        store.store("slot", "hunter2").unwrap();
        assert_eq!(store.load("slot").unwrap().as_deref(), Some("hunter2"));
    }

    #[test]
    fn an_absent_slot_is_none_not_an_error() {
        let (_dir, store) = store();
        assert_eq!(store.load("never-set").unwrap(), None);
    }

    #[test]
    fn forgetting_removes_it() {
        let (_dir, store) = store();
        store.store("slot", "hunter2").unwrap();
        store.forget("slot");
        assert_eq!(store.load("slot").unwrap(), None);
    }

    #[test]
    fn forgetting_something_absent_is_silent() {
        let (_dir, store) = store();
        store.forget("never-set"); // must not panic
    }

    #[test]
    fn several_slots_coexist_and_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
            store.store("a", "one").unwrap();
            store.store("b", "two").unwrap();
        }
        let reopened = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        assert_eq!(reopened.load("a").unwrap().as_deref(), Some("one"));
        assert_eq!(reopened.load("b").unwrap().as_deref(), Some("two"));
    }

    #[test]
    fn overwriting_a_slot_replaces_it() {
        let (_dir, store) = store();
        store.store("slot", "old").unwrap();
        store.store("slot", "new").unwrap();
        assert_eq!(store.load("slot").unwrap().as_deref(), Some("new"));
    }

    #[test]
    fn the_ciphertext_on_disk_does_not_contain_the_plaintext() {
        let (dir, store) = store();
        store.store("slot", "hunter2-plaintext-marker").unwrap();

        let raw = std::fs::read_to_string(dir.path().join(STORE_FILE)).unwrap();
        assert!(
            !raw.contains("hunter2-plaintext-marker"),
            "the secret was written in the clear"
        );
    }

    #[test]
    fn the_same_value_encrypts_differently_each_time() {
        let (dir, store) = store();
        store.store("a", "identical").unwrap();
        store.store("b", "identical").unwrap();

        let raw = std::fs::read_to_string(dir.path().join(STORE_FILE)).unwrap();
        let envelope: Envelope = serde_json::from_str(&raw).unwrap();
        // Nonce reuse under one key is catastrophic for a stream cipher; this
        // pins that each write draws a fresh one.
        assert_ne!(
            envelope.entries["a"].nonce, envelope.entries["b"].nonce,
            "nonce was reused across two encryptions"
        );
        assert_ne!(
            envelope.entries["a"].ciphertext, envelope.entries["b"].ciphertext,
            "identical plaintexts produced identical ciphertexts"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_master_key_is_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, store) = store();
        store.store("slot", "x").unwrap();

        let mode = std::fs::metadata(dir.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secrets.key is readable beyond its owner");
    }

    #[test]
    fn a_secret_written_under_a_different_master_key_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        store.store("slot", "hunter2").unwrap();

        // Simulate a restored backup that carries the store but not the key.
        std::fs::write(dir.path().join(KEY_FILE), [0u8; 32]).unwrap();

        let reopened = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        assert!(
            reopened.load("slot").is_err(),
            "decryption under the wrong key must fail rather than return garbage"
        );
    }

    #[test]
    fn a_corrupt_store_file_does_not_panic() {
        let (dir, store) = store();
        std::fs::write(dir.path().join(STORE_FILE), "{ not json").unwrap();
        assert_eq!(store.load("slot").unwrap(), None);
    }
}

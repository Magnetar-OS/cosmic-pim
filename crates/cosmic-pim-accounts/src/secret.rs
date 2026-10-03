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

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::aead::Aead as _;
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

use crate::error::{Error, Result};

const KEY_FILE: &str = "secrets.key";
const STORE_FILE: &str = "secrets.enc.json";
/// Which backend holds each slot. Plain JSON: slot names are account ids,
/// which already live unencrypted in `accounts.toml` — the *values* are what
/// is secret, and none live here.
const RECORD_FILE: &str = "secrets.backends.json";
const PROBE_SLOT: &str = "__cosmic-pim-backend-probe";

/// How long the keychain probe may take before the store gives up on it.
///
/// A locked Secret Service provider can sit on a `SearchItems` call for
/// *minutes* before answering "the collection is locked" — measured at ~3.5
/// minutes against a locked provider, with every app's init stalled behind
/// it. Three seconds is beyond any healthy daemon's answer time and short
/// enough that a wedged one costs a barely visible pause instead of a hang.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Skips the OS keychain entirely when set (any value).
///
/// The escape hatch for a keyring daemon that is present but broken — or
/// locked forever — which is otherwise unrecoverable from outside the app.
/// Read inside [`SecretStore::open`], so every app in the suite honours it
/// without carrying a flag of its own.
const NO_KEYRING_ENV: &str = "COSMIC_PIM_NO_KEYRING";

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
}

impl SecretStore {
    /// Opens a store, probing the OS keychain to decide the backend.
    ///
    /// `dir` holds the envelope fallback and the per-slot backend record;
    /// nothing secret is written there while the keychain works.
    ///
    /// The probe is bounded by `PROBE_TIMEOUT` — a locked Secret Service
    /// provider blocks for minutes otherwise, and everything downstream of an
    /// app's init would stall behind it. `COSMIC_PIM_NO_KEYRING` skips the
    /// keychain outright.
    #[must_use]
    pub fn open(service: &str, dir: &Path) -> Self {
        if std::env::var_os(NO_KEYRING_ENV).is_some() {
            let mut store = Self::open_envelope_only(service, dir);
            store.fallback_reason = Some(format!("{NO_KEYRING_ENV} is set"));
            return store;
        }

        let (backend, fallback_reason) = match Self::probe_with_timeout(service) {
            Ok(()) => (Backend::OsKeychain, None),
            Err(why) => {
                tracing::warn!(%why, "OS keychain unusable; falling back to a local envelope");
                (Backend::LocalEnvelope, Some(why))
            }
        };

        Self {
            service: service.to_owned(),
            backend,
            fallback_reason,
            dir: dir.to_path_buf(),
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

    /// [`Self::probe`] on its own thread, abandoned if it exceeds
    /// [`PROBE_TIMEOUT`].
    ///
    /// The abandoned thread finishes (or hangs) harmlessly in the background —
    /// its probe entry deletes itself on the way out — while the store gets on
    /// with the envelope. Blocking the caller instead was measured at ~85 s to
    /// four *minutes* of frozen init against a locked provider.
    fn probe_with_timeout(service: &str) -> std::result::Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let owned = service.to_owned();
        let spawned = std::thread::Builder::new()
            .name("keychain-probe".into())
            .spawn(move || {
                let _ = tx.send(Self::probe(&owned).map_err(|e| e.to_string()));
            });
        if spawned.is_err() {
            return Err("could not spawn the keychain probe".to_owned());
        }
        match rx.recv_timeout(PROBE_TIMEOUT) {
            Ok(outcome) => outcome,
            Err(_) => Err(format!(
                "keychain did not answer within {}s (locked or wedged provider?)",
                PROBE_TIMEOUT.as_secs()
            )),
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

    /// Loads a secret, honouring where it was actually written.
    ///
    /// # Why the per-slot record exists
    ///
    /// The backend is decided per *open*. A password stored to the envelope
    /// while the keychain was locked used to become invisible — `Ok(None)`,
    /// not an error — the moment the keychain started answering again, and
    /// the account it belonged to was silently skipped. So every write
    /// records which backend took it, and reads follow the record rather than
    /// the day's probe result. A slot recorded in the keychain while the
    /// keychain is unreachable is an **error naming the problem**, never a
    /// silent `None`.
    pub fn load(&self, slot: &str) -> Result<Option<String>> {
        match self.recorded_backend(slot)? {
            Some(Backend::LocalEnvelope) => self.envelope_load(slot),
            Some(Backend::OsKeychain) => match self.backend {
                Backend::OsKeychain => self.keychain_load(slot),
                Backend::LocalEnvelope => Err(Error::keychain(format!(
                    "this secret lives in the OS keychain, which is unavailable ({})",
                    self.fallback_reason.as_deref().unwrap_or("unknown reason")
                ))),
            },
            // Written before records existed: read the live backend, and on a
            // miss check the envelope — the one place a secret can be without
            // the keychain knowing. Whatever is found gets recorded, so the
            // legacy path runs at most once per slot.
            None => match self.backend {
                Backend::OsKeychain => match self.keychain_load(slot)? {
                    Some(value) => {
                        self.record_found(slot, Backend::OsKeychain);
                        Ok(Some(value))
                    }
                    None => {
                        let fallback = self.envelope_load(slot)?;
                        if fallback.is_some() {
                            self.record_found(slot, Backend::LocalEnvelope);
                        }
                        Ok(fallback)
                    }
                },
                Backend::LocalEnvelope => {
                    let value = self.envelope_load(slot)?;
                    if value.is_some() {
                        self.record_found(slot, Backend::LocalEnvelope);
                    }
                    Ok(value)
                }
            },
        }
    }

    ///
    /// The record of where the secret went is written before any superseded
    /// copy is removed, and a record that cannot be written is an error:
    /// without it a later read follows the old record to the old copy — a
    /// silent `None`, or yesterday's password once the keychain unlocks.
    pub fn store(&self, slot: &str, value: &str) -> Result<()> {
        let previous = self.recorded_backend(slot)?;
        match self.backend {
            Backend::OsKeychain => keyring::Entry::new(&self.service, slot)
                .map_err(Error::keychain)?
                .set_password(value)
                .map_err(Error::keychain)?,
            Backend::LocalEnvelope => self.envelope_store(slot, value)?,
        }
        self.record_backend(slot, self.backend)?;

        // A rewrite that moved backends leaves a stale copy behind. The
        // envelope copy is cheap and safe to remove; a stale *keychain* copy
        // is not touched from the fallback — the keychain being unreachable
        // is why we are here, and one blocked call per save is the bug this
        // module just fixed. The record shadows it either way.
        if previous == Some(Backend::LocalEnvelope) && self.backend == Backend::OsKeychain {
            if let Err(why) = self.envelope_forget(slot) {
                tracing::warn!(slot, %why, "could not remove the superseded envelope copy");
            }
        } else if previous == Some(Backend::OsKeychain) && self.backend == Backend::LocalEnvelope {
            tracing::info!(
                slot,
                "a keychain copy of this secret is now shadowed by the envelope; \
                 it will be overwritten the next time the keychain takes a save"
            );
        }
        Ok(())
    }

    /// Deletes every copy of a secret, then its record.
    ///
    /// A missing entry is success. Anything else is an error, and the record
    /// survives it: erasing the record while a keychain copy remains (the
    /// keychain locked, or this store opened envelope-only) left a secret no
    /// read would ever look for again, with nothing saying it was there
    /// (audit F-42).
    ///
    /// Removes the envelope copy regardless (cheap, and the one place a
    /// stray copy hides), and the keychain copy whenever one may exist.
    pub fn forget(&self, slot: &str) -> Result<()> {
        let recorded = self.recorded_backend(slot)?;
        match self.backend {
            Backend::OsKeychain => {
                let entry = keyring::Entry::new(&self.service, slot).map_err(Error::keychain)?;
                match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => {}
                    Err(e) => return Err(Error::keychain(e)),
                }
            }
            Backend::LocalEnvelope if recorded == Some(Backend::OsKeychain) => {
                return Err(Error::keychain(format!(
                    "this secret lives in the OS keychain, which is unavailable ({}); \
                     it was not deleted",
                    self.fallback_reason.as_deref().unwrap_or("unknown reason")
                )));
            }
            Backend::LocalEnvelope => {}
        }
        self.envelope_forget(slot)?;
        self.erase_record(slot)
    }

    fn keychain_load(&self, slot: &str) -> Result<Option<String>> {
        match keyring::Entry::new(&self.service, slot)
            .map_err(Error::keychain)?
            .get_password()
        {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::keychain(e)),
        }
    }

    /* ---------------- the per-slot backend record ---------------- */

    /// The lock over this store's files, shared by every process and
    /// thread using the same directory.
    ///
    /// Both files are read-modify-write of the whole map, and three apps and
    /// the sync daemon write them. An in-process mutex left processes
    /// overwriting each other's secrets and records.
    fn lock(&self) -> Result<cosmic_pim_core::atomic::Lock> {
        std::fs::create_dir_all(&self.dir)?;
        cosmic_pim_core::atomic::lock(&self.dir.join(STORE_FILE))
            .map_err(|why| Error::keychain(format!("cannot lock the secret store: {why}")))
    }

    /// The record, or none when there is no file yet.
    ///
    /// A file that does not parse reads as empty, unlike the envelope: the
    /// record holds no secret, only where each one went, and every slot
    /// without an entry takes the legacy lookup and is recorded again when
    /// found. Refusing instead would make every save fail until someone
    /// repaired a JSON file by hand. A file that cannot be *read* is an error.
    fn read_records(&self) -> Result<HashMap<String, Backend>> {
        let path = self.dir.join(RECORD_FILE);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_else(|why| {
                tracing::warn!(
                    path = %path.display(), %why,
                    "unreadable secret backend record; every slot will be looked up afresh"
                );
                HashMap::new()
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(e) => Err(Error::keychain(format!(
                "cannot read {}: {e}",
                path.display()
            ))),
        }
    }

    fn recorded_backend(&self, slot: &str) -> Result<Option<Backend>> {
        Ok(self.read_records()?.get(slot).copied())
    }

    fn record_backend(&self, slot: &str, backend: Backend) -> Result<()> {
        let _lock = self.lock()?;
        let mut records = self.read_records()?;
        if records.get(slot) == Some(&backend) {
            return Ok(());
        }
        records.insert(slot.to_owned(), backend);
        self.write_records(&records)
    }

    /// Records where a secret written before records existed was found.
    ///
    /// The one record write allowed to fail quietly: the secret was read, and
    /// a missing record costs one more legacy lookup next time, not a secret.
    fn record_found(&self, slot: &str, backend: Backend) {
        if let Err(why) = self.record_backend(slot, backend) {
            tracing::warn!(slot, %why, "could not record where a legacy secret was found");
        }
    }

    fn erase_record(&self, slot: &str) -> Result<()> {
        let _lock = self.lock()?;
        let mut records = self.read_records()?;
        if records.remove(slot).is_some() {
            self.write_records(&records)?;
        }
        Ok(())
    }

    fn write_records(&self, records: &HashMap<String, Backend>) -> Result<()> {
        let json = serde_json::to_string_pretty(records)
            .map_err(|e| Error::keychain(format!("cannot serialise the backend record: {e}")))?;
        cosmic_pim_core::atomic::write(&self.dir.join(RECORD_FILE), &json, None)
            .map(|_| ())
            .map_err(|e| Error::keychain(format!("cannot write the backend record: {e}")))
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

    /// The envelope on disk, or an empty one when there is no file yet.
    ///
    /// Anything else is an error, never an empty store: every write is a
    /// read-modify-write of the whole file, so an unreadable store read as
    /// empty would be replaced by one holding only the new entry.
    fn read_envelope(&self) -> Result<Envelope> {
        let path = self.dir.join(STORE_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Envelope::default()),
            Err(e) => {
                return Err(Error::keychain(format!(
                    "cannot read {}: {e}",
                    path.display()
                )));
            }
        };
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::keychain(format!("{} is corrupt: {e}", path.display())))
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
        let _lock = self.lock()?;

        let envelope = self.read_envelope()?;
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
        let _lock = self.lock()?;

        let nonce_bytes: [u8; 24] = rand::random();
        let ciphertext = self
            .cipher()?
            .encrypt(&XNonce::from(nonce_bytes), value.as_bytes())
            .map_err(|_| Error::keychain("secret encryption failed"))?;

        let mut envelope = self.read_envelope()?;
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
        let _lock = self.lock()?;

        let mut envelope = self.read_envelope()?;
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
        store.forget("slot").unwrap();
        assert_eq!(store.load("slot").unwrap(), None);
    }

    #[test]
    fn forgetting_something_absent_is_silent() {
        let (_dir, store) = store();
        store.forget("never-set").unwrap(); // must not panic
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
    fn a_corrupt_store_file_is_an_error_not_an_empty_store() {
        // Reading it as empty is a silent miss for every secret in it — and
        // the next write then replaced the file with that empty store plus
        // one entry, destroying the rest for good.
        let (dir, store) = store();
        let path = dir.path().join(STORE_FILE);
        std::fs::write(&path, "{ not json").unwrap();

        assert!(store.load("slot").is_err(), "a corrupt store read as empty");
        assert!(
            store.store("other", "hunter2").is_err(),
            "a write went ahead over a store it could not read"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{ not json",
            "the unreadable store was overwritten"
        );
    }

    /* ---------------- the per-slot backend record ---------------- */

    #[test]
    fn a_write_records_which_backend_took_it() {
        let (dir, store) = store();
        store.store("slot", "hunter2").unwrap();

        let raw = std::fs::read_to_string(dir.path().join(RECORD_FILE)).unwrap();
        assert!(
            raw.contains("local-envelope"),
            "no backend was recorded: {raw}"
        );
    }

    /// The stranding bug this record exists to prevent: a secret written to
    /// the envelope while the keychain was locked must never read back as a
    /// silent `None` under a different backend decision. A record naming an
    /// unreachable keychain is an error that says so.
    #[test]
    fn a_slot_recorded_in_an_unreachable_keychain_is_an_error_not_a_silent_miss() {
        let (dir, store) = store();
        std::fs::write(
            dir.path().join(RECORD_FILE),
            r#"{"work-account":"os-keychain"}"#,
        )
        .unwrap();

        let outcome = store.load("work-account");
        assert!(
            outcome.is_err(),
            "an unreachable recorded backend answered {outcome:?} instead of naming the problem"
        );
        assert!(
            outcome.unwrap_err().to_string().contains("keychain"),
            "the error does not say where the secret lives"
        );
    }

    #[test]
    fn a_recorded_envelope_slot_is_read_from_the_envelope() {
        let (dir, store) = store();
        store.store("slot", "hunter2").unwrap();

        // Reopen and read through the record path explicitly.
        let reopened = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        assert_eq!(
            reopened.recorded_backend("slot").unwrap(),
            Some(Backend::LocalEnvelope)
        );
        assert_eq!(reopened.load("slot").unwrap().as_deref(), Some("hunter2"));
    }

    /// Secrets written before records existed migrate on first read.
    #[test]
    fn a_legacy_slot_without_a_record_is_found_and_recorded() {
        let (dir, store) = store();
        store.store("slot", "hunter2").unwrap();
        std::fs::remove_file(dir.path().join(RECORD_FILE)).unwrap();

        assert_eq!(store.load("slot").unwrap().as_deref(), Some("hunter2"));
        assert_eq!(
            store.recorded_backend("slot").unwrap(),
            Some(Backend::LocalEnvelope),
            "the legacy lookup did not record what it found"
        );
    }

    #[test]
    fn forgetting_erases_the_record_with_the_secret() {
        let (_dir, store) = store();
        store.store("slot", "hunter2").unwrap();
        store.forget("slot").unwrap();

        assert_eq!(store.recorded_backend("slot").unwrap(), None);
        assert_eq!(store.load("slot").unwrap(), None);
    }

    #[test]
    fn a_corrupt_record_file_degrades_to_the_legacy_lookup() {
        let (dir, store) = store();
        store.store("slot", "hunter2").unwrap();
        std::fs::write(dir.path().join(RECORD_FILE), "{ not json").unwrap();

        assert_eq!(store.load("slot").unwrap().as_deref(), Some("hunter2"));
    }

    /// `COSMIC_PIM_NO_KEYRING` must route `open` straight to the envelope —
    /// the escape hatch for a present-but-broken keyring daemon, honoured by
    /// every app because it lives here and not in a per-app flag.
    #[test]
    fn the_no_keyring_env_var_skips_the_keychain_entirely() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: process-global, but no other test in this crate calls
        // `SecretStore::open`, so nothing else observes the variable.
        unsafe { std::env::set_var(NO_KEYRING_ENV, "1") };
        let opened = SecretStore::open("cosmic-pim-test", dir.path());
        unsafe { std::env::remove_var(NO_KEYRING_ENV) };

        assert_eq!(opened.backend(), Backend::LocalEnvelope);
        assert!(
            opened
                .fallback_reason()
                .unwrap_or("")
                .contains(NO_KEYRING_ENV),
            "the UI cannot say why the keychain was skipped"
        );
    }

    #[test]
    fn a_record_that_cannot_be_written_fails_the_store() {
        // The record is what a later read follows. A store that "succeeded"
        // without it left the read looking in the old place.
        let (dir, store) = store();
        std::fs::create_dir_all(dir.path().join(RECORD_FILE)).unwrap();
        assert!(
            store.store("slot", "hunter2").is_err(),
            "the secret was stored with no record of where"
        );
    }

    #[test]
    fn a_keychain_secret_that_could_not_be_deleted_keeps_its_record() {
        // Recorded in the keychain, forgotten from a store that cannot reach
        // it: erasing the record anyway orphaned the keychain copy forever.
        let (dir, store) = store();
        std::fs::write(
            dir.path().join(RECORD_FILE),
            serde_json::to_vec(&HashMap::from([("slot".to_owned(), Backend::OsKeychain)])).unwrap(),
        )
        .unwrap();
        assert!(store.forget("slot").is_err());
        assert_eq!(
            store.recorded_backend("slot").unwrap(),
            Some(Backend::OsKeychain)
        );
    }
}

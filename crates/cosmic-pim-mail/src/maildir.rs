// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! [`MailStore`] over a maildir.
//!
//! # Why maildir and not a database
//!
//! Because the suite's promise is that the user can walk away with their data,
//! and a proprietary message table is where that promise would have quietly
//! died. A maildir is what `mbsync`, `notmuch`, `mu`, `mutt`, and every backup
//! tool already read. The calendar keeps a vdir for exactly the same reason,
//! and this crate is not going to be the place the rule gets an exception.
//!
//! It is also the cheaper option, not the more expensive one. Delivery is a
//! rename; flag changes are a rename; nothing needs a transaction; corruption
//! is confined to one message; and rebuilding the index is a directory walk.
//!
//! # Layout
//!
//! ```text
//! <root>/<local-name>/
//!     cur/                    the messages
//!     new/                    read on scan, never written by us — see below
//!     tmp/                    the maildir spec's staging area
//!     .imap-state.json        the cursor sidecar
//! ```
//!
//! Messages are delivered straight into `cur/`. `new/` means "delivered but not
//! yet seen by a mail *reader*", which is a local concept that we do not own:
//! the message's read state came from the server, is in the flags, and syncs
//! back. A message the user has already read on their phone would land in
//! `new/` and be shown as new, on every device, forever.
//!
//! `new/` is still scanned, because another tool may have delivered there.
//!
//! # What is in the filename, and what is in the sidecar
//!
//! The filename carries the UID (`,U=<n>`, the convention `offlineimap` and
//! `mbsync` established) and the flags (`:2,<letters>`). Both are properties of
//! the message and both are reconstructible by walking the directory — that is
//! what makes the index disposable.
//!
//! The sidecar carries UIDVALIDITY, the UID cursor, and MODSEQ. None of those
//! can be reconstructed from the files: they are opaque tokens the server
//! minted. Putting them in an index would mean clearing a cache re-downloads
//! the mailbox — the same mistake as putting a CalDAV etag in the SQLite cache,
//! and it is called out in `ARCHITECTURE.md` for the calendar case.
//!
//! # Custom keywords
//!
//! Stored the way Dovecot stores them, because that is the mapping every
//! other maildir tool reads: the letters `a`–`z` in the flags field, named
//! by a `dovecot-keywords` file in the maildir root whose line N reads
//! `N keyword-name`. [`crate::model::Flags::keywords`] carries the letters
//! as bits; this store owns the mapping file and hands the names out through
//! [`MailStore::keywords`]. A letter the mapping does not name is preserved
//! in the filename and simply has no name to show — which is exactly how
//! Dovecot treats it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use cosmic_pim_core::atomic;

use crate::error::{Error, Result};
use crate::model::Flags;
use crate::push::{Failure, PendingPush, PushOp, PushQueue};
use crate::store::{Cursor, MailStore, MailboxState, RemoteMessage};

/// The sidecar's filename, beside the maildir's `cur/`.
///
/// Named to sit next to the calendar's `.caldav-state.json` in a listing, and
/// dot-prefixed so neither our own scan nor another maildir tool reads it as a
/// message.
pub const SIDECAR: &str = ".imap-state.json";

/// The keyword mapping's filename — Dovecot's, letter for letter, because
/// interoperability is the entire reason to store keywords this way.
pub const KEYWORDS_FILE: &str = "dovecot-keywords";

/// The `,U=` UID marker, as `offlineimap` and `mbsync` spell it.
const UID_MARKER: &str = ",U=";

/// Separates the message name from its flags. `2` is the only info version
/// maildir ever defined.
const INFO_MARKER: &str = ":2,";

/// Everything about this mailbox that walking the files cannot tell us.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Sidecar {
    #[serde(flatten)]
    cursor: Cursor,
    /// Writes that have not reached the server yet.
    ///
    /// In the sidecar rather than in memory because that is the entire point:
    /// a flag change lost to a crash before it was pushed diverges silently and
    /// permanently. It sits beside the cursor because both are the same kind of
    /// thing — state about the *relationship* with the server, which no amount
    /// of reading the mailbox could reconstruct.
    #[serde(default)]
    pending: Vec<PendingPush>,
}

/// Where mail lives by default: `$XDG_DATA_HOME/mail`.
///
/// Beside `calendars` and `contacts`, and named the same way for the same
/// reason: a user looking for their data should find all of it in one obvious
/// place. `COSMIC_PIM_MAIL_DIR` overrides it, which is how the tests point at a
/// tempdir.
#[must_use]
pub fn default_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("COSMIC_PIM_MAIL_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mail")
}

/// The maildir mirroring one mailbox of one account.
///
/// Accounts are separated by id rather than by address: an address can be
/// re-pointed at a different server, and two accounts can legitimately share
/// one. The id never moves.
#[must_use]
pub fn mailbox_path(root: &Path, account_id: &str, folder: &crate::folder::Folder) -> PathBuf {
    root.join(account_id).join(folder.local_name())
}

/// A maildir holding one IMAP mailbox.
#[derive(Debug)]
pub struct MaildirStore {
    root: PathBuf,
    cursor: Cursor,
    /// UID → the file currently holding it, relative to [`Self::root`].
    ///
    /// Rebuilt by [`Self::rescan`] and maintained across mutations, so a sync
    /// cycle costs one directory walk rather than one per message.
    index: BTreeMap<u32, PathBuf>,
    /// UID → its flags, kept alongside so `state()` needs no `stat` at all.
    flags: BTreeMap<u32, Flags>,
    pending: Vec<PendingPush>,
    /// Row N names keyword bit N. Loaded from [`KEYWORDS_FILE`], rewritten
    /// through the atomic writer when a keyword is interned.
    keywords: Vec<String>,
}

impl MaildirStore {
    /// Opens the maildir at `root`, creating `cur/`, `new/`, and `tmp/` if they
    /// are not there, and reading the sidecar.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for sub in ["cur", "new", "tmp"] {
            fs::create_dir_all(root.join(sub))?;
        }
        let sidecar = read_sidecar(&root)?;
        let keywords = read_keywords(&root);
        let mut store = Self {
            root,
            cursor: sidecar.cursor,
            index: BTreeMap::new(),
            flags: BTreeMap::new(),
            pending: sidecar.pending,
            keywords,
        };
        store.rescan()?;
        Ok(store)
    }

    /// Opens an existing maildir, refusing to create one.
    ///
    /// The distinction matters when the path comes from configuration: silently
    /// creating `~/Mail/Inbx/{cur,new,tmp}` because of a typo hides the mistake
    /// and then reports an empty mailbox.
    pub fn open_existing(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if !root.join("cur").is_dir() {
            return Err(Error::NotAMaildir { path: root });
        }
        Self::open(root)
    }

    /// Rebuilds the UID index by walking `cur/` and `new/`.
    ///
    /// This is the "the index is disposable" property made operational: nothing
    /// but the files is needed to know what the mailbox holds.
    pub fn rescan(&mut self) -> Result<()> {
        self.index.clear();
        self.flags.clear();
        for sub in ["cur", "new"] {
            let dir = self.root.join(sub);
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                // Dotfiles are the sidecar, our own staging temps, and other
                // tools' bookkeeping. The maildir spec reserves them.
                if name.starts_with('.') {
                    continue;
                }
                let Some(uid) = uid_from_name(name) else {
                    // A message another tool delivered without a UID marker. It
                    // is a real message and the user can read it, but it has no
                    // server coordinates, so sync cannot reason about it.
                    continue;
                };
                self.index.insert(uid, Path::new(sub).join(name));
                self.flags.insert(uid, flags_from_name(name));
            }
        }
        Ok(())
    }

    /// The absolute path of the file holding `uid`.
    #[must_use]
    pub fn path_of(&self, uid: u32) -> Option<PathBuf> {
        self.index.get(&uid).map(|rel| self.root.join(rel))
    }

    fn write_sidecar(&self) -> Result<()> {
        let path = self.root.join(SIDECAR);
        let json = serde_json::to_string_pretty(&Sidecar {
            cursor: self.cursor,
            pending: self.pending.clone(),
        })
        .map_err(|source| Error::Sidecar {
            path: path.clone(),
            source,
        })?;
        atomic::write(&path, &json, None)?;
        Ok(())
    }
}

impl MailStore for MaildirStore {
    fn state(&self) -> Result<MailboxState> {
        Ok(MailboxState {
            cursor: self.cursor,
            entries: self.flags.clone(),
        })
    }

    fn upsert(&mut self, message: &RemoteMessage) -> Result<()> {
        let name = file_name_for(message.uid, message.internal_date_ms, message.flags);
        let relative = Path::new("cur").join(&name);
        let target = self.root.join(&relative);

        // `expected: None` — the concurrency guard is for files two writers
        // edit. A maildir message is immutable once delivered: the bytes never
        // change, and a flag change is a rename rather than a write. There is
        // no second writer to lose a race with.
        atomic::write_bytes(&target, &message.raw, None)?;

        // A re-fetch of a UID we already held (a partially applied cycle, or a
        // flag we did not have) leaves the old filename behind, and the scan
        // would then see the same UID twice.
        if let Some(previous) = self.index.insert(message.uid, relative)
            && previous != Path::new("cur").join(&name)
        {
            let _ = fs::remove_file(self.root.join(previous));
        }
        self.flags.insert(message.uid, message.flags);
        Ok(())
    }

    fn set_flags(&mut self, uid: u32, flags: Flags) -> Result<()> {
        let Some(relative) = self.index.get(&uid).cloned() else {
            // Nothing to re-flag. Not an error: a cycle that fetched a flag
            // delta for a message it has not downloaded yet is ordinary, and
            // the fetch that follows carries the flags anyway.
            return Ok(());
        };
        let from = self.root.join(&relative);
        let Some(name) = relative.file_name().and_then(|n| n.to_str()) else {
            return Ok(());
        };
        let renamed = with_flags(name, flags);
        if renamed == name {
            self.flags.insert(uid, flags);
            return Ok(());
        }
        let parent = relative.parent().unwrap_or_else(|| Path::new("cur"));
        let to_relative = parent.join(&renamed);
        // A rename, deliberately, not a rewrite. The flags *are* the filename
        // in maildir, so rewriting the bytes to change one would be pure waste
        // — and would change the mtime every other tool uses to detect that the
        // message itself changed.
        fs::rename(&from, self.root.join(&to_relative))?;
        self.index.insert(uid, to_relative);
        self.flags.insert(uid, flags);
        Ok(())
    }

    fn remove(&mut self, uid: u32) -> Result<()> {
        if let Some(relative) = self.index.remove(&uid) {
            match fs::remove_file(self.root.join(relative)) {
                Ok(()) => {}
                // Already gone. Sync re-runs after partial failures and has to
                // be idempotent.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.flags.remove(&uid);
        Ok(())
    }

    fn raw(&self, uid: u32) -> Result<Option<Vec<u8>>> {
        let Some(path) = self.path_of(uid) else {
            return Ok(None);
        };
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn commit_cursor(&mut self, cursor: Cursor) -> Result<()> {
        self.cursor = cursor;
        self.write_sidecar()
    }

    fn reset(&mut self, uid_validity: u32) -> Result<()> {
        for relative in std::mem::take(&mut self.index).into_values() {
            let _ = fs::remove_file(self.root.join(relative));
        }
        self.flags.clear();
        // Every queued write names a UID in the *old* numbering. Replaying one
        // after a renumbering applies the user's change to whatever message now
        // holds that number, which is worse than dropping it.
        self.pending.clear();
        self.cursor = Cursor {
            uid_validity,
            ..Cursor::default()
        };
        self.write_sidecar()
    }

    fn keywords(&self) -> Vec<String> {
        self.keywords.clone()
    }

    fn intern_keyword(&mut self, name: &str) -> Result<u8> {
        let before = self.keywords.len();
        let bit = crate::store::intern_into(&mut self.keywords, name)?;
        if self.keywords.len() != before {
            write_keywords(&self.root, &self.keywords)?;
        }
        Ok(bit)
    }
}

impl PushQueue for MaildirStore {
    fn pending(&self) -> Vec<PendingPush> {
        self.pending.clone()
    }

    fn enqueue(&mut self, op: PushOp) -> Result<()> {
        crate::push::enqueue_into(&mut self.pending, op);
        self.write_sidecar()
    }

    fn resolve(&mut self, uid: u32) -> Result<()> {
        self.pending.retain(|entry| entry.op.uid() != uid);
        self.write_sidecar()
    }

    fn defer(
        &mut self,
        uid: u32,
        failure: Failure,
        error: &str,
        next_attempt_ms: i64,
    ) -> Result<()> {
        crate::push::defer_in(&mut self.pending, uid, failure, error, next_attempt_ms);
        self.write_sidecar()
    }
}

/// Reads the Dovecot keyword mapping: line N is `N keyword-name`.
///
/// Rows can be sparse in a file another tool wrote (`0 a`, `2 c`); the gaps
/// are kept as empty names so the bit numbering is preserved — renumbering
/// would silently change what a stored flag set means.
fn read_keywords(root: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(root.join(KEYWORDS_FILE)) else {
        return Vec::new();
    };
    let mut table: Vec<String> = Vec::new();
    for line in text.lines() {
        let Some((index, name)) = line.trim().split_once(' ') else {
            continue;
        };
        let Ok(index) = index.parse::<usize>() else {
            continue;
        };
        if index >= usize::from(crate::model::KEYWORD_SLOTS) {
            continue;
        }
        if table.len() <= index {
            table.resize(index + 1, String::new());
        }
        table[index] = name.trim().to_owned();
    }
    table
}

/// Writes the mapping back, atomically — a torn mapping renames every
/// keyword on the next read.
fn write_keywords(root: &Path, table: &[String]) -> Result<()> {
    let mut text = String::new();
    for (index, name) in table.iter().enumerate() {
        if !name.is_empty() {
            text.push_str(&format!("{index} {name}\n"));
        }
    }
    atomic::write(&root.join(KEYWORDS_FILE), &text, None)?;
    Ok(())
}

fn read_sidecar(root: &Path) -> Result<Sidecar> {
    let path = root.join(SIDECAR);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Sidecar::default()),
        Err(e) => return Err(e.into()),
    };
    // A corrupt sidecar is *not* recovered by starting fresh: that would drop
    // queued writes and re-download the mailbox, silently. It surfaces.
    serde_json::from_str::<Sidecar>(&text).map_err(|source| Error::Sidecar { path, source })
}

/// `<seconds>.<uid>.cosmic-pim,U=<uid>:2,<flags>`
///
/// The timestamp comes from the server's INTERNALDATE rather than the clock, so
/// tools that sort `cur/` by filename — and there are several — put the mailbox
/// in the order the user expects rather than in download order.
fn file_name_for(uid: u32, internal_date_ms: i64, flags: Flags) -> String {
    let seconds = internal_date_ms.div_euclid(1000).max(0);
    format!(
        "{seconds}.{uid}.cosmic-pim{UID_MARKER}{uid}{INFO_MARKER}{}",
        flags.to_maildir_info()
    )
}

/// The UID a filename records, if it records one.
fn uid_from_name(name: &str) -> Option<u32> {
    let after = name.split(UID_MARKER).nth(1)?;
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn flags_from_name(name: &str) -> Flags {
    name.split_once(INFO_MARKER)
        .map_or_else(Flags::default, |(_, info)| Flags::from_maildir_info(info))
}

/// The same filename with a different flag set.
fn with_flags(name: &str, flags: Flags) -> String {
    let base = name.split_once(INFO_MARKER).map_or(name, |(base, _)| base);
    format!("{base}{INFO_MARKER}{}", flags.to_maildir_info())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn message(uid: u32, flags: Flags) -> RemoteMessage {
        RemoteMessage {
            uid,
            flags,
            raw: format!("Subject: message {uid}\r\n\r\nbody\r\n").into_bytes(),
            internal_date_ms: 1_700_000_000_000 + i64::from(uid) * 1000,
        }
    }

    fn seen() -> Flags {
        Flags {
            seen: true,
            ..Flags::default()
        }
    }

    fn open() -> (tempfile::TempDir, MaildirStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = MaildirStore::open(dir.path().join("INBOX")).unwrap();
        (dir, store)
    }

    #[test]
    fn a_delivered_message_is_readable_back_byte_for_byte() {
        let (_dir, mut store) = open();
        let message = message(7, seen());
        store.upsert(&message).unwrap();
        assert_eq!(store.raw(7).unwrap().unwrap(), message.raw);
    }

    #[test]
    fn message_bytes_that_are_not_utf8_survive_storage() {
        // A latin-1 body, an 8-bit MIME part, a binary attachment: all
        // routine, none of them valid UTF-8. Lossy conversion would corrupt
        // the message and invalidate its DKIM signature in one step.
        let (_dir, mut store) = open();
        let raw =
            b"Subject: caf\xe9\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9\r\n";
        store
            .upsert(&RemoteMessage {
                uid: 1,
                flags: Flags::default(),
                raw: raw.to_vec(),
                internal_date_ms: 0,
            })
            .unwrap();
        assert_eq!(store.raw(1).unwrap().unwrap(), raw.to_vec());
    }

    #[test]
    fn the_index_rebuilds_from_the_files_alone() {
        // "The index is disposable" has to be literally true, or the sidecar
        // has quietly become the source of truth.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("INBOX");
        {
            let mut store = MaildirStore::open(&path).unwrap();
            store.upsert(&message(1, seen())).unwrap();
            store.upsert(&message(2, Flags::default())).unwrap();
        }
        let reopened = MaildirStore::open(&path).unwrap();
        let state = reopened.state().unwrap();
        assert_eq!(state.entries.len(), 2);
        assert_eq!(state.entries[&1], seen());
        assert_eq!(state.entries[&2], Flags::default());
    }

    #[test]
    fn the_cursor_survives_a_reopen_because_it_cannot_be_derived() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("INBOX");
        let cursor = Cursor {
            uid_validity: 12_345,
            last_uid: 99,
            highest_modseq: 4_242,
            accepts_keywords: true,
        };
        {
            let mut store = MaildirStore::open(&path).unwrap();
            store.commit_cursor(cursor).unwrap();
        }
        assert_eq!(
            MaildirStore::open(&path).unwrap().state().unwrap().cursor,
            cursor
        );
    }

    #[test]
    fn a_flag_change_renames_rather_than_rewrites() {
        let (_dir, mut store) = open();
        store.upsert(&message(3, Flags::default())).unwrap();
        let before = store.path_of(3).unwrap();
        let bytes = store.raw(3).unwrap().unwrap();

        store.set_flags(3, seen()).unwrap();

        let after = store.path_of(3).unwrap();
        assert_ne!(before, after, "the flags did not reach the filename");
        assert!(
            !before.exists(),
            "the old name was left behind as a duplicate"
        );
        assert!(
            after
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(":2,S")
        );
        assert_eq!(
            store.raw(3).unwrap().unwrap(),
            bytes,
            "the bytes were rewritten"
        );
    }

    #[test]
    fn keywords_intern_once_and_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = MaildirStore::open(dir.path()).unwrap();

        let travel = store.intern_keyword("Travel").unwrap();
        let work = store.intern_keyword("work").unwrap();
        assert_eq!((travel, work), (0, 1));
        // Case-insensitive: the same keyword, the same bit, first spelling kept.
        assert_eq!(store.intern_keyword("TRAVEL").unwrap(), 0);
        assert_eq!(store.keywords(), vec!["Travel", "work"]);

        // The mapping is the Dovecot file, readable by anything.
        let text = std::fs::read_to_string(dir.path().join(KEYWORDS_FILE)).unwrap();
        assert_eq!(text, "0 Travel\n1 work\n");

        let reopened = MaildirStore::open(dir.path()).unwrap();
        assert_eq!(reopened.keywords(), vec!["Travel", "work"]);
    }

    #[test]
    fn a_sparse_mapping_written_by_another_tool_keeps_its_numbering() {
        // Renumbering rows would silently change what a stored flag means.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("cur")).unwrap();
        std::fs::write(dir.path().join(KEYWORDS_FILE), "0 alpha\n2 gamma\n").unwrap();

        let mut store = MaildirStore::open(dir.path()).unwrap();
        assert_eq!(store.keywords(), vec!["alpha", "", "gamma"]);
        assert_eq!(store.intern_keyword("gamma").unwrap(), 2);
        assert_eq!(
            store.intern_keyword("delta").unwrap(),
            3,
            "a new keyword took a gap row and renamed somebody's bit"
        );
    }

    #[test]
    fn the_letter_space_is_the_honest_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = MaildirStore::open(dir.path()).unwrap();
        for n in 0..26 {
            store.intern_keyword(&format!("kw{n}")).unwrap();
        }
        assert!(
            store.intern_keyword("one-too-many").is_err(),
            "a 27th keyword has no letter to live in"
        );
        for bad in ["", "has space", "par(en", "back\\slash", "brack]et"] {
            assert!(store.intern_keyword(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_keyword_letter_reaches_the_filename_and_comes_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = MaildirStore::open(dir.path()).unwrap();
        let bit = store.intern_keyword("travel").unwrap();
        store
            .upsert(&RemoteMessage {
                uid: 7,
                flags: Flags::default().with_keyword(bit, true),
                raw: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
                internal_date_ms: 0,
            })
            .unwrap();

        let mut reopened = MaildirStore::open(dir.path()).unwrap();
        reopened.rescan().unwrap();
        let flags = reopened.state().unwrap().entries[&7];
        assert!(
            flags.keywords & (1 << bit) != 0,
            "the keyword letter did not survive the filename round trip"
        );
    }

    #[test]
    fn flags_are_recovered_from_the_filename_on_rescan() {
        let (_dir, mut store) = open();
        store.upsert(&message(4, Flags::default())).unwrap();
        store
            .set_flags(
                4,
                Flags {
                    seen: true,
                    flagged: true,
                    ..Flags::default()
                },
            )
            .unwrap();
        store.rescan().unwrap();
        let state = store.state().unwrap();
        assert!(state.entries[&4].seen && state.entries[&4].flagged);
    }

    #[test]
    fn refetching_a_uid_does_not_leave_a_second_copy() {
        // A cycle that stored the message and then failed before committing
        // its cursor re-fetches it, possibly with different flags.
        let (_dir, mut store) = open();
        store.upsert(&message(5, Flags::default())).unwrap();
        store.upsert(&message(5, seen())).unwrap();
        store.rescan().unwrap();
        let state = store.state().unwrap();
        assert_eq!(
            state.entries.len(),
            1,
            "the mailbox now shows the message twice"
        );
        assert_eq!(state.entries[&5], seen());
    }

    #[test]
    fn removing_a_message_that_is_already_gone_is_not_an_error() {
        let (_dir, mut store) = open();
        store.upsert(&message(6, seen())).unwrap();
        store.remove(6).unwrap();
        store
            .remove(6)
            .expect("sync re-runs and must be idempotent");
        assert!(store.raw(6).unwrap().is_none());
    }

    #[test]
    fn a_renumbering_clears_the_mailbox_and_the_cursor_together() {
        let (_dir, mut store) = open();
        store.upsert(&message(1, seen())).unwrap();
        store
            .commit_cursor(Cursor {
                uid_validity: 1,
                last_uid: 1,
                highest_modseq: 7,
                accepts_keywords: false,
            })
            .unwrap();

        store.reset(2).unwrap();

        let state = store.state().unwrap();
        assert!(state.entries.is_empty(), "old-numbering messages survived");
        assert_eq!(state.cursor.uid_validity, 2);
        assert_eq!(state.cursor.last_uid, 0);
        assert_eq!(
            state.cursor.highest_modseq, 0,
            "a MODSEQ from the old numbering would skip the whole refetch"
        );
    }

    #[test]
    fn the_sidecar_is_not_read_back_as_a_message() {
        let (_dir, mut store) = open();
        store.upsert(&message(1, seen())).unwrap();
        store.commit_cursor(Cursor::default()).unwrap();
        store.rescan().unwrap();
        assert_eq!(store.state().unwrap().entries.len(), 1);
    }

    #[test]
    fn a_message_another_tool_delivered_without_a_uid_is_left_alone() {
        // mbsync and a plain MDA both write files we did not name. They are
        // real messages, but they have no server coordinates, so sync must
        // neither claim them nor delete them.
        let (_dir, mut store) = open();
        let foreign = store.root.join("cur").join("1700000000.M1P2.host:2,S");
        fs::write(&foreign, b"Subject: not ours\r\n\r\n").unwrap();
        store.rescan().unwrap();
        assert!(store.state().unwrap().entries.is_empty());
        assert!(foreign.exists(), "a foreign message was deleted");
    }

    #[test]
    fn opening_a_path_that_is_not_a_maildir_refuses_rather_than_creating_one() {
        let dir = tempfile::tempdir().unwrap();
        let typo = dir.path().join("Inbx");
        assert!(matches!(
            MaildirStore::open_existing(&typo),
            Err(Error::NotAMaildir { .. })
        ));
        assert!(!typo.exists(), "the typo was created and will report empty");
    }

    #[test]
    fn filenames_carry_the_uid_in_the_conventional_place() {
        // `,U=` is what offlineimap and mbsync read. Getting this wrong means
        // no other tool can line our files up with the server.
        let name = file_name_for(42, 1_700_000_000_000, seen());
        assert!(name.contains(",U=42:"), "{name}");
        assert_eq!(uid_from_name(&name), Some(42));
        assert_eq!(flags_from_name(&name), seen());
        assert_eq!(uid_from_name("1700000000.M1P2.host:2,S"), None);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod queue_tests {
    use super::*;
    use crate::push::{Failure, PushOp, PushQueue};

    fn seen() -> Flags {
        Flags {
            seen: true,
            ..Flags::default()
        }
    }

    #[test]
    fn a_queued_write_survives_a_restart() {
        // The whole reason the queue is on disk. A flag change lost to a crash
        // before it was pushed diverges silently and permanently.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("INBOX");
        {
            let mut store = MaildirStore::open(&path).unwrap();
            store
                .enqueue(PushOp::SetFlags {
                    uid: 4,
                    flags: seen(),
                })
                .unwrap();
        }
        let store = MaildirStore::open(&path).unwrap();
        assert_eq!(store.pending().len(), 1);
        assert_eq!(store.pending()[0].op.uid(), 4);
    }

    #[test]
    fn a_blocked_entrys_reason_survives_a_restart_too() {
        // So the UI can still say *why* after the app was closed and reopened.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("INBOX");
        {
            let mut store = MaildirStore::open(&path).unwrap();
            store.enqueue(PushOp::Delete { uid: 9 }).unwrap();
            store
                .defer(9, Failure::User, "NO [NOPERM] read-only mailbox", 0)
                .unwrap();
        }
        let store = MaildirStore::open(&path).unwrap();
        let entry = &store.pending()[0];
        assert_eq!(entry.blocked, Some(Failure::User));
        assert!(entry.last_error.as_deref().unwrap().contains("NOPERM"));
    }

    #[test]
    fn a_renumbering_discards_queued_writes_with_the_messages() {
        // Every queued op names a UID in the old numbering.
        let dir = tempfile::tempdir().unwrap();
        let mut store = MaildirStore::open(dir.path().join("INBOX")).unwrap();
        store
            .enqueue(PushOp::SetFlags {
                uid: 1,
                flags: seen(),
            })
            .unwrap();
        store.reset(2).unwrap();
        assert!(
            store.pending().is_empty(),
            "a queued write would have been applied to a different message"
        );
    }

    #[test]
    fn a_corrupt_sidecar_surfaces_rather_than_silently_resetting() {
        // Starting fresh here would drop queued writes and re-download the
        // mailbox, with nothing in the log to say it happened.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("INBOX");
        MaildirStore::open(&path).unwrap();
        fs::write(path.join(SIDECAR), b"{ truncated").unwrap();
        assert!(matches!(
            MaildirStore::open(&path),
            Err(Error::Sidecar { .. })
        ));
    }
}

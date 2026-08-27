// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Unsent messages, kept on this device.
//!
//! # Why local, and not the server's Drafts folder
//!
//! Because the alternative silently duplicates, and a duplicated draft is
//! worse than a local one.
//!
//! Saving to the server means APPEND. The server then assigns the message a UID
//! that the client does not learn unless the server implements UIDPLUS — and
//! without it, the next sync pulls the draft back down as a *new* message that
//! the client has no way to recognise as the one it just uploaded. Every edit
//! leaves another copy. Solving that needs UIDPLUS where it exists, a
//! `Message-ID` match where it does not, and a reconciliation pass for the
//! servers that mangle both. It is a project, and it is not the project that
//! stands between a user and not losing what they typed.
//!
//! So a draft is a file here, on this machine, and Envelope says so. When
//! server-side drafts arrive, this is where they plug in: the store stays, the
//! sync is added beside it.
//!
//! # Shape
//!
//! One JSON file per draft, holding a [`Draft`], in a directory beside the
//! account's maildirs.
//!
//! **Not** RFC 5322, and the reason is the same one that makes drafts local: a
//! draft is unfinished. It routinely has no recipients yet and often has an
//! address somebody stopped halfway through typing, and a message format
//! refuses to represent either — `lettre` will not build a message with no
//! destination, correctly, because such a thing cannot be sent. Storing the
//! record keeps the round trip exact, including the half-typed address, and
//! costs nothing: these files never leave this machine, so message-format
//! interoperability buys nothing here.
//!
//! Also not a maildir. A maildir filename carries flags and a UID, and a draft
//! has neither — pretending otherwise would invite a sync engine to adopt them.

use std::fs;
use std::path::{Path, PathBuf};

use cosmic_pim_core::atomic;

use crate::compose::Draft;
use crate::error::{Error, Result};
use crate::model::Mailbox;

/// The directory drafts live in, beside the account's maildirs.
///
/// Dot-prefixed so a maildir walker never reads it as a mailbox.
const DIRECTORY: &str = ".drafts";

const EXTENSION: &str = ".draft.json";

/// A deleted-but-mirrored draft's tombstone: the file holds the `Message-ID`
/// whose server copy still needs retiring.
const RETRACT_EXTENSION: &str = ".retract";

/// A saved draft: its id, and enough to list it without opening it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    /// Stable across edits — re-saving replaces rather than accumulates.
    pub id: String,
    pub subject: String,
    /// Who it is addressed to, for the list row.
    pub to: String,
    /// When it was last written, in epoch milliseconds.
    pub saved_ms: i64,
}

/// Drafts for one account.
#[derive(Debug)]
pub struct Drafts {
    root: PathBuf,
}

impl Drafts {
    /// Opens (creating if needed) the draft store under an account's mail root.
    pub fn open(account_root: impl AsRef<Path>) -> Result<Self> {
        let root = account_root.as_ref().join(DIRECTORY);
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Writes a draft, replacing any earlier version with the same id.
    ///
    /// The blind-copy list is kept: this copy is the user's own, and losing the
    /// record of who they were blind-copying between one editing session and
    /// the next is the same data loss saving exists to prevent.
    ///
    /// The mirror linkage survives a save, and the save marks it dirty: the
    /// server's copy is now behind this one, and the next mirror pass knows.
    pub fn save(&self, id: &str, draft: &Draft, now_ms: i64) -> Result<()> {
        if !is_valid_id(id) {
            return Err(Error::Draft(format!("{id} is not a draft id")));
        }
        let mut mirror = self
            .record(id)
            .ok()
            .flatten()
            .map(|record| record.mirror)
            .unwrap_or_default();
        mirror.dirty = true;
        let record = Record {
            saved_ms: now_ms,
            draft: draft.clone(),
            mirror,
        };
        // Through the substrate's writer, so a crash mid-save cannot leave a
        // truncated draft where a whole one was.
        self.write(id, &record)
    }

    /// Reads one draft back into an editable form.
    ///
    /// `from` replaces whatever identity was saved: the account's may have
    /// changed since, and the current one is the address it would actually go
    /// out as.
    pub fn load(&self, id: &str, from: Mailbox) -> Result<Option<Draft>> {
        let Some(record) = self.record(id)? else {
            return Ok(None);
        };
        let mut draft = record.draft;
        draft.from = from;
        Ok(Some(draft))
    }

    /// Every saved draft, most recently written first.
    pub fn list(&self) -> Result<Vec<Saved>> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Ok(Vec::new());
        };

        let mut saved: Vec<Saved> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|n| n.strip_suffix(EXTENSION)) else {
                continue;
            };
            // A draft that will not load is still listed, under its id. It is
            // the user's text; hiding it because the file is damaged would lose
            // it more thoroughly than the damage did.
            let record = self.record(id).ok().flatten();
            saved.push(Saved {
                subject: record
                    .as_ref()
                    .map(|r| r.draft.subject.clone())
                    .unwrap_or_default(),
                to: record
                    .as_ref()
                    .map(|r| {
                        r.draft
                            .to
                            .iter()
                            .map(|to| to.display().to_owned())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default(),
                saved_ms: record
                    .as_ref()
                    .map(|r| r.saved_ms)
                    .unwrap_or_else(|| modified_ms(&entry.path())),
                id: id.to_owned(),
            });
        }

        saved.sort_by_key(|draft| std::cmp::Reverse(draft.saved_ms));
        Ok(saved)
    }

    /// Removes a draft. Already gone is not an error — a draft is deleted when
    /// its message is sent, and a retried send must not fail on the second
    /// attempt.
    ///
    /// A draft that was mirrored leaves a **tombstone** naming its
    /// `Message-ID`, so the server copy can be retired on the next pass even
    /// when this delete happens offline. Without it, discarding a draft on a
    /// train resurrects it on every other device.
    pub fn delete(&self, id: &str) -> Result<()> {
        if let Ok(Some(record)) = self.record(id)
            && let Some(message_id) = record.mirror.message_id
        {
            atomic::write(
                &self.root.join(format!("{id}{RETRACT_EXTENSION}")),
                &message_id,
                None,
            )?;
        }
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Mirrored drafts that were deleted locally and still need their server
    /// copy retired: `(draft id, message id)`.
    pub fn pending_retractions(&self) -> Vec<(String, String)> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut pending: Vec<(String, String)> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name();
                let id = name.to_str()?.strip_suffix(RETRACT_EXTENSION)?.to_owned();
                let message_id = fs::read_to_string(entry.path()).ok()?;
                Some((id, message_id.trim().to_owned()))
            })
            .collect();
        pending.sort();
        pending
    }

    /// Drops a tombstone — its server copy is gone.
    pub fn clear_retraction(&self, id: &str) -> Result<()> {
        if !is_valid_id(id) {
            return Ok(());
        }
        match fs::remove_file(self.root.join(format!("{id}{RETRACT_EXTENSION}"))) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    #[must_use]
    pub fn count(&self) -> usize {
        fs::read_dir(&self.root)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_str()
                            .is_some_and(|name| name.ends_with(EXTENSION))
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    fn record(&self, id: &str) -> Result<Option<Record>> {
        if !is_valid_id(id) {
            return Ok(None);
        }
        let text = match fs::read_to_string(self.path(id)) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|why| Error::Draft(format!("draft {id} could not be read back: {why}")))
    }

    fn path(&self, id: &str) -> PathBuf {
        // Callers validate first; ids are hex, so nothing here can escape the
        // directory. An invalid id is rejected rather than sanitised — a
        // silently rewritten id would load a different draft than it saved.
        self.root.join(format!("{id}{EXTENSION}"))
    }
}

/// What is on disk: the draft, and when it was written.
///
/// The timestamp is stored rather than read from the file's mtime because a
/// copy, a backup restore, or a sync tool rewrites mtimes and would reorder the
/// list for no reason the user could see.
#[derive(serde::Serialize, serde::Deserialize)]
struct Record {
    saved_ms: i64,
    draft: Draft,
    /// Where (and whether) this draft is mirrored on the server. Defaulted on
    /// read so records written before mirroring existed load unchanged.
    #[serde(default)]
    mirror: Mirror,
}

/// The server-side linkage of one draft.
///
/// The local record stays the authority — see the module documentation — and
/// this is the receipt for its last upload: enough to *replace* the server
/// copy rather than accumulate beside it, which is the entire difficulty of
/// server-side drafts.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Mirror {
    /// The `Message-ID` (without brackets) the mirror is filed under. Minted
    /// once per draft and stable across edits, so the old copy can always be
    /// found by search — the replacement path for servers without UIDPLUS.
    pub message_id: Option<String>,
    /// Where the last upload landed, when the server said (UIDPLUS's
    /// APPENDUID). A UID is only meaningful beside its UIDVALIDITY.
    pub uid_validity: Option<u32>,
    pub uid: Option<u32>,
    /// The record has been edited since the server last saw it. Set by every
    /// save, cleared by a successful upload — which is what makes mirroring
    /// safe to retry from a poll: an upload that did not happen leaves this
    /// standing.
    pub dirty: bool,
}

impl Drafts {
    /// The mirror linkage of one draft, if the draft exists.
    pub fn mirror(&self, id: &str) -> Result<Option<Mirror>> {
        Ok(self.record(id)?.map(|record| record.mirror))
    }

    /// The draft exactly as stored, identity included — what a mirror uploads.
    ///
    /// [`Self::load`] replaces the identity with the account's current one,
    /// which is right for *editing*; an upload must write what was saved.
    pub fn peek(&self, id: &str) -> Result<Option<Draft>> {
        Ok(self.record(id)?.map(|record| record.draft))
    }

    /// Every draft the server has not seen the latest version of.
    pub fn dirty(&self) -> Result<Vec<String>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|saved| {
                self.record(&saved.id)
                    .ok()
                    .flatten()
                    .is_some_and(|record| record.mirror.dirty)
            })
            .map(|saved| saved.id)
            .collect())
    }

    /// Records a successful upload: the id it is filed under, and the UID the
    /// server assigned when it said (`None` on servers without UIDPLUS).
    pub fn mark_mirrored(
        &self,
        id: &str,
        message_id: &str,
        landed: Option<(u32, u32)>,
    ) -> Result<()> {
        let Some(mut record) = self.record(id)? else {
            // The draft was deleted while its upload was in flight. Nothing to
            // record — the retraction path handles the server copy.
            return Ok(());
        };
        record.mirror.message_id = Some(message_id.to_owned());
        record.mirror.uid_validity = landed.map(|(validity, _)| validity);
        record.mirror.uid = landed.map(|(_, uid)| uid);
        record.mirror.dirty = false;
        self.write(id, &record)
    }

    /// Creates a local record for a draft that already lives on the server —
    /// one written by another device, opened here for editing.
    ///
    /// Linked and clean: the server copy *is* the latest version until the
    /// first local save marks it dirty.
    pub fn adopt(
        &self,
        id: &str,
        draft: &Draft,
        message_id: &str,
        uid_validity: u32,
        uid: u32,
        now_ms: i64,
    ) -> Result<()> {
        if !is_valid_id(id) {
            return Err(Error::Draft(format!("{id} is not a draft id")));
        }
        self.write(
            id,
            &Record {
                saved_ms: now_ms,
                draft: draft.clone(),
                mirror: Mirror {
                    message_id: Some(message_id.to_owned()),
                    uid_validity: Some(uid_validity),
                    uid: Some(uid),
                    dirty: false,
                },
            },
        )
    }

    fn write(&self, id: &str, record: &Record) -> Result<()> {
        let json =
            serde_json::to_string_pretty(record).map_err(|why| Error::Draft(why.to_string()))?;
        atomic::write(&self.path(id), &json, None)?;
        Ok(())
    }
}

/// A fresh draft id.
///
/// Derived from the clock rather than random so that ids sort by creation and a
/// directory listing is chronological even without stat'ing every file. Two
/// drafts created in the same millisecond would collide; the composer creates
/// one at a time, in response to a keystroke.
#[must_use]
pub fn new_id(now_ms: i64) -> String {
    format!("{:016x}", now_ms.max(0))
}

/// Is this an id this module could have minted?
///
/// Checked before any path is built from it: an id that is not hex has come
/// from somewhere it should not have, and joining it to a directory is how a
/// `../` ends up in a path.
#[must_use]
pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn modified_ms(path: &Path) -> i64 {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|since| i64::try_from(since.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn me() -> Mailbox {
        Mailbox {
            name: Some("Me".into()),
            address: "me@example.com".into(),
        }
    }

    fn draft() -> Draft {
        let mut draft = Draft::new(me());
        draft.to.push(Mailbox {
            name: Some("Ada".into()),
            address: "ada@example.com".into(),
        });
        draft.cc.push(Mailbox {
            name: None,
            address: "bob@example.net".into(),
        });
        draft.subject = "Half-written".into();
        draft.body = "This is as far as I got.".into();
        draft
    }

    #[test]
    fn a_saved_draft_comes_back_as_what_was_typed() {
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let id = new_id(1_700_000_000_000);

        drafts.save(&id, &draft(), 1_700_000_000_000).unwrap();
        let loaded = drafts
            .load(&id, me())
            .unwrap()
            .expect("the draft came back");

        assert_eq!(loaded.subject, "Half-written");
        assert_eq!(loaded.body.trim(), "This is as far as I got.");
        assert_eq!(loaded.to[0].address, "ada@example.com");
        assert_eq!(loaded.cc[0].address, "bob@example.net");
        assert_eq!(loaded.from.address, "me@example.com");
    }

    #[test]
    fn a_blind_copy_survives_an_editing_session() {
        // The user's own copy. Losing who they were blind-copying between one
        // sitting and the next is the same data loss saving exists to prevent.
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let mut draft = draft();
        draft.bcc.push(Mailbox {
            name: None,
            address: "secret@example.org".into(),
        });
        let id = new_id(1);

        drafts.save(&id, &draft, 1).unwrap();
        let loaded = drafts.load(&id, me()).unwrap().unwrap();
        assert_eq!(loaded.bcc[0].address, "secret@example.org");
    }

    #[test]
    fn a_reply_saved_as_a_draft_still_threads_when_it_is_sent() {
        // The threading headers have to survive the round trip through a file,
        // or a reply written on Monday and sent on Tuesday starts a new thread.
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let original = crate::model::Message::parse(
            b"Message-ID: <parent@x>\r\nReferences: <root@x>\r\nFrom: Ada <ada@example.com>\r\n\
              To: me@example.com\r\nSubject: Plan\r\n\r\nbody\r\n",
        )
        .unwrap();

        let id = new_id(2);
        drafts
            .save(&id, &Draft::reply(&original, me(), false), 2)
            .unwrap();

        let loaded = drafts.load(&id, me()).unwrap().unwrap();
        assert_eq!(loaded.in_reply_to.as_deref(), Some("parent@x"));
        assert_eq!(loaded.references, vec!["root@x", "parent@x"]);
        assert_eq!(loaded.subject, "Re: Plan");
    }

    #[test]
    fn re_saving_replaces_rather_than_accumulates() {
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let id = new_id(3);

        for body in ["first", "second", "third"] {
            let mut draft = draft();
            draft.body = body.into();
            drafts.save(&id, &draft, 3).unwrap();
        }

        assert_eq!(drafts.count(), 1, "every keystroke left a file behind");
        assert_eq!(
            drafts.load(&id, me()).unwrap().unwrap().body.trim(),
            "third"
        );
    }

    #[test]
    fn drafts_are_listed_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        for (n, subject) in [(1, "older"), (2, "newer")] {
            let mut draft = draft();
            draft.subject = subject.into();
            drafts.save(&new_id(n), &draft, n).unwrap();
            // Filesystem mtime has coarse resolution on some systems; the ids
            // themselves are chronological, which is the tiebreak.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let listed = drafts.list().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].subject, "newer");
        assert_eq!(listed[0].to, "Ada");
    }

    #[test]
    fn a_sent_draft_is_deleted_and_deleting_twice_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let id = new_id(4);
        drafts.save(&id, &draft(), 4).unwrap();

        drafts.delete(&id).unwrap();
        drafts
            .delete(&id)
            .expect("a retried send must not fail here");
        assert!(drafts.load(&id, me()).unwrap().is_none());
        assert_eq!(drafts.count(), 0);
    }

    #[test]
    fn a_draft_with_no_recipients_yet_still_saves() {
        // The ordinary case: somebody started writing and closed the window.
        // Refusing here would refuse exactly the drafts worth keeping.
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let mut draft = Draft::new(me());
        draft.subject = "Thinking about it".into();
        draft.body = "…".into();

        let id = new_id(5);
        drafts
            .save(&id, &draft, 5)
            .expect("a half-written draft must save");
        let loaded = drafts.load(&id, me()).unwrap().unwrap();
        assert_eq!(loaded.subject, "Thinking about it");
        assert!(loaded.to.is_empty());
    }

    #[test]
    fn a_half_typed_address_comes_back_exactly_as_it_was_typed() {
        // The reason a draft is stored as a record and not as a message: a
        // message format cannot represent "ada@exam", and somebody who stopped
        // mid-word should find their own text where they left it.
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let mut draft = Draft::new(me());
        draft.to.push(Mailbox {
            name: None,
            address: "ada@exam".into(),
        });
        draft.subject = "Partly addressed".into();

        let id = new_id(6);
        drafts.save(&id, &draft, 6).expect("save");
        let loaded = drafts.load(&id, me()).unwrap().unwrap();
        assert_eq!(loaded.to[0].address, "ada@exam");
        assert!(
            loaded.problem().is_some(),
            "an unfinished draft must still know it cannot be sent"
        );
    }

    #[test]
    fn an_empty_store_lists_nothing_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path().join("never-used")).unwrap();
        assert!(drafts.list().unwrap().is_empty());
        assert_eq!(drafts.count(), 0);
    }

    #[test]
    fn ids_are_validated_before_a_path_is_built_from_one() {
        // An id is joined to a directory. One that is not hex has come from
        // somewhere it should not have.
        assert!(is_valid_id(&new_id(1_700_000_000_000)));
        for bad in ["", "../../etc/passwd", "a/b", "..", "not-hex!"] {
            assert!(!is_valid_id(bad), "{bad} was accepted");
        }
    }

    #[test]
    fn a_save_marks_the_mirror_dirty_and_an_upload_cleans_it() {
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let id = new_id(7);

        drafts.save(&id, &draft(), 7).unwrap();
        assert_eq!(drafts.dirty().unwrap(), vec![id.clone()]);

        drafts
            .mark_mirrored(&id, "abc@example.com", Some((41, 9)))
            .unwrap();
        assert!(drafts.dirty().unwrap().is_empty());
        let mirror = drafts.mirror(&id).unwrap().unwrap();
        assert_eq!(mirror.message_id.as_deref(), Some("abc@example.com"));
        assert_eq!(mirror.uid, Some(9));
        assert_eq!(mirror.uid_validity, Some(41));
    }

    #[test]
    fn an_edit_after_an_upload_keeps_the_linkage_and_goes_dirty_again() {
        // The linkage is what lets the next upload *replace* the server copy
        // rather than accumulate beside it. Losing it on save would recreate
        // the duplication problem mirroring exists to solve.
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let id = new_id(8);
        drafts.save(&id, &draft(), 8).unwrap();
        drafts
            .mark_mirrored(&id, "abc@example.com", Some((41, 9)))
            .unwrap();

        let mut edited = draft();
        edited.body = "more".into();
        drafts.save(&id, &edited, 9).unwrap();

        let mirror = drafts.mirror(&id).unwrap().unwrap();
        assert!(mirror.dirty, "the server copy is behind and nothing knows");
        assert_eq!(mirror.message_id.as_deref(), Some("abc@example.com"));
        assert_eq!(mirror.uid, Some(9));
    }

    #[test]
    fn a_record_written_before_mirroring_existed_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let id = new_id(9);
        // The pre-mirror shape, byte for byte: no `mirror` key at all.
        let old = serde_json::json!({
            "saved_ms": 5,
            "draft": Draft::new(me()),
        });
        std::fs::write(
            dir.path().join(DIRECTORY).join(format!("{id}{EXTENSION}")),
            serde_json::to_string(&old).unwrap(),
        )
        .unwrap();

        let loaded = drafts.load(&id, me()).unwrap();
        assert!(loaded.is_some(), "an old record failed to load");
        let mirror = drafts.mirror(&id).unwrap().unwrap();
        assert_eq!(mirror, Mirror::default());
    }

    #[test]
    fn an_adopted_server_draft_is_linked_and_clean() {
        // A draft another device wrote, opened here: the server copy is the
        // latest version until the first local edit.
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let id = new_id(10);
        drafts
            .adopt(&id, &draft(), "other@example.com", 41, 12, 10)
            .unwrap();

        assert!(drafts.dirty().unwrap().is_empty());
        let mirror = drafts.mirror(&id).unwrap().unwrap();
        assert_eq!(mirror.uid, Some(12));
        assert!(drafts.load(&id, me()).unwrap().is_some());
    }

    #[test]
    fn marking_a_deleted_draft_mirrored_is_not_an_error() {
        // The draft was discarded while its upload was in flight.
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        drafts
            .mark_mirrored(&new_id(11), "gone@example.com", None)
            .unwrap();
        assert_eq!(drafts.count(), 0, "a ghost record was created");
    }

    #[test]
    fn deleting_a_mirrored_draft_leaves_a_tombstone_for_the_server_copy() {
        // Discarding on a train: the local record goes now, the server copy
        // goes when there is a server again. Without the tombstone the mirror
        // would resurrect on every other device.
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let id = new_id(12);
        drafts.save(&id, &draft(), 12).unwrap();
        drafts
            .mark_mirrored(&id, "m12@example.com", Some((41, 3)))
            .unwrap();

        drafts.delete(&id).unwrap();

        assert_eq!(
            drafts.pending_retractions(),
            vec![(id.clone(), "m12@example.com".to_owned())]
        );
        assert_eq!(drafts.count(), 0, "the tombstone was counted as a draft");
        assert!(drafts.list().unwrap().is_empty());

        drafts.clear_retraction(&id).unwrap();
        assert!(drafts.pending_retractions().is_empty());
        drafts
            .clear_retraction(&id)
            .expect("clearing twice must not fail");
    }

    #[test]
    fn deleting_a_never_mirrored_draft_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let drafts = Drafts::open(dir.path()).unwrap();
        let id = new_id(13);
        drafts.save(&id, &draft(), 13).unwrap();
        drafts.delete(&id).unwrap();
        assert!(
            drafts.pending_retractions().is_empty(),
            "a draft the server never saw got a tombstone"
        );
    }

    #[test]
    fn the_directory_is_hidden_from_a_maildir_walker() {
        // A sync engine that adopted these would try to give them UIDs.
        assert!(DIRECTORY.starts_with('.'));
    }
}

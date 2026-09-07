// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! What a backing store must provide for a mail sync cycle to run against it.
//!
//! The protocol layer deals in four things: a UID, a set of flags, a blob of
//! RFC 5322 bytes, and a cursor. Everything a store has to do is expressible in
//! those terms, which is why this is a short trait rather than a database
//! schema — the same move that made [`cosmic_pim_caldav::store::CalDavStore`]
//! four methods.
//!
//! There are two implementations: [`crate::maildir::MaildirStore`], and
//! [`MemoryStore`] here, which the tests use to exercise a full cycle without a
//! disk or a server.
//!
//! [`cosmic_pim_caldav::store::CalDavStore`]: https://docs.rs/cosmic-pim-caldav

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::Flags;

/// One message as the server holds it.
///
/// `raw` is the server's **verbatim** bytes, and is deliberately not a parsed
/// [`crate::model::Message`] — see that module for the two reasons, of which
/// "re-serialising invalidates the DKIM signature" is the one with no
/// workaround.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMessage {
    pub uid: u32,
    pub flags: Flags,
    pub raw: Vec<u8>,
    /// The server's INTERNALDATE, in epoch milliseconds.
    ///
    /// Distinct from the `Date` header, which the sender wrote and can be
    /// wrong, absent, or a decade off. Sorting a mailbox by `Date` is how a
    /// message with a broken clock pins itself to the top of the list forever.
    pub internal_date_ms: i64,
}

/// Where a mailbox got to. Every field is server-opaque.
///
/// This is exactly the state that cannot be reconstructed by walking the files,
/// which is why it lives in a sidecar rather than in any index — the same
/// reasoning that puts a CalDAV etag in `.caldav-state.json` and not in the
/// SQLite cache. Rebuild the index and this must survive; lose this and the
/// next sync re-downloads the mailbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cursor {
    /// The mailbox's UIDVALIDITY when we last synced it.
    ///
    /// If the server now reports a different one, every UID below is void. See
    /// [`crate::error::Error::UidValidityChanged`].
    pub uid_validity: u32,
    /// The highest UID we have looked at. The next discovery asks for
    /// `last_uid+1:*`.
    pub last_uid: u32,
    /// CONDSTORE's HIGHESTMODSEQ as of the last *successfully applied* flag
    /// window. Zero when the server has no CONDSTORE.
    ///
    /// "Successfully applied" is load-bearing: advancing this past a window
    /// whose fetch failed loses that window's flag changes permanently, because
    /// "we will pick it up next cycle" only exists while the cursor still names
    /// the old window.
    pub highest_modseq: u64,
    /// Whether the server's PERMANENTFLAGS advertised `\*` — may we create
    /// custom keywords here?
    ///
    /// Recorded per mailbox because it varies per mailbox on the same server,
    /// and writing a keyword to a mailbox that rejects them fails the whole
    /// STORE, taking the system flags in the same command with it.
    pub accepts_keywords: bool,
}

/// Everything we hold for one mailbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailboxState {
    pub cursor: Cursor,
    /// UID → the flags we hold for it. Ordered, because every consumer either
    /// walks it in UID order or takes its maximum.
    pub entries: BTreeMap<u32, Flags>,
}

pub trait MailStore {
    /// Everything we hold for this mailbox, in one read.
    fn state(&self) -> Result<MailboxState>;

    /// Inserts or replaces one message.
    fn upsert(&mut self, message: &RemoteMessage) -> Result<()>;

    /// Records new flags for a message we already hold.
    ///
    /// Separate from [`Self::upsert`] because a flag change must not require
    /// the message bytes. That is the entire point of CONDSTORE: one round trip
    /// brings back every flag delta in a mailbox, and re-fetching a 4 MB
    /// message because someone starred it would make the cheap path the
    /// expensive one.
    fn set_flags(&mut self, uid: u32, flags: Flags) -> Result<()>;

    /// Removes one message. A UID that is already gone is not an error — sync
    /// re-runs after partial failures and has to be idempotent.
    fn remove(&mut self, uid: u32) -> Result<()>;

    /// The stored bytes for one message, or `None` if we do not hold it.
    fn raw(&self, uid: u32) -> Result<Option<Vec<u8>>>;

    /// Records the cursor, ending the cycle.
    ///
    /// Called **only** after every upsert, flag change, and removal has
    /// succeeded. Committing a cursor over a partially-applied cycle convinces
    /// the next run it is up to date, and the missing messages never arrive.
    fn commit_cursor(&mut self, cursor: Cursor) -> Result<()>;

    /// The server renumbered this mailbox: discard everything and start over at
    /// the new UIDVALIDITY.
    ///
    /// Cannot be expressed as a series of [`Self::remove`] calls, and the
    /// difference is not cosmetic. Removing UIDs one at a time leaves a window
    /// in which the store holds some old-numbering messages and some new ones,
    /// and a crash inside that window is unrecoverable — nothing left on disk
    /// says which numbering each message belonged to.
    ///
    /// The keyword table survives a reset on purpose: the names are the
    /// user's vocabulary, not the server's numbering, and a renumbered
    /// mailbox re-fetches messages that still carry the same keywords.
    fn reset(&mut self, uid_validity: u32) -> Result<()>;

    /// The mailbox's keyword table: row N names bit N of
    /// [`Flags::keywords`]. Rows are never renumbered — a bit in a stored
    /// flag set would silently change meaning.
    fn keywords(&self) -> Vec<String>;

    /// The bit for a keyword, interning it if the table has never seen it.
    ///
    /// Matching is ASCII-case-insensitive, because IMAP keywords are atoms
    /// and servers differ on the case they echo back; the first-seen
    /// spelling is the one shown. Errors when all 26 rows are taken — the
    /// maildir letter space is the honest capacity, and inventing a private
    /// overflow scheme would break every other tool that reads the mapping.
    fn intern_keyword(&mut self, name: &str) -> Result<u8>;
}

/// The shared intern rule, so the implementations cannot drift.
pub(crate) fn intern_into(table: &mut Vec<String>, name: &str) -> Result<u8> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, '(' | ')' | '{' | '}' | '%' | '*' | '"' | '\\' | ']'))
    {
        return Err(crate::Error::Imap(format!(
            "{name:?} cannot be an IMAP keyword"
        )));
    }
    if let Some(row) = table
        .iter()
        .position(|existing| existing.eq_ignore_ascii_case(name))
    {
        return Ok(row as u8);
    }
    if table.len() >= usize::from(crate::model::KEYWORD_SLOTS) {
        return Err(crate::Error::Imap(
            "this mailbox already names 26 keywords, which is all the maildir format can hold"
                .into(),
        ));
    }
    table.push(name.to_owned());
    Ok((table.len() - 1) as u8)
}

/// The identity and cursor bookkeeping every id-keyed protocol needs.
///
/// # Why this is shared
///
/// IMAP hands out numeric UIDs and the store is keyed by them. JMAP, the Gmail
/// API and Microsoft Graph all hand out opaque strings instead, and all three
/// therefore need exactly the same two things: a durable string → UID map, so
/// the maildir and everything reading it stay unchanged, and a cursor into the
/// server's change feed. Three copies of that would be three places to get the
/// same subtle thing wrong.
///
/// # The cursor can expire, and that is not an error
///
/// Every one of these protocols has a change feed with a horizon —
/// `cannotCalculateChanges` in JMAP, a 404 or 410 from Gmail's `history.list`,
/// a 410 from a Graph delta link. All three mean the same thing: *I cannot
/// tell you what changed*. They never mean "nothing changed", and they never
/// mean "everything was deleted". Reading them as the first freezes the account
/// forever; reading them as the second empties the user's mailbox. The only
/// correct answer is to drop the cursor and read the mailbox again, which is
/// what [`Self::reset_cursor`] exists to make explicit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteIds {
    /// Server id → the local UID it was assigned.
    #[serde(default)]
    seen: BTreeMap<String, u32>,
    #[serde(default = "first_uid")]
    next_uid: u32,
    /// Where the change feed was last read to: a JMAP state string, a Gmail
    /// `historyId`, a Graph `deltaLink`. Opaque here on purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    /// Which sidecar this came from, so [`Self::save`] needs no reminding.
    #[serde(skip)]
    file: &'static str,
}

fn first_uid() -> u32 {
    1
}

impl Default for RemoteIds {
    fn default() -> Self {
        Self {
            seen: BTreeMap::new(),
            next_uid: first_uid(),
            cursor: None,
            file: "",
        }
    }
}

impl RemoteIds {
    /// Reads the sidecar `file` beside a maildir, or starts empty.
    ///
    /// An unreadable sidecar is treated as absent. The cost is re-reading the
    /// mailbox; the alternative is being unable to open it at all because a
    /// JSON file got truncated.
    #[must_use]
    pub fn load(maildir: &std::path::Path, file: &'static str) -> Self {
        let mut state = match std::fs::read_to_string(maildir.join(file)) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|why| {
                tracing::warn!(
                    path = %maildir.display(), %why,
                    "unreadable sidecar; treating the mailbox as new"
                );
                Self::default()
            }),
            Err(_) => Self::default(),
        };
        state.file = file;
        state
    }

    /// Writes the sidecar atomically — a torn one costs a full re-read.
    pub fn save(&self, maildir: &std::path::Path) -> Result<()> {
        debug_assert!(
            !self.file.is_empty(),
            "saving a RemoteIds that was never loaded"
        );
        let json = serde_json::to_string_pretty(self)
            .map_err(|why| Error::Index(format!("serialising sync state: {why}")))?;
        cosmic_pim_core::atomic::write(&maildir.join(self.file), &json, None)
            .map(|_| ())
            .map_err(|why| Error::Index(format!("writing sync state: {why}")))
    }

    /// The local UID for a server id, if it has one.
    #[must_use]
    pub fn uid_of(&self, id: &str) -> Option<u32> {
        self.seen.get(id).copied()
    }

    /// The server id behind a local UID.
    #[must_use]
    pub fn id_of(&self, uid: u32) -> Option<&str> {
        self.seen
            .iter()
            .find(|(_, value)| **value == uid)
            .map(|(id, _)| id.as_str())
    }

    /// The local UID for a server id, assigning one if it is new.
    ///
    /// Assigning once and never again is what keeps a message that moved, or
    /// arrived twice in a listing, from being stored twice.
    pub fn uid_for(&mut self, id: &str) -> u32 {
        if let Some(uid) = self.seen.get(id) {
            return *uid;
        }
        let uid = self.next_uid;
        self.next_uid = self.next_uid.saturating_add(1);
        self.seen.insert(id.to_owned(), uid);
        uid
    }

    /// Drops a mapping — the message left this mailbox, or was destroyed.
    pub fn forget(&mut self, id: &str) {
        self.seen.remove(id);
    }

    /// How many messages this mailbox believes it holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// The highest UID assigned so far, for the store's cursor.
    #[must_use]
    pub fn highest_uid(&self) -> u32 {
        self.next_uid.saturating_sub(1)
    }

    /// Where the change feed was last read to.
    #[must_use]
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Records a new position in the change feed.
    ///
    /// Called **only** after everything the previous position described has
    /// been applied. Advancing first and failing second skips that window
    /// permanently — the same rule the IMAP MODSEQ cursor and the CalDAV ctag
    /// follow.
    pub fn set_cursor(&mut self, cursor: impl Into<String>) {
        self.cursor = Some(cursor.into());
    }

    /// Drops the cursor, so the next pass reads the mailbox in full.
    ///
    /// What an expired change feed amounts to. See the type's docs.
    pub fn reset_cursor(&mut self) {
        self.cursor = None;
    }
}

/// An in-memory [`MailStore`] for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    pub cursor: Cursor,
    pub messages: BTreeMap<u32, RemoteMessage>,
    pub keyword_table: Vec<String>,
}

impl MailStore for MemoryStore {
    fn state(&self) -> Result<MailboxState> {
        Ok(MailboxState {
            cursor: self.cursor,
            entries: self
                .messages
                .iter()
                .map(|(uid, message)| (*uid, message.flags))
                .collect(),
        })
    }

    fn upsert(&mut self, message: &RemoteMessage) -> Result<()> {
        self.messages.insert(message.uid, message.clone());
        Ok(())
    }

    fn set_flags(&mut self, uid: u32, flags: Flags) -> Result<()> {
        if let Some(message) = self.messages.get_mut(&uid) {
            message.flags = flags;
        }
        Ok(())
    }

    fn remove(&mut self, uid: u32) -> Result<()> {
        self.messages.remove(&uid);
        Ok(())
    }

    fn raw(&self, uid: u32) -> Result<Option<Vec<u8>>> {
        Ok(self.messages.get(&uid).map(|m| m.raw.clone()))
    }

    fn commit_cursor(&mut self, cursor: Cursor) -> Result<()> {
        self.cursor = cursor;
        Ok(())
    }

    fn reset(&mut self, uid_validity: u32) -> Result<()> {
        self.messages.clear();
        self.cursor = Cursor {
            uid_validity,
            ..Cursor::default()
        };
        Ok(())
    }

    fn keywords(&self) -> Vec<String> {
        self.keyword_table.clone()
    }

    fn intern_keyword(&mut self, name: &str) -> Result<u8> {
        intern_into(&mut self.keyword_table, name)
    }
}

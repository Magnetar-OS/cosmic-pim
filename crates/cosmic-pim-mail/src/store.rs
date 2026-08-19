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

use crate::error::Result;
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
    fn reset(&mut self, uid_validity: u32) -> Result<()>;
}

/// An in-memory [`MailStore`] for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    pub cursor: Cursor,
    pub messages: BTreeMap<u32, RemoteMessage>,
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
}

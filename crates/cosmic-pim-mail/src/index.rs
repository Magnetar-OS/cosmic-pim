// SPDX-License-Identifier: MPL-2.0

//! A rebuildable index over the maildirs.
//!
//! # Why this exists
//!
//! Without it, showing a folder means parsing every message in it. That is fine
//! for a few hundred and unacceptable for an archive: a 20 000-message mailbox
//! of ordinary size is several hundred megabytes of MIME to walk, every time
//! somebody clicks the folder. This holds the dozen fields a conversation list
//! actually shows, so the click costs a query.
//!
//! # It is a cache, and that is load-bearing
//!
//! Delete this file and nothing is lost — it rebuilds from the maildirs, which
//! are the truth. That is the same standing the calendar's SQLite index has
//! over the vdir, and it is what keeps the suite's promise honest: the data is
//! files, and everything else is derived.
//!
//! Two consequences follow, and both are rules rather than preferences:
//!
//! - **No sync state here.** UIDVALIDITY, the UID cursor, MODSEQ, and the
//!   writeback queue live in the maildir's own sidecar. Putting any of them
//!   here would mean clearing a cache re-downloads a mailbox — or worse,
//!   silently drops a queued write.
//! - **No message bodies here.** The index holds a snippet for the list. The
//!   message is the file; anything that needs it reads it.
//!
//! # Freshness
//!
//! Entries are keyed by `(account, mailbox, uid)`, and a UID names one
//! immutable message: RFC 3501 guarantees the bytes behind it never change. So
//! an entry can never be stale in content — only absent, or orphaned by a
//! renumbering — and [`Index::sync_mailbox`] handles both by comparing the
//! store's UID set against what is indexed.
//!
//! Flags are the exception and are deliberately **not** stored. They change
//! constantly, so caching them would mean a cache write for every read mark,
//! and a stale one would show unread mail that is not.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::{Error, Result};
use crate::model::{Flags, Message};
use crate::store::MailStore;

/// Bumped whenever the schema changes; a mismatch wipes and rebuilds.
const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS messages (
    account      TEXT    NOT NULL,
    mailbox      TEXT    NOT NULL,
    uid          INTEGER NOT NULL,
    message_id   TEXT    NOT NULL,
    thread_id    TEXT    NOT NULL,
    from_name    TEXT    NOT NULL,
    from_addr    TEXT    NOT NULL,
    subject      TEXT    NOT NULL,
    subject_norm TEXT    NOT NULL,
    date_ms      INTEGER NOT NULL,
    snippet      TEXT    NOT NULL,
    attachments  INTEGER NOT NULL,
    PRIMARY KEY (account, mailbox, uid)
);

CREATE INDEX IF NOT EXISTS messages_thread  ON messages (account, mailbox, thread_id, date_ms);
CREATE INDEX IF NOT EXISTS messages_msgid   ON messages (account, message_id);
CREATE INDEX IF NOT EXISTS messages_subject ON messages (account, subject_norm, date_ms);
";

/// Where the cache lives: `$XDG_CACHE_HOME/cosmic-pim/mail.sqlite`.
///
/// Beside the calendar's `index.sqlite`, in the cache directory, because that
/// is what it is. A user clearing their cache should lose exactly this.
///
/// `COSMIC_PIM_MAIL_INDEX` overrides it, matching how `COSMIC_PIM_MAIL_DIR`
/// overrides the maildir root. An index caches one mail directory, so anything
/// pointing at a different one has to point this somewhere else too — otherwise
/// the cache describes a mailbox that is not there.
#[must_use]
pub fn default_path() -> PathBuf {
    if let Some(path) = std::env::var_os("COSMIC_PIM_MAIL_INDEX") {
        return PathBuf::from(path);
    }
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("cosmic-pim")
        .join("mail.sqlite")
}

/// One message, as a list row needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub uid: u32,
    pub message_id: String,
    pub thread_id: String,
    pub from_name: String,
    pub from_address: String,
    pub subject: String,
    pub subject_norm: String,
    pub date_ms: i64,
    pub snippet: String,
    pub has_attachments: bool,
}

impl Summary {
    /// What a list shows for the sender: the display name, else the address.
    #[must_use]
    pub fn from_display(&self) -> &str {
        if self.from_name.is_empty() {
            &self.from_address
        } else {
            &self.from_name
        }
    }
}

pub struct Index {
    conn: Connection,
}

impl std::fmt::Debug for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Index").finish_non_exhaustive()
    }
}

impl Index {
    /// Opens (or creates) the index, rebuilding it if the schema changed.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Self::prepare(Connection::open(path).map_err(sqlite)?)
    }

    /// An index that never touches a disk, for tests.
    pub fn in_memory() -> Result<Self> {
        Self::prepare(Connection::open_in_memory().map_err(sqlite)?)
    }

    fn prepare(conn: Connection) -> Result<Self> {
        // WAL so a read does not block a write, and NORMAL sync because losing
        // the tail of a cache costs a rescan and nothing else.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(sqlite)?;
        // The sync worker and the UI thread both reach this file, and a folder
        // being indexed while another is being read is the ordinary case rather
        // than a rare one. Without a busy timeout that contention surfaces as
        // "database is locked" — a failure the user sees as an empty folder.
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(sqlite)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(sqlite)?;

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sqlite)?;
        if version != SCHEMA_VERSION {
            // Dropped rather than migrated. There is nothing here that cannot
            // be rebuilt from the maildirs, so a migration would be code
            // written to preserve something worthless.
            conn.execute_batch("DROP TABLE IF EXISTS messages;")
                .map_err(sqlite)?;
        }
        conn.execute_batch(SCHEMA).map_err(sqlite)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(sqlite)?;

        Ok(Self { conn })
    }

    /// Brings the index for one mailbox in line with the store.
    ///
    /// Only new UIDs are parsed — the expensive part — and only orphans are
    /// deleted. Returns how many messages were newly indexed.
    pub fn sync_mailbox(
        &mut self,
        account: &str,
        mailbox: &str,
        store: &impl MailStore,
    ) -> Result<usize> {
        let held: Vec<u32> = store.state()?.entries.keys().copied().collect();
        let indexed = self.indexed_uids(account, mailbox)?;

        // Deletions first: a UID that has gone must not be able to adopt a
        // later message into its thread.
        let gone: Vec<u32> = indexed
            .iter()
            .copied()
            .filter(|uid| held.binary_search(uid).is_err())
            .collect();
        if !gone.is_empty() {
            let transaction = self.conn.transaction().map_err(sqlite)?;
            {
                let mut statement = transaction
                    .prepare("DELETE FROM messages WHERE account=?1 AND mailbox=?2 AND uid=?3")
                    .map_err(sqlite)?;
                for uid in gone {
                    statement
                        .execute(params![account, mailbox, uid])
                        .map_err(sqlite)?;
                }
            }
            transaction.commit().map_err(sqlite)?;
        }

        // Oldest first, so a parent is indexed before the replies that adopt
        // it. Going the other way makes threading depend on arrival order.
        let missing: Vec<u32> = held
            .into_iter()
            .filter(|uid| indexed.binary_search(uid).is_err())
            .collect();

        let mut added = 0;
        for uid in missing {
            let Some(raw) = store.raw(uid)? else { continue };
            let Some(message) = Message::parse(&raw) else {
                // Unparseable bytes are still a message the user can open; they
                // just cannot be threaded or summarised. Skipping keeps the
                // rest of the mailbox working.
                tracing::warn!(mailbox, uid, "a message could not be parsed for the index");
                continue;
            };
            let thread_id = self.resolve(account, mailbox, uid, &message)?;
            self.insert(account, mailbox, uid, &thread_id, &message)?;
            added += 1;
        }
        Ok(added)
    }

    /// Everything in one mailbox, grouped into conversations, newest first.
    pub fn conversations(
        &self,
        account: &str,
        mailbox: &str,
        flags: &BTreeMap<u32, Flags>,
    ) -> Result<Vec<Conversation>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT uid, message_id, thread_id, from_name, from_addr, subject,
                        subject_norm, date_ms, snippet, attachments
                 FROM messages WHERE account=?1 AND mailbox=?2
                 ORDER BY thread_id, date_ms, uid",
            )
            .map_err(sqlite)?;

        let rows = statement
            .query_map(params![account, mailbox], |row| {
                Ok(Summary {
                    uid: row.get(0)?,
                    message_id: row.get(1)?,
                    thread_id: row.get(2)?,
                    from_name: row.get(3)?,
                    from_address: row.get(4)?,
                    subject: row.get(5)?,
                    subject_norm: row.get(6)?,
                    date_ms: row.get(7)?,
                    snippet: row.get(8)?,
                    has_attachments: row.get::<_, i64>(9)? != 0,
                })
            })
            .map_err(sqlite)?;

        let mut threads: Vec<Conversation> = Vec::new();
        for row in rows {
            let summary = row.map_err(sqlite)?;
            match threads.last_mut() {
                Some(last) if last.thread_id == summary.thread_id => last.push(summary, flags),
                _ => threads.push(Conversation::new(summary, flags)),
            }
        }

        // Undated last rather than first: a message whose Date does not parse
        // is a curiosity, not the most important thing the user owns.
        threads.sort_by_key(|thread| std::cmp::Reverse(thread.date_ms));
        Ok(threads)
    }

    /// Messages matching a query, newest first.
    ///
    /// Returns messages rather than conversations, deliberately. A search result
    /// is "the message I am looking for", and grouping it back into a thread
    /// buries the hit among its siblings — which is why every mail client that
    /// threads its inbox shows a flat list for search.
    ///
    /// `mailbox` narrows to one; `None` searches the account. Flag filters
    /// (`is:unread`, `is:starred`) are **not** applied here: flags live in the
    /// store, not the index, and applying them is the caller's job once it has
    /// the flags for the mailboxes involved.
    pub fn search(
        &self,
        account: &str,
        mailbox: Option<&str>,
        query: &crate::search::Query,
        limit: usize,
    ) -> Result<Vec<Hit>> {
        if query.is_empty() {
            return Ok(Vec::new());
        }

        let mut sql = String::from(
            "SELECT mailbox, uid, thread_id, from_name, from_addr, subject, date_ms,
                    snippet, attachments
             FROM messages WHERE account = ?1",
        );
        // Bound parameters throughout — the terms are whatever somebody typed
        // into a search box, and a LIKE pattern built by concatenation is how a
        // search box becomes a SQL injection.
        let mut values: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(account.to_owned())];

        if let Some(mailbox) = mailbox {
            values.push(Box::new(mailbox.to_owned()));
            sql.push_str(&format!(" AND mailbox = ?{}", values.len()));
        }
        for term in &query.terms {
            values.push(Box::new(like(term)));
            let n = values.len();
            sql.push_str(&format!(
                " AND (subject LIKE ?{n} ESCAPE '\\' OR from_name LIKE ?{n} ESCAPE '\\'
                       OR from_addr LIKE ?{n} ESCAPE '\\' OR snippet LIKE ?{n} ESCAPE '\\')"
            ));
        }
        for term in &query.from {
            values.push(Box::new(like(term)));
            let n = values.len();
            sql.push_str(&format!(
                " AND (from_name LIKE ?{n} ESCAPE '\\' OR from_addr LIKE ?{n} ESCAPE '\\')"
            ));
        }
        for term in &query.subject {
            values.push(Box::new(like(term)));
            sql.push_str(&format!(" AND subject LIKE ?{} ESCAPE '\\'", values.len()));
        }
        if query.has_attachment {
            sql.push_str(" AND attachments != 0");
        }
        values.push(Box::new(i64::try_from(limit).unwrap_or(i64::MAX)));
        sql.push_str(&format!(" ORDER BY date_ms DESC LIMIT ?{}", values.len()));

        let mut statement = self.conn.prepare(&sql).map_err(sqlite)?;
        let bound: Vec<&dyn rusqlite::ToSql> = values.iter().map(AsRef::as_ref).collect();
        let rows = statement
            .query_map(rusqlite::params_from_iter(bound), |row| {
                Ok(Hit {
                    mailbox: row.get(0)?,
                    uid: row.get(1)?,
                    thread_id: row.get(2)?,
                    from_name: row.get(3)?,
                    from_address: row.get(4)?,
                    subject: row.get(5)?,
                    date_ms: row.get(6)?,
                    snippet: row.get(7)?,
                    has_attachments: row.get::<_, i64>(8)? != 0,
                })
            })
            .map_err(sqlite)?;

        rows.collect::<std::result::Result<Vec<Hit>, _>>()
            .map_err(sqlite)
    }

    /// Forgets everything for one mailbox.
    ///
    /// Called on a renumbering: every UID indexed for it now names a different
    /// message, so the rows are not stale, they are wrong.
    pub fn forget(&mut self, account: &str, mailbox: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM messages WHERE account=?1 AND mailbox=?2",
                params![account, mailbox],
            )
            .map_err(sqlite)?;
        Ok(())
    }

    fn indexed_uids(&self, account: &str, mailbox: &str) -> Result<Vec<u32>> {
        let mut statement = self
            .conn
            .prepare("SELECT uid FROM messages WHERE account=?1 AND mailbox=?2 ORDER BY uid")
            .map_err(sqlite)?;
        let uids = statement
            .query_map(params![account, mailbox], |row| row.get(0))
            .map_err(sqlite)?
            .collect::<std::result::Result<Vec<u32>, _>>()
            .map_err(sqlite)?;
        Ok(uids)
    }

    /// Threads one message against what is already indexed, and re-files any
    /// children that arrived before it.
    fn resolve(
        &mut self,
        account: &str,
        mailbox: &str,
        uid: u32,
        message: &Message,
    ) -> Result<String> {
        let fallback = format!("{mailbox}/{uid}");
        let resolution = {
            let lookup = SqlIndex {
                conn: &self.conn,
                account,
            };
            crate::threading::resolve_thread(
                &lookup,
                account,
                crate::threading::Threadable {
                    message_id: message.message_id.as_deref(),
                    references_header: &message.references,
                    in_reply_to_header: &message.in_reply_to,
                    subject: &message.subject,
                    subject_norm: &message.subject_norm,
                    uid_fallback: &fallback,
                },
            )
        };

        // The late-parent heal, applied. Without this the children stay under a
        // thread id nothing else will ever join, and the conversation shows as
        // two.
        for dead in &resolution.merged_from {
            self.conn
                .execute(
                    "UPDATE messages SET thread_id=?1 WHERE account=?2 AND thread_id=?3",
                    params![resolution.thread_id, account, dead],
                )
                .map_err(sqlite)?;
        }
        Ok(resolution.thread_id)
    }

    fn insert(
        &self,
        account: &str,
        mailbox: &str,
        uid: u32,
        thread_id: &str,
        message: &Message,
    ) -> Result<()> {
        let sender = message.sender();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO messages
                   (account, mailbox, uid, message_id, thread_id, from_name, from_addr,
                    subject, subject_norm, date_ms, snippet, attachments)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    account,
                    mailbox,
                    uid,
                    message.message_id.as_deref().unwrap_or(""),
                    thread_id,
                    sender.and_then(|s| s.name.as_deref()).unwrap_or(""),
                    sender.map_or("", |s| s.address.as_str()),
                    message.subject,
                    message.subject_norm,
                    message.date.map_or(0, |date| date.timestamp_millis()),
                    snippet(&message.body.text),
                    i64::from(message.attachments.iter().any(|a| !a.inline)),
                ],
            )
            .map_err(sqlite)?;
        Ok(())
    }
}

/// One message a search matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Which mailbox it is in — a search can cross folders, and "where is it"
    /// is half of what the user wanted to know.
    pub mailbox: String,
    pub uid: u32,
    pub thread_id: String,
    pub from_name: String,
    pub from_address: String,
    pub subject: String,
    pub date_ms: i64,
    pub snippet: String,
    pub has_attachments: bool,
}

impl Hit {
    /// What a result row shows for the sender.
    #[must_use]
    pub fn from_display(&self) -> &str {
        if self.from_name.is_empty() {
            &self.from_address
        } else {
            &self.from_name
        }
    }
}

/// One conversation, assembled from its indexed messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub thread_id: String,
    /// The oldest message's normalised subject — so a long thread does not
    /// rename itself every time somebody's client spells `Re:` differently.
    pub subject: String,
    /// Who is in it, in the order they appear, deduplicated.
    pub participants: Vec<String>,
    /// The newest message's date, which is what the list sorts and shows.
    pub date_ms: i64,
    /// The newest message's first line.
    pub snippet: String,
    /// UIDs, oldest first.
    pub uids: Vec<u32>,
    pub unread: bool,
    pub flagged: bool,
    pub has_attachments: bool,
}

impl Conversation {
    fn new(summary: Summary, flags: &BTreeMap<u32, Flags>) -> Self {
        let mut thread = Self {
            thread_id: summary.thread_id.clone(),
            subject: String::new(),
            participants: Vec::new(),
            date_ms: i64::MIN,
            snippet: String::new(),
            uids: Vec::new(),
            unread: false,
            flagged: false,
            has_attachments: false,
        };
        thread.push(summary, flags);
        thread
    }

    /// Rows arrive oldest-first, so the first sets the subject and the last
    /// wins the snippet and the date.
    fn push(&mut self, summary: Summary, flags: &BTreeMap<u32, Flags>) {
        if self.subject.is_empty() && !summary.subject_norm.is_empty() {
            self.subject = summary.subject_norm.clone();
        }
        let who = summary.from_display().to_owned();
        if !who.is_empty() && !self.participants.contains(&who) {
            self.participants.push(who);
        }
        if summary.date_ms >= self.date_ms {
            self.date_ms = summary.date_ms;
            self.snippet = summary.snippet.clone();
        }
        self.has_attachments |= summary.has_attachments;
        let flags = flags.get(&summary.uid).copied().unwrap_or_default();
        self.unread |= !flags.seen;
        self.flagged |= flags.flagged;
        self.uids.push(summary.uid);
    }

    #[must_use]
    pub fn newest_uid(&self) -> Option<u32> {
        self.uids.last().copied()
    }
}

/// A [`crate::threading::ThreadIndex`] backed by the table.
///
/// Scoped to one account, because a thread id is: the same mailing-list thread
/// reaching two accounts is two conversations with separate unread state.
struct SqlIndex<'a> {
    conn: &'a Connection,
    account: &'a str,
}

impl crate::threading::ThreadIndex for SqlIndex<'_> {
    fn thread_of_message(&self, message_id: &str) -> Option<String> {
        // A message with no `Message-ID` is stored with an empty one, and an
        // empty ancestor id must not match it — that would file every such
        // message into one thread.
        if message_id.is_empty() {
            return None;
        }
        self.conn
            .query_row(
                "SELECT thread_id FROM messages WHERE account=?1 AND message_id=?2 LIMIT 1",
                params![self.account, message_id],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    fn oldest_thread_with_subject(&self, subject_norm: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT thread_id FROM messages WHERE account=?1 AND subject_norm=?2
                 ORDER BY date_ms ASC, uid ASC LIMIT 1",
                params![self.account, subject_norm],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    fn has_thread(&self, thread_id: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM messages WHERE account=?1 AND thread_id=?2 LIMIT 1",
                params![self.account, thread_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }
}

/// The list's one-line preview.
///
/// The first non-empty line rather than the first N characters: a message that
/// opens with a greeting on its own line should preview as the greeting, not as
/// the greeting run into the sentence after it.
fn snippet(body: &str) -> String {
    const MAX: usize = 200;
    let line = body
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    if line.chars().count() > MAX {
        line.chars().take(MAX).collect()
    } else {
        line.to_owned()
    }
}

/// A LIKE pattern matching `term` anywhere, with LIKE's own wildcards escaped.
///
/// Without the escape, searching for `50%` matches everything and searching for
/// `report_final` matches `reportXfinal` — both silently, which is the worst
/// way for a search box to be wrong.
fn like(term: &str) -> String {
    let mut escaped = String::with_capacity(term.len() + 2);
    escaped.push('%');
    for c in term.chars() {
        if matches!(c, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped.push('%');
    escaped
}

fn sqlite(error: rusqlite::Error) -> Error {
    Error::Index(error.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, RemoteMessage};

    const ACCOUNT: &str = "acct";
    const MAILBOX: &str = "INBOX";

    fn message(
        uid: u32,
        id: &str,
        references: &str,
        subject: &str,
        from: &str,
        body: &str,
    ) -> RemoteMessage {
        let raw = format!(
            "Message-ID: <{id}>\r\nFrom: {from}\r\nReferences: {references}\r\n\
             Subject: {subject}\r\nDate: Mon, 3 Feb 2025 09:00:00 +0000\r\n\r\n{body}\r\n"
        );
        RemoteMessage {
            uid,
            flags: Flags::default(),
            raw: raw.into_bytes(),
            internal_date_ms: i64::from(uid) * 1000,
        }
    }

    fn store(messages: Vec<RemoteMessage>) -> MemoryStore {
        let mut store = MemoryStore::default();
        for message in messages {
            store.upsert(&message).unwrap();
        }
        store
    }

    fn flags(store: &MemoryStore) -> BTreeMap<u32, Flags> {
        store.state().unwrap().entries
    }

    #[test]
    fn a_conversation_is_assembled_from_its_messages() {
        let store = store(vec![
            message(1, "a@x", "", "Release plan", "Ada <ada@example.com>", "First."),
            message(
                2,
                "b@x",
                "<a@x>",
                "Re: Release plan",
                "Bob <bob@example.net>",
                "Second.",
            ),
            message(3, "c@x", "", "Lunch", "Cleo <cleo@example.org>", "One o'clock?"),
        ]);
        let mut index = Index::in_memory().unwrap();
        assert_eq!(index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap(), 3);

        let threads = index
            .conversations(ACCOUNT, MAILBOX, &flags(&store))
            .unwrap();
        assert_eq!(threads.len(), 2);

        let plan = threads
            .iter()
            .find(|t| t.uids.len() == 2)
            .expect("the reply did not join its parent");
        assert_eq!(plan.subject, "Release plan", "a Re: prefix reached the list");
        assert_eq!(plan.uids, vec![1, 2]);
        assert_eq!(plan.participants, vec!["Ada", "Bob"]);
        assert_eq!(plan.snippet, "Second.", "the snippet is not from the newest");
        assert!(plan.unread);
    }

    #[test]
    fn a_second_pass_over_an_unchanged_mailbox_parses_nothing() {
        // The entire point: clicking a folder must cost a query, not a walk of
        // every message in it.
        let store = store(vec![message(1, "a@x", "", "s", "a@example.com", "b")]);
        let mut index = Index::in_memory().unwrap();
        assert_eq!(index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap(), 1);
        assert_eq!(
            index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap(),
            0,
            "the index re-parsed messages it already held"
        );
    }

    #[test]
    fn only_new_messages_are_parsed_when_a_sync_brings_some() {
        let mut store = store(vec![message(1, "a@x", "", "s", "a@example.com", "b")]);
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();

        store
            .upsert(&message(2, "b@x", "", "t", "b@example.com", "c"))
            .unwrap();
        assert_eq!(index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap(), 1);
    }

    #[test]
    fn a_deleted_message_leaves_the_index() {
        let mut store = store(vec![
            message(1, "a@x", "", "s", "a@example.com", "b"),
            message(2, "b@x", "", "t", "b@example.com", "c"),
        ]);
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();

        store.remove(1).unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();

        let threads = index
            .conversations(ACCOUNT, MAILBOX, &flags(&store))
            .unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].uids, vec![2]);
    }

    #[test]
    fn a_reply_indexed_before_its_parent_still_ends_up_in_one_thread() {
        // Out-of-order arrival is the normal case on a first backfill: the
        // child hashes the parent's Message-ID as its root and sits under an id
        // the parent will not land on.
        let store = store(vec![
            message(1, "reply@x", "<parent@x>", "Re: X", "b@example.com", "second"),
            message(2, "parent@x", "<grand@x>", "Re: X", "a@example.com", "first"),
        ]);
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();

        let threads = index
            .conversations(ACCOUNT, MAILBOX, &flags(&store))
            .unwrap();
        assert_eq!(threads.len(), 1, "the conversation stayed split: {threads:?}");
        assert_eq!(threads[0].uids, vec![1, 2]);
    }

    #[test]
    fn the_index_rebuilds_from_the_store_after_being_thrown_away() {
        // "It is a cache" has to be literally true, or it has quietly become a
        // second source of truth.
        let store = store(vec![message(1, "a@x", "", "s", "a@example.com", "b")]);
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();
        index.forget(ACCOUNT, MAILBOX).unwrap();
        assert!(
            index
                .conversations(ACCOUNT, MAILBOX, &flags(&store))
                .unwrap()
                .is_empty()
        );

        assert_eq!(index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap(), 1);
        assert_eq!(
            index
                .conversations(ACCOUNT, MAILBOX, &flags(&store))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn an_unparseable_message_is_skipped_rather_than_failing_the_mailbox() {
        let mut store = store(vec![message(2, "b@x", "", "s", "b@example.com", "fine")]);
        store
            .upsert(&RemoteMessage {
                uid: 1,
                flags: Flags::default(),
                raw: vec![0xff, 0xfe, 0x00],
                internal_date_ms: 0,
            })
            .unwrap();

        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();
        let threads = index
            .conversations(ACCOUNT, MAILBOX, &flags(&store))
            .unwrap();
        assert!(
            threads.iter().any(|t| t.uids.contains(&2)),
            "one bad message took the mailbox with it"
        );
    }

    #[test]
    fn messages_without_a_message_id_do_not_all_collapse_into_one_thread() {
        // They are stored with an empty id, and an empty ancestor lookup that
        // matched would file every one of them together.
        let mut store = MemoryStore::default();
        for uid in 1..=3u32 {
            store
                .upsert(&RemoteMessage {
                    uid,
                    flags: Flags::default(),
                    raw: format!("From: a@example.com\r\nSubject: note {uid}\r\n\r\nbody\r\n")
                        .into_bytes(),
                    internal_date_ms: i64::from(uid) * 1000,
                })
                .unwrap();
        }
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();
        assert_eq!(
            index
                .conversations(ACCOUNT, MAILBOX, &flags(&store))
                .unwrap()
                .len(),
            3
        );
    }

    fn searchable() -> MemoryStore {
        store(vec![
            message(1, "a@x", "", "Invoice 42 overdue", "Ada <ada@example.com>", "Please pay."),
            message(2, "b@x", "", "Release plan", "Bob <bob@example.net>", "Draft attached."),
            message(3, "c@x", "", "Lunch", "Ada <ada@example.com>", "One o'clock?"),
        ])
    }

    fn search(index: &Index, query: &str) -> Vec<String> {
        index
            .search(ACCOUNT, None, &crate::search::parse(query), 50)
            .unwrap()
            .into_iter()
            .map(|hit| hit.subject)
            .collect()
    }

    #[test]
    fn a_search_matches_sender_subject_and_snippet() {
        let store = searchable();
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();

        assert_eq!(search(&index, "invoice"), ["Invoice 42 overdue"]);
        assert_eq!(search(&index, "from:ada").len(), 2);
        assert_eq!(search(&index, "subject:release"), ["Release plan"]);
        assert_eq!(search(&index, "pay"), ["Invoice 42 overdue"], "the snippet");
    }

    #[test]
    fn terms_narrow_rather_than_widen() {
        let store = searchable();
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();

        assert_eq!(search(&index, "from:ada invoice"), ["Invoice 42 overdue"]);
        assert!(
            search(&index, "from:ada release").is_empty(),
            "two terms behaved as OR"
        );
    }

    #[test]
    fn results_come_back_newest_first() {
        let mut store = MemoryStore::default();
        for (uid, id, date) in [
            (1, "old@x", "Mon, 3 Feb 2025 09:00:00 +0000"),
            (2, "new@x", "Tue, 4 Feb 2025 09:00:00 +0000"),
        ] {
            store
                .upsert(&RemoteMessage {
                    uid,
                    flags: Flags::default(),
                    raw: format!(
                        "Message-ID: <{id}>\r\nFrom: a@example.com\r\nSubject: report {uid}\r\n\
                         Date: {date}\r\n\r\nbody\r\n"
                    )
                    .into_bytes(),
                    internal_date_ms: 0,
                })
                .unwrap();
        }
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();
        assert_eq!(search(&index, "report"), ["report 2", "report 1"]);
    }

    #[test]
    fn like_wildcards_in_a_search_box_are_literal() {
        // Without escaping, searching for "50%" matches everything and
        // "report_final" matches "reportXfinal" — silently, which is the worst
        // way for a search box to be wrong.
        let store = store(vec![
            message(1, "a@x", "", "50% off", "a@example.com", "sale"),
            message(2, "b@x", "", "Release plan", "b@example.com", "plan"),
            message(3, "c@x", "", "report_final", "c@example.com", "done"),
            message(4, "d@x", "", "reportXfinal", "d@example.com", "no"),
        ]);
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();

        assert_eq!(search(&index, "50%"), ["50% off"]);
        assert_eq!(search(&index, "report_final"), ["report_final"]);
    }

    #[test]
    fn a_quote_in_a_search_box_cannot_reach_the_query() {
        // The terms are whatever somebody typed. This must return nothing and
        // leave the table alone.
        let store = searchable();
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();

        assert!(search(&index, "'; DROP TABLE messages; --").is_empty());
        assert_eq!(
            index
                .conversations(ACCOUNT, MAILBOX, &flags(&store))
                .unwrap()
                .len(),
            3,
            "the table did not survive"
        );
    }

    #[test]
    fn an_empty_query_returns_nothing_rather_than_the_mailbox() {
        // A cleared search box must not load everything to show it twice.
        let store = searchable();
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();
        assert!(search(&index, "").is_empty());
        assert!(search(&index, "   ").is_empty());
    }

    #[test]
    fn a_search_says_which_mailbox_a_hit_is_in() {
        // Half of what the user wanted to know.
        let store = searchable();
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, "Archive", &store).unwrap();
        let hits = index
            .search(ACCOUNT, None, &crate::search::parse("invoice"), 50)
            .unwrap();
        assert_eq!(hits[0].mailbox, "Archive");

        // And can be narrowed to one.
        assert!(
            index
                .search(ACCOUNT, Some("INBOX"), &crate::search::parse("invoice"), 50)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_limit_is_honoured() {
        let store = searchable();
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();
        assert_eq!(
            index
                .search(ACCOUNT, None, &crate::search::parse("from:ada"), 1)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn the_snippet_is_the_first_line_with_something_in_it() {
        assert_eq!(snippet("\n\nHello there.\nRest."), "Hello there.");
        assert_eq!(snippet(""), "");
        assert_eq!(snippet(&"a".repeat(500)).chars().count(), 200);
    }

    #[test]
    fn flags_come_from_the_store_not_the_index() {
        // Flags change constantly and a UID's bytes never do. Caching them here
        // would mean every read mark needed a cache write, and a stale one
        // would show unread mail that is not.
        let mut store = store(vec![message(1, "a@x", "", "s", "a@example.com", "b")]);
        let mut index = Index::in_memory().unwrap();
        index.sync_mailbox(ACCOUNT, MAILBOX, &store).unwrap();

        store
            .set_flags(
                1,
                Flags {
                    seen: true,
                    ..Flags::default()
                },
            )
            .unwrap();
        let threads = index
            .conversations(ACCOUNT, MAILBOX, &flags(&store))
            .unwrap();
        assert!(!threads[0].unread, "the index served a stale read mark");
    }
}

// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! What a backing store must provide for a sync cycle to run against it.
//!
//! The protocol layer deals in three things: an href, an etag, and a blob of
//! iCalendar text. Everything a store has to do is expressible in those terms,
//! which is why this trait is six small methods rather than an ORM.
//!
//! Four of them are the cycle itself — read state, upsert, remove, commit ctag.
//! The other two exist because the cycle has to be able to notice that it is
//! about to destroy someone's work: [`CalDavStore::unpushed_local`] answers
//! "is there a local change here that the server has not accepted yet", and
//! [`CalDavStore::record_conflict`] is where the answer goes when the server
//! has meanwhile moved on. See [`Conflict`].
//!
//! In the project this code came from, the implementation was a set of SQLite
//! tables. Here it is a directory of files ([`crate::vdir::VdirStore`]). The
//! reconciler in [`crate::sync`] cannot tell the difference, and the tests use
//! a third, in-memory implementation to exercise a full cycle without a disk or
//! a server.

use std::collections::HashMap;

use crate::error::Result;

/// One event as the server holds it.
///
/// `ics` is the server's **verbatim** bytes. It is deliberately not a parsed
/// `cosmic_pim_core::model::Event`: our model covers what the UI can edit,
/// which is a strict subset of what a VEVENT can carry. Round-tripping through
/// it would silently discard ATTENDEE lists, ORGANIZER, VTIMEZONE blocks,
/// categories, and every `X-` property the server or another client put there —
/// and then hand that lossy version back on the next write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEvent {
    pub href: String,
    /// Verbatim, quotes and `W/` included (RFC 7232 says they are part of the
    /// value). Sanitised only when building an `If-Match`.
    pub etag: String,
    pub ics: String,
}

/// What we currently hold for one collection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectionState {
    /// The collection's ctag as of the last completed sync, if we have one.
    ///
    /// This is the entire point of incremental sync: when the server's ctag is
    /// unchanged, nothing in the collection has changed and the listing REPORT
    /// can be skipped altogether.
    pub ctag: Option<String>,
    /// href → etag for every event we hold.
    pub entries: HashMap<String, String>,
}

/// A local change and the server's change to the same resource, neither of
/// which may be discarded without asking.
///
/// # Why this type exists
///
/// The pull path writes the server's bytes over the local file, unguarded,
/// because for a resource we are merely *fetching* the server is authoritative.
/// That stops being true the moment there is an unsent local edit: the pull
/// overwrites the edit, the queued PUT then reads the file at drain time, finds
/// the server's own bytes there, and pushes them back. The push "succeeds", the
/// queue empties, every indicator says the collection is in sync — and the
/// user's edit is gone with no error anywhere. That is the worst failure this
/// crate can produce, because nothing surfaces it.
///
/// So when both sides changed, neither copy is written over the other. The
/// local file keeps the local edit, the server's bytes are parked here, and the
/// application decides. Resolution is
/// [`crate::VdirStore::resolve_conflict_take_remote`] or
/// [`crate::VdirStore::resolve_conflict_keep_local`].
///
/// # No base copy
///
/// A three-way merge wants the *last synced* bytes as well, and this record
/// deliberately does not carry them: reconstructing them would mean keeping a
/// second copy of every item in the collection (the sidecar holds etags, not
/// payloads), and the bytes are already gone by the time a local edit is
/// queued — the application writes the file first and queues afterwards. So an
/// application can offer "keep mine", "take theirs", or a hand-merge of two
/// texts, but not an automatic merge of non-overlapping properties. Supplying a
/// base would mean either retaining last-synced copies for pending items or
/// passing the pre-edit bytes in at save time; both are a design change, not an
/// implementation detail, and neither is pretended at here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Conflict {
    pub href: String,
    /// What the local file holds — the user's unsent edit.
    pub local: String,
    /// What the server holds now, verbatim.
    pub remote: String,
    /// The etag of [`Conflict::remote`], which is also what a subsequent
    /// `If-Match` must carry for a resolution to be accepted.
    pub remote_etag: String,
}

pub trait CalDavStore {
    /// Everything we hold for this collection, in one read.
    fn state(&self) -> Result<CollectionState>;

    /// Inserts or replaces one event.
    ///
    /// Implementations must record the etag alongside the payload: it is what
    /// the next cycle diffs against, and losing it means re-fetching the whole
    /// collection every time.
    fn upsert(&mut self, event: &RemoteEvent) -> Result<()>;

    /// Removes one event. A resource that is already gone is not an error —
    /// sync is re-run after partial failures and must be idempotent.
    fn remove(&mut self, href: &str) -> Result<()>;

    /// Records the collection's ctag, ending the cycle.
    ///
    /// Called **only** after every upsert and removal has succeeded. Committing
    /// a ctag over a partially-applied cycle would convince the next run it is
    /// up to date, and the missing events would never arrive.
    fn commit_ctag(&mut self, ctag: Option<&str>) -> Result<()>;

    /// The bytes of a local change to `href` that the server has not accepted
    /// yet, or `None` if there is no such change.
    ///
    /// This is what makes the pull path able to tell "the server changed this"
    /// apart from "the server changed this and so did we" — the second of
    /// which is a [`Conflict`] rather than an overwrite.
    ///
    /// A store with no writeback queue has no unsent changes by definition and
    /// answers `None`.
    fn unpushed_local(&self, href: &str) -> Result<Option<String>>;

    /// Parks the server's version of a resource that diverged from ours.
    ///
    /// Implementations must **not** write [`Conflict::remote`] over the local
    /// file — preserving both copies is the entire purpose — but must record
    /// [`Conflict::remote_etag`] as the etag they now hold for the href.
    /// Recording it is what keeps the next cycle from re-fetching the same
    /// divergence forever: the resource is not "unseen", it is "seen and
    /// disputed", and the etag is exactly what a resolution's `If-Match` needs.
    fn record_conflict(&mut self, conflict: &Conflict) -> Result<()>;
}

/// An in-memory [`CalDavStore`] for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    pub ctag: Option<String>,
    pub events: HashMap<String, RemoteEvent>,
    /// Stands in for a writeback queue: hrefs mapped to unsent local bytes.
    pub unpushed: HashMap<String, String>,
    pub conflicts: Vec<Conflict>,
}

impl CalDavStore for MemoryStore {
    fn state(&self) -> Result<CollectionState> {
        Ok(CollectionState {
            ctag: self.ctag.clone(),
            entries: self
                .events
                .iter()
                .map(|(href, event)| (href.clone(), event.etag.clone()))
                .collect(),
        })
    }

    fn upsert(&mut self, event: &RemoteEvent) -> Result<()> {
        self.events.insert(event.href.clone(), event.clone());
        Ok(())
    }

    fn remove(&mut self, href: &str) -> Result<()> {
        self.events.remove(href);
        Ok(())
    }

    fn commit_ctag(&mut self, ctag: Option<&str>) -> Result<()> {
        self.ctag = ctag.map(ToOwned::to_owned);
        Ok(())
    }

    fn unpushed_local(&self, href: &str) -> Result<Option<String>> {
        Ok(self.unpushed.get(href).cloned())
    }

    fn record_conflict(&mut self, conflict: &Conflict) -> Result<()> {
        // The etag moves; the payload does not. Same contract as VdirStore.
        if let Some(event) = self.events.get_mut(&conflict.href) {
            event.etag = conflict.remote_etag.clone();
        }
        self.conflicts.retain(|c| c.href != conflict.href);
        self.conflicts.push(conflict.clone());
        Ok(())
    }
}

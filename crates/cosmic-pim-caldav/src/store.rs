// SPDX-License-Identifier: MPL-2.0

//! What a backing store must provide for a sync cycle to run against it.
//!
//! The protocol layer deals in three things: an href, an etag, and a blob of
//! iCalendar text. Everything a store has to do is expressible in those terms,
//! which is why this trait is four methods rather than an ORM.
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
}

/// An in-memory [`CalDavStore`] for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    pub ctag: Option<String>,
    pub events: HashMap<String, RemoteEvent>,
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
}

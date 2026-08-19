// SPDX-License-Identifier: MPL-2.0

//! CalDAV for the COSMIC PIM suite: discovery, incremental sync, and writeback.
//!
//! # Shape
//!
//! - [`dav`] — the protocol. URL resolution, multistatus XML, the HTTP client.
//!   Stateless and storage-agnostic.
//! - [`plan`] — the reconciliation decision, as a pure function.
//! - [`store`] — the [`CalDavStore`] trait: what a backing store must provide
//!   for a sync cycle to run against it.
//! - [`vdir`] — [`CalDavStore`] over a `cosmic-pim-core` vdir, so synced events
//!   land as ordinary `.ics` files that khal and vdirsyncer can also read.
//! - [`sync`] — the cycle that ties them together.
//! - [`push`] — the durable writeback queue, and the classification that
//!   decides whether a failed push is retried, parked, or dropped.
//! - [`patch`] — byte-preserving writeback into stored resources.
//!
//! # Why the trait exists
//!
//! This code came from a mail client where the calendar lived in SQLite tables
//! (`caldav_calendars`, `caldav_event_map`, `calendar_events`). Here the source
//! of truth is a directory of files. The protocol layer never cared — it deals
//! in hrefs, etags, and iCalendar text — so the port amounted to naming the
//! handful of operations the reconciler actually performs on storage and
//! writing a second implementation of them.
//!
//! Keeping the trait is not speculative generality: the tests use an in-memory
//! implementation to exercise reconciliation without touching a disk or a
//! server, and a contacts app will want CardDAV over the same shape.

pub mod dav;
pub mod error;
pub mod patch;
pub mod push;
pub mod plan;
pub mod store;
pub mod sync;
pub mod vdir;

pub use dav::{CalDavEventEntry, CaldavClient, DiscoveredCalendar, Flavor, PropfindEventsResult};
pub use error::{Error, Result};
pub use plan::{SyncPlan, plan_sync};
pub use store::{CalDavStore, CollectionState, Conflict, RemoteEvent};
pub use sync::{SyncOutcome, sync_collection};
pub use vdir::VdirStore;

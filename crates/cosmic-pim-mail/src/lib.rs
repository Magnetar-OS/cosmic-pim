// SPDX-License-Identifier: MPL-2.0

//! Mail for the COSMIC PIM suite: message model, maildir store, threading, and
//! IMAP sync.
//!
//! Stands *beside* `cosmic-pim-caldav` rather than on it. IMAP is not a WebDAV
//! flavour and shares none of its plumbing — but it does share the invariants,
//! and they are the reason this crate is shaped the way it is:
//!
//! - **Files are the source of truth.** Maildir, not SQLite. A SQLite message
//!   store would be the first place the suite breaks its own rule, and the
//!   "walk away with your data" promise goes with it. `mbsync`, `notmuch`, and
//!   `mu` read the same directories.
//! - **Message bytes are verbatim.** The maildir file holds the server's RFC
//!   5322 bytes exactly as the vdir holds a server's iCalendar text. The model
//!   extracts; it never re-serialises.
//! - **The index is disposable.** Whatever ranks search (tantivy, ported from
//!   the donor) has the same status as the calendar's SQLite cache: delete it,
//!   it rebuilds.
//! - **Push before pull.** Flag changes are writeback. "My read marks keep
//!   reverting" is the same bug as "my edits keep reverting", with the same
//!   cause and the same fix.
//! - **UIDVALIDITY is the 412 analogue.** A change means the server's numbering
//!   was rebuilt underneath us and local state for that mailbox is stale — it
//!   exits the retry loop into a resync, exactly as a stale etag does.
//!
//! See `ARCHITECTURE.md` in this repository for the full set, and `04-envelope`
//! for the port plan.

// Scaffold: this crate is being built out. Modules land here as they are
// ported — model and maildir store first, then threading, then IMAP.

// SPDX-License-Identifier: MPL-2.0

//! The layer that makes the calendar actually sync.
//!
//! Three crates below this one each solve half a problem:
//!
//! - `cosmic-pim-caldav` speaks the protocol, but has no idea whose account it
//!   is or where the password lives.
//! - `cosmic-pim-accounts` holds accounts and credentials, but never opens a
//!   socket.
//! - `cosmic-pim-core` owns the vdir, and has never heard of a server.
//!
//! This crate is the only place that knows about all three, which is what keeps
//! each of them independently testable and separately reusable — a contacts app
//! will want the same three-way join with CardDAV substituted for CalDAV.
//!
//! - [`provision`] — binds a discovered calendar or address book to a vdir
//!   collection, exactly once, across restarts.
//! - [`engine`] — one pass over every enabled account, failing per-collection
//!   rather than per-run.
//! - [`writeback`] — turns a local save or delete into a queued push.
//! - [`conflict`] — what a pass could not decide on its own: both sides
//!   changed the same resource, and a person has to choose.

pub mod conflict;
pub mod engine;
pub mod mail;
pub mod error;
pub mod provision;
pub mod writeback;

pub use conflict::all as conflicts;
pub use engine::{AccountReport, CollectionReport, sync_account, sync_all};
pub use mail::{MailReport, MailboxReport, credentials_for, sync_account_mail};
pub use error::{Error, Result};
pub use provision::{Provisioned, provision_account};
pub use writeback::{queue_delete, queue_save};

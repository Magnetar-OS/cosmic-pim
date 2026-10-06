// Copyright 2026 Dominikos Pritis
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
//! - [`writeback`] — makes a local save or delete and its queued push one
//!   step.
//! - [`conflict`] — what a pass could not decide on its own: both sides
//!   changed the same resource, and a person has to choose.
//! - [`setup`] — from an address to a stored, working account: which
//!   provider, which ways to sign in, and the sign-in itself.
//! - `mail` — the mail pass, behind the default `mail` feature. A contacts
//!   or calendar app turns it off (`default-features = false`) and keeps the
//!   mail and OpenPGP stack out of its build.

pub mod conflict;
pub mod engine;
pub mod error;
pub mod freebusy;
#[cfg(feature = "mail")]
pub mod mail;
pub mod provision;
pub mod setup;
pub mod writeback;

pub use conflict::all as conflicts;
pub use engine::{AccountReport, CollectionReport, SyncTally, sync_account, sync_all};
pub use error::{Error, Result};
pub use freebusy::{Answer, account_for_collection, availability};
#[cfg(feature = "mail")]
pub use mail::{
    DrainReport, MailReport, MailboxReport, credentials_for, drain_outbox, sync_account_mail,
};
pub use provision::{Provisioned, provision_account};
pub use writeback::{
    Saved, queue_delete, queue_save, queue_save_with_base, save_and_queue, save_and_queue_creating,
};

// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Shared PIM substrate for the COSMIC communication suite.
//!
//! Everything here is display-server-free and application-agnostic: it is the
//! layer the calendar, contacts, tasks, and mail apps are all expected to sit
//! on, so that a sync bug is fixed once rather than four times.
//!
//! - [`model`] — events, calendars, and recurrence expansion. No toolkit types.
//! - [`ical`] — the one iCalendar parser/serialiser the whole suite uses.
//! - [`vcard`] — the one vCard parser/serialiser the whole suite uses.
//! - [`store`] — iCalendar files in a vdir, with a SQLite index in front.
//! - [`atomic`] — crash-safe file replacement, used by every writer.
//!
//! # Licence
//!
//! This crate is MPL-2.0 while the COSMIC applications built on it are
//! GPL-3.0-only. That is deliberate — see `LICENSING.md` at the repository
//! root. In short: file-level copyleft keeps improvements to *these* files
//! public without dictating the licence of anything that merely links them.

pub mod atomic;
pub mod ical;
pub mod merge;
pub mod model;
pub mod patch;
pub mod store;
pub mod vcard;

pub use store::{Store, StoreError};

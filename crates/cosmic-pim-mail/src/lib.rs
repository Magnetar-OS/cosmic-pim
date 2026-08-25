// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Mail for the COSMIC PIM suite: the message model, a maildir store,
//! threading, and IMAP sync.
//!
//! # Where this sits
//!
//! Beside `cosmic-pim-caldav`, not on top of it. CalDAV and CardDAV are the
//! same protocol with four substitutions, which is why they share one engine
//! behind a `Flavor` enum. IMAP is not a third flavour of anything: it is a
//! stateful session protocol with its own consistency model (UIDVALIDITY,
//! MODSEQ), and pretending otherwise would mean a fifth field on `Flavor` that
//! every DAV code path has to ignore.
//!
//! What *is* shared is everything below the protocol: `cosmic_pim_core::atomic`
//! for crash-safe writes, `cosmic_pim_core::model::Contact` for resolving a
//! sender to a real person out of the same address book Circle shows, and
//! `cosmic-pim-accounts` for credentials — one Fastmail account, not one per
//! app.
//!
//! # Shape
//!
//! - [`model`] — what a message *is*, extracted from bytes we never rewrite.
//! - [`text`] — HTML → what a human would actually see, and a count of what was
//!   hidden.
//! - [`auth`] — `Authentication-Results` (RFC 8601), per hop and mechanism.
//! - [`attachment`] — getting attachments out of a message, and safely onto a disk.
//! - [`compose`] — drafts, and how a reply or a forward is built from a message.
//! - [`discovery`] — working out where an address's mail lives, from the address.
//! - [`drafts`] — unsent messages, kept on this device.
//! - [`smtp`] — sending, and the one failure that must never be auto-retried.
//! - [`threading`] — JWZ threading with deterministic thread ids.
//! - [`folder`] — mailbox names, hierarchy, and RFC 6154 special use.
//! - [`store`] — the [`MailStore`] trait: what a backing store must provide.
//! - [`maildir`] — [`MailStore`] over a maildir, so `mbsync`, `mu`, and
//!   `notmuch` read the same files.
//! - [`index`] — a rebuildable SQLite cache of what a conversation list shows.
//! - [`outbox`] — messages that have been sent but have not left yet.
//! - [`plan`] — the reconciliation decision, as a pure function.
//! - [`search`] — the query language, as a pure parser.
//! - [`push`] — durable writeback for flag changes, moves, and deletions.
//! - [`imap`] — the session, and the cycle that ties the rest together.
//!
//! # The invariants, translated
//!
//! `ARCHITECTURE.md` states these for calendars. They are not analogies here;
//! they are the same invariants over a different wire format.
//!
//! **Files are the truth, the index is disposable.** A maildir, not a SQLite
//! message table — a SQLite message store would be the first place the suite
//! breaks its own rule, and the "walk away with your data" promise goes with
//! it. Sync state — UIDVALIDITY, the UID cursor, MODSEQ — is server-opaque and
//! cannot be reconstructed from the files, so it lives in a sidecar beside
//! them, never in an index.
//!
//! **Server bytes are stored verbatim.** [`model::Message`] covers what the UI
//! shows, which is a fraction of what an RFC 5322 message carries. Storing the
//! model instead of the bytes would discard MIME structure, signatures, and
//! every header nobody has thought about yet — and a signature that survives
//! the trip is the *entire* value of DKIM.
//!
//! **Writeback is queued and durable.** A `\Seen` flag that fails to reach the
//! server and is then forgotten diverges permanently, for exactly the reason a
//! dropped CalDAV PUT does: the server's state never changed, so the next pull
//! finds nothing to reconcile.
//!
//! **Push before pull.** The other order lets a pull overwrite a local flag
//! change with the server's older copy. It presents as "my read marks keep
//! reverting" — the same bug as "my edits keep reverting", one wire format over.
//!
//! **UIDVALIDITY is the 412.** A stale etag means "re-read before you write".
//! A changed UIDVALIDITY means the same thing about an entire mailbox: every UID
//! we hold now names a different message, or nothing. It is never retryable and
//! must never be handled by pushing harder.

pub mod attachment;
pub mod auth;
pub mod compose;
pub mod discovery;
pub mod drafts;
pub mod error;
pub mod folder;
pub mod gmail;
pub mod graph;
pub mod imap;
pub mod index;
pub mod jmap;
pub mod maildir;
pub mod mbox;
pub mod model;
pub mod outbox;
pub mod plan;
pub mod pop3;
pub mod push;
pub mod sasl;
pub mod search;
pub mod smtp;
pub mod store;
pub mod text;
pub mod threading;
pub mod unsubscribe;

pub use compose::Draft;
pub use discovery::Discovered;
pub use drafts::Drafts;
pub use error::{Error, Result};
pub use folder::{Folder, SpecialUse};
pub use index::{Conversation, Hit, Index, Summary};
pub use model::{Flags, Mailbox, Message};
pub use outbox::Outbox;
pub use plan::{MailboxPlan, plan_fetch, plan_reconcile};
pub use sasl::Credentials;
pub use search::Query;
pub use smtp::{Outcome, SmtpEndpoint};
pub use store::{Cursor, MailStore, MailboxState, MemoryStore, RemoteMessage};
pub use threading::{ThreadIndex, ThreadResolution, Threadable, resolve_thread};

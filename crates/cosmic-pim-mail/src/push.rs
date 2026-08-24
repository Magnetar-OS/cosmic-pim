// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The queue's semantics and the backoff schedule follow
// `cosmic_pim_caldav::push`, which is itself ported from Meltemi's
// `caldav_push_queue`. The failure taxonomy is the one `01-cosmic-pim` asks
// for, spelled for IMAP. See NOTICE and LICENSING.md.

//! Durable writeback: flag changes, moves, and deletions that must reach the
//! server or keep trying.
//!
//! # Why a queue rather than "just STORE it"
//!
//! Marking a message read is a *write*, and a write that fails and is forgotten
//! diverges permanently. The user reads a message on the laptop; the STORE
//! fails because the train went into a tunnel. Locally the message is read. On
//! the server it is unread. The next sync compares flags, finds the server says
//! unread, and dutifully marks it unread again.
//!
//! That is the whole of "my read marks keep reverting", and it is the same bug
//! as "my calendar edits keep reverting" — a dropped write plus a pull that
//! believes the server. Two things fix it, and both are needed: the failed
//! write persists and is retried, and the push runs *before* the pull.
//!
//! # The taxonomy is the point
//!
//! Exponential backoff is right for a timeout and wrong for everything else.
//! Retrying a `[AUTHENTICATIONFAILED]` two hundred times an hour will not
//! discover a new password, and retrying a STORE against a mailbox the server
//! renumbered will cheerfully apply the flag to whatever message now holds that
//! UID. So a failure is classified before it is scheduled:
//!
//! - [`Failure::Retry`] — back off and try again. Network, 5xx-equivalents.
//! - [`Failure::Reconcile`] — the queue cannot fix this; a sync pass can.
//!   UIDVALIDITY changed, or the UID is simply gone. Leaves the loop.
//! - [`Failure::User`] — nothing automatic will help. Bad credentials, no
//!   permission, over quota. Surfaces, and stops.
//!
//! Misclassifying the second as the first is how a client silently applies a
//! flag to the wrong message; misclassifying the third as the first is how a
//! client locks an account out.

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::model::Flags;

/// First retry delay. Doubles per attempt up to [`MAX_DELAY_MS`].
///
/// Sized for mail's cadence: quick enough that a brief drop settles inside a
/// minute, slow enough that a server refusing us is not hammered.
const BASE_DELAY_MS: i64 = 15_000;
const MAX_DELAY_MS: i64 = 60 * 60_000;

/// Exponential backoff, clamped so the shift cannot overflow.
#[must_use]
pub fn retry_delay_ms(attempts: u32) -> i64 {
    let shift = attempts.min(12);
    BASE_DELAY_MS
        .saturating_mul(1_i64 << shift)
        .min(MAX_DELAY_MS)
}

/// What a queued operation does when it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PushOp {
    /// Set this message's system flags to exactly these.
    ///
    /// Absolute rather than a `+FLAGS`/`-FLAGS` delta, and deliberately: a
    /// queue that accumulated deltas would replay them in an order that depends
    /// on when the network came back. The final state is what the user asked
    /// for, so the final state is what gets sent.
    SetFlags { uid: u32, flags: Flags },
    /// Move a message to another mailbox — archive, junk, or a folder the user
    /// dragged it to.
    Move { uid: u32, destination: String },
    /// Mark `\Deleted` and expunge.
    ///
    /// Distinct from [`Self::Move`] to Trash, which is what a UI's "delete"
    /// usually means. This one does not come back.
    Delete { uid: u32 },
}

impl PushOp {
    #[must_use]
    pub fn uid(&self) -> u32 {
        match self {
            Self::SetFlags { uid, .. } | Self::Move { uid, .. } | Self::Delete { uid } => *uid,
        }
    }
}

/// How a failed attempt should be treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Failure {
    /// Transient. Back off and try again.
    Retry,
    /// The queue cannot fix this, but a sync pass can. Hand it to one.
    Reconcile,
    /// Nothing automatic will help. Tell the user.
    User,
}

impl Failure {
    /// Classifies a failed push.
    #[must_use]
    pub fn of(error: &Error) -> Self {
        match error {
            Error::UidValidityChanged { .. } => Self::Reconcile,
            Error::Auth(_) => Self::User,
            other if other.is_transient() => Self::Retry,
            Error::Imap(message) => classify_response(message),
            _ => Self::User,
        }
    }
}

/// Reads the response codes RFC 5530 defines, which is how a server says *why*
/// it refused rather than just that it did.
///
/// Servers that predate RFC 5530 send bare text and land in [`Failure::User`],
/// which is the safe default: it stops and shows the user the server's own
/// words rather than retrying something that will never work.
fn classify_response(message: &str) -> Failure {
    let lower = message.to_ascii_lowercase();
    // The message is gone or the mailbox was rebuilt: a retry would apply the
    // operation to whatever now holds that UID.
    for code in ["[uidvalidity", "[expunged]", "[nonexistent]", "[trycreate]"] {
        if lower.contains(code) {
            return Failure::Reconcile;
        }
    }
    for code in [
        "[authenticationfailed]",
        "[authorizationfailed]",
        "[noperm]",
        "[overquota]",
        "[privacyrequired]",
        "[cannot]",
    ] {
        if lower.contains(code) {
            return Failure::User;
        }
    }
    Failure::User
}

/// A queued operation and its retry state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPush {
    pub op: PushOp,
    #[serde(default)]
    pub attempts: u32,
    /// Epoch milliseconds before which this must not be retried.
    #[serde(default)]
    pub next_attempt_ms: i64,
    /// Why the last attempt failed, for the UI to show.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Set when the operation stopped being retryable. An entry with this set
    /// is inert: it is kept so the reason survives a restart and can be shown,
    /// and is cleared by whatever resolves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<Failure>,
}

impl PendingPush {
    /// Is this entry still going to be attempted?
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.blocked.is_none()
    }
}

/// The queue operations a store must support for writeback to work.
///
/// Separate from [`crate::store::MailStore`] for the reason
/// `cosmic_pim_caldav` keeps them apart: the pull path has two real
/// implementations and this has one, but the backoff schedule still has to be
/// exercisable without a disk.
pub trait PushQueue {
    fn pending(&self) -> Vec<PendingPush>;

    /// Adds an operation, or replaces an existing one for the same UID and
    /// resets it to "due now".
    ///
    /// Replacing rather than appending is the important half. The user stars a
    /// message, unstars it, stars it again: three entries would replay three
    /// times and could leave the server in the middle state if the third
    /// failed. One entry carrying the current flags cannot.
    ///
    /// A [`PushOp::Delete`] or [`PushOp::Move`] supersedes a queued
    /// [`PushOp::SetFlags`] for the same UID — there is no point setting flags
    /// on a message that is about to leave the mailbox — but the reverse is not
    /// true, and enqueueing flags after a move must not cancel the move.
    fn enqueue(&mut self, op: PushOp) -> crate::Result<()>;

    /// Drops the entry for `uid` — it succeeded.
    fn resolve(&mut self, uid: u32) -> crate::Result<()>;

    /// Records a failure and reschedules, or blocks the entry.
    fn defer(
        &mut self,
        uid: u32,
        failure: Failure,
        error: &str,
        next_attempt_ms: i64,
    ) -> crate::Result<()>;
}

/// What [`drain`] needs from a server connection.
///
/// A trait rather than a concrete session so the backoff schedule and the
/// failure taxonomy can be tested exhaustively without a socket — the same
/// reason [`PushQueue`] is one.
pub trait Writeback {
    fn store_flags(&mut self, uid: u32, flags: Flags) -> crate::Result<()>;
    fn move_message(&mut self, uid: u32, destination: &str) -> crate::Result<()>;
    fn delete_message(&mut self, uid: u32) -> crate::Result<()>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    pub succeeded: usize,
    /// Failed transiently and rescheduled.
    pub deferred: usize,
    /// Failed in a way a sync pass has to resolve.
    pub needs_reconcile: usize,
    /// Failed in a way only the user can resolve.
    pub needs_user: usize,
    /// Not yet due under backoff, or already blocked.
    pub skipped: usize,
}

impl DrainOutcome {
    /// Is there anything left that will never move on its own?
    #[must_use]
    pub fn is_stuck(&self) -> bool {
        self.needs_reconcile > 0 || self.needs_user > 0
    }
}

/// Attempts every due operation once.
///
/// `now_ms` is a parameter rather than read from the clock so the backoff
/// schedule is testable without sleeping.
pub fn drain(server: &mut impl Writeback, queue: &mut impl PushQueue, now_ms: i64) -> DrainOutcome {
    let mut outcome = DrainOutcome::default();

    for entry in queue.pending() {
        if !entry.is_live() || entry.next_attempt_ms > now_ms {
            outcome.skipped += 1;
            continue;
        }

        let uid = entry.op.uid();
        let result = match &entry.op {
            PushOp::SetFlags { uid, flags } => server.store_flags(*uid, *flags),
            PushOp::Move { uid, destination } => server.move_message(*uid, destination),
            PushOp::Delete { uid } => server.delete_message(*uid),
        };

        match result {
            Ok(()) => {
                if let Err(why) = queue.resolve(uid) {
                    tracing::warn!(uid, %why, "push succeeded but the queue entry survived");
                }
                outcome.succeeded += 1;
            }
            Err(why) => {
                let failure = Failure::of(&why);
                // Only a retryable failure gets a new attempt time; for the
                // others nothing is going to attempt it, so scheduling one
                // would be a number the UI could only mislead with.
                let next = match failure {
                    Failure::Retry => {
                        let attempts = entry.attempts.saturating_add(1);
                        tracing::warn!(uid, attempts, %why, "writeback failed; will retry");
                        outcome.deferred += 1;
                        now_ms.saturating_add(retry_delay_ms(attempts))
                    }
                    Failure::Reconcile => {
                        tracing::warn!(uid, %why, "writeback needs a sync pass, not a retry");
                        outcome.needs_reconcile += 1;
                        entry.next_attempt_ms
                    }
                    Failure::User => {
                        tracing::warn!(uid, %why, "writeback cannot succeed without the user");
                        outcome.needs_user += 1;
                        entry.next_attempt_ms
                    }
                };
                if let Err(e) = queue.defer(uid, failure, &why.to_string(), next) {
                    tracing::warn!(uid, %e, "could not record a writeback failure");
                }
            }
        }
    }

    outcome
}

/// A [`PushQueue`] over a `Vec`, for tests and for anything holding the queue
/// in memory.
#[derive(Debug, Default)]
pub struct MemoryQueue {
    pub entries: Vec<PendingPush>,
}

impl PushQueue for MemoryQueue {
    fn pending(&self) -> Vec<PendingPush> {
        self.entries.clone()
    }

    fn enqueue(&mut self, op: PushOp) -> crate::Result<()> {
        enqueue_into(&mut self.entries, op);
        Ok(())
    }

    fn resolve(&mut self, uid: u32) -> crate::Result<()> {
        self.entries.retain(|e| e.op.uid() != uid);
        Ok(())
    }

    fn defer(
        &mut self,
        uid: u32,
        failure: Failure,
        error: &str,
        next_attempt_ms: i64,
    ) -> crate::Result<()> {
        defer_in(&mut self.entries, uid, failure, error, next_attempt_ms);
        Ok(())
    }
}

/// The enqueue rule, shared by every [`PushQueue`] implementation so the
/// supersede semantics cannot drift between them.
pub(crate) fn enqueue_into(entries: &mut Vec<PendingPush>, op: PushOp) {
    let uid = op.uid();
    if let Some(existing) = entries.iter_mut().find(|e| e.op.uid() == uid) {
        // Setting flags on a message that is already queued to leave the
        // mailbox is not worth a round trip, and must not cancel the departure.
        let superseded = matches!(op, PushOp::SetFlags { .. })
            && matches!(existing.op, PushOp::Move { .. } | PushOp::Delete { .. });
        if superseded {
            return;
        }
        existing.op = op;
        existing.attempts = 0;
        existing.next_attempt_ms = 0;
        existing.last_error = None;
        existing.blocked = None;
        return;
    }
    entries.push(PendingPush {
        op,
        attempts: 0,
        next_attempt_ms: 0,
        last_error: None,
        blocked: None,
    });
}

pub(crate) fn defer_in(
    entries: &mut [PendingPush],
    uid: u32,
    failure: Failure,
    error: &str,
    next_attempt_ms: i64,
) {
    if let Some(entry) = entries.iter_mut().find(|e| e.op.uid() == uid) {
        entry.last_error = Some(error.to_owned());
        match failure {
            Failure::Retry => {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.next_attempt_ms = next_attempt_ms;
                entry.blocked = None;
            }
            other => entry.blocked = Some(other),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeServer {
        /// Errors to return, newest last; `None` means succeed.
        script: Vec<Option<Error>>,
        calls: Vec<PushOp>,
    }

    impl FakeServer {
        fn failing(error: Error) -> Self {
            Self {
                script: vec![Some(error)],
                calls: Vec::new(),
            }
        }

        fn next(&mut self) -> crate::Result<()> {
            match self.script.pop() {
                Some(Some(error)) => Err(error),
                _ => Ok(()),
            }
        }
    }

    impl Writeback for FakeServer {
        fn store_flags(&mut self, uid: u32, flags: Flags) -> crate::Result<()> {
            self.calls.push(PushOp::SetFlags { uid, flags });
            self.next()
        }
        fn move_message(&mut self, uid: u32, destination: &str) -> crate::Result<()> {
            self.calls.push(PushOp::Move {
                uid,
                destination: destination.to_owned(),
            });
            self.next()
        }
        fn delete_message(&mut self, uid: u32) -> crate::Result<()> {
            self.calls.push(PushOp::Delete { uid });
            self.next()
        }
    }

    fn seen() -> Flags {
        Flags {
            seen: true,
            ..Flags::default()
        }
    }

    fn set_flags(uid: u32) -> PushOp {
        PushOp::SetFlags { uid, flags: seen() }
    }

    #[test]
    fn backoff_doubles_from_fifteen_seconds_to_an_hour_ceiling() {
        assert_eq!(retry_delay_ms(0), 15_000);
        assert_eq!(retry_delay_ms(1), 30_000);
        assert_eq!(retry_delay_ms(2), 60_000);
        assert_eq!(retry_delay_ms(20), MAX_DELAY_MS, "the ceiling did not hold");
    }

    #[test]
    fn backoff_never_overflows_however_long_it_has_been_failing() {
        for attempts in [12, 13, 63, 64, 1000, u32::MAX] {
            assert_eq!(retry_delay_ms(attempts), MAX_DELAY_MS);
        }
    }

    #[test]
    fn re_enqueueing_the_same_uid_replaces_rather_than_appends() {
        let mut queue = MemoryQueue::default();
        queue.enqueue(set_flags(1)).unwrap();
        queue.defer(1, Failure::Retry, "boom", 999_999).unwrap();
        queue.enqueue(set_flags(1)).unwrap();

        let pending = queue.pending();
        assert_eq!(pending.len(), 1, "the queue accumulated duplicates");
        assert_eq!(
            pending[0].attempts, 0,
            "backoff was not reset by a new edit"
        );
        assert_eq!(pending[0].next_attempt_ms, 0);
    }

    #[test]
    fn a_move_supersedes_queued_flags_but_flags_never_cancel_a_move() {
        let mut queue = MemoryQueue::default();
        queue.enqueue(set_flags(1)).unwrap();
        queue
            .enqueue(PushOp::Move {
                uid: 1,
                destination: "Archive".into(),
            })
            .unwrap();
        queue.enqueue(set_flags(1)).unwrap();

        let pending = queue.pending();
        assert_eq!(pending.len(), 1);
        assert!(
            matches!(pending[0].op, PushOp::Move { .. }),
            "a flag change cancelled the archive the user asked for"
        );
    }

    #[test]
    fn a_transient_failure_backs_off_and_stays_live() {
        let mut server = FakeServer::failing(Error::Imap("connection reset by peer".into()));
        let mut queue = MemoryQueue::default();
        queue.enqueue(set_flags(1)).unwrap();

        let outcome = drain(&mut server, &mut queue, 0);

        assert_eq!(outcome.deferred, 1);
        assert!(!outcome.is_stuck());
        let entry = &queue.pending()[0];
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.next_attempt_ms, retry_delay_ms(1));
        assert!(entry.is_live());
        assert!(
            entry.last_error.is_some(),
            "the reason was not kept for the UI"
        );
    }

    #[test]
    fn a_renumbered_mailbox_leaves_the_retry_loop() {
        // Retrying would apply the flag to whatever message now holds the UID.
        let mut server = FakeServer::failing(Error::UidValidityChanged {
            mailbox: "INBOX".into(),
            had: 1,
            now: 2,
        });
        let mut queue = MemoryQueue::default();
        queue.enqueue(set_flags(1)).unwrap();

        let outcome = drain(&mut server, &mut queue, 0);

        assert_eq!(outcome.needs_reconcile, 1);
        assert_eq!(outcome.deferred, 0, "a renumbering was scheduled for retry");
        assert_eq!(queue.pending()[0].blocked, Some(Failure::Reconcile));
    }

    #[test]
    fn bad_credentials_stop_rather_than_hammering_the_server() {
        let mut server = FakeServer::failing(Error::Auth("[AUTHENTICATIONFAILED]".into()));
        let mut queue = MemoryQueue::default();
        queue.enqueue(set_flags(1)).unwrap();

        let outcome = drain(&mut server, &mut queue, 0);

        assert_eq!(outcome.needs_user, 1);
        assert!(outcome.is_stuck());
        assert_eq!(queue.pending()[0].attempts, 0, "a retry slot was consumed");
    }

    #[test]
    fn a_blocked_entry_is_not_attempted_again() {
        let mut queue = MemoryQueue::default();
        queue.enqueue(set_flags(1)).unwrap();
        queue.defer(1, Failure::User, "[NOPERM]", 0).unwrap();

        let mut server = FakeServer::default();
        let outcome = drain(&mut server, &mut queue, i64::MAX);

        assert_eq!(outcome.skipped, 1);
        assert!(server.calls.is_empty(), "a hopeless operation was retried");
    }

    #[test]
    fn a_new_edit_unblocks_a_stopped_entry() {
        // The user fixed the password and starred the message again. The queue
        // must not stay stuck on the old verdict.
        let mut queue = MemoryQueue::default();
        queue.enqueue(set_flags(1)).unwrap();
        queue
            .defer(1, Failure::User, "[AUTHENTICATIONFAILED]", 0)
            .unwrap();
        queue.enqueue(set_flags(1)).unwrap();
        assert!(queue.pending()[0].is_live());
    }

    #[test]
    fn an_entry_that_is_not_due_yet_is_skipped_not_attempted() {
        let mut queue = MemoryQueue::default();
        queue.enqueue(set_flags(1)).unwrap();
        queue.defer(1, Failure::Retry, "boom", 10_000).unwrap();

        let mut server = FakeServer::default();
        let outcome = drain(&mut server, &mut queue, 5_000);

        assert_eq!(outcome.skipped, 1);
        assert!(server.calls.is_empty());
        assert_eq!(queue.pending()[0].attempts, 1, "an attempt was consumed");
    }

    #[test]
    fn a_successful_push_leaves_the_queue_empty() {
        let mut server = FakeServer::default();
        let mut queue = MemoryQueue::default();
        queue.enqueue(set_flags(1)).unwrap();
        queue.enqueue(PushOp::Delete { uid: 2 }).unwrap();

        let outcome = drain(&mut server, &mut queue, 0);

        assert_eq!(outcome.succeeded, 2);
        assert!(queue.pending().is_empty());
    }

    #[test]
    fn response_codes_are_read_rather_than_guessed_at() {
        for (message, expected) in [
            ("NO [EXPUNGED] message no longer exists", Failure::Reconcile),
            ("NO [TRYCREATE] mailbox does not exist", Failure::Reconcile),
            ("NO [OVERQUOTA] mailbox is full", Failure::User),
            ("NO [NOPERM] read-only mailbox", Failure::User),
            ("BYE [UNAVAILABLE] server busy", Failure::Retry),
            ("NO something nobody has documented", Failure::User),
        ] {
            assert_eq!(
                Failure::of(&Error::Imap(message.into())),
                expected,
                "{message}"
            );
        }
    }
}

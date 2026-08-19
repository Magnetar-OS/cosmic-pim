// SPDX-License-Identifier: MPL-2.0
//
// The backoff schedule and the queue's semantics are ported from the
// `caldav_push_queue` design in the Meltemi project. See NOTICE and
// LICENSING.md. The storage is new: Meltemi kept the queue in SQLite, this
// keeps it in the collection's own sidecar so a vdir stays self-contained.

//! Durable writeback queue.
//!
//! # Why a queue rather than "just PUT it"
//!
//! Fire-and-forget writeback — one attempt, warn on failure — produces
//! **permanent** divergence, and this is the part that is easy to get wrong.
//!
//! Consider: the user renames an event, the PUT fails because the laptop's
//! Wi-Fi dropped. The local `.ics` now says "Team sync (moved)"; the server
//! still says "Team sync". The next pull compares the server's etag against the
//! one we stored, finds them **identical** — because nothing changed on the
//! server — and concludes there is nothing to reconcile. The edit is lost
//! silently and forever, and no amount of re-syncing will surface it.
//!
//! So every push that fails must be *retried*, and the record of it must
//! survive a restart. That is this module.
//!
//! # Backoff
//!
//! 30 s doubling to a one-hour ceiling. Sized for a calendar's cadence: fast
//! enough that a brief network blip settles within a minute, slow enough that a
//! server rejecting us (an expired app password, a 403 on a read-only
//! collection) is not hammered hundreds of times an hour.

use serde::{Deserialize, Serialize};

use crate::dav::CaldavClient;
use crate::error::Result;

/// First retry delay. Doubles per attempt up to [`MAX_DELAY_MS`].
const BASE_DELAY_MS: i64 = 30_000;
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
    /// Create or update the resource at `href` with the iCalendar text
    /// currently in the collection's file.
    ///
    /// The payload is read from disk at drain time rather than captured when
    /// queued: if the user edits the same event three times before the network
    /// comes back, we should push the final state once, not replay all three.
    Put {
        href: String,
        /// The `.ics` file inside the collection holding the payload.
        file: String,
        /// The etag we believe the server holds, for `If-Match`. `None` means
        /// the resource is new and the PUT must not overwrite anything.
        etag: Option<String>,
    },
    /// Remove the resource at `href`.
    ///
    /// Carries its own coordinates because the local file is already gone by
    /// the time this runs — there is nothing left on disk to look them up from.
    Delete { href: String, etag: Option<String> },
}

impl PushOp {
    #[must_use]
    pub fn href(&self) -> &str {
        match self {
            Self::Put { href, .. } | Self::Delete { href, .. } => href,
        }
    }
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
}

/// The queue operations a store must support for writeback to work.
///
/// Separate from [`crate::store::CalDavStore`] because the pull path has two
/// real implementations while this has one — but the backoff logic still needs
/// to be exercisable without a disk, which is what the in-memory impl in the
/// tests is for.
pub trait PushQueue {
    fn pending(&self) -> Vec<PendingPush>;

    /// Adds an operation, or resets an existing one for the same href to
    /// "due now".
    ///
    /// Resetting rather than appending is the important half: the newest edit
    /// is the one that should reach the server, and a queue that accumulated
    /// one entry per keystroke would replay a stale state on top of a fresh one.
    fn enqueue(&mut self, op: PushOp) -> Result<()>;

    /// Drops the entry for `href` — it succeeded.
    fn resolve(&mut self, href: &str) -> Result<()>;

    /// Records a failure and reschedules.
    fn defer(&mut self, href: &str, error: &str, next_attempt_ms: i64) -> Result<()>;

    /// The iCalendar text to PUT for a queued file, or `None` if it is gone.
    fn payload(&self, file: &str) -> Option<String>;

    /// The server told us this collection is read-only.
    fn read_only(&self) -> bool;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    pub succeeded: usize,
    pub deferred: usize,
    /// Entries dropped because the thing they referred to no longer exists.
    pub abandoned: usize,
    /// Entries not yet due under backoff.
    pub skipped: usize,
}

impl DrainOutcome {
    #[must_use]
    pub fn settled(&self) -> usize {
        self.succeeded + self.abandoned
    }
}

/// Attempts every due operation once.
///
/// `now_ms` is a parameter rather than read from the clock so the backoff
/// schedule is testable without sleeping.
pub fn drain(client: &CaldavClient, queue: &mut impl PushQueue, now_ms: i64) -> DrainOutcome {
    let mut outcome = DrainOutcome::default();

    if queue.read_only() {
        // Nothing here can ever succeed; the server will 403 every attempt.
        // Draining anyway would burn the backoff schedule and fill the log.
        let pending = queue.pending();
        if !pending.is_empty() {
            tracing::warn!(
                count = pending.len(),
                "queued writes for a collection the server made read-only; not attempting"
            );
        }
        outcome.skipped = pending.len();
        return outcome;
    }

    for entry in queue.pending() {
        if entry.next_attempt_ms > now_ms {
            outcome.skipped += 1;
            continue;
        }

        let href = entry.op.href().to_owned();
        let result = match &entry.op {
            PushOp::Put { href, file, etag } => match queue.payload(file) {
                Some(ics) => client.put_event(href, &ics, etag.as_deref()).map(|_| ()),
                None => {
                    // The file was deleted after the PUT was queued. There is
                    // nothing to send and never will be; a delete for the same
                    // href will have been queued separately.
                    tracing::info!(file, "queued PUT has no payload on disk; dropping it");
                    let _ = queue.resolve(href);
                    outcome.abandoned += 1;
                    continue;
                }
            },
            PushOp::Delete { href, etag } => client.delete_event(href, etag.as_deref()),
        };

        match result {
            Ok(()) => {
                if let Err(why) = queue.resolve(&href) {
                    tracing::warn!(href, %why, "push succeeded but the queue entry survived");
                }
                outcome.succeeded += 1;
            }
            Err(why) => {
                let attempts = entry.attempts.saturating_add(1);
                let next = now_ms.saturating_add(retry_delay_ms(attempts));
                tracing::warn!(href, attempts, %why, "push failed; will retry");
                if let Err(e) = queue.defer(&href, &why.to_string(), next) {
                    tracing::warn!(href, %e, "could not record a push failure");
                }
                outcome.deferred += 1;
            }
        }
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemoryQueue {
        entries: Vec<PendingPush>,
        files: HashMap<String, String>,
        read_only: bool,
    }

    impl PushQueue for MemoryQueue {
        fn pending(&self) -> Vec<PendingPush> {
            self.entries.clone()
        }
        fn enqueue(&mut self, op: PushOp) -> Result<()> {
            let href = op.href().to_owned();
            if let Some(existing) = self.entries.iter_mut().find(|e| e.op.href() == href) {
                existing.op = op;
                existing.next_attempt_ms = 0;
                existing.attempts = 0;
                existing.last_error = None;
            } else {
                self.entries.push(PendingPush {
                    op,
                    attempts: 0,
                    next_attempt_ms: 0,
                    last_error: None,
                });
            }
            Ok(())
        }
        fn resolve(&mut self, href: &str) -> Result<()> {
            self.entries.retain(|e| e.op.href() != href);
            Ok(())
        }
        fn defer(&mut self, href: &str, error: &str, next: i64) -> Result<()> {
            if let Some(e) = self.entries.iter_mut().find(|e| e.op.href() == href) {
                e.attempts += 1;
                e.next_attempt_ms = next;
                e.last_error = Some(error.to_owned());
            }
            Ok(())
        }
        fn payload(&self, file: &str) -> Option<String> {
            self.files.get(file).cloned()
        }
        fn read_only(&self) -> bool {
            self.read_only
        }
    }

    fn put(href: &str) -> PushOp {
        PushOp::Put {
            href: href.into(),
            file: "a.ics".into(),
            etag: Some("\"1\"".into()),
        }
    }

    #[test]
    fn backoff_doubles_from_thirty_seconds_to_an_hour_ceiling() {
        assert_eq!(retry_delay_ms(0), 30_000);
        assert_eq!(retry_delay_ms(1), 60_000);
        assert_eq!(retry_delay_ms(2), 120_000);
        assert_eq!(retry_delay_ms(20), MAX_DELAY_MS, "the ceiling did not hold");
    }

    #[test]
    fn backoff_never_overflows_however_many_attempts() {
        // A shift of 64+ would panic in debug and wrap in release; a queue
        // entry that has been failing for weeks must not be able to do that.
        for attempts in [12, 13, 63, 64, 1000, u32::MAX] {
            assert_eq!(retry_delay_ms(attempts), MAX_DELAY_MS);
        }
    }

    #[test]
    fn re_enqueueing_the_same_href_replaces_rather_than_appends() {
        let mut queue = MemoryQueue::default();
        queue.enqueue(put("/a.ics")).unwrap();
        queue.defer("/a.ics", "boom", 999_999).unwrap();
        queue.enqueue(put("/a.ics")).unwrap();

        let pending = queue.pending();
        assert_eq!(pending.len(), 1, "the queue accumulated duplicate entries");
        assert_eq!(pending[0].attempts, 0, "backoff was not reset by a new edit");
        assert_eq!(pending[0].next_attempt_ms, 0, "the new edit is not due now");
    }

    #[test]
    fn an_entry_that_is_not_due_yet_is_skipped_not_attempted() {
        let mut queue = MemoryQueue::default();
        queue.enqueue(put("/a.ics")).unwrap();
        queue.defer("/a.ics", "boom", 10_000).unwrap();

        // No client is reachable in a unit test, so a non-skipped entry would
        // be *attempted* and fail. `skipped` proves it was never tried.
        let client = CaldavClient::new("http://127.0.0.1:1/", "u", "p");
        let outcome = drain(&client, &mut queue, 5_000);

        assert_eq!(outcome.skipped, 1);
        assert_eq!(outcome.deferred, 0);
        assert_eq!(queue.pending()[0].attempts, 1, "an attempt was consumed");
    }

    #[test]
    fn a_read_only_collection_is_never_pushed_to() {
        let mut queue = MemoryQueue {
            read_only: true,
            ..Default::default()
        };
        queue.enqueue(put("/a.ics")).unwrap();

        let client = CaldavClient::new("http://127.0.0.1:1/", "u", "p");
        let outcome = drain(&client, &mut queue, 0);

        assert_eq!(outcome.succeeded, 0);
        assert_eq!(outcome.deferred, 0, "a doomed push consumed a retry slot");
        assert_eq!(outcome.skipped, 1);
        assert_eq!(
            queue.pending()[0].attempts,
            0,
            "backoff advanced on a collection that can never accept a write"
        );
    }

    #[test]
    fn a_queued_put_whose_file_vanished_is_abandoned_not_retried_forever() {
        let mut queue = MemoryQueue::default();
        queue.enqueue(put("/a.ics")).unwrap();
        // `files` is empty: the payload is gone.

        let client = CaldavClient::new("http://127.0.0.1:1/", "u", "p");
        let outcome = drain(&client, &mut queue, 0);

        assert_eq!(outcome.abandoned, 1);
        assert!(queue.pending().is_empty(), "an unsendable entry was kept");
    }

    #[test]
    fn a_failed_push_is_deferred_with_the_error_recorded() {
        let mut queue = MemoryQueue::default();
        queue.files.insert("a.ics".into(), "BEGIN:VCALENDAR".into());
        queue.enqueue(put("/a.ics")).unwrap();

        // Port 1 refuses instantly, so this exercises the failure path without
        // waiting for a timeout.
        let client = CaldavClient::new("http://127.0.0.1:1/", "u", "p");
        let outcome = drain(&client, &mut queue, 0);

        assert_eq!(outcome.deferred, 1);
        assert_eq!(outcome.succeeded, 0);

        let entry = &queue.pending()[0];
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.next_attempt_ms, retry_delay_ms(1));
        assert!(
            entry.last_error.is_some(),
            "the failure reason was not recorded for the UI"
        );
    }

    #[test]
    fn a_delete_needs_no_payload_on_disk() {
        let mut queue = MemoryQueue::default();
        queue
            .enqueue(PushOp::Delete {
                href: "/gone.ics".into(),
                etag: Some("\"1\"".into()),
            })
            .unwrap();

        let client = CaldavClient::new("http://127.0.0.1:1/", "u", "p");
        let outcome = drain(&client, &mut queue, 0);

        // It fails (nothing is listening) but it must be *attempted* rather
        // than abandoned for a missing file, which a delete never has.
        assert_eq!(outcome.abandoned, 0);
        assert_eq!(outcome.deferred, 1);
    }
}

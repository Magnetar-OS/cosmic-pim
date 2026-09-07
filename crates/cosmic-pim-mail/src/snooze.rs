// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Snooze: a message that comes back later.
//!
//! # What the engine owns, and what it does not
//!
//! A durable schedule and the arithmetic of "is this due yet". It moves
//! nothing: [`Schedule::due`] hands the caller [`Wake`] plans, the caller
//! applies them through the same writeback verbs every other change takes,
//! and [`Schedule::woke`] retires a record once the move actually happened.
//! Apply one in the order the plan implies — mark unread *first* (with
//! [`crate::push::Writeback::mark_unread`], which preserves the other flags),
//! then move — because a moved message has no UID left to address.
//! That split is what keeps snooze testable without a socket and identical
//! across IMAP, JMAP, Gmail and Graph.
//!
//! # Identity is the `Message-ID`, not a UID
//!
//! Snoozing moves the message out of the inbox, and a move renumbers it — the
//! UID it had is gone the moment the snooze takes effect. A UID-keyed
//! schedule would therefore wake nothing, or wake whatever message inherited
//! that number. `Message-ID` is the one identifier that survives a move,
//! survives a resync, and means the same thing on every device.
//!
//! A message with no `Message-ID` cannot be snoozed. That is a refusal rather
//! than a fallback: the alternatives all amount to guessing which message to
//! bring back, and bringing back the wrong one is worse than not offering the
//! button.
//!
//! # The wake time is an instant, decided when the user asks
//!
//! "Tomorrow morning" is resolved by the application against the user's
//! calendar and zone *at snooze time*, and what lands here is an absolute
//! epoch-millisecond instant. So a flight across three time zones does not
//! move a pending wake, and neither does a DST transition: the user asked for
//! a moment, and this stores that moment.
//!
//! # Overdue wakes fire; they never expire
//!
//! A laptop shut for a week wakes everything that came due while it slept,
//! oldest first. Dropping them as "too late" would silently swallow mail the
//! user deliberately deferred — the exact failure snoozing is supposed to
//! prevent. Each record fires once, because it is retired only when the
//! caller confirms the message actually moved back.
//!
//! # Storage
//!
//! One TOML file per account, `.snooze.toml` beside the maildirs —
//! dot-prefixed so a maildir walker never reads it as a mailbox, TOML so a
//! person can read (and cancel) a snooze without this application. The same
//! files-as-truth rule the rest of the suite lives by.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The filename, dot-prefixed for the same reason `.rules.toml` is.
const FILENAME: &str = ".snooze.toml";

/// One deferred message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snoozed {
    /// `Message-ID` with the angle brackets stripped — the identity that
    /// survives the move. See the module documentation.
    pub message_id: String,
    /// The mailbox the message came from, and returns to.
    pub origin: String,
    /// Where it waits meanwhile.
    ///
    /// A real server-side mailbox where one can be made, so the deferral is
    /// visible to every client the user owns and a phone does not keep
    /// showing the message they just dismissed. Where no such mailbox can be
    /// created, the application may name the origin here and hide the message
    /// locally instead — the schedule works the same either way, and only the
    /// [`Wake`] plan's `from` changes.
    pub holding: String,
    /// When it comes back: epoch milliseconds, UTC, absolute.
    pub wake_at_ms: i64,
    /// When the user asked, for a "snoozed 3 days ago" line.
    pub snoozed_at_ms: i64,
    /// The subject as it was, so a list of pending snoozes reads like
    /// something rather than like identifiers.
    #[serde(default)]
    pub subject: String,
}

impl Snoozed {
    /// Whether this record has come due at `now_ms`.
    #[must_use]
    pub fn is_due(&self, now_ms: i64) -> bool {
        self.wake_at_ms <= now_ms
    }
}

/// What the caller must do to bring one message back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wake {
    pub message_id: String,
    /// Where the message is now.
    pub from: String,
    /// Where it belongs again.
    pub to: String,
    /// Whether the restored message should be marked unread.
    ///
    /// Always true: a message that returns already-read returns invisible,
    /// which defeats the entire point of asking for it back. The field exists
    /// so the intent is stated at the call site rather than assumed.
    ///
    /// Honour it with [`crate::push::Writeback::mark_unread`] rather than a
    /// bare `store_flags`, and **before** applying the move: that helper
    /// reads the current flags first (so the user's star survives) and the
    /// move destroys the handle the write needs (`MOVE` never reports the
    /// destination UID).
    pub mark_unread: bool,
}

/// A message that stays where it is — the caller only clears the flag and the
/// record.
impl Wake {
    /// Whether the message actually has to move, or merely be un-hidden.
    #[must_use]
    pub fn is_move(&self) -> bool {
        self.from != self.to
    }
}

/// The snooze schedule for one account, and where it lives.
#[derive(Debug)]
pub struct Schedule {
    path: PathBuf,
    entries: Vec<Snoozed>,
}

/// What is on disk: `[[snoozed]]` blocks, one per deferred message.
#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default, rename = "snoozed")]
    entries: Vec<Snoozed>,
}

impl Schedule {
    /// Loads the account's schedule.
    ///
    /// No file is an empty schedule, not an error. A file that will not parse
    /// **is** an error: quietly treating a corrupt schedule as empty would
    /// bury every message the user deferred, with nothing anywhere to say so.
    pub fn open(account_root: impl AsRef<Path>) -> Result<Self> {
        let path = account_root.as_ref().join(FILENAME);
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str::<File>(&text)
                    .map_err(|why| Error::Draft(format!("{FILENAME} could not be read: {why}")))?
                    .entries
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, entries })
    }

    /// Every pending snooze, soonest first — what a "Snoozed" view lists.
    #[must_use]
    pub fn pending(&self) -> Vec<&Snoozed> {
        let mut out: Vec<&Snoozed> = self.entries.iter().collect();
        out.sort_by_key(|entry| entry.wake_at_ms);
        out
    }

    /// The record for one message, if it is snoozed.
    #[must_use]
    pub fn get(&self, message_id: &str) -> Option<&Snoozed> {
        self.entries.iter().find(|e| e.message_id == message_id)
    }

    /// Defers a message, or reschedules one already deferred.
    ///
    /// Re-snoozing replaces rather than appends: a message is in one place at
    /// a time, and two records for it would wake it twice — the second to a
    /// mailbox it already left. The original `origin` is **kept** when
    /// rescheduling, so a message snoozed from the inbox, woken into it, and
    /// snoozed again still comes home to the inbox.
    ///
    /// An empty `message_id` is refused; see the module documentation.
    pub fn snooze(&mut self, record: Snoozed) -> Result<()> {
        if record.message_id.trim().is_empty() {
            return Err(Error::Draft(
                "a message with no Message-ID cannot be snoozed: nothing would identify it \
                 when it came back"
                    .to_owned(),
            ));
        }

        match self
            .entries
            .iter_mut()
            .find(|e| e.message_id == record.message_id)
        {
            Some(existing) => {
                existing.wake_at_ms = record.wake_at_ms;
                existing.snoozed_at_ms = record.snoozed_at_ms;
                existing.holding = record.holding;
                if !record.subject.is_empty() {
                    existing.subject = record.subject;
                }
            }
            None => self.entries.push(record),
        }
        self.save()
    }

    /// Everything due at `now_ms`, oldest wake first, as plans to apply.
    ///
    /// Nothing is retired here — the caller applies each plan and calls
    /// [`Self::woke`] on the ones that landed. A wake that fails stays due and
    /// is returned again next cycle, which is the same durability rule the
    /// writeback queue follows and for the same reason: a deferral dropped
    /// without being honoured is mail the user never sees again.
    #[must_use]
    pub fn due(&self, now_ms: i64) -> Vec<Wake> {
        let mut ready: Vec<&Snoozed> = self.entries.iter().filter(|e| e.is_due(now_ms)).collect();
        ready.sort_by_key(|entry| entry.wake_at_ms);
        ready
            .into_iter()
            .map(|entry| Wake {
                message_id: entry.message_id.clone(),
                from: entry.holding.clone(),
                to: entry.origin.clone(),
                mark_unread: true,
            })
            .collect()
    }

    /// Retires a record: the message is back where it belongs.
    ///
    /// Returns whether anything was retired, so a caller can tell a completed
    /// wake from one that had already been handled by another process.
    pub fn woke(&mut self, message_id: &str) -> Result<bool> {
        let before = self.entries.len();
        self.entries.retain(|e| e.message_id != message_id);
        if self.entries.len() == before {
            return Ok(false);
        }
        self.save()?;
        Ok(true)
    }

    /// Cancels a snooze early — the user pulled the message back by hand.
    ///
    /// Identical bookkeeping to [`Self::woke`]; a separate name because the
    /// two mean different things at the call site, and a log that cannot tell
    /// them apart cannot explain why a message reappeared.
    pub fn cancel(&mut self, message_id: &str) -> Result<bool> {
        self.woke(message_id)
    }

    /// Writes the schedule back, atomically.
    fn save(&self) -> Result<()> {
        let file = File {
            entries: self.entries.clone(),
        };
        let text = toml::to_string_pretty(&file).map_err(|why| {
            Error::Draft(format!("the snooze schedule could not be written: {why}"))
        })?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        cosmic_pim_core::atomic::write(&self.path, &text, None)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const HOUR_MS: i64 = 3_600_000;

    fn schedule() -> (tempfile::TempDir, Schedule) {
        let dir = tempfile::tempdir().unwrap();
        let schedule = Schedule::open(dir.path()).unwrap();
        (dir, schedule)
    }

    fn record(message_id: &str, wake_at_ms: i64) -> Snoozed {
        Snoozed {
            message_id: message_id.to_owned(),
            origin: "INBOX".to_owned(),
            holding: "Snoozed".to_owned(),
            wake_at_ms,
            snoozed_at_ms: 0,
            subject: "Deferred".to_owned(),
        }
    }

    #[test]
    fn a_snooze_survives_a_reopen() {
        let (dir, mut schedule) = schedule();
        schedule.snooze(record("a@test", 10 * HOUR_MS)).unwrap();

        // Durability is the whole feature: a deferral that dies with the
        // process is a message the user never sees again.
        let reopened = Schedule::open(dir.path()).unwrap();
        assert_eq!(reopened.pending().len(), 1);
        assert_eq!(reopened.get("a@test").unwrap().origin, "INBOX");
    }

    #[test]
    fn nothing_is_due_before_its_time() {
        let (_dir, mut schedule) = schedule();
        schedule.snooze(record("a@test", 10 * HOUR_MS)).unwrap();
        assert!(schedule.due(9 * HOUR_MS).is_empty());
    }

    #[test]
    fn a_due_snooze_plans_the_move_home_and_marks_it_unread() {
        let (_dir, mut schedule) = schedule();
        schedule.snooze(record("a@test", 10 * HOUR_MS)).unwrap();

        let due = schedule.due(10 * HOUR_MS);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].from, "Snoozed");
        assert_eq!(due[0].to, "INBOX");
        assert!(due[0].is_move());
        assert!(
            due[0].mark_unread,
            "a message that returns already-read returns invisible"
        );
    }

    /// The machine was off for a week. Everything deferred meanwhile comes
    /// back — dropping the overdue ones would swallow exactly the mail the
    /// user chose to defer.
    #[test]
    fn overdue_wakes_fire_oldest_first_rather_than_expiring() {
        let (_dir, mut schedule) = schedule();
        schedule.snooze(record("late@test", 2 * HOUR_MS)).unwrap();
        schedule.snooze(record("later@test", 5 * HOUR_MS)).unwrap();
        schedule
            .snooze(record("future@test", 99 * HOUR_MS))
            .unwrap();

        let due = schedule.due(50 * HOUR_MS);
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].message_id, "late@test");
        assert_eq!(due[1].message_id, "later@test");
    }

    /// A wake that failed to apply must come back next cycle.
    #[test]
    fn a_wake_stays_due_until_it_is_confirmed() {
        let (_dir, mut schedule) = schedule();
        schedule.snooze(record("a@test", HOUR_MS)).unwrap();

        assert_eq!(schedule.due(2 * HOUR_MS).len(), 1);
        assert_eq!(
            schedule.due(2 * HOUR_MS).len(),
            1,
            "reading the due list retired a record the caller never applied"
        );

        assert!(schedule.woke("a@test").unwrap());
        assert!(schedule.due(2 * HOUR_MS).is_empty());
    }

    #[test]
    fn confirming_a_wake_that_is_already_gone_is_false_not_an_error() {
        let (_dir, mut schedule) = schedule();
        assert!(!schedule.woke("never-snoozed@test").unwrap());
    }

    #[test]
    fn re_snoozing_reschedules_rather_than_duplicating() {
        let (_dir, mut schedule) = schedule();
        schedule.snooze(record("a@test", HOUR_MS)).unwrap();
        schedule.snooze(record("a@test", 20 * HOUR_MS)).unwrap();

        assert_eq!(
            schedule.pending().len(),
            1,
            "two records for one message would wake it twice"
        );
        assert_eq!(schedule.get("a@test").unwrap().wake_at_ms, 20 * HOUR_MS);
        assert!(schedule.due(2 * HOUR_MS).is_empty());
    }

    /// Woken into the inbox, snoozed again from there: it must still come
    /// home to the inbox, not to wherever it happened to be held.
    #[test]
    fn rescheduling_keeps_the_original_origin() {
        let (_dir, mut schedule) = schedule();
        let mut first = record("a@test", HOUR_MS);
        first.origin = "Projects".to_owned();
        schedule.snooze(first).unwrap();

        let mut again = record("a@test", 20 * HOUR_MS);
        again.origin = "Snoozed".to_owned(); // the app read the current mailbox
        schedule.snooze(again).unwrap();

        assert_eq!(
            schedule.get("a@test").unwrap().origin,
            "Projects",
            "the message would have been sent back to the holding mailbox"
        );
    }

    #[test]
    fn a_message_with_no_id_is_refused_rather_than_guessed_at() {
        let (_dir, mut schedule) = schedule();
        let outcome = schedule.snooze(record("   ", HOUR_MS));
        assert!(outcome.is_err(), "a message with no identity was snoozed");
        assert!(schedule.pending().is_empty());
    }

    #[test]
    fn cancelling_removes_it_without_waiting() {
        let (_dir, mut schedule) = schedule();
        schedule.snooze(record("a@test", 99 * HOUR_MS)).unwrap();
        assert!(schedule.cancel("a@test").unwrap());
        assert!(schedule.pending().is_empty());
    }

    #[test]
    fn pending_is_sorted_by_when_each_comes_back() {
        let (_dir, mut schedule) = schedule();
        schedule.snooze(record("c@test", 30 * HOUR_MS)).unwrap();
        schedule.snooze(record("a@test", 10 * HOUR_MS)).unwrap();
        schedule.snooze(record("b@test", 20 * HOUR_MS)).unwrap();

        let ids: Vec<&str> = schedule
            .pending()
            .iter()
            .map(|e| e.message_id.as_str())
            .collect();
        assert_eq!(ids, ["a@test", "b@test", "c@test"]);
    }

    /// Where no snooze mailbox can be made, the app hides the message locally
    /// and names the origin as the holding place. The wake is then a flag
    /// change, not a move — and the plan says so rather than asking the
    /// caller to compare strings itself.
    #[test]
    fn a_locally_hidden_snooze_plans_no_move() {
        let (_dir, mut schedule) = schedule();
        let mut local = record("a@test", HOUR_MS);
        local.holding = "INBOX".to_owned();
        schedule.snooze(local).unwrap();

        let due = schedule.due(2 * HOUR_MS);
        assert!(!due[0].is_move());
        assert!(due[0].mark_unread);
    }

    #[test]
    fn a_corrupt_schedule_is_an_error_rather_than_a_silent_loss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILENAME), "{ not toml").unwrap();

        // Treating this as "no snoozes" would bury every deferred message
        // with nothing anywhere to say why they never came back.
        assert!(Schedule::open(dir.path()).is_err());
    }

    #[test]
    fn the_file_is_readable_toml_a_person_could_edit() {
        let (dir, mut schedule) = schedule();
        schedule.snooze(record("a@test", 10 * HOUR_MS)).unwrap();

        let raw = std::fs::read_to_string(dir.path().join(FILENAME)).unwrap();
        assert!(raw.contains("[[snoozed]]"), "{raw}");
        assert!(raw.contains("message_id = \"a@test\""), "{raw}");
    }
}

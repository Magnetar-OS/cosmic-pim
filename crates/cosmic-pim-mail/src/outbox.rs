// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Messages that have been sent but have not left yet.
//!
//! # What belongs here, and what must not
//!
//! Only sends the server **definitely did not accept**: a refused connection, a
//! TLS failure, an explicit 4xx. Those are safe to retry unchanged, and
//! retrying them is the whole point — mail written on a train should leave when
//! the train arrives, without anybody having to remember.
//!
//! An [`crate::smtp::Outcome::Ambiguous`] never enters the queue. A timeout in
//! the middle of `DATA` may mean the message is already in the recipient's
//! inbox, and a queue that retried it would send it twice with no way to take
//! either back. Those stay in the composer, in front of the person who can
//! decide. This is the one place in the crate where the usual "retry until it
//! works" posture is exactly wrong, and it is enforced by [`queue`] refusing
//! anything else.
//!
//! # Shape
//!
//! One JSON file per message, holding the [`Draft`] and its retry state, in a
//! directory beside the account's maildirs — the same arrangement, and for the
//! same reason, as [`crate::drafts`]. The draft carries its own attachments, so
//! a queued message is self-contained and survives a restart with the files it
//! was going to send.

use std::fs;
use std::path::{Path, PathBuf};

use cosmic_pim_core::atomic;

use crate::compose::Draft;
use crate::error::{Error, Result};
use crate::sasl::Credentials;
use crate::smtp::{self, Outcome, SmtpEndpoint};

/// Where queued messages live, beside the account's maildirs.
const DIRECTORY: &str = ".outbox";

const EXTENSION: &str = ".outgoing.json";

/// First retry delay, doubling to a ceiling.
///
/// Slower than the flag queue's fifteen seconds: a flag change is cheap to
/// retry and a message is not, and somebody offline is usually offline for
/// minutes rather than seconds.
const BASE_DELAY_MS: i64 = 60_000;
const MAX_DELAY_MS: i64 = 30 * 60_000;

/// How many times a message is retried before it stops on its own.
///
/// A cap, rather than retrying forever, because a send that has failed twelve
/// times over several hours is failing for a reason nobody is going to fix by
/// waiting — and a message silently retrying for a week is worse than one that
/// says it needs attention.
const MAX_ATTEMPTS: u32 = 12;

#[must_use]
pub fn retry_delay_ms(attempts: u32) -> i64 {
    let shift = attempts.min(12);
    BASE_DELAY_MS
        .saturating_mul(1_i64 << shift)
        .min(MAX_DELAY_MS)
}

/// One message waiting to go.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Queued {
    pub id: String,
    pub draft: Draft,
    #[serde(default)]
    pub attempts: u32,
    /// Epoch milliseconds before which this must not be retried.
    #[serde(default)]
    pub next_attempt_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Set when this stopped being retried. It keeps its payload and its place
    /// — it is a pending message, not a discarded one — but nothing will
    /// attempt it again until a person does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub given_up: bool,
}

impl Queued {
    #[must_use]
    pub fn is_live(&self) -> bool {
        !self.given_up
    }

    /// A one-line description for a list row.
    #[must_use]
    pub fn describe(&self) -> String {
        let to = self
            .draft
            .to
            .first()
            .map_or_else(String::new, |m| m.display().to_owned());
        if self.draft.subject.trim().is_empty() {
            to
        } else {
            format!("{} — {to}", self.draft.subject)
        }
    }
}

/// The outbox for one account.
#[derive(Debug)]
pub struct Outbox {
    root: PathBuf,
}

/// What one drain did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Sent. These are the bytes to file in Sent, in the order they went.
    pub sent: Vec<(String, Vec<u8>)>,
    /// Failed again, and rescheduled.
    pub deferred: usize,
    /// Stopped retrying — either it ran out of attempts, or the failure turned
    /// out to be one nothing automatic should touch.
    pub given_up: usize,
    /// Not due yet, or already stopped.
    pub skipped: usize,
}

impl DrainOutcome {
    /// Is there anything a person has to look at?
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.given_up > 0
    }
}

impl Outbox {
    pub fn open(account_root: impl AsRef<Path>) -> Result<Self> {
        let root = account_root.as_ref().join(DIRECTORY);
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Queues a message whose send definitely did not reach the server.
    ///
    /// `outcome` is taken rather than assumed so the invariant is checked
    /// rather than documented: an [`Outcome::Ambiguous`] is refused here, at
    /// the door, and cannot be queued by a caller that forgot.
    pub fn queue(&self, id: &str, draft: &Draft, outcome: &Outcome, now_ms: i64) -> Result<()> {
        match outcome {
            Outcome::NotSent(why) => self.write(&Queued {
                id: id.to_owned(),
                draft: draft.clone(),
                attempts: 1,
                next_attempt_ms: now_ms.saturating_add(retry_delay_ms(1)),
                last_error: Some(why.to_string()),
                given_up: false,
            }),
            Outcome::Sent(_) => Err(Error::Draft(
                "that message was sent; queueing it would send it twice".into(),
            )),
            Outcome::Ambiguous(_) => Err(Error::Draft(
                "that message may already have been delivered and must not be retried \
                 automatically"
                    .into(),
            )),
        }
    }

    /// Everything waiting, oldest first — the order they should go out in.
    pub fn list(&self) -> Result<Vec<Queued>> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Ok(Vec::new());
        };
        let mut queued: Vec<Queued> = entries
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(EXTENSION))
            })
            .filter_map(|entry| {
                let text = fs::read_to_string(entry.path()).ok()?;
                match serde_json::from_str::<Queued>(&text) {
                    Ok(queued) => Some(queued),
                    Err(why) => {
                        // Loud, not silent. A queued message that cannot be
                        // read is a message the user believes they sent.
                        tracing::error!(
                            path = %entry.path().display(),
                            %why,
                            "a queued message could not be read and will not be sent"
                        );
                        None
                    }
                }
            })
            .collect();
        queued.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(queued)
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.list().map(|queued| queued.len()).unwrap_or(0)
    }

    /// Drops one, because it went or because the user discarded it.
    pub fn remove(&self, id: &str) -> Result<()> {
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Queues a message to go out at a chosen time.
    ///
    /// Undo-send's grace delay and "send later" are both this entry with
    /// different clocks: the drain already refuses anything before its
    /// `next_attempt_ms`, so a scheduled send needs no second mechanism.
    ///
    /// Unlike [`Self::queue`] the draft has not failed anywhere, so it is
    /// checked *now*: a message that cannot build would otherwise fail at
    /// its send time, when nobody is looking at a composer any more.
    pub fn schedule(&self, id: &str, draft: &Draft, not_before_ms: i64) -> Result<()> {
        if let Some(problem) = draft.problem() {
            return Err(Error::Draft(problem.to_owned()));
        }
        self.write(&Queued {
            id: id.to_owned(),
            draft: draft.clone(),
            attempts: 0,
            next_attempt_ms: not_before_ms,
            last_error: None,
            given_up: false,
        })
    }

    /// Takes a queued message back, returning its draft — the undo for a
    /// send that has not gone yet.
    ///
    /// `None` means it already left (or never existed), and the caller must
    /// say so rather than reopen a composer for a message the recipients
    /// already have. The take is a rename, so a drain running concurrently
    /// cannot send what was cancelled or cancel what was sent: whichever
    /// claims the file first wins, and the other finds it gone.
    pub fn cancel(&self, id: &str) -> Result<Option<Draft>> {
        if !crate::drafts::is_valid_id(id) {
            return Ok(None);
        }
        let claimed = self.path(id).with_extension("cancelling");
        match fs::rename(self.path(id), &claimed) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let text = fs::read_to_string(&claimed)?;
        let _ = fs::remove_file(&claimed);
        let queued: Queued = serde_json::from_str(&text)
            .map_err(|why| Error::Draft(format!("the cancelled message could not be read: {why}")))?;
        Ok(Some(queued.draft))
    }

    /// Puts a given-up message back in the queue, due now.
    ///
    /// The explicit "try again" a stopped message needs — and the only way one
    /// resumes, because everything automatic has already concluded it will not.
    pub fn retry(&self, id: &str) -> Result<()> {
        let Some(mut queued) = self.read(id)? else {
            return Ok(());
        };
        queued.given_up = false;
        queued.attempts = 0;
        queued.next_attempt_ms = 0;
        self.write(&queued)
    }

    /// Attempts every message that is due, over SMTP.
    ///
    /// `now_ms` is a parameter rather than read from the clock so the backoff
    /// schedule is testable without sleeping.
    pub fn drain(
        &self,
        endpoint: &SmtpEndpoint,
        credentials: &Credentials,
        now_ms: i64,
    ) -> Result<DrainOutcome> {
        self.drain_with(|draft| smtp::send(endpoint, credentials, draft), now_ms)
    }

    /// As [`Self::drain`], with the submission step supplied by the caller.
    ///
    /// This is how the Gmail and Graph engines send: same queue, same backoff,
    /// same never-retry-an-ambiguous-send rule, different wire. The
    /// classification into [`Outcome`] is the submitter's job because only it
    /// knows where its protocol's point of no return is.
    pub fn drain_with(
        &self,
        mut send: impl FnMut(&crate::compose::Draft) -> Outcome,
        now_ms: i64,
    ) -> Result<DrainOutcome> {
        let mut outcome = DrainOutcome::default();

        for mut queued in self.list()? {
            if !queued.is_live() || queued.next_attempt_ms > now_ms {
                outcome.skipped += 1;
                continue;
            }
            // The listing is a snapshot; a cancel may have claimed the file
            // since. Checked immediately before the send, because sending a
            // message the user just took back is the unforgivable direction
            // of this race.
            if !self.path(&queued.id).exists() {
                outcome.skipped += 1;
                continue;
            }

            match send(&queued.draft) {
                Outcome::Sent(filed) => {
                    self.remove(&queued.id)?;
                    outcome.sent.push((queued.id, filed));
                }
                Outcome::NotSent(why) => {
                    queued.attempts = queued.attempts.saturating_add(1);
                    queued.last_error = Some(why.to_string());
                    if queued.attempts >= MAX_ATTEMPTS {
                        // Several hours of failing the same way. Waiting longer
                        // is not going to be what fixes it.
                        queued.given_up = true;
                        outcome.given_up += 1;
                    } else {
                        queued.next_attempt_ms =
                            now_ms.saturating_add(retry_delay_ms(queued.attempts));
                        outcome.deferred += 1;
                    }
                    self.write(&queued)?;
                }
                Outcome::Ambiguous(why) => {
                    // It may have been delivered. Nothing automatic touches it
                    // again — that is the invariant, and this is the one place
                    // a retry could have violated it.
                    tracing::warn!(
                        id = queued.id,
                        %why,
                        "a queued send may have been delivered; not retrying it"
                    );
                    queued.given_up = true;
                    queued.last_error = Some(why.to_string());
                    self.write(&queued)?;
                    outcome.given_up += 1;
                }
            }
        }

        Ok(outcome)
    }

    fn read(&self, id: &str) -> Result<Option<Queued>> {
        if !crate::drafts::is_valid_id(id) {
            return Ok(None);
        }
        let text = match fs::read_to_string(self.path(id)) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|why| Error::Draft(format!("queued message {id} is unreadable: {why}")))
    }

    fn write(&self, queued: &Queued) -> Result<()> {
        if !crate::drafts::is_valid_id(&queued.id) {
            return Err(Error::Draft(format!("{} is not an id", queued.id)));
        }
        let json =
            serde_json::to_string_pretty(queued).map_err(|why| Error::Draft(why.to_string()))?;
        atomic::write(&self.path(&queued.id), &json, None)?;
        Ok(())
    }

    fn path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}{EXTENSION}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    /// The credential every outbox test uses. The mechanism is irrelevant
    /// here — nothing in these tests reaches a server.
    fn password() -> Credentials {
        Credentials::Password("hunter2".into())
    }
    use super::*;
    use crate::model::Mailbox;

    fn draft(subject: &str) -> Draft {
        let mut draft = Draft::new(Mailbox {
            name: Some("Me".into()),
            address: "me@example.com".into(),
        });
        draft.to.push(Mailbox {
            name: Some("Ada".into()),
            address: "ada@example.com".into(),
        });
        draft.subject = subject.into();
        draft.body = "Written on a train.".into();
        draft
    }

    fn outbox() -> (tempfile::TempDir, Outbox) {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        (dir, outbox)
    }

    fn refused() -> Outcome {
        Outcome::NotSent(Error::Smtp("connection refused".into()))
    }

    /// An endpoint nothing is listening on, so a drain fails without waiting.
    fn unreachable() -> SmtpEndpoint {
        SmtpEndpoint {
            host: "127.0.0.1".into(),
            port: 1,
            security: crate::imap::Security::Plaintext,
            username: "me@example.com".into(),
        }
    }

    #[test]
    fn a_send_that_never_reached_the_server_is_queued_and_survives_a_restart() {
        // The whole point: mail written offline should leave when the network
        // comes back, without anybody remembering to press anything.
        let dir = tempfile::tempdir().unwrap();
        {
            let outbox = Outbox::open(dir.path()).unwrap();
            outbox
                .queue("00000001", &draft("On a train"), &refused(), 0)
                .unwrap();
        }
        let outbox = Outbox::open(dir.path()).unwrap();
        let queued = outbox.list().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].draft.subject, "On a train");
        assert_eq!(queued[0].attempts, 1);
        assert!(queued[0].last_error.is_some());
        assert!(queued[0].is_live());
    }

    #[test]
    fn a_message_that_may_have_been_delivered_is_refused_at_the_door() {
        // The invariant, enforced rather than documented: a queue that retried
        // this would send it twice, with no way to take either back.
        let (_dir, outbox) = outbox();
        let ambiguous = Outcome::Ambiguous(Error::Smtp("timed out".into()));
        let refused_error = outbox
            .queue("00000001", &draft("Risky"), &ambiguous, 0)
            .expect_err("an ambiguous send must not be queueable");
        assert!(
            refused_error
                .to_string()
                .contains("may already have been delivered")
        );
        assert!(outbox.list().unwrap().is_empty());
    }

    #[test]
    fn a_message_that_was_sent_is_refused_too() {
        let (_dir, outbox) = outbox();
        assert!(
            outbox
                .queue("00000001", &draft("Gone"), &Outcome::Sent(Vec::new()), 0)
                .is_err()
        );
    }

    #[test]
    fn an_entry_that_is_not_due_yet_is_skipped_rather_than_attempted() {
        let (_dir, outbox) = outbox();
        outbox
            .queue("00000001", &draft("Later"), &refused(), 0)
            .unwrap();

        let outcome = outbox.drain(&unreachable(), &password(), 1_000).unwrap();
        assert_eq!(outcome.skipped, 1);
        assert_eq!(outcome.deferred, 0);
        assert_eq!(
            outbox.list().unwrap()[0].attempts,
            1,
            "an attempt was consumed by an entry that was not due"
        );
    }

    #[test]
    fn a_failing_drain_backs_off_and_keeps_the_message() {
        let (_dir, outbox) = outbox();
        outbox
            .queue("00000001", &draft("Still offline"), &refused(), 0)
            .unwrap();

        let outcome = outbox
            .drain(&unreachable(), &password(), MAX_DELAY_MS + 1)
            .unwrap();
        assert_eq!(outcome.deferred, 1);
        assert!(outcome.sent.is_empty());
        assert!(!outcome.needs_attention());

        let queued = &outbox.list().unwrap()[0];
        assert_eq!(queued.attempts, 2);
        assert!(queued.is_live());
        assert_eq!(
            queued.draft.subject, "Still offline",
            "the message was lost"
        );
    }

    #[test]
    fn a_message_that_keeps_failing_stops_rather_than_retrying_for_a_week() {
        let (_dir, outbox) = outbox();
        outbox
            .queue("00000001", &draft("Doomed"), &refused(), 0)
            .unwrap();

        // The clock has to move past each backoff, or every drain after the
        // first is correctly skipped as not-yet-due.
        let mut now = 0_i64;
        for _ in 0..MAX_ATTEMPTS {
            now += MAX_DELAY_MS + 1;
            outbox.drain(&unreachable(), &password(), now).unwrap();
        }

        let queued = &outbox.list().unwrap()[0];
        assert!(
            queued.given_up,
            "it is still retrying after {MAX_ATTEMPTS} attempts"
        );
        assert!(
            !queued.draft.subject.is_empty(),
            "giving up must not discard the message"
        );
    }

    #[test]
    fn a_stopped_message_is_not_attempted_again_until_someone_says_so() {
        let (_dir, outbox) = outbox();
        outbox
            .queue("00000001", &draft("Stopped"), &refused(), 0)
            .unwrap();
        let mut now = 0_i64;
        for _ in 0..MAX_ATTEMPTS {
            now += MAX_DELAY_MS + 1;
            outbox.drain(&unreachable(), &password(), now).unwrap();
        }

        let outcome = outbox
            .drain(&unreachable(), &password(), now + MAX_DELAY_MS)
            .unwrap();
        assert_eq!(outcome.skipped, 1);
        assert_eq!(outcome.deferred, 0);

        outbox.retry("00000001").unwrap();
        let queued = &outbox.list().unwrap()[0];
        assert!(queued.is_live());
        assert_eq!(queued.attempts, 0);
        assert_eq!(queued.next_attempt_ms, 0, "it is not due now");
    }

    #[test]
    fn messages_go_out_in_the_order_they_were_written() {
        let (_dir, outbox) = outbox();
        for (id, subject) in [
            ("00000003", "third"),
            ("00000001", "first"),
            ("00000002", "second"),
        ] {
            outbox.queue(id, &draft(subject), &refused(), 0).unwrap();
        }
        let subjects: Vec<String> = outbox
            .list()
            .unwrap()
            .into_iter()
            .map(|queued| queued.draft.subject)
            .collect();
        assert_eq!(subjects, ["first", "second", "third"]);
    }

    #[test]
    fn backoff_doubles_from_a_minute_to_a_half_hour_ceiling() {
        assert_eq!(retry_delay_ms(0), 60_000);
        assert_eq!(retry_delay_ms(1), 120_000);
        assert_eq!(retry_delay_ms(20), MAX_DELAY_MS);
        for attempts in [12, 63, 64, u32::MAX] {
            assert_eq!(retry_delay_ms(attempts), MAX_DELAY_MS);
        }
    }

    #[test]
    fn a_scheduled_send_waits_for_its_time_and_then_goes() {
        let (_dir, outbox) = outbox();
        outbox
            .schedule("0000000000000001", &draft("later"), 10_000)
            .unwrap();

        // Before the deadline: nothing is sent, nothing is attempted.
        let early = outbox
            .drain_with(|_| panic!("a not-yet-due message was submitted"), 9_999)
            .unwrap();
        assert_eq!(early.skipped, 1);

        let due = outbox
            .drain_with(|_| Outcome::Sent(b"bytes".to_vec()), 10_000)
            .unwrap();
        assert_eq!(due.sent.len(), 1);
        assert_eq!(outbox.count(), 0);
    }

    #[test]
    fn a_draft_that_cannot_be_sent_is_refused_at_scheduling_time() {
        // The alternative is failing at the send time, when nobody is looking
        // at a composer any more.
        let (_dir, outbox) = outbox();
        let unfinished = Draft::new(Mailbox {
            name: None,
            address: "me@example.com".into(),
        });
        assert!(outbox.schedule("0000000000000002", &unfinished, 0).is_err());
        assert_eq!(outbox.count(), 0);
    }

    #[test]
    fn cancelling_hands_the_draft_back_exactly_once() {
        let (_dir, outbox) = outbox();
        outbox
            .schedule("0000000000000003", &draft("regretted"), i64::MAX)
            .unwrap();

        let taken = outbox.cancel("0000000000000003").unwrap();
        assert_eq!(taken.expect("the draft came back").subject, "regretted");
        assert_eq!(outbox.count(), 0);

        assert!(
            outbox.cancel("0000000000000003").unwrap().is_none(),
            "a second cancel resurrected the message"
        );
    }

    #[test]
    fn a_queued_message_keeps_its_attachments() {
        // The reason a draft holds bytes rather than a path: the file may be
        // long gone by the time the network comes back.
        let (_dir, outbox) = outbox();
        let mut draft = draft("With a file");
        draft.attachments.push(crate::compose::Attachment {
            name: "report.csv".into(),
            mime_type: "text/csv".into(),
            bytes: b"a,b\n1,2\n".to_vec(),
        });
        outbox.queue("00000001", &draft, &refused(), 0).unwrap();

        let queued = &outbox.list().unwrap()[0];
        assert_eq!(queued.draft.attachments[0].bytes, b"a,b\n1,2\n");
    }

    #[test]
    fn removing_a_message_that_is_already_gone_is_not_an_error() {
        let (_dir, outbox) = outbox();
        outbox
            .queue("00000001", &draft("x"), &refused(), 0)
            .unwrap();
        outbox.remove("00000001").unwrap();
        outbox.remove("00000001").unwrap();
        assert_eq!(outbox.count(), 0);
    }

    #[test]
    fn an_id_that_could_escape_the_directory_is_refused() {
        let (_dir, outbox) = outbox();
        assert!(
            outbox
                .queue("../../evil", &draft("x"), &refused(), 0)
                .is_err()
        );
        assert_eq!(outbox.count(), 0);
    }
}

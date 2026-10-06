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
//! works" posture is exactly wrong, and it is enforced by [`Outbox::queue`] refusing
//! anything else.
//!
//! # Why a message stopped
//!
//! A message that is not going anywhere on its own says why, in a type
//! ([`SendFailure`]) rather than a sentence to be parsed, because the three
//! reasons need three different things said to the person who wrote it:
//!
//! - the server **refused** it — nothing was delivered, and it will be refused
//!   again until something is changed;
//! - the outcome is **uncertain** — it may be in the recipients' inboxes, so
//!   the thing to do before sending it again is to look;
//! - it **could not be reached** — nothing is wrong with the message.
//!
//! # What a reply answers
//!
//! A queued reply carries the message it answers ([`Answers`]), and a drain
//! hands it back with the entry it reports sent ([`Sent`]). Marking the
//! original `\Answered` is the caller's — the outbox does not own a mailbox —
//! but the record that it is owed travels with the message, so it cannot be
//! lost between a send queued today and a drain that runs tomorrow.
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
use crate::store::MailboxState;

/// Where queued messages live, beside the account's maildirs.
const DIRECTORY: &str = ".outbox";

const EXTENSION: &str = ".outgoing.json";

/// A message a drain has claimed and is sending. The claim is a rename, so a
/// message is in exactly one of the two states on disk, and the drain holds an
/// advisory lock on the claimed file for as long as it talks to the server —
/// a claim nobody holds is one whose drain died mid-send.
const CLAIMED: &str = ".sending.json";

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
pub const MAX_ATTEMPTS: u32 = 12;

#[must_use]
pub fn retry_delay_ms(attempts: u32) -> i64 {
    let shift = attempts.min(12);
    BASE_DELAY_MS
        .saturating_mul(1_i64 << shift)
        .min(MAX_DELAY_MS)
}

/// How the last attempt to send a queued message ended, when it did not go.
///
/// Kept on the record, so it is still there after a restart, and typed, so
/// an application words each case itself instead of reading a sentence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SendFailure {
    /// The server could not be reached, or asked to be tried later. Nothing
    /// was delivered and nothing is wrong with the message; it is retried on
    /// the backoff schedule until [`MAX_ATTEMPTS`].
    Transient {
        /// What went wrong, in the transport's words.
        reason: String,
    },
    /// The server refused the message and would refuse it again: a login it
    /// will not take, a recipient it rejects, a policy. Nothing was
    /// delivered. Permanent — never retried automatically.
    Refused {
        /// The server's own reply.
        reason: String,
    },
    /// The draft cannot be turned into a message at all — no recipient, an
    /// address that is not one. Nothing was sent, and nothing will be until
    /// the draft is changed.
    Unsendable {
        /// What is wrong with the draft.
        reason: String,
    },
    /// The outcome is not known: the connection broke after the message was
    /// handed over, or the reply could not be read. **It may have been
    /// delivered.** Never retried automatically.
    Uncertain {
        /// What was seen before the outcome was lost.
        reason: String,
    },
    /// The drain that was sending it died before it could record what
    /// happened. **It may have been delivered.** Never retried automatically.
    Interrupted,
}

impl SendFailure {
    /// Reads a send's outcome as a failure. `None` for one that was sent.
    #[must_use]
    pub fn of(outcome: &Outcome) -> Option<Self> {
        match outcome {
            Outcome::Sent(_) => None,
            Outcome::NotSent(why) => Some(Self::transient(why)),
            Outcome::Rejected(why) => Some(Self::refusal(why)),
            Outcome::Ambiguous(why) => Some(Self::uncertain(why)),
        }
    }

    fn transient(why: &Error) -> Self {
        Self::Transient {
            reason: why.to_string(),
        }
    }

    /// A refusal is the server's unless it is the draft's own: a message
    /// that cannot be built never reached a server to be refused by.
    fn refusal(why: &Error) -> Self {
        match why {
            Error::Draft(reason) => Self::Unsendable {
                reason: reason.clone(),
            },
            other => Self::Refused {
                reason: other.to_string(),
            },
        }
    }

    fn uncertain(why: &Error) -> Self {
        Self::Uncertain {
            reason: why.to_string(),
        }
    }

    /// Whether the message may be in the recipients' inboxes already. The
    /// one question to settle before anybody sends it again.
    #[must_use]
    pub fn may_have_been_delivered(&self) -> bool {
        matches!(self, Self::Uncertain { .. } | Self::Interrupted)
    }

    /// Whether trying again unchanged could work.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }

    /// The words that came with the failure, where there were any.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Transient { reason }
            | Self::Refused { reason }
            | Self::Unsendable { reason }
            | Self::Uncertain { reason } => Some(reason),
            Self::Interrupted => None,
        }
    }
}

/// The message a queued reply answers.
///
/// Two references, because each fails where the other holds:
///
/// - [`Self::message_id`] is the stable one. It survives a renumbering, a
///   move to another folder and a mailbox rebuilt from nothing, and
///   [`crate::Index::locate`] turns it back into a place. A message with no
///   `Message-ID` header has none.
/// - [`Self::origin`] is where the message was when the reply was written.
///   It is exact and costs nothing to use, for as long as
///   [`Origin::still_names`] says the numbering it was taken under stands.
///
/// To set `\Answered` once the reply has gone: use the origin while it still
/// names the message, and otherwise find the message by its id.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct Answers {
    /// The answered message's `Message-ID`, without angle brackets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Where the answered message was when the reply was queued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
}

impl Answers {
    /// A reply to the message with this `Message-ID` (brackets and
    /// surrounding space are dropped; an empty id is no id).
    #[must_use]
    pub fn to_message(message_id: &str) -> Self {
        let id = message_id
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim();
        Self {
            message_id: (!id.is_empty()).then(|| id.to_owned()),
            origin: None,
        }
    }

    /// A reply to the message at `origin`, for one that has no `Message-ID`.
    #[must_use]
    pub fn at(origin: Origin) -> Self {
        Self {
            message_id: None,
            origin: Some(origin),
        }
    }

    /// Adds where the message was found.
    #[must_use]
    pub fn found_at(mut self, origin: Origin) -> Self {
        self.origin = Some(origin);
        self
    }
}

/// A message's place in a mailbox, pinned to the numbering it was read under.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Origin {
    /// The mailbox's name on the wire.
    pub mailbox: String,
    /// The server's hierarchy delimiter for it, which a maildir path needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<char>,
    pub uid: u32,
    /// A UID means nothing under another UIDVALIDITY: after a renumbering it
    /// names a different message or none, and marking it would mark a
    /// stranger's mail answered.
    pub uid_validity: u32,
}

impl Origin {
    /// Whether this still names the message it named when it was taken:
    /// `mailbox` has not been renumbered since, and still holds the UID.
    ///
    /// `mailbox` is the current state of the mailbox [`Self::mailbox`] names.
    /// When this is false the message has to be found again by its id.
    #[must_use]
    pub fn still_names(&self, mailbox: &MailboxState) -> bool {
        mailbox.cursor.uid_validity == self.uid_validity && mailbox.entries.contains_key(&self.uid)
    }
}

/// One message waiting to go.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(from = "Stored")]
#[non_exhaustive]
pub struct Queued {
    pub id: String,
    pub draft: Draft,
    #[serde(default)]
    pub attempts: u32,
    /// Epoch milliseconds before which this must not be retried.
    #[serde(default)]
    pub next_attempt_ms: i64,
    /// How the last attempt ended, when it did not send the message. `None`
    /// for a message nothing has tried yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<SendFailure>,
    /// Set when this stopped being retried. It keeps its payload and its place
    /// — it is a pending message, not a discarded one — but nothing will
    /// attempt it again until a person does. [`Self::failure`] says why: a
    /// [`SendFailure::Transient`] here is one that ran out of attempts.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub given_up: bool,
    /// The message this one answers, when it is a reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answers: Option<Answers>,
    /// A drain has claimed this message and is talking to the server right
    /// now. It can be neither taken back nor discarded until that ends. Read
    /// from where the file is, never stored.
    #[serde(skip)]
    pub sending: bool,
}

/// A record as it is on disk, including the ones 2.x wrote.
///
/// Before 3.0 a record said why it had stopped in a sentence (`last_error`)
/// and nothing else. Such a record is read as what can be known from it: one
/// still being retried failed transiently, by construction; one that had
/// stopped may have been refused, or may have been delivered, and the record
/// cannot say which — so it is read as [`SendFailure::Uncertain`], the one
/// that tells its author to look before sending again.
#[derive(serde::Deserialize)]
struct Stored {
    id: String,
    draft: Draft,
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    next_attempt_ms: i64,
    #[serde(default)]
    failure: Option<SendFailure>,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    given_up: bool,
    #[serde(default)]
    answers: Option<Answers>,
}

impl From<Stored> for Queued {
    fn from(stored: Stored) -> Self {
        let failure = stored.failure.or_else(|| {
            stored.last_error.map(|reason| {
                if stored.given_up {
                    SendFailure::Uncertain { reason }
                } else {
                    SendFailure::Transient { reason }
                }
            })
        });
        Self {
            id: stored.id,
            draft: stored.draft,
            attempts: stored.attempts,
            next_attempt_ms: stored.next_attempt_ms,
            failure,
            given_up: stored.given_up,
            answers: stored.answers,
            sending: false,
        }
    }
}

impl Queued {
    #[must_use]
    pub fn is_live(&self) -> bool {
        !self.given_up
    }

    /// Whether this stopped with its outcome unknown, so that it may already
    /// be in the recipients' inboxes.
    #[must_use]
    pub fn may_have_been_delivered(&self) -> bool {
        self.given_up
            && self
                .failure
                .as_ref()
                .is_some_and(SendFailure::may_have_been_delivered)
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

/// One message a drain sent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Sent {
    /// Its id in the outbox.
    pub id: String,
    /// The `Message-ID` it went out under, without angle brackets.
    pub message_id: Option<String>,
    /// The message it answers, as it was queued with.
    pub answers: Option<Answers>,
    /// The bytes that were sent, with the `Bcc` header restored — what to
    /// file in Sent.
    pub bytes: Vec<u8>,
}

/// One message a drain stopped retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stopped {
    /// Its id in the outbox, where it still is.
    pub id: String,
    /// Why. A [`SendFailure::Transient`] here ran out of attempts.
    pub failure: SendFailure,
}

/// What one drain did.
///
/// Always returned whole. A drain that hits a local failure part-way — a
/// record it cannot rewrite, a full disk — stops there and says so in
/// [`Self::error`], and everything it had already done is still in the other
/// fields: a caller cannot lose the list of what was sent by propagating the
/// error, because the error is not in its way.
#[derive(Debug, Default)]
#[must_use = "a drain's outcome says what was sent and whether it stopped early"]
#[non_exhaustive]
pub struct DrainOutcome {
    /// Sent, in the order they went.
    pub sent: Vec<Sent>,
    /// Failed again, and rescheduled.
    pub deferred: usize,
    /// Stopped retrying — it ran out of attempts, or the failure was one
    /// nothing automatic should touch. Each says which.
    pub stopped: Vec<Stopped>,
    /// Not due yet, or already stopped.
    pub skipped: usize,
    /// The local failure that ended the drain early, if one did. What is due
    /// and was not reached stays queued for the next drain. A message whose
    /// record could not be settled after its send is recovered by that drain
    /// as [`SendFailure::Interrupted`] and is never sent twice.
    pub error: Option<Error>,
}

impl DrainOutcome {
    /// Is there anything a person has to look at?
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        !self.stopped.is_empty()
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
    ///
    /// `answers` is the message this one replies to, if it is a reply; it
    /// comes back with the entry when a drain reports it sent.
    pub fn queue(
        &self,
        id: &str,
        draft: &Draft,
        answers: Option<Answers>,
        outcome: &Outcome,
        now_ms: i64,
    ) -> Result<()> {
        match outcome {
            Outcome::NotSent(why) => self.write(&Queued {
                id: id.to_owned(),
                draft: with_message_id(draft, id),
                attempts: 1,
                next_attempt_ms: now_ms.saturating_add(retry_delay_ms(1)),
                failure: Some(SendFailure::Transient {
                    reason: why.to_string(),
                }),
                given_up: false,
                answers,
                sending: false,
            }),
            Outcome::Sent(_) => Err(Error::Draft(
                "that message was sent; queueing it would send it twice".into(),
            )),
            Outcome::Rejected(why) => Err(Error::Draft(format!(
                "that message was refused and would be refused again: {why}"
            ))),
            Outcome::Ambiguous(_) => Err(Error::Draft(
                "that message may already have been delivered and must not be retried \
                 automatically"
                    .into(),
            )),
        }
    }

    /// Queues a message that has never been attempted, due immediately.
    ///
    /// This is the entry for sends that start life in the queue — a
    /// scheduling reply handed over D-Bus, anything programmatic — where no
    /// [`Outcome`] exists because nothing has touched the wire yet. The next
    /// drain makes the first attempt; from there the message is
    /// indistinguishable from one that failed once and was queued by
    /// [`Self::queue`].
    pub fn submit(
        &self,
        id: &str,
        draft: &Draft,
        answers: Option<Answers>,
        now_ms: i64,
    ) -> Result<()> {
        self.write(&Queued {
            id: id.to_owned(),
            draft: with_message_id(draft, id),
            attempts: 0,
            next_attempt_ms: now_ms,
            failure: None,
            given_up: false,
            answers,
            sending: false,
        })
    }

    /// Everything waiting, oldest first — the order they should go out in.
    ///
    /// Includes messages a drain is sending right now, marked
    /// [`Queued::sending`]: they have not left yet, and a list that dropped
    /// them for the length of an SMTP conversation would tell the person
    /// their message had gone.
    pub fn list(&self) -> Result<Vec<Queued>> {
        let mut queued = self.entries(EXTENSION);
        queued.extend(self.entries(CLAIMED).into_iter().map(|mut entry| {
            entry.sending = true;
            entry
        }));
        queued.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(queued)
    }

    /// The readable records whose file name ends in `suffix`.
    fn entries(&self, suffix: &str) -> Vec<Queued> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(suffix))
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
            .collect()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.list().map(|queued| queued.len()).unwrap_or(0)
    }

    /// Drops one, because it went or because the user discarded it.
    ///
    /// Refused while a drain is sending it: discarding a message that may be
    /// arriving in the recipients' inboxes would only hide that it went.
    pub fn remove(&self, id: &str) -> Result<()> {
        if self.claim_path(id).exists() {
            return Err(Error::Draft(
                "that message is being sent right now and cannot be discarded".into(),
            ));
        }
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
    pub fn schedule(
        &self,
        id: &str,
        draft: &Draft,
        answers: Option<Answers>,
        not_before_ms: i64,
    ) -> Result<()> {
        if let Some(problem) = draft.problem() {
            return Err(Error::Draft(problem.to_owned()));
        }
        self.write(&Queued {
            id: id.to_owned(),
            draft: with_message_id(draft, id),
            attempts: 0,
            next_attempt_ms: not_before_ms,
            failure: None,
            given_up: false,
            answers,
            sending: false,
        })
    }

    /// Takes a queued message back, returning its record — the undo for a
    /// send that has not gone yet.
    ///
    /// The whole record, not the draft alone: what it answers comes back with
    /// it, so a reply reopened in a composer is still a reply, and so does
    /// why it had stopped, if it had.
    ///
    /// `None` means it already left, is being sent right now, or never
    /// existed, and the caller must say so rather than reopen a composer for a
    /// message the recipients have or are about to have. The take is a rename,
    /// and so is the drain's claim before it sends, so the two cannot both
    /// win: whichever renames the file first has it, and the other finds it
    /// gone.
    pub fn cancel(&self, id: &str) -> Result<Option<Queued>> {
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
        let queued: Queued = serde_json::from_str(&text).map_err(|why| {
            Error::Draft(format!("the cancelled message could not be read: {why}"))
        })?;
        Ok(Some(queued))
    }

    /// Puts a given-up message back in the queue, due now.
    ///
    /// The explicit "try again" a stopped message needs — and the only way one
    /// resumes, because everything automatic has already concluded it will not.
    /// It starts over: the record of why it stopped is cleared with the count
    /// of attempts, since the next drain's outcome is the one that matters.
    pub fn retry(&self, id: &str) -> Result<()> {
        let Some(mut queued) = self.read(id)? else {
            return Ok(());
        };
        queued.given_up = false;
        queued.attempts = 0;
        queued.next_attempt_ms = 0;
        queued.failure = None;
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
    ) -> DrainOutcome {
        self.drain_with(|draft| smtp::send(endpoint, credentials, draft), now_ms)
    }

    /// As [`Self::drain`], with the submission step supplied by the caller.
    ///
    /// This is how the Gmail and Graph engines send: same queue, same backoff,
    /// same never-retry-an-ambiguous-send rule, different wire. The
    /// classification into [`Outcome`] is the submitter's job because only it
    /// knows where its protocol's point of no return is.
    ///
    /// Not a `Result`: see [`DrainOutcome`]. A local failure is reported in
    /// [`DrainOutcome::error`], beside what the drain did before it.
    pub fn drain_with(
        &self,
        mut send: impl FnMut(&crate::compose::Draft) -> Outcome,
        now_ms: i64,
    ) -> DrainOutcome {
        let mut outcome = DrainOutcome::default();
        if let Err(why) = self.drain_into(&mut outcome, &mut send, now_ms) {
            outcome.error = Some(why);
        }
        outcome
    }

    /// The drain itself. Everything that happened is in `outcome` before any
    /// step that can fail after it, so an early return loses nothing.
    fn drain_into(
        &self,
        outcome: &mut DrainOutcome,
        send: &mut impl FnMut(&crate::compose::Draft) -> Outcome,
        now_ms: i64,
    ) -> Result<()> {
        self.recover_interrupted(outcome)?;

        // Oldest first, as `list` shows them: ids sort by when they were
        // made, and a directory is listed in whatever order it likes.
        let mut waiting = self.entries(EXTENSION);
        waiting.sort_by(|a, b| a.id.cmp(&b.id));

        for listed in waiting {
            if !listed.is_live() || listed.next_attempt_ms > now_ms {
                outcome.skipped += 1;
                continue;
            }
            // Claim before sending. The listing is a snapshot: an Undo may
            // have taken the message since, and sending a message the user
            // just took back is the unforgivable direction of this race.
            let Some((mut queued, claim)) = self.claim(&listed.id)? else {
                outcome.skipped += 1;
                continue;
            };
            if !queued.is_live() || queued.next_attempt_ms > now_ms {
                // Changed between the listing and the claim.
                self.release(&queued, &claim.path)?;
                outcome.skipped += 1;
                continue;
            }

            match send(&queued.draft) {
                Outcome::Sent(bytes) => {
                    // Recorded before the claim is removed: if the removal
                    // fails, the message has still gone and the caller still
                    // has to hear that it did.
                    outcome.sent.push(Sent {
                        id: queued.id,
                        message_id: queued.draft.message_id,
                        answers: queued.answers,
                        bytes,
                    });
                    remove_if_present(&claim.path)?;
                }
                Outcome::NotSent(why) => {
                    let failure = SendFailure::transient(&why);
                    queued.attempts = queued.attempts.saturating_add(1);
                    queued.failure = Some(failure.clone());
                    // Several hours of failing the same way. Waiting longer
                    // is not going to be what fixes it.
                    queued.given_up = queued.attempts >= MAX_ATTEMPTS;
                    if !queued.given_up {
                        queued.next_attempt_ms =
                            now_ms.saturating_add(retry_delay_ms(queued.attempts));
                    }
                    self.release(&queued, &claim.path)?;
                    if queued.given_up {
                        outcome.stopped.push(Stopped {
                            id: queued.id,
                            failure,
                        });
                    } else {
                        outcome.deferred += 1;
                    }
                }
                Outcome::Rejected(why) => {
                    // Refused outright — a login the server will not take, a
                    // recipient it will not accept, a draft that cannot be
                    // built. Twelve more attempts over five hours would be
                    // refused identically; the message waits for a person.
                    self.stop(queued, SendFailure::refusal(&why), &claim.path, outcome)?;
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
                    self.stop(queued, SendFailure::uncertain(&why), &claim.path, outcome)?;
                }
            }
            drop(claim);
        }

        Ok(())
    }

    /// Records that a claimed message will not be retried, and why.
    fn stop(
        &self,
        mut queued: Queued,
        failure: SendFailure,
        claim: &Path,
        outcome: &mut DrainOutcome,
    ) -> Result<()> {
        queued.given_up = true;
        queued.failure = Some(failure.clone());
        self.release(&queued, claim)?;
        outcome.stopped.push(Stopped {
            id: queued.id,
            failure,
        });
        Ok(())
    }

    /// Takes a message for sending: renames it to its claimed name and locks
    /// the claimed file. `None` when it is no longer waiting.
    fn claim(&self, id: &str) -> Result<Option<(Queued, Claim)>> {
        let path = self.claim_path(id);
        match fs::rename(self.path(id), &path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let file = fs::File::open(&path)?;
        file.lock()?;
        let text = fs::read_to_string(&path)?;
        let queued = serde_json::from_str(&text)
            .map_err(|why| Error::Draft(format!("queued message {id} is unreadable: {why}")))?;
        Ok(Some((queued, Claim { path, _file: file })))
    }

    /// Puts a claimed message back in the queue, with its new retry state.
    ///
    /// Written to the waiting name first and the claim removed second, so a
    /// crash between the two leaves a message both waiting and claimed —
    /// which recovery resolves in favour of the waiting copy — and never one
    /// that is neither.
    fn release(&self, queued: &Queued, claim: &Path) -> Result<()> {
        self.write(queued)?;
        remove_if_present(claim)
    }

    /// Settles claims whose drain died mid-send.
    ///
    /// A claim whose lock can be taken is held by nobody. Its message may or
    /// may not have reached the server, which is exactly the ambiguous case:
    /// it is given up, never retried automatically. A claim still locked
    /// belongs to a drain that is running, and is left alone.
    fn recover_interrupted(&self, outcome: &mut DrainOutcome) -> Result<()> {
        for claimed in self.entries(CLAIMED) {
            let path = self.claim_path(&claimed.id);
            let Ok(file) = fs::File::open(&path) else {
                continue;
            };
            match file.try_lock() {
                Ok(()) => {}
                Err(fs::TryLockError::WouldBlock) => continue,
                Err(fs::TryLockError::Error(why)) => return Err(why.into()),
            }
            if self.path(&claimed.id).exists() {
                // Released, but the claim was not yet removed.
                remove_if_present(&path)?;
                continue;
            }
            self.stop(claimed, SendFailure::Interrupted, &path, outcome)?;
        }
        Ok(())
    }

    fn claim_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}{CLAIMED}"))
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

/// The draft as it is queued: with the `Message-ID` it will keep for every
/// attempt, so a retry is recognisably the same message.
fn with_message_id(draft: &Draft, id: &str) -> Draft {
    let mut draft = draft.clone();
    draft.ensure_message_id(id);
    draft
}

/// A message claimed for sending. The open, locked file is what tells a
/// running drain's claim from an abandoned one; dropping it releases the lock.
struct Claim {
    path: PathBuf,
    _file: fs::File,
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
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
    fn a_submitted_message_is_due_immediately_and_goes_on_the_first_drain() {
        // `submit` is for sends that start life in the queue — no Outcome,
        // no attempt yet — so the very next drain must try it, not back off.
        let (_dir, outbox) = outbox();
        outbox
            .submit("0000feed", &draft("Re: standup"), None, 1_000)
            .unwrap();

        let queued = outbox.list().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].attempts, 0);
        assert_eq!(queued[0].failure, None);

        let outcome = outbox.drain_with(|_| Outcome::Sent(b"raw".to_vec()), 1_000);
        assert_eq!(outcome.sent.len(), 1);
        assert_eq!(outbox.count(), 0);
    }

    #[test]
    fn a_send_that_never_reached_the_server_is_queued_and_survives_a_restart() {
        // The whole point: mail written offline should leave when the network
        // comes back, without anybody remembering to press anything.
        let dir = tempfile::tempdir().unwrap();
        {
            let outbox = Outbox::open(dir.path()).unwrap();
            outbox
                .queue("00000001", &draft("On a train"), None, &refused(), 0)
                .unwrap();
        }
        let outbox = Outbox::open(dir.path()).unwrap();
        let queued = outbox.list().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].draft.subject, "On a train");
        assert_eq!(queued[0].attempts, 1);
        assert!(
            queued[0]
                .failure
                .as_ref()
                .is_some_and(SendFailure::is_transient)
        );
        assert!(queued[0].is_live());
    }

    #[test]
    fn a_message_that_may_have_been_delivered_is_refused_at_the_door() {
        // The invariant, enforced rather than documented: a queue that retried
        // this would send it twice, with no way to take either back.
        let (_dir, outbox) = outbox();
        let ambiguous = Outcome::Ambiguous(Error::Smtp("timed out".into()));
        let refused_error = outbox
            .queue("00000001", &draft("Risky"), None, &ambiguous, 0)
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
                .queue(
                    "00000001",
                    &draft("Gone"),
                    None,
                    &Outcome::Sent(Vec::new()),
                    0
                )
                .is_err()
        );
    }

    #[test]
    fn an_entry_that_is_not_due_yet_is_skipped_rather_than_attempted() {
        let (_dir, outbox) = outbox();
        outbox
            .queue("00000001", &draft("Later"), None, &refused(), 0)
            .unwrap();

        let outcome = outbox.drain(&unreachable(), &password(), 1_000);
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
            .queue("00000001", &draft("Still offline"), None, &refused(), 0)
            .unwrap();

        let outcome = outbox.drain(&unreachable(), &password(), MAX_DELAY_MS + 1);
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
            .queue("00000001", &draft("Doomed"), None, &refused(), 0)
            .unwrap();

        // The clock has to move past each backoff, or every drain after the
        // first is correctly skipped as not-yet-due.
        let mut now = 0_i64;
        for _ in 0..MAX_ATTEMPTS {
            now += MAX_DELAY_MS + 1;
            let drained = outbox.drain(&unreachable(), &password(), now);
            assert!(drained.error.is_none(), "{:?}", drained.error);
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
            .queue("00000001", &draft("Stopped"), None, &refused(), 0)
            .unwrap();
        let mut now = 0_i64;
        for _ in 0..MAX_ATTEMPTS {
            now += MAX_DELAY_MS + 1;
            let drained = outbox.drain(&unreachable(), &password(), now);
            assert!(drained.error.is_none(), "{:?}", drained.error);
        }

        let outcome = outbox.drain(&unreachable(), &password(), now + MAX_DELAY_MS);
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
            outbox
                .queue(id, &draft(subject), None, &refused(), 0)
                .unwrap();
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
    fn a_drain_sends_in_the_order_the_list_shows() {
        // The drain walked the directory as the filesystem listed it, so two
        // messages written a second apart could leave in either order.
        //
        // Queued in an order that is neither ascending nor descending:
        // filesystems that list a directory oldest-first and ones that list
        // it newest-first (tmpfs, where tests usually run) would each hide
        // the defect from one of those two.
        let (_dir, outbox) = outbox();
        let ids: Vec<String> = (0..40_u32)
            .map(|n| format!("{:016x}", (n * 17) % 40))
            .collect();
        for id in &ids {
            outbox.submit(id, &draft(id), None, 0).unwrap();
        }
        let mut went = Vec::new();

        let outcome = outbox.drain_with(
            |draft| {
                went.push(draft.subject.clone());
                Outcome::Sent(Vec::new())
            },
            0,
        );

        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        let mut expected = ids;
        expected.sort();
        assert_eq!(went, expected);
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
            .schedule("0000000000000001", &draft("later"), None, 10_000)
            .unwrap();

        // Before the deadline: nothing is sent, nothing is attempted.
        let early = outbox.drain_with(|_| panic!("a not-yet-due message was submitted"), 9_999);
        assert_eq!(early.skipped, 1);

        let due = outbox.drain_with(|_| Outcome::Sent(b"bytes".to_vec()), 10_000);
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
        assert!(
            outbox
                .schedule("0000000000000002", &unfinished, None, 0)
                .is_err()
        );
        assert_eq!(outbox.count(), 0);
    }

    #[test]
    fn cancelling_hands_the_draft_back_exactly_once() {
        let (_dir, outbox) = outbox();
        outbox
            .schedule("0000000000000003", &draft("regretted"), None, i64::MAX)
            .unwrap();

        let taken = outbox.cancel("0000000000000003").unwrap();
        assert_eq!(
            taken.expect("the draft came back").draft.subject,
            "regretted"
        );
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
        outbox
            .queue("00000001", &draft, None, &refused(), 0)
            .unwrap();

        let queued = &outbox.list().unwrap()[0];
        assert_eq!(queued.draft.attachments[0].bytes, b"a,b\n1,2\n");
    }

    #[test]
    fn removing_a_message_that_is_already_gone_is_not_an_error() {
        let (_dir, outbox) = outbox();
        outbox
            .queue("00000001", &draft("x"), None, &refused(), 0)
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
                .queue("../../evil", &draft("x"), None, &refused(), 0)
                .is_err()
        );
        assert_eq!(outbox.count(), 0);
    }

    #[test]
    fn a_refusal_that_will_repeat_stops_at_once_and_keeps_the_message() {
        let (_dir, outbox) = outbox();
        outbox
            .submit("0000000000000009", &draft("bad login"), None, 0)
            .unwrap();
        let outcome = outbox.drain_with(
            |_| Outcome::Rejected(Error::Smtp("535 bad credentials".into())),
            0,
        );
        let refusal = SendFailure::Refused {
            reason: "SMTP: 535 bad credentials".into(),
        };
        assert_eq!(
            outcome.stopped,
            [Stopped {
                id: "0000000000000009".into(),
                failure: refusal.clone(),
            }]
        );
        let queued = &outbox.list().unwrap()[0];
        assert!(
            queued.given_up,
            "a refusal that will repeat was scheduled again"
        );
        assert_eq!(queued.failure, Some(refusal));
        assert!(!queued.may_have_been_delivered());
        assert_eq!(queued.draft.subject, "bad login");
    }

    #[test]
    fn every_attempt_of_a_queued_message_carries_the_same_message_id() {
        let (_dir, outbox) = outbox();
        outbox
            .queue("0000000000000010", &draft("x"), None, &refused(), 0)
            .unwrap();
        let mut seen = Vec::new();
        let mut now = 0;
        for _ in 0..2 {
            now += MAX_DELAY_MS + 1;
            let drained = outbox.drain_with(
                |draft| {
                    seen.push(draft.message_id.clone());
                    refused()
                },
                now,
            );
            assert!(drained.error.is_none(), "{:?}", drained.error);
        }
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], seen[1]);
        assert_eq!(seen[0].as_deref(), Some("0000000000000010@example.com"));
    }

    #[test]
    fn an_undo_during_the_send_cannot_take_back_what_is_going_out() {
        // The drain claims the message before it talks to the server, so an
        // Undo that lands mid-conversation finds it gone and says so, instead
        // of reopening a composer for a message the recipients are getting.
        let (_dir, outbox) = outbox();
        outbox
            .schedule("0000000000000011", &draft("going"), None, 0)
            .unwrap();
        let mut taken_back = None;
        let outcome = outbox.drain_with(
            |_| {
                taken_back = Some(outbox.cancel("0000000000000011").unwrap());
                Outcome::Sent(b"bytes".to_vec())
            },
            0,
        );
        assert_eq!(outcome.sent.len(), 1);
        assert_eq!(
            taken_back,
            Some(None),
            "Undo handed back a message that was being sent"
        );
        assert_eq!(outbox.count(), 0);
    }

    #[test]
    fn a_failed_send_that_was_being_undone_comes_back_once() {
        let (_dir, outbox) = outbox();
        outbox
            .schedule("0000000000000012", &draft("offline"), None, 0)
            .unwrap();
        let mut taken_back = None;
        let drained = outbox.drain_with(
            |_| {
                taken_back = Some(outbox.cancel("0000000000000012").unwrap());
                refused()
            },
            0,
        );
        assert!(drained.error.is_none(), "{:?}", drained.error);
        assert_eq!(taken_back, Some(None));
        let queued = outbox.list().unwrap();
        assert_eq!(queued.len(), 1, "the message was lost or duplicated");
        assert_eq!(queued[0].attempts, 1);
    }

    #[test]
    fn a_message_in_flight_is_listed_and_cannot_be_discarded() {
        let (_dir, outbox) = outbox();
        outbox
            .schedule("0000000000000013", &draft("in flight"), None, 0)
            .unwrap();
        let drained = outbox.drain_with(
            |_| {
                let listed = outbox.list().unwrap();
                assert_eq!(
                    listed.len(),
                    1,
                    "a message being sent vanished from the list"
                );
                assert!(listed[0].sending);
                assert!(outbox.remove("0000000000000013").is_err());
                refused()
            },
            0,
        );
        assert!(drained.error.is_none(), "{:?}", drained.error);
        assert!(!outbox.list().unwrap()[0].sending);
    }

    #[test]
    fn a_send_interrupted_by_a_crash_is_never_retried_automatically() {
        // A claim nobody holds is a drain that died mid-send: the message may
        // have been delivered, so it waits for a person.
        let (dir, outbox) = outbox();
        outbox
            .schedule("0000000000000014", &draft("crashed"), None, 0)
            .unwrap();
        let root = dir.path().join(DIRECTORY);
        std::fs::rename(
            root.join("0000000000000014.outgoing.json"),
            root.join("0000000000000014.sending.json"),
        )
        .unwrap();
        let outcome = outbox.drain_with(|_| panic!("an interrupted send was attempted again"), 0);
        assert_eq!(
            outcome.stopped,
            [Stopped {
                id: "0000000000000014".into(),
                failure: SendFailure::Interrupted,
            }]
        );
        let queued = &outbox.list().unwrap()[0];
        assert!(queued.given_up && !queued.sending);
        assert_eq!(queued.failure, Some(SendFailure::Interrupted));
        assert!(queued.may_have_been_delivered());
    }

    #[test]
    fn a_local_failure_part_way_keeps_the_list_of_what_was_sent() {
        // The first message goes; then the outbox directory stops accepting
        // changes, so its claim cannot be removed. The drain used to return
        // that as `Err`, and the id of a message the recipients now have went
        // with it — nothing could mark what it answered, or file its copy.
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, outbox) = outbox();
        let reply_to = Answers::to_message("<original@example.com>");
        outbox
            .submit(
                "0000000000000021",
                &draft("first"),
                Some(reply_to.clone()),
                0,
            )
            .unwrap();
        outbox
            .submit("0000000000000022", &draft("second"), None, 0)
            .unwrap();
        let root = dir.path().join(DIRECTORY);
        let mut attempted = 0;

        let outcome = outbox.drain_with(
            |_| {
                attempted += 1;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
                Outcome::Sent(b"bytes".to_vec())
            },
            0,
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(outcome.error.is_some(), "the local failure went unreported");
        assert_eq!(attempted, 1, "the drain carried on past a failing disk");
        assert_eq!(outcome.sent.len(), 1);
        assert_eq!(outcome.sent[0].id, "0000000000000021");
        assert_eq!(outcome.sent[0].answers, Some(reply_to));
        assert_eq!(outcome.sent[0].bytes, b"bytes");

        // Nothing is sent twice afterwards: the first message's leftover
        // claim is settled as possibly delivered, and only the second goes.
        let mut went = Vec::new();
        let next = outbox.drain_with(
            |draft| {
                went.push(draft.subject.clone());
                Outcome::Sent(Vec::new())
            },
            0,
        );
        assert!(next.error.is_none(), "{:?}", next.error);
        assert_eq!(went, ["second"]);
        assert_eq!(
            next.stopped,
            [Stopped {
                id: "0000000000000021".into(),
                failure: SendFailure::Interrupted,
            }]
        );
    }

    #[test]
    fn a_local_failure_before_anything_is_sent_is_reported_with_an_empty_list() {
        use std::os::unix::fs::PermissionsExt as _;

        let (dir, outbox) = outbox();
        outbox
            .submit("0000000000000023", &draft("stuck"), None, 0)
            .unwrap();
        let root = dir.path().join(DIRECTORY);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();

        let outcome = outbox.drain_with(|_| panic!("a message nobody could claim was sent"), 0);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(outcome.error.is_some());
        assert_eq!(outcome.sent, []);
        assert_eq!(outbox.count(), 1, "the message was lost");
    }

    /// Drains one message with `outcome`, and returns its record as a fresh
    /// `Outbox` on the same directory reads it — which is what "durably"
    /// means.
    fn stopped_by(outcome: fn() -> Outcome) -> (DrainOutcome, Queued) {
        let (dir, outbox) = outbox();
        outbox
            .submit("0000000000000031", &draft("x"), None, 0)
            .unwrap();
        let drained = outbox.drain_with(|_| outcome(), 0);
        assert!(drained.error.is_none(), "{:?}", drained.error);
        let reopened = Outbox::open(dir.path()).unwrap();
        let queued = reopened.list().unwrap().remove(0);
        (drained, queued)
    }

    #[test]
    fn a_server_refusal_is_recorded_as_one_with_the_servers_reason() {
        let (drained, queued) =
            stopped_by(|| Outcome::Rejected(Error::Smtp("550 5.1.1 no such user".into())));

        let refusal = SendFailure::Refused {
            reason: "SMTP: 550 5.1.1 no such user".into(),
        };
        assert_eq!(queued.failure, Some(refusal.clone()));
        assert!(queued.given_up);
        assert!(!queued.may_have_been_delivered());
        assert_eq!(drained.stopped[0].failure, refusal);
        assert_eq!(
            queued.failure.unwrap().reason(),
            Some("SMTP: 550 5.1.1 no such user")
        );
    }

    #[test]
    fn a_draft_that_cannot_be_built_is_not_blamed_on_the_server() {
        let (_, queued) = stopped_by(|| Outcome::Rejected(Error::Draft("no recipients".into())));

        assert_eq!(
            queued.failure,
            Some(SendFailure::Unsendable {
                reason: "no recipients".into()
            })
        );
        assert!(queued.given_up);
    }

    #[test]
    fn an_ambiguous_send_is_recorded_as_possibly_delivered() {
        let (drained, queued) =
            stopped_by(|| Outcome::Ambiguous(Error::Smtp("timed out after DATA".into())));

        assert_eq!(
            queued.failure,
            Some(SendFailure::Uncertain {
                reason: "SMTP: timed out after DATA".into()
            })
        );
        assert!(queued.given_up);
        assert!(queued.may_have_been_delivered());
        assert!(drained.needs_attention());
    }

    #[test]
    fn a_transient_failure_is_recorded_as_one_and_keeps_being_retried() {
        let (drained, queued) = stopped_by(refused);

        assert_eq!(
            queued.failure,
            Some(SendFailure::Transient {
                reason: "SMTP: connection refused".into()
            })
        );
        assert!(queued.is_live());
        assert!(!queued.may_have_been_delivered());
        assert_eq!(drained.deferred, 1);
        assert_eq!(drained.stopped, []);
    }

    #[test]
    fn a_message_that_ran_out_of_attempts_says_it_was_transient_to_the_end() {
        let (_dir, outbox) = outbox();
        outbox
            .queue("00000001", &draft("Doomed"), None, &refused(), 0)
            .unwrap();
        let mut now = 0_i64;
        let mut stopped = Vec::new();
        for _ in 0..MAX_ATTEMPTS {
            now += MAX_DELAY_MS + 1;
            stopped.extend(outbox.drain_with(|_| refused(), now).stopped);
        }

        assert_eq!(stopped.len(), 1, "it stops once, and is reported once");
        assert!(stopped[0].failure.is_transient());
        let queued = &outbox.list().unwrap()[0];
        assert!(queued.given_up);
        assert!(!queued.may_have_been_delivered());
    }

    #[test]
    fn trying_a_stopped_message_again_starts_it_over() {
        let (_dir, outbox) = outbox();
        outbox
            .submit("0000000000000032", &draft("x"), None, 0)
            .unwrap();
        let drained = outbox.drain_with(|_| Outcome::Rejected(Error::Smtp("535".into())), 0);
        assert_eq!(drained.stopped.len(), 1);

        outbox.retry("0000000000000032").unwrap();

        let queued = &outbox.list().unwrap()[0];
        assert!(queued.is_live());
        assert_eq!(
            queued.failure, None,
            "a message due now still says it was refused"
        );
    }

    #[test]
    fn a_record_written_before_failures_were_typed_is_still_read() {
        // 2.x wrote a sentence. One still being retried was transient by
        // construction; one that had stopped cannot say whether it was
        // refused or delivered, and is read as the case that says "look
        // first".
        let (dir, outbox) = outbox();
        outbox
            .submit("0000000000000041", &draft("live"), None, 0)
            .unwrap();
        let root = dir.path().join(DIRECTORY);
        let draft_json = serde_json::to_string(&draft("old")).unwrap();
        for (id, extra) in [
            (
                "0000000000000042",
                r#""attempts":3,"next_attempt_ms":99,"last_error":"SMTP: connection refused""#,
            ),
            (
                "0000000000000043",
                r#""attempts":1,"last_error":"SMTP: 550 no","given_up":true"#,
            ),
        ] {
            fs::write(
                root.join(format!("{id}{EXTENSION}")),
                format!(r#"{{"id":"{id}","draft":{draft_json},{extra}}}"#),
            )
            .unwrap();
        }

        let listed = outbox.list().unwrap();

        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].failure, None);
        assert_eq!(
            listed[1].failure,
            Some(SendFailure::Transient {
                reason: "SMTP: connection refused".into()
            })
        );
        assert!(listed[1].is_live());
        assert_eq!(listed[1].attempts, 3);
        assert_eq!(listed[1].next_attempt_ms, 99);
        assert_eq!(
            listed[2].failure,
            Some(SendFailure::Uncertain {
                reason: "SMTP: 550 no".into()
            })
        );
        assert!(listed[2].may_have_been_delivered());
    }

    #[test]
    fn a_failure_is_stored_under_a_name_not_a_sentence() {
        let (dir, outbox) = outbox();
        outbox
            .submit("0000000000000044", &draft("x"), None, 0)
            .unwrap();
        let drained = outbox.drain_with(|_| Outcome::Ambiguous(Error::Smtp("eof".into())), 0);
        assert_eq!(drained.stopped.len(), 1);

        let text = fs::read_to_string(
            dir.path()
                .join(DIRECTORY)
                .join(format!("0000000000000044{EXTENSION}")),
        )
        .unwrap();
        let record: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(record["failure"]["kind"], "uncertain");
        assert_eq!(record["failure"]["reason"], "SMTP: eof");
        assert_eq!(record.get("last_error"), None);
    }

    fn origin() -> Origin {
        Origin {
            mailbox: "INBOX".into(),
            delimiter: Some('/'),
            uid: 41,
            uid_validity: 7,
        }
    }

    #[test]
    fn a_reply_carries_what_it_answers_to_the_report_of_its_send() {
        let dir = tempfile::tempdir().unwrap();
        let answers = Answers::to_message(" <original@example.com> ").found_at(origin());
        assert_eq!(answers.message_id.as_deref(), Some("original@example.com"));
        Outbox::open(dir.path())
            .unwrap()
            .schedule(
                "0000000000000051",
                &draft("Re: hello"),
                Some(answers.clone()),
                0,
            )
            .unwrap();

        // Across a restart, which is the point of keeping it on the record.
        let outbox = Outbox::open(dir.path()).unwrap();
        assert_eq!(outbox.list().unwrap()[0].answers, Some(answers.clone()));
        let outcome = outbox.drain_with(|_| Outcome::Sent(b"raw".to_vec()), 0);

        assert_eq!(outcome.sent.len(), 1);
        assert_eq!(outcome.sent[0].answers, Some(answers));
        assert_eq!(
            outcome.sent[0].message_id.as_deref(),
            Some("0000000000000051@example.com"),
            "the report names the message that went"
        );
    }

    #[test]
    fn a_reply_taken_back_is_still_a_reply() {
        let (_dir, outbox) = outbox();
        let answers = Answers::at(origin());
        outbox
            .schedule(
                "0000000000000052",
                &draft("Re: hello"),
                Some(answers.clone()),
                i64::MAX,
            )
            .unwrap();

        let taken = outbox.cancel("0000000000000052").unwrap().unwrap();

        assert_eq!(taken.answers, Some(answers));
        assert_eq!(taken.draft.subject, "Re: hello");
    }

    #[test]
    fn a_failed_reply_keeps_what_it_answers_through_every_retry() {
        let (_dir, outbox) = outbox();
        let answers = Answers::to_message("original@example.com");
        outbox
            .queue(
                "0000000000000053",
                &draft("Re: hello"),
                Some(answers.clone()),
                &refused(),
                0,
            )
            .unwrap();
        let drained = outbox.drain_with(|_| refused(), MAX_DELAY_MS + 1);
        assert_eq!(drained.deferred, 1);

        assert_eq!(outbox.list().unwrap()[0].answers, Some(answers));
    }

    #[test]
    fn an_empty_message_id_is_no_reference() {
        assert_eq!(Answers::to_message("").message_id, None);
        assert_eq!(Answers::to_message(" <> ").message_id, None);
    }

    #[test]
    fn an_origin_names_its_message_only_under_the_numbering_it_was_taken_in() {
        let mut mailbox = MailboxState::default();
        mailbox.cursor.uid_validity = 7;
        mailbox.entries.insert(41, crate::model::Flags::default());

        assert!(origin().still_names(&mailbox));

        // Renumbered: UID 41 is now some other message.
        mailbox.cursor.uid_validity = 8;
        assert!(!origin().still_names(&mailbox));

        // Same numbering, but the message has gone — moved, or expunged.
        mailbox.cursor.uid_validity = 7;
        mailbox.entries.clear();
        assert!(!origin().still_names(&mailbox));
    }
}

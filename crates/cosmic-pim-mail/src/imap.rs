// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The cycle's shape — cursor, windowed discovery, CONDSTORE flag deltas, the
// held-back MODSEQ on a failed window, periodic full reconciliation — is ported
// from `src-tauri/src/mail_sync.rs` in the Meltemi project. The storage is new:
// the donor issued SQL inline, this drives a [`MailStore`]. See NOTICE and
// LICENSING.md.

//! The IMAP session, and the sync cycle that ties the rest of the crate
//! together.
//!
//! # The cycle
//!
//! 1. **SELECT**, and compare UIDVALIDITY. A change means the mailbox was
//!    renumbered and everything we hold for it is void — see below.
//! 2. **Push.** Queued flag changes, moves, and deletions go first.
//! 3. **Pull.** New UIDs above the cursor, fetched in batches.
//! 4. **Flags.** One CONDSTORE round trip carries every flag delta since the
//!    last cycle; without CONDSTORE, the full UID set.
//! 5. **Reconcile**, periodically: the complete UID set, to notice deletions
//!    another client made.
//! 6. **Commit** the cursor — and only then.
//!
//! Step 2 before step 3 is not an optimisation. The other order lets the pull
//! overwrite a local flag change with the server's older copy, after which the
//! queued push re-uploads what was just clobbered. It presents as read marks
//! and stars flickering back, and it is the same bug as CalDAV edits reverting.
//!
//! Step 6 last, and only on success, for the reason the CalDAV ctag is
//! committed last: a cursor written over a partially applied cycle convinces
//! the next run it is up to date, and the messages that did not land never
//! arrive.
//!
//! # UIDVALIDITY
//!
//! A UID is only meaningful together with the mailbox's UIDVALIDITY. When the
//! server changes it — a restore from backup, a mailbox recreated, some
//! migrations — UID 41 no longer names the message it named yesterday. It may
//! name a different message, or none.
//!
//! So a change is handled by discarding the mailbox and starting over, never by
//! reconciling: reconciling would compare flags between messages that have
//! nothing to do with each other and write the results to disk. This is the
//! stale-etag rule at mailbox scale, and it is why
//! [`crate::error::Error::UidValidityChanged`] is classified as needing a sync
//! pass rather than a retry.

use imap::types::Fetch;

use crate::error::{Error, Result};
use crate::folder::{self, Folder};
use crate::model::Flags;
use crate::plan;
use crate::push::{self, DrainOutcome, PushQueue, Writeback};
use crate::sasl::{Credentials, XOAuth2};
use crate::store::{Cursor, MailStore, RemoteMessage};

/// How many messages are fetched in one round trip.
///
/// Large enough that the per-command latency is amortised, small enough that a
/// dropped connection loses one batch rather than the whole backfill — and that
/// the peak memory is bounded by 50 messages, not by the mailbox.
const FETCH_BATCH: usize = 50;

/// `BODY.PEEK[]`, not `BODY[]`.
///
/// `BODY[]` sets `\Seen` as a side effect of reading. A client that syncs with
/// it marks the user's entire mailbox as read on first run — on the server, for
/// every device. There is no undo for that.
const FETCH_ITEMS: &str = "(UID FLAGS INTERNALDATE BODY.PEEK[])";

/// How a connection is encrypted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Security {
    /// TLS from the first byte — port 993, and what every provider wants.
    #[default]
    Tls,
    /// Plaintext, upgraded with STARTTLS — port 143 on servers that still do it
    /// that way.
    StartTls,
    /// No encryption at all.
    ///
    /// Exists for a local test server and for a Dovecot on `localhost`. It is
    /// never a reasonable setting for a remote host and the UI should say so.
    Plaintext,
}

/// Where and how to reach one account's IMAP server.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub security: Security,
    pub username: String,
}

impl Endpoint {
    /// The conventional endpoint for a host: implicit TLS on 993.
    #[must_use]
    pub fn tls(host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 993,
            security: Security::Tls,
            username: username.into(),
        }
    }
}

/// A logged-in IMAP session.
pub struct Session {
    inner: imap::Session<imap::Connection>,
    /// The mailbox currently SELECTed, so a cycle does not re-SELECT what it is
    /// already in.
    selected: Option<String>,
    condstore: bool,
    /// QRESYNC on top of CONDSTORE: the same delta round trip also carries
    /// the deletions, as VANISHED responses.
    qresync: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("selected", &self.selected)
            .field("condstore", &self.condstore)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Connects and authenticates.
    ///
    /// Which mechanism is decided by what it is handed: a password goes over
    /// `LOGIN`, an access token over `AUTHENTICATE XOAUTH2`. Sending a token as
    /// a password — which is what happens if the two are conflated — is refused
    /// by the server in a way that reads as a wrong password.
    pub fn connect(endpoint: &Endpoint, credentials: &Credentials) -> Result<Self> {
        let client = imap::ClientBuilder::new(&endpoint.host, endpoint.port)
            .mode(match endpoint.security {
                Security::Tls => imap::ConnectionMode::Tls,
                Security::StartTls => imap::ConnectionMode::StartTls,
                Security::Plaintext => imap::ConnectionMode::Plaintext,
            })
            .connect()
            .map_err(imap_error)?;

        // Both arms hand the client back with the error so it can be retried;
        // we only want the reason, and it is a credential problem rather than
        // a transport one.
        let mut inner = match credentials {
            Credentials::Password(password) => client
                .login(&endpoint.username, password)
                .map_err(|(error, _client)| Error::Auth(error.to_string()))?,
            Credentials::OAuth2(token) => {
                let authenticator = XOAuth2::new(&endpoint.username, token);
                client
                    .authenticate("XOAUTH2", &authenticator)
                    .map_err(|(error, _client)| Error::Auth(error.to_string()))?
            }
        };

        // CONDSTORE turns flag reconciliation from "ask about every message" to
        // "ask what changed", which is the difference between a round trip
        // proportional to the mailbox and one proportional to the news.
        //
        // Advertised is not enabled. RFC 7162 lets a server withhold
        // HIGHESTMODSEQ until the client opts in, and a real Dovecot does
        // exactly that — SELECT carries no MODSEQ at all until `ENABLE
        // CONDSTORE` has been issued. The scripted test server sent it
        // unconditionally, which is why this was invisible until the client
        // ran against the real thing: the cursor stayed at zero and every
        // cycle silently took the full-reconciliation path instead of the
        // delta. The ENABLE is best-effort — a server that advertises the
        // capability but rejects the command is treated as not having it.
        // QRESYNC preferred — enabling it enables CONDSTORE semantics too, and
        // adds VANISHED, which is how a deletion made by another client
        // arrives in the same round trip as the flag deltas instead of
        // waiting for the periodic full reconciliation. CONDSTORE alone is
        // the fallback; nothing at all falls back to full reconciliation.
        let caps = inner.capabilities();
        let has = |name: &str| caps.as_ref().is_ok_and(|caps| caps.has_str(name));
        let qresync = has("QRESYNC")
            && inner
                .run_command_and_check_ok("ENABLE QRESYNC")
                .map_err(|why| {
                    tracing::debug!(%why, "ENABLE QRESYNC was refused; trying CONDSTORE");
                    why
                })
                .is_ok();
        let condstore = qresync
            || (has("CONDSTORE")
                && inner
                    .run_command_and_check_ok("ENABLE CONDSTORE")
                    .map_err(|why| {
                        tracing::debug!(%why, "ENABLE CONDSTORE was refused; using full reconciliation");
                        why
                    })
                    .is_ok());

        Ok(Self {
            inner,
            selected: None,
            condstore,
            qresync,
        })
    }

    /// Every mailbox the server lists.
    pub fn folders(&mut self) -> Result<Vec<Folder>> {
        let names = self.inner.list(Some(""), Some("*")).map_err(imap_error)?;
        let mut folders: Vec<Folder> = names
            .iter()
            .map(|name| {
                folder::from_list_entry(
                    name.name(),
                    name.delimiter().and_then(|d| d.chars().next()),
                    name.attributes(),
                )
            })
            .collect();
        folder::sort_for_display(&mut folders);
        Ok(folders)
    }

    /// SELECTs `mailbox` unless it is already selected.
    fn select(&mut self, mailbox: &str) -> Result<imap::types::Mailbox> {
        let selected = self.inner.select(mailbox).map_err(imap_error)?;
        self.selected = Some(mailbox.to_owned());
        Ok(selected)
    }

    /// Files a message into a mailbox, with flags.
    ///
    /// Used for the Sent copy. Most servers do **not** file SMTP-submitted mail
    /// themselves — the message goes out and simply never appears in Sent —
    /// so the client has to put it there. Gmail is the notable exception and
    /// appending there produces a duplicate, which is why this is a call the
    /// caller makes rather than something [`crate::smtp::send`] does on its own.
    ///
    /// `\Seen` is set, always: a message the user just wrote is not unread mail
    /// for the user, and a Sent folder with a bold unread count is a bug report
    /// waiting to happen.
    pub fn append(&mut self, mailbox: &str, raw: &[u8], flags: crate::model::Flags) -> Result<()> {
        self.append_returning_uid(mailbox, raw, flags).map(|_| ())
    }

    /// [`Self::append`], reporting where the message landed when the server
    /// says.
    ///
    /// `Some((uidvalidity, uid))` is UIDPLUS's APPENDUID — the receipt that
    /// lets a later operation address exactly the message just filed. `None`
    /// means the server does not offer it, and the caller's fallback is a
    /// `Message-ID` search; a UID guessed any other way could name someone
    /// else's message.
    pub fn append_returning_uid(
        &mut self,
        mailbox: &str,
        raw: &[u8],
        flags: crate::model::Flags,
    ) -> Result<Option<(u32, u32)>> {
        use imap::types::Flag as F;
        let mut imap_flags = vec![F::Seen];
        if flags.flagged {
            imap_flags.push(F::Flagged);
        }
        if flags.draft {
            imap_flags.push(F::Draft);
        }
        let appended = self
            .inner
            .append(mailbox, raw)
            .flags(imap_flags)
            .finish()
            .map_err(imap_error)?;
        let validity = appended.uid_validity;
        let uid = appended.uids.as_ref().and_then(|uids| {
            uids.iter()
                .map(|member| match member {
                    imap_proto::UidSetMember::Uid(uid) => *uid,
                    imap_proto::UidSetMember::UidRange(range) => *range.start(),
                })
                .next()
        });
        Ok(validity.zip(uid))
    }

    /// UIDs in the **selected** mailbox whose `Message-ID` header carries
    /// `id` (without brackets).
    ///
    /// The caller selects first because every use pairs this with operations
    /// on the same mailbox, and a hidden re-SELECT here would silently discard
    /// the caller's context.
    pub fn uids_by_message_id(&mut self, id: &str) -> Result<Vec<u32>> {
        let mut uids: Vec<u32> = self
            .inner
            .uid_search(format!("HEADER Message-ID <{id}>"))
            .map_err(imap_error)?
            .into_iter()
            .collect();
        uids.sort_unstable();
        Ok(uids)
    }

    /// SELECTs `mailbox` for callers outside the sync cycle — the drafts
    /// mirror, which addresses a folder no cycle has selected for it.
    pub fn select_mailbox(&mut self, mailbox: &str) -> Result<imap::types::Mailbox> {
        self.select(mailbox)
    }

    /// CREATEs a mailbox. Already existing is left to the server to say —
    /// RFC 3501 makes it a NO, and the caller decides whether that matters.
    pub fn create_mailbox(&mut self, mailbox: &str) -> Result<()> {
        self.inner.create(mailbox).map_err(imap_error)
    }

    /// RENAMEs a mailbox. RFC 3501 renames the subtree with it — children
    /// move too, which is what a user dragging a folder expects.
    pub fn rename_mailbox(&mut self, from: &str, to: &str) -> Result<()> {
        // The selection cache would otherwise keep addressing the old name.
        if self.selected.as_deref() == Some(from) {
            self.selected = None;
        }
        self.inner.rename(from, to).map_err(imap_error)
    }

    /// DELETEs a mailbox — the folder itself, with every message in it.
    ///
    /// The caller confirms; this executes. Nothing here second-guesses,
    /// because a guard that silently refuses is worse than a dialog that
    /// asks.
    pub fn delete_mailbox(&mut self, mailbox: &str) -> Result<()> {
        if self.selected.as_deref() == Some(mailbox) {
            self.selected = None;
        }
        self.inner.delete(mailbox).map_err(imap_error)
    }

    /// Does the server speak RFC 2177 IDLE?
    ///
    /// Worth asking before [`Self::watch`]: a server without it answers the
    /// command with an error, and the caller's right response is to fall back
    /// to polling rather than to retry.
    pub fn supports_idle(&mut self) -> bool {
        self.inner
            .capabilities()
            .is_ok_and(|caps| caps.has_str("IDLE"))
    }

    /// Selects `mailbox` and blocks until the server says it changed, or
    /// `timeout` passes.
    ///
    /// This is push mail: the server tells us, instead of us asking every few
    /// minutes. The connection carrying the watch should be a **dedicated
    /// session** — IDLE monopolises it, and multiplexing it with a sync cycle
    /// means the cycle waits half an hour for the watch to notice.
    ///
    /// A timeout is not a failure. RFC 2177 tells clients to re-issue IDLE at
    /// least every 29 minutes anyway, and the `imap` crate refreshes the
    /// connection underneath us on the same schedule; the caller just watches
    /// again.
    pub fn watch(&mut self, mailbox: &str, timeout: std::time::Duration) -> Result<Watched> {
        use imap::extensions::idle::WaitOutcome;

        self.select(mailbox)?;
        let mut handle = self.inner.idle();
        handle.timeout(timeout);
        match handle.wait_while(imap::extensions::idle::stop_on_any) {
            Ok(WaitOutcome::MailboxChanged) => Ok(Watched::Changed),
            Ok(WaitOutcome::TimedOut) => Ok(Watched::TimedOut),
            Err(why) => Err(imap_error(why)),
        }
    }

    pub fn logout(&mut self) -> Result<()> {
        self.inner.logout().map_err(imap_error)
    }
}

impl Writeback for Session {
    fn store_flags(&mut self, uid: u32, flags: Flags) -> Result<()> {
        // `FLAGS.SILENT` sets the whole set rather than adding to it, which is
        // what the queue stores: the user's final intent, not a delta.
        let names = flags.to_imap().join(" ");
        self.inner
            .uid_store(uid.to_string(), format!("FLAGS.SILENT ({names})"))
            .map(|_| ())
            .map_err(imap_error)
    }

    fn move_message(&mut self, uid: u32, destination: &str) -> Result<()> {
        match self.inner.uid_mv(uid.to_string(), destination) {
            Ok(()) => Ok(()),
            // RFC 6851 MOVE is not universal. The fallback is the sequence it
            // is defined to be equivalent to, and doing it in that order
            // matters: a COPY that fails must leave the original in place.
            Err(_) => {
                self.inner
                    .uid_copy(uid.to_string(), destination)
                    .map_err(imap_error)?;
                self.inner
                    .uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
                    .map_err(imap_error)?;
                self.expunge_uid(uid)
            }
        }
    }

    fn delete_message(&mut self, uid: u32) -> Result<()> {
        self.inner
            .uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
            .map_err(imap_error)?;
        self.expunge_uid(uid)
    }
}

impl Session {
    /// Expunges one message, preferring UIDPLUS.
    ///
    /// A bare EXPUNGE removes *every* `\Deleted` message in the mailbox,
    /// including ones another client marked and has not expunged yet. Where the
    /// server has UIDPLUS, `UID EXPUNGE` is scoped to ours.
    fn expunge_uid(&mut self, uid: u32) -> Result<()> {
        if self
            .inner
            .capabilities()
            .is_ok_and(|caps| caps.has_str("UIDPLUS"))
        {
            self.inner
                .uid_expunge(uid.to_string())
                .map(|_| ())
                .map_err(imap_error)
        } else {
            // Without UIDPLUS the message stays marked `\Deleted` and is left
            // for the server's own housekeeping. Deliberately: destroying
            // another client's pending deletions to save one round trip is not
            // a trade worth making, and a `\Deleted` message is already hidden
            // by every reasonable UI.
            tracing::info!(
                uid,
                "server has no UIDPLUS; the message is marked deleted but not expunged"
            );
            Ok(())
        }
    }
}

/// What ended a [`Session::watch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watched {
    /// The server reported the mailbox changed — new mail, an expunge, a flag.
    /// The caller's next move is a sync cycle, not a guess about what changed:
    /// the untagged responses IDLE delivers are not enough to act on directly.
    Changed,
    /// Nothing happened within the timeout. Watch again.
    TimedOut,
}

/// What one cycle did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    pub fetched: usize,
    pub reflagged: usize,
    pub removed: usize,
    pub pushed: DrainOutcome,
    /// The mailbox was renumbered and re-downloaded from scratch.
    pub renumbered: bool,
    /// The empty-listing guard fired; deletions were skipped this round.
    pub guard_tripped: bool,
    /// A CONDSTORE window failed and the MODSEQ cursor was deliberately not
    /// advanced, so the next cycle replays it.
    pub modseq_held_back: bool,
}

/// How much work one cycle should do.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncOptions {
    /// Run a full UID-set reconciliation this cycle.
    ///
    /// Not every cycle: it is a round trip proportional to the mailbox, and its
    /// job — noticing that another client deleted something — is not urgent.
    /// Every tenth cycle, and on demand.
    pub reconcile: bool,
    /// Only fetch messages newer than this, in epoch milliseconds. `None`
    /// fetches everything, which is what a small mailbox wants and a
    /// twenty-year archive does not.
    pub since_ms: Option<i64>,
}

/// Runs one sync cycle for one mailbox.
///
/// `store` must be the store for *this* mailbox — the maildir mirroring it.
pub fn sync_mailbox(
    session: &mut Session,
    wire_name: &str,
    store: &mut (impl MailStore + PushQueue),
    options: SyncOptions,
    now_ms: i64,
) -> Result<SyncOutcome> {
    let mut outcome = SyncOutcome::default();
    let mailbox = session.select(wire_name)?;

    let uid_validity = mailbox.uid_validity.unwrap_or(0);
    let mut cursor = store.state()?.cursor;

    // The 412 analogue. Everything we hold is void, including the queue.
    if cursor.uid_validity != 0 && cursor.uid_validity != uid_validity {
        tracing::warn!(
            mailbox = wire_name,
            had = cursor.uid_validity,
            now = uid_validity,
            "mailbox renumbered; discarding local state for it"
        );
        store.reset(uid_validity)?;
        cursor = store.state()?.cursor;
        outcome.renumbered = true;
    }
    cursor.uid_validity = uid_validity;
    cursor.accepts_keywords = mailbox
        .permanent_flags
        .iter()
        .any(|flag| matches!(flag, imap::types::Flag::MayCreate));

    // --- Push, before anything reads the server's version of the flags ------
    outcome.pushed = push::drain(session, store, now_ms);
    // A move or delete the drain just performed leaves the store now, on the
    // strength of the server's own OK. Waiting for the reconciliation to
    // notice would work for a partial mailbox and deadlock for a full one:
    // a mailbox moved to empty produces exactly the empty-listing shape the
    // mass-delete guard refuses to act on.
    for uid in outcome.pushed.departed.clone() {
        store.remove(uid)?;
    }

    // --- Pull: UIDs above the cursor ---------------------------------------
    let state = store.state()?;
    let discovered = discover(session, &cursor, mailbox.exists, options.since_ms)?;
    let to_fetch = plan::plan_fetch(&discovered, &state);
    let mut highest_seen = cursor.last_uid;
    for batch in to_fetch.chunks(FETCH_BATCH) {
        let fetched = fetch_batch(session, batch)?;
        for message in &fetched {
            highest_seen = highest_seen.max(message.uid);
            store.upsert(message)?;
            outcome.fetched += 1;
        }
        // A UID the server listed but would not return is not retried
        // indefinitely; the cursor moves past it. Some servers hold
        // permanently unfetchable messages, and a client that refuses to
        // advance past one never syncs that mailbox again.
        highest_seen = highest_seen.max(batch.iter().copied().max().unwrap_or(0));
    }
    cursor.last_uid = highest_seen;

    // --- Flags --------------------------------------------------------------
    let server_modseq = mailbox.highest_mod_seq.unwrap_or(0);
    if session.condstore && cursor.highest_modseq > 0 && server_modseq > cursor.highest_modseq {
        match fetch_flag_deltas(session, cursor.highest_modseq) {
            Ok((deltas, vanished)) => {
                let held = store.state()?.entries;
                for (uid, flags) in deltas {
                    if let Some(local) = held.get(&uid) {
                        let merged = flags.with_local_only_from(*local);
                        if merged != *local {
                            store.set_flags(uid, merged)?;
                            outcome.reflagged += 1;
                        }
                    }
                }
                // QRESYNC's whole contribution: a deletion another client made
                // leaves this store now, in the same round trip as the flags,
                // instead of lingering until the periodic reconciliation.
                for uid in vanished {
                    if held.contains_key(&uid) {
                        store.remove(uid)?;
                        outcome.removed += 1;
                    }
                }
                cursor.highest_modseq = server_modseq;
            }
            Err(why) => {
                // The cursor stays where it was on purpose. Advancing past a
                // window whose fetch failed loses that window's flag changes
                // forever, because "we will catch it next cycle" only exists
                // while the cursor still names the old window.
                tracing::warn!(mailbox = wire_name, %why, "flag window failed; holding the MODSEQ cursor");
                outcome.modseq_held_back = true;
            }
        }
    } else if server_modseq > 0 {
        // First cycle on a CONDSTORE server: record where we are so the next
        // one can ask for a delta.
        cursor.highest_modseq = server_modseq;
    }

    // --- Full reconciliation ------------------------------------------------
    if options.reconcile {
        let listing = fetch_all_flags(session)?;
        let local = store.state()?.entries;
        let reconciled = plan::plan_reconcile(&listing, &local);
        outcome.guard_tripped = reconciled.guard_tripped;

        for (uid, flags) in &reconciled.flag_updates {
            store.set_flags(*uid, *flags)?;
            outcome.reflagged += 1;
        }
        for batch in reconciled.to_fetch.chunks(FETCH_BATCH) {
            for message in &fetch_batch(session, batch)? {
                cursor.last_uid = cursor.last_uid.max(message.uid);
                store.upsert(message)?;
                outcome.fetched += 1;
            }
        }
        for uid in &reconciled.to_remove {
            store.remove(*uid)?;
            outcome.removed += 1;
        }
    }

    // Last, and only now.
    store.commit_cursor(cursor)?;
    Ok(outcome)
}

/// Candidate new UIDs, ascending.
///
/// On the first cycle this is a SEARCH over the requested window; afterwards it
/// is everything above the cursor.
fn discover(
    session: &mut Session,
    cursor: &Cursor,
    exists: u32,
    since_ms: Option<i64>,
) -> Result<Vec<u32>> {
    if cursor.last_uid == 0 {
        if exists == 0 {
            return Ok(Vec::new());
        }
        let criteria = match since_ms.and_then(imap_date) {
            Some(date) => format!("SINCE {date} NOT DELETED"),
            // A clock so broken the cutoff will not render is not a reason to
            // sync nothing; fetching more than asked is the safe direction.
            None => "NOT DELETED".to_string(),
        };
        let mut uids: Vec<u32> = session
            .inner
            .uid_search(&criteria)
            .map_err(imap_error)?
            .into_iter()
            .collect();
        uids.sort_unstable();
        return Ok(uids);
    }

    let mut uids: Vec<u32> = session
        .inner
        .uid_search(format!("UID {}:* NOT DELETED", cursor.last_uid + 1))
        .map_err(imap_error)?
        .into_iter()
        .collect();
    uids.sort_unstable();
    Ok(uids)
}

fn fetch_batch(session: &mut Session, uids: &[u32]) -> Result<Vec<RemoteMessage>> {
    if uids.is_empty() {
        return Ok(Vec::new());
    }
    let set = uids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let fetches = session
        .inner
        .uid_fetch(set, FETCH_ITEMS)
        .map_err(imap_error)?;
    Ok(fetches.iter().filter_map(remote_message).collect())
}

/// What one CHANGEDSINCE window reported: `(flag deltas, vanished UIDs)`.
type FlagWindow = (Vec<(u32, Flags)>, Vec<u32>);

/// Every flag change since `modseq` — and, with QRESYNC, every deletion —
/// in one round trip.
fn fetch_flag_deltas(session: &mut Session, modseq: u64) -> Result<FlagWindow> {
    // The VANISHED modifier is only legal once QRESYNC is enabled; sending it
    // to a CONDSTORE-only server is a BAD.
    let query = if session.qresync {
        format!("(FLAGS) (CHANGEDSINCE {modseq} VANISHED)")
    } else {
        format!("(FLAGS) (CHANGEDSINCE {modseq})")
    };
    let fetches = session.inner.uid_fetch("1:*", query).map_err(imap_error)?;
    let deltas = fetches
        .iter()
        .filter_map(|fetch| Some((fetch.uid?, Flags::from_imap(fetch.flags()))))
        .collect();

    // VANISHED (EARLIER) arrives as an unsolicited response alongside the
    // fetch. Drained here, right after the command that provoked it, so the
    // deletions are attributed to the window that reported them.
    let mut vanished = Vec::new();
    for response in session.inner.take_all_unsolicited() {
        if let imap::types::UnsolicitedResponse::Vanished { uids, .. } = response {
            for range in uids {
                vanished.extend(range);
            }
        }
    }
    Ok((deltas, vanished))
}

/// The complete UID set with flags — the authoritative listing a full
/// reconciliation needs.
fn fetch_all_flags(session: &mut Session) -> Result<Vec<(u32, Flags)>> {
    let fetches = session
        .inner
        .uid_fetch("1:*", "(FLAGS)")
        .map_err(imap_error)?;
    Ok(fetches
        .iter()
        .filter_map(|fetch| Some((fetch.uid?, Flags::from_imap(fetch.flags()))))
        .collect())
}

fn remote_message(fetch: &Fetch<'_>) -> Option<RemoteMessage> {
    Some(RemoteMessage {
        uid: fetch.uid?,
        flags: Flags::from_imap(fetch.flags()),
        raw: fetch.body()?.to_vec(),
        internal_date_ms: fetch
            .internal_date()
            .map_or(0, |date| date.timestamp_millis()),
    })
}

/// `dd-Mon-yyyy`, the only date format RFC 3501 SEARCH accepts.
fn imap_date(epoch_ms: i64) -> Option<String> {
    use chrono::{DateTime, Datelike as _};
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let date = DateTime::from_timestamp_millis(epoch_ms)?;
    let month = MONTHS.get(date.month0() as usize)?;
    Some(format!("{:02}-{month}-{}", date.day(), date.year()))
}

/// Turns an `imap` error into ours, keeping the transport/credential split.
fn imap_error(error: imap::Error) -> Error {
    match error {
        imap::Error::Io(io) => Error::Io(io),
        other => Error::Imap(other.to_string()),
    }
}

/// A [`MailStore`] plus [`PushQueue`] over memory, for driving a cycle in tests.
#[derive(Debug, Default)]
pub struct MemoryMailbox {
    pub store: crate::store::MemoryStore,
    pub queue: push::MemoryQueue,
}

impl MailStore for MemoryMailbox {
    fn state(&self) -> Result<crate::store::MailboxState> {
        self.store.state()
    }
    fn upsert(&mut self, message: &RemoteMessage) -> Result<()> {
        self.store.upsert(message)
    }
    fn set_flags(&mut self, uid: u32, flags: Flags) -> Result<()> {
        self.store.set_flags(uid, flags)
    }
    fn remove(&mut self, uid: u32) -> Result<()> {
        self.store.remove(uid)
    }
    fn raw(&self, uid: u32) -> Result<Option<Vec<u8>>> {
        self.store.raw(uid)
    }
    fn commit_cursor(&mut self, cursor: Cursor) -> Result<()> {
        self.store.commit_cursor(cursor)
    }
    fn reset(&mut self, uid_validity: u32) -> Result<()> {
        self.queue.entries.clear();
        self.store.reset(uid_validity)
    }
}

impl PushQueue for MemoryMailbox {
    fn pending(&self) -> Vec<push::PendingPush> {
        self.queue.pending()
    }
    fn enqueue(&mut self, op: push::PushOp) -> Result<()> {
        self.queue.enqueue(op)
    }
    fn resolve(&mut self, uid: u32) -> Result<()> {
        self.queue.resolve(uid)
    }
    fn defer(
        &mut self,
        uid: u32,
        failure: push::Failure,
        error: &str,
        next_attempt_ms: i64,
    ) -> Result<()> {
        self.queue.defer(uid, failure, error, next_attempt_ms)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn search_dates_are_rendered_the_only_way_the_rfc_accepts() {
        assert_eq!(imap_date(1_700_000_000_000).as_deref(), Some("14-Nov-2023"));
        assert_eq!(imap_date(0).as_deref(), Some("01-Jan-1970"));
    }

    #[test]
    fn the_fetch_never_asks_for_a_body_that_marks_messages_read() {
        // BODY[] sets \Seen as a side effect. A sync using it marks the user's
        // whole mailbox read, on the server, on every device, with no undo.
        assert!(FETCH_ITEMS.contains("BODY.PEEK["));
        assert!(!FETCH_ITEMS.contains("BODY["));
    }
}

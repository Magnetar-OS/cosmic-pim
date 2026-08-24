// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The label-bits model, the history-expiry decision, and the shape of the
// delta loop are ported from `src-tauri/src/gmail.rs` in the Meltemi project.
// The storage is new: the donor drove SQLite, this drives a maildir. See
// NOTICE and LICENSING.md.

//! The Gmail API as a mail engine, for accounts that offer nothing better.
//!
//! # Why this exists at all, given IMAP
//!
//! Gmail still speaks IMAP, and where IMAP is enough this crate uses it. Two
//! things it cannot do:
//!
//! - **Archiving.** Gmail has no Archive folder; archiving is *removing the
//!   INBOX label*, and IMAP has no way to express that. Over IMAP the change
//!   another client made is invisible until a full-mailbox reconcile.
//! - **Labels.** A message with three labels appears three times over IMAP,
//!   once per pseudo-folder, and there is no way to tell that they are one
//!   message.
//!
//! `history.list` reports `labelRemoved INBOX` as an ordered delta, so the
//! change lands within one poll. That is the whole argument for this module.
//!
//! # It does not break verbatim storage, and that is not an accident
//!
//! `messages.get?format=raw` returns the complete original RFC 5322 as
//! base64url. So this engine is a *change feed* over the API and a *content
//! fetch* of the original octets, exactly as the JMAP engine is — the maildir,
//! the index, threading, search and every other reader are unchanged, and no
//! message is ever reassembled from parsed JSON. A `format=full` fetch would
//! be one request cheaper and would invalidate every DKIM signature it touched.
//!
//! # Labels are the folder model
//!
//! Gmail has no folders. A message's location is derived from its label set,
//! and its read and starred state are labels too (`UNREAD`, `STARRED`). So a
//! local move is a label change, and a label change arriving from the server
//! moves the message between maildirs. [`folder_from_labels`] is that mapping,
//! and its precedence is the user-visible one rather than alphabetical.
//!
//! # The expired cursor is the load-bearing case
//!
//! `history.list` answers 404 or 410 when the cursor predates Gmail's
//! retention — about a week. That means *I cannot tell you what changed*. It
//! never means "nothing changed", which would freeze the account until
//! somebody noticed, and it never means "everything was deleted", which would
//! empty the maildir. The only correct response is to drop the cursor and
//! bootstrap again. See [`crate::store::RemoteIds`].
//!
//! # No push
//!
//! Gmail's push channel is `users.watch`, which needs a Google Cloud Pub/Sub
//! topic and a public HTTPS endpoint — infrastructure a desktop client does
//! not have and should not require an account for. The caller polls.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::folder::{Folder, SpecialUse};
use crate::model::Flags;
use crate::sasl::Credentials;
use crate::store::{Cursor, MailStore, RemoteIds, RemoteMessage};

/// Gmail's own API root. A field rather than a hardcoded literal at the call
/// sites, so a deployment behind a corporate proxy — and the test harness —
/// can point somewhere else without a second code path.
pub const BASE: &str = "https://gmail.googleapis.com/gmail/v1/users/me";

/// Gmail is quick; a stalled request should not hold a pass open.
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// How many ids to ask `messages.list` or `history.list` for at once.
const PAGE_SIZE: usize = 500;

/// The sidecar this engine keeps beside a maildir.
pub const STATE_FILE: &str = ".gmail-state.json";

/// Reads a mailbox's Gmail state, or starts empty.
///
/// The cursor here is a `historyId`. It is account-wide rather than
/// per-mailbox, and each maildir keeps its own copy of where it has been
/// applied to — so a mailbox that failed mid-pass replays its own window
/// rather than the account's.
#[must_use]
pub fn state(maildir: &Path) -> RemoteIds {
    RemoteIds::load(maildir, STATE_FILE)
}

/// A message id with the labels Gmail currently has on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GmailMessage {
    pub id: String,
    pub thread_id: String,
    pub labels: Vec<String>,
    /// Gmail's own arrival timestamp, in epoch milliseconds.
    pub internal_date_ms: i64,
}

impl GmailMessage {
    /// The flags this message's labels amount to.
    #[must_use]
    pub fn flags(&self) -> Flags {
        flags_from_labels(&self.labels)
    }

    /// The maildir this message belongs in.
    #[must_use]
    pub fn folder(&self) -> &'static str {
        folder_from_labels(&self.labels)
    }
}

/// Where a message lives, from its labels.
///
/// Precedence is the *user-visible* one. `TRASH` and `SPAM` beat everything
/// because that is where Gmail's own interface shows the message; `DRAFT`
/// next; then `INBOX`; then `SENT`. A message can be both `SENT` and `INBOX`
/// — self-addressed mail, and anything received from an address the account
/// holds as a send-as alias, which Gmail stamps `SENT` on arrival. Filing
/// those under sent hides them from the inbox and silences their notification,
/// so `INBOX` wins.
///
/// A message with none of these is exactly Gmail's "All Mail without the Inbox
/// label" — the archive.
#[must_use]
pub fn folder_from_labels(labels: &[String]) -> &'static str {
    let has = |name: &str| labels.iter().any(|label| label == name);
    if has("TRASH") {
        "trash"
    } else if has("SPAM") {
        "junk"
    } else if has("DRAFT") {
        "drafts"
    } else if has("INBOX") {
        "inbox"
    } else if has("SENT") {
        "sent"
    } else {
        "archive"
    }
}

/// Read and starred state, which Gmail also keeps as labels.
///
/// `UNREAD` is inverted on purpose: Gmail marks what has *not* been read,
/// IMAP and maildir mark what has. Getting that backwards marks an entire
/// mailbox read, on the server, on every device.
#[must_use]
pub fn flags_from_labels(labels: &[String]) -> Flags {
    let has = |name: &str| labels.iter().any(|label| label == name);
    Flags {
        seen: !has("UNREAD"),
        flagged: has("STARRED"),
        draft: has("DRAFT"),
        answered: false,
        deleted: false,
        passed: false,
    }
}

/// The label changes that turn one flag set into another.
///
/// Returns `(add, remove)`. Only the labels that actually differ, because
/// `messages.modify` rejects an empty list rather than ignoring it, and
/// sending a no-op change still costs quota.
#[must_use]
pub fn label_delta(from: Flags, to: Flags) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut add = Vec::new();
    let mut remove = Vec::new();

    if from.seen != to.seen {
        // Again: the label is UNREAD, so marking read *removes* it.
        if to.seen {
            remove.push("UNREAD");
        } else {
            add.push("UNREAD");
        }
    }
    if from.flagged != to.flagged {
        if to.flagged {
            add.push("STARRED");
        } else {
            remove.push("STARRED");
        }
    }

    (add, remove)
}

/// The maildir folder a local move targets, as a Gmail label change.
///
/// Archiving is the interesting one: it is not a move to a folder, it is the
/// removal of `INBOX` and nothing else. A client that models it as a move to
/// an "Archive" folder either creates a label Gmail does not want or loses the
/// operation entirely.
#[must_use]
pub fn move_delta(destination: &str) -> (Vec<&'static str>, Vec<&'static str>) {
    match destination {
        "archive" => (Vec::new(), vec!["INBOX"]),
        "inbox" => (vec!["INBOX"], Vec::new()),
        "trash" => (vec!["TRASH"], vec!["INBOX"]),
        "junk" => (vec!["SPAM"], vec!["INBOX"]),
        // Restoring from junk is not simply removing SPAM: Gmail leaves the
        // message nowhere visible unless INBOX goes back on.
        "sent" => (vec!["SENT"], Vec::new()),
        _ => (Vec::new(), Vec::new()),
    }
}

/// An authenticated Gmail API client.
pub struct Session {
    http: reqwest::blocking::Client,
    authorization: String,
    base: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GmailSession").finish_non_exhaustive()
    }
}

/// What `history.list` said.
///
/// [`HistoryPage::Expired`] is a third outcome rather than an error or an
/// empty page, and the distinction is the whole point — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HistoryPage {
    Ok {
        records: Vec<Value>,
        next_page_token: Option<String>,
        history_id: Option<String>,
    },
    Expired,
}

impl Session {
    /// Builds a client. Gmail takes a bearer token and nothing else.
    ///
    /// A password is refused rather than sent: Google withdrew password
    /// authentication for this API, and an app password put in an
    /// `Authorization` header produces a 401 that reads as a wrong password.
    pub fn connect(credentials: &Credentials) -> Result<Self> {
        Self::connect_to(BASE, credentials)
    }

    /// As [`Self::connect`], against a different API root.
    pub fn connect_to(base: &str, credentials: &Credentials) -> Result<Self> {
        let Credentials::OAuth2(token) = credentials else {
            return Err(Error::Auth(
                "the Gmail API takes an OAuth access token; Google withdrew password \
                 authentication for it"
                    .to_owned(),
            ));
        };

        let http = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|why| Error::Gmail(why.to_string()))?;

        Ok(Self {
            http,
            authorization: format!("Bearer {token}"),
            base: base.trim_end_matches('/').to_owned(),
        })
    }

    fn get(&self, url: &str) -> Result<(u16, String)> {
        let response = self
            .http
            .get(url)
            .header("Authorization", &self.authorization)
            .header("Accept", "application/json")
            .send()
            .map_err(|why| Error::Gmail(why.to_string()))?;

        let status = response.status().as_u16();
        let body = response
            .text()
            .map_err(|why| Error::Gmail(why.to_string()))?;
        Ok((status, body))
    }

    fn post(&self, url: &str, body: &Value) -> Result<(u16, String)> {
        let response = self
            .http
            .post(url)
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|why| Error::Gmail(why.to_string()))?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .map_err(|why| Error::Gmail(why.to_string()))?;
        Ok((status, text))
    }

    /// Turns a non-2xx into the right kind of error.
    fn refuse(status: u16, what: &str, body: &str) -> Error {
        let detail = body.chars().take(200).collect::<String>();
        if status == 401 || status == 403 {
            Error::Auth(format!(
                "gmail {what} was refused (HTTP {status}): {detail}"
            ))
        } else {
            Error::Gmail(format!("gmail {what} returned HTTP {status}: {detail}"))
        }
    }

    /// The mailbox's current `historyId` — the cursor a bootstrap opens with.
    pub fn profile_history_id(&self) -> Result<String> {
        let base = &self.base;
        let (status, body) = self.get(&format!("{base}/profile"))?;
        if !(200..300).contains(&status) {
            return Err(Self::refuse(status, "profile", &body));
        }

        serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("historyId")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                Error::Gmail(
                    "gmail profile returned no historyId, so there is no cursor to sync from"
                        .to_owned(),
                )
            })
    }

    /// Ids in one label, newest first, bounded by `limit`.
    pub fn list(&self, label: &str, limit: usize) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut page_token: Option<String> = None;

        while ids.len() < limit {
            let take = PAGE_SIZE.min(limit - ids.len());
            let base = &self.base;
            let mut url = format!("{base}/messages?labelIds={label}&maxResults={take}");
            if let Some(token) = &page_token {
                url.push_str("&pageToken=");
                url.push_str(token);
            }

            let (status, body) = self.get(&url)?;
            if !(200..300).contains(&status) {
                return Err(Self::refuse(status, "messages.list", &body));
            }

            let page: Value = serde_json::from_str(&body)
                .map_err(|why| Error::Gmail(format!("parsing messages.list: {why}")))?;

            for message in page
                .get("messages")
                .and_then(Value::as_array)
                .unwrap_or(&Vec::new())
            {
                if let Some(id) = message.get("id").and_then(Value::as_str) {
                    ids.push(id.to_owned());
                }
            }

            match page.get("nextPageToken").and_then(Value::as_str) {
                Some(token) if !token.is_empty() => page_token = Some(token.to_owned()),
                _ => break,
            }
        }

        Ok(ids)
    }

    /// Metadata for one message: its labels, thread and arrival time.
    ///
    /// `format=minimal` on purpose — the bytes come from
    /// [`Self::raw`], and asking for the parsed payload here would be a large
    /// response nothing reads.
    pub fn metadata(&self, id: &str) -> Result<Option<GmailMessage>> {
        let base = &self.base;
        let (status, body) = self.get(&format!("{base}/messages/{id}?format=minimal"))?;
        if status == 404 {
            // Deleted between the listing and now. Not an error: a pass that
            // failed here would fail every time until the listing changed.
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(Self::refuse(status, "messages.get", &body));
        }

        let value: Value = serde_json::from_str(&body)
            .map_err(|why| Error::Gmail(format!("parsing messages.get: {why}")))?;
        Ok(parse_metadata(&value))
    }

    /// The original RFC 5322 octets.
    ///
    /// `format=raw` is what keeps this engine inside the suite's verbatim-bytes
    /// invariant. See the module docs.
    pub fn raw(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let base = &self.base;
        let (status, body) = self.get(&format!("{base}/messages/{id}?format=raw"))?;
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(Self::refuse(status, "messages.get?format=raw", &body));
        }

        let value: Value = serde_json::from_str(&body)
            .map_err(|why| Error::Gmail(format!("parsing messages.get: {why}")))?;

        let encoded = value
            .get("raw")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Gmail(format!("no raw payload for message {id}")))?;

        decode_base64url(encoded).map(Some)
    }

    /// One page of `history.list`.
    fn history_page(&self, since: &str, page_token: Option<&str>) -> Result<HistoryPage> {
        let base = &self.base;
        let mut url = format!(
            "{base}/history?startHistoryId={since}&maxResults={PAGE_SIZE}\
             &historyTypes=messageAdded&historyTypes=messageDeleted\
             &historyTypes=labelAdded&historyTypes=labelRemoved"
        );
        if let Some(token) = page_token {
            url.push_str("&pageToken=");
            url.push_str(token);
        }

        let (status, body) = self.get(&url)?;
        match status {
            // The cursor is older than Gmail's retention. See the module docs
            // for why this is neither an error nor an empty answer.
            404 | 410 => return Ok(HistoryPage::Expired),
            code if !(200..300).contains(&code) => {
                return Err(Self::refuse(code, "history.list", &body));
            }
            _ => {}
        }

        let page: Value = serde_json::from_str(&body)
            .map_err(|why| Error::Gmail(format!("parsing history.list: {why}")))?;

        Ok(HistoryPage::Ok {
            records: page
                .get("history")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            next_page_token: page
                .get("nextPageToken")
                .and_then(Value::as_str)
                .filter(|token| !token.is_empty())
                .map(ToOwned::to_owned),
            history_id: page
                .get("historyId")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(ToOwned::to_owned),
        })
    }

    /// Adds and removes labels on one message.
    pub fn modify(&self, id: &str, add: &[&str], remove: &[&str]) -> Result<()> {
        if add.is_empty() && remove.is_empty() {
            return Ok(());
        }

        let mut body = json!({});
        if !add.is_empty() {
            body["addLabelIds"] = json!(add);
        }
        if !remove.is_empty() {
            body["removeLabelIds"] = json!(remove);
        }

        let (status, text) = self.post(&format!("{}/messages/{id}/modify", self.base), &body)?;
        if !(200..300).contains(&status) {
            return Err(Self::refuse(status, "messages.modify", &text));
        }
        Ok(())
    }

    /// Submits a message for delivery.
    ///
    /// `messages.send` with the raw RFC 5322, base64url-encoded — the same
    /// verbatim-bytes rule in the outbound direction: the message Gmail sends
    /// is byte-for-byte the one the composer built, not a reassembly.
    ///
    /// The message is built **with** its `Bcc` header, which looks wrong
    /// against [`crate::compose::Draft::build`]'s own warning and is not: SMTP
    /// carries recipients in a separate envelope, so the header must be
    /// stripped there — but an API has no envelope. Recipients derive from the
    /// headers, and Gmail, acting as the submission server, strips `Bcc` from
    /// every delivered copy exactly as RFC 5322 §3.6.3 expects. Stripping it
    /// ourselves would mean the blind-copied recipients never receive the
    /// message at all.
    ///
    /// No Sent filing follows: Gmail files its own copy, and appending a
    /// second would duplicate it on every device.
    pub fn submit(&self, draft: &crate::compose::Draft) -> crate::smtp::Outcome {
        use crate::smtp::Outcome;

        let message = match draft.build(true) {
            Ok(message) => message.formatted(),
            Err(why) => return Outcome::NotSent(why),
        };
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&message);

        let url = format!("{}/messages/send", self.base);
        let response = self
            .http
            .post(&url)
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .body(json!({ "raw": encoded }).to_string())
            .send();

        let response = match response {
            Ok(response) => response,
            // A connection that never opened cannot have delivered anything;
            // anything past that point may have.
            Err(why) if why.is_connect() => {
                return Outcome::NotSent(Error::Gmail(format!("messages.send: {why}")));
            }
            Err(why) => {
                return Outcome::Ambiguous(Error::Gmail(format!("messages.send: {why}")));
            }
        };

        let status = response.status().as_u16();
        let body = response.text().unwrap_or_default();
        match status {
            // Gmail acknowledged the submission; its own Sent copy follows.
            200..=299 => Outcome::Sent(message),
            // The request itself was refused before acceptance.
            400..=499 => Outcome::NotSent(Self::refuse(status, "messages.send", &body)),
            // The server had the message when it failed; it may yet deliver.
            _ => Outcome::Ambiguous(Self::refuse(status, "messages.send", &body)),
        }
    }

    /// Moves a message to the bin.
    ///
    /// Deliberately not `messages.delete`, which is permanent and irreversible
    /// and is not what a mail client's delete key should mean.
    pub fn trash(&self, id: &str) -> Result<()> {
        let (status, text) =
            self.post(&format!("{}/messages/{id}/trash", self.base), &json!({}))?;
        if !(200..300).contains(&status) {
            return Err(Self::refuse(status, "messages.trash", &text));
        }
        Ok(())
    }
}

/// Gmail sends URL-safe base64 without padding; some proxies re-pad it.
fn decode_base64url(data: &str) -> Result<Vec<u8>> {
    let mut normalised = data.replace('-', "+").replace('_', "/");
    while !normalised.len().is_multiple_of(4) {
        normalised.push('=');
    }
    base64::engine::general_purpose::STANDARD
        .decode(normalised.as_bytes())
        .map_err(|why| Error::Gmail(format!("decoding a raw message: {why}")))
}

fn parse_metadata(value: &Value) -> Option<GmailMessage> {
    Some(GmailMessage {
        id: value.get("id")?.as_str()?.to_owned(),
        thread_id: value
            .get("threadId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        labels: value
            .get("labelIds")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|label| label.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        internal_date_ms: value
            .get("internalDate")
            .and_then(Value::as_str)
            .and_then(|text| text.parse().ok())
            .unwrap_or_default(),
    })
}

/// Every id a history page mentions, with what happened to it.
///
/// The label deltas are folded in as "this message changed", not applied
/// blindly: a label delta says which labels moved, and the authoritative set
/// comes from re-reading the message. Folding deltas into a stored set is
/// possible and is how the donor does it, but it drifts the moment one page is
/// missed, and re-reading costs one small request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryDelta {
    /// Messages added or changed — treated identically, because a label added
    /// to a message this mailbox has never seen is how an archived message
    /// arrives back in the inbox.
    pub touched: Vec<String>,
    /// Deleted outright, server-side. Surgical, never a sweep.
    pub deleted: Vec<String>,
    /// The cursor these changes bring the client up to.
    pub history_id: Option<String>,
}

fn fold_history(records: &[Value], delta: &mut HistoryDelta) {
    let ids_in = |record: &Value, field: &str| -> Vec<String> {
        record
            .get(field)
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|entry| {
                        entry
                            .get("message")
                            .and_then(|message| message.get("id"))
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    for record in records {
        for id in ids_in(record, "messagesAdded") {
            delta.touched.push(id);
        }
        for id in ids_in(record, "labelsAdded") {
            delta.touched.push(id);
        }
        for id in ids_in(record, "labelsRemoved") {
            delta.touched.push(id);
        }
        for id in ids_in(record, "messagesDeleted") {
            delta.deleted.push(id);
        }
    }

    // One request per message, however many times it was touched in the page.
    delta.touched.sort_unstable();
    delta.touched.dedup();
    delta.deleted.sort_unstable();
    delta.deleted.dedup();
    // A message both touched and deleted in one window is gone; the delete is
    // the later fact whatever order the records arrived in.
    delta.touched.retain(|id| !delta.deleted.contains(id));
}

/// What one Gmail pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GmailOutcome {
    pub fetched: usize,
    pub reflagged: usize,
    /// Left this maildir — deleted, or moved to another label.
    pub removed: usize,
    pub pushed: crate::push::DrainOutcome,
    /// The cursor had expired and the mailbox was read again from scratch.
    pub bootstrapped: bool,
}

/// Gmail message ids never renumber, so the store's UIDVALIDITY is a constant
/// that exists only to keep the shared shape honest.
pub const GMAIL_UID_VALIDITY: u32 = 1;

/// The maildir folders this engine maintains, and the label each bootstraps
/// from.
///
/// `archive` has no label of its own — it is "all mail without INBOX" — so it
/// is populated by history deltas rather than bootstrapped. Bootstrapping it
/// would mean listing the entire account.
const BOOTSTRAP_LABELS: &[(&str, &str)] = &[
    ("inbox", "INBOX"),
    ("sent", "SENT"),
    ("drafts", "DRAFT"),
    ("trash", "TRASH"),
    ("junk", "SPAM"),
];

/// The folder a maildir path was opened for.
#[must_use]
pub fn folder_for(slug: &str) -> Folder {
    Folder {
        wire_name: slug.to_owned(),
        display_name: slug.to_owned(),
        delimiter: '/',
        special_use: match slug {
            "inbox" => Some(SpecialUse::Inbox),
            "sent" => Some(SpecialUse::Sent),
            "drafts" => Some(SpecialUse::Drafts),
            "trash" => Some(SpecialUse::Trash),
            "junk" => Some(SpecialUse::Junk),
            "archive" => Some(SpecialUse::Archive),
            _ => None,
        },
        no_select: false,
    }
}

/// Runs one pass for one maildir.
///
/// `slug` is the canonical folder this maildir mirrors — see
/// [`folder_from_labels`]. The pass pushes queued changes, then applies either
/// the history delta or, when there is no usable cursor, a bootstrap listing.
///
/// A message whose labels no longer place it in `slug` is removed from *this*
/// maildir; the pass over the maildir it moved to will fetch it there. That is
/// how an archive from another client lands, and it is the reason both passes
/// see the same account-wide history.
pub fn sync_folder(
    session: &Session,
    slug: &str,
    store: &mut (impl MailStore + crate::push::PushQueue),
    state: &mut RemoteIds,
    limit: usize,
    now_ms: i64,
) -> Result<GmailOutcome> {
    // Push before pull, as everywhere else: the other order lets the pull
    // overwrite a local flag change with the server's older labels, and the
    // queued push then sends the server's own state back to it.
    let pushed = {
        let mut writeback = GmailWriteback::new(session, state);
        crate::push::drain(&mut writeback, store, now_ms)
    };

    let mut outcome = match state.cursor().map(ToOwned::to_owned) {
        Some(since) => match apply_history(session, slug, store, state, &since)? {
            Some(outcome) => outcome,
            None => {
                // Expired. Not an error, and not "nothing changed".
                state.reset_cursor();
                bootstrap(session, slug, store, state, limit)?
            }
        },
        None => bootstrap(session, slug, store, state, limit)?,
    };

    outcome.pushed = pushed;

    store.commit_cursor(Cursor {
        uid_validity: GMAIL_UID_VALIDITY,
        last_uid: state.highest_uid(),
        ..Default::default()
    })?;

    Ok(outcome)
}

/// Reads this folder's label as it currently stands.
fn bootstrap(
    session: &Session,
    slug: &str,
    store: &mut impl MailStore,
    state: &mut RemoteIds,
    limit: usize,
) -> Result<GmailOutcome> {
    let mut outcome = GmailOutcome {
        bootstrapped: true,
        ..Default::default()
    };

    // Read the cursor *before* the listing, so a change landing during the
    // bootstrap is caught by the next delta rather than skipped by a cursor
    // newer than the data it was recorded with.
    let opened_at = session.profile_history_id()?;

    let Some((_, label)) = BOOTSTRAP_LABELS.iter().find(|(folder, _)| *folder == slug) else {
        // `archive` and anything else: nothing to list, and the deltas will
        // populate it. Opening the cursor is still right — otherwise this
        // maildir bootstraps forever.
        state.set_cursor(opened_at);
        return Ok(outcome);
    };

    let ids = session.list(label, limit)?;
    let known = store.state()?;
    let mut present = Vec::new();

    for id in &ids {
        let Some(message) = session.metadata(id)? else {
            continue;
        };
        if message.folder() != slug {
            // Listed under the label but belongs elsewhere — a TRASHed message
            // still carries INBOX, and Gmail's own interface shows it in the
            // bin.
            continue;
        }

        let uid = state.uid_for(id);
        present.push(uid);

        match known.entries.get(&uid) {
            Some(held) if *held == message.flags() => {}
            Some(_) => {
                store.set_flags(uid, message.flags())?;
                outcome.reflagged += 1;
            }
            None => {
                let Some(raw) = session.raw(id)? else {
                    continue;
                };
                store.upsert(&RemoteMessage {
                    uid,
                    flags: message.flags(),
                    raw,
                    internal_date_ms: message.internal_date_ms,
                })?;
                outcome.fetched += 1;
            }
        }
    }

    // The mass-delete guard: a listing that came back empty while we hold
    // messages is far more likely to be a server having a moment than a
    // mailbox that emptied itself.
    if !ids.is_empty() {
        for uid in known.entries.keys().copied().collect::<Vec<_>>() {
            if !present.contains(&uid) && ids.len() < limit {
                if let Some(id) = state.id_of(uid).map(ToOwned::to_owned) {
                    state.forget(&id);
                }
                store.remove(uid)?;
                outcome.removed += 1;
            }
        }
    } else if !known.entries.is_empty() {
        tracing::warn!(
            slug,
            held = known.entries.len(),
            "gmail listed nothing while we hold messages; skipping removals this pass"
        );
    }

    state.set_cursor(opened_at);
    Ok(outcome)
}

/// Applies `history.list` from the stored cursor. `None` means it expired.
fn apply_history(
    session: &Session,
    slug: &str,
    store: &mut impl MailStore,
    state: &mut RemoteIds,
    since: &str,
) -> Result<Option<GmailOutcome>> {
    let mut outcome = GmailOutcome::default();
    let mut delta = HistoryDelta::default();
    let mut page_token: Option<String> = None;

    loop {
        match session.history_page(since, page_token.as_deref())? {
            HistoryPage::Expired => return Ok(None),
            HistoryPage::Ok {
                records,
                next_page_token,
                history_id,
            } => {
                fold_history(&records, &mut delta);
                if let Some(id) = history_id {
                    delta.history_id = Some(id);
                }
                match next_page_token {
                    Some(token) => page_token = Some(token),
                    None => break,
                }
            }
        }
    }

    let known = store.state()?;

    for id in &delta.touched {
        let Some(message) = session.metadata(id)? else {
            // Gone between the history page and now.
            if let Some(uid) = state.uid_of(id) {
                state.forget(id);
                store.remove(uid)?;
                outcome.removed += 1;
            }
            continue;
        };

        let belongs_here = message.folder() == slug;
        let held = state.uid_of(id);

        match (belongs_here, held) {
            (true, None) => {
                let Some(raw) = session.raw(id)? else {
                    continue;
                };
                let uid = state.uid_for(id);
                store.upsert(&RemoteMessage {
                    uid,
                    flags: message.flags(),
                    raw,
                    internal_date_ms: message.internal_date_ms,
                })?;
                outcome.fetched += 1;
            }
            (true, Some(uid)) => {
                if known.entries.get(&uid) != Some(&message.flags()) {
                    store.set_flags(uid, message.flags())?;
                    outcome.reflagged += 1;
                }
            }
            // Its labels moved it elsewhere — archived, binned, or filed by
            // another client. This is the change IMAP cannot see.
            (false, Some(uid)) => {
                state.forget(id);
                store.remove(uid)?;
                outcome.removed += 1;
            }
            (false, None) => {}
        }
    }

    for id in &delta.deleted {
        if let Some(uid) = state.uid_of(id) {
            state.forget(id);
            store.remove(uid)?;
            outcome.removed += 1;
        }
    }

    // Only now, with the whole window applied.
    if let Some(history_id) = delta.history_id {
        state.set_cursor(history_id);
    }

    Ok(Some(outcome))
}

/// Writeback over the Gmail API: a [`crate::push::Writeback`] that turns local
/// flag and folder changes into label changes.
pub struct GmailWriteback<'a> {
    session: &'a Session,
    state: &'a mut RemoteIds,
}

impl<'a> GmailWriteback<'a> {
    #[must_use]
    pub fn new(session: &'a Session, state: &'a mut RemoteIds) -> Self {
        Self { session, state }
    }

    fn id_for(&self, uid: u32) -> Result<String> {
        self.state
            .id_of(uid)
            .map(ToOwned::to_owned)
            .ok_or_else(|| Error::UidValidityChanged {
                mailbox: "gmail".to_owned(),
                had: uid,
                now: 0,
            })
    }
}

impl crate::push::Writeback for GmailWriteback<'_> {
    fn store_flags(&mut self, uid: u32, flags: Flags) -> Result<()> {
        let id = self.id_for(uid)?;
        // The labels the message already has decide the delta, so an unchanged
        // flag costs no request and a `modify` is never sent empty.
        let current = self
            .session
            .metadata(&id)?
            .map(|message| message.flags())
            .unwrap_or_default();

        let (add, remove) = label_delta(current, flags);
        self.session.modify(&id, &add, &remove)
    }

    fn move_message(&mut self, uid: u32, destination: &str) -> Result<()> {
        let id = self.id_for(uid)?;
        let (add, remove) = move_delta(destination);
        if add.is_empty() && remove.is_empty() {
            return Err(Error::Gmail(format!(
                "no Gmail label corresponds to the folder “{destination}”"
            )));
        }
        self.session.modify(&id, &add, &remove)?;
        // It belongs to another maildir now.
        self.state.forget(&id);
        Ok(())
    }

    fn delete_message(&mut self, uid: u32) -> Result<()> {
        let id = self.id_for(uid)?;
        // The bin, not `messages.delete`. See `Session::trash`.
        self.session.trash(&id)?;
        self.state.forget(&id);
        Ok(())
    }
}

/// Every maildir this engine maintains for an account.
#[must_use]
pub fn folders() -> Vec<Folder> {
    BOOTSTRAP_LABELS
        .iter()
        .map(|(slug, _)| folder_for(slug))
        .chain(std::iter::once(folder_for("archive")))
        .collect()
}

/// Label id → display name, for a UI that wants to show Gmail's own labels.
pub fn labels(session: &Session) -> Result<BTreeMap<String, String>> {
    let (status, body) = session.get(&format!("{}/labels", session.base))?;
    if !(200..300).contains(&status) {
        return Err(Session::refuse(status, "labels.list", &body));
    }

    let page: Value = serde_json::from_str(&body)
        .map_err(|why| Error::Gmail(format!("parsing labels.list: {why}")))?;

    Ok(page
        .get("labels")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|label| {
                    Some((
                        label.get("id")?.as_str()?.to_owned(),
                        label.get("name")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels_of(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn a_message_with_no_location_label_is_archived() {
        // Gmail's "All Mail without the Inbox label". Getting this wrong files
        // every archived message in the inbox.
        assert_eq!(folder_from_labels(&labels_of(&["UNREAD"])), "archive");
        assert_eq!(folder_from_labels(&[]), "archive");
    }

    #[test]
    fn the_bin_and_spam_beat_everything_else() {
        // A binned message keeps INBOX. Showing it in the inbox contradicts
        // Gmail's own interface.
        assert_eq!(folder_from_labels(&labels_of(&["INBOX", "TRASH"])), "trash");
        assert_eq!(folder_from_labels(&labels_of(&["INBOX", "SPAM"])), "junk");
    }

    #[test]
    fn mail_that_is_both_sent_and_in_the_inbox_stays_in_the_inbox() {
        // Self-addressed mail, and anything from a send-as alias, which Gmail
        // stamps SENT on arrival. Filing it under sent hides it and silences
        // its notification.
        assert_eq!(folder_from_labels(&labels_of(&["SENT", "INBOX"])), "inbox");
    }

    #[test]
    fn unread_is_inverted_because_gmail_marks_the_opposite() {
        // The single easiest way to mark an entire mailbox read on every
        // device the account is on.
        assert!(!flags_from_labels(&labels_of(&["UNREAD"])).seen);
        assert!(flags_from_labels(&labels_of(&["INBOX"])).seen);
    }

    #[test]
    fn starring_maps_both_ways() {
        assert!(flags_from_labels(&labels_of(&["STARRED"])).flagged);

        // From unread-and-unstarred to read-and-starred: one label on, one
        // off, in a single request.
        let (add, remove) = label_delta(
            Flags::default(),
            Flags {
                seen: true,
                flagged: true,
                ..Default::default()
            },
        );
        assert_eq!(add, vec!["STARRED"]);
        assert_eq!(remove, vec!["UNREAD"]);

        // And unstarring only touches STARRED.
        let starred = Flags {
            seen: true,
            flagged: true,
            ..Default::default()
        };
        let unstarred = Flags {
            flagged: false,
            ..starred
        };
        assert_eq!(
            label_delta(starred, unstarred),
            (Vec::new(), vec!["STARRED"])
        );
    }

    #[test]
    fn marking_read_removes_the_unread_label() {
        let unread = Flags::default();
        let read = Flags {
            seen: true,
            ..Default::default()
        };

        let (add, remove) = label_delta(unread, read);

        assert!(add.is_empty());
        assert_eq!(remove, vec!["UNREAD"]);
    }

    #[test]
    fn an_unchanged_flag_set_sends_nothing() {
        // `messages.modify` rejects empty label lists, and a no-op still costs
        // quota.
        let flags = Flags {
            seen: true,
            flagged: true,
            ..Default::default()
        };
        assert_eq!(label_delta(flags, flags), (Vec::new(), Vec::new()));
    }

    #[test]
    fn archiving_is_the_removal_of_inbox_and_nothing_else() {
        // The operation IMAP cannot express, and the reason this module
        // exists. A client that models it as a move to a folder either invents
        // a label or loses the change.
        assert_eq!(move_delta("archive"), (Vec::new(), vec!["INBOX"]));
    }

    #[test]
    fn binning_and_junking_also_leave_the_inbox() {
        // Leaving INBOX on means the message shows in both places.
        assert_eq!(move_delta("trash"), (vec!["TRASH"], vec!["INBOX"]));
        assert_eq!(move_delta("junk"), (vec!["SPAM"], vec!["INBOX"]));
    }

    #[test]
    fn base64url_decodes_with_or_without_padding() {
        // Gmail omits padding; some proxies add it back.
        assert_eq!(decode_base64url("aGVsbG8").unwrap(), b"hello");
        assert_eq!(decode_base64url("aGVsbG8=").unwrap(), b"hello");
        // The two characters that differ from standard base64: `-` is 62
        // where standard has `+`, and `_` is 63 where standard has `/`. A
        // decoder that forgets to translate them mangles roughly one message
        // byte in thirty.
        assert_eq!(decode_base64url("--__").unwrap(), vec![251, 239, 255]);
        assert_eq!(
            decode_base64url("--__").unwrap(),
            decode_base64url("++//").unwrap(),
            "the url-safe alphabet did not map onto the standard one"
        );
    }

    #[test]
    fn a_history_page_folds_every_kind_of_change_into_one_visit_each() {
        // A message touched three ways in one window is one request, not three.
        let records = vec![json!({
            "messagesAdded": [ { "message": { "id": "M1" } } ],
            "labelsAdded": [ { "message": { "id": "M1" } }, { "message": { "id": "M2" } } ],
            "labelsRemoved": [ { "message": { "id": "M1" } } ]
        })];

        let mut delta = HistoryDelta::default();
        fold_history(&records, &mut delta);

        assert_eq!(delta.touched, vec!["M1".to_owned(), "M2".to_owned()]);
        assert!(delta.deleted.is_empty());
    }

    #[test]
    fn a_message_deleted_in_the_same_window_is_not_also_fetched() {
        // The records are ordered but the deletion is the later fact whatever
        // order they arrive in; fetching it would 404, or worse, succeed.
        let records = vec![json!({
            "messagesAdded": [ { "message": { "id": "M1" } } ],
            "messagesDeleted": [ { "message": { "id": "M1" } } ]
        })];

        let mut delta = HistoryDelta::default();
        fold_history(&records, &mut delta);

        assert!(delta.touched.is_empty());
        assert_eq!(delta.deleted, vec!["M1".to_owned()]);
    }

    #[test]
    fn metadata_survives_a_message_with_no_labels_at_all() {
        let message = parse_metadata(&json!({ "id": "M1", "internalDate": "1785834000000" }))
            .expect("a message");

        assert_eq!(message.folder(), "archive");
        assert_eq!(message.internal_date_ms, 1_785_834_000_000);
        assert!(
            message.flags().seen,
            "a message with no UNREAD label is read"
        );
    }

    #[test]
    fn a_password_is_refused_rather_than_sent() {
        // Google withdrew password authentication for this API; sending one
        // produces a 401 that reads as a wrong password.
        let error = Session::connect(&Credentials::Password("app-password".into())).unwrap_err();
        assert!(matches!(error, Error::Auth(_)), "got {error}");
    }

    #[test]
    fn every_maintained_folder_has_a_special_use() {
        // The store keys its layout on this, and an unrecognised folder would
        // land in a directory named after a slug nobody chose.
        for folder in folders() {
            assert!(
                folder.special_use.is_some(),
                "{} has no special use",
                folder.wire_name
            );
        }
    }
}

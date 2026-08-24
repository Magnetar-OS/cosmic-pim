// SPDX-License-Identifier: MPL-2.0

//! JMAP for Mail (RFC 8620, RFC 8621).
//!
//! # Why this is not an IMAP variant
//!
//! IMAP is a stateful session over a socket: SELECT a mailbox, hold it, issue
//! commands against it. JMAP is a stateless HTTP API where every request
//! carries its own context and several operations are batched into one round
//! trip. Nothing about the transport, the identity model, or the change
//! tracking is shared, which is why this sits beside [`crate::imap`] rather
//! than behind a flag on it — the same reasoning that keeps `mail` beside
//! `caldav` instead of under it.
//!
//! What *is* shared is everything below: the maildir, the index, threading,
//! search. A JMAP mailbox lands on disk in exactly the same shape an IMAP one
//! does, and every reader of that directory is none the wiser.
//!
//! # Verbatim bytes, over an API that would rather not
//!
//! JMAP's natural unit is a parsed object — `Email/get` returns headers as
//! fields and the body as structured parts. Storing that would break the
//! invariant this whole suite is built on: the message on disk must be the
//! bytes the server holds, because a re-serialised message has a different
//! MIME structure and an invalid DKIM signature, and the loss is invisible
//! until somebody forwards it.
//!
//! So `Email/get` is asked only for metadata plus `blobId`, and the message
//! itself is fetched from the download endpoint, which serves the original
//! RFC 5322 octets. One extra request per message, and it is not optional.
//!
//! # Identity
//!
//! JMAP ids are opaque strings; the rest of this crate is keyed by numeric UID.
//! As in [`crate::pop3`], each id is assigned a local UID once and the mapping
//! is kept in a sidecar — so the store, and everything reading it, is unchanged.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::model::Flags;
use crate::sasl::Credentials;
use crate::store::{Cursor, MailStore, RemoteMessage};

/// JMAP requests are ordinary HTTPS and should not hold a pass open.
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// The core and mail capability URIs, sent with every request that uses them.
const CAP_CORE: &str = "urn:ietf:params:jmap:core";
const CAP_MAIL: &str = "urn:ietf:params:jmap:mail";

/// How many emails to ask for in one `Email/get`. Servers cap this themselves
/// (`maxObjectsInGet`); this is the client-side bound that keeps one response
/// from being tens of megabytes of metadata.
const GET_BATCH: usize = 100;

/// How many changes to ask for in one `Email/changes`. A server may return
/// fewer and set `hasMoreChanges`, which the caller loops on.
const CHANGES_BATCH: usize = 500;

/// Checks that an `Email/set` actually did what it was asked, for one object.
///
/// Positive confirmation, not absence of an error. JMAP reports per-object
/// failures in `notUpdated` rather than as a method error, and it names each
/// success in `updated` — so a response that mentions the id in *neither* did
/// nothing at all. Reading that as success drops the queue entry with the
/// user's change unmade and nothing anywhere to say so, which is the exact
/// shape of failure the durable queue exists to prevent.
fn check_updated(responses: &[Value], id: &str) -> Result<()> {
    let args = responses
        .first()
        .and_then(|entry| entry.get(1))
        .ok_or_else(|| Error::Jmap("Email/set returned nothing".to_owned()))?;

    if let Some(reason) = args.get("notUpdated").and_then(|not| not.get(id)) {
        return Err(Error::Jmap(format!(
            "the server refused the change to {id}: {reason}"
        )));
    }

    // `updated` maps id → null (or an object of server-set properties), so the
    // key being present is the confirmation, whatever its value.
    let confirmed = args
        .get("updated")
        .and_then(Value::as_object)
        .is_some_and(|updated| updated.contains_key(id));

    if confirmed {
        Ok(())
    } else {
        Err(Error::Jmap(format!(
            "the server acknowledged neither success nor failure for {id}"
        )))
    }
}

/// The `type` of a per-call error in a response list, if there is one.
fn method_error(responses: &[Value]) -> Option<String> {
    responses.iter().find_map(|entry| {
        (entry.get(0).and_then(Value::as_str) == Some("error")).then(|| {
            entry
                .get(1)
                .and_then(|args| args.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned()
        })
    })
}

/// What changed in an account since a given state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    pub created: Vec<String>,
    pub updated: Vec<String>,
    pub destroyed: Vec<String>,
    /// The state these changes bring the client up to.
    pub new_state: String,
    /// The server truncated the answer; ask again from `new_state`.
    pub has_more: bool,
}

/// The session resource, as the server describes itself (RFC 8620 §2).
#[derive(Debug, Clone, Deserialize)]
struct SessionResource {
    #[serde(rename = "apiUrl")]
    api_url: String,
    #[serde(rename = "downloadUrl")]
    download_url: String,
    #[serde(rename = "primaryAccounts", default)]
    primary_accounts: BTreeMap<String, String>,
    #[serde(default)]
    capabilities: BTreeMap<String, Value>,
}

/// A JMAP mailbox — the counterpart of an IMAP folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JmapMailbox {
    pub id: String,
    pub name: String,
    /// `inbox`, `sent`, `drafts`, `trash`, `junk`, `archive` — RFC 8621 §2.
    /// The same information IMAP's SPECIAL-USE carries, and the reason a client
    /// can find the Sent folder without guessing at its name in the user's own
    /// language.
    pub role: Option<String>,
    pub total: u32,
    pub unread: u32,
}

/// One email's metadata. The bytes come separately — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JmapEmail {
    pub id: String,
    pub blob_id: String,
    pub keywords: Flags,
    /// When the server received it, in epoch milliseconds.
    pub received_at_ms: i64,
    pub size: u64,
}

/// An authenticated JMAP session.
pub struct Session {
    http: reqwest::blocking::Client,
    authorization: String,
    api_url: String,
    download_url: String,
    account_id: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JmapSession")
            .field("api_url", &self.api_url)
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Fetches the session resource and picks the mail account.
    ///
    /// JMAP authenticates with an `Authorization` header and nothing else —
    /// there is no login command — so a password here is HTTP Basic and a
    /// token is Bearer, exactly as in the CalDAV client.
    pub fn connect(session_url: &str, username: &str, credentials: &Credentials) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|why| Error::Jmap(why.to_string()))?;

        let authorization = match credentials {
            Credentials::OAuth2(token) => format!("Bearer {token}"),
            Credentials::Password(password) => {
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{username}:{password}"),
                );
                format!("Basic {encoded}")
            }
        };

        let response = http
            .get(session_url)
            .header("Authorization", &authorization)
            .header("Accept", "application/json")
            .send()
            .map_err(|why| Error::Jmap(format!("fetching the JMAP session: {why}")))?;

        let status = response.status().as_u16();
        let body = response
            .text()
            .map_err(|why| Error::Jmap(why.to_string()))?;

        if status == 401 || status == 403 {
            return Err(Error::Auth(format!(
                "the JMAP server rejected our credentials (HTTP {status})"
            )));
        }
        if !(200..300).contains(&status) {
            return Err(Error::Jmap(format!(
                "the JMAP session resource returned HTTP {status}"
            )));
        }

        let session: SessionResource = serde_json::from_str(&body)
            .map_err(|why| Error::Jmap(format!("unreadable JMAP session resource: {why}")))?;

        if !session.capabilities.contains_key(CAP_MAIL) {
            return Err(Error::Jmap(
                "this JMAP server does not offer mail".to_owned(),
            ));
        }

        let account_id = session
            .primary_accounts
            .get(CAP_MAIL)
            .cloned()
            .ok_or_else(|| Error::Jmap("the JMAP session names no mail account".to_owned()))?;

        Ok(Self {
            http,
            authorization,
            api_url: session.api_url,
            download_url: session.download_url,
            account_id,
        })
    }

    /// The account this session operates on.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Posts a batch of method calls and returns the responses in order.
    ///
    /// A JMAP request can carry several calls, and a server that supports back
    /// references resolves them against each other server-side. That is the
    /// difference between one round trip and three, and on a mailbox sync it is
    /// most of the wall-clock time.
    fn request(&self, calls: Value) -> Result<Vec<Value>> {
        let responses = self.request_raw(calls)?;

        // An `error` in the *list* is a per-call failure, not a transport one,
        // and it carries the reason. Returning the raw array and letting each
        // caller guess would lose that.
        if let Some(kind) = method_error(&responses) {
            return Err(Error::Jmap(format!(
                "the server refused the request: {kind}"
            )));
        }

        Ok(responses)
    }

    /// As [`Self::request`], but a per-call error comes back as data.
    ///
    /// Exactly one caller wants that: `cannotCalculateChanges` is a routine
    /// answer meaning "my history does not reach back that far", and the right
    /// response is a full resync rather than a failed pass.
    fn request_raw(&self, calls: Value) -> Result<Vec<Value>> {
        let body = json!({
            "using": [CAP_CORE, CAP_MAIL],
            "methodCalls": calls,
        });

        let response = self
            .http
            .post(&self.api_url)
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|why| Error::Jmap(why.to_string()))?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .map_err(|why| Error::Jmap(why.to_string()))?;

        if status == 401 || status == 403 {
            return Err(Error::Auth(format!(
                "the JMAP server rejected our credentials (HTTP {status})"
            )));
        }
        if !(200..300).contains(&status) {
            return Err(Error::Jmap(format!(
                "JMAP request returned HTTP {status}: {}",
                text.chars().take(200).collect::<String>()
            )));
        }

        let parsed: Value = serde_json::from_str(&text)
            .map_err(|why| Error::Jmap(format!("unreadable JMAP response: {why}")))?;

        let responses = parsed
            .get("methodResponses")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Jmap("JMAP response carried no methodResponses".to_owned()))?;

        Ok(responses.clone())
    }

    /// Every mailbox in the account.
    pub fn mailboxes(&self) -> Result<Vec<JmapMailbox>> {
        let responses = self.request(json!([[
            "Mailbox/get",
            { "accountId": self.account_id, "ids": null },
            "0"
        ]]))?;

        let list = responses
            .first()
            .and_then(|entry| entry.get(1))
            .and_then(|args| args.get("list"))
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Jmap("Mailbox/get returned no list".to_owned()))?;

        Ok(list
            .iter()
            .filter_map(|item| {
                Some(JmapMailbox {
                    id: item.get("id")?.as_str()?.to_owned(),
                    name: item.get("name")?.as_str().unwrap_or_default().to_owned(),
                    role: item
                        .get("role")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    total: item
                        .get("totalEmails")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        .min(u64::from(u32::MAX)) as u32,
                    unread: item
                        .get("unreadEmails")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        .min(u64::from(u32::MAX)) as u32,
                })
            })
            .collect())
    }

    /// The ids of the emails in one mailbox, newest first.
    ///
    /// `limit` bounds the backfill: a twenty-year archive should not be
    /// downloaded in one pass, and the sort makes the bound mean "the most
    /// recent N" rather than an arbitrary N.
    pub fn query(&self, mailbox_id: &str, limit: usize) -> Result<Vec<String>> {
        let responses = self.request(json!([[
            "Email/query",
            {
                "accountId": self.account_id,
                "filter": { "inMailbox": mailbox_id },
                "sort": [ { "property": "receivedAt", "isAscending": false } ],
                "limit": limit,
                "calculateTotal": false
            },
            "0"
        ]]))?;

        let ids = responses
            .first()
            .and_then(|entry| entry.get(1))
            .and_then(|args| args.get("ids"))
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Jmap("Email/query returned no ids".to_owned()))?;

        Ok(ids
            .iter()
            .filter_map(|id| id.as_str().map(ToOwned::to_owned))
            .collect())
    }

    /// The account's current `Email` state string, without fetching anything.
    ///
    /// Used to open an incremental era: a full pass records the state it read
    /// *at*, and the next pass asks what has changed since.
    pub fn email_state(&self) -> Result<String> {
        // `Email/get` with an empty id list is the cheapest call that returns a
        // state string. There is no "give me only the state" method.
        let responses = self.request(json!([[
            "Email/get",
            { "accountId": self.account_id, "ids": [] },
            "0"
        ]]))?;

        responses
            .first()
            .and_then(|entry| entry.get(1))
            .and_then(|args| args.get("state"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| Error::Jmap("Email/get returned no state".to_owned()))
    }

    /// What has changed in the account since `since_state`.
    ///
    /// `Ok(None)` means the server cannot answer — its change history does not
    /// reach back that far, which is a routine answer after a long offline
    /// period and not a failure. The caller resyncs in full.
    pub fn changes(&self, since_state: &str) -> Result<Option<Changes>> {
        let responses = self.request_raw(json!([[
            "Email/changes",
            {
                "accountId": self.account_id,
                "sinceState": since_state,
                "maxChanges": CHANGES_BATCH
            },
            "0"
        ]]))?;

        if let Some(kind) = method_error(&responses) {
            if kind == "cannotCalculateChanges" {
                tracing::info!(
                    "the server cannot report changes since our state; resyncing in full"
                );
                return Ok(None);
            }
            return Err(Error::Jmap(format!(
                "Email/changes was refused: {kind}"
            )));
        }

        let args = responses
            .first()
            .and_then(|entry| entry.get(1))
            .ok_or_else(|| Error::Jmap("Email/changes returned nothing".to_owned()))?;

        let ids = |field: &str| -> Vec<String> {
            args.get(field)
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(|id| id.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };

        Ok(Some(Changes {
            created: ids("created"),
            updated: ids("updated"),
            destroyed: ids("destroyed"),
            new_state: args
                .get("newState")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            has_more: args
                .get("hasMoreChanges")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }))
    }

    /// Metadata for a batch of emails. Never the body — see the module docs.
    pub fn get(&self, ids: &[String]) -> Result<Vec<JmapEmail>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let responses = self.request(json!([[
            "Email/get",
            {
                "accountId": self.account_id,
                "ids": ids,
                // blobId is what makes the verbatim fetch possible; without it
                // the only way to get a message is to reassemble it, which is
                // the thing this crate refuses to do.
                "properties": ["id", "blobId", "keywords", "receivedAt", "size"]
            },
            "0"
        ]]))?;

        let list = responses
            .first()
            .and_then(|entry| entry.get(1))
            .and_then(|args| args.get("list"))
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Jmap("Email/get returned no list".to_owned()))?;

        Ok(list.iter().filter_map(parse_email).collect())
    }

    /// Metadata plus mailbox membership, for the incremental path.
    ///
    /// `Email/changes` is account-wide — it reports every email that changed,
    /// in any mailbox — so the membership is what says whether a change is this
    /// mailbox's business. Asking for it only here keeps it off the full-sync
    /// path, where the query has already filtered.
    pub fn get_with_mailboxes(&self, ids: &[String]) -> Result<Vec<(JmapEmail, Vec<String>)>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let responses = self.request(json!([[
            "Email/get",
            {
                "accountId": self.account_id,
                "ids": ids,
                "properties": ["id", "blobId", "keywords", "receivedAt", "size", "mailboxIds"]
            },
            "0"
        ]]))?;

        let list = responses
            .first()
            .and_then(|entry| entry.get(1))
            .and_then(|args| args.get("list"))
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Jmap("Email/get returned no list".to_owned()))?;

        Ok(list
            .iter()
            .filter_map(|item| {
                let email = parse_email(item)?;
                // `mailboxIds` is a set: `{ "mbox-1": true }`.
                let mailboxes = item
                    .get("mailboxIds")
                    .and_then(Value::as_object)
                    .map(|map| {
                        map.iter()
                            .filter(|(_, v)| v.as_bool().unwrap_or(false))
                            .map(|(id, _)| id.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                Some((email, mailboxes))
            })
            .collect())
    }

    /// Moves an email from one mailbox to another.
    ///
    /// A JMAP move is a `mailboxIds` patch, not a copy and a delete: the
    /// message keeps its id, its blob, and its keywords, so nothing has to be
    /// re-downloaded anywhere and no other client sees it vanish and reappear.
    /// The patch form is used rather than a whole replacement `mailboxIds` set,
    /// because a message can legitimately be in more than one mailbox and
    /// replacing the set would silently remove it from the others.
    pub fn move_email(&self, id: &str, from_mailbox: &str, to_mailbox: &str) -> Result<()> {
        let responses = self.request(json!([[
            "Email/set",
            {
                "accountId": self.account_id,
                "update": {
                    id: {
                        format!("mailboxIds/{from_mailbox}"): null,
                        format!("mailboxIds/{to_mailbox}"): true
                    }
                }
            },
            "0"
        ]]))?;

        check_updated(&responses, id)
    }

    /// Destroys an email outright. There is no undo and no Trash.
    pub fn destroy_email(&self, id: &str) -> Result<()> {
        let responses = self.request(json!([[
            "Email/set",
            { "accountId": self.account_id, "destroy": [id] },
            "0"
        ]]))?;

        let args = responses
            .first()
            .and_then(|entry| entry.get(1))
            .ok_or_else(|| Error::Jmap("Email/set returned nothing".to_owned()))?;

        if let Some(reason) = args.get("notDestroyed").and_then(|not| not.get(id)) {
            return Err(Error::Jmap(format!(
                "the server refused to destroy {id}: {reason}"
            )));
        }

        // As with an update: the id has to appear in `destroyed` for this to
        // have happened.
        let confirmed = args
            .get("destroyed")
            .and_then(Value::as_array)
            .is_some_and(|list| list.iter().any(|d| d.as_str() == Some(id)));

        if confirmed {
            Ok(())
        } else {
            Err(Error::Jmap(format!(
                "the server acknowledged neither success nor failure for destroying {id}"
            )))
        }
    }

    /// Downloads the original RFC 5322 octets for a blob.
    pub fn download(&self, blob_id: &str) -> Result<Vec<u8>> {
        let url = self
            .download_url
            .replace("{accountId}", &self.account_id)
            .replace("{blobId}", blob_id)
            .replace("{type}", "application/octet-stream")
            .replace("{name}", "message.eml");

        let response = self
            .http
            .get(&url)
            .header("Authorization", &self.authorization)
            .send()
            .map_err(|why| Error::Jmap(format!("downloading {blob_id}: {why}")))?;

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::Jmap(format!(
                "downloading {blob_id} returned HTTP {status}"
            )));
        }

        response
            .bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|why| Error::Jmap(why.to_string()))
    }

    /// Replaces the keywords on one email.
    ///
    /// The whole set rather than a patch: JMAP accepts both, and sending the
    /// set the client believes in makes the operation idempotent — a retry
    /// after an ambiguous failure converges instead of toggling.
    pub fn set_keywords(&self, id: &str, flags: Flags) -> Result<()> {
        let responses = self.request(json!([[
            "Email/set",
            {
                "accountId": self.account_id,
                "update": { id: { "keywords": keywords_of(flags) } }
            },
            "0"
        ]]))?;

        check_updated(&responses, id)
    }
}

/// Writeback over JMAP: a [`crate::push::Writeback`] bound to one mailbox.
///
/// The queue is keyed by local UID and JMAP is keyed by opaque id, so
/// something has to hold the mapping while a drain runs — that is this. It
/// borrows the state rather than owning a copy, because a `Move` has to forget
/// the id it just sent away and the next pull must not then re-download it
/// under a stale UID.
pub struct JmapWriteback<'a> {
    session: &'a Session,
    mailbox_id: &'a str,
    state: &'a mut JmapState,
}

impl<'a> JmapWriteback<'a> {
    #[must_use]
    pub fn new(session: &'a Session, mailbox_id: &'a str, state: &'a mut JmapState) -> Self {
        Self {
            session,
            mailbox_id,
            state,
        }
    }

    /// The server id for a local UID, or an error naming what is missing.
    ///
    /// A queued operation for a UID with no id means the sidecar and the
    /// maildir have diverged — recoverable, but only by a full read, so it is
    /// reported as needing reconciliation rather than retried forever.
    fn id_for(&self, uid: u32) -> Result<String> {
        self.state.id_of(uid).map(ToOwned::to_owned).ok_or_else(|| {
            Error::UidValidityChanged {
                mailbox: self.mailbox_id.to_owned(),
                had: uid,
                now: 0,
            }
        })
    }
}

impl crate::push::Writeback for JmapWriteback<'_> {
    fn store_flags(&mut self, uid: u32, flags: Flags) -> Result<()> {
        let id = self.id_for(uid)?;
        self.session.set_keywords(&id, flags)
    }

    fn move_message(&mut self, uid: u32, destination: &str) -> Result<()> {
        let id = self.id_for(uid)?;
        self.session
            .move_email(&id, self.mailbox_id, destination)?;
        // It is no longer this mailbox's message. Keeping the mapping would
        // have the next incremental pass see an id it still believes it holds.
        self.state.forget(&id);
        Ok(())
    }

    fn delete_message(&mut self, uid: u32) -> Result<()> {
        let id = self.id_for(uid)?;
        self.session.destroy_email(&id)?;
        self.state.forget(&id);
        Ok(())
    }
}

/// JMAP keywords → our flags.
///
/// RFC 8621 §4.1.1 defines the `$`-prefixed set as the IMAP system flags, minus
/// `\Deleted` and `\Recent`, which JMAP deliberately has no equivalent of: a
/// message is in a mailbox or it is not, and the IMAP dance of marking a
/// message deleted and expunging later does not exist. Nothing is lost by that,
/// but a client that maps `$deleted` onto anything is inventing it.
fn flags_of(keywords: &Value) -> Flags {
    let has = |name: &str| {
        keywords
            .get(name)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    Flags {
        seen: has("$seen"),
        answered: has("$answered"),
        flagged: has("$flagged"),
        draft: has("$draft"),
        deleted: false,
        passed: has("$forwarded"),
    }
}

/// Our flags → JMAP keywords, as a set map.
fn keywords_of(flags: Flags) -> Value {
    let mut map = serde_json::Map::new();
    if flags.seen {
        map.insert("$seen".to_owned(), json!(true));
    }
    if flags.answered {
        map.insert("$answered".to_owned(), json!(true));
    }
    if flags.flagged {
        map.insert("$flagged".to_owned(), json!(true));
    }
    if flags.draft {
        map.insert("$draft".to_owned(), json!(true));
    }
    if flags.passed {
        map.insert("$forwarded".to_owned(), json!(true));
    }
    Value::Object(map)
}

fn parse_email(item: &Value) -> Option<JmapEmail> {
    Some(JmapEmail {
        id: item.get("id")?.as_str()?.to_owned(),
        blob_id: item.get("blobId")?.as_str()?.to_owned(),
        keywords: item.get("keywords").map(flags_of).unwrap_or_default(),
        received_at_ms: item
            .get("receivedAt")
            .and_then(Value::as_str)
            .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
            .map(|at| at.timestamp_millis())
            .unwrap_or_default(),
        size: item.get("size").and_then(Value::as_u64).unwrap_or(0),
    })
}

/// What JMAP has to remember between passes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JmapState {
    /// Server email id → the local UID it was assigned.
    #[serde(default)]
    seen: BTreeMap<String, u32>,
    #[serde(default = "one")]
    next_uid: u32,
    /// The account `Email` state this mailbox has been brought up to.
    ///
    /// Absent means no incremental era has been opened yet, and the next pass
    /// is a full one. Present means the next pass can ask the server what
    /// changed rather than re-reading the mailbox — the difference between a
    /// round trip proportional to the mailbox and one proportional to the news.
    ///
    /// Account-wide even though it is stored per mailbox, because that is what
    /// `Email/changes` is scoped to. Each mailbox independently tracks the
    /// state it has applied, which costs one extra `Email/changes` per mailbox
    /// and keeps every mailbox recoverable on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email_state: Option<String>,
}

fn one() -> u32 {
    1
}

const STATE_FILE: &str = ".jmap-state.json";

impl JmapState {
    /// Reads the sidecar beside a maildir, or starts empty.
    pub fn load(maildir: &Path) -> Self {
        match std::fs::read_to_string(maildir.join(STATE_FILE)) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|why| {
                tracing::warn!(
                    path = %maildir.display(), %why,
                    "unreadable JMAP sidecar; treating the mailbox as new"
                );
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    /// Writes the sidecar atomically — a torn one costs a full re-download.
    pub fn save(&self, maildir: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|why| Error::Jmap(format!("serialising JMAP state: {why}")))?;
        cosmic_pim_core::atomic::write(&maildir.join(STATE_FILE), &json, None)
            .map(|_| ())
            .map_err(|why| Error::Jmap(format!("writing JMAP state: {why}")))
    }

    /// The local UID for a server id, if it has one.
    #[must_use]
    pub fn uid_of(&self, id: &str) -> Option<u32> {
        self.seen.get(id).copied()
    }

    /// The server id behind a local UID.
    #[must_use]
    pub fn id_of(&self, uid: u32) -> Option<&str> {
        self.seen
            .iter()
            .find(|(_, value)| **value == uid)
            .map(|(id, _)| id.as_str())
    }

    fn uid_for(&mut self, id: &str) -> u32 {
        if let Some(uid) = self.seen.get(id) {
            return *uid;
        }
        let uid = self.next_uid;
        self.next_uid = self.next_uid.saturating_add(1);
        self.seen.insert(id.to_owned(), uid);
        uid
    }

    fn forget(&mut self, id: &str) {
        self.seen.remove(id);
    }

    /// The state this mailbox has been brought up to, if any.
    #[must_use]
    pub fn email_state(&self) -> Option<&str> {
        self.email_state.as_deref()
    }

    /// Discards the incremental era, so the next pass reads the mailbox in
    /// full. What a `cannotCalculateChanges` answer amounts to.
    pub fn reset_era(&mut self) {
        self.email_state = None;
    }
}

/// What one JMAP pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JmapOutcome {
    pub fetched: usize,
    pub reflagged: usize,
    pub removed: usize,
    /// What the local writeback queue did before the pull ran.
    pub pushed: crate::push::DrainOutcome,
}

/// JMAP mailboxes are identified by string, and never renumber, so the store's
/// UIDVALIDITY is a constant that exists to keep the shared shape honest.
pub const JMAP_UID_VALIDITY: u32 = 1;

/// Runs one pass over one mailbox, incrementally where it can.
///
/// The first pass reads the mailbox in full and records the account state it
/// read at. Every pass after that asks the server what has changed since —
/// which is a round trip proportional to the news rather than to the mailbox,
/// and is the difference between a five-second poll being affordable and not.
///
/// A server that cannot answer (`cannotCalculateChanges`, after a long enough
/// gap) drops the client back to a full read, which is why the full path stays
/// and is not an optimisation to be removed later.
pub fn sync_mailbox(
    session: &Session,
    mailbox_id: &str,
    store: &mut (impl MailStore + crate::push::PushQueue),
    state: &mut JmapState,
    limit: usize,
    now_ms: i64,
) -> Result<JmapOutcome> {
    // Push before pull, for the reason it is done everywhere else in this
    // suite: the other order lets the pull overwrite a local flag change with
    // the server's older copy, after which the queued push re-sends what was
    // just clobbered. It presents as read marks flickering back.
    let pushed = {
        let mut writeback = JmapWriteback::new(session, mailbox_id, state);
        crate::push::drain(&mut writeback, store, now_ms)
    };

    let mut outcome = sync_after_push(session, mailbox_id, store, state, limit)?;
    outcome.pushed = pushed;
    Ok(outcome)
}

fn sync_after_push(
    session: &Session,
    mailbox_id: &str,
    store: &mut impl MailStore,
    state: &mut JmapState,
    limit: usize,
) -> Result<JmapOutcome> {
    if let Some(since) = state.email_state().map(ToOwned::to_owned) {
        match sync_incremental(session, mailbox_id, store, state, &since)? {
            Some(outcome) => return Ok(outcome),
            // The server's history does not reach back to our state. Fall
            // through and read the mailbox as it is now.
            None => state.reset_era(),
        }
    }

    sync_full(session, mailbox_id, store, state, limit)
}

/// Applies everything that changed since `since`, or `None` if the server
/// cannot say.
fn sync_incremental(
    session: &Session,
    mailbox_id: &str,
    store: &mut impl MailStore,
    state: &mut JmapState,
    since: &str,
) -> Result<Option<JmapOutcome>> {
    let mut outcome = JmapOutcome::default();
    let mut cursor = since.to_owned();

    loop {
        let Some(changes) = session.changes(&cursor)? else {
            return Ok(None);
        };

        // `created` and `updated` are treated identically on purpose: an email
        // moved *into* this mailbox is reported as updated, not created, and
        // handling only `created` would leave it invisible until a full resync.
        let touched: Vec<String> = changes
            .created
            .iter()
            .chain(&changes.updated)
            .cloned()
            .collect();

        let known = store.state()?;

        for batch in touched.chunks(GET_BATCH) {
            for (email, mailboxes) in session.get_with_mailboxes(batch)? {
                let in_this_mailbox = mailboxes.iter().any(|id| id == mailbox_id);
                let held = state.uid_of(&email.id);

                match (in_this_mailbox, held) {
                    // New here: fetch it.
                    (true, None) => {
                        let uid = state.uid_for(&email.id);
                        let raw = session.download(&email.blob_id)?;
                        store.upsert(&RemoteMessage {
                            uid,
                            flags: email.keywords,
                            raw,
                            internal_date_ms: email.received_at_ms,
                        })?;
                        outcome.fetched += 1;
                    }
                    // Still here, and something about it changed. The only
                    // thing that can have is the flags — the bytes of a message
                    // are immutable — so this must not re-download it.
                    (true, Some(uid)) => {
                        if known.entries.get(&uid) != Some(&email.keywords) {
                            store.set_flags(uid, email.keywords)?;
                            outcome.reflagged += 1;
                        }
                    }
                    // Moved out of this mailbox, into another one.
                    (false, Some(uid)) => {
                        state.forget(&email.id);
                        store.remove(uid)?;
                        outcome.removed += 1;
                    }
                    // Another mailbox's business entirely.
                    (false, None) => {}
                }
            }
        }

        // Deleted outright, rather than moved.
        for id in &changes.destroyed {
            if let Some(uid) = state.uid_of(id) {
                state.forget(id);
                store.remove(uid)?;
                outcome.removed += 1;
            }
        }

        // Only after everything in this window is applied. Advancing first and
        // failing second would skip the window permanently — the same rule the
        // IMAP MODSEQ cursor and the CalDAV ctag follow.
        state.email_state = Some(changes.new_state.clone());
        cursor = changes.new_state;

        if !changes.has_more {
            break;
        }
    }

    store.commit_cursor(Cursor {
        uid_validity: JMAP_UID_VALIDITY,
        last_uid: state.next_uid.saturating_sub(1),
        ..Default::default()
    })?;

    Ok(Some(outcome))
}

/// Reads the mailbox as the server currently has it.
///
/// Fetches what is missing, updates the flags of what changed, and removes what
/// has left. The bytes come from the download endpoint, never from `Email/get`
/// — see the module docs.
fn sync_full(
    session: &Session,
    mailbox_id: &str,
    store: &mut impl MailStore,
    state: &mut JmapState,
    limit: usize,
) -> Result<JmapOutcome> {
    let mut outcome = JmapOutcome::default();

    // Read *before* the query, so a change landing during this pass is caught
    // by the next one rather than skipped by a state that is newer than the
    // data it was recorded with.
    let opened_at = session.email_state()?;

    let ids = session.query(mailbox_id, limit)?;
    let known = store.state()?;

    let mut present: BTreeSet<u32> = BTreeSet::new();

    for batch in ids.chunks(GET_BATCH) {
        for email in session.get(batch)? {
            let uid = state.uid_for(&email.id);
            present.insert(uid);

            match known.entries.get(&uid) {
                // Held already: the only thing that can have changed is the
                // flags, and re-downloading a message to learn that would make
                // the cheap path the expensive one.
                Some(held) => {
                    if *held != email.keywords {
                        store.set_flags(uid, email.keywords)?;
                        outcome.reflagged += 1;
                    }
                }
                None => {
                    let raw = session.download(&email.blob_id)?;
                    store.upsert(&RemoteMessage {
                        uid,
                        flags: email.keywords,
                        raw,
                        internal_date_ms: email.received_at_ms,
                    })?;
                    outcome.fetched += 1;
                }
            }
        }
    }

    // Anything held that the query no longer lists has left the mailbox. The
    // guard is the same one the CalDAV planner uses: a server that answered
    // with nothing while we hold messages is far more likely to be having a
    // moment than to have emptied the mailbox.
    if !ids.is_empty() || known.entries.is_empty() {
        let gone: Vec<u32> = known
            .entries
            .keys()
            .copied()
            .filter(|uid| !present.contains(uid))
            .collect();

        // …but only within the window that was actually queried. A `limit` of
        // 500 over a mailbox of 5000 lists only the newest 500, and treating
        // the other 4500 as deleted would empty the maildir.
        if ids.len() < limit {
            for uid in gone {
                if let Some(id) = state.id_of(uid).map(ToOwned::to_owned) {
                    state.forget(&id);
                }
                store.remove(uid)?;
                outcome.removed += 1;
            }
        }
    } else {
        tracing::warn!(
            mailbox_id,
            held = known.entries.len(),
            "the server listed no messages while we hold some; skipping removals this pass"
        );
    }

    state.email_state = Some(opened_at);

    store.commit_cursor(Cursor {
        uid_validity: JMAP_UID_VALIDITY,
        last_uid: state.next_uid.saturating_sub(1),
        ..Default::default()
    })?;

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_method_error_is_found_wherever_it_sits_in_the_batch() {
        // A batch's second call can fail while its first succeeds, and reading
        // only the first would report success over a refused request.
        let responses = vec![
            json!(["Email/get", { "list": [] }, "0"]),
            json!(["error", { "type": "cannotCalculateChanges" }, "1"]),
        ];

        assert_eq!(
            method_error(&responses).as_deref(),
            Some("cannotCalculateChanges")
        );
        assert_eq!(method_error(&responses[..1]), None);
    }

    #[test]
    fn an_error_with_no_type_still_reports_as_one() {
        let responses = vec![json!(["error", {}, "0"])];
        assert_eq!(method_error(&responses).as_deref(), Some("unknown"));
    }

    #[test]
    fn a_set_that_says_nothing_is_not_a_success() {
        // The failure this catches is silent: the queue entry is dropped, the
        // UI reports the change saved, and the server never made it. Absence
        // of an error is not confirmation.
        let responses = vec![json!(["Email/set", { "accountId": "a" }, "0"])];
        assert!(check_updated(&responses, "M1").is_err());
    }

    #[test]
    fn a_set_confirms_by_naming_the_object_it_changed() {
        let responses = vec![json!(["Email/set", { "updated": { "M1": null } }, "0"])];
        assert!(check_updated(&responses, "M1").is_ok());
        // …and confirming a *different* object is not confirming this one.
        assert!(check_updated(&responses, "M2").is_err());
    }

    #[test]
    fn a_refusal_carries_the_servers_reason() {
        let responses = vec![json!([
            "Email/set",
            { "notUpdated": { "M1": { "type": "forbidden" } } },
            "0"
        ])];

        let error = check_updated(&responses, "M1").unwrap_err();

        assert!(error.to_string().contains("forbidden"), "got {error}");
    }

    #[test]
    fn resetting_the_era_forces_the_next_pass_to_read_in_full() {
        let mut state = JmapState {
            email_state: Some("42".into()),
            ..Default::default()
        };
        assert_eq!(state.email_state(), Some("42"));

        state.reset_era();

        assert_eq!(state.email_state(), None);
    }

    #[test]
    fn the_era_survives_a_round_trip_through_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = JmapState::default();
        state.uid_for("M1");
        state.email_state = Some("state-7".into());
        state.save(dir.path()).unwrap();

        assert_eq!(
            JmapState::load(dir.path()).email_state(),
            Some("state-7"),
            "a restart would re-read every mailbox in full"
        );
    }

    #[test]
    fn keywords_map_to_flags_both_ways() {
        let flags = Flags {
            seen: true,
            answered: true,
            flagged: false,
            draft: false,
            deleted: false,
            passed: true,
        };

        let keywords = keywords_of(flags);
        assert_eq!(keywords.get("$seen").and_then(Value::as_bool), Some(true));
        assert_eq!(keywords.get("$answered").and_then(Value::as_bool), Some(true));
        assert!(keywords.get("$flagged").is_none(), "a false keyword was sent as present");
        assert_eq!(flags_of(&keywords), flags);
    }

    #[test]
    fn jmap_has_no_deleted_keyword_and_none_is_invented() {
        // RFC 8621 deliberately drops \Deleted: a message is in a mailbox or it
        // is not. Mapping it onto something would make a local mark look as
        // though the server agreed with it.
        let flags = Flags {
            deleted: true,
            ..Default::default()
        };
        assert_eq!(keywords_of(flags), json!({}));
        assert!(!flags_of(&json!({ "$deleted": true })).deleted);
    }

    #[test]
    fn an_unknown_keyword_is_ignored_rather_than_failing() {
        // Servers and other clients set their own; `$junk` and `$notjunk` are
        // common, and a strict reader would reject half the mailbox.
        let flags = flags_of(&json!({ "$seen": true, "$junk": true, "custom": true }));
        assert!(flags.seen);
        assert!(!flags.flagged);
    }

    #[test]
    fn an_email_without_a_blob_id_is_skipped_rather_than_stored_empty() {
        // The blob id is the only route to the original bytes. An object
        // without one cannot be stored verbatim, and storing a reassembled
        // approximation is what this crate refuses to do.
        assert!(parse_email(&json!({ "id": "M1" })).is_none());
        assert!(parse_email(&json!({ "id": "M1", "blobId": "B1" })).is_some());
    }

    #[test]
    fn received_at_becomes_epoch_milliseconds() {
        let email = parse_email(&json!({
            "id": "M1",
            "blobId": "B1",
            "receivedAt": "2026-08-04T09:00:00Z"
        }))
        .expect("an email");

        assert_eq!(email.received_at_ms, 1_785_834_000_000);
    }

    #[test]
    fn an_undated_email_is_not_a_parse_failure() {
        // A missing receivedAt is a poor sort key, not a reason to drop mail.
        let email = parse_email(&json!({ "id": "M1", "blobId": "B1" })).expect("an email");
        assert_eq!(email.received_at_ms, 0);
    }

    #[test]
    fn a_local_uid_is_assigned_once_per_server_id() {
        let mut state = JmapState::default();
        let first = state.uid_for("M1");

        assert_eq!(state.uid_for("M1"), first);
        assert_ne!(state.uid_for("M2"), first);
        assert_eq!(state.id_of(first), Some("M1"));
    }

    #[test]
    fn the_sidecar_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = JmapState::default();
        let uid = state.uid_for("M1");
        state.save(dir.path()).unwrap();

        assert_eq!(JmapState::load(dir.path()).uid_of("M1"), Some(uid));
    }
}

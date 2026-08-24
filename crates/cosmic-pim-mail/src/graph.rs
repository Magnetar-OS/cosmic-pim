// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The delta-query state machine, the `@removed.reason` distinction, and the
// Exchange datetime fallback ladder are ported from `src-tauri/src/graph.rs`
// in the Meltemi project, which credits ratatoskr (Apache-2.0) for the wire
// protocol and ravn for the removed-reason idea. The storage is new: the donor
// drove SQLite, this drives a maildir. See NOTICE and LICENSING.md.

//! Microsoft Graph as a mail engine, for Microsoft 365 accounts.
//!
//! # Why, given Outlook still speaks IMAP
//!
//! Because increasingly it does not. Microsoft has been withdrawing IMAP and
//! SMTP AUTH from tenants by default, and a tenant administrator can turn both
//! off entirely — at which point Graph is the only way in. This module is the
//! answer to "our IT department disabled IMAP", which is not a hypothetical.
//!
//! # It does not break verbatim storage
//!
//! `GET /me/messages/{id}/$value` returns the message as raw RFC 5322. So, as
//! with the Gmail and JMAP engines, the API is a *change feed* and the content
//! is fetched as the server's own octets. Graph's JSON `body` field is a
//! rendered representation, not the message, and storing it would discard the
//! MIME structure and invalidate the signature over it.
//!
//! # Delta queries, one cursor per folder
//!
//! Graph's change feed is per folder: a delta query returns pages, the last of
//! which carries an `@odata.deltaLink` that is the next pass's cursor. Unlike
//! Gmail's account-wide `historyId`, nothing here is shared between folders,
//! so a folder whose pass failed replays only itself.
//!
//! ## The two subtleties that lose mail
//!
//! **`@removed` is not always a deletion.** An entry carrying
//! `@removed.reason == "changed"` is a property update wearing the tombstone
//! shape — Exchange emits it when a message moves out of the *filter*, not out
//! of existence. Treating every `@removed` as a delete silently drops updated
//! mail. Only `deleted`, and the unspecified default, are removals.
//!
//! **A stale `deltaLink` answers 410.** Same decision as everywhere else in
//! this crate: that means "I cannot tell you what changed", never "nothing
//! changed" and never "everything is gone". The folder's cursor is dropped and
//! that folder — only that folder — is read again.
//!
//! # No push
//!
//! Graph change notifications need a public HTTPS webhook renewed every three
//! days. Same infrastructure objection as Gmail's Pub/Sub topic. The caller
//! polls.

use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::folder::{Folder, SpecialUse};
use crate::model::Flags;
use crate::sasl::Credentials;
use crate::store::{Cursor, MailStore, RemoteIds, RemoteMessage};

/// Graph's root. Every path below hangs off `/me`.
pub const BASE: &str = "https://graph.microsoft.com/v1.0";

const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// The properties a delta page needs. Deliberately minimal: the bytes come
/// from `$value`, and asking for `body` here would multiply every page by the
/// size of the mail in it.
const DELTA_SELECT: &str = "id,isRead,flag,parentFolderId,receivedDateTime";

/// The sidecar this engine keeps beside a maildir.
pub const STATE_FILE: &str = ".graph-state.json";

/// Reads a folder's Graph state, or starts empty. The cursor is a `deltaLink`.
#[must_use]
pub fn state(maildir: &Path) -> RemoteIds {
    RemoteIds::load(maildir, STATE_FILE)
}

/// A Graph mail folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphFolder {
    pub id: String,
    pub display_name: String,
    /// Exchange's own name for a special folder, lowercased.
    pub well_known: Option<String>,
    pub total: u32,
    pub unread: u32,
}

impl GraphFolder {
    /// The maildir slug this folder maps to.
    #[must_use]
    pub fn slug(&self) -> String {
        self.well_known
            .as_deref()
            .and_then(slug_for_well_known)
            .map_or_else(|| self.display_name.clone(), ToOwned::to_owned)
    }
}

/// Exchange's well-known folder names, in the spelling Graph returns.
///
/// `junkemail` and `deleteditems` are the two nobody guesses: a client that
/// matches on display names finds neither in a German or Japanese tenant.
#[must_use]
pub fn slug_for_well_known(name: &str) -> Option<&'static str> {
    Some(match name {
        "inbox" => "inbox",
        "sentitems" => "sent",
        "drafts" => "drafts",
        "deleteditems" => "trash",
        "junkemail" => "junk",
        "archive" => "archive",
        _ => return None,
    })
}

/// One message as a delta page describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphMessage {
    pub id: String,
    pub flags: Flags,
    pub parent_folder_id: Option<String>,
    pub received_ms: i64,
}

/// What a `@removed` rider means.
///
/// See the module docs: getting this wrong drops updated mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// The message is gone.
    Deleted,
    /// A property changed and Exchange used the tombstone shape to say so.
    Changed,
}

/// Classifies an `@removed.reason`.
#[must_use]
pub fn classify_removal(reason: Option<&str>) -> Removal {
    match reason {
        Some("changed") => Removal::Changed,
        // `deleted`, and an unspecified reason, are both real removals.
        _ => Removal::Deleted,
    }
}

/// Exchange's datetimes, which are RFC 3339 except when they are not.
///
/// The no-timezone variants are assumed UTC, which is what Exchange means by
/// them. A message with an unparseable date is not dropped — it sorts to the
/// epoch, which is visible and recoverable, where discarding it is neither.
#[must_use]
pub fn parse_datetime_ms(text: &str) -> Option<i64> {
    if let Ok(at) = chrono::DateTime::parse_from_rfc3339(text) {
        return Some(at.timestamp_millis());
    }
    if let Ok(at) = chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(at.and_utc().timestamp_millis());
    }
    chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .map(|at| at.and_utc().timestamp_millis())
}

/// Graph's read and flag state as ours.
#[must_use]
pub fn flags_from(value: &Value) -> Flags {
    Flags {
        // `isRead` is the right way round, unlike Gmail's UNREAD. Absent means
        // read: Exchange omits it only on objects that are not mail.
        seen: value.get("isRead").and_then(Value::as_bool).unwrap_or(true),
        flagged: value
            .get("flag")
            .and_then(|flag| flag.get("flagStatus"))
            .and_then(Value::as_str)
            .is_some_and(|status| status == "flagged"),
        draft: value
            .get("isDraft")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        answered: false,
        deleted: false,
        passed: false,
    }
}

fn parse_message(value: &Value) -> Option<GraphMessage> {
    Some(GraphMessage {
        id: value.get("id")?.as_str()?.to_owned(),
        flags: flags_from(value),
        parent_folder_id: value
            .get("parentFolderId")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        received_ms: value
            .get("receivedDateTime")
            .and_then(Value::as_str)
            .and_then(parse_datetime_ms)
            .unwrap_or_default(),
    })
}

/// An authenticated Graph client.
pub struct Session {
    http: reqwest::blocking::Client,
    authorization: String,
    base: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphSession").finish_non_exhaustive()
    }
}

/// One page of a delta query.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeltaPage {
    Ok {
        value: Vec<Value>,
        /// More pages follow.
        next_link: Option<String>,
        /// Terminal: the next pass's cursor.
        delta_link: Option<String>,
    },
    /// The cursor is stale. See the module docs.
    Expired,
}

impl Session {
    /// Builds a client.
    ///
    /// Graph takes a bearer token only. An app password is refused rather than
    /// sent — Microsoft does not accept one here, and the resulting 401 reads
    /// as a wrong password.
    pub fn connect(credentials: &Credentials) -> Result<Self> {
        Self::connect_to(BASE, credentials)
    }

    /// As [`Self::connect`], against a different root — a national cloud
    /// (`graph.microsoft.us`, `graph.microsoft.de`) or the test harness.
    pub fn connect_to(base: &str, credentials: &Credentials) -> Result<Self> {
        let Credentials::OAuth2(token) = credentials else {
            return Err(Error::Auth(
                "Microsoft Graph takes an OAuth access token, not a password".to_owned(),
            ));
        };

        let http = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|why| Error::Graph(why.to_string()))?;

        Ok(Self {
            http,
            authorization: format!("Bearer {token}"),
            base: base.trim_end_matches('/').to_owned(),
        })
    }

    fn refuse(status: u16, what: &str, body: &str) -> Error {
        let detail = body.chars().take(200).collect::<String>();
        if status == 401 || status == 403 {
            Error::Auth(format!("graph {what} was refused (HTTP {status}): {detail}"))
        } else {
            Error::Graph(format!("graph {what} returned HTTP {status}: {detail}"))
        }
    }

    fn get(&self, url: &str) -> Result<(u16, String)> {
        let response = self
            .http
            .get(url)
            .header("Authorization", &self.authorization)
            .header("Accept", "application/json")
            .send()
            .map_err(|why| Error::Graph(why.to_string()))?;

        let status = response.status().as_u16();
        let body = response
            .text()
            .map_err(|why| Error::Graph(why.to_string()))?;
        Ok((status, body))
    }

    /// Every mail folder in the mailbox.
    pub fn folders(&self) -> Result<Vec<GraphFolder>> {
        let url = format!(
            "{}/me/mailFolders?$top=200&$select=id,displayName,wellKnownName,\
             totalItemCount,unreadItemCount",
            self.base
        );
        let (status, body) = self.get(&url)?;
        if !(200..300).contains(&status) {
            return Err(Self::refuse(status, "mailFolders", &body));
        }

        let page: Value = serde_json::from_str(&body)
            .map_err(|why| Error::Graph(format!("parsing mailFolders: {why}")))?;

        Ok(page
            .get("value")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|item| {
                        Some(GraphFolder {
                            id: item.get("id")?.as_str()?.to_owned(),
                            display_name: item
                                .get("displayName")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                            well_known: item
                                .get("wellKnownName")
                                .and_then(Value::as_str)
                                .map(str::to_ascii_lowercase),
                            total: item
                                .get("totalItemCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0) as u32,
                            unread: item
                                .get("unreadItemCount")
                                .and_then(Value::as_u64)
                                .unwrap_or(0) as u32,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// The URL that opens a fresh delta era for a folder.
    fn delta_start(&self, folder_id: &str) -> String {
        format!(
            "{}/me/mailFolders/{folder_id}/messages/delta?$select={DELTA_SELECT}",
            self.base
        )
    }

    fn delta_page(&self, url: &str) -> Result<DeltaPage> {
        let (status, body) = self.get(url)?;
        match status {
            // `syncStateNotFound`. See the module docs.
            404 | 410 => return Ok(DeltaPage::Expired),
            code if !(200..300).contains(&code) => {
                return Err(Self::refuse(code, "messages/delta", &body));
            }
            _ => {}
        }

        let page: Value = serde_json::from_str(&body)
            .map_err(|why| Error::Graph(format!("parsing a delta page: {why}")))?;

        Ok(DeltaPage::Ok {
            value: page
                .get("value")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            next_link: page
                .get("@odata.nextLink")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            delta_link: page
                .get("@odata.deltaLink")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        })
    }

    /// The original RFC 5322 octets.
    pub fn raw(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let url = format!("{}/me/messages/{id}/$value", self.base);
        let response = self
            .http
            .get(&url)
            .header("Authorization", &self.authorization)
            .send()
            .map_err(|why| Error::Graph(why.to_string()))?;

        let status = response.status().as_u16();
        if status == 404 {
            // Deleted between the delta page and now.
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            let body = response.text().unwrap_or_default();
            return Err(Self::refuse(status, "$value", &body));
        }

        response
            .bytes()
            .map(|bytes| Some(bytes.to_vec()))
            .map_err(|why| Error::Graph(why.to_string()))
    }

    /// Sets read and flag state on one message.
    pub fn patch_flags(&self, id: &str, flags: Flags) -> Result<()> {
        let body = json!({
            "isRead": flags.seen,
            "flag": {
                "flagStatus": if flags.flagged { "flagged" } else { "notFlagged" }
            }
        });

        let response = self
            .http
            .patch(format!("{}/me/messages/{id}", self.base))
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|why| Error::Graph(why.to_string()))?;

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            let text = response.text().unwrap_or_default();
            return Err(Self::refuse(status, "PATCH message", &text));
        }
        Ok(())
    }

    /// Moves a message to another folder.
    ///
    /// Graph's `move` action, which returns a **new id**: Exchange re-creates
    /// the message in the destination. Anything holding the old id has to
    /// forget it, which is why the writeback drops the mapping rather than
    /// updating it.
    pub fn move_message(&self, id: &str, destination_folder_id: &str) -> Result<String> {
        let body = json!({ "destinationId": destination_folder_id });

        let response = self
            .http
            .post(format!("{}/me/messages/{id}/move", self.base))
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|why| Error::Graph(why.to_string()))?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .map_err(|why| Error::Graph(why.to_string()))?;

        if !(200..300).contains(&status) {
            return Err(Self::refuse(status, "move", &text));
        }

        serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|value| {
                value
                    .get("id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .ok_or_else(|| Error::Graph("a move returned no new message id".to_owned()))
    }

    /// Submits a message for delivery.
    ///
    /// `sendMail` with the MIME content base64-encoded and posted as
    /// `text/plain` — Graph's documented shape for raw submission, and the
    /// verbatim-bytes rule outbound: what Exchange sends is byte-for-byte what
    /// the composer built. This is the path that works when a tenant has SMTP
    /// AUTH switched off, which is the ordinary state of a managed tenant now.
    ///
    /// Built **with** the `Bcc` header, for the same reason as the Gmail
    /// engine: an API has no envelope, recipients derive from the headers, and
    /// Exchange strips `Bcc` from delivered copies as the submission server.
    ///
    /// No Sent filing follows: `saveToSentItems` defaults to true, so Exchange
    /// files its own copy.
    pub fn submit(&self, draft: &crate::compose::Draft) -> crate::smtp::Outcome {
        use crate::smtp::Outcome;
        use base64::Engine as _;

        let message = match draft.build(true) {
            Ok(message) => message.formatted(),
            Err(why) => return Outcome::NotSent(why),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(&message);

        let response = self
            .http
            .post(format!("{}/me/sendMail", self.base))
            .header("Authorization", &self.authorization)
            .header("Content-Type", "text/plain")
            .body(encoded)
            .send();

        let response = match response {
            Ok(response) => response,
            // A connection that never opened cannot have delivered anything;
            // anything past that point may have.
            Err(why) if why.is_connect() => {
                return Outcome::NotSent(Error::Graph(format!("sendMail: {why}")));
            }
            Err(why) => {
                return Outcome::Ambiguous(Error::Graph(format!("sendMail: {why}")));
            }
        };

        let status = response.status().as_u16();
        let body = response.text().unwrap_or_default();
        match status {
            // 202 Accepted is the documented success.
            200..=299 => Outcome::Sent(message),
            400..=499 => Outcome::NotSent(Self::refuse(status, "sendMail", &body)),
            // The server had the message when it failed; it may yet deliver.
            _ => Outcome::Ambiguous(Self::refuse(status, "sendMail", &body)),
        }
    }

    /// Deletes a message. Graph's DELETE moves it to Deleted Items rather than
    /// destroying it, which is what a delete key should mean.
    pub fn delete_message(&self, id: &str) -> Result<()> {
        let response = self
            .http
            .delete(format!("{}/me/messages/{id}", self.base))
            .header("Authorization", &self.authorization)
            .send()
            .map_err(|why| Error::Graph(why.to_string()))?;

        let status = response.status().as_u16();
        // 404 means it is already gone, which is the goal state.
        if !(200..300).contains(&status) && status != 404 {
            let text = response.text().unwrap_or_default();
            return Err(Self::refuse(status, "DELETE message", &text));
        }
        Ok(())
    }
}

/// What one Graph pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GraphOutcome {
    pub fetched: usize,
    pub reflagged: usize,
    pub removed: usize,
    pub pushed: crate::push::DrainOutcome,
    /// The cursor was stale and this folder was read again from scratch.
    pub bootstrapped: bool,
}

/// Graph ids never renumber within a folder, so UIDVALIDITY is a constant.
pub const GRAPH_UID_VALIDITY: u32 = 1;

/// Runs one pass over one folder.
///
/// The first pass has no cursor and walks the delta feed from the beginning,
/// which for Graph *is* the bootstrap — a delta query with no token returns
/// every message and then a `deltaLink`. So there is no separate listing path
/// here, unlike Gmail.
pub fn sync_folder(
    session: &Session,
    folder_id: &str,
    store: &mut (impl MailStore + crate::push::PushQueue),
    state: &mut RemoteIds,
    now_ms: i64,
) -> Result<GraphOutcome> {
    let pushed = {
        let mut writeback = GraphWriteback::new(session, state);
        crate::push::drain(&mut writeback, store, now_ms)
    };

    let from_scratch = state.cursor().is_none();
    let mut outcome = match walk(session, folder_id, store, state, from_scratch)? {
        Some(outcome) => outcome,
        None => {
            // Expired: this folder's cursor only, and this folder only.
            state.reset_cursor();
            walk(session, folder_id, store, state, true)?.ok_or_else(|| {
                Error::Graph("a fresh delta query was itself reported as expired".to_owned())
            })?
        }
    };

    outcome.pushed = pushed;
    outcome.bootstrapped = from_scratch || outcome.bootstrapped;

    store.commit_cursor(Cursor {
        uid_validity: GRAPH_UID_VALIDITY,
        last_uid: state.highest_uid(),
        ..Default::default()
    })?;

    Ok(outcome)
}

/// Walks the delta feed to its `deltaLink`. `None` means the cursor expired.
fn walk(
    session: &Session,
    folder_id: &str,
    store: &mut impl MailStore,
    state: &mut RemoteIds,
    from_scratch: bool,
) -> Result<Option<GraphOutcome>> {
    let mut outcome = GraphOutcome {
        bootstrapped: from_scratch,
        ..Default::default()
    };

    let mut url = if from_scratch {
        session.delta_start(folder_id)
    } else {
        state
            .cursor()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| session.delta_start(folder_id))
    };

    let known = store.state()?;

    loop {
        let page = match session.delta_page(&url)? {
            DeltaPage::Expired => return Ok(None),
            DeltaPage::Ok {
                value,
                next_link,
                delta_link,
            } => (value, next_link, delta_link),
        };
        let (entries, next_link, delta_link) = page;

        for entry in &entries {
            let Some(id) = entry.get("id").and_then(Value::as_str) else {
                continue;
            };

            // A tombstone — but not necessarily a deletion.
            if let Some(removed) = entry.get("@removed") {
                let reason = removed.get("reason").and_then(Value::as_str);
                match classify_removal(reason) {
                    Removal::Deleted => {
                        if let Some(uid) = state.uid_of(id) {
                            state.forget(id);
                            store.remove(uid)?;
                            outcome.removed += 1;
                        }
                    }
                    // A property update wearing the tombstone shape. Deleting
                    // here silently drops mail somebody just changed.
                    Removal::Changed => {}
                }
                continue;
            }

            let Some(message) = parse_message(entry) else {
                continue;
            };

            match state.uid_of(id) {
                Some(uid) => {
                    if known.entries.get(&uid) != Some(&message.flags) {
                        store.set_flags(uid, message.flags)?;
                        outcome.reflagged += 1;
                    }
                }
                None => {
                    let Some(raw) = session.raw(id)? else {
                        continue;
                    };
                    let uid = state.uid_for(id);
                    store.upsert(&RemoteMessage {
                        uid,
                        flags: message.flags,
                        raw,
                        internal_date_ms: message.received_ms,
                    })?;
                    outcome.fetched += 1;
                }
            }
        }

        match (next_link, delta_link) {
            (Some(next), _) => url = next,
            (None, Some(delta)) => {
                // Only now, with every page applied.
                state.set_cursor(delta);
                break;
            }
            (None, None) => {
                // Neither link. Nothing to advance to, so the next pass starts
                // over rather than believing a cursor it does not have.
                break;
            }
        }
    }

    Ok(Some(outcome))
}

/// Writeback over Graph.
pub struct GraphWriteback<'a> {
    session: &'a Session,
    state: &'a mut RemoteIds,
}

impl<'a> GraphWriteback<'a> {
    #[must_use]
    pub fn new(session: &'a Session, state: &'a mut RemoteIds) -> Self {
        Self { session, state }
    }

    fn id_for(&self, uid: u32) -> Result<String> {
        self.state
            .id_of(uid)
            .map(ToOwned::to_owned)
            .ok_or_else(|| Error::UidValidityChanged {
                mailbox: "graph".to_owned(),
                had: uid,
                now: 0,
            })
    }
}

impl crate::push::Writeback for GraphWriteback<'_> {
    fn store_flags(&mut self, uid: u32, flags: Flags) -> Result<()> {
        let id = self.id_for(uid)?;
        self.session.patch_flags(&id, flags)
    }

    /// `destination` is a Graph folder id, not a slug.
    ///
    /// The caller resolves it, because the id is a per-mailbox opaque string
    /// and this layer has no folder list. A `Move` queued with a slug is a
    /// caller bug and is reported rather than guessed at.
    fn move_message(&mut self, uid: u32, destination: &str) -> Result<()> {
        let id = self.id_for(uid)?;
        // The move returns a new id: Exchange re-creates the message in the
        // destination folder. The old mapping is dead either way, and the pass
        // over the destination maildir will pick the message up under its new
        // one.
        let _new_id = self.session.move_message(&id, destination)?;
        self.state.forget(&id);
        Ok(())
    }

    fn delete_message(&mut self, uid: u32) -> Result<()> {
        let id = self.id_for(uid)?;
        self.session.delete_message(&id)?;
        self.state.forget(&id);
        Ok(())
    }
}

/// The maildir a Graph folder maps onto.
#[must_use]
pub fn folder_for(folder: &GraphFolder) -> Folder {
    let slug = folder.slug();
    Folder {
        wire_name: folder.id.clone(),
        display_name: if folder.display_name.is_empty() {
            slug.clone()
        } else {
            folder.display_name.clone()
        },
        delimiter: '/',
        special_use: match slug.as_str() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_tombstone_is_not_a_deletion() {
        // The subtlety that silently drops updated mail. Exchange uses the
        // tombstone shape for "this left the filter", not only for "this is
        // gone".
        assert_eq!(classify_removal(Some("changed")), Removal::Changed);
        assert_eq!(classify_removal(Some("deleted")), Removal::Deleted);
        // An unspecified reason is a real removal — the conservative reading
        // is the one that matches Exchange's own default.
        assert_eq!(classify_removal(None), Removal::Deleted);
    }

    #[test]
    fn is_read_is_the_right_way_round() {
        // Unlike Gmail's UNREAD. Two engines in one crate spelling read state
        // oppositely is exactly where a copy-paste goes wrong.
        assert!(!flags_from(&json!({ "isRead": false })).seen);
        assert!(flags_from(&json!({ "isRead": true })).seen);
    }

    #[test]
    fn a_message_with_no_is_read_is_treated_as_read() {
        // Exchange omits it only on objects that are not mail; defaulting to
        // unread would light up a badge for every one of them.
        assert!(flags_from(&json!({})).seen);
    }

    #[test]
    fn a_flag_status_of_flagged_is_the_only_one_that_counts() {
        assert!(flags_from(&json!({ "flag": { "flagStatus": "flagged" } })).flagged);
        assert!(!flags_from(&json!({ "flag": { "flagStatus": "notFlagged" } })).flagged);
        // `complete` is a finished follow-up, not a star.
        assert!(!flags_from(&json!({ "flag": { "flagStatus": "complete" } })).flagged);
        assert!(!flags_from(&json!({})).flagged);
    }

    #[test]
    fn exchange_datetimes_parse_in_all_three_shapes() {
        // Exchange emits RFC 3339 mostly, and the other two sometimes.
        let expected = 1_785_834_000_000;
        assert_eq!(parse_datetime_ms("2026-08-04T09:00:00Z"), Some(expected));
        assert_eq!(parse_datetime_ms("2026-08-04T09:00:00.0000000"), Some(expected));
        assert_eq!(parse_datetime_ms("2026-08-04T09:00:00"), Some(expected));
        assert_eq!(parse_datetime_ms("not a date"), None);
    }

    #[test]
    fn an_undated_message_is_kept_rather_than_dropped() {
        // A bad sort key is visible and recoverable; discarding the message
        // is neither.
        let message = parse_message(&json!({ "id": "m1" })).expect("a message");
        assert_eq!(message.received_ms, 0);
    }

    #[test]
    fn well_known_names_map_without_looking_at_display_names() {
        // A German tenant's Deleted Items is "Gelöschte Elemente". Matching on
        // display names finds nothing.
        assert_eq!(slug_for_well_known("deleteditems"), Some("trash"));
        assert_eq!(slug_for_well_known("junkemail"), Some("junk"));
        assert_eq!(slug_for_well_known("sentitems"), Some("sent"));
        assert_eq!(slug_for_well_known("somethingelse"), None);
    }

    #[test]
    fn a_user_folder_keeps_its_own_name() {
        let folder = GraphFolder {
            id: "AAMk2".into(),
            display_name: "Receipts".into(),
            well_known: None,
            total: 3,
            unread: 0,
        };

        assert_eq!(folder.slug(), "Receipts");
        assert_eq!(folder_for(&folder).special_use, None);
    }

    #[test]
    fn a_well_known_folder_gets_its_special_use() {
        let folder = GraphFolder {
            id: "AAMk1".into(),
            display_name: "Posteingang".into(),
            well_known: Some("inbox".into()),
            total: 3,
            unread: 1,
        };

        assert_eq!(folder.slug(), "inbox");
        assert_eq!(folder_for(&folder).special_use, Some(SpecialUse::Inbox));
        assert_eq!(
            folder_for(&folder).display_name,
            "Posteingang",
            "the user's own language was replaced by a slug"
        );
    }

    #[test]
    fn a_password_is_refused_rather_than_sent() {
        let error = Session::connect(&Credentials::Password("hunter2".into())).unwrap_err();
        assert!(matches!(error, Error::Auth(_)), "got {error}");
    }
}

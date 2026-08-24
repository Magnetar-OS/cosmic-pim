// SPDX-License-Identifier: MPL-2.0

//! A canned JMAP server driving the real client into a real maildir.
//!
//! The unit tests cover keyword mapping and the sidecar; this proves the
//! session actually walks a mailbox — session resource, `Email/query`,
//! `Email/get`, a blob download per message — and leaves the right bytes on
//! disk. Same job as `live_sync.rs` for IMAP and `live_pop3.rs` for POP3.
//!
//! The server is **stateful**, and that is what makes the incremental path
//! testable: a test mutates the mailbox between passes, the server's `Email`
//! state advances, and `Email/changes` answers from a real history. A fixture
//! that could only serve one fixed mailbox would exercise the full-sync path
//! and nothing else, which is the path that matters least.
//!
//! The most important thing it asserts is that the message stored is the one
//! the download endpoint served, byte for byte, and not something reassembled
//! from `Email/get`. That is the invariant the whole crate is built on and the
//! one a JMAP client is most tempted to break, because the parsed object is
//! right there in the response.

use std::sync::{Arc, Mutex};

use cosmic_pim_mail::Credentials;
use cosmic_pim_mail::jmap::{JmapState, Session, sync_mailbox};
use cosmic_pim_mail::maildir::MaildirStore;
use cosmic_pim_mail::store::MailStore;
use serde_json::{Value, json};

/// The bytes the download endpoint serves. Deliberately carries a header the
/// model does not keep and a DKIM signature, so a reassembled copy would not
/// match.
const RAW_ONE: &[u8] = b"From: ada@example.com\r\n\
Subject: First\r\n\
Message-ID: <one@example.com>\r\n\
X-Unmodelled-Header: kept verbatim\r\n\
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=k1; b=Zm9v\r\n\
\r\n\
Hello.\r\n";

const RAW_TWO: &[u8] = b"From: bob@example.com\r\n\
Subject: Second\r\n\
Message-ID: <two@example.com>\r\n\
\r\n\
Hi.\r\n";

const RAW_THREE: &[u8] = b"From: carol@example.com\r\n\
Subject: Third\r\n\
Message-ID: <three@example.com>\r\n\
\r\n\
Later.\r\n";

/// One email as the server holds it.
#[derive(Clone)]
struct Email {
    id: String,
    blob_id: String,
    raw: Vec<u8>,
    keywords: Value,
    /// Which mailboxes it is in. A move is a change to this, not a delete.
    mailboxes: Vec<String>,
}

impl Email {
    fn new(id: &str, raw: &[u8], keywords: Value) -> Self {
        Self {
            id: id.to_owned(),
            blob_id: format!("blob-{id}"),
            raw: raw.to_vec(),
            keywords,
            mailboxes: vec!["mbox-1".to_owned()],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChangeKind {
    Created,
    Updated,
    Destroyed,
}

/// The mailbox, its `Email` state, and enough history to answer
/// `Email/changes`.
struct ServerState {
    emails: Vec<Email>,
    /// Monotonic; its decimal form is the JMAP state string.
    state: u64,
    /// `(state after the change, id, what happened)`.
    history: Vec<(u64, String, ChangeKind)>,
    /// The oldest state the history can answer from. A client asking about
    /// anything older gets `cannotCalculateChanges`, exactly as a real server
    /// does once its log has rolled over.
    floor: u64,
}

impl ServerState {
    fn record(&mut self, id: &str, kind: ChangeKind) {
        self.state += 1;
        self.history.push((self.state, id.to_owned(), kind));
    }
}

struct Server {
    url: String,
    calls: Arc<Mutex<Vec<String>>>,
    inner: Arc<Mutex<ServerState>>,
    _handle: std::thread::JoinHandle<()>,
}

impl Server {
    /// Every request the client made, in order: JMAP method names, plus
    /// `download <blob>` and `session`.
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }

    fn forget_calls(&self) {
        self.calls.lock().expect("calls").clear();
    }

    fn session_url(&self) -> String {
        format!("{}/session", self.url)
    }

    fn add(&self, email: Email) {
        let mut inner = self.inner.lock().expect("state");
        let id = email.id.clone();
        inner.emails.push(email);
        inner.record(&id, ChangeKind::Created);
    }

    fn set_keywords(&self, id: &str, keywords: Value) {
        let mut inner = self.inner.lock().expect("state");
        if let Some(email) = inner.emails.iter_mut().find(|e| e.id == id) {
            email.keywords = keywords;
        }
        inner.record(id, ChangeKind::Updated);
    }

    /// Moves a message to another mailbox — an *update* in JMAP terms, not a
    /// deletion, which is exactly the case a naive client misses.
    fn move_out(&self, id: &str) {
        let mut inner = self.inner.lock().expect("state");
        if let Some(email) = inner.emails.iter_mut().find(|e| e.id == id) {
            email.mailboxes = vec!["mbox-archive".to_owned()];
        }
        inner.record(id, ChangeKind::Updated);
    }

    fn destroy(&self, id: &str) {
        let mut inner = self.inner.lock().expect("state");
        inner.emails.retain(|e| e.id != id);
        inner.record(id, ChangeKind::Destroyed);
    }

    /// Rolls the change log over, so anything older cannot be answered.
    fn forget_history(&self) {
        let mut inner = self.inner.lock().expect("state");
        inner.history.clear();
        inner.floor = inner.state;
    }
}

fn serve(emails: Vec<Email>) -> Server {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let port = server.server_addr().to_ip().expect("ip").port();
    let url = format!("http://127.0.0.1:{port}");
    let base = url.clone();

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&calls);

    let inner = Arc::new(Mutex::new(ServerState {
        emails,
        state: 1,
        history: Vec::new(),
        floor: 0,
    }));
    let held = Arc::clone(&inner);

    let handle = std::thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let path = request.url().to_owned();
            let mut body = String::new();
            let _ = request.as_reader().read_to_string(&mut body);

            // A blob download: /download/<account>/<blobId>/<name>
            if let Some(rest) = path.strip_prefix("/download/") {
                let blob_id = rest.split('/').nth(1).unwrap_or_default().to_owned();
                recorded
                    .lock()
                    .expect("calls")
                    .push(format!("download {blob_id}"));

                let bytes = held
                    .lock()
                    .expect("state")
                    .emails
                    .iter()
                    .find(|e| e.blob_id == blob_id)
                    .map(|e| e.raw.clone());

                let response = match bytes {
                    Some(raw) => tiny_http::Response::from_data(raw).with_status_code(200),
                    None => {
                        tiny_http::Response::from_data(Vec::new()).with_status_code(404)
                    }
                };
                let _ = request.respond(response);
                continue;
            }

            let payload = if path.ends_with("/session") {
                recorded.lock().expect("calls").push("session".to_owned());
                json!({
                    "apiUrl": format!("{base}/api"),
                    "downloadUrl": format!("{base}/download/{{accountId}}/{{blobId}}/{{name}}"),
                    "capabilities": {
                        "urn:ietf:params:jmap:core": {},
                        "urn:ietf:params:jmap:mail": {}
                    },
                    "primaryAccounts": {
                        "urn:ietf:params:jmap:mail": "acct-1"
                    }
                })
            } else {
                let parsed: Value = serde_json::from_str(&body).unwrap_or(json!({}));
                let mut responses = Vec::new();

                for call in parsed
                    .get("methodCalls")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                {
                    let name = call.get(0).and_then(Value::as_str).unwrap_or("").to_owned();
                    let args = call.get(1).cloned().unwrap_or(json!({}));
                    let call_id = call.get(2).and_then(Value::as_str).unwrap_or("0").to_owned();
                    recorded.lock().expect("calls").push(name.clone());

                    let mut state = held.lock().expect("state");
                    let (reply_name, reply) = respond(&name, &args, &mut state);
                    drop(state);

                    responses.push(json!([reply_name, reply, call_id]));
                }

                json!({ "methodResponses": responses })
            };

            let response = tiny_http::Response::from_string(payload.to_string())
                .with_status_code(200)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .expect("header"),
                );
            let _ = request.respond(response);
        }
    });

    Server {
        url,
        calls,
        inner,
        _handle: handle,
    }
}

/// Answers one method call. Returns `("error", …)` where a real server would.
fn respond(name: &str, args: &Value, state: &mut ServerState) -> (String, Value) {
    let in_mailbox = |email: &Email, id: &str| email.mailboxes.iter().any(|m| m == id);

    let reply = match name {
        "Mailbox/get" => json!({
            "accountId": "acct-1",
            "state": state.state.to_string(),
            "list": [ {
                "id": "mbox-1",
                "name": "Inbox",
                "role": "inbox",
                "totalEmails": state.emails.len(),
                "unreadEmails": 0
            } ]
        }),
        "Email/query" => {
            let mailbox = args
                .get("filter")
                .and_then(|f| f.get("inMailbox"))
                .and_then(Value::as_str)
                .unwrap_or("mbox-1");
            json!({
                "accountId": "acct-1",
                "queryState": state.state.to_string(),
                "ids": state.emails.iter()
                    .filter(|e| in_mailbox(e, mailbox))
                    .map(|e| e.id.clone())
                    .collect::<Vec<_>>()
            })
        }
        "Email/get" => {
            let wanted: Vec<String> = args
                .get("ids")
                .and_then(Value::as_array)
                .map(|ids| {
                    ids.iter()
                        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default();

            let list: Vec<Value> = state
                .emails
                .iter()
                .filter(|e| wanted.contains(&e.id))
                .map(|e| {
                    json!({
                        "id": e.id,
                        "blobId": e.blob_id,
                        "keywords": e.keywords,
                        "receivedAt": "2026-08-04T09:00:00Z",
                        "size": e.raw.len(),
                        "mailboxIds": e.mailboxes.iter()
                            .map(|m| (m.clone(), json!(true)))
                            .collect::<serde_json::Map<_, _>>()
                    })
                })
                .collect();

            json!({
                "accountId": "acct-1",
                // Always present on a real server, and the client opens its
                // incremental era from it.
                "state": state.state.to_string(),
                "list": list,
                "notFound": []
            })
        }
        "Email/changes" => {
            let since: u64 = args
                .get("sinceState")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            if since < state.floor {
                return (
                    "error".to_owned(),
                    json!({ "type": "cannotCalculateChanges" }),
                );
            }

            let mut created = Vec::new();
            let mut updated = Vec::new();
            let mut destroyed = Vec::new();
            for (at, id, kind) in &state.history {
                if *at <= since {
                    continue;
                }
                match kind {
                    ChangeKind::Created => created.push(id.clone()),
                    ChangeKind::Updated => updated.push(id.clone()),
                    ChangeKind::Destroyed => destroyed.push(id.clone()),
                }
            }

            json!({
                "accountId": "acct-1",
                "oldState": since.to_string(),
                "newState": state.state.to_string(),
                "hasMoreChanges": false,
                "created": created,
                "updated": updated,
                "destroyed": destroyed
            })
        }
        "Email/set" => {
            let mut updated = serde_json::Map::new();
            let mut destroyed = Vec::new();
            let mut touched = Vec::new();

            if let Some(update) = args.get("update").and_then(Value::as_object) {
                for (id, patch) in update {
                    let Some(email) = state.emails.iter_mut().find(|e| &e.id == id) else {
                        continue;
                    };
                    let Some(fields) = patch.as_object() else {
                        continue;
                    };
                    for (property, value) in fields {
                        let property = property.as_str();
                        match property {
                            "keywords" => email.keywords = value.clone(),
                            // Patch form: `mailboxIds/<id>` = true, or null to
                            // remove. A real server accepts both this and a
                            // whole-set replacement.
                            path if path.starts_with("mailboxIds/") => {
                                let mailbox = path.trim_start_matches("mailboxIds/").to_owned();
                                if value.is_null() {
                                    email.mailboxes.retain(|m| m != &mailbox);
                                } else if !email.mailboxes.contains(&mailbox) {
                                    email.mailboxes.push(mailbox);
                                }
                            }
                            _ => {}
                        }
                    }
                    updated.insert(id.clone(), Value::Null);
                    touched.push(id.clone());
                }
            }

            if let Some(list) = args.get("destroy").and_then(Value::as_array) {
                for id in list.iter().filter_map(Value::as_str) {
                    if state.emails.iter().any(|e| e.id == id) {
                        state.emails.retain(|e| e.id != id);
                        destroyed.push(id.to_owned());
                    }
                }
            }

            for id in touched {
                state.record(&id, ChangeKind::Updated);
            }
            for id in &destroyed {
                state.record(id, ChangeKind::Destroyed);
            }

            json!({
                "accountId": "acct-1",
                "newState": state.state.to_string(),
                "updated": updated,
                "destroyed": destroyed,
                "notUpdated": {},
                "notDestroyed": {}
            })
        }
        _ => json!({ "accountId": "acct-1" }),
    };

    (name.to_owned(), reply)
}

fn maildir() -> (tempfile::TempDir, MaildirStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = MaildirStore::open(dir.path()).expect("maildir");
    (dir, store)
}

fn connect(server: &Server) -> Session {
    Session::connect(
        &server.session_url(),
        "ada@example.com",
        &Credentials::OAuth2("ya29.token".into()),
    )
    .expect("session")
}

fn sync(server: &Server, store: &mut MaildirStore, state: &mut JmapState) -> cosmic_pim_mail::jmap::JmapOutcome {
    let session = connect(server);
    sync_mailbox(&session, "mbox-1", store, state, 500, 1_000).expect("sync")
}

fn downloads(server: &Server) -> usize {
    server
        .calls()
        .iter()
        .filter(|call| call.starts_with("download"))
        .count()
}

#[test]
fn the_session_resource_names_the_api_and_the_account() {
    let server = serve(vec![]);
    let session = connect(&server);

    assert_eq!(session.account_id(), "acct-1");
    assert_eq!(server.calls(), vec!["session".to_owned()]);
}

#[test]
fn a_mailbox_lists_with_its_role() {
    // The role is what lets a client find Sent without guessing at its name in
    // the user's language.
    let server = serve(vec![Email::new("M1", RAW_ONE, json!({ "$seen": true }))]);
    let session = connect(&server);

    let mailboxes = session.mailboxes().expect("mailboxes");

    assert_eq!(mailboxes.len(), 1);
    assert_eq!(mailboxes[0].role.as_deref(), Some("inbox"));
    assert_eq!(mailboxes[0].name, "Inbox");
}

#[test]
fn a_first_pass_downloads_every_message_into_the_maildir() {
    let server = serve(vec![
        Email::new("M1", RAW_ONE, json!({ "$seen": true })),
        Email::new("M2", RAW_TWO, json!({})),
    ]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());

    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.fetched, 2);
    assert_eq!(store.state().expect("state").entries.len(), 2);
    assert!(
        state.email_state().is_some(),
        "the first pass did not open an incremental era, so every later pass re-reads the mailbox"
    );
}

#[test]
fn the_bytes_stored_are_the_ones_the_server_served() {
    // The invariant. `Email/get` hands over a parsed object and it is tempting
    // to store that; a reassembled message has a different MIME structure and
    // an invalid DKIM signature, and nothing notices until it is forwarded.
    let server = serve(vec![Email::new("M1", RAW_ONE, json!({ "$seen": true }))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());

    sync(&server, &mut store, &mut state);

    let uid = state.uid_of("M1").expect("a local uid");
    let raw = store.raw(uid).expect("read").expect("bytes");

    assert_eq!(raw, RAW_ONE, "the stored message is not the served one");
    assert!(
        server.calls().iter().any(|call| call == "download blob-M1"),
        "the message was never downloaded: {:?}",
        server.calls()
    );
}

#[test]
fn keywords_arrive_as_flags() {
    let server = serve(vec![Email::new(
        "M1",
        RAW_ONE,
        json!({ "$seen": true, "$flagged": true }),
    )]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());

    sync(&server, &mut store, &mut state);

    let uid = state.uid_of("M1").expect("a local uid");
    let flags = store.state().expect("state").entries[&uid];

    assert!(flags.seen);
    assert!(flags.flagged);
    assert!(!flags.answered);
}

#[test]
fn a_quiet_pass_costs_one_request_and_no_downloads() {
    // The whole point of the incremental path. A five-second poll that
    // re-reads the mailbox is not affordable; one that asks "anything new?"
    // is.
    let server = serve(vec![
        Email::new("M1", RAW_ONE, json!({ "$seen": true })),
        Email::new("M2", RAW_TWO, json!({})),
    ]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    server.forget_calls();
    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome, Default::default(), "a quiet pass did work");
    assert_eq!(downloads(&server), 0);
    assert!(
        !server.calls().iter().any(|call| call == "Email/query"),
        "the mailbox was re-read instead of asked for changes: {:?}",
        server.calls()
    );
    assert!(server.calls().iter().any(|call| call == "Email/changes"));
}

#[test]
fn a_new_message_arrives_incrementally() {
    let server = serve(vec![Email::new("M1", RAW_ONE, json!({}))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    server.add(Email::new("M3", RAW_THREE, json!({})));
    server.forget_calls();
    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.fetched, 1);
    assert_eq!(downloads(&server), 1, "only the new message should be fetched");
    assert_eq!(store.state().expect("state").entries.len(), 2);

    let uid = state.uid_of("M3").expect("a local uid");
    assert_eq!(store.raw(uid).expect("read").expect("bytes"), RAW_THREE);
}

#[test]
fn a_flag_changed_on_the_server_costs_no_download() {
    // The reason metadata and bytes are separate: starring a message must not
    // re-fetch it.
    let server = serve(vec![Email::new("M1", RAW_ONE, json!({ "$seen": true }))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    server.set_keywords("M1", json!({ "$seen": true, "$flagged": true }));
    server.forget_calls();
    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.reflagged, 1);
    assert_eq!(outcome.fetched, 0);
    assert_eq!(downloads(&server), 0, "a flag change re-downloaded the message");

    let uid = state.uid_of("M1").expect("a local uid");
    assert!(store.state().expect("state").entries[&uid].flagged);
}

#[test]
fn a_message_moved_to_another_mailbox_leaves_this_one() {
    // JMAP reports a move as an *update*, not a destroy. A client that only
    // watches `destroyed` leaves the message sitting in the wrong maildir
    // until a full resync — which, with incremental sync working, may be
    // never.
    let server = serve(vec![
        Email::new("M1", RAW_ONE, json!({})),
        Email::new("M2", RAW_TWO, json!({})),
    ]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    server.move_out("M1");
    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.removed, 1);
    assert_eq!(store.state().expect("state").entries.len(), 1);
    assert!(state.uid_of("M1").is_none(), "the id mapping outlived the message");
}

#[test]
fn a_deleted_message_is_removed_incrementally() {
    let server = serve(vec![
        Email::new("M1", RAW_ONE, json!({})),
        Email::new("M2", RAW_TWO, json!({})),
    ]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    server.destroy("M2");
    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.removed, 1);
    assert_eq!(store.state().expect("state").entries.len(), 1);
}

#[test]
fn a_server_that_cannot_report_changes_falls_back_to_a_full_read() {
    // After a long enough offline period a server's change log has rolled
    // over. `cannotCalculateChanges` is a routine answer, not a failure, and
    // the client has to be able to start again from the mailbox as it is.
    let server = serve(vec![Email::new("M1", RAW_ONE, json!({}))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    server.add(Email::new("M3", RAW_THREE, json!({})));
    server.forget_history();
    server.forget_calls();

    let outcome = sync(&server, &mut store, &mut state);

    assert!(
        server.calls().iter().any(|call| call == "Email/query"),
        "the client did not fall back to reading the mailbox: {:?}",
        server.calls()
    );
    assert_eq!(outcome.fetched, 1, "the message added while offline never arrived");
    assert_eq!(store.state().expect("state").entries.len(), 2);
    assert!(
        state.email_state().is_some(),
        "the fallback did not re-open an incremental era"
    );
}

#[test]
fn the_incremental_era_survives_a_reopen() {
    // The sidecar is what makes the second *process* incremental, not just the
    // second pass.
    let server = serve(vec![Email::new("M1", RAW_ONE, json!({}))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);
    state.save(dir.path()).expect("save");

    let mut reloaded = JmapState::load(dir.path());
    server.forget_calls();
    sync(&server, &mut store, &mut reloaded);

    assert!(
        !server.calls().iter().any(|call| call == "Email/query"),
        "a restart re-read the whole mailbox"
    );
}

#[test]
fn an_empty_listing_does_not_empty_the_maildir_on_a_full_read() {
    // The mass-delete guard, the same one the CalDAV planner has. A server
    // having a moment must not cost the user their mailbox.
    let server = serve(vec![Email::new("M1", RAW_ONE, json!({}))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    // Drop the message without recording it, so a full read sees an empty
    // mailbox with no explanation — which is what a broken server looks like.
    server.inner.lock().expect("state").emails.clear();
    state.reset_era();

    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.removed, 0, "an empty listing wiped the mailbox");
    assert_eq!(store.state().expect("state").entries.len(), 1);
}

#[test]
fn a_local_flag_change_reaches_the_server_before_the_pull_can_undo_it() {
    // The bug this ordering prevents: the pull writes the server's older
    // keywords over the local ones, and the queued push then sends the
    // server's own state back to it. The star the user set disappears with
    // every indicator reporting success.
    use cosmic_pim_mail::push::{PushOp, PushQueue};
    use cosmic_pim_mail::model::Flags;

    let server = serve(vec![Email::new("M1", RAW_ONE, json!({}))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    let uid = state.uid_of("M1").expect("a local uid");
    store
        .enqueue(PushOp::SetFlags {
            uid,
            flags: Flags {
                flagged: true,
                ..Default::default()
            },
        })
        .expect("enqueue");

    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.pushed.succeeded, 1, "the flag change never went out");
    assert!(store.pending().is_empty(), "the queue entry outlived its push");

    // The server has it, so the pass that follows agrees rather than fighting.
    let held = server.inner.lock().expect("state");
    let email = held.emails.iter().find(|e| e.id == "M1").expect("M1");
    assert_eq!(
        email.keywords.get("$flagged").and_then(Value::as_bool),
        Some(true),
        "the server did not receive the flag"
    );
}

#[test]
fn a_local_move_leaves_the_mailbox_and_forgets_the_id() {
    use cosmic_pim_mail::push::{PushOp, PushQueue};

    let server = serve(vec![
        Email::new("M1", RAW_ONE, json!({})),
        Email::new("M2", RAW_TWO, json!({})),
    ]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    let uid = state.uid_of("M1").expect("a local uid");
    store
        .enqueue(PushOp::Move {
            uid,
            destination: "mbox-archive".into(),
        })
        .expect("enqueue");

    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.pushed.succeeded, 1);
    assert!(
        state.uid_of("M1").is_none(),
        "the id mapping survived a move, so the next pass sees a message it thinks it holds"
    );

    // On the server it is in the other mailbox, not gone.
    let held = server.inner.lock().expect("state");
    let email = held.emails.iter().find(|e| e.id == "M1").expect("M1 was destroyed");
    assert_eq!(email.mailboxes, vec!["mbox-archive".to_owned()]);
}

#[test]
fn a_queued_operation_for_an_unknown_message_asks_for_a_resync() {
    // The sidecar and the maildir have diverged. Retrying forever would never
    // fix it and dropping the entry would lose the user's change silently, so
    // it is handed to a sync pass.
    use cosmic_pim_mail::push::{PushOp, PushQueue};
    use cosmic_pim_mail::model::Flags;

    let server = serve(vec![Email::new("M1", RAW_ONE, json!({}))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    sync(&server, &mut store, &mut state);

    store
        .enqueue(PushOp::SetFlags {
            uid: 9_999,
            flags: Flags::default(),
        })
        .expect("enqueue");

    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.pushed.needs_reconcile, 1);
    assert_eq!(outcome.pushed.succeeded, 0);
}

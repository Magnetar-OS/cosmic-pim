// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! A canned Microsoft Graph driving the real client into a real maildir.
//!
//! The unit tests cover the tombstone classification and the datetime ladder.
//! This is what proves the delta state machine actually walks a folder over
//! HTTP — and in particular the two cases that lose mail when they are got
//! wrong:
//!
//! - a `@removed` entry whose reason is `changed` is an **update**, not a
//!   deletion, and treating it as one silently drops mail somebody just edited;
//! - a stale `deltaLink` answers 410, which means "I cannot tell you what
//!   changed" — not "nothing changed" and not "everything is gone".
//!
//! Neither can be expressed against a fixture that serves a frozen folder, so
//! the server here holds state and hands out real delta links.

use std::sync::{Arc, Mutex};

use cosmic_pim_mail::Credentials;
use cosmic_pim_mail::graph::{self, Session, sync_folder};
use cosmic_pim_mail::maildir::MaildirStore;
use cosmic_pim_mail::store::MailStore;
use serde_json::{Value, json};

const RAW_ONE: &[u8] = b"From: ada@example.com\r\n\
Subject: First\r\n\
Message-ID: <one@example.com>\r\n\
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=k1; b=Zm9v\r\n\
\r\n\
Hello.\r\n";

const RAW_TWO: &[u8] = b"From: bob@example.com\r\n\
Subject: Second\r\n\
Message-ID: <two@example.com>\r\n\
\r\n\
Hi.\r\n";

#[derive(Clone)]
struct Message {
    id: String,
    is_read: bool,
    flagged: bool,
    raw: Vec<u8>,
}

impl Message {
    fn new(id: &str, raw: &[u8]) -> Self {
        Self {
            id: id.to_owned(),
            is_read: false,
            flagged: false,
            raw: raw.to_vec(),
        }
    }
}

/// One entry the next delta page will carry.
#[derive(Clone)]
enum Change {
    Upsert(String),
    /// `@removed` with `reason: deleted`.
    Deleted(String),
    /// `@removed` with `reason: changed` — an update wearing a tombstone.
    ChangedTombstone(String),
}

struct ServerState {
    messages: Vec<Message>,
    /// Changes not yet handed out, keyed by the token that will deliver them.
    pending: Vec<Change>,
    /// Monotonic token counter; `delta-N` is the cursor.
    token: u64,
    /// Cursors below this answer 410.
    floor: u64,
    /// The MIME bytes `sendMail` accepted, decoded.
    submitted: Vec<Vec<u8>>,
    /// When set, `sendMail` refuses with a 400.
    refuse_send: bool,
}

struct Server {
    url: String,
    calls: Arc<Mutex<Vec<String>>>,
    inner: Arc<Mutex<ServerState>>,
    _handle: std::thread::JoinHandle<()>,
}

impl Server {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }

    fn forget_calls(&self) {
        self.calls.lock().expect("calls").clear();
    }

    fn deliver(&self, message: Message) {
        let mut inner = self.inner.lock().expect("state");
        let id = message.id.clone();
        inner.messages.push(message);
        inner.pending.push(Change::Upsert(id));
    }

    fn mark_read(&self, id: &str) {
        let mut inner = self.inner.lock().expect("state");
        if let Some(message) = inner.messages.iter_mut().find(|m| m.id == id) {
            message.is_read = true;
        }
        inner.pending.push(Change::Upsert(id.to_owned()));
    }

    fn delete(&self, id: &str) {
        let mut inner = self.inner.lock().expect("state");
        inner.messages.retain(|m| m.id != id);
        inner.pending.push(Change::Deleted(id.to_owned()));
    }

    /// Emits the tombstone shape Exchange uses for a property change.
    fn changed_tombstone(&self, id: &str) {
        self.inner
            .lock()
            .expect("state")
            .pending
            .push(Change::ChangedTombstone(id.to_owned()));
    }

    /// Invalidates every cursor handed out so far.
    fn expire_cursors(&self) {
        let mut inner = self.inner.lock().expect("state");
        inner.floor = inner.token + 1;
    }

    fn submitted(&self) -> Vec<Vec<u8>> {
        self.inner.lock().expect("state").submitted.clone()
    }

    fn refuse_sends(&self) {
        self.inner.lock().expect("state").refuse_send = true;
    }

    fn flags_of(&self, id: &str) -> Option<(bool, bool)> {
        self.inner
            .lock()
            .expect("state")
            .messages
            .iter()
            .find(|m| m.id == id)
            .map(|m| (m.is_read, m.flagged))
    }
}

fn serve(messages: Vec<Message>) -> Server {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let port = server.server_addr().to_ip().expect("ip").port();
    let url = format!("http://127.0.0.1:{port}");
    let base = url.clone();

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&calls);

    let inner = Arc::new(Mutex::new(ServerState {
        messages,
        pending: Vec::new(),
        token: 0,
        floor: 0,
        submitted: Vec::new(),
        refuse_send: false,
    }));
    let held = Arc::clone(&inner);

    let handle = std::thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let target = request.url().to_owned();
            let method = request.method().as_str().to_owned();
            let mut body = String::new();
            let _ = request.as_reader().read_to_string(&mut body);

            let mut state = held.lock().expect("state");
            let (status, payload, is_bytes) =
                route(&method, &target, &body, &mut state, &base, &recorded);
            drop(state);

            let response = if is_bytes {
                tiny_http::Response::from_data(payload.into_bytes()).with_status_code(status)
            } else {
                tiny_http::Response::from_string(payload)
                    .with_status_code(status)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"application/json"[..],
                        )
                        .expect("header"),
                    )
            };
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

fn route(
    method: &str,
    target: &str,
    body: &str,
    state: &mut ServerState,
    base: &str,
    calls: &Arc<Mutex<Vec<String>>>,
) -> (u16, String, bool) {
    let note = |what: String| calls.lock().expect("calls").push(what);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    if path == "/me/sendMail" && method == "POST" {
        note("sendMail".to_owned());
        if state.refuse_send {
            return (400, json!({ "error": { "code": "invalidRequest" } }).to_string(), false);
        }
        // The engine posts standard base64 of the MIME as text/plain.
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body.trim().as_bytes())
            .unwrap_or_default();
        state.submitted.push(bytes);
        return (202, String::new(), false);
    }

    // GET /me/messages/{id}/$value
    if let Some(rest) = path.strip_prefix("/me/messages/") {
        if let Some(id) = rest.strip_suffix("/$value") {
            note(format!("value {id}"));
            return match state.messages.iter().find(|m| m.id == id) {
                Some(message) => (
                    200,
                    String::from_utf8_lossy(&message.raw).into_owned(),
                    true,
                ),
                None => (404, String::new(), true),
            };
        }
        if let Some(id) = rest.strip_suffix("/move") {
            note(format!("move {id}"));
            let _ = body;
            return (200, json!({ "id": format!("{id}-moved") }).to_string(), false);
        }
        // PATCH or DELETE on the message itself.
        let id = rest.to_owned();
        if method == "DELETE" {
            note(format!("delete {id}"));
            state.messages.retain(|m| m.id != id);
            return (204, String::new(), false);
        }
        if method == "PATCH" {
            note(format!("patch {id}"));
            let patch: Value = serde_json::from_str(body).unwrap_or(json!({}));
            if let Some(message) = state.messages.iter_mut().find(|m| m.id == id) {
                if let Some(read) = patch.get("isRead").and_then(Value::as_bool) {
                    message.is_read = read;
                }
                if let Some(status) = patch
                    .get("flag")
                    .and_then(|f| f.get("flagStatus"))
                    .and_then(Value::as_str)
                {
                    message.flagged = status == "flagged";
                }
            }
            return (200, json!({ "id": id }).to_string(), false);
        }
    }

    if path == "/me/mailFolders" {
        note("folders".to_owned());
        return (
            200,
            json!({
                "value": [
                    {
                        "id": "AAMk-inbox",
                        "displayName": "Posteingang",
                        "wellKnownName": "inbox",
                        "totalItemCount": state.messages.len(),
                        "unreadItemCount": 0
                    }
                ]
            })
            .to_string(),
            false,
        );
    }

    // The delta feed. A first call has no `$deltatoken`; a follow-up carries
    // the one the previous page ended with.
    if path.contains("/messages/delta") {
        let token = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("$deltatoken="))
            .and_then(|value| value.strip_prefix("delta-"))
            .and_then(|value| value.parse::<u64>().ok());

        note(match token {
            Some(t) => format!("delta {t}"),
            None => "delta start".to_owned(),
        });

        if let Some(t) = token
            && t < state.floor
        {
            return (
                410,
                json!({ "error": { "code": "syncStateNotFound" } }).to_string(),
                false,
            );
        }

        let entries: Vec<Value> = if token.is_none() {
            // A delta query with no token IS the bootstrap: every message,
            // then a link.
            state.messages.iter().map(render).collect()
        } else {
            let pending = std::mem::take(&mut state.pending);
            pending
                .iter()
                .filter_map(|change| match change {
                    Change::Upsert(id) => state.messages.iter().find(|m| &m.id == id).map(render),
                    Change::Deleted(id) => Some(json!({
                        "id": id,
                        "@removed": { "reason": "deleted" }
                    })),
                    Change::ChangedTombstone(id) => Some(json!({
                        "id": id,
                        "@removed": { "reason": "changed" }
                    })),
                })
                .collect()
        };

        state.token += 1;
        let next = state.token;

        return (
            200,
            json!({
                "value": entries,
                "@odata.deltaLink":
                    format!("{base}/me/mailFolders/AAMk-inbox/messages/delta?$deltatoken=delta-{next}")
            })
            .to_string(),
            false,
        );
    }

    (404, json!({ "error": { "code": "notFound" } }).to_string(), false)
}

fn render(message: &Message) -> Value {
    json!({
        "id": message.id,
        "isRead": message.is_read,
        "flag": { "flagStatus": if message.flagged { "flagged" } else { "notFlagged" } },
        "parentFolderId": "AAMk-inbox",
        "receivedDateTime": "2026-08-04T09:00:00Z"
    })
}

fn maildir() -> (tempfile::TempDir, MaildirStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = MaildirStore::open(dir.path()).expect("maildir");
    (dir, store)
}

fn session(server: &Server) -> Session {
    Session::connect_to(&server.url, &Credentials::OAuth2("token".into())).expect("session")
}

fn sync(
    server: &Server,
    store: &mut MaildirStore,
    state: &mut cosmic_pim_mail::store::RemoteIds,
) -> graph::GraphOutcome {
    sync_folder(&session(server), "AAMk-inbox", store, state, 1_000).expect("sync")
}

#[test]
fn a_first_pass_walks_the_delta_feed_and_stores_verbatim_bytes() {
    let server = serve(vec![
        Message::new("m1", RAW_ONE),
        Message::new("m2", RAW_TWO),
    ]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());

    let outcome = sync(&server, &mut store, &mut state);

    assert!(outcome.bootstrapped);
    assert_eq!(outcome.fetched, 2);

    // The invariant: the bytes are `$value`'s, not Graph's rendered `body`.
    let uid = state.uid_of("m1").expect("uid");
    assert_eq!(store.raw(uid).expect("read").expect("bytes"), RAW_ONE);
    assert!(server.calls().iter().any(|call| call == "value m1"));
}

#[test]
fn the_delta_link_makes_the_next_pass_incremental() {
    let server = serve(vec![Message::new("m1", RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());
    sync(&server, &mut store, &mut state);

    server.forget_calls();
    let outcome = sync(&server, &mut store, &mut state);

    assert!(!outcome.bootstrapped, "the folder was read from scratch again");
    assert_eq!(outcome.fetched, 0);
    assert!(
        server.calls().iter().any(|call| call.starts_with("delta ")),
        "the stored delta link was not used: {:?}",
        server.calls()
    );
    assert!(!server.calls().iter().any(|call| call.starts_with("value")));
}

#[test]
fn a_new_message_arrives_through_the_delta_feed() {
    let server = serve(vec![Message::new("m1", RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());
    sync(&server, &mut store, &mut state);

    server.deliver(Message::new("m2", RAW_TWO));
    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.fetched, 1);
    assert_eq!(store.state().expect("state").entries.len(), 2);

    let uid = state.uid_of("m2").expect("uid");
    assert_eq!(store.raw(uid).expect("read").expect("bytes"), RAW_TWO);
}

#[test]
fn a_read_mark_from_elsewhere_costs_no_download() {
    let server = serve(vec![Message::new("m1", RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());
    sync(&server, &mut store, &mut state);

    server.mark_read("m1");
    server.forget_calls();
    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.reflagged, 1);
    assert_eq!(outcome.fetched, 0);
    assert!(!server.calls().iter().any(|call| call.starts_with("value")));

    let uid = state.uid_of("m1").expect("uid");
    assert!(store.state().expect("state").entries[&uid].seen);
}

#[test]
fn a_changed_tombstone_does_not_delete_the_message() {
    // THE case. Exchange uses the `@removed` shape for a property change as
    // well as for a deletion; a client that treats them alike silently drops
    // mail somebody just edited.
    let server = serve(vec![Message::new("m1", RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());
    sync(&server, &mut store, &mut state);

    server.changed_tombstone("m1");
    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.removed, 0, "a `changed` tombstone deleted the message");
    assert_eq!(store.state().expect("state").entries.len(), 1);
    assert!(state.uid_of("m1").is_some());
}

#[test]
fn a_deleted_tombstone_does_delete_it() {
    let server = serve(vec![
        Message::new("m1", RAW_ONE),
        Message::new("m2", RAW_TWO),
    ]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());
    sync(&server, &mut store, &mut state);

    server.delete("m2");
    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.removed, 1);
    assert_eq!(store.state().expect("state").entries.len(), 1);
    assert!(state.uid_of("m1").is_some(), "the wrong message was removed");
}

#[test]
fn an_expired_delta_link_re_reads_the_folder_rather_than_emptying_it() {
    // 410 means "I cannot tell you what changed". Reading it as "nothing
    // changed" freezes the folder; reading it as "everything is gone" empties
    // the maildir.
    let server = serve(vec![Message::new("m1", RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());
    sync(&server, &mut store, &mut state);

    server.deliver(Message::new("m2", RAW_TWO));
    server.expire_cursors();
    server.forget_calls();

    let outcome = sync(&server, &mut store, &mut state);

    assert!(outcome.bootstrapped, "the expired cursor did not trigger a re-read");
    assert_eq!(
        store.state().expect("state").entries.len(),
        2,
        "the message that arrived while the cursor was stale never landed"
    );
    assert!(
        server.calls().iter().any(|call| call == "delta start"),
        "no fresh delta query was made: {:?}",
        server.calls()
    );
}

#[test]
fn a_local_flag_change_is_patched_before_the_pull() {
    use cosmic_pim_mail::model::Flags;
    use cosmic_pim_mail::push::{PushOp, PushQueue};

    let server = serve(vec![Message::new("m1", RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());
    sync(&server, &mut store, &mut state);

    let uid = state.uid_of("m1").expect("uid");
    store
        .enqueue(PushOp::SetFlags {
            uid,
            flags: Flags {
                seen: true,
                flagged: true,
                ..Default::default()
            },
        })
        .expect("enqueue");

    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.pushed.succeeded, 1);
    assert_eq!(
        server.flags_of("m1"),
        Some((true, true)),
        "the flag change never reached the server"
    );
}

#[test]
fn a_local_delete_reaches_the_server_and_frees_the_mapping() {
    use cosmic_pim_mail::push::{PushOp, PushQueue};

    let server = serve(vec![Message::new("m1", RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());
    sync(&server, &mut store, &mut state);

    let uid = state.uid_of("m1").expect("uid");
    store.enqueue(PushOp::Delete { uid }).expect("enqueue");

    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.pushed.succeeded, 1);
    assert!(server.calls().iter().any(|call| call == "delete m1"));
    assert!(
        state.uid_of("m1").is_none(),
        "the id mapping survived the delete"
    );
}

#[test]
fn a_move_forgets_the_old_id_because_exchange_issues_a_new_one() {
    // Graph's move re-creates the message in the destination and returns a
    // different id. Keeping the old mapping leaves a UID pointing at nothing.
    use cosmic_pim_mail::push::{PushOp, PushQueue};

    let server = serve(vec![Message::new("m1", RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = graph::state(dir.path());
    sync(&server, &mut store, &mut state);

    let uid = state.uid_of("m1").expect("uid");
    store
        .enqueue(PushOp::Move {
            uid,
            destination: "AAMk-archive".into(),
        })
        .expect("enqueue");

    let outcome = sync(&server, &mut store, &mut state);

    assert_eq!(outcome.pushed.succeeded, 1);
    assert!(server.calls().iter().any(|call| call == "move m1"));
    assert!(state.uid_of("m1").is_none());
}

#[test]
fn a_folder_listing_keeps_the_users_own_language() {
    let server = serve(vec![]);
    let folders = session(&server).folders().expect("folders");

    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].slug(), "inbox", "the well-known name was not used");
    assert_eq!(
        folders[0].display_name, "Posteingang",
        "the display name was replaced by a slug"
    );
}

fn draft() -> cosmic_pim_mail::Draft {
    use cosmic_pim_mail::model::Mailbox;
    let mut draft = cosmic_pim_mail::Draft::new(Mailbox {
        name: Some("Ada".into()),
        address: "ada@example.com".into(),
    });
    draft.to.push(Mailbox {
        name: None,
        address: "bob@example.com".into(),
    });
    draft.bcc.push(Mailbox {
        name: None,
        address: "hidden@example.com".into(),
    });
    draft.subject = "Outbound".into();
    draft.body = "Hello over Graph.".into();
    draft
}

fn queued_outbox(dir: &std::path::Path) -> cosmic_pim_mail::Outbox {
    let outbox = cosmic_pim_mail::Outbox::open(dir.join("outbox")).expect("outbox");
    outbox
        .queue(
            "ab12cd",
            &draft(),
            &cosmic_pim_mail::Outcome::NotSent(cosmic_pim_mail::Error::Smtp(
                "first attempt failed".into(),
            )),
            0,
        )
        .expect("queue");
    outbox
}

#[test]
fn a_queued_send_leaves_through_send_mail_with_its_bcc_intact() {
    // The path that still works when the tenant has SMTP AUTH switched off.
    let server = serve(vec![]);
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = queued_outbox(dir.path());

    let outcome = outbox
        .drain_with(|draft| session(&server).submit(draft), i64::MAX / 2)
        .expect("drain");

    assert_eq!(outcome.sent.len(), 1);
    assert_eq!(outbox.count(), 0, "the queue entry outlived its send");

    let submitted = server.submitted();
    assert_eq!(submitted.len(), 1);
    let text = String::from_utf8_lossy(&submitted[0]);
    assert!(text.contains("Subject: Outbound"));
    // No envelope over an API: recipients derive from the headers, and
    // Exchange strips Bcc on delivery. Stripping it ourselves means the
    // blind-copied recipient never receives the message.
    assert!(
        text.contains("hidden@example.com"),
        "the Bcc recipient was stripped from the submission: {text}"
    );
    assert_eq!(submitted[0], outcome.sent[0].1, "the wire copy differs from the accepted one");
}

#[test]
fn a_refused_send_stays_queued_rather_than_vanishing() {
    let server = serve(vec![]);
    server.refuse_sends();
    let dir = tempfile::tempdir().expect("tempdir");
    let outbox = queued_outbox(dir.path());

    let outcome = outbox
        .drain_with(|draft| session(&server).submit(draft), i64::MAX / 2)
        .expect("drain");

    assert!(outcome.sent.is_empty());
    assert_eq!(outcome.deferred, 1, "a refused send was not rescheduled");
    assert_eq!(outbox.count(), 1, "a refused send vanished from the queue");
    assert!(server.submitted().is_empty());
}

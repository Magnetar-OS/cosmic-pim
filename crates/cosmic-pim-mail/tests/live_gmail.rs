// SPDX-License-Identifier: MPL-2.0

//! A canned Gmail API driving the real client into a real maildir.
//!
//! The unit tests cover the label model in isolation. This is what proves the
//! engine walks an account over HTTP and leaves the right bytes on disk — and
//! in particular that the two things IMAP cannot do actually work:
//!
//! - an **archive** performed elsewhere (INBOX removed) reaches this client
//!   through `history.list` and empties the message out of the inbox maildir;
//! - an **expired cursor** (404 from `history.list`) re-bootstraps rather than
//!   freezing the account or emptying it.
//!
//! The server is stateful, like the JMAP one, because neither of those can be
//! expressed against a fixture that only serves a frozen mailbox.

use std::sync::{Arc, Mutex};

use cosmic_pim_mail::Credentials;
use cosmic_pim_mail::gmail::{self, Session, sync_folder};
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
    labels: Vec<String>,
    raw: Vec<u8>,
}

impl Message {
    fn new(id: &str, labels: &[&str], raw: &[u8]) -> Self {
        Self {
            id: id.to_owned(),
            labels: labels.iter().map(|l| (*l).to_owned()).collect(),
            raw: raw.to_vec(),
        }
    }
}

/// One `history.list` record.
#[derive(Clone)]
struct HistoryRecord {
    at: u64,
    id: String,
    kind: &'static str,
}

struct ServerState {
    messages: Vec<Message>,
    history_id: u64,
    history: Vec<HistoryRecord>,
    /// Below this, `history.list` answers 404 — Gmail's retention horizon.
    floor: u64,
}

impl ServerState {
    fn record(&mut self, id: &str, kind: &'static str) {
        self.history_id += 1;
        self.history.push(HistoryRecord {
            at: self.history_id,
            id: id.to_owned(),
            kind,
        });
    }
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

    /// Applies a label change the way another client would.
    fn relabel(&self, id: &str, add: &[&str], remove: &[&str]) {
        let mut inner = self.inner.lock().expect("state");
        if let Some(message) = inner.messages.iter_mut().find(|m| m.id == id) {
            for label in remove {
                message.labels.retain(|l| l != label);
            }
            for label in add {
                if !message.labels.iter().any(|l| l == label) {
                    message.labels.push((*label).to_owned());
                }
            }
        }
        let kind = if add.is_empty() {
            "labelsRemoved"
        } else {
            "labelsAdded"
        };
        inner.record(id, kind);
    }

    fn deliver(&self, message: Message) {
        let mut inner = self.inner.lock().expect("state");
        let id = message.id.clone();
        inner.messages.push(message);
        inner.record(&id, "messagesAdded");
    }

    fn purge(&self, id: &str) {
        let mut inner = self.inner.lock().expect("state");
        inner.messages.retain(|m| m.id != id);
        inner.record(id, "messagesDeleted");
    }

    /// Rolls the history window past everything so far, so an older cursor is
    /// answered with a 404 — Gmail's ~week of retention, compressed.
    fn expire_history(&self) {
        let mut inner = self.inner.lock().expect("state");
        inner.floor = inner.history_id;
        inner.history.clear();
    }

    fn labels_of(&self, id: &str) -> Vec<String> {
        self.inner
            .lock()
            .expect("state")
            .messages
            .iter()
            .find(|m| m.id == id)
            .map(|m| m.labels.clone())
            .unwrap_or_default()
    }
}

/// The URL prefix the engine uses. The test server answers the same paths
/// under its own root, so the engine's `BASE` is redirected by pointing it at
/// a local address — done by overriding the constant through the environment
/// is not possible, so instead the fixture asserts on paths and the engine is
/// exercised through a proxy base injected at construction.
fn serve(messages: Vec<Message>) -> Server {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let port = server.server_addr().to_ip().expect("ip").port();
    let url = format!("http://127.0.0.1:{port}");

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&calls);

    let inner = Arc::new(Mutex::new(ServerState {
        messages,
        history_id: 100,
        history: Vec::new(),
        floor: 0,
    }));
    let held = Arc::clone(&inner);

    let handle = std::thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let target = request.url().to_owned();
            let method = request.method().as_str().to_owned();
            let mut body = String::new();
            let _ = request.as_reader().read_to_string(&mut body);

            let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
            let params = parse_query(query);
            let mut state = held.lock().expect("state");

            let (status, payload) = route(
                &method,
                path,
                &params,
                &body,
                &mut state,
                &recorded,
            );
            drop(state);

            let response = tiny_http::Response::from_string(payload)
                .with_status_code(status)
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

fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn first<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn route(
    method: &str,
    path: &str,
    params: &[(String, String)],
    _body: &str,
    state: &mut ServerState,
    calls: &Arc<Mutex<Vec<String>>>,
) -> (u16, String) {
    let note = |what: String| calls.lock().expect("calls").push(what);

    // /gmail/v1/users/me/…
    let tail = path.rsplit("/users/me").next().unwrap_or(path);

    if tail == "/profile" {
        note("profile".to_owned());
        return (
            200,
            json!({ "historyId": state.history_id.to_string() }).to_string(),
        );
    }

    if tail == "/history" {
        let since: u64 = first(params, "startHistoryId")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        note(format!("history {since}"));

        if since < state.floor {
            // The cursor predates retention. Gmail answers 404.
            return (404, json!({ "error": { "code": 404 } }).to_string());
        }

        let mut records = Vec::new();
        for record in state.history.iter().filter(|r| r.at > since) {
            records.push(json!({
                record.kind: [ { "message": { "id": record.id } } ]
            }));
        }

        return (
            200,
            json!({
                "history": records,
                "historyId": state.history_id.to_string()
            })
            .to_string(),
        );
    }

    if tail == "/messages" {
        let label = first(params, "labelIds").unwrap_or_default().to_owned();
        note(format!("list {label}"));

        let ids: Vec<Value> = state
            .messages
            .iter()
            .filter(|m| m.labels.iter().any(|l| l == &label))
            .map(|m| json!({ "id": m.id }))
            .collect();

        return (200, json!({ "messages": ids }).to_string());
    }

    if let Some(rest) = tail.strip_prefix("/messages/") {
        // /messages/{id}          (GET, with format=)
        // /messages/{id}/modify   (POST)
        // /messages/{id}/trash    (POST)
        let (id, action) = match rest.split_once('/') {
            Some((id, action)) => (id, action),
            None => (rest, ""),
        };

        if method == "POST" && action == "modify" {
            note(format!("modify {id}"));
            // The engine's own request body is applied by the caller in these
            // tests through `relabel`; here it is enough to acknowledge.
            return (200, json!({ "id": id }).to_string());
        }
        if method == "POST" && action == "trash" {
            note(format!("trash {id}"));
            if let Some(message) = state.messages.iter_mut().find(|m| m.id == id) {
                message.labels.retain(|l| l != "INBOX");
                message.labels.push("TRASH".to_owned());
            }
            state.record(id, "labelsAdded");
            return (200, json!({ "id": id }).to_string());
        }

        let Some(message) = state.messages.iter().find(|m| m.id == id).cloned() else {
            return (404, json!({ "error": { "code": 404 } }).to_string());
        };

        return match first(params, "format") {
            Some("raw") => {
                note(format!("raw {id}"));
                let encoded = base64_url(&message.raw);
                (200, json!({ "id": id, "raw": encoded }).to_string())
            }
            _ => {
                note(format!("meta {id}"));
                (
                    200,
                    json!({
                        "id": id,
                        "threadId": format!("t-{id}"),
                        "labelIds": message.labels,
                        "internalDate": "1785834000000"
                    })
                    .to_string(),
                )
            }
        };
    }

    (404, json!({ "error": { "code": 404 } }).to_string())
}

/// Gmail's flavour: url-safe alphabet, no padding.
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn maildir() -> (tempfile::TempDir, MaildirStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = MaildirStore::open(dir.path()).expect("maildir");
    (dir, store)
}

fn session(server: &Server) -> Session {
    Session::connect_to(&server.url, &Credentials::OAuth2("ya29.token".into()))
        .expect("session")
}

fn sync(
    server: &Server,
    slug: &str,
    store: &mut MaildirStore,
    state: &mut cosmic_pim_mail::store::RemoteIds,
) -> gmail::GmailOutcome {
    sync_folder(&session(server), slug, store, state, 500, 1_000).expect("sync")
}

#[test]
fn a_bootstrap_downloads_the_inbox_verbatim() {
    let server = serve(vec![
        Message::new("M1", &["INBOX", "UNREAD"], RAW_ONE),
        Message::new("M2", &["INBOX"], RAW_TWO),
    ]);
    let (dir, mut store) = maildir();
    let mut state = gmail::state(dir.path());

    let outcome = sync(&server, "inbox", &mut store, &mut state);

    assert!(outcome.bootstrapped);
    assert_eq!(outcome.fetched, 2);

    // The invariant: `format=raw`, byte for byte, DKIM signature intact.
    let uid = state.uid_of("M1").expect("a local uid");
    assert_eq!(store.raw(uid).expect("read").expect("bytes"), RAW_ONE);
    assert!(
        server.calls().iter().any(|call| call == "raw M1"),
        "the message was not fetched as raw: {:?}",
        server.calls()
    );
}

#[test]
fn unread_arrives_the_right_way_round() {
    // Gmail marks UNREAD; maildir marks seen. Inverting this wrongly marks a
    // whole mailbox read on every device.
    let server = serve(vec![
        Message::new("M1", &["INBOX", "UNREAD"], RAW_ONE),
        Message::new("M2", &["INBOX"], RAW_TWO),
    ]);
    let (dir, mut store) = maildir();
    let mut state = gmail::state(dir.path());

    sync(&server, "inbox", &mut store, &mut state);

    let entries = store.state().expect("state").entries;
    let unread = state.uid_of("M1").expect("uid");
    let read = state.uid_of("M2").expect("uid");

    assert!(!entries[&unread].seen);
    assert!(entries[&read].seen);
}

#[test]
fn an_archive_performed_elsewhere_empties_the_inbox_maildir() {
    // THE reason this engine exists. Over IMAP, removing the INBOX label is
    // invisible until a full-mailbox reconcile; `history.list` reports it.
    let server = serve(vec![Message::new("M1", &["INBOX"], RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = gmail::state(dir.path());
    sync(&server, "inbox", &mut store, &mut state);
    assert_eq!(store.state().expect("state").entries.len(), 1);

    server.relabel("M1", &[], &["INBOX"]);
    server.forget_calls();
    let outcome = sync(&server, "inbox", &mut store, &mut state);

    assert!(!outcome.bootstrapped, "an incremental pass re-listed the mailbox");
    assert_eq!(outcome.removed, 1);
    assert!(store.state().expect("state").entries.is_empty());
    assert!(state.uid_of("M1").is_none(), "the id mapping outlived the message");
}

#[test]
fn the_archive_maildir_gains_what_the_inbox_lost() {
    // The other half of the same move: the message is not gone, it is
    // somewhere else, and the pass over that maildir fetches it.
    let server = serve(vec![Message::new("M1", &["INBOX"], RAW_ONE)]);
    let (inbox_dir, mut inbox) = maildir();
    let (archive_dir, mut archive) = maildir();
    let mut inbox_state = gmail::state(inbox_dir.path());
    let mut archive_state = gmail::state(archive_dir.path());

    sync(&server, "inbox", &mut inbox, &mut inbox_state);
    sync(&server, "archive", &mut archive, &mut archive_state);
    assert!(archive.state().expect("state").entries.is_empty());

    server.relabel("M1", &[], &["INBOX"]);

    sync(&server, "inbox", &mut inbox, &mut inbox_state);
    let outcome = sync(&server, "archive", &mut archive, &mut archive_state);

    assert_eq!(outcome.fetched, 1);
    assert_eq!(archive.state().expect("state").entries.len(), 1);
    assert!(inbox.state().expect("state").entries.is_empty());
}

#[test]
fn a_flag_changed_elsewhere_costs_no_download() {
    let server = serve(vec![Message::new("M1", &["INBOX", "UNREAD"], RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = gmail::state(dir.path());
    sync(&server, "inbox", &mut store, &mut state);

    server.relabel("M1", &[], &["UNREAD"]);
    server.forget_calls();
    let outcome = sync(&server, "inbox", &mut store, &mut state);

    assert_eq!(outcome.reflagged, 1);
    assert_eq!(outcome.fetched, 0);
    assert!(
        !server.calls().iter().any(|call| call.starts_with("raw")),
        "a label change re-downloaded the message"
    );

    let uid = state.uid_of("M1").expect("uid");
    assert!(store.state().expect("state").entries[&uid].seen);
}

#[test]
fn a_quiet_pass_asks_for_changes_and_downloads_nothing() {
    let server = serve(vec![Message::new("M1", &["INBOX"], RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = gmail::state(dir.path());
    sync(&server, "inbox", &mut store, &mut state);

    server.forget_calls();
    let outcome = sync(&server, "inbox", &mut store, &mut state);

    assert_eq!(outcome.fetched, 0);
    assert_eq!(outcome.removed, 0);
    assert!(!outcome.bootstrapped);
    assert!(
        !server.calls().iter().any(|call| call.starts_with("list")),
        "a quiet pass re-listed the mailbox: {:?}",
        server.calls()
    );
}

#[test]
fn an_expired_cursor_re_bootstraps_rather_than_freezing_or_emptying() {
    // The load-bearing case. A 404 from history.list means "I cannot tell you
    // what changed" — never "nothing changed" (which freezes the account) and
    // never "everything was deleted" (which empties the maildir).
    let server = serve(vec![Message::new("M1", &["INBOX"], RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = gmail::state(dir.path());
    sync(&server, "inbox", &mut store, &mut state);

    // Time passes; a message arrives; the history window rolls past our cursor.
    server.deliver(Message::new("M2", &["INBOX"], RAW_TWO));
    server.expire_history();
    server.forget_calls();

    let outcome = sync(&server, "inbox", &mut store, &mut state);

    assert!(outcome.bootstrapped, "the expired cursor did not trigger a re-read");
    assert_eq!(
        store.state().expect("state").entries.len(),
        2,
        "the message that arrived while the cursor was stale never landed"
    );
    assert!(
        server.calls().iter().any(|call| call.starts_with("list")),
        "no listing was made: {:?}",
        server.calls()
    );
}

#[test]
fn a_purged_message_is_removed_surgically() {
    let server = serve(vec![
        Message::new("M1", &["INBOX"], RAW_ONE),
        Message::new("M2", &["INBOX"], RAW_TWO),
    ]);
    let (dir, mut store) = maildir();
    let mut state = gmail::state(dir.path());
    sync(&server, "inbox", &mut store, &mut state);

    server.purge("M2");
    let outcome = sync(&server, "inbox", &mut store, &mut state);

    assert_eq!(outcome.removed, 1);
    assert_eq!(store.state().expect("state").entries.len(), 1);
    assert!(state.uid_of("M1").is_some(), "the wrong message was removed");
}

#[test]
fn a_local_delete_goes_to_the_bin_rather_than_being_purged() {
    // `messages.delete` is permanent and irreversible. A delete key must not
    // mean that.
    use cosmic_pim_mail::push::{PushOp, PushQueue};

    let server = serve(vec![Message::new("M1", &["INBOX"], RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = gmail::state(dir.path());
    sync(&server, "inbox", &mut store, &mut state);

    let uid = state.uid_of("M1").expect("uid");
    store.enqueue(PushOp::Delete { uid }).expect("enqueue");

    let outcome = sync(&server, "inbox", &mut store, &mut state);

    assert_eq!(outcome.pushed.succeeded, 1);
    assert!(
        server.calls().iter().any(|call| call == "trash M1"),
        "the message was purged rather than binned: {:?}",
        server.calls()
    );
    assert!(server.labels_of("M1").iter().any(|l| l == "TRASH"));
}

#[test]
fn a_local_archive_removes_the_inbox_label() {
    use cosmic_pim_mail::push::{PushOp, PushQueue};

    let server = serve(vec![Message::new("M1", &["INBOX"], RAW_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = gmail::state(dir.path());
    sync(&server, "inbox", &mut store, &mut state);

    let uid = state.uid_of("M1").expect("uid");
    store
        .enqueue(PushOp::Move {
            uid,
            destination: "archive".into(),
        })
        .expect("enqueue");

    let outcome = sync(&server, "inbox", &mut store, &mut state);

    assert_eq!(outcome.pushed.succeeded, 1);
    assert!(
        server.calls().iter().any(|call| call == "modify M1"),
        "no label change was sent: {:?}",
        server.calls()
    );
    assert!(
        state.uid_of("M1").is_none(),
        "the id mapping survived an archive, so the next pass sees a message it thinks it holds"
    );
}

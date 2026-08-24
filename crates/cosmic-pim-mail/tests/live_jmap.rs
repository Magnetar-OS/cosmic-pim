// SPDX-License-Identifier: MPL-2.0

//! A canned JMAP server driving the real client into a real maildir.
//!
//! The unit tests cover keyword mapping and the sidecar; this proves the
//! session actually walks a mailbox — session resource, `Email/query`,
//! `Email/get`, a blob download per message — and leaves the right bytes on
//! disk. Same job as `live_sync.rs` for IMAP and `live_pop3.rs` for POP3.
//!
//! The most important thing it asserts is that the message stored is the one
//! the download endpoint served, byte for byte, and not something reassembled
//! from `Email/get`. That is the invariant the whole crate is built on and the
//! one a JMAP client is most tempted to break, because the parsed object is
//! right there in the response.

use std::sync::{Arc, Mutex};

use cosmic_pim_mail::jmap::{JmapState, Session, sync_mailbox};
use cosmic_pim_mail::maildir::MaildirStore;
use cosmic_pim_mail::store::MailStore;
use cosmic_pim_mail::Credentials;
use serde_json::{Value, json};

/// The bytes the download endpoint serves. Deliberately carries a header the
/// model does not keep and an unusual MIME shape, so a reassembled copy would
/// not match.
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

struct Server {
    url: String,
    calls: Arc<Mutex<Vec<String>>>,
    _handle: std::thread::JoinHandle<()>,
}

impl Server {
    /// The JMAP method names invoked, in order.
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }

    fn session_url(&self) -> String {
        format!("{}/session", self.url)
    }
}

/// Serves a fixed account: one mailbox, the emails given, and their blobs.
fn serve(emails: Vec<(&'static str, &'static str, &'static [u8], Value)>) -> Server {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let port = server.server_addr().to_ip().expect("ip").port();
    let url = format!("http://127.0.0.1:{port}");
    let base = url.clone();

    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&calls);

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

                let found = emails.iter().find(|(_, blob, _, _)| *blob == blob_id);
                let response = match found {
                    Some((_, _, raw, _)) => tiny_http::Response::from_data(raw.to_vec())
                        .with_status_code(200),
                    None => tiny_http::Response::from_string("no such blob")
                        .with_status_code(404),
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
                    let call_id = call.get(2).and_then(Value::as_str).unwrap_or("0").to_owned();
                    recorded.lock().expect("calls").push(name.clone());

                    let args = match name.as_str() {
                        "Mailbox/get" => json!({
                            "accountId": "acct-1",
                            "list": [ {
                                "id": "mbox-1",
                                "name": "Inbox",
                                "role": "inbox",
                                "totalEmails": emails.len(),
                                "unreadEmails": 0
                            } ]
                        }),
                        "Email/query" => json!({
                            "accountId": "acct-1",
                            "ids": emails.iter().map(|(id, _, _, _)| *id).collect::<Vec<_>>()
                        }),
                        "Email/get" => {
                            let wanted: Vec<String> = call
                                .get(1)
                                .and_then(|a| a.get("ids"))
                                .and_then(Value::as_array)
                                .map(|ids| {
                                    ids.iter()
                                        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                                        .collect()
                                })
                                .unwrap_or_default();

                            let list: Vec<Value> = emails
                                .iter()
                                .filter(|(id, _, _, _)| wanted.iter().any(|w| w == id))
                                .map(|(id, blob, raw, keywords)| {
                                    json!({
                                        "id": id,
                                        "blobId": blob,
                                        "keywords": keywords,
                                        "receivedAt": "2026-08-04T09:00:00Z",
                                        "size": raw.len()
                                    })
                                })
                                .collect();

                            json!({ "accountId": "acct-1", "list": list, "notFound": [] })
                        }
                        _ => json!({ "accountId": "acct-1" }),
                    };

                    responses.push(json!([name, args, call_id]));
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
        _handle: handle,
    }
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
    let server = serve(vec![("M1", "B1", RAW_ONE, json!({ "$seen": true }))]);
    let session = connect(&server);

    let mailboxes = session.mailboxes().expect("mailboxes");

    assert_eq!(mailboxes.len(), 1);
    assert_eq!(mailboxes[0].role.as_deref(), Some("inbox"));
    assert_eq!(mailboxes[0].name, "Inbox");
}

#[test]
fn a_first_pass_downloads_every_message_into_the_maildir() {
    let server = serve(vec![
        ("M1", "B1", RAW_ONE, json!({ "$seen": true })),
        ("M2", "B2", RAW_TWO, json!({})),
    ]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    let session = connect(&server);

    let outcome = sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("sync");

    assert_eq!(outcome.fetched, 2);
    assert_eq!(store.state().expect("state").entries.len(), 2);
}

#[test]
fn the_bytes_stored_are_the_ones_the_server_served() {
    // The invariant. `Email/get` hands over a parsed object and it is tempting
    // to store that; a reassembled message has a different MIME structure and
    // an invalid DKIM signature, and nothing notices until it is forwarded.
    let server = serve(vec![("M1", "B1", RAW_ONE, json!({ "$seen": true }))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    let session = connect(&server);

    sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("sync");

    let uid = state.uid_of("M1").expect("a local uid");
    let raw = store.raw(uid).expect("read").expect("bytes");

    assert_eq!(raw, RAW_ONE, "the stored message is not the served one");
    assert!(
        server.calls().iter().any(|call| call == "download B1"),
        "the message was never downloaded: {:?}",
        server.calls()
    );
}

#[test]
fn keywords_arrive_as_flags() {
    let server = serve(vec![(
        "M1",
        "B1",
        RAW_ONE,
        json!({ "$seen": true, "$flagged": true }),
    )]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    let session = connect(&server);

    sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("sync");

    let uid = state.uid_of("M1").expect("a local uid");
    let flags = store.state().expect("state").entries[&uid];

    assert!(flags.seen);
    assert!(flags.flagged);
    assert!(!flags.answered);
}

#[test]
fn a_second_pass_downloads_nothing_it_already_has() {
    let server = serve(vec![
        ("M1", "B1", RAW_ONE, json!({ "$seen": true })),
        ("M2", "B2", RAW_TWO, json!({})),
    ]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    let session = connect(&server);

    sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("first");
    state.save(dir.path()).expect("save");

    let mut reloaded = JmapState::load(dir.path());
    let outcome =
        sync_mailbox(&session, "mbox-1", &mut store, &mut reloaded, 500).expect("second");

    assert_eq!(outcome.fetched, 0, "the mailbox was downloaded twice");
    assert_eq!(
        server
            .calls()
            .iter()
            .filter(|call| call.starts_with("download"))
            .count(),
        2,
        "a blob was downloaded again on the second pass"
    );
}

#[test]
fn a_flag_changed_on_the_server_costs_no_download() {
    // The whole point of keeping metadata and bytes separate: starring a
    // message must not re-fetch it.
    let server = serve(vec![("M1", "B1", RAW_ONE, json!({ "$seen": true }))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    let session = connect(&server);
    sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("first");

    // The same message, now flagged.
    let server = serve(vec![(
        "M1",
        "B1",
        RAW_ONE,
        json!({ "$seen": true, "$flagged": true }),
    )]);
    let session = connect(&server);
    let outcome = sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("second");

    assert_eq!(outcome.reflagged, 1);
    assert_eq!(outcome.fetched, 0);
    assert!(
        !server.calls().iter().any(|call| call.starts_with("download")),
        "a flag change re-downloaded the message"
    );

    let uid = state.uid_of("M1").expect("a local uid");
    assert!(store.state().expect("state").entries[&uid].flagged);
}

#[test]
fn a_message_that_left_the_mailbox_is_removed_locally() {
    let server = serve(vec![
        ("M1", "B1", RAW_ONE, json!({})),
        ("M2", "B2", RAW_TWO, json!({})),
    ]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    let session = connect(&server);
    sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("first");

    let server = serve(vec![("M1", "B1", RAW_ONE, json!({}))]);
    let session = connect(&server);
    let outcome = sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("second");

    assert_eq!(outcome.removed, 1);
    assert_eq!(store.state().expect("state").entries.len(), 1);
}

#[test]
fn an_empty_listing_does_not_empty_the_maildir() {
    // The mass-delete guard, the same one the CalDAV planner has. A server
    // having a moment must not cost the user their mailbox.
    let server = serve(vec![("M1", "B1", RAW_ONE, json!({}))]);
    let (dir, mut store) = maildir();
    let mut state = JmapState::load(dir.path());
    let session = connect(&server);
    sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("first");

    let server = serve(vec![]);
    let session = connect(&server);
    let outcome = sync_mailbox(&session, "mbox-1", &mut store, &mut state, 500).expect("second");

    assert_eq!(outcome.removed, 0, "an empty listing wiped the mailbox");
    assert_eq!(store.state().expect("state").entries.len(), 1);
}

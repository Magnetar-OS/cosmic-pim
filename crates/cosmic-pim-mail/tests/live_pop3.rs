// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! A canned-response POP3 server driving the real client into a real maildir.
//!
//! The unit tests cover dot-unstuffing and the sidecar in isolation; this is
//! what proves a session actually walks a mailbox over a socket and leaves the
//! right files behind. It is the same job `live_sync.rs` does for IMAP, and it
//! exists for the same reason: the steps being individually correct is not the
//! same as their being wired together in the right order.
//!
//! The server is deliberately literal — it answers exactly what a scenario
//! needs — and it records the commands it received, because half of what
//! matters about POP3 is *which* commands were sent and when.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use cosmic_pim_mail::Credentials;
use cosmic_pim_mail::imap::Security;
use cosmic_pim_mail::maildir::MaildirStore;
use cosmic_pim_mail::pop3::{Endpoint, Pop3State, Retention, Session, sync_inbox};
use cosmic_pim_mail::store::MailStore;

const MESSAGE_ONE: &str = "From: ada@example.com\r\n\
Subject: First\r\n\
Message-ID: <one@example.com>\r\n\
\r\n\
Hello.\r\n";

/// A message whose body contains a line starting with a full stop — the case
/// dot-stuffing exists for, and the one that corrupts silently when a client
/// forgets to un-stuff it.
const MESSAGE_TWO: &str = "From: ada@example.com\r\n\
Subject: Second\r\n\
Message-ID: <two@example.com>\r\n\
\r\n\
A line follows that starts with a dot:\r\n\
.hidden\r\n\
End.\r\n";

struct Server {
    endpoint: Endpoint,
    log: Arc<Mutex<Vec<String>>>,
    _handle: thread::JoinHandle<()>,
}

impl Server {
    fn commands(&self) -> Vec<String> {
        self.log.lock().expect("log").clone()
    }
}

/// Serves a fixed mailbox of `(uidl, body)` until the client quits.
fn serve(messages: Vec<(&'static str, &'static str)>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&log);

    let handle = thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let mut writer = stream.try_clone().expect("clone");
        let mut reader = BufReader::new(stream);

        // Numbers are positions, and a deleted message keeps its position for
        // the rest of the session — exactly as RFC 1939 requires.
        let mut deleted = vec![false; messages.len()];

        let _ = writer.write_all(b"+OK canned POP3 ready\r\n");

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let line = line.trim_end().to_owned();
            recorded.lock().expect("log").push(line.clone());

            let mut parts = line.split_whitespace();
            let verb = parts.next().unwrap_or("").to_ascii_uppercase();
            let argument = parts.next().unwrap_or("");

            let response: Vec<u8> = match verb.as_str() {
                "CAPA" => b"+OK\r\nUIDL\r\nUSER\r\nSASL PLAIN XOAUTH2\r\n.\r\n".to_vec(),
                "USER" | "PASS" => b"+OK\r\n".to_vec(),
                "AUTH" => b"+OK signed in\r\n".to_vec(),
                "STAT" => {
                    let live = deleted.iter().filter(|d| !**d).count();
                    format!("+OK {live} 1024\r\n").into_bytes()
                }
                "UIDL" => {
                    let mut out = String::from("+OK\r\n");
                    for (index, (uidl, _)) in messages.iter().enumerate() {
                        if !deleted[index] {
                            out.push_str(&format!("{} {uidl}\r\n", index + 1));
                        }
                    }
                    out.push_str(".\r\n");
                    out.into_bytes()
                }
                "RETR" => match argument.parse::<usize>() {
                    Ok(number) if number >= 1 && number <= messages.len() => {
                        let body = messages[number - 1].1;
                        let mut out = format!("+OK {} octets\r\n", body.len());
                        // Dot-stuff on the way out, as a server must.
                        for text_line in body.split_terminator("\r\n") {
                            if text_line.starts_with('.') {
                                out.push('.');
                            }
                            out.push_str(text_line);
                            out.push_str("\r\n");
                        }
                        out.push_str(".\r\n");
                        out.into_bytes()
                    }
                    _ => b"-ERR no such message\r\n".to_vec(),
                },
                "DELE" => match argument.parse::<usize>() {
                    Ok(number) if number >= 1 && number <= messages.len() => {
                        deleted[number - 1] = true;
                        b"+OK marked\r\n".to_vec()
                    }
                    _ => b"-ERR no such message\r\n".to_vec(),
                },
                "QUIT" => {
                    let _ = writer.write_all(b"+OK bye\r\n");
                    return;
                }
                _ => b"-ERR unknown command\r\n".to_vec(),
            };

            if writer.write_all(&response).is_err() {
                return;
            }
        }
    });

    Server {
        endpoint: Endpoint {
            host: "127.0.0.1".into(),
            port,
            security: Security::Plaintext,
            username: "ada@example.com".into(),
        },
        log,
        _handle: handle,
    }
}

fn maildir() -> (tempfile::TempDir, MaildirStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = MaildirStore::open(dir.path()).expect("maildir");
    (dir, store)
}

fn connect(server: &Server) -> Session {
    Session::connect(&server.endpoint, &Credentials::Password("hunter2".into()))
        .expect("connect and sign in")
}

#[test]
fn a_first_pass_downloads_the_mailbox_into_the_maildir() {
    let server = serve(vec![("uid-1", MESSAGE_ONE), ("uid-2", MESSAGE_TWO)]);
    let (dir, mut store) = maildir();
    let mut state = Pop3State::load(dir.path());
    let mut session = connect(&server);

    let outcome = sync_inbox(
        &mut session,
        &mut store,
        &mut state,
        Retention::LeaveOnServer,
        1_000,
    )
    .expect("sync");

    assert_eq!(outcome.fetched, 2);
    assert_eq!(outcome.deleted, 0);
    assert_eq!(store.state().expect("state").entries.len(), 2);
}

#[test]
fn a_dot_stuffed_line_survives_the_whole_trip() {
    // The corruption this protocol is famous for. It reaches disk, so it is
    // asserted on the bytes in the maildir rather than on a parser's output.
    let server = serve(vec![("uid-2", MESSAGE_TWO)]);
    let (dir, mut store) = maildir();
    let mut state = Pop3State::load(dir.path());
    let mut session = connect(&server);

    sync_inbox(
        &mut session,
        &mut store,
        &mut state,
        Retention::LeaveOnServer,
        1_000,
    )
    .expect("sync");

    let uid = *store
        .state()
        .expect("state")
        .entries
        .keys()
        .next()
        .expect("one message");
    let raw = store.raw(uid).expect("read").expect("bytes");
    let text = String::from_utf8_lossy(&raw);

    assert!(
        text.contains("\r\n.hidden\r\n"),
        "the leading dot was not un-stuffed: {text:?}"
    );
    assert!(
        !text.contains("..hidden"),
        "the stuffing byte was stored as part of the message"
    );
}

#[test]
fn a_second_pass_downloads_nothing_it_already_has() {
    // Without a durable UIDL map this re-downloads the mailbox on every pass,
    // which is the other classic POP3 failure.
    let server = serve(vec![("uid-1", MESSAGE_ONE), ("uid-2", MESSAGE_TWO)]);
    let (dir, mut store) = maildir();
    let mut state = Pop3State::load(dir.path());

    let mut session = connect(&server);
    sync_inbox(
        &mut session,
        &mut store,
        &mut state,
        Retention::LeaveOnServer,
        1_000,
    )
    .expect("first pass");
    state.save(dir.path()).expect("save");
    session.quit().expect("quit");

    // A new process: nothing but the sidecar carries over.
    let server = serve(vec![("uid-1", MESSAGE_ONE), ("uid-2", MESSAGE_TWO)]);
    let mut reloaded = Pop3State::load(dir.path());
    let mut session = connect(&server);

    let outcome = sync_inbox(
        &mut session,
        &mut store,
        &mut reloaded,
        Retention::LeaveOnServer,
        2_000,
    )
    .expect("second pass");

    assert_eq!(outcome.fetched, 0, "the mailbox was downloaded twice");
    assert_eq!(outcome.skipped, 2);
    assert!(
        !server.commands().iter().any(|c| c.starts_with("RETR")),
        "a RETR was issued for a message already on disk"
    );
}

#[test]
fn leaving_on_the_server_issues_no_deletions() {
    // The default, and the only safe choice when the same account is read on a
    // phone. A stray DELE here destroys someone's mail.
    let server = serve(vec![("uid-1", MESSAGE_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = Pop3State::load(dir.path());
    let mut session = connect(&server);

    sync_inbox(
        &mut session,
        &mut store,
        &mut state,
        Retention::LeaveOnServer,
        1_000,
    )
    .expect("sync");

    assert!(
        !server.commands().iter().any(|c| c.starts_with("DELE")),
        "the default retention deleted mail from the server"
    );
}

#[test]
fn deleting_when_fetched_happens_after_the_message_is_on_disk() {
    let server = serve(vec![("uid-1", MESSAGE_ONE)]);
    let (dir, mut store) = maildir();
    let mut state = Pop3State::load(dir.path());
    let mut session = connect(&server);

    let outcome = sync_inbox(
        &mut session,
        &mut store,
        &mut state,
        Retention::DeleteWhenFetched,
        1_000,
    )
    .expect("sync");

    assert_eq!(outcome.deleted, 1);

    let commands = server.commands();
    let retr = commands
        .iter()
        .position(|c| c.starts_with("RETR"))
        .expect("a RETR");
    let dele = commands
        .iter()
        .position(|c| c.starts_with("DELE"))
        .expect("a DELE");
    assert!(
        retr < dele,
        "the message was deleted before it was downloaded: {commands:?}"
    );
    assert_eq!(store.state().expect("state").entries.len(), 1);
}

#[test]
fn an_account_read_twice_keeps_one_copy_per_message() {
    // The UIDL map is keyed on the server's id, so the same message arriving
    // under a different position must not produce a second local copy.
    let server = serve(vec![("uid-1", MESSAGE_ONE), ("uid-2", MESSAGE_TWO)]);
    let (dir, mut store) = maildir();
    let mut state = Pop3State::load(dir.path());
    let mut session = connect(&server);
    sync_inbox(
        &mut session,
        &mut store,
        &mut state,
        Retention::LeaveOnServer,
        1_000,
    )
    .expect("first");
    session.quit().expect("quit");

    // The first message is gone from the server, so the second one is now
    // message number 1 rather than 2.
    let server = serve(vec![("uid-2", MESSAGE_TWO)]);
    let mut session = connect(&server);
    let outcome = sync_inbox(
        &mut session,
        &mut store,
        &mut state,
        Retention::LeaveOnServer,
        2_000,
    )
    .expect("second");

    assert_eq!(
        outcome.fetched, 0,
        "a renumbered message was downloaded again"
    );
    assert_eq!(
        store.state().expect("state").entries.len(),
        2,
        "the mailbox gained a duplicate"
    );
}

// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! A canned-response IMAP server driving the real client into a real maildir.
//!
//! The unit tests cover the parsers, the reconciler, and the backoff schedule in
//! isolation. This is what proves `sync_mailbox` actually drives them, in the
//! right order, over a real socket — the same job `caldav/tests/live_sync.rs`
//! does for CalDAV, and the test that caught the CalDAV transport being unusable
//! before anything else did.
//!
//! The server is deliberately dumb: it reads a command, matches on the verb,
//! and echoes the client's own tag back. It is not an IMAP implementation and
//! must not grow into one — its value is that it answers *exactly* what a
//! scenario needs and nothing else, so a test that passes says something
//! specific.

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use cosmic_pim_mail::imap::{Endpoint, Security, Session, SyncOptions, Watched, sync_mailbox};
use cosmic_pim_mail::maildir::MaildirStore;
use cosmic_pim_mail::model::{Flags, Message};
use cosmic_pim_mail::push::{PushOp, PushQueue, Writeback as _};
use cosmic_pim_mail::store::MailStore;

/// One message the fake server holds.
#[derive(Clone)]
struct ServerMessage {
    uid: u32,
    flags: &'static str,
    body: &'static str,
}

/// What the fake server should claim about the selected mailbox.
#[derive(Clone)]
struct Scenario {
    uid_validity: u32,
    highest_modseq: u64,
    messages: Vec<ServerMessage>,
    capabilities: &'static str,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            uid_validity: 42,
            highest_modseq: 0,
            messages: Vec::new(),
            capabilities: "IMAP4rev1 UIDPLUS",
        }
    }
}

/// A server listening on an ephemeral port, plus the log of what it was asked.
struct FakeServer {
    port: u16,
    commands: mpsc::Receiver<String>,
}

impl FakeServer {
    fn start(scenario: Scenario) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        let (sender, commands) = mpsc::channel();

        thread::spawn(move || {
            // One connection is all any of these tests needs.
            if let Ok((stream, _)) = listener.accept() {
                serve(stream, &scenario, &sender);
            }
        });

        Self { port, commands }
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            port: self.port,
            security: Security::Plaintext,
            username: "user".into(),
        }
    }

    /// Everything the client sent, in order.
    fn commands(&self) -> Vec<String> {
        self.commands.try_iter().collect()
    }
}

fn serve(stream: TcpStream, scenario: &Scenario, log: &mpsc::Sender<String>) {
    let mut out = stream.try_clone().expect("clone the stream");
    let mut reader = BufReader::new(stream);

    let _ = writeln!(
        out,
        "* OK [CAPABILITY {}] canned server ready\r",
        scenario.capabilities
    );

    let mut line = String::new();
    while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
        let command = line.trim_end().to_string();
        line.clear();
        if command.is_empty() {
            continue;
        }
        let _ = log.send(command.clone());

        let mut parts = command.splitn(2, ' ');
        let tag = parts.next().unwrap_or("*").to_string();
        let rest = parts.next().unwrap_or("").to_string();
        let verb_upper = rest.to_ascii_uppercase();

        let reply = |out: &mut TcpStream, body: String| {
            let _ = out.write_all(body.as_bytes());
            let _ = out.flush();
        };

        if verb_upper.starts_with("LOGIN") {
            reply(&mut out, format!("{tag} OK LOGIN completed\r\n"));
        } else if verb_upper.starts_with("CAPABILITY") {
            reply(
                &mut out,
                format!(
                    "* CAPABILITY {}\r\n{tag} OK CAPABILITY completed\r\n",
                    scenario.capabilities
                ),
            );
        } else if verb_upper.starts_with("SELECT") {
            let mut body = format!(
                "* {} EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n\
                 * OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] limited\r\n\
                 * OK [UIDVALIDITY {}] UIDs valid\r\n\
                 * OK [UIDNEXT {}] predicted next UID\r\n",
                scenario.messages.len(),
                scenario.uid_validity,
                scenario.messages.iter().map(|m| m.uid).max().unwrap_or(0) + 1,
            );
            if scenario.highest_modseq > 0 {
                body.push_str(&format!(
                    "* OK [HIGHESTMODSEQ {}] modseq\r\n",
                    scenario.highest_modseq
                ));
            }
            body.push_str(&format!("{tag} OK [READ-WRITE] SELECT completed\r\n"));
            reply(&mut out, body);
        } else if verb_upper.starts_with("UID SEARCH") {
            let uids: Vec<String> = scenario
                .messages
                .iter()
                .map(|m| m.uid.to_string())
                .collect();
            reply(
                &mut out,
                format!(
                    "* SEARCH {}\r\n{tag} OK SEARCH completed\r\n",
                    uids.join(" ")
                ),
            );
        } else if verb_upper.starts_with("UID FETCH") {
            let wants_body = verb_upper.contains("BODY");
            let mut body = String::new();
            for (index, message) in scenario.messages.iter().enumerate() {
                body.push_str(&format!(
                    "* {} FETCH (UID {} FLAGS ({})",
                    index + 1,
                    message.uid,
                    message.flags
                ));
                if wants_body {
                    body.push_str(&format!(
                        " INTERNALDATE \"14-Nov-2023 12:00:00 +0000\" BODY[] {{{}}}\r\n{}",
                        message.body.len(),
                        message.body
                    ));
                }
                body.push_str(")\r\n");
            }
            body.push_str(&format!("{tag} OK FETCH completed\r\n"));
            reply(&mut out, body);
        } else if verb_upper.starts_with("UID STORE") {
            reply(&mut out, format!("{tag} OK STORE completed\r\n"));
        } else if verb_upper.starts_with("UID EXPUNGE") || verb_upper.starts_with("EXPUNGE") {
            reply(&mut out, format!("{tag} OK EXPUNGE completed\r\n"));
        } else if verb_upper.starts_with("UID MOVE") {
            reply(&mut out, format!("{tag} OK MOVE completed\r\n"));
        } else if verb_upper.starts_with("LIST") {
            reply(
                &mut out,
                format!(
                    "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n\
                     * LIST (\\HasNoChildren \\Sent) \"/\" \"Sent\"\r\n\
                     * LIST (\\HasNoChildren) \"/\" \"&A6ADsQPBA7EDuwOuA8ADxAO1A8I-\"\r\n\
                     {tag} OK LIST completed\r\n"
                ),
            );
        } else if verb_upper.starts_with("IDLE") {
            reply(&mut out, "+ idling\r\n".to_string());
            // A beat later, the server has news. This is the whole point of
            // IDLE: the client is told, rather than asking.
            thread::sleep(std::time::Duration::from_millis(120));
            reply(&mut out, "* 1 EXISTS\r\n".to_string());
            // The client answers DONE; consume it and close out the command.
            let mut done = String::new();
            if reader.read_line(&mut done).is_ok() {
                let _ = log.send(done.trim_end().to_string());
            }
            reply(&mut out, format!("{tag} OK IDLE terminated\r\n"));
        } else if verb_upper.starts_with("LOGOUT") {
            reply(&mut out, format!("* BYE\r\n{tag} OK LOGOUT completed\r\n"));
            return;
        } else {
            reply(&mut out, format!("{tag} OK completed\r\n"));
        }
    }
}

const HELLO: &str = "Message-ID: <hello@example.com>\r\n\
From: Ada <ada@example.com>\r\n\
Subject: Hello\r\n\
Date: Tue, 14 Nov 2023 12:00:00 +0000\r\n\
\r\n\
First message.\r\n";

const REPLY: &str = "Message-ID: <reply@example.com>\r\n\
From: Bob <bob@example.net>\r\n\
References: <hello@example.com>\r\n\
In-Reply-To: <hello@example.com>\r\n\
Subject: Re: Hello\r\n\
Date: Tue, 14 Nov 2023 13:00:00 +0000\r\n\
\r\n\
Second message.\r\n";

fn store(dir: &tempfile::TempDir) -> MaildirStore {
    MaildirStore::open(dir.path().join("INBOX")).expect("open a maildir")
}

fn connect(server: &FakeServer) -> Session {
    Session::connect(
        &server.endpoint(),
        &cosmic_pim_mail::Credentials::Password("hunter2".into()),
    )
    .expect("connect and log in")
}

#[test]
fn a_full_cycle_lands_messages_in_a_maildir_readable_by_anything() {
    let server = FakeServer::start(Scenario {
        messages: vec![
            ServerMessage {
                uid: 1,
                flags: "\\Seen",
                body: HELLO,
            },
            ServerMessage {
                uid: 2,
                flags: "",
                body: REPLY,
            },
        ],
        ..Scenario::default()
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = store(&dir);
    let mut session = connect(&server);

    let outcome =
        sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0).expect("sync");

    assert_eq!(outcome.fetched, 2);
    assert!(!outcome.renumbered);

    // On disk, as files, with the flags in the names — the whole point of
    // choosing maildir.
    let cur = dir.path().join("INBOX").join("cur");
    let names: Vec<String> = std::fs::read_dir(&cur)
        .expect("read cur/")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names
            .iter()
            .any(|n| n.contains(",U=1:") && n.ends_with("S")),
        "the \\Seen flag did not reach a filename: {names:?}"
    );

    // And they parse back into what the reader shows.
    let raw = store.raw(2).expect("read").expect("uid 2 is stored");
    let message = Message::parse(&raw).expect("parse");
    assert_eq!(message.subject, "Re: Hello");
    assert_eq!(
        message.sender().expect("a sender").address,
        "bob@example.net"
    );

    let cursor = store.state().expect("state").cursor;
    assert_eq!(cursor.last_uid, 2);
    assert_eq!(cursor.uid_validity, 42);
}

/// Waking a snoozed message clears `\Seen` and nothing else — and the only
/// place that can be proven is the wire, because `FLAGS.SILENT` replaces the
/// whole set and a client that skipped the read would look identical from the
/// outside until the user noticed their star was gone.
#[test]
fn marking_unread_reads_the_flags_before_it_writes_them() {
    let server = FakeServer::start(Scenario {
        messages: vec![ServerMessage {
            uid: 1,
            flags: "\\Seen \\Flagged",
            body: HELLO,
        }],
        ..Scenario::default()
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let mut session = connect(&server);

    // A wake runs inside a sync pass, which is what selects the mailbox.
    sync_mailbox(
        &mut session,
        "INBOX",
        &mut store(&dir),
        SyncOptions::default(),
        0,
    )
    .expect("sync");
    let _ = server.commands(); // drain, so what follows is the wake's alone

    assert!(session.mark_unread(1).expect("mark unread"));

    let commands = server.commands();
    let fetch = commands
        .iter()
        .position(|c| c.to_ascii_uppercase().contains("UID FETCH"))
        .expect("the flags were never read back");
    let store_at = commands
        .iter()
        .position(|c| c.to_ascii_uppercase().contains("UID STORE"))
        .expect("nothing was written");

    assert!(
        fetch < store_at,
        "the write went out before the read, so it wrote a guess: {commands:?}"
    );
    let written = &commands[store_at];
    assert!(
        written.contains("\\Flagged"),
        "the star was clobbered: {written}"
    );
    assert!(
        !written.to_ascii_uppercase().contains("\\SEEN"),
        "the message stayed read: {written}"
    );
}

#[test]
fn the_body_fetch_uses_peek_so_syncing_never_marks_mail_read() {
    // The single most destructive thing an IMAP client can get wrong, and it is
    // invisible in a unit test: it only shows up in what goes over the wire.
    let server = FakeServer::start(Scenario {
        messages: vec![ServerMessage {
            uid: 1,
            flags: "",
            body: HELLO,
        }],
        ..Scenario::default()
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let mut session = connect(&server);
    sync_mailbox(
        &mut session,
        "INBOX",
        &mut store(&dir),
        SyncOptions::default(),
        0,
    )
    .expect("sync");

    let fetches: Vec<String> = server
        .commands()
        .into_iter()
        .filter(|c| c.to_ascii_uppercase().contains("FETCH"))
        .collect();
    assert!(!fetches.is_empty(), "nothing was fetched at all");
    for command in &fetches {
        assert!(
            !command.contains("BODY[") || command.contains("BODY.PEEK["),
            "this fetch marks the message read on the server: {command}"
        );
    }
}

#[test]
fn queued_flag_changes_are_pushed_before_the_pull_reads_them_back() {
    // Pull-first would overwrite the local change with the server's older copy
    // and then re-upload it: "my read marks keep reverting".
    let server = FakeServer::start(Scenario {
        messages: vec![ServerMessage {
            uid: 1,
            flags: "",
            body: HELLO,
        }],
        ..Scenario::default()
    });
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = store(&dir);
    store
        .enqueue(PushOp::SetFlags {
            uid: 1,
            flags: Flags {
                seen: true,
                ..Flags::default()
            },
        })
        .expect("enqueue");

    let mut session = connect(&server);
    let outcome =
        sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0).expect("sync");

    assert_eq!(outcome.pushed.succeeded, 1);
    assert!(
        store.pending().is_empty(),
        "the queue kept a successful push"
    );

    let commands = server.commands();
    let store_at = commands
        .iter()
        .position(|c| c.to_ascii_uppercase().contains("UID STORE"))
        .expect("no STORE was sent");
    let fetch_at = commands
        .iter()
        .position(|c| c.to_ascii_uppercase().contains("UID FETCH"))
        .expect("no FETCH was sent");
    assert!(
        store_at < fetch_at,
        "the pull ran before the push: {commands:?}"
    );
}

#[test]
fn a_renumbered_mailbox_is_discarded_and_refetched_rather_than_reconciled() {
    // Reconciling would compare flags between messages that have nothing to do
    // with each other and write the results to disk.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("INBOX");

    {
        let server = FakeServer::start(Scenario {
            uid_validity: 1,
            messages: vec![ServerMessage {
                uid: 1,
                flags: "\\Seen",
                body: HELLO,
            }],
            ..Scenario::default()
        });
        let mut store = MaildirStore::open(&path).expect("open");
        let mut session = connect(&server);
        sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0).expect("sync");
        assert_eq!(store.state().expect("state").entries.len(), 1);
    }

    // The server comes back renumbered, with a different message under UID 1.
    let server = FakeServer::start(Scenario {
        uid_validity: 999,
        messages: vec![ServerMessage {
            uid: 1,
            flags: "",
            body: REPLY,
        }],
        ..Scenario::default()
    });
    let mut store = MaildirStore::open(&path).expect("reopen");
    let mut session = connect(&server);
    let outcome =
        sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0).expect("sync");

    assert!(outcome.renumbered);
    let state = store.state().expect("state");
    assert_eq!(state.cursor.uid_validity, 999);
    assert_eq!(state.entries.len(), 1);
    let raw = store.raw(1).expect("read").expect("uid 1");
    assert!(
        String::from_utf8_lossy(&raw).contains("Re: Hello"),
        "UID 1 still holds the message from the old numbering"
    );
}

#[test]
fn a_reconcile_pass_removes_what_another_client_deleted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("INBOX");

    {
        let server = FakeServer::start(Scenario {
            messages: vec![
                ServerMessage {
                    uid: 1,
                    flags: "",
                    body: HELLO,
                },
                ServerMessage {
                    uid: 2,
                    flags: "",
                    body: REPLY,
                },
            ],
            ..Scenario::default()
        });
        let mut store = MaildirStore::open(&path).expect("open");
        let mut session = connect(&server);
        sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0).expect("sync");
    }

    // UID 1 is gone from the server, and the cursor means a plain cycle would
    // never look at it again.
    let server = FakeServer::start(Scenario {
        messages: vec![ServerMessage {
            uid: 2,
            flags: "\\Flagged",
            body: REPLY,
        }],
        ..Scenario::default()
    });
    let mut store = MaildirStore::open(&path).expect("reopen");
    let mut session = connect(&server);
    let outcome = sync_mailbox(
        &mut session,
        "INBOX",
        &mut store,
        SyncOptions {
            reconcile: true,
            since_ms: None,
        },
        0,
    )
    .expect("sync");

    assert_eq!(outcome.removed, 1);
    assert_eq!(outcome.reflagged, 1);
    let state = store.state().expect("state");
    assert!(
        !state.entries.contains_key(&1),
        "a deleted message survived"
    );
    assert!(state.entries[&2].flagged);
}

#[test]
fn an_empty_listing_does_not_empty_the_mailbox() {
    // A server hiccup that answers a reconcile with nothing must not be read as
    // "the user deleted everything".
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("INBOX");

    {
        let server = FakeServer::start(Scenario {
            messages: vec![ServerMessage {
                uid: 1,
                flags: "",
                body: HELLO,
            }],
            ..Scenario::default()
        });
        let mut store = MaildirStore::open(&path).expect("open");
        let mut session = connect(&server);
        sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0).expect("sync");
    }

    let server = FakeServer::start(Scenario::default());
    let mut store = MaildirStore::open(&path).expect("reopen");
    let mut session = connect(&server);
    let outcome = sync_mailbox(
        &mut session,
        "INBOX",
        &mut store,
        SyncOptions {
            reconcile: true,
            since_ms: None,
        },
        0,
    )
    .expect("sync");

    assert!(outcome.guard_tripped);
    assert_eq!(outcome.removed, 0);
    assert_eq!(store.state().expect("state").entries.len(), 1);
}

#[test]
fn folder_discovery_decodes_names_and_reads_special_use() {
    let server = FakeServer::start(Scenario::default());
    let mut session = connect(&server);
    let folders = session.folders().expect("list folders");

    let names: Vec<&str> = folders.iter().map(|f| f.display_name.as_str()).collect();
    assert_eq!(
        names,
        ["INBOX", "Sent", "Παραλήπτες"],
        "special-use mailboxes must sort first and wire names must decode"
    );
    assert_eq!(
        folders[2].wire_name, "&A6ADsQPBA7EDuwOuA8ADxAO1A8I-",
        "the wire name must be kept — it is what SELECT takes"
    );
}

#[test]
fn a_second_cycle_with_nothing_new_fetches_nothing() {
    // The `UID last+1:*` quirk: the range always returns something, so a client
    // that trusts it re-downloads the newest message on every poll.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("INBOX");
    let scenario = Scenario {
        messages: vec![ServerMessage {
            uid: 7,
            flags: "",
            body: HELLO,
        }],
        ..Scenario::default()
    };

    {
        let server = FakeServer::start(scenario.clone());
        let mut store = MaildirStore::open(&path).expect("open");
        let mut session = connect(&server);
        let first = sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0)
            .expect("sync");
        assert_eq!(first.fetched, 1);
    }

    let server = FakeServer::start(scenario);
    let mut store = MaildirStore::open(&path).expect("reopen");
    let mut session = connect(&server);
    let second =
        sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0).expect("sync");

    assert_eq!(second.fetched, 0, "an idle poll re-downloaded the mailbox");
    let commands: HashMap<bool, usize> =
        server
            .commands()
            .into_iter()
            .fold(HashMap::new(), |mut counts, command| {
                *counts
                    .entry(command.to_ascii_uppercase().contains("BODY.PEEK"))
                    .or_default() += 1;
                counts
            });
    assert_eq!(
        commands.get(&true),
        None,
        "a body was fetched with nothing new"
    );
}

#[test]
fn a_watch_returns_when_the_server_reports_news() {
    // Push mail, end to end: the client parks in IDLE and the server's
    // unsolicited EXISTS is what wakes it — no polling involved.
    let server = FakeServer::start(Scenario {
        capabilities: "IMAP4rev1 IDLE",
        messages: vec![ServerMessage {
            uid: 1,
            flags: "",
            body: HELLO,
        }],
        ..Scenario::default()
    });
    let mut session = connect(&server);
    assert!(session.supports_idle(), "the capability was not read");

    let outcome = session
        .watch("INBOX", std::time::Duration::from_secs(10))
        .expect("watch");
    assert_eq!(
        outcome,
        Watched::Changed,
        "the server said EXISTS and the watch did not wake"
    );

    let commands = server.commands();
    assert!(
        commands
            .iter()
            .any(|c| c.to_ascii_uppercase().contains("IDLE")),
        "no IDLE was ever issued: {commands:?}"
    );
    assert!(
        commands
            .iter()
            .any(|c| c.trim().eq_ignore_ascii_case("DONE")),
        "the watch never terminated the IDLE cleanly: {commands:?}"
    );
}

#[test]
fn a_server_without_idle_says_so_up_front() {
    // The caller's right response is the poll it already has — not a retry.
    let server = FakeServer::start(Scenario::default());
    let mut session = connect(&server);
    assert!(
        !session.supports_idle(),
        "IDLE was claimed on a server that does not offer it"
    );
}

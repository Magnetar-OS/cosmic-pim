// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! A scripted SMTP server, taking a real submission from the real transport.
//!
//! `live_sync.rs` proves the read path over a socket; this is the write path.
//! It exists for the same reason and it carries the assertions that can only be
//! made about what actually went over the wire: that `Bcc` reached the envelope
//! and not the message, and that the recipient's copy threads.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

/// Every test here authenticates the same way; the mechanism is not what is
/// under test, the SMTP conversation is.
fn password() -> cosmic_pim_mail::Credentials {
    cosmic_pim_mail::Credentials::Password("hunter2".into())
}

use cosmic_pim_mail::compose::Draft;
use cosmic_pim_mail::imap::Security;
use cosmic_pim_mail::model::{Mailbox, Message};
use cosmic_pim_mail::smtp::{Outcome, SmtpEndpoint, send};

/// What the transcript of one session looked like.
struct Transcript {
    /// The commands, in order, up to and including the message body.
    lines: Vec<String>,
}

impl Transcript {
    /// The `RCPT TO` addresses — the SMTP envelope.
    fn envelope_recipients(&self) -> Vec<String> {
        self.lines
            .iter()
            .filter_map(|line| {
                let upper = line.to_ascii_uppercase();
                upper.starts_with("RCPT TO:").then(|| {
                    line[8..]
                        .trim()
                        .trim_matches(['<', '>'])
                        .to_ascii_lowercase()
                })
            })
            .collect()
    }

    /// Everything after DATA — the RFC 5322 bytes the server received.
    fn message(&self) -> String {
        let start = self
            .lines
            .iter()
            .position(|line| line.eq_ignore_ascii_case("DATA"))
            .map_or(self.lines.len(), |at| at + 1);
        self.lines[start..].join("\r\n")
    }
}

struct FakeSmtp {
    port: u16,
    transcript: mpsc::Receiver<Vec<String>>,
}

/// How the scripted server behaves at the points a real one can fail.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    /// A clean session: every command succeeds.
    Accept,
    /// A 4xx at `MAIL FROM` — a definite non-acceptance, the retryable class.
    TempFailAtMail,
    /// 535 at `AUTH` — a definite non-acceptance that waiting will not fix.
    RejectAuth,
    /// The whole message and its terminating dot arrive, and then the
    /// connection is reset before any reply: the server may well have queued
    /// it. The shape a mobile network produces when it drops mid-send.
    ResetAfterDot,
}

impl FakeSmtp {
    fn start(accept: bool) -> Self {
        Self::scripted(if accept {
            Script::Accept
        } else {
            Script::TempFailAtMail
        })
    }

    fn scripted(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (sender, transcript) = mpsc::channel();

        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let lines = serve(stream, script);
                let _ = sender.send(lines);
            }
        });

        Self { port, transcript }
    }

    fn endpoint(&self) -> SmtpEndpoint {
        SmtpEndpoint {
            host: "127.0.0.1".into(),
            port: self.port,
            security: Security::Plaintext,
            username: "me@example.com".into(),
        }
    }

    fn transcript(&self) -> Transcript {
        Transcript {
            lines: self
                .transcript
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("the server never finished a session"),
        }
    }
}

fn serve(stream: TcpStream, script: Script) -> Vec<String> {
    let mut out = stream.try_clone().expect("clone");
    let mut reader = BufReader::new(stream);
    let mut seen = Vec::new();

    let _ = write!(out, "220 canned.example ESMTP\r\n");

    let mut line = String::new();
    let mut in_data = false;
    while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
        let command = line.trim_end_matches(['\r', '\n']).to_string();
        line.clear();
        seen.push(command.clone());

        if in_data {
            if command == "." {
                in_data = false;
                let _ = write!(out, "250 2.0.0 Ok: queued\r\n");
            }
            continue;
        }

        let upper = command.to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            // AUTH PLAIN so lettre has a mechanism it can use without TLS.
            let _ = write!(out, "250-canned.example\r\n250 AUTH PLAIN LOGIN\r\n");
        } else if upper.starts_with("HELO") {
            let _ = write!(out, "250 canned.example\r\n");
        } else if upper.starts_with("AUTH") {
            let _ = if script == Script::RejectAuth {
                write!(out, "535 5.7.8 Authentication credentials invalid\r\n")
            } else {
                write!(out, "235 2.7.0 Authentication successful\r\n")
            };
        } else if upper.starts_with("MAIL FROM") {
            let _ = if script != Script::TempFailAtMail {
                write!(out, "250 2.1.0 Ok\r\n")
            } else {
                write!(out, "451 4.3.0 Try again later\r\n")
            };
        } else if upper.starts_with("RCPT TO") {
            let _ = write!(out, "250 2.1.5 Ok\r\n");
        } else if upper == "DATA" {
            in_data = true;
            let _ = write!(out, "354 End data with <CR><LF>.<CR><LF>\r\n");
            if script == Script::ResetAfterDot {
                // Let the body and its dot land in our receive buffer, then
                // close without reading them. The kernel answers a close over
                // unread bytes with a RST, so the client's wait for the reply
                // fails with ECONNRESET — after it handed everything over.
                let _ = out.flush();
                thread::sleep(std::time::Duration::from_millis(300));
                seen.push("<reset>".into());
                return seen;
            }
        } else if upper == "QUIT" {
            let _ = write!(out, "221 2.0.0 Bye\r\n");
            break;
        } else {
            let _ = write!(out, "250 2.0.0 Ok\r\n");
        }
        let _ = out.flush();
    }
    seen
}

fn me() -> Mailbox {
    Mailbox {
        name: Some("Me".into()),
        address: "me@example.com".into(),
    }
}

fn to(address: &str) -> Mailbox {
    Mailbox {
        name: None,
        address: address.into(),
    }
}

#[test]
fn a_send_reaches_the_server_and_comes_back_with_the_copy_to_file() {
    let server = FakeSmtp::start(true);
    let mut draft = Draft::new(me());
    draft.to.push(to("ada@example.com"));
    draft.subject = "Hello".into();
    draft.body = "Hi there.".into();

    let outcome = send(&server.endpoint(), &password(), &draft);
    let Outcome::Sent(filed) = outcome else {
        panic!("the send did not succeed: {:?}", outcome.error());
    };

    let transcript = server.transcript();
    assert_eq!(transcript.envelope_recipients(), ["ada@example.com"]);

    let wire = transcript.message();
    assert!(wire.contains("Subject: Hello"), "{wire}");
    assert!(wire.contains("Hi there."), "{wire}");

    // What comes back is what goes into Sent, and it has to be a real message.
    let filed = Message::parse(&filed).expect("the filed copy does not parse");
    assert_eq!(filed.subject, "Hello");
    assert_eq!(filed.sender().expect("a sender").address, "me@example.com");
}

#[test]
fn bcc_reaches_the_envelope_and_never_the_wire() {
    // The whole meaning of the field, asserted where it can actually be
    // checked: the recipient list the server was given, against the bytes the
    // recipients receive.
    let server = FakeSmtp::start(true);
    let mut draft = Draft::new(me());
    draft.to.push(to("ada@example.com"));
    draft.cc.push(to("bob@example.net"));
    draft.bcc.push(to("secret@example.org"));
    draft.subject = "Quiet".into();
    draft.body = "…".into();

    let outcome = send(&server.endpoint(), &password(), &draft);
    let Outcome::Sent(filed) = outcome else {
        panic!("the send did not succeed: {:?}", outcome.error());
    };

    let transcript = server.transcript();
    let mut recipients = transcript.envelope_recipients();
    recipients.sort();
    assert_eq!(
        recipients,
        ["ada@example.com", "bob@example.net", "secret@example.org"],
        "the blind copy never got delivered"
    );

    let wire = transcript.message();
    assert!(
        !wire.contains("secret@example.org"),
        "the blind copy leaked to every recipient:\n{wire}"
    );
    assert!(
        wire.contains("bob@example.net"),
        "the Cc header went missing"
    );

    assert!(
        String::from_utf8_lossy(&filed).contains("secret@example.org"),
        "the Sent copy lost the only record of who was blind-copied"
    );
}

#[test]
fn a_reply_goes_out_threaded_for_the_recipients_client() {
    let server = FakeSmtp::start(true);
    let original = Message::parse(
        b"Message-ID: <parent@x>\r\n\
          References: <root@x>\r\n\
          From: Ada <ada@example.com>\r\n\
          To: me@example.com\r\n\
          Subject: Release plan\r\n\
          Date: Mon, 3 Feb 2025 10:00:00 +0000\r\n\
          \r\n\
          What do you think?\r\n",
    )
    .expect("parse");

    let mut draft = Draft::reply(&original, me(), false);
    draft.body.insert_str(0, "Looks good.");

    let outcome = send(&server.endpoint(), &password(), &draft);
    assert!(outcome.is_sent(), "{:?}", outcome.error());

    let wire = server.transcript().message();
    assert!(wire.contains("In-Reply-To: <parent@x>"), "{wire}");
    assert!(wire.contains("References: <root@x> <parent@x>"), "{wire}");
    assert!(wire.contains("Subject: Re: Release plan"), "{wire}");
    assert!(wire.contains("> What do you think?"), "{wire}");
}

#[test]
fn a_server_that_refuses_before_data_is_safe_to_retry() {
    // 4xx at MAIL FROM: nothing was handed over, so an outbox may try again.
    let server = FakeSmtp::start(false);
    let mut draft = Draft::new(me());
    draft.to.push(to("ada@example.com"));
    draft.subject = "Hello".into();
    draft.body = "Hi.".into();

    let outcome = send(&server.endpoint(), &password(), &draft);
    assert!(!outcome.is_sent());
    assert!(
        outcome.is_retryable(),
        "a definite non-acceptance was made terminal, so the message is stuck: {:?}",
        outcome.error()
    );
}

#[test]
fn an_unreachable_server_is_safe_to_retry() {
    // The offline case. Anything else here means mail written on a train is
    // abandoned rather than queued.
    let endpoint = SmtpEndpoint {
        host: "127.0.0.1".into(),
        port: 1,
        security: Security::Plaintext,
        username: "me@example.com".into(),
    };
    let mut draft = Draft::new(me());
    draft.to.push(to("ada@example.com"));
    draft.subject = "Hello".into();
    draft.body = "Hi.".into();

    let outcome = send(&endpoint, &password(), &draft);
    assert!(outcome.is_retryable(), "{:?}", outcome.error());
}

fn short_draft() -> Draft {
    let mut draft = Draft::new(me());
    draft.to.push(to("ada@example.com"));
    draft.subject = "Hello".into();
    draft.body = "Hi.".into();
    draft
}

#[test]
fn a_connection_lost_after_the_message_was_handed_over_is_never_retried() {
    // The duplicate-send case: the dot went out, the reply never came back.
    // The server may have queued the message, so an automatic retry would
    // deliver it twice.
    let server = FakeSmtp::scripted(Script::ResetAfterDot);
    let outcome = send(&server.endpoint(), &password(), &short_draft());
    assert!(
        matches!(outcome, Outcome::Ambiguous(_)),
        "a send lost after DATA was classed as safe to retry: {:?}",
        outcome.error()
    );
    assert!(server.transcript().lines.iter().any(|l| l == "<reset>"));
}

#[test]
fn a_refused_login_is_a_definite_no_that_retrying_will_not_fix() {
    // 535 before MAIL FROM: nothing was handed over, so it is not ambiguous —
    // and the password will not get better by waiting, so it is not a retry.
    let server = FakeSmtp::scripted(Script::RejectAuth);
    let outcome = send(&server.endpoint(), &password(), &short_draft());
    assert!(
        matches!(outcome, Outcome::Rejected(_)),
        "a refused login was reported as {:?}",
        outcome
    );
    assert!(!outcome.is_retryable());
}

#[test]
fn the_wire_copy_and_the_filed_copy_are_one_message() {
    // One Message-ID and one Date on both: the Sent copy threads with the
    // replies to what actually went out, and a resend can be recognised.
    let server = FakeSmtp::start(true);
    let mut draft = short_draft();
    draft.bcc.push(to("secret@example.org"));
    let Outcome::Sent(filed) = send(&server.endpoint(), &password(), &draft) else {
        panic!("the send did not succeed");
    };
    let wire = server.transcript().message();
    let filed = String::from_utf8(filed).unwrap();
    let header = |text: &str, name: &str| {
        text.lines()
            .find(|line| line.to_ascii_lowercase().starts_with(&format!("{name}:")))
            .map(str::to_owned)
    };
    let id = header(&wire, "message-id").expect("the wire copy has no Message-ID");
    assert_eq!(Some(id), header(&filed, "message-id"));
    assert_eq!(header(&wire, "date"), header(&filed, "date"));
}

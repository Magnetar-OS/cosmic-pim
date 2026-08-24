// SPDX-License-Identifier: MPL-2.0

//! The real client against a real server.
//!
//! The scripted suites (`live_sync.rs`, `live_send.rs`) prove the client is
//! *coherent* — the pieces are wired in the right order. This proves it is
//! *compatible*: a stock Dovecot, not our own canned responses, answering the
//! same calls. It is the difference between "the reconciler is correct" and
//! "the reconciler is correct about what Dovecot actually says", and it is how
//! the CalDAV side caught its transport being unusable.
//!
//! # Running it
//!
//! Gated on `PIM_TEST_IMAP=host:port:user:password`, and **skipped silently**
//! without it — a checkout without Docker must still have a green test suite.
//!
//! ```sh
//! docker run -d --name pim-dovecot -p 14143:31143 \
//!     -e USER_PASSWORD=hunter2 \
//!     -v $PWD/tests/dovecot.conf:/etc/dovecot/dovecot.conf:ro \
//!     dovecot/dovecot:latest
//! PIM_TEST_IMAP=127.0.0.1:14143:tester:hunter2 cargo test --test live_dovecot
//! ```
//!
//! Each run uses a fresh user (any name logs in against the static passdb), so
//! runs do not see each other's mailboxes.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cosmic_pim_mail::Credentials;
use cosmic_pim_mail::folder::SpecialUse;
use cosmic_pim_mail::imap::{Endpoint, Security, Session, SyncOptions, Watched, sync_mailbox};
use cosmic_pim_mail::maildir::MaildirStore;
use cosmic_pim_mail::model::Flags;
use cosmic_pim_mail::push::{PushOp, PushQueue};
use cosmic_pim_mail::store::MailStore;

/// The configured server, or `None` when the test should skip.
fn server() -> Option<(Endpoint, Credentials)> {
    let spec = std::env::var("PIM_TEST_IMAP").ok()?;
    let mut parts = spec.splitn(4, ':');
    let host = parts.next()?.to_owned();
    let port = parts.next()?.parse().ok()?;
    let user = parts.next()?.to_owned();
    let password = parts.next()?.to_owned();
    Some((
        Endpoint {
            host,
            port,
            security: Security::Plaintext,
            username: user,
        },
        Credentials::Password(password),
    ))
}

/// A per-run user, so runs do not see each other's mailboxes.
fn fresh_user(base: &Endpoint) -> Endpoint {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    Endpoint {
        username: format!("{}-{nonce}", base.username),
        ..base.clone()
    }
}

fn connect(endpoint: &Endpoint, credentials: &Credentials) -> Session {
    Session::connect(endpoint, credentials).expect("connect to the test server")
}

const MESSAGE: &[u8] = b"Message-ID: <live@example.com>\r\n\
From: Ada <ada@example.com>\r\n\
To: tester@example.com\r\n\
Subject: Against a real server\r\n\
Date: Mon, 3 Feb 2025 10:00:00 +0000\r\n\
\r\n\
Delivered by APPEND, read back by sync.\r\n";

#[test]
fn the_whole_read_path_works_against_a_real_dovecot() {
    let Some((base, credentials)) = server() else {
        eprintln!("PIM_TEST_IMAP not set; skipping the live server test");
        return;
    };
    let endpoint = fresh_user(&base);
    let dir = tempfile::tempdir().expect("tempdir");

    // --- The server's own folder list carries real special-use flags -------
    let mut session = connect(&endpoint, &credentials);
    let folders = session.folders().expect("LIST");
    assert!(
        folders
            .iter()
            .any(|f| f.special_use == Some(SpecialUse::Trash)),
        "Dovecot declares \\Trash and the client did not see it: {folders:?}"
    );

    // --- Deliver, then sync it back into a maildir -------------------------
    session
        .append("INBOX", MESSAGE, Flags::default())
        .expect("APPEND");

    let mut store = MaildirStore::open(dir.path().join("INBOX")).expect("maildir");
    let outcome =
        sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0).expect("sync");
    assert_eq!(outcome.fetched, 1, "the appended message did not come back");

    let state = store.state().expect("state");
    assert_eq!(state.entries.len(), 1);
    assert!(
        state.cursor.uid_validity > 0,
        "a real server always has a UIDVALIDITY"
    );
    // Not asserted after the *first* cycle, and the reason is a quirk this
    // test discovered: Dovecot 2.4 omits HIGHESTMODSEQ from the SELECT of a
    // mailbox that APPEND auto-created moments earlier — despite RFC 7162
    // requiring it or NOMODSEQ once CONDSTORE is enabled. The re-SELECT on
    // the next cycle carries it, so the client degrades to one full
    // reconciliation and then self-heals; the assertion below, after the
    // second cycle, is what a real server actually promises.
    let uid = *state.entries.keys().next().expect("one uid");
    let raw = store.raw(uid).expect("read").expect("bytes");
    assert!(
        String::from_utf8_lossy(&raw).contains("Delivered by APPEND"),
        "the stored bytes are not the delivered message"
    );

    // --- A queued flag change reaches the server and survives a re-sync ----
    store
        .enqueue(PushOp::SetFlags {
            uid,
            flags: Flags {
                seen: true,
                flagged: true,
                ..Flags::default()
            },
        })
        .expect("enqueue");
    let outcome = sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0)
        .expect("push cycle");
    assert_eq!(outcome.pushed.succeeded, 1, "the STORE did not go out");
    assert!(
        store.state().expect("state").cursor.highest_modseq > 0,
        "by the second SELECT the MODSEQ cursor must be live, or CONDSTORE \
         deltas never engage"
    );

    // A *fresh* maildir proves the flags are the server's now, not ours.
    let mut verify = MaildirStore::open(dir.path().join("verify")).expect("maildir");
    let mut second = connect(&endpoint, &credentials);
    sync_mailbox(
        &mut second,
        "INBOX",
        &mut verify,
        SyncOptions {
            reconcile: true,
            since_ms: None,
        },
        0,
    )
    .expect("verify sync");
    let flags = verify.state().expect("state").entries[&uid];
    assert!(
        flags.seen && flags.flagged,
        "the server does not hold the pushed flags: {flags:?}"
    );

    // --- A queued move lands in Trash, and the reconcile notices -----------
    store
        .enqueue(PushOp::Move {
            uid,
            destination: "Trash".into(),
        })
        .expect("enqueue move");
    sync_mailbox(
        &mut session,
        "INBOX",
        &mut store,
        SyncOptions {
            reconcile: true,
            since_ms: None,
        },
        0,
    )
    .expect("move cycle");
    assert!(
        store.state().expect("state").entries.is_empty(),
        "the moved message is still in the local INBOX"
    );

    let mut trash = MaildirStore::open(dir.path().join("Trash")).expect("maildir");
    sync_mailbox(&mut second, "Trash", &mut trash, SyncOptions::default(), 0).expect("trash sync");
    assert_eq!(
        trash.state().expect("state").entries.len(),
        1,
        "the message never arrived in Trash"
    );

    let _ = session.logout();
    let _ = second.logout();
}

#[test]
fn a_real_idle_wakes_when_mail_arrives() {
    let Some((base, credentials)) = server() else {
        eprintln!("PIM_TEST_IMAP not set; skipping the live IDLE test");
        return;
    };
    let endpoint = fresh_user(&base);

    let mut watcher = connect(&endpoint, &credentials);
    assert!(watcher.supports_idle(), "Dovecot advertises IDLE");

    // Another connection delivers while the first is parked. The deliverer
    // waits a beat so the watch is actually in IDLE when the news lands —
    // the race the other way is fine (the wake happens on entry), but this
    // ordering is the one that proves the push path.
    let deliver_to = endpoint.clone();
    let deliver_credentials = credentials.clone();
    let deliverer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(600));
        let mut session = connect(&deliver_to, &deliver_credentials);
        session
            .append("INBOX", MESSAGE, Flags::default())
            .expect("APPEND from the second connection");
        let _ = session.logout();
    });

    let outcome = watcher
        .watch("INBOX", Duration::from_secs(20))
        .expect("watch");
    deliverer.join().expect("deliverer");
    assert_eq!(
        outcome,
        Watched::Changed,
        "mail arrived and the parked IDLE never woke"
    );
    let _ = watcher.logout();
}

#[test]
fn a_deletion_by_another_client_arrives_with_the_next_delta_not_the_next_reconcile() {
    // QRESYNC's whole contribution. Without it, a message deleted on a phone
    // lingers on the desktop until the periodic full reconciliation — up to
    // ten cycles of a mailbox showing mail that is not there.
    let Some((base, credentials)) = server() else {
        eprintln!("PIM_TEST_IMAP not set; skipping the live QRESYNC test");
        return;
    };
    let endpoint = fresh_user(&base);
    let dir = tempfile::tempdir().expect("tempdir");

    // This client establishes a cursor with the message present.
    let mut session = connect(&endpoint, &credentials);
    session
        .append("INBOX", MESSAGE, Flags::default())
        .expect("APPEND");
    let mut store = MaildirStore::open(dir.path().join("INBOX")).expect("maildir");
    sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0).expect("first sync");
    // The Dovecot quirk again: the first SELECT of an APPEND-created mailbox
    // carries no MODSEQ, so a second cycle is what arms the delta cursor.
    sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0)
        .expect("arming sync");
    let state = store.state().expect("state");
    assert_eq!(state.entries.len(), 1);
    assert!(
        state.cursor.highest_modseq > 0,
        "no delta cursor, so this test would not be testing the delta path"
    );
    let uid = *state.entries.keys().next().expect("one uid");

    // Another client deletes it. Its own sync is what SELECTs the mailbox,
    // which the delete needs.
    let mut other = connect(&endpoint, &credentials);
    let mut other_store = MaildirStore::open(dir.path().join("other")).expect("maildir");
    sync_mailbox(
        &mut other,
        "INBOX",
        &mut other_store,
        SyncOptions::default(),
        0,
    )
    .expect("other's sync");
    use cosmic_pim_mail::push::Writeback as _;
    other
        .delete_message(uid)
        .expect("delete from the other client");
    let _ = other.logout();

    // A plain cycle — no reconcile — must notice, via VANISHED.
    let outcome = sync_mailbox(&mut session, "INBOX", &mut store, SyncOptions::default(), 0)
        .expect("delta sync");
    assert_eq!(
        outcome.removed, 1,
        "the deletion did not arrive with the delta: {outcome:?}"
    );
    assert!(
        store.state().expect("state").entries.is_empty(),
        "the mailbox still shows a message another client deleted"
    );
    let _ = session.logout();
}

// SPDX-License-Identifier: MPL-2.0

//! End-to-end sync against a real HTTP server.
//!
//! The unit tests cover the multistatus parsers and the reconciliation planner
//! in isolation, and the `sync` module's own tests exercise a *mirror* of the
//! cycle rather than the cycle itself. That left the one function that actually
//! matters — [`sync_collection`] — never executed by anything.
//!
//! This closes that: a `tiny_http` server answering PROPFIND and REPORT with
//! canned multistatus XML, and the real client driving the real reconciler into
//! a real vdir on disk. It catches the class of bug no unit test can — the
//! steps being individually correct but wired together wrong.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cosmic_pim_caldav::push::PushQueue;
use cosmic_pim_caldav::{CalDavStore, CaldavClient, VdirStore, sync_collection};
use cosmic_pim_core::model::Rgb;
use cosmic_pim_core::store::vdir;

const EVENT_A: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\nDTEND:20260804T100000Z\r\n\
SUMMARY:Event A\r\nATTENDEE;CN=Someone:mailto:s@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

const TASK: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
BEGIN:VTODO\r\nUID:t@test\r\nSUMMARY:Buy milk\r\nDUE;VALUE=DATE:20260804\r\n\
STATUS:NEEDS-ACTION\r\nPRIORITY:2\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";

const EVENT_B: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
BEGIN:VEVENT\r\nUID:b@test\r\nDTSTART:20260805T090000Z\r\nDTEND:20260805T100000Z\r\n\
SUMMARY:Event B\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// One scripted round of the server's behaviour.
#[derive(Clone)]
struct Round {
    ctag: &'static str,
    /// (href, etag) the listing advertises.
    entries: Vec<(&'static str, &'static str)>,
    /// (href, iCalendar) the multiget returns.
    bodies: Vec<(&'static str, &'static str)>,
}

struct Server {
    url: String,
    propfind_count: Arc<AtomicUsize>,
    report_count: Arc<AtomicUsize>,
    _handle: std::thread::JoinHandle<()>,
}

/// Serves `rounds` in order — one round per sync cycle.
fn serve(rounds: Vec<Round>) -> Server {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let port = server.server_addr().to_ip().expect("ip").port();
    let url = format!("http://127.0.0.1:{port}/cal/");

    let propfind_count = Arc::new(AtomicUsize::new(0));
    let report_count = Arc::new(AtomicUsize::new(0));
    let propfinds = Arc::clone(&propfind_count);
    let reports = Arc::clone(&report_count);

    let handle = std::thread::spawn(move || {
        // A cycle begins with the ctag PROPFIND and then makes two more
        // requests against the SAME round. Advancing on every request (rather
        // than on every cycle) would serve round N's listing against round
        // N+1's ctag, which is not a shape any real server produces.
        let mut next_cycle = 0usize;
        let mut serving = 0usize;

        for mut request in server.incoming_requests() {
            let method = request.method().as_str().to_owned();
            let mut body = String::new();
            let _ = request.as_reader().read_to_string(&mut body);

            if method == "PROPFIND" && body.contains("getctag") {
                serving = next_cycle.min(rounds.len().saturating_sub(1));
                next_cycle += 1;
            }

            let Some(current) = rounds.get(serving) else { break };

            let xml = if method == "PROPFIND" && body.contains("getctag") {
                propfinds.fetch_add(1, Ordering::SeqCst);
                format!(
                    r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/">
<d:response><d:href>/cal/</d:href><d:propstat><d:prop>
<cs:getctag>{}</cs:getctag></d:prop><d:status>HTTP/1.1 200 OK</d:status>
</d:propstat></d:response></d:multistatus>"#,
                    current.ctag
                )
            } else if method == "PROPFIND" {
                propfinds.fetch_add(1, Ordering::SeqCst);
                let mut out = String::from(
                    r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>
<d:href>/cal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype>
</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
                );
                for (href, etag) in &current.entries {
                    out.push_str(&format!(
                        r#"<d:response><d:href>{href}</d:href><d:propstat><d:prop>
<d:getetag>{etag}</d:getetag>
<d:getcontenttype>text/calendar; charset=utf-8</d:getcontenttype>
</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#
                    ));
                }
                out.push_str("</d:multistatus>");
                out
            } else if method == "REPORT" {
                reports.fetch_add(1, Ordering::SeqCst);
                let mut out = String::from(
                    r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">"#,
                );
                for (href, ics) in &current.bodies {
                    // Only return what this round's listing actually mentioned
                    // AND the client asked for.
                    if !body.contains(href) {
                        continue;
                    }
                    let etag = current
                        .entries
                        .iter()
                        .find(|(h, _)| h == href)
                        .map_or("\"x\"", |(_, e)| e);
                    out.push_str(&format!(
                        r#"<d:response><d:href>{href}</d:href><d:propstat><d:prop>
<d:getetag>{etag}</d:getetag><c:calendar-data><![CDATA[{ics}]]></c:calendar-data>
</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#
                    ));
                }
                out.push_str("</d:multistatus>");
                out
            } else {
                let _ = request.respond(tiny_http::Response::empty(405));
                continue;
            };

            let response = tiny_http::Response::from_string(xml)
                .with_status_code(207)
                .with_header(
                    tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"application/xml; charset=utf-8"[..],
                    )
                    .expect("header"),
                );
            let _ = request.respond(response);
        }
    });

    Server {
        url,
        propfind_count,
        report_count,
        _handle: handle,
    }
}

fn collection() -> (tempfile::TempDir, VdirStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).expect("collection");
    (dir, VdirStore::open(meta).expect("store"))
}

#[test]
fn a_first_sync_downloads_every_event_into_the_vdir() {
    let server = serve(vec![Round {
        ctag: "ctag-1",
        entries: vec![("/cal/a.ics", "\"1\""), ("/cal/b.ics", "\"1\"")],
        bodies: vec![("/cal/a.ics", EVENT_A), ("/cal/b.ics", EVENT_B)],
    }]);
    let (_dir, mut store) = collection();
    let client = CaldavClient::new(&server.url, "user", "pass");

    let outcome = sync_collection(&client, &server.url, &mut store).expect("sync");

    assert_eq!(outcome.fetched, 2);
    assert!(!outcome.unchanged);

    // The real assertion: they are readable as ordinary vdir events.
    let mut events = vdir::read_collection(store.collection());
    events.sort_by(|a, b| a.summary.cmp(&b.summary));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].summary, "Event A");
    assert_eq!(events[1].summary, "Event B");
}

#[test]
fn an_unmodelled_property_survives_the_whole_round_trip() {
    let server = serve(vec![Round {
        ctag: "ctag-1",
        entries: vec![("/cal/a.ics", "\"1\"")],
        bodies: vec![("/cal/a.ics", EVENT_A)],
    }]);
    let (_dir, mut store) = collection();
    let client = CaldavClient::new(&server.url, "user", "pass");

    sync_collection(&client, &server.url, &mut store).expect("sync");

    let written = std::fs::read_to_string(store.collection().path.join("a.ics")).expect("file");
    assert!(
        written.contains("ATTENDEE;CN=Someone"),
        "the ATTENDEE our Event model does not represent was lost: {written}"
    );
}

#[test]
fn a_second_sync_with_an_unchanged_ctag_makes_one_request_and_stops() {
    let server = serve(vec![
        Round {
            ctag: "ctag-1",
            entries: vec![("/cal/a.ics", "\"1\"")],
            bodies: vec![("/cal/a.ics", EVENT_A)],
        },
        Round {
            ctag: "ctag-1", // unchanged
            entries: vec![("/cal/a.ics", "\"1\"")],
            bodies: vec![("/cal/a.ics", EVENT_A)],
        },
    ]);
    let (_dir, mut store) = collection();
    let client = CaldavClient::new(&server.url, "user", "pass");

    sync_collection(&client, &server.url, &mut store).expect("first");
    let propfinds_after_first = server.propfind_count.load(Ordering::SeqCst);
    let reports_after_first = server.report_count.load(Ordering::SeqCst);

    let second = sync_collection(&client, &server.url, &mut store).expect("second");

    assert!(second.unchanged, "the ctag short-circuit did not fire");
    assert_eq!(second.fetched, 0);
    assert_eq!(
        server.propfind_count.load(Ordering::SeqCst),
        propfinds_after_first + 1,
        "an unchanged collection cost more than the single ctag probe"
    );
    assert_eq!(
        server.report_count.load(Ordering::SeqCst),
        reports_after_first,
        "an unchanged collection still ran a multiget"
    );
}

#[test]
fn a_changed_etag_refetches_only_the_event_that_changed() {
    let server = serve(vec![
        Round {
            ctag: "ctag-1",
            entries: vec![("/cal/a.ics", "\"1\""), ("/cal/b.ics", "\"1\"")],
            bodies: vec![("/cal/a.ics", EVENT_A), ("/cal/b.ics", EVENT_B)],
        },
        Round {
            ctag: "ctag-2",
            entries: vec![("/cal/a.ics", "\"1\""), ("/cal/b.ics", "\"2\"")],
            bodies: vec![("/cal/a.ics", EVENT_A), ("/cal/b.ics", EVENT_B)],
        },
    ]);
    let (_dir, mut store) = collection();
    let client = CaldavClient::new(&server.url, "user", "pass");

    sync_collection(&client, &server.url, &mut store).expect("first");
    let second = sync_collection(&client, &server.url, &mut store).expect("second");

    assert_eq!(
        second.fetched, 1,
        "an unchanged event was re-downloaded alongside the changed one"
    );
}

#[test]
fn an_event_removed_on_the_server_is_removed_locally() {
    let server = serve(vec![
        Round {
            ctag: "ctag-1",
            entries: vec![("/cal/a.ics", "\"1\""), ("/cal/b.ics", "\"1\"")],
            bodies: vec![("/cal/a.ics", EVENT_A), ("/cal/b.ics", EVENT_B)],
        },
        Round {
            ctag: "ctag-2",
            entries: vec![("/cal/a.ics", "\"1\"")], // b is gone
            bodies: vec![("/cal/a.ics", EVENT_A)],
        },
    ]);
    let (_dir, mut store) = collection();
    let client = CaldavClient::new(&server.url, "user", "pass");

    sync_collection(&client, &server.url, &mut store).expect("first");
    let second = sync_collection(&client, &server.url, &mut store).expect("second");

    assert_eq!(second.deleted, 1);
    let events = vdir::read_collection(store.collection());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].summary, "Event A");
}

#[test]
fn an_empty_listing_does_not_wipe_the_collection() {
    let server = serve(vec![
        Round {
            ctag: "ctag-1",
            entries: vec![("/cal/a.ics", "\"1\""), ("/cal/b.ics", "\"1\"")],
            bodies: vec![("/cal/a.ics", EVENT_A), ("/cal/b.ics", EVENT_B)],
        },
        Round {
            // The SOGo transient-empty-207 shape: a healthy-looking response
            // that lists nothing at all.
            ctag: "ctag-2",
            entries: vec![],
            bodies: vec![],
        },
    ]);
    let (_dir, mut store) = collection();
    let client = CaldavClient::new(&server.url, "user", "pass");

    sync_collection(&client, &server.url, &mut store).expect("first");
    let second = sync_collection(&client, &server.url, &mut store).expect("second");

    assert!(second.guard_tripped, "the mass-delete guard did not fire");
    assert_eq!(second.deleted, 0);
    assert_eq!(
        vdir::read_collection(store.collection()).len(),
        2,
        "a transient empty listing deleted the user's calendar"
    );
}

#[test]
fn the_sync_state_survives_a_reopen_so_a_restart_does_not_refetch() {
    let server = serve(vec![
        Round {
            ctag: "ctag-1",
            entries: vec![("/cal/a.ics", "\"1\"")],
            bodies: vec![("/cal/a.ics", EVENT_A)],
        },
        Round {
            ctag: "ctag-1",
            entries: vec![("/cal/a.ics", "\"1\"")],
            bodies: vec![("/cal/a.ics", EVENT_A)],
        },
    ]);
    let dir = tempfile::tempdir().expect("tempdir");
    let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).expect("collection");
    let client = CaldavClient::new(&server.url, "user", "pass");

    {
        let mut store = VdirStore::open(meta.clone()).expect("store");
        sync_collection(&client, &server.url, &mut store).expect("first");
    }

    // A fresh process: same directory, brand new store object.
    let reopened_meta = vdir::collections(dir.path()).remove(0);
    let mut store = VdirStore::open(reopened_meta).expect("reopen");
    assert_eq!(
        store.state().expect("state").ctag.as_deref(),
        Some("ctag-1"),
        "the ctag did not survive a restart"
    );

    let second = sync_collection(&client, &server.url, &mut store).expect("second");
    assert!(
        second.unchanged,
        "a restart re-downloaded a collection that had not changed"
    );
}

#[test]
fn a_synced_vtodo_is_readable_as_a_task_with_no_caldav_changes() {
    // The CalDAV layer stores the server's bytes verbatim and never parses
    // them, so tasks arrived working the moment the model existed. This pins
    // that: nothing in the sync engine knows what a VTODO is, and it does not
    // need to.
    let server = serve(vec![Round {
        ctag: "ctag-1",
        entries: vec![("/cal/t.ics", "\"1\""), ("/cal/a.ics", "\"1\"")],
        bodies: vec![("/cal/t.ics", TASK), ("/cal/a.ics", EVENT_A)],
    }]);
    let (_dir, mut store) = collection();
    let client = CaldavClient::new(&server.url, "user", "pass");

    let outcome = sync_collection(&client, &server.url, &mut store).expect("sync");
    assert_eq!(outcome.fetched, 2);

    let todos = vdir::read_todos(store.collection());
    assert_eq!(todos.len(), 1, "the task did not come through");
    assert_eq!(todos[0].summary, "Buy milk");
    assert_eq!(todos[0].priority, 2);

    // And the event in the same collection is still exactly one event — the
    // two readers do not see each other's components.
    let events = vdir::read_collection(store.collection());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].summary, "Event A");
}

/// The same event as `EVENT_A`, as another client left it on the server.
const EVENT_A_THEIRS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\nDTEND:20260804T100000Z\r\n\
SUMMARY:Moved to Thursday\r\nATTENDEE;CN=Someone:mailto:s@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// …and as this device left it, unsent.
const EVENT_A_MINE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\nDTEND:20260804T100000Z\r\n\
SUMMARY:Renamed by me\r\nATTENDEE;CN=Someone:mailto:s@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

#[test]
fn a_pull_does_not_overwrite_an_edit_that_has_not_been_pushed_yet() {
    // The failure this pins is the quietest one this crate can produce: the
    // pull writes the server's bytes over the local file, the queued PUT then
    // reads *that file* at drain time, uploads the server's own copy back, and
    // reports success. Queue empty, no error logged, ctag committed — and the
    // user's edit no longer exists anywhere.
    let server = serve(vec![
        Round {
            ctag: "ctag-1",
            entries: vec![("/cal/a.ics", "\"1\"")],
            bodies: vec![("/cal/a.ics", EVENT_A)],
        },
        Round {
            ctag: "ctag-2",
            entries: vec![("/cal/a.ics", "\"2\"")],
            bodies: vec![("/cal/a.ics", EVENT_A_THEIRS)],
        },
    ]);
    let (_dir, mut store) = collection();
    let client = CaldavClient::new(&server.url, "user", "pass");

    // Round one: the event arrives.
    sync_collection(&client, &server.url, &mut store).expect("first sync");
    let href = format!("{}a.ics", server.url);
    let file = store.collection().path.join("a.ics");

    // The user edits it. The push has not gone out — the laptop is on a train.
    std::fs::write(&file, EVENT_A_MINE).expect("local edit");
    store.queue_put(&href).expect("queue");

    // Round two: the server's copy changed too.
    let outcome = sync_collection(&client, &server.url, &mut store).expect("second sync");

    assert_eq!(outcome.conflicts, 1, "the divergence was not noticed");
    assert_eq!(outcome.fetched, 0, "the server's copy was written anyway");
    assert_eq!(
        std::fs::read_to_string(&file).expect("read back"),
        EVENT_A_MINE,
        "the unsent local edit was overwritten by the pull"
    );

    let conflict = store.conflict_for(&href).expect("no conflict recorded");
    // Trimmed: the multiget parser strips trailing whitespace from a payload,
    // so the server's bytes arrive without the final CRLF.
    assert_eq!(conflict.remote.trim_end(), EVENT_A_THEIRS.trim_end());
    assert_eq!(conflict.local, EVENT_A_MINE);
    assert_eq!(
        conflict.remote_etag, "\"2\"",
        "without the server's etag the resolution cannot be accepted by it"
    );
}

#[test]
fn resolving_a_conflict_in_favour_of_the_server_leaves_a_clean_collection() {
    let server = serve(vec![
        Round {
            ctag: "ctag-1",
            entries: vec![("/cal/a.ics", "\"1\"")],
            bodies: vec![("/cal/a.ics", EVENT_A)],
        },
        Round {
            ctag: "ctag-2",
            entries: vec![("/cal/a.ics", "\"2\"")],
            bodies: vec![("/cal/a.ics", EVENT_A_THEIRS)],
        },
        // A third round with nothing new: proof the conflict did not leave the
        // collection permanently re-fetching itself.
        Round {
            ctag: "ctag-2",
            entries: vec![("/cal/a.ics", "\"2\"")],
            bodies: vec![("/cal/a.ics", EVENT_A_THEIRS)],
        },
    ]);
    let (_dir, mut store) = collection();
    let client = CaldavClient::new(&server.url, "user", "pass");

    sync_collection(&client, &server.url, &mut store).expect("first sync");
    let href = format!("{}a.ics", server.url);
    std::fs::write(store.collection().path.join("a.ics"), EVENT_A_MINE).expect("local edit");
    store.queue_put(&href).expect("queue");
    sync_collection(&client, &server.url, &mut store).expect("second sync");

    assert!(store.resolve_conflict_take_remote(&href).expect("resolve"));

    let events = vdir::read_collection(store.collection());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].summary, "Moved to Thursday");
    assert!(store.conflicts().is_empty());
    assert!(
        store.pending().is_empty(),
        "the push carrying the discarded edit is still queued"
    );

    let reports_before = server.report_count.load(Ordering::SeqCst);
    let outcome = sync_collection(&client, &server.url, &mut store).expect("third sync");
    assert!(outcome.unchanged, "the resolved collection re-listed itself");
    assert_eq!(server.report_count.load(Ordering::SeqCst), reports_before);
}

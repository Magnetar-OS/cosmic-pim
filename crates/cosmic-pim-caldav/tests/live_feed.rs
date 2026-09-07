// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! A canned HTTP server serving an ICS feed to the real subscription code.
//!
//! The unit tests cover the splitter; this proves the whole loop — subscribe,
//! fetch, split into the vdir, and refresh again — over a real socket, and in
//! particular the two behaviours a fixture cannot fake:
//!
//! - a **304** costs no body and still resets the interval;
//! - the split files are read back by the ordinary store, so `khal` and the
//!   calendar index see a feed exactly as they see any other collection.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cosmic_pim_caldav::feed::{self, FeedState};
use cosmic_pim_core::model::Rgb;
use cosmic_pim_core::store::vdir;

const FEED_V1: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//test//feed//EN\r\n\
BEGIN:VEVENT\r\n\
UID:jan1@example.com\r\n\
DTSTART;VALUE=DATE:20270101\r\n\
SUMMARY:New Year\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
UID:mar25@example.com\r\n\
DTSTART;VALUE=DATE:20270325\r\n\
SUMMARY:Independence Day\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

/// The same feed a year later: one event renamed, one gone, one new.
const FEED_V2: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//test//feed//EN\r\n\
BEGIN:VEVENT\r\n\
UID:jan1@example.com\r\n\
DTSTART;VALUE=DATE:20270101\r\n\
SUMMARY:New Year's Day\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
UID:may1@example.com\r\n\
DTSTART;VALUE=DATE:20270501\r\n\
SUMMARY:May Day\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

struct Server {
    url: String,
    body: Arc<Mutex<(String, String)>>,
    hits: Arc<AtomicUsize>,
    bodies_served: Arc<AtomicUsize>,
    _handle: std::thread::JoinHandle<()>,
}

impl Server {
    fn publish(&self, body: &str, etag: &str) {
        *self.body.lock().expect("body") = (body.to_owned(), etag.to_owned());
    }
}

/// Serves one feed with an ETag, answering 304 to a matching If-None-Match —
/// which is exactly what a static-file host does.
fn serve(initial: &str, etag: &str) -> Server {
    let server = tiny_http::Server::http("127.0.0.1:0").expect("bind");
    let port = server.server_addr().to_ip().expect("ip").port();
    let url = format!("http://127.0.0.1:{port}/holidays.ics");

    let body = Arc::new(Mutex::new((initial.to_owned(), etag.to_owned())));
    let hits = Arc::new(AtomicUsize::new(0));
    let bodies_served = Arc::new(AtomicUsize::new(0));

    let held = Arc::clone(&body);
    let hit_count = Arc::clone(&hits);
    let served = Arc::clone(&bodies_served);

    let handle = std::thread::spawn(move || {
        for request in server.incoming_requests() {
            hit_count.fetch_add(1, Ordering::SeqCst);
            let (current_body, current_etag) = held.lock().expect("body").clone();

            let sent_match = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("If-None-Match"))
                .map(|header| header.value.as_str().to_owned());

            let response = if sent_match.as_deref() == Some(current_etag.as_str()) {
                tiny_http::Response::from_string(String::new()).with_status_code(304)
            } else {
                served.fetch_add(1, Ordering::SeqCst);
                tiny_http::Response::from_string(current_body)
                    .with_status_code(200)
                    .with_header(
                        tiny_http::Header::from_bytes(&b"ETag"[..], current_etag.as_bytes())
                            .expect("header"),
                    )
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"text/calendar; charset=utf-8"[..],
                        )
                        .expect("header"),
                    )
            };
            let _ = request.respond(response);
        }
    });

    Server {
        url,
        body,
        hits,
        bodies_served,
        _handle: handle,
    }
}

#[test]
fn a_subscription_fills_its_collection_and_the_store_reads_it() {
    let server = serve(FEED_V1, "\"v1\"");
    let dir = tempfile::tempdir().expect("tempdir");
    let meta = feed::subscribe(dir.path(), "Holidays", &server.url, Rgb(1, 2, 3), None)
        .expect("subscribe");

    let outcome = feed::refresh(&meta.path, 1_000).expect("refresh");

    assert_eq!(outcome.updated, 2);
    assert!(!outcome.unchanged);

    // The point of splitting into the vdir: the ordinary store reads a feed
    // like any other collection, with no feed-shaped code anywhere in it.
    let mut events = vdir::read_collection(&meta);
    events.sort_by(|a, b| a.summary.cmp(&b.summary));
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].summary, "Independence Day");
    assert_eq!(events[1].summary, "New Year");
}

#[test]
fn an_unchanged_feed_costs_a_304_and_no_body() {
    let server = serve(FEED_V1, "\"v1\"");
    let dir = tempfile::tempdir().expect("tempdir");
    let meta = feed::subscribe(dir.path(), "Holidays", &server.url, Rgb(1, 2, 3), None)
        .expect("subscribe");
    feed::refresh(&meta.path, 1_000).expect("first refresh");

    let outcome = feed::refresh(&meta.path, 2_000).expect("second refresh");

    assert!(outcome.unchanged);
    assert!(!outcome.changed());
    assert_eq!(
        server.bodies_served.load(Ordering::SeqCst),
        1,
        "the unchanged feed was transferred again"
    );
    assert_eq!(server.hits.load(Ordering::SeqCst), 2);

    // A 304 still resets the interval — otherwise every pass polls the host.
    let state = FeedState::load(&meta.path).expect("sidecar");
    assert_eq!(state.last_checked_ms, 2_000);
    assert!(!state.due(2_000 + 60_000));
}

#[test]
fn a_changed_feed_updates_removes_and_adds_in_place() {
    let server = serve(FEED_V1, "\"v1\"");
    let dir = tempfile::tempdir().expect("tempdir");
    let meta = feed::subscribe(dir.path(), "Holidays", &server.url, Rgb(1, 2, 3), None)
        .expect("subscribe");
    feed::refresh(&meta.path, 1_000).expect("first refresh");

    server.publish(FEED_V2, "\"v2\"");
    let outcome = feed::refresh(&meta.path, 2_000).expect("second refresh");

    // jan1 renamed (rewritten), mar25 gone (removed), may1 new (written).
    assert_eq!(outcome.updated, 2);
    assert_eq!(outcome.removed, 1);

    let mut events = vdir::read_collection(&meta);
    events.sort_by(|a, b| a.summary.cmp(&b.summary));
    let summaries: Vec<&str> = events.iter().map(|e| e.summary.as_str()).collect();
    assert_eq!(summaries, ["May Day", "New Year's Day"]);
}

#[test]
fn an_unchanged_event_is_not_rewritten() {
    // Rewriting identical bytes churns mtimes, and the watcher would wake
    // every reader once per refresh for nothing.
    let server = serve(FEED_V1, "\"v1\"");
    let dir = tempfile::tempdir().expect("tempdir");
    let meta = feed::subscribe(dir.path(), "Holidays", &server.url, Rgb(1, 2, 3), None)
        .expect("subscribe");
    feed::refresh(&meta.path, 1_000).expect("first refresh");

    // Same body under a new etag: a re-fetch happens, nothing changed inside.
    server.publish(FEED_V1, "\"v1-repacked\"");
    let outcome = feed::refresh(&meta.path, 2_000).expect("second refresh");

    assert_eq!(outcome.updated, 0, "identical events were rewritten");
    assert_eq!(outcome.removed, 0);
}

#[test]
fn a_login_page_wearing_the_calendar_content_type_is_refused() {
    // The SSO-portal case, same as the DAV store's: HTML served as
    // text/calendar must not replace a real calendar.
    let server = serve("<html><body>Sign in</body></html>", "\"portal\"");
    let dir = tempfile::tempdir().expect("tempdir");
    let meta = feed::subscribe(dir.path(), "Holidays", &server.url, Rgb(1, 2, 3), None)
        .expect("subscribe");

    assert!(feed::refresh(&meta.path, 1_000).is_err());
    assert!(vdir::read_collection(&meta).is_empty());
}

#[test]
fn a_feed_collection_never_queues_writeback() {
    // Read-only by construction: no .caldav-state.json means no CalDAV
    // binding, and the writeback path declines exactly as it does for a
    // local-only calendar. Nothing here needs to check a flag.
    let server = serve(FEED_V1, "\"v1\"");
    let dir = tempfile::tempdir().expect("tempdir");
    let meta = feed::subscribe(dir.path(), "Holidays", &server.url, Rgb(1, 2, 3), None)
        .expect("subscribe");
    feed::refresh(&meta.path, 1_000).expect("refresh");

    assert!(feed::is_feed(&meta.path));
    let store = cosmic_pim_caldav::VdirStore::open(meta).expect("open");
    assert!(
        store.href().is_none(),
        "a feed collection acquired a CalDAV binding"
    );
}

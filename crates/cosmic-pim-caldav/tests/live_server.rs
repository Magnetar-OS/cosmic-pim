// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The sync engine against a real CalDAV server — no canned XML anywhere.
//!
//! Every other test in this crate scripts the server, which proves the client
//! against what we *believe* servers say. This one is the beginning of the
//! server matrix 00-suite.md asks for: it proves the client against what a
//! server actually says, which is where the quirks table's entries come from —
//! its first afternoon produced six, and every server added since has produced
//! more. CI runs it against Radicale, Xandikos and Nextcloud; Baïkal can join
//! as a container later, and Fastmail/Google/iCloud stay a manual checklist.
//!
//! Ignored by default and gated on the environment, so `cargo test` stays
//! offline and deterministic:
//!
//! ```sh
//! COSMIC_PIM_LIVE_CALDAV_URL=http://127.0.0.1:5232/ci/ \
//! COSMIC_PIM_LIVE_CALDAV_USER=ci COSMIC_PIM_LIVE_CALDAV_PASS=ci \
//! cargo test -p cosmic-pim-caldav --test live_server -- --ignored
//! ```

use cosmic_pim_caldav::push::drain;
use cosmic_pim_caldav::{CalDavStore, CaldavClient, Disposition, VdirStore, sync_collection};
use cosmic_pim_core::model::Rgb;
use cosmic_pim_core::store::vdir;

struct Live {
    base: String,
    user: String,
    pass: String,
}

/// The server to test against, or `None` — in which case the test announces
/// it is skipping rather than failing, so `--ignored` without a server is a
/// no-op instead of a red herring.
fn live() -> Option<Live> {
    let base = std::env::var("COSMIC_PIM_LIVE_CALDAV_URL").ok()?;
    Some(Live {
        base: if base.ends_with('/') { base } else { format!("{base}/") },
        user: std::env::var("COSMIC_PIM_LIVE_CALDAV_USER").unwrap_or_default(),
        pass: std::env::var("COSMIC_PIM_LIVE_CALDAV_PASS").unwrap_or_default(),
    })
}

fn event(uid: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//cosmic-pim//live//EN\r\n\
         BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTART:20270104T090000Z\r\nDTEND:20270104T100000Z\r\n\
         SUMMARY:{summary}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// One deliberately sequential journey: create, discover, sync down, edit,
/// push back, hit the 412, delete. Sequential because each step is the next
/// one's fixture, and a real server's state does not reset between tests.
#[test]
#[ignore = "needs a live CalDAV server; see the module docs"]
fn a_full_round_trip_against_a_real_server() {
    let Some(live) = live() else {
        eprintln!("COSMIC_PIM_LIVE_CALDAV_URL is not set; skipping");
        return;
    };

    // --- discover, then create INSIDE the home -----------------------------
    // Finding #5 of the first live runs: the calendar home is wherever the
    // server says it is — `/ci/` on Radicale, `/ci/calendars/` on Xandikos —
    // and a calendar created at a guessed path exists but is never
    // discovered. So the journey discovers first, exactly as an app must.
    let mut client = CaldavClient::new(&live.base, &live.user, &live.pass);
    client.discover().expect("discovery");
    let home = client
        .calendar_home_url()
        .expect("discovery produced no calendar home")
        .trim_end_matches('/')
        .to_owned();
    let calendar_url_direct = format!("{home}/ci-e2e/");
    let event_url = format!("{calendar_url_direct}ci-round-trip.ics");

    // Finding #8: not one of these four servers announces itself in its
    // `Server` header — they name Apache, nginx, WSGIServer, aiohttp. Two are
    // identifiable by other headers (Nextcloud brands the `DAV:` compliance
    // list, Baïkal exposes `X-Sabre-Version`); two are not identifiable at
    // all, and guessing from `aiohttp` or `WSGIServer` would claim unrelated
    // servers, so they stay Unknown deliberately.
    //
    // Each CI leg therefore declares the detection outcome it expects —
    // `Unknown` included. That makes the limit itself a tested fact: if a
    // release starts volunteering its identity, this fails and the ledger
    // gets upgraded on purpose rather than by accident. Unset outside CI,
    // where the journey does not know who it is talking to.
    if let Ok(expected) = std::env::var("COSMIC_PIM_LIVE_CALDAV_EXPECT") {
        let detected = format!("{:?}", client.detected_server());
        assert!(
            detected.eq_ignore_ascii_case(&expected),
            "detected {detected}, expected {expected} — the server changed \
             what it volunteers, or detection regressed"
        );
    }

    // Finding #1: a PUT into a missing collection is a 409, not an implicit
    // create — which also live-confirms the taxonomy's 409 → Reconcile.
    // MKCALENDAR first, and a second one must read as success (findings #2
    // and #4: "already exists" is 405, or 409/403 + resource-must-be-null,
    // depending on the server).
    client
        .mkcalendar(&calendar_url_direct, "CI round trip")
        .expect("MKCALENDAR");
    client
        .mkcalendar(&calendar_url_direct, "CI round trip")
        .expect("a second MKCALENDAR must be tolerated");

    // Finding #7 (Nextcloud): a 201 to PUT may carry no ETag header at all —
    // the engine never trusted it anyway (drain discards it; the next sync's
    // listing is the source of truth), so nothing in this journey may either.
    client
        .put_event(&event_url, &event("ci-1@cosmic-pim", "Created live"), None)
        .expect("PUT a new event");

    let calendars = client.list_calendars().expect("list calendars");
    let calendar = calendars
        .iter()
        .find(|c| c.href.trim_end_matches('/').ends_with("ci-e2e"))
        .unwrap_or_else(|| panic!("the created calendar was not discovered: {calendars:?}"));

    // --- sync down --------------------------------------------------------
    let dir = tempfile::tempdir().expect("tempdir");
    let meta = vdir::create_collection(dir.path(), "Live", Rgb(1, 2, 3)).expect("collection");
    let mut store = VdirStore::open(meta).expect("store");
    store.set_remote(&calendar.href, false).expect("bind");

    let calendar_url = resolve(&live.base, &calendar.href);
    let outcome = sync_collection(&client, &calendar_url, &mut store).expect("first sync");
    assert!(outcome.fetched >= 1, "the created event never came down");

    let events = vdir::read_collection(store.collection());
    let mine = events
        .iter()
        .find(|e| e.summary == "Created live")
        .expect("the event is not readable from the vdir");
    let _ = mine;

    // --- edit locally, push back ------------------------------------------
    let (file, first_sync_etag) = store
        .entry_for(&event_url)
        .or_else(|| {
            // Servers are free to rewrite the href; find ours by content.
            store.state().ok().and_then(|s| {
                s.entries.keys().find_map(|href| {
                    href.contains("ci-round-trip").then(|| store.entry_for(href)).flatten()
                })
            })
        })
        .expect("the synced event has no sidecar entry");

    std::fs::write(
        store.collection().path.join(&file),
        event("ci-1@cosmic-pim", "Edited live"),
    )
    .expect("local edit");
    let href = store.href_for_file(&file).expect("an href for the file");
    store.queue_put(&href).expect("queue");

    let pushed = drain(&client, &mut store, 0);
    assert_eq!(pushed.succeeded, 1, "the edit did not reach the server: {pushed:?}");

    // And the server agrees: a fresh sync into a fresh store sees the edit.
    let meta = vdir::create_collection(dir.path(), "Verify", Rgb(1, 2, 3)).expect("collection");
    let mut verify = VdirStore::open(meta).expect("store");
    verify.set_remote(&calendar.href, false).expect("bind");
    sync_collection(&client, &calendar_url, &mut verify).expect("verify sync");
    assert!(
        vdir::read_collection(verify.collection())
            .iter()
            .any(|e| e.summary == "Edited live"),
        "the server kept the old copy"
    );

    // --- the 412 path ------------------------------------------------------
    // A stale If-Match must be refused by the server and classified as
    // Reconcile by us — the whole push-error taxonomy in one live exchange.
    let stale = client.put_event(
        &event_url,
        &event("ci-1@cosmic-pim", "Must not land"),
        Some("\"nothing-has-this-etag\""),
    );
    let why = stale.expect_err("a stale etag was accepted");
    assert_eq!(
        why.disposition(),
        Disposition::Reconcile,
        "a 412 was classified as {:?} ({why})",
        why.disposition()
    );

    // --- delete, guarded then idempotent -----------------------------------
    // Finding #3 of the first live run: an etag goes stale the moment the
    // edit round-trips, and servers enforce If-Match on DELETE as strictly as
    // on PUT. Optimistic concurrency covers removal too — a client deleting
    // over a stale etag would be deleting a version it has never seen. The
    // stale value is the *first sync's* etag, which every server provided in
    // its listing — not the PUT response's, which finding #7 says may not
    // exist.
    let stale_delete = client
        .delete_event(&event_url, Some(&first_sync_etag))
        .expect_err("a stale-etag DELETE was accepted");
    assert_eq!(stale_delete.disposition(), Disposition::Reconcile);

    // With the *current* etag — the one the verify sync recorded — it goes.
    let current = verify
        .state()
        .expect("state")
        .entries
        .iter()
        .find(|(href, _)| href.contains("ci-round-trip"))
        .map(|(_, etag)| etag.clone())
        .expect("the verify store holds no etag for the event");
    client
        .delete_event(&event_url, Some(&current))
        .expect("DELETE with the current etag");
    client
        .delete_event(&event_url, None)
        .expect("a second DELETE must be tolerated, not wedged on a 404");

    // And a final sync notices the removal — one way or the other.
    //
    // Finding #6: when the deletion empties the collection completely, the
    // mass-delete guard fires — an empty listing while we hold events is
    // indistinguishable, in one cycle, from a server hiccup, and the guard
    // chooses staleness over data loss. So the designed behaviour here is
    // EITHER the deletion applying (something else still listed) or the
    // guard tripping and the local copy surviving. What must never happen is
    // the third thing: a silent nothing.
    let outcome = sync_collection(&client, &calendar_url, &mut store).expect("final sync");
    if outcome.guard_tripped {
        assert!(
            !vdir::read_collection(store.collection()).is_empty(),
            "the guard tripped and yet the local copy is gone"
        );
    } else {
        assert!(
            outcome.deleted >= 1 || vdir::read_collection(store.collection()).is_empty(),
            "the deletion never propagated and no guard fired"
        );
    }
}

/// Hrefs come back server-relative; the request URL needs them absolute.
fn resolve(base: &str, href: &str) -> String {
    if href.starts_with("http") {
        return href.to_owned();
    }
    let origin = base
        .find("//")
        .and_then(|scheme| base[scheme + 2..].find('/').map(|slash| &base[..scheme + 2 + slash]))
        .unwrap_or(base);
    format!("{}{}", origin, href)
}

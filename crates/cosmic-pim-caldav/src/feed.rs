// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! ICS subscriptions: read-only calendars fetched from a URL.
//!
//! The webcal feed — a public holiday calendar, a sports fixture list, a
//! timetable someone publishes — is one `.ics` file over plain HTTPS. No DAV,
//! no account, no writeback; the server's copy is simply the truth on a
//! schedule. This module lives beside the CalDAV engine because it shares the
//! HTTP stack and the vdir, and shares nothing with the DAV protocol — a feed
//! is not a fifth `Flavor`, for the same reason IMAP is not.
//!
//! # One file in, one file per event out
//!
//! A feed arrives as a single calendar holding every event, and the vdir
//! stores one file per item — that is what makes `khal` and the calendar index
//! read it like any other collection. So the feed is *split*: top-level
//! components grouped by UID (a recurrence master and its `RECURRENCE-ID`
//! overrides share a UID and must stay in one file, or the override is
//! orphaned), every `VTIMEZONE` copied into every file (an event's `TZID` must
//! resolve from its own file), and the calendar-level header preserved.
//!
//! The split copies the source's own bytes, line for line — folding,
//! terminators, and every unmodelled property intact. Not because writeback
//! needs them (there is none), but because the one parser reading the file
//! back must see what the publisher wrote, and a re-serialisation here would
//! be the second serialiser this suite deliberately does not have.
//!
//! # Refresh is conditional
//!
//! Feeds are polled on an interval, and most polls find nothing new. The
//! stored `ETag` and `Last-Modified` are replayed as `If-None-Match` and
//! `If-Modified-Since`, so an unchanged feed costs a 304 and no body — the
//! difference between a poll every fifteen minutes being neighbourly and
//! being a nuisance to whoever hosts the file.
//!
//! # The collection is read-only by construction
//!
//! A feed collection carries an `.ics-feed.json` sidecar and no
//! `.caldav-state.json`, so nothing ever queues writeback for it —
//! `queue_save` finds no CalDAV binding and declines, exactly as it does for
//! any local-only collection. Sync provisioning never adopts it either: it
//! only touches collections bound to an account. The read-only property is
//! structural rather than a flag someone must remember to check.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use cosmic_pim_core::atomic;
use cosmic_pim_core::model::{CalendarMeta, Rgb};
use cosmic_pim_core::patch::{ContentLine, logical_lines, terminator_of};
use cosmic_pim_core::store::vdir;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::vdir::sanitise_stem;

/// The sidecar a feed collection keeps beside its events.
///
/// The leading dot keeps it out of the store's item listing and the watcher's
/// interest set, like every other sidecar in the suite.
pub const STATE_FILE: &str = ".ics-feed.json";

/// Feeds are static files; a hung server should not hold a refresh open.
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// Refuse a feed larger than this. A public calendar is kilobytes; a limit is
/// what stops a misconfigured URL feeding a video into memory.
const MAX_FEED_BYTES: u64 = 32 * 1024 * 1024;

/// How often a feed is checked when the subscriber did not say.
///
/// Holiday calendars change yearly and timetables weekly; hourly is generous
/// for both, and a 304 costs the host almost nothing.
const DEFAULT_REFRESH_MINUTES: u32 = 60;

/// What a feed collection remembers between refreshes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedState {
    /// Where the calendar lives. `https`, after [`normalise_url`].
    pub url: String,
    /// The validators the server sent, replayed on the next fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// When the feed was last *checked* — a 304 counts.
    #[serde(default)]
    pub last_checked_ms: i64,
    #[serde(default = "default_refresh")]
    pub refresh_minutes: u32,
    /// UID → the file holding it, so a refresh updates in place and knows
    /// what to remove.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

fn default_refresh() -> u32 {
    DEFAULT_REFRESH_MINUTES
}

impl FeedState {
    /// Reads the sidecar in `collection`, if this collection is a feed.
    #[must_use]
    pub fn load(collection: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(collection.join(STATE_FILE)).ok()?;
        match serde_json::from_str(&text) {
            Ok(state) => Some(state),
            Err(why) => {
                // Unreadable is reported rather than treated as "not a feed":
                // silently demoting a subscription to a local calendar would
                // stop it updating with nothing anywhere saying so.
                tracing::warn!(path = %collection.display(), %why, "unreadable feed sidecar");
                None
            }
        }
    }

    /// Writes the sidecar atomically — a torn one loses the validators and
    /// the file map, which costs a full re-fetch and re-split.
    pub fn save(&self, collection: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|why| Error::internal(format!("serialising feed state: {why}")))?;
        atomic::write(&collection.join(STATE_FILE), &json, None)
            .map(|_| ())
            .map_err(|why| Error::internal(format!("writing feed state: {why}")))
    }

    /// Whether a refresh is due at `now_ms`.
    ///
    /// A feed that has never been checked is always due — a fresh subscription
    /// should not sit empty for its first interval.
    #[must_use]
    pub fn due(&self, now_ms: i64) -> bool {
        if self.last_checked_ms == 0 {
            return true;
        }
        let interval_ms = i64::from(self.refresh_minutes).saturating_mul(60_000);
        now_ms.saturating_sub(self.last_checked_ms) >= interval_ms
    }
}

/// Whether a collection directory is a feed subscription.
#[must_use]
pub fn is_feed(collection: &Path) -> bool {
    collection.join(STATE_FILE).is_file()
}

/// `webcal://` and `webcals://` are `https` wearing a scheme that tells a
/// desktop "subscribe, don't download". Mapped to `https` rather than `http`:
/// an event feed fetched over plaintext can be tampered with in transit, and a
/// host that genuinely has no TLS can be given as explicit `http://`.
#[must_use]
pub fn normalise_url(url: &str) -> String {
    let trimmed = url.trim();
    if let Some(rest) = trimmed.strip_prefix("webcals://") {
        return format!("https://{rest}");
    }
    if let Some(rest) = trimmed.strip_prefix("webcal://") {
        return format!("https://{rest}");
    }
    trimmed.to_owned()
}

/// Creates a feed collection under `root` and records the subscription.
///
/// The events arrive on the first [`refresh`]; subscribing is deliberately
/// offline so a dialog can complete without waiting on the feed's host.
pub fn subscribe(
    root: &Path,
    name: &str,
    url: &str,
    color: Rgb,
    refresh_minutes: Option<u32>,
) -> Result<CalendarMeta> {
    let meta = vdir::create_collection(root, name, color)?;
    let state = FeedState {
        url: normalise_url(url),
        etag: None,
        last_modified: None,
        last_checked_ms: 0,
        refresh_minutes: refresh_minutes.unwrap_or(DEFAULT_REFRESH_MINUTES),
        files: BTreeMap::new(),
    };
    state.save(&meta.path)?;
    Ok(meta)
}

/// What one refresh did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeedOutcome {
    /// The validators matched and no body was transferred.
    pub unchanged: bool,
    /// Files written or rewritten.
    pub updated: usize,
    /// Files removed because their UID left the feed.
    pub removed: usize,
    /// The feed parsed to nothing while files were held, so removals were
    /// skipped — the same guard the CalDAV planner applies to an empty
    /// listing.
    pub guard_tripped: bool,
}

impl FeedOutcome {
    #[must_use]
    pub fn changed(&self) -> bool {
        self.updated > 0 || self.removed > 0
    }
}

/// Fetches the feed and brings the collection up to date with it.
///
/// `now_ms` is recorded as the check time whatever happens short of an error,
/// so a 304 still resets the interval.
pub fn refresh(collection: &Path, now_ms: i64) -> Result<FeedOutcome> {
    let Some(mut state) = FeedState::load(collection) else {
        return Err(Error::internal(format!(
            "{} is not a feed collection",
            collection.display()
        )));
    };

    let http = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|why| Error::protocol(format!("feed: {why}")))?;

    let mut request = http.get(&state.url).header("Accept", "text/calendar");
    if let Some(etag) = state.etag.as_deref() {
        request = request.header("If-None-Match", etag);
    }
    if let Some(when) = state.last_modified.as_deref() {
        request = request.header("If-Modified-Since", when);
    }

    let response = request
        .send()
        .map_err(|why| Error::protocol(format!("feed {}: {why}", state.url)))?;

    let status = response.status().as_u16();
    if status == 304 {
        state.last_checked_ms = now_ms;
        state.save(collection)?;
        return Ok(FeedOutcome {
            unchanged: true,
            ..Default::default()
        });
    }
    if !(200..300).contains(&status) {
        return Err(Error::status(status, format!("feed {}", state.url)));
    }

    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let last_modified = response
        .headers()
        .get("last-modified")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    let body = {
        use std::io::Read as _;
        let mut text = String::new();
        response
            .take(MAX_FEED_BYTES)
            .read_to_string(&mut text)
            .map_err(|why| Error::protocol(format!("feed {}: reading body: {why}", state.url)))?;
        text
    };

    // The SSO-portal check, same as the DAV store's: a login page served as
    // `200 text/calendar` must not replace a real calendar with HTML.
    if !body
        .trim_start()
        .get(..15)
        .is_some_and(|head| head.eq_ignore_ascii_case("BEGIN:VCALENDAR"))
    {
        return Err(Error::protocol(format!(
            "feed {} did not return an iCalendar body",
            state.url
        )));
    }

    let outcome = apply(collection, &body, &mut state)?;

    state.etag = etag;
    state.last_modified = last_modified;
    state.last_checked_ms = now_ms;
    state.save(collection)?;

    Ok(outcome)
}

/// Splits the fetched calendar and reconciles the collection's files with it.
fn apply(collection: &Path, body: &str, state: &mut FeedState) -> Result<FeedOutcome> {
    let mut outcome = FeedOutcome::default();
    let split = split_by_uid(body);

    if split.is_empty() && !state.files.is_empty() {
        // An empty-but-valid calendar while we hold events is far more likely
        // to be the host having a moment than a feed that emptied itself.
        // The same tradeoff as the CalDAV mass-delete guard, for the same
        // reason: skipping a legitimate emptying costs staleness the next
        // refresh can fix; honouring a bogus one deletes a calendar.
        tracing::warn!(
            collection = %collection.display(),
            held = state.files.len(),
            "the feed parsed to no events while we hold some; skipping removals"
        );
        outcome.guard_tripped = true;
        return Ok(outcome);
    }

    let mut fresh_files: BTreeMap<String, String> = BTreeMap::new();

    for (uid, text) in &split {
        let file = state
            .files
            .get(uid)
            .cloned()
            .unwrap_or_else(|| unique_name(uid, &fresh_files, &state.files));
        let target = collection.join(&file);

        // Write only what changed: rewriting identical bytes churns mtimes,
        // and the watcher would wake every reader once per refresh for
        // nothing.
        let current = std::fs::read_to_string(&target).ok();
        if current.as_deref() != Some(text.as_str()) {
            atomic::write(&target, text, None)
                .map_err(|why| Error::internal(format!("writing {}: {why}", target.display())))?;
            outcome.updated += 1;
        }
        fresh_files.insert(uid.clone(), file);
    }

    for (uid, file) in &state.files {
        if !fresh_files.contains_key(uid) {
            let path = collection.join(file);
            match std::fs::remove_file(&path) {
                Ok(()) => outcome.removed += 1,
                Err(why) if why.kind() == std::io::ErrorKind::NotFound => {}
                Err(why) => {
                    return Err(Error::internal(format!(
                        "removing {}: {why}",
                        path.display()
                    )));
                }
            }
        }
    }

    state.files = fresh_files;
    Ok(outcome)
}

/// A file name for a UID that collides with nothing already in use.
fn unique_name(
    uid: &str,
    fresh: &BTreeMap<String, String>,
    held: &BTreeMap<String, String>,
) -> String {
    let stem = sanitise_stem(uid);
    let taken = |name: &str| {
        fresh.values().any(|file| file == name) || held.values().any(|file| file == name)
    };

    let mut name = format!("{stem}.ics");
    let mut n = 2;
    while taken(&name) {
        name = format!("{stem}-{n}.ics");
        n += 1;
    }
    name
}

/// One calendar in, one calendar text per UID out.
///
/// Each output carries the source's calendar-level header lines, every
/// `VTIMEZONE`, and the components sharing that UID — all as the source's own
/// bytes. Components without a UID are dropped with a warning rather than
/// filed under an invented one: a UID is the identity a refresh reconciles
/// on, and a fabricated identity turns every refresh into a delete-and-recreate.
#[must_use]
pub fn split_by_uid(body: &str) -> Vec<(String, String)> {
    let terminator = terminator_of(body);
    let lines = logical_lines(body);

    let mut header: Vec<&str> = Vec::new();
    let mut timezones: Vec<Vec<&str>> = Vec::new();
    // Insertion-ordered: the feed's own ordering is kept.
    let mut components: Vec<(String, Vec<Vec<&str>>)> = Vec::new();

    let mut inside: Option<(String, Vec<&str>)> = None;
    let mut depth = 0usize;

    for line in &lines {
        let begins = line.begins();
        let ends = line.ends();

        match &mut inside {
            None => {
                if let Some(name) = begins {
                    if name == "VCALENDAR" {
                        continue;
                    }
                    depth = 1;
                    inside = Some((name, vec![line.raw()]));
                } else if ends.as_deref() == Some("VCALENDAR") {
                    continue;
                } else {
                    header.push(line.raw());
                }
            }
            Some((name, collected)) => {
                collected.push(line.raw());
                if begins.is_some() {
                    depth += 1;
                } else if let Some(ended) = ends {
                    depth -= 1;
                    if depth == 0 {
                        debug_assert_eq!(&ended, name, "unbalanced component nesting");
                        let (name, collected) = inside.take().expect("just matched Some");
                        if name == "VTIMEZONE" {
                            timezones.push(collected);
                        } else {
                            match uid_of(&collected) {
                                Some(uid) => match components.iter_mut().find(|(u, _)| *u == uid) {
                                    Some((_, blocks)) => blocks.push(collected),
                                    None => components.push((uid, vec![collected])),
                                },
                                None => {
                                    tracing::warn!(
                                        component = name,
                                        "feed component has no UID; skipping it"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    components
        .into_iter()
        .map(|(uid, blocks)| {
            let mut out = String::new();
            out.push_str("BEGIN:VCALENDAR");
            out.push_str(terminator);
            for line in &header {
                out.push_str(line);
            }
            for timezone in &timezones {
                for line in timezone {
                    out.push_str(line);
                }
            }
            for block in &blocks {
                for line in block {
                    out.push_str(line);
                }
            }
            out.push_str("END:VCALENDAR");
            out.push_str(terminator);
            (uid, out)
        })
        .collect()
}

/// The UID of a collected component, from its own top-level lines.
///
/// Deliberately not recursive: a `VALARM` inside a `VEVENT` may carry
/// properties of its own, and the event's identity must not be read out of
/// its alarm.
fn uid_of(collected: &[&str]) -> Option<String> {
    let mut depth = 0usize;
    for raw in collected {
        // Re-derive the unfolded form for just this line.
        let text: Vec<ContentLine<'_>> = logical_lines(raw);
        let Some(line) = text.first() else { continue };
        if line.begins().is_some() {
            depth += 1;
        } else if line.ends().is_some() {
            depth = depth.saturating_sub(1);
        } else if depth == 1 && line.name() == "UID" {
            let value = line.value().trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A feed the way a real publisher writes one: calendar-level properties,
    /// a timezone, a recurring event with an override, a second event with a
    /// folded summary, and an alarm carrying its own UID-shaped noise.
    const FEED: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Example//Feed//EN\r\n\
X-WR-CALNAME:Public holidays\r\n\
BEGIN:VTIMEZONE\r\n\
TZID:Europe/Athens\r\n\
BEGIN:STANDARD\r\n\
DTSTART:19701025T040000\r\n\
TZOFFSETFROM:+0300\r\n\
TZOFFSETTO:+0200\r\n\
END:STANDARD\r\n\
END:VTIMEZONE\r\n\
BEGIN:VEVENT\r\n\
UID:recurring@example.com\r\n\
DTSTART;TZID=Europe/Athens:20260901T090000\r\n\
RRULE:FREQ=WEEKLY\r\n\
SUMMARY:Weekly\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
UID:recurring@example.com\r\n\
RECURRENCE-ID;TZID=Europe/Athens:20260908T090000\r\n\
DTSTART;TZID=Europe/Athens:20260908T100000\r\n\
SUMMARY:Weekly (moved)\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
UID:single@example.com\r\n\
DTSTART;VALUE=DATE:20261225\r\n\
SUMMARY:A deliberately long summary line that the publisher folded acros\r\n\x20s two physical lines\r\n\
BEGIN:VALARM\r\n\
TRIGGER:-PT15M\r\n\
UID:alarm-not-the-event@example.com\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    #[test]
    fn a_master_and_its_override_stay_in_one_file() {
        // Splitting them apart orphans the override: a reader that opens the
        // override's file finds a RECURRENCE-ID pointing at a series it
        // cannot see.
        let split = split_by_uid(FEED);

        assert_eq!(split.len(), 2);
        let recurring = &split
            .iter()
            .find(|(uid, _)| uid == "recurring@example.com")
            .unwrap()
            .1;
        assert_eq!(recurring.matches("BEGIN:VEVENT").count(), 2);
        assert!(recurring.contains("RECURRENCE-ID"));
    }

    #[test]
    fn every_file_carries_the_timezone_and_the_header() {
        // An event whose TZID cannot resolve from its own file silently
        // becomes floating — the exact bug class the one-parser rule exists
        // for.
        for (uid, text) in split_by_uid(FEED) {
            assert!(text.contains("BEGIN:VTIMEZONE"), "{uid} lost its timezone");
            assert!(
                text.contains("TZID:Europe/Athens"),
                "{uid} lost the zone id"
            );
            assert!(
                text.contains("PRODID:-//Example//Feed//EN"),
                "{uid} lost the header"
            );
            assert!(text.starts_with("BEGIN:VCALENDAR\r\n"));
            assert!(text.ends_with("END:VCALENDAR\r\n"));
        }
    }

    #[test]
    fn folding_survives_the_split_byte_for_byte() {
        // The split copies lines, it does not re-serialise them; a re-folded
        // summary would be the second serialiser this suite does not have.
        let split = split_by_uid(FEED);
        let single = &split
            .iter()
            .find(|(uid, _)| uid == "single@example.com")
            .unwrap()
            .1;

        assert!(
            single.contains("folded acros\r\n s two"),
            "the publisher's own folding was rewritten"
        );
    }

    #[test]
    fn an_alarms_uid_is_not_the_events_identity() {
        // The VALARM inside the second event carries a UID of its own;
        // reading identity out of it would file the event under the alarm.
        let split = split_by_uid(FEED);
        assert!(split.iter().any(|(uid, _)| uid == "single@example.com"));
        assert!(
            !split
                .iter()
                .any(|(uid, _)| uid.contains("alarm-not-the-event"))
        );
    }

    #[test]
    fn an_lf_only_feed_keeps_its_own_terminator() {
        let feed = "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nUID:a@x\nSUMMARY:X\nEND:VEVENT\nEND:VCALENDAR\n";
        let split = split_by_uid(feed);

        assert_eq!(split.len(), 1);
        assert!(split[0].1.contains("BEGIN:VCALENDAR\nVERSION:2.0\n"));
        assert!(
            !split[0].1.contains("\r\n"),
            "the terminator was rewritten to CRLF"
        );
    }

    #[test]
    fn a_component_without_a_uid_is_dropped_rather_than_invented_for() {
        // A fabricated identity makes every refresh a delete-and-recreate.
        let feed = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:No identity\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(split_by_uid(feed).is_empty());
    }

    #[test]
    fn garbage_yields_nothing_rather_than_a_panic() {
        assert!(split_by_uid("").is_empty());
        assert!(split_by_uid("not a calendar at all").is_empty());
    }

    #[test]
    fn webcal_normalises_to_https() {
        assert_eq!(
            normalise_url("webcal://example.com/f.ics"),
            "https://example.com/f.ics"
        );
        assert_eq!(
            normalise_url("webcals://example.com/f.ics"),
            "https://example.com/f.ics"
        );
        assert_eq!(
            normalise_url("https://example.com/f.ics"),
            "https://example.com/f.ics"
        );
        // Explicit http is the escape hatch and is left alone.
        assert_eq!(
            normalise_url("http://old.example/f.ics"),
            "http://old.example/f.ics"
        );
    }

    #[test]
    fn a_subscription_is_a_marked_read_only_collection() {
        let dir = tempfile::tempdir().unwrap();
        let meta = subscribe(
            dir.path(),
            "Holidays",
            "webcal://example.com/holidays.ics",
            Rgb(1, 2, 3),
            None,
        )
        .unwrap();

        assert!(is_feed(&meta.path));
        let state = FeedState::load(&meta.path).expect("a sidecar");
        assert_eq!(state.url, "https://example.com/holidays.ics");
        assert!(state.due(1), "a fresh subscription must be due immediately");
    }

    #[test]
    fn due_respects_the_interval() {
        let mut state = FeedState {
            url: "https://x.example/f.ics".into(),
            etag: None,
            last_modified: None,
            last_checked_ms: 1_000_000,
            refresh_minutes: 60,
            files: BTreeMap::new(),
        };
        assert!(!state.due(1_000_000 + 59 * 60_000));
        assert!(state.due(1_000_000 + 60 * 60_000));
        state.refresh_minutes = 15;
        assert!(state.due(1_000_000 + 15 * 60_000));
    }
}

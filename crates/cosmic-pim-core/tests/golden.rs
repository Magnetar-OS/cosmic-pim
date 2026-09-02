// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The recurrence golden suite: expansion checked against independently
//! derived RFC 5545 expectations, on documents shaped like what real clients
//! write.
//!
//! Every expected instant in this file was worked out by hand from the RFC
//! and a calendar for the year in question — not by running the code and
//! pasting its output back in. That is the point of the suite: it fails when
//! the engine drifts from the RFC, not when it drifts from itself.

use chrono::{NaiveDate, NaiveDateTime, TimeZone, Timelike};
use chrono_tz::Tz;
use cosmic_pim_core::ical::parse_ics;
use cosmic_pim_core::model::{Occurrence, expand, expand_merged};

const ATHENS: Tz = chrono_tz::Europe::Athens;
const NEW_YORK: Tz = chrono_tz::America::New_York;

fn day(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

fn at(y: i32, m: u32, d: u32, h: u32, min: u32) -> NaiveDateTime {
    day(y, m, d).and_hms_opt(h, min, 0).unwrap()
}

fn utc(y: i32, m: u32, d: u32) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::from_utc_datetime(&chrono::Utc, &at(y, m, d, 0, 0))
}

/// Parses a single-master document and expands it over `[from, to)`.
fn expand_doc(
    text: &str,
    from: chrono::DateTime<chrono::Utc>,
    to: chrono::DateTime<chrono::Utc>,
    local: Tz,
) -> Vec<Occurrence> {
    let events = parse_ics(text, "golden", "golden.ics");
    assert_eq!(events.len(), 1, "fixture holds one component");
    let mut out = expand(&events[0], from, to, local);
    out.sort_by_key(Occurrence::sort_key);
    out
}

fn local_starts(occurrences: &[Occurrence]) -> Vec<NaiveDateTime> {
    occurrences.iter().map(|o| o.start).collect()
}

// --- DST -----------------------------------------------------------------

/// Europe/Athens leaves DST on 2026-10-25. A weekly 09:00 Friday meeting
/// stays at 09:00 on the wall clock — which means its UTC instant moves from
/// 06:00Z (EEST, +03) to 07:00Z (EET, +02).
#[test]
fn weekly_athens_keeps_wall_clock_across_dst_end() {
    let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//golden//EN\r\n\
BEGIN:VEVENT\r\n\
UID:athens-weekly@golden\r\n\
DTSTAMP:20261001T000000Z\r\n\
DTSTART;TZID=Europe/Athens:20261016T090000\r\n\
DTEND;TZID=Europe/Athens:20261016T100000\r\n\
RRULE:FREQ=WEEKLY\r\n\
SUMMARY:Weekly review\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    let got = expand_doc(doc, utc(2026, 10, 15), utc(2026, 11, 10), ATHENS);

    assert_eq!(
        local_starts(&got),
        vec![
            at(2026, 10, 16, 9, 0),
            at(2026, 10, 23, 9, 0),
            at(2026, 10, 30, 9, 0),
            at(2026, 11, 6, 9, 0),
        ],
        "wall clock must hold across the DST boundary"
    );

    let utc_hours: Vec<u32> = got
        .iter()
        .map(|o| o.recurrence_id.expect("series member").hour())
        .collect();
    assert_eq!(
        utc_hours,
        vec![6, 6, 7, 7],
        "the UTC instant, not the wall clock, absorbs the offset change"
    );
}

/// America/New_York enters DST on 2026-03-08 (02:00 → 03:00). A daily 09:00
/// event keeps 09:00 locally; UTC moves from 14:00Z (EST) to 13:00Z (EDT).
#[test]
fn daily_new_york_keeps_wall_clock_across_spring_forward() {
    let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//golden//EN\r\n\
BEGIN:VEVENT\r\n\
UID:ny-daily@golden\r\n\
DTSTAMP:20260301T000000Z\r\n\
DTSTART;TZID=America/New_York:20260306T090000\r\n\
DTEND;TZID=America/New_York:20260306T093000\r\n\
RRULE:FREQ=DAILY;COUNT=5\r\n\
SUMMARY:Daily standup\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    let got = expand_doc(doc, utc(2026, 3, 1), utc(2026, 3, 15), NEW_YORK);

    assert_eq!(
        local_starts(&got),
        (6..=10).map(|d| at(2026, 3, d, 9, 0)).collect::<Vec<_>>(),
    );
    let utc_hours: Vec<u32> = got
        .iter()
        .map(|o| o.recurrence_id.expect("series member").hour())
        .collect();
    assert_eq!(utc_hours, vec![14, 14, 13, 13, 13]);
}

// --- End conditions ------------------------------------------------------

/// `COUNT=5` and an inclusive `UNTIL` on the fifth instance bound the same
/// series identically.
#[test]
fn count_and_until_bound_the_same_set() {
    let template = |end: &str| {
        format!(
            "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//golden//EN\r\n\
BEGIN:VEVENT\r\n\
UID:bounds@golden\r\n\
DTSTAMP:20260801T000000Z\r\n\
DTSTART:20260803T090000Z\r\n\
DTEND:20260803T100000Z\r\n\
RRULE:FREQ=DAILY;{end}\r\n\
SUMMARY:Bounded\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n"
        )
    };

    let counted = expand_doc(
        &template("COUNT=5"),
        utc(2026, 8, 1),
        utc(2026, 9, 1),
        chrono_tz::UTC,
    );
    let untiled = expand_doc(
        &template("UNTIL=20260807T090000Z"),
        utc(2026, 8, 1),
        utc(2026, 9, 1),
        chrono_tz::UTC,
    );

    assert_eq!(local_starts(&counted), local_starts(&untiled));
    assert_eq!(
        local_starts(&counted),
        (3..=7).map(|d| at(2026, 8, d, 9, 0)).collect::<Vec<_>>(),
    );
}

// --- Awkward monthly and yearly rules ------------------------------------

/// A monthly event on the 31st occurs only in 31-day months; RFC 5545 skips
/// invalid dates rather than sliding them.
#[test]
fn monthly_on_the_31st_skips_short_months() {
    let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//golden//EN\r\n\
BEGIN:VEVENT\r\n\
UID:monthly-31@golden\r\n\
DTSTAMP:20260101T000000Z\r\n\
DTSTART:20260131T120000Z\r\n\
DTEND:20260131T130000Z\r\n\
RRULE:FREQ=MONTHLY\r\n\
SUMMARY:Month end\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    let got = expand_doc(doc, utc(2026, 1, 1), utc(2027, 1, 1), chrono_tz::UTC);
    let dates: Vec<NaiveDate> = got.iter().map(|o| o.start.date()).collect();

    assert_eq!(
        dates,
        [1u32, 3, 5, 7, 8, 10, 12]
            .into_iter()
            .map(|m| day(2026, m, 31))
            .collect::<Vec<_>>(),
        "only the seven 31-day months of 2026"
    );
}

/// `BYDAY=MO..FR;BYSETPOS=-1`: the last weekday of each month. Hand-checked
/// against a 2026 calendar — October's 31st is a Saturday, so October's hit
/// is Friday the 30th.
#[test]
fn last_weekday_of_month_via_bysetpos() {
    let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//golden//EN\r\n\
BEGIN:VEVENT\r\n\
UID:bysetpos@golden\r\n\
DTSTAMP:20260801T000000Z\r\n\
DTSTART:20260831T170000Z\r\n\
DTEND:20260831T173000Z\r\n\
RRULE:FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-1\r\n\
SUMMARY:Month close\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    let got = expand_doc(doc, utc(2026, 8, 1), utc(2027, 1, 1), chrono_tz::UTC);
    let dates: Vec<NaiveDate> = got.iter().map(|o| o.start.date()).collect();

    assert_eq!(
        dates,
        vec![
            day(2026, 8, 31),  // Monday
            day(2026, 9, 30),  // Wednesday
            day(2026, 10, 30), // Friday — the 31st is a Saturday
            day(2026, 11, 30), // Monday
            day(2026, 12, 31), // Thursday
        ]
    );
}

/// A yearly event anchored on 29 February occurs only in leap years.
#[test]
fn yearly_leap_day_occurs_only_in_leap_years() {
    let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//golden//EN\r\n\
BEGIN:VEVENT\r\n\
UID:leap@golden\r\n\
DTSTAMP:20240101T000000Z\r\n\
DTSTART;VALUE=DATE:20240229\r\n\
DTEND;VALUE=DATE:20240301\r\n\
RRULE:FREQ=YEARLY\r\n\
SUMMARY:Leap day\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    let got = expand_doc(doc, utc(2024, 1, 1), utc(2034, 1, 1), chrono_tz::UTC);
    let dates: Vec<NaiveDate> = got.iter().map(|o| o.start.date()).collect();

    assert_eq!(
        dates,
        vec![day(2024, 2, 29), day(2028, 2, 29), day(2032, 2, 29)]
    );
}

/// `INTERVAL=2` holds its phase: every *other* Tuesday, anchored by DTSTART.
#[test]
fn biweekly_holds_its_phase() {
    let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//golden//EN\r\n\
BEGIN:VEVENT\r\n\
UID:biweekly@golden\r\n\
DTSTAMP:20260801T000000Z\r\n\
DTSTART:20260804T090000Z\r\n\
DTEND:20260804T100000Z\r\n\
RRULE:FREQ=WEEKLY;INTERVAL=2\r\n\
SUMMARY:Sprint planning\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    let got = expand_doc(doc, utc(2026, 8, 1), utc(2026, 10, 1), chrono_tz::UTC);
    let dates: Vec<NaiveDate> = got.iter().map(|o| o.start.date()).collect();

    assert_eq!(
        dates,
        vec![
            day(2026, 8, 4),
            day(2026, 8, 18),
            day(2026, 9, 1),
            day(2026, 9, 15),
            day(2026, 9, 29),
        ]
    );
}

// --- EXDATE and RECURRENCE-ID on a foreign-written document ---------------

/// A Thunderbird-shaped document: weekly master with one excluded instance
/// and one rescheduled instance (an override component). The merged expansion
/// must show the exclusion as absent, the override at its new time, and the
/// remaining instances untouched.
#[test]
fn exdate_and_override_merge_on_a_foreign_document() {
    let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Mozilla.org/NONSGML Mozilla Calendar V1.1//EN\r\n\
BEGIN:VEVENT\r\n\
UID:foreign-series@golden\r\n\
DTSTAMP:20260801T000000Z\r\n\
DTSTART;TZID=Europe/Athens:20260804T090000\r\n\
DTEND;TZID=Europe/Athens:20260804T100000\r\n\
RRULE:FREQ=WEEKLY;COUNT=4\r\n\
EXDATE;TZID=Europe/Athens:20260811T090000\r\n\
SUMMARY:Standup\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
UID:foreign-series@golden\r\n\
DTSTAMP:20260810T000000Z\r\n\
RECURRENCE-ID;TZID=Europe/Athens:20260818T090000\r\n\
DTSTART;TZID=Europe/Athens:20260818T140000\r\n\
DTEND;TZID=Europe/Athens:20260818T150000\r\n\
SUMMARY:Standup (moved)\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    let events = parse_ics(doc, "golden", "golden.ics");
    assert_eq!(events.len(), 2, "master and override");

    let mut got = expand_merged(&events, utc(2026, 8, 1), utc(2026, 9, 1), ATHENS);
    got.sort_by_key(Occurrence::sort_key);

    // COUNT=4 generates 4, 11, 18, 25 Aug; the 11th is excluded; the 18th is
    // replaced by its 14:00 override.
    assert_eq!(
        local_starts(&got),
        vec![
            at(2026, 8, 4, 9, 0),
            at(2026, 8, 18, 14, 0),
            at(2026, 8, 25, 9, 0),
        ]
    );
    assert_eq!(got[1].summary, "Standup (moved)");
}

/// EXDATE spelled the way Google Calendar spells it — several values on one
/// line — still removes every named instance.
#[test]
fn comma_separated_exdates_all_apply() {
    let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Google Inc//Google Calendar 70.9054//EN\r\n\
BEGIN:VEVENT\r\n\
UID:google-exdates@golden\r\n\
DTSTAMP:20260801T000000Z\r\n\
DTSTART:20260803T090000Z\r\n\
DTEND:20260803T093000Z\r\n\
RRULE:FREQ=DAILY;COUNT=7\r\n\
EXDATE:20260804T090000Z,20260806T090000Z\r\n\
SUMMARY:Daily\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    let got = expand_doc(doc, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC);
    let dates: Vec<NaiveDate> = got.iter().map(|o| o.start.date()).collect();

    assert_eq!(
        dates,
        vec![
            day(2026, 8, 3),
            day(2026, 8, 5),
            day(2026, 8, 7),
            day(2026, 8, 8),
            day(2026, 8, 9),
        ]
    );
}

/// A folded long line (RFC 5545 §3.1: CRLF + space) unfolds before parsing —
/// the summary comes back whole.
#[test]
fn folded_lines_unfold_before_parsing() {
    let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//golden//EN\r\n\
BEGIN:VEVENT\r\n\
UID:folded@golden\r\n\
DTSTAMP:20260801T000000Z\r\n\
DTSTART:20260804T090000Z\r\n\
DTEND:20260804T100000Z\r\n\
SUMMARY:A deliberately long summary that a conforming writer \r\n\x20would fold across content lines\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    let events = parse_ics(doc, "golden", "golden.ics");
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].summary,
        "A deliberately long summary that a conforming writer would fold across content lines"
    );
}

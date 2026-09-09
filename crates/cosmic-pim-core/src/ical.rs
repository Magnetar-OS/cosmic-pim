// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The date-time precedence rules, the TZID hardening, and the escaping and
// line-folding helpers in this module are derived from `src-tauri/src/caldav.rs`
// in the Meltemi project (https://github.com/entro314-labs/meltemi). See NOTICE
// and LICENSING.md.

//! The suite's single iCalendar layer: text in, [`Event`] out, and back.
//!
//! # Why calcard and not the `icalendar` crate
//!
//! This module replaced an `icalendar`-based implementation. The reason is not
//! that one crate is nicer than the other — it is that the CalDAV sync engine
//! and the local vdir reader must interpret the *same file* identically, and
//! two parsers do not. Concretely, the old path resolved a zone with a
//! byte-exact `tzid.parse::<chrono_tz::Tz>()`, so a server emitting
//! `TZID=Europe/Athens ` (trailing space, which real servers do) or
//! `TZID=Romance Standard Time` (a Windows alias, which Exchange does) fell
//! through to *floating* and silently shifted the event by the local offset.
//! calcard trims, folds Windows aliases, and honours an inline VTIMEZONE.
//!
//! calcard also parses vCard, which is what makes a contacts app a new module
//! here rather than a new dependency and a second set of these bugs.
//!
//! # What is preserved rather than normalised
//!
//! [`EventTime`] keeps the *form* the source file used — date, floating, or
//! zoned — instead of flattening everything to an instant. That is deliberate:
//! saving an event back must not rewrite the zone another tool chose for it,
//! and an all-day event normalised through UTC lands on the wrong calendar day
//! for every user west of Greenwich.

use std::collections::BTreeMap;

use crate::model::{Attendee, Event, EventTime, Todo, TodoStatus};
use calcard::Parser;
use calcard::icalendar::{
    ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarParameterName,
    ICalendarProperty, ICalendarValue, timezone::TzResolver,
};
use chrono::{NaiveDate, NaiveDateTime, Utc};
use chrono_tz::Tz;

/* ------------------------------------------------------------------ */
/* Parsing                                                            */

/// Parses the `VEVENT`s out of one iCalendar document.
///
/// Never fails: a document that does not parse, or parses to no VEVENT (a
/// VTIMEZONE-only wrapper is a real thing servers send), yields an empty vec.
/// A single corrupt file must not be able to empty a user's calendar.
#[must_use]
pub fn parse_ics(text: &str, calendar_id: &str, file_name: &str) -> Vec<Event> {
    let mut parser = Parser::new(text);
    let mut out = Vec::new();
    // Read straight off the source, because what these keep is the exact
    // spelling — which calcard's parsed component no longer has.
    let mut extras = vevent_extras(text).into_iter();

    loop {
        match parser.entry() {
            calcard::Entry::ICalendar(ical) => {
                let resolver = ical.build_tz_resolver();
                for component in &ical.components {
                    if component.component_type != ICalendarComponentType::VEvent {
                        continue;
                    }
                    // Taken for every VEVENT, converted or not, so the two
                    // walks cannot drift out of step.
                    let extra = extras.next();
                    if let Some(mut event) =
                        convert_event(component, &ical, &resolver, calendar_id, file_name)
                    {
                        if let Some((attendees, organizer, other)) = extra {
                            event.attendees = attendees;
                            event.organizer = organizer;
                            event.other = other;
                        }
                        out.push(event);
                    }
                }
            }
            calcard::Entry::Eof => break,
            calcard::Entry::InvalidLine(line) => {
                // Debug rather than warn: Outlook and Zimbra bridges emit
                // malformed X-properties on otherwise perfectly healthy feeds,
                // and warning on those trains users to ignore the log.
                tracing::debug!(file_name, line, "calcard dropped an invalid iCalendar line");
            }
            other => {
                tracing::debug!(file_name, ?other, "unhandled calcard entry");
            }
        }
    }
    out
}

fn convert_event(
    component: &ICalendarComponent,
    ical: &calcard::icalendar::ICalendar,
    resolver: &TzResolver<&str>,
    calendar_id: &str,
    file_name: &str,
) -> Option<Event> {
    // An event with no usable DTSTART cannot be placed on a grid, so it is not
    // something this app can show.
    let (start_entry, start_is_date) = pick_datetime_entry(component, &ICalendarProperty::Dtstart)?;
    let start = to_event_time(start_entry, start_is_date, resolver)?;

    let end = pick_datetime_entry(component, &ICalendarProperty::Dtend)
        .and_then(|(entry, is_date)| to_event_time(entry, is_date, resolver))
        .or_else(|| end_from_duration(component, start))
        .unwrap_or_else(|| default_end(start));

    let uid = component
        .uid()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{}@cosmic-pim", uuid::Uuid::new_v4()));

    // Same conversion as DTSTART: RFC 5545 requires RECURRENCE-ID's value type
    // to match the master's DTSTART, so the same date/floating/zoned reading
    // applies. Present only on override components.
    let recurrence_id = pick_datetime_entry(component, &ICalendarProperty::RecurrenceId)
        .and_then(|(entry, is_date)| to_event_time(entry, is_date, resolver));

    Some(Event {
        uid,
        calendar_id: calendar_id.to_owned(),
        summary: text_property(component, &ICalendarProperty::Summary).unwrap_or_default(),
        description: text_property(component, &ICalendarProperty::Description),
        location: text_property(component, &ICalendarProperty::Location),
        start,
        end,
        rrule: rrule_text(component),
        exdates: extract_exdates(component),
        alarms: extract_alarms(component, ical),
        sequence: integer_property(component, &ICalendarProperty::Sequence).unwrap_or(0) as i32,
        created: utc_property(component, &ICalendarProperty::Created),
        last_modified: utc_property(component, &ICalendarProperty::LastModified),
        file_name: file_name.to_owned(),
        recurrence_id,
        // Filled by `parse_ics`, which has the source text these are read
        // from verbatim; calcard's parsed component has already lost the
        // spelling they need to keep.
        attendees: Vec::new(),
        organizer: None,
        other: Vec::new(),
    })
}

/// Splits one `ATTENDEE`/`ORGANIZER` content line into the fields scheduling
/// needs, keeping the line itself so nothing unmodelled is lost.
///
/// `line` is unfolded and carries no terminator, e.g.
/// `ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@example.com`.
#[must_use]
pub fn parse_attendee_line(line: &str) -> Option<Attendee> {
    let colon = crate::patch::find_unquoted_colon(line)?;
    let (head, value) = line.split_at(colon);
    let email = crate::model::normalise_address(&value[1..]);
    if email.is_empty() {
        return None;
    }

    let mut name = None;
    let mut partstat = None;
    for param in head.split(';').skip(1) {
        let Some((key, raw)) = param.split_once('=') else {
            continue;
        };
        // A quoted CN may contain anything, including a semicolon — but
        // splitting on ';' has already cut it. Quotes are stripped; a name
        // that was split is still better than none, and the raw line below
        // is what gets written back regardless.
        let raw = raw.trim().trim_matches('"');
        match key.trim().to_ascii_uppercase().as_str() {
            "CN" => name = (!raw.is_empty()).then(|| raw.to_owned()),
            "PARTSTAT" => partstat = (!raw.is_empty()).then(|| raw.to_owned()),
            _ => {}
        }
    }

    Some(Attendee {
        email,
        name,
        partstat,
        raw: Some(line.to_owned()),
    })
}

/// One `ATTENDEE`/`ORGANIZER` line: the original if there was one, otherwise
/// built from the fields.
#[must_use]
pub fn attendee_line(attendee: &Attendee, property: &str) -> String {
    if let Some(raw) = &attendee.raw {
        return raw.clone();
    }
    let mut line = String::from(property);
    if let Some(name) = attendee.name.as_deref().filter(|n| !n.trim().is_empty()) {
        // Quoted, because a display name routinely contains a comma or a
        // colon and either would end the parameter early.
        line.push_str(&format!(";CN=\"{}\"", name.replace('"', "")));
    }
    if let Some(partstat) = &attendee.partstat {
        line.push_str(&format!(";PARTSTAT={partstat}"));
    }
    line.push_str(&format!(":mailto:{}", attendee.email));
    line
}

/// Property names `write_vevent` emits itself. Everything else in a VEVENT is
/// captured verbatim into [`Event::other`] so it survives a round trip.
const MODELLED: &[&str] = &[
    "UID",
    "DTSTAMP",
    "DTSTART",
    "DTEND",
    // Converted into DTEND on the way in; re-emitting it too would give the
    // component two conflicting ends.
    "DURATION",
    "RECURRENCE-ID",
    "SUMMARY",
    "DESCRIPTION",
    "LOCATION",
    "RRULE",
    "EXDATE",
    "SEQUENCE",
    "CREATED",
    "LAST-MODIFIED",
    "ATTENDEE",
    "ORGANIZER",
];

/// What each VEVENT in `text` carries that the model does not interpret:
/// its attendees, its organizer, and every other content line, in document
/// order, one entry per VEVENT.
///
/// Nested components are skipped entirely — `VALARM` is modelled separately
/// and written back from [`Event::alarms`], so collecting its lines here
/// would emit every alarm twice.
fn vevent_extras(text: &str) -> Vec<(Vec<Attendee>, Option<Attendee>, Vec<String>)> {
    let mut out = Vec::new();
    let mut current: Option<(Vec<Attendee>, Option<Attendee>, Vec<String>)> = None;
    let mut nested = 0usize;

    for line in crate::patch::logical_lines(text) {
        if let Some(component) = line.begins() {
            if current.is_some() {
                nested += 1;
            } else if component.eq_ignore_ascii_case("VEVENT") {
                current = Some((Vec::new(), None, Vec::new()));
            }
            continue;
        }
        if let Some(component) = line.ends() {
            if nested > 0 {
                nested -= 1;
            } else if component.eq_ignore_ascii_case("VEVENT")
                && let Some(done) = current.take()
            {
                out.push(done);
            }
            continue;
        }

        // Inside a VALARM, not the event itself.
        if nested > 0 {
            continue;
        }
        let Some((attendees, organizer, other)) = current.as_mut() else {
            continue;
        };

        let unfolded = line.unfolded().to_owned();
        let name = line.name().to_ascii_uppercase();
        match name.as_str() {
            "ATTENDEE" => {
                if let Some(attendee) = parse_attendee_line(&unfolded) {
                    attendees.push(attendee);
                }
            }
            "ORGANIZER" => {
                if organizer.is_none() {
                    *organizer = parse_attendee_line(&unfolded);
                }
            }
            _ if !MODELLED.contains(&name.as_str()) => other.push(unfolded),
            _ => {}
        }
    }

    out
}

/// RFC 5545: a `DATE`-valued event with no `DTEND` lasts one day; a `DATE-TIME`
/// one is zero-length. We give timed events an hour so they stay clickable.
fn default_end(start: EventTime) -> EventTime {
    match start {
        EventTime::Date(d) => EventTime::Date(d + chrono::Duration::days(1)),
        EventTime::Floating(dt) => EventTime::Floating(dt + chrono::Duration::hours(1)),
        EventTime::Zoned(dt, tz) => EventTime::Zoned(dt + chrono::Duration::hours(1), tz),
    }
}

/// `DTEND` may legally be replaced by `DURATION` (RFC 5545 §3.6.1). Ignoring
/// that is how an event imported from a Google feed ends up an hour long
/// regardless of what it actually is.
fn end_from_duration(component: &ICalendarComponent, start: EventTime) -> Option<EventTime> {
    let seconds = component
        .property(&ICalendarProperty::Duration)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::Duration(d) => Some(d.as_seconds()),
            _ => None,
        })?;
    let delta = chrono::Duration::seconds(seconds);

    Some(match start {
        EventTime::Date(d) => EventTime::Date(d + delta),
        EventTime::Floating(dt) => EventTime::Floating(dt + delta),
        EventTime::Zoned(dt, tz) => EventTime::Zoned(dt + delta, tz),
    })
}

/// Ranks `DTSTART`/`DTEND` candidates when a VEVENT carries more than one.
///
/// That is an RFC 5545 §3.6.1 violation, but older Outlook bridges do it: they
/// pair a `TZID`'d source-of-truth value with a floating "compatibility"
/// duplicate, and the order they arrive in is not stable across emitters.
/// Picking the first one means the same event lands at two different times
/// depending on which server relayed it.
///
/// Preference: `VALUE=DATE` > explicit `TZID` > UTC offset > floating.
fn score_datetime_candidate(entry: &ICalendarEntry) -> u8 {
    if is_date_valued(entry) {
        return 4;
    }
    if entry.tz_id().is_some_and(|s| !s.trim().is_empty()) {
        return 3;
    }
    let has_offset = matches!(
        entry.values.first(),
        Some(ICalendarValue::PartialDateTime(dt)) if dt.tz_hour.is_some()
    );
    if has_offset { 2 } else { 1 }
}

fn is_date_valued(entry: &ICalendarEntry) -> bool {
    entry
        .parameter(&ICalendarParameterName::Value)
        .and_then(calcard::icalendar::ICalendarParameterValue::as_text)
        .is_some_and(|t| t.eq_ignore_ascii_case("DATE"))
}

/// Returns `(best entry, is VALUE=DATE)`. Ties keep calcard's order, which is
/// the conservative "first wins" behaviour for well-formed input.
fn pick_datetime_entry<'c, 'p: 'c>(
    component: &'c ICalendarComponent,
    prop: &'p ICalendarProperty,
) -> Option<(&'c ICalendarEntry, bool)> {
    let mut iter = component.properties(prop);
    let first = iter.next()?;
    let mut best = first;
    let mut best_score = score_datetime_candidate(best);
    let mut count = 1;

    for entry in iter {
        count += 1;
        let score = score_datetime_candidate(entry);
        if score > best_score {
            best = entry;
            best_score = score;
        }
    }

    if count > 1 {
        tracing::warn!(
            ?prop,
            count,
            "VEVENT carries several entries for one date-time property (RFC 5545 violation); \
             selected by precedence VALUE=DATE > TZID > UTC > floating"
        );
    }

    Some((best, best_score == 4))
}

/// One `DTSTART`/`DTEND` entry to an [`EventTime`].
///
/// The precedence chain below is not theoretical — each branch exists because a
/// real server got it wrong:
///
/// 1. `VALUE=DATE` → [`EventTime::Date`]. Never resolved through a zone; an
///    all-day event has no instant, and giving it one moves it a day.
/// 2. Explicit `TZID`, **trimmed** before lookup. Servers emit trailing spaces,
///    which a byte-exact match rejects, silently degrading the value to
///    floating and shifting the event. A `TZID` that will not resolve at all
///    falls back to UTC rather than to local: UTC is wrong consistently on
///    every machine, whereas local is wrong differently on each one, which is
///    far harder to notice and to support.
/// 3. An embedded offset (`Z` or `+HH:MM`) → UTC. If a `TZID` *and* an offset
///    are both present (another Outlook special) the offset wins.
/// 4. Otherwise floating, per RFC 5545 §3.3.5.
fn to_event_time(
    entry: &ICalendarEntry,
    is_date_only: bool,
    resolver: &TzResolver<&str>,
) -> Option<EventTime> {
    let ICalendarValue::PartialDateTime(dt) = entry.values.first()? else {
        return None;
    };

    if is_date_only {
        return partial_to_date(dt).map(EventTime::Date);
    }

    let naive = partial_to_naive(dt);

    if let Some(tz_id_raw) = entry.tz_id()
        && dt.tz_hour.is_none()
    {
        let tz_id = tz_id_raw.trim();
        if !tz_id.is_empty() {
            let naive = naive?;
            let resolved = resolver.resolve_or_default(Some(tz_id));
            if !resolved.is_floating()
                && let Some(tz) = resolved.name().and_then(|name| name.parse::<Tz>().ok())
            {
                return Some(EventTime::Zoned(naive, tz));
            }
            tracing::warn!(tz_id = tz_id_raw, "TZID did not resolve; treating as UTC");
            return Some(EventTime::Zoned(naive, chrono_tz::UTC));
        }
    }

    if dt.tz_hour.is_some() {
        // Go through the timestamp so a non-zero offset (`+0300`) is converted
        // rather than being stored as if it were already UTC.
        let seconds = dt.to_timestamp()?;
        let utc = chrono::DateTime::from_timestamp(seconds, 0)?;
        return Some(EventTime::Zoned(utc.naive_utc(), chrono_tz::UTC));
    }

    naive.map(EventTime::Floating)
}

fn partial_to_date(dt: &calcard::common::PartialDateTime) -> Option<NaiveDate> {
    NaiveDate::from_ymd_opt(
        i32::from(dt.year?),
        u32::from(dt.month?),
        u32::from(dt.day?),
    )
}

fn partial_to_naive(dt: &calcard::common::PartialDateTime) -> Option<NaiveDateTime> {
    partial_to_date(dt)?.and_hms_opt(
        u32::from(dt.hour.unwrap_or(0)),
        u32::from(dt.minute.unwrap_or(0)),
        u32::from(dt.second.unwrap_or(0)),
    )
}

fn text_property(component: &ICalendarComponent, prop: &ICalendarProperty) -> Option<String> {
    component
        .property(prop)
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_text)
        .map(ToOwned::to_owned)
        .filter(|s| !s.is_empty())
}

fn integer_property(component: &ICalendarComponent, prop: &ICalendarProperty) -> Option<i64> {
    component
        .property(prop)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::Integer(n) => Some(*n),
            ICalendarValue::Text(t) => t.trim().parse().ok(),
            _ => None,
        })
}

fn utc_property(
    component: &ICalendarComponent,
    prop: &ICalendarProperty,
) -> Option<chrono::DateTime<Utc>> {
    component
        .property(prop)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::PartialDateTime(dt) => dt.to_timestamp(),
            _ => None,
        })
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
}

/// `RRULE` is kept as text because that is what [`crate::model::recur`] feeds
/// to the `rrule` crate. calcard parses it into a struct, whose `Display` is
/// the canonical serialisation, so a round trip through here normalises the
/// property rather than corrupting it.
fn rrule_text(component: &ICalendarComponent) -> Option<String> {
    component
        .property(&ICalendarProperty::Rrule)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::RecurrenceRule(rule) => Some(rule.to_string()),
            ICalendarValue::Text(t) => Some(t.clone()),
            _ => None,
        })
        .filter(|s| !s.trim().is_empty())
}

/// `EXDATE` may appear several times, and each may carry a comma-separated
/// list — calcard surfaces that as several values on one entry.
fn extract_exdates(component: &ICalendarComponent) -> Vec<NaiveDateTime> {
    let mut out = Vec::new();

    for entry in component.properties(&ICalendarProperty::Exdate) {
        let date_only = is_date_valued(entry);
        for value in &entry.values {
            let ICalendarValue::PartialDateTime(dt) = value else {
                continue;
            };
            let parsed = if date_only {
                partial_to_date(dt).map(|d| d.and_time(chrono::NaiveTime::MIN))
            } else {
                partial_to_naive(dt)
            };
            if let Some(naive) = parsed {
                out.push(naive);
            }
        }
    }

    out.sort_unstable();
    out.dedup();
    out
}

/// Reads `VALARM` triggers as offsets from the event's start.
///
/// Only duration triggers are understood. An absolute
/// `TRIGGER;VALUE=DATE-TIME` names one wall-clock instant, which is meaningless
/// the moment the event recurs, and one anchored to the event's end would need
/// the duration to resolve. Both are skipped rather than guessed at: a reminder
/// that fires at the wrong time is worse than one that does not fire.
///
/// VALARMs are siblings in calcard's flat component list, reached through the
/// parent's `component_ids` rather than by nesting.
fn extract_alarms(
    component: &ICalendarComponent,
    ical: &calcard::icalendar::ICalendar,
) -> Vec<chrono::Duration> {
    let mut out = Vec::new();

    for id in &component.component_ids {
        let Some(alarm) = ical.component_by_id(*id) else {
            continue;
        };
        if alarm.component_type != ICalendarComponentType::VAlarm {
            continue;
        }

        let Some(entry) = alarm.property(&ICalendarProperty::Trigger) else {
            continue;
        };

        // RELATED=END would need the event's duration to resolve.
        let related_to_end = entry
            .parameter(&ICalendarParameterName::Related)
            .and_then(calcard::icalendar::ICalendarParameterValue::as_text)
            .is_some_and(|v| v.eq_ignore_ascii_case("END"));
        if related_to_end {
            continue;
        }

        if let Some(ICalendarValue::Duration(d)) = entry.values.first() {
            out.push(chrono::Duration::seconds(d.as_seconds()));
        }
    }

    out.sort();
    out.dedup();
    out
}

/* ------------------------------------------------------------------ */
/* Tasks (VTODO)                                                      */

/// Parses the `VTODO`s out of one iCalendar document.
///
/// Shares every date-time rule with [`parse_ics`] — the TZID trimming, the
/// candidate ranking, the offset conversion — because a `DUE` and a `DTSTART`
/// are the same kind of value and a task read differently from an event in the
/// same file would be its own bug class.
#[must_use]
pub fn parse_todos(text: &str, calendar_id: &str, file_name: &str) -> Vec<Todo> {
    let mut parser = Parser::new(text);
    let mut out = Vec::new();

    loop {
        match parser.entry() {
            calcard::Entry::ICalendar(ical) => {
                let resolver = ical.build_tz_resolver();
                for component in &ical.components {
                    if component.component_type == ICalendarComponentType::VTodo {
                        out.push(convert_todo(
                            component,
                            &ical,
                            &resolver,
                            calendar_id,
                            file_name,
                        ));
                    }
                }
            }
            calcard::Entry::Eof => break,
            calcard::Entry::InvalidLine(line) => {
                tracing::debug!(file_name, line, "calcard dropped an invalid iCalendar line");
            }
            _ => {}
        }
    }
    out
}

fn convert_todo(
    component: &ICalendarComponent,
    ical: &calcard::icalendar::ICalendar,
    resolver: &TzResolver<&str>,
    calendar_id: &str,
    file_name: &str,
) -> Todo {
    // Unlike an event, a task with no date at all is completely ordinary, so
    // there is nothing here that can make the component unusable.
    let due = pick_datetime_entry(component, &ICalendarProperty::Due)
        .and_then(|(entry, is_date)| to_event_time(entry, is_date, resolver));
    let start = pick_datetime_entry(component, &ICalendarProperty::Dtstart)
        .and_then(|(entry, is_date)| to_event_time(entry, is_date, resolver));

    let status = text_property(component, &ICalendarProperty::Status)
        .as_deref()
        .and_then(TodoStatus::parse)
        .unwrap_or_default();

    let percent = integer_property(component, &ICalendarProperty::PercentComplete)
        .unwrap_or(0)
        .clamp(0, 100) as u8;

    Todo {
        uid: component
            .uid()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("{}@cosmic-pim", uuid::Uuid::new_v4())),
        calendar_id: calendar_id.to_owned(),
        summary: text_property(component, &ICalendarProperty::Summary).unwrap_or_default(),
        description: text_property(component, &ICalendarProperty::Description),
        due,
        start,
        status,
        // RFC 5545 §3.8.1.9 bounds PRIORITY at 0–9; anything else is a client
        // bug and clamping keeps it from poisoning the sort.
        priority: integer_property(component, &ICalendarProperty::Priority)
            .unwrap_or(0)
            .clamp(0, 9) as u8,
        percent_complete: percent,
        completed: utc_property(component, &ICalendarProperty::Completed),
        rrule: rrule_text(component),
        alarms: extract_alarms(component, ical),
        related_to: text_property(component, &ICalendarProperty::RelatedTo),
        categories: categories(component),
        sequence: integer_property(component, &ICalendarProperty::Sequence).unwrap_or(0) as i32,
        created: utc_property(component, &ICalendarProperty::Created),
        last_modified: utc_property(component, &ICalendarProperty::LastModified),
        file_name: file_name.to_owned(),
    }
}

/// `CATEGORIES` is a comma-separated list and may appear more than once.
fn categories(component: &ICalendarComponent) -> Vec<String> {
    let mut out = Vec::new();
    for entry in component.properties(&ICalendarProperty::Categories) {
        for value in &entry.values {
            if let Some(text) = value.as_text() {
                out.extend(
                    text.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned),
                );
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Serialises one task as a complete single-VTODO iCalendar document.
#[must_use]
pub fn todo_to_ics(todo: &Todo) -> String {
    let mut out = String::new();
    fold_line("BEGIN:VCALENDAR", &mut out);
    fold_line("VERSION:2.0", &mut out);
    fold_line("PRODID:-//COSMIC//Calendar//EN", &mut out);
    write_vtodo(todo, &mut out);
    fold_line("END:VCALENDAR", &mut out);
    out
}

fn write_vtodo(todo: &Todo, out: &mut String) {
    fold_line("BEGIN:VTODO", out);
    fold_line(&format!("UID:{}", escape_text(&todo.uid)), out);
    fold_line(
        &format!("DTSTAMP:{}", Utc::now().format("%Y%m%dT%H%M%SZ")),
        out,
    );
    fold_line(&format!("SUMMARY:{}", escape_text(&todo.summary)), out);
    fold_line(&format!("STATUS:{}", todo.status.as_ical()), out);

    if let Some(due) = todo.due {
        fold_line(&datetime_line("DUE", due), out);
    }
    if let Some(start) = todo.start {
        fold_line(&datetime_line("DTSTART", start), out);
    }
    if let Some(description) = &todo.description {
        fold_line(&format!("DESCRIPTION:{}", escape_text(description)), out);
    }
    if todo.priority > 0 {
        fold_line(&format!("PRIORITY:{}", todo.priority), out);
    }
    if todo.percent_complete > 0 {
        fold_line(&format!("PERCENT-COMPLETE:{}", todo.percent_complete), out);
    }
    if let Some(completed) = todo.completed {
        fold_line(
            &format!("COMPLETED:{}", completed.format("%Y%m%dT%H%M%SZ")),
            out,
        );
    }
    if let Some(rrule) = &todo.rrule {
        fold_line(&format!("RRULE:{}", rrule.trim()), out);
    }
    if let Some(parent) = &todo.related_to {
        fold_line(&format!("RELATED-TO:{}", escape_text(parent)), out);
    }
    if !todo.categories.is_empty() {
        let list = todo
            .categories
            .iter()
            .map(|c| escape_text(c))
            .collect::<Vec<_>>()
            .join(",");
        fold_line(&format!("CATEGORIES:{list}"), out);
    }
    if todo.sequence > 0 {
        fold_line(&format!("SEQUENCE:{}", todo.sequence), out);
    }
    if let Some(created) = todo.created {
        fold_line(
            &format!("CREATED:{}", created.format("%Y%m%dT%H%M%SZ")),
            out,
        );
    }
    fold_line(
        &format!(
            "LAST-MODIFIED:{}",
            todo.last_modified
                .unwrap_or_else(Utc::now)
                .format("%Y%m%dT%H%M%SZ")
        ),
        out,
    );

    for alarm in &todo.alarms {
        fold_line("BEGIN:VALARM", out);
        fold_line("ACTION:DISPLAY", out);
        fold_line(&format!("DESCRIPTION:{}", escape_text(&todo.summary)), out);
        fold_line(&format!("TRIGGER:{}", format_iso_duration(*alarm)), out);
        fold_line("END:VALARM", out);
    }

    fold_line("END:VTODO", out);
}

/* ------------------------------------------------------------------ */
/* Recurrence identity                                                */

/// The canonical `RECURRENCE-ID` of every VEVENT in a document, in document
/// order. `None` marks a series master.
///
/// The writeback patcher uses this to find *which* VEVENT in a multi-component
/// resource a local edit targets. A recurring event's overrides live in the
/// same `.ics` file as their master, so "patch the event" is meaningless
/// without a way to name one of them.
#[must_use]
pub fn recurrence_ids(text: &str) -> Vec<Option<String>> {
    let mut parser = Parser::new(text);
    let mut out = Vec::new();

    loop {
        match parser.entry() {
            calcard::Entry::ICalendar(ical) => {
                for component in &ical.components {
                    if component.component_type == ICalendarComponentType::VEvent {
                        out.push(recurrence_id_of(component));
                    }
                }
            }
            calcard::Entry::Eof => break,
            _ => {}
        }
    }
    out
}

fn recurrence_id_of(component: &ICalendarComponent) -> Option<String> {
    let (entry, is_date_only) = pick_datetime_entry(component, &ICalendarProperty::RecurrenceId)?;
    let ICalendarValue::PartialDateTime(dt) = entry.values.first()? else {
        return None;
    };
    canonical_datetime_key(entry, dt, is_date_only)
}

/// A wall-clock key naming one recurrence instance.
///
/// Deliberately a STRING rather than a resolved instant. Floating and all-day
/// forms resolved through the local zone produce host-dependent keys, so the
/// same override synced on a UTC machine and a New York machine would be named
/// two different things — and a master and its override would collide the
/// moment the user's timezone changed. Four forms, mirroring the
/// serialisations RFC 5545 permits:
///
/// - `YYYYMMDD` — `VALUE=DATE`
/// - `YYYYMMDDTHHMMSSZ` — UTC. Numeric offsets are *normalised* to `Z` so that
///   a `+0000` emitter and a `Z` emitter agree on the key.
/// - `YYYYMMDDTHHMMSS;TZID=<id>` — zoned
/// - `YYYYMMDDTHHMMSS` — floating
fn canonical_datetime_key(
    entry: &ICalendarEntry,
    dt: &calcard::common::PartialDateTime,
    is_date_only: bool,
) -> Option<String> {
    let year = i32::from(dt.year?);
    let month = u32::from(dt.month?);
    let day = u32::from(dt.day?);

    if is_date_only {
        return Some(format!("{year:04}{month:02}{day:02}"));
    }

    let hour = u32::from(dt.hour.unwrap_or(0));
    let minute = u32::from(dt.minute.unwrap_or(0));
    let second = u32::from(dt.second.unwrap_or(0));
    let body = format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}");

    if dt.tz_hour.is_some() {
        // An explicit offset beats TZID here, matching `to_event_time`, so that
        // a master and its override in a malformed feed still resolve the same
        // way as each other.
        if let Some(naive) = partial_to_naive(dt)
            && (dt.tz_hour != Some(0) || dt.tz_minute.unwrap_or(0) != 0 || dt.tz_minus)
        {
            let seconds = i32::from(dt.tz_hour.unwrap_or(0)) * 3600
                + i32::from(dt.tz_minute.unwrap_or(0)) * 60;
            let offset = if dt.tz_minus { -seconds } else { seconds };
            let utc = naive
                .checked_sub_signed(chrono::Duration::seconds(i64::from(offset)))
                .unwrap_or(naive);
            return Some(format!("{}Z", utc.format("%Y%m%dT%H%M%S")));
        }
        return Some(format!("{body}Z"));
    }

    if let Some(tz_id_raw) = entry.tz_id() {
        let tz_id = tz_id_raw.trim();
        if !tz_id.is_empty() {
            return Some(format!("{body};TZID={tz_id}"));
        }
    }

    Some(body)
}

/* ------------------------------------------------------------------ */
/* Serialisation                                                      */

/// RFC 5545 §3.3.11 TEXT escaping: backslash, semicolon, comma, newline.
///
/// Public because the CalDAV writeback patcher must escape identically; two
/// copies of this would be two places for it to drift.
#[must_use]
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// Folds a content line and terminates it with CRLF.
///
/// RFC 5545 §3.1 says lines SHOULD be ≤75 octets. We fold at 73 because some
/// servers hard-reject at the limit rather than at the limit plus slack, and
/// the margin costs nothing. Folding is at character boundaries — splitting a
/// multi-byte character across a fold produces a file no parser can read.
pub(crate) fn fold_line(line: &str, out: &mut String) {
    const LIMIT: usize = 73;
    let mut count = 0;
    for c in line.chars() {
        if count + c.len_utf8() > LIMIT {
            out.push_str("\r\n ");
            count = 1; // the continuation space counts toward the new line
        }
        out.push(c);
        count += c.len_utf8();
    }
    out.push_str("\r\n");
}

/// Rewrites one VEVENT of an existing document, leaving its siblings intact.
///
/// A recurring event's overrides live in the same file as their master, under
/// the same UID. Serialising a whole file from a single [`Event`] — what
/// [`to_ics`] does — would therefore silently delete every other component the
/// moment one of them is edited. This replaces the component whose
/// `RECURRENCE-ID` matches `event.recurrence_id` (byte-for-byte preserving the
/// rest of the document), or appends the event as a new component when no
/// match exists.
#[must_use]
pub fn upsert_vevent(text: &str, event: &Event) -> String {
    use crate::patch::{logical_lines, terminator_of};

    // Which component to replace: match on the parsed RECURRENCE-ID, in
    // document order — the same order the component walk below sees.
    let rids: Vec<Option<EventTime>> = parse_ics(text, &event.calendar_id, &event.file_name)
        .iter()
        .map(|e| e.recurrence_id)
        .collect();
    let target = rids.iter().position(|rid| *rid == event.recurrence_id);

    // The component already exists: patch it where it lies, so every byte the
    // model does not own survives untouched. Only the insert path below
    // serialises, because only it has nothing to preserve.
    if let Some(index) = target
        && let Some(patched) = patch_vevent(text, index, event)
    {
        return patched;
    }

    let terminator = terminator_of(text);
    let mut component = String::new();
    write_vevent(event, &mut component);
    let component = if terminator == "\n" {
        component.replace("\r\n", "\n")
    } else {
        component
    };

    // A component that is not in the document yet goes in before it closes.
    let lines = logical_lines(text);
    let mut out = String::with_capacity(text.len() + component.len());
    let mut inserted = false;
    for line in &lines {
        if !inserted && line.ends().as_deref() == Some("VCALENDAR") {
            out.push_str(&component);
            inserted = true;
        }
        out.push_str(line.raw());
    }
    if !inserted {
        out.push_str(&component);
    }
    out
}

/// Rewrites one VEVENT's modelled properties in place, leaving every other
/// byte of the document exactly as it was.
///
/// This is the difference between "the model can describe this event" and
/// "the model owns this event". [`write_vevent`] emits the properties the
/// model knows and, since `Event::other` was added, the content lines it does
/// not — but it still re-serialises, so it loses what lives *on* a modelled
/// property: `SUMMARY;LANGUAGE=en-us:Planning` came back as
/// `SUMMARY:Planning`, and the order and folding the source chose were
/// replaced by ours. Patching names only the properties the model actually
/// owns; the patcher passes everything else through byte-for-byte, which is
/// what the contacts side has always done (see `vcard::patch_*`).
///
/// Parameters on a rewritten property are carried across from the source
/// line, because the model owns those properties' *values* and nothing else.
/// The exception is the date-time properties, where `VALUE` and `TZID` encode
/// the value itself and are therefore regenerated — any other parameter on
/// them still survives.
///
/// `None` when the document has no such component, which sends the caller to
/// the insert path.
fn patch_vevent(text: &str, index: usize, event: &Event) -> Option<String> {
    use crate::patch::{Edit, patch_nth_component};

    let source = component_params(text, index);
    let keep = |property: &str, occurrence: usize, value: &str| -> String {
        let params = source
            .get(property)
            .and_then(|all| all.get(occurrence))
            .map_or("", String::as_str);
        format!("{property}{params}:{value}")
    };
    // A date-time's own parameters are the value's encoding, so they are
    // regenerated; anything else the source put there is not ours to drop.
    let datetime = |property: &str, time: EventTime| -> String {
        let generated = datetime_line(property, time);
        let foreign = source
            .get(property)
            .and_then(|all| all.first())
            .map_or_else(String::new, |params| {
                params_except(params, &["VALUE", "TZID"])
            });
        if foreign.is_empty() {
            return generated;
        }
        match crate::patch::find_unquoted_colon(&generated) {
            Some(colon) => format!("{}{foreign}{}", &generated[..colon], &generated[colon..]),
            None => generated,
        }
    };

    let mut edits = BTreeMap::new();
    let set = |edits: &mut BTreeMap<String, Edit>, property: &str, line: String| {
        edits.insert(property.to_owned(), Edit::set(vec![line]));
    };

    // UID is deliberately absent: it is the identity this component was
    // located by, so rewriting it could only ever be wrong.
    let dtstamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    set(&mut edits, "DTSTAMP", keep("DTSTAMP", 0, &dtstamp));
    set(&mut edits, "DTSTART", datetime("DTSTART", event.start));
    set(&mut edits, "DTEND", datetime("DTEND", event.end));
    set(
        &mut edits,
        "SUMMARY",
        keep("SUMMARY", 0, &escape_text(&event.summary)),
    );
    let last_modified = event
        .last_modified
        .unwrap_or_else(Utc::now)
        .format("%Y%m%dT%H%M%SZ")
        .to_string();
    set(
        &mut edits,
        "LAST-MODIFIED",
        keep("LAST-MODIFIED", 0, &last_modified),
    );

    // DURATION is read as DTEND on the way in, so a document carrying one
    // would otherwise end up with two conflicting ends.
    edits.insert("DURATION".to_owned(), Edit::remove());

    for (property, value) in [
        ("DESCRIPTION", event.description.as_deref()),
        ("LOCATION", event.location.as_deref()),
    ] {
        match value {
            Some(value) => set(&mut edits, property, keep(property, 0, &escape_text(value))),
            None => {
                edits.insert(property.to_owned(), Edit::remove());
            }
        }
    }

    match &event.rrule {
        // Structured, not TEXT — escaping would corrupt the semicolons that
        // separate its parts.
        Some(rrule) => set(&mut edits, "RRULE", keep("RRULE", 0, rrule.trim())),
        None => {
            edits.insert("RRULE".to_owned(), Edit::remove());
        }
    }

    if event.sequence > 0 {
        let sequence = event.sequence.to_string();
        set(&mut edits, "SEQUENCE", keep("SEQUENCE", 0, &sequence));
    } else {
        edits.insert("SEQUENCE".to_owned(), Edit::remove());
    }

    if let Some(created) = event.created {
        let created = created.format("%Y%m%dT%H%M%SZ").to_string();
        set(&mut edits, "CREATED", keep("CREATED", 0, &created));
    }

    if let Some(rid) = event.recurrence_id {
        set(&mut edits, "RECURRENCE-ID", datetime("RECURRENCE-ID", rid));
    }

    edits.insert(
        "EXDATE".to_owned(),
        Edit::set(
            event
                .exdates
                .iter()
                .map(|exdate| exdate_line(event, *exdate))
                .collect(),
        ),
    );

    // An attendee read from the document re-emits its own source line, so
    // DELEGATED-FROM, ROLE and every other parameter survive; only one this
    // app added is synthesised.
    edits.insert(
        "ATTENDEE".to_owned(),
        Edit::set(
            event
                .attendees
                .iter()
                .map(|attendee| attendee_line(attendee, "ATTENDEE"))
                .collect(),
        ),
    );
    edits.insert(
        "ORGANIZER".to_owned(),
        match &event.organizer {
            Some(organizer) => Edit::set(vec![attendee_line(organizer, "ORGANIZER")]),
            None => Edit::remove(),
        },
    );

    patch_nth_component(text, "VEVENT", index, &edits)
}

/// The parameter section of every property occurrence inside one VEVENT, in
/// document order — `";LANGUAGE=en-us"`, or `""` where there were none.
///
/// Nested components are skipped for the same reason [`vevent_extras`] skips
/// them: a VALARM's DESCRIPTION is not the event's.
fn component_params(text: &str, index: usize) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seen = 0usize;
    let mut inside = false;
    let mut nested = 0usize;

    for line in crate::patch::logical_lines(text) {
        if let Some(component) = line.begins() {
            if inside {
                nested += 1;
            } else if component.eq_ignore_ascii_case("VEVENT") {
                if seen == index {
                    inside = true;
                }
                seen += 1;
            }
            continue;
        }
        if line.ends().is_some() {
            if nested > 0 {
                nested -= 1;
            } else if inside {
                break;
            }
            continue;
        }
        if inside && nested == 0 {
            out.entry(line.name())
                .or_default()
                .push(line.params().to_owned());
        }
    }
    out
}

/// A parameter section with the named parameters removed, keeping the rest
/// exactly as they were written.
fn params_except(params: &str, generated: &[&str]) -> String {
    let mut out = String::new();
    let mut current = String::new();
    let mut quoted = false;

    let flush = |current: &mut String, out: &mut String| {
        if current.is_empty() {
            return;
        }
        let name = current
            .split('=')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_uppercase();
        if !generated.iter().any(|g| g.eq_ignore_ascii_case(&name)) {
            out.push(';');
            out.push_str(current);
        }
        current.clear();
    };

    for ch in params.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            ';' if !quoted => flush(&mut current, &mut out),
            _ => current.push(ch),
        }
    }
    flush(&mut current, &mut out);
    out
}

/// One EXDATE line, in the value type DTSTART uses.
///
/// EXDATE must match DTSTART's value type, or clients will not match it
/// against the expansion and the excluded instance reappears.
fn exdate_line(event: &Event, exdate: NaiveDateTime) -> String {
    if event.start.is_all_day() {
        return format!("EXDATE;VALUE=DATE:{}", exdate.format("%Y%m%d"));
    }
    match event.start {
        EventTime::Zoned(_, tz) if tz == chrono_tz::UTC => {
            format!("EXDATE:{}Z", exdate.format("%Y%m%dT%H%M%S"))
        }
        EventTime::Zoned(_, tz) => format!(
            "EXDATE;TZID={}:{}",
            tz.name(),
            exdate.format("%Y%m%dT%H%M%S")
        ),
        _ => format!("EXDATE:{}", exdate.format("%Y%m%dT%H%M%S")),
    }
}

/// Removes the VEVENT whose `RECURRENCE-ID` matches `rid` from a document.
///
/// Returns `None` when no component matches, or when the match is the only
/// VEVENT in the document — an empty calendar file is not a meaningful thing
/// to write, and the caller should delete the file instead.
#[must_use]
pub fn remove_vevent(
    text: &str,
    calendar_id: &str,
    file_name: &str,
    rid: Option<EventTime>,
) -> Option<String> {
    use crate::patch::logical_lines;

    let rids: Vec<Option<EventTime>> = parse_ics(text, calendar_id, file_name)
        .iter()
        .map(|e| e.recurrence_id)
        .collect();
    if rids.len() < 2 {
        return None;
    }
    let target = rids.iter().position(|r| *r == rid)?;

    let lines = logical_lines(text);
    let mut out = String::with_capacity(text.len());
    let mut vevent_index = 0usize;
    let mut inside: Option<(usize, bool)> = None; // (nesting depth, skipping)

    for line in &lines {
        match inside {
            None => {
                if line.begins().as_deref() == Some("VEVENT") {
                    let skipping = vevent_index == target;
                    inside = Some((0, skipping));
                    vevent_index += 1;
                    if !skipping {
                        out.push_str(line.raw());
                    }
                    continue;
                }
                out.push_str(line.raw());
            }
            Some((depth, skipping)) => {
                if line.begins().is_some() {
                    inside = Some((depth + 1, skipping));
                } else if line.ends().is_some() {
                    if depth == 0 {
                        inside = None;
                        if skipping {
                            continue;
                        }
                        out.push_str(line.raw());
                        continue;
                    }
                    inside = Some((depth - 1, skipping));
                }
                if !skipping {
                    out.push_str(line.raw());
                }
            }
        }
    }

    Some(out)
}

/// Serialises one event as a complete single-VEVENT iCalendar document.
#[must_use]
pub fn to_ics(event: &Event) -> String {
    let mut out = String::new();
    fold_line("BEGIN:VCALENDAR", &mut out);
    fold_line("VERSION:2.0", &mut out);
    fold_line("PRODID:-//COSMIC//Calendar//EN", &mut out);
    write_vevent(event, &mut out);
    fold_line("END:VCALENDAR", &mut out);
    out
}

/// Serialises several events into one document, for export.
#[must_use]
pub fn to_ics_collection(name: &str, events: &[Event]) -> String {
    let mut out = String::new();
    fold_line("BEGIN:VCALENDAR", &mut out);
    fold_line("VERSION:2.0", &mut out);
    fold_line("PRODID:-//COSMIC//Calendar//EN", &mut out);
    if !name.is_empty() {
        fold_line(&format!("X-WR-CALNAME:{}", escape_text(name)), &mut out);
    }
    for event in events {
        write_vevent(event, &mut out);
    }
    fold_line("END:VCALENDAR", &mut out);
    out
}

fn write_vevent(event: &Event, out: &mut String) {
    fold_line("BEGIN:VEVENT", out);
    fold_line(&format!("UID:{}", escape_text(&event.uid)), out);
    fold_line(
        &format!("DTSTAMP:{}", Utc::now().format("%Y%m%dT%H%M%SZ")),
        out,
    );
    fold_line(&datetime_line("DTSTART", event.start), out);
    fold_line(&datetime_line("DTEND", event.end), out);
    if let Some(rid) = event.recurrence_id {
        // What makes this component an override rather than a second event:
        // the instance of the series it replaces.
        fold_line(&datetime_line("RECURRENCE-ID", rid), out);
    }
    fold_line(&format!("SUMMARY:{}", escape_text(&event.summary)), out);

    if let Some(description) = &event.description {
        fold_line(&format!("DESCRIPTION:{}", escape_text(description)), out);
    }
    if let Some(location) = &event.location {
        fold_line(&format!("LOCATION:{}", escape_text(location)), out);
    }
    if let Some(rrule) = &event.rrule {
        // RRULE is structured, not TEXT — escaping it would corrupt the
        // semicolons that separate its parts.
        fold_line(&format!("RRULE:{}", rrule.trim()), out);
    }
    if event.sequence > 0 {
        fold_line(&format!("SEQUENCE:{}", event.sequence), out);
    }
    if let Some(created) = event.created {
        fold_line(
            &format!("CREATED:{}", created.format("%Y%m%dT%H%M%SZ")),
            out,
        );
    }
    fold_line(
        &format!(
            "LAST-MODIFIED:{}",
            event
                .last_modified
                .unwrap_or_else(Utc::now)
                .format("%Y%m%dT%H%M%SZ")
        ),
        out,
    );

    for exdate in &event.exdates {
        // EXDATE must match DTSTART's value type, or clients will not match it
        // against the expansion and the excluded instance reappears.
        let line = if event.start.is_all_day() {
            format!("EXDATE;VALUE=DATE:{}", exdate.format("%Y%m%d"))
        } else {
            match event.start {
                EventTime::Zoned(_, tz) if tz == chrono_tz::UTC => {
                    format!("EXDATE:{}Z", exdate.format("%Y%m%dT%H%M%S"))
                }
                EventTime::Zoned(_, tz) => format!(
                    "EXDATE;TZID={}:{}",
                    tz.name(),
                    exdate.format("%Y%m%dT%H%M%S")
                ),
                _ => format!("EXDATE:{}", exdate.format("%Y%m%dT%H%M%S")),
            }
        };
        fold_line(&line, out);
    }

    if let Some(organizer) = &event.organizer {
        fold_line(&attendee_line(organizer, "ORGANIZER"), out);
    }
    for attendee in &event.attendees {
        fold_line(&attendee_line(attendee, "ATTENDEE"), out);
    }

    // Everything this model does not interpret, back exactly as it arrived.
    for line in &event.other {
        fold_line(line, out);
    }

    for alarm in &event.alarms {
        fold_line("BEGIN:VALARM", out);
        fold_line("ACTION:DISPLAY", out);
        // DESCRIPTION is REQUIRED on a DISPLAY alarm (RFC 5545 §3.6.6);
        // servers that validate reject the component without it.
        fold_line(&format!("DESCRIPTION:{}", escape_text(&event.summary)), out);
        fold_line(&format!("TRIGGER:{}", format_iso_duration(*alarm)), out);
        fold_line("END:VALARM", out);
    }

    fold_line("END:VEVENT", out);
}

/// Renders a `DTSTART`/`DTEND` line, preserving the value's original form.
fn datetime_line(property: &str, time: EventTime) -> String {
    match time {
        EventTime::Date(d) => format!("{property};VALUE=DATE:{}", d.format("%Y%m%d")),
        EventTime::Floating(dt) => format!("{property}:{}", dt.format("%Y%m%dT%H%M%S")),
        EventTime::Zoned(dt, tz) if tz == chrono_tz::UTC => {
            format!("{property}:{}Z", dt.format("%Y%m%dT%H%M%S"))
        }
        // Emitted without an accompanying VTIMEZONE. Strictly RFC 5545 wants
        // one, but every client resolves a bare IANA TZID (calcard included,
        // via its `Tz::from_str` fallback), and generating correct VTIMEZONE
        // blocks with their transition rules is a large amount of machinery for
        // something nothing in practice needs.
        EventTime::Zoned(dt, tz) => format!(
            "{property};TZID={}:{}",
            tz.name(),
            dt.format("%Y%m%dT%H%M%S")
        ),
    }
}

/* ------------------------------------------------------------------ */
/* Durations                                                          */

/// Parses an RFC 5545 duration such as `-PT15M`, `PT1H30M`, `-P1D`, `P1W`.
#[must_use]
pub fn parse_iso_duration(value: &str) -> Option<chrono::Duration> {
    let raw = value.trim();
    let (negative, rest) = match raw.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, raw.strip_prefix('+').unwrap_or(raw)),
    };

    let rest = rest.strip_prefix('P').or_else(|| rest.strip_prefix('p'))?;

    let (date_part, time_part) = match rest.find(['T', 't']) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };

    let mut seconds: i64 = 0;
    let mut digits = String::new();

    for c in date_part.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let n: i64 = digits.parse().ok()?;
        digits.clear();
        seconds += match c.to_ascii_uppercase() {
            'W' => n * 7 * 86_400,
            'D' => n * 86_400,
            _ => return None,
        };
    }
    if !digits.is_empty() {
        return None;
    }

    for c in time_part.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let n: i64 = digits.parse().ok()?;
        digits.clear();
        seconds += match c.to_ascii_uppercase() {
            'H' => n * 3_600,
            'M' => n * 60,
            'S' => n,
            _ => return None,
        };
    }
    if !digits.is_empty() {
        return None;
    }

    Some(chrono::Duration::seconds(if negative {
        -seconds
    } else {
        seconds
    }))
}

/// Renders a duration back to the RFC 5545 form.
#[must_use]
pub fn format_iso_duration(duration: chrono::Duration) -> String {
    let total = duration.num_seconds();
    let sign = if total < 0 { "-" } else { "" };
    let abs = total.abs();

    let (days, rest) = (abs / 86_400, abs % 86_400);
    let (hours, rest) = (rest / 3_600, rest % 3_600);
    let (minutes, seconds) = (rest / 60, rest % 60);

    let mut out = format!("{sign}P");
    if days > 0 {
        out.push_str(&format!("{days}D"));
    }
    if hours > 0 || minutes > 0 || seconds > 0 || days == 0 {
        out.push('T');
        if hours > 0 {
            out.push_str(&format!("{hours}H"));
        }
        if minutes > 0 {
            out.push_str(&format!("{minutes}M"));
        }
        // A bare "PT" is invalid, so a zero-length trigger still needs a unit.
        if seconds > 0 || (hours == 0 && minutes == 0) {
            out.push_str(&format!("{seconds}S"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(ics: &str) -> Event {
        let mut events = parse_ics(ics, "personal", "x.ics");
        assert_eq!(events.len(), 1, "expected exactly one VEVENT");
        events.remove(0)
    }

    fn wrap(body: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\nBEGIN:VEVENT\r\nUID:x@test\r\n{body}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    #[test]
    fn utc_stamps_parse_as_utc_zoned() {
        let event = one(&wrap("DTSTART:20260804T090000Z\r\nSUMMARY:Standup"));
        assert_eq!(
            event.start,
            EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap(),
                chrono_tz::UTC
            )
        );
    }

    #[test]
    fn a_non_zero_offset_is_converted_to_utc_not_stored_verbatim() {
        // +0300 at 12:00 is 09:00Z. Storing the wall clock as if it were
        // already UTC would put the event three hours early.
        let event = one(&wrap("DTSTART:20260804T120000+0300\r\nSUMMARY:Athens"));
        assert_eq!(
            event.start,
            EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap(),
                chrono_tz::UTC
            )
        );
    }

    #[test]
    fn a_bare_tzid_resolves_without_a_vtimezone_block() {
        let event = one(&wrap(
            "DTSTART;TZID=Europe/Athens:20260804T090000\r\nSUMMARY:Meeting",
        ));
        assert_eq!(
            event.start,
            EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap(),
                chrono_tz::Europe::Athens
            )
        );
    }

    #[test]
    fn a_tzid_with_trailing_whitespace_still_resolves() {
        // The old `icalendar` path failed this byte-exact match and silently
        // degraded the value to floating, shifting the event by the local
        // offset. This is the single most valuable behaviour in this module.
        let event = one(&wrap(
            "DTSTART;TZID=Europe/Athens :20260804T090000\r\nSUMMARY:Meeting",
        ));
        assert_eq!(
            event.start,
            EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap(),
                chrono_tz::Europe::Athens
            ),
            "a trailing space in TZID degraded the event to floating"
        );
    }

    #[test]
    fn a_windows_timezone_name_resolves_to_the_right_instant() {
        // Outlook and Exchange emit Windows zone names rather than IANA ones,
        // so every invitation out of an Office tenant carries one. The failure
        // shape is the trailing space again: no error, no warning, the event
        // silently becomes floating and lands at the wrong hour.
        //
        // What is asserted is the *instant*, not the zone name. CLDR maps a
        // Windows zone to one IANA zone per territory and to a default for the
        // rest — `GTB Standard Time` is Athens, Bucharest, and Chisinau, with
        // Bucharest as that default — and which of those a parser picks is
        // arbitrary and not ours to pin. They keep the same rules, so the
        // instant is the same, and the instant is what a calendar displays.
        let event = one(&wrap(
            "DTSTART;TZID=GTB Standard Time:20260804T090000\r\nSUMMARY:Invitation",
        ));

        let EventTime::Zoned(naive, tz) = event.start else {
            panic!("a Windows TZID fell through to floating: {:?}", event.start);
        };
        assert_eq!(
            naive.and_local_timezone(tz).unwrap().to_utc(),
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap()
                .and_local_timezone(chrono_tz::Europe::Athens)
                .unwrap()
                .to_utc(),
            "a Windows TZID resolved to a zone with the wrong offset"
        );
    }

    #[test]
    fn an_unresolvable_tzid_falls_back_to_utc_not_to_local() {
        let event = one(&wrap(
            "DTSTART;TZID=Nowhere/Fictional:20260804T090000\r\nSUMMARY:Meeting",
        ));
        assert_eq!(
            event.start,
            EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap(),
                chrono_tz::UTC
            ),
            "an unresolvable zone must be wrong consistently, not per-machine"
        );
    }

    #[test]
    fn floating_times_stay_floating() {
        let event = one(&wrap("DTSTART:20260804T090000\r\nSUMMARY:Whenever"));
        assert_eq!(
            event.start,
            EventTime::Floating(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap()
            )
        );
    }

    #[test]
    fn value_date_stays_a_date() {
        let event = one(&wrap(
            "DTSTART;VALUE=DATE:20260804\r\nDTEND;VALUE=DATE:20260805\r\nSUMMARY:Holiday",
        ));
        assert!(event.is_all_day());
        assert_eq!(
            event.start,
            EventTime::Date(NaiveDate::from_ymd_opt(2026, 8, 4).unwrap())
        );
    }

    #[test]
    fn a_tzid_value_wins_over_a_floating_duplicate() {
        // The Outlook-bridge shape: two DTSTARTs, only one of which is right.
        let event = one(&wrap(
            "DTSTART:20260804T090000\r\nDTSTART;TZID=Europe/Athens:20260804T090000\r\nSUMMARY:Dup",
        ));
        assert_eq!(
            event.start,
            EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap(),
                chrono_tz::Europe::Athens
            ),
            "the floating compatibility duplicate was preferred over the TZID value"
        );
    }

    #[test]
    fn duration_substitutes_for_a_missing_dtend() {
        let event = one(&wrap(
            "DTSTART:20260804T090000Z\r\nDURATION:PT90M\r\nSUMMARY:Long",
        ));
        assert_eq!(
            event.end,
            EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(10, 30, 0)
                    .unwrap(),
                chrono_tz::UTC
            ),
            "DURATION was ignored and the event got the default hour"
        );
    }

    #[test]
    fn a_missing_dtend_and_duration_gets_the_default() {
        let event = one(&wrap("DTSTART:20260804T090000Z\r\nSUMMARY:No end"));
        assert_eq!(
            event.end,
            EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(10, 0, 0)
                    .unwrap(),
                chrono_tz::UTC
            )
        );
    }

    #[test]
    fn garbage_yields_no_events_rather_than_an_error() {
        assert!(parse_ics("this is not iCalendar at all", "personal", "x.ics").is_empty());
    }

    #[test]
    fn a_vtimezone_only_document_yields_no_events() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
                   BEGIN:VTIMEZONE\r\nTZID:Europe/Athens\r\nEND:VTIMEZONE\r\nEND:VCALENDAR\r\n";
        assert!(parse_ics(ics, "personal", "x.ics").is_empty());
    }

    #[test]
    fn alarms_are_read_from_valarm_subcomponents() {
        let event = one(&wrap(
            "DTSTART:20260804T090000Z\r\nSUMMARY:Standup\r\n\
             BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Standup\r\nTRIGGER:-PT10M\r\nEND:VALARM",
        ));
        assert_eq!(event.alarms, vec![chrono::Duration::minutes(-10)]);
    }

    #[test]
    fn an_alarm_anchored_to_the_end_is_skipped_rather_than_guessed_at() {
        let event = one(&wrap(
            "DTSTART:20260804T090000Z\r\nSUMMARY:Standup\r\n\
             BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:x\r\n\
             TRIGGER;RELATED=END:-PT10M\r\nEND:VALARM",
        ));
        assert!(
            event.alarms.is_empty(),
            "a RELATED=END trigger was treated as an offset from the start"
        );
    }

    #[test]
    fn exdates_are_collected_across_lines_and_lists() {
        let event = one(&wrap(
            "DTSTART:20260803T090000Z\r\nSUMMARY:Standup\r\nRRULE:FREQ=WEEKLY\r\n\
             EXDATE:20260810T090000Z,20260817T090000Z\r\nEXDATE:20260824T090000Z",
        ));
        assert_eq!(event.exdates.len(), 3, "got {:?}", event.exdates);
    }

    #[test]
    fn rrule_survives_as_text() {
        let event = one(&wrap(
            "DTSTART:20260803T090000Z\r\nSUMMARY:Standup\r\nRRULE:FREQ=WEEKLY;COUNT=5",
        ));
        let rrule = event.rrule.expect("RRULE was dropped");
        assert!(rrule.contains("FREQ=WEEKLY"), "got {rrule}");
        assert!(rrule.contains("COUNT=5"), "got {rrule}");
    }

    /* --- serialisation --- */

    #[test]
    fn every_line_is_crlf_terminated_and_within_the_fold_limit() {
        let mut event = Event::draft(
            "personal",
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        event.summary = "x".repeat(300);

        let ics = to_ics(&event);
        assert!(ics.ends_with("\r\n"));
        for line in ics.split("\r\n") {
            assert!(line.len() <= 75, "line exceeds the fold limit: {line:?}");
        }
    }

    #[test]
    fn folding_never_splits_a_multibyte_character() {
        let mut event = Event::draft(
            "personal",
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        // Greek text, two bytes per character, crossing several fold points.
        event.summary = "Συνάντηση ".repeat(20);

        let ics = to_ics(&event);
        // The real assertion: it parses back. A split character would make the
        // document undecodable rather than merely wrong.
        let back = one(&ics);
        assert_eq!(back.summary, event.summary);
    }

    #[test]
    fn text_special_characters_round_trip() {
        let mut event = Event::draft(
            "personal",
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        event.summary = "Lunch; with, a\\backslash".into();
        event.description = Some("line one\nline two".into());

        let back = one(&to_ics(&event));
        assert_eq!(back.summary, event.summary);
        assert_eq!(back.description, event.description);
    }

    #[test]
    fn an_rrule_semicolon_is_not_escaped_as_text() {
        let mut event = Event::draft(
            "personal",
            NaiveDate::from_ymd_opt(2026, 8, 3)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        event.rrule = Some("FREQ=WEEKLY;COUNT=5".into());

        let ics = to_ics(&event);
        assert!(
            ics.contains("RRULE:FREQ=WEEKLY;COUNT=5"),
            "RRULE was TEXT-escaped, which corrupts it: {ics}"
        );
    }

    #[test]
    fn exdate_value_type_matches_dtstart() {
        let mut event = Event::draft(
            "personal",
            NaiveDate::from_ymd_opt(2026, 8, 3)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        event.start = EventTime::Date(NaiveDate::from_ymd_opt(2026, 8, 3).unwrap());
        event.end = EventTime::Date(NaiveDate::from_ymd_opt(2026, 8, 4).unwrap());
        event.rrule = Some("FREQ=WEEKLY".into());
        event.exdates = vec![
            NaiveDate::from_ymd_opt(2026, 8, 17)
                .unwrap()
                .and_time(chrono::NaiveTime::MIN),
        ];

        let ics = to_ics(&event);
        assert!(
            ics.contains("EXDATE;VALUE=DATE:20260817"),
            "EXDATE type did not match an all-day DTSTART: {ics}"
        );
    }

    #[test]
    fn a_zoned_exdate_carries_the_events_tzid() {
        let mut event = Event::draft(
            "personal",
            NaiveDate::from_ymd_opt(2026, 8, 3)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::Europe::Athens,
        );
        event.rrule = Some("FREQ=WEEKLY".into());
        event.exdates = vec![
            NaiveDate::from_ymd_opt(2026, 8, 17)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
        ];

        let ics = to_ics(&event);
        assert!(
            ics.contains("EXDATE;TZID=Europe/Athens:20260817T090000"),
            "EXDATE lost the event's zone: {ics}"
        );
    }

    #[test]
    fn iso_durations_round_trip() {
        use chrono::Duration;
        for d in [
            Duration::minutes(-15),
            Duration::hours(-1),
            Duration::days(-1),
            Duration::minutes(-90),
            Duration::zero(),
        ] {
            let text = format_iso_duration(d);
            assert_eq!(
                parse_iso_duration(&text),
                Some(d),
                "round trip failed: {text}"
            );
        }
    }

    #[test]
    fn rejects_durations_it_cannot_represent() {
        assert_eq!(parse_iso_duration(""), None);
        assert_eq!(parse_iso_duration("15M"), None, "missing the P prefix");
        assert_eq!(parse_iso_duration("-PT15"), None, "missing the unit");
        assert_eq!(parse_iso_duration("nonsense"), None);
    }
}

#[cfg(test)]
mod preservation_tests {
    use super::*;

    /// A foreign invitation: attendees, an organizer, and a spread of
    /// properties this model does not interpret.
    const INVITATION: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Example Corp//EN\r\n\
BEGIN:VEVENT\r\n\
UID:invite@example.com\r\n\
DTSTAMP:20260901T000000Z\r\n\
DTSTART;TZID=Europe/Athens:20260903T090000\r\n\
DTEND;TZID=Europe/Athens:20260903T100000\r\n\
SUMMARY:Planning\r\n\
ORGANIZER;CN=Ada:mailto:ada@example.com\r\n\
ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED;ROLE=REQ-PARTICIPANT:mailto:bob@example.com\r\n\
ATTENDEE;CN=Cleo;PARTSTAT=NEEDS-ACTION;DELEGATED-FROM=\"mailto:dan@example.com\":mailto:cleo@example.com\r\n\
STATUS:CONFIRMED\r\n\
TRANSP:OPAQUE\r\n\
CLASS:PRIVATE\r\n\
PRIORITY:5\r\n\
URL:https://example.com/meeting\r\n\
CATEGORIES:Work,Planning\r\n\
X-VENDOR-THING:keep me\r\n\
BEGIN:VALARM\r\n\
ACTION:DISPLAY\r\n\
DESCRIPTION:Planning\r\n\
TRIGGER:-PT10M\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    fn parsed() -> Event {
        let events = parse_ics(INVITATION, "personal", "invite.ics");
        assert_eq!(events.len(), 1);
        events.into_iter().next().unwrap()
    }

    /// The document with its content lines unfolded.
    ///
    /// Written output is folded at 73 octets, as RFC 5545 §3.1 requires, so a
    /// long `ATTENDEE` line has a CRLF and a space through the middle of its
    /// address. Every reader unfolds before interpreting; these assertions
    /// are about what survives, not where the folds fall.
    fn written(event: &Event) -> String {
        let out = to_ics(event);
        crate::patch::logical_lines(&out)
            .iter()
            .map(|line| line.unfolded().to_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn attendees_and_the_organizer_are_read() {
        let event = parsed();
        assert_eq!(
            event.organizer.as_ref().map(|o| o.email.as_str()),
            Some("ada@example.com")
        );
        let emails: Vec<&str> = event.attendees.iter().map(|a| a.email.as_str()).collect();
        assert_eq!(emails, vec!["bob@example.com", "cleo@example.com"]);
        assert_eq!(event.attendees[0].name.as_deref(), Some("Bob"));
        assert!(event.attendees[0].accepted());
        assert!(!event.attendees[1].accepted());
    }

    #[test]
    fn an_address_is_normalised_for_comparison() {
        // Free/busy answers come back spelled however the server likes.
        assert_eq!(
            crate::model::normalise_address("MAILTO:Bob@Example.COM"),
            "bob@example.com"
        );
    }

    /// The bug this all exists for: editing an invitation used to drop every
    /// property the model does not carry.
    #[test]
    fn a_round_trip_keeps_what_the_model_does_not_understand() {
        let mut event = parsed();
        event.summary = "Planning (moved)".into();
        let out = written(&event);

        for expected in [
            "ORGANIZER",
            "ada@example.com",
            "bob@example.com",
            "cleo@example.com",
            "STATUS:CONFIRMED",
            "TRANSP:OPAQUE",
            "CLASS:PRIVATE",
            "PRIORITY:5",
            "URL:https://example.com/meeting",
            "CATEGORIES:Work,Planning",
            "X-VENDOR-THING:keep me",
        ] {
            assert!(out.contains(expected), "{expected} was lost:\n{out}");
        }
        assert!(out.contains("Planning (moved)"), "the edit was not applied");
    }

    #[test]
    fn an_unmodelled_attendee_parameter_survives() {
        // Only CN and PARTSTAT are modelled; the rest of the line has to ride
        // along verbatim or a delegation is silently forgotten.
        let out = written(&parsed());
        assert!(
            out.contains("DELEGATED-FROM=\"mailto:dan@example.com\""),
            "an unmodelled parameter was dropped:\n{out}"
        );
        assert!(out.contains("ROLE=REQ-PARTICIPANT"));
    }

    #[test]
    fn the_alarm_is_written_exactly_once() {
        // VALARM is modelled and re-emitted from `alarms`; if the verbatim
        // capture also collected its lines, every save would double the alarm.
        let out = written(&parsed());
        assert_eq!(out.matches("BEGIN:VALARM").count(), 1, "{out}");
        assert_eq!(out.matches("TRIGGER:").count(), 1, "{out}");
    }

    #[test]
    fn a_new_attendee_is_written_from_its_fields() {
        let mut event = parsed();
        event.attendees.push(crate::model::Attendee::new(
            "MAILTO:New@Example.com",
            Some("New Person".into()),
        ));

        let out = written(&event);
        assert!(out.contains("mailto:new@example.com"), "{out}");
        assert!(out.contains("CN=\"New Person\""), "{out}");

        // …and reading it back gives the same person.
        let again = parse_ics(&to_ics(&event), "personal", "invite.ics")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(again.attendees.len(), 3);
        assert_eq!(again.attendees[2].email, "new@example.com");
        assert_eq!(again.attendees[2].name.as_deref(), Some("New Person"));
    }

    #[test]
    fn removing_an_attendee_removes_only_that_line() {
        let mut event = parsed();
        event.attendees.retain(|a| a.email != "cleo@example.com");
        let out = written(&event);
        assert!(out.contains("bob@example.com"));
        assert!(!out.contains("cleo@example.com"), "{out}");
    }

    #[test]
    fn a_master_and_its_override_keep_their_own_extras() {
        // Two VEVENTs in one file: the verbatim capture walks the source text
        // separately from the parser, so a drift between the two walks would
        // hand one component's properties to the other.
        let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Example//EN\r\n\
BEGIN:VEVENT\r\n\
UID:series@example.com\r\n\
DTSTAMP:20260901T000000Z\r\n\
DTSTART:20260804T090000Z\r\n\
DTEND:20260804T100000Z\r\n\
RRULE:FREQ=WEEKLY\r\n\
SUMMARY:Standup\r\n\
X-WHICH:master\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
UID:series@example.com\r\n\
DTSTAMP:20260901T000000Z\r\n\
RECURRENCE-ID:20260811T090000Z\r\n\
DTSTART:20260811T140000Z\r\n\
DTEND:20260811T150000Z\r\n\
SUMMARY:Standup (moved)\r\n\
X-WHICH:override\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

        let events = parse_ics(doc, "personal", "series.ics");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].other, vec!["X-WHICH:master".to_owned()]);
        assert_eq!(events[1].other, vec!["X-WHICH:override".to_owned()]);
    }

    #[test]
    fn an_event_with_nothing_extra_carries_nothing_extra() {
        let doc = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Example//EN\r\n\
BEGIN:VEVENT\r\n\
UID:plain@example.com\r\n\
DTSTAMP:20260901T000000Z\r\n\
DTSTART:20260804T090000Z\r\n\
DTEND:20260804T100000Z\r\n\
SUMMARY:Plain\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        let event = parse_ics(doc, "personal", "plain.ics")
            .into_iter()
            .next()
            .unwrap();
        assert!(event.other.is_empty());
        assert!(event.attendees.is_empty());
        assert!(event.organizer.is_none());
    }
}

#[cfg(test)]
mod recurrence_id_tests {
    use super::*;

    fn doc(bodies: &[&str]) -> String {
        let mut s = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n");
        for body in bodies {
            s.push_str("BEGIN:VEVENT\r\nUID:series@test\r\n");
            s.push_str(body);
            s.push_str("\r\nEND:VEVENT\r\n");
        }
        s.push_str("END:VCALENDAR\r\n");
        s
    }

    #[test]
    fn a_master_has_no_recurrence_id() {
        let ids = recurrence_ids(&doc(&["DTSTART:20260803T090000Z\r\nRRULE:FREQ=WEEKLY"]));
        assert_eq!(ids, vec![None]);
    }

    #[test]
    fn an_override_component_parses_with_its_recurrence_id() {
        let text = doc(&[
            "DTSTART:20260803T090000Z\r\nRRULE:FREQ=WEEKLY\r\nSUMMARY:Standup",
            "DTSTART:20260810T140000Z\r\nRECURRENCE-ID:20260810T090000Z\r\nSUMMARY:Moved",
        ]);
        let events = parse_ics(&text, "personal", "series.ics");

        assert_eq!(events.len(), 2, "both components must survive parsing");
        assert_eq!(events[0].recurrence_id, None);
        assert_eq!(
            events[1].recurrence_id,
            Some(EventTime::Zoned(
                chrono::NaiveDate::from_ymd_opt(2026, 8, 10)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap(),
                chrono_tz::UTC,
            ))
        );
        assert_eq!(events[1].uid, events[0].uid, "an override shares the UID");
    }

    #[test]
    fn a_recurrence_id_round_trips_through_serialisation() {
        let text =
            doc(&["DTSTART:20260810T140000Z\r\nRECURRENCE-ID:20260810T090000Z\r\nSUMMARY:Moved"]);
        let event = parse_ics(&text, "personal", "series.ics").remove(0);

        let written = to_ics(&event);
        assert!(
            written.contains("RECURRENCE-ID:20260810T090000Z"),
            "serialising an override must keep what makes it one:\n{written}"
        );

        let back = parse_ics(&written, "personal", "series.ics").remove(0);
        assert_eq!(back.recurrence_id, event.recurrence_id);
    }

    #[test]
    fn upserting_the_master_leaves_the_override_untouched() {
        let text = doc(&[
            "DTSTART:20260803T090000Z\r\nRRULE:FREQ=WEEKLY\r\nSUMMARY:Standup\r\nX-CUSTOM:kept",
            "DTSTART:20260810T140000Z\r\nRECURRENCE-ID:20260810T090000Z\r\nSUMMARY:Moved",
        ]);
        let mut master = parse_ics(&text, "personal", "series.ics").remove(0);
        master.summary = "Renamed".into();

        let out = upsert_vevent(&text, &master);
        let events = parse_ics(&out, "personal", "series.ics");

        assert_eq!(events.len(), 2, "the override component vanished:\n{out}");
        assert_eq!(events[0].summary, "Renamed");
        assert_eq!(events[1].summary, "Moved");
        // The untouched component passes through byte-for-byte — including a
        // property the model does not represent.
        assert!(out.contains("RECURRENCE-ID:20260810T090000Z"));
    }

    #[test]
    fn upserting_the_override_leaves_the_master_untouched() {
        let text = doc(&[
            "DTSTART:20260803T090000Z\r\nRRULE:FREQ=WEEKLY\r\nSUMMARY:Standup\r\nX-CUSTOM:kept",
            "DTSTART:20260810T140000Z\r\nRECURRENCE-ID:20260810T090000Z\r\nSUMMARY:Moved",
        ]);
        let mut over = parse_ics(&text, "personal", "series.ics").remove(1);
        over.summary = "Moved again".into();

        let out = upsert_vevent(&text, &over);
        let events = parse_ics(&out, "personal", "series.ics");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].summary, "Standup");
        assert_eq!(events[1].summary, "Moved again");
        assert!(
            out.contains("X-CUSTOM:kept"),
            "the master must pass through byte-for-byte:\n{out}"
        );
        assert!(out.contains("RRULE:FREQ=WEEKLY"));
    }

    #[test]
    fn upserting_a_new_override_appends_a_component() {
        let text = doc(&["DTSTART:20260803T090000Z\r\nRRULE:FREQ=WEEKLY\r\nSUMMARY:Standup"]);
        let mut over = parse_ics(&text, "personal", "series.ics").remove(0);
        over.rrule = None;
        over.summary = "One moved instance".into();
        over.recurrence_id = Some(EventTime::Zoned(
            chrono::NaiveDate::from_ymd_opt(2026, 8, 10)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        ));

        let out = upsert_vevent(&text, &over);
        let events = parse_ics(&out, "personal", "series.ics");

        assert_eq!(
            events.len(),
            2,
            "the new component was not appended:\n{out}"
        );
        assert_eq!(events[0].summary, "Standup", "the master must survive");
        assert!(events[1].recurrence_id.is_some());
    }

    #[test]
    fn removing_the_override_keeps_the_master() {
        let text = doc(&[
            "DTSTART:20260803T090000Z\r\nRRULE:FREQ=WEEKLY\r\nSUMMARY:Standup",
            "DTSTART:20260810T140000Z\r\nRECURRENCE-ID:20260810T090000Z\r\nSUMMARY:Moved",
        ]);
        let rid = parse_ics(&text, "personal", "series.ics")[1].recurrence_id;

        let out = remove_vevent(&text, "personal", "series.ics", rid).expect("a match");
        let events = parse_ics(&out, "personal", "series.ics");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, "Standup");
    }

    #[test]
    fn removing_the_last_component_asks_for_file_deletion_instead() {
        let text = doc(&["DTSTART:20260803T090000Z\r\nSUMMARY:Only one"]);
        assert!(remove_vevent(&text, "personal", "one.ics", None).is_none());
    }

    #[test]
    fn master_and_override_are_returned_in_document_order() {
        let ids = recurrence_ids(&doc(&[
            "DTSTART:20260803T090000Z\r\nRRULE:FREQ=WEEKLY",
            "DTSTART:20260810T100000Z\r\nRECURRENCE-ID:20260810T090000Z",
        ]));
        assert_eq!(ids, vec![None, Some("20260810T090000Z".into())]);
    }

    #[test]
    fn a_numeric_zero_offset_normalises_to_z() {
        // `+0000` and `Z` name the same instant; if they produced different
        // keys, a master and its override from two emitters would never match.
        let plus = recurrence_ids(&doc(&[
            "DTSTART:20260810T100000Z\r\nRECURRENCE-ID:20260810T090000+0000",
        ]));
        let zulu = recurrence_ids(&doc(&[
            "DTSTART:20260810T100000Z\r\nRECURRENCE-ID:20260810T090000Z",
        ]));
        assert_eq!(plus, zulu);
    }

    #[test]
    fn a_non_zero_offset_is_converted_to_utc() {
        let ids = recurrence_ids(&doc(&[
            "DTSTART:20260810T100000Z\r\nRECURRENCE-ID:20260810T120000+0300",
        ]));
        assert_eq!(ids, vec![Some("20260810T090000Z".into())]);
    }

    #[test]
    fn a_zoned_recurrence_id_keeps_its_tzid_rather_than_resolving() {
        // Resolving through the local zone would make this key host-dependent.
        let ids = recurrence_ids(&doc(&["DTSTART;TZID=Europe/Athens:20260810T100000\r\n\
             RECURRENCE-ID;TZID=Europe/Athens:20260810T090000"]));
        assert_eq!(ids, vec![Some("20260810T090000;TZID=Europe/Athens".into())]);
    }

    #[test]
    fn an_all_day_recurrence_id_is_a_bare_date() {
        let ids = recurrence_ids(&doc(&[
            "DTSTART;VALUE=DATE:20260810\r\nRECURRENCE-ID;VALUE=DATE:20260810",
        ]));
        assert_eq!(ids, vec![Some("20260810".into())]);
    }

    #[test]
    fn a_floating_recurrence_id_has_no_suffix() {
        let ids = recurrence_ids(&doc(&[
            "DTSTART:20260810T100000\r\nRECURRENCE-ID:20260810T090000",
        ]));
        assert_eq!(ids, vec![Some("20260810T090000".into())]);
    }
}

#[cfg(test)]
mod todo_tests {
    use super::*;

    fn wrap(body: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
             BEGIN:VTODO\r\nUID:t@test\r\n{body}\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"
        )
    }

    fn one(ics: &str) -> Todo {
        let mut todos = parse_todos(ics, "personal", "t.ics");
        assert_eq!(todos.len(), 1, "expected exactly one VTODO");
        todos.remove(0)
    }

    #[test]
    fn a_task_with_no_dates_at_all_is_valid() {
        // The behaviour that most distinguishes a task from an event: this
        // would be unparseable as a VEVENT.
        let todo = one(&wrap("SUMMARY:Buy milk"));
        assert_eq!(todo.summary, "Buy milk");
        assert!(todo.due.is_none());
        assert!(todo.start.is_none());
    }

    #[test]
    fn a_vevent_is_not_read_as_a_task() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
                   BEGIN:VEVENT\r\nUID:e@test\r\nDTSTART:20260804T090000Z\r\n\
                   SUMMARY:Meeting\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(parse_todos(ics, "personal", "e.ics").is_empty());
        // …and the converse, so a mixed collection cannot cross-contaminate.
        assert!(parse_ics(&wrap("SUMMARY:Buy milk"), "personal", "t.ics").is_empty());
    }

    #[test]
    fn due_uses_the_same_timezone_rules_as_an_event_start() {
        let todo = one(&wrap(
            "SUMMARY:x\r\nDUE;TZID=Europe/Athens :20260804T170000",
        ));
        assert_eq!(
            todo.due,
            Some(EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(17, 0, 0)
                    .unwrap(),
                chrono_tz::Europe::Athens
            )),
            "the trailing-space TZID hardening did not apply to DUE"
        );
    }

    #[test]
    fn an_all_day_due_stays_a_date() {
        let todo = one(&wrap("SUMMARY:x\r\nDUE;VALUE=DATE:20260804"));
        assert_eq!(
            todo.due,
            Some(EventTime::Date(
                NaiveDate::from_ymd_opt(2026, 8, 4).unwrap()
            ))
        );
    }

    #[test]
    fn status_percent_and_priority_are_read() {
        let todo = one(&wrap(
            "SUMMARY:x\r\nSTATUS:IN-PROCESS\r\nPERCENT-COMPLETE:40\r\nPRIORITY:2",
        ));
        assert_eq!(todo.status, TodoStatus::InProcess);
        assert_eq!(todo.percent_complete, 40);
        assert_eq!(todo.priority, 2);
    }

    #[test]
    fn an_out_of_range_priority_is_clamped_rather_than_wrapping() {
        // PRIORITY is bounded 0-9; a client sending 99 must not become 99u8 and
        // then sort in a way nothing else agrees with.
        let todo = one(&wrap("SUMMARY:x\r\nPRIORITY:99"));
        assert_eq!(todo.priority, 9);
    }

    #[test]
    fn an_out_of_range_percent_is_clamped() {
        let todo = one(&wrap("SUMMARY:x\r\nPERCENT-COMPLETE:250"));
        assert_eq!(todo.percent_complete, 100);
    }

    #[test]
    fn an_unknown_status_falls_back_to_needs_action() {
        let todo = one(&wrap("SUMMARY:x\r\nSTATUS:BIZARRE"));
        assert_eq!(todo.status, TodoStatus::NeedsAction);
    }

    #[test]
    fn categories_are_split_across_lines_and_commas() {
        let todo = one(&wrap(
            "SUMMARY:x\r\nCATEGORIES:home,errands\r\nCATEGORIES:urgent",
        ));
        assert_eq!(todo.categories, vec!["errands", "home", "urgent"]);
    }

    #[test]
    fn related_to_carries_the_parent_uid_for_subtasks() {
        let todo = one(&wrap("SUMMARY:x\r\nRELATED-TO:parent@test"));
        assert_eq!(todo.related_to.as_deref(), Some("parent@test"));
    }

    #[test]
    fn alarms_are_read_from_valarm() {
        let todo = one(&wrap(
            "SUMMARY:x\r\nDUE:20260804T170000Z\r\n\
             BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:x\r\nTRIGGER:-PT30M\r\nEND:VALARM",
        ));
        assert_eq!(todo.alarms, vec![chrono::Duration::minutes(-30)]);
    }

    /* --- serialisation --- */

    #[test]
    fn a_task_round_trips_through_text() {
        let mut todo = Todo::draft("personal");
        todo.summary = "Buy milk; and bread".into();
        todo.description = Some("From the corner shop".into());
        todo.due = Some(EventTime::Zoned(
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(17, 0, 0)
                .unwrap(),
            chrono_tz::Europe::Athens,
        ));
        todo.priority = 2;
        todo.categories = vec!["errands".into(), "home".into()];
        todo.related_to = Some("parent@test".into());
        todo.alarms = vec![chrono::Duration::minutes(-30)];

        let back = one(&todo_to_ics(&todo));

        assert_eq!(back.summary, todo.summary);
        assert_eq!(back.description, todo.description);
        assert_eq!(back.due, todo.due, "the due date's zone was not preserved");
        assert_eq!(back.priority, 2);
        assert_eq!(back.categories, todo.categories);
        assert_eq!(back.related_to, todo.related_to);
        assert_eq!(back.alarms, todo.alarms);
    }

    #[test]
    fn an_undated_task_round_trips_without_gaining_a_date() {
        let mut todo = Todo::draft("personal");
        todo.summary = "Someday".into();

        let back = one(&todo_to_ics(&todo));
        assert!(
            back.due.is_none() && back.start.is_none(),
            "a date was invented for an undated task"
        );
    }

    #[test]
    fn completion_round_trips_as_status_percent_and_timestamp() {
        let mut todo = Todo::draft("personal");
        todo.summary = "Done thing".into();
        todo.set_done(true);

        let back = one(&todo_to_ics(&todo));
        assert_eq!(back.status, TodoStatus::Completed);
        assert_eq!(back.percent_complete, 100);
        assert!(back.completed.is_some());
        assert!(back.is_done());
    }

    #[test]
    fn every_serialised_line_stays_within_the_fold_limit() {
        let mut todo = Todo::draft("personal");
        todo.summary = "σ".repeat(300);
        let ics = todo_to_ics(&todo);
        for line in ics.split("\r\n") {
            assert!(line.len() <= 75, "line exceeds the fold limit: {line:?}");
        }
        assert_eq!(one(&ics).summary, todo.summary);
    }
}

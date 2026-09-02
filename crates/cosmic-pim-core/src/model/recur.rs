// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Expansion of events into concrete occurrences over a date range.

use super::event::{Event, EventTime, Occurrence};
use chrono::{DateTime, Duration, NaiveDateTime, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use rrule::{RRule, RRuleSet, Unvalidated};

/// Ceiling on instances produced from a single rule per query. A month view asks
/// for ~31 days, so even a daily rule stays far below this; the cap only exists
/// so a pathological file cannot hang the UI thread.
const MAX_OCCURRENCES: u16 = 2_000;

/// Expands a set of events into occurrences, honouring `RECURRENCE-ID`
/// overrides.
///
/// An override VEVENT — same UID as its series master, a `RECURRENCE-ID`
/// naming the instance it replaces — must do two things to the calendar: its
/// own start and properties appear, and the master's generated copy of that
/// instance does not. Expanding each event in isolation cannot know about the
/// other component, which is why this takes the whole candidate set: it is the
/// one place master and override meet.
#[must_use]
pub fn expand_merged(
    events: &[Event],
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    local: Tz,
) -> Vec<Occurrence> {
    use std::collections::{HashMap, HashSet};

    // The instances that have been replaced, per series.
    let mut replaced: HashMap<(&str, &str), HashSet<DateTime<Utc>>> = HashMap::new();
    for event in events {
        if let Some(rid) = event.recurrence_id
            && let Some(instant) = instant_of(rid, local)
        {
            replaced
                .entry((event.calendar_id.as_str(), event.uid.as_str()))
                .or_default()
                .insert(instant);
        }
    }

    let mut out = Vec::new();
    for event in events {
        match event.recurrence_id {
            // An override is a single concrete occurrence at its own time —
            // whether or not its master is in the set (a master can fall
            // outside the query window while its override moved into it).
            Some(rid) => {
                let duration = event.duration(local);
                let start_utc = event.start.to_utc(local);
                if start_utc + duration > from && start_utc < to {
                    out.push(occurrence_at(
                        event,
                        event.start.naive_local(local),
                        duration,
                        instant_of(rid, local),
                    ));
                }
            }
            None => {
                let suppressed = replaced.get(&(event.calendar_id.as_str(), event.uid.as_str()));
                out.extend(
                    expand(event, from, to, local)
                        .into_iter()
                        .filter(|occurrence| match (occurrence.recurrence_id, suppressed) {
                            (Some(instant), Some(set)) => !set.contains(&instant),
                            _ => true,
                        }),
                );
            }
        }
    }
    out
}

/// The `RECURRENCE-ID` value identifying the instance of a series generated at
/// `instant`, matching the master's `DTSTART` in kind and zone — which is what
/// RFC 5545 requires of an override component.
///
/// Inverse of [`instant_of`]: `instant_of(rid_for(start, i, local), local) == i`
/// for any instant a well-formed master can generate.
#[must_use]
pub fn rid_for(master_start: EventTime, instant: DateTime<Utc>, local: Tz) -> EventTime {
    match master_start {
        EventTime::Date(_) => EventTime::Date(instant.with_timezone(&local).date_naive()),
        EventTime::Floating(_) => EventTime::Floating(instant.with_timezone(&local).naive_local()),
        EventTime::Zoned(_, tz) => EventTime::Zoned(instant.with_timezone(&tz).naive_local(), tz),
    }
}

/// `instant` as a wall-clock value in the zone the series iterates in — the
/// value space `EXDATE` entries live in.
#[must_use]
pub fn naive_in_series_zone(
    master_start: EventTime,
    instant: DateTime<Utc>,
    local: Tz,
) -> NaiveDateTime {
    match master_start {
        // Floating and all-day series iterate in the viewer's zone.
        EventTime::Date(_) | EventTime::Floating(_) => instant.with_timezone(&local).naive_local(),
        EventTime::Zoned(_, tz) => instant.with_timezone(&tz).naive_local(),
    }
}

/// The `UNTIL=` value that ends a series *before* the instance at `instant`.
///
/// RFC 5545: `UNTIL` is inclusive and must match `DTSTART`'s value type — a
/// date for all-day series, a UTC date-time for zoned ones, a floating
/// date-time for floating ones.
#[must_use]
pub fn until_before(master_start: EventTime, instant: DateTime<Utc>, local: Tz) -> String {
    match master_start {
        EventTime::Date(_) => {
            let day = instant.with_timezone(&local).date_naive() - Duration::days(1);
            day.format("%Y%m%d").to_string()
        }
        EventTime::Floating(_) => {
            let t = instant.with_timezone(&local).naive_local() - Duration::seconds(1);
            t.format("%Y%m%dT%H%M%S").to_string()
        }
        EventTime::Zoned(..) => {
            let t = instant - Duration::seconds(1);
            t.format("%Y%m%dT%H%M%SZ").to_string()
        }
    }
}

/// `rule` with any `COUNT` or `UNTIL` replaced by `UNTIL=<until>`.
///
/// The rest of the rule passes through verbatim — this is the one edit that
/// must not flatten `BYDAY`, `BYSETPOS`, or anything else the caller does not
/// understand.
#[must_use]
pub fn truncate_rule(rule: &str, until: &str) -> String {
    let mut parts: Vec<&str> = rule
        .split(';')
        .map(str::trim)
        .filter(|part| {
            let key = part.split('=').next().unwrap_or("").trim();
            !part.is_empty()
                && !key.eq_ignore_ascii_case("UNTIL")
                && !key.eq_ignore_ascii_case("COUNT")
        })
        .collect();
    let until = format!("UNTIL={until}");
    parts.push(&until);
    parts.join(";")
}

/// The `COUNT=` value of `rule`, if it carries one.
#[must_use]
pub fn count_of(rule: &str) -> Option<u32> {
    rule.split(';').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("COUNT")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// `rule` with its `COUNT=` value replaced by `count`.
///
/// Everything else passes through verbatim, for the same reason as
/// [`truncate_rule`]: this edit must not flatten parts the caller does not
/// understand. A rule without a `COUNT` is returned unchanged — an unbounded
/// or `UNTIL`-bounded series keeps its own end condition.
#[must_use]
pub fn with_count(rule: &str, count: u32) -> String {
    rule.split(';')
        .map(|part| {
            let key = part.split('=').next().unwrap_or("").trim();
            if key.eq_ignore_ascii_case("COUNT") {
                format!("COUNT={count}")
            } else {
                part.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// The instant a `RECURRENCE-ID` names, in the same value space the master's
/// expansion produces its instants in.
///
/// Zoned values resolve through their own zone; floating and date values
/// through the viewer's, which is also the zone [`expand_rule`] iterates
/// floating and all-day masters in — so a well-formed override (RFC 5545
/// requires its value type to match the master's `DTSTART`) lands on exactly
/// the instant the master would have generated.
pub fn instant_of(rid: EventTime, local: Tz) -> Option<DateTime<Utc>> {
    let (naive, tz) = match rid {
        EventTime::Date(d) => (d.and_time(NaiveTime::MIN), local),
        EventTime::Floating(dt) => (dt, local),
        EventTime::Zoned(dt, tz) => (dt, tz),
    };
    tz.from_local_datetime(&naive)
        .earliest()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Expands `event` into every occurrence overlapping `[from, to)`.
///
/// `local` is the viewer's timezone, used to resolve floating times and to place
/// zoned events on the grid.
#[must_use]
pub fn expand(event: &Event, from: DateTime<Utc>, to: DateTime<Utc>, local: Tz) -> Vec<Occurrence> {
    let duration = event.duration(local);

    let Some(rule) = event.rrule.as_deref() else {
        // Non-recurring: emit it if it overlaps at all.
        let start_utc = event.start.to_utc(local);
        if start_utc + duration > from && start_utc < to {
            return vec![occurrence_at(
                event,
                event.start.naive_local(local),
                duration,
                None,
            )];
        }
        return Vec::new();
    };

    match expand_rule(event, rule, from, to, duration, local) {
        Ok(occurrences) => occurrences,
        Err(why) => {
            // A rule we cannot expand should not make the event vanish — fall back
            // to showing just the first instance.
            tracing::warn!(uid = %event.uid, %why, "unusable RRULE; showing first instance only");
            let start_utc = event.start.to_utc(local);
            if start_utc + duration > from && start_utc < to {
                vec![occurrence_at(
                    event,
                    event.start.naive_local(local),
                    duration,
                    None,
                )]
            } else {
                Vec::new()
            }
        }
    }
}

fn expand_rule(
    event: &Event,
    rule: &str,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    duration: Duration,
    local: Tz,
) -> Result<Vec<Occurrence>, String> {
    // The zone the rule iterates in. RFC 5545 recurrence is defined on the
    // *wall clock* of DTSTART's zone, so a weekly 09:00 meeting stays at 09:00
    // across a DST change rather than drifting to 08:00.
    let rule_tz = match event.start {
        EventTime::Zoned(_, tz) => rrule::Tz::Tz(tz),
        EventTime::Date(_) | EventTime::Floating(_) => rrule::Tz::Tz(local),
    };

    let naive_start = match event.start {
        EventTime::Date(d) => d.and_time(NaiveTime::MIN),
        EventTime::Floating(dt) | EventTime::Zoned(dt, _) => dt,
    };

    let dt_start = rule_tz
        .from_local_datetime(&naive_start)
        .earliest()
        .ok_or_else(|| "DTSTART falls in a DST gap".to_owned())?;

    let parsed: RRule<Unvalidated> = rule.parse().map_err(|e| format!("{e}"))?;
    let mut set: RRuleSet = parsed.build(dt_start).map_err(|e| format!("{e}"))?;

    for exdate in &event.exdates {
        if let Some(dt) = rule_tz.from_local_datetime(exdate).earliest() {
            set = set.exdate(dt);
        }
    }

    // An occurrence that *starts* before the window can still overlap it, so
    // widen the lower bound by the event's own duration before querying.
    let query_from = from - duration;
    let result = set
        .after(query_from.with_timezone(&rule_tz))
        .before(to.with_timezone(&rule_tz))
        .all(MAX_OCCURRENCES);

    if result.limited {
        tracing::warn!(
            uid = %event.uid,
            "recurrence hit the {MAX_OCCURRENCES} instance cap for this range"
        );
    }

    let mut out = Vec::with_capacity(result.dates.len());
    for instant in result.dates {
        let utc = instant.with_timezone(&Utc);
        if utc + duration <= from || utc >= to {
            continue;
        }

        // Place all-day and floating instances by wall clock, zoned ones by
        // converting into the viewer's zone.
        let local_start: NaiveDateTime = match event.start {
            EventTime::Date(_) | EventTime::Floating(_) => instant.naive_local(),
            EventTime::Zoned(..) => utc.with_timezone(&local).naive_local(),
        };

        out.push(occurrence_at(event, local_start, duration, Some(utc)));
    }

    Ok(out)
}

fn occurrence_at(
    event: &Event,
    start: NaiveDateTime,
    duration: Duration,
    recurrence_id: Option<DateTime<Utc>>,
) -> Occurrence {
    Occurrence {
        uid: event.uid.clone(),
        calendar_id: event.calendar_id.clone(),
        summary: event.summary.clone(),
        location: event.location.clone(),
        all_day: event.is_all_day(),
        start,
        end: start + duration,
        recurrence_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::event::EventTime;
    use chrono::{Datelike, NaiveDate, Timelike};

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn event_with(start: EventTime, end: EventTime, rrule: Option<&str>) -> Event {
        Event {
            uid: "test-uid".into(),
            calendar_id: "personal".into(),
            summary: "Standup".into(),
            description: None,
            location: None,
            start,
            end,
            rrule: rrule.map(ToOwned::to_owned),
            exdates: Vec::new(),
            alarms: Vec::new(),
            sequence: 0,
            created: None,
            last_modified: None,
            file_name: "test-uid.ics".into(),
            recurrence_id: None,
        }
    }

    fn at(y: i32, m: u32, d: u32, h: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, 0, 0)
            .unwrap()
    }

    #[test]
    fn count_is_read_and_rewritten_without_touching_the_rest() {
        let rule = "FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-1;COUNT=10";
        assert_eq!(count_of(rule), Some(10));
        assert_eq!(
            with_count(rule, 4),
            "FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-1;COUNT=4"
        );
    }

    #[test]
    fn a_rule_without_count_passes_through_with_count_unchanged() {
        let rule = "FREQ=WEEKLY;UNTIL=20261231T000000Z";
        assert_eq!(count_of(rule), None);
        assert_eq!(with_count(rule, 4), rule);
    }

    #[test]
    fn single_event_appears_once() {
        let e = event_with(
            EventTime::Zoned(at(2026, 8, 4, 9), chrono_tz::UTC),
            EventTime::Zoned(at(2026, 8, 4, 10), chrono_tz::UTC),
            None,
        );
        let got = expand(&e, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].start, at(2026, 8, 4, 9));
    }

    #[test]
    fn single_event_outside_range_is_dropped() {
        let e = event_with(
            EventTime::Zoned(at(2026, 6, 4, 9), chrono_tz::UTC),
            EventTime::Zoned(at(2026, 6, 4, 10), chrono_tz::UTC),
            None,
        );
        assert!(expand(&e, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC).is_empty());
    }

    #[test]
    fn weekly_rule_expands_across_the_month() {
        let e = event_with(
            EventTime::Zoned(at(2026, 8, 3, 9), chrono_tz::UTC), // a Monday
            EventTime::Zoned(at(2026, 8, 3, 10), chrono_tz::UTC),
            Some("FREQ=WEEKLY"),
        );
        let got = expand(&e, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC);
        let days: Vec<u32> = got.iter().map(|o| o.start.date().day()).collect();
        assert_eq!(days, vec![3, 10, 17, 24, 31]);
    }

    #[test]
    fn count_limits_the_series() {
        let e = event_with(
            EventTime::Zoned(at(2026, 8, 3, 9), chrono_tz::UTC),
            EventTime::Zoned(at(2026, 8, 3, 10), chrono_tz::UTC),
            Some("FREQ=DAILY;COUNT=3"),
        );
        let got = expand(&e, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC);
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn exdate_removes_an_instance() {
        let mut e = event_with(
            EventTime::Zoned(at(2026, 8, 3, 9), chrono_tz::UTC),
            EventTime::Zoned(at(2026, 8, 3, 10), chrono_tz::UTC),
            Some("FREQ=WEEKLY"),
        );
        e.exdates.push(at(2026, 8, 17, 9));
        let got = expand(&e, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC);
        let days: Vec<u32> = got.iter().map(|o| o.start.date().day()).collect();
        assert_eq!(days, vec![3, 10, 24, 31]);
    }

    #[test]
    fn event_starting_before_the_window_still_shows() {
        // A 3-day event starting 31 Jul must appear when we ask for August.
        let e = event_with(
            EventTime::Date(NaiveDate::from_ymd_opt(2026, 7, 31).unwrap()),
            EventTime::Date(NaiveDate::from_ymd_opt(2026, 8, 3).unwrap()),
            None,
        );
        let got = expand(&e, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC);
        assert_eq!(
            got.len(),
            1,
            "long event overlapping the window was dropped"
        );
    }

    #[test]
    fn weekly_meeting_keeps_its_wall_clock_across_dst() {
        // Athens leaves DST on 2026-10-25. A 09:00 weekly meeting must stay at
        // 09:00 local, not drift to 08:00.
        let e = event_with(
            EventTime::Zoned(at(2026, 10, 19, 9), chrono_tz::Europe::Athens),
            EventTime::Zoned(at(2026, 10, 19, 10), chrono_tz::Europe::Athens),
            Some("FREQ=WEEKLY"),
        );
        let got = expand(
            &e,
            utc(2026, 10, 1),
            utc(2026, 11, 15),
            chrono_tz::Europe::Athens,
        );
        assert!(got.len() >= 3);
        for o in &got {
            assert_eq!(o.start.time(), NaiveTime::from_hms_opt(9, 0, 0).unwrap());
        }
    }

    #[test]
    fn unparseable_rule_falls_back_to_one_instance() {
        let e = event_with(
            EventTime::Zoned(at(2026, 8, 4, 9), chrono_tz::UTC),
            EventTime::Zoned(at(2026, 8, 4, 10), chrono_tz::UTC),
            Some("FREQ=NONSENSE;;;"),
        );
        let got = expand(&e, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC);
        assert_eq!(got.len(), 1, "a broken rule should not hide the event");
    }

    /// A weekly 09:00 series with the 11 Aug instance moved to 14:00 by an
    /// override component.
    fn series_with_override() -> Vec<Event> {
        let master = event_with(
            EventTime::Zoned(at(2026, 8, 4, 9), chrono_tz::UTC),
            EventTime::Zoned(at(2026, 8, 4, 10), chrono_tz::UTC),
            Some("FREQ=WEEKLY"),
        );

        let mut moved = event_with(
            EventTime::Zoned(at(2026, 8, 11, 14), chrono_tz::UTC),
            EventTime::Zoned(at(2026, 8, 11, 15), chrono_tz::UTC),
            None,
        );
        moved.summary = "Standup (moved)".into();
        moved.recurrence_id = Some(EventTime::Zoned(at(2026, 8, 11, 9), chrono_tz::UTC));

        vec![master, moved]
    }

    #[test]
    fn an_override_replaces_the_generated_instance() {
        let got = expand_merged(
            &series_with_override(),
            utc(2026, 8, 1),
            utc(2026, 9, 1),
            chrono_tz::UTC,
        );

        // Four Tuesdays in the window: three generated, one overridden.
        assert_eq!(got.len(), 4);

        let aug_11: Vec<_> = got
            .iter()
            .filter(|o| o.start.date() == NaiveDate::from_ymd_opt(2026, 8, 11).unwrap())
            .collect();
        assert_eq!(
            aug_11.len(),
            1,
            "the replaced instance must not also appear"
        );
        assert_eq!(aug_11[0].start.time().hour(), 14);
        assert_eq!(aug_11[0].summary, "Standup (moved)");
    }

    #[test]
    fn an_override_moved_out_of_the_window_still_suppresses_its_instance() {
        let mut events = series_with_override();
        // The override now lives in September, outside the queried window —
        // exactly what a candidate query would still hand us.
        events[1].start = EventTime::Zoned(at(2026, 9, 2, 14), chrono_tz::UTC);
        events[1].end = EventTime::Zoned(at(2026, 9, 2, 15), chrono_tz::UTC);

        let got = expand_merged(&events, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC);

        // Three generated Tuesdays; the 11th is gone and its replacement is
        // outside the window.
        assert_eq!(got.len(), 3);
        assert!(
            got.iter()
                .all(|o| o.start.date() != NaiveDate::from_ymd_opt(2026, 8, 11).unwrap()),
            "the replaced instance leaked back in"
        );
    }

    #[test]
    fn an_orphan_override_still_appears() {
        // The master fell outside the candidate set — its series ended long
        // ago, say — but the override moved an instance into this window.
        let events = series_with_override().split_off(1);

        let got = expand_merged(&events, utc(2026, 8, 1), utc(2026, 9, 1), chrono_tz::UTC);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].summary, "Standup (moved)");
    }

    #[test]
    fn the_override_occurrence_names_the_instance_it_replaces() {
        let got = expand_merged(
            &series_with_override(),
            utc(2026, 8, 1),
            utc(2026, 9, 1),
            chrono_tz::UTC,
        );
        let moved = got.iter().find(|o| o.summary.ends_with("(moved)")).unwrap();
        // The identity is the *replaced* instant, not the new start — this is
        // what lets a click on the occurrence find the override component.
        assert_eq!(
            moved.recurrence_id,
            Some(utc(2026, 8, 11) + Duration::hours(9))
        );
    }
}

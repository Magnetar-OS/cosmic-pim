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
    use chrono::{Datelike, NaiveDate};

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
        }
    }

    fn at(y: i32, m: u32, d: u32, h: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, 0, 0)
            .unwrap()
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
}

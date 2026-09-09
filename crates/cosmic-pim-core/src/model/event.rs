// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Events and their expanded occurrences.

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;

/// How a `DTSTART`/`DTEND` was written in the source file.
///
/// We keep the original form rather than normalising to UTC so that saving an
/// event back does not rewrite the timezone another tool chose for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventTime {
    /// `DTSTART;VALUE=DATE:20260804` — an all-day event.
    Date(NaiveDate),
    /// `DTSTART:20260804T090000` — floating local time, no zone attached.
    /// Per RFC 5545 this means "9am wherever the viewer is".
    Floating(NaiveDateTime),
    /// `DTSTART;TZID=Europe/Athens:...`, or a UTC `...Z` stamp (`Tz::UTC`).
    Zoned(NaiveDateTime, Tz),
}

impl EventTime {
    #[must_use]
    pub fn is_all_day(&self) -> bool {
        matches!(self, EventTime::Date(_))
    }

    /// The instant this time refers to, resolving floating times against `local`.
    ///
    /// DST gaps and folds are resolved to the earliest valid instant; a spring-forward
    /// gap has no valid local time, so we fall back to a fixed-offset interpretation
    /// rather than dropping the event entirely.
    #[must_use]
    pub fn to_utc(&self, local: Tz) -> DateTime<Utc> {
        match *self {
            EventTime::Date(d) => resolve(d.and_time(NaiveTime::MIN), local),
            EventTime::Floating(dt) => resolve(dt, local),
            EventTime::Zoned(dt, tz) => resolve(dt, tz),
        }
    }

    /// Wall-clock time as the user should see it, in their local zone.
    #[must_use]
    pub fn naive_local(&self, local: Tz) -> NaiveDateTime {
        match *self {
            // All-day and floating times are already wall-clock — converting them
            // through UTC would shift them across a date boundary.
            EventTime::Date(d) => d.and_time(NaiveTime::MIN),
            EventTime::Floating(dt) => dt,
            EventTime::Zoned(..) => self.to_utc(local).with_timezone(&local).naive_local(),
        }
    }

    /// The local calendar date this time falls on.
    #[must_use]
    pub fn date(&self, local: Tz) -> NaiveDate {
        self.naive_local(local).date()
    }

    /// Rebuilds this value with a new wall-clock time, preserving its kind.
    #[must_use]
    pub fn with_naive(&self, dt: NaiveDateTime) -> Self {
        match *self {
            EventTime::Date(_) => EventTime::Date(dt.date()),
            EventTime::Floating(_) => EventTime::Floating(dt),
            EventTime::Zoned(_, tz) => EventTime::Zoned(dt, tz),
        }
    }
}

/// Resolves a wall-clock time in `tz` to an instant, tolerating DST gaps.
fn resolve(dt: NaiveDateTime, tz: Tz) -> DateTime<Utc> {
    use chrono::offset::LocalResult;
    match tz.from_local_datetime(&dt) {
        LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => t.with_timezone(&Utc),
        // Spring-forward gap: nudge forward an hour, which always lands in the
        // post-transition offset.
        LocalResult::None => {
            let shifted = dt + chrono::Duration::hours(1);
            match tz.from_local_datetime(&shifted) {
                LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => t.with_timezone(&Utc),
                LocalResult::None => Utc.from_utc_datetime(&dt),
            }
        }
    }
}

/// How often an event repeats, as far as the built-in editor can express it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Freq {
    #[default]
    Never,
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

impl Freq {
    pub const ALL: &'static [Freq] = &[
        Freq::Never,
        Freq::Daily,
        Freq::Weekly,
        Freq::Monthly,
        Freq::Yearly,
    ];

    fn as_ical(self) -> Option<&'static str> {
        match self {
            Freq::Never => None,
            Freq::Daily => Some("DAILY"),
            Freq::Weekly => Some("WEEKLY"),
            Freq::Monthly => Some("MONTHLY"),
            Freq::Yearly => Some("YEARLY"),
        }
    }
}

/// When a repeating event stops.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RepeatEnd {
    #[default]
    Never,
    After(u32),
    On(NaiveDate),
}

/// The subset of `RRULE` the editor understands.
///
/// Rules with parts we cannot round-trip (`BYDAY`, `BYSETPOS`, …) deliberately
/// fail to parse into this type. [`Event::rrule`] stays the source of truth, so
/// an unsupported rule is preserved verbatim instead of being silently
/// simplified into something the user did not ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recurrence {
    pub freq: Freq,
    pub interval: u16,
    pub end: RepeatEnd,
}

impl Default for Recurrence {
    fn default() -> Self {
        Self {
            freq: Freq::Never,
            interval: 1,
            end: RepeatEnd::Never,
        }
    }
}

impl Recurrence {
    /// Renders to an `RRULE` value, or `None` when the event does not repeat.
    #[must_use]
    pub fn to_rrule(self) -> Option<String> {
        let freq = self.freq.as_ical()?;
        let mut out = format!("FREQ={freq}");
        if self.interval > 1 {
            out.push_str(&format!(";INTERVAL={}", self.interval));
        }
        match self.end {
            RepeatEnd::Never => {}
            RepeatEnd::After(n) => out.push_str(&format!(";COUNT={n}")),
            RepeatEnd::On(d) => out.push_str(&format!(
                ";UNTIL={:04}{:02}{:02}T235959Z",
                d.year(),
                d.month(),
                d.day()
            )),
        }
        Some(out)
    }

    /// Parses an `RRULE` value, returning `None` if it uses parts the editor
    /// cannot represent.
    #[must_use]
    pub fn parse(rule: &str) -> Option<Self> {
        let mut freq = None;
        let mut interval = 1u16;
        let mut end = RepeatEnd::Never;

        for part in rule.trim().split(';').filter(|p| !p.is_empty()) {
            let (key, value) = part.split_once('=')?;
            match key.trim().to_ascii_uppercase().as_str() {
                "FREQ" => {
                    freq = Some(match value.trim().to_ascii_uppercase().as_str() {
                        "DAILY" => Freq::Daily,
                        "WEEKLY" => Freq::Weekly,
                        "MONTHLY" => Freq::Monthly,
                        "YEARLY" => Freq::Yearly,
                        // SECONDLY/MINUTELY/HOURLY are valid iCalendar but have no
                        // editor affordance, so treat them as unsupported.
                        _ => return None,
                    });
                }
                "INTERVAL" => interval = value.trim().parse().ok()?,
                "COUNT" => end = RepeatEnd::After(value.trim().parse().ok()?),
                "UNTIL" => {
                    let v = value.trim();
                    let date = NaiveDate::parse_from_str(&v[..v.len().min(8)], "%Y%m%d").ok()?;
                    end = RepeatEnd::On(date);
                }
                // WKST only shifts week boundaries; harmless to drop for the
                // frequencies we support.
                "WKST" => {}
                // Anything else (BYDAY, BYMONTHDAY, BYSETPOS, …) is beyond us.
                _ => return None,
            }
        }

        Some(Self {
            freq: freq?,
            interval: interval.max(1),
            end,
        })
    }
}

/// One `ATTENDEE` or `ORGANIZER` on an event.
///
/// The address is what scheduling needs — free/busy asks a server about
/// addresses — but the line it arrived on is kept too, because these carry
/// parameters this model does not interpret (`DELEGATED-TO`, `MEMBER`,
/// `SENT-BY`, `CUTYPE`, …) and rewriting one from the fields below would
/// quietly drop them. A person added here rather than parsed has no `raw`,
/// and is written from the fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attendee {
    /// Lowercased, `mailto:` stripped — the form `query_availability` wants.
    pub email: String,
    /// `CN=`, when the source gave one.
    pub name: Option<String>,
    /// `PARTSTAT=`, verbatim: who has accepted.
    pub partstat: Option<String>,
    /// The content line exactly as it was read, if it was read rather than
    /// built here.
    pub raw: Option<String>,
}

impl Attendee {
    /// A new attendee this app is adding, with no source line behind it.
    #[must_use]
    pub fn new(email: &str, name: Option<String>) -> Self {
        Self {
            email: normalise_address(email),
            name,
            partstat: None,
            raw: None,
        }
    }

    /// How to show them: their name if the source gave one, else the address.
    #[must_use]
    pub fn display(&self) -> &str {
        match self.name.as_deref().filter(|n| !n.trim().is_empty()) {
            Some(name) => name,
            None => &self.email,
        }
    }

    /// Whether they have accepted. `None` — no `PARTSTAT` — is
    /// "needs action" per RFC 5545, not "accepted".
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.partstat
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case("ACCEPTED"))
    }
}

/// `MAILTO:Bob@Example.com` → `bob@example.com`.
///
/// Addresses are compared against what a server echoes back in a free/busy
/// reply, which need not match the case or the prefix that was sent.
#[must_use]
pub fn normalise_address(value: &str) -> String {
    let trimmed = value.trim();
    let without = trimmed
        .strip_prefix("mailto:")
        .or_else(|| trimmed.strip_prefix("MAILTO:"))
        .unwrap_or(trimmed);
    without.trim().to_lowercase()
}

/// A single `VEVENT`, as stored in one `.ics` file.
#[derive(Clone, Debug)]
pub struct Event {
    pub uid: String,
    /// The collection directory this event lives in.
    pub calendar_id: String,
    pub summary: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub start: EventTime,
    /// Exclusive, per RFC 5545. An all-day event on 4 Aug ends on 5 Aug.
    pub end: EventTime,
    /// Raw `RRULE` value, preserved verbatim so unsupported rules survive a
    /// round-trip through this app.
    pub rrule: Option<String>,
    /// `EXDATE` values — occurrences deleted from a series.
    pub exdates: Vec<NaiveDateTime>,
    /// `VALARM` triggers, as offsets from the event's start. Negative means
    /// "before", which is what almost every real alarm is.
    pub alarms: Vec<chrono::Duration>,
    pub sequence: i32,
    pub created: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    /// File name within the collection directory, e.g. `<uid>.ics`.
    pub file_name: String,
    /// `RECURRENCE-ID` — set when this VEVENT is an override of one instance
    /// of a series, naming the instance it replaces in the master's `DTSTART`
    /// value space. `None` for a one-off event or a series master. An override
    /// lives in the same file as its master, under the same UID.
    pub recurrence_id: Option<EventTime>,
    /// Who is invited. Order is the source's.
    pub attendees: Vec<Attendee>,
    /// Who called the meeting.
    pub organizer: Option<Attendee>,
    /// Every other content line of this VEVENT, verbatim and in document
    /// order — `STATUS`, `TRANSP`, `CLASS`, `URL`, `CATEGORIES`, `X-` and
    /// anything else this model does not interpret.
    ///
    /// It exists because writing an event re-serialises it from these fields
    /// rather than editing the file in place, so a property with nowhere to
    /// live here would simply vanish on the next save. Contacts do not have
    /// this problem: `vcard.rs` edits through [`crate::patch`], naming only
    /// the fields that changed, and everything else passes through untouched.
    /// Moving the calendar write path onto the patcher the same way would
    /// make this field unnecessary — and would also fix what it cannot reach,
    /// namely parameters on properties that *are* modelled here
    /// (`SUMMARY;LANGUAGE=en-us` comes back as plain `SUMMARY`).
    ///
    /// Nested components are not collected: `VALARM` blocks are handled
    /// separately, and capturing them here would emit each alarm twice.
    pub other: Vec<String>,
}

impl Event {
    /// A new event occupying `date` from `hour` for one hour.
    #[must_use]
    pub fn draft(calendar_id: &str, start: NaiveDateTime, local: Tz) -> Self {
        let uid = format!("{}@cosmic-pim", uuid::Uuid::new_v4());
        Self {
            file_name: format!("{uid}.ics"),
            uid,
            calendar_id: calendar_id.to_owned(),
            summary: String::new(),
            description: None,
            location: None,
            start: EventTime::Zoned(start, local),
            end: EventTime::Zoned(start + chrono::Duration::hours(1), local),
            rrule: None,
            exdates: Vec::new(),
            alarms: Vec::new(),
            sequence: 0,
            created: Some(Utc::now()),
            last_modified: Some(Utc::now()),
            recurrence_id: None,
            attendees: Vec::new(),
            organizer: None,
            other: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_all_day(&self) -> bool {
        self.start.is_all_day()
    }

    #[must_use]
    pub fn is_recurring(&self) -> bool {
        self.rrule.is_some()
    }

    /// The editor's view of this event's repeat rule. `None` means the rule
    /// exists but is too complex to edit here.
    #[must_use]
    pub fn recurrence(&self) -> Option<Recurrence> {
        match self.rrule.as_deref() {
            None => Some(Recurrence::default()),
            Some(rule) => Recurrence::parse(rule),
        }
    }

    /// Duration between start and end, used to place expanded occurrences.
    #[must_use]
    pub fn duration(&self, local: Tz) -> chrono::Duration {
        let d = self.end.to_utc(local) - self.start.to_utc(local);
        if d <= chrono::Duration::zero() {
            // Guard against malformed files where DTEND <= DTSTART.
            if self.is_all_day() {
                chrono::Duration::days(1)
            } else {
                chrono::Duration::hours(1)
            }
        } else {
            d
        }
    }
}

/// One materialised instance of an event, ready to render.
///
/// Times are local wall-clock: this is what the grid positions against, and it
/// keeps all-day events from sliding across a date boundary near midnight.
#[derive(Clone, Debug)]
pub struct Occurrence {
    pub uid: String,
    pub calendar_id: String,
    pub summary: String,
    pub location: Option<String>,
    pub all_day: bool,
    pub start: NaiveDateTime,
    /// Exclusive.
    pub end: NaiveDateTime,
    /// `None` for a one-off event; for a series member, the instant identifying
    /// which instance this is.
    pub recurrence_id: Option<DateTime<Utc>>,
}

impl Occurrence {
    /// Whether this occurrence covers any part of `date`.
    #[must_use]
    pub fn covers(&self, date: NaiveDate) -> bool {
        let day_start = date.and_time(NaiveTime::MIN);
        let day_end = day_start + chrono::Duration::days(1);
        self.start < day_end && self.end > day_start
    }

    /// Sort key: all-day events first, then by start, then by title for stability.
    #[must_use]
    pub fn sort_key(&self) -> (bool, NaiveDateTime, String) {
        (!self.all_day, self.start, self.summary.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn dt(y: i32, m: u32, d: u32, h: u32, min: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, min, 0)
            .unwrap()
    }

    #[test]
    fn recurrence_roundtrips_simple_rules() {
        let cases = [
            Recurrence {
                freq: Freq::Daily,
                interval: 1,
                end: RepeatEnd::Never,
            },
            Recurrence {
                freq: Freq::Weekly,
                interval: 2,
                end: RepeatEnd::After(10),
            },
            Recurrence {
                freq: Freq::Monthly,
                interval: 1,
                end: RepeatEnd::On(NaiveDate::from_ymd_opt(2026, 12, 31).unwrap()),
            },
        ];
        for c in cases {
            let s = c.to_rrule().expect("repeats");
            assert_eq!(Recurrence::parse(&s), Some(c), "roundtrip failed for {s}");
        }
    }

    #[test]
    fn never_has_no_rrule() {
        assert_eq!(Recurrence::default().to_rrule(), None);
    }

    #[test]
    fn complex_rules_are_rejected_not_simplified() {
        // The point: we must NOT return Some(Weekly) here and drop BYDAY on save.
        assert_eq!(Recurrence::parse("FREQ=WEEKLY;BYDAY=MO,WE,FR"), None);
        assert_eq!(Recurrence::parse("FREQ=MONTHLY;BYSETPOS=-1;BYDAY=FR"), None);
        assert_eq!(Recurrence::parse("FREQ=HOURLY"), None);
    }

    #[test]
    fn wkst_is_tolerated() {
        assert_eq!(
            Recurrence::parse("FREQ=WEEKLY;WKST=MO"),
            Some(Recurrence {
                freq: Freq::Weekly,
                interval: 1,
                end: RepeatEnd::Never
            })
        );
    }

    #[test]
    fn all_day_times_do_not_shift_across_zones() {
        // An all-day event on the 4th must read as the 4th in any zone.
        let t = EventTime::Date(NaiveDate::from_ymd_opt(2026, 8, 4).unwrap());
        for tz in [
            chrono_tz::UTC,
            chrono_tz::Pacific::Kiritimati,
            chrono_tz::Pacific::Midway,
        ] {
            assert_eq!(
                t.date(tz),
                NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
                "shifted in {tz}"
            );
        }
    }

    #[test]
    fn zoned_times_convert_to_local_wall_clock() {
        // Athens is EEST (UTC+3) in August, so 12:00 local is 09:00 UTC.
        let t = EventTime::Zoned(dt(2026, 8, 4, 12, 0), chrono_tz::Europe::Athens);
        assert_eq!(t.naive_local(chrono_tz::UTC), dt(2026, 8, 4, 9, 0));
        // …and 14:00 in Kyiv (EEST too) is 11:00 UTC.
        let t = EventTime::Zoned(dt(2026, 8, 4, 14, 0), chrono_tz::Europe::Kiev);
        assert_eq!(t.naive_local(chrono_tz::UTC), dt(2026, 8, 4, 11, 0));
    }

    #[test]
    fn dst_gap_does_not_panic() {
        // 02:30 on 2026-03-29 does not exist in Athens (clocks jump 03:00 -> 04:00).
        let t = EventTime::Zoned(dt(2026, 3, 29, 3, 30), chrono_tz::Europe::Athens);
        let _ = t.to_utc(chrono_tz::Europe::Athens);
    }

    #[test]
    fn occurrence_covers_spanning_days() {
        let o = Occurrence {
            uid: "x".into(),
            calendar_id: "c".into(),
            summary: "s".into(),
            location: None,
            all_day: false,
            start: dt(2026, 8, 4, 22, 0),
            end: dt(2026, 8, 5, 2, 0),
            recurrence_id: None,
        };
        assert!(o.covers(NaiveDate::from_ymd_opt(2026, 8, 4).unwrap()));
        assert!(o.covers(NaiveDate::from_ymd_opt(2026, 8, 5).unwrap()));
        assert!(!o.covers(NaiveDate::from_ymd_opt(2026, 8, 6).unwrap()));
        // End is exclusive: an event ending at midnight does not touch the next day.
        let o2 = Occurrence {
            end: dt(2026, 8, 5, 0, 0),
            ..o
        };
        assert!(!o2.covers(NaiveDate::from_ymd_opt(2026, 8, 5).unwrap()));
    }
}

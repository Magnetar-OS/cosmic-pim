// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The vdir layout: one directory per calendar, one `.ics` file per event.
//!
//! This is the layout `vdirsyncer` and `khal` use, which is the whole point —
//! events written here can be synced to a CalDAV server by pointing vdirsyncer
//! at the same directory, with no export step.
//!
//! ```text
//! ~/.local/share/calendars/
//! ├── personal/
//! │   ├── displayname        "Personal"
//! │   ├── color              "#2d7dd2"
//! │   ├── 9f3c…-a1.ics
//! │   └── b722…-04.ics
//! └── work/
//!     └── …
//! ```

use super::StoreError;
use crate::atomic;
use crate::model::{CalendarMeta, Event, Rgb, Todo};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

// The iCalendar text layer lives in `crate::ical` so that the CalDAV engine and
// this vdir reader cannot drift in how they interpret the same bytes. These
// re-exports keep `vdir::parse_ics(..)` and friends working for existing
// callers.
pub use crate::ical::{
    format_iso_duration, parse_ics, parse_iso_duration, parse_todos, remove_vevent, to_ics,
    todo_to_ics, upsert_vevent, upsert_vtodo,
};

/// Where calendars live by default: `$XDG_DATA_HOME/calendars`.
///
/// `COSMIC_PIM_CALENDAR_DIR` overrides it, which is how the tests point at a tempdir.
#[must_use]
pub fn default_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("COSMIC_PIM_CALENDAR_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("calendars")
}

/// Lists every collection under `root`, sorted by display name.
///
/// Unreadable directories are skipped with a warning rather than failing the
/// whole load — one bad collection should not empty the app.
#[must_use]
pub fn collections(root: &Path) -> Vec<CalendarMeta> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };

    let mut out: Vec<CalendarMeta> = entries
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter_map(|e| CalendarMeta::load(&e.path()))
        .collect();

    out.sort_by_key(|c| c.name.to_lowercase());
    out
}

/// Creates a new collection directory with its metadata files.
pub fn create_collection(root: &Path, name: &str, color: Rgb) -> Result<CalendarMeta, StoreError> {
    std::fs::create_dir_all(root)?;

    let base = slugify(name);
    let mut dir = root.join(&base);
    let mut n = 2;
    while dir.exists() {
        dir = root.join(format!("{base}-{n}"));
        n += 1;
    }
    std::fs::create_dir(&dir)?;

    let meta = CalendarMeta {
        id: dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&base)
            .to_owned(),
        name: name.trim().to_owned(),
        color,
        path: dir,
        read_only: false,
    };
    meta.save_meta()?;
    Ok(meta)
}

/// Turns a display name into a safe directory name.
fn slugify(name: &str) -> String {
    let s: String = name
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();

    let s = s
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    if s.is_empty() {
        "calendar".to_owned()
    } else {
        s.chars().take(64).collect()
    }
}

/// Reads every event in a collection.
///
/// Malformed files are logged and skipped; a single corrupt `.ics` should not
/// hide the rest of the calendar.
#[must_use]
pub fn read_collection(meta: &CalendarMeta) -> Vec<Event> {
    let Ok(entries) = std::fs::read_dir(&meta.path) else {
        tracing::warn!(path = %meta.path.display(), "cannot read collection");
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("ics") {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => out.extend(parse_ics(&text, &meta.id, file_name)),
            Err(why) => tracing::warn!(path = %path.display(), %why, "cannot read event file"),
        }
    }
    out
}

/// Reads every task in a collection.
///
/// A collection may hold events, tasks, or both: the same `.ics` file format
/// carries either, and CalDAV servers differ on whether they separate them. A
/// file holding only VEVENTs simply yields no tasks here, and vice versa, so
/// both readers can run over the same directory without interfering.
///
/// Unlike events, tasks are not put through the SQLite index. The index exists
/// to make *range* queries over recurring occurrences cheap; a task list is
/// read whole, is small, and has no expansion step, so an index would be
/// bookkeeping with nothing to buy.
#[must_use]
pub fn read_todos(meta: &CalendarMeta) -> Vec<Todo> {
    let Ok(entries) = std::fs::read_dir(&meta.path) else {
        tracing::warn!(path = %meta.path.display(), "cannot read collection");
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("ics") {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => out.extend(parse_todos(&text, &meta.id, file_name)),
            Err(why) => tracing::warn!(path = %path.display(), %why, "cannot read task file"),
        }
    }
    out
}

/// Removes one record from its file, deleting the file only when nothing is
/// left in it.
///
/// A `.ics` may hold several records — two tasks, an imported pair of events,
/// a series beside an unrelated event — so unlinking the file to delete one of
/// them takes the others with it. Rewrite when something remains; unlink when
/// nothing does, because an empty calendar document is not worth keeping.
pub fn remove_record(
    meta: &CalendarMeta,
    file_name: &str,
    component: &str,
    uid: &str,
) -> Result<(), StoreError> {
    if meta.read_only {
        return Err(StoreError::ReadOnly(meta.name.clone()));
    }
    let path = meta.path.join(file_name);
    match std::fs::read_to_string(&path) {
        Ok(text) => match crate::ical::remove_by_uid(&text, component, uid) {
            Some(rest) => atomic::write(&path, &rest, None)
                .map(|_| ())
                .map_err(Into::into),
            // Nothing of value would be left, or the record was not in there.
            None => delete_event(meta, file_name),
        },
        // Already gone; deleting what is not there is not an error a user can
        // act on.
        Err(why) if why.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(why) => Err(why.into()),
    }
}

/// Writes a task to its collection, atomically.
///
/// An existing document is patched, never replaced. A `.ics` may hold more
/// than one VTODO, so serialising this task over the whole file would delete
/// the others outright — along with any VTIMEZONE and everything the model
/// does not carry. Only a file that does not exist yet is written from the
/// model, where there is nothing to lose.
pub fn write_todo(meta: &CalendarMeta, todo: &Todo) -> Result<(), StoreError> {
    if meta.read_only {
        return Err(StoreError::ReadOnly(meta.name.clone()));
    }
    let target = meta.path.join(&todo.file_name);
    let text = match std::fs::read_to_string(&target) {
        Ok(existing) if !existing.trim().is_empty() => upsert_vtodo(&existing, todo),
        _ => todo_to_ics(todo),
    };
    atomic::write(&target, &text, None)
        .map(|_| ())
        .map_err(Into::into)
}

/// Serialises every event in a collection into a single iCalendar document.
#[must_use]
pub fn export_collection(meta: &CalendarMeta) -> String {
    // The zones come from the files themselves: the model has no field for a
    // VTIMEZONE, so an export built from events alone referenced zones it
    // never defined.
    let mut timezones = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(&meta.path)
        .into_iter()
        .flatten()
        .flatten()
    {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "ics")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            timezones.extend(crate::ical::timezones_of(&text));
        }
    }
    crate::ical::to_ics_collection(&meta.name, &read_collection(meta), &timezones)
}

/// Writes an event to its collection, replacing any existing file.
///
/// Goes through [`crate::atomic::write`], so the write is durable (both the
/// data and the rename are fsynced) and a reader — vdirsyncer, khal, our own
/// watcher — never observes a half-written `.ics`.
///
/// This is the unguarded form: it always wins. Use [`write_event_if_unchanged`]
/// anywhere a second writer might be touching the same file.
pub fn write_event(meta: &CalendarMeta, event: &Event) -> Result<(), StoreError> {
    write_event_if_unchanged(meta, event, None).map(|_| ())
}

/// Writes an event, refusing to clobber a file that changed since it was read.
///
/// `expected` is the [`atomic::FileState`] the caller got when it last read the
/// file. If the file on disk no longer matches, the write is refused with
/// [`StoreError::Conflict`] and the incoming version is preserved next to the
/// target as a `.conflict` file — neither side is lost.
///
/// This exists for the sync engine. A CalDAV pull and a user edit race on the
/// same `.ics` routinely, and "last writer wins" silently destroys whichever
/// one lost, with no trace and no way to recover it.
pub fn write_event_if_unchanged(
    meta: &CalendarMeta,
    event: &Event,
    expected: Option<atomic::FileState>,
) -> Result<atomic::FileState, StoreError> {
    if meta.read_only {
        return Err(StoreError::ReadOnly(meta.name.clone()));
    }

    let target = meta.path.join(&event.file_name);

    // A recurring event's overrides share the file. Serialising the whole file
    // from this one event would delete them, so an existing document is
    // patched component-wise: only the VEVENT whose RECURRENCE-ID matches is
    // regenerated, and the rest passes through byte-for-byte.
    let text = match std::fs::read_to_string(&target) {
        Ok(existing) if !existing.trim().is_empty() => upsert_vevent(&existing, event),
        _ => to_ics(event),
    };

    atomic::write(&target, &text, expected).map_err(Into::into)
}

/// The concurrency token for an event's file, for a caller that intends to
/// write it back later via [`write_event_if_unchanged`].
pub fn event_file_state(
    meta: &CalendarMeta,
    file_name: &str,
) -> Result<Option<atomic::FileState>, StoreError> {
    atomic::state_of(&meta.path.join(file_name)).map_err(Into::into)
}

/// Deletes an event's file. A file that is already gone is not an error.
pub fn delete_event(meta: &CalendarMeta, file_name: &str) -> Result<(), StoreError> {
    if meta.read_only {
        return Err(StoreError::ReadOnly(meta.name.clone()));
    }
    match std::fs::remove_file(meta.path.join(file_name)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Last-modified time of a collection's newest file, used to spot external edits.
#[must_use]
pub fn collection_mtime(meta: &CalendarMeta) -> Option<DateTime<Utc>> {
    let entries = std::fs::read_dir(&meta.path).ok()?;
    entries
        .filter_map(Result::ok)
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .max()
        .map(DateTime::<Utc>::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EventTime, Rgb};
    use chrono::NaiveDate;

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn slugify_makes_safe_directory_names() {
        assert_eq!(slugify("Personal"), "personal");
        assert_eq!(slugify("Work / Projects"), "work-projects");
        assert_eq!(slugify("  ../../etc/passwd  "), "etc-passwd");
        assert_eq!(slugify("🎉"), "calendar");
        assert_eq!(slugify(""), "calendar");
    }

    #[test]
    fn create_and_list_collections() {
        let root = temp_root();
        let a = create_collection(root.path(), "Personal", Rgb(0x2d, 0x7d, 0xd2)).unwrap();
        let b = create_collection(root.path(), "Work", Rgb(0x24, 0x9b, 0x74)).unwrap();

        let found = collections(root.path());
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "Personal");
        assert_eq!(found[1].name, "Work");
        assert_eq!(found[0].color, a.color);
        assert_eq!(found[1].id, b.id);
    }

    #[test]
    fn duplicate_names_get_distinct_directories() {
        let root = temp_root();
        let a = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        let b = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(collections(root.path()).len(), 2);
    }

    #[test]
    fn event_roundtrips_through_disk() {
        let root = temp_root();
        let cal = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 30, 0)
                .unwrap(),
            chrono_tz::Europe::Athens,
        );
        event.summary = "Standup".into();
        event.location = Some("Room 3".into());
        event.description = Some("Daily sync".into());
        event.rrule = Some("FREQ=WEEKLY".into());

        write_event(&cal, &event).unwrap();

        let read = read_collection(&cal);
        assert_eq!(read.len(), 1);
        let got = &read[0];
        assert_eq!(got.uid, event.uid);
        assert_eq!(got.summary, "Standup");
        assert_eq!(got.location.as_deref(), Some("Room 3"));
        assert_eq!(got.description.as_deref(), Some("Daily sync"));
        assert_eq!(got.rrule.as_deref(), Some("FREQ=WEEKLY"));
        assert_eq!(got.start, event.start);
        assert_eq!(got.end, event.end);
    }

    #[test]
    fn all_day_events_keep_date_semantics() {
        let root = temp_root();
        let cal = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        event.summary = "Holiday".into();
        event.start = EventTime::Date(NaiveDate::from_ymd_opt(2026, 8, 4).unwrap());
        event.end = EventTime::Date(NaiveDate::from_ymd_opt(2026, 8, 5).unwrap());

        write_event(&cal, &event).unwrap();
        let got = read_collection(&cal).remove(0);

        assert!(got.is_all_day(), "all-day event came back as timed");
        assert_eq!(
            got.start,
            EventTime::Date(NaiveDate::from_ymd_opt(2026, 8, 4).unwrap())
        );
    }

    #[test]
    fn timezone_survives_a_roundtrip() {
        let root = temp_root();
        let cal = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::Europe::Athens,
        );
        event.summary = "Meeting".into();
        write_event(&cal, &event).unwrap();

        let got = read_collection(&cal).remove(0);
        assert_eq!(
            got.start,
            EventTime::Zoned(
                NaiveDate::from_ymd_opt(2026, 8, 4)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap(),
                chrono_tz::Europe::Athens
            ),
            "TZID was not preserved"
        );
    }

    #[test]
    fn missing_dtend_gets_a_sensible_default() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
                   BEGIN:VEVENT\r\nUID:x@test\r\nDTSTART:20260804T090000Z\r\n\
                   SUMMARY:No end\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let events = parse_ics(ics, "personal", "x.ics");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].end,
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
    fn corrupt_file_does_not_hide_siblings() {
        let root = temp_root();
        let cal = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();

        std::fs::write(cal.path.join("broken.ics"), "this is not iCalendar at all").unwrap();

        let mut event = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        event.summary = "Good".into();
        write_event(&cal, &event).unwrap();

        let read = read_collection(&cal);
        assert_eq!(read.len(), 1, "a corrupt file swallowed the valid one");
        assert_eq!(read[0].summary, "Good");
    }

    #[test]
    fn exdates_are_parsed_and_written() {
        let root = temp_root();
        let cal = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 3)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        event.summary = "Standup".into();
        event.rrule = Some("FREQ=WEEKLY".into());
        event.exdates = vec![
            NaiveDate::from_ymd_opt(2026, 8, 17)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
        ];

        write_event(&cal, &event).unwrap();
        let got = read_collection(&cal).remove(0);
        assert_eq!(got.exdates, event.exdates);
    }

    #[test]
    fn parses_the_iso_durations_alarms_use() {
        use chrono::Duration;
        assert_eq!(parse_iso_duration("-PT15M"), Some(Duration::minutes(-15)));
        assert_eq!(parse_iso_duration("-PT1H"), Some(Duration::hours(-1)));
        assert_eq!(parse_iso_duration("PT30M"), Some(Duration::minutes(30)));
        assert_eq!(parse_iso_duration("-P1D"), Some(Duration::days(-1)));
        assert_eq!(parse_iso_duration("-P1W"), Some(Duration::weeks(-1)));
        assert_eq!(parse_iso_duration("-PT1H30M"), Some(Duration::minutes(-90)));
        assert_eq!(parse_iso_duration("PT0S"), Some(Duration::zero()));
    }

    #[test]
    fn rejects_durations_it_cannot_represent() {
        assert_eq!(parse_iso_duration(""), None);
        assert_eq!(parse_iso_duration("15M"), None, "missing the P prefix");
        assert_eq!(parse_iso_duration("-PT15"), None, "missing the unit");
        assert_eq!(parse_iso_duration("nonsense"), None);
    }

    #[test]
    fn iso_durations_roundtrip() {
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
                "roundtrip failed for {text}"
            );
        }
    }

    #[test]
    fn reads_an_alarm_from_a_file() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
                   BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\n\
                   DTEND:20260804T100000Z\r\nSUMMARY:Standup\r\n\
                   BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Standup\r\n\
                   TRIGGER:-PT10M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

        let events = parse_ics(ics, "personal", "a.ics");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].alarms, vec![chrono::Duration::minutes(-10)]);
    }

    #[test]
    fn alarms_survive_a_roundtrip_through_disk() {
        let root = temp_root();
        let cal = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        event.summary = "Standup".into();
        event.alarms = vec![
            chrono::Duration::minutes(-60),
            chrono::Duration::minutes(-10),
        ];

        write_event(&cal, &event).unwrap();
        let got = read_collection(&cal).remove(0);

        assert_eq!(got.alarms, event.alarms, "alarms were lost on save");
    }

    #[test]
    fn an_event_without_alarms_gets_none() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
                   BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\n\
                   SUMMARY:Standup\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(parse_ics(ics, "personal", "a.ics")[0].alarms.is_empty());
    }

    #[test]
    fn delete_is_idempotent() {
        let root = temp_root();
        let cal = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        assert!(delete_event(&cal, "not-there.ics").is_ok());
    }

    #[test]
    fn writes_leave_no_temp_files_behind() {
        let root = temp_root();
        let cal = create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        let mut event = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        event.summary = "X".into();
        write_event(&cal, &event).unwrap();

        let temps: Vec<_> = std::fs::read_dir(&cal.path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(temps.is_empty(), "temp file left in the collection");
    }
}

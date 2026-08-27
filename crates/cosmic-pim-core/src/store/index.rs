// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! A rebuildable SQLite index over the vdir.
//!
//! The `.ics` files are the source of truth; this is purely a cache, and
//! deleting it costs nothing but a rescan. It exists so navigating between
//! months does not mean re-reading and re-parsing every file on disk.
//!
//! Range queries return *candidate* events — anything that could overlap the
//! window — which the caller then expands with [`crate::model::expand`]. The
//! index deliberately does not cache expanded occurrences: recurrence expansion
//! is cheap, and caching it would mean invalidating on timezone and DST changes
//! as well as on edits.

use super::StoreError;
use crate::model::{CalendarMeta, Event, EventTime};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Bumped whenever the schema changes; a mismatch wipes and rebuilds the cache.
const SCHEMA_VERSION: i64 = 3;

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS events (
    calendar_id TEXT    NOT NULL,
    file_name   TEXT    NOT NULL,
    uid         TEXT    NOT NULL,
    summary     TEXT    NOT NULL,
    description TEXT,
    location    TEXT,
    start_kind  INTEGER NOT NULL,
    start_naive INTEGER NOT NULL,
    start_tz    TEXT,
    end_kind    INTEGER NOT NULL,
    end_naive   INTEGER NOT NULL,
    end_tz      TEXT,
    rrule       TEXT,
    exdates     TEXT    NOT NULL,
    alarms      TEXT    NOT NULL DEFAULT '',
    sequence    INTEGER NOT NULL,
    created     INTEGER,
    modified    INTEGER,
    start_utc   INTEGER NOT NULL,
    end_utc     INTEGER NOT NULL,
    until_utc   INTEGER,
    rid_kind    INTEGER NOT NULL DEFAULT -1,
    rid_naive   INTEGER NOT NULL DEFAULT 0,
    rid_tz      TEXT,
    -- The RID columns are part of the key: a series master and its overrides
    -- share (calendar_id, file_name, uid) and differ only in RECURRENCE-ID.
    -- Without them the last component read would silently overwrite the rest.
    PRIMARY KEY (calendar_id, file_name, uid, rid_kind, rid_naive)
);

CREATE INDEX IF NOT EXISTS events_range    ON events (start_utc, end_utc);
CREATE INDEX IF NOT EXISTS events_calendar ON events (calendar_id);
CREATE INDEX IF NOT EXISTS events_uid      ON events (calendar_id, uid);

CREATE TABLE IF NOT EXISTS files (
    calendar_id TEXT    NOT NULL,
    file_name   TEXT    NOT NULL,
    mtime_ns    INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    PRIMARY KEY (calendar_id, file_name)
);

";

/// Created before anything else, so the stored schema version can be read back
/// even when the data tables are about to be dropped.
const META_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

/// Wipes the cached data so it can be recreated at the current schema.
const DROP_DATA: &str = r"
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS files;
";

/// Columns every query depends on. Checked against the live table at open time.
const EXPECTED_COLUMNS: &[&str] = &[
    "calendar_id",
    "file_name",
    "uid",
    "summary",
    "description",
    "location",
    "start_kind",
    "start_naive",
    "start_tz",
    "end_kind",
    "end_naive",
    "end_tz",
    "rrule",
    "exdates",
    "alarms",
    "sequence",
    "created",
    "modified",
    "start_utc",
    "end_utc",
    "until_utc",
];

const KIND_DATE: i64 = 0;
const KIND_FLOATING: i64 = 1;
const KIND_ZONED: i64 = 2;

pub struct Index {
    conn: Connection,
    /// Timezone the cached `start_utc`/`end_utc` columns were resolved against.
    /// Floating and all-day times depend on it, so a change invalidates the cache.
    local: Tz,
}

/// Where the cache lives: `$XDG_CACHE_HOME/cosmic-pim/index.sqlite`.
#[must_use]
pub fn default_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("cosmic-pim")
        .join("index.sqlite")
}

impl Index {
    /// Opens (or creates) the index, rebuilding it if the schema or timezone changed.
    pub fn open(path: &Path, local: Tz) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        // WAL keeps a concurrent reader (the watcher) from blocking writes, and
        // NORMAL sync is right for a cache we can always rebuild.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // The app, the applet, the daemon, and the launcher plugin all open this
        // cache. WAL lets them read concurrently, but writers still serialise —
        // without a busy timeout the loser gets SQLITE_BUSY instead of waiting.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;

        // The version has to be readable before the data tables are touched, so
        // `meta` is created on its own first.
        conn.execute_batch(META_SCHEMA)?;

        let mut index = Self { conn, local };

        let stored_version: Option<i64> =
            index.meta("schema_version")?.and_then(|v| v.parse().ok());
        let stored_tz = index.meta("timezone")?;

        // The recorded version is not trusted on its own. This is a cache, and a
        // half-applied upgrade — the version stamped but the table not rebuilt —
        // would otherwise fail on every query with no way to recover. Checking the
        // real columns costs one pragma and makes the cache self-healing.
        let stale = stored_version != Some(SCHEMA_VERSION)
            || stored_tz.as_deref() != Some(local.name())
            || !index.has_expected_columns()?;

        if stale {
            tracing::info!(
                from = ?stored_version,
                to = SCHEMA_VERSION,
                "index is stale (schema or timezone changed); rebuilding"
            );
            // Drop rather than DELETE. This is a cache, so there is nothing to
            // migrate — and a plain `CREATE TABLE IF NOT EXISTS` over an older
            // database would silently keep the old columns and fail on first write.
            index.conn.execute_batch(DROP_DATA)?;
        }

        index.conn.execute_batch(SCHEMA)?;

        if stale {
            index.set_meta("schema_version", &SCHEMA_VERSION.to_string())?;
            index.set_meta("timezone", local.name())?;
        }

        Ok(index)
    }

    /// An in-memory index, used by tests.
    #[cfg(test)]
    pub fn in_memory(local: Tz) -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(META_SCHEMA)?;
        conn.execute_batch(SCHEMA)?;
        let mut index = Self { conn, local };
        index.set_meta("schema_version", &SCHEMA_VERSION.to_string())?;
        index.set_meta("timezone", local.name())?;
        Ok(index)
    }

    /// Whether the `events` table on disk actually has the columns this build
    /// writes. A missing table counts as stale, which is what we want on a first run.
    fn has_expected_columns(&self) -> Result<bool, StoreError> {
        let mut stmt = self.conn.prepare("PRAGMA table_info(events)")?;
        let found: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<_, _>>()?;

        if found.is_empty() {
            return Ok(false);
        }

        Ok(EXPECTED_COLUMNS
            .iter()
            .all(|column| found.iter().any(|f| f == column)))
    }

    fn meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    fn set_meta(&mut self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Drops everything belonging to calendars that no longer exist on disk.
    pub fn prune_missing_calendars(&mut self, present: &[CalendarMeta]) -> Result<(), StoreError> {
        let known: Vec<String> = self
            .conn
            .prepare("SELECT DISTINCT calendar_id FROM files")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;

        for id in known {
            if !present.iter().any(|c| c.id == id) {
                tracing::debug!(calendar = %id, "dropping index rows for removed calendar");
                self.conn
                    .execute("DELETE FROM events WHERE calendar_id = ?1", [&id])?;
                self.conn
                    .execute("DELETE FROM files WHERE calendar_id = ?1", [&id])?;
            }
        }
        Ok(())
    }

    /// Brings one calendar's rows in line with what is on disk.
    ///
    /// Only files whose mtime or size changed are re-parsed, so a refresh over an
    /// unchanged calendar is a handful of `stat` calls. Returns `true` if
    /// anything actually changed.
    pub fn sync_calendar(&mut self, meta: &CalendarMeta) -> Result<bool, StoreError> {
        // What disk says.
        let mut on_disk: HashMap<String, (i64, i64)> = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&meta.path) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("ics") {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                let Ok(fs_meta) = entry.metadata() else {
                    continue;
                };
                let mtime = fs_meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_nanos() as i64);
                on_disk.insert(name.to_owned(), (mtime, fs_meta.len() as i64));
            }
        }

        // What the index says.
        let indexed: HashMap<String, (i64, i64)> = self
            .conn
            .prepare("SELECT file_name, mtime_ns, size FROM files WHERE calendar_id = ?1")?
            .query_map([&meta.id], |r| {
                Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?)))
            })?
            .collect::<Result<_, _>>()?;

        let mut changed = false;
        let tx = self.conn.transaction()?;

        // Removed files.
        for name in indexed.keys() {
            if !on_disk.contains_key(name) {
                tx.execute(
                    "DELETE FROM events WHERE calendar_id = ?1 AND file_name = ?2",
                    params![&meta.id, name],
                )?;
                tx.execute(
                    "DELETE FROM files WHERE calendar_id = ?1 AND file_name = ?2",
                    params![&meta.id, name],
                )?;
                changed = true;
            }
        }

        // New or modified files.
        for (name, (mtime, size)) in &on_disk {
            if indexed.get(name) == Some(&(*mtime, *size)) {
                continue;
            }
            changed = true;

            let text = std::fs::read_to_string(meta.path.join(name)).unwrap_or_default();
            let events = super::vdir::parse_ics(&text, &meta.id, name);

            tx.execute(
                "DELETE FROM events WHERE calendar_id = ?1 AND file_name = ?2",
                params![&meta.id, name],
            )?;
            for event in &events {
                insert_event(&tx, event, self.local)?;
            }
            tx.execute(
                "INSERT INTO files (calendar_id, file_name, mtime_ns, size) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(calendar_id, file_name) DO UPDATE
                   SET mtime_ns = excluded.mtime_ns, size = excluded.size",
                params![&meta.id, name, mtime, size],
            )?;
        }

        tx.commit()?;
        Ok(changed)
    }

    /// Every event that could overlap `[from, to)`, across the given calendars.
    ///
    /// Recurring events are returned whenever their series *could* reach the
    /// window; the caller expands them to find out whether it actually does.
    pub fn candidates(
        &self,
        calendar_ids: &[String],
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<Event>, StoreError> {
        if calendar_ids.is_empty() {
            return Ok(Vec::new());
        }

        let placeholders = std::iter::repeat_n("?", calendar_ids.len())
            .collect::<Vec<_>>()
            .join(",");

        let sql = format!(
            "SELECT {COLUMNS} FROM events
             WHERE calendar_id IN ({placeholders})
               AND (
                 (rrule IS NULL AND end_utc > ?{a} AND start_utc < ?{b})
                 OR
                 (rrule IS NOT NULL AND start_utc < ?{b} AND (until_utc IS NULL OR until_utc > ?{a}))
               )",
            a = calendar_ids.len() + 1,
            b = calendar_ids.len() + 2,
        );

        let mut stmt = self.conn.prepare(&sql)?;

        let mut values: Vec<Box<dyn rusqlite::ToSql>> = calendar_ids
            .iter()
            .map(|id| Box::new(id.clone()) as Box<dyn rusqlite::ToSql>)
            .collect();
        values.push(Box::new(from.timestamp()));
        values.push(Box::new(to.timestamp()));

        let rows = stmt.query_map(rusqlite::params_from_iter(values.iter()), row_to_event)?;
        let mut events: Vec<Event> = rows.collect::<Result<_, _>>()?;

        // An override can sit outside the query window while the instance it
        // replaces is inside it — moved to next month, say. Expansion still
        // needs it, to suppress the master's generated copy, so pull every
        // override belonging to a recurring candidate the window selected.
        let series: Vec<&Event> = events
            .iter()
            .filter(|e| e.rrule.is_some() && e.recurrence_id.is_none())
            .collect();
        if !series.is_empty() {
            let ph = std::iter::repeat_n("(?,?)", series.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT {COLUMNS} FROM events
                 WHERE rid_kind != {RID_NONE} AND (calendar_id, uid) IN (VALUES {ph})"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let values: Vec<&str> = series
                .iter()
                .flat_map(|e| [e.calendar_id.as_str(), e.uid.as_str()])
                .collect();
            let rows = stmt.query_map(rusqlite::params_from_iter(values.iter()), row_to_event)?;
            for event in rows {
                let event = event?;
                // The in-window pass may already have found it.
                let dup = events.iter().any(|e| {
                    e.uid == event.uid
                        && e.calendar_id == event.calendar_id
                        && e.recurrence_id == event.recurrence_id
                });
                if !dup {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    /// Looks up a single event by UID.
    ///
    /// For a recurring event this is the series master; overrides carry the
    /// same UID and are reached through [`Self::events_with_uid`].
    pub fn event(&self, calendar_id: &str, uid: &str) -> Result<Option<Event>, StoreError> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM events
                     WHERE calendar_id = ?1 AND uid = ?2 AND rid_kind = {RID_NONE}"
                ),
                params![calendar_id, uid],
                row_to_event,
            )
            .optional()?)
    }

    /// Every component stored under one UID: the master first, then its
    /// overrides. One row for a one-off event.
    pub fn events_with_uid(&self, calendar_id: &str, uid: &str) -> Result<Vec<Event>, StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM events
             WHERE calendar_id = ?1 AND uid = ?2
             ORDER BY rid_kind, rid_naive"
        ))?;
        let rows = stmt.query_map(params![calendar_id, uid], row_to_event)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Total number of indexed events, for diagnostics and tests.
    pub fn event_count(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?)
    }
}

const COLUMNS: &str = "calendar_id, file_name, uid, summary, description, location, \
     start_kind, start_naive, start_tz, end_kind, end_naive, end_tz, \
     rrule, exdates, sequence, created, modified, alarms, \
     rid_kind, rid_naive, rid_tz";

/// `rid_kind` for a component that is not an override. Distinct from every
/// [`split_time`] kind, and NOT NULL so it can participate in the primary key.
const RID_NONE: i64 = -1;

fn split_rid(rid: Option<EventTime>) -> (i64, i64, Option<String>) {
    rid.map_or((RID_NONE, 0, None), split_time)
}

fn insert_event(
    tx: &rusqlite::Transaction<'_>,
    event: &Event,
    local: Tz,
) -> Result<(), StoreError> {
    let (start_kind, start_naive, start_tz) = split_time(event.start);
    let (end_kind, end_naive, end_tz) = split_time(event.end);

    let exdates = event
        .exdates
        .iter()
        .map(|d| d.and_utc().timestamp().to_string())
        .collect::<Vec<_>>()
        .join(",");

    let alarms = event
        .alarms
        .iter()
        .map(|d| d.num_seconds().to_string())
        .collect::<Vec<_>>()
        .join(",");

    let (rid_kind, rid_naive, rid_tz) = split_rid(event.recurrence_id);

    tx.execute(
        "INSERT INTO events (
            calendar_id, file_name, uid, summary, description, location,
            start_kind, start_naive, start_tz, end_kind, end_naive, end_tz,
            rrule, exdates, sequence, created, modified,
            start_utc, end_utc, until_utc, alarms,
            rid_kind, rid_naive, rid_tz
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
            ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
            ?22, ?23, ?24
         )
         ON CONFLICT(calendar_id, file_name, uid, rid_kind, rid_naive) DO UPDATE SET
            summary = excluded.summary, description = excluded.description,
            location = excluded.location,
            start_kind = excluded.start_kind, start_naive = excluded.start_naive,
            start_tz = excluded.start_tz,
            end_kind = excluded.end_kind, end_naive = excluded.end_naive,
            end_tz = excluded.end_tz,
            rrule = excluded.rrule, exdates = excluded.exdates,
            alarms = excluded.alarms,
            sequence = excluded.sequence, created = excluded.created,
            modified = excluded.modified,
            start_utc = excluded.start_utc, end_utc = excluded.end_utc,
            until_utc = excluded.until_utc,
            rid_tz = excluded.rid_tz",
        params![
            event.calendar_id,
            event.file_name,
            event.uid,
            event.summary,
            event.description,
            event.location,
            start_kind,
            start_naive,
            start_tz,
            end_kind,
            end_naive,
            end_tz,
            event.rrule,
            exdates,
            event.sequence,
            event.created.map(|d| d.timestamp()),
            event.last_modified.map(|d| d.timestamp()),
            event.start.to_utc(local).timestamp(),
            event.end.to_utc(local).timestamp(),
            series_until(event, local).map(|d| d.timestamp()),
            alarms,
            rid_kind,
            rid_naive,
            rid_tz,
        ],
    )?;
    Ok(())
}

/// The latest instant a series can reach, or `None` when it is unbounded.
///
/// Only `UNTIL` gives us a cheap answer. `COUNT` would need full expansion, so
/// we treat it as unbounded — the query then always considers the event a
/// candidate and expansion filters it out. Conservative, never wrong.
fn series_until(event: &Event, local: Tz) -> Option<DateTime<Utc>> {
    let rule = event.rrule.as_deref()?;
    for part in rule.split(';') {
        let (key, value) = part.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("UNTIL") {
            let v = value.trim().trim_end_matches('Z');
            let parsed = NaiveDateTime::parse_from_str(v, "%Y%m%dT%H%M%S")
                .ok()
                .or_else(|| {
                    chrono::NaiveDate::parse_from_str(v, "%Y%m%d")
                        .ok()
                        .map(|d| d.and_time(chrono::NaiveTime::MIN))
                })?;
            // Add the event's own length: the last instance starts at UNTIL but
            // may run past it.
            return Some(Utc.from_utc_datetime(&parsed) + event.duration(local));
        }
    }
    None
}

fn split_time(t: EventTime) -> (i64, i64, Option<String>) {
    match t {
        EventTime::Date(d) => (
            KIND_DATE,
            d.and_time(chrono::NaiveTime::MIN).and_utc().timestamp(),
            None,
        ),
        EventTime::Floating(dt) => (KIND_FLOATING, dt.and_utc().timestamp(), None),
        EventTime::Zoned(dt, tz) => (
            KIND_ZONED,
            dt.and_utc().timestamp(),
            Some(tz.name().to_owned()),
        ),
    }
}

fn join_time(kind: i64, naive: i64, tz: Option<String>) -> EventTime {
    let dt = DateTime::from_timestamp(naive, 0)
        .map_or_else(|| Utc::now().naive_utc(), |d| d.naive_utc());

    match kind {
        KIND_DATE => EventTime::Date(dt.date()),
        KIND_ZONED => {
            let tz = tz
                .and_then(|name| name.parse::<Tz>().ok())
                .unwrap_or(chrono_tz::UTC);
            EventTime::Zoned(dt, tz)
        }
        _ => EventTime::Floating(dt),
    }
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    let exdates: String = row.get(13)?;

    Ok(Event {
        calendar_id: row.get(0)?,
        file_name: row.get(1)?,
        uid: row.get(2)?,
        summary: row.get(3)?,
        description: row.get(4)?,
        location: row.get(5)?,
        start: join_time(row.get(6)?, row.get(7)?, row.get(8)?),
        end: join_time(row.get(9)?, row.get(10)?, row.get(11)?),
        rrule: row.get(12)?,
        exdates: exdates
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<i64>().ok())
            .filter_map(|secs| DateTime::from_timestamp(secs, 0))
            .map(|d| d.naive_utc())
            .collect(),
        alarms: row
            .get::<_, String>(17)?
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<i64>().ok())
            .map(chrono::Duration::seconds)
            .collect(),
        sequence: row.get(14)?,
        created: row
            .get::<_, Option<i64>>(15)?
            .and_then(|s| DateTime::from_timestamp(s, 0)),
        last_modified: row
            .get::<_, Option<i64>>(16)?
            .and_then(|s| DateTime::from_timestamp(s, 0)),
        recurrence_id: {
            let kind: i64 = row.get(18)?;
            (kind != RID_NONE).then(|| join_time(kind, row.get(19).unwrap_or(0), row.get(20).ok()))
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Rgb;
    use crate::store::vdir;
    use chrono::NaiveDate;

    fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn setup() -> (tempfile::TempDir, CalendarMeta, Index) {
        let root = tempfile::tempdir().unwrap();
        let cal = vdir::create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        let index = Index::in_memory(chrono_tz::UTC).unwrap();
        (root, cal, index)
    }

    fn write(cal: &CalendarMeta, summary: &str, day: u32, rrule: Option<&str>) -> Event {
        let mut e = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, day)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        e.summary = summary.to_owned();
        e.rrule = rrule.map(ToOwned::to_owned);
        vdir::write_event(cal, &e).unwrap();
        e
    }

    #[test]
    fn sync_indexes_events() {
        let (_root, cal, mut index) = setup();
        write(&cal, "Standup", 4, None);

        assert!(index.sync_calendar(&cal).unwrap());
        assert_eq!(index.event_count().unwrap(), 1);
    }

    /// Writes a weekly series whose 11 Aug instance is overridden, master and
    /// override in one file — the shape every other CalDAV client produces.
    fn write_series_with_override(cal: &CalendarMeta) -> Event {
        let master = write(&cal, "Standup", 4, Some("FREQ=WEEKLY"));

        let mut over = master.clone();
        over.rrule = None;
        over.summary = "Standup (moved)".into();
        over.start = crate::model::EventTime::Zoned(
            NaiveDate::from_ymd_opt(2026, 8, 11)
                .unwrap()
                .and_hms_opt(14, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        over.end = crate::model::EventTime::Zoned(
            NaiveDate::from_ymd_opt(2026, 8, 11)
                .unwrap()
                .and_hms_opt(15, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        over.recurrence_id = Some(crate::model::EventTime::Zoned(
            NaiveDate::from_ymd_opt(2026, 8, 11)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        ));
        vdir::write_event(&cal, &over).unwrap();
        master
    }

    #[test]
    fn a_master_and_its_override_are_both_indexed() {
        let (_root, cal, mut index) = setup();
        let master = write_series_with_override(&cal);
        index.sync_calendar(&cal).unwrap();

        // The primary key must keep both components apart: they share
        // calendar, file, and UID, and differ only in RECURRENCE-ID.
        assert_eq!(index.event_count().unwrap(), 2);

        let found = index.event(&cal.id, &master.uid).unwrap().unwrap();
        assert!(
            found.recurrence_id.is_none(),
            "event() must return the master, not whichever row was written last"
        );

        let all = index.events_with_uid(&cal.id, &master.uid).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all[0].recurrence_id.is_none(), "master sorts first");
        assert!(all[1].recurrence_id.is_some());
    }

    #[test]
    fn candidates_carry_the_override_even_when_it_left_the_window() {
        let (_root, cal, mut index) = setup();
        let master = write_series_with_override(&cal);

        // Move the override into September, outside the August window.
        let mut over = index_override(&mut index, &cal, &master);
        over.start = crate::model::EventTime::Zoned(
            NaiveDate::from_ymd_opt(2026, 9, 2)
                .unwrap()
                .and_hms_opt(14, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        over.end = crate::model::EventTime::Zoned(
            NaiveDate::from_ymd_opt(2026, 9, 2)
                .unwrap()
                .and_hms_opt(15, 0, 0)
                .unwrap(),
            chrono_tz::UTC,
        );
        vdir::write_event(&cal, &over).unwrap();
        index.sync_calendar(&cal).unwrap();

        let ids = vec![cal.id.clone()];
        let got = index
            .candidates(&ids, utc(2026, 8, 1), utc(2026, 9, 1))
            .unwrap();

        // Expansion cannot suppress the replaced instance without seeing the
        // override, however far away it moved.
        assert_eq!(got.len(), 2, "the out-of-window override must ride along");
        assert!(got.iter().any(|e| e.recurrence_id.is_some()));
    }

    fn index_override(index: &mut Index, cal: &CalendarMeta, master: &Event) -> Event {
        index.sync_calendar(cal).unwrap();
        index
            .events_with_uid(&cal.id, &master.uid)
            .unwrap()
            .into_iter()
            .find(|e| e.recurrence_id.is_some())
            .expect("the override row")
    }

    #[test]
    fn resync_without_changes_is_a_noop() {
        let (_root, cal, mut index) = setup();
        write(&cal, "Standup", 4, None);

        assert!(
            index.sync_calendar(&cal).unwrap(),
            "first sync should change"
        );
        assert!(
            !index.sync_calendar(&cal).unwrap(),
            "second sync re-parsed unchanged files"
        );
    }

    #[test]
    fn deleting_a_file_removes_its_rows() {
        let (_root, cal, mut index) = setup();
        let e = write(&cal, "Standup", 4, None);
        index.sync_calendar(&cal).unwrap();

        vdir::delete_event(&cal, &e.file_name).unwrap();
        assert!(index.sync_calendar(&cal).unwrap());
        assert_eq!(index.event_count().unwrap(), 0);
    }

    #[test]
    fn range_query_excludes_events_outside_the_window() {
        let (_root, cal, mut index) = setup();
        write(&cal, "August", 4, None);
        index.sync_calendar(&cal).unwrap();

        let ids = vec![cal.id.clone()];
        let hit = index
            .candidates(&ids, utc(2026, 8, 1), utc(2026, 9, 1))
            .unwrap();
        assert_eq!(hit.len(), 1);

        let miss = index
            .candidates(&ids, utc(2026, 6, 1), utc(2026, 7, 1))
            .unwrap();
        assert!(miss.is_empty());
    }

    #[test]
    fn unbounded_series_is_always_a_candidate() {
        let (_root, cal, mut index) = setup();
        write(&cal, "Weekly", 3, Some("FREQ=WEEKLY"));
        index.sync_calendar(&cal).unwrap();

        // Years later, the series is still live.
        let hit = index
            .candidates(
                std::slice::from_ref(&cal.id),
                utc(2030, 1, 1),
                utc(2030, 2, 1),
            )
            .unwrap();
        assert_eq!(hit.len(), 1);
    }

    #[test]
    fn series_with_until_stops_being_a_candidate() {
        let (_root, cal, mut index) = setup();
        write(
            &cal,
            "Course",
            3,
            Some("FREQ=WEEKLY;UNTIL=20260930T000000Z"),
        );
        index.sync_calendar(&cal).unwrap();

        let ids = vec![cal.id.clone()];
        assert_eq!(
            index
                .candidates(&ids, utc(2026, 9, 1), utc(2026, 10, 1))
                .unwrap()
                .len(),
            1
        );
        assert!(
            index
                .candidates(&ids, utc(2027, 1, 1), utc(2027, 2, 1))
                .unwrap()
                .is_empty(),
            "a series past its UNTIL was still returned"
        );
    }

    #[test]
    fn round_trips_all_event_fields() {
        let (_root, cal, mut index) = setup();

        let mut e = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            chrono_tz::Europe::Athens,
        );
        e.summary = "Standup".into();
        e.description = Some("notes".into());
        e.location = Some("Room 3".into());
        e.rrule = Some("FREQ=WEEKLY".into());
        e.exdates = vec![
            NaiveDate::from_ymd_opt(2026, 8, 18)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
        ];
        vdir::write_event(&cal, &e).unwrap();
        index.sync_calendar(&cal).unwrap();

        let got = index.event(&cal.id, &e.uid).unwrap().expect("indexed");
        assert_eq!(got.summary, e.summary);
        assert_eq!(got.description, e.description);
        assert_eq!(got.location, e.location);
        assert_eq!(got.rrule, e.rrule);
        assert_eq!(got.start, e.start, "timezone lost through the index");
        assert_eq!(got.end, e.end);
        assert_eq!(got.exdates, e.exdates);
    }

    #[test]
    fn empty_calendar_list_returns_nothing() {
        let (_root, cal, mut index) = setup();
        write(&cal, "Standup", 4, None);
        index.sync_calendar(&cal).unwrap();
        assert!(
            index
                .candidates(&[], utc(2026, 8, 1), utc(2026, 9, 1))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_older_on_disk_schema_is_rebuilt_not_patched() {
        // The in-memory tests always start from the current schema, so they cannot
        // catch this: `CREATE TABLE IF NOT EXISTS` over a v1 database would leave
        // the old columns in place and fail on the first insert.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.sqlite");

        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE events (calendar_id TEXT, file_name TEXT, uid TEXT);
                 CREATE TABLE files (calendar_id TEXT, file_name TEXT);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('timezone', 'UTC')",
                [],
            )
            .unwrap();
        }

        let mut index = Index::open(&path, chrono_tz::UTC).expect("stale index should rebuild");

        // Writing must now succeed against the current columns.
        let root = tempfile::tempdir().unwrap();
        let cal = vdir::create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        write(&cal, "Standup", 4, None);
        index.sync_calendar(&cal).unwrap();
        assert_eq!(index.event_count().unwrap(), 1);
    }

    #[test]
    fn a_half_applied_upgrade_heals_itself() {
        // The version says "current" but the table is from an older build — the
        // state a partially-successful upgrade leaves behind. Trusting the version
        // alone would make every query fail with no way back.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.sqlite");

        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE events (calendar_id TEXT, file_name TEXT, uid TEXT);
                 CREATE TABLE files (calendar_id TEXT, file_name TEXT);",
            )
            .unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', '{SCHEMA_VERSION}'), ('timezone', 'UTC')"
                ),
                [],
            )
            .unwrap();
        }

        let mut index = Index::open(&path, chrono_tz::UTC).expect("should rebuild");

        let root = tempfile::tempdir().unwrap();
        let cal = vdir::create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        write(&cal, "Standup", 4, None);
        index.sync_calendar(&cal).unwrap();

        // And a query over the rebuilt table must work.
        assert_eq!(
            index
                .candidates(
                    std::slice::from_ref(&cal.id),
                    utc(2026, 8, 1),
                    utc(2026, 9, 1)
                )
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn a_current_index_is_kept_across_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.sqlite");
        let root = tempfile::tempdir().unwrap();
        let cal = vdir::create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        write(&cal, "Standup", 4, None);

        {
            let mut index = Index::open(&path, chrono_tz::UTC).unwrap();
            index.sync_calendar(&cal).unwrap();
            assert_eq!(index.event_count().unwrap(), 1);
        }

        // Same schema and timezone: the cache should survive rather than rebuild.
        let index = Index::open(&path, chrono_tz::UTC).unwrap();
        assert_eq!(
            index.event_count().unwrap(),
            1,
            "an up-to-date index was needlessly wiped"
        );
    }

    #[test]
    fn changing_timezone_invalidates_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.sqlite");
        let root = tempfile::tempdir().unwrap();
        let cal = vdir::create_collection(root.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        write(&cal, "Standup", 4, None);

        {
            let mut index = Index::open(&path, chrono_tz::UTC).unwrap();
            index.sync_calendar(&cal).unwrap();
        }

        // Floating and all-day times are resolved against the local zone, so the
        // cached UTC bounds are wrong once it changes.
        let index = Index::open(&path, chrono_tz::Europe::Athens).unwrap();
        assert_eq!(index.event_count().unwrap(), 0);
    }

    #[test]
    fn pruning_drops_removed_calendars() {
        let (_root, cal, mut index) = setup();
        write(&cal, "Standup", 4, None);
        index.sync_calendar(&cal).unwrap();
        assert_eq!(index.event_count().unwrap(), 1);

        index.prune_missing_calendars(&[]).unwrap();
        assert_eq!(index.event_count().unwrap(), 0);
    }
}

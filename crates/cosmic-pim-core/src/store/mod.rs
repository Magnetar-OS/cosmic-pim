// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Storage: iCalendar files on disk, with a SQLite index in front of them.
//!
//! The split is deliberate. [`vdir`] owns the files, which are the source of
//! truth and remain readable by khal, Thunderbird, or vdirsyncer. [`index`] is a
//! cache that makes range queries cheap; it can be deleted at any time and will
//! rebuild itself. [`Store`] is the only thing the UI talks to.

pub mod contacts;
pub mod index;
pub mod vdir;
pub mod watcher;

use crate::model::{CalendarMeta, Event, Occurrence, Rgb, Todo, expand_merged, local_timezone};
use chrono::{DateTime, Duration, NaiveDate, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("index error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("cannot watch the calendar directory: {0}")]
    Notify(#[from] notify::Error),

    #[error("“{0}” is read-only")]
    ReadOnly(String),

    /// A guarded write lost a race: the file changed between the caller's read
    /// and its write, and the incoming version was parked at `conflict` rather
    /// than being dropped on the floor.
    #[error("{target} was changed by something else; your version was kept as {conflict}")]
    Conflict {
        target: std::path::PathBuf,
        conflict: std::path::PathBuf,
    },

    #[error("no calendar named “{0}”")]
    UnknownCalendar(String),

    #[error("no contact with UID “{0}”")]
    UnknownContact(String),

    #[error("no calendars available")]
    NoCalendars,
}

impl From<crate::atomic::Error> for StoreError {
    fn from(error: crate::atomic::Error) -> Self {
        match error {
            crate::atomic::Error::Io(io) => Self::Io(io),
            crate::atomic::Error::ModifiedSince { target, conflict } => {
                Self::Conflict { target, conflict }
            }
            // A path with no parent or no file name is a caller bug, not a
            // storage condition; there is no useful distinct variant for it.
            other @ (crate::atomic::Error::NoParent(_) | crate::atomic::Error::NoFileName(_)) => {
                Self::Io(std::io::Error::other(other.to_string()))
            }
        }
    }
}

/// What an import did, so the UI can say so.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub added: usize,
    pub updated: usize,
    /// The file names written, relative to the collection's directory — what a
    /// caller needs to queue the imported entries for upload to a server the
    /// collection is bound to. Storage itself never queues; see
    /// `cosmic_pim_sync::queue_save` for the other half.
    pub files: Vec<String>,
}

impl ImportSummary {
    #[must_use]
    pub fn total(&self) -> usize {
        self.added + self.updated
    }
}

/// What [`Store::split_series`] did.
///
/// `Split` boxes its `Event` so the enum is a pointer rather than a whole
/// event: `WholeSeries` carries nothing, and every value of this type — most of
/// them `WholeSeries`, since most edits are not splits — would otherwise be
/// sized for the largest variant.
#[derive(Clone, Debug)]
pub enum SplitOutcome {
    /// The cut landed on or before the first instance, or the event does not
    /// recur — there is nothing before the cut to keep, so no split happened.
    /// The caller should apply its edit to the whole series instead.
    WholeSeries,
    /// The series was split. The value is the successor's master — the event
    /// covering the cut instance and everything after it — for the caller to
    /// apply its edit to and save. Both the truncated master's file and the
    /// successor's file were written; a caller bound to a server must queue
    /// writeback for both.
    Split(Box<Event>),
}

/// Makes a UID safe to use as a file name.
///
/// UIDs are arbitrary text and routinely contain `/` and `@`; without this an
/// imported file could escape its collection directory.
pub(crate) fn sanitise_file_stem(uid: &str) -> String {
    let cleaned: String = uid
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Path separators are already gone, so this cannot traverse. Collapsing runs
    // of dots anyway keeps `..` out of file names entirely, which is one less
    // thing for a future reader to have to reason about.
    let mut collapsed = String::with_capacity(cleaned.len());
    let mut last_was_dot = false;
    for c in cleaned.chars() {
        if c == '.' {
            if !last_was_dot {
                collapsed.push(c);
            }
            last_was_dot = true;
        } else {
            collapsed.push(c);
            last_was_dot = false;
        }
    }

    let trimmed = collapsed.trim_matches('.').trim_matches('-');
    if trimmed.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        trimmed.chars().take(120).collect()
    }
}

/// Everything the UI needs from disk.
pub struct Store {
    root: PathBuf,
    index: index::Index,
    calendars: Vec<CalendarMeta>,
    local: Tz,
}

impl Store {
    /// Opens the store at the default location, creating it if absent.
    pub fn open_default() -> Result<Self, StoreError> {
        Self::open(&vdir::default_root(), &index::default_path())
    }

    pub fn open(root: &Path, index_path: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(root)?;

        let local = local_timezone();
        let index = index::Index::open(index_path, local)?;

        let mut store = Self {
            root: root.to_path_buf(),
            index,
            calendars: Vec::new(),
            local,
        };
        store.refresh()?;
        Ok(store)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn local_timezone(&self) -> Tz {
        self.local
    }

    #[must_use]
    pub fn calendars(&self) -> &[CalendarMeta] {
        &self.calendars
    }

    #[must_use]
    pub fn calendar(&self, id: &str) -> Option<&CalendarMeta> {
        self.calendars.iter().find(|c| c.id == id)
    }

    /// The calendar new events land in unless the user picks another.
    #[must_use]
    pub fn default_calendar(&self) -> Option<&CalendarMeta> {
        self.calendars.iter().find(|c| !c.read_only)
    }

    /// Rescans collections and brings the index up to date.
    ///
    /// Returns `true` if anything changed, so the caller can skip a redraw when
    /// nothing did.
    pub fn refresh(&mut self) -> Result<bool, StoreError> {
        let found = vdir::collections(&self.root);
        let mut changed = found.len() != self.calendars.len()
            || found
                .iter()
                .zip(&self.calendars)
                .any(|(a, b)| a.id != b.id || a.name != b.name || a.color != b.color);

        self.calendars = found;
        self.index.prune_missing_calendars(&self.calendars)?;

        // `calendars` is borrowed immutably by the loop while `index` is borrowed
        // mutably, so take a cheap clone of the list to keep the borrow checker happy.
        let metas = self.calendars.clone();
        for meta in &metas {
            if self.index.sync_calendar(meta)? {
                changed = true;
            }
        }

        Ok(changed)
    }

    /// Every occurrence between `from` (inclusive) and `to` (exclusive), local dates.
    ///
    /// `hidden` names calendars the user has unticked in the sidebar.
    pub fn occurrences(
        &self,
        from: NaiveDate,
        to: NaiveDate,
        hidden: &HashSet<String>,
    ) -> Result<Vec<Occurrence>, StoreError> {
        let visible: Vec<String> = self
            .calendars
            .iter()
            .filter(|c| !hidden.contains(&c.id))
            .map(|c| c.id.clone())
            .collect();

        if visible.is_empty() {
            return Ok(Vec::new());
        }

        let from_utc = self.day_start_utc(from);
        let to_utc = self.day_start_utc(to);

        // Expanded as one set rather than event-by-event: a RECURRENCE-ID
        // override and its master are separate components, and suppressing the
        // replaced instance requires seeing both.
        let candidates = self.index.candidates(&visible, from_utc, to_utc)?;
        let mut out = expand_merged(&candidates, from_utc, to_utc, self.local);

        out.sort_by_key(Occurrence::sort_key);
        Ok(out)
    }

    /// Occurrences grouped per day, ready for a month or week grid.
    pub fn occurrences_by_day(
        &self,
        from: NaiveDate,
        to: NaiveDate,
        hidden: &HashSet<String>,
    ) -> Result<std::collections::BTreeMap<NaiveDate, Vec<Occurrence>>, StoreError> {
        let mut map: std::collections::BTreeMap<NaiveDate, Vec<Occurrence>> =
            std::collections::BTreeMap::new();

        for occurrence in self.occurrences(from, to, hidden)? {
            // A multi-day event belongs to every day it touches, so the grid can
            // draw it in each cell.
            let mut day = occurrence.start.date().max(from);
            let last = occurrence.end.date();
            let last = if occurrence.end.time() == NaiveTime::MIN {
                // End is exclusive: a 09:00–00:00 event does not touch the next day.
                last - Duration::days(1)
            } else {
                last
            };

            while day <= last && day < to {
                map.entry(day).or_default().push(occurrence.clone());
                day += Duration::days(1);
            }
        }

        Ok(map)
    }

    fn day_start_utc(&self, date: NaiveDate) -> DateTime<Utc> {
        use chrono::offset::LocalResult;
        let naive = date.and_time(NaiveTime::MIN);
        match self.local.from_local_datetime(&naive) {
            LocalResult::Single(t) | LocalResult::Ambiguous(t, _) => t.with_timezone(&Utc),
            LocalResult::None => Utc.from_utc_datetime(&naive),
        }
    }

    /// Looks up one event for editing.
    pub fn event(&self, calendar_id: &str, uid: &str) -> Result<Option<Event>, StoreError> {
        self.index.event(calendar_id, uid)
    }

    /// Writes an event and re-indexes its calendar.
    pub fn save(&mut self, event: &Event) -> Result<(), StoreError> {
        let meta = self
            .calendar(&event.calendar_id)
            .ok_or_else(|| StoreError::UnknownCalendar(event.calendar_id.clone()))?
            .clone();

        vdir::write_event(&meta, event)?;
        self.index.sync_calendar(&meta)?;
        Ok(())
    }

    /// The component behind one occurrence: the override for that instance if
    /// one exists, otherwise the series master (or the one-off event itself).
    ///
    /// `instant` is [`Occurrence::recurrence_id`] — `None` for a one-off,
    /// the instance's UTC instant for a series member. This is what an editor
    /// must open when the user clicks an occurrence: opening the master when
    /// an override exists would show, and then rewrite, the wrong component.
    pub fn event_instance(
        &self,
        calendar_id: &str,
        uid: &str,
        instant: Option<DateTime<Utc>>,
    ) -> Result<Option<Event>, StoreError> {
        let components = self.index.events_with_uid(calendar_id, uid)?;

        if let Some(instant) = instant
            && let Some(hit) = components.iter().find(|e| {
                e.recurrence_id.is_some_and(|rid| {
                    crate::model::recur::instant_of(rid, self.local) == Some(instant)
                })
            })
        {
            return Ok(Some(hit.clone()));
        }

        Ok(components.into_iter().find(|e| e.recurrence_id.is_none()))
    }

    /// Deletes an event and re-indexes its calendar.
    ///
    /// For a series this removes the whole file — master and overrides
    /// together, which is what deleting the series means. Removing a single
    /// override goes through [`Self::delete_override`].
    pub fn delete(&mut self, calendar_id: &str, uid: &str) -> Result<(), StoreError> {
        let meta = self
            .calendar(calendar_id)
            .ok_or_else(|| StoreError::UnknownCalendar(calendar_id.to_owned()))?
            .clone();

        if let Some(event) = self.index.event(calendar_id, uid)? {
            vdir::delete_event(&meta, &event.file_name)?;
        }
        self.index.sync_calendar(&meta)?;
        Ok(())
    }

    /// Deletes one instance of a series: an `EXDATE` on the master, plus the
    /// removal of any override component that had modified the same instance.
    ///
    /// This is "delete this event" on a repeating event. It differs from
    /// [`Self::delete_override`], which un-modifies an instance so the
    /// master's generated copy comes back.
    pub fn exclude_occurrence(
        &mut self,
        calendar_id: &str,
        uid: &str,
        instant: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let Some(mut master) = self.index.event(calendar_id, uid)? else {
            // Deleting an instance of something already gone is not an error a
            // user can act on.
            tracing::warn!(uid, "no master to exclude an occurrence from");
            return Ok(());
        };

        let naive = crate::model::naive_in_series_zone(master.start, instant, self.local);
        if !master.exdates.contains(&naive) {
            master.exdates.push(naive);
        }
        master.sequence = master.sequence.saturating_add(1);
        master.last_modified = Some(Utc::now());
        self.save(&master)?;

        // If the instance had been overridden, the override describes an
        // instance that no longer exists.
        let stale: Option<Event> = self
            .index
            .events_with_uid(calendar_id, uid)?
            .into_iter()
            .find(|e| {
                e.recurrence_id
                    .is_some_and(|rid| crate::model::instant_of(rid, self.local) == Some(instant))
            });
        if let Some(over) = stale {
            self.delete_override(&over)?;
        }
        Ok(())
    }

    /// Ends a series before the instance at `instant` — "delete this and all
    /// following". Overrides and exclusions at or past the cut are removed
    /// with it; they describe instances that no longer exist.
    ///
    /// Returns `true` when the cut lands on or before the first instance, in
    /// which case nothing of the series would remain and the whole event is
    /// deleted instead.
    pub fn truncate_series(
        &mut self,
        calendar_id: &str,
        uid: &str,
        instant: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let Some(mut master) = self.index.event(calendar_id, uid)? else {
            tracing::warn!(uid, "no master to truncate");
            return Ok(false);
        };

        if instant <= master.start.to_utc(self.local) {
            self.delete(calendar_id, uid)?;
            return Ok(true);
        }

        if let Some(rule) = master.rrule.as_deref() {
            let until = crate::model::until_before(master.start, instant, self.local);
            master.rrule = Some(crate::model::truncate_rule(rule, &until));
        }

        let cut = crate::model::naive_in_series_zone(master.start, instant, self.local);
        master.exdates.retain(|exdate| *exdate < cut);
        master.sequence = master.sequence.saturating_add(1);
        master.last_modified = Some(Utc::now());
        self.save(&master)?;

        let stale: Vec<Event> = self
            .index
            .events_with_uid(calendar_id, uid)?
            .into_iter()
            .filter(|e| {
                e.recurrence_id
                    .and_then(|rid| crate::model::instant_of(rid, self.local))
                    .is_some_and(|rid| rid >= instant)
            })
            .collect();
        for over in stale {
            self.delete_override(&over)?;
        }
        Ok(false)
    }

    /// Splits a series at `instant` — the write side of editing "this and all
    /// following" occurrences.
    ///
    /// The master keeps everything before the cut, truncated exactly as
    /// [`Self::truncate_series`] truncates it. A successor series under a fresh
    /// UID takes over from the cut instance: the same properties, the same rule
    /// with any `COUNT` reduced by the instances the master keeps, the
    /// exclusions at or past the cut, and every override at or past the cut
    /// re-homed onto it rather than deleted.
    ///
    /// The successor's file is written before the master is truncated, so a
    /// crash between the two writes leaves duplicated instances — a visible,
    /// recoverable state — never lost ones.
    ///
    /// The successor anchors at the cut instance, which the caller obtained
    /// from a generated occurrence, so the rule keeps its phase: a
    /// `FREQ=WEEKLY;INTERVAL=2` series split on one of its own Tuesdays
    /// continues on the same alternating Tuesdays.
    pub fn split_series(
        &mut self,
        calendar_id: &str,
        uid: &str,
        instant: DateTime<Utc>,
    ) -> Result<SplitOutcome, StoreError> {
        let Some(master) = self.index.event(calendar_id, uid)? else {
            tracing::warn!(uid, "no master to split");
            return Ok(SplitOutcome::WholeSeries);
        };
        let Some(rule) = master.rrule.clone() else {
            return Ok(SplitOutcome::WholeSeries);
        };
        if instant <= master.start.to_utc(self.local) {
            return Ok(SplitOutcome::WholeSeries);
        }

        // Times in the value space the series iterates in — the space EXDATEs
        // and wall-clock durations live in.
        fn own_naive(t: crate::model::EventTime) -> chrono::NaiveDateTime {
            match t {
                crate::model::EventTime::Date(d) => d.and_time(NaiveTime::MIN),
                crate::model::EventTime::Floating(dt) | crate::model::EventTime::Zoned(dt, _) => dt,
            }
        }

        let cut = crate::model::naive_in_series_zone(master.start, instant, self.local);
        let start = crate::model::rid_for(master.start, instant, self.local);
        // Wall-clock duration, so a 09:00–10:00 meeting stays an hour on the
        // clock across a DST boundary, matching how the series itself iterates.
        let wall = own_naive(master.end) - own_naive(master.start);
        let end = master.end.with_naive(own_naive(start) + wall);

        // COUNT bounds the generated set *before* EXDATE removal (RFC 5545), so
        // the instances the master keeps are counted with exclusions cleared.
        let successor_rule = match crate::model::count_of(&rule) {
            Some(count) => {
                let mut probe = master.clone();
                probe.exdates.clear();
                let elapsed = crate::model::expand(
                    &probe,
                    master.start.to_utc(self.local),
                    instant,
                    self.local,
                )
                .len() as u32;
                crate::model::with_count(&rule, count.saturating_sub(elapsed).max(1))
            }
            None => rule,
        };

        let now = Utc::now();
        let mut successor = master.clone();
        successor.uid = format!("{}@cosmic-pim", uuid::Uuid::new_v4());
        successor.file_name = format!("{}.ics", successor.uid);
        successor.start = start;
        successor.end = end;
        successor.rrule = Some(successor_rule);
        successor.exdates = master
            .exdates
            .iter()
            .copied()
            .filter(|e| *e >= cut)
            .collect();
        successor.sequence = 0;
        successor.created = Some(now);
        successor.last_modified = Some(now);

        let rehomed: Vec<Event> = self
            .index
            .events_with_uid(calendar_id, uid)?
            .into_iter()
            .filter(|e| {
                e.recurrence_id
                    .and_then(|rid| crate::model::instant_of(rid, self.local))
                    .is_some_and(|rid| rid >= instant)
            })
            .map(|mut over| {
                over.uid = successor.uid.clone();
                over.file_name = successor.file_name.clone();
                over
            })
            .collect();

        self.save(&successor)?;
        for over in &rehomed {
            self.save(over)?;
        }
        // Truncation also deletes the master's overrides at/past the cut — the
        // copies that now live on under the successor.
        self.truncate_series(calendar_id, uid, instant)?;

        Ok(SplitOutcome::Split(Box::new(successor)))
    }

    /// Removes one override component, restoring the master's generated
    /// instance for that slot.
    ///
    /// Deliberately *not* "delete this occurrence": that is an EXDATE on the
    /// master, a different operation. This one undoes the override, so the
    /// series shows the instance the master generates again.
    pub fn delete_override(&mut self, event: &Event) -> Result<(), StoreError> {
        if event.recurrence_id.is_none() {
            return self.delete(&event.calendar_id, &event.uid);
        }

        let meta = self
            .calendar(&event.calendar_id)
            .ok_or_else(|| StoreError::UnknownCalendar(event.calendar_id.clone()))?
            .clone();

        let path = meta.path.join(&event.file_name);
        let text = std::fs::read_to_string(&path)?;
        match vdir::remove_vevent(
            &text,
            &event.calendar_id,
            &event.file_name,
            event.recurrence_id,
        ) {
            Some(rest) => {
                crate::atomic::write(&path, &rest, None)?;
            }
            // The override was the only component left; an empty calendar
            // document is not worth keeping.
            None => vdir::delete_event(&meta, &event.file_name)?,
        }
        self.index.sync_calendar(&meta)?;
        Ok(())
    }

    /// Moves an event to a different calendar, preserving its UID.
    pub fn move_to_calendar(&mut self, event: &Event, to: &str) -> Result<Event, StoreError> {
        if event.calendar_id == to {
            return Ok(event.clone());
        }
        let from_meta = self
            .calendar(&event.calendar_id)
            .ok_or_else(|| StoreError::UnknownCalendar(event.calendar_id.clone()))?
            .clone();

        let mut moved = event.clone();
        moved.calendar_id = to.to_owned();
        self.save(&moved)?;

        vdir::delete_event(&from_meta, &event.file_name)?;
        self.index.sync_calendar(&from_meta)?;
        Ok(moved)
    }

    /// Imports the events from an iCalendar document into `calendar_id`.
    ///
    /// An event whose UID is already present is updated rather than duplicated,
    /// which is what makes re-importing the same file safe — and what makes this
    /// usable as the handler for opening a `.ics` from a file manager or a mail
    /// attachment.
    pub fn import_ics(
        &mut self,
        text: &str,
        calendar_id: &str,
    ) -> Result<ImportSummary, StoreError> {
        let meta = self
            .calendar(calendar_id)
            .ok_or_else(|| StoreError::UnknownCalendar(calendar_id.to_owned()))?
            .clone();

        if meta.read_only {
            return Err(StoreError::ReadOnly(meta.name));
        }

        let incoming = vdir::parse_ics(text, calendar_id, "");
        let mut summary = ImportSummary::default();

        for mut event in incoming {
            // Reuse the existing file when the UID is already known, so a second
            // import overwrites instead of accumulating copies.
            match self.index.event(calendar_id, &event.uid)? {
                Some(existing) => {
                    event.file_name = existing.file_name;
                    summary.updated += 1;
                }
                None => {
                    event.file_name = format!("{}.ics", sanitise_file_stem(&event.uid));
                    summary.added += 1;
                }
            }

            event.calendar_id = calendar_id.to_owned();
            vdir::write_event(&meta, &event)?;
            summary.files.push(event.file_name.clone());
        }

        self.index.sync_calendar(&meta)?;
        Ok(summary)
    }

    /// Every task in every visible calendar, in list order.
    ///
    /// Read straight from disk rather than through the index — see
    /// [`vdir::read_todos`] for why there is no task index.
    #[must_use]
    pub fn todos(&self, hidden: &HashSet<String>) -> Vec<Todo> {
        let mut out: Vec<Todo> = self
            .calendars
            .iter()
            .filter(|c| !hidden.contains(&c.id))
            .flat_map(vdir::read_todos)
            .collect();

        out.sort_by_key(|todo| todo.sort_key(self.local));
        out
    }

    /// Looks up one task for editing.
    #[must_use]
    pub fn todo(&self, calendar_id: &str, uid: &str) -> Option<Todo> {
        let meta = self.calendar(calendar_id)?;
        vdir::read_todos(meta).into_iter().find(|t| t.uid == uid)
    }

    /// Writes a task.
    pub fn save_todo(&mut self, todo: &Todo) -> Result<(), StoreError> {
        let meta = self
            .calendar(&todo.calendar_id)
            .ok_or_else(|| StoreError::UnknownCalendar(todo.calendar_id.clone()))?
            .clone();
        vdir::write_todo(&meta, todo)
    }

    /// Deletes a task.
    pub fn delete_todo(&mut self, calendar_id: &str, uid: &str) -> Result<(), StoreError> {
        let meta = self
            .calendar(calendar_id)
            .ok_or_else(|| StoreError::UnknownCalendar(calendar_id.to_owned()))?
            .clone();

        if let Some(todo) = vdir::read_todos(&meta).into_iter().find(|t| t.uid == uid) {
            vdir::delete_event(&meta, &todo.file_name)?;
        }
        Ok(())
    }

    /// Serialises a whole calendar as one iCalendar document.
    pub fn export_calendar(&self, calendar_id: &str) -> Result<String, StoreError> {
        let meta = self
            .calendar(calendar_id)
            .ok_or_else(|| StoreError::UnknownCalendar(calendar_id.to_owned()))?;

        Ok(vdir::export_collection(meta))
    }

    /// Creates a new collection on disk.
    pub fn create_calendar(&mut self, name: &str, color: Rgb) -> Result<CalendarMeta, StoreError> {
        let meta = vdir::create_collection(&self.root, name, color)?;
        self.refresh()?;
        Ok(meta)
    }

    /// Renames a calendar and/or changes its colour, writing the vdir metadata files.
    pub fn update_calendar(&mut self, id: &str, name: &str, color: Rgb) -> Result<(), StoreError> {
        let mut meta = self
            .calendar(id)
            .ok_or_else(|| StoreError::UnknownCalendar(id.to_owned()))?
            .clone();

        if meta.read_only {
            return Err(StoreError::ReadOnly(meta.name));
        }

        meta.name = name.trim().to_owned();
        meta.color = color;
        meta.save_meta()?;
        self.refresh()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EventTime;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("calendars");
        let index = dir.path().join("index.sqlite");
        let store = Store::open(&root, &index).unwrap();
        (dir, store)
    }

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    /// The store-level round trip of a series with one overridden instance:
    /// what any other CalDAV client writes, read back and queried the way the
    /// month view queries it.
    #[test]
    fn an_override_shows_once_and_survives_editing_the_master() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        // A weekly 09:00 series whose 11 Aug instance was moved to 14:00 —
        // master and override in one file, as a foreign client would write it.
        let mut master = Event::draft(
            &cal.id,
            day(2026, 8, 4).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        );
        master.summary = "Standup".into();
        master.rrule = Some("FREQ=WEEKLY".into());
        store.save(&master).unwrap();

        let mut over = master.clone();
        over.rrule = None;
        over.summary = "Standup (moved)".into();
        over.start = EventTime::Zoned(day(2026, 8, 11).and_hms_opt(14, 0, 0).unwrap(), store.local);
        over.end = EventTime::Zoned(day(2026, 8, 11).and_hms_opt(15, 0, 0).unwrap(), store.local);
        over.recurrence_id = Some(EventTime::Zoned(
            day(2026, 8, 11).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        ));
        store.save(&over).unwrap();

        let got = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();

        // Four Tuesdays; 11 Aug appears exactly once, at its moved time.
        assert_eq!(got.len(), 4);
        let eleventh: Vec<_> = got
            .iter()
            .filter(|o| o.start.date() == day(2026, 8, 11))
            .collect();
        assert_eq!(
            eleventh.len(),
            1,
            "the replaced instance must not double up"
        );
        assert_eq!(eleventh[0].summary, "Standup (moved)");

        // Clicking that occurrence must reach the override, not the master.
        let opened = store
            .event_instance(&cal.id, &master.uid, eleventh[0].recurrence_id)
            .unwrap()
            .unwrap();
        assert_eq!(opened.summary, "Standup (moved)");

        // Editing the master must not eat the override.
        let mut renamed = store.event(&cal.id, &master.uid).unwrap().unwrap();
        renamed.summary = "Renamed".into();
        store.save(&renamed).unwrap();

        let after = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();
        assert_eq!(after.len(), 4);
        assert!(after.iter().any(|o| o.summary == "Standup (moved)"));
        assert_eq!(after.iter().filter(|o| o.summary == "Renamed").count(), 3);

        // And removing the override restores the generated 09:00 instance.
        let over = store
            .event_instance(&cal.id, &master.uid, eleventh[0].recurrence_id)
            .unwrap()
            .unwrap();
        store.delete_override(&over).unwrap();

        let restored = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();
        assert_eq!(restored.len(), 4);
        assert!(
            restored.iter().all(|o| o.summary == "Renamed"),
            "the generated instance should be back: {restored:?}"
        );
    }

    /// A weekly 09:00 series saved into a fresh store.
    fn weekly_series(store: &mut Store) -> (CalendarMeta, Event) {
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();
        let mut master = Event::draft(
            &cal.id,
            day(2026, 8, 4).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        );
        master.summary = "Standup".into();
        master.rrule = Some("FREQ=WEEKLY;INTERVAL=1".into());
        store.save(&master).unwrap();
        (cal, master)
    }

    fn instants(store: &Store) -> Vec<NaiveDate> {
        store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap()
            .iter()
            .map(|o| o.start.date())
            .collect()
    }

    /// The identity of the instance falling on `date` — the exact value the
    /// UI hands back from a clicked occurrence.
    fn instance_on(store: &Store, date: NaiveDate) -> DateTime<Utc> {
        store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap()
            .iter()
            .find(|o| o.start.date() == date)
            .expect("an instance on that date")
            .recurrence_id
            .expect("a series member carries its identity")
    }

    #[test]
    fn excluding_an_occurrence_removes_exactly_that_instance() {
        let (_dir, mut store) = store();
        let (_cal, master) = weekly_series(&mut store);
        let cut = instance_on(&store, day(2026, 8, 11));

        store
            .exclude_occurrence(&master.calendar_id, &master.uid, cut)
            .unwrap();

        assert_eq!(
            instants(&store),
            vec![day(2026, 8, 4), day(2026, 8, 18), day(2026, 8, 25)]
        );
    }

    #[test]
    fn excluding_an_overridden_occurrence_removes_the_override_too() {
        let (_dir, mut store) = store();
        let (_cal, master) = weekly_series(&mut store);

        // The 11th was moved to 14:00 by an override…
        let mut over = master.clone();
        over.rrule = None;
        over.summary = "Moved".into();
        over.start = EventTime::Zoned(day(2026, 8, 11).and_hms_opt(14, 0, 0).unwrap(), store.local);
        over.end = EventTime::Zoned(day(2026, 8, 11).and_hms_opt(15, 0, 0).unwrap(), store.local);
        over.recurrence_id = Some(EventTime::Zoned(
            day(2026, 8, 11).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        ));
        store.save(&over).unwrap();

        // …and then the instance is deleted outright.
        let cut = instance_on(&store, day(2026, 8, 11));
        store
            .exclude_occurrence(&master.calendar_id, &master.uid, cut)
            .unwrap();

        let got = instants(&store);
        assert!(
            !got.contains(&day(2026, 8, 11)),
            "neither the generated instance nor the override may survive: {got:?}"
        );
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn truncating_ends_the_series_before_the_cut() {
        let (_dir, mut store) = store();
        let (_cal, master) = weekly_series(&mut store);
        let cut = instance_on(&store, day(2026, 8, 18));

        let deleted_whole = store
            .truncate_series(&master.calendar_id, &master.uid, cut)
            .unwrap();

        assert!(!deleted_whole);
        assert_eq!(instants(&store), vec![day(2026, 8, 4), day(2026, 8, 11)]);

        // The rule survived the surgery verbatim apart from the cut.
        let after = store
            .event(&master.calendar_id, &master.uid)
            .unwrap()
            .unwrap();
        let rule = after.rrule.unwrap();
        assert!(rule.contains("FREQ=WEEKLY"), "{rule}");
        assert!(rule.contains("INTERVAL=1"), "{rule}");
        assert!(rule.contains("UNTIL="), "{rule}");
    }

    #[test]
    fn truncating_at_the_first_instance_deletes_the_series() {
        let (_dir, mut store) = store();
        let (_cal, master) = weekly_series(&mut store);
        let cut = instance_on(&store, day(2026, 8, 4));

        let deleted_whole = store
            .truncate_series(&master.calendar_id, &master.uid, cut)
            .unwrap();

        assert!(deleted_whole);
        assert!(instants(&store).is_empty());
    }

    #[test]
    fn truncating_purges_overrides_past_the_cut() {
        let (_dir, mut store) = store();
        let (_cal, master) = weekly_series(&mut store);

        let mut over = master.clone();
        over.rrule = None;
        over.summary = "Moved".into();
        over.start = EventTime::Zoned(day(2026, 8, 25).and_hms_opt(14, 0, 0).unwrap(), store.local);
        over.end = EventTime::Zoned(day(2026, 8, 25).and_hms_opt(15, 0, 0).unwrap(), store.local);
        over.recurrence_id = Some(EventTime::Zoned(
            day(2026, 8, 25).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        ));
        store.save(&over).unwrap();

        let cut = instance_on(&store, day(2026, 8, 18));
        store
            .truncate_series(&master.calendar_id, &master.uid, cut)
            .unwrap();

        let got = instants(&store);
        assert_eq!(
            got,
            vec![day(2026, 8, 4), day(2026, 8, 11)],
            "the orphaned override leaked past the cut"
        );
    }

    #[test]
    fn splitting_keeps_every_instance_exactly_once() {
        let (_dir, mut store) = store();
        let (_cal, master) = weekly_series(&mut store);
        let cut = instance_on(&store, day(2026, 8, 18));

        let outcome = store
            .split_series(&master.calendar_id, &master.uid, cut)
            .unwrap();
        let SplitOutcome::Split(successor) = outcome else {
            panic!("a mid-series cut must split");
        };

        // All four Tuesdays survive, each exactly once.
        assert_eq!(
            instants(&store),
            vec![
                day(2026, 8, 4),
                day(2026, 8, 11),
                day(2026, 8, 18),
                day(2026, 8, 25)
            ]
        );

        // The first two belong to the old series, the rest to the successor.
        let occurrences = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();
        let uids: Vec<&str> = occurrences.iter().map(|o| o.uid.as_str()).collect();
        assert_eq!(
            uids,
            vec![
                master.uid.as_str(),
                master.uid.as_str(),
                successor.uid.as_str(),
                successor.uid.as_str()
            ]
        );

        // The old master ends before the cut; an unbounded rule stays unbounded
        // on the successor.
        let old = store
            .event(&master.calendar_id, &master.uid)
            .unwrap()
            .unwrap();
        assert!(old.rrule.unwrap().contains("UNTIL="));
        let new_rule = successor.rrule.clone().unwrap();
        assert!(!new_rule.contains("UNTIL="), "{new_rule}");
        assert!(!new_rule.contains("COUNT="), "{new_rule}");
    }

    #[test]
    fn splitting_reduces_a_count_by_the_instances_the_master_keeps() {
        let (_dir, mut store) = store();
        let (_cal, mut master) = weekly_series(&mut store);
        master.rrule = Some("FREQ=WEEKLY;INTERVAL=1;COUNT=4".into());
        store.save(&master).unwrap();

        let cut = instance_on(&store, day(2026, 8, 18));
        let SplitOutcome::Split(successor) = store
            .split_series(&master.calendar_id, &master.uid, cut)
            .unwrap()
        else {
            panic!("a mid-series cut must split");
        };

        // Part order is not stable across a parse round-trip, so assert on the
        // parts themselves.
        let rule = successor.rrule.clone().unwrap();
        assert!(rule.contains("FREQ=WEEKLY"), "{rule}");
        assert!(rule.contains("COUNT=2"), "{rule}");
        assert!(!rule.contains("UNTIL="), "{rule}");

        // COUNT=4 in total: nothing may leak into September.
        let wide = store
            .occurrences(day(2026, 8, 1), day(2026, 10, 1), &HashSet::new())
            .unwrap();
        assert_eq!(wide.len(), 4);
    }

    #[test]
    fn splitting_rehomes_an_override_past_the_cut() {
        let (_dir, mut store) = store();
        let (_cal, master) = weekly_series(&mut store);

        // The 25th was moved to 14:00 by another client.
        let mut over = master.clone();
        over.rrule = None;
        over.summary = "Moved".into();
        over.start = EventTime::Zoned(day(2026, 8, 25).and_hms_opt(14, 0, 0).unwrap(), store.local);
        over.end = EventTime::Zoned(day(2026, 8, 25).and_hms_opt(15, 0, 0).unwrap(), store.local);
        over.recurrence_id = Some(EventTime::Zoned(
            day(2026, 8, 25).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        ));
        store.save(&over).unwrap();

        let cut = instance_on(&store, day(2026, 8, 18));
        let SplitOutcome::Split(successor) = store
            .split_series(&master.calendar_id, &master.uid, cut)
            .unwrap()
        else {
            panic!("a mid-series cut must split");
        };

        // The override survived the split, under the successor's identity.
        let moved = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap()
            .into_iter()
            .find(|o| o.start.date() == day(2026, 8, 25))
            .expect("the overridden instance survives the split");
        assert_eq!(moved.uid, successor.uid);
        assert_eq!(moved.summary, "Moved");
        assert_eq!(
            moved.start.time(),
            NaiveTime::from_hms_opt(14, 0, 0).unwrap()
        );

        // And it lives in the successor's file: deleting the old series does
        // not take it down.
        store.delete(&master.calendar_id, &master.uid).unwrap();
        assert_eq!(
            instants(&store),
            vec![day(2026, 8, 18), day(2026, 8, 25)],
            "the successor and its override outlive the old master"
        );
    }

    #[test]
    fn splitting_partitions_exclusions_at_the_cut() {
        let (_dir, mut store) = store();
        let (_cal, mut master) = weekly_series(&mut store);
        master.exdates = vec![
            day(2026, 8, 11).and_hms_opt(9, 0, 0).unwrap(),
            day(2026, 8, 25).and_hms_opt(9, 0, 0).unwrap(),
        ];
        store.save(&master).unwrap();

        let cut = instance_on(&store, day(2026, 8, 18));
        let SplitOutcome::Split(successor) = store
            .split_series(&master.calendar_id, &master.uid, cut)
            .unwrap()
        else {
            panic!("a mid-series cut must split");
        };

        // Both exclusions still hold, each on the side of the cut it belongs to.
        assert_eq!(instants(&store), vec![day(2026, 8, 4), day(2026, 8, 18)]);
        assert_eq!(
            successor.exdates,
            vec![day(2026, 8, 25).and_hms_opt(9, 0, 0).unwrap()]
        );
    }

    #[test]
    fn splitting_at_the_first_instance_declines() {
        let (_dir, mut store) = store();
        let (_cal, master) = weekly_series(&mut store);
        let cut = instance_on(&store, day(2026, 8, 4));

        let outcome = store
            .split_series(&master.calendar_id, &master.uid, cut)
            .unwrap();
        assert!(matches!(outcome, SplitOutcome::WholeSeries));

        // Nothing changed: the series is intact under its own identity.
        assert_eq!(instants(&store).len(), 4);
        let unchanged = store
            .event(&master.calendar_id, &master.uid)
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.rrule.as_deref(), Some("FREQ=WEEKLY;INTERVAL=1"));
    }

    /// The whole point of the index carrying attendees: `Store::event` reads
    /// from the cache, and whatever it hands back is what a later save writes.
    /// If the index dropped them, the file would lose them on the next edit
    /// even though the parser had read them correctly.
    #[test]
    fn attendees_survive_a_trip_through_the_index() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        // Written the way a server would send an invitation.
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Example//EN\r\n\
BEGIN:VEVENT\r\nUID:invite@example.com\r\nDTSTAMP:20260901T000000Z\r\n\
DTSTART:20260903T090000Z\r\nDTEND:20260903T100000Z\r\nSUMMARY:Planning\r\n\
ORGANIZER;CN=Ada:mailto:ada@example.com\r\n\
ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@example.com\r\n\
X-VENDOR-THING:keep me\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        std::fs::write(cal.path.join("invite.ics"), ics).unwrap();
        store.refresh().unwrap();

        // Read back through the index, edited, and saved — the ordinary path.
        let mut event = store
            .event(&cal.id, "invite@example.com")
            .unwrap()
            .expect("the invitation is indexed");
        assert_eq!(event.attendees.len(), 1, "the index dropped the attendee");
        assert_eq!(event.attendees[0].email, "bob@example.com");
        assert_eq!(
            event.organizer.as_ref().map(|o| o.email.as_str()),
            Some("ada@example.com")
        );

        event.summary = "Planning (renamed)".into();
        store.save(&event).unwrap();

        let on_disk = std::fs::read_to_string(cal.path.join("invite.ics")).unwrap();
        let unfolded: String = crate::patch::logical_lines(&on_disk)
            .iter()
            .map(|line| line.unfolded().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(unfolded.contains("Planning (renamed)"), "{unfolded}");
        assert!(
            unfolded.contains("bob@example.com"),
            "attendee lost: {unfolded}"
        );
        assert!(
            unfolded.contains("ada@example.com"),
            "organizer lost: {unfolded}"
        );
        assert!(unfolded.contains("X-VENDOR-THING:keep me"), "{unfolded}");
    }

    #[test]
    fn opens_empty_and_reports_no_calendars() {
        let (_dir, store) = store();
        assert!(store.calendars().is_empty());
        assert!(store.default_calendar().is_none());
        assert!(
            store
                .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn create_save_and_query() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            day(2026, 8, 4).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        );
        event.summary = "Standup".into();
        store.save(&event).unwrap();

        let got = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].summary, "Standup");
    }

    #[test]
    fn hidden_calendars_are_excluded() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            day(2026, 8, 4).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        );
        event.summary = "Standup".into();
        store.save(&event).unwrap();

        let hidden: HashSet<String> = [cal.id.clone()].into_iter().collect();
        assert!(
            store
                .occurrences(day(2026, 8, 1), day(2026, 9, 1), &hidden)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn delete_removes_the_event() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            day(2026, 8, 4).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        );
        event.summary = "Standup".into();
        store.save(&event).unwrap();
        store.delete(&cal.id, &event.uid).unwrap();

        assert!(
            store
                .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn multi_day_event_lands_in_every_day_it_touches() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            day(2026, 8, 4).and_hms_opt(0, 0, 0).unwrap(),
            store.local,
        );
        event.summary = "Conference".into();
        event.start = EventTime::Date(day(2026, 8, 4));
        event.end = EventTime::Date(day(2026, 8, 7)); // exclusive: 4th, 5th, 6th
        store.save(&event).unwrap();

        let by_day = store
            .occurrences_by_day(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();

        assert!(by_day.contains_key(&day(2026, 8, 4)));
        assert!(by_day.contains_key(&day(2026, 8, 5)));
        assert!(by_day.contains_key(&day(2026, 8, 6)));
        assert!(
            !by_day.contains_key(&day(2026, 8, 7)),
            "exclusive DTEND leaked into an extra day"
        );
    }

    #[test]
    fn recurring_event_appears_on_each_occurrence_day() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            day(2026, 8, 3).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        );
        event.summary = "Standup".into();
        event.rrule = Some("FREQ=WEEKLY".into());
        store.save(&event).unwrap();

        let by_day = store
            .occurrences_by_day(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();

        for d in [3u32, 10, 17, 24, 31] {
            assert!(by_day.contains_key(&day(2026, 8, d)), "missing {d} Aug");
        }
    }

    #[test]
    fn moving_between_calendars_leaves_one_copy() {
        let (_dir, mut store) = store();
        let a = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();
        let b = store.create_calendar("Work", Rgb(4, 5, 6)).unwrap();

        let mut event = Event::draft(
            &a.id,
            day(2026, 8, 4).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        );
        event.summary = "Standup".into();
        store.save(&event).unwrap();

        let moved = store.move_to_calendar(&event, &b.id).unwrap();
        assert_eq!(moved.calendar_id, b.id);

        let all = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();
        assert_eq!(all.len(), 1, "move left a duplicate behind");
        assert_eq!(all[0].calendar_id, b.id);
    }

    #[test]
    fn refresh_picks_up_externally_written_files() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        // Simulate vdirsyncer dropping a file in.
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
                   BEGIN:VEVENT\r\nUID:external@test\r\nDTSTART:20260804T120000Z\r\n\
                   DTEND:20260804T130000Z\r\nSUMMARY:From sync\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        std::fs::write(cal.path.join("external.ics"), ics).unwrap();

        assert!(
            store.refresh().unwrap(),
            "refresh did not notice the new file"
        );
        let got = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].summary, "From sync");
    }

    const SAMPLE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
         BEGIN:VEVENT\r\nUID:imported-1@test\r\nDTSTART:20260804T090000Z\r\n\
         DTEND:20260804T100000Z\r\nSUMMARY:Imported one\r\nEND:VEVENT\r\n\
         BEGIN:VEVENT\r\nUID:imported-2@test\r\nDTSTART:20260805T090000Z\r\n\
         DTEND:20260805T100000Z\r\nSUMMARY:Imported two\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn import_adds_every_event() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let summary = store.import_ics(SAMPLE, &cal.id).unwrap();
        assert_eq!(summary.added, 2);
        assert_eq!(summary.updated, 0);

        let got = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
            .unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn importing_the_same_file_twice_updates_rather_than_duplicates() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        store.import_ics(SAMPLE, &cal.id).unwrap();
        let second = store.import_ics(SAMPLE, &cal.id).unwrap();

        assert_eq!(second.added, 0, "re-import created duplicates");
        assert_eq!(second.updated, 2);
        assert_eq!(
            store
                .occurrences(day(2026, 8, 1), day(2026, 9, 1), &HashSet::new())
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn a_uid_with_path_separators_cannot_escape_the_collection() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let nasty = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
                     BEGIN:VEVENT\r\nUID:../../../../tmp/escaped\r\n\
                     DTSTART:20260804T090000Z\r\nDTEND:20260804T100000Z\r\n\
                     SUMMARY:Nasty\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

        store.import_ics(nasty, &cal.id).unwrap();

        let written: Vec<String> = std::fs::read_dir(&cal.path)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".ics"))
            .collect();

        assert_eq!(written.len(), 1);
        assert!(
            !written[0].contains('/') && !written[0].contains(".."),
            "unsanitised UID became the file name: {}",
            written[0]
        );

        // The property that actually matters: the file landed inside the collection.
        let written_path = cal.path.join(&written[0]).canonicalize().unwrap();
        assert!(
            written_path.starts_with(cal.path.canonicalize().unwrap()),
            "import escaped the collection directory: {}",
            written_path.display()
        );
    }

    #[test]
    fn export_round_trips_through_import() {
        let (_dir, mut store) = store();
        let a = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();
        let b = store.create_calendar("Work", Rgb(4, 5, 6)).unwrap();

        store.import_ics(SAMPLE, &a.id).unwrap();
        let exported = store.export_calendar(&a.id).unwrap();

        let summary = store.import_ics(&exported, &b.id).unwrap();
        assert_eq!(summary.added, 2, "export lost events on the way back in");

        let hidden: HashSet<String> = [a.id.clone()].into_iter().collect();
        let in_b = store
            .occurrences(day(2026, 8, 1), day(2026, 9, 1), &hidden)
            .unwrap();
        assert_eq!(in_b.len(), 2);
        assert!(in_b.iter().all(|o| o.calendar_id == b.id));
    }

    #[test]
    fn exporting_an_unknown_calendar_is_an_error() {
        let (_dir, store) = store();
        assert!(matches!(
            store.export_calendar("nope"),
            Err(StoreError::UnknownCalendar(_))
        ));
    }

    #[test]
    fn sanitised_stems_stay_usable() {
        assert_eq!(sanitise_file_stem("abc-123"), "abc-123");
        assert_eq!(sanitise_file_stem("a@b.com"), "a-b.com");
        assert_eq!(
            sanitise_file_stem("a..b"),
            "a.b",
            "consecutive dots survived"
        );
        assert!(!sanitise_file_stem("../../etc/passwd").contains(".."));
        // An entirely unusable UID still yields something writable.
        assert!(!sanitise_file_stem("///").is_empty());
    }

    #[test]
    fn saving_to_an_unknown_calendar_is_an_error() {
        let (_dir, mut store) = store();
        let event = Event::draft(
            "nope",
            day(2026, 8, 4).and_hms_opt(9, 0, 0).unwrap(),
            store.local,
        );
        assert!(matches!(
            store.save(&event),
            Err(StoreError::UnknownCalendar(_))
        ));
    }
}

#[cfg(test)]
mod todo_tests {
    use super::*;
    use crate::model::{EventTime, Todo, TodoStatus};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::open(&dir.path().join("calendars"), &dir.path().join("i.sqlite")).unwrap();
        (dir, store)
    }

    #[test]
    fn a_task_round_trips_through_the_store() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let mut todo = Todo::draft(&cal.id);
        todo.summary = "Buy milk".into();
        todo.due = Some(EventTime::Date(
            NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
        ));
        store.save_todo(&todo).unwrap();

        let all = store.todos(&HashSet::new());
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].summary, "Buy milk");
        assert_eq!(all[0].due, todo.due);
    }

    #[test]
    fn tasks_and_events_coexist_in_one_collection_without_seeing_each_other() {
        // The property that lets a CalDAV collection holding both kinds work.
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            store.local,
        );
        event.summary = "Meeting".into();
        store.save(&event).unwrap();

        let mut todo = Todo::draft(&cal.id);
        todo.summary = "Buy milk".into();
        store.save_todo(&todo).unwrap();

        assert_eq!(
            store.todos(&HashSet::new()).len(),
            1,
            "an event leaked into the task list"
        );
        assert_eq!(
            store
                .occurrences(
                    NaiveDate::from_ymd_opt(2026, 8, 1).unwrap(),
                    NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(),
                    &HashSet::new()
                )
                .unwrap()
                .len(),
            1,
            "a task leaked into the calendar grid"
        );
    }

    #[test]
    fn hidden_calendars_are_excluded_from_the_task_list() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();
        let mut todo = Todo::draft(&cal.id);
        todo.summary = "Buy milk".into();
        store.save_todo(&todo).unwrap();

        let hidden: HashSet<String> = [cal.id.clone()].into_iter().collect();
        assert!(store.todos(&hidden).is_empty());
    }

    #[test]
    fn completing_a_task_survives_a_reload() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();
        let mut todo = Todo::draft(&cal.id);
        todo.summary = "Buy milk".into();
        store.save_todo(&todo).unwrap();

        todo.set_done(true);
        store.save_todo(&todo).unwrap();

        let back = store.todo(&cal.id, &todo.uid).expect("task is still there");
        assert!(back.is_done());
        assert_eq!(back.status, TodoStatus::Completed);
    }

    #[test]
    fn deleting_a_task_removes_it() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();
        let mut todo = Todo::draft(&cal.id);
        todo.summary = "Buy milk".into();
        store.save_todo(&todo).unwrap();

        store.delete_todo(&cal.id, &todo.uid).unwrap();
        assert!(store.todos(&HashSet::new()).is_empty());
    }

    #[test]
    fn the_task_list_comes_back_sorted() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let mut undated = Todo::draft(&cal.id);
        undated.summary = "Someday".into();
        store.save_todo(&undated).unwrap();

        let mut soon = Todo::draft(&cal.id);
        soon.summary = "Tomorrow".into();
        soon.due = Some(EventTime::Date(
            NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
        ));
        store.save_todo(&soon).unwrap();

        let mut done = Todo::draft(&cal.id);
        done.summary = "Finished".into();
        done.set_done(true);
        store.save_todo(&done).unwrap();

        let names: Vec<String> = store
            .todos(&HashSet::new())
            .into_iter()
            .map(|t| t.summary)
            .collect();
        assert_eq!(names, vec!["Tomorrow", "Someday", "Finished"]);
    }

    #[test]
    fn saving_to_an_unknown_calendar_is_an_error() {
        let (_dir, mut store) = store();
        let todo = Todo::draft("nope");
        assert!(matches!(
            store.save_todo(&todo),
            Err(StoreError::UnknownCalendar(_))
        ));
    }

    #[test]
    fn an_externally_written_task_file_is_picked_up() {
        let (_dir, mut store) = store();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        // Simulate vdirsyncer dropping in a task from a server.
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
                   BEGIN:VTODO\r\nUID:ext@test\r\nSUMMARY:From sync\r\n\
                   STATUS:NEEDS-ACTION\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        std::fs::write(cal.path.join("external.ics"), ics).unwrap();

        let all = store.todos(&HashSet::new());
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].summary, "From sync");
    }
}

#[cfg(test)]
mod sidecar_hygiene_tests {
    use super::*;
    use crate::model::Todo;

    /// Everything a collection legitimately contains besides its items.
    ///
    /// The readers filter on extension, so this holds today; it is pinned
    /// because the failure is silent and ugly — a sidecar parsed as calendar
    /// data becomes a phantom event that cannot be deleted, since deleting it
    /// removes the file the sync engine needs.
    fn litter(dir: &std::path::Path) {
        for (name, body) in [
            (".caldav-state.json", r#"{"ctag":"x","entries":{}}"#),
            (
                ".abc.ics.tmp",
                "BEGIN:VCALENDAR
END:VCALENDAR
",
            ),
            (
                "abc.ics.1718700000.conflict",
                "BEGIN:VCALENDAR
END:VCALENDAR
",
            ),
            (".vdirsyncer", "status"),
            (".vdirsyncer.status", "{}"),
            ("README", "not calendar data"),
        ] {
            std::fs::write(dir.join(name), body).unwrap();
        }
    }

    #[test]
    fn sidecars_are_not_read_as_events_or_tasks() {
        let dir = tempfile::tempdir().unwrap();
        let mut store =
            Store::open(&dir.path().join("calendars"), &dir.path().join("i.sqlite")).unwrap();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();

        let mut event = Event::draft(
            &cal.id,
            NaiveDate::from_ymd_opt(2026, 8, 4)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap(),
            store.local,
        );
        event.summary = "Real".into();
        store.save(&event).unwrap();

        let mut todo = Todo::draft(&cal.id);
        todo.summary = "Also real".into();
        store.save_todo(&todo).unwrap();

        litter(&cal.path);
        store.refresh().unwrap();

        let occurrences = store
            .occurrences(
                NaiveDate::from_ymd_opt(2026, 8, 1).unwrap(),
                NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(),
                &HashSet::new(),
            )
            .unwrap();
        assert_eq!(occurrences.len(), 1, "a sidecar was read as an event");
        assert_eq!(
            store.todos(&HashSet::new()).len(),
            1,
            "a sidecar was read as a task"
        );
    }

    #[test]
    fn sidecars_are_not_read_as_contacts() {
        let dir = tempfile::tempdir().unwrap();
        let mut books = contacts::ContactStore::open(&dir.path().join("contacts")).unwrap();
        let book = books.create_book("Contacts", Rgb(1, 2, 3)).unwrap();

        std::fs::write(
            book.path.join("ada.vcf"),
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a@t\r\nFN:Ada\r\nEND:VCARD\r\n",
        )
        .unwrap();
        litter(&book.path);

        assert_eq!(books.contacts().len(), 1, "a sidecar was read as a contact");
    }

    #[test]
    fn a_collection_full_of_sidecars_reads_as_empty_rather_than_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let mut store =
            Store::open(&dir.path().join("calendars"), &dir.path().join("i.sqlite")).unwrap();
        let cal = store.create_calendar("Personal", Rgb(1, 2, 3)).unwrap();
        litter(&cal.path);

        assert!(store.refresh().is_ok());
        assert!(store.todos(&HashSet::new()).is_empty());
    }
}

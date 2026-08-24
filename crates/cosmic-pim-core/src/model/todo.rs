// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Tasks: `VTODO`, the other half of what a calendar collection can hold.
//!
//! # Why this lives beside `Event` rather than reusing it
//!
//! A VTODO and a VEVENT look similar and behave differently in the ways that
//! matter. An event *occupies* time — it has a start and an exclusive end, and
//! the question "is it on today's grid" is about overlap. A task has a **due**
//! date and an optional start, either of which may be absent entirely: "buy
//! milk" with no date at all is a completely ordinary task and a nonsensical
//! event. Modelling a task as an event with a zero-length span forces a fake
//! date onto everything undated, and then every query has to know which dates
//! are real.
//!
//! What is shared is everything below the domain: the vdir layout, the atomic
//! writer, the iCalendar text layer, the CalDAV engine. That is the point of
//! the split — this module is a few hundred lines precisely because none of
//! that had to be written again.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use chrono_tz::Tz;

use crate::model::EventTime;

/// RFC 5545 §3.8.1.11 `STATUS` for a VTODO.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TodoStatus {
    #[default]
    NeedsAction,
    InProcess,
    Completed,
    Cancelled,
}

impl TodoStatus {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "NEEDS-ACTION" => Some(Self::NeedsAction),
            "IN-PROCESS" => Some(Self::InProcess),
            "COMPLETED" => Some(Self::Completed),
            "CANCELLED" => Some(Self::Cancelled),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_ical(self) -> &'static str {
        match self {
            Self::NeedsAction => "NEEDS-ACTION",
            Self::InProcess => "IN-PROCESS",
            Self::Completed => "COMPLETED",
            Self::Cancelled => "CANCELLED",
        }
    }

    /// Whether the task is finished, one way or another.
    ///
    /// Cancelled counts: the user is done with it either way, and a list that
    /// keeps showing cancelled tasks under "to do" is wrong.
    #[must_use]
    pub fn is_closed(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

/// One task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Todo {
    pub uid: String,
    /// The collection directory this task lives in.
    pub calendar_id: String,
    pub summary: String,
    pub description: Option<String>,
    /// When it must be done. `None` is normal and common.
    pub due: Option<EventTime>,
    /// When work on it may begin. Rarer than `due`, but servers do send it.
    pub start: Option<EventTime>,
    pub status: TodoStatus,
    /// RFC 5545 §3.8.1.9: 0 = undefined, 1 = highest, 9 = lowest.
    ///
    /// Kept as the raw number rather than a three-value enum because the
    /// numeric scale is what round-trips: mapping 1–4 to "high" and back to 1
    /// would silently rewrite a task another client set to 2.
    pub priority: u8,
    /// 0–100. Only meaningful for [`TodoStatus::InProcess`], but stored
    /// whatever the status, because clients set it independently.
    pub percent_complete: u8,
    pub completed: Option<DateTime<Utc>>,
    /// Raw `RRULE`, preserved verbatim. Recurring tasks are unusual but legal.
    pub rrule: Option<String>,
    /// `VALARM` triggers, as offsets from the due date.
    pub alarms: Vec<chrono::Duration>,
    /// `RELATED-TO` — the uid of a parent task, for subtasks.
    pub related_to: Option<String>,
    pub categories: Vec<String>,
    pub sequence: i32,
    pub created: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    /// File name within the collection directory.
    pub file_name: String,
}

impl Todo {
    /// A new, undated task.
    #[must_use]
    pub fn draft(calendar_id: &str) -> Self {
        let uid = format!("{}@cosmic-pim", uuid::Uuid::new_v4());
        Self {
            file_name: format!("{}.ics", uuid::Uuid::new_v4()),
            uid,
            calendar_id: calendar_id.to_owned(),
            summary: String::new(),
            description: None,
            due: None,
            start: None,
            status: TodoStatus::NeedsAction,
            priority: 0,
            percent_complete: 0,
            completed: None,
            rrule: None,
            alarms: Vec::new(),
            related_to: None,
            categories: Vec::new(),
            sequence: 0,
            created: Some(Utc::now()),
            last_modified: Some(Utc::now()),
        }
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        self.status.is_closed()
    }

    /// The local date this task is due on, if it has a due date.
    #[must_use]
    pub fn due_date(&self, local: Tz) -> Option<NaiveDate> {
        self.due.map(|due| due.date(local))
    }

    /// Whether the task is overdue as of `now`.
    ///
    /// A finished task is never overdue however old it is, and an undated one
    /// cannot be — both are the sort of thing that produces a permanently red
    /// task list if left to a naive date comparison.
    #[must_use]
    pub fn is_overdue(&self, now: NaiveDateTime, local: Tz) -> bool {
        if self.is_done() {
            return false;
        }
        match self.due {
            // An all-day task is due at the END of its day, not at midnight:
            // marking "today" overdue from 00:00 onwards is wrong by a day.
            Some(EventTime::Date(d)) => now.date() > d,
            Some(other) => other.naive_local(local) < now,
            None => false,
        }
    }

    /// Marks the task done, or reopens it.
    ///
    /// Setting `COMPLETED` and `PERCENT-COMPLETE` alongside `STATUS` is not
    /// optional bookkeeping: clients disagree about which one they read, and a
    /// task that says `STATUS:COMPLETED` with `PERCENT-COMPLETE:0` shows up
    /// half-done in some of them.
    pub fn set_done(&mut self, done: bool) {
        if done {
            self.status = TodoStatus::Completed;
            self.percent_complete = 100;
            self.completed = Some(Utc::now());
        } else {
            self.status = TodoStatus::NeedsAction;
            self.percent_complete = 0;
            self.completed = None;
        }
        self.last_modified = Some(Utc::now());
        self.sequence = self.sequence.saturating_add(1);
    }

    /// Sort key for a task list: unfinished first, then by due date with
    /// undated last, then by priority, then by name.
    ///
    /// Undated tasks sort last rather than first because a list that opens with
    /// everything the user never scheduled buries the things that are actually
    /// due.
    #[must_use]
    pub fn sort_key(&self, local: Tz) -> (bool, bool, Option<NaiveDate>, u8, String) {
        let due = self.due_date(local);
        (
            self.is_done(),
            // `Option` sorts `None` FIRST in Rust, which is the opposite of
            // what a task list wants; this leading flag inverts it.
            due.is_none(),
            due,
            // Priority 0 means "unset", which must sort after 1–9 rather than
            // before them.
            if self.priority == 0 {
                u8::MAX
            } else {
                self.priority
            },
            self.summary.to_lowercase(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, m: u32, d: u32, h: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, 0, 0)
            .unwrap()
    }

    #[test]
    fn a_draft_is_undated_and_unfinished() {
        let todo = Todo::draft("personal");
        assert!(todo.due.is_none());
        assert!(!todo.is_done());
        assert_eq!(todo.status, TodoStatus::NeedsAction);
    }

    #[test]
    fn status_round_trips_through_its_ical_form() {
        for status in [
            TodoStatus::NeedsAction,
            TodoStatus::InProcess,
            TodoStatus::Completed,
            TodoStatus::Cancelled,
        ] {
            assert_eq!(TodoStatus::parse(status.as_ical()), Some(status));
        }
        assert_eq!(
            TodoStatus::parse("needs-action"),
            Some(TodoStatus::NeedsAction)
        );
        assert_eq!(TodoStatus::parse("nonsense"), None);
    }

    #[test]
    fn a_cancelled_task_counts_as_closed() {
        assert!(TodoStatus::Cancelled.is_closed());
        assert!(TodoStatus::Completed.is_closed());
        assert!(!TodoStatus::InProcess.is_closed());
    }

    #[test]
    fn marking_done_sets_status_percent_and_timestamp_together() {
        let mut todo = Todo::draft("personal");
        todo.set_done(true);

        assert_eq!(todo.status, TodoStatus::Completed);
        assert_eq!(
            todo.percent_complete, 100,
            "a completed task left at 0% shows half-done in other clients"
        );
        assert!(todo.completed.is_some());
    }

    #[test]
    fn reopening_clears_the_completion_marks() {
        let mut todo = Todo::draft("personal");
        todo.set_done(true);
        todo.set_done(false);

        assert_eq!(todo.status, TodoStatus::NeedsAction);
        assert_eq!(todo.percent_complete, 0);
        assert!(todo.completed.is_none());
    }

    #[test]
    fn an_undated_task_is_never_overdue() {
        let todo = Todo::draft("personal");
        assert!(!todo.is_overdue(at(2030, 1, 1, 12), chrono_tz::UTC));
    }

    #[test]
    fn a_finished_task_is_never_overdue() {
        let mut todo = Todo::draft("personal");
        todo.due = Some(EventTime::Date(
            NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(),
        ));
        todo.set_done(true);
        assert!(!todo.is_overdue(at(2030, 1, 1, 12), chrono_tz::UTC));
    }

    #[test]
    fn an_all_day_task_is_not_overdue_until_its_day_has_passed() {
        let mut todo = Todo::draft("personal");
        todo.due = Some(EventTime::Date(
            NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
        ));

        assert!(
            !todo.is_overdue(at(2026, 8, 4, 0), chrono_tz::UTC),
            "due today became overdue at midnight"
        );
        assert!(!todo.is_overdue(at(2026, 8, 4, 23), chrono_tz::UTC));
        assert!(todo.is_overdue(at(2026, 8, 5, 0), chrono_tz::UTC));
    }

    #[test]
    fn a_timed_task_is_overdue_after_its_moment() {
        let mut todo = Todo::draft("personal");
        todo.due = Some(EventTime::Zoned(at(2026, 8, 4, 17), chrono_tz::UTC));

        assert!(!todo.is_overdue(at(2026, 8, 4, 16), chrono_tz::UTC));
        assert!(todo.is_overdue(at(2026, 8, 4, 18), chrono_tz::UTC));
    }

    #[test]
    fn sorting_puts_unfinished_before_finished() {
        let mut done = Todo::draft("personal");
        done.summary = "aaa".into();
        done.set_done(true);
        let mut open = Todo::draft("personal");
        open.summary = "zzz".into();

        assert!(open.sort_key(chrono_tz::UTC) < done.sort_key(chrono_tz::UTC));
    }

    #[test]
    fn sorting_puts_undated_tasks_last() {
        let mut dated = Todo::draft("personal");
        dated.summary = "zzz".into();
        dated.due = Some(EventTime::Date(
            NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
        ));
        let mut undated = Todo::draft("personal");
        undated.summary = "aaa".into();

        assert!(
            dated.sort_key(chrono_tz::UTC) < undated.sort_key(chrono_tz::UTC),
            "undated tasks buried the ones actually due"
        );
    }

    #[test]
    fn unset_priority_sorts_after_every_real_priority() {
        let mut unset = Todo::draft("personal");
        unset.priority = 0;
        let mut lowest = Todo::draft("personal");
        lowest.priority = 9;

        assert!(
            lowest.sort_key(chrono_tz::UTC) < unset.sort_key(chrono_tz::UTC),
            "priority 0 means unset, not highest"
        );
    }
}

// SPDX-License-Identifier: MPL-2.0

//! The calendar domain: collections, events, and their expansion into occurrences.
//!
//! Nothing here depends on libcosmic, so the whole layer is testable without a
//! display server.

pub mod calendar;
pub mod contact;
pub mod event;
pub mod recur;
pub mod todo;

pub use calendar::{CalendarMeta, DEFAULT_CALENDAR_COLOR, PALETTE, Rgb};
pub use contact::{Address, Contact, StructuredName, Typed};
pub use event::{Event, EventTime, Freq, Occurrence, Recurrence, RepeatEnd};
pub use recur::expand;
pub use todo::{Todo, TodoStatus};

use chrono_tz::Tz;

/// The system's IANA timezone.
///
/// Resolved through `jiff`, which reads `/etc/localtime` and `TZ`. It is already
/// in the dependency graph via libcosmic's calendar widget, so this costs us
/// nothing extra. Falls back to UTC if the system has no usable zone.
#[must_use]
pub fn local_timezone() -> Tz {
    jiff::tz::TimeZone::system()
        .iana_name()
        .and_then(|name| name.parse::<Tz>().ok())
        .unwrap_or(chrono_tz::UTC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_timezone_resolves() {
        // Should never panic, whatever the host is configured with.
        let _ = local_timezone();
    }
}

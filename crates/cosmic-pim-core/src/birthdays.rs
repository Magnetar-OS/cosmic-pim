// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Birthdays as calendar occurrences, straight from the address book.
//!
//! Slate shows birthdays without anyone maintaining a fake birthday calendar:
//! the address book already knows them, so this synthesises an occurrence
//! stream from `BDAY` on demand. Nothing is written anywhere — a birthday is
//! not an event file, it is a fact about a contact, and materialising it as
//! `.ics` would mean a second copy to keep in step with every card edit.
//!
//! Year-less birthdays (`BDAY:--0415` — legal, and common for people who
//! prefer not to state an age) appear in the stream like any other, just with
//! no age to report.
//!
//! # 29 February
//!
//! A birthday on the 29th is celebrated on **28 February** in non-leap years,
//! rather than 1 March or not at all. Skipping it entirely is obviously wrong
//! (the person exists every year); 1 March moves the anniversary into another
//! month, which reads as a bug in a month view. Either convention is arguable;
//! this one is pinned by a test so it stays a decision rather than drifting.

use chrono::{Datelike, NaiveDate};

use crate::model::Contact;

/// One birthday falling inside a queried range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BirthdayOccurrence {
    /// The day it is celebrated this year (see the module note on 29 Feb).
    pub date: NaiveDate,
    /// The book the contact lives in, for click-through.
    pub book_id: String,
    /// The contact's UID within that book.
    pub uid: String,
    /// The contact's display label at synthesis time.
    pub name: String,
    /// The age being turned, when the card states a year. `None` for a
    /// year-less `BDAY` — never invented.
    pub turns: Option<i32>,
}

/// Every birthday in `[start, end)`, sorted by date then name.
///
/// Group cards never have birthdays; contacts without a `BDAY` cost nothing.
/// The caller hands in whatever contacts it already holds —
/// `ContactStore::contacts()` in the apps — so this stays pure and testable.
#[must_use]
pub fn in_range(contacts: &[Contact], start: NaiveDate, end: NaiveDate) -> Vec<BirthdayOccurrence> {
    let mut out = Vec::new();
    if start >= end {
        return out;
    }

    for contact in contacts {
        let (month, day, birth_year) = match (contact.birthday, contact.birthday_month_day) {
            (Some(date), _) => (date.month(), date.day(), Some(date.year())),
            (None, Some((month, day))) => (month, day, None),
            (None, None) => continue,
        };

        for year in start.year()..=end.year() {
            let Some(date) = celebrated_on(year, month, day) else {
                continue;
            };
            if date < start || date >= end {
                continue;
            }
            out.push(BirthdayOccurrence {
                date,
                book_id: contact.addressbook_id.clone(),
                uid: contact.uid.clone(),
                name: contact.label(),
                turns: birth_year.map(|born| year - born),
            });
        }
    }

    out.sort_by(|a, b| (a.date, &a.name).cmp(&(b.date, &b.name)));
    out
}

/// The date a `month`/`day` birthday is celebrated in `year`.
fn celebrated_on(year: i32, month: u32, day: u32) -> Option<NaiveDate> {
    NaiveDate::from_ymd_opt(year, month, day).or_else(|| {
        // Only 29 Feb can fail for a date that was valid in some year.
        (month == 2 && day == 29)
            .then(|| NaiveDate::from_ymd_opt(year, 2, 28))
            .flatten()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn contact(name: &str, birthday: Option<NaiveDate>, md: Option<(u32, u32)>) -> Contact {
        let mut c = Contact::draft("book-1");
        c.display_name = name.to_owned();
        c.birthday = birthday;
        c.birthday_month_day = md;
        c
    }

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn a_birthday_inside_the_range_appears_with_its_age() {
        let ada = contact("Ada", Some(date(1815, 12, 10)), None);
        let hits = in_range(&[ada], date(2026, 12, 1), date(2027, 1, 1));

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].date, date(2026, 12, 10));
        assert_eq!(hits[0].turns, Some(211));
        assert_eq!(hits[0].name, "Ada");
    }

    #[test]
    fn a_year_less_birthday_appears_ageless() {
        let x = contact("Maria", None, Some((4, 15)));
        let hits = in_range(&[x], date(2026, 4, 1), date(2026, 5, 1));

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].date, date(2026, 4, 15));
        assert_eq!(
            hits[0].turns, None,
            "an age was invented for a year-less BDAY"
        );
    }

    #[test]
    fn a_range_spanning_new_year_finds_both_sides() {
        let dec = contact("December", Some(date(1990, 12, 30)), None);
        let jan = contact("January", Some(date(1990, 1, 2)), None);
        let hits = in_range(&[dec, jan], date(2026, 12, 20), date(2027, 1, 10));

        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].date, date(2026, 12, 30));
        assert_eq!(hits[1].date, date(2027, 1, 2));
    }

    #[test]
    fn leap_day_birthdays_land_on_the_28th_in_common_years() {
        let leapling = contact("Leapling", Some(date(2000, 2, 29)), None);

        let common = in_range(
            std::slice::from_ref(&leapling),
            date(2026, 2, 1),
            date(2026, 3, 1),
        );
        assert_eq!(common.len(), 1, "the leapling vanished in a common year");
        assert_eq!(common[0].date, date(2026, 2, 28));

        let leap = in_range(&[leapling], date(2028, 2, 1), date(2028, 3, 1));
        assert_eq!(leap[0].date, date(2028, 2, 29));
    }

    #[test]
    fn contacts_without_birthdays_cost_nothing() {
        let none = contact("Nobody", None, None);
        assert!(in_range(&[none], date(2026, 1, 1), date(2027, 1, 1)).is_empty());
    }

    #[test]
    fn a_birthday_outside_the_range_is_absent() {
        let ada = contact("Ada", Some(date(1815, 12, 10)), None);
        assert!(in_range(&[ada], date(2026, 1, 1), date(2026, 12, 1)).is_empty());
    }

    #[test]
    fn the_range_end_is_exclusive() {
        let ada = contact("Ada", Some(date(1815, 12, 10)), None);
        assert!(
            in_range(
                std::slice::from_ref(&ada),
                date(2026, 12, 1),
                date(2026, 12, 10)
            )
            .is_empty()
        );
        assert_eq!(
            in_range(&[ada], date(2026, 12, 10), date(2026, 12, 11)).len(),
            1
        );
    }

    #[test]
    fn a_multi_year_range_repeats_the_birthday() {
        let ada = contact("Ada", Some(date(1815, 12, 10)), None);
        let hits = in_range(&[ada], date(2026, 1, 1), date(2028, 1, 1));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].turns, Some(211));
        assert_eq!(hits[1].turns, Some(212));
    }

    #[test]
    fn same_day_birthdays_sort_by_name() {
        let b = contact("Beta", Some(date(1990, 6, 1)), None);
        let a = contact("Alpha", Some(date(1985, 6, 1)), None);
        let hits = in_range(&[b, a], date(2026, 6, 1), date(2026, 6, 2));
        assert_eq!(hits[0].name, "Alpha");
        assert_eq!(hits[1].name, "Beta");
    }
}

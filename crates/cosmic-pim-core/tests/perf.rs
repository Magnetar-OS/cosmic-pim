// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Performance baseline for the query path the calendar grids sit on.
//!
//! Ignored by default so `cargo test` stays fast; run it in release, where the
//! numbers mean something:
//!
//! ```sh
//! cargo test --release -p cosmic-pim-core --test perf -- --ignored --nocapture
//! ```
//!
//! The workload models a busy month view: 200 one-off events plus 50 weekly
//! series (≈420 expanded instances) queried over a 31-day window — the shape
//! `Store::occurrences` is called with on every reload. Recorded baselines
//! live in slate's PERFORMANCE.md; re-run this after touching the index query
//! or the expansion path and compare.

use chrono::NaiveDate;
use cosmic_pim_core::Store;
use cosmic_pim_core::model::{Event, Rgb};
use std::collections::HashSet;
use std::time::Instant;

fn day(d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 8, d.min(31)).unwrap()
}

#[test]
#[ignore = "perf baseline; run explicitly in release with --nocapture"]
fn occurrences_over_a_busy_month() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        Store::open(&dir.path().join("calendars"), &dir.path().join("ix.sqlite")).unwrap();
    let cal = store.create_calendar("Perf", Rgb(1, 2, 3)).unwrap();
    let local = store.local_timezone();

    // 200 one-off events spread across the month, up to 5 an hour.
    for i in 0..200u32 {
        let date = day(1 + (i % 28));
        let hour = 8 + (i / 28) % 10;
        let start = date.and_hms_opt(hour, 0, 0).unwrap();
        let mut event = Event::draft(&cal.id, start, local);
        event.summary = format!("One-off {i}");
        store.save(&event).unwrap();
    }

    // 50 weekly series, staggered across weekdays and hours.
    for i in 0..50u32 {
        let start = day(3 + (i % 5)).and_hms_opt(9 + (i % 8), 30, 0).unwrap();
        let mut event = Event::draft(&cal.id, start, local);
        event.summary = format!("Series {i}");
        event.rrule = Some("FREQ=WEEKLY".into());
        store.save(&event).unwrap();
    }

    let hidden = HashSet::new();
    let from = day(1);
    let to = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap();

    // Warm-up, and a sanity check that the workload is what it claims.
    let occurrences = store.occurrences(from, to, &hidden).unwrap();
    assert!(
        occurrences.len() > 350,
        "expected a busy month, got {} occurrences",
        occurrences.len()
    );

    const RUNS: usize = 100;
    let mut samples: Vec<u128> = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let t = Instant::now();
        let got = store.occurrences(from, to, &hidden).unwrap();
        samples.push(t.elapsed().as_micros());
        std::hint::black_box(got);
    }
    samples.sort_unstable();

    println!(
        "occurrences() over 31 days, {} instances: min {} µs · p50 {} µs · p95 {} µs",
        occurrences.len(),
        samples[0],
        samples[RUNS / 2],
        samples[RUNS * 95 / 100],
    );
}

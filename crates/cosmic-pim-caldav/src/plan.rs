// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// Ported verbatim from `src-tauri/src/caldav.rs` in the Meltemi project.
// See NOTICE and LICENSING.md.

//! The reconciliation decision: given what the server lists and what we hold,
//! decide what to fetch and what to delete.
//!
//! This is deliberately a pure function over two plain collections. It has no
//! idea whether "what we hold" is a SQLite table or a directory of files, which
//! is what let it move between the two projects untouched — and it prevents the
//! two subtlest bugs in CalDAV sync, so it is also the part most worth testing.

use std::collections::{HashMap, HashSet};

use crate::dav::PropfindEventsResult;

/// The pure diff between a server listing and the local href→etag map.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct SyncPlan {
    /// New hrefs, plus hrefs whose etag changed.
    pub to_fetch: Vec<String>,
    /// Local hrefs absent from the listing — MINUS server-reported failures.
    pub to_delete: Vec<String>,
    /// True when the empty-listing mass-delete guard fired: the server
    /// returned ZERO entries while the local map is non-empty. That shape is
    /// far more often a server-side hiccup (SOGo transient, an auth blip that
    /// still produced a 207) than a genuine everything-was-deleted; deletes are
    /// skipped for the round and the next sync self-corrects.
    ///
    /// The cost was live-confirmed (server matrix, 2026-08-25): a collection
    /// whose last event was legitimately deleted never emptied locally. The
    /// fix is confirm-on-second-sight, and it lives above this planner: the
    /// cycle remembers the ctag the guard fired under
    /// (`store::EmptySighting`), and a later cycle seeing the same ctag with
    /// the same empty listing confirms the emptying and applies the
    /// deletions. This planner still only *reports* the trip — arming,
    /// confirming, and clearing the sighting are the cycle's business, and a
    /// listing degraded by per-resource failures never arms or confirms.
    pub guard_tripped: bool,
}

pub fn plan_sync(listing: &PropfindEventsResult, local: &HashMap<String, String>) -> SyncPlan {
    let mut plan = SyncPlan::default();

    if listing.entries.is_empty() && !local.is_empty() {
        plan.guard_tripped = true;
        return plan;
    }

    let mut remote_hrefs: HashSet<&str> = HashSet::with_capacity(listing.entries.len());
    for entry in &listing.entries {
        remote_hrefs.insert(entry.uri.as_str());
        match local.get(&entry.uri) {
            Some(stored_etag) if stored_etag == &entry.etag => {}
            _ => plan.to_fetch.push(entry.uri.clone()),
        }
    }
    // A resource the server itself reported as failing is NOT absent — treating
    // it as a deletion is how a transient per-resource 500 silently removes a
    // user's event.
    let failed: HashSet<&str> = listing.failed_uris.iter().map(String::as_str).collect();
    for href in local.keys() {
        if !remote_hrefs.contains(href.as_str()) && !failed.contains(href.as_str()) {
            plan.to_delete.push(href.clone());
        }
    }
    plan.to_delete.sort();
    plan
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dav::CalDavEventEntry;

    /* ---------------- reconcile plan ---------------- */

    fn entry(uri: &str, etag: &str) -> CalDavEventEntry {
        CalDavEventEntry {
            uri: uri.into(),
            etag: etag.into(),
        }
    }

    #[test]
    fn plan_fetches_new_and_changed_deletes_absent() {
        let listing = PropfindEventsResult {
            entries: vec![entry("/a.ics", "\"1\""), entry("/b.ics", "\"2\"")],
            failed_uris: vec![],
        };
        let local: HashMap<String, String> = [
            ("/a.ics".to_string(), "\"1\"".to_string()), // unchanged
            ("/gone.ics".to_string(), "\"9\"".to_string()), // absent → delete
        ]
        .into_iter()
        .collect();
        let plan = plan_sync(&listing, &local);
        assert_eq!(plan.to_fetch, vec!["/b.ics".to_string()]);
        assert_eq!(plan.to_delete, vec!["/gone.ics".to_string()]);
        assert!(!plan.guard_tripped);
    }

    #[test]
    fn plan_preserves_server_reported_failures() {
        // A failed href absent from entries must NOT be deleted.
        let listing = PropfindEventsResult {
            entries: vec![entry("/a.ics", "\"1\"")],
            failed_uris: vec!["/flaky.ics".to_string()],
        };
        let local: HashMap<String, String> = [
            ("/a.ics".to_string(), "\"1\"".to_string()),
            ("/flaky.ics".to_string(), "\"7\"".to_string()),
        ]
        .into_iter()
        .collect();
        let plan = plan_sync(&listing, &local);
        assert!(plan.to_delete.is_empty(), "failed href must be preserved");
    }

    #[test]
    fn plan_trips_mass_delete_guard_on_empty_listing() {
        let listing = PropfindEventsResult::default();
        let local: HashMap<String, String> = [("/a.ics".to_string(), "\"1\"".to_string())]
            .into_iter()
            .collect();
        let plan = plan_sync(&listing, &local);
        assert!(plan.guard_tripped);
        assert!(plan.to_delete.is_empty());
        assert!(plan.to_fetch.is_empty());
    }

    #[test]
    fn plan_etag_comparison_is_verbatim() {
        // "abc" vs W/"abc" vs abc are three DIFFERENT stored values — the
        // comparison must not normalize (that's If-Match's job, not diff's).
        let listing = PropfindEventsResult {
            entries: vec![entry("/a.ics", "W/\"abc\"")],
            failed_uris: vec![],
        };
        let local: HashMap<String, String> = [("/a.ics".to_string(), "\"abc\"".to_string())]
            .into_iter()
            .collect();
        let plan = plan_sync(&listing, &local);
        assert_eq!(plan.to_fetch, vec!["/a.ics".to_string()]);
    }
}

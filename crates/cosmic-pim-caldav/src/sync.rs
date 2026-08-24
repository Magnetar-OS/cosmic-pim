// SPDX-License-Identifier: MPL-2.0

//! One incremental sync cycle for one collection.
//!
//! The shape, and why each step is where it is:
//!
//! 1. **ctag check.** If the collection's ctag is unchanged, nothing in it has
//!    changed and we stop. This is what makes a five-second poll interval
//!    affordable — one cheap PROPFIND instead of listing 5000 events.
//! 2. **List.** A `Depth: 1` PROPFIND for href + etag.
//! 3. **Plan.** [`plan_sync`] diffs the listing against what we hold. Pure.
//! 4. **Fetch.** `calendar-multiget` REPORT, batched, for what changed.
//! 5. **Apply.** Upserts, then deletes.
//! 6. **Commit the ctag** — last, and only if everything above succeeded.
//!
//! Step 6 is load-bearing. Committing a ctag over a partially-applied cycle
//! convinces the next run that it is already up to date, and whatever failed to
//! apply is never retried. Any error short-circuits before the commit, so the
//! next cycle sees the old ctag and redoes the work.
//!
//! "Everything above succeeded" includes the failures that are *not* errors.
//! A cycle that skipped deletions because the mass-delete guard fired, or that
//! asked for bodies the server did not return, has not applied the collection
//! and must not claim the ctag: the ctag only changes when the server changes,
//! so committing one over skipped work means the work waits for an unrelated
//! future edit before it is retried. A conflict is the exception, and
//! deliberately so — see step 5.
//!
//! # Step 5 and the edit that is not there yet
//!
//! An upsert overwrites the local file with the server's bytes. That is right
//! for a resource we are only fetching and wrong for one the user has edited
//! since the last sync, because the queued PUT reads its payload from that same
//! file at drain time: overwrite first and the push uploads the server's own
//! bytes back to it, reporting success, and the edit is gone without a single
//! error being raised anywhere.
//!
//! So before writing, the cycle asks the store whether it is holding an unsent
//! local change for that href. If it is, and it differs from what the server
//! sent, neither copy wins: a [`crate::store::Conflict`] is recorded with both,
//! the local file is left alone, and the application resolves it. The ctag is
//! still committed in that case — the divergence is *recorded*, not pending, so
//! there is nothing for the next cycle to redo.

use crate::dav::CaldavClient;
use crate::error::Result;
use crate::plan::plan_sync;
use crate::store::{CalDavStore, Conflict, RemoteEvent};

/// What one cycle did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    pub fetched: usize,
    pub deleted: usize,
    /// The ctag matched and the cycle stopped after one request.
    pub unchanged: bool,
    /// The mass-delete guard fired: the server listed nothing while we hold
    /// events, so deletions were skipped for this round. See
    /// [`crate::plan::SyncPlan::guard_tripped`].
    pub guard_tripped: bool,
    /// Hrefs the server listed but did not return a body for. They keep their
    /// local copies and their old etags, so the next cycle retries them.
    pub missing_bodies: usize,
    /// Resources changed on both sides, recorded rather than overwritten.
    /// See [`crate::store::Conflict`].
    pub conflicts: usize,
}

impl SyncOutcome {
    /// Whether anything actually changed on disk.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.fetched > 0 || self.deleted > 0
    }

    /// Whether the cycle applied the collection in full.
    ///
    /// The ctag may only be committed when this holds — see the module docs.
    #[must_use]
    fn fully_applied(&self) -> bool {
        self.missing_bodies == 0 && !self.guard_tripped
    }
}

/// Runs one cycle against `calendar_url`, applying the result to `store`.
pub fn sync_collection(
    client: &CaldavClient,
    calendar_url: &str,
    store: &mut impl CalDavStore,
) -> Result<SyncOutcome> {
    let mut outcome = SyncOutcome::default();
    let local = store.state()?;

    // 1. ctag.
    let remote_ctag = client.get_ctag(calendar_url)?;
    if let (Some(remote), Some(stored)) = (remote_ctag.as_deref(), local.ctag.as_deref())
        && remote == stored
    {
        outcome.unchanged = true;
        return Ok(outcome);
    }

    // 2. list.
    let listing = client.list_events(calendar_url)?;

    // 3. plan.
    let plan = plan_sync(&listing, &local.entries);
    outcome.guard_tripped = plan.guard_tripped;
    if plan.guard_tripped {
        tracing::warn!(
            calendar_url,
            held = local.entries.len(),
            "server listed no events while we hold some; skipping deletions this round"
        );
    }

    // 4. fetch.
    let bodies = client.fetch_events(calendar_url, &plan.to_fetch)?;
    let etags: std::collections::HashMap<&str, &str> = listing
        .entries
        .iter()
        .map(|entry| (entry.uri.as_str(), entry.etag.as_str()))
        .collect();

    // 5. apply. Upserts first: if a delete fails halfway, the events we did
    // manage to bring down are already safe on disk, and the uncommitted ctag
    // means the deletes are retried next cycle.
    let mut applied = std::collections::HashSet::new();
    for (href, ics) in &bodies {
        let Some(etag) = etags.get(href.as_str()) else {
            // A body for an href the listing did not mention. Storing it would
            // leave an entry with no etag to diff against, so it would be
            // re-fetched forever.
            tracing::warn!(
                href,
                "multiget returned a body for an unlisted href; ignoring"
            );
            continue;
        };
        // Both sides changed: record it, write neither over the other.
        if let Some(local) = store.unpushed_local(href)?
            && local != *ics
        {
            tracing::warn!(
                href,
                "the server and this device both changed a resource; \
                 keeping the local copy and recording a conflict"
            );
            store.record_conflict(&Conflict {
                href: href.clone(),
                local,
                remote: ics.clone(),
                remote_etag: (*etag).to_owned(),
            })?;
            applied.insert(href.as_str());
            outcome.conflicts += 1;
            continue;
        }

        store.upsert(&RemoteEvent {
            href: href.clone(),
            etag: (*etag).to_owned(),
            ics: ics.clone(),
        })?;
        applied.insert(href.as_str());
        outcome.fetched += 1;
    }

    // An href we asked for and did not get back is left exactly as it was —
    // old copy, old etag — so the next cycle asks again. Recording the new etag
    // without the body would make us believe we were up to date.
    outcome.missing_bodies = plan
        .to_fetch
        .iter()
        .filter(|href| !applied.contains(href.as_str()))
        .count();
    if outcome.missing_bodies > 0 {
        tracing::warn!(
            calendar_url,
            count = outcome.missing_bodies,
            "server listed events it did not return bodies for; retrying next cycle"
        );
    }

    for href in &plan.to_delete {
        store.remove(href)?;
        outcome.deleted += 1;
    }

    // 6. commit — only over a cycle that applied everything it was asked to.
    if outcome.fully_applied() {
        store.commit_ctag(remote_ctag.as_deref())?;
    } else {
        tracing::info!(
            calendar_url,
            missing_bodies = outcome.missing_bodies,
            guard_tripped = outcome.guard_tripped,
            "cycle did not apply in full; leaving the ctag uncommitted so it is retried"
        );
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dav::{CalDavEventEntry, PropfindEventsResult};
    use crate::store::{CollectionState, MemoryStore};
    use std::collections::HashMap;

    /// The cycle without the HTTP client, so reconciliation can be tested
    /// against a scripted server. Mirrors `sync_collection` step for step; the
    /// only thing it does not exercise is the wire, which `dav.rs` covers.
    fn run(
        store: &mut impl CalDavStore,
        remote_ctag: Option<&str>,
        listing: &PropfindEventsResult,
        bodies: &[(String, String)],
    ) -> Result<SyncOutcome> {
        let mut outcome = SyncOutcome::default();
        let local: CollectionState = store.state()?;

        if let (Some(remote), Some(stored)) = (remote_ctag, local.ctag.as_deref())
            && remote == stored
        {
            outcome.unchanged = true;
            return Ok(outcome);
        }

        let plan = plan_sync(listing, &local.entries);
        outcome.guard_tripped = plan.guard_tripped;

        let etags: HashMap<&str, &str> = listing
            .entries
            .iter()
            .map(|e| (e.uri.as_str(), e.etag.as_str()))
            .collect();

        let mut applied = std::collections::HashSet::new();
        for (href, ics) in bodies {
            let Some(etag) = etags.get(href.as_str()) else {
                continue;
            };
            if let Some(local) = store.unpushed_local(href)?
                && local != *ics
            {
                store.record_conflict(&Conflict {
                    href: href.clone(),
                    local,
                    remote: ics.clone(),
                    remote_etag: (*etag).to_owned(),
                })?;
                applied.insert(href.clone());
                outcome.conflicts += 1;
                continue;
            }
            store.upsert(&RemoteEvent {
                href: href.clone(),
                etag: (*etag).to_owned(),
                ics: ics.clone(),
            })?;
            applied.insert(href.clone());
            outcome.fetched += 1;
        }
        outcome.missing_bodies = plan
            .to_fetch
            .iter()
            .filter(|h| !applied.contains(*h))
            .count();

        for href in &plan.to_delete {
            store.remove(href)?;
            outcome.deleted += 1;
        }

        if outcome.fully_applied() {
            store.commit_ctag(remote_ctag)?;
        }
        Ok(outcome)
    }

    const ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
        BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\nSUMMARY:X\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";

    fn listing(entries: &[(&str, &str)], failed: &[&str]) -> PropfindEventsResult {
        PropfindEventsResult {
            entries: entries
                .iter()
                .map(|(uri, etag)| CalDavEventEntry {
                    uri: (*uri).to_owned(),
                    etag: (*etag).to_owned(),
                })
                .collect(),
            failed_uris: failed.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn body(href: &str) -> (String, String) {
        (href.to_owned(), ICS.to_owned())
    }

    #[test]
    fn a_matching_ctag_stops_the_cycle_before_listing() {
        let mut store = MemoryStore::default();
        store.commit_ctag(Some("ctag-1")).unwrap();

        let outcome = run(&mut store, Some("ctag-1"), &listing(&[], &[]), &[]).unwrap();

        assert!(outcome.unchanged);
        assert!(!outcome.changed());
    }

    #[test]
    fn a_changed_ctag_runs_a_full_cycle() {
        let mut store = MemoryStore::default();
        store.commit_ctag(Some("ctag-1")).unwrap();

        let outcome = run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/a.ics", "\"1\"")], &[]),
            &[body("/a.ics")],
        )
        .unwrap();

        assert!(!outcome.unchanged);
        assert_eq!(outcome.fetched, 1);
        assert_eq!(store.ctag.as_deref(), Some("ctag-2"));
    }

    #[test]
    fn an_unchanged_etag_is_not_refetched() {
        let mut store = MemoryStore::default();
        store
            .upsert(&RemoteEvent {
                href: "/a.ics".into(),
                etag: "\"1\"".into(),
                ics: ICS.into(),
            })
            .unwrap();

        let outcome = run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/a.ics", "\"1\"")], &[]),
            &[],
        )
        .unwrap();

        assert_eq!(outcome.fetched, 0, "an unchanged event was re-downloaded");
        assert_eq!(outcome.deleted, 0);
    }

    #[test]
    fn an_event_absent_from_the_listing_is_deleted() {
        let mut store = MemoryStore::default();
        for href in ["/a.ics", "/b.ics"] {
            store
                .upsert(&RemoteEvent {
                    href: href.into(),
                    etag: "\"1\"".into(),
                    ics: ICS.into(),
                })
                .unwrap();
        }

        let outcome = run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/a.ics", "\"1\"")], &[]),
            &[],
        )
        .unwrap();

        assert_eq!(outcome.deleted, 1);
        assert!(store.events.contains_key("/a.ics"));
        assert!(!store.events.contains_key("/b.ics"));
    }

    #[test]
    fn a_server_reported_failure_is_not_treated_as_a_deletion() {
        let mut store = MemoryStore::default();
        store
            .upsert(&RemoteEvent {
                href: "/a.ics".into(),
                etag: "\"1\"".into(),
                ics: ICS.into(),
            })
            .unwrap();

        // The server listed nothing for /a.ics but explicitly reported it as
        // failing. That is an error, not an absence.
        let outcome = run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/b.ics", "\"1\"")], &["/a.ics"]),
            &[body("/b.ics")],
        )
        .unwrap();

        assert_eq!(
            outcome.deleted, 0,
            "a transient failure deleted a real event"
        );
        assert!(store.events.contains_key("/a.ics"));
    }

    #[test]
    fn an_empty_listing_over_a_populated_store_deletes_nothing() {
        let mut store = MemoryStore::default();
        for href in ["/a.ics", "/b.ics", "/c.ics"] {
            store
                .upsert(&RemoteEvent {
                    href: href.into(),
                    etag: "\"1\"".into(),
                    ics: ICS.into(),
                })
                .unwrap();
        }

        let outcome = run(&mut store, Some("ctag-2"), &listing(&[], &[]), &[]).unwrap();

        assert!(outcome.guard_tripped);
        assert_eq!(outcome.deleted, 0, "the mass-delete guard did not hold");
        assert_eq!(store.events.len(), 3);
    }

    #[test]
    fn a_listed_event_with_no_body_keeps_its_old_etag_so_it_is_retried() {
        let mut store = MemoryStore::default();
        store
            .upsert(&RemoteEvent {
                href: "/a.ics".into(),
                etag: "\"1\"".into(),
                ics: ICS.into(),
            })
            .unwrap();

        // The server says /a.ics changed to "2", then returns no body for it.
        let outcome = run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/a.ics", "\"2\"")], &[]),
            &[],
        )
        .unwrap();

        assert_eq!(outcome.missing_bodies, 1);
        assert_eq!(
            store.events["/a.ics"].etag, "\"1\"",
            "the new etag was recorded without the body, so the change is lost forever"
        );
    }

    #[test]
    fn a_first_sync_against_an_empty_store_fetches_everything() {
        let mut store = MemoryStore::default();

        let outcome = run(
            &mut store,
            Some("ctag-1"),
            &listing(&[("/a.ics", "\"1\""), ("/b.ics", "\"1\"")], &[]),
            &[body("/a.ics"), body("/b.ics")],
        )
        .unwrap();

        assert_eq!(outcome.fetched, 2);
        assert!(
            !outcome.guard_tripped,
            "an empty local store is not a guard case"
        );
        assert_eq!(store.events.len(), 2);
    }

    #[test]
    fn etag_comparison_is_verbatim_including_weak_markers() {
        let mut store = MemoryStore::default();
        store
            .upsert(&RemoteEvent {
                href: "/a.ics".into(),
                etag: "\"1\"".into(),
                ics: ICS.into(),
            })
            .unwrap();

        // `W/"1"` is not the same string as `"1"`, so it must re-fetch rather
        // than being cleverly normalised into a match.
        let outcome = run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/a.ics", "W/\"1\"")], &[]),
            &[body("/a.ics")],
        )
        .unwrap();

        assert_eq!(outcome.fetched, 1);
    }

    const SERVER_EDIT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
        BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\nSUMMARY:Theirs\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";

    const LOCAL_EDIT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
        BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\nSUMMARY:Mine\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";

    /// One event held locally with an unsent edit on top of it.
    fn store_with_unsent_edit() -> MemoryStore {
        let mut store = MemoryStore::default();
        store
            .upsert(&RemoteEvent {
                href: "/a.ics".into(),
                etag: "\"1\"".into(),
                ics: ICS.into(),
            })
            .unwrap();
        store.unpushed.insert("/a.ics".into(), LOCAL_EDIT.into());
        store
    }

    #[test]
    fn a_server_change_over_an_unsent_local_edit_is_a_conflict_not_an_overwrite() {
        // Without this branch the pull writes the server's bytes over the local
        // file, the queued PUT then reads that file and uploads the server's
        // own copy back to it, and the edit is gone with every indicator
        // reporting success.
        let mut store = store_with_unsent_edit();

        let outcome = run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/a.ics", "\"2\"")], &[]),
            &[("/a.ics".to_owned(), SERVER_EDIT.to_owned())],
        )
        .unwrap();

        assert_eq!(outcome.conflicts, 1);
        assert_eq!(outcome.fetched, 0, "the server's copy was written anyway");
        assert_eq!(
            store.events["/a.ics"].ics, ICS,
            "the local copy was replaced despite the conflict"
        );

        let conflict = &store.conflicts[0];
        assert_eq!(conflict.local, LOCAL_EDIT);
        assert_eq!(conflict.remote, SERVER_EDIT);
        assert_eq!(conflict.remote_etag, "\"2\"");
    }

    #[test]
    fn a_conflict_still_commits_the_ctag() {
        // A recorded conflict is not unfinished work: there is nothing for the
        // next cycle to redo, and refusing the ctag would make every poll
        // re-list the whole collection until a human resolved it.
        let mut store = store_with_unsent_edit();

        run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/a.ics", "\"2\"")], &[]),
            &[("/a.ics".to_owned(), SERVER_EDIT.to_owned())],
        )
        .unwrap();

        assert_eq!(store.ctag.as_deref(), Some("ctag-2"));
    }

    #[test]
    fn the_server_making_the_same_edit_we_queued_is_not_a_conflict() {
        let mut store = store_with_unsent_edit();

        let outcome = run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/a.ics", "\"2\"")], &[]),
            &[("/a.ics".to_owned(), LOCAL_EDIT.to_owned())],
        )
        .unwrap();

        assert_eq!(
            outcome.conflicts, 0,
            "identical content was called a conflict"
        );
        assert_eq!(outcome.fetched, 1);
    }

    #[test]
    fn a_cycle_that_did_not_get_every_body_leaves_the_ctag_alone() {
        // The ctag only changes when the server changes. Committing one over a
        // cycle that failed to apply part of the collection means the missing
        // part waits for an unrelated future edit before anything retries it —
        // which is exactly the "never arrives" case the ctag comment warns of.
        let mut store = MemoryStore::default();
        store.commit_ctag(Some("ctag-1")).unwrap();

        let outcome = run(
            &mut store,
            Some("ctag-2"),
            &listing(&[("/a.ics", "\"1\""), ("/b.ics", "\"1\"")], &[]),
            &[body("/a.ics")],
        )
        .unwrap();

        assert_eq!(outcome.missing_bodies, 1);
        assert_eq!(
            store.ctag.as_deref(),
            Some("ctag-1"),
            "the ctag advanced over an event that never arrived, so it is never retried"
        );
    }

    #[test]
    fn a_cycle_that_skipped_deletions_leaves_the_ctag_alone() {
        let mut store = MemoryStore::default();
        store
            .upsert(&RemoteEvent {
                href: "/a.ics".into(),
                etag: "\"1\"".into(),
                ics: ICS.into(),
            })
            .unwrap();
        store.commit_ctag(Some("ctag-1")).unwrap();

        // An empty listing while we hold events trips the mass-delete guard.
        let outcome = run(&mut store, Some("ctag-2"), &listing(&[], &[]), &[]).unwrap();

        assert!(outcome.guard_tripped);
        assert_eq!(
            store.ctag.as_deref(),
            Some("ctag-1"),
            "the ctag advanced over skipped deletions, so they are never reconsidered"
        );
    }
}

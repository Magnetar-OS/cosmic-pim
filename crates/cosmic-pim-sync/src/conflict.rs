// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Reading and resolving the conflicts a sync pass recorded.
//!
//! # What a conflict is here
//!
//! The server changed a resource, and so did this device, and the local change
//! had not reached the server yet. Neither copy can be written over the other
//! without losing somebody's work, so [`cosmic_pim_caldav::sync_collection`]
//! records both and leaves the local file alone. See
//! [`cosmic_pim_caldav::Conflict`] for why that is the only safe answer and
//! what the failure looks like when it is skipped.
//!
//! # What an application does with them
//!
//! After a sync pass, `CollectionReport::conflicts` says how many a collection
//! has; [`for_collection`] returns them. Each carries both texts, so a UI can
//! show a diff. The user then picks, and exactly one of two things happens:
//!
//! - [`take_remote`] — the server's copy wins. It is written locally and the
//!   queued push is dropped. No network needed: the bytes were recorded when
//!   the conflict was detected.
//! - [`keep_local`] — this device's copy wins, and is re-queued for upload
//!   against the server's current etag so the push is accepted rather than
//!   412-ing exactly as the first one did. `merged` covers the third answer,
//!   where the user (or a property-level merge) produced a text from both.
//!
//! Nothing here resolves itself with time. A conflict left alone stays put,
//! the local file keeps the local edit, and the push stays parked — which is
//! the point: the alternative to asking is guessing.

use std::path::Path;

use cosmic_pim_caldav::{Conflict, VdirStore};

use crate::error::Result;

/// Every unresolved conflict in one collection.
///
/// An unknown collection has none rather than erroring — the same convention
/// as [`crate::writeback`], so a caller sweeping collections after a sync pass
/// does not need to care whether one was removed underneath it.
pub fn for_collection(root: &Path, collection_id: &str) -> Result<Vec<Conflict>> {
    let Some(meta) = crate::provision::open_collection(root, collection_id) else {
        return Ok(Vec::new());
    };
    Ok(VdirStore::open(meta)?.conflicts().to_vec())
}

/// Every unresolved conflict under `root`, with the collection each is in.
///
/// For the "you have things to decide" surface an application shows once,
/// rather than per calendar.
pub fn all(root: &Path) -> Vec<(String, Conflict)> {
    cosmic_pim_core::store::vdir::collections(root)
        .into_iter()
        .filter_map(|meta| {
            let id = meta.id.clone();
            let store = VdirStore::open(meta)
                .inspect_err(|why| {
                    tracing::warn!(collection = id, %why, "could not read a collection's conflicts");
                })
                .ok()?;
            Some(
                store
                    .conflicts()
                    .iter()
                    .map(|c| (id.clone(), c.clone()))
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
        .collect()
}

/// Discard the local edit and adopt the server's version.
///
/// Returns whether there was a conflict to resolve.
pub fn take_remote(root: &Path, collection_id: &str, href: &str) -> Result<bool> {
    let Some(meta) = crate::provision::open_collection(root, collection_id) else {
        return Ok(false);
    };
    Ok(VdirStore::open(meta)?.resolve_conflict_take_remote(href)?)
}

/// Keep this device's version and re-queue it for upload.
///
/// `merged` writes a different text first — the hand-merged result of the two
/// sides. `None` keeps the file exactly as it stands.
///
/// Returns whether there was a conflict to resolve.
pub fn keep_local(
    root: &Path,
    collection_id: &str,
    href: &str,
    merged: Option<&str>,
) -> Result<bool> {
    let Some(meta) = crate::provision::open_collection(root, collection_id) else {
        return Ok(false);
    };
    Ok(VdirStore::open(meta)?.resolve_conflict_keep_local(href, merged)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_pim_caldav::push::PushQueue;
    use cosmic_pim_caldav::{CalDavStore, RemoteEvent};
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::vdir;

    const HREF: &str = "/cal/a.ics";
    const SERVER_V1: &str = "BEGIN:VCALENDAR\r\nX-V:1\r\nEND:VCALENDAR\r\n";
    const LOCAL_EDIT: &str = "BEGIN:VCALENDAR\r\nX-V:mine\r\nEND:VCALENDAR\r\n";
    const SERVER_V2: &str = "BEGIN:VCALENDAR\r\nX-V:theirs\r\nEND:VCALENDAR\r\n";

    /// A collection with one conflict in it, reached the way a real one is:
    /// synced, edited locally, then changed on the server.
    fn conflicted() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        let id = meta.id.clone();

        let mut store = VdirStore::open(meta).unwrap();
        store.set_remote("/cal/", false).unwrap();
        store
            .upsert(&RemoteEvent {
                href: HREF.into(),
                etag: "\"v1\"".into(),
                ics: SERVER_V1.into(),
            })
            .unwrap();
        std::fs::write(store.collection().path.join("a.ics"), LOCAL_EDIT).unwrap();
        store.queue_put(HREF).unwrap();

        let local = store.unpushed_local(HREF).unwrap().unwrap();
        store
            .record_conflict(&Conflict {
                href: HREF.into(),
                local,
                remote: SERVER_V2.into(),
                remote_etag: "\"v2\"".into(),
            })
            .unwrap();

        (dir, id)
    }

    fn file(root: &Path, id: &str) -> String {
        let meta = crate::provision::open_collection(root, id).unwrap();
        std::fs::read_to_string(meta.path.join("a.ics")).unwrap()
    }

    #[test]
    fn a_recorded_conflict_is_readable_by_collection_and_by_root() {
        let (dir, id) = conflicted();

        let one = for_collection(dir.path(), &id).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].local, LOCAL_EDIT);
        assert_eq!(one[0].remote, SERVER_V2);

        let every = all(dir.path());
        assert_eq!(every.len(), 1);
        assert_eq!(every[0].0, id);
    }

    #[test]
    fn taking_the_remote_version_needs_no_network() {
        let (dir, id) = conflicted();

        assert!(take_remote(dir.path(), &id, HREF).unwrap());

        assert_eq!(file(dir.path(), &id), SERVER_V2);
        assert!(for_collection(dir.path(), &id).unwrap().is_empty());
    }

    #[test]
    fn keeping_the_local_version_leaves_a_live_push_behind() {
        let (dir, id) = conflicted();

        assert!(keep_local(dir.path(), &id, HREF, None).unwrap());

        assert_eq!(file(dir.path(), &id), LOCAL_EDIT);

        let meta = crate::provision::open_collection(dir.path(), &id).unwrap();
        let pending = VdirStore::open(meta).unwrap().pending();
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].blocked, "the resolution left the push parked");
    }

    #[test]
    fn a_merged_text_replaces_both_sides() {
        const MERGED: &str = "BEGIN:VCALENDAR\r\nX-V:both\r\nEND:VCALENDAR\r\n";
        let (dir, id) = conflicted();

        assert!(keep_local(dir.path(), &id, HREF, Some(MERGED)).unwrap());

        assert_eq!(file(dir.path(), &id), MERGED);
    }

    #[test]
    fn an_unknown_collection_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(for_collection(dir.path(), "nope").unwrap().is_empty());
        assert!(!take_remote(dir.path(), "nope", HREF).unwrap());
        assert!(!keep_local(dir.path(), "nope", HREF, None).unwrap());
    }

    #[test]
    fn resolving_twice_reports_that_there_was_nothing_left_to_do() {
        let (dir, id) = conflicted();
        assert!(take_remote(dir.path(), &id, HREF).unwrap());
        assert!(!take_remote(dir.path(), &id, HREF).unwrap());
    }
}

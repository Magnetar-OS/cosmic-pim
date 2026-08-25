// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Turning a local edit into a queued push.
//!
//! The storage layer deliberately knows nothing about CalDAV: `Store::save`
//! writes an `.ics` and stops. That is the right split, but it leaves a gap —
//! something has to notice the write and queue it for the server, or the local
//! copy and the remote one diverge silently and permanently (see
//! [`cosmic_pim_caldav::push`] for why "permanently").
//!
//! This is that something. The app calls it right after a save or a delete.
//!
//! # Local-only calendars
//!
//! A collection with no CalDAV binding is a perfectly normal thing to have —
//! the user made it themselves and no server is involved. Every function here
//! returns `Ok(false)` for that case rather than erroring, so the caller can
//! use the same code path for both and not care which kind it just wrote to.

use std::path::Path;

use cosmic_pim_caldav::VdirStore;

use crate::error::Result;

/// Queues a locally saved event for upload.
///
/// Returns whether anything was queued — `false` means the collection is not
/// CalDAV-backed.
pub fn queue_save(root: &Path, collection_id: &str, file_name: &str) -> Result<bool> {
    let Some(meta) = crate::provision::open_collection(root, collection_id) else {
        return Ok(false);
    };

    // A collection the user disconnected keeps its binding but must not
    // queue: the queue is durable, and an entry accepted now would push the
    // moment the marker came off — hours or months later, unasked.
    if cosmic_pim_caldav::is_local_only(&meta.path) {
        return Ok(false);
    }

    let mut store = VdirStore::open(meta)?;

    if store.is_read_only() {
        // The server will 403 this. Queueing it anyway would leave an entry
        // that can never drain and a UI that claims changes are pending
        // forever.
        tracing::warn!(
            collection_id,
            "edit saved to a collection the server made read-only; it will not be uploaded"
        );
        return Ok(false);
    }

    let Some(href) = store.href_for_file(file_name) else {
        return Ok(false);
    };
    store.queue_put(&href)?;
    Ok(true)
}

/// Queues a locally deleted event for removal on the server.
///
/// Safe to call either side of the local delete: the coordinates live in the
/// sidecar, which the storage layer never touches.
pub fn queue_delete(root: &Path, collection_id: &str, file_name: &str) -> Result<bool> {
    let Some(meta) = crate::provision::open_collection(root, collection_id) else {
        return Ok(false);
    };
    if cosmic_pim_caldav::is_local_only(&meta.path) {
        return Ok(false);
    }
    let mut store = VdirStore::open(meta)?;

    if store.is_read_only() {
        return Ok(false);
    }

    // Only a file the server actually knows about needs a DELETE. An event
    // created and removed locally between two syncs was never uploaded, and
    // asking the server to delete it would just 404.
    let Some(href) = store.entry_for_by_file(file_name).map(|(href, _)| href) else {
        return Ok(false);
    };

    store.queue_delete(&href)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_pim_caldav::push::PushQueue;
    use cosmic_pim_caldav::{CalDavStore, RemoteEvent};
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::vdir;

    const ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\nSUMMARY:X\r\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";

    fn collection(bind: bool) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        let id = meta.id.clone();
        if bind {
            let mut store = VdirStore::open(meta).unwrap();
            store.set_remote("/dav/cal/", false).unwrap();
        }
        (dir, id)
    }

    fn pending(root: &Path, id: &str) -> Vec<String> {
        let meta = crate::provision::open_collection(root, id).unwrap();
        VdirStore::open(meta)
            .unwrap()
            .pending()
            .into_iter()
            .map(|p| p.op.href().to_owned())
            .collect()
    }

    #[test]
    fn a_save_to_a_local_only_calendar_queues_nothing() {
        let (dir, id) = collection(false);
        assert!(!queue_save(dir.path(), &id, "a.ics").unwrap());
        assert!(pending(dir.path(), &id).is_empty());
    }

    #[test]
    fn a_save_to_a_synced_calendar_queues_a_put_under_the_collection_href() {
        let (dir, id) = collection(true);
        assert!(queue_save(dir.path(), &id, "a.ics").unwrap());
        assert_eq!(pending(dir.path(), &id), vec!["/dav/cal/a.ics".to_string()]);
    }

    #[test]
    fn a_save_to_a_known_file_reuses_its_existing_href() {
        let (dir, id) = collection(true);
        {
            let meta = crate::provision::open_collection(dir.path(), &id).unwrap();
            let mut store = VdirStore::open(meta).unwrap();
            // The server named it something quite unlike the file name.
            store
                .upsert(&RemoteEvent {
                    href: "/dav/cal/8f3c-aa11.ics".into(),
                    etag: "\"1\"".into(),
                    ics: ICS.into(),
                })
                .unwrap();
        }
        assert!(queue_save(dir.path(), &id, "8f3c-aa11.ics").unwrap());
        assert_eq!(
            pending(dir.path(), &id),
            vec!["/dav/cal/8f3c-aa11.ics".to_string()],
            "a synced event was queued under a freshly derived href instead of its own"
        );
    }

    #[test]
    fn a_read_only_collection_queues_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Shared", Rgb(1, 2, 3)).unwrap();
        let id = meta.id.clone();
        VdirStore::open(meta)
            .unwrap()
            .set_remote("/dav/shared/", true)
            .unwrap();

        assert!(!queue_save(dir.path(), &id, "a.ics").unwrap());
        assert!(
            pending(dir.path(), &id).is_empty(),
            "queued a push that can only ever 403"
        );
    }

    #[test]
    fn deleting_an_event_the_server_never_saw_queues_nothing() {
        let (dir, id) = collection(true);
        assert!(
            !queue_delete(dir.path(), &id, "never-synced.ics").unwrap(),
            "queued a DELETE for a resource that does not exist on the server"
        );
    }

    #[test]
    fn deleting_a_synced_event_queues_a_delete() {
        let (dir, id) = collection(true);
        {
            let meta = crate::provision::open_collection(dir.path(), &id).unwrap();
            let mut store = VdirStore::open(meta).unwrap();
            store
                .upsert(&RemoteEvent {
                    href: "/dav/cal/a.ics".into(),
                    etag: "\"1\"".into(),
                    ics: ICS.into(),
                })
                .unwrap();
        }
        assert!(queue_delete(dir.path(), &id, "a.ics").unwrap());
        assert_eq!(pending(dir.path(), &id), vec!["/dav/cal/a.ics".to_string()]);
    }

    #[test]
    fn an_unknown_collection_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!queue_save(dir.path(), "no-such-collection", "a.ics").unwrap());
        assert!(!queue_delete(dir.path(), "no-such-collection", "a.ics").unwrap());
    }

    #[test]
    fn a_disconnected_collection_queues_nothing_despite_its_binding() {
        // The marker's whole reason: bound + synced once + marked local-only
        // must behave like a local calendar, not like a paused one whose
        // queue silently fills.
        let (dir, id) = collection(true);
        {
            let meta = crate::provision::open_collection(dir.path(), &id).unwrap();
            cosmic_pim_caldav::mark_local_only(&meta.path).unwrap();
        }

        assert!(!queue_save(dir.path(), &id, "a.ics").unwrap());
        assert!(!queue_delete(dir.path(), &id, "a.ics").unwrap());
        assert!(pending(dir.path(), &id).is_empty());

        // Unmarking reconnects, with the binding intact.
        {
            let meta = crate::provision::open_collection(dir.path(), &id).unwrap();
            cosmic_pim_caldav::unmark_local_only(&meta.path).unwrap();
        }
        assert!(queue_save(dir.path(), &id, "a.ics").unwrap());
    }
}

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
//! This is that something. [`save_and_queue`] runs the app's save and queues
//! it as one step, under the collection's lock, which is the form to use:
//! a sync pass pulling the same resource can then neither overwrite the save
//! before it is queued nor miss it. [`queue_save`] and [`queue_delete`] queue
//! a change already made, as a second step — correct only where no pass can
//! be pulling that resource in between.
//!
//! # Local-only calendars
//!
//! A collection with no CalDAV binding is a perfectly normal thing to have —
//! the user made it themselves and no server is involved. Every function here
//! returns `Ok(false)` for that case rather than erroring, so the caller can
//! use the same code path for both and not care which kind it just wrote to.

use std::path::Path;

use cosmic_pim_caldav::{CalDavStore as _, VdirStore};

use crate::error::{Error, Result};

/// What [`save_and_queue`] did, once the write itself had succeeded.
#[derive(Debug)]
pub struct Saved<T> {
    /// What the write returned.
    pub value: T,
    /// Whether the change was queued for upload.
    ///
    /// `Ok(false)` is a collection with no server to upload to: a local
    /// calendar, one marked local-only, or one the server made read-only.
    /// `Err` means the change **is on disk and is not queued** — it stays on
    /// this device until something queues it — and says why.
    pub queued: Result<bool>,
}

/// Makes a local change and queues it for upload, as one step.
///
/// `write` is the change itself — `Store::save`, a delete, a contact write —
/// and `file_names` are the files of the collection it may touch. What each
/// of them holds when `write` returns is what is queued: an upload for a file
/// that is there, a deletion on the server for one that is gone and that the
/// server knows. The bytes each held *before* `write` ran are captured as
/// the base for an automatic three-way merge, so callers no longer read them
/// themselves.
///
/// # Why one step
///
/// Saving and then calling [`queue_save`] leaves a gap between the two. A
/// sync pass pulling that resource in the gap finds a changed file and
/// nothing queued for it, takes the file for the last synced copy, and
/// writes the server's version over it; the enqueue that follows then pushes
/// the server's own bytes back. The edit is gone and nothing anywhere says
/// so. Here the write and the enqueue happen under the collection's lock,
/// and a pass decides about a resource under the same lock
/// ([`cosmic_pim_caldav::CalDavStore::exclusively`]), so a pass sees either
/// the collection before the save or the save already queued.
///
/// `write` must not call [`queue_save`], [`queue_delete`], this function, or
/// anything else that opens the same collection's sync state: the lock is
/// held around it and is not re-entrant. It should do its write and return.
///
/// # Errors
///
/// An error means nothing was written: either the collection's sync state
/// could not be opened or locked, in which case `write` was not run, or
/// `write` itself failed. A failure to *queue* after a successful write is
/// not an error here; it is [`Saved::queued`].
pub fn save_and_queue<T, E>(
    root: &Path,
    collection_id: &str,
    file_names: &[&str],
    write: impl FnOnce() -> std::result::Result<T, E>,
) -> Result<Saved<T>>
where
    Error: From<E>,
{
    let Some(mut store) = syncing_store(root, collection_id)? else {
        return Ok(Saved {
            value: write()?,
            queued: Ok(false),
        });
    };

    let dir = store.collection().path.clone();
    let mut written = None;
    let queued = store.exclusively(|store| {
        // What is on disk now, under the lock: the hrefs and etags the
        // enqueue below reads, as the last pass left them.
        store.reload()?;
        let bases: Vec<Option<String>> = file_names
            .iter()
            .map(|name| std::fs::read_to_string(dir.join(name)).ok())
            .collect();

        let value = match write() {
            Ok(value) => value,
            Err(why) => {
                written = Some(Err(why));
                return Ok(false);
            }
        };
        written = Some(Ok(value));

        let mut queued = false;
        for (name, base) in file_names.iter().zip(&bases) {
            queued |= queue_what_is_there(store, &dir, name, base.as_deref())?;
        }
        Ok(queued)
    });

    match written {
        Some(Ok(value)) => Ok(Saved {
            value,
            queued: queued.map_err(Error::CalDav),
        }),
        Some(Err(why)) => Err(why.into()),
        // The step never reached the write.
        None => Err(Error::CalDav(queued.err().unwrap_or_else(|| {
            cosmic_pim_caldav::Error::internal(
                "the collection's lock was taken but the write was not run",
            )
        }))),
    }
}

/// The sync state of a collection that has a server to push to, or `None`
/// for one that does not: unknown, never bound, marked local-only, or
/// read-only on the server.
fn syncing_store(root: &Path, collection_id: &str) -> Result<Option<VdirStore>> {
    let Some(meta) = crate::provision::open_collection(root, collection_id) else {
        return Ok(None);
    };
    // A collection the user disconnected keeps its binding but must not
    // queue: the queue is durable, and an entry accepted now would push the
    // moment the marker came off — hours or months later, unasked.
    if cosmic_pim_caldav::is_local_only(&meta.path) {
        return Ok(None);
    }
    let store = VdirStore::open(meta)?;
    if store.href().is_none() {
        return Ok(None);
    }
    if store.is_read_only() {
        // The server will 403 this. Queueing it anyway would leave an entry
        // that can never drain and a UI that claims changes are pending
        // forever.
        tracing::warn!(
            collection_id,
            "edit saved to a collection the server made read-only; it will not be uploaded"
        );
        return Ok(None);
    }
    Ok(Some(store))
}

/// Queues what a local change left in `file_name`: an upload when the file
/// is there, a deletion when it is gone and the server has it.
fn queue_what_is_there(
    store: &mut VdirStore,
    dir: &Path,
    file_name: &str,
    base: Option<&str>,
) -> cosmic_pim_caldav::Result<bool> {
    if dir.join(file_name).exists() {
        let Some(href) = store.href_for_file(file_name) else {
            return Ok(false);
        };
        store.queue_put_with_base(&href, base)?;
        return Ok(true);
    }
    // Only a file the server knows needs a DELETE; one created and removed
    // between two syncs was never uploaded.
    let Some((href, _)) = store.entry_for_by_file(file_name) else {
        return Ok(false);
    };
    store.queue_delete(&href)?;
    Ok(true)
}

/// Queues a locally saved event for upload.
///
/// Returns whether anything was queued — `false` means the collection is not
/// CalDAV-backed.
///
/// This queues a save that has already happened. A sync pass that pulls the
/// same resource between the save and this call overwrites the save; see
/// [`save_and_queue`], which closes that gap and is what an application
/// should call.
///
/// Prefer [`queue_save_with_base`] where the caller read the file before
/// overwriting it: the pre-edit bytes are what make an automatic three-way
/// merge possible if the server turns out to have changed the same resource.
/// This form queues with no base, which merely disables that merge.
pub fn queue_save(root: &Path, collection_id: &str, file_name: &str) -> Result<bool> {
    queue_save_with_base(root, collection_id, file_name, None)
}

/// [`queue_save`], with the file's pre-edit contents.
///
/// `previous` is what the file held *before* the save this call is queueing —
/// exactly the text the server last acknowledged, when the file was in sync at
/// the moment the edit began. The queue keeps it from the first enqueue only
/// (see `VdirStore::queue_put_with_base`), so callers pass what they read and
/// never need to reason about earlier unsent edits themselves.
pub fn queue_save_with_base(
    root: &Path,
    collection_id: &str,
    file_name: &str,
    previous: Option<&str>,
) -> Result<bool> {
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
    store.queue_put_with_base(&href, previous)?;
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
    use cosmic_pim_core::StoreError;
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
            .unwrap()
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
    fn the_pre_edit_bytes_reach_the_queue_as_the_merge_base() {
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

        assert!(queue_save_with_base(dir.path(), &id, "a.ics", Some(ICS)).unwrap());

        let meta = crate::provision::open_collection(dir.path(), &id).unwrap();
        let mut store = VdirStore::open(meta).unwrap();
        assert_eq!(
            store.unpushed_base("/dav/cal/a.ics").unwrap().as_deref(),
            Some(ICS),
            "the base was dropped between the app and the queue"
        );
    }

    const SERVER_V1: &str = "BEGIN:VCALENDAR\r\nX-V:1\r\nEND:VCALENDAR\r\n";
    const LOCAL_EDIT: &str = "BEGIN:VCALENDAR\r\nX-V:1-mine\r\nEND:VCALENDAR\r\n";
    const SERVER_V2: &str = "BEGIN:VCALENDAR\r\nX-V:2-theirs\r\nEND:VCALENDAR\r\n";

    /// A bound collection holding one synced resource, `a.ics`.
    fn synced() -> (tempfile::TempDir, String, std::path::PathBuf) {
        let (dir, id) = collection(true);
        let meta = crate::provision::open_collection(dir.path(), &id).unwrap();
        let file = meta.path.join("a.ics");
        VdirStore::open(meta)
            .unwrap()
            .upsert(&RemoteEvent {
                href: "/dav/cal/a.ics".into(),
                etag: "\"1\"".into(),
                ics: SERVER_V1.into(),
            })
            .unwrap();
        (dir, id, file)
    }

    /// What a sync pass does with one resource the server changed: ask
    /// whether an edit is waiting, and take the server's copy if not.
    fn pull(root: &Path, id: &str) {
        let meta = crate::provision::open_collection(root, id).unwrap();
        let mut store = VdirStore::open(meta).unwrap();
        store
            .exclusively(|store| {
                if store.unpushed_local("/dav/cal/a.ics")?.is_none() {
                    store.upsert(&RemoteEvent {
                        href: "/dav/cal/a.ics".into(),
                        etag: "\"2\"".into(),
                        ics: SERVER_V2.into(),
                    })?;
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn a_pull_cannot_land_between_a_save_and_its_enqueue() {
        // The save writes the file; the pull arrives before the enqueue.
        // With the two as separate steps the pull found a changed file and
        // nothing queued, and wrote the server's copy over the edit.
        let (dir, id, file) = synced();
        let (written, pull_may_run) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                let saved = save_and_queue(dir.path(), &id, &["a.ics"], || {
                    std::fs::write(&file, LOCAL_EDIT)?;
                    written.send(()).unwrap();
                    // The gap a pull used to fit into.
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    Ok::<_, StoreError>(())
                })
                .unwrap();
                assert!(saved.queued.unwrap());
            });
            pull_may_run.recv().unwrap();
            pull(dir.path(), &id);
        });

        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            LOCAL_EDIT,
            "a pull overwrote a save that had not been queued yet"
        );
        assert_eq!(pending(dir.path(), &id), ["/dav/cal/a.ics"]);
    }

    #[test]
    fn the_bytes_before_the_write_become_the_merge_base() {
        let (dir, id, file) = synced();
        save_and_queue(dir.path(), &id, &["a.ics"], || {
            std::fs::write(&file, LOCAL_EDIT).map_err(StoreError::from)
        })
        .unwrap();

        let meta = crate::provision::open_collection(dir.path(), &id).unwrap();
        assert_eq!(
            VdirStore::open(meta)
                .unwrap()
                .unpushed_base("/dav/cal/a.ics")
                .unwrap()
                .as_deref(),
            Some(SERVER_V1)
        );
    }

    #[test]
    fn a_write_that_fails_queues_nothing_and_is_the_error() {
        let (dir, id, _file) = synced();
        let result = save_and_queue(dir.path(), &id, &["a.ics"], || {
            Err::<(), _>(StoreError::from(std::io::Error::other("disk full")))
        });
        assert!(matches!(result, Err(Error::Store(_))), "{result:?}");
        assert!(pending(dir.path(), &id).is_empty());
    }

    #[test]
    fn a_write_that_removes_the_file_queues_its_deletion() {
        let (dir, id, file) = synced();
        let saved = save_and_queue(dir.path(), &id, &["a.ics", "never-synced.ics"], || {
            std::fs::remove_file(&file).map_err(StoreError::from)
        })
        .unwrap();
        assert!(saved.queued.unwrap());

        let meta = crate::provision::open_collection(dir.path(), &id).unwrap();
        let queue = VdirStore::open(meta).unwrap().pending().unwrap();
        assert_eq!(queue.len(), 1, "{queue:?}");
        assert!(
            matches!(&queue[0].op, cosmic_pim_caldav::push::PushOp::Delete { href, .. } if href == "/dav/cal/a.ics")
        );
    }

    #[test]
    fn a_collection_with_no_server_is_written_and_not_queued() {
        let (dir, id) = collection(false);
        let saved = save_and_queue(dir.path(), &id, &["a.ics"], || {
            Ok::<_, StoreError>("written")
        })
        .unwrap();
        assert_eq!(saved.value, "written");
        assert!(!saved.queued.unwrap());

        // Unknown and disconnected collections behave the same way.
        let saved = save_and_queue(dir.path(), "no-such-collection", &["a.ics"], || {
            Ok::<_, StoreError>(())
        })
        .unwrap();
        assert!(!saved.queued.unwrap());
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

// SPDX-License-Identifier: MPL-2.0

//! [`CalDavStore`] over a `cosmic-pim-core` vdir collection.
//!
//! Synced events land as ordinary `.ics` files in the same directory the user's
//! local events live in, which is the whole reason to do it this way: khal,
//! Thunderbird, and vdirsyncer can all read the result, and deleting our SQLite
//! index loses nothing.
//!
//! # Where the sync bookkeeping lives
//!
//! CalDAV needs two things a vdir has no place for: the collection's ctag, and
//! each event's `(href, etag)`. Those go in a sidecar `.caldav-state.json` in
//! the collection directory.
//!
//! A sidecar file rather than a table in the SQLite index, deliberately. The
//! index is documented as a disposable cache that can be deleted at any time
//! and will rebuild itself — but sync state *cannot* be rebuilt from the files,
//! because an etag is the server's opaque token. Putting it in the index would
//! mean that clearing a cache silently triggers a full re-download and, worse,
//! resurrects events deleted on the server while the index was gone. Keeping it
//! next to the data it describes makes the collection self-contained.
//!
//! The leading dot keeps it out of `read_collection` (which reads only `*.ics`)
//! and out of the watcher's interest set.

use std::collections::HashMap;
use std::path::PathBuf;

use cosmic_pim_core::atomic;
use cosmic_pim_core::model::CalendarMeta;
use serde::{Deserialize, Serialize};

use crate::dav::Flavor;
use crate::error::{Error, Result};
use crate::push::{PendingPush, PushOp, PushQueue};
use crate::store::{CalDavStore, CollectionState, RemoteEvent};

const STATE_FILE: &str = ".caldav-state.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SidecarState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ctag: Option<String>,
    /// The collection's href on the server, recorded at provisioning time so a
    /// later sync can find its way back without re-running discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    href: Option<String>,
    /// The server's `current-user-privilege-set` grant, as discovered.
    ///
    /// Kept here rather than derived from directory permissions: the vdir is
    /// writable by us either way, and a shared iCloud or Fastmail calendar we
    /// may only read is a fact about the *server*, not about the filesystem.
    /// Writeback checks this before attempting a PUT that would 403.
    #[serde(default)]
    read_only: bool,
    /// href → what we wrote for it.
    #[serde(default)]
    entries: HashMap<String, SidecarEntry>,
    /// Local changes not yet accepted by the server.
    ///
    /// Durable on purpose: an edit that failed to push must outlive the process
    /// that made it, or it is lost silently — the server's etag never changed,
    /// so the next pull sees nothing to reconcile. See [`crate::push`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending: Vec<PendingPush>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SidecarEntry {
    /// The `.ics` file name inside the collection.
    file: String,
    etag: String,
}

pub struct VdirStore {
    meta: CalendarMeta,
    state: SidecarState,
    /// Which kind of collection this is. Decides the file extension and what
    /// counts as a plausible payload.
    flavor: Flavor,
}

impl VdirStore {
    /// Opens the sync state for a collection, creating it if absent.
    ///
    /// A sidecar that fails to parse is treated as absent rather than fatal.
    /// The cost is one full re-sync; the alternative is an app that cannot open
    /// a calendar because a JSON file got truncated.
    pub fn open(meta: CalendarMeta) -> Result<Self> {
        let path = meta.path.join(STATE_FILE);
        let state = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|why| {
                tracing::warn!(
                    path = %path.display(), %why,
                    "unreadable CalDAV sidecar; treating the collection as unsynced"
                );
                SidecarState::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => SidecarState::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            meta,
            state,
            flavor: Flavor::CalDav,
        })
    }

    /// Opens an address-book collection rather than a calendar.
    pub fn open_carddav(meta: CalendarMeta) -> Result<Self> {
        Ok(Self {
            flavor: Flavor::CardDav,
            ..Self::open(meta)?
        })
    }

    #[must_use]
    pub fn flavor(&self) -> Flavor {
        self.flavor
    }

    /// The file extension resources in this collection use.
    fn extension(&self) -> &'static str {
        match self.flavor {
            Flavor::CalDav => "ics",
            Flavor::CardDav => "vcf",
        }
    }

    #[must_use]
    pub fn collection(&self) -> &CalendarMeta {
        &self.meta
    }

    /// The collection's href on the server, if it has been provisioned.
    #[must_use]
    pub fn href(&self) -> Option<&str> {
        self.state.href.as_deref()
    }

    /// Whether the server told us we may only read this collection.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.state.read_only
    }

    /// Records what discovery learned about this collection.
    pub fn set_remote(&mut self, href: &str, read_only: bool) -> Result<()> {
        self.state.href = Some(href.to_owned());
        self.state.read_only = read_only;
        self.save_sidecar()
    }

    /// The href a local `.ics` file belongs to.
    ///
    /// Known files resolve through the sidecar. A file we have never synced —
    /// an event the user just created locally — has no href yet, so one is
    /// derived from the collection's own href plus the file name. That is the
    /// same shape the server would have given it, and it means a locally
    /// created event and the copy that comes back on the next pull land on the
    /// same resource instead of duplicating.
    ///
    /// `None` when the collection is not CalDAV-backed at all, which is how a
    /// purely local calendar is distinguished from an unsynced event.
    #[must_use]
    pub fn href_for_file(&self, file: &str) -> Option<String> {
        if let Some((href, _)) = self
            .state
            .entries
            .iter()
            .find(|(_, entry)| entry.file == file)
        {
            return Some(href.clone());
        }

        let collection = self.state.href.as_deref()?;
        Some(format!("{}{file}", collection.trim_end_matches('/').to_owned() + "/"))
    }

    /// The href and etag recorded for a local file, if the server knows it.
    ///
    /// Distinct from [`Self::href_for_file`], which *derives* an href for a
    /// file the server has never seen. Here `None` genuinely means "not on the
    /// server", which is what the delete path must not guess at.
    #[must_use]
    pub fn entry_for_by_file(&self, file: &str) -> Option<(String, String)> {
        self.state
            .entries
            .iter()
            .find(|(_, entry)| entry.file == file)
            .map(|(href, entry)| (href.clone(), entry.etag.clone()))
    }

    /// The `.ics` file and last-known etag we hold for an href, if any.
    #[must_use]
    pub fn entry_for(&self, href: &str) -> Option<(String, String)> {
        self.state
            .entries
            .get(href)
            .map(|e| (e.file.clone(), e.etag.clone()))
    }

    /// Queues a local edit for writeback, allocating the file name an href will
    /// use if it does not have one yet.
    pub fn queue_put(&mut self, href: &str) -> Result<()> {
        let file = self.file_name_for(href);
        let etag = self.state.entries.get(href).map(|e| e.etag.clone());
        self.enqueue(PushOp::Put {
            href: href.to_owned(),
            file,
            etag,
        })
    }

    /// Queues a server-side delete, capturing the coordinates before the local
    /// file disappears.
    pub fn queue_delete(&mut self, href: &str) -> Result<()> {
        let etag = self.state.entries.get(href).map(|e| e.etag.clone());
        self.enqueue(PushOp::Delete {
            href: href.to_owned(),
            etag,
        })
    }

    fn state_path(&self) -> PathBuf {
        self.meta.path.join(STATE_FILE)
    }

    /// Persists the sidecar. Atomic, because a torn sidecar is a full re-sync.
    fn save_sidecar(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.state)
            .map_err(|why| Error::internal(format!("serialising CalDAV sync state: {why}")))?;
        atomic::write(&self.state_path(), &json, None)
            .map(|_| ())
            .map_err(|why| Error::internal(format!("writing CalDAV sync state: {why}")))
    }

    /// The file name to store an href under.
    ///
    /// Reuses the name already recorded for that href so an update overwrites
    /// in place rather than accumulating copies. Otherwise it is derived from
    /// the href's last segment, which is what every other vdir tool does and
    /// keeps the directory legible.
    fn file_name_for(&self, href: &str) -> String {
        if let Some(existing) = self.state.entries.get(href) {
            return existing.file.clone();
        }

        let extension = self.extension();
        let stem = href
            .rsplit('/')
            .find(|segment| !segment.is_empty())
            .unwrap_or(href)
            .trim_end_matches(&format!(".{extension}"));

        let mut name = format!("{}.{extension}", sanitise_stem(stem));

        // Two distinct hrefs can sanitise to the same name (different
        // collections on the same server, percent-encoding collapsing). Storing
        // both under one file would make each sync overwrite the other, forever.
        if self
            .state
            .entries
            .values()
            .any(|entry| entry.file == name)
        {
            let mut n = 2;
            loop {
                let candidate = format!("{}-{n}.{extension}", sanitise_stem(stem));
                if !self
                    .state
                    .entries
                    .values()
                    .any(|entry| entry.file == candidate)
                {
                    name = candidate;
                    break;
                }
                n += 1;
            }
        }
        name
    }
}

/// Makes an href segment safe as a file name.
///
/// Hrefs are server-controlled text and routinely contain `/`, `@`, and
/// percent-escapes; without this a hostile or merely careless server could
/// place a file outside the collection directory.
fn sanitise_stem(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();

    // Path separators are already gone so this cannot traverse; collapsing runs
    // of dots keeps `..` out of names entirely, which is one less thing for a
    // future reader to have to reason about.
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
        "event".to_owned()
    } else {
        trimmed.chars().take(120).collect()
    }
}

/// Cheap sanity check that a payload is what this collection expects.
///
/// The protocol layer already gates on content type, but SSO portals answer
/// `200 text/calendar` with a login page often enough that it is worth
/// refusing at the storage boundary too: writing that HTML to a `.ics` would
/// replace a real event with an unparseable file, and the etag would be
/// recorded as if the write had succeeded.
fn looks_plausible(payload: &str, flavor: Flavor) -> bool {
    let head = payload.trim_start();
    match flavor {
        Flavor::CalDav => head
            .get(..15)
            .is_some_and(|h| h.eq_ignore_ascii_case("BEGIN:VCALENDAR")),
        Flavor::CardDav => head
            .get(..11)
            .is_some_and(|h| h.eq_ignore_ascii_case("BEGIN:VCARD")),
    }
}

impl CalDavStore for VdirStore {
    fn state(&self) -> Result<CollectionState> {
        Ok(CollectionState {
            ctag: self.state.ctag.clone(),
            entries: self
                .state
                .entries
                .iter()
                .map(|(href, entry)| (href.clone(), entry.etag.clone()))
                .collect(),
        })
    }

    fn upsert(&mut self, event: &RemoteEvent) -> Result<()> {
        if !looks_plausible(&event.ics, self.flavor) {
            return Err(Error::protocol(format!(
                "refusing to store an implausible payload for {} (expected {:?} data)",
                event.href, self.flavor
            )));
        }

        let file = self.file_name_for(&event.href);
        let target = self.meta.path.join(&file);

        // Unguarded: the server's copy is authoritative for a resource we are
        // pulling. The guarded path exists for the opposite direction, where a
        // local edit must not clobber something sync brought down.
        atomic::write(&target, &event.ics, None)
            .map_err(|why| Error::internal(format!("writing {}: {why}", target.display())))?;

        self.state.entries.insert(
            event.href.clone(),
            SidecarEntry {
                file,
                etag: event.etag.clone(),
            },
        );
        self.save_sidecar()
    }

    fn remove(&mut self, href: &str) -> Result<()> {
        if let Some(entry) = self.state.entries.remove(href) {
            let path = self.meta.path.join(&entry.file);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            self.save_sidecar()?;
        }
        Ok(())
    }

    fn commit_ctag(&mut self, ctag: Option<&str>) -> Result<()> {
        self.state.ctag = ctag.map(ToOwned::to_owned);
        self.save_sidecar()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::vdir;

    const SAMPLE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
         BEGIN:VEVENT\r\nUID:a@test\r\nDTSTART:20260804T090000Z\r\nDTEND:20260804T100000Z\r\n\
         SUMMARY:From the server\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    fn store() -> (tempfile::TempDir, VdirStore) {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        let store = VdirStore::open(meta).unwrap();
        (dir, store)
    }

    fn remote(href: &str, etag: &str) -> RemoteEvent {
        RemoteEvent {
            href: href.into(),
            etag: etag.into(),
            ics: SAMPLE.into(),
        }
    }

    #[test]
    fn an_upserted_event_is_readable_as_an_ordinary_vdir_file() {
        let (_dir, mut store) = store();
        store.upsert(&remote("/cal/abc.ics", "\"v1\"")).unwrap();

        // The point of the whole design: khal and vdirsyncer see this too.
        let events = vdir::read_collection(store.collection());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, "From the server");
    }

    #[test]
    fn the_servers_bytes_are_stored_verbatim() {
        let (_dir, mut store) = store();
        // A property our model does not represent. Re-serialising through
        // `Event` would drop it; storing verbatim keeps it.
        let ics = SAMPLE.replace(
            "SUMMARY:From the server",
            "SUMMARY:From the server\r\nATTENDEE;CN=Someone:mailto:s@example.com",
        );
        store
            .upsert(&RemoteEvent {
                href: "/cal/abc.ics".into(),
                etag: "\"v1\"".into(),
                ics: ics.clone(),
            })
            .unwrap();

        let written =
            std::fs::read_to_string(store.collection().path.join("abc.ics")).unwrap();
        assert!(
            written.contains("ATTENDEE;CN=Someone"),
            "an unmodelled property was lost on the way to disk"
        );
    }

    #[test]
    fn state_round_trips_through_a_reopen() {
        let (dir, mut store) = store();
        store.upsert(&remote("/cal/abc.ics", "\"v1\"")).unwrap();
        store.commit_ctag(Some("ctag-1")).unwrap();

        let meta = vdir::collections(dir.path()).remove(0);
        let reopened = VdirStore::open(meta).unwrap();
        let state = reopened.state().unwrap();

        assert_eq!(state.ctag.as_deref(), Some("ctag-1"));
        assert_eq!(state.entries.get("/cal/abc.ics").map(String::as_str), Some("\"v1\""));
    }

    #[test]
    fn updating_an_href_overwrites_rather_than_accumulating() {
        let (_dir, mut store) = store();
        store.upsert(&remote("/cal/abc.ics", "\"v1\"")).unwrap();
        store.upsert(&remote("/cal/abc.ics", "\"v2\"")).unwrap();

        let ics_files: Vec<_> = std::fs::read_dir(&store.collection().path)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".ics"))
            .collect();
        assert_eq!(ics_files.len(), 1, "update duplicated the file: {ics_files:?}");
        assert_eq!(
            store.state().unwrap().entries["/cal/abc.ics"],
            "\"v2\"",
            "the etag was not advanced"
        );
    }

    #[test]
    fn distinct_hrefs_that_sanitise_alike_get_distinct_files() {
        let (_dir, mut store) = store();
        store.upsert(&remote("/cal/a@b.ics", "\"v1\"")).unwrap();
        store.upsert(&remote("/cal/a%40b.ics", "\"v1\"")).unwrap();

        let state = store.state().unwrap();
        assert_eq!(state.entries.len(), 2);
        let ics_files = std::fs::read_dir(&store.collection().path)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".ics"))
            .count();
        assert_eq!(ics_files, 2, "two hrefs collapsed onto one file");
    }

    #[test]
    fn a_hostile_href_cannot_escape_the_collection() {
        let (_dir, mut store) = store();
        store
            .upsert(&remote("/cal/../../../../tmp/escaped.ics", "\"v1\""))
            .unwrap();

        let written: Vec<_> = std::fs::read_dir(&store.collection().path)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "ics"))
            .collect();
        assert_eq!(written.len(), 1);
        let canonical = written[0].canonicalize().unwrap();
        assert!(
            canonical.starts_with(store.collection().path.canonicalize().unwrap()),
            "escaped the collection: {}",
            canonical.display()
        );
    }

    #[test]
    fn an_sso_login_page_is_refused_rather_than_written() {
        let (_dir, mut store) = store();
        let result = store.upsert(&RemoteEvent {
            href: "/cal/abc.ics".into(),
            etag: "\"v1\"".into(),
            ics: "<!DOCTYPE html><html><body>Please sign in</body></html>".into(),
        });
        assert!(result.is_err(), "an HTML login page was stored as an event");
        assert!(store.state().unwrap().entries.is_empty());
    }

    #[test]
    fn removing_deletes_the_file_and_forgets_the_href() {
        let (_dir, mut store) = store();
        store.upsert(&remote("/cal/abc.ics", "\"v1\"")).unwrap();
        store.remove("/cal/abc.ics").unwrap();

        assert!(store.state().unwrap().entries.is_empty());
        assert!(vdir::read_collection(store.collection()).is_empty());
    }

    #[test]
    fn removing_something_we_never_had_is_not_an_error() {
        let (_dir, mut store) = store();
        assert!(store.remove("/cal/never-seen.ics").is_ok());
    }

    #[test]
    fn the_sidecar_is_invisible_to_the_collection_reader() {
        let (_dir, mut store) = store();
        store.upsert(&remote("/cal/abc.ics", "\"v1\"")).unwrap();
        store.commit_ctag(Some("ctag-1")).unwrap();

        assert!(store.collection().path.join(STATE_FILE).exists());
        assert_eq!(
            vdir::read_collection(store.collection()).len(),
            1,
            "the sidecar was parsed as calendar data"
        );
    }

    #[test]
    fn a_corrupt_sidecar_degrades_to_a_full_resync_rather_than_failing() {
        let (dir, mut store) = store();
        store.upsert(&remote("/cal/abc.ics", "\"v1\"")).unwrap();
        store.commit_ctag(Some("ctag-1")).unwrap();

        std::fs::write(store.collection().path.join(STATE_FILE), "{ truncated").unwrap();

        let meta = vdir::collections(dir.path()).remove(0);
        let reopened = VdirStore::open(meta).expect("a corrupt sidecar must not be fatal");
        let state = reopened.state().unwrap();
        assert!(state.ctag.is_none());
        assert!(state.entries.is_empty());
    }
}

impl PushQueue for VdirStore {
    fn pending(&self) -> Vec<PendingPush> {
        self.state.pending.clone()
    }

    fn enqueue(&mut self, op: PushOp) -> Result<()> {
        let href = op.href().to_owned();
        // Replace rather than append: the newest edit is the one that should
        // reach the server, and replaying a stale state on top of a fresh one
        // is worse than not pushing at all.
        if let Some(existing) = self
            .state
            .pending
            .iter_mut()
            .find(|e| e.op.href() == href)
        {
            existing.op = op;
            existing.attempts = 0;
            existing.next_attempt_ms = 0;
            existing.last_error = None;
        } else {
            self.state.pending.push(PendingPush {
                op,
                attempts: 0,
                next_attempt_ms: 0,
                last_error: None,
            });
        }
        self.save_sidecar()
    }

    fn resolve(&mut self, href: &str) -> Result<()> {
        let before = self.state.pending.len();
        self.state.pending.retain(|e| e.op.href() != href);
        if self.state.pending.len() != before {
            self.save_sidecar()?;
        }
        Ok(())
    }

    fn defer(&mut self, href: &str, error: &str, next_attempt_ms: i64) -> Result<()> {
        if let Some(entry) = self
            .state
            .pending
            .iter_mut()
            .find(|e| e.op.href() == href)
        {
            entry.attempts = entry.attempts.saturating_add(1);
            entry.next_attempt_ms = next_attempt_ms;
            entry.last_error = Some(error.to_owned());
            self.save_sidecar()?;
        }
        Ok(())
    }

    fn payload(&self, file: &str) -> Option<String> {
        std::fs::read_to_string(self.meta.path.join(file)).ok()
    }

    fn read_only(&self) -> bool {
        self.state.read_only
    }
}

#[cfg(test)]
mod push_queue_tests {
    use super::*;
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::vdir;

    fn store() -> (tempfile::TempDir, VdirStore) {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        (dir, VdirStore::open(meta).unwrap())
    }

    #[test]
    fn a_queued_edit_survives_a_reopen() {
        let (dir, mut store) = store();
        store.queue_put("/cal/a.ics").unwrap();

        // This is the whole point of the queue: a process restart between the
        // edit and the network coming back must not lose the edit.
        let meta = vdir::collections(dir.path()).remove(0);
        let reopened = VdirStore::open(meta).unwrap();

        let pending = reopened.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].op.href(), "/cal/a.ics");
    }

    #[test]
    fn a_queued_put_points_at_the_file_the_href_maps_to() {
        let (_dir, mut store) = store();
        store.queue_put("/cal/abc.ics").unwrap();

        let PushOp::Put { file, .. } = &store.pending()[0].op else {
            panic!("expected a Put");
        };
        assert_eq!(file, "abc.ics");
    }

    #[test]
    fn a_delete_captures_the_etag_before_the_file_goes() {
        let (_dir, mut store) = store();
        store
            .upsert(&RemoteEvent {
                href: "/cal/a.ics".into(),
                etag: "\"v7\"".into(),
                ics: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".into(),
            })
            .unwrap();

        store.queue_delete("/cal/a.ics").unwrap();
        store.remove("/cal/a.ics").unwrap();

        let PushOp::Delete { etag, .. } = &store.pending()[0].op else {
            panic!("expected a Delete");
        };
        assert_eq!(
            etag.as_deref(),
            Some("\"v7\""),
            "the etag was lost, so the delete cannot be conditional"
        );
    }

    #[test]
    fn resolving_removes_the_entry_durably() {
        let (dir, mut store) = store();
        store.queue_put("/cal/a.ics").unwrap();
        store.resolve("/cal/a.ics").unwrap();

        let meta = vdir::collections(dir.path()).remove(0);
        assert!(VdirStore::open(meta).unwrap().pending().is_empty());
    }

    #[test]
    fn deferring_records_the_error_durably() {
        let (dir, mut store) = store();
        store.queue_put("/cal/a.ics").unwrap();
        store.defer("/cal/a.ics", "connection refused", 12_345).unwrap();

        let meta = vdir::collections(dir.path()).remove(0);
        let pending = VdirStore::open(meta).unwrap().pending();
        assert_eq!(pending[0].attempts, 1);
        assert_eq!(pending[0].next_attempt_ms, 12_345);
        assert_eq!(pending[0].last_error.as_deref(), Some("connection refused"));
    }

    #[test]
    fn the_payload_is_read_from_disk_at_drain_time_not_captured_when_queued() {
        let (_dir, mut store) = store();
        store
            .upsert(&RemoteEvent {
                href: "/cal/a.ics".into(),
                etag: "\"1\"".into(),
                ics: "BEGIN:VCALENDAR\r\nX-V:1\r\nEND:VCALENDAR\r\n".into(),
            })
            .unwrap();
        store.queue_put("/cal/a.ics").unwrap();

        // A second edit lands before the queue drains. The push must send the
        // FINAL state, not the state at enqueue time.
        std::fs::write(
            store.collection().path.join("a.ics"),
            "BEGIN:VCALENDAR\r\nX-V:2\r\nEND:VCALENDAR\r\n",
        )
        .unwrap();

        assert!(store.payload("a.ics").unwrap().contains("X-V:2"));
    }
}

#[cfg(test)]
mod carddav_tests {
    use super::*;
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::{contacts, vdir};

    const CARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a@test\r\nFN:Ada Lovelace\r\n\
PHOTO;ENCODING=b:AAAA\r\nEND:VCARD\r\n";

    fn book() -> (tempfile::TempDir, VdirStore) {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Contacts", Rgb(1, 2, 3)).unwrap();
        (dir, VdirStore::open_carddav(meta).unwrap())
    }

    #[test]
    fn a_synced_contact_lands_as_a_vcf_readable_by_the_contact_store() {
        let (_dir, mut store) = book();
        store
            .upsert(&RemoteEvent {
                href: "/dav/contacts/default/ada.vcf".into(),
                etag: "\"1\"".into(),
                ics: CARD.into(),
            })
            .unwrap();

        let contacts = contacts::read_book(store.collection());
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].label(), "Ada Lovelace");
        assert!(
            contacts[0].has_photo,
            "the PHOTO our model does not load was lost on the way to disk"
        );
    }

    #[test]
    fn a_derived_file_name_uses_the_vcf_extension() {
        let (_dir, mut store) = book();
        // No extension in the href at all — the store must still choose .vcf,
        // or `read_book` (which reads only *.vcf) would never see it.
        store
            .upsert(&RemoteEvent {
                href: "/dav/contacts/default/8f3c-aa11".into(),
                etag: "\"1\"".into(),
                ics: CARD.into(),
            })
            .unwrap();

        assert_eq!(contacts::read_book(store.collection()).len(), 1);
        let files: Vec<String> = std::fs::read_dir(&store.collection().path)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.') && n != "displayname" && n != "color")
            .collect();
        assert_eq!(files, vec!["8f3c-aa11.vcf".to_string()]);
    }

    #[test]
    fn an_icalendar_payload_is_refused_by_an_address_book() {
        let (_dir, mut store) = book();
        let result = store.upsert(&RemoteEvent {
            href: "/dav/contacts/default/a.vcf".into(),
            etag: "\"1\"".into(),
            ics: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".into(),
        });
        assert!(result.is_err(), "a VCALENDAR was stored in an address book");
    }

    #[test]
    fn an_sso_login_page_is_refused_by_an_address_book_too() {
        let (_dir, mut store) = book();
        let result = store.upsert(&RemoteEvent {
            href: "/dav/contacts/default/a.vcf".into(),
            etag: "\"1\"".into(),
            ics: "<!DOCTYPE html><html>sign in</html>".into(),
        });
        assert!(result.is_err());
    }
}

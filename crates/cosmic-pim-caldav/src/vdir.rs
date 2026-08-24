// Copyright 2026 Dominikos Pritis
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
use crate::store::{CalDavStore, CollectionState, Conflict, RemoteEvent};

const STATE_FILE: &str = ".caldav-state.json";

/// Files another sync engine leaves in a collection it owns.
///
/// vdirsyncer keeps its status database outside the collection, but writes
/// per-collection metadata beside the items, and the names are its own.
/// Anything starting with this prefix means something else is already
/// synchronising this directory.
const FOREIGN_SYNC_PREFIX: &str = ".vdirsyncer";

/// The name of a foreign sync engine's file in `path`, if there is one.
///
/// # Why this check exists
///
/// A vdir can legitimately be synced by vdirsyncer *or* by this crate. Both at
/// once is a divergence machine: the two keep independent state and neither
/// knows the other exists, so each sees the other's writes as an unexpected
/// etag, re-fetches, re-pushes, and the collection oscillates between two
/// versions for as long as both are running. Nothing in either engine detects
/// it, because from the inside each one is behaving correctly.
///
/// The check is deliberately shallow — one directory read, matching on a name
/// prefix. Parsing vdirsyncer's configuration to find out which collections it
/// claims would be more thorough and much more fragile; a marker file in the
/// directory is evidence that needs no interpretation.
#[must_use]
pub fn foreign_sync_marker(path: &std::path::Path) -> Option<String> {
    std::fs::read_dir(path)
        .ok()?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with(FOREIGN_SYNC_PREFIX))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SidecarState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ctag: Option<String>,
    /// The collection's href on the server, recorded at provisioning time so a
    /// later sync can find its way back without re-running discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    href: Option<String>,
    /// The user has been warned that another engine syncs this collection and
    /// asked for it to be synced anyway. See
    /// [`VdirStore::acknowledge_sole_ownership`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    sole_owner_acknowledged: bool,
    /// Whether this directory holds calendars or contacts.
    ///
    /// Recorded rather than inferred from which root it sits under: the
    /// collection is then self-describing, and every entry point that opens one
    /// — writeback, conflict resolution, a future repair tool — gets the right
    /// file extension and payload check without being told which kind it is.
    #[serde(default)]
    flavor: Flavor,
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
    /// Resources both sides changed, awaiting a decision from the user.
    ///
    /// The server's bytes live here rather than on disk because the local file
    /// is still holding the local edit — that is the point. Bounded by the
    /// number of unresolved conflicts, which is a handful at worst, so keeping
    /// payloads in the sidecar costs nothing the way keeping every item's
    /// payload would. See [`crate::store::Conflict`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    conflicts: Vec<Conflict>,
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
            flavor: state.flavor,
            state,
        })
    }

    /// Opens a collection as an address book, whatever its sidecar says.
    ///
    /// Only provisioning needs this: a collection being set up for the first
    /// time has no sidecar to have recorded a flavour in yet. Afterwards
    /// [`Self::open`] reads it back and this is unnecessary.
    pub fn open_carddav(meta: CalendarMeta) -> Result<Self> {
        let mut store = Self::open(meta)?;
        store.flavor = Flavor::CardDav;
        store.state.flavor = Flavor::CardDav;
        Ok(store)
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

    /// Another sync engine's marker file in this collection, if there is one.
    ///
    /// See [`foreign_sync_marker`]. Provisioning refuses such a collection
    /// until [`Self::acknowledge_sole_ownership`] says a human has been asked.
    #[must_use]
    pub fn foreign_sync_marker(&self) -> Option<String> {
        if self.state.sole_owner_acknowledged {
            return None;
        }
        foreign_sync_marker(&self.meta.path)
    }

    /// Records that the user was told another engine syncs this collection and
    /// chose to proceed anyway.
    ///
    /// Durable, because the question is about the collection rather than about
    /// this run, and asking it again every five seconds would train the user to
    /// dismiss it. Reversible only by editing the sidecar — which is the right
    /// weight for "yes, I really do want two sync engines here".
    pub fn acknowledge_sole_ownership(&mut self) -> Result<()> {
        self.state.sole_owner_acknowledged = true;
        self.save_sidecar()
    }

    /// Records what discovery learned about this collection.
    ///
    /// Provisioning calls this, which is where the flavour becomes durable:
    /// from here on, opening the collection is enough to know what it holds.
    pub fn set_remote(&mut self, href: &str, read_only: bool) -> Result<()> {
        self.state.href = Some(href.to_owned());
        self.state.read_only = read_only;
        self.state.flavor = self.flavor;
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
        Some(format!(
            "{}{file}",
            collection.trim_end_matches('/').to_owned() + "/"
        ))
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

    /// Resources both sides changed, still awaiting a decision.
    ///
    /// The application shows these; nothing here resolves itself with time.
    /// Until one of the two resolvers below is called, the local file keeps the
    /// local edit and the queued push stays parked.
    #[must_use]
    pub fn conflicts(&self) -> &[Conflict] {
        &self.state.conflicts
    }

    /// Whether `href` is currently in conflict.
    #[must_use]
    pub fn conflict_for(&self, href: &str) -> Option<&Conflict> {
        self.state.conflicts.iter().find(|c| c.href == href)
    }

    /// Take the server's version: the local edit is discarded.
    ///
    /// The remote bytes recorded at detection time are written to the file and
    /// its etag is already current, so this completes without touching the
    /// network. The queued push goes with the edit it was carrying.
    pub fn resolve_conflict_take_remote(&mut self, href: &str) -> Result<bool> {
        let Some(conflict) = self.conflict_for(href).cloned() else {
            return Ok(false);
        };

        self.upsert(&RemoteEvent {
            href: conflict.href.clone(),
            etag: conflict.remote_etag.clone(),
            ics: conflict.remote.clone(),
        })?;

        self.resolve(href)?;
        self.clear_conflict(href)
    }

    /// Keep the local version: it is re-queued and will overwrite the server's.
    ///
    /// `merged` is for the third answer — neither copy as it stands, but a text
    /// the user (or a property-level merge) produced from both. `None` keeps
    /// the file exactly as it is.
    ///
    /// The re-queued push carries the etag recorded when the conflict was
    /// detected, which is the server's current one, so the `If-Match` matches
    /// and the write is accepted. That is the whole reason detection records
    /// the etag rather than discarding it.
    pub fn resolve_conflict_keep_local(
        &mut self,
        href: &str,
        merged: Option<&str>,
    ) -> Result<bool> {
        let Some(conflict) = self.conflict_for(href).cloned() else {
            return Ok(false);
        };

        if let Some(text) = merged {
            let file = self.file_name_for(&conflict.href);
            let target = self.meta.path.join(&file);
            atomic::write(&target, text, None)
                .map_err(|why| Error::internal(format!("writing {}: {why}", target.display())))?;
            self.state.entries.insert(
                conflict.href.clone(),
                SidecarEntry {
                    file,
                    etag: conflict.remote_etag.clone(),
                },
            );
        }

        // Re-queueing rather than un-parking: `enqueue` reads the etag we now
        // hold, which is the server's, and clears the block in one step.
        self.queue_put(href)?;
        self.clear_conflict(href)
    }

    fn clear_conflict(&mut self, href: &str) -> Result<bool> {
        let before = self.state.conflicts.len();
        self.state.conflicts.retain(|c| c.href != href);
        if self.state.conflicts.len() == before {
            return Ok(false);
        }
        self.save_sidecar()?;
        Ok(true)
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
        if self.state.entries.values().any(|entry| entry.file == name) {
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

        // Read before writing: what the file held a moment ago is what a queued
        // push for this href would have sent, and the two being equal is the
        // one case where that push has nothing left to do.
        let previous = std::fs::read_to_string(&target).ok();

        // Unguarded: the server's copy is authoritative for a resource we are
        // pulling. The caller is responsible for having established that there
        // is no unsent local edit here — see `CalDavStore::unpushed_local` and
        // the conflict path in `crate::sync`, which is what keeps this write
        // from being the one that eats somebody's change.
        atomic::write(&target, &event.ics, None)
            .map_err(|why| Error::internal(format!("writing {}: {why}", target.display())))?;

        self.state.entries.insert(
            event.href.clone(),
            SidecarEntry {
                file,
                etag: event.etag.clone(),
            },
        );

        // A queued push whose payload is what the server just sent us has
        // nothing left to send. Without this, a push parked on a 412 whose
        // change reached the server by another route (a second client, the
        // same edit made twice) would stay parked forever and the UI would
        // claim unsaved changes that no longer exist.
        if previous.as_deref() == Some(event.ics.as_str()) {
            self.state.pending.retain(
                |entry| !matches!(&entry.op, PushOp::Put { href, .. } if href == &event.href),
            );
        }

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

    /// The file's current bytes, when a PUT for this href is still queued.
    ///
    /// A queued **delete** answers `None` on purpose. Its conflict — we removed
    /// the resource, the server edited it — resolves itself in practice, and
    /// resolves the safe way: writeback drains before the pull, so an
    /// online client sends the DELETE first and the server stops listing the
    /// resource. An offline one lets the pull restore the file, and the DELETE
    /// still goes out when the network returns. A resurrected event that
    /// disappears again on the next sync is a visible annoyance; it is not the
    /// silent loss this method exists to prevent.
    fn unpushed_local(&self, href: &str) -> Result<Option<String>> {
        let queued_put = self
            .state
            .pending
            .iter()
            .any(|entry| matches!(&entry.op, PushOp::Put { href: h, .. } if h == href));
        if !queued_put {
            return Ok(None);
        }
        let Some(entry) = self.state.entries.get(href) else {
            // Queued but never synced: the server cannot have changed a
            // resource it has not given us, so there is nothing to diff.
            return Ok(None);
        };
        Ok(std::fs::read_to_string(self.meta.path.join(&entry.file)).ok())
    }

    fn record_conflict(&mut self, conflict: &Conflict) -> Result<()> {
        // The etag moves to the server's current value; the payload does not.
        // Recording the etag is what stops the next cycle re-fetching the same
        // divergence, and it is exactly the If-Match a resolution will need.
        if let Some(entry) = self.state.entries.get_mut(&conflict.href) {
            entry.etag = conflict.remote_etag.clone();
        }

        // The queued push must stop trying. Its bytes would overwrite the
        // server's change, and with the etag now current it would *succeed* at
        // doing so — silently losing the remote side instead of the local one.
        for entry in &mut self.state.pending {
            if entry.op.href() == conflict.href {
                entry.blocked = true;
                entry.last_error = Some("waiting on a conflict to be resolved".to_owned());
            }
        }

        self.state.conflicts.retain(|c| c.href != conflict.href);
        self.state.conflicts.push(conflict.clone());
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

        let written = std::fs::read_to_string(store.collection().path.join("abc.ics")).unwrap();
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
        assert_eq!(
            state.entries.get("/cal/abc.ics").map(String::as_str),
            Some("\"v1\"")
        );
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
        assert_eq!(
            ics_files.len(),
            1,
            "update duplicated the file: {ics_files:?}"
        );
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
        if let Some(existing) = self.state.pending.iter_mut().find(|e| e.op.href() == href) {
            existing.op = op;
            existing.attempts = 0;
            existing.next_attempt_ms = 0;
            existing.last_error = None;
            // A fresh edit supersedes whatever the last one was held up by.
            existing.blocked = false;
        } else {
            self.state.pending.push(PendingPush {
                op,
                attempts: 0,
                next_attempt_ms: 0,
                last_error: None,
                blocked: false,
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
        if let Some(entry) = self.state.pending.iter_mut().find(|e| e.op.href() == href) {
            entry.attempts = entry.attempts.saturating_add(1);
            entry.next_attempt_ms = next_attempt_ms;
            entry.last_error = Some(error.to_owned());
            self.save_sidecar()?;
        }
        Ok(())
    }

    fn park(&mut self, href: &str, error: &str) -> Result<()> {
        if let Some(entry) = self.state.pending.iter_mut().find(|e| e.op.href() == href) {
            entry.blocked = true;
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
        store
            .defer("/cal/a.ics", "connection refused", 12_345)
            .unwrap();

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

#[cfg(test)]
mod conflict_tests {
    use super::*;
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::vdir;

    const SERVER_V1: &str = "BEGIN:VCALENDAR\r\nX-V:1\r\nEND:VCALENDAR\r\n";
    const LOCAL_EDIT: &str = "BEGIN:VCALENDAR\r\nX-V:1-mine\r\nEND:VCALENDAR\r\n";
    const SERVER_V2: &str = "BEGIN:VCALENDAR\r\nX-V:2-theirs\r\nEND:VCALENDAR\r\n";

    const HREF: &str = "/cal/a.ics";

    /// A collection holding one synced event that the user has since edited
    /// without the push getting through — the state every conflict starts from.
    fn diverged() -> (tempfile::TempDir, VdirStore) {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
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
        (dir, store)
    }

    fn file(store: &VdirStore) -> String {
        std::fs::read_to_string(store.collection().path.join("a.ics")).unwrap()
    }

    /// Applying what the pull would apply, once it has decided this is a
    /// conflict. Mirrors the branch in `crate::sync`.
    fn record(store: &mut VdirStore) {
        let local = store.unpushed_local(HREF).unwrap().expect("an unsent edit");
        store
            .record_conflict(&Conflict {
                href: HREF.into(),
                local,
                remote: SERVER_V2.into(),
                remote_etag: "\"v2\"".into(),
            })
            .unwrap();
    }

    #[test]
    fn an_unsent_edit_is_visible_to_the_pull_path() {
        let (_dir, store) = diverged();
        assert_eq!(
            store.unpushed_local(HREF).unwrap().as_deref(),
            Some(LOCAL_EDIT)
        );
    }

    #[test]
    fn a_resource_with_no_queued_push_has_nothing_unsent() {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        let mut store = VdirStore::open(meta).unwrap();
        store
            .upsert(&RemoteEvent {
                href: HREF.into(),
                etag: "\"v1\"".into(),
                ics: SERVER_V1.into(),
            })
            .unwrap();

        assert_eq!(store.unpushed_local(HREF).unwrap(), None);
    }

    #[test]
    fn a_queued_delete_is_not_treated_as_unsent_content() {
        // Delete-versus-edit resolves itself through push-before-pull; see the
        // note on `unpushed_local`. What must not happen is a conflict record
        // holding the bytes of a file the user asked to remove.
        let (_dir, mut store) = diverged();
        store.resolve(HREF).unwrap();
        store.queue_delete(HREF).unwrap();

        assert_eq!(store.unpushed_local(HREF).unwrap(), None);
    }

    #[test]
    fn recording_a_conflict_keeps_the_local_file_untouched() {
        // The entire point: the pull must not write the server's copy over an
        // edit that has not been sent yet.
        let (_dir, mut store) = diverged();
        record(&mut store);

        assert_eq!(file(&store), LOCAL_EDIT, "the local edit was overwritten");
        assert_eq!(store.conflicts().len(), 1);
        assert_eq!(store.conflict_for(HREF).unwrap().remote, SERVER_V2);
    }

    #[test]
    fn recording_a_conflict_adopts_the_servers_etag_and_parks_the_push() {
        let (_dir, mut store) = diverged();
        record(&mut store);

        assert_eq!(
            store.entry_for(HREF).unwrap().1,
            "\"v2\"",
            "the server's etag was not adopted, so the next cycle re-fetches the same divergence"
        );
        assert!(
            store.pending()[0].blocked,
            "the queued push was left live; with the etag now current it would \
             have succeeded at overwriting the server's change"
        );
    }

    #[test]
    fn a_conflict_survives_a_reopen() {
        let (dir, mut store) = diverged();
        record(&mut store);

        let meta = vdir::collections(dir.path()).remove(0);
        let reopened = VdirStore::open(meta).unwrap();

        let conflict = reopened
            .conflict_for(HREF)
            .expect("conflict lost on restart");
        assert_eq!(conflict.local, LOCAL_EDIT);
        assert_eq!(conflict.remote, SERVER_V2);
    }

    #[test]
    fn taking_the_remote_version_writes_it_and_drops_the_push() {
        let (_dir, mut store) = diverged();
        record(&mut store);

        assert!(store.resolve_conflict_take_remote(HREF).unwrap());

        assert_eq!(file(&store), SERVER_V2);
        assert_eq!(store.entry_for(HREF).unwrap().1, "\"v2\"");
        assert!(
            store.pending().is_empty(),
            "a push survived the edit it carried"
        );
        assert!(store.conflicts().is_empty());
    }

    #[test]
    fn keeping_the_local_version_requeues_it_against_the_servers_etag() {
        let (_dir, mut store) = diverged();
        record(&mut store);

        assert!(store.resolve_conflict_keep_local(HREF, None).unwrap());

        assert_eq!(file(&store), LOCAL_EDIT, "the local copy was not kept");
        assert!(store.conflicts().is_empty());

        let entry = &store.pending()[0];
        assert!(!entry.blocked, "the resolved push stayed parked");
        let PushOp::Put { etag, .. } = &entry.op else {
            panic!("expected a Put");
        };
        assert_eq!(
            etag.as_deref(),
            Some("\"v2\""),
            "re-queued with the stale etag, so the resolution would 412 exactly as the original did"
        );
    }

    #[test]
    fn a_merged_resolution_is_what_gets_pushed() {
        const MERGED: &str = "BEGIN:VCALENDAR\r\nX-V:merged\r\nEND:VCALENDAR\r\n";
        let (_dir, mut store) = diverged();
        record(&mut store);

        assert!(
            store
                .resolve_conflict_keep_local(HREF, Some(MERGED))
                .unwrap()
        );

        assert_eq!(file(&store), MERGED);
        assert_eq!(store.payload("a.ics").as_deref(), Some(MERGED));
    }

    #[test]
    fn resolving_something_that_is_not_in_conflict_is_not_an_error() {
        let (_dir, mut store) = diverged();
        assert!(!store.resolve_conflict_take_remote(HREF).unwrap());
        assert!(!store.resolve_conflict_keep_local(HREF, None).unwrap());
    }

    #[test]
    fn a_push_the_server_already_has_stops_being_pending() {
        // The parked-forever case: the same change reached the server by
        // another route, so the pull brings back exactly what we were queued to
        // send. Nothing is left to push, and the UI must stop saying otherwise.
        let (_dir, mut store) = diverged();
        store
            .upsert(&RemoteEvent {
                href: HREF.into(),
                etag: "\"v9\"".into(),
                ics: LOCAL_EDIT.into(),
            })
            .unwrap();

        assert!(store.pending().is_empty());
    }
}

#[cfg(test)]
mod flavor_tests {
    use super::*;
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::vdir;

    const VCARD: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada\r\nUID:a@test\r\nEND:VCARD\r\n";

    #[test]
    fn an_address_book_stays_an_address_book_across_a_reopen() {
        // Writeback and conflict resolution both open a collection by id with
        // no idea what it holds. If the flavour did not survive, they would
        // write `.ics` files into an address book and refuse every vCard as an
        // implausible payload.
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "People", Rgb(1, 2, 3)).unwrap();
        let mut store = VdirStore::open_carddav(meta).unwrap();
        store.set_remote("/dav/contacts/", false).unwrap();

        let meta = vdir::collections(dir.path()).remove(0);
        let reopened = VdirStore::open(meta).unwrap();

        assert_eq!(reopened.flavor(), Flavor::CardDav);
    }

    #[test]
    fn a_reopened_address_book_stores_vcards_under_vcf() {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "People", Rgb(1, 2, 3)).unwrap();
        let mut store = VdirStore::open_carddav(meta).unwrap();
        store.set_remote("/dav/contacts/", false).unwrap();

        let meta = vdir::collections(dir.path()).remove(0);
        let mut reopened = VdirStore::open(meta).unwrap();
        reopened
            .upsert(&RemoteEvent {
                href: "/dav/contacts/ada.vcf".into(),
                etag: "\"1\"".into(),
                ics: VCARD.into(),
            })
            .unwrap();

        assert!(reopened.collection().path.join("ada.vcf").exists());
    }

    #[test]
    fn a_collection_with_no_recorded_flavour_is_a_calendar() {
        // Sidecars written before the flavour existed, and any hand-made one.
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        std::fs::write(meta.path.join(STATE_FILE), r#"{"ctag":"x"}"#).unwrap();

        assert_eq!(VdirStore::open(meta).unwrap().flavor(), Flavor::CalDav);
    }
}

#[cfg(test)]
mod sync_ownership_tests {
    use super::*;
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::vdir;

    fn collection() -> (tempfile::TempDir, CalendarMeta) {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        (dir, meta)
    }

    #[test]
    fn a_collection_nothing_else_syncs_is_free_to_take() {
        let (_dir, meta) = collection();
        assert_eq!(foreign_sync_marker(&meta.path), None);
        assert_eq!(VdirStore::open(meta).unwrap().foreign_sync_marker(), None);
    }

    #[test]
    fn a_vdirsyncer_managed_collection_is_recognised() {
        // Two engines on one collection is the divergence machine described on
        // `foreign_sync_marker`; this is the evidence that stops it.
        let (_dir, meta) = collection();
        std::fs::write(meta.path.join(".vdirsyncer.collection.items"), "").unwrap();

        assert_eq!(
            VdirStore::open(meta)
                .unwrap()
                .foreign_sync_marker()
                .as_deref(),
            Some(".vdirsyncer.collection.items")
        );
    }

    #[test]
    fn our_own_sidecar_is_not_mistaken_for_a_rival() {
        let (_dir, meta) = collection();
        let mut store = VdirStore::open(meta.clone()).unwrap();
        store.set_remote("/cal/", false).unwrap();

        assert!(
            meta.path.join(STATE_FILE).exists(),
            "no sidecar was written"
        );
        assert_eq!(store.foreign_sync_marker(), None);
    }

    #[test]
    fn an_acknowledged_collection_syncs_despite_the_marker() {
        let (dir, meta) = collection();
        std::fs::write(meta.path.join(".vdirsyncer.collection.items"), "").unwrap();

        let mut store = VdirStore::open(meta).unwrap();
        store.acknowledge_sole_ownership().unwrap();
        assert_eq!(store.foreign_sync_marker(), None);

        // And it stays acknowledged: asking again on every five-second poll
        // teaches the user to dismiss the question without reading it.
        let meta = vdir::collections(dir.path()).remove(0);
        assert_eq!(VdirStore::open(meta).unwrap().foreign_sync_marker(), None);
    }
}

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
use crate::store::{
    CalDavStore, CollectionState, Conflict, ConflictKind, EmptySighting, RemoteEvent,
};

const STATE_FILE: &str = ".caldav-state.json";

/// Files another sync engine leaves in a collection it owns.
///
/// vdirsyncer keeps its status database outside the collection, but writes
/// per-collection metadata beside the items, and the names are its own.
/// Anything starting with this prefix means something else is already
/// synchronising this directory.
const FOREIGN_SYNC_PREFIX: &str = ".vdirsyncer";

/// The marker naming a collection as local-only: on this device by choice,
/// never to be adopted, bound, or pushed by any sync engine.
///
/// # Why an explicit marker when unbound already means unsynced
///
/// An unbound collection is *not yet* synced; a marked one is *not to be*
/// synced — and only the user can tell the two apart. The difference bites in
/// exactly one place: a collection that was synced once and then marked (the
/// user "disconnected" it) still carries its binding in `accounts.toml` and
/// its href in the sidecar, and without the marker the next pass would
/// cheerfully resume pushing a calendar the user decided was private. It is
/// also what Circle's on-device notes need before a CRM sidecar can exist at
/// all. The file's content is ignored; its presence is the fact.
const LOCAL_ONLY_MARKER: &str = ".local-only";

/// Marks a collection directory as local-only.
pub fn mark_local_only(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::write(path.join(LOCAL_ONLY_MARKER), b"")
}

/// Removes the marker, making the collection eligible for sync again.
pub fn unmark_local_only(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(path.join(LOCAL_ONLY_MARKER)) {
        Ok(()) => Ok(()),
        Err(why) if why.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(why) => Err(why),
    }
}

/// Whether a collection directory is marked local-only.
#[must_use]
pub fn is_local_only(path: &std::path::Path) -> bool {
    path.join(LOCAL_ONLY_MARKER).is_file()
}

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
    /// The mass-delete guard's pending confirmation, if an empty listing has
    /// been seen once. See [`crate::store::EmptySighting`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    empty_sighting: Option<EmptySighting>,
    /// The last revision handed to a queued push. See
    /// [`PendingPush::revision`].
    #[serde(default)]
    next_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SidecarEntry {
    /// The `.ics` file name inside the collection.
    file: String,
    etag: String,
}

pub struct VdirStore {
    meta: CalendarMeta,
    /// The sidecar as last read or written by this handle.
    ///
    /// A cache, not the authority: every change re-reads the file under the
    /// collection's lock first (see [`Self::update`]), because the app and
    /// the sync daemon hold handles on the same collection at the same time.
    state: SidecarState,
    /// Which kind of collection this is. Decides the file extension and what
    /// counts as a plausible payload.
    flavor: Flavor,
    /// This handle is inside [`CalDavStore::exclusively`] and already holds
    /// the collection's lock, which is not re-entrant.
    held: bool,
}

impl VdirStore {
    /// Opens the sync state for a collection, creating it if absent.
    ///
    /// A sidecar that fails to parse is treated as absent rather than fatal.
    /// The cost is one full re-sync; the alternative is an app that cannot open
    /// a calendar because a JSON file got truncated.
    pub fn open(meta: CalendarMeta) -> Result<Self> {
        let state = read_sidecar(&meta.path.join(STATE_FILE))?.unwrap_or_default();
        Ok(Self {
            meta,
            flavor: state.flavor,
            state,
            held: false,
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
        self.update(|state, _| {
            state.sole_owner_acknowledged = true;
            Ok(())
        })
    }

    /// Records what discovery learned about this collection.
    ///
    /// Provisioning calls this, which is where the flavour becomes durable:
    /// from here on, opening the collection is enough to know what it holds.
    pub fn set_remote(&mut self, href: &str, read_only: bool) -> Result<()> {
        let flavor = self.flavor;
        self.update(|state, _| {
            state.href = Some(href.to_owned());
            state.read_only = read_only;
            state.flavor = flavor;
            Ok(())
        })
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
        self.queue_put_with_base(href, None)
    }

    /// [`Self::queue_put`], with the pre-edit file contents the caller read
    /// before saving.
    ///
    /// `base` sticks from the **first** enqueue: a second edit before the push
    /// drains replaces the operation but keeps the original base, because that
    /// is still the last text the server acknowledged — the correct third
    /// point for a three-way merge if the server turns out to have changed the
    /// same resource meanwhile. Passing `None` never clears a captured base.
    pub fn queue_put_with_base(&mut self, href: &str, base: Option<&str>) -> Result<()> {
        self.update(|state, flavor| {
            queue_put_into(state, flavor, href, base);
            Ok(())
        })
    }

    /// Queues a server-side delete, capturing the coordinates before the local
    /// file disappears.
    pub fn queue_delete(&mut self, href: &str) -> Result<()> {
        self.update(|state, _| {
            let etag = state.entries.get(href).map(|e| e.etag.clone());
            enqueue_into(
                state,
                PushOp::Delete {
                    href: href.to_owned(),
                    etag,
                },
            );
            Ok(())
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

    /// Take the server's version: the local change is discarded.
    ///
    /// For an edit the server also edited, the remote bytes recorded at
    /// detection time are written to the file and its etag is already
    /// current. For an edit the server deleted, the file is deleted here too.
    /// For a deletion the server refused because it had changed the event,
    /// the event comes back with the server's text. None of the three needs
    /// the network, and the queued push goes with the change it was carrying.
    pub fn resolve_conflict_take_remote(&mut self, href: &str) -> Result<bool> {
        let dir = self.meta.path.clone();
        self.update(|state, flavor| {
            let Some(conflict) = state.conflicts.iter().find(|c| c.href == href).cloned() else {
                return Ok(false);
            };
            match conflict.kind {
                ConflictKind::BothEdited | ConflictKind::DeletedHere => upsert_into(
                    state,
                    flavor,
                    &dir,
                    &RemoteEvent {
                        href: conflict.href.clone(),
                        etag: conflict.remote_etag.clone(),
                        ics: conflict.remote.clone(),
                    },
                )?,
                ConflictKind::DeletedOnServer => {
                    if let Some(entry) = state.entries.remove(href) {
                        let path = dir.join(&entry.file);
                        match std::fs::remove_file(&path) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
            }
            state.pending.retain(|e| e.op.href() != href);
            state.conflicts.retain(|c| c.href != href);
            Ok(true)
        })
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
        let dir = self.meta.path.clone();
        self.update(|state, flavor| {
            let Some(conflict) = state.conflicts.iter().find(|c| c.href == href).cloned() else {
                return Ok(false);
            };

            match conflict.kind {
                ConflictKind::DeletedHere => {
                    // The deletion stands: re-queued against the server's
                    // current etag, so it is accepted this time rather than
                    // refused exactly as the first one was.
                    if let Some(entry) = state.entries.get_mut(href) {
                        entry.etag = conflict.remote_etag.clone();
                    }
                    let etag = Some(conflict.remote_etag.clone()).filter(|e| !e.is_empty());
                    enqueue_into(
                        state,
                        PushOp::Delete {
                            href: href.to_owned(),
                            etag,
                        },
                    );
                    state.conflicts.retain(|c| c.href != href);
                    return Ok(true);
                }
                ConflictKind::DeletedOnServer => {
                    // The server no longer has it, so this is a create again:
                    // no etag, and the PUT carries If-None-Match rather than
                    // an If-Match nothing on the server can satisfy. The file
                    // keeps its name.
                    if let Some(entry) = state.entries.remove(href) {
                        state.entries.insert(
                            href.to_owned(),
                            SidecarEntry {
                                file: entry.file,
                                etag: String::new(),
                            },
                        );
                    }
                }
                ConflictKind::BothEdited => {}
            }

            if let Some(text) = merged {
                let file = file_name_for(state, flavor, &conflict.href);
                let target = dir.join(&file);
                atomic::write(&target, text, None).map_err(|why| {
                    Error::internal(format!("writing {}: {why}", target.display()))
                })?;
                state.entries.insert(
                    conflict.href.clone(),
                    SidecarEntry {
                        file,
                        etag: conflict.remote_etag.clone(),
                    },
                );
            }

            // Re-queueing rather than un-parking: the enqueue reads the etag
            // we now hold, which is the server's, and clears the block in one
            // step.
            queue_put_into(state, flavor, href, None);
            state.conflicts.retain(|c| c.href != href);
            Ok(true)
        })
    }

    fn state_path(&self) -> PathBuf {
        self.meta.path.join(STATE_FILE)
    }

    /// The one way the sidecar changes: under the collection's lock, over a
    /// fresh read of the file, then written back whole and atomically.
    ///
    /// The app queues pushes into the sidecar while a sync pass — in this
    /// process or in the daemon — holds its own handle on the same collection
    /// across minutes of network I/O. Saving from memory, as this store once
    /// did, wrote the pass's stale copy over every push queued meanwhile, and
    /// the edits never reached the server. Re-reading under the lock makes
    /// each change apply to what is on disk now, whoever wrote it last.
    ///
    /// The lock is held for the read-change-write cycle only, never across a
    /// request to the server.
    fn update<T>(
        &mut self,
        change: impl FnOnce(&mut SidecarState, Flavor) -> Result<T>,
    ) -> Result<T> {
        let path = self.state_path();
        let _lock = self.lock()?;
        if let Some(fresh) = read_sidecar(&path)? {
            self.state = fresh;
        }
        let value = change(&mut self.state, self.flavor)?;
        let json = serde_json::to_string_pretty(&self.state)
            .map_err(|why| Error::internal(format!("serialising CalDAV sync state: {why}")))?;
        atomic::write(&path, &json, None)
            .map_err(|why| Error::internal(format!("writing CalDAV sync state: {why}")))?;
        Ok(value)
    }

    /// Re-reads the sidecar, so what this handle answers from — the hrefs,
    /// the etags, what is queued — is what is on disk now rather than what it
    /// was when the handle was opened. Another handle, or another process,
    /// may have queued or synced since.
    pub fn reload(&mut self) -> Result<()> {
        let path = self.state_path();
        let _lock = self.lock()?;
        if let Some(fresh) = read_sidecar(&path)? {
            self.state = fresh;
        }
        Ok(())
    }

    /// The collection's lock — or nothing, inside
    /// [`CalDavStore::exclusively`], where this handle already holds it.
    fn lock(&self) -> Result<Option<atomic::Lock>> {
        if self.held {
            return Ok(None);
        }
        let path = self.state_path();
        atomic::lock(&path)
            .map(Some)
            .map_err(|why| Error::internal(format!("locking {}: {why}", path.display())))
    }
}

/// Reads a sidecar. `None` when there is none yet; an unparseable one is
/// logged and read as none, which costs a full re-sync rather than a
/// collection that cannot be opened.
fn read_sidecar(path: &std::path::Path) -> Result<Option<SidecarState>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(serde_json::from_str(&text).unwrap_or_else(|why| {
            tracing::warn!(
                path = %path.display(), %why,
                "unreadable CalDAV sidecar; treating the collection as unsynced"
            );
            SidecarState::default()
        }))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The file extension resources in a collection of `flavor` use.
fn extension(flavor: Flavor) -> &'static str {
    match flavor {
        Flavor::CalDav => "ics",
        Flavor::CardDav => "vcf",
    }
}

/// The file name to store an href under.
///
/// Reuses the name already recorded for that href so an update overwrites in
/// place rather than accumulating copies. Otherwise it is derived from the
/// href's last segment, which is what every other vdir tool does and keeps
/// the directory legible.
fn file_name_for(state: &SidecarState, flavor: Flavor, href: &str) -> String {
    if let Some(existing) = state.entries.get(href) {
        return existing.file.clone();
    }

    let extension = extension(flavor);
    let stem = href
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or(href)
        .trim_end_matches(&format!(".{extension}"));

    let mut name = format!("{}.{extension}", sanitise_stem(stem));

    // Two distinct hrefs can sanitise to the same name (different collections
    // on the same server, percent-encoding collapsing). Storing both under one
    // file would make each sync overwrite the other, forever.
    if state.entries.values().any(|entry| entry.file == name) {
        let mut n = 2;
        loop {
            let candidate = format!("{}-{n}.{extension}", sanitise_stem(stem));
            if !state.entries.values().any(|entry| entry.file == candidate) {
                name = candidate;
                break;
            }
            n += 1;
        }
    }
    name
}

/// Adds an operation, or resets an existing one for the same href to "due
/// now" with a new revision. See [`PushQueue::enqueue`].
fn enqueue_into(state: &mut SidecarState, op: PushOp) {
    state.next_revision = state.next_revision.saturating_add(1);
    let revision = state.next_revision;
    let href = op.href().to_owned();
    // Replace rather than append: the newest edit is the one that should
    // reach the server, and replaying a stale state on top of a fresh one is
    // worse than not pushing at all.
    if let Some(existing) = state.pending.iter_mut().find(|e| e.op.href() == href) {
        existing.op = op;
        existing.attempts = 0;
        existing.next_attempt_ms = 0;
        existing.last_error = None;
        // A fresh edit supersedes whatever the last one was held up by.
        existing.blocked = false;
        existing.revision = revision;
    } else {
        state.pending.push(PendingPush {
            op,
            attempts: 0,
            next_attempt_ms: 0,
            last_error: None,
            blocked: false,
            base: None,
            revision,
        });
    }
}

/// [`VdirStore::queue_put_with_base`] on a sidecar already under the lock.
fn queue_put_into(state: &mut SidecarState, flavor: Flavor, href: &str, base: Option<&str>) {
    let file = file_name_for(state, flavor, href);
    // An empty etag is a resource the server no longer has — see
    // `ConflictKind::DeletedOnServer` — and a PUT for it is a create.
    let etag = state
        .entries
        .get(href)
        .map(|e| e.etag.clone())
        .filter(|etag| !etag.is_empty());
    let already_pending = state.pending.iter().any(|entry| entry.op.href() == href);
    enqueue_into(
        state,
        PushOp::Put {
            href: href.to_owned(),
            file,
            etag,
        },
    );
    if let Some(base) = base
        && !already_pending
        && let Some(entry) = state
            .pending
            .iter_mut()
            .find(|entry| entry.op.href() == href)
        && entry.base.is_none()
    {
        entry.base = Some(base.to_owned());
    }
}

/// [`CalDavStore::upsert`] on a sidecar already under the lock.
fn upsert_into(
    state: &mut SidecarState,
    flavor: Flavor,
    dir: &std::path::Path,
    event: &RemoteEvent,
) -> Result<()> {
    if !looks_plausible(&event.ics, flavor) {
        return Err(Error::protocol(format!(
            "refusing to store an implausible payload for {} (expected {:?} data)",
            event.href, flavor
        )));
    }

    let file = file_name_for(state, flavor, &event.href);
    let target = dir.join(&file);

    // Read before writing: what the file held a moment ago is what a queued
    // push for this href would have sent, and the two being equal is the one
    // case where that push has nothing left to do.
    let previous = std::fs::read_to_string(&target).ok();

    // Unguarded: the server's copy is authoritative for a resource we are
    // pulling. The caller is responsible for having established that there is
    // no unsent local edit here — see `CalDavStore::unpushed_local` and the
    // conflict path in `crate::sync`, which is what keeps this write from
    // being the one that eats somebody's change.
    atomic::write(&target, &event.ics, None)
        .map_err(|why| Error::internal(format!("writing {}: {why}", target.display())))?;

    state.entries.insert(
        event.href.clone(),
        SidecarEntry {
            file,
            etag: event.etag.clone(),
        },
    );

    // A queued push whose payload is what the server just sent us has nothing
    // left to send. Without this, a push parked on a 412 whose change reached
    // the server by another route (a second client, the same edit made twice)
    // would stay parked forever and the UI would claim unsaved changes that
    // no longer exist.
    if previous.as_deref() == Some(event.ics.as_str()) {
        state
            .pending
            .retain(|entry| !matches!(&entry.op, PushOp::Put { href, .. } if href == &event.href));
    }
    Ok(())
}

/// Makes an href segment safe as a file name.
///
/// Hrefs are server-controlled text and routinely contain `/`, `@`, and
/// percent-escapes; without this a hostile or merely careless server could
/// place a file outside the collection directory.
pub(crate) fn sanitise_stem(raw: &str) -> String {
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
        let dir = self.meta.path.clone();
        self.update(|state, flavor| upsert_into(state, flavor, &dir, event))
    }

    fn remove(&mut self, href: &str) -> Result<()> {
        let dir = self.meta.path.clone();
        self.update(|state, _| {
            if let Some(entry) = state.entries.remove(href) {
                let path = dir.join(&entry.file);
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(())
        })
    }

    fn commit_ctag(&mut self, ctag: Option<&str>) -> Result<()> {
        self.update(|state, _| {
            state.ctag = ctag.map(ToOwned::to_owned);
            Ok(())
        })
    }

    /// The file's current bytes, when a PUT for this href is still queued.
    ///
    /// Read against the sidecar as it is on disk *now*: the edit this exists
    /// to protect is usually one the app queued while this pass was talking
    /// to the server.
    ///
    /// A queued **delete** answers `None` on purpose. Its conflict — we removed
    /// the resource, the server edited it — resolves itself in practice, and
    /// resolves the safe way: writeback drains before the pull, so an
    /// online client sends the DELETE first and the server stops listing the
    /// resource. An offline one lets the pull restore the file, and the DELETE
    /// still goes out when the network returns. A resurrected event that
    /// disappears again on the next sync is a visible annoyance; it is not the
    /// silent loss this method exists to prevent.
    fn unpushed_local(&mut self, href: &str) -> Result<Option<String>> {
        self.reload()?;
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

    fn queued_delete(&mut self, href: &str) -> Result<bool> {
        self.reload()?;
        Ok(self
            .state
            .pending
            .iter()
            .any(|entry| matches!(&entry.op, PushOp::Delete { href: h, .. } if h == href)))
    }

    fn record_conflict(&mut self, conflict: &Conflict) -> Result<()> {
        self.update(|state, _| {
            // The etag moves to the server's current value; the payload does
            // not. Recording the etag is what stops the next cycle re-fetching
            // the same divergence, and it is exactly the If-Match a resolution
            // will need.
            if conflict.kind != ConflictKind::DeletedOnServer
                && let Some(entry) = state.entries.get_mut(&conflict.href)
            {
                entry.etag = conflict.remote_etag.clone();
            }

            // The queued push must stop trying. Its bytes would overwrite the
            // server's change, and with the etag now current it would
            // *succeed* at doing so — silently losing the remote side instead
            // of the local one.
            for entry in &mut state.pending {
                if entry.op.href() == conflict.href {
                    entry.blocked = true;
                    entry.last_error = Some("waiting on a conflict to be resolved".to_owned());
                }
            }

            state.conflicts.retain(|c| c.href != conflict.href);
            state.conflicts.push(conflict.clone());
            Ok(())
        })
    }

    fn unpushed_base(&mut self, href: &str) -> Result<Option<String>> {
        self.reload()?;
        Ok(self
            .state
            .pending
            .iter()
            .find(|entry| matches!(&entry.op, PushOp::Put { href: h, .. } if h == href))
            .and_then(|entry| entry.base.clone()))
    }

    /// Writes the merged text as the local copy, adopts the server's etag, and
    /// re-queues the push so the server converges on the merge too.
    ///
    /// The re-queued entry's base is the server's revision — the last text the
    /// server acknowledged, which is what any *further* divergence would need
    /// to merge against. Set explicitly, because the old entry (whose base
    /// predates both edits) is dropped rather than extended: first-enqueue-wins
    /// must not preserve a base from before a merge that already consumed it.
    fn apply_merged(&mut self, merged: &str, remote: &RemoteEvent) -> Result<()> {
        let dir = self.meta.path.clone();
        self.update(|state, flavor| {
            let file = file_name_for(state, flavor, &remote.href);
            let target = dir.join(&file);
            atomic::write(&target, merged, None)
                .map_err(|why| Error::internal(format!("writing {}: {why}", target.display())))?;
            state.entries.insert(
                remote.href.clone(),
                SidecarEntry {
                    file,
                    etag: remote.etag.clone(),
                },
            );
            state.pending.retain(|entry| entry.op.href() != remote.href);
            queue_put_into(state, flavor, &remote.href, Some(&remote.ics));
            // A conflict recorded for this resource on an earlier pass is
            // settled by the merge; left behind, the UI would keep asking
            // about a disagreement that no longer exists (audit F-20).
            state.conflicts.retain(|c| c.href != remote.href);
            Ok(())
        })
    }

    /// Holds the collection's lock for the whole of `step`: every change to
    /// the sidecar and every file write made through this handle inside it
    /// is one step to the app, the daemon, and any other handle.
    fn exclusively<T>(&mut self, step: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let _lock = self.lock()?;
        let outer = std::mem::replace(&mut self.held, true);
        let result = step(self);
        self.held = outer;
        result
    }

    fn empty_sighting(&self) -> Result<Option<EmptySighting>> {
        Ok(self.state.empty_sighting.clone())
    }

    fn record_empty_sighting(&mut self, ctag: Option<&str>) -> Result<()> {
        self.update(|state, _| {
            state.empty_sighting = Some(EmptySighting {
                ctag: ctag.map(ToOwned::to_owned),
            });
            Ok(())
        })
    }

    fn clear_empty_sighting(&mut self) -> Result<()> {
        if self.state.empty_sighting.is_none() {
            return Ok(());
        }
        self.update(|state, _| {
            state.empty_sighting = None;
            Ok(())
        })
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
    /// What is queued, as it is on disk now — including what another handle
    /// queued since this one was opened.
    fn pending(&mut self) -> Result<Vec<PendingPush>> {
        self.reload()?;
        Ok(self.state.pending.clone())
    }

    fn enqueue(&mut self, op: PushOp) -> Result<()> {
        self.update(|state, _| {
            enqueue_into(state, op);
            Ok(())
        })
    }

    fn resolve(&mut self, pushed: &PendingPush, etag: Option<&str>) -> Result<()> {
        self.update(|state, _| {
            let href = pushed.op.href();
            // What the server now holds, whatever the queue says: the etag
            // it returned is the If-Match any later push of this resource
            // needs — including a newer edit queued while this one was in
            // flight, which would otherwise go out with the old etag and be
            // refused as a conflict with ourselves.
            if let (PushOp::Put { file, .. }, Some(etag)) = (&pushed.op, etag) {
                state.entries.insert(
                    href.to_owned(),
                    SidecarEntry {
                        file: file.clone(),
                        etag: etag.to_owned(),
                    },
                );
                for entry in &mut state.pending {
                    if let PushOp::Put {
                        href: h,
                        etag: queued,
                        ..
                    } = &mut entry.op
                        && h == href
                    {
                        *queued = Some(etag.to_owned());
                    }
                }
            }
            state
                .pending
                .retain(|e| !(e.op.href() == href && e.revision == pushed.revision));
            Ok(())
        })
    }

    fn defer(&mut self, pushed: &PendingPush, error: &str, next_attempt_ms: i64) -> Result<()> {
        self.update(|state, _| {
            if let Some(entry) = same_entry(state, pushed) {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.next_attempt_ms = next_attempt_ms;
                entry.last_error = Some(error.to_owned());
            }
            Ok(())
        })
    }

    fn park(&mut self, pushed: &PendingPush, error: &str) -> Result<()> {
        self.update(|state, _| {
            if let Some(entry) = same_entry(state, pushed) {
                entry.blocked = true;
                entry.last_error = Some(error.to_owned());
            }
            Ok(())
        })
    }

    fn payload(&self, file: &str) -> Option<String> {
        std::fs::read_to_string(self.meta.path.join(file)).ok()
    }

    fn read_only(&self) -> bool {
        self.state.read_only
    }
}

/// The queued entry `pushed` was taken from, if nothing has replaced it
/// since. A newer edit re-queued meanwhile has a new revision, and the
/// outcome of pushing the older one says nothing about it.
fn same_entry<'a>(
    state: &'a mut SidecarState,
    pushed: &PendingPush,
) -> Option<&'a mut PendingPush> {
    state
        .pending
        .iter_mut()
        .find(|e| e.op.href() == pushed.op.href() && e.revision == pushed.revision)
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
    fn a_push_queued_by_another_handle_survives_this_handles_next_save() {
        // The app and the sync daemon each hold a handle on one collection.
        // The daemon's pass opened its handle first and saves at the end of a
        // network-bound pass; an edit the app queued in between used to be
        // written over by the pass's stale copy, and never reached the server.
        let (dir, mut pass) = store();
        let meta = vdir::collections(dir.path()).remove(0);
        let mut app = VdirStore::open(meta.clone()).unwrap();

        app.queue_put("/cal/edited.ics").unwrap();
        pass.commit_ctag(Some("ctag-2")).unwrap();

        let mut reopened = VdirStore::open(meta).unwrap();
        let hrefs: Vec<String> = reopened
            .pending()
            .unwrap()
            .iter()
            .map(|entry| entry.op.href().to_owned())
            .collect();
        assert_eq!(hrefs, ["/cal/edited.ics"], "the app's queued edit was lost");
        assert_eq!(reopened.state().unwrap().ctag.as_deref(), Some("ctag-2"));
    }

    #[test]
    fn settling_a_push_leaves_a_newer_edit_of_the_same_resource_queued() {
        // A drain snapshots the queue, then spends seconds on the network;
        // the user edits the same event again meanwhile. The first push's
        // success must not settle the second edit.
        let (dir, mut drain) = store();
        drain.queue_put("/cal/a.ics").unwrap();
        let pushed = crate::push::entry_for_href(&mut drain, "/cal/a.ics");

        let meta = vdir::collections(dir.path()).remove(0);
        VdirStore::open(meta)
            .unwrap()
            .queue_put("/cal/a.ics")
            .unwrap();

        drain.resolve(&pushed, Some("\"etag-2\"")).unwrap();
        let pending = drain.pending().unwrap();
        assert_eq!(
            pending.len(),
            1,
            "the newer edit was dropped as if it had been pushed"
        );
        assert!(
            matches!(&pending[0].op, PushOp::Put { etag: Some(etag), .. } if etag == "\"etag-2\""),
            "the newer edit would go out with the etag the server has replaced: {:?}",
            pending[0].op
        );
    }

    #[test]
    fn nothing_is_queued_into_a_collection_another_handle_holds() {
        // A pull asks whether an edit is waiting and then writes; those two
        // moves have to be one step to an application queueing an edit, or
        // the edit lands between them and is overwritten.
        use std::sync::atomic::{AtomicBool, Ordering};
        let (dir, mut pull) = store();
        let meta = vdir::collections(dir.path()).remove(0);
        let mut app = VdirStore::open(meta).unwrap();
        let decided = AtomicBool::new(false);
        let (inside, entered) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                pull.exclusively(|pull| {
                    assert_eq!(pull.unpushed_local("/cal/a.ics").unwrap(), None);
                    inside.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    decided.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .unwrap();
            });
            entered.recv().unwrap();
            app.queue_put("/cal/a.ics").unwrap();
            assert!(
                decided.load(Ordering::SeqCst),
                "an edit was queued in the middle of another handle's step"
            );
        });
    }

    #[test]
    fn a_handle_inside_its_own_step_does_not_wait_for_itself() {
        let (_dir, mut store) = store();
        store
            .exclusively(|store| {
                store.queue_put("/cal/a.ics")?;
                store.exclusively(|store| store.queue_put("/cal/b.ics"))?;
                // Still held after the inner step ends.
                store.queue_put("/cal/c.ics")
            })
            .unwrap();
        assert_eq!(store.pending().unwrap().len(), 3);
    }

    #[test]
    fn a_queued_edit_survives_a_reopen() {
        let (dir, mut store) = store();
        store.queue_put("/cal/a.ics").unwrap();

        // This is the whole point of the queue: a process restart between the
        // edit and the network coming back must not lose the edit.
        let meta = vdir::collections(dir.path()).remove(0);
        let mut reopened = VdirStore::open(meta).unwrap();

        let pending = reopened.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].op.href(), "/cal/a.ics");
    }

    #[test]
    fn a_queued_put_points_at_the_file_the_href_maps_to() {
        let (_dir, mut store) = store();
        store.queue_put("/cal/abc.ics").unwrap();

        let PushOp::Put { file, .. } = &store.pending().unwrap()[0].op else {
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

        let PushOp::Delete { etag, .. } = &store.pending().unwrap()[0].op else {
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
        let queued = crate::push::entry_for_href(&mut store, "/cal/a.ics");
        store.resolve(&queued, None).unwrap();

        let meta = vdir::collections(dir.path()).remove(0);
        assert_eq!(VdirStore::open(meta).unwrap().pending().unwrap(), []);
    }

    #[test]
    fn deferring_records_the_error_durably() {
        let (dir, mut store) = store();
        store.queue_put("/cal/a.ics").unwrap();
        let queued = crate::push::entry_for_href(&mut store, "/cal/a.ics");
        store.defer(&queued, "connection refused", 12_345).unwrap();

        let meta = vdir::collections(dir.path()).remove(0);
        let pending = VdirStore::open(meta).unwrap().pending().unwrap();
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

        // The fixture asserts its own setup, because most of what it feeds is
        // tested with a *negative*: "no push survived", "nothing is pending".
        // Such an assertion cannot tell "correctly dropped" from "never
        // queued", so it passes just as well against a fixture that silently
        // did nothing — and would go on passing while the feature rotted.
        // Proving the push exists here makes every emptiness assertion
        // downstream mean what it says.
        assert!(
            !store.pending().unwrap().is_empty(),
            "the fixture queued no push, so nothing below can prove one was dropped"
        );
        assert_eq!(
            store.unpushed_local(HREF).unwrap().as_deref(),
            Some(LOCAL_EDIT),
            "the fixture wrote no local edit"
        );

        (dir, store)
    }

    fn file(store: &VdirStore) -> String {
        std::fs::read_to_string(store.collection().path.join("a.ics")).unwrap()
    }

    fn deleted_on_server(store: &mut VdirStore) {
        store
            .record_conflict(&Conflict {
                href: HREF.into(),
                kind: ConflictKind::DeletedOnServer,
                local: LOCAL_EDIT.into(),
                remote: String::new(),
                remote_etag: String::new(),
                base: None,
            })
            .unwrap();
    }

    #[test]
    fn keeping_an_edit_the_server_deleted_creates_it_again() {
        let (_dir, mut store) = diverged();
        deleted_on_server(&mut store);
        assert!(store.resolve_conflict_keep_local(HREF, None).unwrap());

        assert_eq!(file(&store), LOCAL_EDIT);
        let pending = store.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].blocked);
        assert!(
            matches!(&pending[0].op, PushOp::Put { etag: None, .. }),
            "a re-create must not carry an If-Match nothing can satisfy: {:?}",
            pending[0].op
        );
        assert_eq!(store.conflicts(), []);
    }

    #[test]
    fn accepting_the_servers_deletion_deletes_it_here() {
        let (_dir, mut store) = diverged();
        deleted_on_server(&mut store);
        assert!(store.resolve_conflict_take_remote(HREF).unwrap());

        assert!(!store.collection().path.join("a.ics").exists());
        assert!(store.entry_for(HREF).is_none());
        assert_eq!(store.pending().unwrap(), []);
    }

    #[test]
    fn keeping_a_deletion_the_server_refused_sends_it_against_the_new_etag() {
        let (_dir, mut store) = diverged();
        store.queue_delete(HREF).unwrap();
        std::fs::remove_file(store.collection().path.join("a.ics")).unwrap();
        store
            .record_conflict(&Conflict {
                href: HREF.into(),
                kind: ConflictKind::DeletedHere,
                local: String::new(),
                remote: SERVER_V2.into(),
                remote_etag: "\"v2\"".into(),
                base: None,
            })
            .unwrap();

        assert!(store.resolve_conflict_keep_local(HREF, None).unwrap());
        let pending = store.pending().unwrap();
        assert!(
            matches!(&pending[0].op, PushOp::Delete { etag: Some(etag), .. } if etag == "\"v2\""),
            "{:?}",
            pending[0].op
        );
        assert!(!pending[0].blocked);
        assert!(!store.collection().path.join("a.ics").exists());
    }

    #[test]
    fn an_automatic_merge_settles_a_conflict_recorded_earlier() {
        let (_dir, mut store) = diverged();
        record(&mut store);
        store
            .apply_merged(
                LOCAL_EDIT,
                &RemoteEvent {
                    href: HREF.into(),
                    etag: "\"v3\"".into(),
                    ics: SERVER_V2.into(),
                },
            )
            .unwrap();
        assert!(
            store.conflicts().is_empty(),
            "a conflict the merge settled was still waiting for the user"
        );
    }

    /// Applying what the pull would apply, once it has decided this is a
    /// conflict. Mirrors the branch in `crate::sync`.
    fn record(store: &mut VdirStore) {
        let local = store.unpushed_local(HREF).unwrap().expect("an unsent edit");
        store
            .record_conflict(&Conflict {
                kind: ConflictKind::BothEdited,
                href: HREF.into(),
                local,
                remote: SERVER_V2.into(),
                remote_etag: "\"v2\"".into(),
                base: None,
            })
            .unwrap();
    }

    #[test]
    fn an_unsent_edit_is_visible_to_the_pull_path() {
        let (_dir, mut store) = diverged();
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
        let queued = crate::push::entry_for_href(&mut store, HREF);
        store.resolve(&queued, None).unwrap();
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
            store.pending().unwrap()[0].blocked,
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
            store.pending().unwrap().is_empty(),
            "a push survived the edit it carried"
        );
        assert_eq!(store.conflicts(), []);
    }

    #[test]
    fn keeping_the_local_version_requeues_it_against_the_servers_etag() {
        let (_dir, mut store) = diverged();
        record(&mut store);

        assert!(store.resolve_conflict_keep_local(HREF, None).unwrap());

        assert_eq!(file(&store), LOCAL_EDIT, "the local copy was not kept");
        assert_eq!(store.conflicts(), []);

        let entry = &store.pending().unwrap()[0];
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

        assert_eq!(store.pending().unwrap(), []);
    }
}

#[cfg(test)]
mod base_capture_tests {
    use super::*;
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::vdir;

    const HREF: &str = "/cal/a.ics";
    const V1: &str = "BEGIN:VCALENDAR\r\nX-V:1\r\nEND:VCALENDAR\r\n";
    const EDIT_1: &str = "BEGIN:VCALENDAR\r\nX-V:1-mine\r\nEND:VCALENDAR\r\n";
    const EDIT_2: &str = "BEGIN:VCALENDAR\r\nX-V:2-mine\r\nEND:VCALENDAR\r\n";

    fn synced() -> (tempfile::TempDir, VdirStore) {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        let mut store = VdirStore::open(meta).unwrap();
        store.set_remote("/cal/", false).unwrap();
        store
            .upsert(&RemoteEvent {
                href: HREF.into(),
                etag: "\"v1\"".into(),
                ics: V1.into(),
            })
            .unwrap();
        (dir, store)
    }

    #[test]
    fn the_first_enqueue_captures_the_base_durably() {
        let (dir, mut store) = synced();
        store.queue_put_with_base(HREF, Some(V1)).unwrap();

        assert_eq!(store.unpushed_base(HREF).unwrap().as_deref(), Some(V1));

        // Durable: the base has to survive the process, exactly like the edit.
        let meta = vdir::collections(dir.path()).remove(0);
        let mut reopened = VdirStore::open(meta).unwrap();
        assert_eq!(reopened.unpushed_base(HREF).unwrap().as_deref(), Some(V1));
    }

    #[test]
    fn a_second_edit_keeps_the_first_edits_base() {
        // The server still holds V1; a merge after the second edit must diff
        // against V1, not against the first edit.
        let (_dir, mut store) = synced();
        std::fs::write(store.collection().path.join("a.ics"), EDIT_1).unwrap();
        store.queue_put_with_base(HREF, Some(V1)).unwrap();

        std::fs::write(store.collection().path.join("a.ics"), EDIT_2).unwrap();
        store.queue_put_with_base(HREF, Some(EDIT_1)).unwrap();

        assert_eq!(
            store.unpushed_base(HREF).unwrap().as_deref(),
            Some(V1),
            "the base moved with the second edit; a merge would diff against the wrong text"
        );
    }

    #[test]
    fn a_baseless_enqueue_never_clears_a_captured_base() {
        let (_dir, mut store) = synced();
        store.queue_put_with_base(HREF, Some(V1)).unwrap();
        store.queue_put(HREF).unwrap();

        assert_eq!(store.unpushed_base(HREF).unwrap().as_deref(), Some(V1));
    }

    #[test]
    fn the_base_goes_with_the_entry_when_the_push_succeeds() {
        let (_dir, mut store) = synced();
        store.queue_put_with_base(HREF, Some(V1)).unwrap();
        let queued = crate::push::entry_for_href(&mut store, HREF);
        store.resolve(&queued, None).unwrap();

        assert_eq!(store.unpushed_base(HREF).unwrap(), None);
    }

    #[test]
    fn a_sidecar_written_before_bases_existed_still_parses() {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        std::fs::write(
            meta.path.join(STATE_FILE),
            r#"{"ctag":"x","entries":{},"pending":[{"op":{"kind":"put","href":"/cal/a.ics","file":"a.ics","etag":null}}]}"#,
        )
        .unwrap();

        let mut store = VdirStore::open(meta).expect("an old sidecar must not be fatal");
        assert_eq!(store.pending().unwrap().len(), 1);
        assert_eq!(store.unpushed_base("/cal/a.ics").unwrap(), None);
    }

    #[test]
    fn apply_merged_writes_requeues_and_rebases() {
        const MERGED: &str = "BEGIN:VCALENDAR\r\nX-V:merged\r\nEND:VCALENDAR\r\n";
        const SERVER_V2: &str = "BEGIN:VCALENDAR\r\nX-V:2-theirs\r\nEND:VCALENDAR\r\n";
        let (_dir, mut store) = synced();
        std::fs::write(store.collection().path.join("a.ics"), EDIT_1).unwrap();
        store.queue_put_with_base(HREF, Some(V1)).unwrap();

        store
            .apply_merged(
                MERGED,
                &RemoteEvent {
                    href: HREF.into(),
                    etag: "\"v2\"".into(),
                    ics: SERVER_V2.into(),
                },
            )
            .unwrap();

        let file = std::fs::read_to_string(store.collection().path.join("a.ics")).unwrap();
        assert_eq!(file, MERGED, "the merged text did not reach the file");
        assert_eq!(store.entry_for(HREF).unwrap().1, "\"v2\"");

        let pending = store.pending().unwrap();
        assert_eq!(pending.len(), 1, "the merge was not re-queued for upload");
        let PushOp::Put { etag, .. } = &pending[0].op else {
            panic!("expected a Put");
        };
        assert_eq!(etag.as_deref(), Some("\"v2\""), "the push would 412");
        assert_eq!(
            pending[0].base.as_deref(),
            Some(SERVER_V2),
            "a further divergence would merge against a base from before this merge"
        );
    }
}

#[cfg(test)]
mod empty_sighting_tests {
    use super::*;
    use cosmic_pim_core::model::Rgb;
    use cosmic_pim_core::store::vdir;

    #[test]
    fn a_sighting_round_trips_through_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let meta = vdir::create_collection(dir.path(), "Personal", Rgb(1, 2, 3)).unwrap();
        let mut store = VdirStore::open(meta).unwrap();

        assert_eq!(store.empty_sighting().unwrap(), None);
        store.record_empty_sighting(Some("ctag-9")).unwrap();

        let meta = vdir::collections(dir.path()).remove(0);
        let mut reopened = VdirStore::open(meta).unwrap();
        assert_eq!(
            reopened.empty_sighting().unwrap(),
            Some(EmptySighting {
                ctag: Some("ctag-9".into())
            })
        );

        reopened.clear_empty_sighting().unwrap();
        assert_eq!(reopened.empty_sighting().unwrap(), None);
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

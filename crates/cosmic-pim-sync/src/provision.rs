// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The join between "a calendar on a server" and "a directory on disk".
//!
//! Discovery and the vdir store were written against each other's absence: the
//! protocol layer talks in hrefs, the storage layer talks in collection
//! directories, and nothing connected the two. This is that connection.
//!
//! # The idempotence problem
//!
//! Provisioning runs on every sync, not just the first, because a user can add
//! a calendar on the server at any time. So the interesting question is not
//! "how do I create a collection" but "how do I know I already did".
//!
//! The answer is [`Account::collections`], an href → collection-id map
//! persisted in `accounts.toml`. Matching on *display name* instead would be
//! the obvious shortcut and is wrong twice over: renaming a calendar on the
//! server would orphan its local collection and re-download everything into a
//! new one, and two calendars legitimately sharing a name (a personal and a
//! shared "Work") would collapse into a single directory and interleave their
//! events.
//!
//! The binding is also written into the collection's own sidecar, so a
//! collection remains self-describing even if `accounts.toml` is lost.
//!
//! # Calendars and address books are the same problem
//!
//! CardDAV discovery differs from CalDAV's by a home-set property name and a
//! resourcetype marker, both of which live behind [`Flavor`] inside the
//! client. So this module does not branch on the kind of collection at all: it
//! asks the client what it is, opens the matching store, and provisions into
//! whichever root it was given. An address book is a calendar with a different
//! file extension as far as anything here is concerned.

use std::path::Path;

use cosmic_pim_accounts::Account;
use cosmic_pim_caldav::{CaldavClient, Flavor, VdirStore};
use cosmic_pim_core::model::{CalendarMeta, DEFAULT_CALENDAR_COLOR, Rgb};
use cosmic_pim_core::store::vdir;

use crate::error::Result;

/// One calendar, bound to the collection that mirrors it.
#[derive(Debug, Clone)]
pub struct Provisioned {
    /// The calendar's href on the server.
    pub href: String,
    pub display_name: String,
    /// The vdir collection id (its directory name).
    pub collection_id: String,
    /// True when this run created the collection, rather than finding it.
    pub created: bool,
    /// The server says we may only read this one.
    pub read_only: bool,
    /// Another sync engine's marker file found in the collection, if any.
    ///
    /// The collection is still provisioned and still bound — it is a real
    /// calendar and the user can see it — but syncing it is refused until they
    /// say otherwise, because two engines on one collection diverge silently.
    /// See [`cosmic_pim_caldav::vdir::foreign_sync_marker`].
    pub contested: Option<String>,
    /// Calendar or address book — decides which store opens it, and which
    /// root it lives under.
    pub flavor: Flavor,
}

/// Discovers the account's collections and ensures each has a vdir directory.
///
/// Which kind of collection is decided by the client: a `CaldavClient::new`
/// finds calendars under the calendar root, a [`CaldavClient::carddav`] finds
/// address books under the contacts root. Pass the matching root.
///
/// Returns one entry per collection the server offers. The caller is
/// responsible for persisting the bindings — see [`crate::engine::sync_account`],
/// which does it through `AccountStore::bind_collection`.
pub fn provision_account(
    client: &mut CaldavClient,
    account: &Account,
    root: &Path,
) -> Result<Vec<Provisioned>> {
    client.discover()?;
    let calendars = client.list_calendars()?;

    // Read the collections once: `create_collection` appends, so re-scanning
    // per calendar would be quadratic on an account with many calendars.
    let mut existing = vdir::collections(root);
    let mut out = Vec::with_capacity(calendars.len());

    for calendar in calendars {
        let display_name = calendar
            .display_name
            .clone()
            .map(|n| n.trim().to_owned())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| name_from_href(&calendar.href, client.flavor()));

        // `None` means the server sent no privilege set at all, which older
        // servers commonly do; treat that as editable rather than locking the
        // user out of their own calendar.
        let read_only = calendar.can_edit == Some(false);

        let bound = account
            .collections
            .get(&calendar.href)
            .and_then(|id| existing.iter().find(|c| &c.id == id).cloned());

        // The disconnect case: a collection that was synced once and then
        // marked local-only still carries its binding, and resuming it would
        // push a calendar the user decided was private. The binding is left
        // in place — unmarking reconnects without re-provisioning — but this
        // pass creates nothing, syncs nothing, and says nothing per-cycle.
        if let Some(meta) = &bound
            && cosmic_pim_caldav::is_local_only(&meta.path)
        {
            tracing::debug!(
                collection = meta.id,
                "bound collection is marked local-only; leaving it alone"
            );
            continue;
        }

        let (meta, created) = match bound {
            Some(meta) => (meta, false),
            None => {
                let color = calendar
                    .color
                    .as_deref()
                    .and_then(Rgb::parse)
                    .unwrap_or(DEFAULT_CALENDAR_COLOR);
                let meta = vdir::create_collection(root, &display_name, color)?;
                existing.push(meta.clone());
                (meta, true)
            }
        };

        // Record the server coordinates in the collection itself, so it stays
        // self-describing if accounts.toml is lost or hand-edited.
        let mut store = open_store(client.flavor(), meta.clone())?;
        store.set_remote(&calendar.href, read_only)?;

        let contested = store.foreign_sync_marker();
        if let Some(marker) = &contested {
            tracing::warn!(
                collection = meta.id,
                marker,
                "another sync engine already owns this collection; not syncing it"
            );
        }

        out.push(Provisioned {
            href: calendar.href,
            display_name,
            collection_id: meta.id,
            created,
            read_only,
            contested,
            flavor: client.flavor(),
        });
    }

    Ok(out)
}

/// Opens a collection's sync state with the right file extension and payload
/// check for its kind.
pub(crate) fn open_store(flavor: Flavor, meta: CalendarMeta) -> Result<VdirStore> {
    match flavor {
        Flavor::CalDav => Ok(VdirStore::open(meta)?),
        Flavor::CardDav => Ok(VdirStore::open_carddav(meta)?),
    }
}

/// A readable name for a calendar whose server did not supply one.
///
/// Servers that omit `displayname` are usually the same ones with opaque
/// UUID hrefs, so this is often ugly — but an ugly name the user can rename is
/// better than an empty one, and much better than refusing the calendar.
fn name_from_href(href: &str, flavor: Flavor) -> String {
    let fallback = match flavor {
        Flavor::CalDav => "Calendar",
        Flavor::CardDav => "Contacts",
    };
    href.rsplit('/')
        .find(|segment| !segment.is_empty())
        .filter(|segment| !segment.is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

/// Opens the [`VdirStore`] for a previously provisioned collection.
pub fn open_collection(root: &Path, collection_id: &str) -> Option<CalendarMeta> {
    vdir::collections(root)
        .into_iter()
        .find(|c| c.id == collection_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_derived_from_the_last_href_segment() {
        assert_eq!(
            name_from_href("/dav/calendars/user/work/", Flavor::CalDav),
            "work"
        );
        assert_eq!(
            name_from_href("/dav/calendars/user/work", Flavor::CalDav),
            "work"
        );
    }

    #[test]
    fn an_unusable_href_still_yields_a_name() {
        assert_eq!(name_from_href("/", Flavor::CalDav), "Calendar");
        assert_eq!(name_from_href("", Flavor::CalDav), "Calendar");
    }

    #[test]
    fn an_unnamed_address_book_is_not_called_calendar() {
        assert_eq!(name_from_href("/", Flavor::CardDav), "Contacts");
    }
}

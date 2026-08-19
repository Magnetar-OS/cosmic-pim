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

use std::path::Path;

use cosmic_pim_accounts::Account;
use cosmic_pim_caldav::{CaldavClient, VdirStore};
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
}

/// Discovers the account's calendars and ensures each has a vdir collection.
///
/// Returns one entry per calendar the server offers. The caller is responsible
/// for persisting the bindings — see [`crate::engine::sync_account`], which
/// does it through `AccountStore::bind_collection`.
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
            .unwrap_or_else(|| name_from_href(&calendar.href));

        // `None` means the server sent no privilege set at all, which older
        // servers commonly do; treat that as editable rather than locking the
        // user out of their own calendar.
        let read_only = calendar.can_edit == Some(false);

        let bound = account
            .collections
            .get(&calendar.href)
            .and_then(|id| existing.iter().find(|c| &c.id == id).cloned());

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
        let mut store = VdirStore::open(meta.clone())?;
        store.set_remote(&calendar.href, read_only)?;

        out.push(Provisioned {
            href: calendar.href,
            display_name,
            collection_id: meta.id,
            created,
            read_only,
        });
    }

    Ok(out)
}

/// A readable name for a calendar whose server did not supply one.
///
/// Servers that omit `displayname` are usually the same ones with opaque
/// UUID hrefs, so this is often ugly — but an ugly name the user can rename is
/// better than an empty one, and much better than refusing the calendar.
fn name_from_href(href: &str) -> String {
    href.rsplit('/')
        .find(|segment| !segment.is_empty())
        .filter(|segment| !segment.is_empty())
        .unwrap_or("Calendar")
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
        assert_eq!(name_from_href("/dav/calendars/user/work/"), "work");
        assert_eq!(name_from_href("/dav/calendars/user/work"), "work");
    }

    #[test]
    fn an_unusable_href_still_yields_a_name() {
        assert_eq!(name_from_href("/"), "Calendar");
        assert_eq!(name_from_href(""), "Calendar");
    }
}

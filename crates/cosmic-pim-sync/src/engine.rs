// SPDX-License-Identifier: MPL-2.0

//! One sync pass over every enabled account.
//!
//! # Failure policy
//!
//! Nothing here short-circuits. One unreachable server, one calendar whose
//! PROPFIND 500s, one account with a stale password — none of them may stop the
//! other accounts and calendars from syncing. Every failure is captured in the
//! report rather than propagated, so the caller ends up with a complete picture
//! of what worked and what did not, and the UI can show a per-calendar error
//! instead of a single opaque "sync failed".
//!
//! The one thing that *is* fatal to an account is a missing password, because
//! every subsequent request would fail identically and hammering the server
//! with known-bad credentials is how an account gets rate-limited or locked.

use std::path::Path;

use cosmic_pim_accounts::{Account, AccountStore, AuthMethod};
use cosmic_pim_caldav::push::{DrainOutcome, drain};
use cosmic_pim_caldav::{CaldavClient, Flavor, SyncOutcome, sync_collection};

use crate::error::{Error, Result};
use crate::provision::{Provisioned, open_store, provision_account};

/// What happened to one collection.
#[derive(Debug)]
pub struct CollectionReport {
    pub collection_id: String,
    pub display_name: String,
    pub href: String,
    /// Calendar or address book.
    pub flavor: Flavor,
    /// What the local writeback queue did before the pull ran.
    pub pushed: DrainOutcome,
    pub outcome: Result<SyncOutcome>,
}

impl CollectionReport {
    #[must_use]
    pub fn changed(&self) -> bool {
        matches!(&self.outcome, Ok(o) if o.changed()) || self.pushed.succeeded > 0
    }

    /// Local edits still waiting to reach the server.
    #[must_use]
    pub fn has_unpushed_changes(&self) -> bool {
        self.pushed.deferred > 0 || self.pushed.skipped > 0
    }

    /// Resources the server changed while we were holding an unsent change to
    /// the same ones. Read the records with [`crate::conflicts`].
    #[must_use]
    pub fn conflicts(&self) -> usize {
        match &self.outcome {
            Ok(outcome) => outcome.conflicts,
            Err(_) => 0,
        }
    }

    /// Whether this collection needs a person rather than another sync: a
    /// password to re-enter, write access it does not have, a full account, or
    /// a conflict to decide.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.pushed.needs_attention() || self.conflicts() > 0
    }
}

/// What happened to one account.
#[derive(Debug)]
pub struct AccountReport {
    pub account_id: String,
    pub display_name: String,
    /// Every collection of both kinds, calendars first.
    ///
    /// `Err` means the account failed before any collection was reached —
    /// no password, discovery refused, the host is down.
    pub collections: Result<Vec<CollectionReport>>,
    /// Why address books were not reached, when they were not.
    ///
    /// Separate from `collections` because "this server offers no CardDAV" is
    /// the ordinary case for a calendar-only account and must not present as a
    /// failed sync — while a CardDAV server that *is* there and refused us has
    /// to be visible rather than silently skipped. There is no collection to
    /// hang such an error on, so it hangs here.
    pub contacts_unavailable: Option<String>,
}

impl AccountReport {
    /// Whether anything landed on disk, so the caller can skip a redraw.
    #[must_use]
    pub fn changed(&self) -> bool {
        matches!(&self.collections, Ok(reports) if reports.iter().any(CollectionReport::changed))
    }

    /// A one-line summary for the log and the UI's status area.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.collections {
            Err(why) => format!("{}: {why}", self.display_name),
            Ok(reports) => {
                let fetched: usize = reports
                    .iter()
                    .filter_map(|r| r.outcome.as_ref().ok())
                    .map(|o| o.fetched)
                    .sum();
                let deleted: usize = reports
                    .iter()
                    .filter_map(|r| r.outcome.as_ref().ok())
                    .map(|o| o.deleted)
                    .sum();
                let pushed: usize = reports.iter().map(|r| r.pushed.succeeded).sum();
                let failed = reports.iter().filter(|r| r.outcome.is_err()).count();
                let conflicts: usize = reports.iter().map(CollectionReport::conflicts).sum();
                let blocked: usize = reports
                    .iter()
                    .map(|r| r.pushed.needs_user + r.pushed.needs_reconcile)
                    .sum();

                let mut parts = Vec::new();
                if fetched > 0 {
                    parts.push(format!("{fetched} in"));
                }
                if deleted > 0 {
                    parts.push(format!("{deleted} removed"));
                }
                if pushed > 0 {
                    parts.push(format!("{pushed} out"));
                }
                if failed > 0 {
                    parts.push(format!("{failed} failed"));
                }
                // These are the two the user can act on, so they say so rather
                // than hiding inside a count of things that "did not sync".
                if conflicts > 0 {
                    parts.push(format!("{conflicts} to resolve"));
                }
                if blocked > 0 {
                    parts.push(format!("{blocked} held"));
                }
                if parts.is_empty() {
                    parts.push("up to date".to_owned());
                }
                format!("{}: {}", self.display_name, parts.join(", "))
            }
        }
    }
}

/// Syncs every enabled account, recording new collection bindings as it goes.
///
/// Two roots because the suite keeps two: `$XDG_DATA_HOME/calendars` and
/// `$XDG_DATA_HOME/contacts`. One account can offer both, and a server offering
/// neither is not an error.
pub fn sync_all(
    store: &mut AccountStore,
    calendar_root: &Path,
    contacts_root: &Path,
) -> Vec<AccountReport> {
    // Clone the account list up front: `bind_collection` needs `&mut store`
    // while we are iterating, and the alternative is threading indices through
    // the whole call chain for no benefit.
    let accounts: Vec<Account> = store.enabled().cloned().collect();

    accounts
        .iter()
        .map(|account| sync_one(store, account, calendar_root, contacts_root))
        .collect()
}

fn sync_one(
    store: &mut AccountStore,
    account: &Account,
    calendar_root: &Path,
    contacts_root: &Path,
) -> AccountReport {
    let report = |collections, contacts_unavailable| AccountReport {
        account_id: account.id.clone(),
        display_name: account.display_name.clone(),
        collections,
        contacts_unavailable,
    };

    // Before anything reaches the network: an OAuth account's secret slot holds
    // a refresh token, and every client below sends what it is given as an HTTP
    // Basic password. Attempting it would put that token on the wire, collect a
    // 401, and tell the user their password is wrong.
    if account.auth == AuthMethod::OAuth {
        return report(
            Err(Error::UnsupportedAuth(account.display_name.clone())),
            None,
        );
    }

    let password = match store.password(&account.id) {
        Ok(Some(password)) => password,
        Ok(None) => {
            return report(
                Err(Error::MissingPassword(account.display_name.clone())),
                None,
            );
        }
        Err(why) => return report(Err(why.into()), None),
    };

    let mut client = CaldavClient::new(&account.url, &account.username, &password);

    let calendars = match provision_account(&mut client, account, calendar_root) {
        Ok(provisioned) => provisioned,
        Err(why) => return report(Err(why), None),
    };

    // Address books are discovered with a second client because CardDAV has
    // its own principal and home-set. Failing to find any is not an account
    // failure: plenty of servers offer calendars and no contacts at all, and
    // treating that as a broken account would light up every calendar-only
    // setup with a permanent error.
    let mut carddav = CaldavClient::carddav(&account.url, &account.username, &password);
    let (address_books, contacts_unavailable) =
        match provision_account(&mut carddav, account, contacts_root) {
            Ok(provisioned) => (provisioned, None),
            Err(why) => {
                tracing::info!(
                    account = account.display_name, %why,
                    "no address books reached for this account; syncing calendars only"
                );
                (Vec::new(), Some(why.to_string()))
            }
        };

    // Persist bindings before syncing. If sync then fails, the next run still
    // recognises these collections instead of creating duplicates beside them.
    for entry in calendars.iter().chain(&address_books).filter(|p| p.created) {
        if let Err(why) = store.bind_collection(&account.id, &entry.href, &entry.collection_id) {
            tracing::warn!(
                account = account.display_name, href = entry.href, %why,
                "could not persist a collection binding; the next sync may duplicate it"
            );
        }
    }

    let reports = calendars
        .iter()
        .map(|entry| sync_provisioned(&client, entry, calendar_root))
        .chain(
            address_books
                .iter()
                .map(|entry| sync_provisioned(&carddav, entry, contacts_root)),
        )
        .collect();

    report(Ok(reports), contacts_unavailable)
}

fn sync_provisioned(client: &CaldavClient, entry: &Provisioned, root: &Path) -> CollectionReport {
    let mut pushed = DrainOutcome::default();

    let outcome = (|| {
        // Nothing about a contested collection improves by trying: the marker
        // is in the directory, the other engine is running on its own
        // schedule, and one round of both pushing is enough to start the
        // oscillation. The error carries the reason to the UI, which is where
        // the decision belongs.
        if let Some(marker) = &entry.contested {
            return Err(Error::ForeignSyncOwner {
                collection: entry.display_name.clone(),
                marker: marker.clone(),
            });
        }

        let meta =
            crate::provision::open_collection(root, &entry.collection_id).ok_or_else(|| {
                Error::CalDav(cosmic_pim_caldav::Error::internal(format!(
                    "collection “{}” vanished between provisioning and sync",
                    entry.collection_id
                )))
            })?;

        let mut store = open_store(entry.flavor, meta)?;

        // Push before pulling. Draining afterwards would mean the pull
        // overwrites a local edit with the server's older copy, and the queued
        // push then re-uploads what the pull just clobbered — a write/read
        // ordering bug that presents as edits mysteriously reverting.
        pushed = drain(client, &mut store, chrono_now_ms());

        Ok(sync_collection(client, &entry.href, &mut store)?)
    })();

    CollectionReport {
        collection_id: entry.collection_id.clone(),
        display_name: entry.display_name.clone(),
        href: entry.href.clone(),
        flavor: entry.flavor,
        pushed,
        outcome,
    }
}

/// Wall-clock milliseconds. Isolated so the drain schedule has one source of
/// truth and tests can reason about it.
fn chrono_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Syncs one account, for "test this account" in a settings dialog.
pub fn sync_account(
    store: &mut AccountStore,
    account_id: &str,
    calendar_root: &Path,
    contacts_root: &Path,
) -> Result<AccountReport> {
    let account = store
        .get(account_id)
        .ok_or_else(|| cosmic_pim_accounts::Error::UnknownAccount(account_id.to_owned()))?
        .clone();
    Ok(sync_one(store, &account, calendar_root, contacts_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_pim_accounts::{Account, AccountStore, AuthMethod, SecretStore};

    /// An account store backed by a temp directory and the envelope secret
    /// backend, so a test never touches the developer's real keychain.
    fn store_with(auth: AuthMethod) -> (tempfile::TempDir, AccountStore, String) {
        let dir = tempfile::tempdir().unwrap();
        let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        let mut store = AccountStore::open(&dir.path().join("accounts.toml"), secrets).unwrap();

        let mut account = Account::new("Work", "https://dav.example.com/", "ada@example.com");
        account.auth = auth;
        let id = account.id.clone();
        store.add(account, "s3cret").unwrap();

        (dir, store, id)
    }

    #[test]
    fn an_oauth_account_is_refused_before_anything_reaches_the_network() {
        // The secret slot for an OAuth account holds a refresh token, and every
        // client below sends what it is handed as an HTTP Basic password.
        // Proceeding would put that token on the wire and report the resulting
        // 401 as a wrong password — for a password the user never set.
        let (dir, mut store, id) = store_with(AuthMethod::OAuth);

        let report = sync_account(&mut store, &id, dir.path(), dir.path()).unwrap();

        let Err(Error::UnsupportedAuth(name)) = report.collections else {
            panic!("an OAuth account was attempted with Basic credentials");
        };
        assert_eq!(name, "Work");
    }

    #[test]
    fn a_password_account_gets_as_far_as_the_network() {
        // The same account with the default auth method must *not* be refused
        // here — the guard has to be about OAuth, not about accounts in general.
        // `dav.example.com` does not resolve, so this fails at discovery, which
        // is exactly how far it should get.
        let (dir, mut store, id) = store_with(AuthMethod::Password);

        let report = sync_account(&mut store, &id, dir.path(), dir.path()).unwrap();

        assert!(
            !matches!(report.collections, Err(Error::UnsupportedAuth(_))),
            "a password account was refused as unsupported"
        );
    }
}

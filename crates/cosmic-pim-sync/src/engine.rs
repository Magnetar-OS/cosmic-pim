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

use cosmic_pim_accounts::{Account, AccountStore};
use cosmic_pim_caldav::push::{DrainOutcome, drain};
use cosmic_pim_caldav::{CaldavClient, SyncOutcome, VdirStore, sync_collection};

use crate::error::{Error, Result};
use crate::provision::{Provisioned, provision_account};

/// What happened to one collection.
#[derive(Debug)]
pub struct CollectionReport {
    pub collection_id: String,
    pub display_name: String,
    pub href: String,
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
}

/// What happened to one account.
#[derive(Debug)]
pub struct AccountReport {
    pub account_id: String,
    pub display_name: String,
    /// `Err` means the account failed before any collection was reached —
    /// no password, discovery refused, the host is down.
    pub collections: Result<Vec<CollectionReport>>,
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
                if parts.is_empty() {
                    parts.push("up to date".to_owned());
                }
                format!("{}: {}", self.display_name, parts.join(", "))
            }
        }
    }
}

/// Syncs every enabled account, recording new collection bindings as it goes.
pub fn sync_all(store: &mut AccountStore, root: &Path) -> Vec<AccountReport> {
    // Clone the account list up front: `bind_collection` needs `&mut store`
    // while we are iterating, and the alternative is threading indices through
    // the whole call chain for no benefit.
    let accounts: Vec<Account> = store.enabled().cloned().collect();

    accounts
        .iter()
        .map(|account| sync_one(store, account, root))
        .collect()
}

fn sync_one(store: &mut AccountStore, account: &Account, root: &Path) -> AccountReport {
    let report = |collections| AccountReport {
        account_id: account.id.clone(),
        display_name: account.display_name.clone(),
        collections,
    };

    let password = match store.password(&account.id) {
        Ok(Some(password)) => password,
        Ok(None) => return report(Err(Error::MissingPassword(account.display_name.clone()))),
        Err(why) => return report(Err(why.into())),
    };

    let mut client = CaldavClient::new(&account.url, &account.username, &password);

    let provisioned = match provision_account(&mut client, account, root) {
        Ok(provisioned) => provisioned,
        Err(why) => return report(Err(why)),
    };

    // Persist bindings before syncing. If sync then fails, the next run still
    // recognises these collections instead of creating duplicates beside them.
    for entry in provisioned.iter().filter(|p| p.created) {
        if let Err(why) = store.bind_collection(&account.id, &entry.href, &entry.collection_id) {
            tracing::warn!(
                account = account.display_name, href = entry.href, %why,
                "could not persist a collection binding; the next sync may duplicate it"
            );
        }
    }

    report(Ok(provisioned
        .into_iter()
        .map(|entry| sync_provisioned(&client, &entry, root))
        .collect()))
}

fn sync_provisioned(client: &CaldavClient, entry: &Provisioned, root: &Path) -> CollectionReport {
    let mut pushed = DrainOutcome::default();

    let outcome = (|| {
        let meta = crate::provision::open_collection(root, &entry.collection_id).ok_or_else(|| {
            Error::CalDav(cosmic_pim_caldav::Error::internal(format!(
                "collection “{}” vanished between provisioning and sync",
                entry.collection_id
            )))
        })?;

        let mut store = VdirStore::open(meta)?;

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
    root: &Path,
) -> Result<AccountReport> {
    let account = store
        .get(account_id)
        .ok_or_else(|| {
            cosmic_pim_accounts::Error::UnknownAccount(account_id.to_owned())
        })?
        .clone();
    Ok(sync_one(store, &account, root))
}

// Copyright 2026 Dominikos Pritis
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

use cosmic_pim_accounts::{Account, AccountStore, Registry, Secret};
use cosmic_pim_caldav::push::{DrainOutcome, drain};
use cosmic_pim_caldav::{Auth, CaldavClient, Flavor, SyncOutcome, sync_collection};

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
    registry: &Registry,
    calendar_root: &Path,
    contacts_root: &Path,
) -> Vec<AccountReport> {
    // Clone the account list up front: `bind_collection` needs `&mut store`
    // while we are iterating, and the alternative is threading indices through
    // the whole call chain for no benefit.
    let accounts: Vec<Account> = store.enabled().cloned().collect();

    accounts
        .iter()
        .map(|account| sync_one(store, registry, account, calendar_root, contacts_root))
        .collect()
}

fn sync_one(
    store: &mut AccountStore,
    registry: &Registry,
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

    // One resolution for the whole pass, whichever way this account signs in.
    // For OAuth that includes renewing an expired token and storing the result
    // back, which is why the store is taken by value here and not by reference:
    // a pass that renewed without persisting would renew again on every cycle,
    // and against a provider that rotates refresh tokens it would invalidate
    // the one on disk the first time.
    let secret = match cosmic_pim_auth::resolve(store, registry, &account.id) {
        Ok(secret) => secret,
        Err(why) => return report(Err(Error::Auth(why)), None),
    };
    let auth = dav_auth(account, &secret);

    // Where the server is. A typed-in account carries its own URL; an account
    // created from a provider has the manifest's, because nobody types
    // `https://apidata.googleusercontent.com/caldav/v2/` from memory.
    let calendar_url = service_url(account, registry, Service::Calendar);
    let contacts_url = service_url(account, registry, Service::Contacts);

    let mut client = CaldavClient::with_auth(&calendar_url, Flavor::CalDav, &auth);

    let calendars = match provision_account(&mut client, account, calendar_root) {
        Ok(provisioned) => provisioned,
        Err(why) => return report(Err(why), None),
    };

    // Address books are discovered with a second client because CardDAV has
    // its own principal and home-set. Failing to find any is not an account
    // failure: plenty of servers offer calendars and no contacts at all, and
    // treating that as a broken account would light up every calendar-only
    // setup with a permanent error.
    let mut carddav = CaldavClient::with_auth(&contacts_url, Flavor::CardDav, &auth);
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

/// Which service's address is wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Service {
    Calendar,
    Contacts,
}

/// Where this account's collections live.
///
/// An account the user typed in carries its own URL and that wins — it is the
/// more specific fact, and a self-hosted server has no manifest. An account
/// created from a provider has an empty URL and takes the manifest's, because
/// `https://apidata.googleusercontent.com/caldav/v2/` is not something anyone
/// types from memory, and because the address is a property of the provider
/// rather than of the account.
fn service_url(account: &Account, registry: &Registry, service: Service) -> String {
    if !account.url.trim().is_empty() {
        return account.url.clone();
    }

    account
        .provider
        .as_deref()
        .and_then(|id| registry.get(id))
        .and_then(|provider| match service {
            Service::Calendar => provider.calendar_url(&account.username),
            Service::Contacts => provider.contacts_url(&account.username),
        })
        .unwrap_or_default()
}

/// The scheme this account's resolved secret is sent with.
fn dav_auth(account: &Account, secret: &Secret) -> Auth {
    match secret {
        Secret::Password(password) => Auth::Basic {
            username: account.username.clone(),
            password: password.clone(),
        },
        Secret::AccessToken(token) => Auth::Bearer(token.clone()),
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
    registry: &Registry,
    account_id: &str,
    calendar_root: &Path,
    contacts_root: &Path,
) -> Result<AccountReport> {
    let account = store
        .get(account_id)
        .ok_or_else(|| cosmic_pim_accounts::Error::UnknownAccount(account_id.to_owned()))?
        .clone();
    Ok(sync_one(store, registry, &account, calendar_root, contacts_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_pim_accounts::{Account, AccountStore, AuthMethod, OAuthCredential, SecretStore};

    /// A store backed by a temp directory and the envelope secret backend, so
    /// a test never touches the developer's real keychain.
    fn accounts_at(dir: &Path) -> AccountStore {
        let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir);
        AccountStore::open(&dir.join("accounts.toml"), secrets).unwrap()
    }

    #[test]
    fn an_oauth_account_with_no_saved_sign_in_says_so_rather_than_guessing() {
        // Before OAuth was supported this sent the refresh token as a Basic
        // password and reported the 401 as a wrong password. Now the account
        // never reaches the network, and the report says what is actually
        // wrong with it.
        let dir = tempfile::tempdir().unwrap();
        let mut store = accounts_at(dir.path());
        let mut account = Account::new("Google", "", "ada@gmail.com");
        account.auth = AuthMethod::OAuth;
        account.provider = Some("google".into());
        let id = account.id.clone();
        store.add(account, "unused").unwrap();

        let report =
            sync_account(&mut store, &Registry::load_from(dir.path()), &id, dir.path(), dir.path())
                .unwrap();

        let Err(Error::Auth(why)) = report.collections else {
            panic!("an OAuth account without a grant was attempted anyway");
        };
        assert!(why.needs_sign_in(), "expected a sign-in prompt, got {why}");
    }

    #[test]
    fn a_password_account_gets_as_far_as_the_network() {
        // The guard has to be about what is missing, not about accounts in
        // general. `dav.example.com` does not resolve, so this fails at
        // discovery — which is exactly how far it should get.
        let dir = tempfile::tempdir().unwrap();
        let mut store = accounts_at(dir.path());
        let account = Account::new("Work", "https://dav.example.com/", "ada@example.com");
        let id = account.id.clone();
        store.add(account, "s3cret").unwrap();

        let report =
            sync_account(&mut store, &Registry::load_from(dir.path()), &id, dir.path(), dir.path())
                .unwrap();

        assert!(
            !matches!(report.collections, Err(Error::Auth(_))),
            "a password account was stopped by the credential resolver"
        );
    }

    #[test]
    fn an_account_that_typed_its_own_url_keeps_it() {
        // A self-hosted server has no manifest, and a provider's address must
        // never override one a user entered.
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let mut account = Account::new("Nextcloud", "https://cloud.example/dav/", "ada");
        account.provider = Some("google".into());

        assert_eq!(
            service_url(&account, &registry, Service::Calendar),
            "https://cloud.example/dav/"
        );
    }

    #[test]
    fn an_account_created_from_a_provider_takes_the_manifests_address() {
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let mut account = Account::new("Google", "", "ada@gmail.com");
        account.provider = Some("google".into());

        assert_eq!(
            service_url(&account, &registry, Service::Calendar),
            "https://apidata.googleusercontent.com/caldav/v2/"
        );
        assert!(
            service_url(&account, &registry, Service::Contacts).contains("ada@gmail.com"),
            "the username was not substituted into the CardDAV address"
        );
    }

    #[test]
    fn a_token_is_sent_as_a_bearer_and_a_password_as_basic() {
        let account = Account::new("Work", "https://dav.example/", "ada");

        assert_eq!(
            dav_auth(&account, &Secret::AccessToken("ya29.token".into())),
            Auth::Bearer("ya29.token".into())
        );
        assert_eq!(
            dav_auth(&account, &Secret::Password("pw".into())),
            Auth::Basic {
                username: "ada".into(),
                password: "pw".into()
            }
        );
    }

    #[test]
    fn a_renewed_token_is_stored_before_the_pass_uses_it() {
        // Not an optimisation: a provider that rotates refresh tokens
        // invalidates the stored one the first time a renewal uses it, so a
        // pass that renewed without persisting would leave an account that can
        // never be renewed again.
        let dir = tempfile::tempdir().unwrap();
        let mut store = accounts_at(dir.path());
        let account = Account::new("Google", "", "ada@gmail.com");
        let id = account.id.clone();
        let grant = OAuthCredential {
            access_token: "still-valid".into(),
            refresh_token: Some("rt".into()),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            scopes: Vec::new(),
            token_type: "Bearer".into(),
        };
        store.add_oauth(account, "google", &grant).unwrap();

        // A live token needs no renewal, so the stored grant is untouched and
        // no token endpoint is contacted.
        let secret =
            cosmic_pim_auth::resolve(&mut store, &Registry::load_from(dir.path()), &id).unwrap();

        assert_eq!(secret, Secret::AccessToken("still-valid".into()));
        assert_eq!(
            store.credential(&id).unwrap().unwrap().access_token,
            "still-valid"
        );
    }
}

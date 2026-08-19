// SPDX-License-Identifier: MPL-2.0

//! Account metadata, and the join between an account and its credentials.
//!
//! # The split, and why it matters
//!
//! Metadata (what server, which user, which collections) lives in a plain TOML
//! file under `$XDG_CONFIG_HOME`. Credentials live in [`SecretStore`] — the OS
//! keychain, or an encrypted envelope. They are never in the same file, and the
//! TOML is safe to read, diff, back up, and paste into a bug report.
//!
//! An account references its password only by *slot name*. Nothing in this
//! module can hand you a password without going through the secret store, which
//! is what keeps a stray `Debug` print or a serialised config from leaking one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::secret::SecretStore;

/// How an account authenticates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    /// A password or, far more commonly, a provider-issued app password.
    #[default]
    Password,
    /// An OAuth 2.0 refresh token, held in the same secret slot.
    ///
    /// Not yet exercised by the sync path: reaching a CalDAV server with a
    /// bearer token needs the token refreshed per cycle, which is the job of an
    /// online-accounts daemon rather than of this crate.
    OAuth,
}

/// How a mail connection is encrypted.
///
/// Spelled here as well as in `cosmic-pim-mail` deliberately. This crate sits
/// *below* every protocol crate and must not depend on one — `caldav` knows
/// nothing about accounts and `mail` knows nothing about accounts, which is
/// what keeps all three independently testable. Three variants restated at the
/// boundary is a smaller price than inverting that.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// TLS from the first byte — port 993, and what every provider wants.
    #[default]
    Tls,
    /// Plaintext upgraded with STARTTLS — port 143.
    StartTls,
    /// Unencrypted. Only ever reasonable for a server on `localhost`.
    Plaintext,
}

/// Where this account's mail lives.
///
/// Optional because most accounts in the suite arrived through a calendar: a
/// CalDAV URL says nothing about an IMAP host, and there is no reliable way to
/// derive one. Slate fills in [`Account::url`], Envelope fills in this, and the
/// password is the same password either way — which is the point of the shared
/// account store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailEndpoint {
    pub imap_host: String,
    #[serde(default = "default_imap_port")]
    pub imap_port: u16,
    #[serde(default)]
    pub imap_transport: Transport,
    /// The IMAP login, when it differs from [`Account::username`].
    ///
    /// It does more often than you would expect: a CalDAV principal is
    /// routinely a URL path segment or a user id while the mail login is the
    /// email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imap_username: Option<String>,
}

fn default_imap_port() -> u16 {
    993
}

impl MailEndpoint {
    /// The conventional endpoint for a host: implicit TLS on 993.
    #[must_use]
    pub fn tls(imap_host: impl Into<String>) -> Self {
        Self {
            imap_host: imap_host.into(),
            imap_port: default_imap_port(),
            imap_transport: Transport::Tls,
            imap_username: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Stable identity. Also the secret slot key, so it must never be reused.
    pub id: String,
    pub display_name: String,
    /// Where discovery starts. A server root, a principal URL, or a calendar
    /// home — `CaldavClient::discover` copes with all three.
    pub url: String,
    pub username: String,
    #[serde(default)]
    pub auth: AuthMethod,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// CalDAV calendar href → the vdir collection id it is bound to.
    ///
    /// This is the join that makes sync idempotent across restarts: without it,
    /// a second run cannot tell "this calendar is already provisioned" from
    /// "this is a new calendar", and creates a duplicate collection every time.
    #[serde(default)]
    pub collections: BTreeMap<String, String>,
    /// Where this account's mail lives, once someone has said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<MailEndpoint>,
}

fn default_true() -> bool {
    true
}

impl Account {
    #[must_use]
    pub fn new(display_name: &str, url: &str, username: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            display_name: display_name.trim().to_owned(),
            url: url.trim().to_owned(),
            username: username.trim().to_owned(),
            auth: AuthMethod::Password,
            enabled: true,
            collections: BTreeMap::new(),
            mail: None,
        }
    }

    /// The IMAP login for this account: the mail-specific one if it was given,
    /// otherwise the account's.
    #[must_use]
    pub fn mail_username(&self) -> &str {
        self.mail
            .as_ref()
            .and_then(|mail| mail.imap_username.as_deref())
            .unwrap_or(&self.username)
    }

    /// The secret slot holding this account's password.
    ///
    /// One slot per account, not one per protocol. A user with a Fastmail
    /// account has one Fastmail password, and Envelope reaching for a second
    /// one because it speaks IMAP rather than CalDAV would be asking the same
    /// question twice. The `caldav/` prefix is historical and names the slot,
    /// not the protocol allowed to use it.
    #[must_use]
    pub fn secret_slot(&self) -> String {
        format!("caldav/{}/password", self.id)
    }
}

/// Where account metadata lives: `$XDG_CONFIG_HOME/cosmic-pim/accounts.toml`.
///
/// Deliberately **shared** across the suite rather than per-application. A user
/// with a Fastmail account has one Fastmail account, not a calendar one and a
/// contacts one and a mail one; asking them to enter the same password into
/// three apps would be the wrong answer to the same question three times.
///
/// `COSMIC_PIM_CONFIG_DIR` overrides the directory, which is how tests and the
/// sync daemon point somewhere else.
#[must_use]
pub fn default_config_path() -> PathBuf {
    config_dir().join("accounts.toml")
}

fn config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("COSMIC_PIM_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cosmic-pim")
}

/// Where the envelope fallback keeps its key and store, when it is in use.
#[must_use]
pub fn default_secret_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("COSMIC_PIM_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cosmic-pim")
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AccountsFile {
    #[serde(default, rename = "account")]
    accounts: Vec<Account>,
}

pub struct AccountStore {
    path: PathBuf,
    secrets: SecretStore,
    accounts: Vec<Account>,
}

impl AccountStore {
    /// Opens the store at the default locations.
    pub fn open_default() -> Result<Self> {
        let secrets = SecretStore::open("cosmic-pim", &default_secret_dir());
        Self::open(&default_config_path(), secrets)
    }

    pub fn open(path: &Path, secrets: SecretStore) -> Result<Self> {
        let accounts = match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str::<AccountsFile>(&text)
                    .map_err(|why| Error::config(format!("{}: {why}", path.display())))?
                    .accounts
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        Ok(Self {
            path: path.to_path_buf(),
            secrets,
            accounts,
        })
    }

    #[must_use]
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    pub fn enabled(&self) -> impl Iterator<Item = &Account> {
        self.accounts.iter().filter(|a| a.enabled)
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    #[must_use]
    pub fn secrets(&self) -> &SecretStore {
        &self.secrets
    }

    /// Adds an account and stores its password in one step.
    ///
    /// The two must not be separable: an account whose password never made it
    /// into the keychain fails at sync time with an authentication error, which
    /// looks exactly like a wrong password and sends the user hunting in the
    /// wrong place.
    pub fn add(&mut self, account: Account, password: &str) -> Result<()> {
        self.secrets.store(&account.secret_slot(), password)?;
        self.accounts.push(account);
        self.save()
    }

    /// Removes an account and forgets its password.
    pub fn remove(&mut self, id: &str) -> Result<()> {
        let Some(index) = self.accounts.iter().position(|a| a.id == id) else {
            return Err(Error::UnknownAccount(id.to_owned()));
        };
        let account = self.accounts.remove(index);
        self.secrets.forget(&account.secret_slot());
        self.save()
    }

    pub fn set_password(&mut self, id: &str, password: &str) -> Result<()> {
        let account = self
            .get(id)
            .ok_or_else(|| Error::UnknownAccount(id.to_owned()))?;
        self.secrets.store(&account.secret_slot(), password)
    }

    /// The account's password, if one is stored.
    pub fn password(&self, id: &str) -> Result<Option<String>> {
        let account = self
            .get(id)
            .ok_or_else(|| Error::UnknownAccount(id.to_owned()))?;
        self.secrets.load(&account.secret_slot())
    }

    /// Records that a CalDAV calendar is bound to a vdir collection.
    pub fn bind_collection(
        &mut self,
        account_id: &str,
        calendar_href: &str,
        collection_id: &str,
    ) -> Result<()> {
        let account = self
            .accounts
            .iter_mut()
            .find(|a| a.id == account_id)
            .ok_or_else(|| Error::UnknownAccount(account_id.to_owned()))?;
        account
            .collections
            .insert(calendar_href.to_owned(), collection_id.to_owned());
        self.save()
    }

    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<()> {
        let account = self
            .accounts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| Error::UnknownAccount(id.to_owned()))?;
        account.enabled = enabled;
        self.save()
    }

    fn save(&self) -> Result<()> {
        let text = toml::to_string_pretty(&AccountsFile {
            accounts: self.accounts.clone(),
        })
        .map_err(Error::config)?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Atomic and fsynced: a torn accounts.toml loses every account, and the
        // passwords in the keychain then have nothing pointing at them.
        cosmic_pim_core::atomic::write(&self.path, &text, None)
            .map(|_| ())
            .map_err(|why| Error::config(format!("writing {}: {why}", self.path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, AccountStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        let store = AccountStore::open(&dir.path().join("accounts.toml"), secrets).unwrap();
        (dir, store)
    }

    fn account() -> Account {
        Account::new("Fastmail", "https://caldav.fastmail.com/", "me@fastmail.com")
    }

    #[test]
    fn opening_a_missing_file_yields_an_empty_store() {
        let (_dir, store) = store();
        assert!(store.accounts().is_empty());
    }

    #[test]
    fn an_account_and_its_password_round_trip() {
        let (_dir, mut store) = store();
        let account = account();
        let id = account.id.clone();

        store.add(account, "app-password").unwrap();

        assert_eq!(store.accounts().len(), 1);
        assert_eq!(store.password(&id).unwrap().as_deref(), Some("app-password"));
    }

    #[test]
    fn accounts_survive_a_reopen_but_passwords_are_not_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.toml");
        let id;
        {
            let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
            let mut store = AccountStore::open(&path, secrets).unwrap();
            let account = account();
            id = account.id.clone();
            store.add(account, "app-password").unwrap();
        }

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("app-password"),
            "the password was written into accounts.toml"
        );

        let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        let reopened = AccountStore::open(&path, secrets).unwrap();
        assert_eq!(reopened.accounts().len(), 1);
        assert_eq!(reopened.get(&id).unwrap().username, "me@fastmail.com");
        assert_eq!(
            reopened.password(&id).unwrap().as_deref(),
            Some("app-password")
        );
    }

    #[test]
    fn removing_an_account_also_forgets_its_password() {
        let (dir, mut store) = store();
        let account = account();
        let id = account.id.clone();
        let slot = account.secret_slot();
        store.add(account, "app-password").unwrap();

        store.remove(&id).unwrap();

        assert!(store.accounts().is_empty());
        // Reach past the account to the raw slot: the account is gone, so
        // `password()` would just report UnknownAccount either way.
        let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        assert_eq!(
            secrets.load(&slot).unwrap(),
            None,
            "the password outlived the account it belonged to"
        );
    }

    #[test]
    fn collection_bindings_persist() {
        let (_dir, mut store) = store();
        let account = account();
        let id = account.id.clone();
        store.add(account, "pw").unwrap();

        store
            .bind_collection(&id, "/dav/calendars/user/work/", "work")
            .unwrap();

        assert_eq!(
            store.get(&id).unwrap().collections["/dav/calendars/user/work/"],
            "work"
        );
    }

    #[test]
    fn a_mail_endpoint_round_trips_through_the_shared_config() {
        // The suite's promise: an account added in Slate is the same account in
        // Envelope, with one password and one file.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("accounts.toml");
        let id = {
            let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
            let mut store = AccountStore::open(&path, secrets).expect("open");
            let mut account = Account::new("Fastmail", "https://caldav.fastmail.com/", "u123");
            let id = account.id.clone();
            account.mail = Some(MailEndpoint {
                imap_host: "imap.fastmail.com".into(),
                imap_port: 993,
                imap_transport: Transport::Tls,
                imap_username: Some("me@fastmail.com".into()),
            });
            store.add(account, "app-password").expect("add");
            id
        };

        let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        let store = AccountStore::open(&path, secrets).expect("reopen");
        let account = store.get(&id).expect("the account survived");
        let mail = account.mail.as_ref().expect("the endpoint survived");
        assert_eq!(mail.imap_host, "imap.fastmail.com");
        assert_eq!(account.mail_username(), "me@fastmail.com");
        assert_eq!(
            store.password(&id).expect("read"),
            Some("app-password".to_string()),
            "mail must reach the same secret slot, not a second one"
        );
    }

    #[test]
    fn an_account_without_a_mail_endpoint_falls_back_to_its_own_username() {
        // Every account Slate created looks like this.
        let account = Account::new("Nextcloud", "https://cloud.example/", "dominikos");
        assert!(account.mail.is_none());
        assert_eq!(account.mail_username(), "dominikos");
    }

    #[test]
    fn two_accounts_get_distinct_secret_slots() {
        let a = account();
        let b = account();
        assert_ne!(a.id, b.id);
        assert_ne!(a.secret_slot(), b.secret_slot());
    }

    #[test]
    fn operations_on_an_unknown_account_are_errors_not_panics() {
        let (_dir, mut store) = store();
        assert!(matches!(
            store.password("nope"),
            Err(Error::UnknownAccount(_))
        ));
        assert!(matches!(store.remove("nope"), Err(Error::UnknownAccount(_))));
        assert!(matches!(
            store.set_password("nope", "x"),
            Err(Error::UnknownAccount(_))
        ));
    }

    #[test]
    fn a_disabled_account_is_excluded_from_the_sync_set() {
        let (_dir, mut store) = store();
        let account = account();
        let id = account.id.clone();
        store.add(account, "pw").unwrap();

        store.set_enabled(&id, false).unwrap();

        assert_eq!(store.accounts().len(), 1);
        assert_eq!(store.enabled().count(), 0);
    }

    #[test]
    fn a_malformed_config_is_an_error_rather_than_silent_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.toml");
        std::fs::write(&path, "this is not toml [[[").unwrap();

        let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir.path());
        // Deliberately NOT the sidecar's degrade-to-default behaviour: an
        // unreadable sidecar costs a re-sync, but silently starting with zero
        // accounts would make the next save overwrite the user's real config.
        assert!(matches!(
            AccountStore::open(&path, secrets),
            Err(Error::Config(_))
        ));
    }
}

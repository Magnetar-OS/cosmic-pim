// Copyright 2026 Dominikos Pritis
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

use crate::credential::OAuthCredential;
use crate::error::{Error, Result};
use crate::secret::SecretStore;

/// How an account authenticates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    /// A password or, far more commonly, a provider-issued app password.
    #[default]
    Password,
    /// An OAuth 2.0 grant, held in [`Account::credential_slot`] as a whole
    /// [`crate::OAuthCredential`] rather than as a bare token.
    ///
    /// The account's [`Account::provider`] names the manifest that says how to
    /// renew it. Resolving a grant to the token of the moment is
    /// `cosmic_pim_auth::resolve`; nothing below that layer sees a refresh.
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
    /// Which protocol to read this account's mail with.
    ///
    /// A property of the endpoint rather than something probed per pass: a
    /// provider that offers both IMAP and JMAP has a better answer than a
    /// capability check does, and a user who wants the other one has said so
    /// once rather than fighting a heuristic every cycle.
    #[serde(default)]
    pub protocol: crate::provider::MailProtocol,

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

    /// The submission server. Empty means "the same host as IMAP", which is
    /// right for nearly every provider — `imap.` and `smtp.` on one domain, or
    /// the same hostname for both.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_transport: Transport,

    /// The address mail is sent *from*, and the name to put on it.
    ///
    /// Separate from the login because they are separate things: the login is
    /// often a user id, and a provider with aliases lets one login send as
    /// several addresses. Empty falls back to the IMAP username when that looks
    /// like an address, which covers the common case without asking.
    /// The JMAP session resource, for [`crate::provider::MailProtocol::Jmap`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jmap_session_url: Option<String>,

    /// The POP3 server, for [`crate::provider::MailProtocol::Pop3`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pop3_host: String,
    #[serde(default = "default_pop3_port")]
    pub pop3_port: u16,
    #[serde(default)]
    pub pop3_transport: Transport,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from_address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from_name: String,

    /// Additional addresses this account may send as.
    ///
    /// The provider has to be configured to accept them — an alias here that
    /// the server does not know is a message the server will refuse or, worse,
    /// rewrite. The client's job is to offer the choice and put the right
    /// name on it; it cannot make an address deliverable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<Alias>,
}

/// One additional From identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alias {
    /// The display name for this identity. Empty means "the account's own".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub address: String,
}

fn default_smtp_port() -> u16 {
    465
}

fn default_imap_port() -> u16 {
    993
}

fn default_pop3_port() -> u16 {
    995
}

impl MailEndpoint {
    /// The conventional endpoint for a host: implicit TLS on 993 and 465.
    #[must_use]
    pub fn tls(imap_host: impl Into<String>) -> Self {
        Self {
            protocol: crate::provider::MailProtocol::Imap,
            imap_host: imap_host.into(),
            imap_port: default_imap_port(),
            imap_transport: Transport::Tls,
            imap_username: None,
            smtp_host: String::new(),
            smtp_port: default_smtp_port(),
            smtp_transport: Transport::Tls,
            jmap_session_url: None,
            pop3_host: String::new(),
            pop3_port: default_pop3_port(),
            pop3_transport: Transport::Tls,
            from_address: String::new(),
            from_name: String::new(),
            aliases: Vec::new(),
        }
    }

    /// The submission host: the one given, else the IMAP host.
    #[must_use]
    pub fn submission_host(&self) -> &str {
        if self.smtp_host.trim().is_empty() {
            &self.imap_host
        } else {
            &self.smtp_host
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
    /// The provider manifest this account came from, if it came from one.
    ///
    /// Required for [`AuthMethod::OAuth`] — it is where the token endpoint and
    /// the client id live, and a grant cannot be renewed without them. Optional
    /// otherwise: an account typed in by hand has a URL and a password and
    /// needs no manifest at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
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
            provider: None,
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

    /// The address this account sends from, and the name to put on it.
    ///
    /// Falls back to the mail login when it looks like an address, which is the
    /// overwhelmingly common case and saves asking a question whose answer is
    /// already on screen. Returns `None` when there is nothing that could
    /// plausibly be an address — a composer with no From is a composer that
    /// cannot send, and saying so is better than sending as a user id.
    #[must_use]
    pub fn from_identity(&self) -> Option<(String, String)> {
        let mail = self.mail.as_ref();
        let address = mail
            .map(|m| m.from_address.trim())
            .filter(|a| !a.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| {
                let login = self.mail_username();
                login.contains('@').then(|| login.to_owned())
            })?;
        let name = mail
            .map(|m| m.from_name.trim())
            .filter(|n| !n.is_empty())
            .map_or_else(|| self.display_name.clone(), ToOwned::to_owned);
        Some((name, address))
    }

    /// Every identity mail may go out as: the primary first, then the
    /// aliases, each `(name, address)`.
    ///
    /// Duplicates of the primary are dropped rather than listed twice, and an
    /// alias with no name of its own borrows the primary's — a From line with
    /// a bare address where every other message carries a name reads like a
    /// different sender.
    #[must_use]
    pub fn identities(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = self.from_identity().into_iter().collect();
        let primary_name = out
            .first()
            .map(|(name, _)| name.clone())
            .unwrap_or_default();
        if let Some(mail) = self.mail.as_ref() {
            for alias in &mail.aliases {
                let address = alias.address.trim();
                if address.is_empty() || out.iter().any(|(_, a)| a.eq_ignore_ascii_case(address)) {
                    continue;
                }
                let name = Some(alias.name.trim())
                    .filter(|n| !n.is_empty())
                    .map_or_else(|| primary_name.clone(), ToOwned::to_owned);
                out.push((name, address.to_owned()));
            }
        }
        out
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

    /// The secret slot holding this account's OAuth grant.
    ///
    /// Separate from [`Self::secret_slot`] rather than reusing it: the two hold
    /// different shapes (a password, versus JSON), and an account that is
    /// migrated from one mechanism to the other must not leave a value behind
    /// that the other reader would try to parse.
    #[must_use]
    pub fn credential_slot(&self) -> String {
        format!("oauth/{}/credential", self.id)
    }

    /// Whether this account signs in with OAuth.
    #[must_use]
    pub fn is_oauth(&self) -> bool {
        self.auth == AuthMethod::OAuth
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

pub(crate) fn config_dir() -> PathBuf {
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
        // Both slots: an account that was migrated between mechanisms has a
        // value in each, and leaving either behind means a removed account's
        // credentials outlive it in the keychain.
        self.secrets.forget(&account.credential_slot());
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

    /// Adds an OAuth account and stores the grant it was created with.
    ///
    /// The counterpart of [`Self::add`], and inseparable for the same reason:
    /// an account whose grant never reached the keychain fails at sync time
    /// looking exactly like a revoked authorisation.
    pub fn add_oauth(
        &mut self,
        mut account: Account,
        provider_id: &str,
        credential: &OAuthCredential,
    ) -> Result<()> {
        account.auth = AuthMethod::OAuth;
        account.provider = Some(provider_id.to_owned());
        self.store_credential_for(&account, credential)?;
        self.accounts.push(account);
        self.save()
    }

    /// Replaces an account's OAuth grant — after a refresh, or a re-sign-in.
    pub fn set_credential(&mut self, id: &str, credential: &OAuthCredential) -> Result<()> {
        let account = self
            .get(id)
            .ok_or_else(|| Error::UnknownAccount(id.to_owned()))?
            .clone();
        self.store_credential_for(&account, credential)
    }

    /// The account's OAuth grant, if one is stored.
    ///
    /// A slot holding something that is not a grant is reported as an error
    /// rather than as an absent credential: "you are signed out" and "your
    /// keychain entry is corrupt" need different answers from the user, and
    /// silently re-running a sign-in flow over a decryption failure would hide
    /// a real fault.
    pub fn credential(&self, id: &str) -> Result<Option<OAuthCredential>> {
        let account = self
            .get(id)
            .ok_or_else(|| Error::UnknownAccount(id.to_owned()))?;
        let Some(json) = self.secrets.load(&account.credential_slot())? else {
            return Ok(None);
        };
        serde_json::from_str(&json).map(Some).map_err(|why| {
            Error::config(format!(
                "stored OAuth grant for “{id}” is unreadable: {why}"
            ))
        })
    }

    fn store_credential_for(&self, account: &Account, credential: &OAuthCredential) -> Result<()> {
        let json = serde_json::to_string(credential)
            .map_err(|why| Error::config(format!("serialising an OAuth grant: {why}")))?;
        self.secrets.store(&account.credential_slot(), &json)
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

    /// Records where this account's mail lives, or clears it.
    ///
    /// A separate call from [`Self::add`] because the two facts arrive from
    /// different applications at different times: Slate creates the account
    /// with a CalDAV URL, and Envelope fills this in later. Neither should have
    /// to know the other's fields to write its own.
    pub fn set_mail_endpoint(&mut self, id: &str, mail: Option<MailEndpoint>) -> Result<()> {
        let account = self
            .accounts
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| Error::UnknownAccount(id.to_owned()))?;
        account.mail = mail;
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
        Account::new(
            "Fastmail",
            "https://caldav.fastmail.com/",
            "me@fastmail.com",
        )
    }

    #[test]
    fn identities_lead_with_the_primary_and_fill_in_missing_alias_names() {
        let mut account = account();
        let mut mail = MailEndpoint::tls("imap.fastmail.com");
        mail.from_address = "me@fastmail.com".into();
        mail.from_name = "Ada".into();
        mail.aliases = vec![
            Alias {
                name: String::new(),
                address: "sales@example.com".into(),
            },
            Alias {
                name: "Support".into(),
                address: "help@example.com".into(),
            },
            // A duplicate of the primary must not be listed twice.
            Alias {
                name: "Me again".into(),
                address: "ME@fastmail.com".into(),
            },
        ];
        account.mail = Some(mail);

        let identities = account.identities();
        assert_eq!(
            identities,
            vec![
                ("Ada".to_owned(), "me@fastmail.com".to_owned()),
                ("Ada".to_owned(), "sales@example.com".to_owned()),
                ("Support".to_owned(), "help@example.com".to_owned()),
            ]
        );
    }

    #[test]
    fn an_account_without_aliases_has_exactly_its_primary_identity() {
        let mut account = account();
        let mut mail = MailEndpoint::tls("imap.fastmail.com");
        mail.from_address = "me@fastmail.com".into();
        account.mail = Some(mail);
        assert_eq!(account.identities().len(), 1);
    }

    #[test]
    fn an_endpoint_written_before_aliases_existed_still_loads() {
        let toml = r#"
            protocol = "imap"
            imap_host = "imap.example.com"
        "#;
        let endpoint: MailEndpoint = toml::from_str(toml).expect("an old endpoint must load");
        assert!(endpoint.aliases.is_empty());
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
        assert_eq!(
            store.password(&id).unwrap().as_deref(),
            Some("app-password")
        );
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
                imap_username: Some("me@fastmail.com".into()),
                ..MailEndpoint::tls("imap.fastmail.com")
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
            mail.submission_host(),
            "imap.fastmail.com",
            "an unset submission host must fall back rather than be empty"
        );
        assert_eq!(
            account.from_identity(),
            Some(("Fastmail".to_string(), "me@fastmail.com".to_string())),
            "the login is already an address; asking for it again is a question \
             whose answer is on screen"
        );
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
        assert_eq!(
            account.from_identity(),
            None,
            "a user id is not an address, and sending as one would be worse \
             than saying the From is not set"
        );
    }

    #[test]
    fn an_explicit_from_identity_beats_the_login() {
        // A provider with aliases: one login, several addresses it may send as.
        let mut account = Account::new("Work", "https://dav.example/", "u-4213");
        account.mail = Some(MailEndpoint {
            from_address: "dominikos@example.com".into(),
            from_name: "Dominikos Pritis".into(),
            smtp_host: "smtp.example.com".into(),
            ..MailEndpoint::tls("imap.example.com")
        });
        assert_eq!(
            account.from_identity(),
            Some((
                "Dominikos Pritis".to_string(),
                "dominikos@example.com".to_string()
            ))
        );
        assert_eq!(
            account.mail.as_ref().unwrap().submission_host(),
            "smtp.example.com"
        );
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
        assert!(matches!(
            store.remove("nope"),
            Err(Error::UnknownAccount(_))
        ));
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

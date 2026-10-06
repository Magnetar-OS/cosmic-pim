// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Providers: what a named service offers, and how to sign in to it.
//!
//! # Why this is data and not code
//!
//! Every OAuth provider differs in four boring ways — two URLs, a scope list,
//! and a handful of query parameters — and in no interesting ones. Encoding
//! that as a `match` on an enum means a new provider is a code change, a
//! release, and a rebuild for every application in the suite. Encoding it as a
//! manifest means a new provider is a file.
//!
//! The same shape covers the *non*-OAuth half. Fastmail, Migadu, Mailbox.org
//! and a self-hosted Nextcloud all have well-known CalDAV, CardDAV, IMAP and
//! SMTP endpoints that a user should not have to type; a manifest with no
//! `[oauth]` section says exactly that. So the registry answers both questions
//! an account-creation dialog has — "how do I sign in" and "where is the
//! server" — for providers with an OAuth flow and providers with an app
//! password alike.
//!
//! # Client credentials are deployment configuration, not code
//!
//! An OAuth client id identifies *the application asking*, and Google and
//! Microsoft issue them per registered application to a named owner who accepts
//! their terms. There is no id this project could ship that would be correct
//! for a downstream package, so the built-in manifests carry none, and a
//! provider without one is reported as unconfigured rather than half-working.
//!
//! A packager supplies them by shipping a file in a system directory:
//!
//! ```toml
//! # /usr/share/cosmic-pim/providers/google.toml
//! id = "google"
//!
//! [oauth]
//! client_id = "…apps.googleusercontent.com"
//! client_secret = "…"          # omitted for a public client using PKCE
//! ```
//!
//! # Where manifests are read from
//!
//! Lowest precedence first, each layer overlaying the one before it field by
//! field:
//!
//! 1. the built-ins compiled into this crate;
//! 2. `cosmic-pim/providers/` under each `$XDG_DATA_DIRS` entry — what a
//!    distribution's package installs, `/usr/share` by default;
//! 3. `/etc/cosmic-pim/providers/` — what an administrator sets for a site;
//! 4. `$XDG_CONFIG_HOME/cosmic-pim/providers/` — what one user sets.
//!
//! So a distribution's client id, a company's tenant-locked Microsoft
//! endpoints and a user's own experiment are the same mechanism at three
//! scopes, and none of them is a patch. See [`provider_dirs`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::account::{MailEndpoint, Transport};
use crate::error::{Error, Result};

/// Manifests compiled in, so the common providers work with no packaging step.
const BUILT_IN: &[(&str, &str)] = &[
    ("google", include_str!("../providers/google.toml")),
    ("microsoft", include_str!("../providers/microsoft.toml")),
    ("fastmail", include_str!("../providers/fastmail.toml")),
    ("icloud", include_str!("../providers/icloud.toml")),
    ("yahoo", include_str!("../providers/yahoo.toml")),
    ("aol", include_str!("../providers/aol.toml")),
    ("proton", include_str!("../providers/proton.toml")),
    ("mailbox-org", include_str!("../providers/mailbox-org.toml")),
    ("posteo", include_str!("../providers/posteo.toml")),
    ("gmx", include_str!("../providers/gmx.toml")),
];

/// One provider, as declared by a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub name: String,
    /// How an account with this provider signs in. Absent means a password —
    /// which for most providers means an app password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuth>,
    /// Where each service lives. Absent entries are services the provider does
    /// not offer, or offers over a protocol this suite does not speak.
    #[serde(default)]
    pub services: Services,
    /// A note the sign-in dialog should show — "create an app password first",
    /// most often. Providers whose failure mode is a confused user are worth
    /// the two lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// The page [`Self::hint`] is about — where an app password is created,
    /// most often — so a dialog can offer to open it rather than describe
    /// where it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_url: Option<String>,
    /// The mail domains that are this provider's own, lowercase — `gmail.com`
    /// for Google. How [`Registry::for_email`] recognises an address.
    ///
    /// Only domains the provider itself hands out: a company with Google
    /// Workspace on its own domain is not listed here and cannot be, and
    /// falls through to autodiscovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// The password route of a provider whose own route is the browser.
    ///
    /// Google still takes an app password over IMAP and SMTP; Microsoft takes
    /// none. Where one exists it is what makes the provider usable on an
    /// installation with no client id for it, so the manifest says so rather
    /// than the code guessing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_password: Option<AppPassword>,
}

/// The four things an OAuth provider differs by.
///
/// `Debug` is written by hand, to leave the client secret out: a provider
/// is exactly the kind of value that ends up in a log line.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuth {
    /// Issued to a registered application. See the module docs for why this is
    /// not shipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Absent for a public client, which is what a desktop application is:
    /// a secret shipped in a package is not a secret, and PKCE is what
    /// replaces it. Microsoft accepts this; Google issues one anyway and
    /// checks it, so it is optional rather than forbidden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub auth_url: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    /// Extra authorize-URL parameters. Google needs `access_type=offline` or it
    /// issues no refresh token at all and the account silently stops working an
    /// hour later; kept generic so that stays a manifest fact.
    #[serde(default)]
    pub extra_params: BTreeMap<String, String>,
    /// The loopback port the redirect comes back on. Fixed per provider because
    /// the redirect URI has to be registered with them in advance.
    #[serde(default = "default_redirect_port")]
    pub redirect_port: u16,
}

fn default_redirect_port() -> u16 {
    49_173
}

impl std::fmt::Debug for OAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("scopes", &self.scopes)
            .field("extra_params", &self.extra_params)
            .field("redirect_port", &self.redirect_port)
            .finish()
    }
}

impl OAuth {
    /// The registered redirect URI: loopback, on the port the manifest names.
    ///
    /// `127.0.0.1` rather than `localhost`: RFC 8252 §8.3 requires the literal
    /// address, because `localhost` can resolve to an interface another process
    /// on the machine is listening on.
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.redirect_port)
    }

    /// Whether a client id has been configured for this provider.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.client_id
            .as_ref()
            .is_some_and(|id| !id.trim().is_empty())
    }
}

/// What to tell someone signing in to an OAuth provider with an app password
/// instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AppPassword {
    /// How to get one, and what it does not cover.
    pub hint: String,
    /// Where one is created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help_url: Option<String>,
}

/// Where a provider's services live.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Services {
    /// CalDAV root, principal, or calendar home. `{username}` is substituted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar: Option<String>,
    /// CardDAV root. `{username}` is substituted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contacts: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<MailService>,
}

/// A provider's mail endpoints, before an account personalises them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailService {
    /// `imap`, or `jmap` for a provider that offers it.
    #[serde(default)]
    pub protocol: MailProtocol,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub imap_host: String,
    #[serde(default = "default_imap_port")]
    pub imap_port: u16,
    #[serde(default)]
    pub imap_transport: Transport,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_transport: Transport,
    /// The JMAP session resource, for a provider that offers JMAP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jmap_session_url: Option<String>,
    /// POP3, for the providers where it is the only thing on offer.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pop3_host: String,
    #[serde(default = "default_pop3_port")]
    pub pop3_port: u16,
    #[serde(default)]
    pub pop3_transport: Transport,
}

fn default_imap_port() -> u16 {
    993
}

fn default_smtp_port() -> u16 {
    465
}

fn default_pop3_port() -> u16 {
    995
}

/// Which protocol a provider's mail is reached over.
///
/// Not a capability list: this is the one the suite should *use*, chosen by the
/// manifest because the provider knows better than a probe does. Fastmail
/// offers IMAP and JMAP; JMAP is the better answer there and saying so is a
/// one-word manifest edit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MailProtocol {
    #[default]
    Imap,
    Jmap,
    /// Download-and-forget. No folders, no server-side flags — see
    /// `cosmic_pim_mail::pop3` for what that costs.
    Pop3,
    /// The Gmail API. Chosen over IMAP for a Google account because IMAP
    /// cannot express an archive — Gmail has no Archive folder, only the
    /// removal of the INBOX label — so a change made on a phone stays
    /// invisible until a full reconcile.
    Gmail,
    /// Microsoft Graph. Chosen over IMAP for a Microsoft account because
    /// tenants increasingly have IMAP switched off, and because Graph's delta
    /// queries are what IMAP's CONDSTORE would be if Exchange implemented it
    /// consistently.
    Graph,
}

impl MailService {
    /// This provider's endpoints, filled in for one account.
    #[must_use]
    pub fn endpoint_for(&self, username: &str) -> MailEndpoint {
        MailEndpoint {
            protocol: self.protocol,
            imap_host: self.imap_host.clone(),
            imap_port: self.imap_port,
            imap_transport: self.imap_transport,
            imap_username: Some(username.to_owned()),
            smtp_host: self.smtp_host.clone(),
            smtp_port: self.smtp_port,
            smtp_transport: self.smtp_transport,
            jmap_session_url: self.jmap_session_url.clone(),
            pop3_host: self.pop3_host.clone(),
            pop3_port: self.pop3_port,
            pop3_transport: self.pop3_transport,
            from_address: username.to_owned(),
            from_name: String::new(),
            aliases: Vec::new(),
        }
    }
}

impl Provider {
    /// The CalDAV URL for one account, `{username}` substituted.
    #[must_use]
    pub fn calendar_url(&self, username: &str) -> Option<String> {
        self.services
            .calendar
            .as_deref()
            .map(|url| substitute(url, username))
    }

    /// The CardDAV URL for one account, `{username}` substituted.
    #[must_use]
    pub fn contacts_url(&self, username: &str) -> Option<String> {
        self.services
            .contacts
            .as_deref()
            .map(|url| substitute(url, username))
    }
}

/// Percent-encodes nothing: a username lands in a path segment, and the one
/// character that matters there is `/`, which no provider allows in a login.
fn substitute(template: &str, username: &str) -> String {
    template.replace("{username}", username)
}

impl Provider {
    /// A ready-to-store account for this provider.
    ///
    /// Names the provider and fills in the mail endpoints, so that adding an
    /// account is one question — who are you — rather than the eight-field
    /// dialog that asks a user for an IMAP hostname they have never heard of.
    /// What it does *not* do is store anything: the caller pairs this with the
    /// credential and hands both to [`crate::AccountStore`], which keeps "an
    /// account exists" and "its secret is saved" from ever being separable.
    ///
    /// The account's own `url` is left empty on purpose. It is one address,
    /// and a provider has two — calendars and address books, usually on
    /// different hosts — which the sync engine reads from the manifest by
    /// the provider's id. An account that carried the calendar address as its
    /// own was asked for its contacts at that address too, and had none.
    #[must_use]
    pub fn account_for(&self, username: &str) -> crate::Account {
        let mut account = crate::Account::new(&self.name, "", username);
        account.provider = Some(self.id.clone());
        account.mail = self
            .services
            .mail
            .as_ref()
            .map(|m| m.endpoint_for(username));
        account
    }
}

impl Provider {
    /// A mail account for this provider that signs in with an app password,
    /// for a provider whose own route is the browser.
    ///
    /// Mail over IMAP and SMTP, and nothing else: the engine the manifest
    /// prefers — the Gmail API — takes a token and not a password, and so do
    /// the provider's calendars and contacts. So the account names no
    /// provider, which is what keeps the sync engine from knocking on DAV
    /// endpoints that will refuse it on every pass.
    ///
    /// `None` when the provider has no such route, or no IMAP host to use it
    /// against.
    #[must_use]
    pub fn app_password_account(&self, username: &str) -> Option<crate::Account> {
        self.app_password.as_ref()?;
        let mail = self.services.mail.as_ref()?;
        if mail.imap_host.is_empty() {
            return None;
        }
        let mut account = crate::Account::new(&self.name, "", username);
        account.mail = Some(MailEndpoint {
            protocol: MailProtocol::Imap,
            ..mail.endpoint_for(username)
        });
        Some(account)
    }
}

/// Every provider this installation knows about.
///
/// Built-ins first, then anything in the config directory — which both adds
/// providers and overrides built-ins of the same id, so supplying a client id
/// and retargeting an endpoint use one mechanism.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    providers: BTreeMap<String, Provider>,
}

impl Registry {
    /// Loads built-ins, then overlays every directory in [`provider_dirs`].
    #[must_use]
    pub fn load() -> Self {
        Self::load_from_dirs(&provider_dirs())
    }

    /// As [`Self::load`], reading overrides from `dir` alone.
    #[must_use]
    pub fn load_from(dir: &Path) -> Self {
        Self::load_from_dirs(&[dir.to_path_buf()])
    }

    /// Built-ins, then each of `dirs` in order — a later directory overlays an
    /// earlier one.
    ///
    /// A manifest that will not parse is skipped with a warning rather than
    /// failing the load: one bad file in a drop-in directory must not take
    /// every account offline.
    #[must_use]
    pub fn load_from_dirs(dirs: &[PathBuf]) -> Self {
        let mut providers = BTreeMap::new();

        for (id, text) in BUILT_IN {
            match toml::from_str::<Provider>(text) {
                Ok(provider) => {
                    providers.insert((*id).to_owned(), provider);
                }
                Err(why) => {
                    debug_assert!(false, "built-in provider {id} does not parse: {why}");
                    tracing::error!(id, %why, "built-in provider manifest does not parse");
                }
            }
        }

        for dir in dirs {
            overlay_dir(&mut providers, dir);
        }

        Self { providers }
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.providers.get(id)
    }

    /// Every provider, ordered by id.
    #[must_use]
    pub fn all(&self) -> Vec<&Provider> {
        self.providers.values().collect()
    }

    /// Providers an account-creation dialog can actually complete: an OAuth
    /// provider with no client id would take the user to a Google error page.
    #[must_use]
    pub fn usable(&self) -> Vec<&Provider> {
        self.providers
            .values()
            .filter(|p| p.oauth.as_ref().is_none_or(OAuth::is_configured))
            .collect()
    }

    /// The provider an email address belongs to, by its domain.
    ///
    /// Only the exact domains a manifest lists — `gmail.com` is Google, but a
    /// company with Google Workspace on its own domain is not detectable this
    /// way and falls through to autodiscovery, which is the right answer for
    /// it.
    #[must_use]
    pub fn for_email(&self, email: &str) -> Option<&Provider> {
        let (_, domain) = email.trim().rsplit_once('@')?;
        let domain = domain.to_ascii_lowercase();
        self.providers
            .values()
            .find(|provider| provider.domains.contains(&domain))
    }
}

/// Overlays every manifest in `dir` onto `providers`.
///
/// In file-name order, so two files naming the same id in one directory
/// resolve the same way on every run rather than in whatever order the
/// filesystem lists them.
fn overlay_dir(providers: &mut BTreeMap<String, Provider>, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "toml"))
        .collect();
    paths.sort();

    for path in paths {
        // The id first, and only the id. A file that overrides a built-in
        // is usually two lines — a client id and nothing else — so parsing
        // it as a whole `Provider` would reject it for the endpoints it
        // deliberately does not restate.
        let id = match read_id(&path) {
            Ok(id) => id,
            Err(why) => {
                tracing::warn!(
                    path = %path.display(), %why,
                    "ignoring a provider manifest with no readable id"
                );
                continue;
            }
        };

        let loaded = match providers.get(&id) {
            // Overriding a built-in or an earlier layer: overlay field by
            // field.
            Some(base) => merge(base, &path),
            // A provider nobody has heard of has to be complete.
            None => read_manifest(&path),
        };

        match loaded {
            Ok(provider) => {
                providers.insert(id, provider);
            }
            Err(why) => {
                tracing::warn!(
                    path = %path.display(), %why,
                    "ignoring an unusable provider manifest"
                );
            }
        }
    }
}

/// The `id` field, without requiring anything else in the file to be present.
fn read_id(path: &Path) -> Result<String> {
    #[derive(Deserialize)]
    struct IdOnly {
        id: String,
    }
    let text = std::fs::read_to_string(path)?;
    let parsed: IdOnly =
        toml::from_str(&text).map_err(|why| Error::config(format!("{}: {why}", path.display())))?;
    Ok(parsed.id)
}

fn read_manifest(path: &Path) -> Result<Provider> {
    let text = std::fs::read_to_string(path)?;
    toml::from_str(&text).map_err(|why| Error::config(format!("{}: {why}", path.display())))
}

/// Overlays an override file onto a built-in, field by field.
///
/// Deliberately not "parse the override as a whole `Provider` and take it": an
/// override supplying only a client id would then blank out the endpoints it
/// did not mention, and the account would sign in and sync nothing.
fn merge(base: &Provider, path: &Path) -> Result<Provider> {
    #[derive(Deserialize)]
    struct Overlay {
        name: Option<String>,
        hint: Option<String>,
        help_url: Option<String>,
        domains: Option<Vec<String>>,
        app_password: Option<AppPassword>,
        oauth: Option<OAuthOverlay>,
        services: Option<Services>,
    }

    #[derive(Deserialize)]
    struct OAuthOverlay {
        client_id: Option<String>,
        client_secret: Option<String>,
        auth_url: Option<String>,
        token_url: Option<String>,
        scopes: Option<Vec<String>>,
        extra_params: Option<BTreeMap<String, String>>,
        redirect_port: Option<u16>,
    }

    let text = std::fs::read_to_string(path)?;
    let overlay: Overlay =
        toml::from_str(&text).map_err(|why| Error::config(format!("{}: {why}", path.display())))?;

    let mut merged = base.clone();
    if let Some(name) = overlay.name {
        merged.name = name;
    }
    if let Some(hint) = overlay.hint {
        merged.hint = Some(hint);
    }
    if let Some(help_url) = overlay.help_url {
        merged.help_url = Some(help_url);
    }
    if let Some(domains) = overlay.domains {
        merged.domains = domains;
    }
    if let Some(app_password) = overlay.app_password {
        merged.app_password = Some(app_password);
    }
    if let Some(services) = overlay.services {
        merged.services = services;
    }
    if let Some(over) = overlay.oauth {
        let mut oauth = merged.oauth.clone().unwrap_or(OAuth {
            client_id: None,
            client_secret: None,
            auth_url: String::new(),
            token_url: String::new(),
            scopes: Vec::new(),
            extra_params: BTreeMap::new(),
            redirect_port: default_redirect_port(),
        });
        if let Some(v) = over.client_id {
            oauth.client_id = Some(v);
        }
        if let Some(v) = over.client_secret {
            oauth.client_secret = Some(v);
        }
        if let Some(v) = over.auth_url {
            oauth.auth_url = v;
        }
        if let Some(v) = over.token_url {
            oauth.token_url = v;
        }
        if let Some(v) = over.scopes {
            oauth.scopes = v;
        }
        if let Some(v) = over.extra_params {
            // Extended, not replaced, like every other layer here: an
            // override that adds one parameter must not drop the built-in
            // `access_type=offline`, without which Google issues no refresh
            // token and the account stops working an hour later.
            oauth.extra_params.extend(v);
        }
        if let Some(v) = over.redirect_port {
            oauth.redirect_port = v;
        }
        merged.oauth = Some(oauth);
    }
    Ok(merged)
}

/// Where one user's drop-in and override manifests live.
#[must_use]
pub fn default_provider_dir() -> PathBuf {
    crate::account::config_dir().join("providers")
}

/// Every directory manifests are read from, lowest precedence first: the
/// system data directories, `/etc`, then the user's own.
///
/// With `COSMIC_PIM_CONFIG_DIR` set, that directory alone — the variable
/// exists so tests and a sandboxed daemon see a closed world, and a client id
/// leaking in from the host's `/usr/share` would open it.
#[must_use]
pub fn provider_dirs() -> Vec<PathBuf> {
    if std::env::var_os("COSMIC_PIM_CONFIG_DIR").is_some() {
        return vec![default_provider_dir()];
    }

    let data_dirs = std::env::var_os("XDG_DATA_DIRS")
        .filter(|dirs| !dirs.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    layered_dirs(&data_dirs, &default_provider_dir())
}

/// `$XDG_DATA_DIRS` lists its most important directory first; overlaying
/// wants the least important first, so it is walked in reverse.
fn layered_dirs(data_dirs: &std::ffi::OsStr, user: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::split_paths(data_dirs)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("cosmic-pim/providers"))
        .collect();
    dirs.reverse();
    dirs.push(PathBuf::from("/etc/cosmic-pim/providers"));
    dirs.push(user.to_path_buf());
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_built_in_manifest_parses() {
        // A malformed built-in would otherwise surface as "that provider does
        // not exist" at sign-in time, with the reason only in a log.
        for (id, text) in BUILT_IN {
            let provider: Provider = toml::from_str(text)
                .unwrap_or_else(|why| panic!("built-in provider {id} does not parse: {why}"));
            assert_eq!(&provider.id, id, "manifest id does not match its file name");
            assert_ne!(provider.name.trim(), "");
        }
    }

    #[test]
    fn google_asks_for_a_refresh_token_explicitly() {
        // Without `access_type=offline` Google issues an access token and no
        // refresh token, so the account works for one hour and then stops with
        // an authentication error that looks like a revoked password.
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let google = registry.get("google").expect("google is built in");
        let oauth = google.oauth.as_ref().expect("google uses OAuth");
        assert_eq!(
            oauth.extra_params.get("access_type").map(String::as_str),
            Some("offline")
        );
    }

    #[test]
    fn the_built_in_oauth_providers_ship_no_client_id() {
        // Shipping one would mean every downstream package impersonating this
        // project's registration. See the module docs.
        let registry = Registry::load_from(Path::new("/nonexistent"));
        for id in ["google", "microsoft"] {
            let oauth = registry.get(id).unwrap().oauth.as_ref().unwrap();
            assert!(!oauth.is_configured(), "{id} ships a client id");
        }
    }

    #[test]
    fn an_unconfigured_oauth_provider_is_not_offered() {
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let usable: Vec<&str> = registry.usable().iter().map(|p| p.id.as_str()).collect();

        assert!(
            !usable.contains(&"google"),
            "an unusable provider was offered"
        );
        // App-password providers need no configuration and are always usable.
        assert!(usable.contains(&"fastmail"));
    }

    #[test]
    fn a_config_manifest_supplies_the_client_id_without_erasing_anything_else() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("google.toml"),
            "id = \"google\"\nname = \"Google\"\n\n[oauth]\nclient_id = \"abc.apps.googleusercontent.com\"\n",
        )
        .unwrap();

        let registry = Registry::load_from(dir.path());
        let google = registry.get("google").unwrap();
        let oauth = google.oauth.as_ref().unwrap();

        assert!(oauth.is_configured());
        assert!(
            oauth.token_url.contains("oauth2"),
            "the built-in endpoints were erased by an override that did not mention them"
        );
        assert!(
            google.services.calendar.is_some(),
            "the built-in service endpoints were erased"
        );
        assert!(registry.usable().iter().any(|p| p.id == "google"));
    }

    #[test]
    fn a_drop_in_manifest_adds_a_provider() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("uni.toml"),
            "id = \"uni\"\nname = \"University\"\n\n[services]\ncalendar = \"https://dav.uni.example/{username}/\"\n",
        )
        .unwrap();

        let registry = Registry::load_from(dir.path());
        let uni = registry
            .get("uni")
            .expect("drop-in provider was not loaded");

        assert_eq!(
            uni.calendar_url("ada").as_deref(),
            Some("https://dav.uni.example/ada/")
        );
        assert!(
            uni.oauth.is_none(),
            "a manifest with no [oauth] is a password provider"
        );
    }

    #[test]
    fn a_broken_manifest_does_not_take_the_others_down() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.toml"), "this is not toml {{{").unwrap();

        let registry = Registry::load_from(dir.path());

        assert!(
            registry.get("google").is_some(),
            "one bad file emptied the registry"
        );
    }

    #[test]
    fn a_well_known_domain_finds_its_provider() {
        let registry = Registry::load_from(Path::new("/nonexistent"));

        assert_eq!(
            registry.for_email("ada@gmail.com").map(|p| p.id.as_str()),
            Some("google")
        );
        assert_eq!(
            registry.for_email("ada@ICLOUD.COM").map(|p| p.id.as_str()),
            Some("icloud")
        );
        // Google Workspace on a custom domain is not detectable here, and
        // guessing would send a Nextcloud user through a Google sign-in.
        assert_eq!(registry.for_email("ada@example.com"), None);
    }

    #[test]
    fn google_and_microsoft_default_to_their_own_apis() {
        // Not a preference: IMAP cannot express a Gmail archive, and a
        // Microsoft tenant may have IMAP switched off entirely. The IMAP
        // details stay filled in so switching back is one field.
        let registry = Registry::load_from(Path::new("/nonexistent"));

        let google = registry
            .get("google")
            .unwrap()
            .services
            .mail
            .as_ref()
            .unwrap();
        assert_eq!(google.protocol, MailProtocol::Gmail);
        assert_eq!(google.imap_host, "imap.gmail.com");

        let microsoft = registry
            .get("microsoft")
            .unwrap()
            .services
            .mail
            .as_ref()
            .unwrap();
        assert_eq!(microsoft.protocol, MailProtocol::Graph);
        assert_eq!(microsoft.imap_host, "outlook.office365.com");
    }

    #[test]
    fn the_api_scopes_are_requested_alongside_the_imap_ones() {
        // Asking for both means an account switched from the API to IMAP, or
        // back, needs no second trip through a consent screen.
        let registry = Registry::load_from(Path::new("/nonexistent"));

        let google = registry.get("google").unwrap().oauth.as_ref().unwrap();
        assert!(google.scopes.iter().any(|s| s.contains("gmail.modify")));
        assert!(
            google
                .scopes
                .iter()
                .any(|s| s == "https://mail.google.com/")
        );

        let microsoft = registry.get("microsoft").unwrap().oauth.as_ref().unwrap();
        assert!(
            microsoft
                .scopes
                .iter()
                .any(|s| s.contains("Mail.ReadWrite"))
        );
        assert!(
            microsoft
                .scopes
                .iter()
                .any(|s| s.contains("IMAP.AccessAsUser"))
        );
    }

    #[test]
    fn an_account_created_from_a_provider_needs_no_further_questions() {
        // The point of the registry: adding a Fastmail account should ask who
        // you are and nothing else — not for an IMAP hostname, a port, a
        // CalDAV path, or a submission server.
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let fastmail = registry.get("fastmail").expect("built in");

        let account = fastmail.account_for("ada@fastmail.com");

        assert_eq!(account.provider.as_deref(), Some("fastmail"));
        // The provider's id is what locates its calendars and address books;
        // see `account_for`.
        assert_eq!(account.url, "");
        assert_eq!(
            fastmail.calendar_url(&account.username).as_deref(),
            Some("https://caldav.fastmail.com/dav/calendars/user/ada@fastmail.com/")
        );

        let mail = account.mail.expect("mail endpoints");
        assert_eq!(mail.protocol, MailProtocol::Jmap);
        assert_eq!(
            mail.jmap_session_url.as_deref(),
            Some("https://api.fastmail.com/jmap/session")
        );
        // …and the IMAP details are still filled in, because a user who
        // prefers IMAP changes one field rather than typing four.
        assert_eq!(mail.imap_host, "imap.fastmail.com");
        assert_eq!(mail.smtp_host, "smtp.fastmail.com");
    }

    #[test]
    fn a_provider_with_no_calendar_names_none_rather_than_a_wrong_one() {
        // Outlook.com withdrew CalDAV. Inventing an address would produce an
        // account that fails every pass against a server that was never there.
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let microsoft = registry.get("microsoft").expect("built in");

        let account = microsoft.account_for("ada@outlook.com");

        assert_eq!(microsoft.calendar_url(&account.username), None);
        assert_eq!(microsoft.contacts_url(&account.username), None);
        assert_eq!(
            account.mail.expect("mail endpoints").imap_host,
            "outlook.office365.com"
        );
    }

    #[test]
    fn no_two_built_ins_claim_the_same_domain() {
        // `for_email` takes the first match, so a domain listed twice would
        // send an address to whichever provider sorts first — silently.
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for provider in registry.all() {
            for domain in &provider.domains {
                assert_eq!(
                    domain,
                    &domain.to_ascii_lowercase(),
                    "{} lists a domain that is not lowercase",
                    provider.id
                );
                if let Some(other) = seen.insert(domain, &provider.id) {
                    panic!("{domain} is claimed by both {other} and {}", provider.id);
                }
            }
        }
    }

    #[test]
    fn a_system_manifest_and_a_user_manifest_both_apply() {
        // The distribution ships the client id; a user retargets the scopes.
        // Neither may erase the other, or the built-in endpoints under both.
        let system = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        std::fs::write(
            system.path().join("google.toml"),
            "id = \"google\"\n\n[oauth]\nclient_id = \"distro.apps.googleusercontent.com\"\n",
        )
        .unwrap();
        std::fs::write(
            user.path().join("google.toml"),
            "id = \"google\"\n\n[oauth]\nscopes = [\"openid\"]\n",
        )
        .unwrap();

        let registry =
            Registry::load_from_dirs(&[system.path().to_path_buf(), user.path().to_path_buf()]);
        let oauth = registry.get("google").unwrap().oauth.as_ref().unwrap();

        assert_eq!(
            oauth.client_id.as_deref(),
            Some("distro.apps.googleusercontent.com"),
            "the user's manifest erased the distribution's client id"
        );
        assert_eq!(oauth.scopes, ["openid"]);
        assert!(oauth.token_url.contains("oauth2"));
    }

    #[test]
    fn an_override_adding_a_parameter_keeps_the_built_in_ones() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("google.toml"),
            "id = \"google\"\n[oauth]\nclient_id = \"x\"\n[oauth.extra_params]\nhd = \"example.com\"\n",
        )
        .unwrap();

        let registry = Registry::load_from(dir.path());
        let params = &registry
            .get("google")
            .unwrap()
            .oauth
            .as_ref()
            .unwrap()
            .extra_params;

        assert_eq!(params.get("hd").map(String::as_str), Some("example.com"));
        assert_eq!(
            params.get("access_type").map(String::as_str),
            Some("offline"),
            "the override dropped the parameter that gets a refresh token"
        );
    }

    #[test]
    fn a_providers_client_secret_stays_out_of_debug_output() {
        let oauth = OAuth {
            client_secret: Some("do-not-log-me".into()),
            ..Registry::load_from(Path::new("/nonexistent"))
                .get("google")
                .unwrap()
                .oauth
                .clone()
                .unwrap()
        };

        assert!(!format!("{oauth:?}").contains("do-not-log-me"));
    }

    #[test]
    fn a_later_directory_wins_over_an_earlier_one() {
        let system = tempfile::tempdir().unwrap();
        let user = tempfile::tempdir().unwrap();
        for (dir, id) in [(&system, "system-id"), (&user, "user-id")] {
            std::fs::write(
                dir.path().join("google.toml"),
                format!("id = \"google\"\n\n[oauth]\nclient_id = \"{id}\"\n"),
            )
            .unwrap();
        }

        let registry =
            Registry::load_from_dirs(&[system.path().to_path_buf(), user.path().to_path_buf()]);
        let oauth = registry.get("google").unwrap().oauth.as_ref().unwrap();

        assert_eq!(oauth.client_id.as_deref(), Some("user-id"));
    }

    #[test]
    fn two_files_for_one_provider_resolve_in_file_name_order() {
        // Directory listing order is whatever the filesystem says; without a
        // sort the winner would differ between machines.
        let dir = tempfile::tempdir().unwrap();
        for (file, id) in [("20-site.toml", "second"), ("10-distro.toml", "first")] {
            std::fs::write(
                dir.path().join(file),
                format!("id = \"google\"\n\n[oauth]\nclient_id = \"{id}\"\n"),
            )
            .unwrap();
        }

        let registry = Registry::load_from(dir.path());
        let oauth = registry.get("google").unwrap().oauth.as_ref().unwrap();

        assert_eq!(oauth.client_id.as_deref(), Some("second"));
    }

    #[test]
    fn the_system_directories_are_read_before_the_users() {
        let dirs = layered_dirs(
            std::ffi::OsStr::new("/usr/local/share:/usr/share:relative"),
            Path::new("/home/ada/.config/cosmic-pim/providers"),
        );

        assert_eq!(
            dirs,
            [
                // `$XDG_DATA_DIRS` puts the most important first; an overlay
                // wants it last among the data directories.
                PathBuf::from("/usr/share/cosmic-pim/providers"),
                PathBuf::from("/usr/local/share/cosmic-pim/providers"),
                PathBuf::from("/etc/cosmic-pim/providers"),
                PathBuf::from("/home/ada/.config/cosmic-pim/providers"),
            ],
            "a relative entry must be dropped, and the user's directory must come last"
        );
    }

    #[test]
    fn a_manifest_can_claim_a_domain() {
        // What lets a university or a company be recognised from an address
        // without a release of anything.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("uni.toml"),
            "id = \"uni\"\nname = \"University\"\ndomains = [\"uni.example\"]\n",
        )
        .unwrap();

        let registry = Registry::load_from(dir.path());

        assert_eq!(
            registry.for_email("Ada@Uni.Example").map(|p| p.id.as_str()),
            Some("uni")
        );
    }

    #[test]
    fn proton_is_reached_through_bridge_on_loopback() {
        // There is no Proton server a client can sign in to; an entry naming
        // one would fail as a wrong password against a host that never
        // answers IMAP.
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let proton = registry.for_email("ada@proton.me").expect("recognised");
        let account = proton.account_for("ada@proton.me");
        let mail = account.mail.expect("mail endpoints");

        assert_eq!(mail.imap_host, "127.0.0.1");
        assert_eq!(mail.imap_port, 1143);
        assert_eq!(mail.imap_transport, Transport::StartTls);
        assert_eq!(mail.smtp_port, 1025);
        assert_eq!(
            proton.calendar_url("ada@proton.me"),
            None,
            "Bridge serves no calendar, and inventing one fails every sync"
        );
        assert!(proton.help_url.is_some());
    }

    #[test]
    fn a_password_provider_with_dav_needs_no_further_questions() {
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let yahoo = registry.for_email("ada@ymail.com").expect("recognised");

        assert!(yahoo.oauth.is_none());
        assert_eq!(
            yahoo.contacts_url("ada@ymail.com").as_deref(),
            Some("https://carddav.address.yahoo.com/")
        );
        assert_eq!(
            yahoo.calendar_url("ada@ymail.com").as_deref(),
            Some("https://caldav.calendar.yahoo.com/")
        );
        let account = yahoo.account_for("ada@ymail.com");
        assert_eq!(account.provider.as_deref(), Some("yahoo"));
        assert_eq!(account.mail.expect("mail").imap_host, "imap.mail.yahoo.com");
    }

    #[test]
    fn google_takes_an_app_password_for_mail_and_microsoft_takes_none() {
        // On an installation with no client id this is the difference between
        // "Gmail works" and "Gmail cannot be added", and for Outlook.com
        // there is nothing to fall back to.
        let registry = Registry::load_from(Path::new("/nonexistent"));

        let google = registry.get("google").unwrap();
        let account = google
            .app_password_account("ada@gmail.com")
            .expect("google has a password route");
        let mail = account.mail.expect("mail endpoints");
        assert_eq!(
            mail.protocol,
            MailProtocol::Imap,
            "the Gmail engine takes a token, not a password"
        );
        assert_eq!(mail.imap_host, "imap.gmail.com");
        assert_eq!(
            account.provider, None,
            "a provider here would send a password to Google's DAV endpoints"
        );

        let microsoft = registry.get("microsoft").unwrap();
        assert!(microsoft.app_password_account("ada@outlook.com").is_none());
    }

    #[test]
    fn the_redirect_uri_is_literal_loopback() {
        // RFC 8252 §8.3: `localhost` may resolve to an interface another
        // process is listening on.
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let oauth = registry.get("google").unwrap().oauth.as_ref().unwrap();
        assert!(oauth.redirect_uri().starts_with("http://127.0.0.1:"));
    }
}

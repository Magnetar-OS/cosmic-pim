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
//! A packager supplies them by dropping a file in the config directory:
//!
//! ```toml
//! # $XDG_CONFIG_HOME/cosmic-pim/providers/google.toml
//! [oauth]
//! client_id = "…apps.googleusercontent.com"
//! client_secret = "…"          # omitted for a public client using PKCE
//! ```
//!
//! Anything in a config-directory manifest overrides the built-in of the same
//! id, so the same mechanism retargets a scope list or an endpoint without a
//! patch.

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
}

/// The four things an OAuth provider differs by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

impl MailService {
    /// This provider's endpoints, filled in for one account.
    #[must_use]
    pub fn endpoint_for(&self, username: &str) -> MailEndpoint {
        MailEndpoint {
            imap_host: self.imap_host.clone(),
            imap_port: self.imap_port,
            imap_transport: self.imap_transport,
            imap_username: Some(username.to_owned()),
            smtp_host: self.smtp_host.clone(),
            smtp_port: self.smtp_port,
            smtp_transport: self.smtp_transport,
            from_address: username.to_owned(),
            from_name: String::new(),
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
    /// Loads built-ins, then overlays the config directory.
    #[must_use]
    pub fn load() -> Self {
        Self::load_from(&default_provider_dir())
    }

    /// As [`Self::load`], reading overrides from `dir`.
    ///
    /// A manifest that will not parse is skipped with a warning rather than
    /// failing the load: one bad file in a drop-in directory must not take
    /// every account offline.
    #[must_use]
    pub fn load_from(dir: &Path) -> Self {
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

        let Ok(entries) = std::fs::read_dir(dir) else {
            return Self { providers };
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "toml") {
                continue;
            }

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
                // Overriding a built-in: overlay field by field.
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
    /// Only exact, well-known domains — `gmail.com` is Google, but a company
    /// with Google Workspace on its own domain is not detectable this way and
    /// falls through to autodiscovery, which is the right answer for it.
    #[must_use]
    pub fn for_email(&self, email: &str) -> Option<&Provider> {
        let domain = email.rsplit('@').next()?.trim().to_ascii_lowercase();
        let id = match domain.as_str() {
            "gmail.com" | "googlemail.com" => "google",
            "outlook.com" | "hotmail.com" | "live.com" | "msn.com" => "microsoft",
            "fastmail.com" | "fastmail.fm" => "fastmail",
            "icloud.com" | "me.com" | "mac.com" => "icloud",
            _ => return None,
        };
        self.get(id)
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
            oauth.extra_params = v;
        }
        if let Some(v) = over.redirect_port {
            oauth.redirect_port = v;
        }
        merged.oauth = Some(oauth);
    }
    Ok(merged)
}

/// Where drop-in and override manifests live.
#[must_use]
pub fn default_provider_dir() -> PathBuf {
    crate::account::config_dir().join("providers")
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
            assert!(!provider.name.trim().is_empty());
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
    fn the_redirect_uri_is_literal_loopback() {
        // RFC 8252 §8.3: `localhost` may resolve to an interface another
        // process is listening on.
        let registry = Registry::load_from(Path::new("/nonexistent"));
        let oauth = registry.get("google").unwrap().oauth.as_ref().unwrap();
        assert!(oauth.redirect_uri().starts_with("http://127.0.0.1:"));
    }
}

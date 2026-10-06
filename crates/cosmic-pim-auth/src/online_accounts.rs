// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! GNOME Online Accounts as a second source of sign-ins.
//!
//! # Why a second source
//!
//! This crate's own flow needs an OAuth client id, and a client id is a
//! registration somebody has to hold with Google or Microsoft — see
//! `cosmic_pim_accounts::provider`. Where a distribution has none yet, the
//! desktop often already has a service that does: GNOME Online Accounts keeps
//! Google and Microsoft sign-ins for every application on the session bus,
//! under GNOME's own registration, and renews them itself.
//!
//! So an account can be *backed* by one of GOA's. Nothing about how it is
//! used changes: [`crate::resolve`] hands back an access token either way,
//! and asks GOA for a fresh one where it would otherwise have posted to a
//! token endpoint.
//!
//! # What is taken from GOA, and what is not
//!
//! The token, and who it belongs to. Nothing else. Where the mail, calendars
//! and contacts live comes from this suite's own provider manifests, because
//! those name the engines the suite actually drives — the Gmail API and
//! Microsoft Graph — and GOA's own idea of a Google account is IMAP.
//!
//! The grant is GOA's and stays there: the refresh token never crosses the
//! bus, and an access token that does is good for about an hour.
//!
//! # Nothing here starts the daemon
//!
//! [`OnlineAccounts::connect`] answers `None` when nothing owns the name,
//! rather than activating it. A desktop without GOA installed is the ordinary
//! case, and asking the bus to start a service that is not there costs a
//! timeout on every launch.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use cosmic_pim_accounts::OAuthCredential;
use zbus::blocking::{Connection, Proxy, fdo::DBusProxy, fdo::ObjectManagerProxy};
use zbus::names::BusName;
use zbus::zvariant::OwnedValue;

use crate::error::{Error, Result};

const BUS: &str = "org.gnome.OnlineAccounts";
const ROOT: &str = "/org/gnome/OnlineAccounts";
const ACCOUNT: &str = "org.gnome.OnlineAccounts.Account";
const OAUTH2: &str = "org.gnome.OnlineAccounts.OAuth2Based";

/// GOA's own error for a grant that has died and needs the user.
const NOT_AUTHORIZED: &str = "org.gnome.OnlineAccounts.Error.NotAuthorized";

/// A renewal is one HTTPS round trip made by the daemon. Longer than that and
/// a sync pass is better off reporting it than waiting.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// One account GOA holds a sign-in for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineAccount {
    /// GOA's id for the account. Stable for as long as the account exists,
    /// and what an account backed by it is named after — see
    /// `cosmic_pim_accounts::Account::online_account`.
    pub id: String,
    /// GOA's name for the kind of account: `google`, `ms_graph`.
    pub provider_type: String,
    /// Who the account belongs to, as shown to the user. For Google and
    /// Microsoft this is the address, which is also the login.
    pub identity: String,
    /// GOA could not renew the grant and is waiting for the user to sign in
    /// again, in GOA's own settings.
    pub attention_needed: bool,
    /// The user switched this service off for the account, in GOA's settings.
    pub mail_disabled: bool,
    pub calendar_disabled: bool,
    pub contacts_disabled: bool,
}

impl OnlineAccount {
    /// The account's address, when [`Self::identity`] has the shape of one.
    ///
    /// What GOA calls an identity is whatever its provider chose to show, and
    /// it reaches this process over the session bus. Before it becomes a
    /// login name and a `From` address it has to be exactly one address;
    /// `None` when it is anything else.
    #[must_use]
    pub fn address(&self) -> Option<&str> {
        let identity = self.identity.trim();
        crate::token::is_address(identity).then_some(identity)
    }

    /// The id of this suite's provider manifest for the account, when it has
    /// one. `None` for the kinds GOA offers that carry no OAuth grant this
    /// suite could use — a Kerberos login, a WebDAV share.
    #[must_use]
    pub fn provider_id(&self) -> Option<&'static str> {
        match self.provider_type.as_str() {
            "google" => Some("google"),
            "ms_graph" => Some("microsoft"),
            _ => None,
        }
    }
}

/// Whether Online Accounts can hold a sign-in for this suite's provider
/// `provider_id` — the reverse of [`OnlineAccount::provider_id`].
#[must_use]
pub fn serves(provider_id: &str) -> bool {
    matches!(provider_id, "google" | "microsoft")
}

/// A connection to the GOA daemon.
#[derive(Debug, Clone)]
pub struct OnlineAccounts {
    connection: Connection,
}

impl OnlineAccounts {
    /// Connects, if GOA is running on this session.
    ///
    /// `Ok(None)` when it is not — which is every desktop that does not ship
    /// it, and not an error.
    pub fn connect() -> Result<Option<Self>> {
        let connection = zbus::blocking::connection::Builder::session()
            .and_then(|builder| builder.method_timeout(CALL_TIMEOUT).build())
            .map_err(bus_error)?;
        Self::on(connection)
    }

    /// As [`Self::connect`], on a connection the caller made — a private bus,
    /// in a test.
    pub fn on(connection: Connection) -> Result<Option<Self>> {
        let name = BusName::try_from(BUS).map_err(|why| Error::Protocol(why.to_string()))?;
        let running = DBusProxy::new(&connection)
            .and_then(|bus| bus.name_has_owner(name).map_err(Into::into))
            .map_err(bus_error)?;
        Ok(running.then_some(Self { connection }))
    }

    /// Every account GOA holds that carries an OAuth grant.
    pub fn list(&self) -> Result<Vec<OnlineAccount>> {
        let objects = ObjectManagerProxy::builder(&self.connection)
            .destination(BUS)
            .and_then(|builder| builder.path(ROOT))
            .and_then(|builder| builder.build())
            .and_then(|manager| manager.get_managed_objects().map_err(Into::into))
            .map_err(bus_error)?;

        let mut accounts: Vec<OnlineAccount> = objects
            .values()
            .filter_map(|interfaces| {
                // Without this interface there is no token to ask for.
                interfaces.get(OAUTH2)?;
                let properties = interfaces.get(ACCOUNT)?;
                Some(OnlineAccount {
                    id: text(properties, "Id")?,
                    provider_type: text(properties, "ProviderType")?,
                    identity: text(properties, "PresentationIdentity")
                        .filter(|identity| !identity.is_empty())
                        .or_else(|| text(properties, "Identity"))?,
                    attention_needed: flag(properties, "AttentionNeeded"),
                    mail_disabled: flag(properties, "MailDisabled"),
                    calendar_disabled: flag(properties, "CalendarDisabled"),
                    contacts_disabled: flag(properties, "ContactsDisabled"),
                })
            })
            .collect();
        accounts.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(accounts)
    }

    /// A current access token for the account GOA calls `id`.
    ///
    /// GOA renews the grant first if it has to. The credential that comes
    /// back carries no refresh token on purpose: renewal is GOA's, and the
    /// way to get the next token is to ask here again.
    pub fn access_token(&self, id: &str) -> Result<OAuthCredential> {
        let path = self.path_of(id)?;
        let proxy = |interface: &'static str| {
            Proxy::new(&self.connection, BUS, path.as_str(), interface).map_err(bus_error)
        };

        // Ask GOA to make sure the grant is live before asking for a token:
        // `GetAccessToken` alone hands back whatever is cached.
        proxy(ACCOUNT)?
            .call::<_, _, i32>("EnsureCredentials", &())
            .map_err(call_error)?;
        let (access_token, expires_in): (String, i32) = proxy(OAUTH2)?
            .call("GetAccessToken", &())
            .map_err(call_error)?;

        Ok(OAuthCredential {
            access_token,
            refresh_token: None,
            // GOA answers 0 when it does not know. Leaving the expiry absent
            // then would mean "assume it is still good" forever; an hour is
            // what both providers issue.
            expires_at: Some(
                Utc::now()
                    + ChronoDuration::seconds(if expires_in > 0 {
                        i64::from(expires_in)
                    } else {
                        3600
                    }),
            ),
            scopes: Vec::new(),
            token_type: "Bearer".to_owned(),
        })
    }

    /// The object path of the account with this id.
    ///
    /// Looked up rather than built from the id: the path is GOA's to choose.
    fn path_of(&self, id: &str) -> Result<String> {
        let objects = ObjectManagerProxy::builder(&self.connection)
            .destination(BUS)
            .and_then(|builder| builder.path(ROOT))
            .and_then(|builder| builder.build())
            .and_then(|manager| manager.get_managed_objects().map_err(Into::into))
            .map_err(bus_error)?;
        objects
            .iter()
            .find(|(_, interfaces)| {
                interfaces
                    .get(ACCOUNT)
                    .and_then(|properties| text(properties, "Id"))
                    .is_some_and(|found| found == id)
            })
            .map(|(path, _)| path.to_string())
            .ok_or_else(|| {
                Error::GrantRejected(
                    "the account is no longer in Online Accounts; add it there again".to_owned(),
                )
            })
    }
}

fn text(properties: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    properties
        .get(key)
        .and_then(|value| value.downcast_ref::<String>().ok())
}

fn flag(properties: &HashMap<String, OwnedValue>, key: &str) -> bool {
    properties
        .get(key)
        .and_then(|value| value.downcast_ref::<bool>().ok())
        .unwrap_or(false)
}

/// The bus itself failing: worth another try later.
fn bus_error(why: zbus::Error) -> Error {
    Error::Transport(format!("Online Accounts could not be reached: {why}"))
}

/// A call GOA answered with an error.
///
/// GOA says `NotAuthorized` for exactly the case that needs a person — the
/// grant was revoked, or the password changed. Everything else is the daemon
/// or the network having a moment.
fn call_error(why: zbus::Error) -> Error {
    match &why {
        zbus::Error::MethodError(name, detail, _) if name.as_str() == NOT_AUTHORIZED => {
            Error::GrantRejected(format!(
                "sign in to the account again in Online Accounts ({})",
                detail
                    .as_deref()
                    .unwrap_or("the sign-in is no longer valid")
            ))
        }
        _ => bus_error(why),
    }
}

/// A private session bus with a stand-in for the GOA daemon on it, so the
/// client is exercised over a real bus without touching the user's session or
/// their accounts.
#[cfg(test)]
pub(crate) mod testing {
    use std::io::BufRead as _;

    use zbus::blocking::Connection;

    use super::{BUS, ROOT};

    /// A `dbus-daemon` of our own, torn down on drop.
    pub(crate) struct PrivateBus {
        child: std::process::Child,
        address: String,
        _dir: tempfile::TempDir,
    }

    impl PrivateBus {
        /// # Panics
        ///
        /// When `dbus-daemon` is not installed or does not start: a test that
        /// needs a bus must fail loudly rather than pass without one.
        pub(crate) fn start() -> Self {
            let dir = tempfile::tempdir().expect("a temporary directory for the bus");
            let config = dir.path().join("bus.conf");
            std::fs::write(
                &config,
                // `/tmp` rather than the temporary directory: a socket path
                // has a 108-byte limit, and `TMPDIR` can be longer than that.
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
            )
            .expect("writing the bus configuration");

            let mut child = std::process::Command::new("dbus-daemon")
                .arg(format!("--config-file={}", config.display()))
                .arg("--nofork")
                .arg("--print-address=1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("dbus-daemon must be installed to run the Online Accounts tests");

            let stdout = child.stdout.take().expect("the bus's stdout");
            let mut address = String::new();
            std::io::BufReader::new(stdout)
                .read_line(&mut address)
                .expect("the bus prints its address");

            Self {
                child,
                address: address.trim().to_owned(),
                _dir: dir,
            }
        }

        /// A new connection to this bus.
        pub(crate) fn connect(&self) -> Connection {
            zbus::blocking::connection::Builder::address(self.address.as_str())
                .expect("a valid bus address")
                .build()
                .expect("connecting to the private bus")
        }

        /// Puts a stand-in GOA daemon on the bus, holding `accounts`. The
        /// returned connection is the daemon: drop it and the name is gone.
        pub(crate) fn serve(&self, accounts: Vec<FakeAccount>) -> Connection {
            let mut builder = zbus::blocking::connection::Builder::address(self.address.as_str())
                .expect("a valid bus address")
                .serve_at(ROOT, zbus::fdo::ObjectManager)
                .expect("the object manager");
            for account in accounts {
                // Owned: the builder keeps the path past this iteration.
                let path =
                    zbus::zvariant::ObjectPath::try_from(format!("{ROOT}/Accounts/{}", account.id))
                        .expect("a valid object path");
                if account.oauth {
                    builder = builder
                        .serve_at(
                            path.clone(),
                            FakeOAuth2 {
                                token: account.token.clone(),
                            },
                        )
                        .expect("the OAuth2 interface");
                }
                builder = builder
                    .serve_at(path, account)
                    .expect("the account interface");
            }
            builder
                .name(BUS)
                .expect("the GOA name")
                .build()
                .expect("the stand-in daemon")
        }
    }

    impl Drop for PrivateBus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// One account as the stand-in daemon presents it.
    #[derive(Clone)]
    pub(crate) struct FakeAccount {
        pub(crate) id: String,
        pub(crate) provider_type: String,
        pub(crate) identity: String,
        /// The token `GetAccessToken` hands out.
        pub(crate) token: String,
        /// GOA's state for a grant that died: `EnsureCredentials` refuses.
        pub(crate) revoked: bool,
        /// Whether the account has an OAuth grant at all.
        pub(crate) oauth: bool,
    }

    impl FakeAccount {
        pub(crate) fn google(id: &str, identity: &str) -> Self {
            Self {
                id: id.to_owned(),
                provider_type: "google".to_owned(),
                identity: identity.to_owned(),
                token: format!("token-for-{id}"),
                revoked: false,
                oauth: true,
            }
        }
    }

    #[derive(Debug, zbus::DBusError)]
    #[zbus(prefix = "org.gnome.OnlineAccounts.Error")]
    enum GoaError {
        #[zbus(error)]
        ZBus(zbus::Error),
        NotAuthorized(String),
    }

    #[zbus::interface(name = "org.gnome.OnlineAccounts.Account")]
    impl FakeAccount {
        #[zbus(property)]
        fn id(&self) -> String {
            self.id.clone()
        }

        #[zbus(property)]
        fn provider_type(&self) -> String {
            self.provider_type.clone()
        }

        #[zbus(property)]
        fn presentation_identity(&self) -> String {
            self.identity.clone()
        }

        #[zbus(property)]
        fn identity(&self) -> String {
            "1234567890".to_owned()
        }

        #[zbus(property)]
        fn attention_needed(&self) -> bool {
            self.revoked
        }

        #[zbus(property)]
        fn mail_disabled(&self) -> bool {
            false
        }

        #[zbus(property)]
        fn calendar_disabled(&self) -> bool {
            true
        }

        #[zbus(property)]
        fn contacts_disabled(&self) -> bool {
            false
        }

        fn ensure_credentials(&self) -> Result<i32, GoaError> {
            if self.revoked {
                return Err(GoaError::NotAuthorized(
                    "Credentials have expired".to_owned(),
                ));
            }
            Ok(3000)
        }
    }

    struct FakeOAuth2 {
        token: String,
    }

    #[zbus::interface(name = "org.gnome.OnlineAccounts.OAuth2Based")]
    impl FakeOAuth2 {
        fn get_access_token(&self) -> (String, i32) {
            (self.token.clone(), 3000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{FakeAccount, PrivateBus};
    use super::*;

    #[test]
    fn a_session_without_the_daemon_has_no_online_accounts() {
        // The ordinary case on a desktop that does not ship GOA. It must be
        // an answer, not an error, and it must not try to start anything.
        let bus = PrivateBus::start();

        let service = OnlineAccounts::on(bus.connect()).expect("the bus is there");

        assert!(service.is_none());
    }

    #[test]
    fn the_accounts_with_a_grant_are_listed_with_who_they_belong_to() {
        let bus = PrivateBus::start();
        let _daemon = bus.serve(vec![
            FakeAccount::google("account_2", "grace@gmail.com"),
            FakeAccount {
                provider_type: "ms_graph".to_owned(),
                ..FakeAccount::google("account_1", "ada@outlook.com")
            },
            // A Kerberos login has no OAuth grant and nothing this suite can
            // ask for a token with.
            FakeAccount {
                provider_type: "kerberos".to_owned(),
                oauth: false,
                ..FakeAccount::google("account_3", "ada@EXAMPLE.COM")
            },
        ]);
        let service = OnlineAccounts::on(bus.connect())
            .unwrap()
            .expect("the daemon is running");

        let accounts = service.list().expect("list");

        let seen: Vec<(&str, &str, Option<&str>)> = accounts
            .iter()
            .map(|a| (a.id.as_str(), a.identity.as_str(), a.provider_id()))
            .collect();
        assert_eq!(
            seen,
            [
                ("account_1", "ada@outlook.com", Some("microsoft")),
                ("account_2", "grace@gmail.com", Some("google")),
            ]
        );
        assert!(accounts[0].calendar_disabled);
        assert!(!accounts[0].mail_disabled);
    }

    #[test]
    fn an_identity_is_an_address_only_when_it_is_exactly_one() {
        let account = |identity: &str| OnlineAccount {
            id: "account_1".to_owned(),
            provider_type: "google".to_owned(),
            identity: identity.to_owned(),
            attention_needed: false,
            mail_disabled: false,
            calendar_disabled: false,
            contacts_disabled: false,
        };

        assert_eq!(account(" ada@gmail.com ").address(), Some("ada@gmail.com"));
        for identity in [
            "Ada Lovelace",
            "1234567890",
            "ada@gmail.com\r\nBcc: eve@example.com",
            "ada@gmail.com, eve@example.com",
            "",
        ] {
            assert_eq!(account(identity).address(), None, "{identity:?}");
        }
    }

    #[test]
    fn a_token_comes_back_with_an_expiry_and_no_refresh_token() {
        // The refresh token is GOA's and never crosses the bus. A credential
        // claiming to be renewable would be renewed against a token endpoint
        // that has never heard of it.
        let bus = PrivateBus::start();
        let _daemon = bus.serve(vec![FakeAccount::google("account_1", "ada@gmail.com")]);
        let service = OnlineAccounts::on(bus.connect()).unwrap().unwrap();

        let credential = service.access_token("account_1").expect("a token");

        assert_eq!(credential.access_token, "token-for-account_1");
        assert!(!credential.is_renewable());
        assert!(!credential.is_expired());
        assert!(
            credential.expires_at.is_some(),
            "with no expiry the token would be reused until the server refused it"
        );
    }

    #[test]
    fn a_grant_goa_cannot_renew_asks_for_a_sign_in_there() {
        let bus = PrivateBus::start();
        let _daemon = bus.serve(vec![FakeAccount {
            revoked: true,
            ..FakeAccount::google("account_1", "ada@gmail.com")
        }]);
        let service = OnlineAccounts::on(bus.connect()).unwrap().unwrap();

        let error = service.access_token("account_1").unwrap_err();

        assert!(error.needs_sign_in(), "got {error}");
        assert!(!error.is_transient());
        assert!(service.list().unwrap()[0].attention_needed);
    }

    #[test]
    fn an_account_removed_from_goa_asks_for_a_sign_in_rather_than_a_retry() {
        // Retrying would go on until somebody noticed; the account is gone.
        let bus = PrivateBus::start();
        let _daemon = bus.serve(vec![FakeAccount::google("account_1", "ada@gmail.com")]);
        let service = OnlineAccounts::on(bus.connect()).unwrap().unwrap();

        let error = service.access_token("account_9").unwrap_err();

        assert!(error.needs_sign_in(), "got {error}");
    }
}

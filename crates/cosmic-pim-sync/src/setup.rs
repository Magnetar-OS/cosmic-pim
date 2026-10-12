// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! From an address to a working account.
//!
//! Everything an "add an account" window has to decide, below the window. A
//! person types an address; [`plan`] says, with no network, which provider it
//! belongs to, which ways of signing in can work on this installation — best
//! first — and what the account will bring: mail, calendars, contacts. Then
//! one of three calls finishes the job and stores the account in the suite's
//! shared list, where Envelope, Slate and Circle all find it:
//!
//! - [`add_with_password`] — finds the servers, **tries the password**, and
//!   stores the account only if the server took it. A password stored
//!   untried fails an hour later as a sync error, far from the form where it
//!   could have been fixed.
//! - [`add_with_mail_servers`] and [`add_with_dav_url`] — the same, at
//!   servers the person named, for a domain whose servers cannot be found
//!   from the address.
//! - [`sign_in`] — the provider's own sign-in in the browser. The account is
//!   named after whoever actually signed in, not after what was typed.
//!   [`sign_in_with_provider`] is the same with the provider picked by the
//!   person, for an address on a domain of its own.
//! - [`link_online_account`] and [`adopt_online_accounts`] — an account whose
//!   sign-in GNOME Online Accounts keeps.
//!
//! # The routes, and their order
//!
//! A provider's own sign-in comes first when this installation has a client id
//! for it: it is this suite's registration, with the scopes its engines use.
//! Online Accounts comes next, where it is running and knows the provider.
//! A password comes last for a provider whose own route is the browser — for
//! Google that is an app password, and it reaches mail only.
//!
//! An address that belongs to no provider is a password account whose servers
//! are found from the address when it is added.

use cosmic_pim_accounts::{Account, AccountStore, OAuthCredential, Provider, Registry};
use cosmic_pim_auth::{OnlineAccount, OnlineAccounts};

/// Where GOA-held accounts come from: the daemon, or a stand-in in a test.
pub trait OnlineAccountSource {
    /// Every account the source holds that carries an OAuth grant.
    fn list(&self) -> Result<Vec<OnlineAccount>, cosmic_pim_auth::Error>;
    /// A current access token for the account the source calls `id`.
    fn access_token(&self, id: &str) -> Result<OAuthCredential, cosmic_pim_auth::Error>;
}

impl OnlineAccountSource for OnlineAccounts {
    fn list(&self) -> Result<Vec<OnlineAccount>, cosmic_pim_auth::Error> {
        OnlineAccounts::list(self)
    }

    fn access_token(&self, id: &str) -> Result<OAuthCredential, cosmic_pim_auth::Error> {
        OnlineAccounts::access_token(self, id)
    }
}

/// One way an address can sign in.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Route {
    /// The provider's own sign-in, in the user's browser.
    SignIn,
    /// Through GNOME Online Accounts, which holds a registration of its own.
    OnlineAccounts,
    /// A password — for most providers, an app password made for this.
    Password {
        /// What to tell the person first: where to make one, what it covers.
        hint: Option<String>,
        /// The page the hint is about.
        help_url: Option<String>,
    },
}

/// What an account would bring, by service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Services {
    pub mail: bool,
    pub calendar: bool,
    pub contacts: bool,
}

/// What an address means, before anything is asked of the network.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// The address, trimmed.
    pub address: String,
    /// The provider whose domain it is, when a manifest claims the domain.
    pub provider: Option<Provider>,
    /// Every way in that can work on this installation, best first.
    ///
    /// Empty means none can: an Outlook.com address where there is neither a
    /// client id for Microsoft nor Online Accounts. The window should say so
    /// rather than offer a password field that cannot succeed.
    pub routes: Vec<Route>,
}

impl Plan {
    /// What the account would bring if added by `route`.
    ///
    /// For an address no provider claims, mail is a hope rather than a
    /// promise — it is settled by autodiscovery when the account is added —
    /// and calendars and contacts are unknown until a server is named.
    #[must_use]
    pub fn services(&self, route: &Route) -> Services {
        let Some(provider) = &self.provider else {
            return Services {
                mail: true,
                ..Services::default()
            };
        };
        let everything = Services {
            mail: provider.services.mail.is_some(),
            calendar: provider.services.calendar.is_some(),
            contacts: provider.services.contacts.is_some(),
        };
        match route {
            Route::SignIn | Route::OnlineAccounts => everything,
            // The browser is the provider's own route, so a password is the
            // app-password fallback, and that reaches mail only.
            Route::Password { .. } if provider.oauth.is_some() => Services {
                mail: everything.mail,
                ..Services::default()
            },
            Route::Password { .. } => everything,
        }
    }
}

/// What an account already in the store brings, as the sync engine will see
/// it: mail when it has a mail server, calendars and contacts when there is
/// an address to find them at — its own, or its provider's.
#[must_use]
pub fn services_of(account: &Account, registry: &Registry) -> Services {
    use crate::engine::{Service, service_url};
    Services {
        mail: account.mail.is_some(),
        calendar: !service_url(account, registry, Service::Calendar).is_empty(),
        contacts: !service_url(account, registry, Service::Contacts).is_empty(),
    }
}

/// Works out what an address means. No network, cheap enough to call on
/// every keystroke.
///
/// `online_accounts` says whether GNOME Online Accounts is running here —
/// asked once, by the caller, rather than on every keystroke.
///
/// `None` when the text is not yet an address.
#[must_use]
pub fn plan(registry: &Registry, address: &str, online_accounts: bool) -> Option<Plan> {
    let address = address.trim();
    let (local, domain) = address.rsplit_once('@')?;
    if local.is_empty() || !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.')
    {
        return None;
    }

    let provider = registry.for_email(address).cloned();
    let routes = match &provider {
        None => vec![Route::Password {
            hint: None,
            help_url: None,
        }],
        Some(provider) => match &provider.oauth {
            None => vec![Route::Password {
                hint: provider.hint.clone(),
                help_url: provider.help_url.clone(),
            }],
            Some(oauth) => {
                let mut routes = Vec::new();
                if oauth.is_configured() {
                    routes.push(Route::SignIn);
                }
                if online_accounts && cosmic_pim_auth::online_accounts::serves(&provider.id) {
                    routes.push(Route::OnlineAccounts);
                }
                if let Some(fallback) = &provider.app_password {
                    routes.push(Route::Password {
                        hint: Some(fallback.hint.clone()),
                        help_url: fallback.help_url.clone(),
                    });
                }
                routes
            }
        },
    };

    Some(Plan {
        address: address.to_owned(),
        provider,
        routes,
    })
}

/// Why an account could not be added.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SetupError {
    /// The server refused the password. The provider's hint, where it has
    /// one, is the most useful thing to show next to this.
    #[error("the password was not accepted: {0}")]
    Rejected(String),
    /// The server could not be reached. Worth trying again.
    #[error("the server could not be reached: {0}")]
    Unreachable(String),
    /// No servers could be found for the address, so they have to be named.
    #[error("no mail server could be found for this address: {0}")]
    NoServer(String),
    /// This way in cannot work for this address here — see [`Plan::routes`].
    #[error("this address cannot be added that way on this computer")]
    NoRoute,
    /// The sign-in did not complete.
    #[error(transparent)]
    SignIn(#[from] cosmic_pim_auth::Error),
    /// The account store refused the write.
    #[error(transparent)]
    Store(#[from] cosmic_pim_accounts::Error),
    /// Anything else the server said.
    #[error("{0}")]
    Failed(String),
}

/// Finds the servers for a password account, tries the password against them,
/// and stores the account if it was accepted.
///
/// Blocking: it may fetch an autoconfig document and it logs in to a server,
/// so it belongs on a worker thread. Returns the new account's id.
///
/// `name` is what the account is called, and the name on its mail; empty
/// means the address.
pub fn add_with_password(
    store: &mut AccountStore,
    registry: &Registry,
    plan: &Plan,
    name: &str,
    password: &str,
) -> Result<String, SetupError> {
    let mut account = password_account(plan)?;
    name_account(&mut account, name);

    verify(&account, registry, password)?;

    let id = account.id.clone();
    store.add(account, password)?;
    Ok(id)
}

/// Stores a password account at mail servers the person named, after logging
/// in to them with the password.
///
/// For an address whose servers cannot be found — a domain of its own with no
/// autoconfig — where the form asks for them instead. `mail` is everything it
/// asked: the protocol (`Imap`, `Pop3` or `Jmap`), the incoming server, the
/// submission server, and `imap_username` when the login is not the address.
/// `from_address` empty means `plan.address`.
///
/// The incoming login is tried first, then for IMAP and POP3 the SMTP login
/// (JMAP sends through its own session). Only when every login was accepted
/// is the account stored, under no provider: named servers are not a
/// manifest's, and naming one would send the password to its calendars too.
/// `Gmail` and `Graph` take a token, not a password, and are
/// [`SetupError::NoRoute`].
///
/// Blocking, so a worker call. Returns the new account's id. `name` is as for
/// [`add_with_password`].
#[cfg(feature = "mail")]
pub fn add_with_mail_servers(
    store: &mut AccountStore,
    plan: &Plan,
    name: &str,
    mut mail: cosmic_pim_accounts::MailEndpoint,
    password: &str,
) -> Result<String, SetupError> {
    use cosmic_pim_accounts::MailProtocol;

    if mail.from_address.trim().is_empty() {
        mail.from_address.clone_from(&plan.address);
    }
    let sends_by_smtp = matches!(mail.protocol, MailProtocol::Imap | MailProtocol::Pop3);
    let mut account = Account::new(&plan.address, "", &plan.address);
    account.mail = Some(mail);
    name_account(&mut account, name);

    log_in_to_mail(&account, password)?;
    if sends_by_smtp {
        log_in_to_smtp(&account, password)?;
    }

    let id = account.id.clone();
    store.add(account, password)?;
    Ok(id)
}

/// Stores a calendars-and-contacts account at a CalDAV or CardDAV address the
/// person typed, after logging in to it with the password.
///
/// `url` is where discovery starts — a server root, a principal or a home, as
/// for [`Account::url`]. `username` is the login; empty means `plan.address`.
/// The server is asked for its calendars first and, when it has none to
/// offer, for its address books, so a contacts-only server is accepted too.
/// A refused login is [`SetupError::Rejected`] and is not tried twice.
///
/// The account has no mail and no provider. Blocking. Returns the new
/// account's id. `name` is as for [`add_with_password`].
pub fn add_with_dav_url(
    store: &mut AccountStore,
    plan: &Plan,
    name: &str,
    url: &str,
    username: &str,
    password: &str,
) -> Result<String, SetupError> {
    use cosmic_pim_caldav::Flavor;

    let url = url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(SetupError::NoServer(format!(
            "“{}” is not a web address",
            url.escape_debug()
        )));
    }
    let login = match username.trim() {
        "" => plan.address.as_str(),
        login => login,
    };
    let mut account = Account::new(&plan.address, url, login);
    name_account(&mut account, name);

    if let Err(calendars) = log_in_to_dav(url, login, password, Flavor::CalDav) {
        if matches!(calendars, SetupError::Rejected(_)) {
            return Err(calendars);
        }
        log_in_to_dav(url, login, password, Flavor::CardDav).map_err(|_| calendars)?;
    }

    let id = account.id.clone();
    store.add(account, password)?;
    Ok(id)
}

/// The account a password would add, before anything is tried.
fn password_account(plan: &Plan) -> Result<Account, SetupError> {
    if !plan
        .routes
        .iter()
        .any(|route| matches!(route, Route::Password { .. }))
    {
        return Err(SetupError::NoRoute);
    }
    match &plan.provider {
        Some(provider) if provider.oauth.is_some() => provider
            .app_password_account(&plan.address)
            .ok_or(SetupError::NoRoute),
        Some(provider) => Ok(provider.account_for(&plan.address)),
        None => discovered_account(&plan.address),
    }
}

#[cfg(feature = "mail")]
fn discovered_account(address: &str) -> Result<Account, SetupError> {
    use cosmic_pim_accounts::{MailEndpoint, Transport};
    use cosmic_pim_mail::imap::Security;

    let found = cosmic_pim_mail::discovery::discover(address)
        .map_err(|why| SetupError::NoServer(why.to_string()))?;
    let transport = |security: Security| match security {
        Security::Tls => Transport::Tls,
        Security::StartTls => Transport::StartTls,
        Security::Plaintext => Transport::Plaintext,
    };

    let mut account = Account::new(address, "", address);
    account.mail = Some(MailEndpoint {
        imap_port: found.imap_port,
        imap_transport: transport(found.imap_security),
        // Only when it differs: most servers log in with the address, and an
        // account that restates it says the same thing twice.
        imap_username: Some(found.username).filter(|login| !login.is_empty() && login != address),
        smtp_host: found.smtp_host,
        smtp_port: found.smtp_port,
        smtp_transport: transport(found.smtp_security),
        from_address: address.to_owned(),
        ..MailEndpoint::tls(found.imap_host)
    });
    Ok(account)
}

/// Without the mail stack there is nothing to discover a mail server with;
/// the address's servers have to be named.
#[cfg(not(feature = "mail"))]
fn discovered_account(_address: &str) -> Result<Account, SetupError> {
    Err(SetupError::NoServer(
        "this application finds calendar and contacts servers only when they are named".to_owned(),
    ))
}

/// Logs in once, with the password, to the service the account will use.
///
/// Mail when it has mail — the login that fails most often, because it is the
/// one app passwords exist for — and the calendar server otherwise.
fn verify(account: &Account, registry: &Registry, password: &str) -> Result<(), SetupError> {
    if account.mail.is_some() {
        return verify_mail(account, registry, password);
    }
    verify_dav(account, registry, password)
}

#[cfg(feature = "mail")]
fn verify_mail(account: &Account, _registry: &Registry, password: &str) -> Result<(), SetupError> {
    log_in_to_mail(account, password)
}

/// Logs in once to the account's incoming mail server.
#[cfg(feature = "mail")]
fn log_in_to_mail(account: &Account, password: &str) -> Result<(), SetupError> {
    use cosmic_pim_accounts::{MailProtocol, Transport};
    use cosmic_pim_mail::imap::Security;
    use cosmic_pim_mail::{Credentials, imap, jmap, pop3};

    let Some(mail) = account.mail.as_ref() else {
        return Ok(());
    };
    let credentials = Credentials::Password(password.to_owned());
    let security = |transport: Transport| match transport {
        Transport::Tls => Security::Tls,
        Transport::StartTls => Security::StartTls,
        Transport::Plaintext => Security::Plaintext,
    };
    let login = account.mail_username().to_owned();

    let outcome = match mail.protocol {
        MailProtocol::Imap => imap::Session::connect(
            &imap::Endpoint {
                host: mail.imap_host.clone(),
                port: mail.imap_port,
                security: security(mail.imap_transport),
                username: login,
            },
            &credentials,
        )
        .map(drop),
        MailProtocol::Jmap => {
            let Some(url) = mail.jmap_session_url.as_deref() else {
                return Err(SetupError::NoServer("no JMAP session address".to_owned()));
            };
            jmap::Session::connect(url, &login, &credentials).map(drop)
        }
        MailProtocol::Pop3 => pop3::Session::connect(
            &pop3::Endpoint {
                host: mail.pop3_host.clone(),
                port: mail.pop3_port,
                security: security(mail.pop3_transport),
                username: login,
            },
            &credentials,
        )
        .map(drop),
        // Token engines: a password cannot drive them, and `password_account`
        // never builds one.
        MailProtocol::Gmail | MailProtocol::Graph => return Err(SetupError::NoRoute),
    };

    outcome.map_err(mail_setup_error)
}

/// Logs in once to the account's submission server, sending nothing.
#[cfg(feature = "mail")]
fn log_in_to_smtp(account: &Account, password: &str) -> Result<(), SetupError> {
    let Some(mail) = account.mail.as_ref() else {
        return Ok(());
    };
    cosmic_pim_mail::smtp::verify(
        &crate::mail::smtp_endpoint(account, mail),
        &cosmic_pim_mail::Credentials::Password(password.to_owned()),
    )
    .map_err(mail_setup_error)
}

/// What a failed mail login means to someone adding an account.
#[cfg(feature = "mail")]
fn mail_setup_error(why: cosmic_pim_mail::Error) -> SetupError {
    match why {
        cosmic_pim_mail::Error::Auth(reason) => SetupError::Rejected(reason),
        // A refused connection is not transient to a sync loop, but to
        // someone adding an account it is the most useful thing to hear:
        // Proton Mail Bridge is not running, or the port is wrong.
        other @ (cosmic_pim_mail::Error::Io(_) | cosmic_pim_mail::Error::Transport { .. }) => {
            SetupError::Unreachable(other.to_string())
        }
        other if other.is_transient() => SetupError::Unreachable(other.to_string()),
        other => SetupError::Failed(other.to_string()),
    }
}

/// Without the mail stack a mail login cannot be tried, and an account with
/// mail is stored as it is: its calendar, if any, is tried instead.
#[cfg(not(feature = "mail"))]
fn verify_mail(account: &Account, registry: &Registry, password: &str) -> Result<(), SetupError> {
    verify_dav(account, registry, password)
}

/// Finds the principal on the account's calendar server, which needs a login.
fn verify_dav(account: &Account, registry: &Registry, password: &str) -> Result<(), SetupError> {
    let url = crate::engine::service_url(account, registry, crate::engine::Service::Calendar);
    if url.is_empty() {
        // Nothing to log in to: an account with neither mail nor a calendar
        // address was never going to sync, and the form should not have let
        // it through. Stored as it is rather than refused on a technicality.
        return Ok(());
    }
    log_in_to_dav(
        &url,
        &account.username,
        password,
        cosmic_pim_caldav::Flavor::CalDav,
    )
}

/// Finds the principal and the `flavor`'s home at `url`, which needs a login.
fn log_in_to_dav(
    url: &str,
    username: &str,
    password: &str,
    flavor: cosmic_pim_caldav::Flavor,
) -> Result<(), SetupError> {
    use cosmic_pim_caldav::{Auth, CaldavClient, Disposition};

    let auth = Auth::Basic {
        username: username.to_owned(),
        password: password.to_owned(),
    };
    CaldavClient::with_auth(url, flavor, &auth)
        .discover()
        .map_err(|why| match why.disposition() {
            Disposition::NeedsUser => SetupError::Rejected(why.to_string()),
            Disposition::Retry => SetupError::Unreachable(why.to_string()),
            Disposition::Reconcile | Disposition::Fatal => SetupError::Failed(why.to_string()),
        })
}

/// The name an account shows and puts on its mail.
fn name_account(account: &mut Account, name: &str) {
    let name = name.trim();
    if !name.is_empty() {
        account.display_name = name.to_owned();
    }
    if let Some(mail) = account.mail.as_mut() {
        mail.from_name = name.to_owned();
    }
}

/// Runs the provider's own sign-in, start to finish, and stores the account.
///
/// Blocking for up to the flow's five-minute redirect deadline, so strictly a
/// worker call. `open` is handed the authorize URL and must open it in the
/// user's own browser — see `cosmic_pim_auth::flow` for why never an embedded
/// view.
///
/// The account is named after whoever signed in, which the provider says in
/// the grant. The typed address is used only for a provider that does not.
/// Returns the new account's id.
pub fn sign_in(
    store: &mut AccountStore,
    plan: &Plan,
    open: impl FnOnce(&str) -> std::io::Result<()>,
) -> Result<String, SetupError> {
    let provider = plan.provider.as_ref().ok_or(SetupError::NoRoute)?;
    sign_in_with_provider(store, provider, &plan.address, open)
}

/// [`sign_in`] at a provider the person picked, rather than the one the
/// address's domain belongs to.
///
/// For an address on a domain of its own whose mail a provider hosts — Google
/// Workspace, Microsoft 365 — which no manifest can claim, so [`plan`] finds
/// no provider for it. `provider` is from the [`Registry`]; it must have an
/// OAuth client id configured here, or this is [`SetupError::NoRoute`].
/// `address` is used only when the grant does not say who signed in.
///
/// Blocking, as [`sign_in`]. Returns the new account's id.
pub fn sign_in_with_provider(
    store: &mut AccountStore,
    provider: &Provider,
    address: &str,
    open: impl FnOnce(&str) -> std::io::Result<()>,
) -> Result<String, SetupError> {
    let oauth = provider
        .oauth
        .as_ref()
        .filter(|oauth| oauth.is_configured())
        .ok_or(SetupError::NoRoute)?;

    let pending = cosmic_pim_auth::begin(oauth)?;
    open(pending.authorize_url())
        .map_err(|why| SetupError::Failed(format!("the browser could not be opened: {why}")))?;
    let code = pending.wait()?;
    let grant = pending.exchange(&code, oauth)?;

    let (address, name) = grant.identity.as_ref().map_or_else(
        || (address.trim().to_owned(), None),
        |identity| (identity.email.clone(), identity.name.clone()),
    );
    let mut account = provider.account_for(&address);
    if let Some(name) = name {
        name_account(&mut account, &name);
    }
    let id = account.id.clone();
    store.add_oauth(account, &provider.id, &grant.credential)?;
    Ok(id)
}

/// Adds the account Online Accounts holds as `online`, or finds it if it is
/// already here.
///
/// A token is asked for first, so an account that GOA cannot actually sign
/// in to is reported now rather than stored broken. Returns the account's id,
/// which is the same every time for the same GOA account.
pub fn link_online_account(
    store: &mut AccountStore,
    registry: &Registry,
    service: &impl OnlineAccountSource,
    online: &OnlineAccount,
) -> Result<String, SetupError> {
    let provider = online
        .provider_id()
        .and_then(|id| registry.get(id))
        .ok_or(SetupError::NoRoute)?;

    // Both arrive over the session bus, and both end up somewhere a stray
    // character matters: the id in file names, the identity as a login and a
    // `From` address.
    let address = online.address().ok_or_else(|| {
        SetupError::Failed(format!(
            "Online Accounts names this account “{}”, which is not a mail address",
            online.identity.escape_debug()
        ))
    })?;
    let mut account =
        Account::for_online_account(&provider.name, address, &provider.id, &online.id).ok_or_else(
            || {
                SetupError::Failed(format!(
                    "Online Accounts gave this account an id that cannot be used: “{}”",
                    online.id.escape_debug()
                ))
            },
        )?;
    if let Some(existing) = store.get(&account.id) {
        return Ok(existing.id.clone());
    }
    account.mail = provider
        .services
        .mail
        .as_ref()
        .filter(|_| !online.mail_disabled)
        .map(|mail| mail.endpoint_for(address));

    let credential = service.access_token(&online.id)?;
    let id = account.id.clone();
    store.add_oauth(account, &provider.id, &credential)?;
    Ok(id)
}

/// What [`adopt_online_accounts`] changed.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Adopted {
    /// Accounts linked for the first time, by id.
    pub linked: Vec<String>,
    /// Accounts removed here because Online Accounts no longer has them.
    pub removed: Vec<String>,
    /// GOA accounts that could not be linked, by GOA id, with the reason.
    pub failed: Vec<(String, String)>,
}

/// Brings the account list in step with Online Accounts: every GOA account
/// with a provider this suite can use is linked, and every linked account GOA
/// no longer has is removed.
///
/// Removal is only ever decided from a successful listing. GOA not running
/// is not "GOA has no accounts" — that is the difference between a daemon
/// that has not started yet and an instruction to delete everything.
pub fn adopt_online_accounts(
    store: &mut AccountStore,
    registry: &Registry,
    service: &impl OnlineAccountSource,
) -> Result<Adopted, SetupError> {
    let online = service.list()?;
    let mut adopted = Adopted::default();

    for account in &online {
        if account.provider_id().is_none() {
            continue;
        }
        let already = store
            .accounts()
            .iter()
            .any(|known| known.online_account() == Some(account.id.as_str()));
        if already {
            continue;
        }
        match link_online_account(store, registry, service, account) {
            Ok(id) => adopted.linked.push(id),
            Err(why) => adopted.failed.push((account.id.clone(), why.to_string())),
        }
    }

    let gone: Vec<String> = store
        .accounts()
        .iter()
        .filter(|known| {
            known
                .online_account()
                .is_some_and(|id| !online.iter().any(|account| account.id == id))
        })
        .map(|known| known.id.clone())
        .collect();
    for id in gone {
        store.remove(&id)?;
        adopted.removed.push(id);
    }

    Ok(adopted)
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;

    use cosmic_pim_accounts::{MailProtocol, SecretStore};

    use super::*;

    fn store_at(dir: &Path) -> AccountStore {
        let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir);
        AccountStore::open(&dir.join("accounts.toml"), secrets).unwrap()
    }

    fn built_in() -> Registry {
        Registry::load_from(Path::new("/nonexistent"))
    }

    fn routes(plan: &Plan) -> Vec<&'static str> {
        plan.routes
            .iter()
            .map(|route| match route {
                Route::SignIn => "sign-in",
                Route::OnlineAccounts => "online-accounts",
                Route::Password { .. } => "password",
            })
            .collect()
    }

    #[test]
    fn a_stored_account_says_what_it_brings() {
        let registry = built_in();
        let fastmail = registry
            .get("fastmail")
            .unwrap()
            .account_for("ada@fastmail.com");
        let gmail_by_password = registry
            .get("google")
            .unwrap()
            .app_password_account("ada@gmail.com")
            .unwrap();

        assert_eq!(
            services_of(&fastmail, &registry),
            Services {
                mail: true,
                calendar: true,
                contacts: true
            }
        );
        assert_eq!(
            services_of(&gmail_by_password, &registry),
            Services {
                mail: true,
                ..Services::default()
            }
        );
    }

    #[test]
    fn text_that_is_not_yet_an_address_has_no_plan() {
        for text in ["", "ada", "ada@", "@example.com", "ada@example", "ada@.com"] {
            assert!(plan(&built_in(), text, true).is_none(), "{text:?}");
        }
    }

    #[test]
    fn a_password_provider_asks_for_its_own_kind_of_password() {
        let plan = plan(&built_in(), " ada@fastmail.com ", false).unwrap();

        assert_eq!(plan.address, "ada@fastmail.com");
        let [Route::Password { hint, help_url }] = plan.routes.as_slice() else {
            panic!("expected a password, got {:?}", plan.routes);
        };
        assert!(
            hint.as_deref()
                .is_some_and(|hint| hint.contains("app password"))
        );
        assert!(help_url.is_some());
        assert_eq!(
            plan.services(&plan.routes[0]),
            Services {
                mail: true,
                calendar: true,
                contacts: true
            }
        );
    }

    #[test]
    fn gmail_with_no_client_id_offers_what_does_work_best_first() {
        let without = plan(&built_in(), "ada@gmail.com", false).unwrap();
        assert_eq!(routes(&without), ["password"]);
        assert_eq!(
            without.services(&without.routes[0]),
            Services {
                mail: true,
                ..Services::default()
            },
            "an app password reaches mail only, and the window has to say so"
        );

        let with_goa = plan(&built_in(), "ada@gmail.com", true).unwrap();
        assert_eq!(routes(&with_goa), ["online-accounts", "password"]);
        assert!(with_goa.services(&with_goa.routes[0]).calendar);
    }

    #[test]
    fn a_configured_client_id_puts_the_providers_own_sign_in_first() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("google.toml"),
            "id = \"google\"\n[oauth]\nclient_id = \"magnetar.apps.googleusercontent.com\"\n",
        )
        .unwrap();

        let plan = plan(&Registry::load_from(dir.path()), "ada@gmail.com", true).unwrap();

        assert_eq!(routes(&plan), ["sign-in", "online-accounts", "password"]);
    }

    #[test]
    fn outlook_with_neither_a_client_id_nor_online_accounts_has_no_way_in() {
        // Microsoft takes no password for Outlook.com. An empty list is the
        // honest answer; a password field would fail every time.
        let alone = plan(&built_in(), "ada@outlook.com", false).unwrap();
        assert_eq!(alone.routes, []);

        let with_goa = plan(&built_in(), "ada@outlook.com", true).unwrap();
        assert_eq!(routes(&with_goa), ["online-accounts"]);
    }

    #[test]
    fn an_address_no_provider_claims_is_a_password_account_for_mail() {
        let plan = plan(&built_in(), "ada@uni.example", true).unwrap();

        assert!(plan.provider.is_none());
        assert_eq!(routes(&plan), ["password"]);
        let services = plan.services(&plan.routes[0]);
        assert!(services.mail && !services.calendar && !services.contacts);
    }

    /// A plaintext IMAP server on loopback that takes one login, and accepts
    /// it only with `password`.
    fn imap_server(password: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut out = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let _ = write!(out, "* OK ready\r\n");
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                let command = line.trim_end().to_owned();
                line.clear();
                let (tag, rest) = command.split_once(' ').unwrap_or((&command, ""));
                let upper = rest.to_ascii_uppercase();
                let _ = if upper.starts_with("LOGIN") {
                    if rest.ends_with(&format!(" \"{password}\""))
                        || rest.ends_with(&format!(" {password}"))
                    {
                        write!(out, "{tag} OK logged in\r\n")
                    } else {
                        write!(
                            out,
                            "{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n"
                        )
                    }
                } else if upper.starts_with("CAPABILITY") {
                    write!(out, "* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n")
                } else if upper.starts_with("LOGOUT") {
                    let _ = write!(out, "* BYE\r\n{tag} OK done\r\n");
                    break;
                } else {
                    write!(out, "{tag} OK done\r\n")
                };
            }
        });
        port
    }

    /// A registry with a provider whose mail server is on `port` of this
    /// machine, claiming `example.test`.
    fn local_provider(dir: &Path, port: u16) -> Registry {
        std::fs::write(
            dir.join("local.toml"),
            format!(
                "id = \"local\"\nname = \"Local Mail\"\nhint = \"Use the password the server gave you.\"\n\
                 domains = [\"example.test\"]\n\n[services.mail]\nprotocol = \"imap\"\n\
                 imap_host = \"127.0.0.1\"\nimap_port = {port}\nimap_transport = \"plaintext\"\n\
                 smtp_host = \"127.0.0.1\"\nsmtp_port = 1\nsmtp_transport = \"plaintext\"\n"
            ),
        )
        .unwrap();
        Registry::load_from(dir)
    }

    #[test]
    fn a_password_the_server_accepts_is_stored_with_the_whole_account() {
        let dir = tempfile::tempdir().unwrap();
        let registry = local_provider(dir.path(), imap_server("right"));
        let mut store = store_at(dir.path());
        let plan = plan(&registry, "ada@example.test", false).unwrap();

        let id = add_with_password(&mut store, &registry, &plan, "Ada Lovelace", "right")
            .expect("the password was right");

        let account = store.get(&id).expect("stored");
        assert_eq!(account.display_name, "Ada Lovelace");
        assert_eq!(
            account.provider.as_deref(),
            Some("local"),
            "without the provider, Slate and Circle cannot find its calendars"
        );
        let mail = account.mail.as_ref().expect("mail endpoints");
        assert_eq!(mail.imap_host, "127.0.0.1");
        assert_eq!(mail.from_name, "Ada Lovelace");
        assert_eq!(store.password(&id).unwrap().as_deref(), Some("right"));
    }

    #[test]
    fn a_password_the_server_refuses_is_not_stored() {
        // Stored untried, it would fail an hour later as a sync error, far
        // from the form where it could have been corrected.
        let dir = tempfile::tempdir().unwrap();
        let registry = local_provider(dir.path(), imap_server("right"));
        let mut store = store_at(dir.path());
        let plan = plan(&registry, "ada@example.test", false).unwrap();

        let error = add_with_password(&mut store, &registry, &plan, "", "wrong").unwrap_err();

        assert!(matches!(error, SetupError::Rejected(_)), "got {error}");
        assert_eq!(store.accounts(), []);
    }

    #[test]
    fn a_server_that_is_not_listening_is_unreachable_not_a_wrong_password() {
        // Proton Mail Bridge not running looks exactly like this, and "your
        // password is wrong" would send the user to change a password that
        // is fine.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = tempfile::tempdir().unwrap();
        let registry = local_provider(dir.path(), port);
        let mut store = store_at(dir.path());
        let plan = plan(&registry, "ada@example.test", false).unwrap();

        let error = add_with_password(&mut store, &registry, &plan, "", "right").unwrap_err();

        assert!(matches!(error, SetupError::Unreachable(_)), "got {error}");
        assert_eq!(store.accounts(), []);
    }

    #[test]
    fn a_password_cannot_add_an_account_that_has_no_password_route() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let plan = plan(&built_in(), "ada@outlook.com", false).unwrap();

        let error = add_with_password(&mut store, &built_in(), &plan, "", "x").unwrap_err();

        assert!(matches!(error, SetupError::NoRoute));
    }

    #[test]
    fn a_gmail_app_password_makes_an_imap_account_with_no_provider() {
        // The Gmail engine and Google's DAV endpoints take a token; naming
        // the provider would send the password there on every pass.
        let plan = plan(&built_in(), "ada@gmail.com", false).unwrap();

        let account = password_account(&plan).unwrap();

        assert_eq!(account.provider, None);
        let mail = account.mail.unwrap();
        assert_eq!(mail.protocol, MailProtocol::Imap);
        assert_eq!(mail.imap_host, "imap.gmail.com");
    }

    /// Answers the authorization redirect the way a browser would once the
    /// user has signed in.
    fn browser(url: &str) -> std::io::Result<()> {
        let port: u16 = url
            .split("redirect_uri=http%3A%2F%2F127.0.0.1%3A")
            .nth(1)
            .and_then(|rest| rest.split("%2F").next())
            .and_then(|port| port.parse().ok())
            .expect("a loopback redirect in the authorize URL");
        let state = url
            .split(['?', '&'])
            .find_map(|pair| pair.strip_prefix("state="))
            .expect("a state in the authorize URL")
            .to_owned();
        std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let _ = write!(
                stream,
                "GET /callback?code=the-code&state={state} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            );
            let _ = std::io::Read::read_to_end(&mut stream, &mut Vec::new());
        });
        Ok(())
    }

    /// A token endpoint that answers once with a grant for Grace, whoever
    /// typed what.
    fn token_endpoint() -> String {
        token_endpoint_for("grace@gmail.com")
    }

    /// A token endpoint that answers once with a grant for `email`.
    fn token_endpoint_for(email: &'static str) -> String {
        use base64::Engine as _;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        std::thread::spawn(move || {
            if let Ok(request) = server.recv() {
                let header = "Content-Type: application/json"
                    .parse::<tiny_http::Header>()
                    .unwrap();
                // `e30` is `{}`; the payload is the claims below, for the
                // client id the manifest in the test names.
                let claims = format!(
                    r#"{{"aud":"test","exp":{},"email":"{email}","name":"Grace Hopper"}}"#,
                    chrono::Utc::now().timestamp() + 3600
                );
                let body = format!(
                    r#"{{"access_token":"at","refresh_token":"rt","expires_in":3600,"id_token":"e30.{}.sig"}}"#,
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims)
                );
                let _ = request.respond(tiny_http::Response::from_string(body).with_header(header));
            }
        });
        format!("http://127.0.0.1:{port}/token")
    }

    #[test]
    fn a_sign_in_names_the_account_after_whoever_signed_in() {
        // Typed one address, signed in to the other in the browser: the grant
        // is Grace's, so the account must be too.
        let dir = tempfile::tempdir().unwrap();
        let redirect_port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        std::fs::write(
            dir.path().join("google.toml"),
            format!(
                "id = \"google\"\n[oauth]\nclient_id = \"test\"\ntoken_url = \"{}\"\n\
                 redirect_port = {redirect_port}\n",
                token_endpoint()
            ),
        )
        .unwrap();
        let registry = Registry::load_from(dir.path());
        let mut store = store_at(dir.path());
        let plan = plan(&registry, "ada@gmail.com", false).unwrap();

        let id = sign_in(&mut store, &plan, browser).expect("signed in");

        let account = store.get(&id).unwrap();
        assert_eq!(account.username, "grace@gmail.com");
        assert_eq!(account.display_name, "Grace Hopper");
        assert_eq!(account.provider.as_deref(), Some("google"));
        assert!(account.is_oauth());
        assert_eq!(
            account.mail.as_ref().unwrap().protocol,
            MailProtocol::Gmail,
            "a signed-in Google account uses the Gmail engine"
        );
        assert!(store.credential(&id).unwrap().unwrap().is_renewable());
    }

    /// A Google manifest with a client id, its token endpoint answering for
    /// `email`.
    fn google_for(dir: &Path, email: &'static str) -> Registry {
        let redirect_port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        std::fs::write(
            dir.join("google.toml"),
            format!(
                "id = \"google\"\n[oauth]\nclient_id = \"test\"\ntoken_url = \"{}\"\n\
                 redirect_port = {redirect_port}\n",
                token_endpoint_for(email)
            ),
        )
        .unwrap();
        Registry::load_from(dir)
    }

    #[test]
    fn an_address_on_its_own_domain_signs_in_at_the_provider_the_person_picked() {
        // Google Workspace on company.example: no manifest claims the domain,
        // so the address alone finds no way to sign in.
        let dir = tempfile::tempdir().unwrap();
        let registry = google_for(dir.path(), "ada@company.example");
        let mut store = store_at(dir.path());
        let plan = plan(&registry, "ada@company.example", false).unwrap();
        assert!(plan.provider.is_none());
        assert!(matches!(
            sign_in(&mut store, &plan, browser),
            Err(SetupError::NoRoute)
        ));

        let google = registry.get("google").unwrap();
        let id =
            sign_in_with_provider(&mut store, google, &plan.address, browser).expect("signed in");

        let account = store.get(&id).unwrap();
        assert_eq!(account.username, "ada@company.example");
        assert_eq!(account.provider.as_deref(), Some("google"));
        assert!(account.is_oauth());
        assert_eq!(
            account.mail.as_ref().unwrap().protocol,
            MailProtocol::Gmail,
            "a Workspace account uses the Gmail engine like any other"
        );
    }

    #[test]
    fn a_picked_provider_with_no_client_id_here_cannot_sign_in() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let registry = built_in();
        let google = registry.get("google").unwrap();

        let error = sign_in_with_provider(&mut store, google, "ada@company.example", |_| {
            panic!("no browser may open without a client id")
        })
        .unwrap_err();

        assert!(matches!(error, SetupError::NoRoute), "got {error}");
        assert_eq!(store.accounts(), []);
    }

    /// A plaintext submission server on loopback that takes one login, and
    /// accepts it only with `password`.
    #[cfg(feature = "mail")]
    fn smtp_server(password: &'static str) -> u16 {
        use base64::Engine as _;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut out = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let _ = write!(out, "220 local ESMTP\r\n");
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                let command = line.trim_end().to_owned();
                line.clear();
                let upper = command.to_ascii_uppercase();
                let _ = if upper.starts_with("EHLO") {
                    write!(out, "250-local\r\n250 AUTH PLAIN\r\n")
                } else if let Some(token) = command.strip_prefix("AUTH PLAIN ") {
                    // `\0login\0password`, base64.
                    let given = base64::engine::general_purpose::STANDARD
                        .decode(token)
                        .unwrap_or_default();
                    if given.ends_with(format!("\0{password}").as_bytes()) {
                        write!(out, "235 2.7.0 Authentication successful\r\n")
                    } else {
                        write!(out, "535 5.7.8 Authentication credentials invalid\r\n")
                    }
                } else if upper == "QUIT" {
                    let _ = write!(out, "221 Bye\r\n");
                    break;
                } else {
                    write!(out, "250 Ok\r\n")
                };
            }
        });
        port
    }

    /// IMAP and SMTP on loopback, as a form would collect them.
    #[cfg(feature = "mail")]
    fn named_servers(imap_port: u16, smtp_port: u16) -> cosmic_pim_accounts::MailEndpoint {
        use cosmic_pim_accounts::{MailEndpoint, Transport};
        MailEndpoint {
            imap_port,
            imap_transport: Transport::Plaintext,
            smtp_host: "127.0.0.1".to_owned(),
            smtp_port,
            smtp_transport: Transport::Plaintext,
            ..MailEndpoint::tls("127.0.0.1")
        }
    }

    #[cfg(feature = "mail")]
    #[test]
    fn named_mail_servers_that_take_the_password_are_stored() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let plan = plan(&built_in(), "ada@nowhere.example", false).unwrap();
        let servers = named_servers(imap_server("right"), smtp_server("right"));

        let id = add_with_mail_servers(&mut store, &plan, "Ada", servers, "right")
            .expect("both logins were accepted");

        let account = store.get(&id).unwrap();
        assert_eq!(account.provider, None);
        assert_eq!(account.username, "ada@nowhere.example");
        let mail = account.mail.as_ref().unwrap();
        assert_eq!(mail.from_address, "ada@nowhere.example");
        assert_eq!(mail.from_name, "Ada");
        assert_eq!(mail.smtp_host, "127.0.0.1");
        assert_eq!(store.password(&id).unwrap().as_deref(), Some("right"));
    }

    #[cfg(feature = "mail")]
    #[test]
    fn named_servers_are_not_stored_when_the_submission_server_refuses_the_password() {
        // The incoming server took it and the outgoing one did not: stored,
        // the account would read mail and fail on the first send.
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let plan = plan(&built_in(), "ada@nowhere.example", false).unwrap();
        let servers = named_servers(imap_server("right"), smtp_server("other"));

        let error = add_with_mail_servers(&mut store, &plan, "", servers, "right").unwrap_err();

        assert!(matches!(error, SetupError::Rejected(_)), "got {error}");
        assert_eq!(store.accounts(), []);
    }

    #[cfg(feature = "mail")]
    #[test]
    fn named_servers_are_not_stored_when_the_incoming_server_refuses_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let plan = plan(&built_in(), "ada@nowhere.example", false).unwrap();
        let servers = named_servers(imap_server("right"), smtp_server("wrong"));

        let error = add_with_mail_servers(&mut store, &plan, "", servers, "wrong").unwrap_err();

        assert!(matches!(error, SetupError::Rejected(_)), "got {error}");
        assert_eq!(store.accounts(), []);
    }

    #[cfg(feature = "mail")]
    #[test]
    fn a_token_engine_cannot_be_named_with_a_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let plan = plan(&built_in(), "ada@nowhere.example", false).unwrap();
        let servers = cosmic_pim_accounts::MailEndpoint {
            protocol: MailProtocol::Gmail,
            ..named_servers(1, 1)
        };

        let error = add_with_mail_servers(&mut store, &plan, "", servers, "x").unwrap_err();

        assert!(matches!(error, SetupError::NoRoute), "got {error}");
        assert_eq!(store.accounts(), []);
    }

    /// A WebDAV server on loopback that knows `ada` by `password`, with an
    /// address book home and — when `calendars` — a calendar home.
    fn dav_server(password: &'static str, calendars: bool) -> String {
        use base64::Engine as _;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("ada:{password}"))
        );
        std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let authorized = request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("Authorization") && h.value.as_str() == expected);
                if !authorized {
                    let challenge = "WWW-Authenticate: Basic realm=\"dav\""
                        .parse::<tiny_http::Header>()
                        .unwrap();
                    let _ = request.respond(
                        tiny_http::Response::from_string("")
                            .with_status_code(401)
                            .with_header(challenge),
                    );
                    continue;
                }
                let mut body = String::new();
                let _ = std::io::Read::read_to_string(request.as_reader(), &mut body);
                let prop = if body.contains("current-user-principal") {
                    "<D:current-user-principal><D:href>/principal/</D:href></D:current-user-principal>"
                } else if body.contains("calendar-home-set") && calendars {
                    "<C:calendar-home-set><D:href>/calendars/</D:href></C:calendar-home-set>"
                } else if body.contains("addressbook-home-set") {
                    "<C:addressbook-home-set><D:href>/contacts/</D:href></C:addressbook-home-set>"
                } else {
                    ""
                };
                let xml = format!(
                    "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\" \
                     xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:response><D:href>{}</D:href>\
                     <D:propstat><D:prop>{prop}</D:prop><D:status>HTTP/1.1 200 OK</D:status>\
                     </D:propstat></D:response></D:multistatus>",
                    request.url()
                );
                let header = "Content-Type: application/xml; charset=utf-8"
                    .parse::<tiny_http::Header>()
                    .unwrap();
                let _ = request.respond(
                    tiny_http::Response::from_string(xml)
                        .with_status_code(207)
                        .with_header(header),
                );
            }
        });
        format!("http://127.0.0.1:{port}/")
    }

    #[test]
    fn a_typed_dav_address_that_takes_the_password_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let plan = plan(&built_in(), "ada@nowhere.example", false).unwrap();
        let url = dav_server("right", true);

        let id = add_with_dav_url(&mut store, &plan, "Ada", &url, "ada", "right")
            .expect("the login was accepted");

        let account = store.get(&id).unwrap();
        assert_eq!(account.url, url);
        assert_eq!(account.username, "ada");
        assert_eq!(account.display_name, "Ada");
        assert_eq!(account.provider, None);
        assert!(account.mail.is_none());
        assert_eq!(store.password(&id).unwrap().as_deref(), Some("right"));
    }

    #[test]
    fn a_typed_dav_address_that_refuses_the_password_is_rejected_not_unreachable() {
        // A wrong password reported as "could not be reached" sends the
        // person to check a server address that is right.
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let plan = plan(&built_in(), "ada@nowhere.example", false).unwrap();
        let url = dav_server("right", true);

        let error = add_with_dav_url(&mut store, &plan, "", &url, "ada", "wrong").unwrap_err();

        assert!(matches!(error, SetupError::Rejected(_)), "got {error}");
        assert_eq!(store.accounts(), []);
    }

    #[test]
    fn a_contacts_only_dav_server_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let plan = plan(&built_in(), "ada@nowhere.example", false).unwrap();
        let url = dav_server("right", false);

        let id = add_with_dav_url(&mut store, &plan, "", &url, "ada", "right")
            .expect("the address book home was found");

        assert_eq!(store.get(&id).unwrap().url, url);
    }

    #[test]
    fn text_that_is_not_a_web_address_is_not_tried() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let plan = plan(&built_in(), "ada@nowhere.example", false).unwrap();

        let error =
            add_with_dav_url(&mut store, &plan, "", "dav.nowhere.example", "", "x").unwrap_err();

        assert!(matches!(error, SetupError::NoServer(_)), "got {error}");
        assert_eq!(store.accounts(), []);
    }

    /// Online Accounts, as a list held in memory.
    struct FakeSource {
        accounts: Vec<OnlineAccount>,
        listing_fails: bool,
        refuses: Vec<&'static str>,
    }

    impl FakeSource {
        fn with(accounts: &[(&str, &str, &str)]) -> Self {
            Self {
                accounts: accounts
                    .iter()
                    .map(|(id, kind, identity)| OnlineAccount::new(id, kind, identity))
                    .collect(),
                listing_fails: false,
                refuses: Vec::new(),
            }
        }
    }

    impl OnlineAccountSource for FakeSource {
        fn list(&self) -> Result<Vec<OnlineAccount>, cosmic_pim_auth::Error> {
            if self.listing_fails {
                return Err(cosmic_pim_auth::Error::Transport(
                    "the daemon went away".into(),
                ));
            }
            Ok(self.accounts.clone())
        }

        fn access_token(&self, id: &str) -> Result<OAuthCredential, cosmic_pim_auth::Error> {
            if self.refuses.contains(&id) {
                return Err(cosmic_pim_auth::Error::GrantRejected("expired".into()));
            }
            Ok(OAuthCredential {
                access_token: format!("token-{id}"),
                refresh_token: None,
                expires_at: None,
                scopes: Vec::new(),
                token_type: "Bearer".into(),
            })
        }
    }

    #[test]
    fn online_accounts_are_linked_once_each() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let source = FakeSource::with(&[
            ("account_1", "google", "ada@gmail.com"),
            ("account_2", "ms_graph", "ada@outlook.com"),
            // Nothing this suite can use.
            ("account_3", "kerberos", "ada@EXAMPLE.COM"),
        ]);

        let first = adopt_online_accounts(&mut store, &built_in(), &source).unwrap();
        let again = adopt_online_accounts(&mut store, &built_in(), &source).unwrap();

        assert_eq!(first.linked.len(), 2);
        assert!(again.linked.is_empty(), "a second pass linked a duplicate");
        assert_eq!(store.accounts().len(), 2);
        let outlook = store
            .accounts()
            .iter()
            .find(|account| account.online_account() == Some("account_2"))
            .unwrap();
        assert_eq!(outlook.provider.as_deref(), Some("microsoft"));
        assert_eq!(outlook.username, "ada@outlook.com");
        assert_eq!(
            outlook.mail.as_ref().unwrap().protocol,
            MailProtocol::Graph,
            "Microsoft's engine is Graph, whoever holds the grant"
        );
    }

    #[test]
    fn an_account_removed_from_online_accounts_is_removed_here_and_nothing_else_is() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let mine = Account::new("Fastmail", "", "ada@fastmail.com");
        let mine_id = mine.id.clone();
        store.add(mine, "app-password").unwrap();
        adopt_online_accounts(
            &mut store,
            &built_in(),
            &FakeSource::with(&[
                ("account_1", "google", "ada@gmail.com"),
                ("account_2", "google", "grace@gmail.com"),
            ]),
        )
        .unwrap();

        let after = adopt_online_accounts(
            &mut store,
            &built_in(),
            &FakeSource::with(&[("account_2", "google", "grace@gmail.com")]),
        )
        .unwrap();

        assert_eq!(after.removed, ["goa-account_1"]);
        let left: Vec<&str> = store.accounts().iter().map(|a| a.id.as_str()).collect();
        assert!(
            left.contains(&mine_id.as_str()),
            "an account of its own was removed"
        );
        assert!(left.contains(&"goa-account_2"));
        assert_eq!(left.len(), 2);
    }

    #[test]
    fn a_failed_listing_removes_nothing() {
        // The daemon not answering is not the daemon saying there is nothing.
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        adopt_online_accounts(
            &mut store,
            &built_in(),
            &FakeSource::with(&[("account_1", "google", "ada@gmail.com")]),
        )
        .unwrap();

        let failing = FakeSource {
            listing_fails: true,
            ..FakeSource::with(&[])
        };
        assert!(adopt_online_accounts(&mut store, &built_in(), &failing).is_err());

        assert_eq!(store.accounts().len(), 1);
    }

    #[test]
    fn an_online_account_with_an_id_that_names_a_path_is_not_linked() {
        // The id becomes part of the account's id, which names its lock file
        // and its mail directory.
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let source = FakeSource::with(&[
            ("../../etc/cron.d/x", "google", "ada@gmail.com"),
            ("account/1", "google", "grace@gmail.com"),
            ("", "google", "alan@gmail.com"),
        ]);

        let adopted = adopt_online_accounts(&mut store, &built_in(), &source).unwrap();

        assert_eq!(adopted.failed.len(), 3, "{adopted:?}");
        assert_eq!(adopted.linked, [] as [String; 0]);
        assert_eq!(store.accounts(), []);
    }

    #[test]
    fn an_online_account_whose_identity_is_not_an_address_is_not_linked() {
        // It would be the IMAP login and the `From` address.
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let source = FakeSource::with(&[
            ("account_1", "google", "Ada Lovelace"),
            (
                "account_2",
                "google",
                "ada@gmail.com\r\nBcc: eve@example.com",
            ),
        ]);

        let adopted = adopt_online_accounts(&mut store, &built_in(), &source).unwrap();

        assert_eq!(adopted.failed.len(), 2, "{adopted:?}");
        assert_eq!(store.accounts(), []);
    }

    #[test]
    fn an_online_account_that_cannot_sign_in_is_reported_not_stored() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = store_at(dir.path());
        let source = FakeSource {
            refuses: vec!["account_1"],
            ..FakeSource::with(&[("account_1", "google", "ada@gmail.com")])
        };

        let adopted = adopt_online_accounts(&mut store, &built_in(), &source).unwrap();

        assert_eq!(adopted.failed.len(), 1);
        assert_eq!(store.accounts(), []);
    }
}

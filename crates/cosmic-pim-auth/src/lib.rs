// SPDX-License-Identifier: MPL-2.0

//! OAuth 2.0 sign-in and token renewal for the COSMIC PIM suite.
//!
//! # Where this sits
//!
//! `accounts` stores what an account is and what it signs in with, and never
//! opens a socket. This crate is the socket: it runs the authorization-code
//! flow, redeems the code, and renews a grant when it expires. The layering
//! matters — putting the flow inside `accounts` would mean the crate that holds
//! passwords also links an HTTP client, and every application that only wanted
//! to read an account name would link it too.
//!
//! Nothing above this needs to know a token was ever refreshed. [`resolve`]
//! takes an account and hands back the secret to use *now*, renewing on the way
//! if it has to, and every protocol client — CalDAV, CardDAV, IMAP, SMTP,
//! JMAP — takes that resolved secret and no more.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use cosmic_pim_accounts::{AccountStore, Registry};
//!
//! let mut accounts = AccountStore::open_default()?;
//! let registry = Registry::load();
//! let id = accounts.accounts()[0].id.clone();
//!
//! // Renews and re-stores the grant if the access token has expired.
//! let secret = cosmic_pim_auth::resolve(&mut accounts, &registry, &id)?;
//! # let _ = secret;
//! # Ok(())
//! # }
//! ```
//!
//! # Adding an account
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use cosmic_pim_accounts::{Account, AccountStore, Registry};
//!
//! let registry = Registry::load();
//! let provider = registry.get("google").expect("built in");
//! let oauth = provider.oauth.as_ref().expect("google uses OAuth");
//!
//! let pending = cosmic_pim_auth::begin(oauth)?;
//! // The user's own browser — never an embedded web view. See `flow`.
//! open_in_browser(pending.authorize_url());
//!
//! let code = pending.wait()?;
//! let credential = pending.exchange(&code, oauth)?;
//!
//! let mut accounts = AccountStore::open_default()?;
//! let account = Account::new("Google", "", "ada@gmail.com");
//! accounts.add_oauth(account, &provider.id, &credential)?;
//! # fn open_in_browser(_: &str) {}
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod flow;
pub mod pkce;
pub mod token;

use cosmic_pim_accounts::{AccountStore, AuthMethod, Registry, Secret};

pub use error::{Error, Result};
pub use flow::{Pending, begin, refresh};
pub use pkce::Pkce;
pub use token::TokenResponse;

/// The secret to put on the wire for this account, right now.
///
/// For a password account this is a keychain read. For an OAuth account it is
/// the stored access token, or — if that has expired — a renewal, which is
/// **stored back** before it is returned. Storing it back is not an
/// optimisation: a pass that renewed without persisting would renew again on
/// every cycle, and a provider that rotates refresh tokens would invalidate the
/// one on disk the first time, leaving an account that cannot be renewed at
/// all.
///
/// Takes `&mut AccountStore` for exactly that reason. A read-only variant would
/// be the easier signature and the wrong one.
pub fn resolve(
    accounts: &mut AccountStore,
    registry: &Registry,
    account_id: &str,
) -> Result<Secret> {
    let account = accounts
        .get(account_id)
        .ok_or_else(|| cosmic_pim_accounts::Error::UnknownAccount(account_id.to_owned()))?
        .clone();

    if account.auth == AuthMethod::Password {
        let password = accounts
            .password(account_id)?
            .ok_or_else(|| cosmic_pim_accounts::Error::MissingSecret(account.display_name))?;
        return Ok(Secret::Password(password));
    }

    let provider_id = account
        .provider
        .as_deref()
        .ok_or_else(|| Error::NoProvider(account.display_name.clone()))?;
    let provider = registry.get(provider_id).ok_or_else(|| {
        Error::UnknownProvider(account.display_name.clone(), provider_id.to_owned())
    })?;
    let oauth = provider
        .oauth
        .as_ref()
        .ok_or_else(|| Error::NoProvider(account.display_name.clone()))?;

    let stored = accounts
        .credential(account_id)?
        .ok_or_else(|| Error::GrantRejected("no sign-in is saved for this account".to_owned()))?;

    if !stored.is_expired() {
        return Ok(Secret::AccessToken(stored.access_token));
    }

    if !stored.is_renewable() {
        return Err(Error::NoRefreshToken);
    }

    tracing::debug!(
        account = account.display_name,
        "access token expired; renewing"
    );
    let renewed = refresh(oauth, &stored)?;
    accounts.set_credential(account_id, &renewed)?;

    Ok(Secret::AccessToken(renewed.access_token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use cosmic_pim_accounts::{Account, OAuthCredential, SecretStore};

    fn accounts_at(dir: &std::path::Path) -> AccountStore {
        let secrets = SecretStore::open_envelope_only("cosmic-pim-test", dir);
        AccountStore::open(&dir.join("accounts.toml"), secrets).expect("store")
    }

    fn grant(expires_in: i64) -> OAuthCredential {
        OAuthCredential {
            access_token: "stored-access-token".into(),
            refresh_token: Some("stored-refresh-token".into()),
            expires_at: Some(Utc::now() + Duration::seconds(expires_in)),
            scopes: Vec::new(),
            token_type: "Bearer".into(),
        }
    }

    #[test]
    fn a_password_account_resolves_to_its_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut accounts = accounts_at(dir.path());
        let account = Account::new("Fastmail", "https://caldav.fastmail.com/", "ada");
        let id = account.id.clone();
        accounts.add(account, "app-password").unwrap();

        let secret = resolve(&mut accounts, &Registry::load_from(dir.path()), &id).unwrap();

        assert_eq!(secret, Secret::Password("app-password".into()));
    }

    #[test]
    fn a_live_access_token_is_used_without_touching_the_network() {
        // The common case, and it must cost nothing: a sync pass every five
        // seconds must not post to a token endpoint every five seconds.
        let dir = tempfile::tempdir().unwrap();
        let mut accounts = accounts_at(dir.path());
        let account = Account::new("Google", "", "ada@gmail.com");
        let id = account.id.clone();
        accounts.add_oauth(account, "google", &grant(3600)).unwrap();

        let secret = resolve(&mut accounts, &Registry::load_from(dir.path()), &id).unwrap();

        assert_eq!(secret, Secret::AccessToken("stored-access-token".into()));
    }

    #[test]
    fn an_oauth_account_with_no_saved_grant_asks_for_a_sign_in() {
        let dir = tempfile::tempdir().unwrap();
        let mut accounts = accounts_at(dir.path());
        let mut account = Account::new("Google", "", "ada@gmail.com");
        account.auth = AuthMethod::OAuth;
        account.provider = Some("google".into());
        let id = account.id.clone();
        accounts.add(account, "ignored").unwrap();

        let error = resolve(&mut accounts, &Registry::load_from(dir.path()), &id).unwrap_err();

        assert!(
            error.needs_sign_in(),
            "expected a sign-in prompt, got {error}"
        );
    }

    #[test]
    fn an_expired_grant_with_no_refresh_token_asks_for_a_sign_in_rather_than_retrying() {
        let dir = tempfile::tempdir().unwrap();
        let mut accounts = accounts_at(dir.path());
        let account = Account::new("Google", "", "ada@gmail.com");
        let id = account.id.clone();
        let credential = OAuthCredential {
            refresh_token: None,
            ..grant(-10)
        };
        accounts.add_oauth(account, "google", &credential).unwrap();

        let error = resolve(&mut accounts, &Registry::load_from(dir.path()), &id).unwrap_err();

        assert!(matches!(error, Error::NoRefreshToken));
        assert!(
            !error.is_transient(),
            "a dead grant was marked as worth retrying"
        );
    }

    #[test]
    fn an_account_naming_an_uninstalled_provider_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut accounts = accounts_at(dir.path());
        let account = Account::new("Somewhere", "", "ada");
        let id = account.id.clone();
        accounts
            .add_oauth(account, "not-installed", &grant(3600))
            .unwrap();

        let error = resolve(&mut accounts, &Registry::load_from(dir.path()), &id).unwrap_err();

        assert!(matches!(error, Error::UnknownProvider(_, _)), "got {error}");
    }
}

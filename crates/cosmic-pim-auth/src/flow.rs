// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The authorization-code flow, start to finish.
//!
//! # The shape of it
//!
//! 1. [`begin`] produces a URL and keeps the halves that must not travel with
//!    it — the PKCE verifier and the state.
//! 2. The application opens that URL in the user's own browser. Not an embedded
//!    web view: RFC 8252 §8.12 is explicit that an app-controlled view defeats
//!    the point, because the user cannot see the address bar and the app can
//!    read the password out of the form. It also loses every session the user
//!    already has, and every hardware key registered to the browser.
//! 3. The provider redirects to `http://127.0.0.1:<port>/callback?code=…`.
//!    [`Pending::wait`] is listening there and takes the code.
//! 4. [`Pending::exchange`] posts the code and the verifier to the token
//!    endpoint and gets a grant back.
//!
//! Steps 3 and 4 are separate calls because the application will want to close
//! the browser window and show progress between them.
//!
//! # Why the redirect is a loopback listener
//!
//! The alternatives are worse. A custom URI scheme (`cosmic-pim://`) needs a
//! desktop-file registration, is claimable by any other application on the
//! machine, and does not work at all from a browser in a different sandbox. An
//! out-of-band code the user copies and pastes has been deprecated by Google
//! outright. Loopback is what RFC 8252 §7.3 recommends and what every provider
//! supports.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use chrono::Utc;
use cosmic_pim_accounts::{OAuthCredential, provider::OAuth};

use crate::error::{Error, Result};
use crate::pkce::{Pkce, random_state};
use crate::token::{self, TokenRequest};

/// How long to wait for the user to finish signing in before giving up.
///
/// Generous on purpose: this covers reading a consent screen, a password
/// manager, and a second factor on a phone that is in another room.
const REDIRECT_TIMEOUT: Duration = Duration::from_secs(300);

/// A sign-in that has been started and not yet completed.
///
/// Holds the two secrets that must never travel in the authorize URL. Dropping
/// it abandons the attempt, which is the correct outcome of a cancelled dialog:
/// the code that eventually arrives is then unredeemable.
#[derive(Debug)]
pub struct Pending {
    /// The URL to open in the user's browser.
    authorize_url: String,
    pkce: Pkce,
    state: String,
    redirect_uri: String,
    listener: TcpListener,
}

/// Starts a sign-in and binds the redirect listener.
///
/// The listener is bound *now* rather than after the browser is opened: binding
/// can fail — another process may hold the port, or a previous attempt may not
/// have released it — and finding that out after sending the user to a consent
/// screen means they authorise something that then cannot receive the answer.
pub fn begin(provider: &OAuth) -> Result<Pending> {
    if !provider.is_configured() {
        return Err(Error::Unconfigured);
    }

    let listener = TcpListener::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        provider.redirect_port,
    )))
    .map_err(|why| {
        Error::Redirect(format!(
            "could not listen on 127.0.0.1:{} for the sign-in redirect: {why}",
            provider.redirect_port
        ))
    })?;

    let pkce = Pkce::generate();
    let state = random_state();
    let redirect_uri = provider.redirect_uri();

    let mut params: BTreeMap<&str, String> = BTreeMap::new();
    params.insert("response_type", "code".to_owned());
    params.insert("client_id", provider.client_id.clone().unwrap_or_default());
    params.insert("redirect_uri", redirect_uri.clone());
    params.insert("scope", provider.scopes.join(" "));
    params.insert("state", state.clone());
    params.insert("code_challenge", pkce.challenge().to_owned());
    params.insert("code_challenge_method", pkce.method().to_owned());
    for (key, value) in &provider.extra_params {
        params.insert(key.as_str(), value.clone());
    }

    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let separator = if provider.auth_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let authorize_url = format!("{}{separator}{query}", provider.auth_url);

    Ok(Pending {
        authorize_url,
        pkce,
        state,
        redirect_uri,
        listener,
    })
}

impl Pending {
    /// The URL to open in the user's browser. See the module docs on why it
    /// must be *their* browser.
    #[must_use]
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }

    /// The port the redirect will arrive on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .map(|addr| addr.port())
            .unwrap_or_default()
    }

    /// Blocks until the provider redirects, and returns the authorization code.
    ///
    /// Answers the browser with a small page either way, because the user is
    /// looking at it: a tab that hangs on a connection reset gives them no way
    /// to tell "it worked, close this" from "something broke".
    pub fn wait(&self) -> Result<String> {
        self.listener
            .set_nonblocking(false)
            .map_err(|why| Error::Redirect(why.to_string()))?;

        let deadline = std::time::Instant::now() + REDIRECT_TIMEOUT;

        loop {
            if std::time::Instant::now() >= deadline {
                return Err(Error::Redirect(
                    "timed out waiting for the sign-in to finish".to_owned(),
                ));
            }

            let (stream, _peer) = self
                .listener
                .accept()
                .map_err(|why| Error::Redirect(why.to_string()))?;

            match self.handle(stream) {
                // A browser fetching /favicon.ico, or a probe. Keep listening:
                // the real redirect has not arrived yet.
                Ok(None) => continue,
                Ok(Some(code)) => return Ok(code),
                Err(why) => return Err(why),
            }
        }
    }

    /// Reads one request. `Ok(None)` means it was not the redirect.
    fn handle(&self, mut stream: TcpStream) -> Result<Option<String>> {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|why| Error::Redirect(why.to_string()))?;

        let mut line = String::new();
        BufReader::new(
            stream
                .try_clone()
                .map_err(|why| Error::Redirect(why.to_string()))?,
        )
        .read_line(&mut line)
        .map_err(|why| Error::Redirect(why.to_string()))?;

        // "GET /callback?code=…&state=… HTTP/1.1"
        let Some(target) = line.split_whitespace().nth(1) else {
            respond(&mut stream, 400, "Malformed request.");
            return Ok(None);
        };
        let Some((path, query)) = target.split_once('?') else {
            respond(&mut stream, 404, "Nothing here.");
            return Ok(None);
        };
        if !path.starts_with("/callback") {
            respond(&mut stream, 404, "Nothing here.");
            return Ok(None);
        }

        let params = parse_query(query);

        // The provider's own refusal — the user pressed Deny, or the client id
        // is wrong. Surfacing its text beats "no code arrived".
        if let Some(error) = params.get("error") {
            let description = params
                .get("error_description")
                .map_or_else(String::new, |d| format!(": {d}"));
            respond(&mut stream, 200, "Sign-in failed. You can close this tab.");
            return Err(Error::Denied(format!("{error}{description}")));
        }

        // Before anything else is believed. A code delivered by a local
        // process that did not start this flow would otherwise bind the
        // account to whatever identity that process authorised.
        match params.get("state") {
            Some(state) if *state == self.state => {}
            _ => {
                respond(&mut stream, 400, "Unexpected sign-in response.");
                return Err(Error::StateMismatch);
            }
        }

        let Some(code) = params.get("code") else {
            respond(&mut stream, 400, "No authorization code in the response.");
            return Err(Error::Redirect(
                "the provider redirected without an authorization code".to_owned(),
            ));
        };

        respond(&mut stream, 200, "Signed in. You can close this tab.");
        Ok(Some(code.clone()))
    }

    /// Redeems the code for a grant.
    pub fn exchange(&self, code: &str, provider: &OAuth) -> Result<OAuthCredential> {
        let mut form = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("redirect_uri", self.redirect_uri.clone()),
            ("code_verifier", self.pkce.verifier().to_owned()),
            ("client_id", provider.client_id.clone().unwrap_or_default()),
        ];
        if let Some(secret) = provider.client_secret.as_deref().filter(|s| !s.is_empty()) {
            form.push(("client_secret", secret.to_owned()));
        }

        let response = token::post(&provider.token_url, &form)?;
        let credential = response.into_credential(Utc::now());

        if !credential.is_renewable() {
            // Worth refusing rather than storing: the account would work for an
            // hour and then need a sign-in the user has no reason to expect.
            // For Google this means `access_type=offline` is missing from the
            // manifest; for Microsoft, the `offline_access` scope.
            return Err(Error::NoRefreshToken);
        }

        Ok(credential)
    }
}

/// Exchanges a refresh token for a fresh grant.
///
/// Free-standing rather than a method: a renewal happens on a sync pass hours
/// after the sign-in, in a different process, with no [`Pending`] anywhere.
pub fn refresh(provider: &OAuth, previous: &OAuthCredential) -> Result<OAuthCredential> {
    let Some(refresh_token) = previous.refresh_token.as_deref() else {
        return Err(Error::NoRefreshToken);
    };

    let mut form = vec![
        ("grant_type", "refresh_token".to_owned()),
        ("refresh_token", refresh_token.to_owned()),
        ("client_id", provider.client_id.clone().unwrap_or_default()),
    ];
    if let Some(secret) = provider.client_secret.as_deref().filter(|s| !s.is_empty()) {
        form.push(("client_secret", secret.to_owned()));
    }
    // Some providers narrow the grant if scope is omitted on renewal.
    if !provider.scopes.is_empty() {
        form.push(("scope", provider.scopes.join(" ")));
    }

    let response = token::post(&provider.token_url, &form)?;
    Ok(response.into_credential(Utc::now()).renewed_from(previous))
}

/// A `TokenRequest` is what the token module needs; this keeps the trait
/// surface between the two modules explicit rather than passing tuples around.
impl TokenRequest for Pending {
    fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let page = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>COSMIC PIM</title>\
         <body style=\"font-family:system-ui;padding:3rem;text-align:center\"><p>{body}</p>"
    );
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect()
}

/// Percent-encoding for a query value. Deliberately conservative: everything
/// outside the RFC 3986 unreserved set is escaped, which is always valid even
/// where it is not required.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(port: u16) -> OAuth {
        OAuth {
            client_id: Some("client-123".into()),
            client_secret: None,
            auth_url: "https://provider.example/authorize".into(),
            token_url: "https://provider.example/token".into(),
            scopes: vec!["mail".into(), "calendar".into()],
            extra_params: BTreeMap::from([("access_type".to_owned(), "offline".to_owned())]),
            redirect_port: port,
        }
    }

    /// A port the OS picked, so tests can run in parallel and on a machine
    /// where 49173 is taken.
    fn free_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port()
    }

    #[test]
    fn an_unconfigured_provider_never_opens_a_browser() {
        let unconfigured = OAuth {
            client_id: None,
            ..provider(free_port())
        };
        assert!(matches!(begin(&unconfigured), Err(Error::Unconfigured)));
    }

    #[test]
    fn the_authorize_url_carries_pkce_and_the_providers_own_parameters() {
        let pending = begin(&provider(free_port())).expect("begin");
        let url = pending.authorize_url();

        assert!(url.starts_with("https://provider.example/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("code_challenge="));
        assert!(
            url.contains("access_type=offline"),
            "provider parameters were dropped"
        );
        assert!(
            url.contains("scope=mail%20calendar"),
            "scopes must be space-joined and encoded"
        );
        assert!(
            !url.contains("code_verifier"),
            "the verifier leaked into the URL, which defeats PKCE entirely"
        );
    }

    #[test]
    fn the_redirect_listener_is_bound_before_the_user_is_sent_anywhere() {
        // Binding after the browser opens means a user can authorise an
        // application that then cannot receive the answer.
        let port = free_port();
        let pending = begin(&provider(port)).expect("begin");
        assert_eq!(pending.port(), port);

        // The port is genuinely taken now.
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err(),
            "the listener was not actually bound"
        );
    }

    #[test]
    fn a_port_already_in_use_fails_before_the_flow_starts() {
        let port = free_port();
        let _hog = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("bind");

        assert!(matches!(begin(&provider(port)), Err(Error::Redirect(_))));
    }

    /// Drives a redirect at the listener the way a browser would.
    fn redirect(port: u16, query: &str) {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
        write!(
            stream,
            "GET /callback?{query} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .expect("write");
        stream.flush().expect("flush");
    }

    fn state_of(url: &str) -> String {
        url.split('&')
            .find_map(|p| p.strip_prefix("state="))
            .expect("state in the authorize URL")
            .to_owned()
    }

    #[test]
    fn the_code_is_taken_from_the_redirect() {
        let pending = begin(&provider(free_port())).expect("begin");
        let (port, state) = (pending.port(), state_of(pending.authorize_url()));

        std::thread::spawn(move || redirect(port, &format!("code=abc123&state={state}")));

        assert_eq!(pending.wait().expect("wait"), "abc123");
    }

    #[test]
    fn a_redirect_with_the_wrong_state_is_refused() {
        // RFC 6749 §10.12. Any local process can reach this port; accepting a
        // code it delivered would bind the account to its identity, silently.
        let pending = begin(&provider(free_port())).expect("begin");
        let port = pending.port();

        std::thread::spawn(move || redirect(port, "code=attacker&state=not-ours"));

        assert!(matches!(pending.wait(), Err(Error::StateMismatch)));
    }

    #[test]
    fn a_refusal_from_the_provider_is_reported_with_its_own_words() {
        let pending = begin(&provider(free_port())).expect("begin");
        let (port, state) = (pending.port(), state_of(pending.authorize_url()));

        std::thread::spawn(move || {
            redirect(
                port,
                &format!("error=access_denied&error_description=User%20said%20no&state={state}"),
            );
        });

        let Err(Error::Denied(why)) = pending.wait() else {
            panic!("a denied sign-in was not reported as one");
        };
        assert!(why.contains("access_denied"));
        assert!(
            why.contains("User said no"),
            "the provider's explanation was dropped"
        );
    }

    #[test]
    fn a_stray_request_does_not_end_the_wait() {
        // Browsers ask for /favicon.ico. Treating that as the redirect would
        // fail every sign-in in Firefox and none in curl.
        let pending = begin(&provider(free_port())).expect("begin");
        let (port, state) = (pending.port(), state_of(pending.authorize_url()));

        std::thread::spawn(move || {
            let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");
            write!(stream, "GET /favicon.ico HTTP/1.1\r\n\r\n").expect("write");
            drop(stream);
            std::thread::sleep(Duration::from_millis(50));
            redirect(port, &format!("code=after-favicon&state={state}"));
        });

        assert_eq!(pending.wait().expect("wait"), "after-favicon");
    }

    #[test]
    fn percent_encoding_round_trips_the_characters_that_appear_in_tokens() {
        for value in [
            "a b",
            "ya29.a0+/=",
            "https://x.example/p?q=1&r=2",
            "ünïcode",
        ] {
            assert_eq!(
                decode(&encode(value)),
                value,
                "round trip failed for {value:?}"
            );
        }
    }
}

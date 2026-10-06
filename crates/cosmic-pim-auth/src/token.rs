// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The token endpoint: one form post, one JSON answer.
//!
//! Both halves of the flow — redeeming a code and renewing a grant — differ
//! only in the form fields, so the request, the error handling, and the
//! response shape live here once.
//!
//! # Reading the failure correctly matters
//!
//! RFC 6749 §5.2 gives the token endpoint a small vocabulary, and two of its
//! words mean opposite things to a sync loop. `invalid_grant` means the refresh
//! token is dead — revoked, expired, or invalidated by a password change — and
//! the only cure is a new sign-in; retrying is pointless forever.
//! `temporarily_unavailable`, or a 5xx, is the provider having a moment and
//! retrying is exactly right. Collapsing the two means either badgering a
//! provider that will never say yes, or throwing away a working account over a
//! blip.

use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use cosmic_pim_accounts::OAuthCredential;
use serde::Deserialize;

use crate::error::{Error, Result};

/// Token endpoints are quick, and a hung one should not hold a sync pass.
const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Implemented by the flow so the two modules share a vocabulary rather than
/// tuples.
pub trait TokenRequest {
    fn redirect_uri(&self) -> &str;
}

/// A successful token response (RFC 6749 §5.1).
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Seconds from now. Converted to an absolute instant on arrival, because a
    /// duration stored on disk stops meaning anything the moment the process
    /// restarts.
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// Space-separated, and omitted entirely when identical to what was asked.
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default = "bearer")]
    pub token_type: String,
    /// The OpenID Connect ID token, sent when `openid` was among the scopes.
    /// Only on a code exchange; a renewal has no reason to repeat it.
    #[serde(default)]
    pub id_token: Option<String>,
}

/// The tokens are redacted (audit O-04).
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            // Names the person who signed in.
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

fn bearer() -> String {
    "Bearer".to_owned()
}

/// Who a grant belongs to, as the provider's ID token says.
///
/// This is what lets a sign-in be one click. Without it the application has to
/// ask for an address before opening the browser and then trust that the
/// account signed in to is the one that was typed — and someone with two
/// Google accounts, signed in to the other one, gets an account labelled with
/// one address holding a grant for the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The address the provider knows this user by, which is also the login
    /// for its IMAP, SMTP and DAV services.
    pub email: String,
    /// The user's name, when the provider sent one.
    pub name: Option<String>,
}

/// How far this machine's clock may be behind the provider's before an ID
/// token minted a moment ago reads as expired.
const CLOCK_LEEWAY: ChronoDuration = ChronoDuration::minutes(5);

impl Identity {
    /// Reads the identity out of an ID token, after checking the token is
    /// one this sign-in may rely on.
    ///
    /// # What vouches for the token
    ///
    /// The signature is **not** checked, and that is deliberate rather than
    /// skipped: OpenID Connect Core §3.1.3.7 (6) allows a client that received
    /// the token directly from the token endpoint over TLS to rely on that
    /// connection in place of the signature, and that is the only place a
    /// token reaches this function from — [`post`] refuses an endpoint that
    /// is not HTTPS and follows no redirect, so the bytes came from the host
    /// the manifest names or from nobody. It must never be handed a token
    /// that arrived any other way — through the browser redirect, say —
    /// because then nothing at all vouches for it.
    ///
    /// The checks that rule does not waive are made:
    ///
    /// - `aud` names this application's client id (§3.1.3.7 (3)), so a token
    ///   minted for another application is not taken for this sign-in's;
    /// - `exp` is in the future (§3.1.3.7 (9)), give or take a clock that is
    ///   a few minutes off;
    /// - the address is one the provider stands behind: an `email` the token
    ///   itself marks `email_verified: false` is not taken.
    ///
    /// `iss` is not compared: a manifest names endpoints rather than an
    /// issuer, and Microsoft's `common` endpoint answers with a different
    /// issuer per tenant. The TLS connection to the manifest's token endpoint
    /// is what identifies the issuer here. No `nonce` is sent, so none comes
    /// back; the code is bound to this sign-in by PKCE instead.
    ///
    /// # What comes back
    ///
    /// `Ok(None)` when the token is good and names no address — Microsoft
    /// omits `email` for a work account and puts the login in
    /// `preferred_username`, which is taken when it has the shape of an
    /// address; a token with neither names nobody, and the caller has to ask.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] when the token is not a JWT, or fails one of the
    /// checks above. Deliberately not `None`: a token that should not be
    /// believed must stop the sign-in, not quietly fall back to whatever
    /// address was typed.
    pub(crate) fn from_id_token(
        id_token: &str,
        client_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Self>> {
        use base64::Engine as _;

        #[derive(Deserialize)]
        struct Claims {
            #[serde(default)]
            aud: serde_json::Value,
            #[serde(default)]
            exp: Option<i64>,
            #[serde(default)]
            email: Option<String>,
            #[serde(default)]
            email_verified: serde_json::Value,
            #[serde(default)]
            preferred_username: Option<String>,
            #[serde(default)]
            name: Option<String>,
        }

        let unusable = |why: &str| Error::Protocol(format!("the provider's ID token {why}"));

        let mut parts = id_token.split('.');
        let (Some(_header), Some(payload), Some(_signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(unusable("is not a signed token"));
        };
        let claims: Claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| unusable("could not be read"))?;

        // A string, or a list of them (OIDC Core §2).
        let for_this_client = !client_id.is_empty()
            && match &claims.aud {
                serde_json::Value::String(audience) => audience == client_id,
                serde_json::Value::Array(audiences) => audiences
                    .iter()
                    .any(|audience| audience.as_str() == Some(client_id)),
                _ => false,
            };
        if !for_this_client {
            return Err(unusable("was issued to a different application"));
        }

        let expiry = claims
            .exp
            .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
            .ok_or_else(|| unusable("carries no expiry"))?;
        if expiry + CLOCK_LEEWAY < now {
            return Err(unusable("has expired"));
        }

        // `false`, or the string some providers send in its place. Absent is
        // not a denial: Microsoft sends no such claim at all.
        let email_denied = matches!(&claims.email_verified, serde_json::Value::Bool(false))
            || claims
                .email_verified
                .as_str()
                .is_some_and(|text| text.eq_ignore_ascii_case("false"));

        let Some(email) = [
            claims.email.filter(|_| !email_denied),
            claims.preferred_username,
        ]
        .into_iter()
        .flatten()
        .map(|address| address.trim().to_owned())
        .find(|address| is_address(address)) else {
            return Ok(None);
        };
        Ok(Some(Self {
            email,
            name: claims
                .name
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty() && !name.chars().any(char::is_control)),
        }))
    }
}

/// Whether `text` has the shape of one mail address: something, an `@`,
/// a domain, and none of the characters that would let it be read as two
/// addresses, a display name, or a second line.
///
/// Not RFC 5322 — an address that arrives from a provider becomes a login
/// name, a `From` address and a line in `accounts.toml`, and the point is
/// that it cannot be anything but one address in any of them.
pub(crate) fn is_address(text: &str) -> bool {
    let Some((local, domain)) = text.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !local.contains('@')
        && text.len() <= 254
        && !text.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | ';' | '"' | '\\')
        })
}

impl TokenResponse {
    /// Who signed in, when the response carried an ID token saying so.
    ///
    /// Crate-private on purpose: the only response whose ID token may be
    /// believed is one [`post`] has just returned, for the reasons on
    /// [`Identity::from_id_token`], and a public reader would be an
    /// invitation to believe one that came from anywhere.
    ///
    /// # Errors
    ///
    /// When there is an ID token and it must not be relied on.
    pub(crate) fn identity(&self, client_id: &str, now: DateTime<Utc>) -> Result<Option<Identity>> {
        self.id_token.as_deref().map_or(Ok(None), |token| {
            Identity::from_id_token(token, client_id, now)
        })
    }

    /// Converts to the stored shape, resolving `expires_in` against `now`.
    ///
    /// The ID token is dropped here: it has said who signed in and is not a
    /// credential, so it has no business in the secret store.
    #[must_use]
    pub fn into_credential(self, now: DateTime<Utc>) -> OAuthCredential {
        OAuthCredential {
            access_token: self.access_token,
            refresh_token: self.refresh_token.filter(|t| !t.trim().is_empty()),
            expires_at: self
                .expires_in
                .map(|seconds| now + ChronoDuration::seconds(seconds)),
            scopes: self
                .scope
                .map(|s| s.split_whitespace().map(ToOwned::to_owned).collect())
                .unwrap_or_default(),
            token_type: self.token_type,
        }
    }
}

/// An error response (RFC 6749 §5.2).
#[derive(Debug, Clone, Deserialize)]
struct ErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Refuses a token endpoint a secret must not be posted to.
///
/// RFC 6749 §3.2 requires TLS here, and everything this crate believes about
/// a token response — the grant, and who it belongs to — rests on the
/// connection having been to the host the manifest names. A manifest with a
/// mistyped `http://` would otherwise send the authorization code, the client
/// secret and every later refresh token in the clear, and take whatever
/// answered for the provider.
///
/// Plain HTTP is allowed to a loopback address written as a literal, where
/// the traffic never leaves the machine: that is a provider under test, or a
/// local identity server.
fn check_endpoint(token_url: &str) -> Result<()> {
    let url = reqwest::Url::parse(token_url).map_err(|why| {
        Error::Protocol(format!("the provider's token endpoint is not a URL: {why}"))
    })?;
    let host = url.host_str().unwrap_or_default();
    // The parser has already normalised the host; an IPv6 literal is the one
    // form it leaves in brackets.
    let literal = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    let loopback = literal
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback());

    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(Error::Protocol(format!(
            "the provider's token endpoint must be https: {}://{host}",
            url.scheme()
        ))),
    }
}

/// Posts a form to a token endpoint and interprets the answer.
///
/// # Errors
///
/// [`Error::Protocol`] before anything is sent when the endpoint is not
/// HTTPS (see `check_endpoint`); otherwise as the endpoint answered.
pub fn post(token_url: &str, form: &[(&str, String)]) -> Result<TokenResponse> {
    check_endpoint(token_url)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(TOKEN_TIMEOUT)
        // A token endpoint has no business redirecting, and following one
        // would repeat the client secret and the refresh token to a host the
        // manifest never named.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|why| Error::Transport(why.to_string()))?;

    let response = client
        .post(token_url)
        // Providers differ on whether they return JSON without being asked;
        // Microsoft has historically answered `text/plain` to a bare request.
        .header("Accept", "application/json")
        .form(
            &form
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<Vec<_>>(),
        )
        .send()
        .map_err(|why| Error::Transport(why.to_string()))?;

    let status = response.status().as_u16();
    let body = response
        .text()
        .map_err(|why| Error::Transport(why.to_string()))?;

    if (200..300).contains(&status) {
        return serde_json::from_str(&body).map_err(|why| {
            Error::Protocol(format!("token endpoint returned unreadable JSON: {why}"))
        });
    }

    // A structured error is the useful case; a proxy's HTML 502 is the other.
    match serde_json::from_str::<ErrorResponse>(&body) {
        Ok(error) => Err(classify(status, &error.error, error.error_description)),
        Err(_) => Err(if (500..600).contains(&status) {
            Error::Transport(format!("token endpoint returned HTTP {status}"))
        } else {
            Error::Protocol(format!(
                "token endpoint returned HTTP {status}: {}",
                body.chars().take(200).collect::<String>()
            ))
        }),
    }
}

/// Maps an OAuth error code to something a caller can act on.
fn classify(status: u16, code: &str, description: Option<String>) -> Error {
    let detail = description.map_or_else(|| code.to_owned(), |d| format!("{code}: {d}"));

    match code {
        // The grant is dead. A new sign-in is the only cure — a retry loop
        // here would run until the user noticed, which could be days.
        "invalid_grant" => Error::GrantRejected(detail),
        // The application's own registration is wrong: bad client id, wrong
        // secret, a redirect URI the provider does not have on file. Nothing
        // the user can fix and nothing a retry changes.
        "invalid_client" | "unauthorized_client" | "invalid_request" | "unsupported_grant_type" => {
            Error::Protocol(detail)
        }
        // The user has to re-consent — a scope was added, or the provider
        // requires interaction again.
        "invalid_scope" | "consent_required" | "interaction_required" => {
            Error::GrantRejected(detail)
        }
        "temporarily_unavailable" | "server_error" => Error::Transport(detail),
        _ if (500..600).contains(&status) => Error::Transport(detail),
        _ => Error::Protocol(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_carries_no_token() {
        let response: TokenResponse = serde_json::from_str(
            r#"{"access_token":"ya29.hunter2","refresh_token":"1//hunter2","expires_in":3600}"#,
        )
        .unwrap();
        let printed = format!("{response:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }

    #[test]
    fn expires_in_becomes_an_absolute_instant() {
        // A duration outlives its meaning the moment the process restarts.
        let now = Utc::now();
        let response = TokenResponse {
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            expires_in: Some(3600),
            scope: None,
            token_type: "Bearer".into(),
            id_token: None,
        };

        let credential = response.into_credential(now);
        let expiry = credential.expires_at.expect("an expiry");

        assert!(
            (expiry - (now + ChronoDuration::hours(1)))
                .num_seconds()
                .abs()
                < 2
        );
    }

    #[test]
    fn a_space_separated_scope_becomes_a_list() {
        let response = TokenResponse {
            access_token: "at".into(),
            refresh_token: None,
            expires_in: None,
            scope: Some("openid  https://mail.example/all ".into()),
            token_type: "Bearer".into(),
            id_token: None,
        };

        assert_eq!(
            response.into_credential(Utc::now()).scopes,
            vec!["openid".to_owned(), "https://mail.example/all".to_owned()]
        );
    }

    #[test]
    fn an_empty_refresh_token_is_treated_as_absent() {
        // Some providers send `"refresh_token": ""` on renewal, which would
        // otherwise overwrite a perfectly good one with nothing.
        let response = TokenResponse {
            access_token: "at".into(),
            refresh_token: Some("  ".into()),
            expires_in: None,
            scope: None,
            token_type: "Bearer".into(),
            id_token: None,
        };

        assert!(!response.into_credential(Utc::now()).is_renewable());
    }

    const CLIENT: &str = "magnetar.apps.example";

    /// An unsigned JWT with these claims — the shape of an ID token, which is
    /// all the reader looks at.
    fn jwt(claims: &str) -> String {
        use base64::Engine as _;
        let encode = |text: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
        format!(
            "{}.{}.signature",
            encode(r#"{"alg":"RS256","typ":"JWT"}"#),
            encode(claims)
        )
    }

    /// An ID token for [`CLIENT`], good for an hour from `now`, carrying
    /// `claims` as well.
    fn id_token(now: DateTime<Utc>, claims: &str) -> String {
        let comma = if claims.is_empty() { "" } else { "," };
        jwt(&format!(
            r#"{{"sub":"1","aud":"{CLIENT}","exp":{}{comma}{claims}}}"#,
            now.timestamp() + 3600
        ))
    }

    fn read(token: &str, now: DateTime<Utc>) -> Result<Option<Identity>> {
        Identity::from_id_token(token, CLIENT, now)
    }

    #[test]
    fn the_id_token_says_who_signed_in() {
        let now = Utc::now();
        let token = id_token(now, r#""email":"ada@gmail.com","name":"Ada Lovelace""#);

        assert_eq!(
            read(&token, now).unwrap(),
            Some(Identity {
                email: "ada@gmail.com".into(),
                name: Some("Ada Lovelace".into()),
            })
        );
    }

    #[test]
    fn a_work_account_with_no_email_claim_is_known_by_its_login() {
        // Entra ID omits `email` for a work or school account; the login in
        // `preferred_username` is the address IMAP wants anyway.
        let now = Utc::now();
        let token = id_token(now, r#""preferred_username":"ada@contoso.com""#);

        let identity = read(&token, now).unwrap().expect("an identity");

        assert_eq!(identity.email, "ada@contoso.com");
        assert_eq!(identity.name, None);
    }

    #[test]
    fn a_good_id_token_naming_nobody_yields_no_identity() {
        // A guessed address would label the account wrongly; none at all
        // makes the caller ask.
        let now = Utc::now();
        for claims in [
            "",
            r#""preferred_username":"ada""#,
            r#""email":"not an address""#,
        ] {
            assert_eq!(
                read(&id_token(now, claims), now).unwrap(),
                None,
                "from {claims:?}"
            );
        }
    }

    #[test]
    fn something_that_is_not_an_id_token_stops_the_sign_in() {
        // `None` here would fall back to the typed address — the very thing
        // reading the token exists to stop.
        let now = Utc::now();
        for token in ["not-a-jwt", "a.%%%.c", "", "a.b", "a.b.c.d"] {
            let error = read(token, now).expect_err(token);
            assert!(matches!(error, Error::Protocol(_)), "{token:?}: {error}");
        }
    }

    #[test]
    fn an_id_token_issued_to_another_application_is_refused() {
        // OIDC Core §3.1.3.7 (3). The TLS connection says who sent the token,
        // not who it was minted for.
        let now = Utc::now();
        let exp = now.timestamp() + 3600;
        for claims in [
            format!(r#"{{"aud":"someone-else","exp":{exp},"email":"ada@gmail.com"}}"#),
            format!(r#"{{"aud":["a","b"],"exp":{exp},"email":"ada@gmail.com"}}"#),
            format!(r#"{{"exp":{exp},"email":"ada@gmail.com"}}"#),
            format!(r#"{{"aud":7,"exp":{exp},"email":"ada@gmail.com"}}"#),
        ] {
            let error = read(&jwt(&claims), now).expect_err(&claims);
            assert!(
                error.to_string().contains("different application"),
                "{claims}: {error}"
            );
        }

        // A list that includes this client is this client's.
        let listed = jwt(&format!(
            r#"{{"aud":["other","{CLIENT}"],"exp":{exp},"email":"ada@gmail.com"}}"#
        ));
        assert!(read(&listed, now).unwrap().is_some());

        // And with no client id of our own, nothing can be ours.
        let ours = id_token(now, r#""email":"ada@gmail.com""#);
        assert!(Identity::from_id_token(&ours, "", now).is_err());
    }

    #[test]
    fn an_expired_or_undated_id_token_is_refused() {
        let now = Utc::now();
        let stale = jwt(&format!(
            r#"{{"aud":"{CLIENT}","exp":{},"email":"ada@gmail.com"}}"#,
            now.timestamp() - 3600
        ));
        assert!(
            read(&stale, now)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );

        let undated = jwt(&format!(r#"{{"aud":"{CLIENT}","email":"ada@gmail.com"}}"#));
        assert!(read(&undated, now).is_err());

        // A clock a couple of minutes ahead of the provider's is ordinary.
        let just = jwt(&format!(
            r#"{{"aud":"{CLIENT}","exp":{},"email":"ada@gmail.com"}}"#,
            now.timestamp() - 120
        ));
        assert!(read(&just, now).unwrap().is_some());
    }

    #[test]
    fn an_address_the_provider_will_not_vouch_for_is_not_taken() {
        // An `email` claim can be something a tenant administrator typed.
        // Where the token itself says it is unverified, the login is used
        // instead, and with no login there is no identity.
        let now = Utc::now();
        for denial in ["false", r#""false""#] {
            let both = id_token(
                now,
                &format!(
                    r#""email":"ceo@victim.example","email_verified":{denial},"preferred_username":"mallory@tenant.example""#
                ),
            );
            assert_eq!(
                read(&both, now).unwrap().map(|identity| identity.email),
                Some("mallory@tenant.example".to_owned())
            );

            let only = id_token(
                now,
                &format!(r#""email":"ceo@victim.example","email_verified":{denial}"#),
            );
            assert_eq!(read(&only, now).unwrap(), None);
        }

        let verified = id_token(now, r#""email":"ada@gmail.com","email_verified":true"#);
        assert!(read(&verified, now).unwrap().is_some());
    }

    #[test]
    fn an_address_is_one_address_and_nothing_else() {
        for good in ["ada@gmail.com", "a.b+c@sub.example.org", "ada@localhost"] {
            assert!(is_address(good), "{good}");
        }
        for bad in [
            "",
            "ada",
            "@example.com",
            "ada@",
            "a@b@c",
            "ada @example.com",
            "ada@example.com\r\nBcc: x@y.z",
            "ada@example.com\u{1}auth=Bearer x",
            "Ada <ada@example.com>",
            "ada@example.com, eve@example.com",
            "ada@example.com;eve@example.com",
            "\"ada\"@example.com",
        ] {
            assert!(!is_address(bad), "{bad:?}");
        }
        assert!(!is_address(&format!("{}@example.com", "a".repeat(250))));
    }

    #[test]
    fn a_name_that_carries_a_line_break_is_dropped() {
        let now = Utc::now();
        let token = id_token(now, r#""email":"ada@gmail.com","name":"Ada\r\nBcc: x@y.z""#);

        assert_eq!(read(&token, now).unwrap().unwrap().name, None);
    }

    #[test]
    fn the_id_token_is_not_kept_with_the_credential() {
        let now = Utc::now();
        let response = TokenResponse {
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            expires_in: None,
            scope: None,
            token_type: "Bearer".into(),
            id_token: Some(id_token(now, r#""email":"ada@gmail.com""#)),
        };
        assert_eq!(
            response
                .identity(CLIENT, now)
                .unwrap()
                .map(|identity| identity.email),
            Some("ada@gmail.com".to_owned())
        );

        let stored = serde_json::to_string(&response.into_credential(now)).unwrap();

        assert!(!stored.contains("id_token"));
    }

    #[test]
    fn a_token_endpoint_that_is_not_https_is_refused_before_anything_is_sent() {
        // The listener would see the client secret and the refresh token.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();

        for url in [
            format!("http://localhost:{port}/token"),
            "http://oauth2.example.com/token".to_owned(),
            "ftp://127.0.0.1/token".to_owned(),
            "oauth2.example.com/token".to_owned(),
        ] {
            let error = post(&url, &[("client_secret", "hunter2".to_owned())]).expect_err(&url);
            assert!(matches!(error, Error::Protocol(_)), "{url}: {error}");
            assert!(!error.to_string().contains("hunter2"));
        }
        assert!(
            listener.accept().is_err(),
            "something was sent to a plain-HTTP endpoint that is not a loopback literal"
        );

        assert!(check_endpoint("https://oauth2.googleapis.com/token").is_ok());
        assert!(check_endpoint("http://127.0.0.1:8080/token").is_ok());
        assert!(check_endpoint("http://[::1]:8080/token").is_ok());
    }

    #[test]
    fn a_token_endpoint_that_redirects_is_not_followed() {
        // Following it would repeat the form — client secret, refresh token —
        // to a host the manifest never named.
        let elsewhere = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let target = format!(
            "http://127.0.0.1:{}/token",
            elsewhere.server_addr().to_ip().unwrap().port()
        );
        let first = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!(
            "http://127.0.0.1:{}/token",
            first.server_addr().to_ip().unwrap().port()
        );
        std::thread::spawn(move || {
            if let Ok(request) = first.recv() {
                let location = format!("Location: {target}")
                    .parse::<tiny_http::Header>()
                    .unwrap();
                let _ = request.respond(tiny_http::Response::empty(307).with_header(location));
            }
        });

        let error = post(&url, &[("refresh_token", "rt".to_owned())]).unwrap_err();

        assert!(matches!(error, Error::Protocol(_)), "{error}");
        assert!(
            elsewhere
                .recv_timeout(Duration::from_millis(300))
                .unwrap()
                .is_none(),
            "the form was repeated to the redirect target"
        );
    }

    #[test]
    fn a_dead_grant_is_distinguished_from_a_provider_having_a_moment() {
        // The distinction the sync loop branches on: one needs a person, the
        // other needs a wait.
        assert!(matches!(
            classify(
                400,
                "invalid_grant",
                Some("Token has been expired or revoked.".into())
            ),
            Error::GrantRejected(_)
        ));
        assert!(matches!(
            classify(503, "temporarily_unavailable", None),
            Error::Transport(_)
        ));
        assert!(matches!(
            classify(500, "whatever", None),
            Error::Transport(_)
        ));
    }

    #[test]
    fn a_misconfigured_client_is_not_retried() {
        for code in ["invalid_client", "unauthorized_client", "invalid_request"] {
            assert!(
                matches!(classify(400, code, None), Error::Protocol(_)),
                "{code} was classified as something a retry could fix"
            );
        }
    }

    #[test]
    fn the_providers_description_survives_into_the_message() {
        let error = classify(400, "invalid_grant", Some("Bad Request".into()));
        assert!(error.to_string().contains("Bad Request"));
    }
}

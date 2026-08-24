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
#[derive(Debug, Clone, Deserialize)]
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
}

fn bearer() -> String {
    "Bearer".to_owned()
}

impl TokenResponse {
    /// Converts to the stored shape, resolving `expires_in` against `now`.
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

/// Posts a form to a token endpoint and interprets the answer.
pub fn post(token_url: &str, form: &[(&str, String)]) -> Result<TokenResponse> {
    let client = reqwest::blocking::Client::builder()
        .timeout(TOKEN_TIMEOUT)
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
    fn expires_in_becomes_an_absolute_instant() {
        // A duration outlives its meaning the moment the process restarts.
        let now = Utc::now();
        let response = TokenResponse {
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            expires_in: Some(3600),
            scope: None,
            token_type: "Bearer".into(),
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
        };

        assert!(!response.into_credential(Utc::now()).is_renewable());
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

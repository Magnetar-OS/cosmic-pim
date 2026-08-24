// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! What an account authenticates with, whichever way it signs in.
//!
//! # Why one type for two mechanisms
//!
//! Every protocol client in the suite needs the same thing at the same moment:
//! the secret to put on the wire right now. For an app password that is a
//! constant; for OAuth it is an access token that expires, typically in an
//! hour, and has to be exchanged for a new one before it does.
//!
//! Modelling those as two unrelated paths pushes the difference into every
//! caller — and the callers are the CalDAV client, the CardDAV client, the IMAP
//! session, the SMTP transport and the JMAP client, none of which have any
//! business knowing about token refresh. So they take a [`Secret`], which is
//! already resolved, and the resolving happens once, in one place.
//!
//! # Expiry is treated as early
//!
//! [`OAuthCredential::is_expired`] answers true a minute before the token
//! actually expires. A sync pass that takes forty seconds and starts with
//! thirty seconds of validity left fails halfway through, and the half that
//! failed looks like a server problem rather than an expiry. The skew costs one
//! refresh an hour at most.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// A resolved secret, ready to put on the wire.
///
/// Nothing downstream of this needs to know which sign-in produced it — that
/// is the point of the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    /// A password, which for most providers means an app password.
    Password(String),
    /// A currently-valid OAuth 2.0 access token, for `Bearer` over HTTP and
    /// `XOAUTH2` over IMAP and SMTP.
    AccessToken(String),
}

impl Secret {
    /// The bytes to send. Callers that genuinely do not care which mechanism
    /// they hold — an HTTP Basic password field, say — use this.
    #[must_use]
    pub fn expose(&self) -> &str {
        match self {
            Self::Password(value) | Self::AccessToken(value) => value,
        }
    }
}

/// Deliberately opaque: a `Secret` in a log line, an error, or a panic message
/// is a credential in a log line.
impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("<password>"),
            Self::AccessToken(_) => f.write_str("<access token>"),
        }
    }
}

/// An OAuth 2.0 grant as the token endpoint returned it.
///
/// Stored whole rather than as a bare refresh token: the access token is worth
/// keeping across restarts (it is valid for an hour and a fresh one costs a
/// round trip), and `scope` is worth keeping because a provider may grant less
/// than was asked for, which is the difference between "mail does not sync" and
/// "mail was never authorised".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthCredential {
    pub access_token: String,
    /// Absent when the provider issued none — which for Google means the
    /// authorize URL was missing `access_type=offline`, and the account will
    /// stop working within the hour. Callers should treat this as a defect at
    /// sign-in time rather than discovering it later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// When [`Self::access_token`] stops being accepted. Absent means the
    /// provider did not say, which is treated as "assume it is still good and
    /// find out from the server".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// What was actually granted, which is not always what was asked for.
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_token_type")]
    pub token_type: String,
}

fn default_token_type() -> String {
    "Bearer".to_owned()
}

/// How long before real expiry a token is treated as expired. See the module
/// docs.
const EXPIRY_SKEW: Duration = Duration::seconds(60);

impl OAuthCredential {
    /// Whether the access token needs replacing before it is used.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now())
    }

    /// As [`Self::is_expired`], against a supplied clock so the skew is
    /// testable without waiting an hour.
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at
            .is_some_and(|expiry| now + EXPIRY_SKEW >= expiry)
    }

    /// Whether this grant can be renewed without sending the user back to the
    /// provider.
    #[must_use]
    pub fn is_renewable(&self) -> bool {
        self.refresh_token
            .as_ref()
            .is_some_and(|token| !token.trim().is_empty())
    }

    /// Carries forward what a refresh response left out.
    ///
    /// A refresh returns a new access token and, from most providers, *no*
    /// refresh token — the old one stays valid. Overwriting it with `None`
    /// would turn a renewable account into one that needs signing in again an
    /// hour later, which is the single easiest way to get this wrong.
    #[must_use]
    pub fn renewed_from(mut self, previous: &Self) -> Self {
        if !self.is_renewable() {
            self.refresh_token = previous.refresh_token.clone();
        }
        if self.scopes.is_empty() {
            self.scopes = previous.scopes.clone();
        }
        self
    }

    /// Whether every scope in `wanted` was granted.
    #[must_use]
    pub fn granted_all(&self, wanted: &[String]) -> bool {
        // An empty scope list in the response means "as requested" per RFC 6749
        // §5.1, not "nothing".
        self.scopes.is_empty() || wanted.iter().all(|w| self.scopes.contains(w))
    }
}

impl std::fmt::Display for OAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OAuth grant ({}, {})",
            if self.is_renewable() {
                "renewable"
            } else {
                "not renewable"
            },
            self.expires_at.map_or_else(
                || "no stated expiry".to_owned(),
                |at| format!("expires {at}")
            )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(expires_in_secs: i64) -> OAuthCredential {
        OAuthCredential {
            access_token: "ya29.secret-token".into(),
            refresh_token: Some("rt".into()),
            expires_at: Some(Utc::now() + Duration::seconds(expires_in_secs)),
            scopes: vec!["mail".into()],
            token_type: "Bearer".into(),
        }
    }

    #[test]
    fn a_token_about_to_expire_counts_as_expired() {
        // Thirty seconds is not enough to finish a sync pass with, and a pass
        // that dies halfway presents as a server fault rather than an expiry.
        assert!(grant(30).is_expired());
        assert!(!grant(600).is_expired());
    }

    #[test]
    fn a_token_with_no_stated_expiry_is_used_until_the_server_refuses_it() {
        let credential = OAuthCredential {
            expires_at: None,
            ..grant(0)
        };
        assert!(!credential.is_expired());
    }

    #[test]
    fn a_refresh_that_returns_no_refresh_token_keeps_the_old_one() {
        // The most consequential detail in this file. Most providers omit the
        // refresh token on renewal because the old one is still valid; taking
        // the response at face value turns a working account into one that
        // demands a new sign-in an hour later.
        let previous = grant(3600);
        let response = OAuthCredential {
            access_token: "fresh".into(),
            refresh_token: None,
            expires_at: Some(Utc::now() + Duration::hours(1)),
            scopes: Vec::new(),
            token_type: "Bearer".into(),
        };

        let renewed = response.renewed_from(&previous);

        assert_eq!(renewed.access_token, "fresh");
        assert_eq!(renewed.refresh_token.as_deref(), Some("rt"));
        assert_eq!(renewed.scopes, vec!["mail".to_owned()]);
        assert!(renewed.is_renewable());
    }

    #[test]
    fn a_rotated_refresh_token_replaces_the_old_one() {
        // Microsoft rotates. Keeping the old one would work until the provider
        // invalidated it, then fail in a way that looks random.
        let previous = grant(3600);
        let response = OAuthCredential {
            refresh_token: Some("rotated".into()),
            ..grant(3600)
        };

        assert_eq!(
            response.renewed_from(&previous).refresh_token.as_deref(),
            Some("rotated")
        );
    }

    #[test]
    fn a_grant_missing_a_scope_is_detectable() {
        let credential = OAuthCredential {
            scopes: vec!["calendar".into()],
            ..grant(3600)
        };

        assert!(credential.granted_all(&["calendar".to_owned()]));
        assert!(!credential.granted_all(&["calendar".to_owned(), "mail".to_owned()]));
    }

    #[test]
    fn an_empty_scope_response_means_as_requested() {
        // RFC 6749 §5.1: the scope parameter is omitted when it is identical
        // to the one asked for.
        let credential = OAuthCredential {
            scopes: Vec::new(),
            ..grant(3600)
        };
        assert!(credential.granted_all(&["anything".to_owned()]));
    }

    #[test]
    fn a_secret_does_not_print_itself() {
        // These end up in tracing fields and error messages by accident, and
        // once one is in a log file it is in every log aggregator downstream.
        assert_eq!(Secret::Password("hunter2".into()).to_string(), "<password>");
        assert_eq!(
            Secret::AccessToken("ya29.x".into()).to_string(),
            "<access token>"
        );
        assert!(!format!("{}", grant(60)).contains("secret-token"));
    }
}

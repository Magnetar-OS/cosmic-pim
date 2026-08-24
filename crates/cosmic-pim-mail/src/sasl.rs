// SPDX-License-Identifier: MPL-2.0

//! How a mail session proves who it is.
//!
//! # Two mechanisms, one type
//!
//! An app password goes over IMAP `LOGIN` and SMTP `AUTH PLAIN`. An OAuth
//! access token goes over `XOAUTH2`, and cannot be sent as a password: a server
//! that receives `LOGIN user ya29.…` rejects it, and the rejection reads as a
//! wrong password rather than as a wrong *mechanism*, which is a genuinely
//! confusing place to leave someone whose password is not the problem.
//!
//! So the choice is made once, from the account, and both the IMAP session and
//! the SMTP transport take the result.
//!
//! # XOAUTH2 is not a standard, and is what everybody implements
//!
//! Google defined it; Microsoft adopted it. RFC 7628 (`OAUTHBEARER`) is the
//! actual standard and neither of the two providers that matter accepts it, so
//! implementing OAUTHBEARER would be correct and useless. The wire format is a
//! single base64 blob:
//!
//! ```text
//! user=<address>^Auth=Bearer <token>^A^A
//! ```
//!
//! where `^A` is `0x01`. The two trailing separators are not padding — a server
//! reading the field list stops at the empty one, and omitting either produces
//! an authentication failure with no useful diagnostic anywhere.

/// What a session authenticates with.
///
/// Deliberately *not* `cosmic_pim_accounts::Secret`, though it mirrors it. This
/// crate sits beside `caldav`, below `accounts`, and knows nothing about
/// account storage — that is what keeps it testable without a keychain and
/// reusable without one. `sync` owns the one conversion, because `sync` is the
/// crate that knows about both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credentials {
    /// A password, which for most providers means an app password.
    Password(String),
    /// A valid OAuth 2.0 access token. Renewal happens above this crate.
    OAuth2(String),
}

impl Credentials {
    /// Whether this needs `AUTHENTICATE XOAUTH2` rather than `LOGIN`.
    #[must_use]
    pub fn is_oauth2(&self) -> bool {
        matches!(self, Self::OAuth2(_))
    }

    /// The secret itself. Only the two call sites that put it on the wire.
    #[must_use]
    pub fn expose(&self) -> &str {
        match self {
            Self::Password(value) | Self::OAuth2(value) => value,
        }
    }
}

/// Never prints the secret: these reach tracing fields and panic messages.
impl std::fmt::Display for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("<password>"),
            Self::OAuth2(_) => f.write_str("<access token>"),
        }
    }
}

/// The XOAUTH2 initial client response, before base64.
///
/// Kept separate from the encoding so the layout — which is the part that goes
/// wrong — is testable as bytes.
#[must_use]
pub fn xoauth2_payload(user: &str, token: &str) -> Vec<u8> {
    format!("user={user}\x01auth=Bearer {token}\x01\x01").into_bytes()
}

/// Answers an IMAP `AUTHENTICATE XOAUTH2` challenge.
///
/// The `imap` crate base64-encodes whatever this returns, so the response is
/// the raw payload. The server sends an empty challenge first; a *second*
/// challenge means it is reporting an error as base64 JSON, and the protocol
/// requires an empty line to acknowledge it before the tagged `NO` arrives.
/// Returning the payload again there would restart the exchange and hang.
pub struct XOAuth2 {
    user: String,
    token: String,
}

impl XOAuth2 {
    #[must_use]
    pub fn new(user: &str, token: &str) -> Self {
        Self {
            user: user.to_owned(),
            token: token.to_owned(),
        }
    }
}

impl imap::Authenticator for XOAuth2 {
    type Response = Vec<u8>;

    fn process(&self, challenge: &[u8]) -> Self::Response {
        if challenge.is_empty() {
            xoauth2_payload(&self.user, &self.token)
        } else {
            // The error challenge. Acknowledge with an empty response so the
            // server can send its tagged NO and the reason reaches the caller.
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imap::Authenticator as _;

    #[test]
    fn the_xoauth2_payload_has_both_trailing_separators() {
        // Omitting either produces an authentication failure with no
        // diagnostic — the single most common way to get XOAUTH2 wrong.
        let payload = xoauth2_payload("ada@gmail.com", "ya29.token");

        assert_eq!(
            payload,
            b"user=ada@gmail.com\x01auth=Bearer ya29.token\x01\x01"
        );
        assert!(payload.ends_with(&[0x01, 0x01]));
    }

    #[test]
    fn the_first_challenge_is_answered_with_the_payload() {
        let authenticator = XOAuth2::new("ada@gmail.com", "ya29.token");

        assert_eq!(
            authenticator.process(b""),
            xoauth2_payload("ada@gmail.com", "ya29.token")
        );
    }

    #[test]
    fn an_error_challenge_is_acknowledged_rather_than_answered() {
        // Re-sending the payload here restarts the exchange, and the session
        // hangs waiting for a response that never comes.
        let authenticator = XOAuth2::new("ada@gmail.com", "ya29.token");
        let error_challenge = br#"{"status":"400","schemes":"Bearer"}"#;

        assert!(authenticator.process(error_challenge).is_empty());
    }

    #[test]
    fn the_mechanism_follows_the_kind_of_credential() {
        assert!(!Credentials::Password("pw".into()).is_oauth2());
        assert!(Credentials::OAuth2("ya29".into()).is_oauth2());
    }

    #[test]
    fn credentials_do_not_print_themselves() {
        assert_eq!(Credentials::Password("hunter2".into()).to_string(), "<password>");
        assert_eq!(Credentials::OAuth2("ya29.x".into()).to_string(), "<access token>");
    }
}

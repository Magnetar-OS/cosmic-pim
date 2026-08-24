// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The pre-acceptance / ambiguous split is ported from `smtp_send_as` in the
// Meltemi project. See NOTICE and LICENSING.md.

//! Sending, and the one failure that must never be retried automatically.
//!
//! # The invariant
//!
//! Every other failure in this crate is safe to retry — a fetch that failed
//! fetches again, a STORE that failed stores again, and the worst case is a
//! wasted round trip. Sending is not like that. Once the message has been
//! handed over, a failure can mean either of two things:
//!
//! - the server never accepted it (connection refused, TLS handshake, auth
//!   rejected, an explicit 4xx) — nothing was delivered, and retrying is not
//!   only safe, it is the right thing;
//! - the server *may* have accepted it — a timeout in the middle of `DATA`, a
//!   response we could not parse, a connection dropped after the dot. The
//!   message may be in the recipient's inbox right now.
//!
//! An automatic retry on the second class sends the message twice, and there is
//! no way to take one back. So [`Outcome::Ambiguous`] is terminal: the send is
//! recorded, the user is told, and *they* decide whether to send it again. A
//! duplicate the user chose is a nuisance; a duplicate the client chose is a
//! client that cannot be trusted with a resignation letter.
//!
//! This is the one place where the substrate's usual "retry until it works"
//! posture is exactly wrong, which is why the classification is a type rather
//! than a comment.
//!
//! # Filing the Sent copy
//!
//! Most servers do not file SMTP-sent mail into Sent — the client APPENDs it.
//! [`Session::append`] does that, and the copy keeps its `Bcc` header while the
//! copy that went to the server did not: the recipients must not learn who was
//! blind-copied, and the sender must not lose the only record that they were.

use lettre::Transport as _;

use crate::error::{Error, Result};
use crate::imap::Security;
use crate::sasl::Credentials;

/// Where and how to reach one account's submission server.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SmtpEndpoint {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub security: Security,
    pub username: String,
}

impl SmtpEndpoint {
    /// The conventional endpoint: implicit TLS on 465.
    ///
    /// 587 with STARTTLS is the other common shape and is what a server without
    /// 465 wants; both are submission ports, and 25 is not — a client should
    /// never be talking to 25.
    #[must_use]
    pub fn tls(host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 465,
            security: Security::Tls,
            username: username.into(),
        }
    }
}

/// What happened to a send.
#[derive(Debug)]
pub enum Outcome {
    /// The server accepted the message. These are the bytes that were sent,
    /// with the `Bcc` header restored, ready to be filed to Sent.
    Sent(Vec<u8>),
    /// The server definitely did not accept it. Safe to retry unchanged.
    NotSent(Error),
    /// It may or may not have been delivered.
    ///
    /// **Never retry this automatically.** Surface it, and let the user decide.
    Ambiguous(Error),
}

impl Outcome {
    #[must_use]
    pub fn is_sent(&self) -> bool {
        matches!(self, Self::Sent(_))
    }

    /// May something other than a person retry this?
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::NotSent(_))
    }

    /// The failure, if it failed.
    #[must_use]
    pub fn error(&self) -> Option<&Error> {
        match self {
            Self::Sent(_) => None,
            Self::NotSent(error) | Self::Ambiguous(error) => Some(error),
        }
    }
}

/// Sends a draft.
///
/// Returns [`Outcome`] rather than `Result` because the caller has to act on
/// *which* failure this was, and a `Result` invites treating them the same.
pub fn send(
    endpoint: &SmtpEndpoint,
    credentials: &Credentials,
    draft: &crate::compose::Draft,
) -> Outcome {
    // Built twice, deliberately: the copy that goes over the wire has no `Bcc`
    // header, the copy filed to Sent does. Building one and stripping a header
    // afterwards would mean editing RFC 5322 bytes, which is the thing this
    // crate does not do.
    let outgoing = match draft.build(false) {
        Ok(message) => message,
        Err(why) => return Outcome::NotSent(why),
    };
    let filed = match draft.build(true) {
        Ok(message) => message.formatted(),
        Err(why) => return Outcome::NotSent(why),
    };

    let transport = match transport(endpoint, credentials) {
        Ok(transport) => transport,
        Err(why) => return Outcome::NotSent(why),
    };

    match transport.send(&outgoing) {
        Ok(_) => Outcome::Sent(filed),
        Err(why) => classify(&why),
    }
}

/// Which side of the acceptance line a failure fell on.
///
/// A timeout counts as ambiguous even though it usually is not: a timeout
/// during `DATA` is indistinguishable from a timeout during `EHLO`, and the
/// cost of being wrong in the two directions is not symmetric. Being wrong
/// towards "ambiguous" costs the user a button press; being wrong the other way
/// sends the message twice.
fn classify(error: &lettre::transport::smtp::Error) -> Outcome {
    let wrapped = Error::Smtp(error.to_string());
    if error.is_permanent()
        || error.is_timeout()
        || error.is_response()
        || error.is_client()
        || error.is_transport_shutdown()
    {
        Outcome::Ambiguous(wrapped)
    } else {
        // Connection refused, TLS handshake, an explicit 4xx: the server said
        // no before the message was ever handed over.
        Outcome::NotSent(wrapped)
    }
}

fn transport(endpoint: &SmtpEndpoint, credentials: &Credentials) -> Result<lettre::SmtpTransport> {
    use lettre::transport::smtp::authentication::{Credentials as SmtpCredentials, Mechanism};

    let builder = match endpoint.security {
        Security::Tls => lettre::SmtpTransport::relay(&endpoint.host),
        Security::StartTls => lettre::SmtpTransport::starttls_relay(&endpoint.host),
        // Submission without encryption sends the password in the clear. It
        // exists for a server on `localhost` and for the test harness, and the
        // UI is expected to say so.
        Security::Plaintext => Ok(lettre::SmtpTransport::builder_dangerous(&endpoint.host)),
    }
    .map_err(|why| Error::Smtp(why.to_string()))?;

    let builder = builder
        .port(endpoint.port)
        .credentials(SmtpCredentials::new(
            endpoint.username.clone(),
            credentials.expose().to_owned(),
        ));

    // Pinned rather than negotiated when the credential is a token. lettre
    // picks the strongest mechanism the server advertises, and Gmail advertises
    // PLAIN alongside XOAUTH2 — so an access token would go out as a PLAIN
    // password and be refused, with the refusal reading as a bad password.
    Ok(if credentials.is_oauth2() {
        builder.authentication(vec![Mechanism::Xoauth2]).build()
    } else {
        builder.build()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::compose::Draft;
    use crate::model::Mailbox;

    fn draft() -> Draft {
        let mut draft = Draft::new(Mailbox {
            name: Some("Me".into()),
            address: "me@example.com".into(),
        });
        draft.to.push(Mailbox {
            name: None,
            address: "ada@example.com".into(),
        });
        draft.subject = "Hello".into();
        draft.body = "Hi there.".into();
        draft
    }

    #[test]
    fn an_unsendable_draft_never_reaches_a_socket() {
        let endpoint = SmtpEndpoint {
            host: "127.0.0.1".into(),
            port: 1,
            security: Security::Plaintext,
            username: "me".into(),
        };
        let outcome = send(
            &endpoint,
            &Credentials::Password(String::new()),
            &Draft::new(Mailbox::default()),
        );
        assert!(
            outcome.is_retryable(),
            "validation was reported as ambiguous"
        );
        assert!(
            outcome.error().unwrap().to_string().contains("no sender"),
            "{:?}",
            outcome.error()
        );
    }

    #[test]
    fn a_refused_connection_is_safe_to_retry() {
        // Port 1 refuses instantly: the server never saw the message.
        let endpoint = SmtpEndpoint {
            host: "127.0.0.1".into(),
            port: 1,
            security: Security::Plaintext,
            username: "me".into(),
        };
        let outcome = send(
            &endpoint,
            &Credentials::Password("hunter2".into()),
            &draft(),
        );
        assert!(
            outcome.is_retryable(),
            "an offline send was made terminal: {:?}",
            outcome.error()
        );
    }

    #[test]
    fn the_ambiguous_outcome_is_not_retryable() {
        // The property the whole module exists for, asserted directly because
        // provoking a real mid-DATA timeout in a unit test is not worth the
        // machinery.
        let ambiguous = Outcome::Ambiguous(Error::Smtp("timed out".into()));
        assert!(!ambiguous.is_retryable());
        assert!(!ambiguous.is_sent());
        assert!(Outcome::NotSent(Error::Smtp("refused".into())).is_retryable());
        assert!(Outcome::Sent(Vec::new()).is_sent());
        assert!(!Outcome::Sent(Vec::new()).is_retryable());
    }

    #[test]
    fn the_filed_copy_keeps_bcc_and_is_what_the_outcome_carries() {
        let mut draft = draft();
        draft.bcc.push(Mailbox {
            name: None,
            address: "secret@example.org".into(),
        });
        let filed = String::from_utf8(draft.build(true).unwrap().formatted()).unwrap();
        let wire = String::from_utf8(draft.build(false).unwrap().formatted()).unwrap();
        assert!(filed.contains("secret@example.org"));
        assert!(!wire.contains("secret@example.org"));
    }
}

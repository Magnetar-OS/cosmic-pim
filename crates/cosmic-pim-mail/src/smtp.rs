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
//! A third outcome sits beside the first: the server said no *and* will say no
//! again — a refused login, a rejected recipient, a draft that cannot be built.
//! [`Outcome::Rejected`] is as safe as `NotSent` (nothing was delivered) and as
//! final as `Ambiguous` (nothing automatic should try again).
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
//! [`crate::imap::Session::append`] does that, and the copy keeps its `Bcc` header while the
//! copy that went to the server did not: the recipients must not learn who was
//! blind-copied, and the sender must not lose the only record that they were.

use crate::error::Error;
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
    /// The server definitely did not accept it, and sending it again unchanged
    /// will be refused the same way: the draft cannot be built, the login was
    /// refused, a recipient was rejected. Nothing was delivered, and nothing
    /// automatic should try again — a person has to change something first.
    Rejected(Error),
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
            Self::NotSent(error) | Self::Rejected(error) | Self::Ambiguous(error) => Some(error),
        }
    }
}

/// Sends a draft.
///
/// Returns [`Outcome`] rather than `Result` because the caller has to act on
/// *which* failure this was, and a `Result` invites treating them the same.
///
/// # Where the point of no return is
///
/// The SMTP conversation is driven one step at a time rather than through
/// `lettre`'s one-call transport, because only the step tells the two failure
/// classes apart. `lettre` reports a reset connection as the same `Network`
/// error whether it happened during the greeting or after the terminating
/// dot, and a socket read timeout on Linux surfaces as `WouldBlock`, which its
/// timeout test does not recognise — so a send whose reply was lost after the
/// server had the whole message used to come back as safe to retry, and the
/// outbox sent it again a minute later.
///
/// - Connecting, TLS, `AUTH`, `MAIL FROM`, `RCPT TO` and `DATA` all happen
///   before the message exists on the server. A failure there is
///   [`Outcome::NotSent`], or [`Outcome::Rejected`] when the server answered
///   with a permanent 5xx.
/// - From the first byte of the message on, only an explicit reply to the
///   dot is conclusive: 4xx is `NotSent`, 5xx is `Rejected`. Anything else —
///   a reset, a timeout, a reply that does not parse — is
///   [`Outcome::Ambiguous`].
pub fn send(
    endpoint: &SmtpEndpoint,
    credentials: &Credentials,
    draft: &crate::compose::Draft,
) -> Outcome {
    // Built once, then copied: the copy filed to Sent keeps its `Bcc` header
    // and the copy that goes over the wire drops it, and everything else —
    // Date, Message-ID, the MIME boundaries — is the same message, so the
    // sender's copy threads with the replies to what actually went out.
    let mut message = match draft.build(true) {
        Ok(message) => message,
        Err(why) => return Outcome::Rejected(why),
    };
    let filed = message.formatted();
    message
        .headers_mut()
        .remove::<lettre::message::header::Bcc>();
    let wire = message.formatted();

    match submit(endpoint, credentials, message.envelope(), &wire) {
        Ok(()) => Outcome::Sent(filed),
        Err(outcome) => outcome,
    }
}

/// How long any one step of the conversation may take before it is given up
/// on — `lettre`'s own default.
const STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn submit(
    endpoint: &SmtpEndpoint,
    credentials: &Credentials,
    envelope: &lettre::address::Envelope,
    wire: &[u8],
) -> std::result::Result<(), Outcome> {
    use lettre::transport::smtp::commands::{Data, Mail, Rcpt};
    use lettre::transport::smtp::extension::{Extension, MailBodyParameter, MailParameter};

    let mut connection = connect(endpoint, credentials).map_err(|why| before_data(&why))?;

    // The same internationalisation rules `lettre`'s own send applies: ask for
    // SMTPUTF8 and 8BITMIME when the message needs them, and refuse to send
    // what the server has said it cannot carry.
    let info = connection.server_info();
    let mut options = Vec::new();
    let non_ascii = envelope
        .from()
        .into_iter()
        .chain(envelope.to())
        .any(|address| !AsRef::<str>::as_ref(address).is_ascii());
    if non_ascii {
        if !info.supports_feature(Extension::SmtpUtfEight) {
            return Err(Outcome::Rejected(Error::Smtp(
                "a recipient address is not ASCII and the server does not accept SMTPUTF8".into(),
            )));
        }
        options.push(MailParameter::SmtpUtfEight);
    }
    if !wire.is_ascii() {
        if !info.supports_feature(Extension::EightBitMime) {
            return Err(Outcome::Rejected(Error::Smtp(
                "the message is not ASCII and the server does not accept 8BITMIME".into(),
            )));
        }
        options.push(MailParameter::Body(MailBodyParameter::EightBitMime));
    }

    let handshake = (|| {
        connection.command(Mail::new(envelope.from().cloned(), options))?;
        for recipient in envelope.to() {
            connection.command(Rcpt::new(recipient.clone(), vec![]))?;
        }
        connection.command(Data)
    })();
    if let Err(why) = handshake {
        connection.abort();
        return Err(before_data(&why));
    }

    // The point of no return: from here the server may hold the message.
    let reply = connection.message(wire);
    match reply {
        Ok(_) => {
            // Delivered. A failed QUIT costs nothing that matters.
            if let Err(why) = connection.quit() {
                tracing::debug!(%why, "SMTP QUIT failed after an accepted message");
            }
            Ok(())
        }
        Err(why) => {
            connection.abort();
            Err(after_data(&why))
        }
    }
}

fn connect(
    endpoint: &SmtpEndpoint,
    credentials: &Credentials,
) -> std::result::Result<
    lettre::transport::smtp::client::SmtpConnection,
    lettre::transport::smtp::Error,
> {
    use lettre::transport::smtp::authentication::{
        Credentials as SmtpCredentials, DEFAULT_MECHANISMS, Mechanism,
    };
    use lettre::transport::smtp::client::{SmtpConnection, TlsParameters};
    use lettre::transport::smtp::extension::ClientId;

    let hello = ClientId::default();
    // A local server's certificate is self-signed and is not checked; see
    // `imap::is_loopback`.
    let tls = || {
        TlsParameters::builder(endpoint.host.clone())
            .dangerous_accept_invalid_certs(crate::imap::is_loopback(&endpoint.host))
            .build_native()
    };
    let wrapper = match endpoint.security {
        Security::Tls => Some(tls()?),
        Security::StartTls | Security::Plaintext => None,
    };
    let mut connection = SmtpConnection::connect(
        (endpoint.host.as_str(), endpoint.port),
        Some(STEP_TIMEOUT),
        &hello,
        wrapper.as_ref(),
        None,
    )?;
    if endpoint.security == Security::StartTls {
        // Required, not opportunistic: a server that stops advertising
        // STARTTLS must not be handed the password in the clear.
        connection.starttls(&tls()?, &hello)?;
    }
    // Submission without encryption sends the password in the clear. It
    // exists for a server on `localhost` and for the test harness, and the UI
    // is expected to say so.

    // Pinned rather than negotiated when the credential is a token. The
    // strongest advertised mechanism would otherwise win, and Gmail advertises
    // PLAIN alongside XOAUTH2 — so an access token would go out as a PLAIN
    // password and be refused, with the refusal reading as a bad password.
    let mechanisms: &[Mechanism] = if credentials.is_oauth2() {
        &[Mechanism::Xoauth2]
    } else {
        DEFAULT_MECHANISMS
    };
    connection.auth(
        mechanisms,
        &SmtpCredentials::new(endpoint.username.clone(), credentials.expose().to_owned()),
    )?;
    Ok(connection)
}

/// A failure before the message was handed over: never ambiguous.
///
/// A permanent (5xx) answer — a refused login, a rejected sender or
/// recipient — will be given again to the same request, so it is
/// [`Outcome::Rejected`]. Everything else (no route, a TLS failure, a 4xx, a
/// dropped connection) may well succeed later.
fn before_data(error: &lettre::transport::smtp::Error) -> Outcome {
    let wrapped = Error::Smtp(error.to_string());
    if error.is_permanent() || error.is_client() {
        Outcome::Rejected(wrapped)
    } else {
        Outcome::NotSent(wrapped)
    }
}

/// A failure once the message was on its way.
///
/// Only an explicit answer to the terminating dot settles it; a lost answer
/// is the case that sends a message twice when guessed wrong.
fn after_data(error: &lettre::transport::smtp::Error) -> Outcome {
    let wrapped = Error::Smtp(error.to_string());
    if error.is_transient() {
        Outcome::NotSent(wrapped)
    } else if error.is_permanent() {
        Outcome::Rejected(wrapped)
    } else {
        Outcome::Ambiguous(wrapped)
    }
}

/// How an HTTP submission API's refusal classifies, for the Gmail and Graph
/// engines: 401 (a token that renewal fixes), 408 and 429 (come back later)
/// may be retried, and every other 4xx will be refused the same way again.
pub(crate) fn http_refusal(status: u16, error: Error) -> Outcome {
    match status {
        401 | 408 | 429 => Outcome::NotSent(error),
        _ => Outcome::Rejected(error),
    }
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
            matches!(outcome, Outcome::Rejected(_)),
            "a draft that cannot be built was reported as {outcome:?}; retrying it cannot help"
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

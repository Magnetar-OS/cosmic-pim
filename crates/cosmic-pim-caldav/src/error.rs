// SPDX-License-Identifier: MPL-2.0

//! Errors for the CalDAV layer.
//!
//! Meltemi expressed these as `CommandError::mail(..)` and
//! `CommandError::system(..)` — variants of an app-wide enum that also had to
//! be serialisable across a Tauri IPC boundary. Splitting them into a small
//! local enum is the only substantive change made while porting the protocol
//! code, and it is what makes the crate reusable.
//!
//! # Why the status code is a field and not part of the message
//!
//! The distinction a caller needs is not "did this fail" but **what would make
//! it stop failing**, and for a write that is decided almost entirely by the
//! HTTP status:
//!
//! - `503` or a dropped connection — the server or the network is having a
//!   moment. Waiting is exactly the right response.
//! - `412 Precondition Failed` — our `If-Match` names an etag the server no
//!   longer holds, because the resource changed under us. Waiting is exactly
//!   the *wrong* response: the retry sends the same stale `If-Match` and gets
//!   the same 412, forever, while the local edit sits unsent. It has to leave
//!   the retry loop and go through reconciliation.
//! - `401`/`403`/`507` — an expired app password, a collection we may not
//!   write, a full mailbox. No amount of retrying substitutes for a human.
//!
//! Formatting the code into a message string made all three look identical to
//! [`crate::push::drain`], which is why every failure used to get the same
//! exponential backoff. [`Disposition`] is the classification the queue
//! actually branches on, and it is derived from the status rather than guessed
//! from the text.

use std::fmt::Display;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server was unreachable, or answered with something unusable — a
    /// dropped connection, a TLS failure, XML that is not a multistatus, an
    /// SSO login page where a calendar should be. Corresponds to Meltemi's
    /// `CommandError::mail`.
    ///
    /// No status: these are failures of the exchange rather than answers
    /// within it. A server that *answered*, with a code we could not use,
    /// belongs in [`Error::Status`].
    #[error("{0}")]
    Protocol(String),

    /// The server answered a request with a status we could not accept.
    ///
    /// Kept structured because [`Error::disposition`] classifies on it — see
    /// the module docs for why that classification is the whole point.
    #[error("{context} (HTTP {status})")]
    Status { status: u16, context: String },

    /// A fault on our side of the wire — a malformed request we built, a
    /// method string that will not parse. Corresponds to
    /// `CommandError::system`.
    #[error("{0}")]
    Internal(String),

    /// The backing store refused a read or a write.
    #[error("store: {0}")]
    Store(#[from] cosmic_pim_core::StoreError),

    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// What would make a failed operation stop failing.
///
/// The push queue branches on this rather than on the error's text. Every
/// variant means a different *action*, and picking the wrong one has a cost
/// worse than a slow retry: classifying a 412 as [`Disposition::Retry`]
/// reproduces the silent divergence the durable queue exists to prevent, just
/// more slowly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Try again later. Timeouts, dropped connections, 5xx, 429, 423.
    Retry,

    /// Pull and reconcile first — the server's copy moved on from the one our
    /// `If-Match` names. Retrying unchanged can only 412 again.
    Reconcile,

    /// A human has to do something: re-enter a password, gain write access,
    /// free up quota. Retrying hammers a server that is already saying no,
    /// which is how an account gets rate-limited or locked out.
    NeedsUser,

    /// Nothing will make this succeed. A request we built wrong, a payload the
    /// server refuses to parse, a collection that is gone. Retrying burns
    /// battery to reach the same conclusion.
    Fatal,
}

impl Error {
    pub fn protocol(e: impl Display) -> Self {
        Self::Protocol(e.to_string())
    }

    pub fn internal(e: impl Display) -> Self {
        Self::Internal(e.to_string())
    }

    /// An answer we could not accept, carrying the code that says why.
    pub fn status(status: u16, context: impl Display) -> Self {
        Self::Status {
            status,
            context: context.to_string(),
        }
    }

    /// The HTTP status, when the failure was an answer rather than a failure
    /// to get one.
    #[must_use]
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// How a caller should respond to this failure. See [`Disposition`].
    #[must_use]
    pub fn disposition(&self) -> Disposition {
        match self {
            // The exchange itself failed. Nearly always transient, and the
            // cases that are not (a permanently dead host) cost only a backoff
            // that widens to an hour.
            Self::Protocol(_) | Self::Io(_) => Disposition::Retry,

            // Our own bug, or a store that will refuse identically next time.
            Self::Internal(_) | Self::Store(_) => Disposition::Fatal,

            Self::Status { status, .. } => match status {
                // The resource changed under our If-Match.
                412 => Disposition::Reconcile,

                // 409 in WebDAV means the parent collection is missing, which
                // for us means the collection was deleted or renamed on the
                // server: a resync problem, not a retry one.
                409 => Disposition::Reconcile,

                // Credentials, permissions, quota. All need a person.
                401 | 402 | 403 | 507 => Disposition::NeedsUser,

                // 423 Locked and 429 Too Many Requests are explicitly
                // "later, not never".
                408 | 423 | 429 => Disposition::Retry,

                // Anything the server blames on itself.
                500..=599 => Disposition::Retry,

                // Every other 4xx is a statement about the request we sent:
                // 400 malformed, 404 the collection is gone, 405 the method is
                // refused, 415 the content type is wrong. Replaying it
                // unchanged cannot help.
                400..=499 => Disposition::Fatal,

                // A non-2xx we do not recognise. Retry is the conservative
                // choice: it costs a widening backoff, whereas treating a
                // novel code as fatal drops a write on the floor.
                _ => Disposition::Retry,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each of these was picked because getting it wrong has a specific,
    /// known consequence — see the module docs.
    #[test]
    fn a_stale_etag_goes_to_reconciliation_rather_than_backoff() {
        let e = Error::status(412, "caldav: PUT /cal/a.ics");
        assert_eq!(e.disposition(), Disposition::Reconcile);
        assert_eq!(e.http_status(), Some(412));
    }

    #[test]
    fn credentials_and_permissions_and_quota_ask_for_a_human() {
        for status in [401, 402, 403, 507] {
            assert_eq!(
                Error::status(status, "x").disposition(),
                Disposition::NeedsUser,
                "HTTP {status} was not surfaced to the user"
            );
        }
    }

    #[test]
    fn server_side_and_transient_failures_back_off() {
        for status in [408, 423, 429, 500, 502, 503, 504] {
            assert_eq!(
                Error::status(status, "x").disposition(),
                Disposition::Retry,
                "HTTP {status} did not back off"
            );
        }
        assert_eq!(
            Error::protocol("connection reset").disposition(),
            Disposition::Retry
        );
        assert_eq!(
            Error::Io(std::io::Error::other("broken pipe")).disposition(),
            Disposition::Retry
        );
    }

    #[test]
    fn a_request_the_server_rejects_on_its_face_is_not_retried() {
        for status in [400, 404, 405, 415, 422] {
            assert_eq!(
                Error::status(status, "x").disposition(),
                Disposition::Fatal,
                "HTTP {status} was retried despite being about the request itself"
            );
        }
        assert_eq!(
            Error::internal("bad method").disposition(),
            Disposition::Fatal
        );
    }

    #[test]
    fn a_missing_collection_resyncs_rather_than_retrying() {
        assert_eq!(
            Error::status(409, "x").disposition(),
            Disposition::Reconcile
        );
    }

    #[test]
    fn an_unrecognised_status_errs_towards_retrying() {
        // Dropping a write because a server invented a code would be the
        // worse failure of the two.
        assert_eq!(Error::status(599, "x").disposition(), Disposition::Retry);
        assert_eq!(Error::status(199, "x").disposition(), Disposition::Retry);
    }

    #[test]
    fn the_status_is_in_the_message_a_user_sees() {
        assert_eq!(
            Error::status(412, "caldav: PUT /cal/a.ics").to_string(),
            "caldav: PUT /cal/a.ics (HTTP 412)"
        );
    }
}

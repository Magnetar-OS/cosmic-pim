// SPDX-License-Identifier: MPL-2.0

//! One error type for the crate, with the distinctions the sync cycle acts on.

use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("atomic write failed: {0}")]
    Atomic(#[from] cosmic_pim_core::atomic::Error),

    #[error("IMAP: {0}")]
    Imap(String),

    /// The mailbox was renumbered by the server. Every UID we hold for it is
    /// void — not stale, *void*: UID 41 now names a different message or no
    /// message at all.
    ///
    /// This is the one failure that must never be retried as-is. Retrying a
    /// fetch against renumbered UIDs silently stores the wrong message under
    /// the right name, which is worse than failing.
    #[error("mailbox {mailbox} was renumbered (UIDVALIDITY {had} → {now})")]
    UidValidityChanged { mailbox: String, had: u32, now: u32 },

    #[error("the server rejected our credentials: {0}")]
    Auth(String),

    /// The draft cannot be turned into a message.
    #[error("{0}")]
    Draft(String),

    #[error("SMTP: {0}")]
    Smtp(String),

    /// A JMAP request failed, or the server answered with something unusable.
    #[error("JMAP: {0}")]
    Jmap(String),

    /// POP3 said no, or said something unusable.
    ///
    /// Its own variant rather than folded into [`Error::Imap`]: the two have
    /// different consequences and a message that says IMAP about a POP3 account
    /// sends whoever reads it looking in the wrong place.
    #[error("POP3: {0}")]
    Pop3(String),

    #[error("{0}")]
    Discovery(String),

    /// The index is a cache; a failure here is recoverable by rebuilding it,
    /// and is never a reason to lose a message.
    #[error("index: {0}")]
    Index(String),

    #[error("{path} is not a maildir (no cur/ directory)")]
    NotAMaildir { path: PathBuf },

    #[error("sidecar {path} is unreadable: {source}")]
    Sidecar {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl Error {
    /// Distinguishes a network hiccup from a server saying no.
    ///
    /// The writeback queue backs off on the first and stops on the second. Get
    /// this wrong in the retryable direction and an expired app password is
    /// hammered hundreds of times an hour; get it wrong in the other direction
    /// and a train-tunnel Wi-Fi drop looks like a permanent failure and the
    /// user's edit is abandoned.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::Interrupted
            ),
            Self::Imap(message) => is_transient_text(message),
            // A renumbering needs a re-reconcile, not a retry; auth needs the
            // user. Neither is fixed by waiting.
            _ => false,
        }
    }
}

/// The `imap` crate collapses transport failures into strings by the time they
/// reach us, so the classification has to read them. Kept in one place, and
/// deliberately conservative: an unrecognised message is treated as permanent
/// so that a genuinely broken push surfaces rather than retrying forever.
fn is_transient_text(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "timed out",
        "timeout",
        "connection reset",
        "connection refused",
        "connection aborted",
        "broken pipe",
        "not connected",
        "unexpected eof",
        "eof",
        "temporarily unavailable",
        "try again",
        "[unavailable]",
        "[inuse]",
        "[serverbug]",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renumbering_and_auth_are_never_retried() {
        assert!(
            !Error::UidValidityChanged {
                mailbox: "INBOX".into(),
                had: 1,
                now: 2
            }
            .is_transient(),
            "a renumbered mailbox was classified as retryable; retrying stores \
             the wrong message under the right UID"
        );
        assert!(!Error::Auth("[AUTHENTICATIONFAILED]".into()).is_transient());
    }

    #[test]
    fn network_failures_are_retried() {
        for text in [
            "connection reset by peer",
            "Connection refused (os error 111)",
            "operation timed out",
            "* BYE [UNAVAILABLE] server is busy",
        ] {
            assert!(
                Error::Imap(text.into()).is_transient(),
                "{text:?} should back off, not abandon the write"
            );
        }
    }

    #[test]
    fn an_unrecognised_failure_is_permanent() {
        // Conservative on purpose: a push failing for a reason we have never
        // seen should surface to the user, not spin in the queue.
        assert!(!Error::Imap("NO [OVERQUOTA] mailbox is full".into()).is_transient());
    }
}

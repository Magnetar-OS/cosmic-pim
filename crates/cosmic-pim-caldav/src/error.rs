// SPDX-License-Identifier: MPL-2.0

//! Errors for the CalDAV layer.
//!
//! Meltemi expressed these as `CommandError::mail(..)` and
//! `CommandError::system(..)` — variants of an app-wide enum that also had to
//! be serialisable across a Tauri IPC boundary. Splitting them into a small
//! local enum is the only substantive change made while porting the protocol
//! code, and it is what makes the crate reusable.
//!
//! The distinction that matters to a caller is whether retrying could help:
//! [`Error::Protocol`] means the server said or did something we could not use
//! (often transient), [`Error::Internal`] means we did (never transient).

use std::fmt::Display;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server was unreachable, or answered with something unusable.
    /// Corresponds to Meltemi's `CommandError::mail`.
    #[error("{0}")]
    Protocol(String),

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

impl Error {
    pub fn protocol(e: impl Display) -> Self {
        Self::Protocol(e.to_string())
    }

    pub fn internal(e: impl Display) -> Self {
        Self::Internal(e.to_string())
    }

    /// Whether retrying the same operation later could plausibly succeed.
    ///
    /// The push queue uses this to decide between backing off and giving up:
    /// retrying an internal error forever just burns battery.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Protocol(_) | Self::Io(_))
    }
}

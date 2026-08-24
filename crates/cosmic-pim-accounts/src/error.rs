// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Errors for account metadata and credential storage.

use std::fmt::Display;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// The keychain, or the envelope that stands in for it, refused.
    #[error("credential storage: {0}")]
    Keychain(String),

    #[error("account configuration: {0}")]
    Config(String),

    #[error("no account with id “{0}”")]
    UnknownAccount(String),

    /// The account exists but nothing is stored for it to authenticate with.
    ///
    /// Kept apart from an authentication failure deliberately: "nothing was
    /// saved" and "what was saved is wrong" send a user to two different
    /// places, and reporting the first as the second sends them to re-type a
    /// password that was never the problem.
    #[error("no credential is stored for account “{0}”")]
    MissingSecret(String),

    /// A lock was poisoned, meaning a previous holder panicked. Fail closed
    /// rather than proceeding over state of unknown validity.
    #[error("credential store lock was poisoned by an earlier panic")]
    Poisoned,
}

impl Error {
    pub fn keychain(e: impl Display) -> Self {
        Self::Keychain(e.to_string())
    }

    pub fn config(e: impl Display) -> Self {
        Self::Config(e.to_string())
    }

    #[must_use]
    pub fn poisoned() -> Self {
        Self::Poisoned
    }
}

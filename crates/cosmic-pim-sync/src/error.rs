// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Errors for the orchestration layer.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    CalDav(#[from] cosmic_pim_caldav::Error),

    #[error(transparent)]
    Account(#[from] cosmic_pim_accounts::Error),

    #[error(transparent)]
    Mail(#[from] cosmic_pim_mail::Error),

    /// Signing in, or renewing a sign-in, did not produce a usable token.
    #[error(transparent)]
    Auth(#[from] cosmic_pim_auth::Error),

    #[error(transparent)]
    Store(#[from] cosmic_pim_core::StoreError),

    /// The collection carries another sync engine's metadata.
    ///
    /// Refused rather than synced: two engines on one collection keep
    /// independent state, so each sees the other's writes as an unexpected
    /// etag and the two versions oscillate indefinitely. Nothing detects it
    /// from the inside, which is why it is stopped at the door.
    #[error(
        "“{collection}” is already synced by another program (found {marker}); \
         syncing it here as well would make the two overwrite each other"
    )]
    ForeignSyncOwner { collection: String, marker: String },

    /// The account exists but has no password in the keychain. Distinct from an
    /// authentication failure on purpose: the fix is "re-enter your password",
    /// not "your password is wrong", and conflating them sends the user
    /// hunting in the wrong place.
    #[error("no password stored for account “{0}”")]
    MissingPassword(String),
}

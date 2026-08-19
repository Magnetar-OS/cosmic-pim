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
    Store(#[from] cosmic_pim_core::StoreError),

    /// The account exists but has no password in the keychain. Distinct from an
    /// authentication failure on purpose: the fix is "re-enter your password",
    /// not "your password is wrong", and conflating them sends the user
    /// hunting in the wrong place.
    #[error("no password stored for account “{0}”")]
    MissingPassword(String),
}

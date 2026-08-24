// SPDX-License-Identifier: MPL-2.0

//! Why a sign-in or a renewal did not produce a token.
//!
//! The variants exist to be branched on. A sync pass that cannot tell
//! [`Error::GrantRejected`] (the user must sign in again) from
//! [`Error::Transport`] (the provider is down) either nags about a working
//! account or silently stops syncing a broken one.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No OAuth client id is configured for this provider.
    ///
    /// A packaging matter, not a user one — see
    /// `cosmic_pim_accounts::provider` for where the id goes.
    #[error(
        "no OAuth client id is configured for this provider; \
         drop one into the providers directory to enable it"
    )]
    Unconfigured,

    /// The provider refused, or the user pressed Deny.
    #[error("the sign-in was refused: {0}")]
    Denied(String),

    /// A redirect arrived carrying a `state` this process did not issue.
    ///
    /// Any local process can connect to the loopback listener. A code from one
    /// that did not start this flow would bind the account to somebody else's
    /// identity, so it is refused rather than reported (RFC 6749 §10.12).
    #[error("the sign-in response did not match the request that started it; it was ignored")]
    StateMismatch,

    /// The loopback redirect could not be received: the port was taken, the
    /// user never finished, or the browser never came back.
    #[error("{0}")]
    Redirect(String),

    /// The grant carries no refresh token, so it would stop working within the
    /// hour with no way to renew it.
    ///
    /// Almost always a manifest defect rather than a provider one: Google needs
    /// `access_type=offline`, Microsoft needs the `offline_access` scope.
    #[error(
        "the provider issued no refresh token, so this account would stop working \
         within the hour; the provider manifest is missing its offline-access request"
    )]
    NoRefreshToken,

    /// The refresh token is no longer accepted — revoked, expired, or
    /// invalidated by a password change. Only a new sign-in fixes this.
    #[error("the saved sign-in is no longer valid and has to be renewed by hand: {0}")]
    GrantRejected(String),

    /// The provider could not be reached, or answered with a server error.
    /// Worth retrying.
    #[error("could not reach the sign-in provider: {0}")]
    Transport(String),

    /// The provider answered with something unusable, or refused the request
    /// itself. Not worth retrying unchanged.
    #[error("{0}")]
    Protocol(String),

    /// The account store refused a read or a write.
    #[error(transparent)]
    Accounts(#[from] cosmic_pim_accounts::Error),

    /// The account signs in with OAuth but names no provider, so there is no
    /// token endpoint to renew against.
    #[error("account “{0}” signs in with OAuth but names no provider")]
    NoProvider(String),

    /// The account names a provider this installation does not have a manifest
    /// for.
    #[error("account “{0}” names provider “{1}”, which is not installed")]
    UnknownProvider(String, String),
}

impl Error {
    /// Whether waiting and trying again could plausibly help.
    ///
    /// The sync pass uses this to decide between backing off and telling the
    /// user their account needs attention.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transport(_))
    }

    /// Whether the user has to sign in again by hand.
    #[must_use]
    pub fn needs_sign_in(&self) -> bool {
        matches!(self, Self::GrantRejected(_) | Self::NoRefreshToken)
    }
}

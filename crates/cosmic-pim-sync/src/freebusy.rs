// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! "When are these people busy?" — RFC 6638 free/busy, for a calendar app.
//!
//! The protocol half lives in [`cosmic_pim_caldav::itip`]; what this adds is
//! the part that needs an account: which server to ask, how to sign in to it,
//! and which of the user's accounts owns the calendar the event is in.
//!
//! The distinction the caller must not flatten: a server that runs no
//! scheduling engine cannot be asked at all, and an attendee whose server
//! declines to answer is not free. Both are represented, neither as an empty
//! busy list.

use crate::error::{Error, Result};
use cosmic_pim_accounts::{Account, AccountStore, Registry};
use cosmic_pim_caldav::itip::Availability;
use cosmic_pim_caldav::{CaldavClient, Flavor};

/// What a free/busy query came back with.
#[derive(Debug, Clone)]
pub enum Answer {
    /// The server runs no scheduling engine (no `schedule-outbox-URL`), so the
    /// question cannot be put to it. Not the same as everyone being free.
    Unsupported,
    /// One entry per attendee asked about, in the order they were asked.
    Answers(Vec<Availability>),
}

/// The account whose sync owns `collection_id`, if one does.
///
/// A calendar that no account claims — a local one, or a subscription — has
/// no server to ask, which is why this is an `Option` rather than a failure.
#[must_use]
pub fn account_for_collection(accounts: &AccountStore, collection_id: &str) -> Option<String> {
    accounts.accounts().iter().find_map(|account| {
        account
            .collections
            .values()
            .any(|bound| bound == collection_id)
            .then(|| account.id.clone())
    })
}

/// The address this account books meetings as.
#[must_use]
pub fn organizer_address(account: &Account) -> String {
    cosmic_pim_core::model::normalise_address(&account.username)
}

/// Asks `account`'s server when `attendees` are busy in the window between
/// `from_ms` and `to_ms` (Unix milliseconds — the unit the iTIP layer takes,
/// which keeps a date library out of this crate's public API).
///
/// Renewing an expired OAuth token is part of resolving the account, which is
/// why the store is taken mutably — the same reason [`crate::sync_account`]
/// does.
pub fn availability(
    accounts: &mut AccountStore,
    registry: &Registry,
    account_id: &str,
    attendees: &[String],
    from_ms: i64,
    to_ms: i64,
) -> Result<Answer> {
    if attendees.is_empty() {
        return Ok(Answer::Answers(Vec::new()));
    }

    let account = accounts
        .get(account_id)
        .ok_or_else(|| {
            Error::Account(cosmic_pim_accounts::Error::UnknownAccount(
                account_id.to_owned(),
            ))
        })?
        .clone();

    let secret = cosmic_pim_auth::resolve(accounts, registry, account_id).map_err(Error::Auth)?;
    let auth = crate::engine::dav_auth(&account, &secret);
    let url = crate::engine::service_url(&account, registry, crate::engine::Service::Calendar);

    let client = CaldavClient::with_auth(&url, Flavor::CalDav, &auth);
    let Some(outbox) = client.discover_scheduling()?.outbox_url else {
        return Ok(Answer::Unsupported);
    };

    let answers = cosmic_pim_caldav::itip::query_availability(
        &client,
        &outbox,
        &organizer_address(&account),
        attendees,
        from_ms,
        to_ms,
    )?;
    Ok(Answer::Answers(answers))
}

// SPDX-License-Identifier: MPL-2.0

//! One mail sync pass for one account.
//!
//! The counterpart of [`crate::engine`]'s calendar pass, and deliberately the
//! same shape: connect once, walk the collections, and fail per mailbox rather
//! than per account. A Gmail account with two hundred labels must not lose all
//! of them because one is momentarily unselectable.
//!
//! # Why this is not in `cosmic-pim-mail`
//!
//! The mail crate knows how to sync *a mailbox it is handed a session for*. It
//! does not know where accounts live, which credential this one uses, whether
//! that credential is still valid, or where on disk the maildirs go. Those are
//! the joins, and joins are what this crate is for — the same reason the CalDAV
//! crate does not know what an account is.

use std::path::Path;

use cosmic_pim_accounts::{Account, MailEndpoint};
use cosmic_pim_mail::imap::{Endpoint, Security, Session, SyncOptions};
use cosmic_pim_mail::maildir::{MaildirStore, mailbox_path};
use cosmic_pim_mail::{Credentials, Folder, SmtpEndpoint};
use cosmic_pim_mail::imap::SyncOutcome;

use crate::error::{Error, Result};

/// What happened to one mailbox.
#[derive(Debug)]
pub struct MailboxReport {
    pub wire_name: String,
    pub display_name: String,
    pub outcome: Result<SyncOutcome>,
}

impl MailboxReport {
    #[must_use]
    pub fn changed(&self) -> bool {
        matches!(&self.outcome, Ok(o) if o.fetched > 0 || o.removed > 0 || o.reflagged > 0)
    }
}

/// What happened to one account's mail.
#[derive(Debug, Default)]
pub struct MailReport {
    pub mailboxes: Vec<MailboxReport>,
    /// Messages that left the outbox this pass.
    pub sent: usize,
    /// Sends the outbox has given up on. These need a person.
    pub given_up: usize,
}

impl MailReport {
    #[must_use]
    pub fn changed(&self) -> bool {
        self.sent > 0 || self.mailboxes.iter().any(MailboxReport::changed)
    }

    /// Mailboxes that failed this pass.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.mailboxes.iter().filter(|m| m.outcome.is_err()).count()
    }
}

/// Translates a stored endpoint into the shape the IMAP session takes.
fn imap_endpoint(account: &Account, mail: &MailEndpoint) -> Endpoint {
    Endpoint {
        host: mail.imap_host.clone(),
        port: mail.imap_port,
        security: security(mail.imap_transport),
        username: account.mail_username().to_owned(),
    }
}

fn smtp_endpoint(account: &Account, mail: &MailEndpoint) -> SmtpEndpoint {
    SmtpEndpoint {
        host: mail.submission_host().to_owned(),
        port: mail.smtp_port,
        security: security(mail.smtp_transport),
        username: account.mail_username().to_owned(),
    }
}

/// The two crates spell this the same way and neither may depend on the other,
/// so the mapping lives here. See `cosmic_pim_accounts::Transport` for why.
fn security(transport: cosmic_pim_accounts::Transport) -> Security {
    match transport {
        cosmic_pim_accounts::Transport::Tls => Security::Tls,
        cosmic_pim_accounts::Transport::StartTls => Security::StartTls,
        cosmic_pim_accounts::Transport::Plaintext => Security::Plaintext,
    }
}

/// Syncs every mailbox of one account, and drains its outbox.
///
/// The outbox goes **first**, for the reason writeback goes before a pull
/// everywhere else in this suite: a message sent and then filed to Sent by the
/// server should be found by the pull that follows, in the same pass, rather
/// than appearing a cycle later.
pub fn sync_account_mail(
    account: &Account,
    credentials: &Credentials,
    mail_root: &Path,
    options: SyncOptions,
    now_ms: i64,
) -> Result<MailReport> {
    let Some(mail) = account.mail.as_ref() else {
        // No mail endpoint configured is not a failure — most accounts in a
        // calendar-only setup have none.
        return Ok(MailReport::default());
    };

    let mut report = MailReport::default();

    let mut session = Session::connect(&imap_endpoint(account, mail), credentials)
        .map_err(Error::Mail)?;

    // The outbox before the pull. Sends are the user's own words waiting to
    // leave; a pass that fetches first leaves them queued for another cycle.
    match drain_outbox(account, mail, credentials, mail_root, now_ms, &mut session) {
        Ok((sent, given_up)) => {
            report.sent = sent;
            report.given_up = given_up;
        }
        Err(why) => {
            // A submission server being down must not stop the pull: reading
            // mail still works when sending does not.
            tracing::warn!(account = account.display_name, %why, "could not drain the outbox");
        }
    }

    let folders = session.folders().map_err(Error::Mail)?;

    for folder in folders {
        if folder.no_select {
            // A container that exists only to hold children. SELECT on it is
            // an error rather than an empty mailbox.
            continue;
        }
        let outcome = sync_one(&mut session, account, &folder, mail_root, options, now_ms);
        report.mailboxes.push(MailboxReport {
            wire_name: folder.wire_name.clone(),
            display_name: folder.display_name.clone(),
            outcome,
        });
    }

    // Best effort: a failed LOGOUT costs nothing that matters, and reporting it
    // as a sync failure would mark a completely successful pass as broken.
    if let Err(why) = session.logout() {
        tracing::debug!(account = account.display_name, %why, "IMAP logout failed");
    }

    Ok(report)
}

fn sync_one(
    session: &mut Session,
    account: &Account,
    folder: &Folder,
    mail_root: &Path,
    options: SyncOptions,
    now_ms: i64,
) -> Result<SyncOutcome> {
    let path = mailbox_path(mail_root, &account.id, folder);
    let mut store = MaildirStore::open(&path).map_err(Error::Mail)?;
    cosmic_pim_mail::imap::sync_mailbox(session, &folder.wire_name, &mut store, options, now_ms)
        .map_err(Error::Mail)
}

/// Sends what is queued, and files each accepted message to Sent.
///
/// Filing is what makes a sent message visible on the user's phone. It is
/// deliberately *not* fatal: the message has already been delivered, and
/// failing the pass over the copy would invite a retry that sends it twice.
fn drain_outbox(
    account: &Account,
    mail: &MailEndpoint,
    credentials: &Credentials,
    mail_root: &Path,
    now_ms: i64,
    session: &mut Session,
) -> Result<(usize, usize)> {
    let outbox = cosmic_pim_mail::Outbox::open(mail_root.join(&account.id).join("outbox"))
        .map_err(Error::Mail)?;

    let outcome = outbox
        .drain(&smtp_endpoint(account, mail), credentials, now_ms)
        .map_err(Error::Mail)?;

    let sent = outcome.sent.len();
    for (id, filed) in outcome.sent {
        // Filed as read: the sender wrote it, so presenting it as unread mail
        // on their phone would be noise.
        let flags = cosmic_pim_mail::Flags {
            seen: true,
            ..Default::default()
        };
        if let Err(why) = session.append("Sent", &filed, flags) {
            tracing::warn!(
                account = account.display_name, message = id, %why,
                "a message was sent but could not be filed to Sent"
            );
        }
    }

    Ok((sent, outcome.given_up))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_pim_accounts::Transport;

    fn account_with_mail() -> Account {
        let mut account = Account::new("Work", "https://dav.example/", "ada@example.com");
        account.mail = Some(MailEndpoint {
            imap_host: "imap.example.com".into(),
            imap_port: 993,
            imap_transport: Transport::Tls,
            imap_username: Some("ada@example.com".into()),
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_transport: Transport::StartTls,
            from_address: "ada@example.com".into(),
            from_name: "Ada".into(),
        });
        account
    }

    #[test]
    fn an_account_with_no_mail_endpoint_is_not_a_failure() {
        // The ordinary state of a calendar-only account.
        let account = Account::new("Calendar only", "https://dav.example/", "ada");
        let dir = tempfile::tempdir().unwrap();

        let report = sync_account_mail(
            &account,
            &Credentials::Password("pw".into()),
            dir.path(),
            SyncOptions::default(),
            0,
        )
        .expect("a missing mail endpoint must not be an error");

        assert!(report.mailboxes.is_empty());
        assert!(!report.changed());
    }

    #[test]
    fn submission_falls_back_to_the_imap_host() {
        // A user who typed one host should not have to type it twice, and
        // `smtp.` prefixing is a guess that is wrong for Fastmail.
        let account = account_with_mail();
        let endpoint = smtp_endpoint(&account, account.mail.as_ref().unwrap());

        assert_eq!(endpoint.host, "imap.example.com");
        assert_eq!(endpoint.port, 587);
        assert_eq!(endpoint.security, Security::StartTls);
    }

    #[test]
    fn the_mail_login_can_differ_from_the_account_login() {
        // A CalDAV principal and an IMAP login are not always the same string,
        // and on a self-hosted server they frequently are not.
        let mut account = account_with_mail();
        account.username = "ada".into();
        account.mail.as_mut().unwrap().imap_username = Some("ada@example.com".into());

        assert_eq!(
            imap_endpoint(&account, account.mail.as_ref().unwrap()).username,
            "ada@example.com"
        );
    }

    #[test]
    fn every_transport_maps_to_its_counterpart() {
        // Two crates spell this enum, and a wrong mapping here would silently
        // downgrade a connection rather than failing.
        assert_eq!(security(Transport::Tls), Security::Tls);
        assert_eq!(security(Transport::StartTls), Security::StartTls);
        assert_eq!(security(Transport::Plaintext), Security::Plaintext);
    }
}

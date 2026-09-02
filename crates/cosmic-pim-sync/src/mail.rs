// Copyright 2026 Dominikos Pritis
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

use cosmic_pim_accounts::{Account, MailEndpoint, MailProtocol, Secret};
use cosmic_pim_mail::imap::SyncOutcome;
use cosmic_pim_mail::imap::{Endpoint, Security, Session, SyncOptions};
use cosmic_pim_mail::maildir::{MaildirStore, mailbox_path};
use cosmic_pim_mail::{Credentials, Folder, SmtpEndpoint};

use crate::error::{Error, Result};

/// What happened to one mailbox.
#[derive(Debug)]
pub struct MailboxReport {
    pub wire_name: String,
    pub display_name: String,
    /// The full folder, where the protocol produced one.
    ///
    /// `Some` for IMAP, whose LIST carries the hierarchy delimiter and the
    /// server's own RFC 6154 special-use declaration — which is how a Trash
    /// named "Papierkorb" is still known to be the Trash. `None` for the
    /// label-shaped protocols, where the names above are all there is and a
    /// UI reconstructs what it needs from them.
    pub folder: Option<Folder>,
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

/// A resolved account secret, in the shape the mail protocols take.
///
/// A free function rather than a `From` impl because both types are foreign to
/// this crate and the orphan rule forbids one. That is the right outcome
/// anyway: `mail` deliberately knows nothing about the account store, and
/// `accounts` knows nothing about protocols, so the crate that knows both is
/// the only honest home for the conversion.
#[must_use]
pub fn credentials_for(secret: &Secret) -> Credentials {
    match secret {
        Secret::Password(password) => Credentials::Password(password.clone()),
        Secret::AccessToken(token) => Credentials::OAuth2(token.clone()),
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

    // Which protocol is a stored property of the endpoint, not a probe. See
    // `MailEndpoint::protocol`.
    match mail.protocol {
        MailProtocol::Imap => {
            sync_over_imap(account, mail, credentials, mail_root, options, now_ms)
        }
        MailProtocol::Jmap => sync_over_jmap(account, mail, credentials, mail_root, now_ms),
        MailProtocol::Pop3 => sync_over_pop3(account, mail, credentials, mail_root, now_ms),
        MailProtocol::Gmail => sync_over_gmail(account, credentials, mail_root, now_ms),
        MailProtocol::Graph => sync_over_graph(account, credentials, mail_root, now_ms),
    }
}

fn sync_over_imap(
    account: &Account,
    mail: &MailEndpoint,
    credentials: &Credentials,
    mail_root: &Path,
    options: SyncOptions,
    now_ms: i64,
) -> Result<MailReport> {
    let mut report = MailReport::default();

    let mut session =
        Session::connect(&imap_endpoint(account, mail), credentials).map_err(Error::Mail)?;

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
            folder: Some(folder),
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

/// Drains an account's outbox through a caller-supplied submitter.
///
/// The API engines send through here — Gmail's `messages.send`, Graph's
/// `sendMail` — and both file their own Sent copy server-side, so unlike the
/// SMTP path there is nothing to append afterwards. The accepted copies come
/// back for the one caller (JMAP) whose server does not file for it.
struct Drained {
    sent: usize,
    given_up: usize,
    /// `(queue id, accepted bytes)`, in the order they went.
    accepted: Vec<(String, Vec<u8>)>,
}

fn drain_outbox_with(
    account: &Account,
    mail_root: &Path,
    now_ms: i64,
    submit: impl FnMut(&cosmic_pim_mail::Draft) -> cosmic_pim_mail::Outcome,
) -> Result<Drained> {
    let outbox = cosmic_pim_mail::Outbox::open(mail_root.join(&account.id))
        .map_err(Error::Mail)?;
    let outcome = outbox.drain_with(submit, now_ms).map_err(Error::Mail)?;
    Ok(Drained {
        sent: outcome.sent.len(),
        given_up: outcome.given_up,
        accepted: outcome.sent,
    })
}

/// How much of a Gmail label one bootstrap brings down.
///
/// A bound rather than everything: a twenty-year archive backfills over
/// several passes instead of one enormous one, and `messages.list` is
/// newest-first so the bound means "the most recent N".
const GMAIL_WINDOW: usize = 500;

/// Syncs a Google account over the Gmail API.
///
/// One maildir per canonical label — see `cosmic_pim_mail::gmail`. Every
/// folder shares the account's history feed, so an archive shows up as a
/// removal in one pass and a fetch in another, and both land in the same
/// sync.
fn sync_over_gmail(
    account: &Account,
    credentials: &Credentials,
    mail_root: &Path,
    now_ms: i64,
) -> Result<MailReport> {
    use cosmic_pim_mail::gmail;

    let session = gmail::Session::connect(credentials).map_err(Error::Mail)?;
    let mut report = MailReport::default();

    // The outbox before the pull, as everywhere else. Gmail files its own
    // Sent copy, so the accepted bytes are dropped rather than appended.
    match drain_outbox_with(account, mail_root, now_ms, |draft| session.submit(draft)) {
        Ok(drained) => {
            report.sent = drained.sent;
            report.given_up = drained.given_up;
        }
        Err(why) => {
            // Submission being down must not stop the pull: reading mail
            // still works when sending does not.
            tracing::warn!(account = account.display_name, %why, "could not drain the outbox");
        }
    }

    for folder in gmail::folders() {
        let slug = folder.wire_name.clone();
        let outcome = (|| {
            let path = mailbox_path(mail_root, &account.id, &folder);
            let mut store = MaildirStore::open(&path).map_err(Error::Mail)?;
            let mut state = gmail::state(&path);
            let outcome = gmail::sync_folder(
                &session,
                &slug,
                &mut store,
                &mut state,
                GMAIL_WINDOW,
                now_ms,
            )
            .map_err(Error::Mail)?;
            state.save(&path).map_err(Error::Mail)?;
            Ok(SyncOutcome {
                fetched: outcome.fetched,
                reflagged: outcome.reflagged,
                removed: outcome.removed,
                pushed: outcome.pushed,
                ..Default::default()
            })
        })();

        report.mailboxes.push(MailboxReport {
            wire_name: folder.wire_name,
            display_name: folder.display_name,
            folder: None,
            outcome,
        });
    }

    Ok(report)
}

/// Syncs a Microsoft account over Graph.
///
/// One delta cursor per folder, so a folder whose pass failed replays only
/// itself.
fn sync_over_graph(
    account: &Account,
    credentials: &Credentials,
    mail_root: &Path,
    now_ms: i64,
) -> Result<MailReport> {
    use cosmic_pim_mail::graph;

    let session = graph::Session::connect(credentials).map_err(Error::Mail)?;
    let mut report = MailReport::default();

    // The outbox before the pull. `sendMail` is the path that still works
    // when a tenant has SMTP AUTH switched off, and Exchange files its own
    // Sent copy (`saveToSentItems` defaults true).
    match drain_outbox_with(account, mail_root, now_ms, |draft| session.submit(draft)) {
        Ok(drained) => {
            report.sent = drained.sent;
            report.given_up = drained.given_up;
        }
        Err(why) => {
            tracing::warn!(account = account.display_name, %why, "could not drain the outbox");
        }
    }

    for remote in session.folders().map_err(Error::Mail)? {
        let folder = graph::folder_for(&remote);
        let outcome = (|| {
            let path = mailbox_path(mail_root, &account.id, &folder);
            let mut store = MaildirStore::open(&path).map_err(Error::Mail)?;
            let mut state = graph::state(&path);
            let outcome = graph::sync_folder(&session, &remote.id, &mut store, &mut state, now_ms)
                .map_err(Error::Mail)?;
            state.save(&path).map_err(Error::Mail)?;
            Ok(SyncOutcome {
                fetched: outcome.fetched,
                reflagged: outcome.reflagged,
                removed: outcome.removed,
                pushed: outcome.pushed,
                ..Default::default()
            })
        })();

        report.mailboxes.push(MailboxReport {
            wire_name: remote.id,
            display_name: folder.display_name,
            folder: None,
            outcome,
        });
    }

    Ok(report)
}

/// How much of a mailbox one JMAP pass brings down.
///
/// A bound rather than everything: `Email/query` is sorted newest-first, so
/// this means "the most recent 500" and a twenty-year archive backfills over
/// several passes instead of one enormous one.
const JMAP_WINDOW: usize = 500;

fn sync_over_jmap(
    account: &Account,
    mail: &MailEndpoint,
    credentials: &Credentials,
    mail_root: &Path,
    now_ms: i64,
) -> Result<MailReport> {
    use cosmic_pim_mail::jmap;

    let Some(session_url) = mail.jmap_session_url.as_deref() else {
        return Err(Error::Mail(cosmic_pim_mail::Error::Jmap(
            "this account is set to use JMAP but names no session resource".to_owned(),
        )));
    };

    let session = jmap::Session::connect(session_url, account.mail_username(), credentials)
        .map_err(Error::Mail)?;

    let mut report = MailReport::default();
    let mailboxes = session.mailboxes().map_err(Error::Mail)?;

    // The outbox before the pull. Submission is SMTP — the manifest fills the
    // host in — but unlike the IMAP path there is no session to APPEND the
    // Sent copy through, so it is filed over JMAP itself: upload the accepted
    // bytes as a blob, then Email/import them into the mailbox whose role is
    // `sent`. Filing failures warn rather than fail: the message is already
    // delivered, and a retry that re-sends it is the one wrong answer.
    match drain_outbox_with(account, mail_root, now_ms, |draft| {
        cosmic_pim_mail::smtp::send(&smtp_endpoint(account, mail), credentials, draft)
    }) {
        Ok(drained) => {
            report.sent = drained.sent;
            report.given_up = drained.given_up;

            let sent_mailbox = mailboxes
                .iter()
                .find(|m| m.role.as_deref() == Some("sent"))
                .map(|m| m.id.clone());
            for (id, bytes) in drained.accepted {
                let Some(sent_id) = sent_mailbox.as_deref() else {
                    tracing::warn!(
                        account = account.display_name,
                        "no mailbox with the sent role; a sent message was not filed"
                    );
                    break;
                };
                let outcome = session
                    .upload(&bytes)
                    .and_then(|blob_id| session.import(&blob_id, sent_id));
                if let Err(why) = outcome {
                    tracing::warn!(
                        account = account.display_name, message = id, %why,
                        "a message was sent but could not be filed to Sent"
                    );
                }
            }
        }
        Err(why) => {
            tracing::warn!(account = account.display_name, %why, "could not drain the outbox");
        }
    }

    for mailbox in mailboxes {
        // JMAP has no wire/display distinction — a mailbox name is a name —
        // but the local directory still has to be a legal path, so it goes
        // through the same naming the IMAP path uses.
        let folder = cosmic_pim_mail::Folder {
            wire_name: mailbox.id.clone(),
            display_name: mailbox.name.clone(),
            delimiter: '/',
            special_use: mailbox.role.as_deref().and_then(special_use),
            no_select: false,
        };

        let outcome = (|| {
            let path = mailbox_path(mail_root, &account.id, &folder);
            let mut store = MaildirStore::open(&path).map_err(Error::Mail)?;
            let mut state = jmap::state(&path);
            let outcome = jmap::sync_mailbox(
                &session,
                &mailbox.id,
                &mut store,
                &mut state,
                JMAP_WINDOW,
                now_ms,
            )
            .map_err(Error::Mail)?;
            state.save(&path).map_err(Error::Mail)?;
            Ok(SyncOutcome {
                fetched: outcome.fetched,
                reflagged: outcome.reflagged,
                removed: outcome.removed,
                pushed: outcome.pushed,
                ..Default::default()
            })
        })();

        report.mailboxes.push(MailboxReport {
            wire_name: mailbox.id,
            display_name: mailbox.name,
            folder: None,
            outcome,
        });
    }

    Ok(report)
}

/// JMAP's roles and IMAP's SPECIAL-USE attributes carry the same information
/// under different names, and the store keys folder layout on ours.
fn special_use(role: &str) -> Option<cosmic_pim_mail::SpecialUse> {
    use cosmic_pim_mail::SpecialUse;
    Some(match role {
        "inbox" => SpecialUse::Inbox,
        "sent" => SpecialUse::Sent,
        "drafts" => SpecialUse::Drafts,
        "trash" => SpecialUse::Trash,
        "junk" => SpecialUse::Junk,
        "archive" => SpecialUse::Archive,
        _ => return None,
    })
}

fn sync_over_pop3(
    account: &Account,
    mail: &MailEndpoint,
    credentials: &Credentials,
    mail_root: &Path,
    now_ms: i64,
) -> Result<MailReport> {
    use cosmic_pim_mail::pop3;

    // POP3 has exactly one mailbox and no way to name another, so the maildir
    // is the account's inbox and nothing else is walked.
    let folder = cosmic_pim_mail::Folder {
        wire_name: "INBOX".to_owned(),
        display_name: "Inbox".to_owned(),
        delimiter: '/',
        special_use: Some(cosmic_pim_mail::SpecialUse::Inbox),
        no_select: false,
    };

    let endpoint = pop3::Endpoint {
        host: if mail.pop3_host.trim().is_empty() {
            mail.imap_host.clone()
        } else {
            mail.pop3_host.clone()
        },
        port: mail.pop3_port,
        security: security(mail.pop3_transport),
        username: account.mail_username().to_owned(),
    };

    let mut session = pop3::Session::connect(&endpoint, credentials).map_err(Error::Mail)?;

    let path = mailbox_path(mail_root, &account.id, &folder);
    let outcome = (|| {
        let mut store = MaildirStore::open(&path).map_err(Error::Mail)?;
        let mut state = pop3::Pop3State::load(&path);
        // Leave everything on the server. Deleting is a decision only the user
        // can make — the same mailbox is very often also read on a phone — and
        // a default that removes mail is not one to arrive at by omission.
        let outcome = pop3::sync_inbox(
            &mut session,
            &mut store,
            &mut state,
            pop3::Retention::LeaveOnServer,
            now_ms,
        )
        .map_err(Error::Mail)?;
        state.save(&path).map_err(Error::Mail)?;
        Ok(SyncOutcome {
            fetched: outcome.fetched,
            ..Default::default()
        })
    })();

    // QUIT applies deletions; skipping it on the error path is deliberate.
    if outcome.is_ok()
        && let Err(why) = session.quit()
    {
        tracing::debug!(account = account.display_name, %why, "POP3 QUIT failed");
    }

    Ok(MailReport {
        mailboxes: vec![MailboxReport {
            wire_name: folder.wire_name,
            display_name: folder.display_name,
            folder: None,
            outcome,
        }],
        ..Default::default()
    })
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
    let outbox = cosmic_pim_mail::Outbox::open(mail_root.join(&account.id))
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
            protocol: MailProtocol::Imap,
            imap_host: "imap.example.com".into(),
            imap_port: 993,
            imap_transport: Transport::Tls,
            imap_username: Some("ada@example.com".into()),
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_transport: Transport::StartTls,
            jmap_session_url: None,
            pop3_host: String::new(),
            pop3_port: 995,
            pop3_transport: Transport::Tls,
            from_address: "ada@example.com".into(),
            from_name: "Ada".into(),
            aliases: Vec::new(),
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
    fn the_drain_reads_the_outbox_the_app_writes() {
        // Regression: the drain used to open `<account>/outbox`, and
        // `Outbox::open` joins its own `.outbox` on top — so the sync pass
        // drained a phantom empty directory and queued sends never left on
        // the next check. The paths must resolve to the same place.
        use cosmic_pim_mail::compose::Draft;
        use cosmic_pim_mail::model::Mailbox;
        use cosmic_pim_mail::smtp::Outcome;

        let account = account_with_mail();
        let dir = tempfile::tempdir().unwrap();

        // Queue exactly as the app does: Outbox::open on the account root.
        let mut draft = Draft::new(Mailbox {
            name: None,
            address: "ada@example.com".into(),
        });
        draft.to.push(Mailbox {
            name: None,
            address: "bob@example.net".into(),
        });
        draft.subject = "waiting".into();
        let outbox = cosmic_pim_mail::Outbox::open(dir.path().join(&account.id)).unwrap();
        outbox
            .queue(
                "0000000000000001",
                &draft,
                &Outcome::NotSent(cosmic_pim_mail::Error::Imap("offline".into())),
                0,
            )
            .unwrap();

        // Drain exactly as the sync pass does, far enough in the future that
        // the backoff has elapsed, with a submitter that always accepts.
        let drained = drain_outbox_with(&account, dir.path(), i64::MAX, |built| {
            Outcome::Sent(format!("To: {}\r\n\r\nx", built.to[0].address).into_bytes())
        })
        .expect("drain");

        assert_eq!(
            drained.sent, 1,
            "the drain did not see the message the app queued"
        );
        assert_eq!(outbox.count(), 0, "the sent message stayed queued");
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
    fn a_resolved_secret_picks_the_mechanism_the_session_will_use() {
        assert_eq!(
            credentials_for(&Secret::AccessToken("ya29".into())),
            Credentials::OAuth2("ya29".into())
        );
        assert!(!credentials_for(&Secret::Password("pw".into())).is_oauth2());
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

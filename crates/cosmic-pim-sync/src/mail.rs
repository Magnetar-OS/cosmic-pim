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
    /// The outbox ids of the messages that left this pass, in the order they
    /// went — what an app keyed a queued message's follow-up on (marking the
    /// message it answers, for one) can settle by. Complete even when a
    /// mailbox failed after the drain: see [`sync_account_mail`]'s errors.
    pub sent: Vec<String>,
    /// Sends the outbox has given up on. These need a person.
    pub given_up: usize,
}

impl MailReport {
    #[must_use]
    pub fn changed(&self) -> bool {
        !self.sent.is_empty() || self.mailboxes.iter().any(MailboxReport::changed)
    }

    /// Mailboxes that failed this pass.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.mailboxes.iter().filter(|m| m.outcome.is_err()).count()
    }
}

/// What [`drain_outbox`] did.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct DrainReport {
    /// The outbox ids of the messages that went, in the order they went —
    /// the same ids [`MailReport::sent`] carries.
    pub sent: Vec<String>,
    /// Sends the outbox gave up on during this drain. These need a person.
    pub given_up: usize,
}

/// Sends what is due in one account's outbox, and does nothing else.
///
/// The light alternative to [`sync_account_mail`] for an application with a
/// send due on an account it is not otherwise syncing: no mailbox is listed
/// or pulled. Each protocol submits the way its sync pass does — SMTP for
/// IMAP, JMAP and POP3 accounts, `messages.send` for Gmail, `sendMail` for
/// Graph — through the same outbox, with the same claim, backoff and
/// never-retry-an-ambiguous-send rules.
///
/// The Sent copy goes where the pass puts it. IMAP and JMAP connect to file
/// it only when something actually went, and a filing failure is logged,
/// not returned: the message has been delivered, and an error would invite
/// sending it again. Gmail and Graph file their own copy; POP3 has no Sent
/// folder.
///
/// # Errors
///
/// When the outbox cannot be read or written, or a Gmail or Graph session
/// cannot be set up (a password where an OAuth token is needed). A message
/// that fails to send is not an error: it stays queued, with its reason.
pub fn drain_outbox(
    account: &Account,
    credentials: &Credentials,
    mail_root: &Path,
    now_ms: i64,
) -> Result<DrainReport> {
    let Some(mail) = account.mail.as_ref() else {
        return Ok(DrainReport::default());
    };

    let drained = match mail.protocol {
        MailProtocol::Imap => {
            let drained = send_over_smtp(account, mail, credentials, mail_root, now_ms)?;
            if !drained.accepted.is_empty() {
                let filed = Session::connect(&imap_endpoint(account, mail), credentials).and_then(
                    |mut session| {
                        let folders = session.folders()?;
                        file_over_imap(account, &mut session, &folders, &drained.accepted);
                        if let Err(why) = session.logout() {
                            tracing::debug!(account = account.display_name, %why, "IMAP logout failed");
                        }
                        Ok(())
                    },
                );
                if let Err(why) = filed {
                    tracing::warn!(
                        account = account.display_name, %why,
                        "sent, but the Sent copies could not be filed"
                    );
                }
            }
            drained
        }
        MailProtocol::Jmap => {
            let drained = send_over_smtp(account, mail, credentials, mail_root, now_ms)?;
            if !drained.accepted.is_empty() {
                let filed = mail
                    .jmap_session_url
                    .as_deref()
                    .ok_or_else(|| {
                        cosmic_pim_mail::Error::Jmap(
                            "this account is set to use JMAP but names no session resource"
                                .to_owned(),
                        )
                    })
                    .and_then(|url| {
                        cosmic_pim_mail::jmap::Session::connect(
                            url,
                            account.mail_username(),
                            credentials,
                        )
                    })
                    .and_then(|session| {
                        let mailboxes = session.mailboxes()?;
                        file_over_jmap(account, &session, &mailboxes, &drained.accepted);
                        Ok(())
                    });
                if let Err(why) = filed {
                    tracing::warn!(
                        account = account.display_name, %why,
                        "sent, but the Sent copies could not be filed"
                    );
                }
            }
            drained
        }
        MailProtocol::Pop3 => send_over_smtp(account, mail, credentials, mail_root, now_ms)?,
        MailProtocol::Gmail => {
            let session =
                cosmic_pim_mail::gmail::Session::connect(credentials).map_err(Error::Mail)?;
            drain_outbox_with(account, mail_root, now_ms, |draft| session.submit(draft))?
        }
        MailProtocol::Graph => {
            let session =
                cosmic_pim_mail::graph::Session::connect(credentials).map_err(Error::Mail)?;
            drain_outbox_with(account, mail_root, now_ms, |draft| session.submit(draft))?
        }
    };

    Ok(DrainReport {
        sent: drained.ids(),
        given_up: drained.given_up,
    })
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
///
/// # Errors
///
/// Only from a step before the outbox is drained: the session, and the folder
/// list the pass walks and files Sent copies into. So an error means this
/// pass sent nothing. Once the drain has run, whatever fails after it is
/// reported per mailbox in [`MailboxReport::outcome`] (and counted by
/// [`MailReport::failed`]) — including a POP3 server that cannot be reached,
/// which is its inbox failing — and [`MailReport::sent`] holds what went.
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
        MailProtocol::Pop3 => Ok(sync_over_pop3(
            account,
            mail,
            credentials,
            mail_root,
            now_ms,
        )),
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

    // The folder list first: the Sent copy of anything the outbox sends is
    // filed into the folder the server calls Sent, whatever its name.
    let folders = session.folders().map_err(Error::Mail)?;

    // The outbox before the pull. Sends are the user's own words waiting to
    // leave; a pass that fetches first leaves them queued for another cycle.
    match send_over_smtp(account, mail, credentials, mail_root, now_ms) {
        Ok(drained) => {
            file_over_imap(account, &mut session, &folders, &drained.accepted);
            report.sent = drained.ids();
            report.given_up = drained.given_up;
        }
        Err(why) => {
            // A submission server being down must not stop the pull: reading
            // mail still works when sending does not.
            tracing::warn!(account = account.display_name, %why, "could not drain the outbox");
        }
    }

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
    given_up: usize,
    /// `(queue id, accepted bytes)`, in the order they went.
    accepted: Vec<(String, Vec<u8>)>,
}

impl Drained {
    /// The queue ids that went, in order.
    fn ids(&self) -> Vec<String> {
        self.accepted.iter().map(|(id, _)| id.clone()).collect()
    }
}

fn drain_outbox_with(
    account: &Account,
    mail_root: &Path,
    now_ms: i64,
    submit: impl FnMut(&cosmic_pim_mail::Draft) -> cosmic_pim_mail::Outcome,
) -> Result<Drained> {
    let outbox = cosmic_pim_mail::Outbox::open(mail_root.join(&account.id)).map_err(Error::Mail)?;
    let outcome = outbox.drain_with(submit, now_ms).map_err(Error::Mail)?;
    Ok(Drained {
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
            report.sent = drained.accepted.into_iter().map(|(id, _)| id).collect();
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
            let result = gmail::sync_folder(
                &session,
                &slug,
                &mut store,
                &mut state,
                GMAIL_WINDOW,
                now_ms,
            );
            let outcome = save_after(result, || state.save(&path))?;
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
    let session = cosmic_pim_mail::graph::Session::connect(credentials).map_err(Error::Mail)?;
    sync_graph_session(account, &session, mail_root, now_ms)
}

/// The Graph pass over a session already built — split from
/// [`sync_over_graph`] so a test can point it at a scripted server.
fn sync_graph_session(
    account: &Account,
    session: &cosmic_pim_mail::graph::Session,
    mail_root: &Path,
    now_ms: i64,
) -> Result<MailReport> {
    use cosmic_pim_mail::graph;

    let mut report = MailReport::default();

    // The folder list before the drain, as the IMAP and JMAP passes do: it is
    // the last step that can fail the whole pass, and an error returned after
    // the drain would take the ids of what it sent with it.
    let folders = session.folders().map_err(Error::Mail)?;

    // The outbox before the pull. `sendMail` is the path that still works
    // when a tenant has SMTP AUTH switched off, and Exchange files its own
    // Sent copy (`saveToSentItems` defaults true).
    match drain_outbox_with(account, mail_root, now_ms, |draft| session.submit(draft)) {
        Ok(drained) => {
            report.sent = drained.accepted.into_iter().map(|(id, _)| id).collect();
            report.given_up = drained.given_up;
        }
        Err(why) => {
            tracing::warn!(account = account.display_name, %why, "could not drain the outbox");
        }
    }

    for remote in folders {
        let folder = graph::folder_for(&remote);
        let outcome = (|| {
            let path = mailbox_path(mail_root, &account.id, &folder);
            let mut store = MaildirStore::open(&path).map_err(Error::Mail)?;
            let mut state = graph::state(&path);
            let result = graph::sync_folder(session, &remote.id, &mut store, &mut state, now_ms);
            let outcome = save_after(result, || state.save(&path))?;
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
    match send_over_smtp(account, mail, credentials, mail_root, now_ms) {
        Ok(drained) => {
            file_over_jmap(account, &session, &mailboxes, &drained.accepted);
            report.sent = drained.ids();
            report.given_up = drained.given_up;
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
            let result = jmap::sync_mailbox(
                &session,
                &mailbox.id,
                &mut store,
                &mut state,
                JMAP_WINDOW,
                now_ms,
            );
            let outcome = save_after(result, || state.save(&path))?;
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
) -> MailReport {
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

    // The outbox first, before POP3 is reached at all: submission is SMTP,
    // and a mailbox server that is down must not keep the user's mail from
    // leaving. This pass once had no drain, so a send queued on a POP3
    // account — a failed attempt, Send later, Undo's grace — never went.
    // POP3 has no Sent folder to file the copy into.
    let (sent, given_up) = match send_over_smtp(account, mail, credentials, mail_root, now_ms) {
        Ok(drained) => (drained.ids(), drained.given_up),
        Err(why) => {
            tracing::warn!(account = account.display_name, %why, "could not drain the outbox");
            (Vec::new(), 0)
        }
    };

    // A POP3 server that cannot be reached is this inbox failing, and is
    // reported as such rather than returned: an error here would take the ids
    // of what the drain just sent with it, and the caller could no longer
    // settle the messages they answered or file their Sent copies.
    let path = mailbox_path(mail_root, &account.id, &folder);
    let outcome = pop3::Session::connect(&endpoint, credentials)
        .map_err(Error::Mail)
        .and_then(|mut session| {
            let outcome = (|| {
                let mut store = MaildirStore::open(&path).map_err(Error::Mail)?;
                let mut state = pop3::Pop3State::load(&path);
                // Leave everything on the server. Deleting is a decision only
                // the user can make — the same mailbox is very often also read
                // on a phone — and a default that removes mail is not one to
                // arrive at by omission.
                let result = pop3::sync_inbox(
                    &mut session,
                    &mut store,
                    &mut state,
                    pop3::Retention::LeaveOnServer,
                    now_ms,
                );
                let outcome = save_after(result, || state.save(&path))?;
                Ok(SyncOutcome {
                    fetched: outcome.fetched,
                    ..Default::default()
                })
            })();

            // QUIT applies deletions; skipping it on the error path is
            // deliberate.
            if outcome.is_ok()
                && let Err(why) = session.quit()
            {
                tracing::debug!(account = account.display_name, %why, "POP3 QUIT failed");
            }
            outcome
        });

    MailReport {
        mailboxes: vec![MailboxReport {
            wire_name: folder.wire_name,
            display_name: folder.display_name,
            folder: None,
            outcome,
        }],
        sent,
        given_up,
    }
}

/// Saves an id-keyed engine's sidecar after a pass, whether or not the pass
/// succeeded.
///
/// The sidecar maps server ids to the UIDs of files already written, and the
/// engines advance its change-feed cursor only over windows applied in full,
/// so what it holds after a failure is still true. Not saving it is what
/// failed: the next pass handed the same UIDs to other messages and read their
/// files as already held (audit F-24). A save failure after a failed pass is
/// logged and the pass's own error is the one reported.
fn save_after<T>(
    result: cosmic_pim_mail::Result<T>,
    save: impl FnOnce() -> cosmic_pim_mail::Result<()>,
) -> Result<T> {
    let saved = save();
    match (result, saved) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Ok(_), Err(why)) => Err(Error::Mail(why)),
        (Err(why), Ok(())) => Err(Error::Mail(why)),
        (Err(why), Err(save_error)) => {
            tracing::warn!(%save_error, "the sync state of a failed pass could not be saved either");
            Err(Error::Mail(why))
        }
    }
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

/// The mailbox the Sent copies go to: the one the server declares `\Sent`
/// (RFC 6154), or failing that the one whose name says so.
///
/// Never a literal `"Sent"`: on Gmail that is `[Gmail]/Sent Mail`, on
/// Exchange `Sent Items`, on Courier `INBOX.Sent`, and on a localised server
/// something else again. An APPEND to `"Sent"` there fails, or creates a
/// stray folder beside the real one (audit F-31).
fn sent_mailbox(folders: &[Folder]) -> Option<&str> {
    folders
        .iter()
        .find(|folder| folder.special_use == Some(cosmic_pim_mail::SpecialUse::Sent))
        .map(|folder| folder.wire_name.as_str())
}

/// Sends what is due in the outbox over the account's SMTP submission
/// server — IMAP, JMAP and POP3 accounts all submit this way.
fn send_over_smtp(
    account: &Account,
    mail: &MailEndpoint,
    credentials: &Credentials,
    mail_root: &Path,
    now_ms: i64,
) -> Result<Drained> {
    let endpoint = smtp_endpoint(account, mail);
    drain_outbox_with(account, mail_root, now_ms, |draft| {
        cosmic_pim_mail::smtp::send(&endpoint, credentials, draft)
    })
}

/// Files each accepted message into the folder the IMAP server calls Sent.
///
/// Filing is what makes a sent message visible on the user's phone. It is
/// deliberately *not* fatal: the message has already been delivered, and
/// failing the pass over the copy would invite a retry that sends it twice.
fn file_over_imap(
    account: &Account,
    session: &mut Session,
    folders: &[Folder],
    accepted: &[(String, Vec<u8>)],
) {
    // Filed as read: the sender wrote it, so presenting it as unread mail on
    // their phone would be noise.
    let flags = cosmic_pim_mail::Flags {
        seen: true,
        ..Default::default()
    };
    let sent = sent_mailbox(folders);
    for (id, filed) in accepted {
        match sent {
            Some(mailbox) => {
                if let Err(why) = session.append(mailbox, filed, flags) {
                    tracing::warn!(
                        account = account.display_name, message = id, %why,
                        "a message was sent but could not be filed to Sent"
                    );
                }
            }
            None => tracing::warn!(
                account = account.display_name,
                message = id,
                "a message was sent, but the server has no Sent folder to file it in"
            ),
        }
    }
}

/// Files each accepted message into the JMAP mailbox with the `sent` role:
/// upload the bytes as a blob, then `Email/import` them. Warns rather than
/// fails, for the reason [`file_over_imap`] gives.
fn file_over_jmap(
    account: &Account,
    session: &cosmic_pim_mail::jmap::Session,
    mailboxes: &[cosmic_pim_mail::jmap::JmapMailbox],
    accepted: &[(String, Vec<u8>)],
) {
    let sent_mailbox = mailboxes
        .iter()
        .find(|m| m.role.as_deref() == Some("sent"))
        .map(|m| m.id.clone());
    for (id, bytes) in accepted {
        let Some(sent_id) = sent_mailbox.as_deref() else {
            tracing::warn!(
                account = account.display_name,
                "no mailbox with the sent role; a sent message was not filed"
            );
            break;
        };
        let outcome = session
            .upload(bytes)
            .and_then(|blob_id| session.import(&blob_id, sent_id));
        if let Err(why) = outcome {
            tracing::warn!(
                account = account.display_name, message = id, %why,
                "a message was sent but could not be filed to Sent"
            );
        }
    }
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
            drained.accepted.len(),
            1,
            "the drain did not see the message the app queued"
        );
        assert_eq!(outbox.count(), 0, "the sent message stayed queued");
    }

    /// An endpoint on this machine that refuses connections at once.
    fn refusing(account: &mut Account, protocol: MailProtocol) {
        let mail = account.mail.as_mut().unwrap();
        mail.protocol = protocol;
        mail.imap_host = "127.0.0.1".into();
        mail.imap_port = 1;
        mail.imap_transport = Transport::Plaintext;
        mail.pop3_host = "127.0.0.1".into();
        mail.pop3_port = 1;
        mail.pop3_transport = Transport::Plaintext;
        mail.smtp_host = "127.0.0.1".into();
        mail.smtp_port = 1;
        mail.smtp_transport = Transport::Plaintext;
    }

    /// Queues one message, due now, the way the app does.
    fn queue_one(account: &Account, root: &Path) -> cosmic_pim_mail::Outbox {
        use cosmic_pim_mail::compose::Draft;
        use cosmic_pim_mail::model::Mailbox;
        let mut draft = Draft::new(Mailbox {
            name: None,
            address: "ada@example.com".into(),
        });
        draft.to.push(Mailbox {
            name: None,
            address: "bob@example.net".into(),
        });
        draft.subject = "waiting".into();
        let outbox = cosmic_pim_mail::Outbox::open(root.join(&account.id)).unwrap();
        outbox.submit("0000000000000001", &draft, 0).unwrap();
        outbox
    }

    #[test]
    fn the_pop3_pass_sends_what_its_outbox_holds() {
        // The pass had no drain: a POP3 account's queued sends never left.
        let mut account = account_with_mail();
        refusing(&mut account, MailProtocol::Pop3);
        let dir = tempfile::tempdir().unwrap();
        let outbox = queue_one(&account, dir.path());

        // POP3 is unreachable too, and the drain must not wait on it.
        let _ = sync_account_mail(
            &account,
            &Credentials::Password("pw".into()),
            dir.path(),
            SyncOptions::default(),
            1_000,
        );

        let queued = &outbox.list().unwrap()[0];
        assert_eq!(queued.attempts, 1, "the queued message was never attempted");
        assert!(queued.last_error.is_some());
    }

    /// A submission server on this machine that accepts every message.
    /// Returns its port.
    fn accepting_smtp() -> u16 {
        use std::io::{BufRead as _, BufReader, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut out = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let _ = write!(out, "220 scripted ESMTP\r\n");
            let mut line = String::new();
            let mut in_data = false;
            while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                let command = line.trim_end().to_ascii_uppercase();
                line.clear();
                let reply = if in_data {
                    if command != "." {
                        continue;
                    }
                    in_data = false;
                    "250 2.0.0 queued"
                } else if command.starts_with("EHLO") {
                    // AUTH PLAIN, which the client may use without TLS.
                    "250-scripted\r\n250 AUTH PLAIN LOGIN"
                } else if command.starts_with("AUTH") {
                    "235 2.7.0 ok"
                } else if command == "DATA" {
                    in_data = true;
                    "354 go ahead"
                } else if command == "QUIT" {
                    let _ = write!(out, "221 bye\r\n");
                    return;
                } else {
                    "250 ok"
                };
                let _ = write!(out, "{reply}\r\n");
            }
        });
        port
    }

    #[test]
    fn a_pop3_pass_reports_what_it_sent_when_the_mailbox_server_is_down() {
        // SMTP took the message, then POP3 could not be reached. The pass
        // returned that error and the sent id with it, so the app could
        // neither mark what the message answered nor file its Sent copy.
        let mut account = account_with_mail();
        refusing(&mut account, MailProtocol::Pop3);
        account.mail.as_mut().unwrap().smtp_port = accepting_smtp();
        let dir = tempfile::tempdir().unwrap();
        let outbox = queue_one(&account, dir.path());

        let report = sync_account_mail(
            &account,
            &Credentials::Password("pw".into()),
            dir.path(),
            SyncOptions::default(),
            1_000,
        )
        .expect("a pass that sent something must report it");

        assert_eq!(report.sent, ["0000000000000001"]);
        assert_eq!(outbox.count(), 0, "the message did not go");
        assert_eq!(report.failed(), 1, "the unreachable inbox went unreported");
        assert_eq!(report.mailboxes[0].wire_name, "INBOX");
    }

    /// A Graph root on this machine that accepts `sendMail` and answers every
    /// other request 503. Returns its URL and the request lines it received.
    fn graph_that_cannot_list() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = std::sync::Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let mut out = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut request = String::new();
                if reader.read_line(&mut request).is_err() {
                    continue;
                }
                let mut length = 0;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 {
                        break;
                    }
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                let status = if request.starts_with("POST /me/sendMail ") {
                    "202 Accepted"
                } else {
                    "503 Service Unavailable"
                };
                log.lock().unwrap().push(request.trim_end().to_owned());
                let _ = write!(
                    out,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        });
        (url, seen)
    }

    #[test]
    fn a_graph_pass_that_fails_has_sent_nothing() {
        // `sendMail` took the message, then the folder list failed. The pass
        // returned that error and the sent id with it.
        let (url, seen) = graph_that_cannot_list();
        let mut account = account_with_mail();
        account.mail.as_mut().unwrap().protocol = MailProtocol::Graph;
        let dir = tempfile::tempdir().unwrap();
        let outbox = queue_one(&account, dir.path());
        let session =
            cosmic_pim_mail::graph::Session::connect_to(&url, &Credentials::OAuth2("t".into()))
                .unwrap();

        let result = sync_graph_session(&account, &session, dir.path(), 1_000);

        assert!(result.is_err(), "the folder list failed");
        assert_eq!(
            outbox.count(),
            1,
            "the pass sent a message and then returned an error in place of its id"
        );
        assert!(
            !seen.lock().unwrap().iter().any(|r| r.contains("sendMail")),
            "sendMail was called by a pass that went on to fail"
        );
    }

    #[test]
    fn draining_alone_reaches_no_mailbox_server() {
        // Only the submission server is contacted, and the mailbox server
        // only to file what actually went: here nothing does, so an IMAP
        // server that is down does not matter.
        let mut account = account_with_mail();
        refusing(&mut account, MailProtocol::Imap);
        let dir = tempfile::tempdir().unwrap();
        let password = Credentials::Password("pw".into());

        let nothing = drain_outbox(&account, &password, dir.path(), 1_000).unwrap();
        assert!(nothing.sent.is_empty() && nothing.given_up == 0);

        let outbox = queue_one(&account, dir.path());
        let report = drain_outbox(&account, &password, dir.path(), 1_000).unwrap();
        assert!(report.sent.is_empty());
        assert_eq!(report.given_up, 0);
        let queued = &outbox.list().unwrap()[0];
        assert_eq!(queued.attempts, 1, "the due message was not attempted");
        assert!(queued.is_live(), "a refused connection gave the message up");
    }

    #[test]
    fn every_protocol_drains_its_own_way() {
        // POP3 submits over SMTP like IMAP; the API engines need a token and
        // say so rather than sending nothing quietly.
        let dir = tempfile::tempdir().unwrap();
        let password = Credentials::Password("pw".into());
        let mut pop3 = account_with_mail();
        refusing(&mut pop3, MailProtocol::Pop3);
        let outbox = queue_one(&pop3, dir.path());
        drain_outbox(&pop3, &password, dir.path(), 1_000).unwrap();
        assert_eq!(outbox.list().unwrap()[0].attempts, 1);

        for protocol in [MailProtocol::Gmail, MailProtocol::Graph] {
            let mut account = account_with_mail();
            account.mail.as_mut().unwrap().protocol = protocol;
            assert!(drain_outbox(&account, &password, dir.path(), 1_000).is_err());
        }

        let calendar_only = Account::new("Calendar only", "https://dav.example/", "ada");
        assert!(
            drain_outbox(&calendar_only, &password, dir.path(), 1_000)
                .unwrap()
                .sent
                .is_empty()
        );
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

    #[test]
    fn the_sent_copy_goes_to_the_folder_the_server_calls_sent() {
        let folders = [
            cosmic_pim_mail::folder::from_list_entry("INBOX", Some('/'), &[]),
            cosmic_pim_mail::folder::from_list_entry("INBOX.Sent Items", Some('.'), &[]),
        ];
        assert_eq!(sent_mailbox(&folders), Some("INBOX.Sent Items"));
        assert_eq!(sent_mailbox(&folders[..1]), None);
    }
}

// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The drafts mirror: what makes a local draft visible in the server's Drafts
//! folder without ever duplicating it.
//!
//! # The shape
//!
//! The local record ([`crate::drafts`]) stays the authority this device edits.
//! Each sweep uploads every record the server has not seen the latest version
//! of, and retires the copy the previous upload left — so the folder holds
//! exactly one message per draft, always the newest.
//!
//! Replacement is the entire difficulty, and it has two legs:
//!
//! - **UIDPLUS** (RFC 4315): APPEND answers with the UID it assigned, so the
//!   next sweep can address the old copy exactly.
//! - **`Message-ID` search** everywhere else: a draft always mirrors under the
//!   same id, minted once from the draft's own id, so the old copy is
//!   findable by a header search even on servers that never say where an
//!   APPEND landed.
//!
//! The search runs *before* the append, so the new copy can never match its
//! own retirement query — which is the reconciliation pass for servers that
//! mangle both legs: whatever matched the id before the upload is, by
//! construction, not the message just uploaded.
//!
//! # Offline
//!
//! A sweep needs a session, and drafts are edited without one. Every save
//! marks the record dirty; every local delete of a mirrored draft leaves a
//! tombstone. The sweep drains both, so it is safe — and expected — to call
//! it from the same poll that drains the outbox: the writes made on the train
//! go out on the next check.

use crate::drafts::Drafts;
use crate::imap::Session;
use crate::model::Flags;
use crate::push::Writeback as _;

/// What one sweep did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Drafts whose latest version reached the folder.
    pub uploaded: usize,
    /// Superseded or discarded server copies retired.
    pub retired: usize,
    /// `(draft id, why)` for everything that stays dirty and will be retried
    /// on the next sweep.
    pub failed: Vec<(String, String)>,
}

impl SweepReport {
    /// Did the sweep do anything a caller should refresh for?
    #[must_use]
    pub fn changed(&self) -> bool {
        self.uploaded > 0 || self.retired > 0
    }
}

/// Uploads every dirty draft and drains every pending retraction, against the
/// account's Drafts folder (`wire_name`).
///
/// `domain` seeds minted `Message-ID`s — the account address's domain, so the
/// ids are globally unique without being anyone's real message.
pub fn sweep(
    session: &mut Session,
    wire_name: &str,
    drafts: &Drafts,
    domain: &str,
    now_ms: i64,
) -> SweepReport {
    let mut report = SweepReport::default();

    let mailbox = match session.select_mailbox(wire_name) {
        Ok(mailbox) => mailbox,
        Err(why) => {
            // Nothing can proceed, and nothing is lost: dirt and tombstones
            // survive for the next sweep.
            report.failed.push((String::new(), why.to_string()));
            return report;
        }
    };
    let uid_validity = mailbox.uid_validity.unwrap_or(0);

    // Retractions first: a tombstone's copy must not outlive this sweep just
    // because an upload later in the loop failed.
    for (id, message_id) in drafts.pending_retractions() {
        match retire(session, &message_id, &[]) {
            Ok(retired) => {
                report.retired += retired;
                if let Err(why) = drafts.clear_retraction(&id) {
                    tracing::warn!(id, %why, "a retired draft's tombstone survived");
                }
            }
            Err(why) => report.failed.push((id, why.to_string())),
        }
    }

    let dirty = match drafts.dirty() {
        Ok(dirty) => dirty,
        Err(why) => {
            report.failed.push((String::new(), why.to_string()));
            return report;
        }
    };
    for id in dirty {
        match mirror_one(session, wire_name, drafts, &id, domain, uid_validity, now_ms) {
            Ok(retired) => {
                report.uploaded += 1;
                report.retired += retired;
            }
            Err(why) => report.failed.push((id, why.to_string())),
        }
    }
    report
}

/// Uploads one draft and retires what it replaces. Returns how many old
/// copies were retired.
fn mirror_one(
    session: &mut Session,
    wire_name: &str,
    drafts: &Drafts,
    id: &str,
    domain: &str,
    uid_validity: u32,
    now_ms: i64,
) -> crate::Result<usize> {
    let Some(draft) = drafts.peek(id)? else {
        // Deleted between the dirty listing and now. The delete left a
        // tombstone if one was needed; nothing to upload.
        return Ok(0);
    };
    let message_id = drafts
        .mirror(id)?
        .and_then(|mirror| mirror.message_id)
        .unwrap_or_else(|| mint_message_id(id, domain));

    // Before the append, so the new copy can never match its own retirement
    // query.
    let old = session.uids_by_message_id(&message_id)?;

    let landed = session.append_returning_uid(
        wire_name,
        &draft.mirror_bytes(&message_id, now_ms),
        Flags {
            draft: true,
            ..Flags::default()
        },
    )?;

    // Without UIDPLUS the receipt is a second search: whatever now matches
    // and did not before is the copy just filed.
    let landed = landed.or_else(|| {
        session
            .uids_by_message_id(&message_id)
            .ok()?
            .into_iter()
            .filter(|uid| !old.contains(uid))
            .max()
            .map(|uid| (uid_validity, uid))
    });

    let retired = retire(session, &message_id, &old)?;
    drafts.mark_mirrored(id, &message_id, landed)?;
    Ok(retired)
}

/// Deletes every message matching `message_id`, keeping `keep_none_but` —
/// pass the pre-append listing to delete exactly those, or `&[]` to search
/// fresh and delete all matches (a retraction).
fn retire(session: &mut Session, message_id: &str, exactly: &[u32]) -> crate::Result<usize> {
    let uids = if exactly.is_empty() {
        session.uids_by_message_id(message_id)?
    } else {
        exactly.to_vec()
    };
    let mut retired = 0;
    for uid in uids {
        session.delete_message(uid)?;
        retired += 1;
    }
    Ok(retired)
}

/// The `Message-ID` a draft mirrors under: minted once, stable across edits.
///
/// The draft id is already unique per store; the domain scopes it globally.
/// A host that cannot be a real deliverable domain is fine here — better, in
/// fact, than one that can.
#[must_use]
pub fn mint_message_id(draft_id: &str, domain: &str) -> String {
    let domain = domain.trim().trim_matches('@');
    let domain = if domain.is_empty() || !domain.contains('.') {
        "draft.invalid"
    } else {
        domain
    };
    format!("{draft_id}.draft@{domain}")
}

#[cfg(test)]
mod tests {
    use super::mint_message_id;

    #[test]
    fn minted_ids_are_stable_and_scoped_to_the_account_domain() {
        assert_eq!(
            mint_message_id("00000abc", "example.com"),
            "00000abc.draft@example.com"
        );
        assert_eq!(
            mint_message_id("00000abc", "example.com"),
            mint_message_id("00000abc", "example.com"),
            "an edit would orphan the previous copy"
        );
    }

    #[test]
    fn a_missing_or_unusable_domain_falls_back_to_an_undeliverable_one() {
        for bad in ["", "@", "localhost", "  "] {
            assert!(
                mint_message_id("1f", bad).ends_with("@draft.invalid"),
                "{bad:?} produced a deliverable-looking id"
            );
        }
    }
}

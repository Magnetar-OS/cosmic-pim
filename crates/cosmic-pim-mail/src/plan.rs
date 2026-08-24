// SPDX-License-Identifier: MPL-2.0

//! The reconciliation decision: given what the server lists and what we hold,
//! decide what to fetch, what to re-flag, and what to drop.
//!
//! Deliberately a pure function over two plain collections, for the same reason
//! [`cosmic_pim_caldav::plan`] is: it has no idea whether "what we hold" is a
//! maildir or a hash map, it is the part where the expensive mistakes live, and
//! being pure is what makes those mistakes cheap to write tests for.
//!
//! [`cosmic_pim_caldav::plan`]: https://docs.rs/cosmic-pim-caldav

use std::collections::BTreeMap;

use crate::model::Flags;

/// The diff between a server listing and what the store holds.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MailboxPlan {
    /// UIDs the server has and we do not.
    pub to_fetch: Vec<u32>,
    /// UIDs whose flags differ, with the server's version.
    pub flag_updates: Vec<(u32, Flags)>,
    /// UIDs we hold that the server no longer lists.
    pub to_remove: Vec<u32>,
    /// The empty-listing guard fired: the server returned zero UIDs while we
    /// hold messages.
    ///
    /// That shape is far more often a server hiccup or a half-failed SELECT
    /// than a genuine "the user emptied this mailbox", so removals are skipped
    /// for the round and the next sync self-corrects. Getting this wrong
    /// deletes a mailbox; getting it wrong in the other direction delays a
    /// deletion by one cycle.
    pub guard_tripped: bool,
}

/// UIDs above the cursor that we do not already hold, ascending.
///
/// The `> last_uid` filter is not redundant with asking for `last_uid+1:*`:
/// RFC 3501 specifies that a `*` range always returns *something*, so a mailbox
/// with nothing new answers `last+1:*` with its highest existing UID. A client
/// that trusts the range re-fetches the newest message on every single poll.
#[must_use]
pub fn plan_fetch(server_uids: &[u32], state: &crate::store::MailboxState) -> Vec<u32> {
    let mut uids: Vec<u32> = server_uids
        .iter()
        .copied()
        .filter(|uid| *uid > state.cursor.last_uid && !state.entries.contains_key(uid))
        .collect();
    uids.sort_unstable();
    uids.dedup();
    uids
}

/// The full reconciliation against an authoritative listing of the mailbox.
///
/// `server` must be the complete UID set with flags — the answer to a
/// `UID FETCH 1:* (FLAGS)`, not a windowed subset. Handing this a window would
/// make every message outside the window look deleted.
#[must_use]
pub fn plan_reconcile(server: &[(u32, Flags)], local: &BTreeMap<u32, Flags>) -> MailboxPlan {
    let mut plan = MailboxPlan::default();

    if server.is_empty() && !local.is_empty() {
        plan.guard_tripped = true;
        return plan;
    }

    let mut seen = std::collections::HashSet::with_capacity(server.len());
    for (uid, flags) in server {
        seen.insert(*uid);
        match local.get(uid) {
            None => plan.to_fetch.push(*uid),
            Some(held) => {
                // The server is authoritative for the five system flags and
                // knows nothing about maildir's `P`, so keeping the local value
                // is what stops every reconciliation from clearing it.
                let merged = flags.with_local_only_from(*held);
                if merged != *held {
                    plan.flag_updates.push((*uid, merged));
                }
            }
        }
    }
    for uid in local.keys() {
        if !seen.contains(uid) {
            plan.to_remove.push(*uid);
        }
    }

    plan.to_fetch.sort_unstable();
    plan.flag_updates.sort_unstable_by_key(|(uid, _)| *uid);
    plan.to_remove.sort_unstable();
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Cursor, MailboxState};

    fn seen() -> Flags {
        Flags {
            seen: true,
            ..Flags::default()
        }
    }

    fn state(last_uid: u32, held: &[(u32, Flags)]) -> MailboxState {
        MailboxState {
            cursor: Cursor {
                uid_validity: 1,
                last_uid,
                ..Cursor::default()
            },
            entries: held.iter().copied().collect(),
        }
    }

    #[test]
    fn the_star_range_quirk_does_not_cause_a_refetch() {
        // `UID 10:*` on a mailbox whose highest UID is 9 answers with 9. A
        // client that trusts the range re-downloads that message every poll.
        let state = state(9, &[(9, seen())]);
        assert!(
            plan_fetch(&[9], &state).is_empty(),
            "the newest message was re-fetched on an idle poll"
        );
        assert_eq!(plan_fetch(&[9, 10, 11], &state), vec![10, 11]);
    }

    #[test]
    fn a_uid_we_already_hold_is_never_refetched_even_above_the_cursor() {
        // Can happen after a partial cycle: the message landed, the cursor
        // commit did not.
        let state = state(5, &[(7, seen())]);
        assert_eq!(plan_fetch(&[7, 8], &state), vec![8]);
    }

    #[test]
    fn reconcile_fetches_new_reflags_changed_and_drops_absent() {
        let local: BTreeMap<u32, Flags> = [(1, seen()), (2, Flags::default()), (3, seen())]
            .into_iter()
            .collect();
        let server = [(1, seen()), (2, seen()), (4, Flags::default())];

        let plan = plan_reconcile(&server, &local);
        assert_eq!(plan.to_fetch, vec![4]);
        assert_eq!(plan.flag_updates, vec![(2, seen())]);
        assert_eq!(plan.to_remove, vec![3]);
        assert!(!plan.guard_tripped);
    }

    #[test]
    fn an_empty_listing_never_empties_the_mailbox() {
        let local: BTreeMap<u32, Flags> = [(1, seen())].into_iter().collect();
        let plan = plan_reconcile(&[], &local);
        assert!(plan.guard_tripped);
        assert!(
            plan.to_remove.is_empty(),
            "a server hiccup deleted the mailbox"
        );
        assert!(plan.to_fetch.is_empty());
    }

    #[test]
    fn an_empty_mailbox_that_is_genuinely_empty_is_not_a_guard_trip() {
        let plan = plan_reconcile(&[], &BTreeMap::new());
        assert!(!plan.guard_tripped);
        assert_eq!(plan, MailboxPlan::default());
    }

    #[test]
    fn a_maildir_only_flag_survives_reconciliation() {
        // The server cannot report `P` and must not be read as clearing it.
        let local: BTreeMap<u32, Flags> = [(
            1,
            Flags {
                passed: true,
                seen: true,
                ..Flags::default()
            },
        )]
        .into_iter()
        .collect();
        let plan = plan_reconcile(&[(1, seen())], &local);
        assert!(
            plan.flag_updates.is_empty(),
            "reconciliation rewrote a message to clear a flag the server never saw"
        );
    }

    #[test]
    fn a_flag_cleared_on_the_server_is_cleared_locally() {
        // Both directions, not just "the server set something". Marking a
        // message unread on a phone has to reach the desktop.
        let local: BTreeMap<u32, Flags> = [(1, seen())].into_iter().collect();
        let plan = plan_reconcile(&[(1, Flags::default())], &local);
        assert_eq!(plan.flag_updates, vec![(1, Flags::default())]);
    }
}

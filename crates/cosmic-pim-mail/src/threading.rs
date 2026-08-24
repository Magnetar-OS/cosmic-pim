// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The algorithm, the deterministic-id scheme, and the healing rules are ported
// from `src-tauri/src/threading.rs` in the Meltemi project. The storage is new:
// the donor took a `rusqlite::Connection` and issued queries inline, this takes
// a [`ThreadIndex`]. See NOTICE and LICENSING.md.

//! JWZ threading, with deterministic thread ids.
//!
//! # The keystone
//!
//! A thread's id is a hash of its **root** `Message-ID` — the first entry of the
//! `References` chain. Any message sharing a reference-chain root therefore
//! hashes to the same thread id, in any process, at any time, with no lookup at
//! all. Two replies to a parent we have never seen still land together: their
//! phantom root hashes identically.
//!
//! That single property is what makes threading survivable in a client that
//! syncs incrementally. Without it, "which thread is this in" is a question
//! about state, and state arrives out of order.
//!
//! # What hashing alone cannot do
//!
//! [`resolve_thread`] heals the three cases where a pure hash gets it wrong:
//!
//! - **Adoption.** A message whose `References` name something we already hold
//!   joins *that message's stored thread id*, which may not be the id its own
//!   chain would hash to. Keying on the provisional id instead of the stored one
//!   is a known accumulator bug: threads fragment a little more each sync.
//! - **Subject fallback.** A reply with no `References` at all — Outlook Web
//!   used to do this, and phones still do — joins the oldest thread with the
//!   same normalised subject.
//! - **Late parents.** Children that arrived before their parent sit under an id
//!   hashed from the parent's `Message-ID`. When the parent finally arrives and
//!   lands somewhere else, those children have to be moved. The resolution
//!   reports that as [`ThreadResolution::merged_from`].
//!
//! # Why a trait rather than a store
//!
//! Same reason [`crate::store::MailStore`] is a trait, and the same three
//! questions the donor asked SQLite are the whole interface. Threading is a
//! pure function of those three answers, so it is testable with a `HashMap` and
//! cannot acquire an opinion about storage.

use std::collections::HashMap;

/// Strips `Re:`/`Fwd:`/`Fw:`/`R:` prefixes and `[list]` tags until fixpoint, so
/// `"Re: [devs] Fwd: Release"` reduces to `"Release"`.
///
/// `R:` is in the list because it is what Italian and Greek mail clients write,
/// and a thread that splits in half depending on the sender's locale is a bug
/// the user cannot even describe.
#[must_use]
pub fn normalize_subject(subject: &str) -> String {
    let mut s = subject.trim().to_string();
    let mut changed = true;
    while changed {
        changed = false;
        if s.starts_with('[')
            && let Some(end) = s.find(']')
        {
            s = s[end + 1..].trim_start().to_string();
            changed = true;
        }
        let lower = s.to_lowercase();
        for prefix in &["re:", "fwd:", "fw:", "r:"] {
            if lower.starts_with(prefix) {
                s = s[prefix.len()..].trim_start().to_string();
                changed = true;
                break;
            }
        }
    }
    s.trim().to_string()
}

/// Parses a `References`/`In-Reply-To` header into individual `Message-ID`s,
/// angle brackets stripped, order preserved (oldest first, per RFC 5322).
///
/// Falls back to whitespace splitting when nothing is bracketed. Real headers
/// are malformed often enough that a strict parser would drop whole threads.
#[must_use]
pub fn parse_references(refs: &str) -> Vec<String> {
    let refs = refs.trim();
    if refs.is_empty() {
        return Vec::new();
    }
    let mut ids = Vec::new();
    let mut in_bracket = false;
    let mut current = String::new();
    for ch in refs.chars() {
        if ch == '<' {
            in_bracket = true;
            current.clear();
        } else if ch == '>' && in_bracket {
            in_bracket = false;
            let trimmed = current.trim().to_string();
            if !trimmed.is_empty() {
                ids.push(trimmed);
            }
        } else if in_bracket {
            current.push(ch);
        }
    }
    if ids.is_empty() {
        for token in refs.split_whitespace() {
            let cleaned = token.trim_start_matches('<').trim_end_matches('>').trim();
            if !cleaned.is_empty() {
                ids.push(cleaned.to_string());
            }
        }
    }
    ids
}

/// djb2 → hex. Collisions between distinct roots are possible (birthday bound
/// around 65k threads per account) and accepted: the cost is two conversations
/// shown as one, and the benefit is a thread id that is 9 bytes rather than 40
/// and computable without allocation.
fn djb2_hash(s: &str) -> String {
    let mut hash: u32 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(byte));
    }
    format!("{hash:x}")
}

/// Deterministic, account-scoped thread id from a root `Message-ID`.
///
/// Account-scoped because the same mailing-list thread reaching two of the
/// user's accounts is two conversations: they have different unread state,
/// different replies, and archiving one must not archive the other.
#[must_use]
pub fn thread_id_for_root(account_id: &str, root_message_id: &str) -> String {
    format!("r{account_id}-{}", djb2_hash(root_message_id))
}

/// The reference chain of a message: `References` ids, then any `In-Reply-To`
/// ids not already present.
#[must_use]
pub fn reference_chain(references_header: &str, in_reply_to_header: &str) -> Vec<String> {
    let mut ids = parse_references(references_header);
    for id in parse_references(in_reply_to_header) {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// Root `Message-ID` selection: first id of the chain, else the message's own
/// `Message-ID`, else the caller's fallback (a UID-derived string).
///
/// The fallback exists because a message with neither is still a message, and
/// giving it no thread would drop it out of a threaded list entirely.
#[must_use]
pub fn root_reference<'a>(
    chain: &'a [String],
    message_id: Option<&'a str>,
    fallback: &'a str,
) -> &'a str {
    chain
        .first()
        .map(String::as_str)
        .or(message_id)
        .unwrap_or(fallback)
}

/// The three questions threading asks about what is already stored.
///
/// Everything else is arithmetic on header text.
pub trait ThreadIndex {
    /// The thread id recorded for the message with this `Message-ID`, if we
    /// hold it.
    ///
    /// This must return the **stored** id, not one recomputed from the ancestor's
    /// headers. Recomputing is the fragmentation bug: an ancestor that was
    /// itself adopted into another thread would hand back an id nothing is
    /// filed under.
    fn thread_of_message(&self, message_id: &str) -> Option<String>;

    /// The oldest thread whose normalised subject is exactly this, if any.
    ///
    /// Oldest rather than "any": with several candidates the choice has to be
    /// deterministic, or two clients — or the same client on a re-index — merge
    /// the same messages into different threads.
    fn oldest_thread_with_subject(&self, subject_norm: &str) -> Option<String>;

    /// Do we hold any message under this thread id?
    fn has_thread(&self, thread_id: &str) -> bool;
}

/// Where a freshly parsed message belongs, and what its arrival repaired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadResolution {
    pub thread_id: String,
    /// Provisional thread ids whose existing messages must be re-filed under
    /// [`Self::thread_id`] — the late-parent heal. Empty in the ordinary case.
    pub merged_from: Vec<String>,
}

/// Everything about one message that threading needs.
#[derive(Debug, Clone, Copy)]
pub struct Threadable<'a> {
    pub message_id: Option<&'a str>,
    pub references_header: &'a str,
    pub in_reply_to_header: &'a str,
    /// The subject as written — needed to tell a genuine reply-without-references
    /// from an original message that happens to share a subject.
    pub subject: &'a str,
    pub subject_norm: &'a str,
    /// Used as the root when the message has no `Message-ID` and no references.
    /// A `mailbox/uid` string is the obvious choice.
    pub uid_fallback: &'a str,
}

/// Decides the thread for a new message, and detects the merges its arrival
/// enables.
///
/// Precedence:
/// 1. **Adoption** — nearest stored ancestor first. `In-Reply-To` is the tail of
///    the chain, so the walk is in reverse: the immediate parent's thread is a
///    better answer than the thread of something 40 messages up.
/// 2. **Subject fallback** — only for a message with no references *and* a
///    reply-shaped subject. Without the second condition, every message titled
///    "Invoice" would join one enormous thread.
/// 3. **Deterministic root hash** — including the phantom-root case.
pub fn resolve_thread(
    index: &impl ThreadIndex,
    account_id: &str,
    message: Threadable<'_>,
) -> ThreadResolution {
    let chain = reference_chain(message.references_header, message.in_reply_to_header);

    let adopted = chain
        .iter()
        .rev()
        .find_map(|ancestor| index.thread_of_message(ancestor));

    let thread_id = if let Some(id) = adopted {
        id
    } else {
        // `subject_norm != subject.trim()` is the test for "this subject
        // carried a Re:/Fwd: prefix", which is the only evidence available that
        // a reference-less message is a reply at all.
        let reply_shaped = chain.is_empty()
            && !message.subject_norm.is_empty()
            && message.subject_norm != message.subject.trim();
        let by_subject = if reply_shaped {
            index.oldest_thread_with_subject(message.subject_norm)
        } else {
            None
        };
        by_subject.unwrap_or_else(|| {
            let root = root_reference(&chain, message.message_id, message.uid_fallback);
            thread_id_for_root(account_id, root)
        })
    };

    // Children that arrived before us hashed our own Message-ID as their root.
    // If we landed elsewhere, they are now orphans of a thread that no longer
    // exists as far as the UI is concerned.
    let mut merged_from = Vec::new();
    if let Some(own_id) = message.message_id {
        let provisional = thread_id_for_root(account_id, own_id);
        if provisional != thread_id && index.has_thread(&provisional) {
            merged_from.push(provisional);
        }
    }

    ThreadResolution {
        thread_id,
        merged_from,
    }
}

/// A [`ThreadIndex`] over plain maps, for tests and for a caller that has
/// already loaded a mailbox.
#[derive(Debug, Default)]
pub struct MemoryIndex {
    /// `Message-ID` → the thread id it is filed under.
    pub by_message_id: HashMap<String, String>,
    /// Thread id → (normalised subject, oldest message time in ms).
    pub threads: HashMap<String, (String, i64)>,
}

impl MemoryIndex {
    /// Records one stored message.
    pub fn insert(&mut self, message_id: &str, thread_id: &str, subject_norm: &str, date_ms: i64) {
        self.by_message_id
            .insert(message_id.to_owned(), thread_id.to_owned());
        self.threads
            .entry(thread_id.to_owned())
            .and_modify(|(_, oldest)| *oldest = (*oldest).min(date_ms))
            .or_insert_with(|| (subject_norm.to_owned(), date_ms));
    }
}

impl ThreadIndex for MemoryIndex {
    fn thread_of_message(&self, message_id: &str) -> Option<String> {
        self.by_message_id.get(message_id).cloned()
    }

    fn oldest_thread_with_subject(&self, subject_norm: &str) -> Option<String> {
        self.threads
            .iter()
            .filter(|(_, (subject, _))| subject == subject_norm)
            .min_by_key(|(id, (_, oldest))| (*oldest, (*id).clone()))
            .map(|(id, _)| id.clone())
    }

    fn has_thread(&self, thread_id: &str) -> bool {
        self.threads.contains_key(thread_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "acct-1";

    fn threadable<'a>(
        message_id: Option<&'a str>,
        references: &'a str,
        in_reply_to: &'a str,
        subject: &'a str,
        subject_norm: &'a str,
    ) -> Threadable<'a> {
        Threadable {
            message_id,
            references_header: references,
            in_reply_to_header: in_reply_to,
            subject,
            subject_norm,
            uid_fallback: "INBOX/1",
        }
    }

    #[test]
    fn subject_prefixes_strip_to_fixpoint_in_any_order() {
        assert_eq!(normalize_subject("Re: [devs] Fwd: Release"), "Release");
        assert_eq!(normalize_subject("RE: FW: re: Budget"), "Budget");
        assert_eq!(
            normalize_subject("R: Ciao"),
            "Ciao",
            "the Italian/Greek prefix"
        );
        assert_eq!(normalize_subject("Release"), "Release");
    }

    #[test]
    fn malformed_reference_headers_still_yield_ids() {
        assert_eq!(parse_references("<a@x> <b@x>"), vec!["a@x", "b@x"]);
        assert_eq!(
            parse_references("a@x b@x"),
            vec!["a@x", "b@x"],
            "unbracketed ids are common enough that dropping them loses threads"
        );
        assert!(parse_references("   ").is_empty());
    }

    #[test]
    fn two_replies_to_an_unseen_parent_land_in_one_thread() {
        // The phantom root: neither reply's parent was ever synced.
        let index = MemoryIndex::default();
        let a = resolve_thread(
            &index,
            ACCOUNT,
            threadable(Some("a@x"), "<root@x>", "<root@x>", "Re: X", "X"),
        );
        let b = resolve_thread(
            &index,
            ACCOUNT,
            threadable(Some("b@x"), "<root@x>", "<root@x>", "Re: X", "X"),
        );
        assert_eq!(a.thread_id, b.thread_id);
        assert_eq!(a.thread_id, thread_id_for_root(ACCOUNT, "root@x"));
    }

    #[test]
    fn adoption_uses_the_ancestors_stored_id_not_a_recomputed_one() {
        // The parent was itself adopted into a thread whose id does NOT match
        // what its own chain hashes to. Recomputing here would file the child
        // under an id nothing is stored against — the fragmentation bug.
        let mut index = MemoryIndex::default();
        index.insert("parent@x", "legacy-thread", "X", 1_000);

        let child = resolve_thread(
            &index,
            ACCOUNT,
            threadable(
                Some("c@x"),
                "<root@x> <parent@x>",
                "<parent@x>",
                "Re: X",
                "X",
            ),
        );
        assert_eq!(child.thread_id, "legacy-thread");
    }

    #[test]
    fn the_nearest_stored_ancestor_wins() {
        let mut index = MemoryIndex::default();
        index.insert("root@x", "old-thread", "X", 1_000);
        index.insert("parent@x", "current-thread", "X", 2_000);

        let child = resolve_thread(
            &index,
            ACCOUNT,
            threadable(
                Some("c@x"),
                "<root@x> <parent@x>",
                "<parent@x>",
                "Re: X",
                "X",
            ),
        );
        assert_eq!(
            child.thread_id, "current-thread",
            "the walk went oldest-first and picked a distant ancestor"
        );
    }

    #[test]
    fn a_reply_with_no_references_joins_by_subject() {
        let mut index = MemoryIndex::default();
        index.insert("orig@x", "t-original", "Budget", 1_000);

        let reply = resolve_thread(
            &index,
            ACCOUNT,
            threadable(Some("r@x"), "", "", "Re: Budget", "Budget"),
        );
        assert_eq!(reply.thread_id, "t-original");
    }

    #[test]
    fn a_fresh_message_never_joins_a_thread_by_subject_alone() {
        // Without the reply-shape test, every message titled "Invoice" would
        // collapse into one conversation.
        let mut index = MemoryIndex::default();
        index.insert("orig@x", "t-original", "Invoice", 1_000);

        let fresh = resolve_thread(
            &index,
            ACCOUNT,
            threadable(Some("n@x"), "", "", "Invoice", "Invoice"),
        );
        assert_eq!(fresh.thread_id, thread_id_for_root(ACCOUNT, "n@x"));
    }

    #[test]
    fn subject_merge_picks_the_oldest_candidate_deterministically() {
        let mut index = MemoryIndex::default();
        index.insert("b@x", "t-newer", "Budget", 5_000);
        index.insert("a@x", "t-older", "Budget", 1_000);

        for _ in 0..8 {
            let reply = resolve_thread(
                &index,
                ACCOUNT,
                threadable(Some("r@x"), "", "", "Re: Budget", "Budget"),
            );
            assert_eq!(reply.thread_id, "t-older", "the choice was order-sensitive");
        }
    }

    #[test]
    fn a_late_parent_reports_the_orphans_it_reclaims() {
        // The child arrived first and hashed the parent's Message-ID as root.
        let mut index = MemoryIndex::default();
        let provisional = thread_id_for_root(ACCOUNT, "parent@x");
        index.insert("child@x", &provisional, "X", 2_000);
        // The parent is itself a reply, so it lands elsewhere.
        index.insert("grand@x", "t-grand", "X", 500);

        let parent = resolve_thread(
            &index,
            ACCOUNT,
            threadable(Some("parent@x"), "<grand@x>", "<grand@x>", "Re: X", "X"),
        );
        assert_eq!(parent.thread_id, "t-grand");
        assert_eq!(
            parent.merged_from,
            vec![provisional],
            "the children that arrived first were left in a dead thread"
        );
    }

    #[test]
    fn no_merge_is_reported_when_there_is_nothing_to_move() {
        let index = MemoryIndex::default();
        let msg = resolve_thread(
            &index,
            ACCOUNT,
            threadable(Some("a@x"), "<root@x>", "", "Re: X", "X"),
        );
        assert!(msg.merged_from.is_empty());
    }

    #[test]
    fn a_message_with_no_ids_at_all_still_gets_a_thread() {
        let index = MemoryIndex::default();
        let msg = resolve_thread(&index, ACCOUNT, threadable(None, "", "", "hi", "hi"));
        assert_eq!(msg.thread_id, thread_id_for_root(ACCOUNT, "INBOX/1"));
    }

    #[test]
    fn thread_ids_are_account_scoped() {
        assert_ne!(
            thread_id_for_root("a", "root@x"),
            thread_id_for_root("b", "root@x"),
            "the same list thread in two accounts is two conversations"
        );
    }
}

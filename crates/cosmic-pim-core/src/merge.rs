// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Three-way merge of iCalendar and vCard documents, unit by unit.
//!
//! # What this is for
//!
//! When the server and this device both changed one resource, the sync engine
//! records a conflict rather than letting either copy silently win. Most of
//! those conflicts are not real disagreements: the server moved the start time
//! and this device renamed the summary. Given the *base* — the last-synced
//! bytes both edits started from — the two changes can be told apart and
//! combined, and the user never sees a question they would have answered with
//! "well, both, obviously".
//!
//! # What "conservative" means here
//!
//! [`merge3`] returns `None` — merge refused, record the conflict — whenever
//! the answer is not mechanical:
//!
//! - both sides changed the same property to different values;
//! - both sides touched the same collectively-tracked sub-component set
//!   (VALARM, VTIMEZONE — anything without a natural identity);
//! - a keyed sub-component (a VEVENT named by UID + RECURRENCE-ID) was added
//!   or removed on one side while the other side changed it;
//! - the documents are not the same kind of component at all.
//!
//! A refused merge costs one question in the conflict UI. A wrong merge writes
//! invented data to every device the user owns. The asymmetry decides every
//! borderline case.
//!
//! The question itself is served by the same machinery: [`overlaps`] lists
//! exactly the units [`merge3`] refused over — base, local, and remote
//! versions side by side — and [`resolve`] rebuilds the document from the
//! user's per-unit choices, merging everything undisputed the ordinary way.
//! That is the whole per-property conflict UI contract: show `overlaps`,
//! collect a [`Side`] per unit, write back what `resolve` returns.
//!
//! # Units
//!
//! A component's contents divide into units, compared side by side:
//!
//! - **Properties**, keyed by `(group, NAME)`. All occurrences of one key are
//!   one unit — `ATTENDEE` lines move as a block, so reordering or editing any
//!   of them counts as changing them all. Values are compared *unfolded*, so a
//!   re-folded but identical line is not a change.
//! - **Keyed children**: `VEVENT`, `VTODO`, `VJOURNAL`, identified by their
//!   `UID` and `RECURRENCE-ID` values. These recurse — the server editing an
//!   override's `DTSTART` while we edit the master's `SUMMARY` merges cleanly.
//! - **Collective children**: every other component name (`VALARM`,
//!   `VTIMEZONE`, …) is tracked as one unit per name. They have no reliable
//!   identity, so "both sides touched the alarms" is a conflict, not a guess.
//!
//! The merged output starts from the **remote** text — the server's bytes pass
//! through byte-for-byte wherever this side did not change them, which keeps
//! the verbatim-storage invariant for everything the merge did not touch.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::patch::{ContentLine, fold, logical_lines, terminator_of};

/// Component names that carry a usable identity (`UID` + `RECURRENCE-ID`).
const KEYED: [&str; 3] = ["VEVENT", "VTODO", "VJOURNAL"];

/// Merges two divergent revisions of one document, given their common base.
///
/// `None` means the changes overlap and a human has to choose; see the module
/// docs for exactly when. `Some` is a document carrying the remote revision
/// with the local revision's changes applied on top.
#[must_use]
pub fn merge3(base: &str, local: &str, remote: &str) -> Option<String> {
    // Even the trivial cases check that all three are the same kind of
    // document: a "merge" that hands back a VCALENDAR because the other two
    // copies of a vCard happened to be equal is not a merge, it is a swap.
    let kind = |text: &str| logical_lines(text).first().and_then(ContentLine::begins);
    let base_kind = kind(base)?;
    if kind(local)? != base_kind || kind(remote)? != base_kind {
        return None;
    }

    // Nothing to reconcile when one side did not actually change.
    if local == base {
        return Some(remote.to_owned());
    }
    if remote == base || local == remote {
        return Some(local.to_owned());
    }
    merge_component(base, local, remote)
}

/* ---------------- inventory ---------------- */

/// One unit's identity within a component.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    /// `(group, NAME)` of a property line.
    Prop(Option<String>, String),
    /// A keyed child: `(component name, UID value, RECURRENCE-ID value)`.
    Child(String, String, String),
    /// All children of one un-keyed component name, as a block.
    Collective(String),
}

/// One item of a component's interior, in document order.
#[derive(Debug)]
enum Item {
    /// A property line, by index into the line vector.
    Prop(Key, usize),
    /// A child component, by line range (BEGIN..=END).
    Child(Key, Range<usize>),
}

struct Inventory<'a> {
    lines: Vec<ContentLine<'a>>,
    /// The component name of the outermost BEGIN/END.
    component: String,
    items: Vec<Item>,
}

impl Inventory<'_> {
    /// The unit's content for comparison: unfolded lines, in order, across
    /// every occurrence. `None` when the component has no such unit.
    fn value(&self, key: &Key) -> Option<Vec<String>> {
        let mut out = Vec::new();
        let mut found = false;
        for item in &self.items {
            match item {
                Item::Prop(k, line) if k == key => {
                    found = true;
                    out.push(self.lines[*line].unfolded().to_owned());
                }
                Item::Child(k, range) if k == key => {
                    found = true;
                    out.extend(
                        self.lines[range.clone()]
                            .iter()
                            .map(|l| l.unfolded().to_owned()),
                    );
                }
                _ => {}
            }
        }
        found.then_some(out)
    }

    /// The raw text of a keyed child, for recursive merging.
    fn child_text(&self, key: &Key) -> Option<String> {
        self.items.iter().find_map(|item| match item {
            Item::Child(k, range) if k == key => Some(
                self.lines[range.clone()]
                    .iter()
                    .map(ContentLine::raw)
                    .collect(),
            ),
            _ => None,
        })
    }

    fn keys(&self) -> Vec<Key> {
        let mut out: Vec<Key> = Vec::new();
        for item in &self.items {
            let key = match item {
                Item::Prop(k, _) | Item::Child(k, _) => k.clone(),
            };
            if !out.contains(&key) {
                out.push(key);
            }
        }
        out
    }
}

/// Parses one component's text into its inventory.
///
/// `None` for anything that is not exactly one component: no BEGIN, unbalanced
/// nesting, trailing content — a merge over text this code half-understands
/// would be a merge over guesses.
fn inventory(text: &str) -> Option<Inventory<'_>> {
    let lines = logical_lines(text);
    let component = lines.first()?.begins()?;

    let mut items = Vec::new();
    let mut i = 1usize;
    let end = lines.len().checked_sub(1)?;
    if lines[end].ends()? != component {
        return None;
    }

    while i < end {
        let line = &lines[i];
        if let Some(child) = line.begins() {
            // Find the matching END, tracking nesting inside the child.
            let start = i;
            let mut depth = 1usize;
            i += 1;
            while i < end && depth > 0 {
                if lines[i].begins().is_some() {
                    depth += 1;
                } else if lines[i].ends().is_some() {
                    depth -= 1;
                }
                i += 1;
            }
            if depth != 0 {
                return None;
            }
            let range = start..i;
            let key = if KEYED.contains(&child.as_str()) {
                let field = |name: &str| {
                    lines[range.clone()]
                        .iter()
                        .find(|l| l.name() == name)
                        .map(|l| l.value().trim().to_owned())
                        .unwrap_or_default()
                };
                Key::Child(child, field("UID"), field("RECURRENCE-ID"))
            } else {
                Key::Collective(child)
            };
            items.push(Item::Child(key, range));
        } else if line.ends().is_some() {
            // An END with no matching BEGIN at this depth.
            return None;
        } else {
            let key = Key::Prop(line.group().map(ToOwned::to_owned), line.name());
            items.push(Item::Prop(key, i));
            i += 1;
        }
    }

    // Two keyed children with the same identity would make substitution
    // ambiguous. Real files do not do this; a merge over one that does would
    // be a guess.
    let mut seen = Vec::new();
    for item in &items {
        if let Item::Child(key @ Key::Child(..), _) = item {
            if seen.contains(&key) {
                return None;
            }
            seen.push(key);
        }
    }

    Some(Inventory {
        lines,
        component,
        items,
    })
}

/* ---------------- overlaps, and choosing over them ---------------- */

/// Which revision's version of one disputed unit survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
}

/// One unit both revisions changed, incompatibly — the thing a conflict UI
/// puts in front of the user, with all three versions to diff.
///
/// `unit` is a stable label doubling as the choice key for [`resolve`]:
/// `"SUMMARY"`, `"item1.EMAIL"`, `"VALARM"`, and for a dispute *inside* a
/// keyed child, a slash path like `"VEVENT s@x 20260810T090000Z/SUMMARY"`.
/// The values are unfolded logical lines; `None` means the unit does not
/// exist in that revision (added on one side, or deleted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlap {
    pub unit: String,
    pub base: Option<Vec<String>>,
    pub local: Option<Vec<String>>,
    pub remote: Option<Vec<String>>,
}

/// The disputed units of a divergence — what [`merge3`] could not decide.
///
/// Empty means the revisions merge cleanly (or one side did not change);
/// `None` means the texts cannot be compared at all (unparseable, or not the
/// same kind of document), in which case the only honest resolutions are
/// wholesale keep-local / take-remote.
#[must_use]
pub fn overlaps(base: &str, local: &str, remote: &str) -> Option<Vec<Overlap>> {
    if local == base || remote == base || local == remote {
        return Some(Vec::new());
    }
    let mut found = Vec::new();
    merge_with(base, local, remote, "", &mut |unit, b, l, r| {
        found.push(Overlap {
            unit: unit.to_owned(),
            base: b.map(<[String]>::to_vec),
            local: l.map(<[String]>::to_vec),
            remote: r.map(<[String]>::to_vec),
        });
        // Any answer keeps the walk going; the output text is discarded.
        Some(Side::Remote)
    })?;
    Some(found)
}

/// Builds the merged text from per-unit choices over the [`overlaps`].
///
/// `choices` maps each [`Overlap::unit`] to the side that survives; every
/// disputed unit must be decided — a missing choice yields `None` rather than
/// a half-resolved document. Units that were never in dispute merge exactly
/// as [`merge3`] would have merged them.
#[must_use]
pub fn resolve(
    base: &str,
    local: &str,
    remote: &str,
    choices: &BTreeMap<String, Side>,
) -> Option<String> {
    merge_with(base, local, remote, "", &mut |unit, _, _, _| {
        choices.get(unit).copied()
    })
}

/// The choice-key label for one unit, extended by `path` when nested.
fn label(path: &str, key: &Key) -> String {
    let own = match key {
        Key::Prop(None, name) | Key::Collective(name) => name.clone(),
        Key::Prop(Some(group), name) => format!("{group}.{name}"),
        Key::Child(name, uid, rid) if rid.is_empty() => format!("{name} {uid}"),
        Key::Child(name, uid, rid) => format!("{name} {uid} {rid}"),
    };
    if path.is_empty() {
        own
    } else {
        format!("{path}/{own}")
    }
}

/* ---------------- the merge ---------------- */

/// What to do about one genuinely overlapping unit. `None` aborts the merge.
type Decide<'a> =
    dyn FnMut(&str, Option<&[String]>, Option<&[String]>, Option<&[String]>) -> Option<Side> + 'a;

fn merge_component(base: &str, local: &str, remote: &str) -> Option<String> {
    // The strict form: any overlap is fatal. `merge3`'s behaviour.
    merge_with(base, local, remote, "", &mut |_, _, _, _| None)
}

fn merge_with(
    base: &str,
    local: &str,
    remote: &str,
    path: &str,
    decide: &mut Decide<'_>,
) -> Option<String> {
    let base_inv = inventory(base)?;
    let local_inv = inventory(local)?;
    let remote_inv = inventory(remote)?;

    if base_inv.component != local_inv.component || base_inv.component != remote_inv.component {
        return None;
    }

    // Every unit any revision mentions, in a stable order.
    let mut keys = base_inv.keys();
    for key in local_inv.keys().into_iter().chain(remote_inv.keys()) {
        if !keys.contains(&key) {
            keys.push(key);
        }
    }

    let terminator = terminator_of(remote);

    // What the local revision's version of each changed unit looks like,
    // re-terminated for the remote document. `None` payload = unit deleted.
    let mut substitutions: BTreeMap<Key, Option<String>> = BTreeMap::new();

    for key in &keys {
        let b = base_inv.value(key);
        let l = local_inv.value(key);
        let r = remote_inv.value(key);

        let local_changed = l != b;
        let remote_changed = r != b;

        if !local_changed {
            continue; // remote's version flows through the reconstruction
        }
        let take_local = if remote_changed {
            if l == r {
                continue; // both made the identical change
            }
            // Both changed a keyed child: recurse — the disagreement may be
            // about different units inside it, each decidable on its own.
            if let (Key::Child(..), Some(_), Some(_), Some(_)) = (key, &b, &l, &r) {
                let merged = merge_with(
                    &base_inv.child_text(key)?,
                    &local_inv.child_text(key)?,
                    &remote_inv.child_text(key)?,
                    &label(path, key),
                    decide,
                )?;
                substitutions.insert(key.clone(), Some(merged));
                continue;
            }
            // A genuine overlap: someone decides, or nobody does and the
            // merge honestly fails.
            match decide(&label(path, key), b.as_deref(), l.as_deref(), r.as_deref())? {
                Side::Local => true,
                // Remote's version (or its deletion) flows through the
                // reconstruction untouched.
                Side::Remote => continue,
            }
        } else {
            true // changed locally only: local is authoritative for this unit
        };

        debug_assert!(take_local);
        let replacement = match &l {
            None => None,
            Some(unfolded_lines) => {
                let mut text = String::new();
                for line in unfolded_lines {
                    fold(line, terminator, &mut text);
                }
                Some(text)
            }
        };
        substitutions.insert(key.clone(), replacement);
    }

    // Reconstruct on the remote text: its bytes pass through untouched except
    // where a substitution replaces a unit, emitted once at the unit's first
    // occurrence.
    let mut out = String::with_capacity(remote.len() + 256);
    out.push_str(remote_inv.lines[0].raw());

    let mut emitted: Vec<&Key> = Vec::new();
    for item in &remote_inv.items {
        let (key, raw): (&Key, String) = match item {
            Item::Prop(k, line) => (k, remote_inv.lines[*line].raw().to_owned()),
            Item::Child(k, range) => (
                k,
                remote_inv.lines[range.clone()]
                    .iter()
                    .map(ContentLine::raw)
                    .collect(),
            ),
        };
        match substitutions.get(key) {
            None => out.push_str(&raw),
            Some(replacement) => {
                if !emitted.contains(&key) {
                    emitted.push(key);
                    if let Some(text) = replacement {
                        out.push_str(text);
                    }
                }
                // Later occurrences of a substituted unit are dropped: the
                // replacement covered the whole unit.
            }
        }
    }

    // Units the local revision added that the remote never had.
    for (key, replacement) in &substitutions {
        if !emitted.contains(&key)
            && let Some(text) = replacement
        {
            out.push_str(text);
        }
    }

    out.push_str(remote_inv.lines[remote_inv.lines.len() - 1].raw());
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn event(summary: &str, dtstart: &str, location: Option<&str>) -> String {
        let mut s = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n");
        s.push_str("BEGIN:VEVENT\r\nUID:a@test\r\n");
        s.push_str(&format!("DTSTART:{dtstart}\r\n"));
        s.push_str(&format!("SUMMARY:{summary}\r\n"));
        if let Some(location) = location {
            s.push_str(&format!("LOCATION:{location}\r\n"));
        }
        s.push_str("X-KEEP:untouched\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n");
        s
    }

    #[test]
    fn disjoint_property_edits_merge() {
        let base = event("Team sync", "20260810T090000Z", None);
        let local = event("Team sync (moved)", "20260810T090000Z", None);
        let remote = event("Team sync", "20260810T100000Z", None);

        let merged = merge3(&base, &local, &remote).expect("disjoint edits must merge");
        assert!(merged.contains("SUMMARY:Team sync (moved)\r\n"), "{merged}");
        assert!(merged.contains("DTSTART:20260810T100000Z\r\n"), "{merged}");
        assert!(merged.contains("X-KEEP:untouched\r\n"));
    }

    #[test]
    fn the_same_property_changed_both_ways_is_a_conflict() {
        let base = event("Team sync", "20260810T090000Z", None);
        let local = event("Sprint review", "20260810T090000Z", None);
        let remote = event("Retrospective", "20260810T090000Z", None);

        assert!(
            merge3(&base, &local, &remote).is_none(),
            "two different renames merged; whose title survived?"
        );
    }

    #[test]
    fn the_same_change_on_both_sides_converges() {
        let base = event("Team sync", "20260810T090000Z", None);
        let both = event("Sprint review", "20260810T090000Z", None);

        let merged = merge3(&base, &both, &both).expect("identical changes agree");
        assert!(merged.contains("SUMMARY:Sprint review\r\n"));
    }

    #[test]
    fn an_unchanged_side_yields_the_other() {
        let base = event("A", "20260810T090000Z", None);
        let remote = event("B", "20260810T090000Z", None);
        assert_eq!(merge3(&base, &base, &remote).unwrap(), remote);
        assert_eq!(merge3(&base, &remote, &base).unwrap(), remote);
    }

    #[test]
    fn a_locally_added_property_lands_in_the_merge() {
        let base = event("Team sync", "20260810T090000Z", None);
        let local = event("Team sync", "20260810T090000Z", Some("Room 5"));
        let remote = event("Team sync", "20260810T100000Z", None);

        let merged = merge3(&base, &local, &remote).expect("an addition is not an overlap");
        assert!(merged.contains("LOCATION:Room 5\r\n"), "{merged}");
        assert!(merged.contains("DTSTART:20260810T100000Z\r\n"));
    }

    #[test]
    fn a_locally_removed_property_stays_removed() {
        let base = event("Team sync", "20260810T090000Z", Some("Room 5"));
        let local = event("Team sync", "20260810T090000Z", None);
        let remote = event("Team sync", "20260810T100000Z", Some("Room 5"));

        let merged = merge3(&base, &local, &remote).expect("a removal is not an overlap");
        assert!(!merged.contains("LOCATION"), "{merged}");
        assert!(merged.contains("DTSTART:20260810T100000Z\r\n"));
    }

    #[test]
    fn remove_versus_edit_of_the_same_property_is_a_conflict() {
        let base = event("Team sync", "20260810T090000Z", Some("Room 5"));
        let local = event("Team sync", "20260810T090000Z", None);
        let remote = event("Team sync", "20260810T090000Z", Some("Room 6"));

        assert!(merge3(&base, &local, &remote).is_none());
    }

    #[test]
    fn remote_bytes_pass_through_verbatim_where_untouched() {
        // The remote revision carries a property our model knows nothing
        // about, oddly folded. It must come out byte-for-byte.
        let base = event("Team sync", "20260810T090000Z", None);
        let local = event("Team sync (moved)", "20260810T090000Z", None);
        let remote = base.replace(
            "X-KEEP:untouched\r\n",
            "ATTENDEE;CN=\"Lovelace, Ada\":mailto\r\n :ada@example.com\r\nX-KEEP:untouched\r\n",
        );

        let merged = merge3(&base, &local, &remote).expect("merged");
        assert!(
            merged.contains("ATTENDEE;CN=\"Lovelace, Ada\":mailto\r\n :ada@example.com\r\n"),
            "the server's own folding was rewritten: {merged}"
        );
    }

    #[test]
    fn refolding_is_not_a_change() {
        let base = event("Team sync", "20260810T090000Z", None);
        // The server re-folded SUMMARY without changing its content, and
        // changed DTSTART. We renamed. The re-fold must not read as an edit
        // colliding with ours.
        let local = event("Sprint review", "20260810T090000Z", None);
        let remote = event("Team sync", "20260810T100000Z", None)
            .replace("SUMMARY:Team sync\r\n", "SUMMARY:Team\r\n  sync\r\n");

        let merged = merge3(&base, &local, &remote).expect("a re-fold is not an edit");
        assert!(merged.contains("SUMMARY:Sprint review\r\n"), "{merged}");
    }

    /* ---------------- multi-component files ---------------- */

    fn series(master_summary: &str, override_summary: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
             BEGIN:VEVENT\r\nUID:s@x\r\nDTSTART:20260803T090000Z\r\n\
             RRULE:FREQ=WEEKLY\r\nSUMMARY:{master_summary}\r\nEND:VEVENT\r\n\
             BEGIN:VEVENT\r\nUID:s@x\r\nRECURRENCE-ID:20260810T090000Z\r\n\
             DTSTART:20260810T100000Z\r\nSUMMARY:{override_summary}\r\nEND:VEVENT\r\n\
             END:VCALENDAR\r\n"
        )
    }

    #[test]
    fn edits_to_different_components_of_one_file_merge() {
        let base = series("Master", "Override");
        let local = series("Master renamed", "Override");
        let remote = series("Master", "Override renamed");

        let merged = merge3(&base, &local, &remote).expect("different components");
        assert!(merged.contains("SUMMARY:Master renamed\r\n"), "{merged}");
        assert!(merged.contains("SUMMARY:Override renamed\r\n"), "{merged}");
    }

    #[test]
    fn disjoint_edits_inside_one_component_merge_recursively() {
        // Both sides touched the SAME override — but different properties of
        // it. The recursion is what makes this merge instead of conflict.
        let base = series("Master", "Override");
        let local = series("Master", "Override renamed");
        let remote = base.replace(
            "DTSTART:20260810T100000Z\r\n",
            "DTSTART:20260810T110000Z\r\n",
        );

        let merged = merge3(&base, &local, &remote).expect("recursive merge");
        assert!(merged.contains("SUMMARY:Override renamed\r\n"), "{merged}");
        assert!(merged.contains("DTSTART:20260810T110000Z\r\n"), "{merged}");
    }

    #[test]
    fn the_same_property_of_the_same_component_is_still_a_conflict() {
        let base = series("Master", "Override");
        let local = series("Master", "Mine");
        let remote = series("Master", "Theirs");

        assert!(merge3(&base, &local, &remote).is_none());
    }

    #[test]
    fn an_override_added_locally_survives_a_remote_master_edit() {
        let one = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
             BEGIN:VEVENT\r\nUID:s@x\r\nDTSTART:20260803T090000Z\r\n\
             RRULE:FREQ=WEEKLY\r\nSUMMARY:Master\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let local = series("Master", "Skipped this week");
        let remote = one.replace("SUMMARY:Master", "SUMMARY:Master renamed");

        let merged = merge3(one, &local, &remote).expect("an added override is not an overlap");
        assert!(merged.contains("SUMMARY:Master renamed\r\n"), "{merged}");
        assert!(
            merged.contains("RECURRENCE-ID:20260810T090000Z\r\n"),
            "{merged}"
        );
        assert!(merged.contains("SUMMARY:Skipped this week\r\n"));
    }

    #[test]
    fn both_touching_the_alarms_is_a_conflict() {
        // VALARMs have no identity; guessing which alarm is "the same one"
        // invents data. Both-changed → the user decides.
        let alarm = |trigger: &str| {
            format!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:a@x\r\n\
                 SUMMARY:S\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:{trigger}\r\n\
                 END:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
            )
        };
        let base = alarm("-PT10M");
        let local = alarm("-PT5M");
        let remote = alarm("-PT30M");
        assert!(merge3(&base, &local, &remote).is_none());
    }

    #[test]
    fn an_alarm_change_on_one_side_merges() {
        let doc = |summary: &str, trigger: &str| {
            format!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:a@x\r\n\
                 SUMMARY:{summary}\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:{trigger}\r\n\
                 END:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
            )
        };
        let base = doc("S", "-PT10M");
        let local = doc("S", "-PT5M");
        let remote = doc("Renamed", "-PT10M");

        let merged = merge3(&base, &local, &remote).expect("one side only");
        assert!(merged.contains("TRIGGER:-PT5M\r\n"), "{merged}");
        assert!(merged.contains("SUMMARY:Renamed\r\n"));
    }

    /* ---------------- vCards ---------------- */

    const CARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:ada@test\r\nFN:Ada Lovelace\r\n\
EMAIL;TYPE=work:ada@work.example\r\nitem1.EMAIL:ada@home.example\r\n\
item1.X-ABLabel:Summer house\r\nTEL:+30123\r\nEND:VCARD\r\n";

    #[test]
    fn disjoint_vcard_edits_merge_and_groups_survive() {
        let local = CARD.replace("TEL:+30123", "TEL:+30999");
        let remote = CARD.replace("FN:Ada Lovelace", "FN:Ada Byron");

        let merged = merge3(CARD, &local, &remote).expect("disjoint");
        assert!(merged.contains("TEL:+30999\r\n"), "{merged}");
        assert!(merged.contains("FN:Ada Byron\r\n"));
        assert!(
            merged.contains("item1.X-ABLabel:Summer house\r\n"),
            "the Apple group was damaged: {merged}"
        );
    }

    #[test]
    fn grouped_and_ungrouped_occurrences_are_separate_units() {
        // Local edits the grouped email, remote the ungrouped one. Different
        // (group, NAME) keys — no overlap.
        let local = CARD.replace(
            "item1.EMAIL:ada@home.example",
            "item1.EMAIL:new@home.example",
        );
        let remote = CARD.replace(
            "EMAIL;TYPE=work:ada@work.example",
            "EMAIL;TYPE=work:new@work.example",
        );

        let merged = merge3(CARD, &local, &remote).expect("separate keys");
        assert!(
            merged.contains("item1.EMAIL:new@home.example\r\n"),
            "{merged}"
        );
        assert!(merged.contains("EMAIL;TYPE=work:new@work.example\r\n"));
    }

    #[test]
    fn reordering_a_multi_valued_property_counts_as_changing_it() {
        // ATTENDEE-style lists move as one unit. Local reordered; remote
        // edited one entry. Guessing an alignment invents data.
        let base = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a\r\nFN:A\r\n\
TEL:+1\r\nTEL:+2\r\nEND:VCARD\r\n";
        let local = base.replace("TEL:+1\r\nTEL:+2", "TEL:+2\r\nTEL:+1");
        let remote = base.replace("TEL:+2", "TEL:+3");
        assert!(merge3(base, &local, &remote).is_none());
    }

    /* ---------------- refusals and structure ---------------- */

    #[test]
    fn different_component_kinds_never_merge() {
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:A\r\nEND:VCARD\r\n";
        let cal = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n";
        assert!(merge3(card, cal, card).is_none());
    }

    #[test]
    fn garbage_is_refused_not_guessed_at() {
        let doc = event("A", "20260810T090000Z", None);
        let local = event("B", "20260810T090000Z", None);
        assert!(merge3(&doc, &local, "<html>sign in</html>").is_none());
        assert!(merge3("truncated\r\n", &doc, &local).is_none());
    }

    #[test]
    fn lf_only_remote_documents_stay_lf_only() {
        let base = event("Team sync", "20260810T090000Z", None).replace("\r\n", "\n");
        let local = event("Team sync (moved)", "20260810T090000Z", None).replace("\r\n", "\n");
        let remote = event("Team sync", "20260810T100000Z", None).replace("\r\n", "\n");

        let merged = merge3(&base, &local, &remote).expect("merged");
        assert!(!merged.contains('\r'), "an LF document gained CRLF");
        assert!(merged.contains("SUMMARY:Team sync (moved)\n"));
    }

    /* ---------------- overlaps and per-unit resolution ---------------- */

    #[test]
    fn a_clean_merge_has_no_overlaps() {
        let base = event("Team sync", "20260810T090000Z", None);
        let local = event("Team sync (moved)", "20260810T090000Z", None);
        let remote = event("Team sync", "20260810T100000Z", None);
        assert_eq!(overlaps(&base, &local, &remote), Some(Vec::new()));
    }

    #[test]
    fn a_disputed_property_lists_all_three_versions() {
        let base = event("Team sync", "20260810T090000Z", None);
        let local = event("Sprint review", "20260810T090000Z", None);
        let remote = event("Retrospective", "20260810T090000Z", None);

        let found = overlaps(&base, &local, &remote).expect("comparable");
        assert_eq!(found.len(), 1);
        let o = &found[0];
        assert_eq!(o.unit, "VEVENT a@test/SUMMARY");
        assert_eq!(
            o.base.as_deref(),
            Some(&["SUMMARY:Team sync".to_owned()][..])
        );
        assert_eq!(
            o.local.as_deref(),
            Some(&["SUMMARY:Sprint review".to_owned()][..])
        );
        assert_eq!(
            o.remote.as_deref(),
            Some(&["SUMMARY:Retrospective".to_owned()][..])
        );
    }

    #[test]
    fn choosing_a_side_per_unit_builds_the_document() {
        // Two disputes: the summary and the location. One goes each way, and
        // the undisputed DTSTART edit still merges like merge3 would.
        let base = event("Team sync", "20260810T090000Z", Some("Room 5"));
        let local = event("Sprint review", "20260810T090000Z", Some("Room 6"));
        let remote = event("Retrospective", "20260810T100000Z", Some("Room 7"));

        let found = overlaps(&base, &local, &remote).expect("comparable");
        assert_eq!(found.len(), 2, "{found:?}");

        let mut choices = BTreeMap::new();
        choices.insert("VEVENT a@test/SUMMARY".to_owned(), Side::Local);
        choices.insert("VEVENT a@test/LOCATION".to_owned(), Side::Remote);

        let text = resolve(&base, &local, &remote, &choices).expect("every unit decided");
        assert!(text.contains("SUMMARY:Sprint review\r\n"), "{text}");
        assert!(text.contains("LOCATION:Room 7\r\n"), "{text}");
        assert!(
            text.contains("DTSTART:20260810T100000Z\r\n"),
            "the undisputed remote edit was lost: {text}"
        );
    }

    #[test]
    fn an_undecided_unit_refuses_rather_than_half_resolving() {
        let base = event("Team sync", "20260810T090000Z", None);
        let local = event("Sprint review", "20260810T090000Z", None);
        let remote = event("Retrospective", "20260810T090000Z", None);

        assert!(
            resolve(&base, &local, &remote, &BTreeMap::new()).is_none(),
            "a document was produced with a dispute nobody decided"
        );
    }

    #[test]
    fn resolve_with_no_disputes_equals_merge3() {
        let base = event("Team sync", "20260810T090000Z", None);
        let local = event("Team sync (moved)", "20260810T090000Z", None);
        let remote = event("Team sync", "20260810T100000Z", None);

        assert_eq!(
            resolve(&base, &local, &remote, &BTreeMap::new()),
            merge3(&base, &local, &remote)
        );
    }

    #[test]
    fn a_dispute_inside_an_override_carries_its_path() {
        let base = series("Master", "Override");
        let local = series("Master", "Mine");
        let remote = series("Master", "Theirs");

        let found = overlaps(&base, &local, &remote).expect("comparable");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].unit, "VEVENT s@x 20260810T090000Z/SUMMARY");

        let mut choices = BTreeMap::new();
        choices.insert(found[0].unit.clone(), Side::Local);
        let text = resolve(&base, &local, &remote, &choices).expect("decided");
        assert!(text.contains("SUMMARY:Mine\r\n"), "{text}");
        assert!(text.contains("SUMMARY:Master\r\n"));
    }

    #[test]
    fn remove_versus_edit_is_decidable_both_ways() {
        let base = event("Team sync", "20260810T090000Z", Some("Room 5"));
        let local = event("Team sync", "20260810T090000Z", None);
        let remote = event("Team sync", "20260810T090000Z", Some("Room 6"));

        let found = overlaps(&base, &local, &remote).expect("comparable");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].local, None, "the deletion did not read as absence");

        let mut keep_deletion = BTreeMap::new();
        keep_deletion.insert(found[0].unit.clone(), Side::Local);
        let gone = resolve(&base, &local, &remote, &keep_deletion).unwrap();
        assert!(!gone.contains("LOCATION"), "{gone}");

        let mut keep_theirs = BTreeMap::new();
        keep_theirs.insert(found[0].unit.clone(), Side::Remote);
        let kept = resolve(&base, &local, &remote, &keep_theirs).unwrap();
        assert!(kept.contains("LOCATION:Room 6\r\n"), "{kept}");
    }

    #[test]
    fn garbage_has_no_overlaps_to_offer() {
        let doc = event("A", "20260810T090000Z", None);
        let local = event("B", "20260810T090000Z", None);
        assert_eq!(overlaps(&doc, &local, "<html>sign in</html>"), None);
    }

    #[test]
    fn merging_is_idempotent_against_the_merged_result() {
        let base = event("Team sync", "20260810T090000Z", None);
        let local = event("Team sync (moved)", "20260810T090000Z", None);
        let remote = event("Team sync", "20260810T100000Z", None);

        let merged = merge3(&base, &local, &remote).unwrap();
        // Merging the result against itself changes nothing.
        assert_eq!(merge3(&merged, &merged, &merged).unwrap(), merged);
    }
}

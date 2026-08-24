// SPDX-License-Identifier: MPL-2.0
//
// The line primitives are derived from `src-tauri/src/caldav.rs` in the Meltemi
// project. See NOTICE and LICENSING.md.

//! Byte-preserving edits to iCalendar and vCard text.
//!
//! # Why one patcher for both formats
//!
//! Our models cover what a user interface can edit, which is a fraction of what
//! a VEVENT or a vCard carries. The suite's answer is to store the source bytes
//! verbatim and *patch* them — replacing only the properties an editor can
//! change, and passing everything else through untouched. Re-serialising from
//! the model instead would silently discard ATTENDEE, ORGANIZER, VTIMEZONE,
//! PHOTO, GEO, IMPP, and every `X-` property in the file.
//!
//! iCalendar (RFC 5545 §3.1) and vCard (RFC 6350 §3.2) share one grammar for
//! this:
//!
//! ```text
//! [group "."] name *(";" param) ":" value CRLF
//! ```
//!
//! Same folding, same escaping, same quoted-parameter rules. Only vCard uses
//! the group prefix. So this is one tested code path rather than two, which
//! matters because the failure mode is silent: a patcher that mangles a
//! property does not error, it just loses somebody's data on the next sync.
//!
//! # Groups, and why they are handled the way they are
//!
//! vCard lets related lines share a group prefix, which Apple uses to attach a
//! custom label to a value:
//!
//! ```text
//! item1.EMAIL;type=INTERNET:ada@example.com
//! item1.X-ABLabel:Personal
//! ```
//!
//! The two lines are one logical thing. Rewriting `EMAIL` lines positionally
//! without noticing the group would orphan the `X-ABLabel` — it would still be
//! there, now labelling nothing, or labelling a different address. This is the
//! classic vCard data-loss site.
//!
//! So [`Edit::Set`] deliberately **only touches ungrouped lines**. Grouped ones
//! pass through byte-for-byte, and their values are edited by addressing them
//! explicitly with [`Edit::SetInGroup`], which never changes the grouping. An
//! editor can therefore show a grouped entry and change its value, but cannot
//! accidentally restructure or orphan one.

use std::collections::BTreeMap;

/// One logical content line, with its source bytes preserved.
///
/// `raw` is the exact slice the line occupied, folding and terminator included,
/// so a line nothing edits can be written back byte-for-byte.
#[derive(Debug, Clone)]
pub struct ContentLine<'a> {
    raw: &'a str,
    unfolded: String,
}

impl<'a> ContentLine<'a> {
    /// The source bytes, verbatim.
    #[must_use]
    pub fn raw(&self) -> &'a str {
        self.raw
    }

    /// The line with folding removed.
    #[must_use]
    pub fn unfolded(&self) -> &str {
        &self.unfolded
    }

    /// The vCard group prefix, if there is one (`item1` in `item1.EMAIL:…`).
    ///
    /// A dot only counts as a group separator when it precedes the property
    /// name — a dot inside a *value* (`URL:http://x.com`) must not be mistaken
    /// for one, which is why this only looks left of the first `;` or `:`.
    #[must_use]
    pub fn group(&self) -> Option<&str> {
        let head = &self.unfolded[..self.head_end()];
        let dot = head.find('.')?;
        let group = &head[..dot];
        // A group is a name, not arbitrary text.
        if group.is_empty()
            || !group
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        Some(group)
    }

    /// The property name, uppercased, with any group prefix removed.
    #[must_use]
    pub fn name(&self) -> String {
        let head = &self.unfolded[..self.head_end()];
        let start = self.group().map_or(0, |g| g.len() + 1);
        head[start..].trim().to_ascii_uppercase()
    }

    /// The parameter section, between the name and the value's colon.
    #[must_use]
    pub fn params(&self) -> &str {
        let head_end = self.head_end();
        let colon = find_unquoted_colon(&self.unfolded).unwrap_or(self.unfolded.len());
        if head_end >= colon {
            return "";
        }
        &self.unfolded[head_end..colon]
    }

    /// The value, after the first unquoted colon.
    #[must_use]
    pub fn value(&self) -> &str {
        match find_unquoted_colon(&self.unfolded) {
            Some(i) => &self.unfolded[i + 1..],
            None => "",
        }
    }

    /// Where the `[group "."] name` part ends.
    fn head_end(&self) -> usize {
        let colon = find_unquoted_colon(&self.unfolded).unwrap_or(self.unfolded.len());
        self.unfolded[..colon]
            .find(';')
            .map_or(colon, |i| i.min(colon))
    }

    /// `Some(component)` when this is a `BEGIN:` line.
    #[must_use]
    pub fn begins(&self) -> Option<String> {
        component_delimiter(&self.unfolded).and_then(|(is_begin, name)| is_begin.then_some(name))
    }

    /// `Some(component)` when this is an `END:` line.
    #[must_use]
    pub fn ends(&self) -> Option<String> {
        component_delimiter(&self.unfolded).and_then(|(is_begin, name)| (!is_begin).then_some(name))
    }
}

/// Splits text into logical content lines, unfolding continuations.
///
/// Never allocates for the raw slices, so untouched lines cost nothing to carry
/// through a patch.
#[must_use]
pub fn logical_lines(text: &str) -> Vec<ContentLine<'_>> {
    let bytes = text.as_bytes();
    let mut out: Vec<ContentLine<'_>> = Vec::new();
    let mut raw_start = 0usize;
    let mut unfolded = String::new();
    let mut have_logical = false;

    let mut pos = 0usize;
    while pos < text.len() {
        let (content_end, next_pos) = match text[pos..].find('\n') {
            Some(i) => {
                let nl = pos + i;
                let ce = if nl > pos && bytes[nl - 1] == b'\r' {
                    nl - 1
                } else {
                    nl
                };
                (ce, nl + 1)
            }
            None => (text.len(), text.len()),
        };
        let content = &text[pos..content_end];

        if have_logical && (content.starts_with(' ') || content.starts_with('\t')) {
            // A continuation: strip exactly one leading fold character. Any
            // further whitespace is part of the value.
            unfolded.push_str(&content[1..]);
        } else {
            if have_logical {
                out.push(ContentLine {
                    raw: &text[raw_start..pos],
                    unfolded: std::mem::take(&mut unfolded),
                });
            }
            raw_start = pos;
            unfolded.clear();
            unfolded.push_str(content);
            have_logical = true;
        }
        pos = next_pos;
    }

    if have_logical {
        out.push(ContentLine {
            raw: &text[raw_start..],
            unfolded,
        });
    }
    out
}

/// The line terminator the document uses.
///
/// Both RFCs mandate CRLF and real servers emit LF anyway. Rewriting a
/// document's terminators changes bytes we were asked to leave alone, and can
/// break a server's own `If-Match` bookkeeping, so a patch preserves whatever
/// it found.
#[must_use]
pub fn terminator_of(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

/// The first colon that is not inside a quoted parameter value.
///
/// `ATTENDEE;CN="Lovelace, Ada":mailto:ada@example.com` has three colons and
/// only the second one separates the value.
#[must_use]
pub fn find_unquoted_colon(s: &str) -> Option<usize> {
    let mut in_quotes = false;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b':' if !in_quotes => return Some(i),
            _ => {}
        }
    }
    None
}

/// `BEGIN:`/`END:` recognition → `(is_begin, uppercased component name)`.
#[must_use]
pub fn component_delimiter(unfolded: &str) -> Option<(bool, String)> {
    if unfolded.len() >= 6 && unfolded[..6].eq_ignore_ascii_case("BEGIN:") {
        return Some((true, unfolded[6..].trim().to_ascii_uppercase()));
    }
    if unfolded.len() >= 4 && unfolded[..4].eq_ignore_ascii_case("END:") {
        return Some((false, unfolded[4..].trim().to_ascii_uppercase()));
    }
    None
}

/// Folds a logical line and appends it with `terminator`.
///
/// Folds at 73 octets rather than the RFC's 75: some servers hard-reject at the
/// limit rather than at the limit plus slack, and the margin costs nothing.
/// Folding is at character boundaries — splitting a multi-byte character across
/// a fold produces a document no parser can read.
pub fn fold(line: &str, terminator: &str, out: &mut String) {
    const LIMIT: usize = 73;
    let mut count = 0;
    for c in line.chars() {
        if count + c.len_utf8() > LIMIT {
            out.push_str(terminator);
            out.push(' ');
            count = 1; // the continuation space counts toward the new line
        }
        out.push(c);
        count += c.len_utf8();
    }
    out.push_str(terminator);
}

/// What to do with one property inside the patched component.
///
/// A struct rather than an enum because the two halves are independent and a
/// caller routinely needs both at once: a contact's email list contains
/// ungrouped addresses *and* Apple-grouped ones, and rewriting the first set
/// while editing values in the second is one operation, not a choice between
/// two.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Edit {
    /// What the **ungrouped** occurrences of this property become.
    ///
    /// Three distinct states, and the distinction matters:
    ///
    /// - `Some(lines)` — replace them with exactly these, in order. Surplus
    ///   existing lines are dropped; surplus new lines are inserted where the
    ///   first one was, or before the component's END if it had none.
    /// - `Some(vec![])` — remove them.
    /// - `None` — leave them alone. For an edit that only rewrites a grouped
    ///   value, where collapsing "no opinion" into "remove" would delete the
    ///   user's other addresses as a side effect.
    ///
    /// Each entry is a whole logical line, e.g.
    /// `"EMAIL;TYPE=work:ada@example.com"`.
    pub lines: Option<Vec<String>>,

    /// Group name → new value, for grouped occurrences.
    ///
    /// A group not named here is left byte-for-byte alone. This is the only
    /// safe way to edit an Apple-style labelled entry: the group prefix, the
    /// parameters, and the sibling `X-ABLabel` all stay exactly as they were.
    pub groups: BTreeMap<String, String>,
}

impl Edit {
    /// Replace the ungrouped occurrences with these lines.
    #[must_use]
    pub fn set(lines: Vec<String>) -> Self {
        Self {
            lines: Some(lines),
            groups: BTreeMap::new(),
        }
    }

    /// Remove the ungrouped occurrences, leaving grouped ones alone.
    #[must_use]
    pub fn remove() -> Self {
        Self::set(Vec::new())
    }

    /// Touch only grouped occurrences; leave ungrouped ones exactly as they are.
    #[must_use]
    pub fn groups_only() -> Self {
        Self::default()
    }

    /// Also rewrite the value of one grouped occurrence.
    #[must_use]
    pub fn with_group(mut self, group: impl Into<String>, value: impl Into<String>) -> Self {
        self.groups.insert(group.into(), value.into());
        self
    }
}

/// Applies `edits` to the first component named `component`.
///
/// Returns `None` when no such component exists — the caller decides what that
/// means rather than getting a silently unchanged document.
///
/// Everything not named in `edits` passes through byte-for-byte, including
/// nested components, unknown properties, and the document's own folding and
/// line terminators.
#[must_use]
pub fn patch_component(
    text: &str,
    component: &str,
    edits: &BTreeMap<String, Edit>,
) -> Option<String> {
    patch_nth_component(text, component, 0, edits)
}

/// As [`patch_component`], but targets the `index`-th component of that name.
///
/// A recurring event's overrides live in the same file as their master, so
/// "patch the event" is meaningless without a way to name one of them.
#[must_use]
pub fn patch_nth_component(
    text: &str,
    component: &str,
    index: usize,
    edits: &BTreeMap<String, Edit>,
) -> Option<String> {
    let component = component.to_ascii_uppercase();
    let lines = logical_lines(text);
    let terminator = terminator_of(text);

    // Locate the target component's line range.
    let mut depth_stack: Vec<String> = Vec::new();
    let mut seen = 0usize;
    let mut start = None;
    let mut end = None;

    for (i, line) in lines.iter().enumerate() {
        if let Some(name) = line.begins() {
            if name == component && start.is_none() {
                if seen == index {
                    start = Some(i);
                }
                seen += 1;
            }
            depth_stack.push(name);
        } else if let Some(name) = line.ends() {
            depth_stack.pop();
            if name == component && start.is_some() && end.is_none() {
                end = Some(i);
                break;
            }
        }
    }

    let (start, end) = (start?, end?);

    // Which ungrouped occurrences exist, per property, inside the target only.
    let mut emitted: BTreeMap<String, bool> = BTreeMap::new();
    let mut out = String::with_capacity(text.len() + 128);
    // Nesting *within* the target. A VALARM inside a VEVENT carries its own
    // SUMMARY and DESCRIPTION; without this, editing the event's SUMMARY would
    // rewrite the alarm's too — and an alarm is exactly the kind of thing the
    // model does not represent and must not lose.
    let mut nested = 0usize;

    for (i, line) in lines.iter().enumerate() {
        if i <= start || i >= end {
            out.push_str(line.raw());
            continue;
        }

        if line.begins().is_some() {
            nested += 1;
            out.push_str(line.raw());
            continue;
        }
        if line.ends().is_some() {
            nested = nested.saturating_sub(1);
            out.push_str(line.raw());
            continue;
        }
        if nested > 0 {
            out.push_str(line.raw());
            continue;
        }

        let name = line.name();
        let group = line.group().map(ToOwned::to_owned);

        let edit = edits.get(&name);

        match (edit, group.as_deref()) {
            // A grouped line whose group this edit names: rewrite the value,
            // keeping the group prefix and every parameter.
            (Some(edit), Some(existing)) if edit.groups.contains_key(existing) => {
                let unfolded = line.unfolded();
                let head = &unfolded[..find_unquoted_colon(unfolded).unwrap_or(unfolded.len())];
                let value = &edit.groups[existing];
                fold(&format!("{head}:{value}"), terminator, &mut out);
            }
            // Any other grouped line is untouchable — see the module docs.
            (_, Some(_)) => out.push_str(line.raw()),

            (Some(Edit { lines: None, .. }), None) => out.push_str(line.raw()),

            (Some(edit), None) => {
                // The replacement set is authoritative: emit it once, at the
                // position of the first occurrence, and drop the rest.
                if emitted.insert(name.clone(), true).is_none() {
                    for replacement in edit.lines.iter().flatten() {
                        fold(replacement, terminator, &mut out);
                    }
                }
            }

            (None, None) => out.push_str(line.raw()),
        }
    }

    // Properties the component did not already have get appended before END.
    let mut additions = String::new();
    for (name, edit) in edits {
        if !emitted.contains_key(name) {
            for replacement in edit.lines.iter().flatten() {
                fold(replacement, terminator, &mut additions);
            }
        }
    }

    if additions.is_empty() {
        Some(out)
    } else {
        // Splice before the target component's END line.
        //
        // `rfind` rather than `find`: a nested component's END may have byte-
        // identical text (`END:VEVENT` inside a document with several), and the
        // target's own END is always the last one at or before this point,
        // because everything after it was copied verbatim from beyond `end`.
        let end_raw = lines[end].raw();
        let at = out.rfind(end_raw)?;
        let mut spliced = String::with_capacity(out.len() + additions.len());
        spliced.push_str(&out[..at]);
        spliced.push_str(&additions);
        spliced.push_str(&out[at..]);
        Some(spliced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edits(pairs: &[(&str, Edit)]) -> BTreeMap<String, Edit> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    const CARD: &str = "BEGIN:VCARD\r\n\
VERSION:4.0\r\n\
UID:ada@test\r\n\
FN:Ada Lovelace\r\n\
EMAIL;TYPE=work:ada@work.example\r\n\
item1.EMAIL;type=INTERNET:ada@home.example\r\n\
item1.X-ABLabel:Summer house\r\n\
PHOTO;ENCODING=b:AAAABBBB\r\n\
END:VCARD\r\n";

    /* ---------------- line parsing ---------------- */

    #[test]
    fn a_line_splits_into_group_name_params_and_value() {
        let lines = logical_lines("item1.EMAIL;TYPE=work:ada@example.com\r\n");
        let line = &lines[0];
        assert_eq!(line.group(), Some("item1"));
        assert_eq!(line.name(), "EMAIL");
        assert_eq!(line.params(), ";TYPE=work");
        assert_eq!(line.value(), "ada@example.com");
    }

    #[test]
    fn an_ungrouped_line_has_no_group() {
        let lines = logical_lines("EMAIL:ada@example.com\r\n");
        assert_eq!(lines[0].group(), None);
        assert_eq!(lines[0].name(), "EMAIL");
    }

    #[test]
    fn a_dot_in_a_value_is_not_a_group() {
        // The bug this prevents: `URL:http://x.com` reading as group `URL:http`.
        let lines = logical_lines("URL:http://example.com/a.b\r\n");
        assert_eq!(lines[0].group(), None);
        assert_eq!(lines[0].name(), "URL");
        assert_eq!(lines[0].value(), "http://example.com/a.b");
    }

    #[test]
    fn a_quoted_colon_in_a_parameter_is_not_the_value_separator() {
        let lines = logical_lines("ATTENDEE;CN=\"Lovelace, Ada: FRS\":mailto:ada@x.com\r\n");
        assert_eq!(lines[0].name(), "ATTENDEE");
        assert_eq!(lines[0].value(), "mailto:ada@x.com");
    }

    #[test]
    fn folded_lines_are_unfolded_but_keep_their_raw_bytes() {
        let text = "NOTE:one two\r\n  three\r\n";
        let lines = logical_lines(text);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].unfolded(), "NOTE:one two three");
        assert_eq!(lines[0].raw(), text, "raw bytes were not preserved");
    }

    #[test]
    fn folding_never_splits_a_multibyte_character() {
        let mut out = String::new();
        fold(&format!("NOTE:{}", "Λ".repeat(200)), "\r\n", &mut out);
        for line in out.split("\r\n") {
            assert!(line.len() <= 75, "line over the limit: {line:?}");
        }
        // The real assertion: it survives a round trip.
        let back = logical_lines(&out);
        assert_eq!(back[0].value(), "Λ".repeat(200));
    }

    #[test]
    fn the_terminator_is_detected_not_assumed() {
        assert_eq!(terminator_of("A:1\r\nB:2\r\n"), "\r\n");
        assert_eq!(terminator_of("A:1\nB:2\n"), "\n");
    }

    /* ---------------- patching ---------------- */

    #[test]
    fn setting_a_property_replaces_it_in_place() {
        let out = patch_component(
            CARD,
            "VCARD",
            &edits(&[("FN", Edit::set(vec!["FN:Ada Byron".into()]))]),
        )
        .expect("patched");
        assert!(out.contains("FN:Ada Byron\r\n"));
        assert!(!out.contains("FN:Ada Lovelace"));
    }

    #[test]
    fn untouched_lines_survive_byte_for_byte() {
        let out = patch_component(
            CARD,
            "VCARD",
            &edits(&[("FN", Edit::set(vec!["FN:Ada Byron".into()]))]),
        )
        .expect("patched");

        // The whole reason this module exists: a property the model does not
        // know about must come out exactly as it went in.
        assert!(out.contains("PHOTO;ENCODING=b:AAAABBBB\r\n"));
        assert!(out.contains("UID:ada@test\r\n"));
        assert!(out.contains("VERSION:4.0\r\n"));
    }

    #[test]
    fn a_grouped_line_is_never_touched_by_an_ungrouped_set() {
        // The classic vCard data-loss site: rewriting EMAIL positionally would
        // clobber `item1.EMAIL` and orphan its `item1.X-ABLabel`.
        let out = patch_component(
            CARD,
            "VCARD",
            &edits(&[(
                "EMAIL",
                Edit::set(vec!["EMAIL;TYPE=work:new@work.example".into()]),
            )]),
        )
        .expect("patched");

        assert!(out.contains("EMAIL;TYPE=work:new@work.example\r\n"));
        assert!(
            out.contains("item1.EMAIL;type=INTERNET:ada@home.example\r\n"),
            "the grouped email was rewritten"
        );
        assert!(
            out.contains("item1.X-ABLabel:Summer house\r\n"),
            "the label was orphaned"
        );
    }

    #[test]
    fn a_grouped_value_can_be_edited_without_disturbing_its_group() {
        let out = patch_component(
            CARD,
            "VCARD",
            &edits(&[(
                "EMAIL",
                Edit::groups_only().with_group("item1", "moved@home.example"),
            )]),
        )
        .expect("patched");

        assert!(
            out.contains("item1.EMAIL;type=INTERNET:moved@home.example\r\n"),
            "the group or its parameters were lost: {out}"
        );
        assert!(out.contains("item1.X-ABLabel:Summer house\r\n"));
        // The ungrouped one is untouched by a grouped edit.
        assert!(out.contains("EMAIL;TYPE=work:ada@work.example\r\n"));
    }

    #[test]
    fn removing_drops_only_ungrouped_occurrences() {
        let out =
            patch_component(CARD, "VCARD", &edits(&[("EMAIL", Edit::remove())])).expect("patched");
        assert!(!out.contains("EMAIL;TYPE=work:ada@work.example"));
        assert!(out.contains("item1.EMAIL;type=INTERNET:ada@home.example\r\n"));
    }

    #[test]
    fn several_values_replace_one() {
        let out = patch_component(
            CARD,
            "VCARD",
            &edits(&[(
                "EMAIL",
                Edit::set(vec![
                    "EMAIL;TYPE=work:a@x.example".into(),
                    "EMAIL;TYPE=home:b@x.example".into(),
                ]),
            )]),
        )
        .expect("patched");
        assert!(out.contains("EMAIL;TYPE=work:a@x.example\r\n"));
        assert!(out.contains("EMAIL;TYPE=home:b@x.example\r\n"));
        assert!(!out.contains("ada@work.example"));
    }

    #[test]
    fn a_property_the_card_lacks_is_appended_before_end() {
        let out = patch_component(
            CARD,
            "VCARD",
            &edits(&[("NICKNAME", Edit::set(vec!["NICKNAME:Countess".into()]))]),
        )
        .expect("patched");

        let nick = out.find("NICKNAME:Countess").expect("added");
        let end = out.find("END:VCARD").expect("has an end");
        assert!(nick < end, "the addition landed outside the component");
    }

    #[test]
    fn lf_only_documents_stay_lf_only() {
        let lf = CARD.replace("\r\n", "\n");
        let out = patch_component(
            &lf,
            "VCARD",
            &edits(&[("FN", Edit::set(vec!["FN:Ada Byron".into()]))]),
        )
        .expect("patched");
        assert!(!out.contains('\r'), "an LF document gained CRLF");
        assert!(out.contains("FN:Ada Byron\n"));
    }

    #[test]
    fn an_absent_component_is_none_rather_than_an_unchanged_document() {
        assert!(patch_component(CARD, "VEVENT", &edits(&[])).is_none());
    }

    #[test]
    fn an_empty_edit_set_returns_the_document_unchanged() {
        let out = patch_component(CARD, "VCARD", &edits(&[])).expect("patched");
        assert_eq!(out, CARD, "a no-op patch changed bytes");
    }

    #[test]
    fn patching_is_idempotent() {
        let e = edits(&[("FN", Edit::set(vec!["FN:Ada Byron".into()]))]);
        let once = patch_component(CARD, "VCARD", &e).expect("first");
        let twice = patch_component(&once, "VCARD", &e).expect("second");
        assert_eq!(once, twice, "a second identical patch changed the document");
    }

    /* ---------------- multi-component documents ---------------- */

    const SERIES: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
BEGIN:VEVENT\r\n\
UID:s@x\r\n\
SUMMARY:Master\r\n\
BEGIN:VALARM\r\n\
ACTION:DISPLAY\r\n\
SUMMARY:Alarm text\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
UID:s@x\r\n\
RECURRENCE-ID:20260810T090000Z\r\n\
SUMMARY:Override\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    #[test]
    fn only_the_targeted_component_is_patched() {
        let out = patch_nth_component(
            SERIES,
            "VEVENT",
            1,
            &edits(&[("SUMMARY", Edit::set(vec!["SUMMARY:Edited override".into()]))]),
        )
        .expect("patched");

        assert!(
            out.contains("SUMMARY:Master\r\n"),
            "the master was rewritten"
        );
        assert!(out.contains("SUMMARY:Edited override\r\n"));
        assert!(!out.contains("SUMMARY:Override\r\n"));
    }

    #[test]
    fn a_nested_component_is_not_reached_into() {
        // A SUMMARY edit on the VEVENT must not rewrite the VALARM's SUMMARY.
        let out = patch_nth_component(
            SERIES,
            "VEVENT",
            0,
            &edits(&[("SUMMARY", Edit::set(vec!["SUMMARY:Edited master".into()]))]),
        )
        .expect("patched");

        assert!(out.contains("SUMMARY:Edited master\r\n"));
        assert!(
            out.contains("SUMMARY:Alarm text\r\n"),
            "the edit reached into the VALARM: {out}"
        );
    }

    #[test]
    fn an_index_past_the_end_is_none() {
        assert!(patch_nth_component(SERIES, "VEVENT", 5, &edits(&[])).is_none());
    }
}

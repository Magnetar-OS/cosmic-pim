// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// Ported from `src-tauri/src/caldav.rs` in the Meltemi project
// (https://github.com/entro314-labs/meltemi). See NOTICE and LICENSING.md.

//! Byte-preserving writeback: patch a local edit **into** the stored resource.
//!
//! # Why this file exists at all
//!
//! [`crate::store::RemoteEvent`] holds the server's iCalendar bytes verbatim,
//! precisely so that ATTENDEE lists, ORGANIZER, STATUS, VTIMEZONE blocks,
//! CATEGORIES, sibling override VEVENTs, and every `X-` property survive a
//! round trip through a client that does not model them.
//!
//! That guarantee is only worth anything if **writing** preserves them too.
//! Rebuilding a minimal VEVENT from our own `Event` and PUT-ing it would
//! amputate everything the editor does not model — so the first time a user
//! renamed a meeting, its attendee list would vanish from the server and every
//! other participant's calendar. Verbatim storage plus lossy writeback is worse
//! than lossy storage, because the data loss is invisible until it is remote.
//!
//! So: one linear walk over the stored text, replacing only the properties a
//! local edit can actually change (SUMMARY, LOCATION, DESCRIPTION, DTSTART,
//! DTEND, RRULE, plus DURATION which DTEND supersedes and DTSTAMP which
//! refreshes) inside the *one* VEVENT the edit targets. Everything else passes
//! through byte for byte.
//!
//! # Two subtleties worth knowing before editing this
//!
//! **The original serialisation form wins.** A `DTSTART;TZID=Europe/Athens`
//! must not come back as UTC just because we happen to hold an instant. It
//! would look identical today and drift by an hour at the next DST boundary the
//! server's rules disagree with ours about. [`DateTimeForm`] carries the
//! original form across the rewrite.
//!
//! **Line terminators are preserved.** Some servers emit LF-only despite the
//! RFC; rewriting to CRLF changes bytes we were asked to leave alone and can
//! break a server's own `If-Match` bookkeeping. Hence `fold_ical_line_with`
//! taking a terminator rather than hardcoding one.

use calcard::Parser;
use calcard::icalendar::timezone::TzResolver;
use chrono::Utc;
use cosmic_pim_core::ical::escape_text;
// The content-line primitives live in core so that iCalendar and vCard share
// one tested implementation — see `cosmic_pim_core::patch`.
use cosmic_pim_core::patch::{component_delimiter, find_unquoted_colon, logical_lines};

/// Wall-clock milliseconds, for DTSTAMP.
fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// Whether an UNFOLDED content line is an ATTENDEE property whose
/// cal-address names `me_lower` (lowercased, mailto:-stripped). The
/// property-name check requires `;` or `:` at byte 8 so `ATTENDEEX-FOO`
/// style extension names can't match.
fn attendee_line_matches(line: &str, me_lower: &str) -> bool {
    let bytes = line.as_bytes();
    if bytes.len() < 9 || !bytes[..8].eq_ignore_ascii_case(b"ATTENDEE") {
        return false;
    }
    if bytes[8] != b';' && bytes[8] != b':' {
        return false;
    }
    let Some(colon) = find_unquoted_colon(line) else {
        return false;
    };
    let value = line[colon + 1..].trim().trim_matches('"');
    let v_lower = value.to_lowercase();
    let addr = v_lower.strip_prefix("mailto:").unwrap_or(&v_lower);
    addr == me_lower
}

/// Rewrite the PARTSTAT parameter of one UNFOLDED ATTENDEE line: an existing
/// PARTSTAT (matched case-insensitively, outside quotes, original name
/// casing preserved) gets its value replaced; when absent the parameter is
/// appended just before the value colon. Every other byte of the line -
/// param order, casing, quoting - passes through untouched.
fn patch_partstat_in_attendee_line(line: &str, partstat: &str) -> String {
    let colon = find_unquoted_colon(line).unwrap_or(line.len());
    let params = &line[..colon];
    let value = &line[colon..]; // includes the ':' (or "" for a malformed line)

    // Segment params on unquoted ';'. Segment 0 is the property name.
    let mut segments: Vec<&str> = Vec::new();
    let mut seg_start = 0usize;
    let mut in_quotes = false;
    for (i, b) in params.bytes().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b';' if !in_quotes => {
                segments.push(&params[seg_start..i]);
                seg_start = i + 1;
            }
            _ => {}
        }
    }
    segments.push(&params[seg_start..]);

    let mut out = String::with_capacity(line.len() + 24);
    let mut replaced = false;
    for (idx, seg) in segments.iter().enumerate() {
        if idx > 0 {
            out.push(';');
            if !replaced
                && let Some(eq) = seg.find('=')
                && seg[..eq].trim().eq_ignore_ascii_case("PARTSTAT")
            {
                out.push_str(&seg[..eq]);
                out.push('=');
                out.push_str(partstat);
                replaced = true;
                continue;
            }
        }
        out.push_str(seg);
    }
    if !replaced {
        out.push_str(";PARTSTAT=");
        out.push_str(partstat);
    }
    out.push_str(value);
    out
}

/// Fold a content line at 73 octets using the given line terminator
/// (`fold_ical_line` hardcodes CRLF; the RSVP patch preserves the source
/// document's terminator style instead). No trailing terminator is emitted -
/// the caller appends one iff the original line carried one.
fn fold_ical_line_with(line: &str, term: &str, out: &mut String) {
    const LIMIT: usize = 73;
    let mut count = 0;
    for c in line.chars() {
        if count + c.len_utf8() > LIMIT {
            out.push_str(term);
            out.push(' ');
            count = 1; // the continuation space counts toward the next line
        }
        out.push(c);
        count += c.len_utf8();
    }
}

/// Emit one logical line: my ATTENDEE line is patched + refolded; everything
/// else is copied from the source byte-for-byte (`raw` includes any interior
/// fold sequences and the trailing terminator).
fn emit_rsvp_logical_line(
    raw: &str,
    unfolded: &str,
    me_lower: &str,
    partstat: &str,
    term: &str,
    out: &mut String,
    patched: &mut bool,
) {
    if attendee_line_matches(unfolded, me_lower) {
        let new_line = patch_partstat_in_attendee_line(unfolded, partstat);
        fold_ical_line_with(&new_line, term, out);
        if raw.ends_with('\n') {
            out.push_str(term);
        }
        *patched = true;
    } else {
        out.push_str(raw);
    }
}

/// Patch the PARTSTAT of `me_email`'s ATTENDEE line(s) inside a stored iCal
/// document. String-level on purpose - reserializing through calcard would
/// rewrite the whole document (X-properties, VTIMEZONEs, param order) and
/// servers diff PUT bodies; this touches ONLY my ATTENDEE lines.
///
/// Robustness: physical lines are grouped into logical lines (RFC 5545 §3.1
/// folding - continuation = leading SPACE or HTAB), the match runs against
/// the UNFOLDED text so a `mailto:` split across a fold boundary still hits,
/// the patched line is refolded at ≤75 octets with the document's own
/// terminator style, and every non-matching logical line is copied out
/// byte-for-byte. Matching patches ALL of my ATTENDEE lines (master +
/// overrides in one resource each carry one). Returns `None` when no
/// ATTENDEE line names `me_email`.
pub fn patch_attendee_partstat(ical: &str, me_email: &str, partstat: &str) -> Option<String> {
    let me_norm = me_email.trim().to_lowercase();
    let me_lower = me_norm.strip_prefix("mailto:").unwrap_or(&me_norm);
    let term = if ical.contains("\r\n") { "\r\n" } else { "\n" };

    let mut out = String::with_capacity(ical.len() + 32);
    let mut patched = false;
    for line in logical_lines(ical) {
        let (raw, unfolded) = (line.raw(), line.unfolded());
        emit_rsvp_logical_line(
            raw,
            unfolded,
            me_lower,
            partstat,
            term,
            &mut out,
            &mut patched,
        );
    }
    patched.then_some(out)
}

/* ------------------------------------------------------------------ */
/* Local-edit writeback patch (F-CAL-3)                               */

/// The editable field set a local edit carries (`save_calendar_event`'s
/// columns) - the exact scope [`patch_event_ics`] may rewrite. Everything
/// else in the stored resource survives byte-for-byte.
pub struct LocalEventPatch<'a> {
    pub title: &'a str,
    pub location: &'a str,
    pub notes: &'a str,
    pub start_ms: i64,
    pub end_ms: i64,
    pub all_day: bool,
    pub rrule: &'a str,
    /// Alarm offsets (minutes before start) replacing the VEVENT's VALARMs -
    /// mirroring `replace_reminders`' documented downgrade to DISPLAY.
    pub reminders: &'a [i64],
}

/// Serialization form of an original DTSTART/DTEND line, preserved on
/// writeback so a local edit can't rewrite the server's TZID into UTC -
/// the exact future-DST-shift hazard F-CAL-3 names.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DateTimeForm {
    Date,
    Utc,
    Zoned(String),
    Floating,
}

/// Property name of an unfolded content line, uppercased
/// (`DTSTART;TZID=x:...` → `DTSTART`).
fn line_property_name(unfolded: &str) -> String {
    let end = unfolded.find([';', ':']).unwrap_or(unfolded.len());
    unfolded[..end].trim().to_ascii_uppercase()
}

/// Classify an original DTSTART/DTEND line's serialization form from its
/// parameters (unquoted-`;` segmentation, quoted values respected - the same
/// discipline as `patch_partstat_in_attendee_line`).
fn datetime_form(unfolded: &str) -> DateTimeForm {
    let colon = find_unquoted_colon(unfolded).unwrap_or(unfolded.len());
    let params = &unfolded[..colon];
    let mut segments: Vec<&str> = Vec::new();
    let mut seg_start = 0usize;
    let mut in_quotes = false;
    for (i, b) in params.bytes().enumerate() {
        match b {
            b'"' => in_quotes = !in_quotes,
            b';' if !in_quotes => {
                segments.push(&params[seg_start..i]);
                seg_start = i + 1;
            }
            _ => {}
        }
    }
    segments.push(&params[seg_start..]);

    let mut is_date = false;
    let mut tzid: Option<String> = None;
    for seg in segments.iter().skip(1) {
        if let Some(eq) = seg.find('=') {
            let name = seg[..eq].trim();
            let value = seg[eq + 1..].trim().trim_matches('"');
            if name.eq_ignore_ascii_case("VALUE") && value.eq_ignore_ascii_case("DATE") {
                is_date = true;
            } else if name.eq_ignore_ascii_case("TZID") && !value.is_empty() {
                tzid = Some(value.to_string());
            }
        }
    }
    if is_date {
        return DateTimeForm::Date;
    }
    if let Some(id) = tzid {
        return DateTimeForm::Zoned(id);
    }
    let value = unfolded.get(colon + 1..).unwrap_or("").trim();
    if value.ends_with(['Z', 'z']) {
        DateTimeForm::Utc
    } else {
        DateTimeForm::Floating
    }
}

/// Epoch ms → `YYYYMMDDTHHMMSSZ` (UTC basic form).
fn fmt_utc_basic(ms: i64) -> String {
    use chrono::TimeZone;
    chrono::Utc.timestamp_millis_opt(ms).single().map_or_else(
        || "19700101T000000Z".to_string(),
        |dt| dt.format("%Y%m%dT%H%M%SZ").to_string(),
    )
}

/// Epoch ms → the LOCAL calendar date `YYYYMMDD` (the all-day anchor -
/// matching how ingestion resolved `VALUE=DATE` at local midnight).
fn fmt_local_date_basic(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map_or_else(
        || "19700101".to_string(),
        |utc| {
            utc.with_timezone(&chrono::Local)
                .format("%Y%m%d")
                .to_string()
        },
    )
}

/// Epoch ms → floating local wall clock `YYYYMMDDTHHMMSS` (RFC 5545 §3.3.5:
/// floating means "the calendar's own zone" = the host zone here, the same
/// reading ingestion applied).
fn fmt_local_floating(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map_or_else(
        || "19700101T000000".to_string(),
        |utc| {
            utc.with_timezone(&chrono::Local)
                .format("%Y%m%dT%H%M%S")
                .to_string()
        },
    )
}

/// Serialize one DTSTART/DTEND replacement in the ORIGINAL line's form. A
/// TZID that no longer resolves (through the document's own VTIMEZONEs
/// first, IANA second) degrades to UTC with a warning - absolute and wrong
/// about future DST is still better than silently floating.
fn format_datetime_line(
    prop: &str,
    ms: i64,
    form: &DateTimeForm,
    resolver: &TzResolver<&str>,
) -> String {
    match form {
        DateTimeForm::Date => format!("{prop};VALUE=DATE:{}", fmt_local_date_basic(ms)),
        DateTimeForm::Utc => format!("{prop}:{}", fmt_utc_basic(ms)),
        DateTimeForm::Floating => format!("{prop}:{}", fmt_local_floating(ms)),
        DateTimeForm::Zoned(id) => {
            let tz = resolver.resolve_or_default(Some(id.trim()));
            if tz.is_floating() {
                tracing::warn!(
                    "caldav: stored TZID {id:?} did not resolve on writeback; writing UTC"
                );
                return format!("{prop}:{}", fmt_utc_basic(ms));
            }
            match chrono::DateTime::from_timestamp_millis(ms) {
                Some(utc) => {
                    let wall = utc.with_timezone(&tz).naive_local();
                    format!("{prop};TZID={id}:{}", wall.format("%Y%m%dT%H%M%S"))
                }
                None => format!("{prop}:{}", fmt_utc_basic(ms)),
            }
        }
    }
}

/// Emit the replacement property lines + VALARM blocks for the target VEVENT
/// (called just before its `END:VEVENT`).
fn emit_patched_props(
    out: &mut String,
    term: &str,
    patch: &LocalEventPatch,
    start_form: &DateTimeForm,
    end_form: &DateTimeForm,
    next_sequence: i64,
    resolver: &TzResolver<&str>,
) {
    fn put(line: &str, term: &str, out: &mut String) {
        fold_ical_line_with(line, term, out);
        out.push_str(term);
    }
    put(&format!("DTSTAMP:{}", fmt_utc_basic(now_ms())), term, out);
    put(
        &format_datetime_line("DTSTART", patch.start_ms, start_form, resolver),
        term,
        out,
    );
    put(
        &format_datetime_line("DTEND", patch.end_ms, end_form, resolver),
        term,
        out,
    );
    if !patch.rrule.trim().is_empty() {
        // RRULE is structured, not TEXT - no escaping.
        put(&format!("RRULE:{}", patch.rrule.trim()), term, out);
    }
    put(&format!("SUMMARY:{}", escape_text(patch.title)), term, out);
    if !patch.location.is_empty() {
        put(
            &format!("LOCATION:{}", escape_text(patch.location)),
            term,
            out,
        );
    }
    if !patch.notes.is_empty() {
        put(
            &format!("DESCRIPTION:{}", escape_text(patch.notes)),
            term,
            out,
        );
    }
    put(&format!("SEQUENCE:{next_sequence}"), term, out);
    for minutes in patch.reminders {
        // `PT0S` is the legal "at start" spelling (see `build_event_ics`).
        let trigger = if *minutes <= 0 {
            "PT0S".to_string()
        } else {
            format!("-PT{minutes}M")
        };
        put("BEGIN:VALARM", term, out);
        put("ACTION:DISPLAY", term, out);
        put(
            &format!("DESCRIPTION:{}", escape_text(patch.title)),
            term,
            out,
        );
        put(&format!("TRIGGER:{trigger}"), term, out);
        put("END:VALARM", term, out);
    }
}

/// Patch a local edit into the STORED resource (F-CAL-3), instead of
/// rebuilding a minimal VEVENT that amputates everything the editor doesn't
/// model. Only the editable properties (SUMMARY/LOCATION/DESCRIPTION/
/// DTSTART/DTEND/RRULE, plus DURATION which DTEND supersedes and DTSTAMP
/// which refreshes) are replaced inside the ONE target VEVENT
/// (`target_rid`-matched; `''` = the master); SEQUENCE bumps by one;
/// VALARM blocks are re-emitted from the stored reminder set. Attendees,
/// organizer, STATUS, VTIMEZONEs, X-properties, CATEGORIES, sibling
/// override VEVENTs - and the original TZID form of the times - all pass
/// through byte-for-byte (the RSVP patcher's discipline, generalized).
///
/// `None` when no VEVENT matches `target_rid` - the caller decides the
/// fallback.
// One linear byte-preserving walk; splitting it would scatter the state machine.
#[allow(clippy::too_many_lines)]
pub fn patch_event_ics(ical: &str, target_rid: &str, patch: &LocalEventPatch) -> Option<String> {
    // Identify the target VEVENT by document order through the same parser
    // the ingest path uses, so RECURRENCE-ID matching shares one canonical
    // form with the stored `recurrence_id` column.
    let target_index = cosmic_pim_core::ical::recurrence_ids(ical)
        .iter()
        .position(|rid| rid.as_deref().unwrap_or("") == target_rid)?;

    // The document's own VTIMEZONEs drive TZID resolution for the rewritten
    // times; IANA names cover the rest (calcard resolver semantics).
    let mut parser = Parser::new(ical);
    let ical_doc = loop {
        match parser.entry() {
            calcard::Entry::ICalendar(doc) => break doc,
            calcard::Entry::Eof => return None,
            _ => {}
        }
    };
    let resolver = ical_doc.build_tz_resolver();

    let term = if ical.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(ical.len() + 256);

    let mut vevent_counter = 0usize;
    let mut in_vevent = false;
    let mut current_is_target = false;
    let mut subcomponent_depth = 0usize;
    let mut orig_dtstart: Option<String> = None;
    let mut orig_dtend: Option<String> = None;
    let mut orig_sequence: i64 = 0;

    for line in logical_lines(ical) {
        let (raw, unfolded) = (line.raw(), line.unfolded());
        if let Some((is_begin, name)) = component_delimiter(unfolded) {
            if is_begin {
                if name == "VEVENT" && !in_vevent {
                    in_vevent = true;
                    current_is_target = vevent_counter == target_index;
                    vevent_counter += 1;
                    out.push_str(raw);
                } else if in_vevent {
                    // VALARM (or any nested block) inside a VEVENT: the
                    // target's blocks are re-emitted from `patch.reminders`.
                    subcomponent_depth += 1;
                    if !current_is_target {
                        out.push_str(raw);
                    }
                } else {
                    out.push_str(raw); // VTIMEZONE etc.
                }
            } else if name == "VEVENT" && in_vevent && subcomponent_depth == 0 {
                if current_is_target {
                    let start_form = resolve_form(orig_dtstart.take(), patch.all_day, None);
                    let end_form =
                        resolve_form(orig_dtend.take(), patch.all_day, Some(&start_form));
                    emit_patched_props(
                        &mut out,
                        term,
                        patch,
                        &start_form,
                        &end_form,
                        orig_sequence + 1,
                        &resolver,
                    );
                }
                in_vevent = false;
                current_is_target = false;
                out.push_str(raw);
            } else if in_vevent && subcomponent_depth > 0 {
                subcomponent_depth -= 1;
                if !current_is_target {
                    out.push_str(raw);
                }
            } else {
                out.push_str(raw);
            }
            continue;
        }
        if in_vevent && current_is_target {
            if subcomponent_depth > 0 {
                continue; // dropped VALARM content
            }
            match line_property_name(unfolded).as_str() {
                "SUMMARY" | "LOCATION" | "DESCRIPTION" | "RRULE" | "DURATION" | "DTSTAMP" => {}
                "SEQUENCE" => {
                    let colon = find_unquoted_colon(unfolded).unwrap_or(unfolded.len());
                    orig_sequence = unfolded
                        .get(colon + 1..)
                        .unwrap_or("")
                        .trim()
                        .parse()
                        .unwrap_or(0);
                }
                "DTSTART" => orig_dtstart = Some(unfolded.to_owned()),
                "DTEND" => orig_dtend = Some(unfolded.to_owned()),
                _ => out.push_str(raw),
            }
            continue;
        }
        out.push_str(raw);
    }
    Some(out)
}

/// Pick the writeback form for one datetime property: the edit's all-day
/// flag wins (a toggled all-day must serialize as DATE and vice versa as
/// UTC), otherwise the original line's own form; a DTEND that never existed
/// (DURATION-only resources) inherits DTSTART's form.
fn resolve_form(
    original: Option<String>,
    all_day: bool,
    inherit: Option<&DateTimeForm>,
) -> DateTimeForm {
    if all_day {
        return DateTimeForm::Date;
    }
    match original.as_deref().map(datetime_form) {
        Some(DateTimeForm::Date) | None => inherit
            .filter(|f| **f != DateTimeForm::Date)
            .cloned()
            .unwrap_or(DateTimeForm::Utc),
        Some(form) => form,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Assertions compare UNFOLDED content: the patcher refolds long lines
    /// at 75 octets (correct output), which raw `contains` would miss.
    fn unfold(s: &str) -> String {
        s.replace("\r\n ", "").replace("\n ", "")
    }

    #[test]
    fn partstat_patch_replaces_existing_param_and_leaves_others_untouched() {
        let ical = "BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\n\
UID:u1\r\n\
ATTENDEE;CN=Boss;PARTSTAT=DECLINED:mailto:boss@example.com\r\n\
ATTENDEE;CN=Me;PARTSTAT=NEEDS-ACTION;ROLE=REQ-PARTICIPANT:mailto:me@example.com\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        let out = patch_attendee_partstat(ical, "me@example.com", "ACCEPTED").expect("patched");
        assert!(
            unfold(&out).contains(
                "ATTENDEE;CN=Me;PARTSTAT=ACCEPTED;ROLE=REQ-PARTICIPANT:mailto:me@example.com\r\n"
            ),
            "{out}"
        );
        // The OTHER attendee's PARTSTAT and every surrounding line pass
        // through byte-for-byte.
        assert!(out.contains("ATTENDEE;CN=Boss;PARTSTAT=DECLINED:mailto:boss@example.com\r\n"));
        assert!(out.starts_with("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:u1\r\n"));
        assert!(out.ends_with("END:VEVENT\r\nEND:VCALENDAR\r\n"));
    }

    #[test]
    fn partstat_patch_inserts_param_when_absent() {
        let ical = "BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\n\
UID:u2\r\n\
ATTENDEE;CN=Me:mailto:me@example.com\r\n\
ATTENDEE:mailto:me2@example.com\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        let out = patch_attendee_partstat(ical, "ME@Example.com", "DECLINED").expect("patched");
        assert!(
            out.contains("ATTENDEE;CN=Me;PARTSTAT=DECLINED:mailto:me@example.com\r\n"),
            "{out}"
        );
        // The bare param-less form gets the param too when it's mine.
        let out2 = patch_attendee_partstat(ical, "me2@example.com", "TENTATIVE").expect("patched");
        assert!(
            out2.contains("ATTENDEE;PARTSTAT=TENTATIVE:mailto:me2@example.com\r\n"),
            "{out2}"
        );
    }

    #[test]
    fn partstat_patch_preserves_param_name_casing_and_handles_quoted_colons() {
        // Lowercase param name stays lowercase; a quoted CN containing ':'
        // and ';' must not derail the params/value split.
        let ical = "BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\n\
UID:u3\r\n\
ATTENDEE;CN=\"Boss; The: Real One\";partstat=needs-action:mailto:me@example.com\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        let out = patch_attendee_partstat(ical, "me@example.com", "TENTATIVE").expect("patched");
        assert!(
            unfold(&out).contains(
                "ATTENDEE;CN=\"Boss; The: Real One\";partstat=TENTATIVE:mailto:me@example.com\r\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn a_refold_counts_octets_not_characters() {
        // The limit is 75 *octets* (RFC 5545 §3.1), and Greek is two octets a
        // character, so a folder counting characters passes an ASCII test and
        // emits over-long lines the moment a user writes in their own
        // language. `core::patch` pins this for its own folder; this crate
        // carries a second implementation, and a rule is only held where it
        // is tested.
        let name = "Λ".repeat(60);
        let ical = format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:u5\r\n\
             DTSTART:20260901T100000Z\r\n\
             ATTENDEE;CN={name};PARTSTAT=NEEDS-ACTION:mailto:me@example.com\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        );

        let out = patch_attendee_partstat(&ical, "me@example.com", "ACCEPTED").expect("patched");
        for line in out.split("\r\n") {
            assert!(line.len() <= 75, "line over 75 octets: {}", line.len());
        }
        // And the name survives the refold intact — a fold that split a
        // character would corrupt it rather than merely lengthen a line.
        let unfolded: String = crate::patch::logical_lines(&out)
            .iter()
            .map(|line| line.unfolded().to_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            unfolded.contains(&name),
            "the refold corrupted the name:\n{unfolded}"
        );
        assert!(unfolded.contains("PARTSTAT=ACCEPTED"));
    }

    #[test]
    fn partstat_patch_unfolds_patches_and_refolds() {
        // The fold boundary splits "PARTSTAT" / "=NEEDS-ACTION" across
        // physical lines - only unfold-then-match can see the parameter.
        // Built by concat: a `\`-continuation string literal would strip the
        // continuation line's leading space - the very fold marker under test.
        let ical = concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:u4\r\n",
            "DTSTART:20260901T100000Z\r\n",
            "ATTENDEE;CN=A Very Long Name That Goes On And On For Quite A While;PARTSTAT\r\n",
            " =NEEDS-ACTION;ROLE=REQ-PARTICIPANT;RSVP=TRUE:mailto:me@example.com\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n",
        );
        let out = patch_attendee_partstat(ical, "me@example.com", "ACCEPTED").expect("patched");
        for line in out.split("\r\n") {
            assert!(line.len() <= 75, "line over 75 octets: {}", line.len());
        }
        // ASCII only above, which cannot tell octets from characters — see
        // the multibyte test below for the half this one does not reach.
        // The refolded document must still parse, and the patched attendee
        // must survive the refold. Asserted on the unfolded text rather than a
        // parsed attendee list because our Event model deliberately does not
        // carry attendees — which is exactly why this patcher exists.
        assert_eq!(
            cosmic_pim_core::ical::parse_ics(&out, "test", "x.ics").len(),
            1,
            "refolding corrupted the document"
        );
        let unfolded = unfold(&out);
        assert!(
            unfolded.contains("ATTENDEE;PARTSTAT=ACCEPTED;CN=")
                || unfolded.contains("PARTSTAT=ACCEPTED"),
            "PARTSTAT was lost in the refold: {unfolded}"
        );
        assert!(
            unfolded.contains("me@example.com"),
            "the attendee itself was lost: {unfolded}"
        );
    }

    #[test]
    fn partstat_patch_preserves_lf_only_terminators_and_misses_cleanly() {
        let lf_ical = "BEGIN:VCALENDAR\n\
BEGIN:VEVENT\n\
UID:u5\n\
ATTENDEE:mailto:me@example.com\n\
END:VEVENT\n\
END:VCALENDAR\n";
        let out = patch_attendee_partstat(lf_ical, "me@example.com", "ACCEPTED").expect("patched");
        assert!(!out.contains('\r'), "LF document must stay LF");
        assert!(out.contains("ATTENDEE;PARTSTAT=ACCEPTED:mailto:me@example.com\n"));
        // No ATTENDEE line for me → None (rsvp_event surfaces invalid_input).
        assert_eq!(
            patch_attendee_partstat(lf_ical, "nobody@example.com", "ACCEPTED"),
            None
        );
        // ATTENDEEX-style extension property names never match.
        let ext = "BEGIN:VCALENDAR\nATTENDEE-X:mailto:me@example.com\nEND:VCALENDAR\n";
        assert_eq!(
            patch_attendee_partstat(ext, "me@example.com", "ACCEPTED"),
            None
        );
    }

    /* ---------------- free-busy ---------------- */

    /// the editor doesn't model must survive VERBATIM, and the TZID form of
    /// the times must not be rewritten to UTC.
    #[test]
    fn patch_preserves_attendees_override_and_tzid() {
        let ical = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Server//EN\r\n\
BEGIN:VTIMEZONE\r\n\
TZID:Europe/Athens\r\n\
BEGIN:STANDARD\r\n\
DTSTART:19701025T040000\r\n\
TZOFFSETFROM:+0300\r\n\
TZOFFSETTO:+0200\r\n\
END:STANDARD\r\n\
END:VTIMEZONE\r\n\
BEGIN:VEVENT\r\n\
UID:series@example.com\r\n\
SEQUENCE:3\r\n\
DTSTAMP:20260101T000000Z\r\n\
DTSTART;TZID=Europe/Athens:20260901T100000\r\n\
DTEND;TZID=Europe/Athens:20260901T110000\r\n\
SUMMARY:Old title\r\n\
RRULE:FREQ=WEEKLY\r\n\
STATUS:CONFIRMED\r\n\
ORGANIZER;CN=Boss:mailto:boss@example.com\r\n\
ATTENDEE;CN=Me;PARTSTAT=ACCEPTED:mailto:me@example.com\r\n\
X-CUSTOM-PROP:survives\r\n\
BEGIN:VALARM\r\n\
ACTION:EMAIL\r\n\
TRIGGER:-PT10M\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
UID:series@example.com\r\n\
RECURRENCE-ID;TZID=Europe/Athens:20260908T100000\r\n\
DTSTART;TZID=Europe/Athens:20260908T140000\r\n\
DTEND;TZID=Europe/Athens:20260908T150000\r\n\
SUMMARY:Old title (moved)\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        // Athens is UTC+3 in September: 10:00 local = 07:00Z.
        let start_ms = 1_788_246_000_000; // 2026-09-01T07:00:00Z
        let patch = LocalEventPatch {
            title: "New title",
            location: "",
            notes: "",
            start_ms,
            end_ms: start_ms + 3_600_000,
            all_day: false,
            rrule: "FREQ=WEEKLY",
            reminders: &[15],
        };
        let out = patch_event_ics(ical, "", &patch).expect("patched");

        // The edit landed.
        assert!(out.contains("SUMMARY:New title\r\n"), "{out}");
        assert!(!out.contains("SUMMARY:Old title\r\n"));
        // SEQUENCE bumped, DTSTAMP refreshed.
        assert!(out.contains("SEQUENCE:4\r\n"), "{out}");
        assert!(!out.contains("DTSTAMP:20260101T000000Z"));
        // TZID retained - no UTC rewrite (the F-CAL-3 DST hazard).
        assert!(
            out.contains("DTSTART;TZID=Europe/Athens:20260901T100000\r\n"),
            "{out}"
        );
        assert!(
            out.contains("DTEND;TZID=Europe/Athens:20260901T110000\r\n"),
            "{out}"
        );
        // Attendees, organizer, status, X-props, VTIMEZONE: verbatim.
        assert!(out.contains("ATTENDEE;CN=Me;PARTSTAT=ACCEPTED:mailto:me@example.com\r\n"));
        assert!(out.contains("ORGANIZER;CN=Boss:mailto:boss@example.com\r\n"));
        assert!(out.contains("STATUS:CONFIRMED\r\n"));
        assert!(out.contains("X-CUSTOM-PROP:survives\r\n"));
        assert!(out.contains("TZID:Europe/Athens\r\n"));
        assert!(out.contains("TZOFFSETFROM:+0300\r\n"));
        // The sibling override VEVENT survives byte-for-byte.
        assert!(out.contains("RECURRENCE-ID;TZID=Europe/Athens:20260908T100000\r\n"));
        assert!(out.contains("SUMMARY:Old title (moved)\r\n"));
        assert!(out.contains("DTSTART;TZID=Europe/Athens:20260908T140000\r\n"));
        // The master's VALARM set was replaced by the edit's reminders.
        assert!(out.contains("TRIGGER:-PT15M\r\n"), "{out}");
        assert!(!out.contains("TRIGGER:-PT10M"), "old alarm replaced");
        assert_eq!(out.matches("BEGIN:VALARM").count(), 1);

        // And the result still parses: two VEVENTs, master retitled.
        let events = cosmic_pim_core::ical::parse_ics(&out, "test", "x.ics");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].summary, "New title");
        assert_eq!(events[0].sequence, 4);
        assert_eq!(
            events[0].start.to_utc(chrono_tz::UTC).timestamp_millis(),
            start_ms,
            "same instant through the preserved TZID"
        );
        assert_eq!(events[1].summary, "Old title (moved)");
    }

    #[test]
    fn patch_targets_the_override_when_rid_matches() {
        let ical = "BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\n\
UID:s@x\r\n\
DTSTART:20260901T100000Z\r\n\
SUMMARY:Master\r\n\
RRULE:FREQ=WEEKLY\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
UID:s@x\r\n\
RECURRENCE-ID:20260908T100000Z\r\n\
DTSTART:20260908T100000Z\r\n\
SUMMARY:Instance\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        let patch = LocalEventPatch {
            title: "Instance edited",
            location: "",
            notes: "",
            start_ms: 1_788_861_600_000, // 2026-09-08T10:00:00Z
            end_ms: 1_788_865_200_000,
            all_day: false,
            rrule: "",
            reminders: &[],
        };
        let out = patch_event_ics(ical, "20260908T100000Z", &patch).expect("patched");
        assert!(out.contains("SUMMARY:Master\r\n"), "master untouched");
        assert!(out.contains("SUMMARY:Instance edited\r\n"));
        assert!(!out.contains("SUMMARY:Instance\r\n"));
        // No VEVENT matches a bogus rid.
        assert!(patch_event_ics(ical, "19990101T000000Z", &patch).is_none());
    }
}

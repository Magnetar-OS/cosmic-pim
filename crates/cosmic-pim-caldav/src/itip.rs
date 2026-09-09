// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The METHOD dispatch, the attendee gate, the SEQUENCE rule, and the
// single-instance CANCEL behaviour are ported from `src-tauri/src/itip.rs` in
// the Meltemi project. The storage is new: the donor drove SQLite rows, this
// drives vdir files. See NOTICE and LICENSING.md.

//! iTIP (RFC 5546): the calendar events that arrive as mail.
//!
//! An invitation is a `text/calendar` MIME part carrying a `METHOD`. Envelope
//! finds the part; this module says what it *means* and applies it to a vdir
//! collection — which is how an invite accepted in the mail client appears in
//! the calendar without either app knowing the other exists. The scheduling
//! half of RFC 6638 (server inboxes and outboxes) is deliberately absent: that
//! is suite step 7, and it will *use* this module rather than replace it,
//! because the semantics of a REQUEST are the same whether it arrived over
//! SMTP or over a CalDAV inbox.
//!
//! # The three decisions that prevent real damage
//!
//! **The attendee gate.** A `REQUEST` or `CANCEL` is applied only when this
//! account's address is on the attendee list — exact, lowercased,
//! `mailto:`-stripped. Without it, an invitation forwarded through a mailing
//! list lands on the calendar of everyone who received it.
//!
//! **The SEQUENCE rule.** An incoming `REQUEST` or `CANCEL` whose `SEQUENCE`
//! is *lower* than the stored event's is stale — out-of-order delivery, or a
//! re-fetched mailbox replaying old mail — and applying it would overwrite
//! newer state with older. Equal sequence still applies: RFC 5546 §3.2.2 uses
//! same-sequence re-sends to refresh non-versioned detail.
//!
//! **CANCEL is scoped by RECURRENCE-ID.** A cancel carrying one marks that
//! single instance cancelled; only a cancel without one removes the series.
//! Collapsing the two deletes every occurrence of a weekly meeting because the
//! organizer cancelled one Tuesday — the classic iTIP data-loss bug, and the
//! reason this is a match on the field rather than a branch someone remembers.
//!
//! # Verbatim, with one deliberate exception
//!
//! A stored `REQUEST` keeps the organizer's own bytes — attendees, X- props,
//! VTIMEZONEs, everything — with the `METHOD` line removed, because RFC 4791
//! §4.1 forbids `METHOD` in a calendar object resource and every CalDAV server
//! rejects a PUT carrying one. [`strip_method`] removes exactly that line and
//! nothing else.

use std::path::{Path, PathBuf};

use cosmic_pim_core::atomic;
use cosmic_pim_core::ical::escape_text;
use cosmic_pim_core::patch::{fold, logical_lines, terminator_of};

use crate::error::{Error, Result};
use crate::vdir::sanitise_stem;

/// The RFC 5546 methods, plus the ones we recognise only to ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// An invitation, or an update to one.
    Request,
    /// An attendee answering. Its ATTENDEE is the *other* person, by design.
    Reply,
    Cancel,
    /// Unsolicited publication — a feed wearing iTIP clothes.
    Publish,
    /// COUNTER, REFRESH, DECLINECOUNTER, ADD: recognised, not handled.
    Other,
}

impl Method {
    fn parse(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "REQUEST" => Self::Request,
            "REPLY" => Self::Reply,
            "CANCEL" => Self::Cancel,
            "PUBLISH" => Self::Publish,
            _ => Self::Other,
        }
    }
}

/// One person on an iTIP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    /// Lowercased, `mailto:`-stripped.
    pub email: String,
    pub name: Option<String>,
    /// `ACCEPTED`, `DECLINED`, `TENTATIVE`, `NEEDS-ACTION` — uppercased.
    pub partstat: Option<String>,
}

/// What an iTIP payload says, read from its first VEVENT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Itip {
    pub method: Method,
    pub uid: String,
    /// The RECURRENCE-ID value with its TZID, when the payload targets one
    /// instance. Kept in the source's own spelling — it is compared against
    /// stored files, never reinterpreted.
    pub recurrence_id: Option<String>,
    pub sequence: i64,
    pub summary: Option<String>,
    pub organizer: Option<Participant>,
    pub attendees: Vec<Participant>,
    pub has_dtstart: bool,
}

impl Itip {
    /// Whether this payload is addressed to `me` — the REQUEST/CANCEL gate.
    ///
    /// Exact match after normalisation, nothing fuzzier: an invitation
    /// forwarded through a mailing list must not land on every subscriber's
    /// calendar, and "close enough" address matching is how that happens.
    #[must_use]
    pub fn is_addressed_to(&self, me: &str) -> bool {
        let me = normalise_email(me);
        !me.is_empty() && self.attendees.iter().any(|a| a.email == me)
    }

    /// Whether this payload may overwrite an event stored with
    /// `stored_sequence`.
    ///
    /// Lower is stale; **equal still applies** (RFC 5546 §3.2.2 — a
    /// same-sequence re-send refreshes non-versioned detail).
    #[must_use]
    pub fn supersedes(&self, stored_sequence: i64) -> bool {
        self.sequence >= stored_sequence
    }
}

/// Parses an iTIP payload. `None` when it has no METHOD or no usable VEVENT —
/// a plain calendar attachment is not an invitation.
#[must_use]
pub fn parse(ics: &str) -> Option<Itip> {
    let lines = logical_lines(ics);

    let mut method: Option<Method> = None;
    let mut depth = 0usize;
    let mut in_event_at: Option<usize> = None;

    let mut uid = None;
    let mut recurrence_id = None;
    let mut sequence: i64 = 0;
    let mut summary = None;
    let mut organizer = None;
    let mut attendees = Vec::new();
    let mut has_dtstart = false;
    let mut saw_event = false;

    for line in &lines {
        if let Some(name) = line.begins() {
            depth += 1;
            if name == "VEVENT" && in_event_at.is_none() && !saw_event {
                in_event_at = Some(depth);
                saw_event = true;
            }
            continue;
        }
        if line.ends().is_some() {
            if in_event_at == Some(depth) {
                in_event_at = None;
            }
            depth = depth.saturating_sub(1);
            continue;
        }

        let name = line.name();
        if depth == 1 && name == "METHOD" {
            method = Some(Method::parse(line.value()));
            continue;
        }

        // Only the first VEVENT's own lines, not an override's and not a
        // VALARM's: the payload's headline facts come from its first
        // component, and a VALARM's properties are not the event's.
        if in_event_at != Some(depth) {
            continue;
        }

        match name.as_str() {
            "UID" => uid = Some(line.value().trim().to_owned()),
            "RECURRENCE-ID" => {
                let tzid = param(line.params(), "TZID");
                let value = line.value().trim();
                recurrence_id = Some(match tzid {
                    Some(zone) => format!("{value};TZID={zone}"),
                    None => value.to_owned(),
                });
            }
            "SEQUENCE" => sequence = line.value().trim().parse().unwrap_or(0),
            "SUMMARY" => summary = Some(line.value().trim().to_owned()),
            "DTSTART" => has_dtstart = true,
            "ORGANIZER" => organizer = Some(participant(line.params(), line.value())),
            "ATTENDEE" => attendees.push(participant(line.params(), line.value())),
            _ => {}
        }
    }

    Some(Itip {
        method: method?,
        uid: uid.filter(|u| !u.is_empty())?,
        recurrence_id,
        sequence,
        summary,
        organizer,
        attendees,
        has_dtstart,
    })
}

fn participant(params: &str, value: &str) -> Participant {
    Participant {
        email: normalise_email(value),
        name: param(params, "CN"),
        partstat: param(params, "PARTSTAT").map(|p| p.to_ascii_uppercase()),
    }
}

/// One parameter's value out of a raw parameter string, quotes removed.
fn param(params: &str, wanted: &str) -> Option<String> {
    // Parameters are `;`-separated, but a quoted value may contain `;`.
    let mut rest = params;
    while let Some(start) = rest.find(';') {
        rest = &rest[start + 1..];
        let (name, after) = rest.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case(wanted) {
            continue;
        }
        return Some(if let Some(quoted) = after.strip_prefix('"') {
            quoted.split('"').next().unwrap_or_default().to_owned()
        } else {
            after
                .split([';', ':'])
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned()
        });
    }
    None
}

fn normalise_email(raw: &str) -> String {
    let lower = raw.trim().to_lowercase();
    lower
        .strip_prefix("mailto:")
        .unwrap_or(&lower)
        .trim()
        .to_owned()
}

/// The payload with its `METHOD` line removed and nothing else touched.
///
/// RFC 4791 §4.1 forbids `METHOD` in a calendar object resource; a PUT
/// carrying one is rejected by every server. Everything else — folding,
/// terminators, X- properties — passes through byte for byte.
#[must_use]
pub fn strip_method(ics: &str) -> String {
    let mut out = String::with_capacity(ics.len());
    let mut depth = 0usize;
    for line in logical_lines(ics) {
        if line.begins().is_some() {
            depth += 1;
        } else if line.ends().is_some() {
            depth = depth.saturating_sub(1);
        } else if depth == 1 && line.name() == "METHOD" {
            continue;
        }
        out.push_str(line.raw());
    }
    out
}

/// Adds a `METHOD` to a stored calendar object — the exact inverse of
/// [`strip_method`], and the whole of "turn this event into an invitation".
///
/// The organizer's REQUEST *is* the stored event, byte for byte, with one
/// line added. Rebuilding it from a parsed model instead is how an
/// invitation arrives missing the VALARM the organizer set, the VTIMEZONE
/// the attendee's client needs, and every X- property the two of them were
/// silently exchanging. Nothing here is re-serialised: the METHOD goes in at
/// the VCALENDAR level after the last of VERSION/PRODID/CALSCALE, which is
/// where RFC 5545 §3.6 expects it and where a reader will not be surprised
/// by it, and every other byte passes through untouched.
///
/// An existing METHOD is replaced rather than duplicated — two METHOD lines
/// are invalid, and a REQUEST accidentally still carrying `METHOD:REPLY`
/// would be applied backwards by the receiver.
#[must_use]
pub fn with_method(ics: &str, method: &str) -> String {
    let method_line = format!("METHOD:{}", method.trim().to_ascii_uppercase());
    let terminator = terminator_of(ics);
    let lines = logical_lines(ics);

    // Where the METHOD belongs: after the calendar-level preamble, before the
    // first component. Falling back to "right after BEGIN:VCALENDAR" keeps a
    // preamble-less object valid rather than refusing it.
    let mut depth = 0usize;
    let mut insert_at = None;
    for (index, line) in lines.iter().enumerate() {
        if let Some(name) = line.begins() {
            depth += 1;
            if depth == 1 && name == "VCALENDAR" {
                insert_at = Some(index + 1);
                continue;
            }
            if depth == 2 {
                // A component started; the preamble is over.
                break;
            }
            continue;
        }
        if line.ends().is_some() {
            depth = depth.saturating_sub(1);
            continue;
        }
        if depth == 1 && matches!(line.name().as_str(), "VERSION" | "PRODID" | "CALSCALE") {
            insert_at = Some(index + 1);
        }
    }
    let Some(insert_at) = insert_at else {
        // Not a VCALENDAR at all. Returning it unchanged rather than wrapping
        // it: a caller that handed us the wrong bytes needs to see that.
        return ics.to_owned();
    };

    let mut out = String::with_capacity(ics.len() + method_line.len() + 2);
    let mut depth = 0usize;
    for (index, line) in lines.iter().enumerate() {
        if index == insert_at {
            fold(&method_line, terminator, &mut out);
        }
        if line.begins().is_some() {
            depth += 1;
        } else if line.ends().is_some() {
            depth = depth.saturating_sub(1);
        } else if depth == 1 && line.name() == "METHOD" {
            continue;
        }
        out.push_str(line.raw());
    }
    out
}

/// Raises the `SEQUENCE` of every VEVENT in a stored object by one.
///
/// RFC 5546 §3.2.2: the organizer increments SEQUENCE when a change matters
/// to attendees — a moved time, a changed location — and leaves it alone
/// when it does not, because attendees whose clients see a raised sequence
/// are asked to answer again. Every VEVENT in the file moves together: a
/// master and its overrides are one scheduling object, and bumping only some
/// of them leaves the series answering at two different versions.
///
/// Byte-preserving like everything else here — only the SEQUENCE values are
/// rewritten, and a VEVENT without one gains `SEQUENCE:1`, since absent means
/// zero (RFC 5545 §3.8.7.4).
#[must_use]
pub fn bump_sequence(ics: &str) -> String {
    let terminator = terminator_of(ics);
    let lines = logical_lines(ics);

    // Which VEVENTs lack a SEQUENCE, so one can be inserted before END.
    let mut out = String::with_capacity(ics.len() + 16);
    let mut depth = 0usize;
    let mut in_event_at: Option<usize> = None;
    let mut event_had_sequence = false;

    for line in &lines {
        if let Some(name) = line.begins() {
            depth += 1;
            if name == "VEVENT" && in_event_at.is_none() {
                in_event_at = Some(depth);
                event_had_sequence = false;
            }
            out.push_str(line.raw());
            continue;
        }
        if line.ends().is_some() {
            if in_event_at == Some(depth) {
                if !event_had_sequence {
                    fold("SEQUENCE:1", terminator, &mut out);
                }
                in_event_at = None;
            }
            depth = depth.saturating_sub(1);
            out.push_str(line.raw());
            continue;
        }

        if in_event_at == Some(depth) && line.name() == "SEQUENCE" {
            event_had_sequence = true;
            let current: i64 = line.value().trim().parse().unwrap_or(0);
            fold(
                &format!("SEQUENCE:{}", current.max(0).saturating_add(1)),
                terminator,
                &mut out,
            );
            continue;
        }
        out.push_str(line.raw());
    }
    out
}

/// Sends a stored event to its attendees as an invitation (RFC 6638 §3.2).
///
/// `ics` is the event exactly as it sits in the vdir. It is wrapped with
/// `METHOD:REQUEST` and POSTed to the organizer's Outbox; the server fans it
/// out and returns a verdict per attendee.
///
/// This is the server-scheduling path, and it is the one to prefer when
/// `discover_scheduling` offers an outbox: the server knows which attendees
/// are local, handles the ones that are not over iMIP or iSchedule, and files
/// its own copy of what it sent. Where there is no outbox, the same bytes go
/// to Envelope to be mailed — which is why this returns the wrapped payload's
/// verdicts rather than hiding the transport.
///
/// Bump the sequence first ([`bump_sequence`]) when re-sending a change
/// attendees must answer again; this call does not decide that, because only
/// the caller knows whether the edit was significant.
pub fn send_invitation(
    client: &crate::dav::CaldavClient,
    outbox_url: &str,
    ics: &str,
) -> Result<Vec<crate::dav::ScheduleResponse>> {
    client.post_scheduling(outbox_url, &with_method(ics, "REQUEST"))
}

/// Withdraws a stored event from its attendees (RFC 5546 §3.2.5).
///
/// The event's own bytes with `METHOD:CANCEL`, which is what makes the
/// receiver's [`apply`] scope the cancellation correctly: a payload carrying
/// RECURRENCE-ID cancels that instance, one without cancels the series. The
/// caller controls which by passing the master or a single override — the
/// same distinction, from the sending side.
pub fn send_cancellation(
    client: &crate::dav::CaldavClient,
    outbox_url: &str,
    ics: &str,
) -> Result<Vec<crate::dav::ScheduleResponse>> {
    client.post_scheduling(outbox_url, &with_method(ics, "CANCEL"))
}

/// What applying one payload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A REQUEST landed as a new file.
    Created { file: String },
    /// A REQUEST replaced or extended a stored file.
    Updated { file: String },
    /// A REPLY patched attendee participation into a stored file.
    ReplyApplied { file: String, updated: usize },
    /// A CANCEL without RECURRENCE-ID removed the stored file.
    Cancelled { file: String },
    /// A CANCEL with RECURRENCE-ID marked one instance cancelled.
    InstanceCancelled { file: String },
    /// The payload's SEQUENCE is lower than the stored event's. Nothing was
    /// touched — applying it would overwrite newer state with older.
    Stale,
    /// REQUEST/CANCEL whose attendees do not include this account. A
    /// forwarded or mislabelled invite; not ours to act on.
    NotForMe,
    /// REPLY or CANCEL naming a UID this collection does not hold.
    NoMatch,
    /// PUBLISH, COUNTER, REFRESH… — recognised and left alone.
    Ignored,
}

impl Outcome {
    /// The file this outcome touched, for the caller to queue writeback on.
    ///
    /// Writeback is deliberately not queued here: this runs inside a mail
    /// sync pass and must stay decided-by-the-caller, exactly as the donor's
    /// version stayed network-free.
    #[must_use]
    pub fn file(&self) -> Option<&str> {
        match self {
            Self::Created { file }
            | Self::Updated { file }
            | Self::ReplyApplied { file, .. }
            | Self::InstanceCancelled { file } => Some(file),
            _ => None,
        }
    }
}

/// Applies one iTIP payload to a vdir collection directory.
///
/// `me` is the account address the mail arrived at, for the attendee gate.
pub fn apply(collection: &Path, ics: &str, me: &str) -> Result<Outcome> {
    let Some(itip) = parse(ics) else {
        return Ok(Outcome::Ignored);
    };
    if !itip.has_dtstart && itip.method == Method::Request {
        return Ok(Outcome::Ignored);
    }

    match itip.method {
        Method::Request => {
            if !itip.is_addressed_to(me) {
                return Ok(Outcome::NotForMe);
            }
            apply_request(collection, ics, &itip)
        }
        Method::Reply => apply_reply(collection, &itip),
        Method::Cancel => {
            if !itip.is_addressed_to(me) {
                return Ok(Outcome::NotForMe);
            }
            apply_cancel(collection, &itip)
        }
        Method::Publish | Method::Other => Ok(Outcome::Ignored),
    }
}

/// The stored file holding `uid`, found by reading each candidate's own UID.
///
/// A scan rather than an index, deliberately: collections are hundreds of
/// files at most, invitations arrive a few per day, and an index would be a
/// second copy of a fact the files already hold.
fn find_by_uid(collection: &Path, uid: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(collection).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "ics") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if stored_uid(&text).as_deref() == Some(uid) {
            return Some(path);
        }
    }
    None
}

fn stored_uid(ics: &str) -> Option<String> {
    let mut depth = 0usize;
    for line in logical_lines(ics) {
        if line.begins().is_some() {
            depth += 1;
        } else if line.ends().is_some() {
            depth = depth.saturating_sub(1);
        } else if depth == 2 && line.name() == "UID" {
            return Some(line.value().trim().to_owned());
        }
    }
    None
}

/// The highest SEQUENCE any component in the stored file carries.
fn stored_sequence(ics: &str) -> i64 {
    let mut highest = 0i64;
    for line in logical_lines(ics) {
        if line.name() == "SEQUENCE"
            && let Ok(sequence) = line.value().trim().parse::<i64>()
        {
            highest = highest.max(sequence);
        }
    }
    highest
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// A file name for `uid` that nothing in `collection` is already using.
///
/// `find_by_uid` answering `None` means "no file holds this UID". It does not
/// mean "this name is free": [`sanitise_stem`] is lossy, so two UIDs derive
/// one stem easily — `@` cleans to `-`, and any two sharing a 120-character
/// prefix collide on the truncation. Writing an invitation at an occupied
/// name replaced an event that had nothing to do with the sender, which is a
/// stranger deleting your appointment by sending you mail.
///
/// The same defence the sync store and the feed splitter already use, for the
/// same reason; this path was the one that did not have it.
fn unused_name(collection: &Path, uid: &str) -> String {
    let stem = sanitise_stem(uid);
    let mut name = format!("{stem}.ics");
    let mut n = 2;
    while collection.join(&name).exists() {
        name = format!("{stem}-{n}.ics");
        n += 1;
    }
    name
}

fn apply_request(collection: &Path, ics: &str, itip: &Itip) -> Result<Outcome> {
    let stripped = strip_method(ics);

    match find_by_uid(collection, &itip.uid) {
        None => {
            let file = unused_name(collection, &itip.uid);
            let target = collection.join(&file);
            atomic::write(&target, &stripped, None)
                .map_err(|why| Error::internal(format!("writing {}: {why}", target.display())))?;
            Ok(Outcome::Created { file })
        }
        Some(path) => {
            let stored = std::fs::read_to_string(&path)
                .map_err(|why| Error::internal(format!("reading {}: {why}", path.display())))?;
            if !itip.supersedes(stored_sequence(&stored)) {
                return Ok(Outcome::Stale);
            }

            let text = match &itip.recurrence_id {
                // A whole-series update: the organizer's payload is the new
                // truth for the series, overrides included.
                //
                // This is the one place in the suite where writing a whole
                // document over a file that may hold several components is
                // CORRECT, and it needs saying because three data-corruption
                // bugs were fixed in exactly that shape — a task save deleting
                // its file's other tasks, a contact save overwriting another
                // person's card, an event save discarding what it did not
                // model. Those were wrong because the writer owned one record
                // and destroyed its neighbours. This one is right because RFC
                // 5546 §3.2.2 makes an organizer's REQUEST without a
                // RECURRENCE-ID authoritative for the entire series: the
                // overrides being replaced are ones the organizer is
                // superseding, and keeping them would resurrect instances the
                // organizer has just redefined. Do not "fix" this into a
                // patch; see ARCHITECTURE.md's verbatim-storage section.
                None => stripped,
                // One instance changed: the master and the other overrides
                // stand, and only this override is replaced or added.
                Some(rid) => merge_override(&stored, &stripped, rid),
            };

            atomic::write(&path, &text, None)
                .map_err(|why| Error::internal(format!("writing {}: {why}", path.display())))?;
            Ok(Outcome::Updated {
                file: file_name_of(&path),
            })
        }
    }
}

fn apply_reply(collection: &Path, itip: &Itip) -> Result<Outcome> {
    if itip.attendees.is_empty() {
        return Ok(Outcome::Ignored);
    }
    let Some(path) = find_by_uid(collection, &itip.uid) else {
        return Ok(Outcome::NoMatch);
    };
    let stored = std::fs::read_to_string(&path)
        .map_err(|why| Error::internal(format!("reading {}: {why}", path.display())))?;

    // Deliberately NOT gated on attendee-is-me: a REPLY's attendee is the
    // *other* person answering our invitation.
    let mut text = stored;
    let mut updated = 0usize;
    for attendee in &itip.attendees {
        let Some(partstat) = attendee.partstat.as_deref() else {
            continue;
        };
        if let Some(patched) =
            crate::patch::patch_attendee_partstat(&text, &attendee.email, partstat)
        {
            text = patched;
            updated += 1;
        }
    }

    if updated > 0 {
        atomic::write(&path, &text, None)
            .map_err(|why| Error::internal(format!("writing {}: {why}", path.display())))?;
    }
    Ok(Outcome::ReplyApplied {
        file: file_name_of(&path),
        updated,
    })
}

fn apply_cancel(collection: &Path, itip: &Itip) -> Result<Outcome> {
    let Some(path) = find_by_uid(collection, &itip.uid) else {
        return Ok(Outcome::NoMatch);
    };
    let stored = std::fs::read_to_string(&path)
        .map_err(|why| Error::internal(format!("reading {}: {why}", path.display())))?;
    if !itip.supersedes(stored_sequence(&stored)) {
        return Ok(Outcome::Stale);
    }

    match &itip.recurrence_id {
        None => {
            // The whole series. The file goes; the caller queues the DELETE.
            std::fs::remove_file(&path)
                .map_err(|why| Error::internal(format!("removing {}: {why}", path.display())))?;
            Ok(Outcome::Cancelled {
                file: file_name_of(&path),
            })
        }
        Some(rid) => {
            // One instance: a cancelled override, materialised if the file
            // only holds the master. Every other occurrence stands — this is
            // the branch that stops "the organizer cancelled one Tuesday"
            // from deleting the weekly series.
            let cancelled = cancelled_override(itip, rid, terminator_of(&stored));
            let text = merge_override(&stored, &cancelled, rid);
            atomic::write(&path, &text, None)
                .map_err(|why| Error::internal(format!("writing {}: {why}", path.display())))?;
            Ok(Outcome::InstanceCancelled {
                file: file_name_of(&path),
            })
        }
    }
}

/// Replaces the override with `rid` in `stored` by the (only) VEVENT in
/// `incoming`, or appends it before `END:VCALENDAR` when no such override
/// exists yet.
///
/// Structural, like the feed splitter: the file is taken apart into its
/// prelude, its components, and its trailer, each as the source's own bytes;
/// one component is swapped; the rest are reassembled untouched.
fn merge_override(stored: &str, incoming: &str, rid: &str) -> String {
    let override_block = first_vevent(incoming);

    let mut prelude = String::new();
    let mut components: Vec<String> = Vec::new();
    let mut trailer = String::new();

    let mut current: Option<String> = None;
    let mut depth = 0usize;

    for line in logical_lines(stored) {
        if let Some(name) = line.begins() {
            if name == "VCALENDAR" && depth == 0 {
                depth = 1;
                prelude.push_str(line.raw());
                continue;
            }
            depth += 1;
            if depth == 2 && current.is_none() {
                current = Some(String::new());
            }
        } else if let Some(name) = line.ends() {
            if name == "VCALENDAR" && depth == 1 {
                trailer.push_str(line.raw());
                depth = 0;
                continue;
            }
            depth = depth.saturating_sub(1);
            if depth == 1 {
                let mut block = current.take().unwrap_or_default();
                block.push_str(line.raw());
                components.push(block);
                continue;
            }
        }

        match &mut current {
            Some(block) => block.push_str(line.raw()),
            None => prelude.push_str(line.raw()),
        }
    }

    let mut out = String::with_capacity(stored.len() + override_block.len());
    out.push_str(&prelude);
    for component in &components {
        if !component_has_rid(component, rid) {
            out.push_str(component);
        }
    }
    out.push_str(&override_block);
    out.push_str(&trailer);
    out
}

/// Whether a single component's text carries `rid` at its own top level.
fn component_has_rid(component: &str, rid: &str) -> bool {
    let mut depth = 0usize;
    for line in logical_lines(component) {
        if line.begins().is_some() {
            depth += 1;
        } else if line.ends().is_some() {
            depth = depth.saturating_sub(1);
        } else if depth == 1 && line.name() == "RECURRENCE-ID" {
            let tzid = param(line.params(), "TZID");
            let value = line.value().trim();
            let spelled = match tzid {
                Some(zone) => format!("{value};TZID={zone}"),
                None => value.to_owned(),
            };
            return spelled == rid;
        }
    }
    false
}

/// The first VEVENT of `ics`, raw bytes, BEGIN through END inclusive.
fn first_vevent(ics: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    let mut depth = 0usize;
    for line in logical_lines(ics) {
        if line.begins().as_deref() == Some("VEVENT") && !inside {
            inside = true;
            depth = 0;
        }
        if inside {
            out.push_str(line.raw());
            if line.begins().is_some() {
                depth += 1;
            } else if line.ends().is_some() {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
        }
    }
    out
}

/// A minimal cancelled override, built from what the CANCEL itself carries.
///
/// The one place this module writes lines of its own — and every line of it
/// is data the CANCEL supplied or a required timestamp.
fn cancelled_override(itip: &Itip, rid: &str, terminator: &str) -> String {
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let mut out = String::new();
    fold("BEGIN:VEVENT", terminator, &mut out);
    fold(
        &format!("UID:{}", escape_text(&itip.uid)),
        terminator,
        &mut out,
    );
    fold(&recurrence_id_line(rid), terminator, &mut out);
    fold(
        &format!("SEQUENCE:{}", itip.sequence.max(0)),
        terminator,
        &mut out,
    );
    fold(&format!("DTSTAMP:{dtstamp}"), terminator, &mut out);
    fold("STATUS:CANCELLED", terminator, &mut out);
    fold("END:VEVENT", terminator, &mut out);
    out
}

/// Re-spells a canonical `value;TZID=zone` key as a property line.
fn recurrence_id_line(rid: &str) -> String {
    if let Some((value, zone)) = rid.split_once(";TZID=") {
        return format!("RECURRENCE-ID;TZID={zone}:{value}");
    }
    if rid.len() == 8 && rid.bytes().all(|b| b.is_ascii_digit()) {
        return format!("RECURRENCE-ID;VALUE=DATE:{rid}");
    }
    format!("RECURRENCE-ID:{rid}")
}

/// Everything a `METHOD:REPLY` needs, read off the stored invitation.
#[derive(Debug, Clone)]
pub struct Reply<'a> {
    pub uid: &'a str,
    /// `None` answers for the whole series.
    pub recurrence_id: Option<&'a str>,
    /// Echoed verbatim: RFC 5546 says a REPLY answers the REQUEST's sequence.
    pub sequence: i64,
    pub organizer_email: &'a str,
    pub summary: Option<&'a str>,
    /// `ACCEPTED` | `TENTATIVE` | `DECLINED`.
    pub partstat: &'a str,
}

/// Builds the `METHOD:REPLY` calendar an attendee sends back.
///
/// Envelope mails this to the organizer; Slate can use it on servers that do
/// no scheduling of their own. Deliberately minimal — my ATTENDEE with the
/// answered PARTSTAT, the organizer echoed, the sequence echoed, a fresh
/// DTSTAMP — because a REPLY that restates the whole event invites the
/// organizer's client to diff fields the attendee never meant to touch.
#[must_use]
pub fn build_reply(reply: &Reply<'_>, me_email: &str, me_name: &str) -> String {
    let terminator = "\r\n";
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let mut out = String::new();
    fold("BEGIN:VCALENDAR", terminator, &mut out);
    fold("PRODID:-//cosmic-pim//itip//EN", terminator, &mut out);
    fold("VERSION:2.0", terminator, &mut out);
    fold("METHOD:REPLY", terminator, &mut out);
    fold("BEGIN:VEVENT", terminator, &mut out);
    fold(
        &format!("UID:{}", escape_text(reply.uid)),
        terminator,
        &mut out,
    );
    if let Some(rid) = reply.recurrence_id.filter(|r| !r.trim().is_empty()) {
        fold(&recurrence_id_line(rid), terminator, &mut out);
    }
    fold(
        &format!("SEQUENCE:{}", reply.sequence.max(0)),
        terminator,
        &mut out,
    );
    fold(&format!("DTSTAMP:{dtstamp}"), terminator, &mut out);
    fold(
        &format!(
            "ORGANIZER:mailto:{}",
            escape_text(reply.organizer_email.trim())
        ),
        terminator,
        &mut out,
    );
    let cn = if me_name.trim().is_empty() {
        String::new()
    } else {
        format!(";CN={}", escape_text(me_name.trim()))
    };
    fold(
        &format!(
            "ATTENDEE;PARTSTAT={}{cn}:mailto:{}",
            reply.partstat,
            escape_text(me_email.trim())
        ),
        terminator,
        &mut out,
    );
    if let Some(summary) = reply.summary.filter(|s| !s.trim().is_empty()) {
        fold(
            &format!("SUMMARY:{}", escape_text(summary.trim())),
            terminator,
            &mut out,
        );
    }
    fold("END:VEVENT", terminator, &mut out);
    fold("END:VCALENDAR", terminator, &mut out);
    out
}

/// Someone's busy time, as their server reported it.
///
/// The window only — no summary, no location, no attendees. That is the whole
/// point of free/busy: a colleague's server will tell you *when* they are
/// unavailable without telling you what they are doing, which is why this can
/// be asked of people whose calendars you cannot read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusyPeriod {
    pub start_ms: i64,
    pub end_ms: i64,
    /// The `FBTYPE` parameter, uppercased — `BUSY`, `BUSY-TENTATIVE`,
    /// `BUSY-UNAVAILABLE`. Defaults to `BUSY` per RFC 5545 §3.2.9 when the
    /// parameter is absent, which is how most servers write it.
    pub kind: String,
}

/// One attendee's answer to a free/busy request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {
    /// As the server spelled it, `mailto:` stripped and lowercased, so it
    /// compares against the address that was asked for.
    pub attendee: String,
    /// The iTIP request-status for this attendee. `2.x` means the periods
    /// below are an answer; anything else means they are not, and `busy` is
    /// empty rather than misleadingly free.
    pub request_status: String,
    pub busy: Vec<BusyPeriod>,
}

impl Availability {
    /// Whether this attendee actually answered.
    ///
    /// The distinction that matters to a scheduling UI: "free" and "would not
    /// say" are different answers, and showing the second as the first books
    /// meetings on top of people.
    #[must_use]
    pub fn answered(&self) -> bool {
        self.request_status.trim_start().starts_with('2')
    }
}

/// Builds the `METHOD:REQUEST` VFREEBUSY that asks when attendees are busy.
///
/// RFC 6638 §4.3: the organizer POSTs this to their own scheduling Outbox and
/// the server fans it out — to local users directly, to remote ones over
/// iMIP or iSchedule if it can. The UID is fresh per request because a
/// free/busy question is not an event and nothing should ever be filed
/// against it.
#[must_use]
pub fn build_freebusy_request(
    organizer_email: &str,
    attendee_emails: &[String],
    start_ms: i64,
    end_ms: i64,
) -> String {
    let terminator = "\r\n";
    let now = chrono::Utc::now();
    let dtstamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    // Unique without pulling in a UUID dependency for a value nothing stores:
    // the timestamp to the nanosecond plus the organizer's own address.
    let uid = format!(
        "freebusy-{}-{}@cosmic-pim",
        now.timestamp_nanos_opt()
            .unwrap_or_else(|| now.timestamp_millis()),
        organizer_email.trim()
    );

    let mut out = String::new();
    fold("BEGIN:VCALENDAR", terminator, &mut out);
    fold("PRODID:-//cosmic-pim//itip//EN", terminator, &mut out);
    fold("VERSION:2.0", terminator, &mut out);
    fold("METHOD:REQUEST", terminator, &mut out);
    fold("BEGIN:VFREEBUSY", terminator, &mut out);
    fold(&format!("UID:{}", escape_text(&uid)), terminator, &mut out);
    fold(&format!("DTSTAMP:{dtstamp}"), terminator, &mut out);
    fold(
        &format!("DTSTART:{}", utc_stamp(start_ms)),
        terminator,
        &mut out,
    );
    fold(
        &format!("DTEND:{}", utc_stamp(end_ms)),
        terminator,
        &mut out,
    );
    fold(
        &format!("ORGANIZER:mailto:{}", escape_text(organizer_email.trim())),
        terminator,
        &mut out,
    );
    for attendee in attendee_emails {
        let attendee = attendee.trim();
        if attendee.is_empty() {
            continue;
        }
        fold(
            &format!("ATTENDEE:mailto:{}", escape_text(attendee)),
            terminator,
            &mut out,
        );
    }
    fold("END:VFREEBUSY", terminator, &mut out);
    fold("END:VCALENDAR", terminator, &mut out);
    out
}

/// Reads the `FREEBUSY` periods out of a VFREEBUSY reply.
///
/// A period is `start/end` or `start/duration` (RFC 5545 §3.8.2.6), and one
/// property may carry a comma-separated list of them. Anything unparseable is
/// skipped rather than guessed at: a free/busy view with a missing block
/// shows a meeting that could be double-booked, but an *invented* block hides
/// a slot that was actually free, and only one of those is discovered by the
/// person looking at the grid.
#[must_use]
pub fn parse_freebusy(ics: &str) -> Vec<BusyPeriod> {
    let mut out = Vec::new();
    for line in logical_lines(ics) {
        if line.begins().is_some() || line.ends().is_some() || line.name() != "FREEBUSY" {
            continue;
        }
        let kind = param(line.params(), "FBTYPE")
            .map_or_else(|| "BUSY".to_owned(), |v| v.trim().to_ascii_uppercase());
        // FREE periods are the absence of busy-ness; recording them as busy
        // would invert the answer.
        if kind == "FREE" {
            continue;
        }
        for period in line.value().split(',') {
            if let Some((start_ms, end_ms)) = parse_period(period.trim()) {
                out.push(BusyPeriod {
                    start_ms,
                    end_ms,
                    kind: kind.clone(),
                });
            }
        }
    }
    out
}

/// `start/end` or `start/duration`, both in UTC, to a millisecond range.
fn parse_period(period: &str) -> Option<(i64, i64)> {
    let (start, rest) = period.split_once('/')?;
    let start_ms = parse_utc_stamp(start)?;
    let end_ms = if rest.starts_with('P') || rest.starts_with("+P") || rest.starts_with("-P") {
        start_ms + parse_duration_ms(rest)?
    } else {
        parse_utc_stamp(rest)?
    };
    (end_ms >= start_ms).then_some((start_ms, end_ms))
}

/// `YYYYMMDDTHHMMSSZ` — the only form RFC 5545 §3.3.5 permits in a period,
/// and the only one accepted here: a floating or zoned stamp in a free/busy
/// answer has no defined meaning across the two calendars being compared.
fn parse_utc_stamp(stamp: &str) -> Option<i64> {
    let stamp = stamp.trim();
    if !stamp.ends_with('Z') {
        return None;
    }
    chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%dT%H%M%SZ")
        .ok()
        .map(|dt| dt.and_utc().timestamp_millis())
}

/// An RFC 5545 §3.3.6 duration, restricted to what a period can carry.
fn parse_duration_ms(text: &str) -> Option<i64> {
    let text = text.trim();
    let (sign, text) = match text.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1i64, text.strip_prefix('+').unwrap_or(text)),
    };
    let rest = text.strip_prefix('P')?;
    let mut total_ms = 0i64;
    let mut in_time = false;
    let mut digits = String::new();

    for ch in rest.chars() {
        match ch {
            'T' => {
                in_time = true;
                digits.clear();
            }
            '0'..='9' => digits.push(ch),
            unit => {
                let value: i64 = digits.parse().ok()?;
                digits.clear();
                let ms = match (unit, in_time) {
                    ('W', false) => value.checked_mul(7 * 24 * 3_600_000)?,
                    ('D', false) => value.checked_mul(24 * 3_600_000)?,
                    ('H', true) => value.checked_mul(3_600_000)?,
                    ('M', true) => value.checked_mul(60_000)?,
                    ('S', true) => value.checked_mul(1_000)?,
                    _ => return None,
                };
                total_ms = total_ms.checked_add(ms)?;
            }
        }
    }
    // Trailing digits with no unit ("PT30") are malformed, not a default.
    digits.is_empty().then_some(sign * total_ms)
}

fn utc_stamp(ms: i64) -> String {
    use chrono::TimeZone;
    chrono::Utc.timestamp_millis_opt(ms).single().map_or_else(
        || "19700101T000000Z".to_owned(),
        |dt| dt.format("%Y%m%dT%H%M%SZ").to_string(),
    )
}

/// Asks the server when `attendees` are busy between `start_ms` and `end_ms`.
///
/// The whole RFC 6638 §4.3 exchange: build the VFREEBUSY REQUEST, POST it to
/// the organizer's own scheduling Outbox, and read one answer per attendee.
/// Requires a server that runs the scheduling engine — `discover_scheduling`
/// returns the outbox URL, and `None` there means this cannot be asked at all
/// rather than that everyone is free.
///
/// An attendee the server would not answer for comes back with its
/// request-status and no periods; see [`Availability::answered`], because
/// "would not say" must not render as "free".
pub fn query_availability(
    client: &crate::dav::CaldavClient,
    outbox_url: &str,
    organizer_email: &str,
    attendee_emails: &[String],
    start_ms: i64,
    end_ms: i64,
) -> Result<Vec<Availability>> {
    let request = build_freebusy_request(organizer_email, attendee_emails, start_ms, end_ms);
    let responses = client.post_scheduling(outbox_url, &request)?;
    Ok(responses
        .into_iter()
        .map(|response| Availability {
            attendee: normalise_email(&response.recipient),
            busy: response
                .calendar_data
                .as_deref()
                .filter(|_| response.succeeded())
                .map(parse_freebusy)
                .unwrap_or_default(),
            request_status: response.request_status,
        })
        .collect())
}

#[cfg(test)]
mod organizer_tests {
    use super::*;

    /// A stored event with the cargo an invitation must not lose: a
    /// VTIMEZONE, a VALARM, and vendor properties nothing here models.
    const STORED: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//cosmic-pim//EN\r\n\
CALSCALE:GREGORIAN\r\n\
BEGIN:VTIMEZONE\r\n\
TZID:Europe/Athens\r\n\
BEGIN:STANDARD\r\n\
DTSTART:19701025T040000\r\n\
TZOFFSETFROM:+0300\r\n\
TZOFFSETTO:+0200\r\n\
END:STANDARD\r\n\
END:VTIMEZONE\r\n\
BEGIN:VEVENT\r\n\
UID:meet-1@example.com\r\n\
SEQUENCE:2\r\n\
DTSTART;TZID=Europe/Athens:20270105T100000\r\n\
DTEND;TZID=Europe/Athens:20270105T110000\r\n\
SUMMARY:Planning\r\n\
ORGANIZER:mailto:me@example.com\r\n\
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:ada@example.com\r\n\
X-VENDOR-THING:keep me\r\n\
BEGIN:VALARM\r\n\
ACTION:DISPLAY\r\n\
DESCRIPTION:Reminder\r\n\
TRIGGER:-PT15M\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    #[test]
    fn an_invitation_is_the_stored_event_plus_one_line() {
        // The entire discipline in one assertion: wrapping and unwrapping
        // must be lossless, so the invitation an attendee receives carries
        // the organizer's own bytes rather than our idea of them.
        let request = with_method(STORED, "REQUEST");
        assert!(request.contains("METHOD:REQUEST\r\n"));
        assert_eq!(strip_method(&request), STORED);
    }

    #[test]
    fn the_method_lands_after_the_preamble_not_inside_a_component() {
        let request = with_method(STORED, "REQUEST");
        let method_at = request.find("METHOD:REQUEST").expect("a METHOD");
        let calscale_at = request.find("CALSCALE:").expect("the preamble");
        let first_component = request.find("BEGIN:VTIMEZONE").expect("a component");
        assert!(
            calscale_at < method_at && method_at < first_component,
            "METHOD landed outside the calendar preamble"
        );
    }

    #[test]
    fn an_existing_method_is_replaced_never_duplicated() {
        // A REQUEST still carrying METHOD:REPLY would be applied backwards by
        // the receiver — it would read our invitation as somebody's answer.
        let reply = with_method(STORED, "REPLY");
        let request = with_method(&reply, "REQUEST");
        assert_eq!(request.matches("METHOD:").count(), 1, "{request}");
        assert!(request.contains("METHOD:REQUEST"));
    }

    #[test]
    fn wrapping_keeps_the_timezone_the_alarm_and_the_vendor_property() {
        let request = with_method(STORED, "REQUEST");
        assert!(request.contains("BEGIN:VTIMEZONE"), "the timezone was lost");
        assert!(request.contains("BEGIN:VALARM"), "the alarm was lost");
        assert!(
            request.contains("X-VENDOR-THING:keep me"),
            "vendor data lost"
        );
        assert!(request.contains("DTSTART;TZID=Europe/Athens:20270105T100000"));
    }

    #[test]
    fn something_that_is_not_a_calendar_comes_back_untouched() {
        // Silently wrapping junk in a VCALENDAR would hide the caller's bug
        // until an attendee's client rejected the result.
        let junk = "not a calendar at all\r\n";
        assert_eq!(with_method(junk, "REQUEST"), junk);
    }

    #[test]
    fn a_bump_raises_every_vevent_together() {
        // A master and its overrides are one scheduling object; bumping only
        // one leaves the series answering at two versions.
        let two_events = STORED.replace(
            "END:VEVENT\r\nEND:VCALENDAR",
            "END:VEVENT\r\n\
             BEGIN:VEVENT\r\n\
             UID:meet-1@example.com\r\n\
             RECURRENCE-ID;TZID=Europe/Athens:20270112T100000\r\n\
             SEQUENCE:5\r\n\
             SUMMARY:Planning (moved)\r\n\
             END:VEVENT\r\n\
             END:VCALENDAR",
        );
        let bumped = bump_sequence(&two_events);
        assert!(bumped.contains("SEQUENCE:3\r\n"), "the master did not move");
        assert!(
            bumped.contains("SEQUENCE:6\r\n"),
            "the override did not move"
        );
        assert_eq!(bumped.matches("SEQUENCE:").count(), 2);
    }

    #[test]
    fn an_event_without_a_sequence_gains_one() {
        // Absent means zero (RFC 5545 §3.8.7.4), so the first bump is 1 — not
        // a no-op, which would leave the change unannounced.
        let no_sequence = STORED.replace("SEQUENCE:2\r\n", "");
        let bumped = bump_sequence(&no_sequence);
        assert!(bumped.contains("SEQUENCE:1\r\n"), "{bumped}");
        // And it goes inside the VEVENT, not after it.
        let seq_at = bumped.find("SEQUENCE:1").expect("a sequence");
        let end_at = bumped.find("END:VEVENT").expect("an end");
        assert!(seq_at < end_at);
    }

    #[test]
    fn a_bump_changes_nothing_but_the_sequence() {
        let bumped = bump_sequence(STORED);
        assert_eq!(
            bumped.replace("SEQUENCE:3", "SEQUENCE:2"),
            STORED,
            "a bump rewrote something other than the sequence"
        );
    }

    #[test]
    fn a_cancel_keeps_the_recurrence_id_that_scopes_it() {
        // The sending half of the classic iTIP data-loss bug: a cancel for
        // one instance must carry its RECURRENCE-ID, or the receiver deletes
        // the whole series.
        let one_instance = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\n\
BEGIN:VEVENT\r\nUID:meet-1@example.com\r\n\
RECURRENCE-ID;TZID=Europe/Athens:20270112T100000\r\n\
SEQUENCE:2\r\nSUMMARY:Planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let cancel = with_method(one_instance, "CANCEL");
        assert!(cancel.contains("METHOD:CANCEL\r\n"));
        assert!(
            cancel.contains("RECURRENCE-ID;TZID=Europe/Athens:20270112T100000\r\n"),
            "the instance scope was lost — this cancels the series"
        );
        // And it parses back as what we meant to send.
        let parsed = parse(&cancel).expect("a cancel");
        assert_eq!(parsed.method, Method::Cancel);
        assert!(parsed.recurrence_id.is_some());
    }
}

#[cfg(test)]
mod freebusy_tests {
    use super::*;

    /// What a server answers for someone with two meetings — the second
    /// written as start/duration, which half of them do.
    const REPLY: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Server//EN\r\n\
METHOD:REPLY\r\n\
BEGIN:VFREEBUSY\r\n\
UID:freebusy-1@example.com\r\n\
DTSTAMP:20270104T080000Z\r\n\
DTSTART:20270104T000000Z\r\n\
DTEND:20270105T000000Z\r\n\
ORGANIZER:mailto:me@example.com\r\n\
ATTENDEE:mailto:ada@example.com\r\n\
FREEBUSY;FBTYPE=BUSY:20270104T090000Z/20270104T100000Z\r\n\
FREEBUSY;FBTYPE=BUSY-TENTATIVE:20270104T140000Z/PT1H30M\r\n\
END:VFREEBUSY\r\n\
END:VCALENDAR\r\n";

    /// Every payload this module hands to a server or a mail client must
    /// survive the one parser this suite has.
    ///
    /// `contains` on text the builder just wrote cannot tell a valid calendar
    /// from a plausible-looking one: it re-asserts the format string. These
    /// builders are hand-rolled — they do not go through `to_ics` — so
    /// nothing else would catch a stray fold, a missing END, or a component
    /// nested wrong, and the failure would surface as a server rejecting an
    /// invitation rather than as a test.
    fn parses_as_a_calendar(ics: &str) -> usize {
        let mut parser = calcard::Parser::new(ics);
        match parser.entry() {
            calcard::Entry::ICalendar(calendar) => calendar.components.len(),
            other => panic!("not a calendar: {other:?}\n{ics}"),
        }
    }

    #[test]
    fn every_built_payload_parses_back() {
        // A free/busy request, as posted to a scheduling outbox.
        let freebusy = build_freebusy_request(
            "me@example.com",
            &["ada@example.com".into()],
            1_767_484_800_000,
            1_767_571_200_000,
        );
        assert!(parses_as_a_calendar(&freebusy) >= 2, "{freebusy}");

        // A reply, as mailed to an organizer — and it must read back as the
        // REPLY it claims to be, not merely as valid text.
        let reply = build_reply(
            &Reply {
                uid: "meet-1@org.example",
                recurrence_id: None,
                sequence: 2,
                organizer_email: "boss@org.example",
                summary: Some("Planning"),
                partstat: "ACCEPTED",
            },
            "me@example.com",
            "Ada Lovelace",
        );
        assert!(parses_as_a_calendar(&reply) >= 2, "{reply}");
        let parsed = parse(&reply).expect("a reply must parse as iTIP");
        assert_eq!(parsed.method, Method::Reply);
        assert_eq!(parsed.uid, "meet-1@org.example");
        assert_eq!(parsed.sequence, 2);
    }

    #[test]
    fn a_request_names_every_attendee_and_bounds_the_window() {
        let ics = build_freebusy_request(
            "me@example.com",
            &["ada@example.com".into(), "babbage@example.com".into()],
            1_767_484_800_000,
            1_767_571_200_000,
        );
        assert!(ics.contains("METHOD:REQUEST\r\n"));
        assert!(ics.contains("BEGIN:VFREEBUSY\r\n"));
        assert!(ics.contains("ORGANIZER:mailto:me@example.com\r\n"));
        assert!(ics.contains("ATTENDEE:mailto:ada@example.com\r\n"));
        assert!(ics.contains("ATTENDEE:mailto:babbage@example.com\r\n"));
        // The window is what the server answers within; without it a server
        // is free to answer for a day or a decade.
        assert!(ics.contains("DTSTART:20260104T000000Z\r\n"), "{ics}");
        assert!(ics.contains("DTEND:20260105T000000Z\r\n"), "{ics}");
    }

    #[test]
    fn an_empty_attendee_is_skipped_rather_than_sent_as_mailto_nothing() {
        let ics = build_freebusy_request(
            "me@example.com",
            &["  ".into(), "ada@example.com".into()],
            0,
            1_000,
        );
        assert!(!ics.contains("ATTENDEE:mailto:\r\n"), "{ics}");
        assert_eq!(ics.matches("ATTENDEE:").count(), 1);
    }

    #[test]
    fn both_period_forms_parse_to_the_same_kind_of_answer() {
        let busy = parse_freebusy(REPLY);
        assert_eq!(busy.len(), 2);
        assert_eq!(busy[0].kind, "BUSY");
        assert_eq!(busy[1].kind, "BUSY-TENTATIVE");
        // start/duration resolves to the same shape as start/end: 14:00 + 1h30.
        assert_eq!(busy[1].end_ms - busy[1].start_ms, 90 * 60 * 1_000);
        assert_eq!(busy[0].end_ms - busy[0].start_ms, 60 * 60 * 1_000);
    }

    #[test]
    fn a_free_period_is_not_recorded_as_busy() {
        // FBTYPE=FREE says the opposite of every other value; treating it as
        // busy would block the exact slots the server offered.
        let ics = REPLY.replace(
            "FREEBUSY;FBTYPE=BUSY:20270104T090000Z/20270104T100000Z",
            "FREEBUSY;FBTYPE=FREE:20270104T090000Z/20270104T100000Z",
        );
        let busy = parse_freebusy(&ics);
        assert_eq!(busy.len(), 1);
        assert_eq!(busy[0].kind, "BUSY-TENTATIVE");
    }

    #[test]
    fn a_property_may_carry_several_periods() {
        let ics = REPLY.replace(
            "FREEBUSY;FBTYPE=BUSY:20270104T090000Z/20270104T100000Z",
            "FREEBUSY:20270104T090000Z/20270104T100000Z,20270104T110000Z/20270104T113000Z",
        );
        let busy = parse_freebusy(&ics);
        assert_eq!(busy.len(), 3);
        // No FBTYPE at all means BUSY (RFC 5545 §3.2.9), not "unknown".
        assert_eq!(busy[0].kind, "BUSY");
        assert_eq!(busy[1].kind, "BUSY");
    }

    #[test]
    fn unparseable_periods_are_dropped_never_guessed() {
        // A skipped block risks a double-booking the user can see; an
        // invented one hides a free slot they cannot. Only one is recoverable.
        let ics = REPLY.replace(
            "FREEBUSY;FBTYPE=BUSY:20270104T090000Z/20270104T100000Z",
            "FREEBUSY:20270104T090000/20270104T100000",
        );
        let busy = parse_freebusy(&ics);
        assert_eq!(busy.len(), 1, "a floating period was accepted: {busy:?}");

        // Backwards periods are refused too — a negative-length busy block
        // renders as an inverted band in any grid that draws it.
        let backwards = REPLY.replace(
            "FREEBUSY;FBTYPE=BUSY:20270104T090000Z/20270104T100000Z",
            "FREEBUSY:20270104T100000Z/20270104T090000Z",
        );
        assert_eq!(parse_freebusy(&backwards).len(), 1);
    }

    #[test]
    fn a_reply_with_no_freebusy_lines_means_free_not_broken() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REPLY\r\n\
                   BEGIN:VFREEBUSY\r\nUID:x@y\r\nDTSTAMP:20270104T080000Z\r\n\
                   ATTENDEE:mailto:ada@example.com\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n";
        assert!(parse_freebusy(ics).is_empty());
    }

    #[test]
    fn durations_cover_the_units_a_period_may_use() {
        assert_eq!(parse_duration_ms("PT30M"), Some(30 * 60 * 1_000));
        assert_eq!(parse_duration_ms("PT1H"), Some(3_600_000));
        assert_eq!(parse_duration_ms("P1D"), Some(86_400_000));
        assert_eq!(parse_duration_ms("P1W"), Some(7 * 86_400_000));
        assert_eq!(parse_duration_ms("PT1H30M"), Some(90 * 60 * 1_000));
        // Minutes and months share the letter M; only the position tells them
        // apart, and a period may not carry months at all.
        assert_eq!(parse_duration_ms("P1M"), None);
        assert_eq!(parse_duration_ms("PT30"), None);
        assert_eq!(parse_duration_ms("30M"), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An invitation the way a real organizer's client writes one.
    fn request(sequence: i64) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Org//EN\r\nMETHOD:REQUEST\r\n\
             BEGIN:VTIMEZONE\r\nTZID:Europe/Athens\r\nBEGIN:STANDARD\r\nDTSTART:19701025T040000\r\n\
             TZOFFSETFROM:+0300\r\nTZOFFSETTO:+0200\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n\
             BEGIN:VEVENT\r\nUID:meet-1@org.example\r\nSEQUENCE:{sequence}\r\n\
             DTSTART;TZID=Europe/Athens:20270105T100000\r\nDTEND;TZID=Europe/Athens:20270105T110000\r\n\
             SUMMARY:Planning\r\nORGANIZER;CN=Boss:mailto:boss@org.example\r\n\
             ATTENDEE;CN=Ada;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:ada@example.com\r\n\
             ATTENDEE;PARTSTAT=ACCEPTED:mailto:boss@org.example\r\n\
             X-MICROSOFT-CDO-BUSYSTATUS:BUSY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    fn cancel(sequence: i64, rid: Option<&str>) -> String {
        let rid_line = rid.map_or(String::new(), |r| {
            format!("RECURRENCE-ID;TZID=Europe/Athens:{r}\r\n")
        });
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:CANCEL\r\n\
             BEGIN:VEVENT\r\nUID:meet-1@org.example\r\nSEQUENCE:{sequence}\r\n{rid_line}\
             ORGANIZER:mailto:boss@org.example\r\n\
             ATTENDEE:mailto:ada@example.com\r\nSTATUS:CANCELLED\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    fn reply(partstat: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REPLY\r\n\
             BEGIN:VEVENT\r\nUID:meet-1@org.example\r\nSEQUENCE:1\r\n\
             ORGANIZER:mailto:boss@org.example\r\n\
             ATTENDEE;PARTSTAT={partstat}:mailto:colleague@example.com\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    #[test]
    fn an_invitation_parses_with_its_people_and_sequence() {
        let itip = parse(&request(3)).expect("an invitation");

        assert_eq!(itip.method, Method::Request);
        assert_eq!(itip.uid, "meet-1@org.example");
        assert_eq!(itip.sequence, 3);
        assert_eq!(itip.summary.as_deref(), Some("Planning"));
        assert_eq!(
            itip.organizer.as_ref().map(|o| o.email.as_str()),
            Some("boss@org.example")
        );
        assert_eq!(itip.attendees.len(), 2);
        assert_eq!(itip.attendees[0].email, "ada@example.com");
        assert_eq!(itip.attendees[0].name.as_deref(), Some("Ada"));
        assert_eq!(itip.attendees[0].partstat.as_deref(), Some("NEEDS-ACTION"));
    }

    #[test]
    fn a_calendar_without_a_method_is_not_an_invitation() {
        let plain = request(0).replace("METHOD:REQUEST\r\n", "");
        assert!(parse(&plain).is_none());
    }

    #[test]
    fn the_attendee_gate_is_exact() {
        // The forwarded-through-a-mailing-list case: subscribers received the
        // mail, but only the named attendee gets the event.
        let itip = parse(&request(0)).expect("an invitation");

        assert!(itip.is_addressed_to("ada@example.com"));
        assert!(
            itip.is_addressed_to("MAILTO:Ada@Example.COM"),
            "normalisation failed"
        );
        assert!(!itip.is_addressed_to("list@example.com"));
        assert!(!itip.is_addressed_to("ada@example.com.attacker.example"));
        assert!(!itip.is_addressed_to(""));
    }

    #[test]
    fn equal_sequence_applies_and_lower_does_not() {
        // RFC 5546 §3.2.2: same-sequence re-sends refresh non-versioned
        // detail. Off-by-one here either drops legitimate updates or applies
        // stale ones.
        let itip = parse(&request(2)).expect("an invitation");
        assert!(itip.supersedes(1));
        assert!(itip.supersedes(2));
        assert!(!itip.supersedes(3));
    }

    #[test]
    fn strip_method_removes_exactly_one_line() {
        let stripped = strip_method(&request(0));

        assert!(!stripped.contains("METHOD:"));
        // Everything else survives byte-for-byte, X- properties included.
        assert!(stripped.contains("X-MICROSOFT-CDO-BUSYSTATUS:BUSY\r\n"));
        assert!(stripped.contains("BEGIN:VTIMEZONE"));
        assert_eq!(
            stripped.len(),
            request(0).len() - "METHOD:REQUEST\r\n".len()
        );
    }

    // ------------------------------------------------------------------
    // Application against a vdir directory
    // ------------------------------------------------------------------

    fn collection() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn an_invitation_never_overwrites_an_event_whose_name_it_collides_with() {
        // The create-at-derived-name verb, in this module. `find_by_uid`
        // answering None means "no file holds this UID" — it does not mean
        // "this file name is free". Two UIDs derive one stem easily enough
        // (`@` cleans to `-`, and any two sharing a 120-character prefix
        // collide on the truncation), and writing the invitation at that name
        // replaced an unrelated event that had nothing to do with the sender.
        let dir = collection();

        // An event already stored under the name `a-x.com.ics`.
        let existing = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Mine//EN\r\n\
BEGIN:VEVENT\r\nUID:a-x.com\r\nDTSTAMP:20260801T000000Z\r\n\
DTSTART:20260804T090000Z\r\nDTEND:20260804T100000Z\r\n\
SUMMARY:My own appointment\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        std::fs::write(dir.path().join("a-x.com.ics"), existing).expect("write");

        // An invitation whose UID cleans to the same stem.
        let invitation = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Org//EN\r\n\
METHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:a@x.com\r\nSEQUENCE:0\r\n\
DTSTAMP:20260801T000000Z\r\nDTSTART:20260805T090000Z\r\nDTEND:20260805T100000Z\r\n\
SUMMARY:Someone else's meeting\r\nORGANIZER:mailto:boss@org.example\r\n\
ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:me@example.com\r\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";

        let outcome = apply(dir.path(), invitation, "me@example.com").expect("apply");
        assert!(matches!(outcome, Outcome::Created { .. }), "{outcome:?}");

        // The appointment that was already there is untouched.
        let mine = std::fs::read_to_string(dir.path().join("a-x.com.ics")).expect("still there");
        assert!(
            mine.contains("SUMMARY:My own appointment"),
            "an invitation overwrote an unrelated event:\n{mine}"
        );
        assert!(mine.contains("UID:a-x.com"));

        // And the invitation landed somewhere of its own.
        let files: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
            .collect();
        assert_eq!(
            files.len(),
            2,
            "the invitation did not get its own file: {files:?}"
        );
        let landed = files
            .iter()
            .find(|name| *name != "a-x.com.ics")
            .expect("a second file");
        let text = std::fs::read_to_string(dir.path().join(landed)).expect("read");
        assert!(text.contains("UID:a@x.com"), "{text}");
        assert!(text.contains("SUMMARY:Someone else's meeting"));
    }

    #[test]
    fn a_request_lands_as_a_file_with_the_organizers_bytes() {
        let dir = collection();

        let outcome = apply(dir.path(), &request(0), "ada@example.com").expect("apply");

        let Outcome::Created { file } = outcome else {
            panic!("expected Created, got {outcome:?}");
        };
        let stored = std::fs::read_to_string(dir.path().join(&file)).expect("read");
        assert!(stored.contains("X-MICROSOFT-CDO-BUSYSTATUS:BUSY"));
        assert!(stored.contains("ATTENDEE;CN=Ada"));
        assert!(
            !stored.contains("METHOD:"),
            "a stored object carrying METHOD is rejected by every CalDAV PUT"
        );
    }

    #[test]
    fn a_forwarded_invitation_is_not_applied() {
        let dir = collection();

        let outcome = apply(dir.path(), &request(0), "bystander@example.com").expect("apply");

        assert_eq!(outcome, Outcome::NotForMe);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "a forwarded invite landed on the wrong calendar"
        );
    }

    #[test]
    fn an_update_replaces_and_a_stale_resend_does_not() {
        let dir = collection();
        apply(dir.path(), &request(1), "ada@example.com").expect("first");

        let newer = request(2).replace("SUMMARY:Planning", "SUMMARY:Planning (moved)");
        let outcome = apply(dir.path(), &newer, "ada@example.com").expect("second");
        assert!(matches!(outcome, Outcome::Updated { .. }));

        // The old sequence arriving late — out-of-order delivery.
        let stale = apply(dir.path(), &request(1), "ada@example.com").expect("third");
        assert_eq!(stale, Outcome::Stale);

        let file = find_by_uid(dir.path(), "meet-1@org.example").expect("file");
        let stored = std::fs::read_to_string(file).expect("read");
        assert!(
            stored.contains("Planning (moved)"),
            "the stale re-send overwrote newer state with older"
        );
    }

    #[test]
    fn a_series_cancel_removes_the_file() {
        let dir = collection();
        apply(dir.path(), &request(1), "ada@example.com").expect("request");

        let outcome = apply(dir.path(), &cancel(2, None), "ada@example.com").expect("cancel");

        assert!(matches!(outcome, Outcome::Cancelled { .. }));
        assert!(find_by_uid(dir.path(), "meet-1@org.example").is_none());
    }

    #[test]
    fn an_instance_cancel_keeps_the_series() {
        // THE bug this module exists to not have: the organizer cancels one
        // Tuesday and the whole weekly series vanishes.
        let dir = collection();
        apply(dir.path(), &request(1), "ada@example.com").expect("request");

        let outcome = apply(
            dir.path(),
            &cancel(2, Some("20270112T100000")),
            "ada@example.com",
        )
        .expect("cancel");

        assert!(matches!(outcome, Outcome::InstanceCancelled { .. }));
        let file = find_by_uid(dir.path(), "meet-1@org.example")
            .expect("the series was deleted by a single-instance cancel");
        let stored = std::fs::read_to_string(file).expect("read");
        assert!(stored.contains("SUMMARY:Planning"), "the master is gone");
        assert!(stored.contains("STATUS:CANCELLED"));
        assert!(stored.contains("RECURRENCE-ID;TZID=Europe/Athens:20270112T100000"));
        assert_eq!(stored.matches("BEGIN:VEVENT").count(), 2);
    }

    #[test]
    fn a_stale_cancel_deletes_nothing() {
        let dir = collection();
        apply(dir.path(), &request(5), "ada@example.com").expect("request");

        let outcome = apply(dir.path(), &cancel(1, None), "ada@example.com").expect("cancel");

        assert_eq!(outcome, Outcome::Stale);
        assert!(
            find_by_uid(dir.path(), "meet-1@org.example").is_some(),
            "a replayed old CANCEL deleted a live series"
        );
    }

    #[test]
    fn a_reply_patches_the_answering_attendee_only() {
        // A REPLY's attendee is the *other* person — the gate must not apply,
        // and only their PARTSTAT moves.
        let with_colleague = request(1).replace(
            "ATTENDEE;PARTSTAT=ACCEPTED:mailto:boss@org.example\r\n",
            "ATTENDEE;PARTSTAT=ACCEPTED:mailto:boss@org.example\r\n\
             ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:colleague@example.com\r\n",
        );
        let dir = collection();
        apply(dir.path(), &with_colleague, "ada@example.com").expect("request");

        let outcome = apply(dir.path(), &reply("DECLINED"), "ada@example.com").expect("reply");

        let Outcome::ReplyApplied { file, updated } = outcome else {
            panic!("expected ReplyApplied, got {outcome:?}");
        };
        assert_eq!(updated, 1);
        let stored = std::fs::read_to_string(dir.path().join(&file)).expect("read");
        assert!(
            stored.contains("PARTSTAT=DECLINED") && stored.contains("colleague@example.com"),
            "the answer did not land: {stored}"
        );
        assert!(
            stored.contains("PARTSTAT=NEEDS-ACTION") && stored.contains("ada@example.com"),
            "someone else's participation moved"
        );
    }

    #[test]
    fn a_reply_for_an_unknown_event_reports_no_match() {
        let dir = collection();
        assert_eq!(
            apply(dir.path(), &reply("ACCEPTED"), "ada@example.com").expect("reply"),
            Outcome::NoMatch
        );
    }

    #[test]
    fn a_publish_is_left_alone() {
        let publish = request(0).replace("METHOD:REQUEST", "METHOD:PUBLISH");
        let dir = collection();
        assert_eq!(
            apply(dir.path(), &publish, "ada@example.com").expect("apply"),
            Outcome::Ignored
        );
    }

    #[test]
    fn the_built_reply_echoes_what_rfc_5546_requires() {
        let text = build_reply(
            &Reply {
                uid: "meet-1@org.example",
                recurrence_id: None,
                sequence: 4,
                organizer_email: "boss@org.example",
                summary: Some("Planning"),
                partstat: "ACCEPTED",
            },
            "ada@example.com",
            "Ada",
        );

        assert!(text.contains("METHOD:REPLY"));
        assert!(text.contains("UID:meet-1@org.example"));
        // The sequence answers the REQUEST's, verbatim — a reply with its own
        // idea of the sequence looks like a counter-proposal.
        assert!(text.contains("SEQUENCE:4"));
        assert!(text.contains("ORGANIZER:mailto:boss@org.example"));
        assert!(text.contains("ATTENDEE;PARTSTAT=ACCEPTED;CN=Ada:mailto:ada@example.com"));
        assert!(text.contains("DTSTAMP:"));
        // And it is parseable by this very module, as the organizer's client
        // will parse it.
        let parsed = parse(&text).expect("the built reply does not parse");
        assert_eq!(parsed.method, Method::Reply);
        assert_eq!(parsed.sequence, 4);
    }

    #[test]
    fn an_instance_reply_carries_its_recurrence_id() {
        let text = build_reply(
            &Reply {
                uid: "meet-1@org.example",
                recurrence_id: Some("20270112T100000;TZID=Europe/Athens"),
                sequence: 0,
                organizer_email: "boss@org.example",
                summary: None,
                partstat: "DECLINED",
            },
            "ada@example.com",
            "",
        );

        assert!(text.contains("RECURRENCE-ID;TZID=Europe/Athens:20270112T100000"));
        let parsed = parse(&text).expect("parse");
        assert_eq!(
            parsed.recurrence_id.as_deref(),
            Some("20270112T100000;TZID=Europe/Athens")
        );
    }
}

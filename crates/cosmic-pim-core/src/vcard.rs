// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The suite's vCard layer: text in, [`Contact`] out, and back.
//!
//! The same calcard parser that reads iCalendar reads vCard, which is most of
//! why contacts were a module rather than a project. The escaping and folding
//! rules are shared with [`crate::ical`] too — RFC 6350 §3.2 and RFC 5545 §3.1
//! specify the same line folding, and the same four TEXT escapes.
//!
//! # Round-trip fidelity
//!
//! [`to_vcard`] serialises the fields [`Contact`] models, which is roughly a
//! third of what a real vCard carries. That is fine for a contact this app
//! created and **lossy** for one that came from a server, which is why
//! [`Contact::raw`] exists and why the CardDAV store keeps the server's bytes
//! rather than a re-serialisation. Editing a synced contact goes through
//! [`patch_vcard`], which rewrites only the modelled properties and passes
//! every other byte through.

use calcard::Parser;
use calcard::vcard::{
    VCard, VCardEntry, VCardKind, VCardParameterName, VCardProperty, VCardValue, VCardVersion,
};
use chrono::NaiveDate;

use crate::ical::{escape_text, fold_line};
use crate::model::{Address, Contact, StructuredName, Typed};

/// Parses the vCards out of one document.
///
/// A `.vcf` may hold several cards back to back, which is how exports and some
/// servers deliver them. Never fails: unparseable input yields an empty vec.
#[must_use]
pub fn parse_vcards(text: &str, addressbook_id: &str, file_name: &str) -> Vec<Contact> {
    let mut parser = Parser::new(text);
    let mut out = Vec::new();

    loop {
        match parser.entry() {
            calcard::Entry::VCard(card) => {
                out.push(convert(&card, text, addressbook_id, file_name));
            }
            calcard::Entry::Eof => break,
            calcard::Entry::InvalidLine(line) => {
                tracing::debug!(file_name, line, "calcard dropped an invalid vCard line");
            }
            _ => {}
        }
    }
    out
}

fn convert(card: &VCard, raw: &str, addressbook_id: &str, file_name: &str) -> Contact {
    let (birthday, birthday_month_day) = birthday(card);
    Contact {
        uid: card
            .uid()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("{}@cosmic-pim", uuid::Uuid::new_v4())),
        addressbook_id: addressbook_id.to_owned(),
        display_name: text_of(card, &VCardProperty::Fn).unwrap_or_default(),
        name: structured_name(card),
        nicknames: list_of(card, &VCardProperty::Nickname),
        emails: typed_list(card, &VCardProperty::Email),
        phones: typed_list(card, &VCardProperty::Tel),
        addresses: addresses(card),
        organisation: text_of(card, &VCardProperty::Org),
        title: text_of(card, &VCardProperty::Title),
        note: text_of(card, &VCardProperty::Note),
        birthday,
        birthday_month_day,
        urls: typed_list(card, &VCardProperty::Url),
        categories: list_of(card, &VCardProperty::Categories),
        is_group: is_group(card),
        members: members(card),
        rev: card
            .property(&VCardProperty::Rev)
            .and_then(|e| e.values.first())
            .and_then(|v| match v {
                VCardValue::PartialDateTime(dt) => dt.to_timestamp(),
                _ => None,
            })
            .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0)),
        has_photo: card.property(&VCardProperty::Photo).is_some(),
        raw: raw.to_owned(),
        file_name: file_name.to_owned(),
    }
}

fn text_of(card: &VCard, prop: &VCardProperty) -> Option<String> {
    card.property(prop)
        .and_then(|entry| entry.values.first())
        .and_then(VCardValue::as_text)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// A property whose value is a comma-separated list, and which may repeat.
fn list_of(card: &VCard, prop: &VCardProperty) -> Vec<String> {
    let mut out = Vec::new();
    for entry in card.properties(prop) {
        for value in &entry.values {
            match value {
                // calcard already splits a structured value for us.
                VCardValue::Component(parts) => out.extend(
                    parts
                        .iter()
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty()),
                ),
                other => {
                    if let Some(text) = other.as_text() {
                        out.extend(
                            text.split(',')
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(ToOwned::to_owned),
                        );
                    }
                }
            }
        }
    }
    out.dedup();
    out
}

/// The `TYPE` parameters of an entry, lowercased.
fn types_of(entry: &VCardEntry) -> Vec<String> {
    entry
        .parameters(&VCardParameterName::Type)
        .filter_map(calcard::vcard::VCardParameterValue::as_text)
        .flat_map(|t| {
            // A single TYPE parameter may carry a comma-separated list.
            t.split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn pref_of(entry: &VCardEntry) -> Option<u8> {
    entry
        .parameters(&VCardParameterName::Pref)
        .find_map(|value| match value {
            calcard::vcard::VCardParameterValue::Integer(n) => u8::try_from(*n).ok(),
            other => other.as_text().and_then(|t| t.trim().parse().ok()),
        })
}

fn typed_list(card: &VCard, prop: &VCardProperty) -> Vec<Typed> {
    card.properties(prop)
        .filter_map(|entry| {
            let value = entry
                .values
                .first()
                .and_then(VCardValue::as_text)
                .map(str::trim)
                .filter(|s| !s.is_empty())?;

            // vCard 3.0 has no PREF parameter — it spells preference as
            // `TYPE=PREF` (RFC 2426 §3.3). Fold that spelling into the same
            // model field, and keep it out of `types` so the UI does not show
            // a label reading "pref" next to a home number.
            let mut types = types_of(entry);
            let mut pref = pref_of(entry);
            if let Some(index) = types.iter().position(|t| t == "pref") {
                types.remove(index);
                pref = pref.or(Some(1));
            }

            Some(Typed {
                value: value.to_owned(),
                types,
                pref,
                group: entry.group.clone(),
            })
        })
        .collect()
}

/// `N` is five semicolon-separated components (RFC 6350 §6.2.2).
fn structured_name(card: &VCard) -> StructuredName {
    let Some(entry) = card.property(&VCardProperty::N) else {
        return StructuredName::default();
    };

    let parts: Vec<String> = match entry.values.first() {
        Some(VCardValue::Component(parts)) => parts.clone(),
        _ => entry
            .values
            .iter()
            .map(|v| v.as_text().unwrap_or_default().to_owned())
            .collect(),
    };
    let at = |i: usize| {
        parts
            .get(i)
            .map(|s| s.trim().to_owned())
            .unwrap_or_default()
    };

    StructuredName {
        family: at(0),
        given: at(1),
        additional: at(2),
        prefix: at(3),
        suffix: at(4),
    }
}

/// `ADR` is seven semicolon-separated components (RFC 6350 §6.3.1).
fn addresses(card: &VCard) -> Vec<Address> {
    card.properties(&VCardProperty::Adr)
        .map(|entry| {
            let parts: Vec<String> = match entry.values.first() {
                Some(VCardValue::Component(parts)) => parts.clone(),
                _ => entry
                    .values
                    .iter()
                    .map(|v| v.as_text().unwrap_or_default().to_owned())
                    .collect(),
            };
            let at = |i: usize| {
                parts
                    .get(i)
                    .map(|s| s.trim().to_owned())
                    .unwrap_or_default()
            };

            Address {
                po_box: at(0),
                extended: at(1),
                street: at(2),
                locality: at(3),
                region: at(4),
                postal_code: at(5),
                country: at(6),
                types: types_of(entry),
            }
        })
        // Servers do emit entirely blank ADR lines; showing an empty address
        // block for them is worse than dropping them.
        .filter(|a| !a.is_empty())
        .collect()
}

/// `BDAY`: a full date where the card gives one, a bare `(month, day)` where
/// it legally omits the year (`--0415`), free text dropped.
///
/// The two halves are mutually exclusive: inventing a year for a year-less
/// birthday would put the anniversary on the wrong date in every year but the
/// invented one, so a year-less `BDAY` never becomes a `NaiveDate` — it feeds
/// the birthday stream ageless instead.
fn birthday(card: &VCard) -> (Option<NaiveDate>, Option<(u32, u32)>) {
    let Some(entry) = card.property(&VCardProperty::Bday) else {
        return (None, None);
    };
    let Some(VCardValue::PartialDateTime(dt)) = entry.values.first() else {
        return (None, None);
    };
    let (Some(month), Some(day)) = (dt.month, dt.day) else {
        return (None, None);
    };
    match dt.year {
        Some(year) => (
            NaiveDate::from_ymd_opt(i32::from(year), u32::from(month), u32::from(day)),
            None,
        ),
        // Validate through a leap year so `--0229` survives.
        None => (
            None,
            NaiveDate::from_ymd_opt(2000, u32::from(month), u32::from(day))
                .map(|_| (u32::from(month), u32::from(day))),
        ),
    }
}

/// Whether a card is a group, in either spelling.
///
/// vCard 4.0 says `KIND:group` (RFC 6350 §6.1.4). Apple — and therefore most
/// CardDAV servers holding cards Apple clients wrote — says
/// `X-ADDRESSBOOKSERVER-KIND:group` on 3.0 cards, where KIND does not exist.
/// Both mean the same thing, and a client that reads only one of them shows
/// half the user's groups.
fn is_group(card: &VCard) -> bool {
    if let Some(entry) = card.property(&VCardProperty::Kind)
        && entry
            .values
            .iter()
            .any(|v| matches!(v, VCardValue::Kind(VCardKind::Group)))
    {
        return true;
    }
    card.property(&VCardProperty::Other("X-ADDRESSBOOKSERVER-KIND".to_owned()))
        .and_then(|e| e.values.first())
        .and_then(VCardValue::as_text)
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("group"))
}

/// A group card's member URIs, verbatim, in either spelling.
fn members(card: &VCard) -> Vec<String> {
    let mut out: Vec<String> = card
        .properties(&VCardProperty::Member)
        .filter_map(|e| e.values.first())
        .filter_map(VCardValue::as_text)
        .map(|s| s.trim().to_owned())
        .collect();
    out.extend(
        card.properties(&VCardProperty::Other(
            "X-ADDRESSBOOKSERVER-MEMBER".to_owned(),
        ))
        .filter_map(|e| e.values.first())
        .filter_map(VCardValue::as_text)
        .map(|s| s.trim().to_owned()),
    );
    out
}

/// The UID a member URI names: `urn:uuid:abc` → `abc`, a bare value stays
/// itself. `mailto:` members name an address rather than a card and yield
/// `None` — matching them to a contact is an application decision.
#[must_use]
pub fn member_uid(uri: &str) -> Option<&str> {
    let trimmed = uri.trim();
    if let Some(uid) = trimmed
        .strip_prefix("urn:uuid:")
        .or_else(|| trimmed.strip_prefix("URN:UUID:"))
    {
        return Some(uid);
    }
    if trimmed.contains(':') {
        // Some other URI scheme — not a card reference we can resolve.
        return None;
    }
    Some(trimmed)
}

/// The member URI for a contact's UID, in the form servers write.
#[must_use]
pub fn member_uri(uid: &str) -> String {
    format!("urn:uuid:{uid}")
}

/// Rewrites a group card's member list, leaving every other byte alone.
///
/// Existing member lines are replaced wholesale by `members` (verbatim URIs —
/// pass through what was parsed, plus [`member_uri`] forms for additions), in
/// **the spelling the card already uses**: a card carrying
/// `X-ADDRESSBOOKSERVER-MEMBER` keeps that spelling, a 4.0 card gets `MEMBER`.
/// Writing RFC 6350 `MEMBER` into an Apple-style 3.0 group is the data-loss
/// site 03 warns about — Apple clients ignore it and the membership diverges.
///
/// The card patched is the one carrying `uid`, not simply the first: a `.vcf`
/// may hold many, and each `Contact` parsed from such a file carries the whole
/// file as its `raw`. A single-card document is patched whatever its UID says.
///
/// Returns `None` if `raw` contains no VCARD, or holds several and none of
/// them is this one.
#[must_use]
pub fn set_members(raw: &str, uid: &str, members: &[String]) -> Option<String> {
    use crate::patch::{Edit, patch_nth_component};
    use std::collections::BTreeMap;

    // The card's own spelling wins; only a card with no member lines at all
    // falls back to its version's native form.
    let apple_spelling = raw
        .to_ascii_uppercase()
        .contains("X-ADDRESSBOOKSERVER-MEMBER")
        || (!raw.to_ascii_uppercase().contains("\nMEMBER")
            && version_of_card(raw, uid) == WriteVersion::V3);

    let property = if apple_spelling {
        "X-ADDRESSBOOKSERVER-MEMBER"
    } else {
        "MEMBER"
    };

    let mut edits: BTreeMap<String, Edit> = BTreeMap::new();
    let lines: Vec<String> = members
        .iter()
        .map(|uri| format!("{property}:{uri}"))
        .collect();
    edits.insert(property.to_owned(), Edit::set(lines));
    // Clear the other spelling too, or a rename from one client and a member
    // change from another leaves both lists on the card, disagreeing.
    let other = if apple_spelling {
        "MEMBER"
    } else {
        "X-ADDRESSBOOKSERVER-MEMBER"
    };
    edits.insert(other.to_owned(), Edit::remove());

    patch_nth_component(raw, "VCARD", vcard_index_of(raw, uid)?, &edits)
}

/// Serialises a brand-new group card.
///
/// 4.0 gets `KIND:group`; 3.0 gets `X-ADDRESSBOOKSERVER-KIND:group`, the
/// spelling Apple defined and 3.0-first servers expect — RFC 2426 has no KIND.
#[must_use]
pub fn group_vcard(name: &str, uid: &str, version: WriteVersion) -> String {
    let mut out = String::new();
    fold_line("BEGIN:VCARD", &mut out);
    match version {
        WriteVersion::V3 => {
            fold_line("VERSION:3.0", &mut out);
            fold_line("X-ADDRESSBOOKSERVER-KIND:group", &mut out);
        }
        WriteVersion::V4 => {
            fold_line("VERSION:4.0", &mut out);
            fold_line("KIND:group", &mut out);
        }
    }
    fold_line(&format!("UID:{}", escape_text(uid)), &mut out);
    fold_line(&format!("FN:{}", escape_text(name)), &mut out);
    // Apple's own group cards carry N as well; harmless on 4.0.
    fold_line(&format!("N:{};;;;", escape_text(name)), &mut out);
    fold_line(
        &format!("REV:{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ")),
        &mut out,
    );
    fold_line("END:VCARD", &mut out);
    out
}

/// Splits a document into one verbatim text segment per card.
///
/// [`parse_vcards`] hands every contact the *whole* file as its `raw`, which is
/// right for a vdir (one card per file) and wrong for an import: writing each
/// contact of a ten-card export would put all ten cards into every target file.
/// This recovers the per-card bytes so an import can stay lossless. vCards
/// cannot nest, so a line scan is exact.
#[must_use]
pub fn split_vcards(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;

    // Physical lines, terminators preserved: the segment must be byte-faithful,
    // and folding never splits a BEGIN/END line in practice (they are short).
    let mut rest = text;
    while !rest.is_empty() {
        let end = rest.find('\n').map_or(rest.len(), |i| i + 1);
        let (line, tail) = rest.split_at(end);
        rest = tail;

        let upper = line.trim().to_ascii_uppercase();
        if upper == "BEGIN:VCARD" {
            current = Some(String::new());
        }
        if let Some(segment) = current.as_mut() {
            segment.push_str(line);
        }
        if upper == "END:VCARD"
            && let Some(segment) = current.take()
        {
            out.push(segment);
        }
    }
    out
}

/* ------------------------------------------------------------------ */
/* Photos                                                             */

/// A contact's photo, as the card carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Photo {
    /// Inline image bytes (vCard 3.0 `ENCODING=b`, or a 4.0 `data:` URI —
    /// calcard decodes both), with the content type when the card names one.
    Bytes {
        data: Vec<u8>,
        content_type: Option<String>,
    },
    /// A remote or file URI. Deliberately not fetched here: whether to touch
    /// the network for an avatar is an application policy (and default-off in
    /// every app in this suite), not a parsing decision.
    Uri(String),
}

/// An image format, identified from the bytes themselves.
///
/// Recognised by magic number rather than taken from the card's declared
/// content type, because the declared type is routinely absent, routinely
/// wrong, and — the case that matters — stated just as confidently by a payload
/// that is truncated or is not an image at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Png,
    Jpeg,
    Gif,
    WebP,
    Bmp,
    Tiff,
    Svg,
}

impl ImageFormat {
    /// The format `data` actually begins with, or `None` if it is not one we
    /// recognise.
    #[must_use]
    pub fn sniff(data: &[u8]) -> Option<Self> {
        const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";

        if data.starts_with(PNG) {
            return Some(Self::Png);
        }
        // JPEG: SOI marker, then any APPn/marker byte.
        if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Some(Self::Jpeg);
        }
        if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
            return Some(Self::Gif);
        }
        // RIFF container whose form type is WEBP.
        if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
            return Some(Self::WebP);
        }
        if data.starts_with(b"BM") {
            return Some(Self::Bmp);
        }
        if data.starts_with(&[0x49, 0x49, 0x2A, 0x00])
            || data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])
        {
            return Some(Self::Tiff);
        }
        // SVG is text, so look past any leading whitespace or XML declaration.
        let head = data.get(..256).unwrap_or(data);
        if let Ok(text) = std::str::from_utf8(head) {
            let trimmed = text.trim_start();
            if trimmed.starts_with("<svg") || trimmed.starts_with("<?xml") && text.contains("<svg")
            {
                return Some(Self::Svg);
            }
        }
        None
    }
}

impl Photo {
    /// The format the inline bytes actually are, if this is an inline photo at
    /// all and the bytes are a recognised image.
    #[must_use]
    pub fn detected_format(&self) -> Option<ImageFormat> {
        match self {
            Self::Bytes { data, .. } => ImageFormat::sniff(data),
            Self::Uri(_) => None,
        }
    }

    /// Whether these bytes stand a chance of rendering.
    ///
    /// **Check this before handing the bytes to a toolkit's image widget.**
    /// Iced accepts any byte string and only discovers it cannot decode at
    /// draw time, at which point it renders *nothing* — so a contact whose card
    /// carries a truncated or bogus PHOTO becomes an invisible hole in the list
    /// rather than falling back to generated initials. Real address books
    /// contain such cards: exporters truncate, and `X-ABCROP-RECTANGLE` entries
    /// carry parameters where an image is expected.
    #[must_use]
    pub fn is_renderable(&self) -> bool {
        self.detected_format().is_some()
    }
}

/// Extracts the photo from a stored card, decoding inline forms to bytes.
///
/// Separate from [`parse_vcards`] on purpose: a photo can be hundreds of
/// kilobytes, and the contact list would otherwise pull every one of them into
/// memory to render rows that show no image at all. [`Contact::has_photo`] says
/// whether calling this is worth it; this does the actual work, once, for the
/// card on screen.
#[must_use]
pub fn photo(raw: &str) -> Option<Photo> {
    let mut parser = Parser::new(raw);
    let card = loop {
        match parser.entry() {
            calcard::Entry::VCard(card) => break card,
            calcard::Entry::Eof => return None,
            _ => {}
        }
    };

    let entry = card.property(&VCardProperty::Photo)?;
    match entry.values.first()? {
        VCardValue::Binary(data) => Some(Photo::Bytes {
            data: data.data.clone(),
            content_type: data.content_type.clone(),
        }),
        // calcard decodes a 3.0 `ENCODING=b` payload but still delivers it as
        // `Text` — of the *decoded* bytes. A URI is the only text form the RFCs
        // allow here, so anything without a scheme is that decoded payload.
        VCardValue::Text(text) if !text.trim().is_empty() => {
            let trimmed = text.trim();
            if looks_like_uri(trimmed) {
                Some(Photo::Uri(trimmed.to_owned()))
            } else {
                Some(Photo::Bytes {
                    // The bytes went through a &str, so this is only exact for
                    // payloads that happened to be valid UTF-8 — real JPEG and
                    // PNG data is not. Prefer the Binary arm above, which 4.0
                    // data: URIs take; this is the best that can be done with
                    // what the parser kept.
                    data: text.as_bytes().to_vec(),
                    content_type: None,
                })
            }
        }
        _ => None,
    }
}

/// Whether a PHOTO text value is a URI rather than a decoded inline payload:
/// an RFC 3986 scheme followed by `:`.
fn looks_like_uri(s: &str) -> bool {
    let Some(colon) = s.find(':') else {
        return false;
    };
    let scheme = &s[..colon];
    !scheme.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Replaces (or sets) a card's photo, in the card's own dialect, leaving every
/// other byte alone.
///
/// - 4.0 cards get `PHOTO:data:<mime>;base64,…` (RFC 6350 §6.2.4 via RFC 2397).
/// - 3.0 cards get `PHOTO;ENCODING=b;TYPE=<subtype>:…` (RFC 2426 §3.1.4).
///
/// The card patched is the one carrying `uid`, not simply the first: a `.vcf`
/// may hold many, and each `Contact` parsed from such a file carries the whole
/// file as its `raw`. A single-card document is patched whatever its UID says.
///
/// Returns `None` if `raw` contains no VCARD, or holds several and none of
/// them is this one.
#[must_use]
pub fn set_photo(raw: &str, uid: &str, data: &[u8], mime: &str) -> Option<String> {
    use crate::patch::{Edit, patch_nth_component};
    use base64::Engine as _;
    use std::collections::BTreeMap;

    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    let line = match version_of_card(raw, uid) {
        WriteVersion::V4 => format!("PHOTO:data:{mime};base64,{encoded}"),
        WriteVersion::V3 => {
            // 3.0's TYPE names the image subtype, uppercased by convention:
            // TYPE=JPEG, not TYPE=image/jpeg.
            let subtype = mime
                .rsplit('/')
                .next()
                .unwrap_or("JPEG")
                .to_ascii_uppercase();
            format!("PHOTO;ENCODING=b;TYPE={subtype}:{encoded}")
        }
    };

    let mut edits = BTreeMap::new();
    edits.insert("PHOTO".to_owned(), Edit::set(vec![line]));
    patch_nth_component(raw, "VCARD", vcard_index_of(raw, uid)?, &edits)
}

/// Removes a card's photo, leaving every other byte alone.
///
/// The card patched is the one carrying `uid`, not simply the first: a `.vcf`
/// may hold many, and each `Contact` parsed from such a file carries the whole
/// file as its `raw`. A single-card document is patched whatever its UID says.
///
/// Returns `None` if `raw` contains no VCARD, or holds several and none of
/// them is this one.
#[must_use]
pub fn remove_photo(raw: &str, uid: &str) -> Option<String> {
    use crate::patch::{Edit, patch_nth_component};
    use std::collections::BTreeMap;

    let mut edits = BTreeMap::new();
    edits.insert("PHOTO".to_owned(), Edit::remove());
    patch_nth_component(raw, "VCARD", vcard_index_of(raw, uid)?, &edits)
}

/* ------------------------------------------------------------------ */
/* Patching an existing card                                          */

/// Rewrites `original` so it carries `contact`'s modelled fields, leaving
/// everything else byte-for-byte.
///
/// **This is the function to save a synced contact with.** [`to_vcard`] builds
/// a card from scratch and therefore drops PHOTO, GEO, IMPP, `X-` properties,
/// and anything else this crate does not model — fine for a card this app
/// created, silent data loss for one that came from a server.
///
/// Grouped lines (`item1.EMAIL` and its `item1.X-ABLabel`) are preserved
/// untouched, so Apple-style custom labels survive. That also means an edit to
/// `contact.emails` does not reach them; see [`crate::patch`] for why, and for
/// how to address one deliberately.
///
/// The card patched is the one whose `UID` matches `contact`, not simply the
/// first. A `.vcf` may hold many cards — every export from Google, Apple and
/// Outlook is one file containing all of them — and `parse_vcards` gives each
/// resulting `Contact` the *whole file* as its `raw`. Patching index 0
/// regardless therefore wrote the second contact's name, email and address
/// over the first contact's card while leaving the first card's UID in place:
/// one person's record wearing another person's details, and the edit never
/// reaching the person who made it.
///
/// A single-card document is patched whatever its UID says, since there is
/// nothing it could be confused with.
///
/// Returns `None` if `original` contains no VCARD, or holds several and none
/// of them is this contact — in which case the caller must not fall back to
/// serialising, because that would write one card over all of them.
#[must_use]
pub fn patch_vcard(original: &str, contact: &Contact) -> Option<String> {
    use crate::patch::Edit;
    use std::collections::BTreeMap;

    let mut edits: BTreeMap<String, Edit> = BTreeMap::new();

    // Rewritten lines must speak the card's own dialect: `PREF=1` written into
    // a 3.0 card is quiet non-conformance a strict server strips, and the
    // preference is then lost remotely. The version comes from the card, not
    // from a caller preference — a patch never converts.
    let version = version_of_card(original, &contact.uid);

    let set = |edits: &mut BTreeMap<String, Edit>, name: &str, lines: Vec<String>| {
        edits.insert(name.to_owned(), Edit::set(lines));
    };

    /// Splits a typed list into the ungrouped lines to write and the grouped
    /// values to edit in place.
    ///
    /// Without this split, an entry parsed from `item1.EMAIL` would be written
    /// back as a plain `EMAIL` line *in addition to* the untouched grouped one
    /// — the contact would gain a duplicate address on every save.
    fn split_typed(name: &str, values: &[Typed], version: WriteVersion) -> Edit {
        let mut edit = Edit::set(
            values
                .iter()
                .filter(|v| !v.is_grouped())
                .map(|v| typed_line_versioned(name, v, version))
                .collect(),
        );
        for value in values.iter().filter(|v| v.is_grouped()) {
            if let Some(group) = &value.group {
                edit = edit.with_group(group.clone(), escape_text(&value.value));
            }
        }
        edit
    }

    // FN is REQUIRED (RFC 6350 §6.2.1), so it is set rather than removable.
    edits.insert(
        "FN".to_owned(),
        Edit::set(vec![format!("FN:{}", escape_text(&contact.label()))]),
    );

    if contact.name.is_empty() {
        edits.insert("N".to_owned(), Edit::remove());
    } else {
        set(
            &mut edits,
            "N",
            vec![format!(
                "N:{};{};{};{};{}",
                escape_text(&contact.name.family),
                escape_text(&contact.name.given),
                escape_text(&contact.name.additional),
                escape_text(&contact.name.prefix),
                escape_text(&contact.name.suffix),
            )],
        );
    }

    set(
        &mut edits,
        "NICKNAME",
        contact
            .nicknames
            .iter()
            .map(|n| format!("NICKNAME:{}", escape_text(n)))
            .collect(),
    );
    edits.insert(
        "EMAIL".to_owned(),
        split_typed("EMAIL", &contact.emails, version),
    );
    edits.insert(
        "TEL".to_owned(),
        split_typed("TEL", &contact.phones, version),
    );
    edits.insert("URL".to_owned(), split_typed("URL", &contact.urls, version));
    set(
        &mut edits,
        "ADR",
        contact.addresses.iter().map(address_line).collect(),
    );

    set(
        &mut edits,
        "ORG",
        contact
            .organisation
            .iter()
            .map(|o| format!("ORG:{}", escape_text(o)))
            .collect(),
    );
    set(
        &mut edits,
        "TITLE",
        contact
            .title
            .iter()
            .map(|t| format!("TITLE:{}", escape_text(t)))
            .collect(),
    );
    set(
        &mut edits,
        "NOTE",
        contact
            .note
            .iter()
            .map(|n| format!("NOTE:{}", escape_text(n)))
            .collect(),
    );
    set(
        &mut edits,
        "BDAY",
        contact
            .birthday
            .iter()
            .map(|b| match version {
                WriteVersion::V3 => format!("BDAY:{}", b.format("%Y-%m-%d")),
                WriteVersion::V4 => format!("BDAY:{}", b.format("%Y%m%d")),
            })
            .collect(),
    );

    set(
        &mut edits,
        "CATEGORIES",
        if contact.categories.is_empty() {
            Vec::new()
        } else {
            vec![format!(
                "CATEGORIES:{}",
                contact
                    .categories
                    .iter()
                    .map(|c| escape_text(c))
                    .collect::<Vec<_>>()
                    .join(",")
            )]
        },
    );

    // REV records when we last touched the card; servers and other clients use
    // it to break ties.
    edits.insert(
        "REV".to_owned(),
        Edit::set(vec![format!(
            "REV:{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
        )]),
    );

    match vcard_index_of(original, &contact.uid) {
        Some(index) => crate::patch::patch_nth_component(original, "VCARD", index, &edits),
        None => None,
    }
}

/// The version declared by the card carrying `uid`, rather than by whichever
/// card happens to come first in the document.
///
/// The distinction only exists for a multi-card file, and only bites when the
/// cards disagree — an export that concatenates a 4.0 card and a 3.0 one. The
/// dialect has to follow the card being written or a patch converts it by
/// accident, which is the one thing the patcher promises never to do.
///
/// Falls back to the document's own answer when the card cannot be located,
/// which is the single-card case and the pre-existing behaviour.
#[must_use]
pub fn version_of_card(raw: &str, uid: &str) -> WriteVersion {
    vcard_index_of(raw, uid)
        .and_then(|index| split_vcards(raw).into_iter().nth(index))
        .map_or_else(|| declared_version(raw), |card| declared_version(&card))
}

/// Which VCARD in `text` carries `uid`, in document order.
///
/// `Some(0)` for a single-card document whatever its UID, because a lone card
/// is unambiguous and a great many of them carry no UID at all.
#[must_use]
pub fn vcard_index_of(text: &str, uid: &str) -> Option<usize> {
    let mut uids: Vec<Option<String>> = Vec::new();
    let mut inside = false;
    let mut nested = 0usize;
    let mut current: Option<String> = None;

    for line in crate::patch::logical_lines(text) {
        if let Some(component) = line.begins() {
            if inside {
                nested += 1;
            } else if component.eq_ignore_ascii_case("VCARD") {
                inside = true;
                current = None;
            }
            continue;
        }
        if line.ends().is_some() {
            if nested > 0 {
                nested -= 1;
            } else if inside {
                uids.push(current.take());
                inside = false;
            }
            continue;
        }
        if inside && nested == 0 && line.name() == "UID" {
            current = Some(line.value().trim().to_owned());
        }
    }

    match uids.len() {
        0 => None,
        1 => Some(0),
        _ => uids
            .iter()
            .position(|candidate| candidate.as_deref() == Some(uid)),
    }
}

fn address_line(address: &Address) -> String {
    let params = if address.types.is_empty() {
        String::new()
    } else {
        format!(";TYPE={}", address.types.join(","))
    };
    format!(
        "ADR{params}:{};{};{};{};{};{};{}",
        escape_text(&address.po_box),
        escape_text(&address.extended),
        escape_text(&address.street),
        escape_text(&address.locality),
        escape_text(&address.region),
        escape_text(&address.postal_code),
        escape_text(&address.country),
    )
}

/* ------------------------------------------------------------------ */
/* Serialisation                                                      */

/// Which vCard version [`to_vcard_versioned`] writes.
///
/// The suite's default for **new** cards is 3.0: Nextcloud, Radicale, and most
/// CardDAV servers are 3.0-first, and a 4.0 card handed to a 3.0-only peer is
/// the interop failure users actually hit. 4.0 is the explicit choice, never a
/// silent conversion — an existing card keeps whatever version its bytes carry,
/// because editing goes through the patcher, not through this writer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WriteVersion {
    #[default]
    V3,
    V4,
}

/// The version a stored card declares, for writing patched lines in its own
/// dialect. An absent or unrecognised `VERSION` reads as 3.0 — the permissive
/// reading, since 4.0-only syntax in a card that never claimed 4.0 is the
/// riskier guess.
#[must_use]
pub fn declared_version(raw: &str) -> WriteVersion {
    for line in crate::patch::logical_lines(raw) {
        if line.name() == "VERSION" {
            return if line.value().trim() == "4.0" {
                WriteVersion::V4
            } else {
                WriteVersion::V3
            };
        }
    }
    WriteVersion::V3
}

/// Serialises a contact as a vCard 4.0 document.
///
/// Lossy for anything this crate does not model — see the module docs. Use it
/// for contacts the app created, not to rewrite one that came from a server.
#[must_use]
pub fn to_vcard(contact: &Contact) -> String {
    to_vcard_versioned(contact, WriteVersion::V4)
}

/// Serialises a contact in the requested version.
///
/// The differences that matter for the fields this crate models:
/// - `VERSION` line, obviously.
/// - **Preference**: 4.0 writes `PREF=1`; 3.0 has no PREF parameter and spells
///   it `TYPE=PREF` (RFC 2426 §3.3). Writing `PREF=1` into a 3.0 card is the
///   kind of quiet non-conformance that works until a strict server strips it.
/// - **BDAY**: 4.0 uses the basic form (`18151210`), 3.0 the extended
///   (`1815-12-10`) — RFC 2426 shows only the extended form.
#[must_use]
pub fn to_vcard_versioned(contact: &Contact, version: WriteVersion) -> String {
    let mut out = String::new();
    fold_line("BEGIN:VCARD", &mut out);
    fold_line(
        match version {
            WriteVersion::V3 => "VERSION:3.0",
            WriteVersion::V4 => "VERSION:4.0",
        },
        &mut out,
    );
    fold_line(&format!("UID:{}", escape_text(&contact.uid)), &mut out);

    // FN is REQUIRED by RFC 6350 §6.2.1 — a card without one is rejected by
    // strict servers, so it is derived rather than omitted when empty.
    fold_line(&format!("FN:{}", escape_text(&contact.label())), &mut out);

    if !contact.name.is_empty() {
        fold_line(
            &format!(
                "N:{};{};{};{};{}",
                escape_text(&contact.name.family),
                escape_text(&contact.name.given),
                escape_text(&contact.name.additional),
                escape_text(&contact.name.prefix),
                escape_text(&contact.name.suffix),
            ),
            &mut out,
        );
    }

    for nickname in &contact.nicknames {
        fold_line(&format!("NICKNAME:{}", escape_text(nickname)), &mut out);
    }
    for email in &contact.emails {
        fold_line(&typed_line_versioned("EMAIL", email, version), &mut out);
    }
    for phone in &contact.phones {
        fold_line(&typed_line_versioned("TEL", phone, version), &mut out);
    }
    for url in &contact.urls {
        fold_line(&typed_line_versioned("URL", url, version), &mut out);
    }

    for address in &contact.addresses {
        fold_line(&address_line(address), &mut out);
    }

    if let Some(org) = &contact.organisation {
        fold_line(&format!("ORG:{}", escape_text(org)), &mut out);
    }
    if let Some(title) = &contact.title {
        fold_line(&format!("TITLE:{}", escape_text(title)), &mut out);
    }
    if let Some(note) = &contact.note {
        fold_line(&format!("NOTE:{}", escape_text(note)), &mut out);
    }
    if let Some(birthday) = contact.birthday {
        let formatted = match version {
            WriteVersion::V3 => birthday.format("%Y-%m-%d"),
            WriteVersion::V4 => birthday.format("%Y%m%d"),
        };
        fold_line(&format!("BDAY:{formatted}"), &mut out);
    }
    if !contact.categories.is_empty() {
        let list = contact
            .categories
            .iter()
            .map(|c| escape_text(c))
            .collect::<Vec<_>>()
            .join(",");
        fold_line(&format!("CATEGORIES:{list}"), &mut out);
    }

    fold_line(
        &format!("REV:{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ")),
        &mut out,
    );
    fold_line("END:VCARD", &mut out);
    out
}

fn typed_line_versioned(property: &str, value: &Typed, version: WriteVersion) -> String {
    let mut params = String::new();

    // 3.0 folds preference into TYPE; 4.0 has a parameter for it.
    let mut types = value.types.clone();
    if value.pref.is_some() && version == WriteVersion::V3 {
        types.push("pref".to_owned());
    }
    if !types.is_empty() {
        params.push_str(&format!(";TYPE={}", types.join(",")));
    }
    if let Some(pref) = value.pref
        && version == WriteVersion::V4
    {
        params.push_str(&format!(";PREF={pref}"));
    }
    format!("{property}{params}:{}", escape_text(&value.value))
}

/// The vCard version calcard would write, for callers that use its writer.
#[must_use]
pub fn default_version() -> VCardVersion {
    VCardVersion::V4_0
}

#[cfg(test)]
mod tests {

    /* ------------- editing one card in a file that holds several ------------- */

    /// What every mainstream exporter produces: one file, all the contacts.
    const TWO_CARDS: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:card-1\r\n\
FN:Ada Lovelace\r\nN:Lovelace;Ada;;;\r\nEMAIL:ada@example.com\r\n\
X-WHICH:first\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:3.0\r\nUID:card-2\r\nFN:Charles Babbage\r\n\
N:Babbage;Charles;;;\r\nEMAIL:babbage@example.com\r\nX-WHICH:second\r\n\
END:VCARD\r\n";

    #[test]
    fn editing_the_second_card_does_not_rewrite_the_first() {
        // The bug this pins was identity-level: `parse_vcards` gives every
        // contact the WHOLE file as its `raw`, and patching index 0 regardless
        // wrote the second person's name and email over the first person's
        // card while leaving the first card's UID in place. Ada's record came
        // back reading "Charles Babbage", and Charles's edit never landed.
        let mut second = parse_vcards(TWO_CARDS, "book", "both.vcf")
            .into_iter()
            .find(|c| c.uid == "card-2")
            .expect("the second card");
        second.display_name = "Charles Babbage (edited)".into();

        let out = patch_vcard(&second.raw, &second).expect("a patched document");

        // The first card is untouched, identity and all.
        assert!(
            out.contains("FN:Ada Lovelace"),
            "Ada's card was rewritten:\n{out}"
        );
        assert!(out.contains("EMAIL:ada@example.com"));
        assert!(out.contains("X-WHICH:first"));
        // And the edit reached the card it was for.
        assert!(out.contains("FN:Charles Babbage (edited)"), "{out}");
        assert_eq!(out.matches("BEGIN:VCARD").count(), 2);
    }

    #[test]
    fn a_lone_card_is_patched_whatever_its_uid_says() {
        // Most vdir files hold one card and a great many carry no UID at all,
        // so a single card must stay patchable by identity or not.
        let one = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Nobody\r\nEND:VCARD\r\n";
        let mut contact = parse_vcards(one, "book", "one.vcf")
            .into_iter()
            .next()
            .expect("a card");
        contact.uid = "an-id-the-card-does-not-carry".into();
        contact.display_name = "Somebody".into();

        let out = patch_vcard(one, &contact).expect("a lone card is patchable");
        assert!(out.contains("FN:Somebody"), "{out}");
    }

    #[test]
    fn a_card_missing_from_a_multi_card_file_is_refused_not_guessed() {
        // Returning None here is what stops the caller serialising one card
        // over a document holding many. Guessing at index 0 is how the bug
        // above happened.
        let mut stranger = parse_vcards(TWO_CARDS, "book", "both.vcf")
            .into_iter()
            .next()
            .expect("a card to clone");
        stranger.uid = "card-99".into();

        assert!(
            patch_vcard(TWO_CARDS, &stranger).is_none(),
            "a contact not in the file was patched into somebody else's card"
        );
    }

    #[test]
    fn the_index_lookup_finds_each_card_by_its_own_uid() {
        assert_eq!(vcard_index_of(TWO_CARDS, "card-1"), Some(0));
        assert_eq!(vcard_index_of(TWO_CARDS, "card-2"), Some(1));
        assert_eq!(vcard_index_of(TWO_CARDS, "card-3"), None);
        assert_eq!(vcard_index_of("", "anything"), None);
    }
    use super::*;

    fn wrap(body: &str) -> String {
        format!("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:c@test\r\n{body}\r\nEND:VCARD\r\n")
    }

    fn one(text: &str) -> Contact {
        let mut all = parse_vcards(text, "default", "c.vcf");
        assert_eq!(all.len(), 1, "expected exactly one vCard");
        all.remove(0)
    }

    #[test]
    fn a_minimal_card_parses() {
        let c = one(&wrap("FN:Ada Lovelace"));
        assert_eq!(c.display_name, "Ada Lovelace");
        assert_eq!(c.uid, "c@test");
    }

    #[test]
    fn the_structured_name_is_split_into_its_components() {
        let c = one(&wrap("FN:Ada Lovelace\r\nN:Lovelace;Ada;Augusta;Dr;FRS"));
        assert_eq!(c.name.family, "Lovelace");
        assert_eq!(c.name.given, "Ada");
        assert_eq!(c.name.additional, "Augusta");
        assert_eq!(c.name.prefix, "Dr");
        assert_eq!(c.name.suffix, "FRS");
    }

    #[test]
    fn emails_carry_their_types_and_pref() {
        let c = one(&wrap(
            "FN:Ada\r\nEMAIL;TYPE=home:ada@home.example\r\nEMAIL;TYPE=work;PREF=1:ada@work.example",
        ));
        assert_eq!(c.emails.len(), 2);
        assert_eq!(c.emails[0].types, vec!["home"]);
        assert_eq!(c.emails[1].pref, Some(1));
        assert_eq!(
            Contact::preferred(&c.emails).map(|e| e.value.as_str()),
            Some("ada@work.example"),
            "PREF was ignored in favour of document order"
        );
    }

    #[test]
    fn a_comma_separated_type_parameter_becomes_several_types() {
        let c = one(&wrap("FN:Ada\r\nTEL;TYPE=\"work,voice\":+15551234"));
        assert!(
            c.phones[0].types.contains(&"work".to_string())
                && c.phones[0].types.contains(&"voice".to_string()),
            "got {:?}",
            c.phones[0].types
        );
    }

    #[test]
    fn an_address_is_split_into_its_seven_components() {
        let c = one(&wrap(
            "FN:Ada\r\nADR;TYPE=home:;;1 Main St;Athens;Attica;10431;Greece",
        ));
        assert_eq!(c.addresses.len(), 1);
        let a = &c.addresses[0];
        assert_eq!(a.street, "1 Main St");
        assert_eq!(a.locality, "Athens");
        assert_eq!(a.region, "Attica");
        assert_eq!(a.postal_code, "10431");
        assert_eq!(a.country, "Greece");
        assert_eq!(a.types, vec!["home"]);
    }

    #[test]
    fn an_entirely_blank_address_is_dropped() {
        let c = one(&wrap("FN:Ada\r\nADR;TYPE=home:;;;;;;"));
        assert!(
            c.addresses.is_empty(),
            "an empty ADR became a visible address block"
        );
    }

    #[test]
    fn a_full_birthday_is_read() {
        let c = one(&wrap("FN:Ada\r\nBDAY:18151210"));
        assert_eq!(c.birthday, NaiveDate::from_ymd_opt(1815, 12, 10));
    }

    #[test]
    fn a_year_less_birthday_is_dropped_rather_than_given_a_fake_year() {
        // `--1210` is legal vCard. Inventing a year would put the anniversary
        // on the wrong date in every year but the invented one.
        let c = one(&wrap("FN:Ada\r\nBDAY:--1210"));
        assert!(c.birthday.is_none());
    }

    #[test]
    fn categories_split_on_commas() {
        let c = one(&wrap("FN:Ada\r\nCATEGORIES:friends,work"));
        assert_eq!(c.categories, vec!["friends", "work"]);
    }

    #[test]
    fn a_photo_is_flagged_but_not_loaded() {
        let c = one(&wrap("FN:Ada\r\nPHOTO;ENCODING=b;TYPE=JPEG:AAAA"));
        assert!(c.has_photo);
    }

    #[test]
    fn the_raw_source_is_kept_for_lossless_writeback() {
        let text = wrap("FN:Ada\r\nX-CUSTOM-THING:preserved");
        let c = one(&text);
        assert!(
            c.raw.contains("X-CUSTOM-THING:preserved"),
            "the unmodelled property was not retained in `raw`"
        );
    }

    #[test]
    fn several_cards_in_one_file_all_parse() {
        let text = format!("{}{}", wrap("FN:Ada"), wrap("FN:Alan"));
        let all = parse_vcards(&text, "default", "c.vcf");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn garbage_yields_no_contacts_rather_than_an_error() {
        assert!(parse_vcards("this is not a vCard", "default", "c.vcf").is_empty());
    }

    /* --- serialisation --- */

    #[test]
    fn a_contact_round_trips_through_text() {
        let mut c = Contact::draft("default");
        c.display_name = "Ada Lovelace".into();
        c.name = StructuredName {
            family: "Lovelace".into(),
            given: "Ada".into(),
            ..StructuredName::default()
        };
        c.emails = vec![Typed {
            value: "ada@example.com".into(),
            types: vec!["work".into()],
            pref: Some(1),
            group: None,
        }];
        c.phones = vec![Typed::new("+15551234")];
        c.organisation = Some("Analytical Engines".into());
        c.note = Some("Met at the exhibition".into());
        c.birthday = NaiveDate::from_ymd_opt(1815, 12, 10);
        c.categories = vec!["friends".into()];
        c.addresses = vec![Address {
            street: "1 Main St".into(),
            locality: "Athens".into(),
            types: vec!["home".into()],
            ..Address::default()
        }];

        let back = one(&to_vcard(&c));

        assert_eq!(back.display_name, "Ada Lovelace");
        assert_eq!(back.name.family, "Lovelace");
        assert_eq!(back.emails[0].value, "ada@example.com");
        assert_eq!(back.emails[0].pref, Some(1));
        assert_eq!(back.phones[0].value, "+15551234");
        assert_eq!(back.organisation.as_deref(), Some("Analytical Engines"));
        assert_eq!(back.note.as_deref(), Some("Met at the exhibition"));
        assert_eq!(back.birthday, c.birthday);
        assert_eq!(back.categories, vec!["friends"]);
        assert_eq!(back.addresses[0].street, "1 Main St");
    }

    #[test]
    fn fn_is_always_emitted_even_when_the_display_name_is_blank() {
        // RFC 6350 §6.2.1 makes FN mandatory; strict servers reject a card
        // without one.
        let mut c = Contact::draft("default");
        c.name.family = "Lovelace".into();
        c.name.given = "Ada".into();

        let text = to_vcard(&c);
        assert!(text.contains("FN:Ada Lovelace"), "{text}");
    }

    #[test]
    fn text_special_characters_round_trip() {
        let mut c = Contact::draft("default");
        c.display_name = "Ada; Lovelace, Dr".into();
        c.note = Some("line one\nline two".into());

        let back = one(&to_vcard(&c));
        assert_eq!(back.display_name, "Ada; Lovelace, Dr");
        assert_eq!(back.note.as_deref(), Some("line one\nline two"));
    }

    #[test]
    fn every_serialised_line_stays_within_the_fold_limit() {
        let mut c = Contact::draft("default");
        c.display_name = "Λ".repeat(300);
        let text = to_vcard(&c);
        for line in text.split("\r\n") {
            assert!(line.len() <= 75, "line exceeds the fold limit: {line:?}");
        }
        assert_eq!(one(&text).display_name, c.display_name);
    }
}

#[cfg(test)]
mod patch_tests {
    use super::*;

    const SYNCED: &str = "BEGIN:VCARD\r\n\
VERSION:4.0\r\n\
UID:ada@server\r\n\
FN:Ada Lovelace\r\n\
N:Lovelace;Ada;;;\r\n\
EMAIL;TYPE=work:ada@work.example\r\n\
item1.EMAIL;type=INTERNET:ada@home.example\r\n\
item1.X-ABLabel:Summer house\r\n\
TEL;TYPE=cell:+15550100\r\n\
PHOTO;ENCODING=b:AAAABBBBCCCC\r\n\
X-ABShowAs:COMPANY\r\n\
GEO:geo:51.5,-0.1\r\n\
REV:20200101T000000Z\r\n\
END:VCARD\r\n";

    fn parsed() -> Contact {
        let mut all = parse_vcards(SYNCED, "default", "ada.vcf");
        all.remove(0)
    }

    #[test]
    fn patching_preserves_everything_the_model_does_not_carry() {
        // The whole point. `to_vcard` would drop all four of these.
        let mut contact = parsed();
        contact.display_name = "Ada Byron".into();

        let out = patch_vcard(&contact.raw.clone(), &contact).expect("patched");

        assert!(out.contains("PHOTO;ENCODING=b:AAAABBBBCCCC\r\n"), "{out}");
        assert!(out.contains("X-ABShowAs:COMPANY\r\n"));
        assert!(out.contains("GEO:geo:51.5,-0.1\r\n"));
        assert!(out.contains("UID:ada@server\r\n"));
        assert!(out.contains("FN:Ada Byron\r\n"));
    }

    #[test]
    fn to_vcard_would_have_lost_them_which_is_why_patch_exists() {
        let contact = parsed();
        let rebuilt = to_vcard(&contact);
        assert!(
            !rebuilt.contains("PHOTO"),
            "the premise of this module changed"
        );
        assert!(!rebuilt.contains("X-ABShowAs"));
        assert!(!rebuilt.contains("GEO:"));
    }

    #[test]
    fn an_apple_grouped_email_and_its_label_survive_an_email_edit() {
        let mut contact = parsed();
        // The modelled list holds both, but only the ungrouped one is rewritten.
        contact.emails = vec![Typed {
            value: "new@work.example".into(),
            types: vec!["work".into()],
            pref: None,
            group: None,
        }];

        let out = patch_vcard(&contact.raw.clone(), &contact).expect("patched");

        assert!(out.contains("EMAIL;TYPE=work:new@work.example\r\n"));
        assert!(
            out.contains("item1.EMAIL;type=INTERNET:ada@home.example\r\n"),
            "the grouped address was clobbered: {out}"
        );
        assert!(
            out.contains("item1.X-ABLabel:Summer house\r\n"),
            "the custom label was orphaned: {out}"
        );
    }

    #[test]
    fn clearing_a_field_removes_the_property() {
        let mut contact = parsed();
        contact.phones.clear();

        let out = patch_vcard(&contact.raw.clone(), &contact).expect("patched");
        assert!(!out.contains("TEL;TYPE=cell"), "{out}");
    }

    #[test]
    fn adding_a_field_the_card_lacked_inserts_it() {
        let mut contact = parsed();
        contact.note = Some("Met at the exhibition".into());

        let out = patch_vcard(&contact.raw.clone(), &contact).expect("patched");
        assert!(out.contains("NOTE:Met at the exhibition\r\n"), "{out}");
        // …inside the card, not after it.
        assert!(out.find("NOTE:").unwrap() < out.find("END:VCARD").unwrap());
    }

    #[test]
    fn rev_is_refreshed_on_every_patch() {
        let contact = parsed();
        let out = patch_vcard(&contact.raw.clone(), &contact).expect("patched");
        assert!(
            !out.contains("REV:20200101T000000Z"),
            "REV was not refreshed"
        );
        assert!(out.contains("REV:"));
    }

    #[test]
    fn a_patched_card_still_parses_to_the_same_contact() {
        let mut contact = parsed();
        contact.display_name = "Ada Byron".into();
        contact.organisation = Some("Analytical Engines".into());

        let out = patch_vcard(&contact.raw.clone(), &contact).expect("patched");
        let back = parse_vcards(&out, "default", "ada.vcf").remove(0);

        assert_eq!(back.display_name, "Ada Byron");
        assert_eq!(back.organisation.as_deref(), Some("Analytical Engines"));
        assert!(back.has_photo, "the photo was lost through a round trip");
        // Both emails come back — the grouped one was never touched.
        assert_eq!(back.emails.len(), 2);
    }

    #[test]
    fn patching_is_idempotent_apart_from_rev() {
        let contact = parsed();
        let once = patch_vcard(&contact.raw.clone(), &contact).expect("first");
        let twice = patch_vcard(&once, &contact).expect("second");

        let strip_rev = |s: &str| {
            s.lines()
                .filter(|l| !l.starts_with("REV:"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(strip_rev(&once), strip_rev(&twice));
    }

    #[test]
    fn a_document_with_no_vcard_is_none() {
        let contact = parsed();
        assert!(patch_vcard("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n", &contact).is_none());
    }
}

#[cfg(test)]
mod photo_tests {
    use super::*;

    #[test]
    fn an_inline_base64_photo_decodes_to_bytes() {
        // "AAAABBBB" is valid base64 for six bytes.
        let raw = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:x\r\nFN:Ada\r\n\
PHOTO;ENCODING=b;TYPE=JPEG:AAAABBBB\r\nEND:VCARD\r\n";
        match photo(raw) {
            Some(Photo::Bytes { data, .. }) => assert!(!data.is_empty()),
            other => panic!("expected inline bytes, got {other:?}"),
        }
    }

    #[test]
    fn a_uri_photo_is_returned_unfetched() {
        let raw = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:x\r\nFN:Ada\r\n\
PHOTO:https://example.com/ada.jpeg\r\nEND:VCARD\r\n";
        assert_eq!(
            photo(raw),
            Some(Photo::Uri("https://example.com/ada.jpeg".into()))
        );
    }

    #[test]
    fn a_card_without_a_photo_yields_none() {
        let raw = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:x\r\nFN:Ada\r\nEND:VCARD\r\n";
        assert_eq!(photo(raw), None);
        assert_eq!(photo(""), None);
        assert_eq!(photo("not a vcard"), None);
    }

    /// A data: URI (the 4.0 inline form) must come back as bytes, not as a URI
    /// string the UI would then have to parse itself.
    #[test]
    fn a_data_uri_photo_decodes_to_bytes() {
        // A 1x1 PNG, base64-encoded.
        let raw = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:x\r\nFN:Ada\r\n\
PHOTO:data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==\r\nEND:VCARD\r\n";
        match photo(raw) {
            Some(Photo::Bytes { data, content_type }) => {
                assert!(
                    data.starts_with(&[0x89, b'P', b'N', b'G']),
                    "not decoded to PNG bytes"
                );
                assert_eq!(content_type.as_deref(), Some("image/png"));
            }
            other => panic!("expected decoded bytes, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;

    #[test]
    fn a_multi_card_file_splits_into_verbatim_segments() {
        let text = "BEGIN:VCARD\r\nUID:a\r\nFN:Ada\r\nX-KEEP:me\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nUID:b\r\nFN:Bob\r\nEND:VCARD\r\n";
        let parts = split_vcards(text);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("X-KEEP:me\r\n"));
        assert!(!parts[0].contains("Bob"));
        assert_eq!(parts.concat(), text, "splitting changed bytes");
    }

    #[test]
    fn junk_between_cards_is_dropped_and_a_truncated_card_is_not_returned() {
        let text = "noise\nBEGIN:VCARD\nUID:a\nEND:VCARD\nnoise\nBEGIN:VCARD\nUID:cut";
        let parts = split_vcards(text);
        assert_eq!(parts.len(), 1);
        assert!(parts[0].starts_with("BEGIN:VCARD"));
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(split_vcards("").is_empty());
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;
    use crate::model::Typed;

    fn ada() -> Contact {
        let mut c = Contact::draft("d");
        c.display_name = "Ada".into();
        c.emails = vec![Typed {
            value: "ada@example.com".into(),
            types: vec!["work".into()],
            pref: Some(1),
            group: None,
        }];
        c.birthday = chrono::NaiveDate::from_ymd_opt(1815, 12, 10);
        c
    }

    /// 3.0 has no PREF parameter — preference is TYPE=PREF (RFC 2426 §3.3).
    #[test]
    fn v3_spells_preference_as_type_pref_and_v4_as_a_parameter() {
        let v3 = to_vcard_versioned(&ada(), WriteVersion::V3);
        assert!(v3.contains("VERSION:3.0"), "{v3}");
        assert!(v3.contains("EMAIL;TYPE=work,pref:ada@example.com"), "{v3}");
        assert!(
            !v3.contains("PREF=1"),
            "a 3.0 card carries no PREF parameter: {v3}"
        );
        assert!(v3.contains("BDAY:1815-12-10"), "{v3}");

        let v4 = to_vcard_versioned(&ada(), WriteVersion::V4);
        assert!(v4.contains("VERSION:4.0"), "{v4}");
        assert!(v4.contains("PREF=1"), "{v4}");
        assert!(v4.contains("BDAY:18151210"), "{v4}");
    }

    /// Both spellings must parse back to the same model, or the two versions
    /// would disagree about who the preferred address is.
    #[test]
    fn both_preference_spellings_parse_to_the_same_model() {
        for version in [WriteVersion::V3, WriteVersion::V4] {
            let text = to_vcard_versioned(&ada(), version);
            let back = parse_vcards(&text, "d", "a.vcf").remove(0);
            assert_eq!(
                back.emails[0].pref,
                Some(1),
                "preference lost through {version:?}"
            );
            assert_eq!(
                back.emails[0].types,
                vec!["work"],
                "TYPE=PREF leaked into the visible labels for {version:?}"
            );
            assert_eq!(back.birthday, ada().birthday, "{version:?}");
        }
    }

    /// A patch speaks the card's own dialect — editing a 3.0 card must not
    /// plant 4.0 syntax in it.
    #[test]
    fn patching_a_v3_card_writes_v3_preference() {
        let original = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:x\r\nFN:Ada\r\n\
EMAIL;TYPE=work:old@example.com\r\nEND:VCARD\r\n";
        let mut contact = parse_vcards(original, "d", "a.vcf").remove(0);
        contact.emails[0].pref = Some(1);

        let patched = patch_vcard(original, &contact).unwrap();
        assert!(patched.contains("VERSION:3.0"), "{patched}");
        assert!(
            !patched.contains("PREF="),
            "4.0 syntax in a 3.0 card: {patched}"
        );
        assert!(patched.contains("TYPE=work,pref"), "{patched}");
    }

    #[test]
    fn the_declared_version_is_read_and_absent_means_v3() {
        assert_eq!(
            declared_version("BEGIN:VCARD\r\nVERSION:4.0\r\nEND:VCARD\r\n"),
            WriteVersion::V4
        );
        assert_eq!(
            declared_version("BEGIN:VCARD\r\nVERSION:3.0\r\nEND:VCARD\r\n"),
            WriteVersion::V3
        );
        assert_eq!(
            declared_version("BEGIN:VCARD\r\nEND:VCARD\r\n"),
            WriteVersion::V3
        );
    }
}

#[cfg(test)]
mod photo_write_tests {
    use super::*;

    const V4: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:x\r\nFN:Ada\r\n\
X-KEEP:me\r\nEND:VCARD\r\n";
    const V3: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:x\r\nFN:Ada\r\n\
PHOTO;ENCODING=b;TYPE=JPEG:OLDOLD==\r\nEND:VCARD\r\n";

    #[test]
    fn setting_a_photo_speaks_the_cards_dialect() {
        let png = [0x89, b'P', b'N', b'G'];

        let v4 = set_photo(V4, "x", &png, "image/png").unwrap();
        assert!(v4.contains("PHOTO:data:image/png;base64,"), "{v4}");
        assert!(v4.contains("X-KEEP:me"), "{v4}");

        let v3 = set_photo(V3, "x", &png, "image/png").unwrap();
        assert!(v3.contains("PHOTO;ENCODING=b;TYPE=PNG:"), "{v3}");
        assert!(!v3.contains("OLDOLD"), "the old photo survived: {v3}");
        assert!(!v3.contains("data:"), "4.0 syntax in a 3.0 card: {v3}");
    }

    #[test]
    fn a_set_photo_reads_back_through_the_photo_accessor() {
        let png = [0x89, b'P', b'N', b'G', 0x0d, 0x0a];
        let card = set_photo(V4, "x", &png, "image/png").unwrap();
        match photo(&card) {
            Some(Photo::Bytes { data, .. }) => assert_eq!(data, png),
            other => panic!("round trip failed: {other:?}"),
        }
    }

    #[test]
    fn removing_a_photo_removes_only_the_photo() {
        let stripped = remove_photo(V3, "x").unwrap();
        assert!(!stripped.contains("PHOTO"), "{stripped}");
        assert!(stripped.contains("FN:Ada"), "{stripped}");

        // Removing from a card with no photo is a no-op, not an error.
        let unchanged = remove_photo(V4, "x").unwrap();
        assert!(unchanged.contains("X-KEEP:me"));
    }

    /// The same shape as the `patch_vcard` bug, in the photo patcher: a
    /// `.vcf` holding two people, each `Contact` carrying the whole file as
    /// its `raw`. Patching index 0 put the second person's photo on the first
    /// person's card.
    #[test]
    fn a_photo_lands_on_its_own_card_in_a_multi_card_file() {
        let two = format!("{V4}{V3}");
        let png = [0x89, b'P', b'N', b'G'];

        // Both fixtures say UID:x, so distinguish them first.
        let two = two.replacen("UID:x", "UID:first", 1);
        let two = two.replacen("UID:x", "UID:second", 1);

        let patched = set_photo(&two, "second", &png, "image/png").unwrap();
        let (first, second) = patched.split_once("BEGIN:VCARD\r\nVERSION:3.0").unwrap();
        assert!(
            !first.contains("PHOTO:data:"),
            "the second card's photo landed on the first card: {first}"
        );
        assert!(
            second.contains("PHOTO;ENCODING=b"),
            "the photo reached the right card but in the wrong dialect — the \
             version was read from the document's first card, not from this \
             one: {second}"
        );
    }

    /// A contact absent from a multi-card file must be refused, not written
    /// into whichever card happened to be first.
    #[test]
    fn patching_a_card_that_is_not_in_a_multi_card_file_is_refused() {
        let two = format!("{V4}{V3}")
            .replacen("UID:x", "UID:first", 1)
            .replacen("UID:x", "UID:second", 1);

        assert!(set_photo(&two, "nobody", &[1], "image/png").is_none());
        assert!(remove_photo(&two, "nobody").is_none());
    }

    #[test]
    fn garbage_yields_none() {
        assert!(set_photo("", "x", &[1], "image/png").is_none());
        assert!(remove_photo("no card here", "x").is_none());
    }
}

#[cfg(test)]
mod group_tests {
    use super::*;

    const APPLE_GROUP: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:g1\r\n\
N:Friends;;;;\r\nFN:Friends\r\nX-ADDRESSBOOKSERVER-KIND:group\r\n\
X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:ada@server\r\n\
X-CUSTOM:keep-me\r\nEND:VCARD\r\n";

    const V4_GROUP: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:g2\r\nFN:Work\r\n\
KIND:group\r\nMEMBER:urn:uuid:bob@server\r\nEND:VCARD\r\n";

    #[test]
    fn both_group_spellings_parse_as_groups_with_their_members() {
        let apple = parse_vcards(APPLE_GROUP, "d", "g.vcf").remove(0);
        assert!(apple.is_group);
        assert_eq!(apple.members, vec!["urn:uuid:ada@server"]);

        let v4 = parse_vcards(V4_GROUP, "d", "g.vcf").remove(0);
        assert!(v4.is_group);
        assert_eq!(v4.members, vec!["urn:uuid:bob@server"]);

        let person = parse_vcards(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:p\r\nFN:Ada\r\nEND:VCARD\r\n",
            "d",
            "p.vcf",
        )
        .remove(0);
        assert!(!person.is_group);
    }

    #[test]
    fn member_uris_resolve_to_uids_where_they_can() {
        assert_eq!(member_uid("urn:uuid:abc@x"), Some("abc@x"));
        assert_eq!(member_uid("URN:UUID:ABC"), Some("ABC"));
        assert_eq!(member_uid("bare-uid"), Some("bare-uid"));
        assert_eq!(member_uid("mailto:a@b"), None, "an address is not a card");
        assert_eq!(member_uri("abc"), "urn:uuid:abc");
    }

    /// The data-loss site: an Apple-style group must keep the Apple spelling,
    /// or Apple clients stop seeing the membership.
    #[test]
    fn membership_edits_keep_the_cards_own_spelling() {
        let more = vec![
            "urn:uuid:ada@server".to_owned(),
            "urn:uuid:new@server".to_owned(),
        ];
        let apple = set_members(APPLE_GROUP, "g1", &more).unwrap();
        assert_eq!(
            apple.matches("X-ADDRESSBOOKSERVER-MEMBER:").count(),
            2,
            "{apple}"
        );
        assert!(
            !apple.contains("\nMEMBER:"),
            "RFC spelling in an Apple group: {apple}"
        );
        assert!(apple.contains("X-CUSTOM:keep-me"), "{apple}");
        assert!(apple.contains("X-ADDRESSBOOKSERVER-KIND:group"), "{apple}");

        let v4 = set_members(V4_GROUP, "g2", &more).unwrap();
        assert_eq!(v4.matches("\nMEMBER:").count(), 2, "{v4}");
        assert!(!v4.contains("X-ADDRESSBOOKSERVER"), "{v4}");
    }

    #[test]
    fn removing_the_last_member_leaves_a_valid_empty_group() {
        let emptied = set_members(V4_GROUP, "g2", &[]).unwrap();
        assert!(!emptied.contains("MEMBER"), "{emptied}");
        assert!(emptied.contains("KIND:group"), "{emptied}");
        let back = parse_vcards(&emptied, "d", "g.vcf").remove(0);
        assert!(back.is_group);
        assert!(back.members.is_empty());
    }

    #[test]
    fn a_new_group_speaks_its_versions_dialect_and_round_trips() {
        let v3 = group_vcard("Friends", "g-new", WriteVersion::V3);
        assert!(v3.contains("X-ADDRESSBOOKSERVER-KIND:group"), "{v3}");
        assert!(
            !v3.contains("KIND:group\r\n")
                || !v3.contains("VERSION:3.0")
                || v3.contains("X-ADDRESSBOOKSERVER"),
            "{v3}"
        );
        let back = parse_vcards(&v3, "d", "g.vcf").remove(0);
        assert!(back.is_group, "the 3.0 spelling did not parse back");
        assert_eq!(back.label(), "Friends");

        let v4 = group_vcard("Work", "g2-new", WriteVersion::V4);
        assert!(v4.contains("KIND:group"), "{v4}");
        assert!(parse_vcards(&v4, "d", "g.vcf").remove(0).is_group);
    }

    /// A member added to a fresh 3.0 group gets the Apple spelling — the group
    /// was created for a 3.0-first server, so its members must be visible to
    /// the clients that server serves.
    /// The same shape as the `patch_vcard` bug, in the member patcher: two
    /// groups in one file, each parsed `Contact` carrying the whole file as
    /// its `raw`. Patching index 0 put the second group's members on the
    /// first group's card.
    #[test]
    fn members_land_on_their_own_card_in_a_multi_card_file() {
        let two = format!("{APPLE_GROUP}{V4_GROUP}");
        // A member neither fixture already carries, so the assertion is
        // about where this write went and not about what was there before.
        let patched = set_members(&two, "g2", &[member_uri("zoe@server")]).unwrap();
        let (apple, v4) = patched.split_once("BEGIN:VCARD\r\nVERSION:4.0").unwrap();

        assert!(
            !apple.contains("zoe@server"),
            "the 4.0 group's member landed on the Apple group: {apple}"
        );
        assert!(v4.contains("MEMBER:urn:uuid:zoe@server"), "{v4}");
        assert!(
            apple.contains("urn:uuid:ada@server"),
            "the Apple group's own member was lost: {apple}"
        );
    }

    /// A group absent from a multi-card file is refused, not written into
    /// whichever card happened to be first.
    #[test]
    fn setting_members_on_a_group_not_in_the_file_is_refused() {
        let two = format!("{APPLE_GROUP}{V4_GROUP}");
        assert!(set_members(&two, "nobody", &[]).is_none());
    }

    #[test]
    fn a_fresh_v3_group_gains_members_in_the_apple_spelling() {
        let card = group_vcard("Friends", "g", WriteVersion::V3);
        let with = set_members(&card, "g", &[member_uri("ada@server")]).unwrap();
        assert!(
            with.contains("X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:ada@server"),
            "{with}"
        );
        let back = parse_vcards(&with, "d", "g.vcf").remove(0);
        assert_eq!(back.members, vec!["urn:uuid:ada@server"]);
    }

    /// Editing a group's name through the ordinary contact save must not
    /// touch its kind or members — they are unmodelled on purpose.
    #[test]
    fn renaming_a_group_through_patch_vcard_keeps_kind_and_members() {
        let mut group = parse_vcards(APPLE_GROUP, "d", "g.vcf").remove(0);
        group.display_name = "Best Friends".into();
        group.name.family = "Best Friends".into();

        let patched = patch_vcard(APPLE_GROUP, &group).unwrap();
        assert!(patched.contains("FN:Best Friends"), "{patched}");
        assert!(
            patched.contains("X-ADDRESSBOOKSERVER-KIND:group"),
            "{patched}"
        );
        assert!(
            patched.contains("X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:ada@server"),
            "{patched}"
        );
    }
}

#[cfg(test)]
mod photo_format_tests {
    use super::*;

    #[test]
    fn real_image_headers_are_recognised() {
        assert_eq!(
            ImageFormat::sniff(b"\x89PNG\r\n\x1a\nrest"),
            Some(ImageFormat::Png)
        );
        assert_eq!(
            ImageFormat::sniff(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]),
            Some(ImageFormat::Jpeg)
        );
        assert_eq!(ImageFormat::sniff(b"GIF89a...."), Some(ImageFormat::Gif));
        assert_eq!(
            ImageFormat::sniff(b"RIFF\0\0\0\0WEBPVP8 "),
            Some(ImageFormat::WebP)
        );
        assert_eq!(ImageFormat::sniff(b"BM\0\0\0\0"), Some(ImageFormat::Bmp));
        assert_eq!(
            ImageFormat::sniff(&[0x49, 0x49, 0x2A, 0x00, 0x08]),
            Some(ImageFormat::Tiff)
        );
        assert_eq!(
            ImageFormat::sniff(b"<svg xmlns=\"http://www.w3.org/2000/svg\">"),
            Some(ImageFormat::Svg)
        );
    }

    #[test]
    fn garbage_is_not_an_image() {
        // The exact shape that produced an invisible contact row: base64 that
        // decodes to a few bytes of nothing in particular.
        assert_eq!(ImageFormat::sniff(b"\x00\x00\x00\x00\x04\x10"), None);
        assert_eq!(ImageFormat::sniff(b""), None);
        assert_eq!(ImageFormat::sniff(b"not an image at all"), None);
    }

    #[test]
    fn a_riff_container_that_is_not_webp_is_not_an_image() {
        // A WAV file is RIFF too; matching on the magic alone would accept it.
        assert_eq!(ImageFormat::sniff(b"RIFF\0\0\0\0WAVEfmt "), None);
    }

    #[test]
    fn a_truncated_riff_header_does_not_panic() {
        assert_eq!(ImageFormat::sniff(b"RIFF"), None);
        assert_eq!(ImageFormat::sniff(b"RIFF\0\0\0"), None);
    }

    #[test]
    fn a_card_with_an_undecodable_photo_is_flagged_unrenderable() {
        // has_photo is true — the property exists — but the payload is not an
        // image, so the UI must fall back to initials rather than draw a hole.
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a@t\r\nFN:Ada\r\n\
                    PHOTO;ENCODING=b:AAAABBBB\r\nEND:VCARD\r\n";
        let contact = parse_vcards(card, "d", "a.vcf").remove(0);
        assert!(contact.has_photo, "the property is present");

        let photo = photo(card).expect("a photo value");
        assert!(
            !photo.is_renderable(),
            "undecodable bytes were reported as renderable"
        );
    }

    #[test]
    fn a_card_with_a_real_png_is_renderable() {
        use base64::Engine as _;
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let encoded = base64::engine::general_purpose::STANDARD.encode(png);
        let card = format!(
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a@t\r\nFN:Ada\r\n\
             PHOTO;ENCODING=b;TYPE=PNG:{encoded}\r\nEND:VCARD\r\n"
        );

        let photo = photo(&card).expect("a photo value");
        assert_eq!(photo.detected_format(), Some(ImageFormat::Png));
        assert!(photo.is_renderable());
    }

    #[test]
    fn a_remote_uri_is_never_renderable_from_bytes_we_hold() {
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a@t\r\nFN:Ada\r\n\
                    PHOTO:https://example.com/ada.png\r\nEND:VCARD\r\n";
        let photo = photo(card).expect("a photo value");
        assert!(matches!(photo, Photo::Uri(_)));
        assert!(!photo.is_renderable(), "a URI carries no bytes to render");
    }
}

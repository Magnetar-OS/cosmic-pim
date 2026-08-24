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
    VCard, VCardEntry, VCardParameterName, VCardProperty, VCardValue, VCardVersion,
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
        birthday: birthday(card),
        urls: typed_list(card, &VCardProperty::Url),
        categories: list_of(card, &VCardProperty::Categories),
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
            Some(Typed {
                value: value.to_owned(),
                types: types_of(entry),
                pref: pref_of(entry),
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

/// `BDAY`, when it is a real date.
///
/// vCard permits a year-less birthday (`--0415`) and even free text. Neither
/// maps onto `NaiveDate`, and inventing a year would put the contact's birthday
/// on the wrong anniversary, so both are dropped rather than guessed at.
fn birthday(card: &VCard) -> Option<NaiveDate> {
    let entry = card.property(&VCardProperty::Bday)?;
    let VCardValue::PartialDateTime(dt) = entry.values.first()? else {
        return None;
    };
    NaiveDate::from_ymd_opt(
        i32::from(dt.year?),
        u32::from(dt.month?),
        u32::from(dt.day?),
    )
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
        && scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
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
/// Returns `None` if `original` contains no VCARD.
#[must_use]
pub fn patch_vcard(original: &str, contact: &Contact) -> Option<String> {
    use crate::patch::{Edit, patch_component};
    use std::collections::BTreeMap;

    let mut edits: BTreeMap<String, Edit> = BTreeMap::new();

    let set = |edits: &mut BTreeMap<String, Edit>, name: &str, lines: Vec<String>| {
        edits.insert(name.to_owned(), Edit::set(lines));
    };

    /// Splits a typed list into the ungrouped lines to write and the grouped
    /// values to edit in place.
    ///
    /// Without this split, an entry parsed from `item1.EMAIL` would be written
    /// back as a plain `EMAIL` line *in addition to* the untouched grouped one
    /// — the contact would gain a duplicate address on every save.
    fn split_typed(name: &str, values: &[Typed]) -> Edit {
        let mut edit = Edit::set(
            values
                .iter()
                .filter(|v| !v.is_grouped())
                .map(|v| typed_line(name, v))
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
    edits.insert("EMAIL".to_owned(), split_typed("EMAIL", &contact.emails));
    edits.insert("TEL".to_owned(), split_typed("TEL", &contact.phones));
    edits.insert("URL".to_owned(), split_typed("URL", &contact.urls));
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
            .map(|b| format!("BDAY:{}", b.format("%Y%m%d")))
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

    patch_component(original, "VCARD", &edits)
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

/// Serialises a contact as a vCard 4.0 document.
///
/// Lossy for anything this crate does not model — see the module docs. Use it
/// for contacts the app created, not to rewrite one that came from a server.
#[must_use]
pub fn to_vcard(contact: &Contact) -> String {
    let mut out = String::new();
    fold_line("BEGIN:VCARD", &mut out);
    fold_line("VERSION:4.0", &mut out);
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
        fold_line(&typed_line("EMAIL", email), &mut out);
    }
    for phone in &contact.phones {
        fold_line(&typed_line("TEL", phone), &mut out);
    }
    for url in &contact.urls {
        fold_line(&typed_line("URL", url), &mut out);
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
        fold_line(&format!("BDAY:{}", birthday.format("%Y%m%d")), &mut out);
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

fn typed_line(property: &str, value: &Typed) -> String {
    let mut params = String::new();
    if !value.types.is_empty() {
        params.push_str(&format!(";TYPE={}", value.types.join(",")));
    }
    if let Some(pref) = value.pref {
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
                assert!(data.starts_with(&[0x89, b'P', b'N', b'G']), "not decoded to PNG bytes");
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

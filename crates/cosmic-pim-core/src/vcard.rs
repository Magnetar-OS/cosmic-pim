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
//! rather than a re-serialisation. Editing a synced contact needs a patcher of
//! the kind `cosmic_pim_caldav::patch` provides for events; until that exists,
//! callers should treat a synced contact as read-only.

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
    let at = |i: usize| parts.get(i).map(|s| s.trim().to_owned()).unwrap_or_default();

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
            let at = |i: usize| parts.get(i).map(|s| s.trim().to_owned()).unwrap_or_default();

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
        let params = if address.types.is_empty() {
            String::new()
        } else {
            format!(";TYPE={}", address.types.join(","))
        };
        fold_line(
            &format!(
                "ADR{params}:{};{};{};{};{};{};{}",
                escape_text(&address.po_box),
                escape_text(&address.extended),
                escape_text(&address.street),
                escape_text(&address.locality),
                escape_text(&address.region),
                escape_text(&address.postal_code),
                escape_text(&address.country),
            ),
            &mut out,
        );
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

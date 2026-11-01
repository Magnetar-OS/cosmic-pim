// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Completing a recipient from the address book, as it is typed.
//!
//! Shared by every field that takes people: the To, Cc and Bcc of a mail
//! composer, the attendees of an event. The address book is the suite's
//! contacts, read from the same vdir the contacts application keeps, with no
//! service in between.
//!
//! The intended use is two steps, because reading every card from disk per
//! key would be the slow part of typing: read the book once
//! ([`read_address_book`]) — when the application starts, and again when a
//! form that completes from it opens — and match against that copy on every
//! keystroke ([`complete`], [`accept`]).
//!
//! A field is a comma-separated list, as an RFC 5322 address list is: a comma
//! inside a quoted display name (`"Lovelace, Ada" <ada@example>`) or between
//! angle brackets does not end a recipient ([`split`], [`parse`]). What is
//! completed is the entry being typed, after the last separating comma; the
//! ones before it are left as they are.

use std::path::Path;

use crate::store::contacts::{self, ContactStore};

/// The most completions offered at once. More is a list to read, not a
/// shortcut.
pub const LIMIT: usize = 6;

/// One address a person has, as the address book knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Known {
    pub name: String,
    pub address: String,
}

impl Known {
    /// How it is written into a recipient field: `Name <address>`, with the
    /// name quoted when it holds a comma or another character that would
    /// change how the field reads ([`mailbox`]).
    #[must_use]
    pub fn mailbox(&self) -> String {
        mailbox(&self.name, &self.address)
    }
}

/// Every address in the address book, one entry per address — a person with
/// a work and a home address is two completions.
#[must_use]
pub fn address_book(store: &ContactStore) -> Vec<Known> {
    let mut known: Vec<Known> = store
        .contacts()
        .iter()
        .flat_map(|contact| {
            // A card with no name is labelled by its first address, which is
            // not a name to write beside its second.
            let name = Some(contact.label())
                .filter(|label| {
                    contact
                        .emails
                        .iter()
                        .all(|email| email.value.trim() != label)
                })
                .unwrap_or_default();
            contact
                .emails
                .iter()
                .map(|email| email.value.trim().to_owned())
                .filter(|address| address.contains('@'))
                .map(move |address| Known {
                    name: name.clone(),
                    address,
                })
        })
        .collect();
    known.sort_by_key(|entry| (entry.name.to_lowercase(), entry.address.to_lowercase()));
    // One entry per address: the same address on two cards — a contact and
    // its linked copy from another book — is one completion.
    let mut seen = std::collections::HashSet::new();
    known.retain(|entry| seen.insert(entry.address.to_lowercase()));
    known
}

/// The address book at its default place. Empty when there is none, which is
/// every desktop without the suite's contacts — completion then offers
/// nothing.
#[must_use]
pub fn read_address_book() -> Vec<Known> {
    read_address_book_at(&contacts::default_root())
}

/// The address book kept under `root`.
///
/// Looked for before it is opened: opening creates the directory, and the
/// address book is the contacts application's to create. One that is there
/// and cannot be read is logged and read as empty, so a broken card never
/// stops somebody typing an address by hand.
#[must_use]
pub fn read_address_book_at(root: &Path) -> Vec<Known> {
    if !root.is_dir() {
        return Vec::new();
    }
    match ContactStore::open(root) {
        Ok(store) => address_book(&store),
        Err(why) => {
            tracing::warn!(%why, "could not read the address book to complete recipients from");
            Vec::new()
        }
    }
}

/// Writes one recipient: `address` alone when there is no name to show,
/// `Name <address>` otherwise.
///
/// A name holding any of RFC 5322's specials — a comma above all — is
/// quoted, with `"` and `\` escaped inside, so the field reads back as the
/// one recipient it is ([`parse`]). Whitespace runs in the name collapse to
/// one space.
#[must_use]
pub fn mailbox(name: &str, address: &str) -> String {
    let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() || name.eq_ignore_ascii_case(address) {
        return address.to_owned();
    }
    if name.contains([',', ';', '<', '>', '"', '\\', '@', ':', '(', ')', '[', ']']) {
        let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\" <{address}>")
    } else {
        format!("{name} <{address}>")
    }
}

/// The byte offsets of the commas in `field` that separate recipients: not
/// one inside double quotes (where a backslash escapes the next character)
/// or inside angle brackets.
fn separators(field: &str) -> Vec<usize> {
    let mut at = Vec::new();
    let (mut quoted, mut escaped, mut angle) = (false, false, false);
    for (index, c) in field.char_indices() {
        if quoted {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => quoted = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => quoted = true,
            '<' => angle = true,
            '>' => angle = false,
            ',' if !angle => at.push(index),
            _ => {}
        }
    }
    at
}

/// The recipients in a field, each trimmed, empty ones left out.
#[must_use]
pub fn split(field: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let mut start = 0;
    for at in separators(field).into_iter().chain([field.len()]) {
        let entry = field[start..at].trim();
        if !entry.is_empty() {
            entries.push(entry);
        }
        start = at + 1;
    }
    entries
}

/// One recipient, as typed, into its display name and its address: `Name
/// <address>`, `"Quoted, Name" <address>` or a bare `address`. The name is
/// unquoted and unescaped; the address is returned as written.
#[must_use]
pub fn parse(entry: &str) -> (Option<String>, String) {
    let entry = entry.trim();
    // The angle bracket that opens the address: the last one outside quotes,
    // so a `<` inside a quoted name is not mistaken for it.
    let mut quoted = false;
    let mut escaped = false;
    let mut open = None;
    for (index, c) in entry.char_indices() {
        if quoted {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => quoted = false,
                _ => {}
            }
        } else if c == '"' {
            quoted = true;
        } else if c == '<' {
            open = Some(index);
        }
    }
    let Some(open) = open else {
        return (None, entry.to_owned());
    };
    let address = entry[open + 1..]
        .trim_end()
        .trim_end_matches('>')
        .trim()
        .to_owned();
    let name = entry[..open].trim();
    let name = match name.strip_prefix('"').and_then(|n| n.strip_suffix('"')) {
        Some(inner) => {
            let mut unescaped = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    unescaped.extend(chars.next());
                } else {
                    unescaped.push(c);
                }
            }
            unescaped
        }
        None => name.to_owned(),
    };
    let name = name.trim();
    ((!name.is_empty()).then(|| name.to_owned()), address)
}

/// What is being typed: the text after the last separating comma.
fn typing(field: &str) -> &str {
    separators(field)
        .last()
        .map_or(field, |&at| &field[at + 1..])
        .trim()
}

/// The recipients already finished: everything before the last separating
/// comma.
fn finished(field: &str) -> &str {
    separators(field).last().map_or("", |&at| &field[..at])
}

/// The completions for what is being typed at the end of `field`.
///
/// Nothing for fewer than two characters: one letter matches half the book.
/// A match at the start of a word of the name, or of the address, comes
/// before one in the middle. An address already in the field is not offered
/// again, and neither is one typed out in full: there is nothing left of it
/// to complete.
#[must_use]
pub fn complete(book: &[Known], field: &str) -> Vec<Known> {
    let needle = typing(field).to_lowercase();
    if needle.chars().count() < 2 || needle.contains('<') {
        return Vec::new();
    }
    let already = finished(field).to_lowercase();

    let mut ranked: Vec<(u8, &Known)> = book
        .iter()
        .filter_map(|known| {
            let name = known.name.to_lowercase();
            let address = known.address.to_lowercase();
            if already.contains(&address) || address == needle {
                return None;
            }
            let starts = address.starts_with(&needle)
                || name
                    .split_whitespace()
                    .any(|word| word.starts_with(&needle));
            if starts {
                Some((0, known))
            } else if name.contains(&needle) || address.contains(&needle) {
                Some((1, known))
            } else {
                None
            }
        })
        .collect();
    ranked.sort_by_key(|(rank, _)| *rank);
    ranked
        .into_iter()
        .take(LIMIT)
        .map(|(_, known)| known.clone())
        .collect()
}

/// `field` with what was being typed replaced by `known`, ready for the next
/// recipient.
#[must_use]
pub fn accept(field: &str, known: &Known) -> String {
    let kept = finished(field).trim_end();
    if kept.is_empty() {
        format!("{}, ", known.mailbox())
    } else {
        format!("{kept}, {}, ", known.mailbox())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn book() -> Vec<Known> {
        [
            ("Ada Lovelace", "ada@analytical.example"),
            ("Ada Lovelace", "countess@home.example"),
            ("Grace Hopper", "grace@navy.example"),
            ("Alan Turing", "alan@bletchley.example"),
            ("Barbara Liskov", "liskov@mit.example"),
        ]
        .into_iter()
        .map(|(name, address)| Known {
            name: name.to_owned(),
            address: address.to_owned(),
        })
        .collect()
    }

    fn addresses(found: &[Known]) -> Vec<&str> {
        found.iter().map(|known| known.address.as_str()).collect()
    }

    #[test]
    fn the_address_book_is_every_address_once_under_its_owner_s_name() {
        use crate::model::{Contact, Rgb, Typed};

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("contacts");
        let mut store = ContactStore::open(&root).expect("store");
        let book = store.create_book("Personal", Rgb(1, 2, 3)).expect("book");

        let mut ada = Contact::draft(&book.id);
        ada.display_name = "Ada Lovelace".into();
        ada.emails = vec![
            Typed::new("ada@analytical.example"),
            Typed::new(" countess@home.example "),
            // Not an address: a note somebody typed into the field.
            Typed::new("ask her sister"),
        ];
        store.save(&ada).expect("save");

        // The same person again, as another book's copy of the card.
        let mut copy = Contact::draft(&book.id);
        copy.display_name = "A. Lovelace".into();
        copy.emails = vec![Typed::new("ADA@analytical.example")];
        store.save(&copy).expect("save");

        // Nobody's name: only addresses.
        let mut nameless = Contact::draft(&book.id);
        nameless.emails = vec![
            Typed::new("office@works.example"),
            Typed::new("billing@works.example"),
        ];
        store.save(&nameless).expect("save");

        let book = read_address_book_at(&root);

        let written: Vec<String> = book.iter().map(Known::mailbox).collect();
        assert_eq!(
            written,
            [
                "billing@works.example",
                "office@works.example",
                "A. Lovelace <ADA@analytical.example>",
                "Ada Lovelace <countess@home.example>",
            ]
        );
    }

    #[test]
    fn no_address_book_is_nothing_to_complete_and_none_is_made() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("contacts");

        assert_eq!(read_address_book_at(&root), []);
        assert!(!root.exists(), "reading the address book created it");
    }

    #[test]
    fn a_name_completes_to_every_address_the_person_has() {
        let found = complete(&book(), "lov");

        assert_eq!(
            addresses(&found),
            ["ada@analytical.example", "countess@home.example"]
        );
    }

    #[test]
    fn a_word_start_comes_before_a_match_in_the_middle() {
        // "li" starts Liskov and sits inside nothing else first.
        let found = complete(&book(), "li");

        assert_eq!(
            found.first().map(|k| k.address.as_str()),
            Some("liskov@mit.example")
        );
    }

    #[test]
    fn only_the_recipient_being_typed_is_completed() {
        let found = complete(&book(), "grace@navy.example, tur");

        assert_eq!(addresses(&found), ["alan@bletchley.example"]);
    }

    #[test]
    fn an_address_already_in_the_field_is_not_offered_again() {
        let found = complete(&book(), "Ada Lovelace <ada@analytical.example>, ad");

        assert_eq!(addresses(&found), ["countess@home.example"]);
    }

    #[test]
    fn an_address_typed_out_in_full_is_not_offered_back() {
        assert_eq!(complete(&book(), "Grace@Navy.example"), []);
        // One letter short of it, it still is.
        assert_eq!(
            addresses(&complete(&book(), "grace@navy.exampl")),
            ["grace@navy.example"]
        );
    }

    #[test]
    fn trailing_space_after_a_name_still_completes_it() {
        assert_eq!(
            addresses(&complete(&book(), "grac ")),
            ["grace@navy.example"]
        );
    }

    #[test]
    fn one_letter_offers_nothing() {
        assert_eq!(complete(&book(), "a"), []);
        assert_eq!(complete(&book(), "grace@navy.example, "), []);
    }

    #[test]
    fn accepting_replaces_what_was_typed_and_leaves_room_for_the_next() {
        let grace = &book()[2];

        assert_eq!(accept("gra", grace), "Grace Hopper <grace@navy.example>, ");
        assert_eq!(
            accept("alan@bletchley.example, gra", grace),
            "alan@bletchley.example, Grace Hopper <grace@navy.example>, "
        );
    }

    #[test]
    fn a_comma_in_a_name_does_not_split_the_recipient() {
        let known = Known {
            name: "Lovelace, Ada".to_owned(),
            address: "ada@analytical.example".to_owned(),
        };

        assert_eq!(
            known.mailbox(),
            "\"Lovelace, Ada\" <ada@analytical.example>"
        );
        assert_eq!(
            split(&format!("{}, grace@navy.example", known.mailbox()))
                .into_iter()
                .map(parse)
                .collect::<Vec<_>>(),
            [
                (
                    Some("Lovelace, Ada".to_owned()),
                    "ada@analytical.example".to_owned()
                ),
                (None, "grace@navy.example".to_owned()),
            ]
        );
    }

    #[test]
    fn a_name_with_quotes_and_backslashes_round_trips() {
        let written = mailbox(r#"Ada "Countess" \ Lovelace"#, "ada@analytical.example");
        assert_eq!(
            written,
            r#""Ada \"Countess\" \\ Lovelace" <ada@analytical.example>"#
        );
        assert_eq!(
            parse(&written),
            (
                Some(r#"Ada "Countess" \ Lovelace"#.to_owned()),
                "ada@analytical.example".to_owned()
            )
        );
    }

    #[test]
    fn fields_split_on_commas_outside_quotes_and_brackets_only() {
        assert_eq!(
            split(r#"ada@x.example, "Doe, Jane" <jane@y.example> ,, Bob <bob@z.example>"#),
            [
                "ada@x.example",
                r#""Doe, Jane" <jane@y.example>"#,
                "Bob <bob@z.example>"
            ]
        );
        assert_eq!(split("  , ,"), Vec::<&str>::new());
        assert_eq!(
            parse("Bob Smith <Bob@Example.NET>"),
            (Some("Bob Smith".to_owned()), "Bob@Example.NET".to_owned())
        );
        assert_eq!(parse("cleo@x.org"), (None, "cleo@x.org".to_owned()));
    }

    #[test]
    fn completing_after_a_quoted_comma_keeps_the_finished_recipient_whole() {
        let ada = "\"Lovelace, Ada\" <ada@analytical.example>";
        let field = format!("{ada}, gra");
        assert_eq!(
            addresses(&complete(&book(), &field)),
            ["grace@navy.example"]
        );
        assert_eq!(
            accept(&field, &book()[2]),
            format!("{ada}, Grace Hopper <grace@navy.example>, ")
        );
    }

    #[test]
    fn an_address_with_no_name_is_written_once() {
        for name in ["", "  ", "Ada@Analytical.example"] {
            let known = Known {
                name: name.to_owned(),
                address: "ada@analytical.example".to_owned(),
            };

            assert_eq!(known.mailbox(), "ada@analytical.example");
        }
    }
}

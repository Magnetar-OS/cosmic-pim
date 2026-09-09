// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Contacts: the vCard side of the suite.
//!
//! # What is modelled, and what is deliberately not
//!
//! vCard 4.0 has around forty properties, most of which no desktop address book
//! shows. This models the ones a contacts UI actually renders — names, emails,
//! phones, addresses, organisation, birthday, note, categories — and treats the
//! rest as data to be preserved rather than understood.
//!
//! "Preserved rather than understood" is doing real work there. The CardDAV
//! engine stores a server's bytes verbatim (the same guarantee the calendar
//! has), so a contact synced from a server keeps its PHOTO, its GEO, its
//! X-ABLabel entries and everything else — none of which appear below. That
//! only stays true as long as **writing** goes back through the original bytes
//! too; see [`Contact::raw`].

use chrono::{DateTime, NaiveDate, Utc};

/// A value with its vCard `TYPE` parameters, e.g. an email tagged `home`.
///
/// The types are kept as free text rather than an enum: RFC 6350 defines a set
/// but explicitly permits `X-` extensions, and Apple and Google both ship them.
/// An enum would silently discard the label a user actually chose.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Typed {
    pub value: String,
    /// Lowercased `TYPE` values, e.g. `["home"]`, `["work", "voice"]`.
    pub types: Vec<String>,
    /// `PREF` — lower is more preferred. `None` when unset.
    pub pref: Option<u8>,
    /// The vCard group this came from, if any (`item1` in `item1.EMAIL`).
    ///
    /// Provenance, not decoration. A grouped line usually has a sibling
    /// carrying its custom label (`item1.X-ABLabel:Summer house`), and the two
    /// are one logical thing. The writer uses this to edit such an entry *in
    /// place* rather than rewriting it as an ungrouped line, which would orphan
    /// the label. A UI can use it to show that the entry has a custom label.
    pub group: Option<String>,

    /// Every other parameter on this entry's line, as `NAME=value` text.
    ///
    /// Provenance, like `group`, and for the same reason: the writer rebuilds
    /// a modelled line from these fields, so a parameter with nowhere to live
    /// here is a parameter deleted from the user's card on the next save —
    /// and pushed to the server, on every device. The loss is not confined to
    /// vendor extensions: `PID` is RFC 6350's property-level sync identity,
    /// and `ALTID`, `LANGUAGE` and `MEDIATYPE` are all standard.
    ///
    /// Carried per entry rather than reconstructed at write time, which is
    /// what makes an edited *value* safe. Matching new values against old
    /// lines would need either an identity this type does not have or
    /// positional matching, and position is the thing this crate has spent
    /// its bug history learning not to trust. An entry a UI builds fresh has
    /// none, which is correct: it came from no line.
    pub params: Vec<String>,
}

impl Typed {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            types: Vec::new(),
            pref: None,
            group: None,
            params: Vec::new(),
        }
    }

    /// Whether this entry came from a grouped vCard line, and so must be
    /// edited in place rather than rewritten.
    #[must_use]
    pub fn is_grouped(&self) -> bool {
        self.group.is_some()
    }

    /// A human label for the value: its first type, or nothing.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.types.first().map(String::as_str)
    }
}

/// A structured postal address (vCard `ADR`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Address {
    pub po_box: String,
    pub extended: String,
    pub street: String,
    pub locality: String,
    pub region: String,
    pub postal_code: String,
    pub country: String,
    pub types: Vec<String>,
    /// Every other parameter on the `ADR` line, as `NAME=value` text — see
    /// [`Typed::params`]. `GEO=` and `LABEL=` live here, and both are
    /// standard.
    pub params: Vec<String>,
}

impl Address {
    /// Whether every component is empty — servers do emit blank ADR lines.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        [
            &self.po_box,
            &self.extended,
            &self.street,
            &self.locality,
            &self.region,
            &self.postal_code,
            &self.country,
        ]
        .iter()
        .all(|part| part.trim().is_empty())
    }

    /// The address on one line, for a summary row.
    #[must_use]
    pub fn one_line(&self) -> String {
        [
            self.street.as_str(),
            self.locality.as_str(),
            self.region.as_str(),
            self.postal_code.as_str(),
            self.country.as_str(),
        ]
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
    }
}

/// The `N` property: the name, broken into its parts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StructuredName {
    pub family: String,
    pub given: String,
    pub additional: String,
    pub prefix: String,
    pub suffix: String,
}

impl StructuredName {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.family.trim().is_empty() && self.given.trim().is_empty()
    }

    /// "Given Family", for deriving a display name when `FN` is missing.
    #[must_use]
    pub fn joined(&self) -> String {
        [
            self.prefix.as_str(),
            self.given.as_str(),
            self.additional.as_str(),
            self.family.as_str(),
            self.suffix.as_str(),
        ]
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub uid: String,
    /// The collection directory this contact lives in.
    pub addressbook_id: String,
    /// `FN` — the formatted name. Required by RFC 6350, and the only thing
    /// guaranteed present, so it is what the UI sorts and displays.
    pub display_name: String,
    pub name: StructuredName,
    pub nicknames: Vec<String>,
    pub emails: Vec<Typed>,
    pub phones: Vec<Typed>,
    pub addresses: Vec<Address>,
    pub organisation: Option<String>,
    /// The `ORG` units beneath the organisation name — RFC 6350 §6.6.4 makes
    /// ORG a hierarchy, `Company;Division;Team`, and this carries everything
    /// after the first component.
    ///
    /// Separate from `organisation` because a UI wants the company name, not
    /// a semicolon-joined string, and because the components have to be
    /// escaped individually: writing the hierarchy back through one field
    /// would escape its separators and turn three components into one name
    /// containing semicolons.
    pub organisation_units: Vec<String>,
    pub title: Option<String>,
    pub note: Option<String>,
    pub birthday: Option<NaiveDate>,
    /// `BDAY` when the card gives a month and day but **no year** (`--0415`,
    /// legal vCard and common for contacts who prefer not to state an age).
    ///
    /// Mutually exclusive with [`Self::birthday`] by construction — a card has
    /// one `BDAY`, and this field is only set when a year is absent. `(month,
    /// day)`. The editor leaves it alone (there is no full date to edit into),
    /// but the birthday stream serves it, ageless.
    pub birthday_month_day: Option<(u32, u32)>,
    pub urls: Vec<Typed>,
    pub categories: Vec<String>,
    /// `REV` — the contact's own last-modified stamp.
    pub rev: Option<DateTime<Utc>>,
    /// Whether this card is a group (vCard 4.0 `KIND:group`, or Apple's
    /// `X-ADDRESSBOOKSERVER-KIND:group` on 3.0 cards).
    ///
    /// A group card is not a person: address-book UIs list it among groups,
    /// not contacts, and its `MEMBER` URIs point at the cards it contains.
    pub is_group: bool,
    /// `MEMBER` / `X-ADDRESSBOOKSERVER-MEMBER` values, **verbatim**.
    ///
    /// Kept as the URIs the card carries (`urn:uuid:…`, occasionally
    /// `mailto:…`) rather than parsed down to UIDs, because writing back
    /// anything but the original bytes for an untouched member would be the
    /// same silent-rewrite bug the patcher exists to prevent. Use
    /// [`member_uid`](crate::vcard::member_uid) to compare against a UID.
    pub members: Vec<String>,
    /// Whether the source carried a `PHOTO`.
    ///
    /// The bytes are not loaded: a photo can be hundreds of kilobytes and an
    /// address-book list would pull every one of them into memory to render
    /// rows that show a 32-pixel circle. The flag is enough to decide whether
    /// to fetch one lazily.
    pub has_photo: bool,
    /// The source vCard, verbatim.
    ///
    /// Kept so that saving a contact can patch the original text rather than
    /// re-serialising from the fields above — the same discipline
    /// `patch_event_ics` enforces for events, and for the same reason: this
    /// struct models perhaps a third of what a real vCard carries.
    pub raw: String,
    /// File name within the collection directory.
    pub file_name: String,
}

impl Contact {
    #[must_use]
    pub fn draft(addressbook_id: &str) -> Self {
        Self {
            uid: format!("{}@cosmic-pim", uuid::Uuid::new_v4()),
            addressbook_id: addressbook_id.to_owned(),
            display_name: String::new(),
            name: StructuredName::default(),
            nicknames: Vec::new(),
            emails: Vec::new(),
            phones: Vec::new(),
            addresses: Vec::new(),
            organisation: None,
            organisation_units: Vec::new(),
            title: None,
            note: None,
            birthday: None,
            birthday_month_day: None,
            urls: Vec::new(),
            categories: Vec::new(),
            rev: None,
            is_group: false,
            members: Vec::new(),
            has_photo: false,
            raw: String::new(),
            file_name: format!("{}.vcf", uuid::Uuid::new_v4()),
        }
    }

    /// The best available name for display.
    ///
    /// `FN` is required by the RFC and routinely absent anyway, so this falls
    /// back through the structured name, the organisation, and finally the
    /// first email — an address book row must never be blank.
    #[must_use]
    pub fn label(&self) -> String {
        if !self.display_name.trim().is_empty() {
            return self.display_name.trim().to_owned();
        }
        if !self.name.is_empty() {
            return self.name.joined();
        }
        if let Some(org) = self.organisation.as_deref().map(str::trim)
            && !org.is_empty()
        {
            return org.to_owned();
        }
        self.emails
            .first()
            .map(|e| e.value.clone())
            .unwrap_or_default()
    }

    /// The preferred value from a typed list: lowest `PREF`, else the first.
    #[must_use]
    pub fn preferred(values: &[Typed]) -> Option<&Typed> {
        values
            .iter()
            .filter(|v| v.pref.is_some())
            .min_by_key(|v| v.pref.unwrap_or(u8::MAX))
            .or_else(|| values.first())
    }

    /// Sort key for an address book: by family name where there is one, so a
    /// list reads the way a phone book does, falling back to the display label.
    #[must_use]
    pub fn sort_key(&self) -> (String, String) {
        let primary = if self.name.family.trim().is_empty() {
            self.label()
        } else {
            self.name.family.clone()
        };
        (primary.to_lowercase(), self.name.given.to_lowercase())
    }

    /// Whether any modelled field matches `needle`, case-insensitively.
    #[must_use]
    pub fn matches(&self, needle: &str) -> bool {
        let needle = needle.trim().to_lowercase();
        if needle.is_empty() {
            return true;
        }
        let hit = |s: &str| s.to_lowercase().contains(&needle);

        hit(&self.label())
            || self.emails.iter().any(|e| hit(&e.value))
            // Phone numbers are matched with separators stripped, so searching
            // "5551234" finds "+1 (555) 123-4".
            || self.phones.iter().any(|p| {
                hit(&p.value)
                    || p.value
                        .chars()
                        .filter(char::is_ascii_digit)
                        .collect::<String>()
                        .contains(&needle)
            })
            || self.organisation.as_deref().is_some_and(hit)
            || self.nicknames.iter().any(|n| hit(n))
            || self.categories.iter().any(|c| hit(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_label_prefers_fn() {
        let mut c = Contact::draft("default");
        c.display_name = "Ada Lovelace".into();
        c.name.family = "Byron".into();
        assert_eq!(c.label(), "Ada Lovelace");
    }

    #[test]
    fn the_label_falls_back_through_name_org_and_email() {
        let mut c = Contact::draft("default");
        c.name.given = "Ada".into();
        c.name.family = "Lovelace".into();
        assert_eq!(c.label(), "Ada Lovelace");

        let mut c = Contact::draft("default");
        c.organisation = Some("Analytical Engines Ltd".into());
        assert_eq!(c.label(), "Analytical Engines Ltd");

        let mut c = Contact::draft("default");
        c.emails = vec![Typed::new("ada@example.com")];
        assert_eq!(c.label(), "ada@example.com");
    }

    #[test]
    fn a_contact_with_nothing_at_all_yields_an_empty_label_not_a_panic() {
        assert_eq!(Contact::draft("default").label(), "");
    }

    #[test]
    fn the_structured_name_joins_in_reading_order() {
        let name = StructuredName {
            prefix: "Dr".into(),
            given: "Ada".into(),
            additional: "Augusta".into(),
            family: "Lovelace".into(),
            suffix: "FRS".into(),
        };
        assert_eq!(name.joined(), "Dr Ada Augusta Lovelace FRS");
    }

    #[test]
    fn preferred_picks_the_lowest_pref_not_the_first() {
        let values = vec![
            Typed {
                value: "second@example.com".into(),
                types: vec!["work".into()],
                pref: Some(10),
                group: None,
                params: Vec::new(),
            },
            Typed {
                value: "first@example.com".into(),
                types: vec!["home".into()],
                pref: Some(1),
                group: None,
                params: Vec::new(),
            },
        ];
        assert_eq!(
            Contact::preferred(&values).map(|t| t.value.as_str()),
            Some("first@example.com")
        );
    }

    #[test]
    fn preferred_falls_back_to_the_first_when_nothing_is_marked() {
        let values = vec![Typed::new("a@example.com"), Typed::new("b@example.com")];
        assert_eq!(
            Contact::preferred(&values).map(|t| t.value.as_str()),
            Some("a@example.com")
        );
    }

    #[test]
    fn sorting_is_by_family_name_where_there_is_one() {
        let mut ada = Contact::draft("d");
        ada.display_name = "Ada Lovelace".into();
        ada.name.family = "Lovelace".into();
        ada.name.given = "Ada".into();

        let mut alan = Contact::draft("d");
        alan.display_name = "Alan Turing".into();
        alan.name.family = "Turing".into();
        alan.name.given = "Alan".into();

        assert!(
            ada.sort_key() < alan.sort_key(),
            "sorted by given name rather than family"
        );
    }

    #[test]
    fn a_contact_with_no_family_name_sorts_on_its_label() {
        let mut org = Contact::draft("d");
        org.organisation = Some("Acme".into());
        let mut person = Contact::draft("d");
        person.name.family = "Zeta".into();

        assert!(org.sort_key() < person.sort_key());
    }

    #[test]
    fn search_matches_names_emails_and_organisations() {
        let mut c = Contact::draft("d");
        c.display_name = "Ada Lovelace".into();
        c.emails = vec![Typed::new("ada@example.com")];
        c.organisation = Some("Analytical Engines".into());

        assert!(c.matches("lovelace"));
        assert!(c.matches("ADA@EXAMPLE"));
        assert!(c.matches("analytical"));
        assert!(!c.matches("babbage"));
    }

    #[test]
    fn search_ignores_phone_number_punctuation() {
        let mut c = Contact::draft("d");
        c.display_name = "Ada".into();
        c.phones = vec![Typed::new("+1 (555) 123-4567")];

        assert!(
            c.matches("5551234567"),
            "a number typed without punctuation did not match"
        );
    }

    #[test]
    fn an_empty_search_matches_everything() {
        assert!(Contact::draft("d").matches("   "));
    }

    #[test]
    fn a_blank_address_is_recognised_as_empty() {
        assert!(Address::default().is_empty());

        let mut a = Address {
            types: vec!["home".into()],
            ..Address::default()
        };
        assert!(a.is_empty(), "types alone do not make an address");

        a.street = "1 Main St".into();
        assert!(!a.is_empty());
    }

    #[test]
    fn an_address_renders_on_one_line_without_blank_gaps() {
        let a = Address {
            street: "1 Main St".into(),
            locality: "Athens".into(),
            postal_code: "10431".into(),
            ..Address::default()
        };
        assert_eq!(a.one_line(), "1 Main St, Athens, 10431");
    }
}

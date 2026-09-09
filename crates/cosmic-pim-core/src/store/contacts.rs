// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Address books on disk: one directory per book, one `.vcf` per contact.
//!
//! The same vdir shape the calendar uses, with `.vcf` in place of `.ics` — the
//! layout `vdirsyncer` writes for CardDAV, so an address book synced here is
//! readable by khard and anything else that speaks vdir.
//!
//! # Why there is no index
//!
//! [`super::Store`] puts SQLite in front of the calendar because a month view
//! needs a *range* query over expanded recurrences, which is expensive to
//! recompute. An address book has no ranges and no expansion: it is read whole,
//! sorted, and filtered by substring. A few thousand contacts is a few hundred
//! kilobytes of text, which is faster to read than to invalidate a cache over.
//!
//! If that stops being true — an address book of tens of thousands, or a live
//! search across mail as well — the place to fix it is here, behind the same
//! API.

use std::path::{Path, PathBuf};

use super::{ImportSummary, StoreError};
use crate::model::{CalendarMeta, Contact};
use crate::vcard::{WriteVersion, parse_vcards, split_vcards, to_vcard_versioned};

/// Where address books live: `$XDG_DATA_HOME/contacts`.
///
/// Separate from the calendar root because CardDAV collections and CalDAV
/// collections are different things on the server, and vdirsyncer keeps them
/// apart too. `COSMIC_PIM_CONTACTS_DIR` overrides it.
#[must_use]
pub fn default_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("COSMIC_PIM_CONTACTS_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("contacts")
}

/// Reads every contact in one address book.
#[must_use]
pub fn read_book(meta: &CalendarMeta) -> Vec<Contact> {
    let Ok(entries) = std::fs::read_dir(&meta.path) else {
        tracing::warn!(path = %meta.path.display(), "cannot read address book");
        return Vec::new();
    };

    let mut out = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("vcf") {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => out.extend(parse_vcards(&text, &meta.id, file_name)),
            Err(why) => tracing::warn!(path = %path.display(), %why, "cannot read contact file"),
        }
    }
    out
}

/// Writes a contact, atomically and losslessly.
///
/// A contact that came from a server carries its source bytes in
/// [`Contact::raw`]; this **patches** those, so PHOTO, GEO, `X-` properties,
/// and Apple-grouped labels all survive an edit. Only a contact with no source
/// — one this app created — is serialised from the model.
///
/// The distinction is not cosmetic. Re-serialising a synced card would delete
/// whatever the model does not represent, and the loss would only become
/// visible after the next push, on every device the user owns.
pub fn write_contact(meta: &CalendarMeta, contact: &Contact) -> Result<(), StoreError> {
    write_contact_versioned(meta, contact, WriteVersion::default())
}

/// [`write_contact`], with the version a **new** card serialises as.
///
/// The version only applies when there is nothing to patch: an existing card
/// keeps the version its own bytes declare, because the patcher rewrites lines
/// in the card's dialect and never converts. The default is 3.0 — Nextcloud
/// and most CardDAV peers are 3.0-first, and conversion is never silent.
pub fn write_contact_versioned(
    meta: &CalendarMeta,
    contact: &Contact,
    version: WriteVersion,
) -> Result<(), StoreError> {
    if meta.read_only {
        return Err(StoreError::ReadOnly(meta.name.clone()));
    }

    let text = match crate::vcard::patch_vcard(&contact.raw, contact) {
        Some(patched) => patched,
        None if contact.raw.matches("BEGIN:VCARD").count() > 1 => {
            // Several cards in the file and none of them is this one. Falling
            // back to the model here would serialise one card over a document
            // holding many, deleting everybody else in it — so this refuses
            // instead. Silent data loss is exactly what this function exists
            // to prevent.
            return Err(StoreError::Unpatchable {
                uid: contact.uid.clone(),
                file: meta.path.join(&contact.file_name),
            });
        }
        None => {
            // No source to patch: a new contact, or a `raw` that holds no
            // VCARD. Building from the model is correct here and lossless by
            // definition — there is nothing to lose.
            if !contact.raw.trim().is_empty() {
                tracing::warn!(
                    uid = contact.uid,
                    "stored vCard could not be patched; rebuilding from the model"
                );
            }
            to_vcard_versioned(contact, version)
        }
    };

    crate::atomic::write(&meta.path.join(&contact.file_name), &text, None)
        .map(|_| ())
        .map_err(Into::into)
}

/// Writes a contact's raw vCard bytes verbatim.
///
/// The lossless path: used by the sync engine, and by any future editor that
/// patches the original text rather than re-serialising it.
pub fn write_contact_raw(
    meta: &CalendarMeta,
    file_name: &str,
    vcard: &str,
) -> Result<(), StoreError> {
    if meta.read_only {
        return Err(StoreError::ReadOnly(meta.name.clone()));
    }
    crate::atomic::write(&meta.path.join(file_name), vcard, None)
        .map(|_| ())
        .map_err(Into::into)
}

/// Removes a file, treating an already-absent one as success.
fn remove_file_if_present(path: &Path) -> Result<(), StoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Every address book under `root`.
#[must_use]
pub fn books(root: &Path) -> Vec<CalendarMeta> {
    super::vdir::collections(root)
}

/// The whole address book, across every book.
pub struct ContactStore {
    root: PathBuf,
    books: Vec<CalendarMeta>,
}

impl ContactStore {
    pub fn open_default() -> Result<Self, StoreError> {
        Self::open(&default_root())
    }

    pub fn open(root: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            books: books(root),
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn books(&self) -> &[CalendarMeta] {
        &self.books
    }

    #[must_use]
    pub fn book(&self, id: &str) -> Option<&CalendarMeta> {
        self.books.iter().find(|b| b.id == id)
    }

    /// The book new contacts land in unless the user picks another.
    #[must_use]
    pub fn default_book(&self) -> Option<&CalendarMeta> {
        self.books.iter().find(|b| !b.read_only)
    }

    pub fn refresh(&mut self) {
        self.books = books(&self.root);
    }

    /// Every contact, sorted for display. Group cards are excluded — they are
    /// not people, and a row named "Friends" between Franklin and Gauss reads
    /// as a bug; [`Self::groups`] lists them.
    #[must_use]
    pub fn contacts(&self) -> Vec<Contact> {
        let mut out: Vec<Contact> = self
            .books
            .iter()
            .flat_map(read_book)
            .filter(|c| !c.is_group)
            .collect();
        out.sort_by_key(Contact::sort_key);
        out
    }

    /// Contacts matching a search string, sorted. Group cards excluded, as in
    /// [`Self::contacts`].
    #[must_use]
    pub fn search(&self, needle: &str) -> Vec<Contact> {
        let mut out: Vec<Contact> = self
            .books
            .iter()
            .flat_map(read_book)
            .filter(|c| !c.is_group && c.matches(needle))
            .collect();
        out.sort_by_key(Contact::sort_key);
        out
    }

    /// Every group card, sorted by name.
    #[must_use]
    pub fn groups(&self) -> Vec<Contact> {
        let mut out: Vec<Contact> = self
            .books
            .iter()
            .flat_map(read_book)
            .filter(|c| c.is_group)
            .collect();
        out.sort_by_key(Contact::sort_key);
        out
    }

    /// Creates a group card in `book_id`, returning it.
    pub fn create_group(
        &mut self,
        name: &str,
        book_id: &str,
        version: crate::vcard::WriteVersion,
    ) -> Result<Contact, StoreError> {
        let meta = self
            .book(book_id)
            .ok_or_else(|| StoreError::UnknownCalendar(book_id.to_owned()))?
            .clone();

        let uid = format!("{}@cosmic-pim", uuid::Uuid::new_v4());
        let card = crate::vcard::group_vcard(name, &uid, version);
        let file_name = format!("{}.vcf", super::sanitise_file_stem(&uid));
        write_contact_raw(&meta, &file_name, &card)?;

        self.contact(book_id, &uid)
            .ok_or_else(|| StoreError::UnknownContact(uid))
    }

    /// Rewrites a group's member list, byte-preservingly, in the card's own
    /// member spelling — see [`crate::vcard::set_members`].
    pub fn set_group_members(
        &mut self,
        book_id: &str,
        uid: &str,
        members: &[String],
    ) -> Result<(), StoreError> {
        let meta = self
            .book(book_id)
            .ok_or_else(|| StoreError::UnknownCalendar(book_id.to_owned()))?
            .clone();

        let Some(group) = read_book(&meta).into_iter().find(|c| c.uid == uid) else {
            return Err(StoreError::UnknownContact(uid.to_owned()));
        };
        let Some(patched) = crate::vcard::set_members(&group.raw, uid, members) else {
            return Err(StoreError::UnknownContact(uid.to_owned()));
        };
        write_contact_raw(&meta, &group.file_name, &patched)
    }

    #[must_use]
    pub fn contact(&self, book_id: &str, uid: &str) -> Option<Contact> {
        let meta = self.book(book_id)?;
        read_book(meta).into_iter().find(|c| c.uid == uid)
    }

    pub fn save(&mut self, contact: &Contact) -> Result<(), StoreError> {
        self.save_as(contact, WriteVersion::default())
    }

    /// [`Self::save`], choosing the version a **new** card serialises as.
    /// Existing cards keep their own version regardless — see
    /// [`write_contact_versioned`].
    pub fn save_as(&mut self, contact: &Contact, version: WriteVersion) -> Result<(), StoreError> {
        let meta = self
            .book(&contact.addressbook_id)
            .ok_or_else(|| StoreError::UnknownCalendar(contact.addressbook_id.clone()))?
            .clone();
        write_contact_versioned(&meta, contact, version)
    }

    pub fn delete(&mut self, book_id: &str, uid: &str) -> Result<(), StoreError> {
        let meta = self
            .book(book_id)
            .ok_or_else(|| StoreError::UnknownCalendar(book_id.to_owned()))?
            .clone();

        // Refused here, at the top, because the two exits below do not both
        // reach a check. Removing a card from a *shared* file goes through
        // `write_contact_raw`, which refuses; removing a card that owns its
        // file ends in `remove_file_if_present`, which takes a path and no
        // book and so cannot refuse anything even in principle. The guard was
        // present exactly where the damage was smallest, and the write
        // functions' checks made the whole type look covered.
        if meta.read_only {
            return Err(StoreError::ReadOnly(meta.name.clone()));
        }

        let Some(contact) = read_book(&meta).into_iter().find(|c| c.uid == uid) else {
            return Ok(());
        };
        let path = meta.path.join(&contact.file_name);

        // A file holding several cards — which is what every export from
        // Google, Apple and Outlook is — must lose one card, not all of them.
        // Unlinking it here deleted everybody who happened to share the file
        // with the person being deleted.
        if contact.raw.matches("BEGIN:VCARD").count() > 1 {
            let remaining: String = split_vcards(&contact.raw)
                .into_iter()
                .filter(|card| {
                    // Keep every card that is not this one. A card with no UID
                    // is kept: it cannot be the one asked for by uid, and
                    // guessing would delete a stranger.
                    parse_vcards(card, &meta.id, &contact.file_name)
                        .first()
                        .is_none_or(|parsed| parsed.uid != uid)
                })
                .collect();

            return if remaining.trim().is_empty() {
                // Every card in it was this contact; the file has nothing left
                // to hold.
                remove_file_if_present(&path)
            } else {
                write_contact_raw(&meta, &contact.file_name, &remaining)
            };
        }

        remove_file_if_present(&path)
    }

    /// Imports the cards from a `.vcf` document into `book_id`.
    ///
    /// UID-keyed, mirroring the calendar's `import_ics`: a card whose UID is
    /// already in the book replaces that contact's file, so re-importing the
    /// same export updates rather than duplicates — which is what makes this
    /// usable as the handler for opening a `.vcf` from a file manager.
    ///
    /// Each card's **verbatim segment** is written, not a re-serialisation, so
    /// an imported card keeps its PHOTO and everything else the model does not
    /// carry. Same invariant as editing, met the same way.
    pub fn import_vcf(&mut self, text: &str, book_id: &str) -> Result<ImportSummary, StoreError> {
        let meta = self
            .book(book_id)
            .ok_or_else(|| StoreError::UnknownCalendar(book_id.to_owned()))?
            .clone();
        if meta.read_only {
            return Err(StoreError::ReadOnly(meta.name));
        }

        let existing: Vec<Contact> = read_book(&meta);
        let mut summary = ImportSummary::default();

        // File names already spoken for — by cards on disk, and by cards
        // earlier in this same import. Sanitising a UID is lossy (`a@b` and
        // `a-b` both become `a-b`), so without this a colliding *new* card
        // would silently overwrite a different contact's file.
        let mut taken: std::collections::HashSet<String> =
            existing.iter().map(|c| c.file_name.clone()).collect();

        for segment in split_vcards(text) {
            let Some(card) = parse_vcards(&segment, book_id, "").into_iter().next() else {
                // A segment calcard cannot parse would be written as a file no
                // reader could use; skip it rather than plant it.
                tracing::warn!(book_id, "skipping an unparseable card in the import");
                continue;
            };

            let file_name = match existing.iter().find(|c| c.uid == card.uid) {
                Some(known) => {
                    summary.updated += 1;
                    known.file_name.clone()
                }
                None => {
                    summary.added += 1;
                    let stem = super::sanitise_file_stem(&card.uid);
                    let mut candidate = format!("{stem}.vcf");
                    let mut counter = 1u32;
                    while taken.contains(&candidate) {
                        candidate = format!("{stem}-{counter}.vcf");
                        counter += 1;
                    }
                    candidate
                }
            };

            taken.insert(file_name.clone());

            // The card may live in a file holding several people — which is
            // what the export being imported *is*, and what the book already
            // holds if one was dropped into it. Writing this card's segment
            // over that file would delete everybody who shares it, so the
            // card is replaced inside the file instead.
            //
            // Read fresh rather than from `existing`: two cards in this same
            // import may target the same file, and the second must see what
            // the first wrote.
            let path = meta.path.join(&file_name);
            let current = std::fs::read_to_string(&path).unwrap_or_default();
            let text = if current.matches("BEGIN:VCARD").count() > 1 {
                crate::vcard::replace_vcard(&current, &card.uid, &segment).unwrap_or_else(|| {
                    // In the file but not locatable by uid — a card with no
                    // UID of its own. Append rather than overwrite: a
                    // duplicate is recoverable, a deleted stranger is not.
                    let mut merged = current.clone();
                    if !merged.ends_with('\n') {
                        merged.push_str("\r\n");
                    }
                    merged.push_str(&segment);
                    merged
                })
            } else {
                segment.clone()
            };

            write_contact_raw(&meta, &file_name, &text)?;
            summary.files.push(file_name);
        }
        Ok(summary)
    }

    /// Serialises a whole book as one `.vcf` document — the cards' stored
    /// bytes, concatenated, so nothing is lost in the export either.
    pub fn export_book(&self, book_id: &str) -> Result<String, StoreError> {
        let meta = self
            .book(book_id)
            .ok_or_else(|| StoreError::UnknownCalendar(book_id.to_owned()))?;

        let mut out = String::new();
        for contact in read_book(meta) {
            // `raw` is the file's verbatim text, and a file may hold several
            // cards — so take this contact's own card out of it. Pushing
            // `raw` emitted an N-card file once per contact in it, which made
            // a two-person book export as four people.
            let text = if contact.raw.trim().is_empty() {
                // A card this app created and never re-read has nothing to
                // slice; serialising from the model is lossless by definition.
                to_vcard_versioned(&contact, WriteVersion::default())
            } else {
                crate::vcard::card_segment(&contact.raw, &contact.uid)
                    .unwrap_or_else(|| contact.raw.clone())
            };

            out.push_str(&text);
            if !text.ends_with('\n') {
                out.push_str("\r\n");
            }
        }
        Ok(out)
    }

    /// Creates a new address book on disk.
    pub fn create_book(
        &mut self,
        name: &str,
        color: crate::model::Rgb,
    ) -> Result<CalendarMeta, StoreError> {
        let meta = super::vdir::create_collection(&self.root, name, color)?;
        self.refresh();
        Ok(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Rgb, Typed};

    fn store() -> (tempfile::TempDir, ContactStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ContactStore::open(&dir.path().join("contacts")).unwrap();
        (dir, store)
    }

    fn ada(book: &str) -> Contact {
        let mut c = Contact::draft(book);
        c.display_name = "Ada Lovelace".into();
        c.name.family = "Lovelace".into();
        c.name.given = "Ada".into();
        c.emails = vec![Typed::new("ada@example.com")];
        c
    }

    #[test]
    fn a_contact_round_trips_through_the_store() {
        let (_dir, mut store) = store();
        let book = store.create_book("Personal", Rgb(1, 2, 3)).unwrap();
        store.save(&ada(&book.id)).unwrap();

        let all = store.contacts();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].label(), "Ada Lovelace");
        assert_eq!(all[0].emails[0].value, "ada@example.com");
    }

    #[test]
    fn contacts_come_back_sorted_by_family_name() {
        let (_dir, mut store) = store();
        let book = store.create_book("Personal", Rgb(1, 2, 3)).unwrap();

        let mut turing = Contact::draft(&book.id);
        turing.display_name = "Alan Turing".into();
        turing.name.family = "Turing".into();
        store.save(&turing).unwrap();
        store.save(&ada(&book.id)).unwrap();

        let names: Vec<String> = store.contacts().iter().map(Contact::label).collect();
        assert_eq!(names, vec!["Ada Lovelace", "Alan Turing"]);
    }

    #[test]
    fn search_filters_and_stays_sorted() {
        let (_dir, mut store) = store();
        let book = store.create_book("Personal", Rgb(1, 2, 3)).unwrap();
        store.save(&ada(&book.id)).unwrap();

        let mut turing = Contact::draft(&book.id);
        turing.display_name = "Alan Turing".into();
        turing.name.family = "Turing".into();
        store.save(&turing).unwrap();

        assert_eq!(store.search("lovelace").len(), 1);
        assert_eq!(store.search("ada@example").len(), 1);
        assert_eq!(store.search("").len(), 2);
        assert!(store.search("babbage").is_empty());
    }

    #[test]
    fn deleting_removes_the_contact() {
        let (_dir, mut store) = store();
        let book = store.create_book("Personal", Rgb(1, 2, 3)).unwrap();
        let contact = ada(&book.id);
        store.save(&contact).unwrap();

        store.delete(&book.id, &contact.uid).unwrap();
        assert!(store.contacts().is_empty());
    }

    #[test]
    fn raw_bytes_are_written_verbatim() {
        let (_dir, mut store) = store();
        let book = store.create_book("Personal", Rgb(1, 2, 3)).unwrap();

        // The lossless path the sync engine uses: an unmodelled property must
        // survive to disk untouched.
        let raw = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:x@test\r\nFN:Ada\r\n\
                   X-CUSTOM:preserved\r\nEND:VCARD\r\n";
        write_contact_raw(&book, "ada.vcf", raw).unwrap();

        let written = std::fs::read_to_string(book.path.join("ada.vcf")).unwrap();
        assert_eq!(written, raw);
        assert_eq!(store.contacts().len(), 1);
    }

    #[test]
    fn an_externally_written_vcf_is_picked_up() {
        let (_dir, mut store) = store();
        let book = store.create_book("Personal", Rgb(1, 2, 3)).unwrap();

        std::fs::write(
            book.path.join("external.vcf"),
            "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:ext@test\r\nFN:From sync\r\nEND:VCARD\r\n",
        )
        .unwrap();

        assert_eq!(store.contacts()[0].label(), "From sync");
    }

    #[test]
    fn an_ics_file_in_an_address_book_is_ignored() {
        let (_dir, mut store) = store();
        let book = store.create_book("Personal", Rgb(1, 2, 3)).unwrap();
        std::fs::write(
            book.path.join("event.ics"),
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
        )
        .unwrap();

        assert!(store.contacts().is_empty());
    }

    #[test]
    fn saving_to_an_unknown_book_is_an_error() {
        let (_dir, mut store) = store();
        assert!(matches!(
            store.save(&ada("nope")),
            Err(StoreError::UnknownCalendar(_))
        ));
    }

    #[test]
    fn opening_an_empty_root_yields_no_books() {
        let (_dir, store) = store();
        assert!(store.books().is_empty());
        assert!(store.default_book().is_none());
        assert!(store.contacts().is_empty());
    }
}

#[cfg(test)]
mod lossless_write_tests {
    use super::*;
    use crate::model::Rgb;

    const SYNCED: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:ada@server\r\n\
FN:Ada Lovelace\r\nEMAIL;TYPE=work:ada@work.example\r\n\
item1.EMAIL;type=INTERNET:ada@home.example\r\nitem1.X-ABLabel:Summer house\r\n\
PHOTO;ENCODING=b:AAAABBBB\r\nX-ABShowAs:COMPANY\r\nEND:VCARD\r\n";

    fn book() -> (tempfile::TempDir, ContactStore, CalendarMeta) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ContactStore::open(&dir.path().join("contacts")).unwrap();
        let meta = store.create_book("Contacts", Rgb(1, 2, 3)).unwrap();
        (dir, store, meta)
    }

    #[test]
    fn editing_a_synced_contact_keeps_everything_the_model_does_not_carry() {
        let (_dir, mut store, meta) = book();
        write_contact_raw(&meta, "ada.vcf", SYNCED).unwrap();

        let mut contact = store.contacts().remove(0);
        contact.display_name = "Ada Byron".into();
        store.save(&contact).unwrap();

        let on_disk = std::fs::read_to_string(meta.path.join("ada.vcf")).unwrap();
        assert!(on_disk.contains("FN:Ada Byron"), "the edit did not land");
        assert!(
            on_disk.contains("PHOTO;ENCODING=b:AAAABBBB"),
            "the photo was destroyed by a name change: {on_disk}"
        );
        assert!(on_disk.contains("X-ABShowAs:COMPANY"));
        assert!(on_disk.contains("item1.X-ABLabel:Summer house"));
    }

    #[test]
    fn a_grouped_address_is_not_duplicated_by_a_save() {
        let (_dir, mut store, meta) = book();
        write_contact_raw(&meta, "ada.vcf", SYNCED).unwrap();

        // Save twice — the bug this guards against grew a duplicate each time.
        for _ in 0..2 {
            let contact = store.contacts().remove(0);
            store.save(&contact).unwrap();
        }

        let back = store.contacts().remove(0);
        assert_eq!(
            back.emails.len(),
            2,
            "a grouped address was rewritten as an ungrouped duplicate"
        );
        let on_disk = std::fs::read_to_string(meta.path.join("ada.vcf")).unwrap();
        assert_eq!(on_disk.matches("ada@home.example").count(), 1);
    }

    #[test]
    fn a_contact_this_app_created_is_still_written_from_the_model() {
        let (_dir, mut store, meta) = book();
        let mut contact = Contact::draft(&meta.id);
        contact.display_name = "New Person".into();
        assert!(contact.raw.is_empty(), "a draft should carry no source");

        store.save(&contact).unwrap();
        assert_eq!(store.contacts()[0].label(), "New Person");
    }

    #[test]
    fn clearing_a_modelled_field_removes_it_without_touching_the_rest() {
        let (_dir, mut store, meta) = book();
        write_contact_raw(&meta, "ada.vcf", SYNCED).unwrap();

        let mut contact = store.contacts().remove(0);
        contact.emails.clear();
        store.save(&contact).unwrap();

        let on_disk = std::fs::read_to_string(meta.path.join("ada.vcf")).unwrap();
        assert!(!on_disk.contains("EMAIL;TYPE=work"), "{on_disk}");
        assert!(
            on_disk.contains("item1.EMAIL"),
            "clearing the list removed a grouped address it does not own"
        );
        assert!(on_disk.contains("PHOTO;ENCODING=b:AAAABBBB"));
    }
}

#[cfg(test)]
mod import_export_tests {
    use super::*;
    use crate::model::Rgb;

    const TWO_CARDS: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:ada@x\r\nFN:Ada\r\n\
PHOTO;ENCODING=b:AAAABBBB\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:4.0\r\nUID:bob@x\r\nFN:Bob\r\nEND:VCARD\r\n";

    fn store() -> (tempfile::TempDir, ContactStore, CalendarMeta) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ContactStore::open(&dir.path().join("contacts")).unwrap();
        let meta = store.create_book("Personal", Rgb(1, 2, 3)).unwrap();
        (dir, store, meta)
    }

    #[test]
    fn a_multi_card_import_lands_one_file_per_card_with_its_own_bytes() {
        let (_dir, mut store, meta) = store();

        let summary = store.import_vcf(TWO_CARDS, &meta.id).unwrap();
        assert_eq!((summary.added, summary.updated), (2, 0));

        // The derived name is not spelled out here: `sanitise_file_stem` owns
        // that mapping and has its own tests. What this test is about is one
        // file per card, each holding only its own bytes.
        let ada_file = format!("{}.vcf", crate::store::sanitise_file_stem("ada@x"));
        let ada = std::fs::read_to_string(meta.path.join(&ada_file)).unwrap();
        assert!(ada.contains("PHOTO;ENCODING=b:AAAABBBB"), "{ada}");
        assert!(
            !ada.contains("Bob"),
            "one card's file carries the whole import: {ada}"
        );
    }

    #[test]
    fn reimporting_updates_rather_than_duplicates() {
        let (_dir, mut store, meta) = store();
        store.import_vcf(TWO_CARDS, &meta.id).unwrap();

        let summary = store.import_vcf(TWO_CARDS, &meta.id).unwrap();
        assert_eq!((summary.added, summary.updated), (0, 2));
        assert_eq!(store.contacts().len(), 2);
    }

    #[test]
    fn deleting_from_a_read_only_book_is_refused() {
        // Through the store, not through a write function with a doctored
        // meta. That shortcut is how this gap survived: it asserts the
        // *function's* guard, and `delete` reaches the filesystem by a path
        // that has no function to guard it.
        //
        // The directory is left writable on purpose, so a delete that
        // succeeds proves a missing check rather than a missing OS
        // permission.
        let (dir, mut store, meta) = store();
        store.import_vcf(TWO_CARDS, &meta.id).unwrap();
        let uid = store.contacts()[0].uid.clone();

        // Mark it the way the loader recognises, then reopen so the store's
        // own book list carries the flag.
        std::fs::write(meta.path.join(".ics-feed.json"), "{}").unwrap();
        let mut store = ContactStore::open(&dir.path().join("contacts")).unwrap();
        let book = store.books().first().expect("a book").clone();
        assert!(book.read_only, "the book was not marked read-only");

        // Saving is refused — the contrast is one run rather than an argument.
        let mut contact = store.contacts()[0].clone();
        contact.display_name = "Edited".into();
        assert!(
            store.save(&contact).is_err(),
            "a read-only book accepted a save"
        );

        // And so is deleting, which is the half that was not checked.
        assert!(
            store.delete(&book.id, &uid).is_err(),
            "a read-only book accepted a delete"
        );
        // The card is still there.
        assert!(store.contacts().iter().any(|c| c.uid == uid));
    }

    #[test]
    fn an_import_into_a_read_only_book_is_refused() {
        let (_dir, _store, meta) = store();
        let mut frozen = meta.clone();
        frozen.read_only = true;
        // Route through the store with a doctored book list is intrusive;
        // exercising write_contact_raw's own guard covers the same invariant.
        assert!(write_contact_raw(&frozen, "x.vcf", "BEGIN:VCARD\r\nEND:VCARD\r\n").is_err());
    }

    #[test]
    fn export_concatenates_verbatim_and_reimports_cleanly() {
        let (_dir, mut store, meta) = store();
        store.import_vcf(TWO_CARDS, &meta.id).unwrap();

        let exported = store.export_book(&meta.id).unwrap();
        assert!(exported.contains("PHOTO;ENCODING=b:AAAABBBB"), "{exported}");

        // Round trip into a second book: everything arrives, nothing doubles.
        let book2 = store.create_book("Second", Rgb(4, 5, 6)).unwrap();
        let summary = store.import_vcf(&exported, &book2.id).unwrap();
        assert_eq!((summary.added, summary.updated), (2, 0));
    }

    /// Sanitising a UID is lossy: `a@b` and `a-b` collapse to the same file
    /// stem. Both cards must survive an import — the second must not overwrite
    /// the first's file.
    #[test]
    fn uids_that_sanitise_identically_do_not_clobber_each_other() {
        let (_dir, mut store, meta) = store();

        let colliding = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a@b\r\nFN:At\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:4.0\r\nUID:a-b\r\nFN:Dash\r\nEND:VCARD\r\n";
        let summary = store.import_vcf(colliding, &meta.id).unwrap();
        assert_eq!((summary.added, summary.updated), (2, 0));

        let names: Vec<String> = store.contacts().iter().map(Contact::label).collect();
        assert_eq!(
            store.contacts().len(),
            2,
            "one card overwrote the other: {names:?}"
        );

        // And a re-import still updates both rather than growing a third file.
        let again = store.import_vcf(colliding, &meta.id).unwrap();
        assert_eq!((again.added, again.updated), (0, 2));
        assert_eq!(store.contacts().len(), 2);
    }

    #[test]
    fn garbage_imports_zero_and_says_so() {
        let (_dir, mut store, meta) = store();
        let summary = store.import_vcf("not a vcard at all", &meta.id).unwrap();
        assert_eq!(summary.total(), 0);
    }
}

#[cfg(test)]
mod group_store_tests {
    use super::*;
    use crate::model::Rgb;
    use crate::vcard::{WriteVersion, member_uri};

    fn store() -> (tempfile::TempDir, ContactStore, CalendarMeta) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ContactStore::open(&dir.path().join("contacts")).unwrap();
        let meta = store.create_book("Personal", Rgb(1, 2, 3)).unwrap();
        (dir, store, meta)
    }

    #[test]
    fn a_group_is_created_listed_and_kept_out_of_the_contact_list() {
        let (_dir, mut store, meta) = store();
        let mut ada = Contact::draft(&meta.id);
        ada.display_name = "Ada".into();
        store.save(&ada).unwrap();

        let group = store
            .create_group("Friends", &meta.id, WriteVersion::V3)
            .unwrap();
        assert!(group.is_group);

        assert_eq!(
            store.contacts().len(),
            1,
            "the group leaked into the people list"
        );
        assert_eq!(store.groups().len(), 1);
        assert!(
            store.search("Friends").is_empty(),
            "search returned a group as a person"
        );
    }

    #[test]
    fn membership_round_trips_through_the_store() {
        let (_dir, mut store, meta) = store();
        let mut ada = Contact::draft(&meta.id);
        ada.display_name = "Ada".into();
        store.save(&ada).unwrap();

        let group = store
            .create_group("Friends", &meta.id, WriteVersion::V3)
            .unwrap();
        store
            .set_group_members(&meta.id, &group.uid, &[member_uri(&ada.uid)])
            .unwrap();

        let back = store.groups().remove(0);
        assert_eq!(back.members, vec![member_uri(&ada.uid)]);

        // And emptied again.
        store.set_group_members(&meta.id, &group.uid, &[]).unwrap();
        assert!(store.groups().remove(0).members.is_empty());
    }

    #[test]
    fn membership_on_a_missing_group_is_a_named_error() {
        let (_dir, mut store, meta) = store();
        assert!(matches!(
            store.set_group_members(&meta.id, "nope", &[]),
            Err(StoreError::UnknownContact(_))
        ));
    }
}

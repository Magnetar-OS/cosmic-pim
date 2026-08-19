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

use super::StoreError;
use crate::model::{CalendarMeta, Contact};
use crate::vcard::{parse_vcards, to_vcard};

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

/// Writes a contact, atomically.
///
/// **Lossy for a synced contact.** [`to_vcard`] serialises only the modelled
/// fields, so a contact that came from a server loses its PHOTO and every other
/// property this crate does not represent. Callers must not use this to save an
/// edit to a synced contact until a vCard patcher exists — see
/// [`crate::vcard`].
pub fn write_contact(meta: &CalendarMeta, contact: &Contact) -> Result<(), StoreError> {
    if meta.read_only {
        return Err(StoreError::ReadOnly(meta.name.clone()));
    }
    crate::atomic::write(&meta.path.join(&contact.file_name), &to_vcard(contact), None)
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

    /// Every contact, sorted for display.
    #[must_use]
    pub fn contacts(&self) -> Vec<Contact> {
        let mut out: Vec<Contact> = self.books.iter().flat_map(read_book).collect();
        out.sort_by_key(Contact::sort_key);
        out
    }

    /// Contacts matching a search string, sorted.
    #[must_use]
    pub fn search(&self, needle: &str) -> Vec<Contact> {
        let mut out: Vec<Contact> = self
            .books
            .iter()
            .flat_map(read_book)
            .filter(|c| c.matches(needle))
            .collect();
        out.sort_by_key(Contact::sort_key);
        out
    }

    #[must_use]
    pub fn contact(&self, book_id: &str, uid: &str) -> Option<Contact> {
        let meta = self.book(book_id)?;
        read_book(meta).into_iter().find(|c| c.uid == uid)
    }

    pub fn save(&mut self, contact: &Contact) -> Result<(), StoreError> {
        let meta = self
            .book(&contact.addressbook_id)
            .ok_or_else(|| StoreError::UnknownCalendar(contact.addressbook_id.clone()))?
            .clone();
        write_contact(&meta, contact)
    }

    pub fn delete(&mut self, book_id: &str, uid: &str) -> Result<(), StoreError> {
        let meta = self
            .book(book_id)
            .ok_or_else(|| StoreError::UnknownCalendar(book_id.to_owned()))?
            .clone();

        if let Some(contact) = read_book(&meta).into_iter().find(|c| c.uid == uid) {
            match std::fs::remove_file(meta.path.join(&contact.file_name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
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
        std::fs::write(book.path.join("event.ics"), "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n")
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

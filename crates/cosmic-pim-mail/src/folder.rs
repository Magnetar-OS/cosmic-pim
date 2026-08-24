// SPDX-License-Identifier: MPL-2.0
//
// The modified-UTF-7 codecs and the special-use detection are ported from
// `src-tauri/src/mail_sync.rs` in the Meltemi project. See NOTICE and
// LICENSING.md.

//! Mailbox names, hierarchy, and RFC 6154 special use.
//!
//! # Three spellings of one name
//!
//! A mailbox called `Wichtig` in German, or anything at all in Greek, has three
//! representations and confusing them is a whole class of bug:
//!
//! - the **wire name**, modified UTF-7 as RFC 3501 §5.1.3 defines it — this is
//!   what SELECT takes and what LIST returns;
//! - the **display name**, the decoded UTF-8 a person reads;
//! - the **local name**, what the maildir directory is called.
//!
//! [`Folder`] holds all three and they are not interchangeable. Selecting a
//! mailbox by its display name silently fails on every server for every
//! non-ASCII folder, which presents as "my folders are empty" for everyone
//! outside the English-speaking world and for nobody testing in it.
//!
//! # Special use
//!
//! RFC 6154 lets a server *declare* which mailbox is Sent, Trash, Junk, and so
//! on. Where it does, that declaration is used; where it does not — and plenty
//! of servers do not — the name is matched against the handful of spellings
//! that are actually in use. Guessing is worse than asking, but not guessing at
//! all means the app cannot file a sent message.

use base64::Engine as _;

/// A mailbox with a defined role, per RFC 6154 plus `Inbox`.
///
/// `Inbox` is not an RFC 6154 attribute — INBOX is special in RFC 3501 itself,
/// case-insensitively — but every consumer wants it in the same enum.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum SpecialUse {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Junk,
    Archive,
}

impl SpecialUse {
    /// Sort key for the folder list: the roles people use most, in the order
    /// every mail client has shown them for thirty years.
    #[must_use]
    pub fn order(self) -> u8 {
        match self {
            Self::Inbox => 0,
            Self::Drafts => 1,
            Self::Sent => 2,
            Self::Archive => 3,
            Self::Junk => 4,
            Self::Trash => 5,
        }
    }
}

/// One mailbox as the server listed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// The wire name — modified UTF-7, exactly as LIST returned it. **This is
    /// what SELECT takes.**
    pub wire_name: String,
    /// The decoded name, for display.
    pub display_name: String,
    /// The hierarchy delimiter the server reported, e.g. `/` or `.`.
    ///
    /// Not a constant: Courier uses `.`, Dovecot's maildir++ layout uses `.`,
    /// Dovecot's `Maildir` layout uses `/`, and Exchange uses `/`. Splitting a
    /// path on the wrong one produces a flat list of folders with slashes in
    /// their names.
    pub delimiter: char,
    pub special_use: Option<SpecialUse>,
    /// The server said this mailbox cannot be selected — it exists only to hold
    /// children. Trying to SELECT it is an error, not an empty mailbox.
    pub no_select: bool,
}

impl Folder {
    /// The path segments of the display name, split on this server's delimiter.
    #[must_use]
    pub fn path(&self) -> Vec<&str> {
        self.display_name.split(self.delimiter).collect()
    }

    /// How deep this mailbox is nested. INBOX is 0.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.path().len().saturating_sub(1)
    }

    /// The last path segment — what a tree view puts on the row.
    #[must_use]
    pub fn leaf_name(&self) -> &str {
        self.path().last().copied().unwrap_or(&self.display_name)
    }

    /// A filesystem-safe directory name for this mailbox's maildir.
    ///
    /// The wire name is used rather than the display name so the mapping is
    /// stable: a display name depends on our decoder, and a decoder change
    /// would orphan every message on disk. Path separators and anything that
    /// cannot appear in a filename are percent-escaped; the result is
    /// reversible, which matters because a maildir directory has to be
    /// matchable back to the mailbox it mirrors.
    #[must_use]
    pub fn local_name(&self) -> String {
        let mut out = String::with_capacity(self.wire_name.len());
        for byte in self.wire_name.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'+' | b'&' | b',' => {
                    out.push(char::from(byte));
                }
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    }
}

/// Builds a [`Folder`] from one LIST response line.
#[must_use]
pub fn from_list_entry(
    wire_name: &str,
    delimiter: Option<char>,
    attributes: &[imap_proto::NameAttribute<'_>],
) -> Folder {
    use imap_proto::NameAttribute as A;
    Folder {
        display_name: decode_modified_utf7(wire_name),
        wire_name: wire_name.to_owned(),
        // A server that reports no delimiter has a flat namespace. `/` is a
        // harmless stand-in there: nothing contains it, so nothing splits.
        delimiter: delimiter.unwrap_or('/'),
        special_use: detect_special_use(attributes, wire_name),
        no_select: attributes.iter().any(|a| matches!(a, A::NoSelect)),
    }
}

/// RFC 6154 special use from LIST attributes, falling back to name heuristics.
#[must_use]
pub fn detect_special_use(
    attributes: &[imap_proto::NameAttribute<'_>],
    wire_name: &str,
) -> Option<SpecialUse> {
    use imap_proto::NameAttribute as A;
    // INBOX is defined by RFC 3501 to be case-insensitive and is never
    // attributed, so it is checked before anything else.
    if wire_name.eq_ignore_ascii_case("inbox") {
        return Some(SpecialUse::Inbox);
    }
    for attribute in attributes {
        match attribute {
            A::Sent => return Some(SpecialUse::Sent),
            A::Trash => return Some(SpecialUse::Trash),
            A::Junk => return Some(SpecialUse::Junk),
            A::Drafts => return Some(SpecialUse::Drafts),
            A::Archive | A::All => return Some(SpecialUse::Archive),
            _ => {}
        }
    }
    // Heuristics on the leaf segment only. `Work/Archive` is an archive;
    // `Archive/Work` is not.
    let lower = decode_modified_utf7(wire_name).to_lowercase();
    let leaf = lower.rsplit(['/', '.']).next().unwrap_or(&lower);
    match leaf {
        "inbox" => Some(SpecialUse::Inbox),
        "sent" | "sent messages" | "sent items" | "sent mail" => Some(SpecialUse::Sent),
        "trash" | "deleted" | "deleted items" | "deleted messages" | "bin" => {
            Some(SpecialUse::Trash)
        }
        "junk" | "spam" | "junk e-mail" | "bulk mail" => Some(SpecialUse::Junk),
        "archive" | "archives" | "all mail" => Some(SpecialUse::Archive),
        "drafts" | "draft" => Some(SpecialUse::Drafts),
        _ => None,
    }
}

/// Orders a folder list the way a person expects to see it: the special-use
/// mailboxes first in their conventional order, then everything else
/// alphabetically, with children directly under their parents.
pub fn sort_for_display(folders: &mut [Folder]) {
    folders.sort_by(|a, b| {
        let rank = |f: &Folder| f.special_use.map_or(u8::MAX, SpecialUse::order);
        rank(a).cmp(&rank(b)).then_with(|| {
            a.display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase())
        })
    });
}

/// Modified UTF-7 (RFC 3501 §5.1.3) → UTF-8, for display.
///
/// `&` opens a base64 run using `,` for `/`; `&-` is a literal `&`. A malformed
/// run falls back to reproducing the raw text — a display glitch, never an
/// error that stops folder discovery, because one server quirk must not make
/// the whole mailbox list unavailable.
#[must_use]
pub fn decode_modified_utf7(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        let mut run = String::new();
        let mut terminated = false;
        for r in chars.by_ref() {
            if r == '-' {
                terminated = true;
                break;
            }
            run.push(r);
        }
        if run.is_empty() {
            // "&-" is a literal ampersand; so is an unterminated bare "&".
            out.push('&');
            continue;
        }
        let b64: String = run.replace(',', "/");
        let padded = match b64.len() % 4 {
            0 => b64,
            n => format!("{}{}", b64, "=".repeat(4 - n)),
        };
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(padded)
            .ok()
            .filter(|bytes| bytes.len() % 2 == 0)
            .map(|bytes| {
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_be_bytes(*pair))
                    .collect();
                String::from_utf16_lossy(&units)
            });
        match decoded {
            Some(text) if terminated => out.push_str(&text),
            _ => {
                out.push('&');
                out.push_str(&run);
                if terminated {
                    out.push('-');
                }
            }
        }
    }
    out
}

/// UTF-8 → modified UTF-7, for a mailbox the app is about to CREATE or RENAME.
///
/// Discovery only ever needs the decode direction, since every wire name
/// arrives from the server. Creating a folder is the first time the client has
/// to spell one itself, and a name with a non-ASCII character in it — which is
/// most names, in most languages — is otherwise sent as raw UTF-8 and either
/// rejected or stored mangled.
#[must_use]
pub fn encode_modified_utf7(s: &str) -> String {
    fn flush(run: &mut Vec<u16>, out: &mut String) {
        if run.is_empty() {
            return;
        }
        let bytes: Vec<u8> = run.iter().flat_map(|u| u.to_be_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        out.push('&');
        out.push_str(&b64.replace('/', ","));
        out.push('-');
        run.clear();
    }
    let mut out = String::with_capacity(s.len());
    let mut run: Vec<u16> = Vec::new();
    for c in s.chars() {
        if c == '&' {
            flush(&mut run, &mut out);
            out.push_str("&-");
        } else if ('\u{20}'..='\u{7e}').contains(&c) {
            flush(&mut run, &mut out);
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            run.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use imap_proto::NameAttribute as A;

    #[test]
    fn modified_utf7_round_trips_the_names_that_break_naive_clients() {
        for (utf8, wire) in [
            ("Inbox", "Inbox"),
            ("Wichtig", "Wichtig"),
            ("Παραλήπτες", "&A6ADsQPBA7EDuwOuA8ADxAO1A8I-"),
            ("受信箱", "&U9dP4Xux-"),
            ("R&D", "R&-D"),
            ("Ünread/Später", "&ANw-nread/Sp&AOQ-ter"),
        ] {
            assert_eq!(encode_modified_utf7(utf8), wire, "encoding {utf8:?}");
            assert_eq!(decode_modified_utf7(wire), utf8, "decoding {wire:?}");
        }
    }

    #[test]
    fn a_malformed_run_degrades_to_raw_text_rather_than_failing() {
        // One server quirk must not take the whole folder list with it.
        assert_eq!(decode_modified_utf7("&not-base64-!!-"), "&not-base64-!!-");
        assert_eq!(decode_modified_utf7("trailing&"), "trailing&");
    }

    #[test]
    fn the_server_declaration_beats_the_name_heuristic() {
        let folder = from_list_entry("Papierkorb", Some('/'), &[A::Trash]);
        assert_eq!(folder.special_use, Some(SpecialUse::Trash));
        assert_eq!(folder.display_name, "Papierkorb");
    }

    #[test]
    fn names_are_matched_when_the_server_declares_nothing() {
        for (name, expected) in [
            ("Sent Items", SpecialUse::Sent),
            ("INBOX/Drafts", SpecialUse::Drafts),
            ("[Gmail]/All Mail", SpecialUse::Archive),
            ("Junk E-mail", SpecialUse::Junk),
        ] {
            assert_eq!(
                from_list_entry(name, Some('/'), &[]).special_use,
                Some(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn inbox_is_recognised_whatever_its_case() {
        for name in ["INBOX", "Inbox", "inbox"] {
            assert_eq!(
                from_list_entry(name, Some('/'), &[]).special_use,
                Some(SpecialUse::Inbox)
            );
        }
    }

    #[test]
    fn only_the_leaf_segment_names_a_role() {
        // `Archive/Work` is a folder inside the archive, not the archive.
        assert_eq!(
            from_list_entry("Archive/Work", Some('/'), &[]).special_use,
            None
        );
        assert_eq!(
            from_list_entry("Work/Archive", Some('/'), &[]).special_use,
            Some(SpecialUse::Archive)
        );
    }

    #[test]
    fn the_servers_delimiter_is_used_not_a_hardcoded_slash() {
        // Courier and maildir++ use '.', and splitting those on '/' produces
        // one folder with dots in its name instead of a tree.
        let folder = from_list_entry("INBOX.Projects.Alpha", Some('.'), &[]);
        assert_eq!(folder.path(), vec!["INBOX", "Projects", "Alpha"]);
        assert_eq!(folder.leaf_name(), "Alpha");
        assert_eq!(folder.depth(), 2);
    }

    #[test]
    fn a_noselect_placeholder_is_marked_rather_than_looking_empty() {
        let folder = from_list_entry("Archive", Some('/'), &[A::NoSelect]);
        assert!(
            folder.no_select,
            "SELECTing this is an error, not an empty mailbox"
        );
    }

    #[test]
    fn local_names_are_filesystem_safe_and_derived_from_the_wire_name() {
        // Derived from the wire name so a change to our decoder cannot orphan
        // messages already on disk.
        let folder = from_list_entry("INBOX.Παραλήπτες", Some('.'), &[]);
        let local = folder.local_name();
        assert!(!local.contains('.'), "a path separator survived: {local}");
        assert!(!local.contains('/'));
        assert!(local.starts_with("INBOX"));
    }

    #[test]
    fn display_order_puts_the_standard_mailboxes_first() {
        let mut folders = vec![
            from_list_entry("Work", Some('/'), &[]),
            from_list_entry("Trash", Some('/'), &[]),
            from_list_entry("INBOX", Some('/'), &[]),
            from_list_entry("Archive", Some('/'), &[]),
            from_list_entry("Aardvark", Some('/'), &[]),
        ];
        sort_for_display(&mut folders);
        let names: Vec<&str> = folders.iter().map(|f| f.display_name.as_str()).collect();
        assert_eq!(names, ["INBOX", "Archive", "Trash", "Aardvark", "Work"]);
    }
}

// SPDX-License-Identifier: MPL-2.0
//
// The filename sanitiser and the collision-suffixing rule are ported from
// `src-tauri/src/attachments.rs` in the Meltemi project. See NOTICE and
// LICENSING.md.

//! Getting attachments out of a message, and safely onto a disk.
//!
//! # The bytes stay in the message
//!
//! [`crate::model::Attachment`] describes a part — name, type, size — and does
//! not carry it. That is what keeps a list view from holding every attachment
//! of every message in memory to draw a paperclip. The bytes are extracted on
//! demand, from the file, by [`bytes_of`].
//!
//! # A filename in a message is attacker-controlled
//!
//! It is a string a stranger chose, and it is about to be joined to a path.
//! `../../.bashrc`, `CON.txt`, a name that is 4 KB of Unicode, a name that is
//! only dots — all of these arrive in real mail, and none of them are hard to
//! send. [`sanitize`] is not politeness; it is the boundary between a message
//! and a filesystem.
//!
//! The rules are deliberately stricter than Linux needs, because a saved file
//! travels: onto a USB stick, into a shared folder, into a Windows VM. A name
//! Linux accepts and Windows cannot create is a file the user loses later,
//! somewhere confusing.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::Message;

/// The bytes of one attachment, read out of the message.
///
/// `index` is the position in [`crate::model::Message::attachments`], which is
/// the order `mail_parser` walks the MIME tree — stable for a given message,
/// because the message never changes.
pub fn bytes_of(raw: &[u8], index: usize) -> Result<Vec<u8>> {
    let parsed = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| Error::Draft("that message could not be read".into()))?;

    parsed
        .attachments()
        .nth(index)
        .map(|part| part.contents().to_vec())
        .ok_or_else(|| Error::Draft("that attachment is not in the message".into()))
}

/// Saves one attachment into `folder`, without overwriting anything.
///
/// Returns where it landed, which is not necessarily `<folder>/<name>`: the
/// name is sanitised, and a collision gets a counter. Telling the caller the
/// real path is the point — "Saved to Downloads" is useless if the file is
/// actually `report (3).pdf`.
pub fn save_into(folder: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    std::fs::create_dir_all(folder)?;
    let destination = collision_free_path(folder, &sanitize(name))?;
    // Through the substrate's writer: a crash or a full disk must not leave a
    // truncated file that looks like a whole one.
    cosmic_pim_core::atomic::write_bytes(&destination, bytes, None)?;
    Ok(destination)
}

/// Saves every non-inline attachment of a message.
///
/// Inline parts are skipped: they are the images the body refers to, and a
/// newsletter would otherwise deposit forty spacer GIFs in the user's
/// Downloads folder.
pub fn save_all(raw: &[u8], folder: &Path) -> Result<Vec<PathBuf>> {
    let Some(message) = Message::parse(raw) else {
        return Err(Error::Draft("that message could not be read".into()));
    };

    let mut saved = Vec::new();
    for (index, attachment) in message.attachments.iter().enumerate() {
        if attachment.inline {
            continue;
        }
        let bytes = bytes_of(raw, index)?;
        saved.push(save_into(folder, &attachment.name, &bytes)?);
    }
    Ok(saved)
}

/// Turns a filename from a message into one that is safe to create.
///
/// Path separators and the characters Windows forbids become `_`; control
/// characters go the same way. A name that is empty, or only dots, becomes
/// `attachment` — `.` and `..` are not filenames, and a leading dot would hide
/// the file from the user who just asked to save it. Windows device names get a
/// prefix, because `CON.txt` cannot be created on NTFS however it is spelled.
#[must_use]
pub fn sanitize(name: &str) -> String {
    const MAX: usize = 200;

    let mut out = String::with_capacity(name.len().min(MAX));
    for c in name.chars() {
        let unsafe_char =
            matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*') || (c as u32) < 0x20;
        out.push(if unsafe_char { '_' } else { c });
    }

    let trimmed = out.trim().trim_matches('.').to_string();
    if trimmed.is_empty() {
        return "attachment".to_string();
    }
    // Most filesystems cap a component at 255 bytes. Truncating by characters
    // keeps that safe for anything short of pathological, and keeps the
    // extension, which is what decides how the file opens.
    let capped = if trimmed.chars().count() > MAX {
        let (stem, extension) = split_extension(&trimmed);
        let keep: String = stem.chars().take(MAX - 16).collect();
        match extension {
            Some(extension) => format!("{keep}.{}", extension.chars().take(15).collect::<String>()),
            None => keep,
        }
    } else {
        trimmed
    };

    if is_windows_device(&capped) {
        return format!("_{capped}");
    }
    capped
}

/// Windows reserved device names, matched on the part before any extension —
/// these cannot be created on NTFS even with an extension attached.
fn is_windows_device(name: &str) -> bool {
    let (stem, _) = split_extension(name);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "NUL"
            | "AUX"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// `(stem, extension)`. `".hidden"` is all stem; a trailing dot has no
/// extension.
fn split_extension(name: &str) -> (&str, Option<&str>) {
    match name.rfind('.') {
        Some(0) | None => (name, None),
        Some(at) if at + 1 < name.len() => (&name[..at], Some(&name[at + 1..])),
        _ => (name, None),
    }
}

/// A destination that does not exist yet: `report.pdf` → `report (1).pdf`.
///
/// Never overwrites. Two messages from two people can perfectly well both
/// attach `invoice.pdf`, and the second one silently replacing the first is a
/// data loss the user has no way to notice.
fn collision_free_path(folder: &Path, name: &str) -> Result<PathBuf> {
    let candidate = folder.join(name);
    if !candidate.exists() {
        return Ok(candidate);
    }
    let (stem, extension) = split_extension(name);
    for n in 1..1000 {
        let next = match extension {
            Some(extension) => folder.join(format!("{stem} ({n}).{extension}")),
            None => folder.join(format!("{name} ({n})")),
        };
        if !next.exists() {
            return Ok(next);
        }
    }
    Err(Error::Draft(format!(
        "there are already a thousand files named {name} in {}",
        folder.display()
    )))
}

/// A content type guessed from a filename's extension.
///
/// For *outgoing* attachments only, where there is nothing else to go on. An
/// incoming part carries its own `Content-Type` and that is what is believed —
/// guessing over the top of what the sender declared would be inventing.
#[must_use]
pub fn mime_for(name: &str) -> &'static str {
    let (_, extension) = split_extension(name);
    match extension.map(str::to_ascii_lowercase).as_deref() {
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("txt" | "log" | "md") => "text/plain",
        Some("csv") => "text/csv",
        Some("html" | "htm") => "text/html",
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("zip") => "application/zip",
        Some("gz" | "tgz") => "application/gzip",
        Some("odt") => "application/vnd.oasis.opendocument.text",
        Some("ods") => "application/vnd.oasis.opendocument.spreadsheet",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xls") => "application/vnd.ms-excel",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("ics") => "text/calendar",
        Some("eml") => "message/rfc822",
        // The RFC 2046 default, and the honest answer: unknown bytes.
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const WITH_ATTACHMENT: &[u8] = b"From: a@example.com\r\n\
Subject: Here it is\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
See attached.\r\n\
--b\r\n\
Content-Type: text/csv; name=\"report.csv\"\r\n\
Content-Disposition: attachment; filename=\"report.csv\"\r\n\
\r\n\
a,b\r\n1,2\r\n\
--b--\r\n";

    #[test]
    fn attachment_bytes_come_out_of_the_message() {
        let message = Message::parse(WITH_ATTACHMENT).unwrap();
        assert_eq!(message.attachments.len(), 1);
        assert_eq!(message.attachments[0].name, "report.csv");

        let bytes = bytes_of(WITH_ATTACHMENT, 0).unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes).trim_end(), "a,b\r\n1,2");
    }

    #[test]
    fn asking_for_an_attachment_that_is_not_there_says_so() {
        assert!(bytes_of(WITH_ATTACHMENT, 5).is_err());
    }

    #[test]
    fn a_traversal_in_a_filename_cannot_escape_the_folder() {
        // The name is a string a stranger chose, about to be joined to a path.
        let dir = tempfile::tempdir().unwrap();
        let saved = save_into(dir.path(), "../../.bashrc", b"nope").unwrap();
        assert_eq!(
            saved.parent().unwrap(),
            dir.path(),
            "the file landed outside the folder it was saved into"
        );
        // The dots survive as ordinary characters; what matters is that no
        // separator did, so the name cannot be more than one component.
        let name = saved.file_name().unwrap().to_string_lossy();
        assert!(!name.contains('/') && !name.contains('\\'), "{name}");
    }

    #[test]
    fn names_that_are_not_names_become_one() {
        assert_eq!(sanitize(""), "attachment");
        assert_eq!(sanitize("   "), "attachment");
        assert_eq!(sanitize("..."), "attachment");
        assert_eq!(
            sanitize(".bashrc"),
            "bashrc",
            "a leading dot would hide the file from the person who saved it"
        );
    }

    #[test]
    fn separators_and_windows_forbidden_characters_are_replaced() {
        assert_eq!(sanitize("a/b\\c"), "a_b_c");
        assert_eq!(sanitize("re:port<1>.pdf"), "re_port_1_.pdf");
        assert_eq!(sanitize("tab\there"), "tab_here");
    }

    #[test]
    fn windows_device_names_are_escaped_even_with_an_extension() {
        // `CON.txt` cannot be created on NTFS however it is spelled, and a
        // saved file travels — onto a stick, into a VM.
        assert_eq!(sanitize("CON.txt"), "_CON.txt");
        assert_eq!(sanitize("nul"), "_nul");
        assert_eq!(sanitize("console.txt"), "console.txt", "not a device name");
    }

    #[test]
    fn a_very_long_name_is_capped_but_keeps_its_extension() {
        // The extension is what decides how the file opens.
        let name = format!("{}.pdf", "a".repeat(500));
        let safe = sanitize(&name);
        assert!(safe.chars().count() <= 200, "{}", safe.chars().count());
        assert!(safe.ends_with(".pdf"), "{safe}");
    }

    #[test]
    fn saving_twice_never_overwrites() {
        // Two people can perfectly well both attach `invoice.pdf`, and the
        // second silently replacing the first is a loss with no signal.
        let dir = tempfile::tempdir().unwrap();
        let first = save_into(dir.path(), "invoice.pdf", b"one").unwrap();
        let second = save_into(dir.path(), "invoice.pdf", b"two").unwrap();

        assert_ne!(first, second);
        assert_eq!(second.file_name().unwrap(), "invoice (1).pdf");
        assert_eq!(std::fs::read(&first).unwrap(), b"one");
        assert_eq!(std::fs::read(&second).unwrap(), b"two");
    }

    #[test]
    fn save_all_writes_the_real_attachments_and_skips_inline_parts() {
        let dir = tempfile::tempdir().unwrap();
        let saved = save_all(WITH_ATTACHMENT, dir.path()).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(std::fs::read(&saved[0]).unwrap(), b"a,b\r\n1,2");
    }

    #[test]
    fn outgoing_types_are_guessed_from_the_extension_and_default_honestly() {
        assert_eq!(mime_for("report.PDF"), "application/pdf");
        assert_eq!(mime_for("photo.jpeg"), "image/jpeg");
        assert_eq!(mime_for("notes"), "application/octet-stream");
        assert_eq!(mime_for("archive.tar.gz"), "application/gzip");
    }
}

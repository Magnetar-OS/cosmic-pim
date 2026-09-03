// SPDX-License-Identifier: MPL-2.0

//! mbox, both directions: reading an archive in, writing one out.
//!
//! # The format, such as it is
//!
//! mbox is barely a format: messages concatenated, each introduced by a line
//! starting `From ` (the *separator* line, not a header), with any line in a
//! body that itself starts `From ` escaped to `>From ` by the writer. That
//! escaping is the whole trick — and the classic corruption, because not every
//! writer does it, and an unescaped `From ` mid-body splits one message into
//! two.
//!
//! This reader handles the format every real exporter writes — mboxrd-style
//! `>From ` unstuffing included — and does not try to outguess broken files:
//! a `From ` line at column zero after a blank line is a separator, which is
//! the mboxo/mboxrd convention Thunderbird, Gmail Takeout, and `formail` all
//! follow. [`write`] emits the same dialect, so an archive this crate wrote
//! and read back is byte-identical to what went in.
//!
//! # The one place a message's bytes are modified
//!
//! Everything else in this crate stores messages verbatim, because
//! re-serialising one invalidates its DKIM signature. mbox cannot: a body
//! line beginning `From ` would be read back as the start of another message,
//! so writing one *must* stuff it to `>From `. That is the format's own
//! requirement rather than a choice, it is exactly reversible (the reader
//! unstuffs the same runs), and the round trip is pinned by a test. A
//! signature verifies again the moment the message leaves the archive.
//!
//! # What mbox cannot represent
//!
//! A message whose last byte is not a newline. The next entry's separator has
//! to start at column zero, so the writer supplies the missing terminator and
//! the reader hands it back — one byte longer than it went in. Nothing else
//! differs, and no message that ever crossed a wire is affected: RFC 5322
//! ends every line, body included, with CRLF. Stated here because a
//! round-trip test that quietly special-cased it would be hiding the one
//! place this module is lossy.

/// Splits an mbox into its messages, `>From ` unstuffed.
///
/// Bytes in, bytes out: an mbox is a container of RFC 5322 messages, and those
/// are byte formats — a lossy string conversion here would corrupt every
/// legacy-charset body in the archive.
#[must_use]
pub fn messages(mbox: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut current: Option<Vec<u8>> = None;
    let mut at_boundary = true;

    for line in split_keeping_ends(mbox) {
        if at_boundary && line.starts_with(b"From ") {
            // A separator line. It is envelope metadata mbox invented, not a
            // header of the message — it is dropped, not kept.
            if let Some(message) = current.take() {
                out.push(trim_trailing_blank(message));
            }
            current = Some(Vec::new());
        } else if let Some(message) = current.as_mut() {
            // mboxrd unstuffing: the writer turned a body's `From ` into
            // `>From `, and `>>From ` into `>>>From `, to protect the
            // separator. Reversed exactly, so a quoted `>From me` in prose
            // survives one round trip unchanged.
            if stripped_quote_prefix(line).starts_with(b"From ") && line.starts_with(b">") {
                message.extend_from_slice(&line[1..]);
            } else {
                message.extend_from_slice(line);
            }
        }
        // A separator is only a separator at a message boundary: the start of
        // the file, or right after a blank line. `From ` mid-paragraph in an
        // unescaped file stays where it is.
        at_boundary = line == b"\n" || line == b"\r\n";
    }
    if let Some(message) = current.take() {
        out.push(trim_trailing_blank(message));
    }
    out
}

fn split_keeping_ends(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = bytes;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let end = rest
            .iter()
            .position(|&b| b == b'\n')
            .map_or(rest.len(), |at| at + 1);
        let (line, tail) = rest.split_at(end);
        rest = tail;
        Some(line)
    })
}

/// The line with any run of `>` removed, for the unstuffing test.
fn stripped_quote_prefix(line: &[u8]) -> &[u8] {
    let mut rest = line;
    while let Some(tail) = rest.strip_prefix(b">") {
        rest = tail;
    }
    rest
}

/// Drops the blank separator line the format puts between messages.
fn trim_trailing_blank(mut message: Vec<u8>) -> Vec<u8> {
    for ending in [b"\r\n".as_slice(), b"\n".as_slice()] {
        if message.ends_with(ending) {
            let trimmed = message.len() - ending.len();
            let before = &message[..trimmed];
            if before.ends_with(b"\n") {
                message.truncate(trimmed);
                break;
            }
        }
    }
    message
}

/// Writes messages as an mbox archive: bytes in, bytes out.
///
/// Each entry gets the separator line the format requires, its body lines
/// stuffed, and a blank line after it. [`messages`] reads the result back
/// byte-for-byte — that round trip is the contract, and the reason both
/// halves live in one file.
#[must_use]
pub fn write<'a>(messages: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for raw in messages {
        append(&mut out, raw);
    }
    out
}

/// Appends one message to an archive being built.
///
/// The envelope sender and date on the separator line are read from the
/// message's own `From` and `Date` where it has them. They are mbox's
/// invention rather than part of the message, every reader discards them, and
/// this crate's own reader discards them too — so a message that carries
/// neither gets the conventional placeholders instead of blocking an export.
pub fn append(out: &mut Vec<u8>, raw: &[u8]) {
    let (sender, date) = envelope_of(raw);
    append_with_envelope(out, raw, &sender, &date);
}

/// [`append`], with the separator line's two fields supplied.
///
/// For an exporter that knows the real envelope sender — a `Return-Path`, or
/// what the server said at delivery — which is better evidence than the
/// `From` header a spammer wrote.
pub fn append_with_envelope(out: &mut Vec<u8>, raw: &[u8], sender: &str, date: &str) {
    out.extend_from_slice(b"From ");
    out.extend_from_slice(sanitise_field(sender, "MAILER-DAEMON").as_bytes());
    out.push(b' ');
    out.extend_from_slice(sanitise_field(date, DEFAULT_DATE).as_bytes());
    out.push(b'\n');

    // Stuffing is per *line*, and only in the body sense mbox means: any line
    // at column zero that a reader would mistake for a separator. `>From `
    // becomes `>>From ` so the reader's unstuffing returns it unchanged.
    for line in split_keeping_ends(raw) {
        if stripped_quote_prefix(line).starts_with(b"From ") {
            out.push(b'>');
        }
        out.extend_from_slice(line);
    }

    // Every entry ends with a newline and then the blank line that makes the
    // next `From ` a separator. A message that did not end in a newline gets
    // one: without it the blank line would land inside its last body line.
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.push(b'\n');
}

/// The conventional placeholder date, in the C-locale `asctime` shape every
/// mbox separator uses.
const DEFAULT_DATE: &str = "Thu Jan  1 00:00:00 1970";

/// The envelope sender and date for a message's separator line, from its own
/// headers.
fn envelope_of(raw: &[u8]) -> (String, String) {
    let Some(message) = crate::model::Message::parse(raw) else {
        return ("MAILER-DAEMON".to_owned(), DEFAULT_DATE.to_owned());
    };
    let sender = message
        .sender()
        .map_or_else(|| "MAILER-DAEMON".to_owned(), |m| m.address.clone());
    let date = message.date.map_or_else(
        || DEFAULT_DATE.to_owned(),
        // C-locale asctime: `%e` space-pads the day, which is what every
        // reader's parser (and every diff against another exporter) expects.
        |d| d.format("%a %b %e %H:%M:%S %Y").to_string(),
    );
    (sender, date)
}

/// Keeps a separator field on one line and non-empty.
///
/// A display name with a newline in it — or an address a broken parser handed
/// back with one — would otherwise write a second line that reads as the start
/// of a message.
fn sanitise_field(value: &str, fallback: &str) -> String {
    let cleaned: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .filter(|c| !c.is_whitespace() || *c == ' ')
        .collect();
    let cleaned = cleaned.trim().to_owned();
    if cleaned.is_empty() {
        fallback.to_owned()
    } else {
        cleaned
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    /* ---------------- writing ---------------- */

    /// The contract between the two halves of this module.
    #[test]
    fn an_archive_this_module_wrote_reads_back_byte_for_byte() {
        let one: &[u8] = b"From: Ada <ada@example.com>\nSubject: First\n\nBody one.\n";
        let two: &[u8] = b"From: Bob <bob@example.com>\nSubject: Second\n\nBody two.\n";

        let archive = write([one, two]);
        let back = messages(&archive);

        assert_eq!(back.len(), 2);
        assert_eq!(back[0], one);
        assert_eq!(back[1], two);
    }

    /// The format's whole trick, and its classic corruption. A body line that
    /// looks like a separator must survive.
    #[test]
    fn a_body_line_that_looks_like_a_separator_survives_the_round_trip() {
        let raw: &[u8] = b"From: Ada <ada@example.com>\nSubject: Trap\n\n\
From here on it gets worse.\nOrdinary line.\n";

        let archive = write([raw]);
        assert!(
            archive.windows(6).any(|w| w == b">From "),
            "the body line was not stuffed, so it will split the message in two"
        );

        let back = messages(&archive);
        assert_eq!(back.len(), 1, "the archive split one message into two");
        assert_eq!(back[0], raw);
    }

    /// mboxrd: quote runs grow by one on write and shrink by one on read, so
    /// prose that already begins `>From ` comes back unchanged.
    #[test]
    fn an_already_quoted_from_line_round_trips() {
        let raw: &[u8] = b"From: Ada <ada@example.com>\nSubject: Quoting\n\n\
>From the earlier mail:\n>>From the one before that:\n";

        let back = messages(&write([raw]));
        assert_eq!(back.len(), 1);
        assert_eq!(back[0], raw);
    }

    #[test]
    fn the_separator_carries_the_senders_address_and_date() {
        let raw: &[u8] = b"From: Ada <ada@example.com>\n\
Date: Mon, 3 Feb 2025 10:00:00 +0000\nSubject: Dated\n\nBody.\n";

        let archive = write([raw]);
        let first =
            String::from_utf8_lossy(&archive[..archive.iter().position(|&b| b == b'\n').unwrap()])
                .into_owned();

        assert!(first.starts_with("From ada@example.com "), "{first}");
        assert!(first.contains("Feb"), "{first}");
        assert!(first.contains("2025"), "{first}");
    }

    /// A message missing both fields must still export. mbox's envelope is
    /// its own invention and every reader discards it — refusing the export
    /// over it would lose the message to keep a placeholder honest.
    #[test]
    fn a_message_with_no_from_or_date_still_exports_and_reads_back() {
        let raw: &[u8] = b"Subject: Anonymous\n\nBody.\n";

        let archive = write([raw]);
        assert!(
            archive.starts_with(b"From MAILER-DAEMON "),
            "{:?}",
            &archive[..40]
        );
        assert_eq!(messages(&archive)[0], raw);
    }

    /// The one lossy case, pinned so it stays known and stays minimal: mbox
    /// is line-oriented, so a message with no final newline gains exactly
    /// one. Every message that crossed a wire already ends in CRLF.
    #[test]
    fn a_message_with_no_final_newline_gains_exactly_one() {
        let raw: &[u8] = b"From: Ada <ada@example.com>\nSubject: Truncated\n\nNo trailing newline";

        let back = messages(&write([raw]));
        assert_eq!(back.len(), 1);
        assert_eq!(
            back[0].len(),
            raw.len() + 1,
            "more than the missing terminator changed"
        );
        assert_eq!(&back[0][..raw.len()], raw, "the body itself was altered");
        assert_eq!(back[0].last(), Some(&b'\n'));
    }

    /// CRLF is what RFC 5322 mandates and what a synced message actually
    /// carries; the writer must not rewrite terminators — that is what
    /// invalidates a signature.
    #[test]
    fn crlf_messages_keep_their_terminators() {
        let raw: &[u8] = b"From: Ada <ada@example.com>\r\nSubject: Wire form\r\n\r\nBody.\r\n";

        let archive = write([raw]);
        let back = messages(&archive);
        assert_eq!(
            back[0], raw,
            "the message's own line endings were rewritten"
        );
    }

    /// A separator field is one line by construction: a newline smuggled into
    /// an address would otherwise write a line the reader takes for the start
    /// of another message.
    #[test]
    fn a_newline_in_the_envelope_cannot_forge_a_separator() {
        let mut archive = Vec::new();
        append_with_envelope(
            &mut archive,
            b"Subject: Hostile\n\nBody.\n",
            "ada@example.com\nFrom attacker@example.com Mon Feb  3 10:00:00 2025",
            "Mon Feb  3 10:00:00 2025",
        );

        assert_eq!(
            messages(&archive).len(),
            1,
            "an address forged a second message"
        );
    }

    #[test]
    fn an_empty_archive_is_empty_rather_than_a_stray_separator() {
        assert!(write(std::iter::empty()).is_empty());
        assert!(messages(&write(std::iter::empty())).is_empty());
    }

    /// The export → import path a person actually walks when they leave
    /// Thunderbird and come back.
    #[test]
    fn a_full_mailbox_round_trips_through_the_reader() {
        let bodies: Vec<Vec<u8>> = (0..25)
            .map(|i| {
                format!(
                    "From: Sender {i} <s{i}@example.com>\n\
                     Date: Mon, 3 Feb 2025 10:00:00 +0000\n\
                     Message-ID: <{i}@example.com>\nSubject: Message {i}\n\n\
                     Body {i}\nFrom the top.\n"
                )
                .into_bytes()
            })
            .collect();

        let archive = write(bodies.iter().map(Vec::as_slice));
        let back = messages(&archive);

        assert_eq!(back.len(), bodies.len());
        for (before, after) in bodies.iter().zip(&back) {
            assert_eq!(before, after);
        }
    }
    use super::*;

    const TWO: &[u8] = b"From ada@example.com Mon Feb  3 10:00:00 2025\n\
From: Ada <ada@example.com>\n\
Subject: First\n\
\n\
Body one.\n\
\n\
From bob@example.net Mon Feb  3 11:00:00 2025\n\
From: Bob <bob@example.net>\n\
Subject: Second\n\
\n\
Body two.\n";

    #[test]
    fn messages_are_split_on_separators_and_the_separator_is_dropped() {
        let messages = messages(TWO);
        assert_eq!(messages.len(), 2);
        let first = String::from_utf8_lossy(&messages[0]);
        assert!(
            first.starts_with("From: Ada"),
            "the separator leaked in: {first}"
        );
        assert!(first.contains("Body one."));
        let second = String::from_utf8_lossy(&messages[1]);
        assert!(second.contains("Subject: Second"));
    }

    #[test]
    fn the_split_messages_parse_as_messages() {
        for raw in messages(TWO) {
            let message = crate::model::Message::parse(&raw).expect("parses");
            assert!(!message.subject.is_empty());
        }
    }

    #[test]
    fn stuffed_from_lines_are_unstuffed_exactly_once() {
        let mbox = b"From x\n\
Subject: s\n\
\n\
>From the beginning, it was clear.\n\
>>From deeper quoting.\n\
Ordinary line.\n";
        let messages = messages(mbox);
        let body = String::from_utf8_lossy(&messages[0]);
        assert!(body.contains("\nFrom the beginning"), "{body}");
        assert!(
            body.contains("\n>From deeper quoting"),
            "double-stuffing must lose exactly one level: {body}"
        );
    }

    #[test]
    fn an_unescaped_from_mid_paragraph_does_not_split_the_message() {
        // The classic corruption, refused: `From ` is a separator only at a
        // boundary — start of file or after a blank line.
        let mbox = b"From x\n\
Subject: s\n\
\n\
He said it plainly.\n\
From here on, nothing changed.\n";
        assert_eq!(messages(mbox).len(), 1, "a body line split the message");
    }

    #[test]
    fn a_from_line_after_a_blank_line_is_a_separator() {
        // The exact same text, at a boundary, is two messages — that is the
        // convention every real exporter follows.
        let mbox = b"From x\n\
Subject: s\n\
\n\
Body.\n\
\n\
From y\n\
Subject: t\n\
\n\
Other.\n";
        assert_eq!(messages(mbox).len(), 2);
    }

    #[test]
    fn empty_and_rubbish_inputs_yield_nothing() {
        assert!(messages(b"").is_empty());
        assert!(messages(b"not an mbox at all\n").is_empty());
    }

    #[test]
    fn non_utf8_bodies_survive_byte_for_byte() {
        let mbox = b"From x\n\
Subject: caf\xe9\n\
\n\
caf\xe9 in latin-1\n";
        let messages = messages(mbox);
        assert_eq!(messages.len(), 1);
        assert!(
            messages[0].windows(4).any(|w| w == b"\xe9 in"),
            "a legacy-charset byte was mangled"
        );
    }
}

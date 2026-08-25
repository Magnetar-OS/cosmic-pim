// SPDX-License-Identifier: MPL-2.0

//! Reading mbox files, for import.
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
//! follow.

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
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

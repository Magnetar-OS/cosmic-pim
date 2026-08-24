// SPDX-License-Identifier: MPL-2.0

//! What a message is, as far as anything above this crate is concerned.
//!
//! # Extract, never re-serialise
//!
//! [`Message`] is built *from* RFC 5322 bytes and is never turned back into
//! them. This is the same rule `cosmic_pim_caldav::store::RemoteEvent` follows
//! for iCalendar, and it matters more here, not less:
//!
//! - A message carries MIME structure, `Received` chains, `List-*` headers,
//!   `X-` headers, and parts nobody has thought about yet. The model covers
//!   what a reader displays, which is a small fraction of that.
//! - A DKIM signature covers the bytes. Re-serialising a message — even
//!   "losslessly", even just re-folding a header — invalidates it. The whole
//!   value of DKIM is that the signature survived the trip; a client that
//!   quietly breaks it has thrown away the only cryptographic evidence the
//!   message carries.
//!
//! So the maildir file holds the server's bytes and this module holds a view of
//! them. Anything that needs a header we did not extract re-parses the file.

use chrono::{DateTime, TimeZone as _, Utc};
use mail_parser::{Message as ParsedMessage, MessageParser, MimeHeaders as _};

use crate::text::{self, ExtractedText};

/// One address, with the display name the message gave it (if any).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Mailbox {
    /// Display name as written, unescaped and unfolded by the parser.
    pub name: Option<String>,
    /// The addr-spec, lowercased.
    ///
    /// Lowercasing the *whole* address is technically wrong — RFC 5321 makes
    /// the local part case-sensitive — and is done anyway, because no mail
    /// system in practice treats `Bob@` and `bob@` as different people, and
    /// matching a sender against an address book that lowercases is worth more
    /// than a conformance point nobody exercises.
    pub address: String,
}

impl Mailbox {
    /// What to show in a message list: the display name, else the address.
    #[must_use]
    pub fn display(&self) -> &str {
        match &self.name {
            Some(name) if !name.trim().is_empty() => name,
            _ => &self.address,
        }
    }

    /// The domain part, for grouping and for matching an auth result's
    /// `header.d` against who the message claims to be from.
    #[must_use]
    pub fn domain(&self) -> &str {
        self.address.rsplit('@').next().unwrap_or("")
    }
}

/// The IMAP system flags (RFC 3501 §2.3.2) plus maildir's `P` (passed).
///
/// Deliberately a struct of bools rather than a set of strings: these five are
/// the flags with defined semantics, every server has them, and both the
/// maildir filename and the IMAP wire form are fixed vocabularies. Custom
/// keywords are a different thing with a different lifetime and are not
/// modelled here — see [`crate::maildir`] for why they are not in the filename.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Flags {
    /// `\Seen` / maildir `S`.
    pub seen: bool,
    /// `\Answered` / maildir `R` (replied).
    pub answered: bool,
    /// `\Flagged` / maildir `F`.
    pub flagged: bool,
    /// `\Draft` / maildir `D`.
    pub draft: bool,
    /// `\Deleted` / maildir `T` (trashed).
    ///
    /// Note this is the IMAP *mark*, not a removal: a message stays in the
    /// mailbox, listed and fetchable, until an EXPUNGE. Treating the flag as a
    /// deletion is how a client makes messages vanish that the server still has.
    pub deleted: bool,
    /// Maildir `P`. No IMAP equivalent; preserved so a round trip through our
    /// store does not destroy what another maildir client recorded.
    pub passed: bool,
}

impl Flags {
    /// Parses a maildir info suffix — the part after `:2,` — ignoring anything
    /// outside the standard vocabulary.
    ///
    /// Unknown letters are dropped rather than rejected: Dovecot writes `a`–`z`
    /// there for custom keywords, and a message carrying one is still a
    /// perfectly good message.
    #[must_use]
    pub fn from_maildir_info(info: &str) -> Self {
        let mut flags = Self::default();
        for c in info.chars() {
            match c {
                'S' => flags.seen = true,
                'R' => flags.answered = true,
                'F' => flags.flagged = true,
                'D' => flags.draft = true,
                'T' => flags.deleted = true,
                'P' => flags.passed = true,
                _ => {}
            }
        }
        flags
    }

    /// The maildir info suffix for these flags, in the ASCII order the format
    /// requires (`DFPRST`).
    ///
    /// The ordering is not cosmetic: maildir specifies the flags are stored in
    /// ASCII order, and a reader that sorts before comparing will see `FS` and
    /// `SF` as different filenames for the same message.
    #[must_use]
    pub fn to_maildir_info(self) -> String {
        let mut info = String::with_capacity(6);
        for (set, letter) in [
            (self.draft, 'D'),
            (self.flagged, 'F'),
            (self.passed, 'P'),
            (self.answered, 'R'),
            (self.seen, 'S'),
            (self.deleted, 'T'),
        ] {
            if set {
                info.push(letter);
            }
        }
        info
    }

    /// The IMAP system flags to send in a STORE, in wire spelling.
    ///
    /// `P` has no representation and is silently omitted — it is a maildir-local
    /// fact and telling a server about it would be inventing a keyword.
    #[must_use]
    pub fn to_imap(self) -> Vec<&'static str> {
        let mut names = Vec::with_capacity(5);
        for (set, name) in [
            (self.seen, "\\Seen"),
            (self.answered, "\\Answered"),
            (self.flagged, "\\Flagged"),
            (self.draft, "\\Draft"),
            (self.deleted, "\\Deleted"),
        ] {
            if set {
                names.push(name);
            }
        }
        names
    }

    /// Reads the flags out of an IMAP FETCH response.
    ///
    /// `\Recent` is deliberately not modelled: it is session state, not a
    /// property of the message, and the server clears it out from under us.
    /// Persisting it would produce a flag that flickers on every sync.
    #[must_use]
    pub fn from_imap(flags: &[::imap::types::Flag<'_>]) -> Self {
        use ::imap::types::Flag as F;
        let mut out = Self::default();
        for flag in flags {
            match flag {
                F::Seen => out.seen = true,
                F::Answered => out.answered = true,
                F::Flagged => out.flagged = true,
                F::Draft => out.draft = true,
                F::Deleted => out.deleted = true,
                _ => {}
            }
        }
        out
    }

    /// Merges the maildir-only bits of `other` into `self`.
    ///
    /// Used when the server is authoritative for the five system flags but the
    /// local file is the only place `P` exists. Without this, every flag
    /// reconciliation would quietly clear it.
    #[must_use]
    pub fn with_local_only_from(mut self, other: Self) -> Self {
        self.passed = other.passed;
        self
    }
}

/// An attachment, described but not extracted.
///
/// The bytes stay in the message file. A reader that wants them re-parses;
/// a list view wants only this much, and holding every attachment of every
/// message in memory to render a paperclip icon is how a mail client ends up
/// using two gigabytes on a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub mime_type: String,
    pub size: usize,
    /// True for a part referenced by a `cid:` URL from the HTML body — an
    /// inline image, not something to list as an attachment.
    pub inline: bool,
}

/// A message, extracted for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// `Message-ID` with the angle brackets stripped, if the message had one.
    pub message_id: Option<String>,
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    /// Blind carbon copies.
    ///
    /// Empty on essentially every *received* message — the header is stripped
    /// before delivery, which is what the field means. It is present on the
    /// copies we file ourselves: a message in Sent, and a saved draft, both
    /// keep it so the sender can still see who they copied.
    pub bcc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    pub subject: String,
    /// The subject with `Re:`/`Fwd:`/`[list]` prefixes stripped — the key
    /// threading falls back to when a reply carries no `References`.
    pub subject_norm: String,
    pub date: Option<DateTime<Utc>>,
    /// `In-Reply-To`, re-rendered as the angle-bracketed header text the
    /// threading functions parse. Empty when absent.
    pub in_reply_to: String,
    /// `References`, same treatment.
    pub references: String,
    /// What a human would actually see, with a count of what was hidden.
    pub body: ExtractedText,
    /// True when the message's HTML referenced anything off-host.
    ///
    /// The reader blocks remote content by default, and a message that has none
    /// should not be offered an "load remote content" affordance it does not
    /// need. Tracking pixels are the reason the default is what it is.
    pub has_remote_content: bool,
    pub attachments: Vec<Attachment>,
    /// `Authentication-Results`, newest hop first.
    pub auth: Vec<crate::auth::AuthHop>,
}

impl Message {
    /// Parses RFC 5322 bytes into the display view.
    ///
    /// Returns `None` only when the bytes are not a message at all. Everything
    /// short of that — a missing `Date`, a truncated MIME part, a header that
    /// does not decode — yields a `Message` with that field empty, because a
    /// mail client that refuses to show broken mail is a mail client that hides
    /// exactly the messages the user most needs to see.
    #[must_use]
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let parsed = MessageParser::default().parse(raw)?;
        Some(Self::from_parsed(&parsed))
    }

    fn from_parsed(msg: &ParsedMessage<'_>) -> Self {
        let subject = msg.subject().unwrap_or_default().to_string();
        let html = msg.body_html(0).map(std::borrow::Cow::into_owned);
        let plain = msg.body_text(0).map(std::borrow::Cow::into_owned);

        // HTML wins when present: it is what the sender laid out, and the
        // `text/plain` alternative of a marketing mail is routinely a stub
        // reading "view this in your browser". Extraction gives us the visible
        // text either way, so preferring HTML costs nothing.
        let body = match (&html, &plain) {
            (Some(html), _) => text::extract(html),
            (None, Some(plain)) => text::extract_plain(plain),
            (None, None) => ExtractedText::default(),
        };

        Self {
            message_id: msg.message_id().map(strip_angles),
            from: mailboxes(msg.from()),
            to: mailboxes(msg.to()),
            cc: mailboxes(msg.cc()),
            bcc: mailboxes(msg.bcc()),
            reply_to: mailboxes(msg.reply_to()),
            subject_norm: crate::threading::normalize_subject(&subject),
            subject,
            date: msg
                .date()
                .and_then(|d| Utc.timestamp_opt(d.to_timestamp(), 0).single()),
            in_reply_to: header_id_list(msg.in_reply_to()),
            references: header_id_list(msg.references()),
            has_remote_content: html.as_deref().is_some_and(text::references_remote_content),
            body,
            attachments: attachments(msg),
            auth: crate::auth::from_message(msg),
        }
    }

    /// The address a reply should go to: `Reply-To` when the sender asked for
    /// one, otherwise `From`.
    #[must_use]
    pub fn reply_target(&self) -> &[Mailbox] {
        if self.reply_to.is_empty() {
            &self.from
        } else {
            &self.reply_to
        }
    }

    /// The first sender, which is what a list view shows.
    #[must_use]
    pub fn sender(&self) -> Option<&Mailbox> {
        self.from.first()
    }
}

fn strip_angles(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}

/// `mail_parser` hands back one address, a group, or a list behind one type;
/// flatten all three into the shape a UI iterates over.
fn mailboxes(address: Option<&mail_parser::Address<'_>>) -> Vec<Mailbox> {
    let Some(address) = address else {
        return Vec::new();
    };
    address
        .iter()
        .filter_map(|addr| {
            let email = addr.address()?.trim();
            if email.is_empty() {
                return None;
            }
            Some(Mailbox {
                name: addr
                    .name()
                    .map(|n| n.trim().to_string())
                    .filter(|n| !n.is_empty()),
                address: email.to_ascii_lowercase(),
            })
        })
        .collect()
}

/// Re-render a parsed id list as header text (`<a> <b>`).
///
/// The threading functions take header *text* rather than a parsed list on
/// purpose: they have to cope with the malformed headers real mail carries, and
/// handing them a list that a parser already gave up on would hide exactly the
/// cases they exist to handle.
fn header_id_list(value: &mail_parser::HeaderValue<'_>) -> String {
    value.as_text_list().map_or_else(String::new, |ids| {
        ids.iter()
            .map(|id| format!("<{}>", id.trim().trim_matches(['<', '>'])))
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn attachments(msg: &ParsedMessage<'_>) -> Vec<Attachment> {
    msg.attachments()
        .map(|part| Attachment {
            name: part
                .attachment_name()
                .unwrap_or("attachment")
                .trim()
                .to_string(),
            mime_type: part.content_type().map_or_else(
                || "application/octet-stream".to_string(),
                |ct| match ct.subtype() {
                    Some(sub) => format!("{}/{}", ct.ctype(), sub),
                    None => ct.ctype().to_string(),
                },
            ),
            size: part.len(),
            inline: part.content_id().is_some(),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SIMPLE: &[u8] = b"From: Ada Lovelace <Ada@Example.COM>\r\n\
To: bob@example.net\r\n\
Subject: Re: [devs] analytical engine\r\n\
Message-ID: <abc@example.com>\r\n\
In-Reply-To: <parent@example.com>\r\n\
References: <root@example.com> <parent@example.com>\r\n\
Date: Mon, 3 Feb 2025 10:00:00 +0000\r\n\
\r\n\
Body text.\r\n";

    #[test]
    fn headers_are_extracted_for_display() {
        let msg = Message::parse(SIMPLE).unwrap();
        assert_eq!(msg.sender().unwrap().display(), "Ada Lovelace");
        assert_eq!(
            msg.sender().unwrap().address,
            "ada@example.com",
            "the address was not folded to lowercase, so it will not match an \
             address book entry"
        );
        assert_eq!(msg.sender().unwrap().domain(), "example.com");
        assert_eq!(msg.message_id.as_deref(), Some("abc@example.com"));
        assert_eq!(msg.subject_norm, "analytical engine");
        assert_eq!(msg.date.unwrap().timestamp(), 1_738_576_800);
    }

    #[test]
    fn reference_headers_round_trip_into_threadable_text() {
        let msg = Message::parse(SIMPLE).unwrap();
        assert_eq!(
            msg.references, "<root@example.com> <parent@example.com>",
            "References must reach threading as header text, oldest first"
        );
        assert_eq!(msg.in_reply_to, "<parent@example.com>");
    }

    #[test]
    fn a_reply_goes_to_reply_to_when_the_sender_asked() {
        let raw = b"From: list@example.com\r\nReply-To: humans@example.com\r\n\r\nhi\r\n";
        let msg = Message::parse(raw).unwrap();
        assert_eq!(msg.reply_target()[0].address, "humans@example.com");
        let msg = Message::parse(SIMPLE).unwrap();
        assert_eq!(msg.reply_target()[0].address, "ada@example.com");
    }

    #[test]
    fn a_message_with_nothing_in_it_still_parses() {
        // Not a hypothetical: servers store bodiless probes, and a client that
        // returns None here shows the user an empty mailbox.
        let msg = Message::parse(b"\r\n").unwrap();
        assert!(msg.from.is_empty());
        assert_eq!(msg.subject, "");
        assert!(msg.date.is_none());
    }

    #[test]
    fn maildir_flag_letters_round_trip_in_ascii_order() {
        let flags = Flags {
            seen: true,
            flagged: true,
            draft: true,
            ..Default::default()
        };
        assert_eq!(
            flags.to_maildir_info(),
            "DFS",
            "flags must be ASCII-ordered"
        );
        assert_eq!(Flags::from_maildir_info("SFD"), flags);
    }

    #[test]
    fn unknown_maildir_letters_are_ignored_not_rejected() {
        // Dovecot writes a-z for custom keywords in the same field.
        let flags = Flags::from_maildir_info("Sab");
        assert!(flags.seen);
        assert!(!flags.draft);
    }

    #[test]
    fn passed_survives_a_server_flag_reconciliation() {
        let local = Flags {
            passed: true,
            seen: true,
            ..Default::default()
        };
        let from_server = Flags {
            seen: true,
            flagged: true,
            ..Default::default()
        };
        let merged = from_server.with_local_only_from(local);
        assert!(
            merged.passed,
            "P is maildir-only and the server cannot report it"
        );
        assert!(merged.flagged);
    }

    #[test]
    fn imap_flags_omit_the_maildir_only_one() {
        let flags = Flags {
            seen: true,
            passed: true,
            ..Default::default()
        };
        assert_eq!(
            flags.to_imap(),
            vec!["\\Seen"],
            "P was invented as a keyword"
        );
    }
}

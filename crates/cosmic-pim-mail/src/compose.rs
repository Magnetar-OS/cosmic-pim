// SPDX-License-Identifier: MPL-2.0

//! Drafts: what to send, and how a reply or a forward is built from a message.
//!
//! # Plain text
//!
//! A [`Draft`] has one body and it is `text/plain`. This is a decision, not a
//! stage on the way to an HTML composer:
//!
//! - The reader shows text (see [`crate::text`] for why), so an HTML composer
//!   would be writing in a format the application itself cannot display.
//! - Composer scope is the classic way a mail client never ships. Reply,
//!   forward, and quoting are the operations people actually perform; font
//!   pickers are not.
//!
//! When HTML composition does arrive it belongs here, as a second body on the
//! same draft, with the text part still generated — never instead of it.
//!
//! # What a draft is not
//!
//! It is not RFC 5322 bytes. [`Draft::build`] produces those, once, at send
//! time. Keeping a draft as a structure rather than as text means quoting,
//! recipient edits, and validation all operate on fields rather than on a
//! parse-and-reserialise cycle — which is the same reason a stored message is
//! never re-serialised, arrived at from the other direction.

use lettre::message::{Mailbox as LettreMailbox, Message as LettreMessage, header};

use crate::error::{Error, Result};
use crate::model::{Mailbox, Message};

/// How much of a message is quoted into a reply.
///
/// Real threads accumulate: a twentieth reply carries nineteen quoted copies,
/// and none of them are read. The cap keeps a draft from being mostly its own
/// history while still including enough for the recipient to see what is being
/// answered.
const QUOTE_LIMIT_LINES: usize = 50;

/// A message being written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Draft {
    pub from: Mailbox,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    /// Blind carbon copies.
    ///
    /// These ride the SMTP envelope and must **not** appear in the bytes the
    /// recipients receive — that is the entire meaning of the field, and a
    /// client that leaks it has told every recipient who else was copied. They
    /// *are* kept in the copy filed to Sent, so the sender can still see what
    /// they did.
    pub bcc: Vec<Mailbox>,
    pub subject: String,
    pub body: String,
    /// The `Message-ID` this is a reply to, without angle brackets.
    pub in_reply_to: Option<String>,
    /// The reference chain this reply extends, oldest first, without brackets.
    pub references: Vec<String>,
}

impl Draft {
    /// A blank draft from one identity.
    #[must_use]
    pub fn new(from: Mailbox) -> Self {
        Self {
            from,
            ..Self::default()
        }
    }

    /// A reply to `message`.
    ///
    /// `reply_all` adds everyone the original was addressed to, minus the
    /// sender's own address. Dropping the sender's own address is not a
    /// nicety: a reply-all that includes yourself puts a copy of every sent
    /// message back in your inbox, and on a mailing list it is how loops start.
    #[must_use]
    pub fn reply(message: &Message, from: Mailbox, reply_all: bool) -> Self {
        // `Reply-To` when the sender asked for one — a list posts under its own
        // address and expects replies there, not to whoever happened to send.
        let mut to: Vec<Mailbox> = message.reply_target().to_vec();
        let mut cc = Vec::new();

        if reply_all {
            for recipient in message.to.iter().chain(message.cc.iter()) {
                if recipient.address == from.address
                    || to.iter().any(|m| m.address == recipient.address)
                    || cc.iter().any(|m: &Mailbox| m.address == recipient.address)
                {
                    continue;
                }
                cc.push(recipient.clone());
            }
        }
        to.retain(|m| m.address != from.address);
        // Replying to your own sent message is a real thing people do — a
        // follow-up on a thread nobody answered — and it must not produce a
        // draft addressed to nobody.
        if to.is_empty() {
            to = message.to.clone();
        }

        Self {
            references: reply_references(message),
            in_reply_to: message.message_id.clone(),
            subject: prefixed("Re", &message.subject_norm),
            body: quote(message),
            from,
            to,
            cc,
            bcc: Vec::new(),
        }
    }

    /// A forward of `message`, addressed to nobody yet.
    ///
    /// Attachments are **not** carried: the draft holds the body it quotes, and
    /// re-attaching would mean re-serialising parts out of a message this crate
    /// promises never to rewrite. Forwarding with attachments needs the
    /// `message/rfc822` path, which is the honest implementation and is not
    /// this one.
    #[must_use]
    pub fn forward(message: &Message, from: Mailbox) -> Self {
        Self {
            subject: prefixed("Fwd", &message.subject_norm),
            body: forwarded(message),
            from,
            ..Self::default()
        }
    }

    /// Every address the message will actually go to.
    pub fn recipients(&self) -> impl Iterator<Item = &Mailbox> {
        self.to.iter().chain(&self.cc).chain(&self.bcc)
    }

    /// Why this draft cannot be sent yet, if it cannot.
    ///
    /// A separate check from [`Self::build`] so the composer can grey out its
    /// send button for the same reasons the send would fail, rather than
    /// discovering them afterwards.
    #[must_use]
    pub fn problem(&self) -> Option<&'static str> {
        if self.from.address.is_empty() {
            return Some("this draft has no sender");
        }
        if self.recipients().next().is_none() {
            return Some("this draft has no recipients");
        }
        if let Some(bad) = self
            .recipients()
            .chain(std::iter::once(&self.from))
            .find(|m| !looks_like_an_address(&m.address))
        {
            let _ = bad;
            return Some("one of the addresses is not an address");
        }
        None
    }

    /// Builds the RFC 5322 message.
    ///
    /// `keep_bcc` decides whether the `Bcc` header survives into the bytes:
    /// **false** for the copy that goes to the server, **true** for the copy
    /// filed to Sent. Sending with it true tells every recipient who was
    /// blind-copied; filing with it false loses the only record the sender has.
    pub fn build(&self, keep_bcc: bool) -> Result<LettreMessage> {
        if let Some(problem) = self.problem() {
            return Err(Error::Draft(problem.to_owned()));
        }

        let mut builder = LettreMessage::builder()
            .from(mailbox(&self.from)?)
            .subject(self.subject.clone());

        if keep_bcc {
            builder = builder.keep_bcc();
        }
        for recipient in &self.to {
            builder = builder.to(mailbox(recipient)?);
        }
        for recipient in &self.cc {
            builder = builder.cc(mailbox(recipient)?);
        }
        for recipient in &self.bcc {
            builder = builder.bcc(mailbox(recipient)?);
        }

        // Both headers, not one. `In-Reply-To` names the immediate parent and
        // `References` carries the chain: a client given only the first has to
        // guess at the thread root, and a client given only the second cannot
        // tell which message was actually being answered.
        if let Some(parent) = &self.in_reply_to {
            builder = builder.in_reply_to(format!("<{parent}>"));
        }
        if !self.references.is_empty() {
            builder = builder.references(
                self.references
                    .iter()
                    .map(|id| format!("<{id}>"))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }

        builder
            .header(header::ContentType::TEXT_PLAIN)
            .body(self.body.clone())
            .map_err(|why| Error::Draft(why.to_string()))
    }
}

fn mailbox(from: &Mailbox) -> Result<LettreMailbox> {
    let address = from
        .address
        .parse()
        .map_err(|why| Error::Draft(format!("{} is not an address: {why}", from.address)))?;
    Ok(LettreMailbox::new(
        from.name.clone().filter(|n| !n.trim().is_empty()),
        address,
    ))
}

/// The reference chain a reply should carry: the parent's chain plus the parent.
///
/// Capped, because a long-running list thread accumulates hundreds and some
/// servers reject an over-long header outright. The RFC's own guidance is to
/// keep the first and the most recent, which is what the split preserves: the
/// first entry is what every threading implementation hashes as the root.
fn reply_references(message: &Message) -> Vec<String> {
    const MAX: usize = 20;
    let mut chain =
        crate::threading::reference_chain(&message.references, &message.in_reply_to);
    if let Some(id) = &message.message_id
        && !chain.contains(id)
    {
        chain.push(id.clone());
    }
    if chain.len() > MAX {
        let root = chain.remove(0);
        let tail = chain.split_off(chain.len() - (MAX - 1));
        chain = std::iter::once(root).chain(tail).collect();
    }
    chain
}

/// `Re: subject`, without stacking a prefix that is already there.
///
/// `subject_norm` has had every prefix stripped, so this cannot produce
/// `Re: Re: Fwd: Re:` — the thing that makes long threads unreadable in clients
/// that just prepend.
fn prefixed(prefix: &str, subject_norm: &str) -> String {
    if subject_norm.is_empty() {
        format!("{prefix}:")
    } else {
        format!("{prefix}: {subject_norm}")
    }
}

/// The attribution line and the quoted body.
fn quote(message: &Message) -> String {
    let who = message
        .sender()
        .map_or_else(|| "someone".to_string(), |from| from.display().to_owned());
    let when = message
        .date
        .map(|date| date.format("%-d %b %Y at %H:%M").to_string())
        .unwrap_or_default();

    let attribution = if when.is_empty() {
        format!("{who} wrote:")
    } else {
        format!("On {when}, {who} wrote:")
    };

    let mut out = String::from("\n\n");
    out.push_str(&attribution);
    out.push('\n');
    out.push_str(&quoted_lines(&message.body.text));
    out
}

fn quoted_lines(body: &str) -> String {
    let mut out = String::new();
    for (index, line) in body.lines().enumerate() {
        if index == QUOTE_LIMIT_LINES {
            out.push_str("> [...]\n");
            break;
        }
        // No trailing space on an empty quoted line: `"> "` is trailing
        // whitespace, which some transports strip and every diff complains
        // about.
        if line.is_empty() {
            out.push_str(">\n");
        } else {
            out.push_str("> ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// A forward: the headers a recipient needs to understand what they are
/// looking at, then the body, unquoted.
///
/// Unquoted on purpose — a forward is being handed on as content, not answered.
fn forwarded(message: &Message) -> String {
    let mut out = String::from("\n\n---------- Forwarded message ----------\n");
    if let Some(from) = message.sender() {
        out.push_str(&format!("From: {} <{}>\n", from.display(), from.address));
    }
    if let Some(date) = message.date {
        out.push_str(&format!("Date: {}\n", date.format("%-d %b %Y at %H:%M")));
    }
    if !message.subject.is_empty() {
        out.push_str(&format!("Subject: {}\n", message.subject));
    }
    let to = message
        .to
        .iter()
        .map(|m| m.address.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if !to.is_empty() {
        out.push_str(&format!("To: {to}\n"));
    }
    out.push('\n');
    out.push_str(&message.body.text);
    out
}

/// The cheapest check that catches a typo without rejecting a valid address.
///
/// Deliberately not an RFC 5321 validator: the grammar permits quoted local
/// parts, IP-literal domains, and UTF-8 throughout, and a client that refuses
/// what the standard allows is worse than one that lets the server say no.
/// This catches "forgot the @" and "typed two", which is what people actually
/// do.
fn looks_like_an_address(address: &str) -> bool {
    let mut parts = address.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn me() -> Mailbox {
        Mailbox {
            name: Some("Me".into()),
            address: "me@example.com".into(),
        }
    }

    fn parse(raw: &str) -> Message {
        Message::parse(raw.as_bytes()).expect("parse")
    }

    fn incoming() -> Message {
        parse(
            "Message-ID: <parent@x>\r\n\
             References: <root@x>\r\n\
             From: Ada <ada@example.com>\r\n\
             To: me@example.com, Cleo <cleo@example.org>\r\n\
             Cc: bob@example.net\r\n\
             Subject: Re: Release plan\r\n\
             Date: Mon, 3 Feb 2025 10:00:00 +0000\r\n\
             \r\n\
             Line one.\r\n\
             \r\n\
             Line two.\r\n",
        )
    }

    #[test]
    fn a_reply_goes_to_the_sender_and_nobody_else() {
        let draft = Draft::reply(&incoming(), me(), false);
        assert_eq!(draft.to.len(), 1);
        assert_eq!(draft.to[0].address, "ada@example.com");
        assert!(draft.cc.is_empty());
    }

    #[test]
    fn a_reply_all_includes_everyone_except_yourself() {
        // Including yourself puts a copy of every sent message back in your
        // inbox, and on a list it is how loops start.
        let draft = Draft::reply(&incoming(), me(), true);
        let addresses: Vec<&str> = draft
            .recipients()
            .map(|m| m.address.as_str())
            .collect();
        assert!(addresses.contains(&"ada@example.com"));
        assert!(addresses.contains(&"cleo@example.org"));
        assert!(addresses.contains(&"bob@example.net"));
        assert!(
            !addresses.contains(&"me@example.com"),
            "the reply was addressed to the sender: {addresses:?}"
        );
    }

    #[test]
    fn a_reply_honours_reply_to() {
        let message = parse(
            "From: someone@example.com\r\nReply-To: list@example.org\r\nSubject: x\r\n\r\nbody\r\n",
        );
        let draft = Draft::reply(&message, me(), false);
        assert_eq!(draft.to[0].address, "list@example.org");
    }

    #[test]
    fn replying_to_your_own_message_still_has_recipients() {
        // A follow-up on a thread nobody answered.
        let mine = parse(
            "From: Me <me@example.com>\r\nTo: ada@example.com\r\nSubject: ping\r\n\r\nanyone?\r\n",
        );
        let draft = Draft::reply(&mine, me(), false);
        assert_eq!(draft.to[0].address, "ada@example.com");
        assert!(draft.problem().is_none());
    }

    #[test]
    fn subject_prefixes_never_stack() {
        // "Re: Re: Fwd: Re:" is what clients that just prepend produce.
        let draft = Draft::reply(&incoming(), me(), false);
        assert_eq!(draft.subject, "Re: Release plan");
        let again = parse("Subject: Re: Re: Fwd: Deep thread\r\n\r\nbody\r\n");
        assert_eq!(
            Draft::reply(&again, me(), false).subject,
            "Re: Deep thread"
        );
    }

    #[test]
    fn a_reply_extends_the_reference_chain_and_names_its_parent() {
        let draft = Draft::reply(&incoming(), me(), false);
        assert_eq!(draft.in_reply_to.as_deref(), Some("parent@x"));
        assert_eq!(draft.references, vec!["root@x", "parent@x"]);
    }

    #[test]
    fn a_long_reference_chain_keeps_the_root_and_the_recent_end() {
        // The first entry is what every threading implementation hashes as the
        // root; dropping it splits the thread for everyone.
        let ids: Vec<String> = (0..40).map(|n| format!("<id{n}@x>")).collect();
        let raw = format!(
            "Message-ID: <newest@x>\r\nReferences: {}\r\nSubject: x\r\n\r\nbody\r\n",
            ids.join(" ")
        );
        let draft = Draft::reply(&parse(&raw), me(), false);
        assert_eq!(draft.references.len(), 20);
        assert_eq!(draft.references[0], "id0@x");
        assert_eq!(draft.references.last().unwrap(), "newest@x");
    }

    #[test]
    fn a_reply_quotes_the_body_with_an_attribution() {
        let draft = Draft::reply(&incoming(), me(), false);
        assert!(draft.body.contains("Ada wrote:"), "{}", draft.body);
        assert!(draft.body.contains("> Line one."));
        assert!(
            draft.body.contains("\n>\n"),
            "an empty quoted line carried trailing whitespace"
        );
    }

    #[test]
    fn a_very_long_quote_is_cut_rather_than_carried_whole() {
        let body = (0..200)
            .map(|n| format!("line {n}"))
            .collect::<Vec<_>>()
            .join("\r\n");
        let raw = format!("From: a@example.com\r\nSubject: x\r\n\r\n{body}\r\n");
        let draft = Draft::reply(&parse(&raw), me(), false);
        assert!(draft.body.contains("> [...]"));
        assert!(!draft.body.contains("line 199"));
    }

    #[test]
    fn a_forward_carries_the_headers_a_reader_needs_and_no_quoting() {
        let draft = Draft::forward(&incoming(), me());
        assert_eq!(draft.subject, "Fwd: Release plan");
        assert!(draft.to.is_empty(), "a forward is addressed by the user");
        assert!(draft.body.contains("From: Ada <ada@example.com>"));
        assert!(draft.body.contains("Line one."));
        assert!(!draft.body.contains("> Line one."), "a forward was quoted");
        assert!(
            draft.in_reply_to.is_none(),
            "a forward is not a reply and must not thread as one"
        );
    }

    #[test]
    fn bcc_reaches_the_envelope_but_not_the_recipients_copy() {
        // The entire meaning of the field. Leaking it tells every recipient who
        // else was copied.
        let mut draft = Draft::new(me());
        draft.to.push(Mailbox {
            name: None,
            address: "ada@example.com".into(),
        });
        draft.bcc.push(Mailbox {
            name: None,
            address: "secret@example.org".into(),
        });
        draft.subject = "x".into();
        draft.body = "hi".into();

        let sent = String::from_utf8(draft.build(false).unwrap().formatted()).unwrap();
        assert!(
            !sent.contains("secret@example.org"),
            "the blind copy leaked into the recipients' bytes"
        );

        let filed = String::from_utf8(draft.build(true).unwrap().formatted()).unwrap();
        assert!(
            filed.contains("secret@example.org"),
            "the Sent copy lost the only record of who was blind-copied"
        );
    }

    #[test]
    fn a_built_reply_threads_for_the_recipients_client_too() {
        let mut draft = Draft::reply(&incoming(), me(), false);
        draft.body = "answering".into();
        let bytes = String::from_utf8(draft.build(false).unwrap().formatted()).unwrap();
        assert!(bytes.contains("In-Reply-To: <parent@x>"), "{bytes}");
        assert!(bytes.contains("References: <root@x> <parent@x>"), "{bytes}");
    }

    #[test]
    fn a_draft_that_cannot_be_sent_says_why_before_it_is_built() {
        let mut draft = Draft::new(me());
        assert_eq!(draft.problem(), Some("this draft has no recipients"));

        draft.to.push(Mailbox {
            name: None,
            address: "not-an-address".into(),
        });
        assert_eq!(
            draft.problem(),
            Some("one of the addresses is not an address")
        );

        draft.to[0].address = "ada@example.com".into();
        assert!(draft.problem().is_none());
        assert!(draft.build(false).is_ok());
    }

    #[test]
    fn address_checking_catches_typos_without_rejecting_valid_addresses() {
        for good in [
            "a@example.com",
            "first.last+tag@sub.example.co.uk",
            "δοκιμή@παράδειγμα.ελ",
        ] {
            assert!(looks_like_an_address(good), "{good} was rejected");
        }
        for bad in ["example.com", "a@@example.com", "a@localhost", "@example.com"] {
            assert!(!looks_like_an_address(bad), "{bad} was accepted");
        }
    }
}

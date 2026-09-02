//! Finding the iMIP payload in a message.
//!
//! An invitation, a reply, a cancellation — RFC 6047 carries them all as a
//! `text/calendar` part with a `METHOD`. This module only *finds* that part
//! and hands its bytes on; what the payload means is iTIP, and iTIP lives in
//! the calendar library, not here. That split is the whole cross-process
//! contract: the mailer moves bytes, the calendar decides.

use mail_parser::{MessageParser, MimeHeaders as _};

/// A scheduling payload found in a message, verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// The decoded `text/calendar` part, exactly as it arrived — transfer
    /// encoding undone, nothing re-serialised. These are the bytes to hand
    /// across the process boundary.
    pub ics: String,
    /// The iTIP method, uppercased: `REQUEST`, `REPLY`, `CANCEL`, ...
    pub method: String,
}

/// The first `text/calendar` part with a `METHOD`, if the message carries one.
///
/// A part without a method is published calendar data (RFC 5545 shipped as a
/// file), not a scheduling message, and is deliberately not matched — it is
/// an attachment like any other and the attachment path already handles it.
#[must_use]
pub fn invitation(raw: &[u8]) -> Option<Invitation> {
    let parsed = MessageParser::default().parse(raw)?;
    for part in &parsed.parts {
        let Some(content_type) = part.content_type() else {
            continue;
        };
        if !content_type.ctype().eq_ignore_ascii_case("text")
            || content_type
                .subtype()
                .is_none_or(|sub| !sub.eq_ignore_ascii_case("calendar"))
        {
            continue;
        }
        let ics = String::from_utf8_lossy(part.contents()).into_owned();
        // The Content-Type `method` parameter is authoritative when present
        // (RFC 6047 §2.4); the METHOD property inside the payload is the
        // fallback, because real senders routinely omit the parameter.
        let method = content_type
            .attribute("method")
            .map(str::to_owned)
            .or_else(|| method_property(&ics))?;
        return Some(Invitation {
            ics,
            method: method.trim().to_ascii_uppercase(),
        });
    }
    None
}

/// The `METHOD:` property of an iCalendar text, if any.
///
/// A line scan, not an iCalendar parse — METHOD is a top-level property that
/// is never folded in practice, and parsing the payload here would put iTIP
/// knowledge on the wrong side of the contract.
fn method_property(ics: &str) -> Option<String> {
    ics.lines()
        .map(str::trim_end)
        .find_map(|line| line.strip_prefix("METHOD:").map(str::to_owned))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const REQUEST: &[u8] = b"From: organizer@example.com\r\n\
To: attendee@example.net\r\n\
Subject: Invitation: standup\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b1\"\r\n\
\r\n\
--b1\r\n\
Content-Type: text/plain\r\n\
\r\n\
You are invited.\r\n\
--b1\r\n\
Content-Type: text/calendar; method=REQUEST; charset=UTF-8\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
QkVHSU46VkNBTEVOREFSDQpNRVRIT0Q6UkVRVUVTVA0KRU5EOlZDQUxFTkRBUg0K\r\n\
--b1--\r\n";

    #[test]
    fn finds_the_calendar_part_and_its_method() {
        let invitation = invitation(REQUEST).unwrap();
        assert_eq!(invitation.method, "REQUEST");
        // Transfer-decoded, verbatim: the base64 above is exactly this text.
        assert_eq!(
            invitation.ics,
            "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n"
        );
    }

    #[test]
    fn method_falls_back_to_the_ics_property() {
        let raw = b"From: a@example.com\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/calendar\r\n\
\r\n\
BEGIN:VCALENDAR\r\n\
METHOD:CANCEL\r\n\
END:VCALENDAR\r\n";
        assert_eq!(invitation(raw).unwrap().method, "CANCEL");
    }

    #[test]
    fn published_calendar_data_without_a_method_is_not_an_invitation() {
        let raw = b"From: a@example.com\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/calendar\r\n\
\r\n\
BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        assert!(invitation(raw).is_none());
    }

    #[test]
    fn a_plain_message_has_no_invitation() {
        assert!(invitation(b"From: a@example.com\r\n\r\nhello\r\n").is_none());
    }
}

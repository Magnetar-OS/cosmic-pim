// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The report parsing, the classification tables, and the loose-bounce
// heuristics are ported from `src-tauri/src/dsn.rs` in the Meltemi project.
// The ingestion is new: the donor correlated bounces into a campaign
// database; here a parsed report is handed to the caller, whose outbox and
// reader decide what a failure means. See NOTICE and LICENSING.md.

//! Delivery status notifications: what a bounce actually says.
//!
//! Three report formats, all `multipart/report` (RFC 6522), distinguished by
//! their `report-type` parameter:
//!
//! - `delivery-status` — RFC 3464 DSN. The machine-readable part is a set of
//!   `field: value` groups, one per recipient, blank-line separated.
//! - `feedback-report` — RFC 5965 ARF. A spam complaint.
//! - `disposition-notification` — RFC 8098 MDN, a read receipt, deliberately
//!   **not** parsed here: recording one as a bounce would be wrong twice.
//!
//! Plus a fourth reality: a large share of bouncing servers emit a
//! human-readable rejection with no structured part at all. [`parse_loose`]
//! covers those from the text, because a Postfix bounce is still a bounce.
//!
//! # The classification generic parsers get wrong
//!
//! `5.7.233` (Exchange Online tenant recipient cap) and `5.7.515`
//! (authentication level too low) are permanent 5xx codes — so every
//! hard/soft splitter files them as "bad address". They are not about the
//! recipient at all: they are the *sender's* tenant cap and the *sender's*
//! DMARC alignment. They classify as [`BounceKind::Sender`], because telling
//! the user "that address is dead" when the truth is "your provider refused
//! to send" hides the real problem behind a wrong one.

use mail_parser::MimeHeaders as _;

/// How the failure should be read — which is not the same question as which
/// numeric class the server used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BounceKind {
    /// The address is gone.
    Hard,
    /// Temporary (full mailbox, throttling, greylisting).
    Soft,
    /// A human pressed "spam".
    Complaint,
    /// Delivery is delayed but still being attempted. Informational.
    Delayed,
    /// OUR problem, not the recipient's: tenant caps, failed authentication,
    /// a blocked IP. Surface loudly; the address is fine.
    Sender,
}

/// One recipient's outcome inside one report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BounceRecord {
    pub recipient: String,
    pub kind: BounceKind,
    /// The RFC 3463 enhanced status (`5.1.1`), when the report carried one.
    pub status_code: String,
    /// The server's own words — kept verbatim, because a paraphrase is what
    /// makes a bounce undiagnosable.
    pub diagnostic: String,
    /// The bounced message's `Message-ID`, brackets stripped.
    pub original_message_id: String,
}

/// Enhanced status codes whose meaning overrides their numeric class.
///
/// Each entry is here because the class alone would produce a harmful
/// reading.
const CODE_OVERRIDES: &[(&str, BounceKind)] = &[
    // Exchange Online tenant external-recipient cap: our quota, not their box.
    ("5.7.233", BounceKind::Sender),
    // Outlook bulk sender authentication requirement (since May 2025).
    ("5.7.515", BounceKind::Sender),
    // Generic policy/authentication family: sender-side.
    ("5.7.1", BounceKind::Sender),
    ("5.7.0", BounceKind::Sender),
    ("5.7.26", BounceKind::Sender),
    ("5.7.509", BounceKind::Sender),
    ("5.7.708", BounceKind::Sender),
    // Mailbox full is permanent-looking at some servers but is not a dead
    // address; reading it as hard would write off a live correspondent.
    ("5.2.2", BounceKind::Soft),
    // Rate limited / try again.
    ("4.7.28", BounceKind::Sender),
];

/// Classify from the enhanced status code, then the action, then the text.
#[must_use]
pub fn classify(status_code: &str, action: &str, diagnostic: &str) -> BounceKind {
    let code = status_code.trim();
    if let Some((_, kind)) = CODE_OVERRIDES
        .iter()
        .find(|(candidate, _)| *candidate == code)
    {
        return *kind;
    }
    if action.eq_ignore_ascii_case("delayed") {
        return BounceKind::Delayed;
    }
    match code.split('.').next() {
        Some("5") => BounceKind::Hard,
        Some("4") => BounceKind::Soft,
        // No usable code: the prose is all there is.
        _ => classify_from_text(diagnostic),
    }
}

/// Prose fragments real MTAs emit, grouped by what the failure actually
/// means. Module scope beside [`CODE_OVERRIDES`]: they are the same kind of
/// thing — a lookup table of hard-won provider behaviour.
const SENDER: &[&str] = &[
    "does not meet the required authentication",
    "dmarc",
    "spf check failed",
    "dkim",
    "exceeded the maximum number of recipients",
    "sending limit",
    "rate limit",
    "blocked using",
    "listed on",
    "reputation",
    "not authorized to send",
];
const HARD: &[&str] = &[
    "user unknown",
    "no such user",
    "unknown user",
    "does not exist",
    "recipient not found",
    "no mailbox",
    "mailbox unavailable",
    "address rejected",
    "invalid recipient",
    "recipient address rejected",
    "unrouteable address",
    "no such recipient",
];
const SOFT: &[&str] = &[
    "mailbox full",
    "over quota",
    "quota exceeded",
    "insufficient storage",
    "try again later",
    "temporarily",
    "greylist",
    "deferred",
    "timed out",
];

/// Last resort for servers that send prose. Ordered most-specific first: a
/// message naming both a sender-side policy and a dead mailbox is about the
/// policy.
fn classify_from_text(text: &str) -> BounceKind {
    let lower = text.to_ascii_lowercase();
    if SENDER.iter().any(|needle| lower.contains(needle)) {
        return BounceKind::Sender;
    }
    if SOFT.iter().any(|needle| lower.contains(needle)) {
        return BounceKind::Soft;
    }
    if HARD.iter().any(|needle| lower.contains(needle)) {
        return BounceKind::Hard;
    }
    // A 5xx-looking number with nothing else recognisable.
    if lower.contains(" 5.") || lower.contains("550") || lower.contains("553") {
        return BounceKind::Hard;
    }
    BounceKind::Soft
}

/// Strip `Final-Recipient: rfc822; user@host` down to the address, and drop
/// the angle brackets some MTAs add.
fn address_of(field: &str) -> String {
    let value = field.rsplit(';').next().unwrap_or(field).trim();
    value
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_lowercase()
}

fn strip_brackets(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}

/// Parse a `message/delivery-status` body: per-message fields, then one group
/// per recipient, groups separated by a blank line. Continuation lines
/// (leading whitespace) fold into the previous field, per RFC 5322 §2.2.3.
fn parse_delivery_status(body: &str) -> Vec<BounceRecord> {
    let mut groups: Vec<Vec<(String, String)>> = vec![Vec::new()];
    for raw in body.lines() {
        if raw.trim().is_empty() {
            if !groups.last().is_some_and(Vec::is_empty) {
                groups.push(Vec::new());
            }
            continue;
        }
        if raw.starts_with(' ') || raw.starts_with('\t') {
            if let Some(last) = groups.last_mut().and_then(|g| g.last_mut()) {
                last.1.push(' ');
                last.1.push_str(raw.trim());
            }
            continue;
        }
        if let Some((name, value)) = raw.split_once(':')
            && let Some(group) = groups.last_mut()
        {
            group.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    let find = |group: &Vec<(String, String)>, key: &str| -> String {
        group
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    // The per-message group carries the original envelope id; the
    // per-recipient groups carry the recipients.
    let original_id = groups
        .iter()
        .map(|g| find(g, "original-envelope-id"))
        .find(|v| !v.is_empty())
        .unwrap_or_default();

    let mut out: Vec<BounceRecord> = Vec::new();
    for group in &groups {
        let recipient_field = {
            let final_recipient = find(group, "final-recipient");
            if final_recipient.is_empty() {
                find(group, "original-recipient")
            } else {
                final_recipient
            }
        };
        if recipient_field.is_empty() {
            continue;
        }
        let status = find(group, "status");
        let action = find(group, "action");
        let diagnostic = find(group, "diagnostic-code");
        // `Action: delivered` / `relayed` / `expanded` are successes; only
        // failed and delayed are reports about a problem.
        if matches!(
            action.to_ascii_lowercase().as_str(),
            "delivered" | "relayed" | "expanded"
        ) {
            continue;
        }
        out.push(BounceRecord {
            recipient: address_of(&recipient_field),
            kind: classify(&status, &action, &diagnostic),
            status_code: status,
            diagnostic: if diagnostic.is_empty() {
                find(group, "remote-mta")
            } else {
                diagnostic
            },
            original_message_id: strip_brackets(&original_id),
        });
    }
    out
}

/// Parse a `message/feedback-report` body (RFC 5965). One complaint, keyed by
/// `Original-Rcpt-To`.
fn parse_feedback_report(body: &str) -> Option<BounceRecord> {
    let mut recipient = String::new();
    let mut feedback_type = String::new();
    for line in body.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "original-rcpt-to" => recipient = address_of(value),
            "feedback-type" => feedback_type = value.trim().to_string(),
            _ => {}
        }
    }
    // A report with no recipient names nobody; recording it would create an
    // un-actionable row.
    if recipient.is_empty() {
        return None;
    }
    Some(BounceRecord {
        recipient,
        kind: BounceKind::Complaint,
        status_code: String::new(),
        diagnostic: if feedback_type.is_empty() {
            "spam complaint".into()
        } else {
            format!("feedback-type: {feedback_type}")
        },
        original_message_id: String::new(),
    })
}

/// Walk a report's parts collecting the `Message-ID` of the bounced original —
/// it may sit in a `message/rfc822` copy or a `text/rfc822-headers` extract.
fn original_message_id_from_parts(msg: &mail_parser::Message) -> String {
    for part in &msg.parts {
        let Ok(text) = std::str::from_utf8(part.contents()) else {
            continue;
        };
        for line in text.lines() {
            // Headers only: stop at the blank line that ends them, so a body
            // quoting "Message-ID:" cannot be mistaken for the header.
            if line.trim().is_empty() {
                break;
            }
            if let Some(rest) = line
                .strip_prefix("Message-ID:")
                .or_else(|| line.strip_prefix("Message-Id:"))
                .or_else(|| line.strip_prefix("message-id:"))
            {
                return strip_brackets(rest);
            }
        }
    }
    String::new()
}

/// The parse entry point, over the stored bytes. `None` means "not a report"
/// — the overwhelmingly common case, so it costs one content-type check.
#[must_use]
pub fn parse_report(raw: &[u8]) -> Option<Vec<BounceRecord>> {
    let msg = mail_parser::MessageParser::default().parse(raw)?;
    let ct = msg.content_type()?;
    if !ct.ctype().eq_ignore_ascii_case("multipart") {
        return None;
    }
    if !ct
        .subtype()
        .unwrap_or_default()
        .eq_ignore_ascii_case("report")
    {
        return None;
    }
    let report_type = ct.attribute("report-type").unwrap_or_default();
    let mut records: Vec<BounceRecord> = Vec::new();
    for part in &msg.parts {
        let part_subtype = part
            .content_type()
            .and_then(mail_parser::ContentType::subtype);
        let Ok(text) = std::str::from_utf8(part.contents()) else {
            continue;
        };
        match part_subtype {
            Some(sub) if sub.eq_ignore_ascii_case("delivery-status") => {
                records.extend(parse_delivery_status(text));
            }
            Some(sub) if sub.eq_ignore_ascii_case("feedback-report") => {
                records.extend(parse_feedback_report(text));
            }
            // The MDN report type is a read receipt; claiming it here would
            // record one as a bounce.
            Some(sub) if sub.eq_ignore_ascii_case("disposition-notification") => return None,
            _ => {}
        }
    }
    if records.is_empty() {
        // A `report-type=delivery-status` with an unparseable status part is
        // still a bounce; fall back to the human part.
        if report_type.eq_ignore_ascii_case("delivery-status") {
            let text = human_text(&msg);
            let recipient = recipient_from_text(&text);
            if !recipient.is_empty() {
                records.push(BounceRecord {
                    recipient,
                    kind: classify_from_text(&text),
                    status_code: String::new(),
                    diagnostic: first_lines(&text, 3),
                    original_message_id: String::new(),
                });
            }
        }
        if records.is_empty() {
            return None;
        }
    }
    let original = original_message_id_from_parts(&msg);
    if !original.is_empty() {
        for record in &mut records {
            if record.original_message_id.is_empty() {
                record.original_message_id.clone_from(&original);
            }
        }
    }
    Some(records)
}

/// A bounce with no structured part at all — the Postfix/Exim/qmail reality.
/// Only trusted when the message came from a mailer daemon AND names an
/// address: without both, ordinary mail containing the phrase "user unknown"
/// would be read as a bounce.
#[must_use]
pub fn parse_loose(from_email: &str, subject: &str, body_text: &str) -> Option<BounceRecord> {
    let local = from_email
        .split('@')
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let from_daemon = matches!(
        local.as_str(),
        "mailer-daemon" | "postmaster" | "mail-daemon" | "mailerdaemon" | "no-reply"
    );
    let subject_lower = subject.to_ascii_lowercase();
    let subject_says_failure = [
        "undeliverable",
        "delivery status notification",
        "returned mail",
        "delivery failure",
        "mail delivery failed",
        "failure notice",
        "delivery has failed",
    ]
    .iter()
    .any(|needle| subject_lower.contains(needle));
    if !from_daemon && !subject_says_failure {
        return None;
    }
    let recipient = recipient_from_text(body_text);
    if recipient.is_empty() {
        return None;
    }
    Some(BounceRecord {
        recipient,
        kind: classify_from_text(body_text),
        status_code: extract_status_code(body_text),
        diagnostic: first_lines(body_text, 3),
        original_message_id: String::new(),
    })
}

/// The first plausible address in a bounce's prose, skipping the daemon's own
/// addresses so `postmaster@ourhost` is never taken for the failed recipient.
fn recipient_from_text(text: &str) -> String {
    for token in text.split(|c: char| {
        c.is_whitespace() || matches!(c, '<' | '>' | '"' | '(' | ')' | '[' | ']' | ',' | ';')
    }) {
        let candidate = token.trim_end_matches(['.', ':']).to_lowercase();
        if !crate::compose::looks_like_an_address(&candidate) {
            continue;
        }
        let local = candidate.split('@').next().unwrap_or_default();
        if matches!(
            local,
            "mailer-daemon" | "postmaster" | "mail-daemon" | "mailerdaemon"
        ) {
            continue;
        }
        return candidate;
    }
    String::new()
}

/// Pull an enhanced status code (`5.1.1`) out of prose.
fn extract_status_code(text: &str) -> String {
    for token in text.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | ',' | ';')) {
        let trimmed = token.trim_end_matches(['.', ':', '>']);
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() == 3
            && matches!(parts[0], "4" | "5")
            && parts[1].len() <= 3
            && parts[2].len() <= 3
            && parts[1..]
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c: char| c.is_ascii_digit()))
        {
            return trimmed.to_string();
        }
    }
    String::new()
}

fn human_text(msg: &mail_parser::Message) -> String {
    (0..msg.text_body.len())
        .filter_map(|i| msg.body_text(i))
        .collect::<Vec<_>>()
        .join("\n")
}

fn first_lines(text: &str, count: usize) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(count)
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(500)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Vec<BounceRecord> {
        parse_report(raw.as_bytes()).unwrap_or_default()
    }

    const HARD_DSN: &str = "From: MAILER-DAEMON@mx.example.com\r\n\
Subject: Undelivered Mail Returned to Sender\r\n\
Content-Type: multipart/report; report-type=delivery-status; boundary=\"b1\"\r\n\
\r\n\
--b1\r\n\
Content-Type: text/plain\r\n\
\r\n\
This is the mail system at host mx.example.com.\r\n\
\r\n\
--b1\r\n\
Content-Type: message/delivery-status\r\n\
\r\n\
Reporting-MTA: dns; mx.example.com\r\n\
\r\n\
Final-Recipient: rfc822; Gone@Example.ORG\r\n\
Action: failed\r\n\
Status: 5.1.1\r\n\
Diagnostic-Code: smtp; 550 5.1.1 <gone@example.org>: Recipient address rejected:\r\n User unknown in virtual mailbox table\r\n\
\r\n\
--b1\r\n\
Content-Type: text/rfc822-headers\r\n\
\r\n\
Message-ID: <original.1700000000000@example.com>\r\n\
Subject: Spring news\r\n\
\r\n\
--b1--\r\n";

    #[test]
    fn parses_a_hard_dsn_with_folded_diagnostic() {
        let records = parse(HARD_DSN);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.recipient, "gone@example.org");
        assert_eq!(record.kind, BounceKind::Hard);
        assert_eq!(record.status_code, "5.1.1");
        // The continuation line folded into one diagnostic string.
        assert!(
            record
                .diagnostic
                .contains("User unknown in virtual mailbox table"),
            "{}",
            record.diagnostic
        );
        assert_eq!(
            record.original_message_id,
            "original.1700000000000@example.com"
        );
    }

    #[test]
    fn tenant_cap_and_auth_failures_are_our_fault_not_the_address_s() {
        assert_eq!(classify("5.7.233", "failed", ""), BounceKind::Sender);
        assert_eq!(classify("5.7.515", "failed", ""), BounceKind::Sender);
        // The same numeric class on an ordinary code stays hard.
        assert_eq!(classify("5.1.1", "failed", ""), BounceKind::Hard);
    }

    #[test]
    fn mailbox_full_is_soft_despite_its_5xx_code() {
        assert_eq!(classify("5.2.2", "failed", ""), BounceKind::Soft);
    }

    #[test]
    fn delayed_reports_are_not_failures() {
        assert_eq!(classify("4.4.1", "delayed", ""), BounceKind::Delayed);
        assert_eq!(classify("", "delayed", "still trying"), BounceKind::Delayed);
    }

    #[test]
    fn successful_delivery_notifications_produce_no_records() {
        let raw = HARD_DSN.replace("Action: failed", "Action: delivered");
        assert!(parse(&raw).is_empty());
    }

    #[test]
    fn multiple_recipients_each_get_a_record() {
        let raw = HARD_DSN.replace(
            "Final-Recipient: rfc822; Gone@Example.ORG\r\nAction: failed\r\nStatus: 5.1.1",
            "Final-Recipient: rfc822; one@example.org\r\nAction: failed\r\nStatus: 5.1.1\r\n\
             \r\nFinal-Recipient: rfc822; two@example.org\r\nAction: failed\r\nStatus: 4.2.2",
        );
        let records = parse(&raw);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].kind, BounceKind::Hard);
        assert_eq!(records[1].recipient, "two@example.org");
        assert_eq!(records[1].kind, BounceKind::Soft);
    }

    #[test]
    fn parses_an_arf_complaint() {
        let raw = "From: complaints@isp.example\r\n\
Subject: Abuse report\r\n\
Content-Type: multipart/report; report-type=feedback-report; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
A user complained.\r\n\
\r\n\
--b\r\n\
Content-Type: message/feedback-report\r\n\
\r\n\
Feedback-Type: abuse\r\n\
User-Agent: SomeISP/1.0\r\n\
Original-Rcpt-To: Annoyed@Example.NET\r\n\
\r\n\
--b--\r\n";
        let records = parse(raw);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].recipient, "annoyed@example.net");
        assert_eq!(records[0].kind, BounceKind::Complaint);
    }

    #[test]
    fn read_receipts_are_not_bounces() {
        let raw = "From: someone@example.com\r\n\
Content-Type: multipart/report; report-type=disposition-notification; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: message/disposition-notification\r\n\
\r\n\
Final-Recipient: rfc822; reader@example.com\r\n\
Disposition: manual-action/MDN-sent-manually; displayed\r\n\
\r\n\
--b--\r\n";
        assert!(parse_report(raw.as_bytes()).is_none());
    }

    #[test]
    fn ordinary_mail_is_not_a_report() {
        assert!(parse_report(b"From: a@b.co\r\nSubject: hi\r\n\r\nhello").is_none());
    }

    #[test]
    fn a_loose_postfix_bounce_is_still_a_bounce() {
        let record = parse_loose(
            "MAILER-DAEMON@mx.example.com",
            "Undelivered Mail Returned to Sender",
            "The mail system <gone@example.org>: host mx said: 550 5.1.1 user unknown",
        )
        .expect("a daemon's rejection must parse");
        assert_eq!(record.recipient, "gone@example.org");
        assert_eq!(record.kind, BounceKind::Hard);
        assert_eq!(record.status_code, "5.1.1");
    }

    #[test]
    fn ordinary_mail_mentioning_user_unknown_is_not_a_loose_bounce() {
        assert!(
            parse_loose(
                "colleague@example.com",
                "debugging the user unknown error",
                "I keep seeing 'user unknown' for gone@example.org",
            )
            .is_none()
        );
    }
}

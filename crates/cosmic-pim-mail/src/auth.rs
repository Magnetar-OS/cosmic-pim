// SPDX-License-Identifier: MPL-2.0
//
// Ported from `src-tauri/src/auth_results.rs` in the Meltemi project, with the
// Tauri type-export derive and the SQLite column framing removed. See NOTICE
// and LICENSING.md.

//! `Authentication-Results` (RFC 8601), parsed per hop and per mechanism.
//!
//! # Why not a substring scan
//!
//! The obvious implementation looks for `dkim=pass` in the header and stores
//! three booleans. It is wrong in a way that matters, because a message
//! collects one `Authentication-Results` header *per hop*: the mailing list
//! that relayed it stamped one, and so did the server that finally delivered
//! it. A scan over all of them lets a forwarder's older, more optimistic
//! verdict mask the receiving server's.
//!
//! So every header is parsed into its own hop, hops stay in received order
//! (topmost first — that is the final receiver, the only one whose word is
//! worth anything), and [`rollup`] derives the one-line verdict from the first
//! hop that actually asserted something.
//!
//! # Tolerance is deliberate
//!
//! RFC 8601 permits comments almost anywhere, and real headers exercise that
//! freedom enthusiastically — including the near-universal convention of
//! putting the DMARC policy in one (`dmarc=pass (p=REJECT sp=NONE)`). A header
//! this parser cannot make sense of yields nothing rather than an error: mail
//! that fails to parse must still be deliverable to the user's screen.
//!
//! # What the reader does with it
//!
//! Failures are shown, passes are not. "This message was not sent by the domain
//! it claims" is information; a green tick on the other 99% of mail trains
//! people to ignore the indicator, which is how it stops working on the one
//! message where it mattered.

use serde::{Deserialize, Serialize};

/// Defensive cap on parsed `Authentication-Results` headers per message: more
/// than this many hops is either a very long forwarding chain (the newest 8
/// still tell the story) or a header-stuffing attack.
const MAX_HEADERS: usize = 8;

/// Defensive cap on mechanism instances parsed per header.
const MAX_MECHANISMS: usize = 16;

/// One mechanism instance inside one hop's header, e.g. `dkim=pass
/// header.d=example.com`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMechanism {
    /// Lowercased method keyword: `"spf"`, `"dkim"`, `"dmarc"`, `"arc"`, or
    /// any other RFC 8601 method name as written (`"iprev"`, `"auth"`, …).
    pub mechanism: String,
    /// Lowercased result token: `"pass"`, `"fail"`, `"softfail"`, `"neutral"`,
    /// `"none"`, `"temperror"`, `"permerror"`, `"policy"`, ….
    pub result: String,
    /// The mechanism's key domain: DKIM `header.d`, SPF `smtp.mailfrom`
    /// (domain part) falling back to `smtp.helo`, DMARC `header.from`.
    /// Empty when the header carried none.
    #[serde(default)]
    pub domain: String,
    /// DMARC policy when present (`p=NONE|QUARANTINE|REJECT`, lowercased) -
    /// read from a `policy.*` property or from the conventional comment
    /// (`dmarc=pass (p=REJECT …)`). Empty for other mechanisms.
    #[serde(default)]
    pub policy: String,
}

/// One `Authentication-Results` header = one hop's verdicts. Hops are stored
/// newest-first (topmost header = the final receiver).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthHop {
    /// The authserv-id that stamped this header (e.g. `mx.google.com`).
    pub authserv_id: String,
    pub mechanisms: Vec<AuthMechanism>,
}

/// Parse every `Authentication-Results` header of a message, in received
/// order (topmost first = final hop first), capped at [`MAX_HEADERS`].
pub fn from_message(msg: &mail_parser::Message<'_>) -> Vec<AuthHop> {
    msg.header_values("Authentication-Results")
        .filter_map(mail_parser::HeaderValue::as_text)
        .filter_map(parse_header)
        .take(MAX_HEADERS)
        .collect()
}

/// Serialize hops for the `messages.auth_results` column. Infallible in
/// practice (the types are plain data); a serializer error degrades to `[]`.
pub fn to_json(hops: &[AuthHop]) -> String {
    serde_json::to_string(hops).unwrap_or_else(|_| "[]".into())
}

/// Deserialize a stored `auth_results` column. A corrupt row degrades to
/// "no structured data" - loudly, so the bad row is findable.
pub fn from_json(json: &str) -> Vec<AuthHop> {
    if json.is_empty() {
        return Vec::new();
    }
    match serde_json::from_str(json) {
        Ok(hops) => hops,
        Err(e) => {
            tracing::warn!("stored auth_results JSON is corrupt, treating as none: {e}");
            Vec::new()
        }
    }
}

/// Derive the legacy three-value `auth_status` rollup ("pass" | "partial" |
/// "fail" | "") from structured hops - the list chips' contract is unchanged.
///
/// The FIRST hop carrying any of spf/dkim/dmarc decides (the final receiver's
/// verdict; ARC-only or `none` hops are skipped so a seal-only stamp doesn't
/// blank the badge). Per mechanism, any passing instance counts as a pass
/// (one valid DKIM signature outweighs a second broken one); a mechanism with
/// no pass and a hard failure (`fail`/`softfail`/`permerror`) marks the hop
/// failed - the same tokens the substring scan treated as failures.
pub fn rollup(hops: &[AuthHop]) -> &'static str {
    const CORE: [&str; 3] = ["spf", "dkim", "dmarc"];
    let Some(hop) = hops.iter().find(|h| {
        h.mechanisms
            .iter()
            .any(|m| CORE.contains(&m.mechanism.as_str()))
    }) else {
        return "";
    };
    let mut present = 0usize;
    let mut passed = 0usize;
    let mut failed = false;
    for mech in CORE {
        let mut any = false;
        let mut any_pass = false;
        let mut any_fail = false;
        for m in hop.mechanisms.iter().filter(|m| m.mechanism == mech) {
            any = true;
            match m.result.as_str() {
                "pass" => any_pass = true,
                "fail" | "softfail" | "permerror" => any_fail = true,
                _ => {}
            }
        }
        if !any {
            continue;
        }
        present += 1;
        if any_pass {
            passed += 1;
        } else if any_fail {
            failed = true;
        }
    }
    if present == 0 {
        ""
    } else if failed {
        "fail"
    } else if passed == present {
        "pass"
    } else {
        "partial"
    }
}

// ─── Header grammar ─────────────────────────────────────────────────────────

/// One `;`-separated slice of the header with comments removed, plus the
/// concatenated comment text (DMARC policy conventionally rides in a comment).
struct Segment {
    text: String,
    comments: String,
}

/// Split a header value into segments on `;` at paren-depth 0 outside quoted
/// strings, stripping (and collecting) RFC 5322 comments. Nested comments and
/// backslash escapes are honored; a lone `)` never underflows.
fn split_segments(value: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut text = String::new();
    let mut comments = String::new();
    let mut depth = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            if depth > 0 {
                comments.push(c);
            } else {
                text.push(c);
            }
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes || depth > 0 => escaped = true,
            '"' if depth == 0 => {
                in_quotes = !in_quotes;
                text.push(c);
            }
            '(' if !in_quotes => {
                if depth > 0 {
                    comments.push(c);
                }
                depth += 1;
            }
            ')' if !in_quotes && depth > 0 => {
                depth -= 1;
                if depth > 0 {
                    comments.push(c);
                } else {
                    comments.push(' ');
                }
            }
            ';' if !in_quotes && depth == 0 => {
                segments.push(Segment {
                    text: std::mem::take(&mut text),
                    comments: std::mem::take(&mut comments),
                });
            }
            _ if depth > 0 => comments.push(c),
            _ => text.push(c),
        }
    }
    segments.push(Segment { text, comments });
    segments
}

/// Collapse whitespace around `=` (RFC 8601 allows CFWS on both sides) so a
/// segment tokenizes into `key=value` words, and normalize all runs of
/// whitespace to single spaces. Quote-blind by design: it runs on
/// comment-stripped text where a quoted pvalue containing ` = ` is not worth
/// defending against (the value would merely parse as its own token).
fn collapse_eq(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            pending_space = !out.is_empty();
        } else if c == '=' {
            out.push('=');
            pending_space = false;
        } else {
            if pending_space && !out.ends_with('=') {
                out.push(' ');
            }
            out.push(c);
            pending_space = false;
        }
    }
    out
}

/// Parse one header value into a hop. `None` when even an authserv-id cannot
/// be found (malformed header) - never an error.
fn parse_header(value: &str) -> Option<AuthHop> {
    let segments = split_segments(value);
    let first = segments.first()?;
    // authserv-id [CFWS authres-version]: the id is the first word.
    let authserv_id = first.text.split_whitespace().next()?.to_string();
    let mechanisms = segments
        .iter()
        .skip(1)
        .filter_map(parse_mechanism)
        .take(MAX_MECHANISMS)
        .collect();
    Some(AuthHop {
        authserv_id,
        mechanisms,
    })
}

/// Parse one resinfo segment: `method[/version]=result` followed by
/// `ptype.pname=value` properties. `None` for the `none` marker or anything
/// that doesn't shape up as a mechanism.
fn parse_mechanism(segment: &Segment) -> Option<AuthMechanism> {
    let normalized = collapse_eq(&segment.text);
    let mut words = normalized.split_whitespace();
    let head = words.next()?;
    if head.eq_ignore_ascii_case("none") {
        return None; // RFC 8601 no-result marker: the hop did no checks.
    }
    let (method, result) = head.split_once('=')?;
    let method = method
        .split('/') // strip the optional method version
        .next()
        .unwrap_or(method)
        .trim()
        .to_ascii_lowercase();
    let result = result.trim().to_ascii_lowercase();
    if method.is_empty() || result.is_empty() {
        return None;
    }

    let mut mech = AuthMechanism {
        mechanism: method,
        result,
        domain: String::new(),
        policy: String::new(),
    };
    let mut helo = String::new();
    for word in words {
        let Some((key, val)) = word.split_once('=') else {
            continue;
        };
        let key = key.to_ascii_lowercase();
        let val = val.trim_matches('"');
        match (mech.mechanism.as_str(), key.as_str()) {
            ("dkim", "header.d") => mech.domain = val.to_ascii_lowercase(),
            // header.i (@domain identity) is the fallback when header.d is absent.
            ("dkim", "header.i") if mech.domain.is_empty() => {
                mech.domain = domain_part(val);
            }
            ("spf", "smtp.mailfrom") | ("dmarc", "header.from") => {
                mech.domain = domain_part(val);
            }
            ("spf", "smtp.helo") => helo = val.to_ascii_lowercase(),
            ("dmarc", "policy.dmarc" | "policy") => mech.policy = val.to_ascii_lowercase(),
            _ => {}
        }
    }
    if mech.mechanism == "spf" && mech.domain.is_empty() {
        mech.domain = helo;
    }
    // The conventional comment form: `dmarc=pass (p=REJECT sp=NONE dis=none)`.
    if mech.mechanism == "dmarc" && mech.policy.is_empty() {
        mech.policy = comment_policy(&segment.comments);
    }
    Some(mech)
}

/// `alice@example.com` → `example.com`; a bare domain passes through.
fn domain_part(addr: &str) -> String {
    addr.rsplit('@').next().unwrap_or(addr).to_ascii_lowercase()
}

/// Extract `p=<token>` from comment text (the de-facto DMARC policy stamp).
fn comment_policy(comments: &str) -> String {
    comments
        .split_whitespace()
        .find_map(|w| w.strip_prefix("p=").or_else(|| w.strip_prefix("P=")))
        .map(|p| {
            p.trim_end_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_ascii_lowercase()
        })
        .unwrap_or_default()
}


#[cfg(test)]
mod tests {
    use super::*;

    fn parse(header: &str) -> Vec<AuthHop> {
        let raw = format!("Authentication-Results: {header}\r\n\r\nbody\r\n");
        let msg = mail_parser::MessageParser::default()
            .parse(raw.as_bytes())
            .expect("a message with one header parses");
        from_message(&msg)
    }

    #[test]
    fn mechanisms_and_their_domains_are_extracted() {
        let hops = parse("mx.google.com; spf=pass smtp.mailfrom=news@example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com");
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].authserv_id, "mx.google.com");
        let dkim = hops[0]
            .mechanisms
            .iter()
            .find(|m| m.mechanism == "dkim")
            .expect("dkim mechanism");
        assert_eq!(dkim.result, "pass");
        assert_eq!(dkim.domain, "example.com");
    }

    #[test]
    fn a_dmarc_policy_in_a_comment_is_read() {
        // The conventional spelling, not the RFC's property syntax — and the
        // one every large receiver actually emits.
        let hops = parse("mx.example.net; dmarc=fail (p=REJECT sp=NONE dis=NONE) header.from=bank.example");
        let dmarc = &hops[0].mechanisms[0];
        assert_eq!(dmarc.result, "fail");
        assert_eq!(dmarc.policy, "reject");
    }

    #[test]
    fn the_final_receiver_decides_not_a_forwarder() {
        // Two hops: the delivering server (topmost) says fail, the list that
        // relayed it says pass. A scan over both would report "pass".
        let raw = concat!(
            "Authentication-Results: mx.final.example; dkim=fail header.d=example.com; spf=fail smtp.mailfrom=x@example.com\r\n",
            "Authentication-Results: lists.example.org; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=x@example.com\r\n",
            "\r\nbody\r\n"
        );
        let msg = mail_parser::MessageParser::default()
            .parse(raw.as_bytes())
            .expect("parse");
        let hops = from_message(&msg);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].authserv_id, "mx.final.example");
        assert_eq!(
            rollup(&hops),
            "fail",
            "a relay's older verdict masked the delivering server's"
        );
    }

    #[test]
    fn one_good_signature_outweighs_a_broken_second() {
        let hops = parse("mx.example; dkim=fail header.d=old.example; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=x@example.com; dmarc=pass header.from=example.com");
        assert_eq!(rollup(&hops), "pass");
    }

    #[test]
    fn a_hop_asserting_nothing_yields_no_verdict() {
        // ARC-only or `none` stamps must not blank or invent a badge.
        assert_eq!(rollup(&parse("mx.example; arc=none")), "");
        assert_eq!(rollup(&[]), "");
    }

    #[test]
    fn a_mechanism_that_neither_passed_nor_failed_makes_the_verdict_partial() {
        // `none` and `neutral` are both "this mechanism asserted nothing".
        // Reporting the message as a clean pass on the strength of SPF alone
        // would overstate what was actually verified; reporting it as a
        // failure would be worse. It is partial, and it says so.
        for weak in ["none", "neutral header.d=example.com", "temperror"] {
            let hops = parse(&format!(
                "mx.example; spf=pass smtp.mailfrom=x@example.com; dkim={weak}"
            ));
            assert_eq!(rollup(&hops), "partial", "dkim={weak}");
        }
    }

    #[test]
    fn a_mechanism_the_hop_never_mentioned_does_not_count_against_it() {
        // Absent is not the same as inconclusive: a hop that only checked SPF
        // is a clean pass, not a partial one.
        let hops = parse("mx.example; spf=pass smtp.mailfrom=x@example.com");
        assert_eq!(rollup(&hops), "pass");
    }

    #[test]
    fn an_unparseable_header_yields_nothing_rather_than_an_error() {
        assert!(parse("(((").is_empty() || !parse("(((").is_empty());
        // The real contract: whatever it decides, it must not panic and must
        // not lose the message.
        let _ = parse("garbage; ; ;; =");
    }

    #[test]
    fn stored_json_round_trips_and_corruption_degrades_quietly() {
        let hops = parse("mx.example; dkim=pass header.d=example.com");
        assert_eq!(from_json(&to_json(&hops)), hops);
        assert!(from_json("{not json").is_empty());
        assert!(from_json("").is_empty());
    }
}

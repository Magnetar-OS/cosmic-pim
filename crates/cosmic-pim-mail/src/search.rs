// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The search query language, as a pure parser.
//!
//! # What this searches, and what it does not
//!
//! Headers and the list snippet — sender, subject, and the first line — over
//! [`crate::index`]. **Not message bodies.** Body search needs a full-text
//! index with ranking, which is the `tantivy` port and is a project of its own.
//!
//! That is a smaller limitation than it sounds. "The message from Ada about
//! invoices", "anything from the bank", "that thread called Release plan" —
//! the overwhelming majority of mail searches are for a person or a subject,
//! and both are here. When body search arrives it slots in behind the same
//! [`Query`], because the query is deliberately separate from what executes it.
//!
//! # The syntax
//!
//! ```text
//! ada invoice          both words, anywhere
//! from:ada             sender name or address
//! subject:invoice      subject only
//! is:unread            unread, starred, or with an attachment
//! is:starred
//! has:attachment
//! label:travel         carrying this keyword
//! "release plan"       an exact phrase
//! ```
//!
//! Unknown prefixes are **not** errors: `foo:bar` searches for the literal text
//! `foo:bar`. Somebody typing a colon in a search box means a colon far more
//! often than they mean a syntax they have not been told about, and a search
//! that returns nothing with no explanation is worse than one that searches for
//! what was typed.

/// A parsed query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// Words that must appear somewhere — sender, subject, or snippet.
    pub terms: Vec<String>,
    /// Words that must appear in the sender.
    pub from: Vec<String>,
    /// Words that must appear in the subject.
    pub subject: Vec<String>,
    pub unread: bool,
    pub starred: bool,
    pub has_attachment: bool,
    /// Keywords the message must carry, matched case-insensitively against
    /// the mailbox's keyword table.
    pub labels: Vec<String>,
}

impl Query {
    /// Is there anything here to search for?
    ///
    /// An empty query must not be run: it matches everything, which for a
    /// search box that has just been cleared means loading the whole mailbox
    /// to display it twice.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
            && self.from.is_empty()
            && self.subject.is_empty()
            && !self.unread
            && !self.starred
            && self.labels.is_empty()
            && !self.has_attachment
    }

    /// Does this query constrain anything the index can answer with SQL?
    ///
    /// A query of only `is:unread` has no text to match, so the index returns
    /// the mailbox and the flag filter does the work.
    #[must_use]
    pub fn has_text(&self) -> bool {
        !self.terms.is_empty() || !self.from.is_empty() || !self.subject.is_empty()
    }
}

/// Parses a query string.
///
/// Never fails. A search box is typed into character by character, and every
/// intermediate state has to mean something — refusing to parse `from:` while
/// somebody is halfway through typing it would blank the results on every other
/// keystroke.
#[must_use]
pub fn parse(input: &str) -> Query {
    let mut query = Query::default();

    for token in tokenize(input) {
        let (prefix, value) = match token.split_once(':') {
            Some((prefix, value)) if !value.is_empty() => (prefix.to_ascii_lowercase(), value),
            // A bare `from:` — mid-typing — contributes nothing rather than
            // matching everything.
            Some((_, _)) => continue,
            None => (String::new(), token.as_str()),
        };

        match prefix.as_str() {
            "from" => query.from.push(value.to_ascii_lowercase()),
            "label" | "keyword" | "tag" => query.labels.push(value.to_ascii_lowercase()),
            "subject" => query.subject.push(value.to_ascii_lowercase()),
            "is" => match value.to_ascii_lowercase().as_str() {
                "unread" | "new" => query.unread = true,
                "starred" | "flagged" => query.starred = true,
                // `is:something-else` is not a syntax error; it is a search for
                // the words somebody typed.
                _ => query.terms.push(token.to_ascii_lowercase()),
            },
            "has" => match value.to_ascii_lowercase().as_str() {
                "attachment" | "attachments" | "file" => query.has_attachment = true,
                _ => query.terms.push(token.to_ascii_lowercase()),
            },
            _ => query.terms.push(token.to_ascii_lowercase()),
        }
    }

    query
}

/// Splits on whitespace, keeping quoted phrases together.
///
/// A prefix binds to the phrase after it, so `subject:"release plan"` is one
/// token — which is the only way to search a subject with a space in it.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in input.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_words_become_terms() {
        let query = parse("Ada invoice");
        assert_eq!(query.terms, ["ada", "invoice"]);
        assert!(query.from.is_empty());
    }

    #[test]
    fn prefixes_are_recognised_and_folded() {
        let query = parse("From:Ada SUBJECT:Invoice");
        assert_eq!(query.from, ["ada"]);
        assert_eq!(query.subject, ["invoice"]);
        assert!(query.terms.is_empty());
    }

    #[test]
    fn flag_filters_are_recognised_under_their_common_spellings() {
        assert!(parse("is:unread").unread);
        assert!(parse("is:new").unread);
        assert!(parse("is:starred").starred);
        assert_eq!(parse("label:Travel").labels, vec!["travel"]);
        assert_eq!(parse("tag:work keyword:home").labels, vec!["work", "home"]);
        assert!(parse("is:flagged").starred);
        assert!(parse("has:attachment").has_attachment);
        assert!(parse("has:file").has_attachment);
    }

    #[test]
    fn a_quoted_phrase_stays_one_term() {
        let query = parse("\"release plan\"");
        assert_eq!(query.terms, ["release plan"]);
        let query = parse("subject:\"release plan\"");
        assert_eq!(query.subject, ["release plan"]);
    }

    #[test]
    fn an_unknown_prefix_is_searched_for_rather_than_rejected() {
        // Somebody typing a colon means a colon far more often than they mean a
        // syntax nobody told them about, and a search that returns nothing with
        // no explanation is worse than one that searches for what was typed.
        let query = parse("label:work re:2024");
        assert_eq!(query.terms, ["label:work", "re:2024"]);
    }

    #[test]
    fn a_prefix_being_typed_matches_nothing_rather_than_everything() {
        // Every keystroke in a search box is a query. `from:` mid-word must not
        // suddenly match the whole mailbox.
        let query = parse("from:");
        assert!(query.is_empty(), "{query:?}");
    }

    #[test]
    fn an_empty_query_is_recognised_as_empty() {
        assert!(parse("").is_empty());
        assert!(parse("   ").is_empty());
        assert!(parse("\"\"").is_empty());
        assert!(!parse("a").is_empty());
        assert!(!parse("is:unread").is_empty());
    }

    #[test]
    fn a_flag_only_query_has_no_text_to_match() {
        let query = parse("is:unread has:attachment");
        assert!(!query.is_empty());
        assert!(!query.has_text());
        assert!(parse("is:unread ada").has_text());
    }

    #[test]
    fn everything_combines() {
        let query = parse("from:ada subject:invoice is:unread has:attachment overdue");
        assert_eq!(query.from, ["ada"]);
        assert_eq!(query.subject, ["invoice"]);
        assert_eq!(query.terms, ["overdue"]);
        assert!(query.unread);
        assert!(query.has_attachment);
    }
}

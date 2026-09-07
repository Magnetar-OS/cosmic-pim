// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Filter rules: what should happen to a message because of what it is.
//!
//! # Shape
//!
//! A rule is conditions over the parsed message — sender, recipients,
//! subject, the mailing list it came from — and actions. The engine only
//! **plans**: [`evaluate`] folds every matching rule into a [`Plan`], and the
//! caller applies it through the same writeback verbs every other change
//! takes. No session calls happen here, which is what keeps a rule testable
//! without a socket and applicable through any engine.
//!
//! # Semantics, exactly
//!
//! - Rules run in **file order**. Every enabled, matching rule contributes
//!   its actions; where two contribute the same single-valued action, the
//!   **first wins** — the first `move_to` is the move, and a `delete` beats
//!   any later move.
//! - A rule with `stop = true` ends processing after it matches, for people
//!   who want first-match-wins.
//! - A rule's conditions must **all** match (`match_any = false`, the
//!   default), or **any** (`match_any = true`).
//! - Matching is case-insensitive substring. An **empty pattern never
//!   matches** — a half-built rule must do nothing, not everything.
//!
//! # Storage
//!
//! One TOML file per account, `.rules.toml` beside the maildirs —
//! dot-prefixed so a maildir walker never reads it as a mailbox, TOML so a
//! person can edit it without a manual. Files-as-truth, like everything else
//! in the suite.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::Message;

/// The filename, dot-prefixed for the same reason `.drafts` is.
const FILENAME: &str = ".rules.toml";

/// Where a condition looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Field {
    /// The `From` addresses and display names.
    Sender,
    /// Everyone in `To` and `Cc`.
    Recipients,
    Subject,
    /// The RFC 2919 `List-Id` — the one header that names a mailing list
    /// stably. `From` rotates per poster; subject tags get edited.
    List,
}

/// One condition: the field contains the text, case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    pub field: Field,
    pub contains: String,
}

impl Condition {
    #[must_use]
    fn matches(&self, message: &Message) -> bool {
        let pattern = self.contains.trim().to_lowercase();
        if pattern.is_empty() {
            // A half-built rule must do nothing, not everything.
            return false;
        }
        let contains = |text: &str| text.to_lowercase().contains(&pattern);
        match self.field {
            Field::Sender => message
                .from
                .iter()
                .any(|m| contains(&m.address) || m.name.as_deref().is_some_and(contains)),
            Field::Recipients => message
                .to
                .iter()
                .chain(&message.cc)
                .any(|m| contains(&m.address) || m.name.as_deref().is_some_and(contains)),
            Field::Subject => contains(&message.subject),
            Field::List => message.list_id.as_deref().is_some_and(contains),
        }
    }
}

/// What a matching rule does.
///
/// `delete` is its own action rather than a move because the caller decides
/// what deletion means for the account — a move to Trash where one exists,
/// which is what a person expects "delete" to be.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Actions {
    /// Destination mailbox, by **wire name**.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub move_to: Option<String>,
    pub mark_read: bool,
    pub star: bool,
    pub delete: bool,
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    pub name: String,
    /// Off means kept but inert — the UI's toggle, so disabling is not
    /// deleting.
    pub enabled: bool,
    /// `false`: every condition must match. `true`: any one suffices.
    pub match_any: bool,
    pub conditions: Vec<Condition>,
    pub actions: Actions,
    /// End processing after this rule matches.
    pub stop: bool,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            match_any: false,
            conditions: Vec::new(),
            actions: Actions::default(),
            stop: false,
        }
    }
}

impl Rule {
    /// Does this rule match, per its own all/any setting?
    ///
    /// A rule with no conditions matches nothing: "always" is a footgun to
    /// opt into by writing a condition that says so, not a default.
    #[must_use]
    pub fn matches(&self, message: &Message) -> bool {
        if self.conditions.is_empty() {
            return false;
        }
        if self.match_any {
            self.conditions.iter().any(|c| c.matches(message))
        } else {
            self.conditions.iter().all(|c| c.matches(message))
        }
    }
}

/// What the caller should do to one message, folded from every matching rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// The first matching rule's destination, if any asked for one. `None`
    /// when `delete` is set — deletion beats filing.
    pub move_to: Option<String>,
    pub mark_read: bool,
    pub star: bool,
    pub delete: bool,
    /// The names of the rules that fired, in order, for the status line.
    pub matched: Vec<String>,
}

impl Plan {
    /// Is there anything to do?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.move_to.is_none() && !self.mark_read && !self.star && !self.delete
    }
}

/// Folds every enabled, matching rule into one [`Plan`] — see the module
/// documentation for the exact semantics.
#[must_use]
pub fn evaluate(rules: &[Rule], message: &Message) -> Plan {
    let mut plan = Plan::default();
    for rule in rules {
        if !rule.enabled || !rule.matches(message) {
            continue;
        }
        plan.matched.push(rule.name.clone());
        if plan.move_to.is_none() && !plan.delete {
            plan.move_to = rule.actions.move_to.clone();
        }
        if rule.actions.delete {
            plan.delete = true;
            // Deletion beats filing, whichever order they matched in: a
            // message cannot be in Trash and a folder at once, and of the two
            // instructions the destructive one is the one the user wrote a
            // rule to make happen.
            plan.move_to = None;
        }
        plan.mark_read |= rule.actions.mark_read;
        plan.star |= rule.actions.star;
        if rule.stop {
            break;
        }
    }
    plan
}

/// The rules for one account, and where they live.
#[derive(Debug)]
pub struct Rules {
    path: PathBuf,
    pub rules: Vec<Rule>,
}

/// What is on disk. A wrapper table so the file reads
/// `[[rule]] … [[rule]] …`, which is the TOML a person can extend by copying
/// a block.
#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
}

impl Rules {
    /// Loads the account's rules. No file is no rules, not an error; a file
    /// that will not parse **is** one — silently dropping the user's rules
    /// and then not applying them is the worst available behaviour.
    pub fn open(account_root: impl AsRef<Path>) -> Result<Self> {
        let path = account_root.as_ref().join(FILENAME);
        let rules = match std::fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str::<File>(&text)
                    .map_err(|why| Error::Draft(format!("{FILENAME} could not be read: {why}")))?
                    .rules
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, rules })
    }

    /// Writes the rules back, atomically.
    pub fn save(&self) -> Result<()> {
        let file = File {
            rules: self.rules.clone(),
        };
        let text = toml::to_string_pretty(&file)
            .map_err(|why| Error::Draft(format!("rules could not be serialised: {why}")))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        cosmic_pim_core::atomic::write(&self.path, &text, None)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn message(raw: &str) -> Message {
        Message::parse(raw.as_bytes()).unwrap()
    }

    fn newsletter() -> Message {
        message(
            "From: News <updates@shop.example>\r\n\
             To: me@example.com\r\nCc: Team <team@example.com>\r\n\
             List-Id: Offers <offers.shop.example>\r\n\
             Subject: WEEKLY deals inside\r\n\r\nbody\r\n",
        )
    }

    fn rule(name: &str, field: Field, contains: &str, actions: Actions) -> Rule {
        Rule {
            name: name.into(),
            conditions: vec![Condition {
                field,
                contains: contains.into(),
            }],
            actions,
            ..Rule::default()
        }
    }

    #[test]
    fn conditions_match_case_insensitively_over_the_right_fields() {
        let msg = newsletter();
        for (field, hit, miss) in [
            (Field::Sender, "UPDATES@shop", "team@"),
            (Field::Recipients, "team@example", "updates@"),
            (Field::Subject, "weekly", "monthly"),
            (Field::List, "offers.shop", "devs."),
        ] {
            let matches = |contains: &str| {
                Condition {
                    field,
                    contains: contains.into(),
                }
                .matches(&msg)
            };
            assert!(matches(hit), "{field:?} should match {hit}");
            assert!(!matches(miss), "{field:?} should not match {miss}");
        }
    }

    #[test]
    fn an_empty_pattern_never_matches() {
        // A half-built rule must do nothing, not everything.
        for field in [
            Field::Sender,
            Field::Recipients,
            Field::Subject,
            Field::List,
        ] {
            assert!(
                !Condition {
                    field,
                    contains: "  ".into()
                }
                .matches(&newsletter())
            );
        }
    }

    #[test]
    fn all_and_any_do_what_they_say() {
        let both = Rule {
            conditions: vec![
                Condition {
                    field: Field::Subject,
                    contains: "weekly".into(),
                },
                Condition {
                    field: Field::Subject,
                    contains: "nowhere".into(),
                },
            ],
            ..Rule::default()
        };
        assert!(!both.matches(&newsletter()), "all-of matched on one of two");

        let either = Rule {
            match_any: true,
            ..both
        };
        assert!(either.matches(&newsletter()), "any-of missed its one hit");
    }

    #[test]
    fn a_rule_with_no_conditions_matches_nothing() {
        assert!(!Rule::default().matches(&newsletter()));
    }

    #[test]
    fn matching_rules_fold_and_the_first_move_wins() {
        let rules = vec![
            rule(
                "file offers",
                Field::List,
                "offers.",
                Actions {
                    move_to: Some("Newsletters".into()),
                    mark_read: true,
                    ..Actions::default()
                },
            ),
            rule(
                "also stars",
                Field::Subject,
                "deals",
                Actions {
                    move_to: Some("Elsewhere".into()),
                    star: true,
                    ..Actions::default()
                },
            ),
        ];
        let plan = evaluate(&rules, &newsletter());
        assert_eq!(plan.move_to.as_deref(), Some("Newsletters"));
        assert!(plan.mark_read && plan.star);
        assert_eq!(plan.matched, vec!["file offers", "also stars"]);
    }

    #[test]
    fn delete_beats_filing_in_either_order() {
        let filed_then_deleted = vec![
            rule(
                "file",
                Field::Subject,
                "deals",
                Actions {
                    move_to: Some("Somewhere".into()),
                    ..Actions::default()
                },
            ),
            rule(
                "bin",
                Field::List,
                "offers.",
                Actions {
                    delete: true,
                    ..Actions::default()
                },
            ),
        ];
        let plan = evaluate(&filed_then_deleted, &newsletter());
        assert!(plan.delete);
        assert_eq!(plan.move_to, None, "a deleted message was also filed");

        let deleted_then_filed: Vec<Rule> = filed_then_deleted.into_iter().rev().collect();
        let plan = evaluate(&deleted_then_filed, &newsletter());
        assert!(plan.delete);
        assert_eq!(plan.move_to, None);
    }

    #[test]
    fn a_disabled_rule_is_kept_but_inert() {
        let mut r = rule(
            "off",
            Field::Subject,
            "deals",
            Actions {
                star: true,
                ..Actions::default()
            },
        );
        r.enabled = false;
        let plan = evaluate(&[r], &newsletter());
        assert!(plan.is_empty());
        assert!(plan.matched.is_empty());
    }

    #[test]
    fn stop_ends_processing_after_a_match() {
        let mut first = rule(
            "first",
            Field::Subject,
            "deals",
            Actions {
                mark_read: true,
                ..Actions::default()
            },
        );
        first.stop = true;
        let second = rule(
            "second",
            Field::Subject,
            "deals",
            Actions {
                star: true,
                ..Actions::default()
            },
        );
        let plan = evaluate(&[first, second], &newsletter());
        assert!(plan.mark_read);
        assert!(!plan.star, "a rule after stop still ran");
        assert_eq!(plan.matched, vec!["first"]);
    }

    #[test]
    fn rules_round_trip_through_the_file_a_person_would_edit() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Rules::open(dir.path()).unwrap();
        assert!(store.rules.is_empty(), "a missing file is no rules");

        store.rules.push(rule(
            "file offers",
            Field::List,
            "offers.",
            Actions {
                move_to: Some("Newsletters".into()),
                mark_read: true,
                ..Actions::default()
            },
        ));
        store.save().unwrap();

        let text = std::fs::read_to_string(dir.path().join(FILENAME)).unwrap();
        assert!(
            text.contains("[[rule]]"),
            "the file should read as blocks a person can copy: {text}"
        );

        let back = Rules::open(dir.path()).unwrap();
        assert_eq!(back.rules, store.rules);
    }

    #[test]
    fn a_file_that_will_not_parse_is_an_error_not_an_empty_ruleset() {
        // Silently dropping the user's rules and then not applying them is
        // the worst available behaviour.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILENAME), "[[rule\nbroken").unwrap();
        assert!(Rules::open(dir.path()).is_err());
    }

    #[test]
    fn the_filename_is_hidden_from_a_maildir_walker() {
        assert!(FILENAME.starts_with('.'));
    }
}

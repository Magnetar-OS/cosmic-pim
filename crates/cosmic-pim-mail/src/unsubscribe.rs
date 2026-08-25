// SPDX-License-Identifier: MPL-2.0

//! One-click unsubscribe (RFC 8058).
//!
//! # Why this exists at all
//!
//! The alternative to a working unsubscribe is the junk button, and the junk
//! button trains the filter that this sender — whom the user did once invite —
//! is an attacker. RFC 8058 is the mechanism the large receivers pushed on
//! bulk senders precisely so that leaving a list is one honest request:
//! an empty POST to the `https:` target, `List-Unsubscribe=One-Click` as the
//! body, no page, no confirmation maze, no "why are you leaving" survey.
//!
//! # What this deliberately does not do
//!
//! Follow a `GET`. RFC 8058 requires POST exactly because mail scanners
//! prefetch GET links — an unsubscribe that fires when an antivirus looks at
//! it unsubscribes people who never asked. The same reasoning caps this
//! module at the one-click case: a plain `https:` target without the
//! one-click header is a *page*, and pages belong in the browser.

use std::time::Duration;

use crate::error::{Error, Result};

/// Performs one one-click unsubscribe.
///
/// Blocking, briefly — meant for a worker thread. `url` must be an `https:`
/// target from a message that carried the RFC 8058 header; the caller has
/// [`crate::model::Message::one_click_unsubscribe`] to check.
pub fn one_click(url: &str) -> Result<()> {
    if !url.to_ascii_lowercase().starts_with("https://") {
        return Err(Error::Draft(
            "one-click unsubscribe only ever posts to https".into(),
        ));
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        // A redirect chain from an unsubscribe endpoint is somebody being
        // clever with tracking; the POST either lands or it does not.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|why| Error::Draft(why.to_string()))?;

    let response = client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("List-Unsubscribe=One-Click")
        .send()
        .map_err(|why| Error::Draft(format!("the unsubscribe could not be sent: {why}")))?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(Error::Draft(format!(
            "the sender's unsubscribe endpoint answered {}",
            response.status()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_is_ever_posted_to() {
        // An http target identifies the recipient of a mailing to anyone
        // listening; a mailto target is a message, not a POST.
        for url in [
            "http://example.com/u",
            "mailto:leave@example.com",
            "ftp://x",
        ] {
            assert!(one_click(url).is_err(), "{url} was accepted");
        }
    }
}

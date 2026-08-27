// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The round-trip corpus (ROADMAP, Milestone 1 gates): realistic exports in,
//! byte-diff out, both formats, through the patcher.
//!
//! # What is actually being protected
//!
//! The suite's core promise is that editing one property of an event or a
//! contact loses nothing else — not the properties our model does not know,
//! not the folding the exporter chose, not the parameters a different client
//! will read next week. The unit tests prove that on minimal inputs; this
//! corpus proves it on inputs shaped like what real exporters emit, because
//! the failures live in the shapes: quoted parameters holding the delimiter
//! characters, base64 payloads folded across dozens of lines, Apple's
//! `item1.` groups, Windows timezone names with spaces, `X-` properties three
//! levels of vendor deep.
//!
//! Each fixture is **synthetic but faithful**: written to match the documented
//! and observed output shapes of the named exporter (property vocabulary,
//! folding style, parameter quoting, terminators), so the corpus runs offline
//! and carries nobody's real calendar. When a genuine export surfaces a shape
//! these miss, the fix is to extend the fixture with that shape — the corpus
//! is meant to accrete, like the quirks ledger.
//!
//! # The two assertions
//!
//! **A no-op patch is byte-identical.** `patch_component` with no edits must
//! reproduce the input exactly — folding, terminators, ordering, everything.
//! This is the invariant writeback stands on: everything not named in an edit
//! passes through untouched.
//!
//! **A real edit touches only its own line.** Splitting the patched output
//! and the input into lines, the diff must be exactly the lines the edit
//! names — nothing refolded elsewhere, no group orphaned, no parameter
//! reordered. "Modulo folding" from the roadmap applies to the *edited* line
//! only, which the patcher writes in its own folding; every other byte is
//! bit-for-bit.

use std::collections::BTreeMap;

use cosmic_pim_core::patch::{Edit, patch_component};

// ---------------------------------------------------------------------------
// iCalendar fixtures
// ---------------------------------------------------------------------------

/// Google Calendar (Takeout) shape: UTC times, heavy X-GOOGLE- vocabulary,
/// an ATTENDEE list with quoted CNs containing commas, folded DESCRIPTION
/// with escaped newlines.
const GOOGLE_TAKEOUT_ICS: &str = "BEGIN:VCALENDAR\r\n\
PRODID:-//Google Inc//Google Calendar 70.9054//EN\r\n\
VERSION:2.0\r\n\
CALSCALE:GREGORIAN\r\n\
METHOD:PUBLISH\r\n\
X-WR-CALNAME:ada@example.com\r\n\
X-WR-TIMEZONE:Europe/Athens\r\n\
BEGIN:VEVENT\r\n\
DTSTART:20260910T070000Z\r\n\
DTEND:20260910T080000Z\r\n\
DTSTAMP:20260901T120000Z\r\n\
UID:6c4v0c9h68pj4b9k60o30b9k6s@google.com\r\n\
ORGANIZER;CN=\"Lovelace, Ada\":mailto:ada@example.com\r\n\
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;CN=\"Lovel\r\n\
\x20ace, Ada\";X-NUM-GUESTS=0:mailto:ada@example.com\r\n\
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=\r\n\
\x20TRUE;CN=babbage@example.com;X-NUM-GUESTS=0:mailto:babbage@example.com\r\n\
CREATED:20260830T090000Z\r\n\
DESCRIPTION:Agenda\\n1. The engine\\n2. The cards\\, all of them\\n\\nJoin: http\r\n\
\x20s://meet.example.com/abc-defg-hij\r\n\
LAST-MODIFIED:20260901T120000Z\r\n\
LOCATION:Room 12\\, Floor 3\r\n\
SEQUENCE:2\r\n\
STATUS:CONFIRMED\r\n\
SUMMARY:Engine review\r\n\
TRANSP:OPAQUE\r\n\
X-GOOGLE-CONFERENCE:https://meet.example.com/abc-defg-hij\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

/// iCloud shape: local times with an embedded VTIMEZONE, Apple's structured
/// location with a quoted semicolon-bearing value, a TRAVEL advisory, and a
/// VALARM child that must survive untouched.
const ICLOUD_ICS: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Apple Inc.//macOS 15.0//EN\r\n\
CALSCALE:GREGORIAN\r\n\
BEGIN:VTIMEZONE\r\n\
TZID:Europe/Athens\r\n\
BEGIN:DAYLIGHT\r\n\
TZOFFSETFROM:+0200\r\n\
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\n\
DTSTART:19810329T030000\r\n\
TZNAME:EEST\r\n\
TZOFFSETTO:+0300\r\n\
END:DAYLIGHT\r\n\
BEGIN:STANDARD\r\n\
TZOFFSETFROM:+0300\r\n\
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\n\
DTSTART:19961027T040000\r\n\
TZNAME:EET\r\n\
TZOFFSETTO:+0200\r\n\
END:STANDARD\r\n\
END:VTIMEZONE\r\n\
BEGIN:VEVENT\r\n\
CREATED:20260820T101500Z\r\n\
DTEND;TZID=Europe/Athens:20260915T190000\r\n\
DTSTAMP:20260820T101501Z\r\n\
DTSTART;TZID=Europe/Athens:20260915T180000\r\n\
LAST-MODIFIED:20260820T101501Z\r\n\
LOCATION:Odeon of Herodes Atticus\\nDionysiou Areopagitou\\, Athens\r\n\
SEQUENCE:0\r\n\
SUMMARY:Concert\r\n\
UID:1E2D3C4B-5A69-7887-96A5-B4C3D2E1F0A9\r\n\
X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS=\"Dionysiou Areopagitou; At\r\n\
\x20hens; 105 55\";X-APPLE-RADIUS=100;X-TITLE=Odeon:geo:37.970,23.724\r\n\
X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC\r\n\
BEGIN:VALARM\r\n\
ACTION:DISPLAY\r\n\
DESCRIPTION:Reminder\r\n\
TRIGGER:-PT45M\r\n\
UID:9F8E7D6C-ALARM\r\n\
X-WR-ALARMUID:9F8E7D6C-ALARM\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

/// Outlook shape: a Windows TZID with spaces used inside quoted parameters,
/// the X-MICROSOFT vocabulary, and an HTML description folded hard.
const OUTLOOK_ICS: &str = "BEGIN:VCALENDAR\r\n\
PRODID:-//Microsoft Corporation//Outlook 16.0 MIMEDIR//EN\r\n\
VERSION:2.0\r\n\
METHOD:PUBLISH\r\n\
X-MS-OLK-FORCEINSPECTOROPEN:TRUE\r\n\
BEGIN:VTIMEZONE\r\n\
TZID:GTB Standard Time\r\n\
BEGIN:STANDARD\r\n\
DTSTART:16011028T040000\r\n\
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\n\
TZOFFSETFROM:+0300\r\n\
TZOFFSETTO:+0200\r\n\
END:STANDARD\r\n\
BEGIN:DAYLIGHT\r\n\
DTSTART:16010325T030000\r\n\
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\n\
TZOFFSETFROM:+0200\r\n\
TZOFFSETTO:+0300\r\n\
END:DAYLIGHT\r\n\
END:VTIMEZONE\r\n\
BEGIN:VEVENT\r\n\
CLASS:PUBLIC\r\n\
CREATED:20260825T140000Z\r\n\
DESCRIPTION:Quarterly numbers.\\nBring the deck.\\n\r\n\
DTEND;TZID=\"GTB Standard Time\":20260920T113000\r\n\
DTSTAMP:20260825T140001Z\r\n\
DTSTART;TZID=\"GTB Standard Time\":20260920T103000\r\n\
LAST-MODIFIED:20260825T140001Z\r\n\
PRIORITY:5\r\n\
SEQUENCE:0\r\n\
SUMMARY;LANGUAGE=en-us:Quarterly review\r\n\
TRANSP:OPAQUE\r\n\
UID:040000008200E00074C5B7101A82E00800000000B0C4D5E6F7A8B9CA\r\n\
X-ALT-DESC;FMTTYPE=text/html:<html><head><meta name=Generator content=\"Mic\r\n\
\x20rosoft Exchange\"></head><body><p>Quarterly numbers.<br>Bring the deck.</p>\r\n\
\x20</body></html>\r\n\
X-MICROSOFT-CDO-BUSYSTATUS:BUSY\r\n\
X-MICROSOFT-CDO-IMPORTANCE:1\r\n\
X-MICROSOFT-DISALLOW-COUNTER:FALSE\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

/// Nextcloud (sabre/dav) shape: a recurring master and its RECURRENCE-ID
/// override in one file — the patcher must be able to edit the override
/// without disturbing the master, which is `patch_nth_component`'s job, but
/// the no-op case here proves neither is disturbed by the other's presence.
const NEXTCLOUD_ICS: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//IDN nextcloud.com//Calendar app 4.7.6//EN\r\n\
CALSCALE:GREGORIAN\r\n\
BEGIN:VEVENT\r\n\
CREATED:20260801T080000Z\r\n\
DTSTAMP:20260801T080000Z\r\n\
LAST-MODIFIED:20260801T080000Z\r\n\
SEQUENCE:3\r\n\
UID:c0ffee11-2233-4455-6677-889900aabbcc\r\n\
DTSTART;TZID=Europe/Athens:20260907T090000\r\n\
DTEND;TZID=Europe/Athens:20260907T093000\r\n\
STATUS:CONFIRMED\r\n\
SUMMARY:Standup\r\n\
RRULE:FREQ=WEEKLY;BYDAY=MO\r\n\
CATEGORIES:work,team\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
CREATED:20260801T080000Z\r\n\
DTSTAMP:20260905T070000Z\r\n\
LAST-MODIFIED:20260905T070000Z\r\n\
SEQUENCE:4\r\n\
UID:c0ffee11-2233-4455-6677-889900aabbcc\r\n\
RECURRENCE-ID;TZID=Europe/Athens:20260914T090000\r\n\
DTSTART;TZID=Europe/Athens:20260914T100000\r\n\
DTEND;TZID=Europe/Athens:20260914T103000\r\n\
STATUS:CONFIRMED\r\n\
SUMMARY:Standup (moved for the holiday)\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

// ---------------------------------------------------------------------------
// vCard fixtures
// ---------------------------------------------------------------------------

/// iCloud/macOS Contacts shape: Apple item-groups labelling values, a folded
/// base64 PHOTO, and the X-ABLabel lines whose orphaning is the classic vCard
/// data-loss bug.
const APPLE_VCF: &str = "BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
PRODID:-//Apple Inc.//macOS 15.0//EN\r\n\
N:Lovelace;Ada;;;\r\n\
FN:Ada Lovelace\r\n\
ORG:Analytical Engines Ltd;Research\r\n\
EMAIL;type=INTERNET;type=WORK;type=pref:ada@engines.example\r\n\
item1.EMAIL;type=INTERNET:ada@personal.example\r\n\
item1.X-ABLabel:Personal\r\n\
item2.URL;type=pref:https://findingada.example\r\n\
item2.X-ABLabel:_$!<HomePage>!$_\r\n\
TEL;type=CELL;type=VOICE;type=pref:+30 690 000 0000\r\n\
item3.ADR;type=HOME;type=pref:;;12 Byron Street;Athens;;105 55;Greece\r\n\
item3.X-ABADR:gr\r\n\
BDAY;value=date:1815-12-10\r\n\
PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwc\r\n\
\x20JCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/\r\n\
\x20wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAA\r\n\
\x20AAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9\r\n\
\x20oADAMBAAIRAxEAPwCdABmX/9k=\r\n\
NOTE:Met at the symposium. Prefers written follow-ups.\r\n\
X-SOCIALPROFILE;type=twitter:https://twitter.example/ada\r\n\
UID:D2C1B0A9-8877-6655-4433-221100FFEEDD\r\n\
END:VCARD\r\n";

/// Google Contacts export shape: 3.0 with the Google vocabulary, an unfolded
/// long NOTE (Google does not fold), and LF-significant escapes.
const GOOGLE_VCF: &str = "BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
N:Babbage;Charles;;;\r\n\
FN:Charles Babbage\r\n\
EMAIL;TYPE=INTERNET:babbage@example.com\r\n\
TEL;TYPE=CELL:+44 20 0000 0000\r\n\
ADR;TYPE=HOME:;;1 Dorset Street;London;;W1U 4EG;UK\r\n\
ORG:Difference Engine Co.\r\n\
TITLE:Chief Engineer\r\n\
NOTE:Owes me a differencing wheel.\\nRemind about the Turin lecture notes an\r\n\
\x20d the punched-card order from last spring.\r\n\
X-GOOGLE-TALK:babbage\r\n\
CATEGORIES:myContacts,starred\r\n\
END:VCARD\r\n";

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

fn no_edits() -> BTreeMap<String, Edit> {
    BTreeMap::new()
}

/// Every corpus document, its format's component name, and a label for
/// failure messages.
fn corpus() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("google-takeout", "VEVENT", GOOGLE_TAKEOUT_ICS),
        ("icloud", "VEVENT", ICLOUD_ICS),
        ("outlook", "VEVENT", OUTLOOK_ICS),
        ("nextcloud", "VEVENT", NEXTCLOUD_ICS),
        ("apple-contacts", "VCARD", APPLE_VCF),
        ("google-contacts", "VCARD", GOOGLE_VCF),
    ]
}

#[test]
fn a_no_op_patch_reproduces_every_export_byte_for_byte() {
    // The invariant writeback stands on: everything not named in an edit
    // passes through untouched. Byte-for-byte, not "semantically equal" —
    // a re-folded line is a changed line to the next client's diff, and an
    // invalidated DKIM-style signature to anything that signs.
    for (label, component, text) in corpus() {
        let patched = patch_component(text, component, &no_edits())
            .unwrap_or_else(|| panic!("{label}: the patcher found no {component}"));
        assert_eq!(
            patched, text,
            "{label}: a no-op patch changed bytes"
        );
    }
}

#[test]
fn every_export_parses_to_something_rather_than_nothing() {
    // Not the point of the corpus, but the cheapest possible canary: an
    // export our own parser reads as empty is an export the apps would
    // silently not display, whatever the patcher preserves.
    use cosmic_pim_core::ical::parse_ics;
    use cosmic_pim_core::vcard::parse_vcards;

    for (label, component, text) in corpus() {
        let items = match component {
            "VEVENT" => parse_ics(text, "corpus", "corpus.ics").len(),
            _ => parse_vcards(text, "corpus", "corpus.vcf").len(),
        };
        assert!(items > 0, "{label}: parsed to nothing");
    }
}

/// The lines of `text`, for the touched-lines diff.
fn physical_lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

/// Asserts that `patched` differs from `original` only in lines belonging to
/// `property` — the "modulo folding of the edited line" contract.
fn assert_only_property_changed(label: &str, original: &str, patched: &str, property: &str) {
    let before = physical_lines(original);
    let after = physical_lines(patched);

    // Walk from both ends: the shared prefix and suffix must be identical,
    // and everything in the differing middle must be the property's own
    // physical lines (its first line, or a folded continuation).
    let mut start = 0;
    while start < before.len() && start < after.len() && before[start] == after[start] {
        start += 1;
    }
    let mut end_before = before.len();
    let mut end_after = after.len();
    while end_before > start
        && end_after > start
        && before[end_before - 1] == after[end_after - 1]
    {
        end_before -= 1;
        end_after -= 1;
    }

    for line in before[start..end_before].iter().chain(&after[start..end_after]) {
        let is_own = line.to_ascii_uppercase().starts_with(property)
            || line.starts_with(' ')
            || line.starts_with('\t');
        assert!(
            is_own,
            "{label}: editing {property} disturbed an unrelated line: {line:?}"
        );
    }
}

#[test]
fn editing_the_summary_touches_nothing_but_the_summary() {
    for (label, component, text) in corpus() {
        if component != "VEVENT" {
            continue;
        }
        let mut edits = BTreeMap::new();
        edits.insert(
            "SUMMARY".to_owned(),
            Edit::set(vec!["SUMMARY:Renamed by the corpus".to_owned()]),
        );

        let patched = patch_component(text, component, &edits)
            .unwrap_or_else(|| panic!("{label}: no VEVENT"));

        assert!(patched.contains("SUMMARY:Renamed by the corpus"), "{label}");
        assert_only_property_changed(label, text, &patched, "SUMMARY");

        // The vendor vocabulary is the loss-prone cargo; spot-check per shape.
        match label {
            "google-takeout" => {
                assert!(patched.contains("X-GOOGLE-CONFERENCE"), "{label}");
                assert!(
                    patched.contains("CN=\"Lovel\r\n ace, Ada\""),
                    "{label}: the folded quoted CN was disturbed"
                );
            }
            "icloud" => {
                assert!(patched.contains("X-APPLE-STRUCTURED-LOCATION"), "{label}");
                assert!(patched.contains("BEGIN:VALARM"), "{label}: the alarm vanished");
            }
            "outlook" => {
                assert!(
                    patched.contains("DTSTART;TZID=\"GTB Standard Time\""),
                    "{label}: the quoted Windows TZID was disturbed"
                );
                assert!(patched.contains("X-MICROSOFT-CDO-BUSYSTATUS"), "{label}");
            }
            "nextcloud" => {
                // Only the MASTER was renamed; the override keeps its own name.
                assert!(
                    patched.contains("SUMMARY:Standup (moved for the holiday)"),
                    "{label}: the override's summary was collateral damage"
                );
                assert!(patched.contains("RRULE:FREQ=WEEKLY;BYDAY=MO"), "{label}");
            }
            _ => {}
        }
    }
}

#[test]
fn editing_an_ungrouped_email_leaves_the_apple_groups_alone() {
    // THE classic vCard data-loss site. The work address is ungrouped; the
    // personal one is item1-grouped with its X-ABLabel sibling. Replacing the
    // ungrouped set must leave both item1 lines byte-for-byte — a patcher
    // that rewrites EMAILs positionally orphans the label.
    let mut edits = BTreeMap::new();
    edits.insert(
        "EMAIL".to_owned(),
        Edit::set(vec![
            "EMAIL;type=INTERNET;type=WORK;type=pref:ada@analytical.example".to_owned(),
        ]),
    );

    let patched = patch_component(APPLE_VCF, "VCARD", &edits).expect("a VCARD");

    assert!(patched.contains("ada@analytical.example"));
    assert!(!patched.contains("ada@engines.example"), "the old work address survived");
    assert!(
        patched.contains("item1.EMAIL;type=INTERNET:ada@personal.example\r\n"),
        "the grouped personal address was disturbed"
    );
    assert!(
        patched.contains("item1.X-ABLabel:Personal\r\n"),
        "the label was orphaned — the classic bug"
    );
    // And the folded PHOTO is still exactly itself.
    assert!(patched.contains("PHOTO;ENCODING=b;TYPE=JPEG:/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwc\r\n"));
    assert!(patched.contains(" oADAMBAAIRAxEAPwCdABmX/9k=\r\n"));
}

#[test]
fn editing_a_grouped_value_keeps_the_group_and_its_label() {
    let mut edits = BTreeMap::new();
    edits.insert(
        "EMAIL".to_owned(),
        Edit::groups_only().with_group("item1", "ada@newpersonal.example"),
    );

    let patched = patch_component(APPLE_VCF, "VCARD", &edits).expect("a VCARD");

    assert!(patched.contains("ada@newpersonal.example"));
    assert!(
        patched.contains("item1.X-ABLabel:Personal\r\n"),
        "the sibling label was lost"
    );
    assert!(
        patched.contains("EMAIL;type=INTERNET;type=WORK;type=pref:ada@engines.example\r\n"),
        "the ungrouped work address was collateral damage"
    );
}

#[test]
fn an_edit_and_its_exact_revert_restore_every_export_byte_for_byte() {
    // The strongest cheap statement of losslessness: rename, then rename
    // back with the original's own logical line, and the document must be
    // exactly what it was — proving the patcher's rewrite of the edited line
    // is stable, not merely close.
    for (label, component, text) in corpus() {
        if component != "VEVENT" {
            continue;
        }
        // The original SUMMARY line, unfolded, exactly as an app would have
        // read it before editing.
        let original_summary = text
            .lines()
            .find(|line| line.starts_with("SUMMARY"))
            .expect("every fixture has a SUMMARY")
            .trim_end_matches('\r')
            .to_owned();

        let mut rename = BTreeMap::new();
        rename.insert(
            "SUMMARY".to_owned(),
            Edit::set(vec!["SUMMARY:Temporarily renamed".to_owned()]),
        );
        let renamed = patch_component(text, component, &rename)
            .unwrap_or_else(|| panic!("{label}: no {component}"));

        let mut revert = BTreeMap::new();
        revert.insert("SUMMARY".to_owned(), Edit::set(vec![original_summary]));
        let restored = patch_component(&renamed, component, &revert)
            .unwrap_or_else(|| panic!("{label}: no {component} after rename"));

        assert_eq!(
            restored, text,
            "{label}: rename + revert did not restore the original bytes"
        );
    }
}

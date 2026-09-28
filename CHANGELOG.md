# Changelog

All notable changes to the cosmic-pim crates. The six crates are versioned
together from the workspace manifest. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
Cargo's reading of [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `AccountStore::save` no longer drops an account another app added on the
  second save from a long-lived handle (audit F-01).
- Writes through `atomic::write` stage in a per-writer temp file, so two
  processes writing one file no longer publish a mix of both (audit F-02).
- A corrupt or unreadable secret envelope is an error instead of an empty
  store, so the next write no longer wipes every envelope-held secret (audit
  F-03).
- CalDAV/CardDAV responses keep their XML entity and character references:
  escaped calendar data such as `R&amp;D` is stored as `R&D`, not `RD` (audit
  F-04).
- A DAV listing that reported a failed resource no longer commits the
  collection's ctag, so that resource's change is not left waiting for an
  unrelated edit (audit F-05).
- A JMAP full read no longer deletes every message beyond a server-clamped
  query limit (audit F-06).
- `itip::build_reply` quotes a CN that holds `:`, `;` or `,` instead of
  backslash-escaping it, so organizers can match the replying attendee (audit
  F-07).
- SMTP: a connection lost or timed out after the message was handed over
  (after DATA) is reported as `Outcome::Ambiguous` instead of retryable, so
  the outbox no longer sends it twice; a refused login is no longer reported
  as "may have been delivered" (audit F-30).
- The copy sent over SMTP and the copy filed to Sent are one message with one
  `Message-ID` and `Date`, and a queued message keeps its `Message-ID` across
  retries (audit F-32).
- A send the server refuses for good (a draft that cannot be built, 5xx at
  login or recipient, a 4xx other than 401/408/429 from Gmail or Graph) stops
  at once instead of retrying twelve times over five hours (audit F-33).
- Outbox: the drain claims a message (renames and locks it) before sending, so
  Undo during an SMTP conversation reports that the message is going instead
  of handing back a draft that is delivered anyway, and a failed attempt no
  longer recreates a cancelled message. A send interrupted by a crash is given
  up, never retried (audit F-29, Envelope F-14).

### Changed

- `jmap::Session::query` returns `(ids, applied_limit)`: the limit the server
  actually applied, which RFC 8620 lets it clamp (audit F-06).
- `smtp::Outcome` gains `Rejected(Error)`: not delivered, and retrying
  unchanged will be refused again. Callers that match on `Outcome` must handle
  it; the outbox marks such a message given up and keeps it.
- `outbox::Queued` gains `sending: bool` (read from disk, never stored).
  `Outbox::list` includes messages a drain is sending; `Outbox::cancel`
  returns `None` for them; `Outbox::remove` refuses them with an error.

### Added

- `compose::Draft::message_id` and `Draft::ensure_message_id(local)`: the
  `Message-ID` a message goes out under. The outbox assigns one from the queue
  id.


## [1.1.0] - 2026-09-22

Tagged, never published to crates.io.

### Fixed

- A mail-only account (no DAV address) is no longer DAV-synced against an
  empty URL, and its secret is no longer resolved for a pass that would not
  contact a server.
- The workspace builds from its own clone again.

## [1.0.0] - 2026-09-10

First release on crates.io: `cosmic-pim-core`, `cosmic-pim-caldav`,
`cosmic-pim-accounts`, `cosmic-pim-auth`, `cosmic-pim-mail` and
`cosmic-pim-sync`.

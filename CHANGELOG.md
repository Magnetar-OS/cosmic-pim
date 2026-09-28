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

### Changed

- `jmap::Session::query` returns `(ids, applied_limit)`: the limit the server
  actually applied, which RFC 8620 lets it clamp (audit F-06).

### Added

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

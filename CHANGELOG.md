# Changelog

All notable changes to the cosmic-pim crates. The six crates are versioned
together from the workspace manifest. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
Cargo's reading of [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `AccountStore::save` no longer drops an account another app added on the
  second save from a long-lived handle (audit F-01).

### Changed

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

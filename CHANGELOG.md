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
- JMAP, Gmail, Graph and POP3 never hand out a local UID a message file
  already carries, and their id maps are saved after a failed pass too, so a
  failed or lost sidecar no longer shows one message's bytes under another's
  id or overwrites POP3's only copies (audit F-24).
- The CalDAV/CardDAV sync sidecar is changed only under the collection's lock
  and over a fresh read, so a push the app queues while a sync pass (in-
  process or the daemon) holds the collection is no longer erased by the
  pass's stale save; a push's success no longer settles a newer edit of the
  same resource queued during it (audit F-09, Slate F-06).
- A CalDAV create is sent with `If-None-Match: *`, and the ETag a PUT returns
  is recorded, so the next edit carries the right `If-Match` (audit F-18).
- A server-side delete of an event or contact edited here and not yet pushed
  is recorded as a conflict instead of removing the file and the edit (audit
  F-08).
- A deletion made here that the server refused because it changed the resource
  is recorded as a conflict instead of staying parked forever while the next
  pull puts the item back (audit F-17).
- An automatic three-way merge clears a conflict recorded for the same
  resource on an earlier pass (audit F-20).
- Deleting an event or task whose record cannot be found in its file (an
  escaped `UID`, a stale index) is an error instead of unlinking the whole
  file and every other record in it; a VTODO beside the last event is kept
  (audit F-11).
- Saving an event in a file that also holds a VEVENT without a usable DTSTART
  patches the right component instead of the one before it (audit F-12).
- OpenPGP: only a signature on the message's own top-level part verifies the
  message. A genuinely signed part wrapped beside unsigned text (the MIME-
  wrapping spoof) no longer gives that text the sender's "Verified" verdict;
  encryption is likewise read from the top-level part only (audit F-45).
- iTIP: a REQUEST or CANCEL is applied only when it comes from the event's
  organizer. One naming a different organizer from the stored event, naming
  none, mailed by someone other than the organizer (when the caller passes the
  sender), or targeting an event this account organizes returns
  `Outcome::NotFromOrganizer` and changes nothing (audit F-38).

### Changed

- `jmap::Session::query` returns `(ids, applied_limit)`: the limit the server
  actually applied, which RFC 8620 lets it clamp (audit F-06).
- `smtp::Outcome` gains `Rejected(Error)`: not delivered, and retrying
  unchanged will be refused again. Callers that match on `Outcome` must handle
  it; the outbox marks such a message given up and keeps it.
- `outbox::Queued` gains `sending: bool` (read from disk, never stored).
  `Outbox::list` includes messages a drain is sending; `Outbox::cancel`
  returns `None` for them; `Outbox::remove` refuses them with an error.
- `caldav::push::PushQueue`: `pending(&mut self) -> Result<Vec<PendingPush>>`;
  `resolve(&mut self, pushed: &PendingPush, etag: Option<&str>)`, `defer(&mut
  self, pushed: &PendingPush, error, next_attempt_ms)` and `park(&mut self,
  pushed: &PendingPush, error)` act only on the entry they were handed.
  `PendingPush` gains `revision: u64`. `CalDavStore::unpushed_local` and
  `unpushed_base` take `&mut self` (they re-read the sidecar).
- `caldav::Conflict` has a new public field `kind`; code building a `Conflict`
  literal must set it. `CalDavStore` gains `queued_delete` (default `false`).
- `ical::remove_by_uid` returns `ical::Removal` (`Rewritten(String)`,
  `Emptied`, `NotFound`); `ical::remove_vevent` takes the `uid` as well and
  returns `Removal`. `StoreError::RecordNotFound { uid, file }` is new.
- `itip::apply(collection, ics, me, sender: Option<&str>)` takes the mail's
  sender; `itip::Outcome` gains `NotFromOrganizer`; `itip::Participant` gains
  `sent_by`; `Itip::is_from_organizer(me, sender)` is new.

### Added

- `compose::Draft::message_id` and `Draft::ensure_message_id(local)`: the
  `Message-ID` a message goes out under. The outbox assigns one from the queue
  id.
- `cosmic_pim_core::atomic::lock(target) -> Result<Lock, Error>`: an exclusive
  cross-process advisory lock (`flock` on a sibling `.<name>.lock`) for a
  file's read-modify-write cycle (audit O-01).
- `caldav::ConflictKind` (`BothEdited`, `DeletedOnServer`, `DeletedHere`) and
  `Conflict::kind`. `conflict::take_remote` / `keep_local` (and the
  `VdirStore` resolvers) do the right thing per kind: accept or undo the
  server's deletion, or restore or re-send the local deletion (audit O-08).




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

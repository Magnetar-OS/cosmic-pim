# Changelog

All notable changes to the cosmic-pim crates. The six crates are versioned
together from the workspace manifest. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
Cargo's reading of [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `model::Trigger { alarm, days }` (`#[non_exhaustive]`, built with
  `Trigger::new(alarm, days)`): a VALARM trigger with the days its offset was
  written in kept apart, and `Trigger::fires_at(start, end)`, which takes
  `DateTime<chrono_tz::Tz>` in the event's zone and counts those days on the
  wall clock, adding the rest as exact time (RFC 5545 section 3.3.6). A
  `-P1D` reminder for a 09:00 event fires at 09:00 the day before across a
  daylight-saving change, not 24 hours before; `-PT24H` still fires 24
  hours before. The readers are `Store::triggers(&Event)`,
  `Store::todo_triggers(&Todo)`, `ical::event_triggers(text, uid,
  recurrence_id)` and `ical::todo_triggers(text, uid)`. `Alarm`,
  `Alarm::fires_at` and the `alarms` readers are unchanged: their offsets
  stay exact (Slate audit F-09 follow-up).
- `cosmic_pim_sync::save_and_queue_creating(root, collection_id, file_names,
  write)`: `save_and_queue` for a write that also creates files whose names
  it learns only by writing them (a new invitation, an import). `write`
  returns `(value, created_names)`, and the created files are queued under
  the same lock, with no merge base. Callers that queued such files in a
  second step afterwards can go through it instead.

### Changed

- `save_and_queue` no longer queues a file the write left as it was (the
  same bytes, or absent before and after). A write that changes nothing,
  such as an invitation reply that turns out stale, uploads nothing, and
  `Saved::queued` is `Ok(false)` for it. Re-saving identical bytes therefore
  does not queue a change that failed to queue earlier; `queue_save` still
  does.

### Fixed

- `ical::parse_iso_duration` returns `None` for a duration too long to
  represent, where it could overflow or panic.

- A POP3 sync pass whose POP3 server cannot be reached no longer returns an
  error after its outbox drain has sent mail. The pass sends over SMTP before
  it connects to POP3, and the error took the sent ids with it, so the caller
  could neither mark the messages they answered nor file their Sent copies.
  The connection failure is now the inbox's `MailboxReport::outcome` (counted
  by `MailReport::failed`), and `MailReport::sent` keeps what went.
- A Graph sync pass lists its folders before it drains the outbox, as the
  IMAP and JMAP passes do. It listed them after, so a folder list that failed
  returned an error in place of the ids `sendMail` had just accepted.
  `sync_account_mail` now documents the rule every protocol keeps: an error
  means the pass sent nothing, and once the drain has run, later failures are
  reported per mailbox and `MailReport::sent` holds what went.

## [2.1.0] - 2026-09-30

A minor version: every API change is an addition (new functions, types, a
re-export and a trait method with a default body), so code built against
2.0.0 compiles unchanged. The one change of observable output is under
**Changed**: `Debug` now redacts secrets. Consumers stay on `"2"`.

### Added

- `model::Alarm` (`Start(Duration)`, `End(Duration)`, `At(DateTime<Utc>)`)
  with `Alarm::fires_at(start, end)`, and the readers that return every alarm
  a component carries: `Store::alarms(&Event)`, `Store::todo_alarms(&Todo)`,
  `ical::event_alarms(text, uid, recurrence_id)` and `ical::todo_alarms(text,
  uid)`. Alarms set relative to the end or at a fixed time were skipped when
  reading, so an event whose only alarm was one of those looked as if it had
  none. `Event::alarms` and `Todo::alarms` are unchanged: the start-relative
  offsets (Slate audit F-09).
- `Recurrence::to_rrule_keeping(start, original)` renders a rule over the one
  the series already has: `WKST`, the order of the parts and the spelling of
  every part that did not change are kept, so a rule `Recurrence::parse`
  accepts survives a parse and render byte for byte. `to_rrule` still renders
  from the fields alone, for a series that had no rule (Slate audit F-04).
- `cosmic_pim_sync::save_and_queue(root, collection_id, file_names, write)`
  runs an application's own save (or delete) and queues its upload as one step
  under the collection's lock, returning `Saved { value, queued }`. A sync
  pass can no longer pull a resource between the save and its enqueue and
  overwrite the edit. It captures the pre-edit bytes as the merge base itself
  and queues a deletion when the write removed the file. `queue_save`,
  `queue_save_with_base` and `queue_delete` are unchanged and keep the gap
  (audit F-09 residual, Slate F-06).
- `CalDavStore::exclusively(step)` (default: runs `step`) holds a store against
  every other writer for one step; `VdirStore` implements it with the
  collection's lock, and the sync cycle decides about each pulled or deleted
  resource inside it. `VdirStore::reload()` re-reads the sidecar.
- `Pending::wait_for(timeout)`: `Pending::wait` with a timeout of the
  caller's choosing.
- `AccountStore::credential_lock(id)`: a cross-process lock over one
  account's grant, held while it is renewed.
- `cosmic_pim_sync::drain_outbox(&Account, &Credentials, mail_root, now_ms)
  -> Result<DrainReport>` sends what is due in one account's outbox and does
  nothing else: no mailbox is listed or pulled. It submits the way the
  account's sync pass does (SMTP for IMAP, JMAP and POP3; `messages.send` for
  Gmail; `sendMail` for Graph) and files the Sent copy where that pass would,
  connecting to IMAP or JMAP only when something went. `DrainReport { sent,
  given_up }` carries the outbox ids that went, like `MailReport::sent`.
- `patch::remove_grouped(raw, uid, &[GroupedEntry])` takes grouped entries
  out of a card together with the `X-ABLabel` and `X-ABADR` lines they leave
  labelling nothing, byte for byte otherwise; `patch::GroupedEntry { property,
  group }` names one, and `Contact::grouped_entries()` lists a contact's. The
  patcher edits grouped values but never removed one, so a grouped address
  deleted in an editor came back on the next read (Circle audit S-05).

### Changed

- `{:?}` no longer prints secrets: `accounts::Secret`, `OAuthCredential`,
  `auth::TokenResponse`, `Pkce`, `Pending` and `mail::Credentials` have
  `Debug` implementations that redact passwords, tokens and the PKCE verifier
  (audit O-04).

### Fixed

- The calendar index no longer remembers a file it could not read as a file
  with no events: the file is read again on the next sync, instead of its
  events staying missing until something else changed it (audit F-22).
- The calendar index rebuilds itself when its table predates the recurrence-id
  and attendee columns, instead of passing the staleness check and failing on
  every write (audit F-46).
- An index row whose recurrence-id cannot be read is an error, like every
  other column, instead of an override of the instance at 1970-01-01 (audit
  F-46).
- The vdir watcher wakes its reader when the kernel's event queue overflowed
  and the events were dropped (notify's "rescan" event), instead of ignoring
  it and leaving the view stale after a large sync (audit F-46).
- `birthdays::in_range` no longer reports a birthday in a year before the
  contact was born, at a negative age (audit F-46).
- Deleting or importing one contact in a `.vcf` that holds several cards
  written with lowercase `begin:vcard` no longer unlinks or replaces the file
  and everyone else in it: cards are counted whatever case the delimiters use
  (audit F-46).
- Saving an event or task into a file that exists but cannot be read (bytes
  that are not UTF-8, a permission error) is an error instead of replacing the
  file with a fresh single-record document; importing a contact over such a
  file is refused the same way.
- An alarm with `ACTION:NONE` (how Apple's calendars write "no alarm") is no
  longer read as an alarm.
- Adding, changing or removing a reminder on an event or task that already
  exists is written to its file. The save patched properties only, and an
  alarm is a nested component, so the edit was accepted and then dropped.
  Alarms the edit did not touch — another client's e-mail alarm, an alarm
  relative to the end or at a fixed time — are left exactly as written.
- `Store::move_to_calendar` moves the whole event: a series arrives in the
  other calendar with its changed occurrences, its timezones and everything
  the model does not carry, as written. It used to save the master alone and
  then remove every component with that UID from the old file, which deleted
  the changed occurrences. A read-only calendar at either end is refused
  before anything is written.
- ICS feeds: a feed found empty while events are held is read again on the
  next refresh and believed then, instead of its validators being recorded so
  that every later refresh was a 304 and an emptied feed kept its events for
  good. A feed over the size limit, or one whose body stops before
  `END:VCALENDAR`, is refused instead of being truncated and applied, which
  removed every event past the cut (audit F-21).
- A sync pass asks whether a resource has an unsent local edit and writes the
  server's copy as one step under the collection's lock, so an edit queued
  between the question and the write is no longer overwritten.
- OAuth sign-in: a sign-in abandoned in the browser now gives up after its
  timeout (five minutes for `wait`) and releases the redirect port. The wait
  blocked in `accept` and looked at its deadline only when a connection
  arrived, so it never ended (audit F-43).
- OAuth sign-in: a connection to the redirect listener that sends nothing —
  a browser's spare connection — is set aside after two seconds instead of
  failing the whole sign-in while the real redirect waits behind it.
- `auth::resolve` renews an expired grant under a per-account lock and reads
  it again first, so two processes finding the same expired token (an app and
  the sync daemon) redeem the refresh token once. A provider that rotates
  refresh tokens refused the second redemption with `invalid_grant`, which
  asked the user to sign in again (audit F-44).
- Drafts mirror: a display name holding a comma, colon, parentheses or angle
  brackets is written as an encoded word, so `Smith, John` stays one
  recipient instead of becoming two, and an address holding a line break,
  whitespace or `<>,;` is not an address, so it can no longer add a header of
  its own to the mirror copy (audit F-35).
- Account discovery reads an autoconfig value that holds an entity or
  character reference (`R&amp;D`, `&#46;`) whole, instead of keeping only the
  last piece of it (audit F-46).
- Account discovery refuses `localhost.` and names under `.localhost`, which
  resolvers answer with loopback, and judges an IPv4 address carried in an
  IPv6 one (`::ffff:127.0.0.1`) as the IPv4 address it is, so neither can
  point a probe at this machine (audit F-46).
- IMAP `Session::append` files a message with exactly the flags asked for.
  `\Seen` was added whatever the caller said, so an mbox import of unread mail
  arrived read. The drafts mirror asks for `\Seen` itself, as before (audit
  F-46).
- POP3: a message line longer than 64 KiB (an unwrapped base64 part, an HTML
  body on one line) is stored whole. It was stored as several lines with
  breaks inserted, and a piece that began with `.` was un-stuffed or taken
  for the end of the message (audit F-46).
- `drafts::new_id` mints an id that is unique on its own: the clock, then 64
  random bits. From the clock alone, two ids minted in one millisecond — two
  windows sending at once, a queued reply and a saved draft — were the same,
  and one record overwrote the other. Ids still sort by creation time.
- Gmail: after an expired history cursor, the archive holding mail is read
  again — its newest part listed by query, and every held message the
  listing does not name asked about by itself — so mail archived during the
  gap arrives and mail that left the archive goes. It used to open a new
  cursor and nothing else (audit F-28).
- Gmail: a message moved out of junk or the bin (to the inbox, the archive or
  Sent) loses `SPAM` and `TRASH`, which outrank every other label; moved to
  the inbox from junk it stayed in junk and came back there (audit F-28).
- The POP3 sync pass sends what the account's outbox holds, over SMTP and
  before POP3 is reached. It had no drain at all, so a send queued on a POP3
  account (a failed attempt, Send later, the undo grace) never went.
- Saving a contact whose card holds two lines of one property in one group
  (`item1.EMAIL:a` and `item1.EMAIL:b`) keeps each line's own value. Both
  were rewritten to the last one on any save (Circle audit S-04).

## [2.0.0] - 2026-09-29

A major version because the public API changed incompatibly (Cargo reads a
breaking change after 1.0.0 as a major bump; 1.1.0 was tagged but never
published). Every changed or removed item is listed under **Changed**, with
what to call instead. Consumers move from `"1"` to `"2"`.

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
- A maildir's sync sidecar is changed only under its lock and over a fresh
  read, so a flag, move or delete the app queues while a sync pass holds the
  mailbox is no longer erased by the pass's cursor commit; a pushed change no
  longer settles a newer one for the same message (Envelope audit F-02).
- `AccountStore` applies every change to `accounts.toml` as it is on disk now,
  under the file's lock: a long-lived handle no longer writes back an account
  another app removed, nor reverts another app's edit to an account it holds
  (audit F-10). An account is removed from the file before its secrets are
  forgotten.
- The secret store's backend record is written before a superseded copy is
  removed, and a record that cannot be written fails the save instead of
  leaving later reads to find nothing or yesterday's password (audit F-41).
- `SecretStore::forget` returns an error and keeps the record when a copy
  could not be deleted (keychain locked, envelope-only mode), instead of
  orphaning the keychain copy (audit F-42).
- The secret envelope and its backend record are read-modify-written under a
  cross-process lock, not an in-process mutex, so two apps saving secrets no
  longer overwrite each other's.
- The IMAP sync pass files an outbox message's Sent copy into the folder the
  server declares `\Sent` (or names as such), not a mailbox literally called
  "Sent", which failed or created a stray folder on Gmail, Exchange, Courier
  and localised servers (audit F-31, Envelope F-04).
- JMAP, Gmail and Graph writeback failures are classified by HTTP status:
  timeouts, resets, 408, 429 and 5xx are retried with backoff, and 404/410 go
  to a sync pass, instead of every failure blocking as "needs the user" and
  read marks reverting (audit F-25, O-03).
- An all-day event on a daylight-saving fall-back day no longer spans two
  days, and a timed event across a transition ends at its own end time on the
  grid (Slate audit F-18).
- A series that "ends on" a date gets `UNTIL` at the end of that day in the
  series' own zone (DATE for all-day series, floating for floating ones)
  instead of the end of the UTC day, and a UTC `UNTIL` is read back as a date
  in the series' zone (Slate audit F-05).
- Range queries on a day whose midnight does not exist (daylight saving
  starting at 00:00) start at the day's first real hour instead of midnight
  read as UTC, and a DATE or floating `UNTIL` no longer drops a series' last
  instances from the index (audit F-23).
- Deleting one instance or "this and following" of an invitation no longer
  raises its `SEQUENCE`, and splitting one no longer resets it, so the
  organizer's later updates are not dropped as stale; the counter still
  advances on the user's own series (Slate audit F-25).
- Moving a whole series no longer orphans its overrides: they are re-targeted
  to the moved instances instead of showing beside them (audit F-13, Slate
  F-03).
- An account whose CardDAV server refused the sync is no longer reported as up
  to date: the report's tally carries `contacts_unavailable` (audit F-47,
  Circle S-01).
- Drafts mirror: an edit saved while its previous version was uploading stays
  marked for upload; a draft discarded during its first upload gets a
  tombstone so the server copy is retired; two sweeps of one account take
  turns instead of both uploading the same draft (audit F-34, Envelope F-15).
- iTIP: a CANCEL for one instance writes an EXDATE on the master and removes
  that instance's override, so the instance actually leaves the calendar (a
  moved one no longer snaps back) (audit F-36).
- iTIP: a REPLY updates exactly one attendee, only in the instance its
  RECURRENCE-ID names (adding an override when needed), only with a valid
  PARTSTAT, and not when older than the stored event; a one-instance answer no
  longer rewrites the whole series (audit F-37).
- iTIP: a REQUEST or CANCEL at the stored SEQUENCE but with an older DTSTAMP
  is stale, so an old invitation reopened from mail no longer rolls back newer
  details (audit F-39).
- iTIP: `send_invitation` and `send_cancellation` stamp every VEVENT with the
  current DTSTAMP, and a CANCEL carries `STATUS:CANCELLED` (audit F-40).
- Automatic three-way merge now works on real data: DTSTAMP, LAST-MODIFIED,
  REV and SEQUENCE changed on both sides take the later value instead of
  counting as an overlap, so edits to different properties merge (audit F-19).
- An EXDATE written in UTC (or another zone) under a zoned DTSTART excludes
  the right instance instead of letting it reappear, and saving an event
  leaves DTSTART, DTEND, EXDATE and RECURRENCE-ID as written unless the edit
  changed them (an unresolvable TZID is no longer rewritten as UTC) (audit
  F-14).
- Saving a contact patches its file as it is now, under an optimistic
  concurrency guard, instead of the snapshot it was loaded with, so a newer
  change to another card in the same `.vcf` is no longer reverted and pushed
  (audit F-15).
- Saving a contact leaves FN, N, NICKNAME, ADR, ORG, TITLE, NOTE, BDAY and
  CATEGORIES exactly as written unless the edit changed them, so their
  parameters survive (`BDAY;X-APPLE-OMIT-YEAR` no longer turns a year-less
  birthday into 1604), and an Apple-grouped `itemN.ADR` is edited in place
  instead of duplicated on every save (audit F-16).
- JMAP flag writes patch only the five system keywords, so marking a message
  read no longer strips `$junk`, `$MDNSent` or the user's labels; JMAP, Gmail
  and Graph pulls no longer zero the flag bits their protocol does not carry
  (answered, forwarded, custom keywords) (audit F-26).
- Graph: after an expired delta link, the fresh re-read removes the messages
  it no longer lists (deleted or moved during the gap) instead of keeping them
  forever, with the empty-listing guard the other engines use (audit F-27).

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
- `mail::push::PushQueue`: `pending(&self) -> Result<Vec<PendingPush>>`;
  `resolve(&mut self, pushed: &PendingPush)` and `defer(&mut self, pushed:
  &PendingPush, failure, error, next_attempt_ms)` settle only that exact
  queued operation.
- `SecretStore::forget(&self, slot) -> Result<()>` (was `()`);
  `AccountStore::remove` reports a secret it could not delete.
  `accounts::Error::Poisoned` and `Error::poisoned()` are removed (no lock can
  be poisoned any more).
- `sync::MailReport::sent` is `Vec<String>`: the outbox ids that left this
  pass (was a count), so an app can settle per-message follow-ups such as
  marking the answered message.
- `model::Recurrence::to_rrule(self, start: EventTime)` and
  `Recurrence::parse(rule, start: EventTime)` take the series' DTSTART.
  `Event::recurrence()` is unchanged.
- `sync::AccountReport::summary() -> String` is replaced by
  `AccountReport::tally() -> SyncTally` (fetched, deleted, pushed, failed,
  conflicts, held, `account_error`, `contacts_unavailable`, plus
  `has_problems()` and `is_quiet()`), so apps word the status line in their
  own language (audit F-48, O-05, Circle S-02).
- `drafts::Drafts::mark_mirrored(id, message_id, landed, uploaded: &Draft)`
  takes the draft that was uploaded.
- `itip::Itip` gains `dtstamp: Option<String>`;
  `Itip::supersedes(stored_sequence, stored_dtstamp: Option<&str>)`. New
  `itip::scheduling_message(ics, method) -> String` builds what the organizer
  sends.
- `cosmic-pim-mail` depends on `cosmic-ext-nib-text` 1.2.0 (was 1.1.0).
- `model::Address` gains `group: Option<String>`; code building an `Address`
  literal must set it (or use `..Address::default()`).

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
- `AccountStore::reload(&mut self) -> Result<()>`: re-read the accounts for a
  long-lived handle before showing or routing by them (Slate audit F-15).
- `mail::Error::Transport { service, message }` and `mail::Error::Status {
  service, status, message }` (with `Error::transport` / `Error::status`
  constructors) for the HTTP mail engines.
- `Store::save_series(&mut self, previous: &Event, series: &Event) ->
  Result<(), StoreError>`: saves a whole-series edit and moves every
  override's `RECURRENCE-ID` (and, for an override that kept its instance's
  time, its start and end) by the same shift (audit F-13, Slate F-03).
- `cosmic-pim-sync` feature `mail` (default on): the mail sync pass and its
  re-exports. A contacts or calendar consumer that sets `default-features =
  false` no longer links the mail and OpenPGP stack (pgp, rsa, lettre, imap,
  scraper) (audit O-02, Circle C-09).
- `mail::model::Flags::reported_over(server, held, reported: Reported) ->
  Flags` and `mail::model::Reported` (`READ_STAR_DRAFT`, `SYSTEM`).
- `mail::store::RemoteIds::ids()`: every `(server id, local UID)` mapping.










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

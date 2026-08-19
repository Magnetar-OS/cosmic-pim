# cosmic-pim — Substrate

## As built (verified against README + ARCHITECTURE.md)

Four crates, downward-only deps: `core` (model, one calcard-based
iCalendar/vCard layer, vdir store, SQLite range-query cache, watcher, atomic
writer), `caldav` (CalDAV+CardDAV via a `Flavor` enum, reconciler, durable
push queue, `CalDavStore`/`PushQueue` traits), `accounts` (keychain + encrypted
fallback, one accounts.toml for the suite), `sync` (one pass per account,
per-collection error isolation). ~290 tests. Invariants pinned: vdir is truth /
index is disposable, sync state in sidecar not cache, verbatim bytes + patching
writeback, durable queued pushes, push-before-pull, one parser. The VTODO cost
accounting (zero sync-engine lines) is the standing proof the shape works.

## Fixes

- **Patcher generalization** (the priority item — see 00): move
  `caldav::patch` to `core` as a format-agnostic content-line patcher with
  vCard group-prefix awareness. Tests: property replace/add/remove under
  folding, groups (`item1.*` stay grouped), parameter edits, idempotence,
  untouched-bytes stability under fuzzing.
- **Push-queue error taxonomy**: retryable (timeout, 5xx, connection) vs
  needs-reconcile (412) vs needs-user (401/403, quota). 412 exits the backoff
  loop into the reconciler; auth errors surface through sync reports. Pin with
  tests per class.
- **Sidecar ignore tests** for watcher and store (00).
- **Windows TZ mapping** in `core::ical` via CLDR windowsZones, applied when a
  TZID fails IANA lookup, before the floating fallback. Same bug class as the
  trailing-space fix; same one-parser leverage.
- **ARCHITECTURE.md additions**: parent-directory fsync stated explicitly;
  sync-ownership rule; a "how the invariants translate to mail" section
  (verbatim RFC 5322 bytes, UIDVALIDITY as the 412-analog, push-before-pull
  for flag changes — "my read marks keep reverting" is the same bug as
  "my edits keep reverting"); note that step 4 of "adding an application"
  (add a Flavor) does not apply to mail — IMAP is not a WebDAV flavor.

## Gaps (dependency order)

### Conflict surfacing

The reconciler resolves what it can; the missing piece is the API for what it
can't. On 412-with-divergence, produce a conflict record — local bytes, remote
bytes, base bytes (last-synced state) — persisted in the sidecar, exposed
through sync reports, resolvable by an app choosing per-property (via the
patcher) or wholesale. Non-overlapping property changes auto-merge; overlapping
go to the record. Both apps' conflict UI consumes this; neither can build it
until the engine emits it.

### Per-server quirks table

One module, data-driven, keyed on server detection (server header /
DAV-capabilities probe): known deviations for Nextcloud, Radicale, Baïkal,
Fastmail, Google CalDAV, iCloud. Start empty; populate from the CI matrix and
field reports. The alternative is if-ladders scattered through the engine.

### ICS subscriptions

Read-only remote collections (webcal/https): a collection type in the store
marked read-only, conditional fetch (ETag/Last-Modified) on a per-feed
interval, items written through the normal vdir path so every reader sees them.
Belongs beside `caldav` (it's HTTP, not DAV). Slate's most-requested
low-effort feature.

### `cosmic-pim-mail`

The crate Envelope waits on (04 for the port plan). Substrate-side decisions:
- **Store: maildir.** Continues files-as-truth — interoperable with mbsync,
  notmuch, mu; index rebuildable; "walk away with your data" holds. SQLite as
  message store would be the first place the suite breaks its own rule.
  Tantivy (ported from Meltemi) is the disposable index, same status as the
  calendar's SQLite cache.
- Parser boundary: `mail-parser`; model extracts, never re-serialises;
  message bytes verbatim.
- Store trait mirroring `CalDavStore` — protocol code storage-agnostic,
  in-memory impl for tests, per the CalDAV porting precedent.

### Scheduling module (for iMIP, later)

RFC 6638 is not four substitutions — inbox/outbox collections and new request
shapes. When it arrives: a module beside `dav` that *uses* `Flavor`'s plumbing,
not a fifth field on it. Also home of iTIP semantics shared by Slate and
Envelope: SEQUENCE handling, RECURRENCE-ID-scoped updates, PARTSTAT, METHOD
validation. Design placeholder now; build at suite step 7.

### Contact-adjacent substrate work (pulled by Circle, 03)

- Local-only collections: a book/calendar directory flagged non-synced —
  trivial in vdir (it's just a directory no account claims) but needs an
  explicit marker so sync provisioning never adopts it. Prerequisite for
  Circle's notes/CRM sidecar and any "on this device" data.
- Birthday synthesis: BDAY (including no-year dates) → occurrence stream the
  calendar index can serve, so Slate displays birthdays without a fake .ics.
- Optional, later: LDAP read-only source behind the store's collection
  abstraction (`ldap3`), searched live, cached, never written.

## Publishing

Blocked on the Meltemi declaration (00). After that: crates.io or stay
git-tagged — either works; the `[patch]`+path arrangement documented in the
README is fine for the sibling-checkout phase but is the thing to retire first
once tags exist, because it silently masks version skew between apps.

## Risks

- calcard is load-bearing for both formats; track upstream, keep the
  round-trip corpus as the regression net for its upgrades.
- `rrule`/chrono expansion correctness is a Slate-visible risk owned here —
  the libical golden suite (00) is the gate.
- Quirks accumulation post-CI-matrix will dominate maintenance; the table
  pattern is what keeps it from dominating the code.

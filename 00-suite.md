# Suite — Cross-Cutting Fixes, Gaps, and Sequencing

Covers what spans repositories. Per-project files: 01 cosmic-pim, 02 Slate,
03 Circle, 04 Envelope. Everything here is dependency-ordered, not dated.

## Fixes (cheap, do first)

1. **Doc drift.** cosmic-pim's table says Slate is "Working — CalDAV sync";
   Slate's README says "No CalDAV sync built in — use vdirsyncer" and pitches
   vdirsyncer in the intro. One is stale. Also Rust 1.93+ (Slate README) vs the
   1.97+ toolchain actually in use. First two files a contributor reads.
2. **Directory fsync wording.** "fsync data and the rename" in ARCHITECTURE.md
   should say the *parent directory* is fsynced after rename explicitly — it's
   the step everyone skips, and the doc exists to pin exactly such things.
3. **Sidecar hygiene test.** Watcher and store must ignore `.caldav-state.json`,
   vdirsyncer's own status/metadata files, `displayname`, `color`. Presumably
   true today; pin it with a test so it stays true when the next sidecar appears.

## Structural decisions to make once

### One sync owner per collection

The suite now has two legitimate sync engines for the same vdir: vdirsyncer
(pitched in Slate's README) and `cosmic-pim-sync` (shipped in the substrate).
Both against the same collection is a divergence machine — independent state
stores, both pushing, each seeing the other's writes as unexpected etags.

- State the rule in ARCHITECTURE.md: the vdir interop promise covers *readers*
  (khal, khard, Thunderbird) and *either* sync engine, never both on one
  collection.
- Enforce softly: if `cosmic-pim-sync` is asked to sync a collection that has
  vdirsyncer status metadata, warn and require explicit confirmation.

### Content-line patcher moves to core

`caldav::patch` is the mechanism behind the verbatim-storage invariant, and
Circle's editing is blocked on a vCard equivalent. vCard and iCalendar share the
content-line grammar (folding, escaping, parameters); vCard adds group prefixes
(`item1.EMAIL` / `item1.X-ABLabel`). So:

- Move the patcher to `cosmic-pim-core` as a format-agnostic, group-aware
  content-line patcher; `caldav` re-exports for compatibility.
- One tested code path then protects both formats, including the Apple
  `X-ABLabel` grouping — the classic vCard data-loss site.
- This single item unblocks all of Circle's write path (03).

### Writeback error classification

Exponential backoff is correct for timeouts/5xx and *wrong* for 412 (stale etag
— never succeeds by retrying; needs pull-and-reconcile) and 401/403 (needs the
user). Misclassifying 412 as retryable reproduces the exact silent divergence
the queue exists to prevent, slower. Pin the classification with tests; it is
the part the next error path added will get wrong. Surface non-retryables to
the apps (see conflict surfacing, 01).

### Reminders belong in the substrate

Slate's `reminders/` — trigger scheduling, once-per-occurrence, staleness drop,
D-Bus name arbitration with the success-exit second daemon — passes the
"would a second app want it" test the moment Circle grows keep-in-touch
reminders. Substrate-shaped code currently living in an app. Move when Circle
needs it, not before; note it now so nobody duplicates it.

### Licensing gate

Meltemi carries no licence declaration; cosmic-pim's iCalendar/CalDAV layers
derive from it, blocking crates.io publication, and Envelope wants to lift ~25k
more lines. If every derived line is solely yours, this is a one-commit fix
(add MPL-2.0-compatible declaration to Meltemi). If Meltemi has outside
contributors, their agreement is needed for the derived portions. Resolve
before more Envelope code moves — the unlicensed-provenance pile only grows.

## Known-future bug class: Windows timezone names

The trailing-space `TZID=Europe/Athens ` bug has a sequel with the same failure
shape: Outlook-originated events carry `TZID=GTB Standard Time` (Greece's own,
conveniently) and IANA-only mapping falls through to floating. Unavoidable the
moment Envelope delivers invitations. Queue a CLDR `windowsZones` mapping in
`core::ical` now — the one-parser invariant makes it a single fix.

## Platform notes

- **Secret Service.** `cosmic-pim-accounts` uses the OS keychain with an
  encrypted fallback. COSMIC ships no Secret Service provider, so on stock
  COSMIC the fallback is likely the live path. Locket (the passman) implementing
  the org.freedesktop.secrets D-Bus API would make it the credential backend for
  the suite and every other app on the desktop — the strongest positioning
  Locket can have; put it on Locket's spec.
- **Cross-app queries need no daemon.** All apps link the substrate, so
  Envelope resolves a sender to `core::model::Contact` as a library call.
  The earlier daemon-centric design is unnecessary in the as-built shape;
  the per-app thin binaries (applet/daemon/launcher) are the right pattern.
  The only cross-*process* contract needed is Envelope↔Slate iMIP (04).

## Testing gaps, suite level

- **Server matrix CI.** `live_sync.rs` (canned multistatus against the real
  client) is the right kind of test; add containerized Radicale and Baïkal
  (trivial) and Nextcloud (official image) jobs exercising 412 paths,
  tombstones, and token-expiry resync. Fastmail/Google/iCloud stay a manual
  conformance checklist. Feed findings into a per-server quirks table (01).
- **RRULE conformance.** Golden tests against libical-generated expansions:
  DST transitions (Europe/Athens + one US zone), COUNT vs UNTIL,
  EXDATE + RECURRENCE-ID combinations, monthly-on-31st, BYSETPOS.
- **Round-trip corpus.** Real exports (Google Takeout, iCloud, Outlook,
  Nextcloud) in; byte-diff out modulo folding — for both formats, through the
  unified patcher.

## Sequencing across repos (dependency order)

1. Doc fixes; sync-ownership rule; sidecar test. (days-scale, unblocks nothing
   but stops bleeding)
2. Patcher → core, group-aware. Unblocks Circle editing entirely.
3. Meltemi licence declaration. Unblocks all Envelope porting.
4. Writeback classification + conflict surfacing API. Unblocks conflict UI in
   both apps.
5. Slate data-model completion: RECURRENCE-ID overrides, per-event TZ (02).
6. Envelope: mail model/store → threading → IMAP → UI (04, their own order,
   already dependency-correct).
7. iMIP receive-side (needs 3, 5, 6, plus scheduling module in 01).
8. Windows TZ mapping any time before 7.

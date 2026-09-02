# Roadmap

The direction: each application in the suite goes **1:1 against the best
existing app in its category** — every functionality covered, nothing waved
away — while being pixel-perfect against COSMIC's own first-party apps,
delightful to use, and 100% inside the ecosystem's conventions. Wayland is the
display server; wgpu is the renderer; the substrate stays the reason a bug is
fixed once.

Like everything else in these docs, this is **dependency-ordered, not dated**.
It sits on top of [00-suite.md](00-suite.md), [01-cosmic-pim.md](01-cosmic-pim.md),
and the per-app files (02 in slate, 03 in circle, 04 in envelope): those hold
the item-level detail; this file holds the milestones, the parity targets, and
the exit criteria. Where they conflict, the per-item docs win on *how*, this
file wins on *when relative to what*.

## Status ledger

Updated as milestones move; the one place a session checks before claiming
work. Last touched 2026-09-02.

- **Milestone 0 — done.** Docs agree with the code; the Meltemi MPL-2.0 grant
  exists (per-file, extended as ports continue); all four repos green.
- **Milestone 1 — done except two in-flight items.** Landed: conflict base
  capture + automatic three-way merge + per-unit `overlaps`/`resolve`
  (`core::merge`), mass-delete confirm-on-second-sight, error taxonomy,
  quirks tables (DAV seeded, IMAP seeded from Dovecot), Windows TZ mapping,
  local-only collections, birthday synthesis (`core::birthdays`), round-trip
  corpus, scheduling placeholder (`caldav::itip`). In flight: the RRULE
  golden suite (`tests/golden.rs`), and the Baïkal/Nextcloud CI legs
  (Radicale, Xandikos, Dovecot already run).
- **Milestone 2 — moving.** Substrate side largely ahead of the apps:
  occurrence overrides (RECURRENCE-ID end to end), server-side drafts
  mirror, filter rules + List-Id, outbox with scheduled sends and honest
  cancel, send-as aliases, mbox import (parse side), DSN parsing.
  `PARITY.md` audits are committed in all three app repos —
  data-loss-shaped gaps and ranked ceiling gaps are enumerated there.
  Circle adopted `queue_save_with_base` (CardDAV auto-merge is live end to
  end). App-side adoption open: conflict UIs, Slate's
  `queue_save_with_base` sites, birthday display, three-scope recurrence
  editing.
- **Milestone 4 — pulled forward.** The iMIP hand-off contract is specified
  (ARCHITECTURE.md, `Scheduling1`, encoding included) and Envelope's half is
  implemented and committed (invitation detection, `DeliverInvitation`
  caller with NameHasOwner degradation, `SendSchedulingReply` export into
  the durable outbox; substrate `mail::calendar::invitation` +
  `Outbox::submit`). Slate's half is the open item; end-to-end test when it
  lands.
- **Milestones 3, 5, 6 — not started**, except items the fleet pulled
  forward (folder management in Envelope exceeds the Geary baseline
  already).

---

## The benchmarks

"Feature complete" is meaningless without naming the app being measured
against. Three per category: a **baseline** (must fully cover), a **ceiling**
(the parity target), and a **polish reference** (how it should feel, not what
it does).

| App | Baseline | Ceiling | Polish reference |
|---|---|---|---|
| **Slate** | GNOME Calendar | Thunderbird calendar | Fantastical / Apple Calendar |
| **Circle** | GNOME Contacts | GNOME Contacts + Monica's CRM layer | Apple Contacts |
| **Envelope** | Geary | Thunderbird | Apple Mail |
| **Suite** | — | Thunderbird (the one Linux app doing all three) | — |

The suite-level claim to be able to make at the end: *a Thunderbird user can
move to Slate + Circle + Envelope and lose nothing they use* — while gaining
files-as-truth, suite-wide accounts, and a desktop that treats the three as
native.

Parity is audited, not assumed: each app grows a `PARITY.md` checklist built
by walking the ceiling app's menus and settings screens feature by feature,
each row marked **have / gap / rejected-with-reason**. A rejection with a
reason is an answer; an unlisted feature is a hole.

## The four tracks

Every milestone below advances one or more of these; naming them keeps the
work honest about *which* goal an item serves.

1. **Parity** — the functionality gap against the ceiling app.
2. **Polish** — pixel-perfect against first-party COSMIC apps, reactive,
   delightful; measured in frame times and in side-by-side screenshots, not
   in adjectives.
3. **Integration** — the conventions checklist at 100%, the peripheral apps
   (applets, daemons, launcher plugins), and the cross-app contracts.
4. **Engineering** — architecture, tests, CI, packaging, performance budgets.

---

## Milestone 0 — Stop the bleeding

*(00 §Fixes — days-scale, everything else stacks on a truthful base)*

- Doc drift: the cosmic-pim table vs Slate's README on CalDAV sync; the Rust
  1.93/1.97 claim. First files a contributor reads.
- One-sync-owner-per-collection rule stated in ARCHITECTURE.md and enforced
  softly (`ForeignSyncOwner` exists; the README pitch must stop contradicting
  it).
- Sidecar-hygiene tests pinned (watcher and store ignore `.caldav-state.json`,
  vdirsyncer files, `displayname`, `color`).
- Parent-directory-fsync wording made explicit in ARCHITECTURE.md.
- **Meltemi licence declaration** — verified a one-commit fix (single author).
  This gates crates.io publication and every further Envelope port; there is
  no reason left to defer it.

**Exit:** docs agree with the code, the licence gate is open, `cargo test
--workspace` green in all four repos.

## Milestone 1 — Substrate completion

*(01 §Gaps — the engine features both apps' UI is blocked on)*

- **Conflict surfacing API**: local/remote/base bytes persisted in the
  sidecar, exposed through sync reports, resolvable per-property (via the
  patcher) or wholesale. Non-overlapping changes auto-merge. Neither app can
  build its conflict UI until the engine emits this.
- **Writeback error taxonomy** pinned per class with tests: retryable
  (timeout/5xx/429) vs reconcile (412) vs needs-user (401/403/507) vs drop —
  already in the invariants; the milestone is the test coverage and the
  surfacing through sync reports.
- **Per-server quirks table** for DAV and IMAP, one data-driven shape (the
  Dovecot HIGHESTMODSEQ entry is the seed), populated from the CI matrix and
  field reports, never documentation.
- **Windows timezone mapping** (CLDR `windowsZones`) in `core::ical`, tried
  when IANA lookup fails, before the floating fallback. Prerequisite for iMIP
  against Outlook-originated invitations.
- **Local-only collections** — landed; keep as the base for Circle's link
  store and CRM sidecar.
- **Birthday synthesis**: BDAY (including year-less) → occurrence stream the
  calendar index serves, so Slate shows birthdays without a fake `.ics`.
- **Scheduling module design placeholder** beside `dav`: iTIP semantics
  (SEQUENCE, RECURRENCE-ID scope, PARTSTAT, METHOD validation) shared by
  Slate and Envelope. Built at Milestone 4; shaped now so nothing else grows
  into its spot.
- **Reminders move to the substrate** when Circle's keep-in-touch needs them
  (00) — the trigger is Circle's CRM tier, not a date.

**Exit:** an app can render a conflict, a parked auth failure, and a quirky
server without touching protocol code; the golden-suite gates below exist.

**Engineering gates opened here** (they guard everything after):

- Server-matrix CI: containerized Radicale, Baïkal, Nextcloud (DAV) and
  Dovecot (IMAP) driving the real engines — 412 paths, tombstones,
  token-expiry, UIDVALIDITY bump. Fastmail/Google/iCloud/Exchange stay a
  manual conformance checklist feeding the quirks table.
- RRULE golden suite against libical expansions: DST transitions
  (Europe/Athens + one US zone), COUNT vs UNTIL, EXDATE + RECURRENCE-ID,
  monthly-on-31st, BYSETPOS.
- Round-trip corpus: real exports (Google Takeout, iCloud, Outlook,
  Nextcloud) in, byte-diff out modulo folding, both formats, through the
  patcher.

## Milestone 2 — App parity, the data-correct tier

The features whose absence loses data or trust, per app, in each app's own
dependency order. This is where the `PARITY.md` audits are written and the
gap lists below get corrected against reality.

**Slate** *(02 §1–4)*

- Occurrence-scoped edits — the headline gap. *This event* (RECURRENCE-ID
  override), *this and following* (UNTIL split + override re-homing), *all
  events*; the same three scopes on delete. Read-side override merging
  verified **first** — if display ignores RECURRENCE-ID today, that is a
  correctness bug ahead of the feature. Gated on the RRULE golden suite.
- Per-event timezone: TZID picker, start-TZ ≠ end-TZ, all-day stays DATE;
  then a secondary-timezone column in week/day.
- Conflict UI over the Milestone 1 API.
- ICS subscriptions UI (engine already shipped): add-URL, refresh interval,
  read-only badge.

**Circle** *(03 §4–6 — write path, photos, shell parity already done)*

- `KIND:group` / addressbook-group cards — engine landed in the substrate;
  the UI and per-server quirks entries are the open half. Drag-to-assign,
  group-as-compose-list.
- Linking: app-level person over per-account cards, per-field precedence,
  every edit landing on exactly one card, link store in a local-only
  collection. The distinguishing model — this is what the baseline apps
  don't have.
- Duplicate review: exact email / E.164 phone candidates, transliteration-
  aware name suggestions (Γιώργος ↔ George), side-by-side diff, default
  action **link**, never auto-merge.

**Envelope** *(04 §Next)*

- Server-side drafts (UIDPLUS, Message-ID fallback, reconciliation pass).
- The triage verbs the registry already has slots for: **undo send**
  (outbox + delay), **snooze**, **labels/keywords**, **rules** (client-side
  filters first; Sieve where the server offers it).
- mbox **import** (export exists) — the Thunderbird migration path in
  practice, so it belongs in the parity tier, not QoL.
- OpenPGP first, S/MIME after (donor modules exist; port order per 04).

**Exit:** each `PARITY.md` shows no *data-loss-shaped* gap against the
baseline app; every remaining ceiling gap is listed with have/gap/rejected
status.

## Milestone 3 — Parity, the daily-driver tier

**Slate** *(02 §5–6)*: drag-to-move/resize with the three-scope prompt,
snap, working-hours shading, now-line, ISO weeks; agenda view and year
heatmap; in-app search; **undo** (journal the patcher's inverse — the
verbatim model makes inverses well-defined); meeting-link detection with
join actions; missed-alarm digest on resume; quick-add with deterministic
NL parsing (English + Greek, parse shown before commit); per-calendar
default alarm and duration.

**Circle** *(03 §7–8)*: the CRM layer — timestamped notes in the local-only
sidecar, last-contacted (manual now, automatic once Envelope's hook lands),
keep-in-touch cadence + overdue smart list on the substrate reminder engine,
RELATED links, local attachments. Then LDAP read-only, behind the store's
collection abstraction.

**Envelope**: the parity audit against Thunderbird will surface the long
tail (folder management verbs, saved searches, per-account identities and
signatures, address autocomplete via Circle, print/export). One decision the
1:1 goal **forces onto the table** rather than lets stand silently:

> **HTML display.** 04 records text-only as a deliberate security position,
> and it is the right default. But no mainstream client parity claim
> survives without *any* HTML view — a receipt or a boarding pass is
> unreadable as extracted text. The recommendation: keep text-first as the
> default rendering, add an **opt-in, per-message sanitized HTML view** —
> no remote content ever fetched, no scripts, CSP-equivalent by
> construction — in this milestone, and revisit rich-text compose only
> after it exists (the "composer writes what the reader can't show"
> argument then dissolves on its own). The encrypted store stays rejected;
> files-as-truth is the suite's promise.

**Exit:** a user of each baseline app switches and files no "it can't do X"
issue; the ceiling gap list is short enough to print.

## Milestone 4 — The suite acts as one

*(the cross-app contracts, 00/02/03/04 — this is what no benchmark app can
match)*

- **iMIP / scheduling**: substrate scheduling module built (iTIP semantics,
  then RFC 6638); Envelope detects `text/calendar` + METHOD and hands the
  payload to Slate over the one cross-process D-Bus contract; Slate renders
  the invitation with a slot conflict check; Accept/Tentative/Decline sets
  PARTSTAT and asks Envelope to send the REPLY. Degrades to "import this
  .ics" without Envelope. Organizer send-side and free/busy after.
  Depends on: Milestone 1 (Windows TZ, scheduling module), Slate's
  occurrence edits, Envelope's send path — all in place by here.
- **Sender → person**: Envelope resolves addresses through the shared
  contact model (a library call, no daemon); avatar and name in the list,
  click-through to Circle.
- **Last-contact hook**: Envelope reports sent/received per linked address;
  Circle's CRM consumes it.
- **`mailto:` registration** (Envelope) so Circle's compose actions and
  Slate's attendee links have a target; **envelope-launcher** completing the
  launcher-plugin trio; birthdays from Circle appearing in Slate via the
  Milestone 1 synthesis.
- **Locket as Secret Service provider** (00 §Platform): on Locket's spec,
  not here — but it is what makes the suite's keychain path the live path on
  stock COSMIC. Track it.

**Exit:** an invitation received in Envelope is accepted in Slate and the
organizer gets the reply; a sender in Envelope is a person in Circle; every
app is reachable from the launcher.

## Milestone 5 — Pixel-perfect, delightful, reactive

Polish is a phase with exit criteria, not a mood. The reference is
[cosmic-conventions.md](cosmic-conventions.md) plus side-by-side comparison
with cosmic-edit / cosmic-files on a live session.

- **Token audit**: zero raw pixel values, zero literal colours, all spacing
  and radii from the theme, semantic container/button classes throughout —
  greppable, so make it a CI grep. Light/dark/accent/high-contrast all
  screenshot-diffed.
- **Motion**: `cosmic::iced::animation` (lilt) for every state change that
  moves — view transitions, drawer, list insertions, the time-grid ghost
  preview. Interruptible always; no animation longer than it takes to read.
- **Interaction latency budgets, measured**: first frame < 100 ms warm;
  every keystroke-to-paint < one frame at 240 Hz on the wgpu renderer; the
  Slate time grid profiled with 200+ visible events *before* Milestone 3's
  interactions were built on it (02 names this the biggest UI unknown — the
  measurement belongs at the top of this milestone if it hasn't happened by
  then). Custom wgpu primitives (the cosmic-ext-camera pattern) only where
  measurement demands, likely candidates: the time grid, the conversation
  list.
- **wgpu everywhere**: the `wgpu` libcosmic feature on in all three apps,
  the softbuffer fallback verified working (a VM with no GPU is a user),
  frame times captured on both paths.
- **Keyboard-complete**: every action reachable without a pointer; KeyBind
  tables (never hand-rolled matching), shortcuts printed in menus, the
  registry/palette/cheat-sheet pattern Envelope already has extended to
  Slate and Circle.
- **Empty states, error states, loading states** designed, not defaulted —
  a new user's first five minutes in each app walked and screenshotted.
- **Accessibility**: full keyboard nav (libcosmic's own, not fought),
  contrast in both modes, text scaling at 125%/150%, reduced-motion
  honoured.
- **i18n complete**: no user-visible literal, plurals through Fluent, Greek
  as the proving second locale; xdgen adopted where it doesn't break
  single-instance (the Peek finding), deferred otherwise.

**Exit:** a screenshot of any view next to a first-party COSMIC app looks
like the same desktop made it; the latency budgets hold on a 240 Hz session
and in the no-GPU fallback.

## Milestone 6 — 100% conventions, packaging, release

The [conventions checklist](cosmic-conventions.md#checklist-for-a-new-cosmic-application)
at 15/15 per app, plus what "shipping" means:

- Metainfo complete (`com.system76.CosmicApplication` provides, branding,
  releases matching Cargo.toml, reachable URLs, screenshots);
  `desktop-file-validate` + `appstreamcli validate` in CI, `MimeType=` on
  one line (the measured Peek bug).
- Per-size icons (the higher-effort option — this is a polish suite),
  frosted keys gated, launch sequences with activation token + switcheroo +
  systemd scope everywhere an app launches an app.
- `debian/`, `flake.nix`, `hooks/pre-commit.hook`, vendored builds working
  (`just vendor` with git deps), per the conventions' packaging tier —
  none of the projects has these yet; they arrive here.
- Substrate published: crates.io after the Meltemi declaration (Milestone
  0), or git tags — either, but the `[patch]`+path sibling arrangement is
  retired first, because it silently masks version skew between apps.
- CHANGELOGs per release, conventional commits, tagged versions across the
  four repos moving together.

**Exit:** a distro packager builds all four repos from the tarballs without
reading anything but the justfiles; the apps are installable from a repo and
listed in the COSMIC store.

---

## Standing rules that shape every milestone

- **The substrate stays toolkit-free.** Pixel-perfect is an app concern;
  nothing in this roadmap adds libcosmic below the app layer.
- **Would a second app want it?** Then it lands in the substrate first, even
  when one app pulls it (reminders, scheduling, quirks, the patcher — all
  already followed this rule).
- **Files as truth, verbatim bytes, one parser, push-before-pull** — the
  ARCHITECTURE.md invariants are not renegotiated by parity pressure. Where
  a benchmark feature collides with one (encrypted store), the invariant
  wins and the rejection is recorded in `PARITY.md`.
- **Measure before building on top** — the time grid before drag
  interactions, list performance before windowed rendering, wgpu frame
  times before custom primitives.
- **Non-goals stay non-goals**: AI scheduling, social feeds, enrichment,
  auto-merge, an inference budget anywhere. The one flagged reversal (opt-in
  sanitized HTML view) is argued above, in the open.

## Risks, suite level

- **The server zoo dominates post-CI-matrix maintenance** — the quirks-table
  pattern is what keeps it out of the engine code; discipline there is the
  mitigation, per 01/04.
- **Time-grid performance under iced** is the one UI unknown that could force
  architecture (custom primitive) late; it is scheduled to be measured two
  milestones before it can hurt.
- **calcard and rrule/chrono are load-bearing** for both formats; the golden
  suite and round-trip corpus are the regression net for their upgrades.
- **libcosmic tracks a moving branch** (unpinned by convention) — the
  screenshot-diff suite in Milestone 5 doubles as the early-warning system
  for upstream visual changes.
- **Parity-list creep**: the ceiling apps ship features monthly. `PARITY.md`
  is re-audited at each milestone exit, and "rejected with reason" is a
  first-class answer — the goal is covering their functionality, not
  chasing their release notes.

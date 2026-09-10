# Architecture

The canonical description of how the suite fits together. The application
repositories link here rather than restating it, so there is one copy to keep
true.

## The shape

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│    Slate    │  │   Circle    │  │  Envelope   │   applications (GPL-3.0-only)
│  calendar   │  │  contacts   │  │    mail     │   one repo each
│   + tasks   │  │             │  │             │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
        ┌───────────────▼────────────────┐
        │          cosmic-pim            │           substrate (MPL-2.0)
        │  ┌──────────────────────────┐  │           this repo
        │  │      cosmic-pim-sync     │  │  orchestration: one pass per account
        │  └────┬──────────────┬──────┘  │
        │       │              │         │
        │  ┌────▼─────┐  ┌─────▼──────┐  │
        │  │  caldav  │  │    auth    │  │  protocol      OAuth 2.0 flow
        │  └────┬─────┘  └─────┬──────┘  │
        │       │        ┌─────▼──────┐  │
        │       │        │  accounts  │  │  credentials, providers
        │       │        └─────┬──────┘  │
        │       │    ┌─────────┤         │
        │       │    │  mail   │         │  IMAP/JMAP/POP3, maildir
        │       │    └────┬────┘         │
        │  ┌────▼─────────▼──────────┐   │
        │  │      cosmic-pim-core    │   │  model, iCalendar/vCard, vdir,
        │  └─────────────────────────┘   │  SQLite index, atomic writes
        └────────────────────────────────┘
```

Dependencies point downward only. `core` knows nothing about servers; `caldav`
and `mail` know nothing about accounts; `accounts` never opens a socket. `sync`
is the only crate that knows about the others, which is what keeps them
independently testable and separately reusable.

`auth` sits **above** `accounts` for that last reason. Running an OAuth flow
means an HTTP client and a listening socket, and putting those in the crate
that holds passwords would link both into every application that only wanted to
read an account name. So `accounts` owns the credential and the provider
manifests, which are storage and data; `auth` performs the exchange that
produces one. The seam is `cosmic_pim_auth::resolve`, which hands back the
secret to use *now* — renewing an expired token and re-storing it on the way —
so that no protocol client ever learns what a refresh token is.

`mail` sits **beside** `caldav`, not on it. CalDAV and CardDAV are one protocol
with four substitutions, which is why they share an engine behind a `Flavor`
enum. IMAP is not a third flavour of anything — it is a stateful session
protocol with its own consistency model (UIDVALIDITY, MODSEQ) — so adding it as
a fifth field on `Flavor` would mean every DAV code path carrying something it
has to ignore. What the two share is everything below them.

## Why the substrate is its own repository

Three applications consume it, and a fourth is expected to. Keeping it inside
any one application would make the other two depend on that application — Circle
would pull in Slate to read a vCard.

It is also the answer to "how do we not write the same sync bug four times".
Everything expensive lives here once: the reconciler's defences against real
servers misbehaving, the crash-safe writer, the timezone handling. A fix lands
in one place and all three apps get it.

## What actually gets shared

| Concern | Where | Notes |
|---|---|---|
| Events, tasks, contacts | `core::model` | Plain data. No toolkit types, no I/O. |
| iCalendar text | `core::ical` | One parser for the whole suite — see below. |
| vCard text | `core::vcard` | Same parser crate (`calcard`), same escaping and folding rules. |
| Files on disk | `core::store` | vdir: a directory per collection, one file per item. |
| Durable writes | `core::atomic` | Temp file → fsync it → rename → **fsync the parent directory**; optimistic concurrency. |
| CalDAV / CardDAV | `caldav` | One engine, two flavours. |
| ICS subscriptions | `caldav::feed` | A URL fetched on an interval, split into ordinary vdir files. Read-only by construction. |
| iTIP | `caldav::itip` | RFC 5546: what an invitation means, applied to a vdir. Shared by Slate and Envelope; RFC 6638 scheduling will use it, not replace it. |
| Server quirks | `caldav::quirks` | The ledger of what each server does differently, each fact naming its defence. Populated from CI and field reports, never from documentation. |
| RFC 5322 messages | `mail::model` | Extract-only. Nothing ever writes a message back through the parser. |
| Signing in | `auth` | OAuth 2.0 with PKCE, a loopback redirect, and renewal. One flow for every provider. |
| Where a service lives | `accounts::provider` | Manifests, not a match arm. A new provider is a file. |
| Messages on disk | `mail::maildir` | A maildir per mailbox: `mbsync`, `mu`, and `notmuch` read the same files. |
| IMAP | `mail::imap` | Session, cycle, durable writeback, and `watch` over IDLE. |
| JMAP | `mail::jmap` | RFC 8620/8621. Metadata by API, bytes by blob download; incremental via `Email/changes`; `watch` over the EventSource. |
| Gmail | `mail::gmail` | The Gmail API. Labels are the folder model; bytes by `format=raw`. |
| Microsoft Graph | `mail::graph` | Delta queries per folder; bytes by `$value`. |
| Id and cursor bookkeeping | `mail::store::RemoteIds` | Shared by all three: string id → local UID, plus a change-feed cursor that can expire. |
| POP3 | `mail::pop3` | RFC 1939, for accounts that offer nothing else. |
| SMTP | `mail::smtp` | Sending, and the one failure that must never be auto-retried. |
| Conversation lists | `mail::index` | A rebuildable SQLite cache, same standing as the calendar's. |
| Accounts, passwords | `accounts` | OS keychain, encrypted fallback. Shared across all three apps. |
| A sync pass | `sync` | Provision, push, pull, per-collection error isolation. Calendars and address books in one pass. |
| Conflicts | `sync::conflict` | Both sides changed one resource. Read them, resolve them. |

### Shared account store

Account metadata lives at `$XDG_CONFIG_HOME/cosmic-pim/accounts.toml`, with
credentials in the OS keychain — **once for the suite**, not once per app. A
user with a Fastmail account has one Fastmail account; asking for the same
password in three places is the wrong answer to the same question three times.

An account added in Slate's settings already appears in Envelope.

### Data locations

| Data | Path | Override |
|---|---|---|
| Calendars and tasks | `$XDG_DATA_HOME/calendars` | `COSMIC_PIM_CALENDAR_DIR` |
| Address books | `$XDG_DATA_HOME/contacts` | `COSMIC_PIM_CONTACTS_DIR` |
| Accounts | `$XDG_CONFIG_HOME/cosmic-pim` | `COSMIC_PIM_CONFIG_DIR` |
| Mail | `$XDG_DATA_HOME/mail` | `COSMIC_PIM_MAIL_DIR` |
| Event index (cache) | `$XDG_CACHE_HOME/cosmic-pim/index.sqlite` | — |
| Conversation index (cache) | `$XDG_CACHE_HOME/cosmic-pim/mail.sqlite` | `COSMIC_PIM_MAIL_INDEX` |

The vdir paths match what `vdirsyncer` writes, deliberately. Anything that
speaks vdir — `khal`, `khard`, Thunderbird — reads the same files. Mail is one
maildir per mailbox under `<account-id>/`, on the same principle: `mbsync`,
`notmuch`, `mu`, and `mutt` read them without being told anything.

## Invariants worth knowing before changing anything

These are each here because getting them wrong produced a real bug, and each is
pinned by a test.

**The vdir is the source of truth; the SQLite index is a disposable cache.**
Delete the index and it rebuilds. Sync state is therefore *not* in it — an etag
is a server-opaque token that cannot be reconstructed from the files. It lives
in a `.caldav-state.json` sidecar beside the data. Putting it in the cache would
mean clearing a cache resurrects events the server deleted.

**Server bytes are stored verbatim.** Our models cover what the UI can edit,
which is a fraction of what a VEVENT or vCard carries. Round-tripping through
them would silently discard ATTENDEE, ORGANIZER, VTIMEZONE, PHOTO, and every
`X-` property. So the sync engine writes the server's bytes untouched — and
writeback *patches* that text rather than re-serialising (`caldav::patch`).
Verbatim storage plus lossy writeback is worse than lossy storage, because the
loss only becomes visible once it is remote.

**Every write path patches, not just the sync one.** The rule above has
several enforcement points and only one of them used to be documented, which
is how all the others were re-serialising for as long as they existed. A
local edit goes through `store::vdir::write_event_if_unchanged`,
`store::vdir::write_todo` or `store::contacts::write_contact` — none of which
the sentence above covers — and each one now patches the file it is editing
(`ical::upsert_vevent`, `ical::upsert_vtodo`, `vcard::patch_vcard`). Only a
file that does not exist yet is serialised from the model, where there is
nothing to lose.

The failures this cost were not subtle, and they were found in an afternoon
once someone looked for the shape rather than the symptom. Saving a task
wrote one VTODO over a file that could hold several, deleting the other tasks
in it. Editing an event lost every unmodelled property, and then — after that
was mitigated — still lost the parameters on modelled ones. Saving a contact
patched the *first* card in the file rather than the contact's own, so
editing the second person in an imported address book wrote their name and
email over the first person's card while leaving that card's UID in place.

**Deleting a record rewrites its file; only an emptied file is unlinked.**
`store::vdir::remove_record` is the single place that decides between the
two, for both events and tasks. Deleting used to unlink the file outright,
which took every other record in it — so a `.ics` holding two tasks lost both
when the user deleted one. This is the same bug as the write ones and it
outlived them by an afternoon, because the audit that found those enumerated
every `atomic::write` call site and deletion does not write. *The boundary of
an audit is part of its result*: "I checked every write path" reads as "I
checked every path" to everyone including the person who wrote it.

**The verbs that touch a shared file, and which have been swept.** A `.ics`
or `.vcf` may hold several records, and every operation that treats one as
though it held one record corrupts the rest. The bugs came in four verbs, and
each was found only after someone asked which verbs had *not* been looked at
— re-sweeping an already-swept verb never found anything:

| Verb | What went wrong | Where it is decided now |
|---|---|---|
| Write over an existing file | one record serialised over its neighbours | `upsert_vevent`, `upsert_vtodo`, `patch_vcard` |
| Delete | unlinked the file, taking the neighbours | `vdir::remove_record`, `ContactStore::delete` |
| Create at a derived name | two UIDs deriving one name, second written over first | `sanitise_file_stem`, `itip::unused_name`, and the collision loops in `caldav::vdir`/`feed` |
| Move between collections | a write plus a delete, and the delete half unlinked | `move_to_calendar`, through `remove_record` |
| Export | contacts emitted a multi-card file once per card; calendars dropped the VTIMEZONE while keeping the `TZID=` references to it | `export_collection`, `ical::timezones_of` |

**The container is not only the file.** The table above is about documents
holding several records, and the same question repeats at every level where
the model is narrower than the format — each level invisible from the one
above. A *line* holds parameters the model does not name (`PID`, `ALTID`,
`GEO=`), which the writer dropped while faithfully preserving whole
properties. A *value* holds components (`ORG:Company;Division;Team`), of
which the model named the first. A *component* is itself a list, where a
category written `friends\, close` was re-split on its own escaped comma
into two. Each was found only after the level above it was fixed and someone
asked what the next one down was; none of them would have been caught by
re-examining the level above.

Two rules came out of that. Components are escaped individually, never as one
joined string — escaping the join writes `Company\;Division\;Team`, a single
name containing semicolons, which is a different fact about the contact. And
*assertions about preservation must unfold first*: a 75-octet fold can split
any value mid-word, and a `contains` that cannot see across the continuation
reads correct folding as data loss, which is how a correct folder gets
"fixed".

**Every rung has two failure modes**, and they are not the same bug seen
twice. One is that *the model is narrower than the format* — the fixes above.
The other is that *the interface is narrower than the model*, and fixing the
first only makes the second visible. Both lose the same data, and an
application can be perfectly correct about one while losing everything to the
other.

Two forms of the second, both found in an editor within an hour of the
matching substrate fix landing:

- **Do not rebuild an entry from field state.** Parameters and components
  travel *in* the model entry, so an editor that reconstructs each entry from
  its own widgets hands the writer an empty one and drops everything, with
  every test here still passing.
- **Do not render a list to a flat string and parse the string back.** An
  interface that shows categories as one comma-separated field and splits
  that field on save turns `friends\, close` into two categories — no matter
  what the parser does, because the interface flattened the value and then
  parsed its own flattening. If a display must flatten, it has to escape in
  the format's own spelling and honour the escape coming back.

The substrate has projections of its own, and they were checked rather than
assumed: the SQLite index joins attendee and unmodelled lines with `\n`,
which is safe because an unfolded content line cannot contain one, and its
two comma-joined columns carry integers only. Contacts do not pass through
the index at all.

An app must mutate its entries in place and must not round-trip a value
through a display string. Both belong in the app's own tests: the substrate
cannot see either mistake.

**Fixing one level can make a defect at another worse, not just visible.**
Every other case here works the same way — repairing a rung reveals the one
below it, which makes the work cumulative and safe. One did the opposite. A
contact share wrote a *display* string into `ORG:`, harmless-looking while
the display was only a company name; the moment department units were
correctly made visible, the share began filing people under a company named
`Mathematician, Analytical Engine Co ‣ Research`. Displaying the units was
right, and it is what turned a latent leak into a worse one. Generally: when
a value crosses from one representation to another, enriching it at the
source amplifies any leak downstream in proportion — which is the argument
for the round-trip test below, since that test is the only check standing at
the crossing.

**Stage hunks, not files, and verify gates against HEAD.** Several sessions
write this checkout at once, so a file you edited may also carry someone
else's uncommitted work, and `git add <file>` commits both. That is how the
toolchain pin and the manifest came to disagree: a commit meant to change a
comment also swept up an uncommitted channel bump sitting in the same file,
and the drift it created was against a manifest that was consistent until
then.

The reverse costs more and hides better: HEAD *lacking* something a commit
meant to include. A build that reads a **path** — `include_bytes!`, an asset
list, a packaging manifest, a container file a CI job mounts — is satisfied by
the working tree, and the tree holds every session's untracked files. So a
reference to a file nobody committed resolves for everyone on the machine and
for nobody else. No test covers it, because tests run where the file is; and
`git status` files it under the one heading everybody has trained themselves
to skim. The precondition is a file present but not committed that something
committed names, and bounding that takes two questions rather than one.
`git status --porcelain -uall` finds untracked files; it does **not** list
ignored ones, and a gitignored file a build reads is exactly as absent from a
clone as an untracked one, so `--ignored=matching` belongs in the same
command. Worse, the ignored set is machine-dependent unless the rules are kept in the
repository. This checkout ignored `.vscode/` through the developer's *global*
config, so the audit read "nothing untracked" here and would have found an
untracked file on anyone else's machine — the bound was true locally and
nowhere else. The rules are repo-local now, which is what makes the check
mean the same thing for everyone.

Two commands make that answerable rather than assumed, and both print their
operand rather than a verdict: `git check-ignore -v <path>` names the rule
that decided, and `-c core.excludesFile=/dev/null` shows what a contributor
with no global ignores sees.

Both questions asked here: no untracked entries, two ignored ones — `target/`
and `.vscode/` — and nothing committed names either. The four `include_str!`
provider manifests and the Dovecot config a CI job mounts were confirmed with
`git ls-tree`, which asks what is committed, rather than by looking for them
on disk, which asks whether the tree has them and is the question that
created the problem.

**A lockfile can carry a dependency no manifest in this repository names.**
Path dependencies read the filesystem, so a sibling repo's *uncommitted*
manifest change enters this workspace's graph immediately, and the next
routine `cargo test` rewrites `Cargo.lock` to match. Committing that lock
encodes a crate nothing here asks for and CI may be unable to fetch — and it
does so through a file people stage without reading, because a lockfile diff
always looks like noise. The rule: never commit a `Cargo.lock` carrying an
entry you cannot trace to a change in this repository. This is live right
now — the working tree's lock names `cosmic-ext-nib-text`, from another
crate's uncommitted manifest edit, while HEAD's lock is clean.

The reverse direction is the same fact seen from the other repository: an
uncommitted edit here changes a *consumer's* dependency graph with no commit
in either repository, so their `--locked` check fails on a crate they never
named. A substrate manifest change is therefore a cross-repository release —
every consumer moves in the same change, or none does.

The same shape makes local verification lie. Every tool reaches for the
working tree — `cat`, `grep`, `cargo` — while CI sees HEAD, and in a shared
checkout those differ by whatever other sessions have open. A gate checked
against the tree can report green on a fix that is not committed. Read HEAD
deliberately (`git show <rev>:<path>`, or a throwaway `git worktree`), and
have the check print the values it compared rather than a verdict: an audit
across several commits caught a broken extractor precisely because the
printed values were empty, where a bare PASS/FAIL would have read as a
finding about the history.

**The artefact that was wrong had every checkable property right.** That is
the single line this section is made of, and it is why reading never found
any of these and running something always did. A comment that quantified
correctly over call sites the code did not honour. An `If-Match` defence
documented in three registers and implemented in none. A read-only guard
present on every path except the one that removed the file. A toolchain pin
agreeing with a file six lines away. An icon committed under the right name,
at the right size, in the right format, of the wrong application. In each
case every property a reader could check was satisfied, and the thing itself
was wrong. A comment is also deletable exactly when nothing depends on it —
the sentence that would have prevented that icon shipping was written, was
correct, and was removed by someone tidying. The remedy is never a better
sentence; it is making something run that fails without it.

**A payload built by hand needs a test that reads it back.** Anything
assembled outside the normal writer — an iTIP reply, a VFREEBUSY request, a
calendar export, a DAV request body, a JSON message to an external process —
tends to be tested with `contains` on text the builder just wrote, which
re-asserts the format string and cannot tell a valid document from a
plausible-looking one. Parse it with the *consumer's own reader*: `calcard`
for calendars, `quick_xml` for DAV bodies, the consumer's real types for
anything crossing a process boundary. A look-alike struct written to agree
with the writer proves nothing. The failure these catch has a long fuse — a
server rejecting an invitation, a launcher that silently finds nothing —
because there is no test between the mistake and the user.

This table is a record of what has been checked, not a claim that the list is
complete — that claim was made twice during the sweep and was wrong both
times. *The boundary of an audit is part of its result*: "I checked every
write path" reads as "I checked every path" to everyone including the person
who wrote it, and the fix for that is to state the verb, not the conclusion.

**A component is addressed by identity, never by position.** Every one of
those paths locates its component before touching it — a VEVENT by
RECURRENCE-ID or UID, a VTODO by UID, a VCARD by UID — because a file holding
one record is the case our own fixtures generate and a file holding many is
the case every real exporter produces. `patch::patch_nth_component` takes the
index for the same reason. The related bug underneath them wrote an added
property into whichever sibling component came last, because it located the
insertion point by searching the output text for `END:` rather than by the
index it already had.

Two lessons worth keeping, because both were paid for. *Using the right
mechanism is not the same claim as being correct*: contacts genuinely did
edit through the patcher, which is why this document held them up as the
example and why two people reading the code stopped at that fact — it patched,
it just patched the wrong component, and a wrong implementation of the right
pattern is harder to see than a wrong pattern because the reason to look has
already been answered. And *a comment explaining why something surprising is
safe does a test's job without a test's guarantees*: the `rfind` above had
one, it was specific and confident and wrong, and it was read past by
everyone who touched the file.

**Writeback is queued and durable.** A push that fails and is forgotten diverges
*permanently*: the server's etag never changed, so the next pull finds nothing
to reconcile and the edit is lost with no trace. Failed pushes persist in the
sidecar with exponential backoff.

**Push before pull.** The other order lets a pull overwrite a local edit with the
server's older copy, after which the queued push re-uploads what was just
clobbered. It presents as edits mysteriously reverting.

**A pull never overwrites an unsent local edit.** Push-before-pull orders the
two; it does not help when the push *failed* and the server changed the same
resource anyway. Then the pull writes the server's bytes over the local file,
the queued PUT reads that file at drain time, uploads the server's own copy back
to it, and reports success — queue empty, ctag committed, no error raised
anywhere, and the edit gone. So the cycle asks the store for unsent local bytes
before writing, and when both sides changed it records a `Conflict` holding both
versions instead of choosing one (`caldav::store::Conflict`). Resolution is the
application's: keep local, take remote, or supply a merge. Nothing resolves
itself with time, because the alternative to asking is guessing.

**A divergence with a base merges itself when the edits do not overlap.** The
writeback queue captures the pre-edit bytes at the first enqueue (an app passes
them through `sync::queue_save_with_base`; a second edit before the push drains
keeps the original base, because that is still the last text the server
acknowledged). With that third point in hand, `core::merge::merge3` runs a
conservative unit-level three-way merge before anything is recorded: the server
moved the event and this device renamed it → both changes land, the merged text
is re-queued so the server converges, and no question is asked because there
was no question. Only a genuine overlap — the same property, the same
identityless sub-component — becomes a `Conflict`, which now carries the base
for a per-property resolution UI. No base means no merge is attempted: guessing
is still worse than asking.

**An empty listing is believed on the second sighting, not the first.** The
mass-delete guard treats one empty listing over a populated collection as a
server hiccup and skips deletions — but a collection whose last event was
legitimately deleted would then never empty locally. So the guard records the
ctag the empty listing arrived under, and a later cycle seeing the *same* ctag
with the same genuinely-empty listing (a listing that is only "empty" because
every resource individually failed never counts) applies the emptying. A
different ctag re-arms the sighting; any non-empty listing clears it.

**A failed write is classified, not just retried.** `Error::Status` carries the
HTTP code and `Disposition` says what it means: retry (timeouts, 5xx, 429),
reconcile (412 — our `If-Match` is stale, and every retry sends the same stale
value), needs-user (401/403/507), or drop. A 412 treated as retryable reproduces
the exact silent divergence the durable queue exists to prevent, only slower;
a 401 treated as retryable is how an account gets rate-limited. The two that a
retry cannot fix are *parked* rather than dropped — the edit survives without
costing a request an hour.

**The ctag is committed only over a cycle that applied in full.** A ctag changes
only when the server does, so claiming one over skipped deletions or bodies the
server never sent means that work waits for an unrelated future edit before
anything retries it. Recorded conflicts are the exception: there is nothing left
for the next cycle to redo.

**Both fsyncs, not one.** `atomic::write` syncs the temp file *and then the
parent directory* after the rename. The second one is the step everyone skips:
`sync_all` on the file gets the data to the platter, but the rename is a
directory-metadata operation in its own journal, so a power loss just after a
successful rename can leave the directory entry pointing at the old inode or at
nothing. Data synced, name lost.

**One parser, not two.** `core::ical` exists because the sync engine and the
local reader must interpret the *same file* identically. They did not: the
previous implementation matched timezones byte-exactly, so a server sending
`TZID=Europe/Athens ` (trailing space — real servers do this) fell through to
floating and shifted the event by the local offset.

## The same invariants, over mail

Mail is a different wire format, not a different set of rules. Every invariant
above has an exact counterpart, and each is pinned by a test in
`cosmic-pim-mail`.

**Files are the truth; the index is disposable.** A maildir per mailbox, not a
SQLite message table — a message store in a database would be the first place
the suite broke its own rule, and "walk away with your data" would go with it.
The UID and the flags live in the filename (`,U=42:2,S`, as `offlineimap` and
`mbsync` spell it), so a directory walk rebuilds everything.

**Sync state lives in a sidecar.** UIDVALIDITY, the UID cursor, and MODSEQ are
tokens the server minted and nothing on disk could reconstruct, so they sit in
`.imap-state.json` beside `cur/` — the same relationship `.caldav-state.json`
has to a vdir collection, for the same reason.

**Message bytes are verbatim.** `mail::model::Message` covers what the reader
shows, which is a fraction of what RFC 5322 carries. Storing the model rather
than the bytes would discard MIME structure and every unmodelled header — and it
would invalidate the DKIM signature, which is the one piece of cryptographic
evidence the message carries and whose entire value is that it survived the trip.
Nothing re-serialises a message; a flag change is a **rename**, not a rewrite.

**Writeback is queued and durable.** A `\Seen` that fails and is forgotten
diverges permanently for exactly the reason a dropped PUT does: the server's
state never changed, so the next pull finds nothing to reconcile. Failed pushes
persist in the sidecar with exponential backoff, classified as retryable,
needs-reconcile, or needs-user — retrying an `[AUTHENTICATIONFAILED]` two hundred
times an hour will not discover a new password.

**Push before pull.** Identical reasoning, and the presenting symptom is "my read
marks keep reverting" rather than "my edits keep reverting".

**UIDVALIDITY is the 412.** A stale etag means "re-read before you write". A
changed UIDVALIDITY means the same thing about a whole mailbox: UID 41 now names
a different message, or none. It is never retryable, and it is handled by
discarding the mailbox and refetching — reconciling would compare flags between
messages that have nothing to do with each other and write the result to disk.

**Never `BODY[]`.** The fetch is `BODY.PEEK[]`. `BODY[]` sets `\Seen` as a side
effect of reading, so a client that syncs with it marks the user's entire mailbox
read — on the server, on every device, with no undo. This one is asserted against
the bytes on the wire in `tests/live_sync.rs`, because it is invisible anywhere
else.

**One parser, not two.** `mail::text` is the only thing that turns a message body
into text, for the reader and for anything that indexes it. Envelope renders text
rather than HTML, which is why there is no sanitiser to disagree with a renderer
and why a tracking pixel has nothing to fire from.

**The token is resolved once, above every protocol.** An access token expires
in about an hour, and there are five clients that need one: CalDAV, CardDAV,
IMAP, SMTP, JMAP. Teaching each of them to renew would put the account store,
the provider registry and an HTTP client inside every one, and would be wrong
in five places independently. So they take an already-valid secret and nothing
else. The renewal happens in `cosmic_pim_auth::resolve`, which **stores the new
grant before returning it** — not an optimisation: a provider that rotates
refresh tokens invalidates the stored one the first time a renewal uses it, so
a pass that renewed without persisting would leave an account that can never be
renewed again.

**JMAP metadata comes from the API; JMAP bytes do not.** `Email/get` will hand
over headers as fields and the body as structured parts, and storing that would
break verbatim storage in the one protocol where it is easiest to break: a
reassembled message has a different MIME structure and an invalid DKIM
signature, and nothing notices until it is forwarded. So `Email/get` is asked
for metadata plus `blobId` only, and the message itself comes from the download
endpoint as the original octets. One extra request per message, and it is not
optional.

**Submission is verbatim too, and Bcc is the proof.** Every engine sends the
composer's own bytes — SMTP, Gmail's `messages.send`, Graph's `sendMail` — and
the difference between them is one header. SMTP carries recipients in a
separate envelope, so the wire copy is built *without* `Bcc`; an API has no
envelope, recipients derive from the headers, so the API copy is built *with*
it and the provider strips it on delivery as the submission server (RFC 5322
§3.6.3). Stripping it ourselves on the API path means the blind-copied
recipient never receives the message at all. Filing differs the same way: the
API providers file their own Sent copy, SMTP-over-IMAP appends one, and
SMTP-over-JMAP uploads the accepted bytes and `Email/import`s them into the
`sent`-role mailbox — never re-rendered.

**A provider API is a change feed, not a message store.** Gmail and Graph both
serve the original RFC 5322 octets — `messages.get?format=raw` and
`GET /me/messages/{id}/$value` — so an engine built on either stays inside the
verbatim-bytes rule: the API says *what changed*, and the bytes come from the
raw endpoint. Their parsed representations (Gmail's `format=full`, Graph's
`body`) are one request cheaper and would invalidate the DKIM signature of
every message they touched. This is why there is no second storage path for
them, and why a JMAP, Gmail or Graph mailbox lands in a maildir that `mbsync`
and `notmuch` read exactly like an IMAP one.

**Every change feed has a horizon, and running off it is not an error.**
`cannotCalculateChanges` in JMAP, 404 or 410 from Gmail's `history.list`, 410
from a Graph delta link: all three mean *I cannot tell you what changed*. None
of them means "nothing changed", which freezes the account until somebody
notices, and none means "everything was deleted", which empties the maildir.
The only correct answer is to drop the cursor and read again — which is why
the full-read path in each engine is not an optimisation that can be removed
once the incremental one works.

**A JMAP write is confirmed, not merely unrefused.** `Email/set` reports
per-object failures in `notUpdated` rather than as a method error, and names
each success in `updated` — so a response mentioning an object in neither did
nothing at all. Treating absence of an error as success drops the queue entry
with the user's change unmade and nothing anywhere to say so, which is the
exact shape of loss the durable queue exists to prevent. The client requires
the positive acknowledgement.

**Gmail's read flag is inverted, and Graph's is not.** Gmail marks `UNREAD`;
IMAP, maildir and Graph all mark what *has* been read. Two engines in one crate
spelling the same state oppositely is precisely where a copy-paste marks an
entire mailbox read on every device the account is on, so each engine's mapping
is pinned by its own test.

**A Graph `@removed` is not always a removal.** An entry carrying
`@removed.reason == "changed"` is a property update wearing the tombstone
shape — Exchange emits it when a message leaves the *filter*, not existence.
Treating every tombstone as a delete silently drops mail somebody just edited.

**POP3 is not a small IMAP, and is not pretended to be.** One mailbox, no
folders, no server-side flags, nothing visible to a second device. Flags are
local facts; the writeback queue is not involved because there is nowhere to
write back to. Identity comes from `UIDL`, and a server without it is refused
rather than guessed at — there would be no way to tell a downloaded message
from a new one. Message *numbers* are never persisted: they are positions in
one session, and a stored one deletes whatever has drifted into that position
since.

Two things from the calendar side deliberately do **not** carry over. Step 4 of
"adding another application" below — add a `Flavor` — does not apply: IMAP is not
a WebDAV flavour. And `caldav::patch` has no mail counterpart, because a message
is never edited in place; the equivalent operation is a rename.

## The one cross-process contract: iMIP hand-off

Everything else the apps share is a library call, because they all link the
substrate. Invitations are the exception: the *payload* arrives in Envelope
and the *decision* belongs in Slate, and the two are separate processes. This
section is the contract; both sides implement it against their existing
single-instance D-Bus names, so no new daemon exists and nothing changes when
one app is not installed.

The iTIP semantics — attendee gate, SEQUENCE rule, RECURRENCE-ID-scoped
CANCEL, reply construction — live in `caldav::itip` and are **not** part of
the contract. The contract only moves bytes and names an account; whichever
side applies a payload does it through the same library everyone links.

**Interface** `com.magnetaros.CosmicPim.Scheduling1`, on the session
bus, exported at the object path derived from each app's own well-known name
(`/com/magnetaros/Slate`, `/com/magnetaros/Envelope`).

The calendar side (Slate) exports:

```
DeliverInvitation(ics: s, account_id: s) → (accepted: b)
```

Envelope calls it with the verbatim `text/calendar` part and the suite
account id the message arrived on. `true` means Slate has the payload and
will put its invitation view — conflict check for the slot, the three
PARTSTAT buttons — in front of the user; the decision happens there, later,
asynchronously. Slate applies the outcome to the vdir via `itip::apply` and
never talks back about it on this call.

The mailer side (Envelope) exports:

```
SendSchedulingReply(ics: s, account_id: s, to: s) → (queued: b)
```

Slate calls it with the `METHOD:REPLY` text `itip::build_reply` produced, the
account to send from, and the organizer's `mailto:`. `true` means the reply
is in Envelope's durable outbox — queued is the promise, not delivered, and
that is enough: the outbox already owns retries and the honest cancel.

**Encoding.** `ics` is the *transfer-decoded* part as text: base64 or
quoted-printable undone, then decoded to UTF-8 per the MIME part's declared
charset (D-Bus `s` carries nothing else). "Verbatim" here means never
re-serialised through a parser — folding, ordering, and unknown properties
survive — not raw wire bytes; a part whose charset label lies may carry
replacement characters in its free text, which is the mislabeled message's
problem, not the contract's. Nothing about scheduling writes these bytes
back to a mail server, so DKIM is not in play on this path.

**Degradation is part of the contract.** Each side treats the other's
well-known name being unowned (no `StartServiceByName` — an invitation must
not *launch* a mail client) as the feature being absent, not as an error:
Envelope falls back to "save / import this .ics", which works today; Slate
falls back to storing the PARTSTAT locally and telling the user to reply from
their mail client. Both fallbacks are the pre-contract behaviour, which is
what keeps the contract minimal — either app is fully useful alone, and the
pair is more than the sum only when both are present.

**Versioning.** The `1` suffix is the whole policy: a breaking change is a
new interface name exported alongside the old one, never a changed signature
under the same name.

## Local-only collections

An unbound collection is *not yet* synced; one marked local-only (a
`.local-only` file in the directory) is *not to be* synced — and only the user
can tell those apart. The distinction bites in one place: a collection that was
synced once and then disconnected still carries its binding, and without the
marker the next pass would resume pushing a calendar the user decided was
private. Provisioning leaves a marked collection alone, writeback declines to
queue for it (the queue is durable, and an entry accepted now would fire when
the marker came off, unasked), and unmarking reconnects with the binding
intact. This is also the prerequisite for Circle's on-device notes.

## One sync engine per collection

The vdir layout means a collection can legitimately be synced by `vdirsyncer`
*or* by `cosmic-pim-sync`. **Never both.**

They keep independent state — vdirsyncer has its own status database, we have
`.caldav-state.json` — and neither knows the other exists. Both pushing to one
collection is a divergence machine: each sees the other's writes as an
unexpected etag, re-fetches, re-pushes, and the two states oscillate.

The interop promise is therefore narrower than "anything that speaks vdir":

- **Readers** — `khal`, `khard`, Thunderbird, a text editor — any number, always.
- **Writers that do not sync** — same.
- **Sync engines** — exactly one per collection.

This is enforced rather than documented. Provisioning looks for a
`.vdirsyncer*` file in the collection directory and, finding one, binds the
collection but refuses to sync it, reporting `ForeignSyncOwner` to the
application. `VdirStore::acknowledge_sole_ownership` records a user who has been
asked and wants it anyway; the answer is durable, because asking again on every
five-second poll teaches people to dismiss the question unread.

The check is deliberately shallow — one directory read, matching a name prefix.
Parsing vdirsyncer's configuration to learn which collections it claims would be
more thorough and much more fragile; a marker file needs no interpretation.

## Extension points

**`CalDavStore`** (`caldav::store`) — six methods: read state, upsert, remove,
commit ctag, and the two that keep a pull from eating an unsent edit — report
local bytes not yet accepted by the server, and record a conflict. Implemented
over the vdir, and over memory for tests. Implement it to sync into something
else.

**`PushQueue`** (`caldav::push`) — the writeback queue, separate because the pull
path has two real implementations and this has one, but the backoff logic still
needs testing without a disk.

**Provider manifests** (`accounts::provider`) — a TOML file naming a provider's
OAuth endpoints and its CalDAV, CardDAV and mail addresses. Built-ins are
compiled in; a file in `$XDG_CONFIG_HOME/cosmic-pim/providers/` adds one or
overrides a field of one. Adding a provider is not a code change, and no OAuth
client id is shipped — one identifies the application asking, and there is none
this project could publish that would be correct for a downstream package.

**`Flavor`** (`caldav::dav`) — CalDAV and CardDAV are the same protocol with four
substitutions: home-set property, resourcetype marker, multiget report name,
payload element. An enum, not a second crate. A collection records its own
flavour in its sidecar at provisioning time, so opening one by id is enough to
know whether it holds `.ics` or `.vcf` — writeback and conflict resolution need
no other channel to be told.

## Where does this code go?

| If it… | Then it belongs in… |
|---|---|
| parses or writes a wire format | `core::ical` / `core::vcard` |
| describes data independently of any screen | `core::model` |
| touches files in a collection | `core::store` |
| speaks HTTP to a server | `caldav` |
| holds a password or an account | `accounts` |
| says where a named provider's services live | `accounts::provider` |
| talks to a provider's *login* endpoint | `auth` |
| joins an account to a collection | `sync` |
| renders, or reads a keyboard | the application |

The test: **would a second app want it?** If yes, it goes in the substrate even
if only one app needs it today. Contacts cost ~700 lines because everything
underneath already existed.

## Adding another application

1. Model the data in `core::model` if it is not already there.
2. Add a text layer in `core` if the format is new.
3. Add reading and writing to `core::store`.
4. If it syncs over WebDAV, add a `Flavor` — do not fork the engine. If it
   speaks something else, it is a crate beside `caldav`, the way `mail` is;
   the test is whether it shares the four substitutions, not whether it is a
   protocol.
5. The app itself is then a front end: a `Cargo.toml` depending on the
   substrate, an `app.rs`, and views.

Tasks (VTODO) were the test of this and cost roughly 200 lines of model, 200 of
iCalendar, 60 of store, and **zero** in the sync engine — a synced VTODO worked
the moment the model existed, because the engine never parses what it stores.

## COSMIC conventions, applied to a library

`cosmic-conventions.md` records what the COSMIC ecosystem's repositories agree
on. Most of it is about applications — libcosmic, applets, desktop entries,
layer surfaces — and lands on Slate, Circle and Envelope rather than here. For
the substrate, the project-level conventions and the deliberate divergences:

| Convention | Here | Why |
|---|---|---|
| `rust-toolchain.toml` agreeing with `rust-version` | follows | 1.98.0 in both; raise together. |
| `rustfmt.toml`, `imports_granularity = "Module"` | follows | |
| `Cargo.lock` committed, libraries included | follows | |
| justfile with the conventional recipe set | follows | Trimmed of install/uninstall — a library ships nothing installable. `vendor` stays for offline distro builds. |
| Copyright line + SPDX header per source file | follows | |
| MPL-2.0 for the linkable layer, GPL-3.0-only apps | follows | The same split libcosmic itself uses. See LICENSING.md. |
| libcosmic as a git dependency | **rejected** | The substrate is deliberately toolkit-free; that is what makes it testable headless and reusable outside COSMIC. The apps take libcosmic. |
| cosmic-config for configuration | **rejected** | `accounts.toml` + the keychain, shared suite-wide. cosmic-config is per-app desktop state; account identity is neither per-app nor desktop state, and depending on it would drag the toolkit in. |
| i18n / Fluent catalogues | **rejected** | No user-visible strings — errors here are for developers and logs; the apps translate what they present. |
| RDNN identity, desktop entry, metainfo, icons | n/a | Nothing here is launchable or discoverable. |

## Testing

Roughly 930 tests in the substrate, `cargo test --workspace`.

`caldav/tests/live_server.rs` is the odd one out: it scripts nothing. Gated on
`COSMIC_PIM_LIVE_CALDAV_URL` and ignored by default, it drives the real engine
through a full round trip — create, discover, sync, edit, push, the 412, delete
— against whatever CalDAV server the environment names. CI points it at
Radicale; it is the beginning of the server matrix, and the place the quirks
table's entries will come from.

The one worth knowing about is `caldav/tests/live_sync.rs`: a real HTTP server
answering PROPFIND and REPORT with canned multistatus XML, driving the real
client into a real vdir. The unit tests cover the parsers and the planner in
isolation; that test is what proves they are wired together in the right order.
It is also what caught the transport being unusable — `ureq` 3 enforces a
hardcoded HTTP-method allowlist and rejects every WebDAV verb before it reaches
the socket. Hence `reqwest`. Do not "simplify" back to `ureq`.

The mail crate has three of them, one per protocol, and they are the reason
adding a protocol has not meant re-learning the same lessons: `live_sync.rs`
scripts an IMAP server, `live_pop3.rs` a POP3 one — asserting dot-unstuffing
through to the bytes on disk, and that `RETR` precedes `DELE` — and
`live_jmap.rs` a JMAP one, asserting that the message stored is the one the
download endpoint served rather than anything reassembled from `Email/get`.

`mail/tests/live_sync.rs` is its counterpart: a scripted IMAP server on a real
socket, driving the real client into a real maildir. It exists for the same
reason, and it carries the two assertions that can only be made about the wire —
that the fetch uses `BODY.PEEK[]`, and that the STORE goes out before the FETCH.

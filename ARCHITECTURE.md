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
        │  │  caldav  │  │  accounts  │  │  protocol      credentials
        │  └────┬─────┘  └─────┬──────┘  │
        │       │    ┌─────────┤         │
        │       │    │  mail   │         │  IMAP, maildir, threading
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
| RFC 5322 messages | `mail::model` | Extract-only. Nothing ever writes a message back through the parser. |
| Messages on disk | `mail::maildir` | A maildir per mailbox: `mbsync`, `mu`, and `notmuch` read the same files. |
| IMAP | `mail::imap` | Session, cycle, and durable writeback. Not a DAV flavour. |
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
| Event index (cache) | `$XDG_CACHE_HOME/cosmic-pim` | — |

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

Two things from the calendar side deliberately do **not** carry over. Step 4 of
"adding another application" below — add a `Flavor` — does not apply: IMAP is not
a WebDAV flavour. And `caldav::patch` has no mail counterpart, because a message
is never edited in place; the equivalent operation is a rename.

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

## Testing

Roughly 480 tests in the substrate, `cargo test --workspace`.

The one worth knowing about is `caldav/tests/live_sync.rs`: a real HTTP server
answering PROPFIND and REPORT with canned multistatus XML, driving the real
client into a real vdir. The unit tests cover the parsers and the planner in
isolation; that test is what proves they are wired together in the right order.
It is also what caught the transport being unusable — `ureq` 3 enforces a
hardcoded HTTP-method allowlist and rejects every WebDAV verb before it reaches
the socket. Hence `reqwest`. Do not "simplify" back to `ureq`.

`mail/tests/live_sync.rs` is its counterpart: a scripted IMAP server on a real
socket, driving the real client into a real maildir. It exists for the same
reason, and it carries the two assertions that can only be made about the wire —
that the fetch uses `BODY.PEEK[]`, and that the STORE goes out before the FETCH.

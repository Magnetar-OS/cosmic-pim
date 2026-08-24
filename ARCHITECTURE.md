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
| RFC 5322 messages | `mail::model` | Extract-only. Nothing ever writes a message back through the parser. |
| Signing in | `auth` | OAuth 2.0 with PKCE, a loopback redirect, and renewal. One flow for every provider. |
| Where a service lives | `accounts::provider` | Manifests, not a match arm. A new provider is a file. |
| Messages on disk | `mail::maildir` | A maildir per mailbox: `mbsync`, `mu`, and `notmuch` read the same files. |
| IMAP | `mail::imap` | Session, cycle, and durable writeback. Not a DAV flavour. |
| JMAP | `mail::jmap` | RFC 8620/8621. Metadata by API, bytes by blob download; incremental via `Email/changes`. |
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

## Testing

Roughly 740 tests in the substrate, `cargo test --workspace`.

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

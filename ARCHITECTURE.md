# Architecture

The canonical description of how the suite fits together. The application
repositories link here rather than restating it, so there is one copy to keep
true.

## The shape

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│    Slate    │  │   Circle    │  │  Envelope   │   applications (GPL-3.0-only)
│  calendar   │  │  contacts   │  │    mail     │   one repo each
│   + tasks   │  │             │  │  (scaffold) │
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
        │       │              │         │
        │  ┌────▼──────────────▼──────┐  │
        │  │      cosmic-pim-core     │  │  model, iCalendar/vCard, vdir,
        │  └──────────────────────────┘  │  SQLite index, atomic writes
        └────────────────────────────────┘
```

Dependencies point downward only. `core` knows nothing about servers; `caldav`
knows nothing about accounts; `accounts` never opens a socket. `sync` is the
only crate that knows about all three, which is what keeps the others
independently testable and separately reusable.

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
| Accounts, passwords | `accounts` | OS keychain, encrypted fallback. Shared across all three apps. |
| A sync pass | `sync` | Provision, push, pull, per-collection error isolation. |

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
| Event index (cache) | `$XDG_CACHE_HOME/cosmic-pim` | — |

The vdir paths match what `vdirsyncer` writes, deliberately. Anything that
speaks vdir — `khal`, `khard`, Thunderbird — reads the same files.

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

An application asked to sync a collection carrying vdirsyncer status metadata
should warn rather than proceed silently.

## Extension points

**`CalDavStore`** (`caldav::store`) — four methods: read state, upsert, remove,
commit ctag. Implemented over the vdir, and over memory for tests. Implement it
to sync into something else.

**`PushQueue`** (`caldav::push`) — the writeback queue, separate because the pull
path has two real implementations and this has one, but the backoff logic still
needs testing without a disk.

**`Flavor`** (`caldav::dav`) — CalDAV and CardDAV are the same protocol with four
substitutions: home-set property, resourcetype marker, multiget report name,
payload element. An enum, not a second crate.

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
4. If it syncs over WebDAV, add a `Flavor` — do not fork the engine.
5. The app itself is then a front end: a `Cargo.toml` depending on the
   substrate, an `app.rs`, and views.

Tasks (VTODO) were the test of this and cost roughly 200 lines of model, 200 of
iCalendar, 60 of store, and **zero** in the sync engine — a synced VTODO worked
the moment the model existed, because the engine never parses what it stores.

## Testing

Roughly 290 tests in the substrate, `cargo test --workspace`.

The one worth knowing about is `caldav/tests/live_sync.rs`: a real HTTP server
answering PROPFIND and REPORT with canned multistatus XML, driving the real
client into a real vdir. The unit tests cover the parsers and the planner in
isolation; that test is what proves they are wired together in the right order.
It is also what caught the transport being unusable — `ureq` 3 enforces a
hardcoded HTTP-method allowlist and rejects every WebDAV verb before it reaches
the socket. Hence `reqwest`. Do not "simplify" back to `ureq`.

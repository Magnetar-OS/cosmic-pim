# cosmic-pim

The shared substrate under the COSMIC personal-information suite: storage, sync,
credentials, and the iCalendar/vCard layer.

This repository holds no user interface. It is the layer three applications sit
on so that a sync bug is fixed once rather than three times.

## The suite

| Repository | App | What it is | State |
|---|---|---|---|
| [slate](https://github.com/entro314-labs/slate) | **Slate** | Calendar and tasks | Working — CalDAV sync in-app and in a background daemon, reminders, panel applet, launcher plugin |
| [circle](https://github.com/entro314-labs/circle) | **Circle** | Contacts | Reads and searches a real address book; the lossless write path is done, the editing UI is not |
| [envelope](https://github.com/entro314-labs/envelope) | **Envelope** | Mail | Reads, threads, and syncs a real mailbox over IMAP; no composer yet |
| **cosmic-pim** | — | This substrate | 477 tests |

Names: *Slate* holds what's on your slate; *Circle* is your circle of people;
*Envelope* is the universal mail symbol as a word.

## The crates

| Crate | What it is |
|---|---|
| `cosmic-pim-core` | The model (events, tasks, contacts), the one iCalendar/vCard parser the suite shares, vdir storage, a SQLite index for calendar range queries, filesystem watching, and a crash-safe writer |
| `cosmic-pim-caldav` | CalDAV **and** CardDAV — protocol, reconciliation, durable writeback queue, and a store trait implemented over the vdir |
| `cosmic-pim-accounts` | Accounts and credentials: the OS keychain, with an encrypted local fallback for hosts that have none |
| `cosmic-pim-mail` | Mail — the message model over verbatim RFC 5322 bytes, a maildir store, JWZ threading, HTML-to-visible-text extraction, and IMAP with durable writeback |
| `cosmic-pim-sync` | The layer that joins `core`, `caldav`, and `accounts` — provisioning, one sync pass per account over calendars and address books, and the conflicts a pass could not resolve alone |

Dependencies point downward only. See [ARCHITECTURE.md](ARCHITECTURE.md) for the
diagram, the invariants, and where new code belongs.

## Using these

Not published to crates.io — see [Licensing](#licensing). Depend by git:

```toml
[dependencies]
cosmic-pim-core = { git = "https://github.com/entro314-labs/cosmic-pim", tag = "v0.1.0" }

# Uncomment to develop against a sibling checkout without retagging.
# [patch.'https://github.com/entro314-labs/cosmic-pim']
# cosmic-pim-core = { path = "../cosmic-pim/crates/cosmic-pim-core" }
```

A `[patch]` alone does not let you skip the git source: cargo still resolves it.
Until this repository is pushed, the applications use sibling **path**
dependencies, with the git form written in a comment ready to swap.

## What you get for free

Reading a calendar, with sync, is about this much:

```rust
use cosmic_pim_core::store::Store;

let store = Store::open_default()?;
let today = chrono::Local::now().date_naive();
let days = store.occurrences_by_day(today, today + chrono::Duration::days(7), &hidden)?;
let tasks = store.todos(&hidden);
```

An address book:

```rust
use cosmic_pim_core::store::contacts::ContactStore;

let book = ContactStore::open_default()?;
let matches = book.search("lovelace");
```

One sync pass over every enabled account — calendars and address books
together, failing per collection rather than per run:

```rust
let reports = cosmic_pim_sync::sync_all(&mut accounts, &calendar_root, &contacts_root);
```

What a pass could not decide on its own — the server and this device changed the
same event, and the local change had not been uploaded yet — is recorded with
both versions intact rather than guessed at:

```rust
for (collection, conflict) in cosmic_pim_sync::conflicts(&calendar_root) {
    // conflict.local and conflict.remote are both here; the user chooses.
    cosmic_pim_sync::conflict::take_remote(&calendar_root, &collection, &conflict.href)?;
}
```

## Interoperability

The on-disk layout is [vdir](https://vdirsyncer.pimutils.org/en/stable/vdir.html)
— a directory per collection, one `.ics` or `.vcf` per item. That is not an
implementation detail we happened to land on; it is the point. `khal`, `khard`,
`vdirsyncer`, and Thunderbird read the same files, and a user can walk away with
their data as plain text at any moment.

## Building

```sh
cargo test --workspace
```

## Licensing

MPL-2.0. The applications are GPL-3.0-only and *link* these crates without
absorbing them. [LICENSING.md](LICENSING.md) explains why that split exists, why
not MIT and not LGPL, and the one trap (MPL Exhibit B) that would break it.

**Not publishable yet.** The iCalendar and CalDAV layers derive from the
[Meltemi](https://github.com/entro314-labs/meltemi) project, which carries no
licence declaration at all. That has to be resolved before anything here is
published to crates.io or offered upstream. Details in LICENSING.md.

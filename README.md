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
| **cosmic-pim** | — | This substrate | 740 tests |

Names: *Slate* holds what's on your slate; *Circle* is your circle of people;
*Envelope* is the universal mail symbol as a word.

## The crates

| Crate | What it is |
|---|---|
| `cosmic-pim-core` | The model (events, tasks, contacts), the one iCalendar/vCard parser the suite shares, vdir storage, a SQLite index for calendar range queries, filesystem watching, and a crash-safe writer |
| `cosmic-pim-caldav` | CalDAV **and** CardDAV — protocol, reconciliation, durable writeback queue, and a store trait implemented over the vdir |
| `cosmic-pim-accounts` | Accounts and credentials: the OS keychain with an encrypted local fallback, and the provider manifests that say where a named service lives |
| `cosmic-pim-auth` | OAuth 2.0 sign-in and token renewal — the only crate here that talks to a provider's login endpoint |
| `cosmic-pim-mail` | Mail — the message model over verbatim RFC 5322 bytes, a maildir store, JWZ threading, HTML-to-visible-text extraction, and five engines (IMAP, JMAP, POP3, the Gmail API, Microsoft Graph) with durable writeback |
| `cosmic-pim-sync` | The layer that joins `core`, `caldav`, and `accounts` — provisioning, one sync pass per account over calendars and address books, and the conflicts a pass could not resolve alone |

Dependencies point downward only. See [ARCHITECTURE.md](ARCHITECTURE.md) for the
diagram, the invariants, and where new code belongs.

## Accounts

Signing in works two ways, and an application does not have to care which.

Most servers — Fastmail, Nextcloud, Migadu, a university, a Synology box —
take a URL and an app password. Google and Microsoft withdrew password
authentication and take OAuth, so the suite runs the authorization-code flow
itself: PKCE, a loopback redirect, and a refresh token renewed when it expires.

```rust
use cosmic_pim_accounts::{AccountStore, Registry};

let registry = Registry::load();
let provider = registry.get("fastmail").expect("built in");

// Everything the manifest knows — CalDAV, CardDAV, mail — filled in.
let account = provider.account_for("ada@fastmail.com");
accounts.add(account, &app_password)?;
```

An OAuth provider is the same shape with the flow in between:

```rust
let oauth = provider.oauth.as_ref().expect("this provider uses OAuth");
let pending = cosmic_pim_auth::begin(oauth)?;
open_in_the_users_browser(pending.authorize_url());

let credential = pending.exchange(&pending.wait()?, oauth)?;
accounts.add_oauth(provider.account_for(&address), &provider.id, &credential)?;
```

From there nothing distinguishes the two. `cosmic_pim_auth::resolve` hands back
the secret of the moment — a password, or an access token it renewed and
re-stored on the way — and the CalDAV client sends `Basic` or `Bearer`, the
IMAP session `LOGIN` or `AUTHENTICATE XOAUTH2`, without knowing which.

**Providers are data.** Google, Microsoft, Fastmail and iCloud ship compiled
in; a manifest dropped in `$XDG_CONFIG_HOME/cosmic-pim/providers/` adds one or
overrides a field of one. **No OAuth client id is shipped** — one identifies
the application asking, and there is none this project could publish that would
be right for a downstream package — so Google and Microsoft need a two-line
manifest before they can be used:

```toml
# $XDG_CONFIG_HOME/cosmic-pim/providers/google.toml
id = "google"
[oauth]
client_id = "…apps.googleusercontent.com"
```

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
let reports = cosmic_pim_sync::sync_all(&mut accounts, &registry, &calendar_root, &contacts_root);
```

Mail, in whichever protocol the account uses — IMAP, JMAP, POP3, the Gmail API
or Microsoft Graph. Every one of them lands in the same maildir, because each
provider API is used as a change feed while the message bytes still come from
its raw endpoint:

```rust
let secret = cosmic_pim_auth::resolve(&mut accounts, &registry, &account.id)?;
let report = cosmic_pim_sync::sync_account_mail(
    &account,
    &cosmic_pim_sync::credentials_for(&secret),
    &mail_root,
    Default::default(),
    now_ms,
)?;
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

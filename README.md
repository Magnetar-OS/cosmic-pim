# cosmic-pim

The shared substrate under the COSMIC personal-information suite: storage, sync,
credentials, and the iCalendar/vCard layer.

This repository holds no user interface. It is the layer three applications sit
on so that a sync bug is fixed once rather than three times.

## The suite

| Repository | App | What it is | State |
|---|---|---|---|
| [slate](https://github.com/Magnetar-OS/slate) | **Slate** | Calendar and tasks | Working — CalDAV sync in-app and in a background daemon, reminders, panel applet, launcher plugin |
| [circle](https://github.com/Magnetar-OS/circle) | **Circle** | Contacts | Working — create and edit with photos and groups, CardDAV sync, GNOME Contacts parity closed |
| [envelope](https://github.com/Magnetar-OS/envelope) | **Envelope** | Mail | Working — reads, threads and syncs over IMAP; composes and sends over SMTP with a durable outbox, drafts and attachments |
| **cosmic-pim** | — | This substrate | 1372 tests |

Names: *Slate* holds what's on your slate; *Circle* is your circle of people;
*Envelope* is the universal mail symbol as a word.

## The crates

| Crate | What it is |
|---|---|
| `cosmic-pim-core` | The model (events, tasks, contacts), the one iCalendar/vCard parser the suite shares, vdir storage, a SQLite index for calendar range queries, filesystem watching, a crash-safe writer, and recipient completion from the address book |
| `cosmic-pim-caldav` | CalDAV **and** CardDAV — protocol, reconciliation, durable writeback queue, and a store trait implemented over the vdir |
| `cosmic-pim-accounts` | Accounts and credentials: the OS keychain with an encrypted local fallback, and the provider manifests that say where a named service lives |
| `cosmic-pim-auth` | OAuth 2.0 sign-in and token renewal — the only crate here that talks to a provider's login endpoint — and GNOME Online Accounts as a second source of sign-ins |
| `cosmic-pim-mail` | Mail — the message model over verbatim RFC 5322 bytes, a maildir store, JWZ threading, HTML-to-visible-text extraction, and five engines (IMAP, JMAP, POP3, the Gmail API, Microsoft Graph) with durable writeback |
| `cosmic-pim-sync` | The layer that joins `core`, `caldav`, and `accounts` — provisioning, one sync pass per account over calendars and address books, the conflicts a pass could not resolve alone, and `setup`: from a typed address to a stored, working account |

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

let grant = pending.exchange(&pending.wait()?, oauth)?;
// The grant says whose it is, so nobody typed an address first.
let address = grant.identity.expect("the manifest asks for `openid`").email;
accounts.add_oauth(provider.account_for(&address), &provider.id, &grant.credential)?;
```

From there nothing distinguishes the two. `cosmic_pim_auth::resolve` hands back
the secret of the moment — a password, or an access token it renewed and
re-stored on the way — and the CalDAV client sends `Basic` or `Bearer`, the
IMAP session `LOGIN` or `AUTHENTICATE XOAUTH2`, without knowing which.

**Who signed in is read from the provider, not from a form.** The identity
comes from the ID token in the token endpoint's own response, and is believed
only when the endpoint is `https`, the token was issued to this application's
client id, it has not expired, and the provider does not mark the address
unverified. A token that fails one of those stops the sign-in.

**An add-account window does not have to assemble any of this.**
`cosmic_pim_sync::setup` takes a typed address and answers, with no network,
which provider it belongs to and every way of signing in that can work on this
installation, best first — the provider's own sign-in where a client id is
configured, GNOME Online Accounts where it is running, a password otherwise.
Then one call finishes the job and stores the account for every application
in the suite:

```rust
use cosmic_pim_sync::setup::{self, Route};

let plan = setup::plan(&registry, "ada@fastmail.com", online_accounts_running)
    .expect("an address");
let id = match plan.routes.first() {
    // Finds the servers, tries the password, stores only what was accepted.
    Some(Route::Password { .. }) => {
        setup::add_with_password(&mut accounts, &registry, &plan, "Ada", &password)?
    }
    // The browser flow; the account is named after whoever signed in.
    Some(Route::SignIn) => setup::sign_in(&mut accounts, &plan, open_in_the_users_browser)?,
    _ => return Ok(()), // Online Accounts, or no way in on this installation
};
```

**Providers are data.** Google, Microsoft, Fastmail, iCloud, Yahoo, AOL,
Proton Mail (through Proton Mail Bridge), mailbox.org, Posteo and GMX ship
compiled in, each with the mail domains that are its own, so an address is
enough to find it. A manifest adds a provider or overrides a field of one, and
is read from three places, each overlaying the one before:

| Directory | Whose |
|---|---|
| `cosmic-pim/providers/` under each `$XDG_DATA_DIRS` entry (`/usr/share`) | the distribution's package |
| `/etc/cosmic-pim/providers/` | the administrator's |
| `$XDG_CONFIG_HOME/cosmic-pim/providers/` | the user's |

**No OAuth client id is shipped** — one identifies the application asking, and
there is none this project could publish that would be right for a downstream
package — so Google and Microsoft need a two-line manifest before they can be
used. A distribution ships it once for every user:

```toml
# /usr/share/cosmic-pim/providers/google.toml
id = "google"
[oauth]
client_id = "…apps.googleusercontent.com"
```

**A server on loopback is not asked for a real certificate.** Proton Mail
Bridge serves IMAP and SMTP on `127.0.0.1` with a certificate it signed
itself, as any local server must. For a host written as a loopback address
the TLS handshake accepts it; for every other host, including the name
`localhost`, the certificate is verified as usual.

## Using these

On crates.io. Depend on the crates you need:

```toml
[dependencies]
cosmic-pim-core = "3"
cosmic-pim-sync = "3"

# A contacts or calendar app with no mail: keep the mail and OpenPGP stack
# out of the build.
# cosmic-pim-sync = { version = "3", default-features = false }

# Uncomment to develop against a sibling checkout.
# [patch.crates-io]
# cosmic-pim-core = { path = "../cosmic-pim/crates/cosmic-pim-core" }
```

`CHANGELOG.md` lists every public API change, with what to call instead.

## Sending

A message that could not be sent waits in the account's outbox
(`cosmic_pim_mail::Outbox`) and leaves on a later pass. Three things about it
are deliberate:

- **A drain reports what it did even when it stops early.** `drain` returns a
  `DrainOutcome`, not a `Result`: a local failure part-way is a field beside
  the messages already sent, so their ids cannot be lost with an error.
- **Why a message stopped is a type.** `Queued::failure` is a `SendFailure` —
  refused by the server (with its reason), possibly delivered, or simply not
  reached — stored on the record, so an application words each case itself.
  A send that may have been delivered is never retried automatically.
- **A reply remembers what it answers.** `Answers` rides on the queued record
  and comes back with the entry a drain reports sent: the `Message-ID`, which
  survives a renumbering, and the mailbox and UID, which are exact while the
  numbering stands. `Index::locate` turns the id back into a place.

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

A local edit and the upload it needs, as one step, so that a sync pass can
neither overwrite the edit before it is queued nor miss it:

```rust
let saved = cosmic_pim_sync::save_and_queue(
    &calendar_root,
    &event.calendar_id,
    &[&event.file_name],
    || store.save(&event),
)?;
if let Err(why) = saved.queued {
    // Saved on this device, but not queued for the server.
}
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

When the server and this device changed the same event, the pass first tries to
settle it without asking: an app that saves through `save_and_queue` (which
captures the pre-edit bytes) gets non-overlapping changes three-way merged and
re-queued automatically. Only genuinely overlapping edits are recorded — local,
remote, and base intact — for the user to decide:

```rust
for (collection, conflict) in cosmic_pim_sync::conflicts(&calendar_root) {
    // conflict.local and conflict.remote are both here; the user chooses.
    cosmic_pim_sync::conflict::take_remote(&calendar_root, &collection, &conflict.href)?;
}
```

An ICS subscription — a holiday calendar, a timetable, anything published as a
`webcal://` URL — becomes an ordinary read-only collection, refreshed with
conditional requests and split into one file per event so every vdir reader
sees it:

```rust
use cosmic_pim_caldav::feed;

let meta = feed::subscribe(&calendar_root, "Holidays", url, color, None)?;
feed::refresh(&meta.path, now_ms)?;
```

And mail can be *pushed* rather than polled, where the server offers it — IMAP
IDLE, or JMAP's event source — with one blocking primitive on each session:

```rust
match imap_session.watch("INBOX", Duration::from_secs(25 * 60))? {
    Watched::Changed => { /* run a sync pass */ }
    Watched::TimedOut => { /* watch again */ }
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

The iCalendar, CalDAV, and mail layers derive from the
[Meltemi](https://github.com/entro314-labs/meltemi) project, which now grants
MPL-2.0 on the donor files explicitly — publishing here is no longer
licence-blocked. Details in LICENSING.md.

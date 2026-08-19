# Licensing

## The decision

| Layer | Licence | Why |
|---|---|---|
| `crates/cosmic-pim-core` | **MPL-2.0** | Shared substrate. File-level copyleft. |
| `crates/cosmic-pim-caldav` | **MPL-2.0** | Shared substrate. File-level copyleft. |
| `src/` — the COSMIC apps and their binaries | **GPL-3.0-only** | Unchanged. The app is and stays GPL. |

The split is the whole point. Everything under `crates/` is intended to be
consumed by the calendar, a contacts app, a tasks app, a mail client, by
`cosmic-utils` projects, and by our own products — some of which are
commercial. Everything under `src/` is one GPL application.

## Why this had to be decided first

GPL-3.0-only is a one-way door. If the shared CalDAV engine, the vdir store, and
the atomic writer had been extracted *as GPL-3*, then:

- Meltemi and Anasa could never adopt the extracted crates back, because Anasa
  ships a commercial licence (Polar.sh billing, `apps/landing`) and Meltemi is
  unlicensed and headed the same way.
- Every downstream COSMIC app linking the substrate would be forced to GPL-3,
  which kills the "one sync engine for the whole desktop" goal before it starts.

We would have been donating our own engine to a licence we cannot use it under.
That is why this is step one rather than a cleanup item.

## Why MPL-2.0 and not something else

**Not MIT/Apache-2.0.** These crates encode expensive, hard-won knowledge — the
CalDAV reconciler's defences against SSO portals returning HTML that parses as
an empty multistatus, iCloud's per-tenant redirect handling, SOGo's transient
empty 207. A permissive licence lets that be absorbed into a closed product with
nothing coming back. We want the fixes back.

**Not LGPL-3.** LGPL's boundary is the *linkage* boundary, which is ill-defined
for Rust: static linking is the norm, generics and `#[inline]` cross the
boundary at compile time, and there is no stable ABI. It is a poor fit and the
community treats it as such.

**MPL-2.0's boundary is the file.** Modify a file in `crates/`, publish that
file. Link the crate from anything, under any licence, and nothing is imposed on
your own files. That maps exactly onto what we want: the engine stays open, the
apps stay free to choose.

## GPL compatibility — and the one trap to avoid

MPL-2.0 is deliberately GPL-compatible. Section 3.3 permits distributing a
Larger Work under a "Secondary Licence" (GPL-2.0+, LGPL-2.1+, AGPL-3.0+), which
is precisely what this repository does: the GPL-3 binary in `src/` statically
links the MPL-2.0 crates and is distributed as a GPL-3 whole. The MPL'd files
remain under MPL for anyone who extracts them.

**The trap:** MPL-2.0 Exhibit B ("Incompatible With Secondary Licenses") *turns
that off*. Do not add the Exhibit B notice to any file in `crates/`. If it ever
appears, the GPL-3 app can no longer legally link the substrate. The header used
throughout is Exhibit A only:

```rust
// SPDX-License-Identifier: MPL-2.0
```

## Provenance and outstanding obligations

Code in `crates/` derives from two of our own repositories. Both need attention:

### Anasa — MIT, obligation live

`crates/cosmic-pim-core/src/atomic.rs` is derived from
`anasa/apps/desktop/src-tauri/src/atomic_write.rs`, which is MIT
(`license = "MIT"` in that crate's manifest). MIT permits relicensing the
derivative under MPL-2.0, **provided the original copyright and permission
notice are retained**. That notice lives in `NOTICE` at the repository root and
in the module header of `atomic.rs`. Do not remove either.

### Meltemi — no licence at all, blocking

`meltemi` has **no LICENSE file and no `license` field** in
`src-tauri/Cargo.toml`. Under default copyright that means all rights reserved.
Because we hold the copyright, we may license it however we choose — but "we
own it" is not the same as "it is licensed", and the distinction matters the
moment a contributor, an acquirer, or a downstream packager looks at it.

**Which files are affected — two crates, not one.** An earlier note in this file
named only `cosmic-pim-caldav`. That was incomplete:

| File | Derived from |
|---|---|
| `crates/cosmic-pim-caldav/src/dav.rs` | `meltemi/src-tauri/src/caldav.rs` |
| `crates/cosmic-pim-caldav/src/patch.rs` | same |
| `crates/cosmic-pim-caldav/src/plan.rs` | same |
| `crates/cosmic-pim-core/src/ical.rs` | same — the date-time precedence rules, the TZID hardening, the escaping and folding helpers |
| `crates/cosmic-pim-accounts/src/secret.rs` | `meltemi/src-tauri/src/secrets.rs` |

So the blocker covers **`cosmic-pim-core`, `cosmic-pim-caldav`, and
`cosmic-pim-accounts`** — which in practice means the whole substrate, since
`cosmic-pim-sync` depends on all three.

**Required before any of this is published or upstreamed:**

1. Add `LICENSE` + `license =` to the `meltemi` repository, declaring the licence
   its code is offered under.
2. Record that the lifted layers are additionally offered under MPL-2.0, so this
   repository's copy has a stated provenance rather than an implicit one.

Until (1) and (2) are done, treat the whole substrate as internal-only: building,
testing, and consuming it from our own applications by git dependency is fine;
publishing to crates.io or offering it upstream to `cosmic-utils` is not.

This does **not** block the applications. Slate, Circle, and Envelope are GPL-3
and distributed by us, and we hold the copyright on the borrowed code — the
problem is a missing declaration, not a missing right.

## Contributing back to cosmic-utils

`discovery.rs` and `oauth.rs` are proposed for `cosmic-utils/accounts`, which is
**GPL-3.0**. Contributing MPL-2.0 files into a GPL-3 project is fine in that
direction — GPL-3 absorbs MPL-2.0 under §3.3 — but note it is one-way: once
those files live in `accounts` and are modified there, the modifications come
back to us as GPL-3, not MPL-2.0. Offer them as MPL-2.0-licensed files so the
originals stay dual-usable, and expect that to be a discussion point in review.

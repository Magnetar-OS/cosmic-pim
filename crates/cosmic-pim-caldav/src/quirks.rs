// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! The per-server quirks table: what each server is known to do differently.
//!
//! # Why a table and not if-ladders
//!
//! Every deviation this engine defends against is currently a comment beside
//! the defence — SOGo's 500-in-propstat next to the status gate, Zimbra's
//! non-ASCII etags next to the lossy decode. That is the right place for the
//! *defence*, but it makes the knowledge unfindable: the answer to "what do we
//! know about Nextcloud" is a grep. This module is the ledger. One entry per
//! server, each fact pointing at where the engine handles it, so the
//! alternative future — `if server == Nextcloud` scattered through the sync
//! cycle — never starts.
//!
//! # The discipline
//!
//! A fact enters this table from one of two sources: the CI server matrix
//! (`tests/live_server.rs` — Radicale, Xandikos and Nextcloud so far), or a
//! field report
//! with the wire traffic to back it. Not from documentation — the entire reason the
//! table exists is that servers do not match their documentation.
//!
//! Most entries are **defended everywhere**: the engine behaves the same
//! against every server, because the defence costs nothing when the quirk is
//! absent. A quirk only becomes a [`Quirks`] field consulted at runtime when
//! defending unconditionally would be wrong for the well-behaved majority —
//! none has crossed that line yet, and the bar for crossing it is deliberate.
//!
//! # Detection
//!
//! From a [`Fingerprint`]: the headers one response volunteered, plus the
//! URL's host as a fallback for the hosted providers that hide their software
//! behind proxies.
//!
//! **The `Server` header identifies almost nobody.** This was the module's own
//! founding assumption and the CI matrix demolished it on 2026-09-03. All four
//! servers, read off the wire:
//!
//! | Server | `Server:` header | What actually identifies it |
//! |---|---|---|
//! | Radicale 3.7 | `WSGIServer/0.2 CPython/3.14.7` | nothing |
//! | Xandikos 0.4 | `Python/3.14 aiohttp/3.14.3` | nothing |
//! | Nextcloud 34 | `Apache/2.4.68 (Debian)` | `DAV:` tokens `nc-*`, `nextcloud-*` |
//! | Baïkal 0.10 | `nginx/1.29.3` | `X-Sabre-Version` |
//!
//! Every one of them names the *web server or language runtime* it happens to
//! be running on. This module previously shipped unit tests asserting header
//! strings like `Apache/2.4.57 (Debian) Nextcloud` and `Radicale/3.1.8` —
//! shapes nobody had observed, which is the exact failure the discipline above
//! forbids, committed by this module against itself.
//!
//! So detection reads three signals, and for two of the four the honest answer
//! is still [`Server::Unknown`]. That is not a gap to paper over: a heuristic
//! on `WSGIServer` or `aiohttp` would match any unrelated Python DAV server
//! and put *wrong* facts into a ledger whose whole value is being right. The
//! live matrix asserts the outcome per server — including the two Unknowns —
//! so if a future release starts announcing itself, the test fails and the
//! ledger gets upgraded deliberately.
//!
//! Detection is best-effort by construction: an unrecognised server gets
//! [`Server::Unknown`] and the same defended-everywhere behaviour as everyone
//! else. That is exactly why two Unknowns cost nothing today — every entry in
//! this table is currently a fact with an *unconditional* defence, so nothing
//! is skipped for want of a name. The day an entry needs a runtime branch is
//! the day the Unknowns start to matter.

/// The servers this suite has met, in the field or in CI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    Nextcloud,
    Radicale,
    Baikal,
    Sogo,
    Fastmail,
    Google,
    ICloud,
    /// Exchange, Outlook.com, and the SSO front-ends that sit before them.
    Exchange,
    Cyrus,
    Davical,
    Zimbra,
    Xandikos,
    Unknown,
}

/// What one response volunteered about the server behind it.
///
/// A struct rather than a widening parameter list because the signals are
/// peers, not a primary plus fallbacks: for the two most-deployed servers the
/// `Server` header is the one that says nothing useful. Every field is
/// optional — a proxy may scrub any of them, and detection degrades to
/// [`Server::Unknown`] rather than guessing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Fingerprint<'a> {
    /// The `Server` response header.
    pub server: Option<&'a str>,
    /// The request URL's host, for hosted providers behind scrubbing proxies.
    pub host: Option<&'a str>,
    /// The `DAV:` compliance-class header. Nextcloud brands its own extensions
    /// here, which is the only identity it volunteers.
    pub dav: Option<&'a str>,
    /// The `X-Sabre-Version` header. sabre/dav sets it on every DAV response,
    /// and behind nginx it is all Baïkal offers.
    pub sabre_version: Option<&'a str>,
}

/// Detects the server from what the wire volunteered.
///
/// Ordered most specific first: a product's own extension tokens beat a
/// product name in the `Server` header, which beats the underlying library,
/// which beats the host. Nextcloud is checked before sabre/dav because
/// Nextcloud *is* sabre/dav with additions, and the additions are the answer.
#[must_use]
pub fn detect(fingerprint: Fingerprint<'_>) -> Server {
    let Fingerprint {
        server,
        host,
        dav,
        sabre_version,
    } = fingerprint;

    // The DAV compliance header, where a server lists the extensions it
    // implements. Products that extend the protocol name themselves here and
    // nowhere else.
    if let Some(dav) = dav {
        let dav = dav.to_ascii_lowercase();
        if dav.contains("nextcloud-") || dav.contains("nc-calendar") || dav.contains("nc-paginate")
        {
            return Server::Nextcloud;
        }
    }

    if let Some(header) = server {
        let header = header.to_ascii_lowercase();
        // Order matters where products stack: Nextcloud answers through
        // Apache or nginx, so the product token is searched before the
        // web-server token could shadow it.
        if header.contains("nextcloud") {
            return Server::Nextcloud;
        }
        if header.contains("radicale") {
            return Server::Radicale;
        }
        if header.contains("xandikos") {
            return Server::Xandikos;
        }
        if header.contains("sabre") || header.contains("baikal") {
            // Baïkal is sabre/dav in a costume; ownCloud-era servers also
            // announce sabre. Baïkal until a finer signal is needed.
            return Server::Baikal;
        }
        if header.contains("sogo") {
            return Server::Sogo;
        }
        if header.contains("cyrus") {
            return Server::Cyrus;
        }
        if header.contains("davical") {
            return Server::Davical;
        }
        if header.contains("zimbra") {
            return Server::Zimbra;
        }
        if header.contains("microsoft") || header.contains("exchange") {
            return Server::Exchange;
        }
    }

    // sabre/dav announces itself on every DAV response even when the front
    // end's `Server` header says only nginx or Apache. Reached only after the
    // product checks above, so a sabre-based product that named itself keeps
    // its own identity.
    if sabre_version.is_some() {
        return Server::Baikal;
    }

    if let Some(host) = host {
        let host = host.to_ascii_lowercase();
        // Matching stops at the label boundary, or `evilfastmail.com`
        // detects as Fastmail.
        let is = |domain: &str| host == domain || host.ends_with(&format!(".{domain}"));
        if is("fastmail.com") {
            return Server::Fastmail;
        }
        if is("googleusercontent.com") || is("google.com") {
            return Server::Google;
        }
        if is("icloud.com") {
            return Server::ICloud;
        }
        if is("office365.com") || is("outlook.com") {
            return Server::Exchange;
        }
    }

    Server::Unknown
}

/// What is on record for one server.
///
/// Every field is a *fact with a defence*, and the defence is named so the
/// table stays a ledger rather than becoming a second engine. Runtime
/// branching fields join here only when a defence cannot be unconditional —
/// see the module docs for the bar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Quirks {
    /// Has answered a request-level failure as a 500 *inside* a propstat
    /// while the response element said 200.
    /// Defended everywhere: the propstat status gate in `dav`'s multistatus
    /// parsers commits values only under an OK propstat line.
    pub error_inside_propstat: bool,

    /// Has shipped non-ASCII bytes in an `ETag` header.
    /// Defended everywhere: the header is decoded lossily and a value that is
    /// not RFC 7232-legal is skipped when building `If-Match`, degrading to
    /// an unconditional write rather than a wedged 412 loop.
    pub non_ascii_etags: bool,

    /// Enforces RFC 7232 strictly: a weak etag in `If-Match` 412s every
    /// PUT/DELETE, wedging a client that stores etags verbatim.
    /// Defended everywhere: `prepare_if_match_etag` refuses to send a weak
    /// or illegal value.
    pub strict_if_match: bool,

    /// Discovery crosses origins: the principal or home-set lives on a
    /// different host than the entry point (per-partition hosts).
    /// Defended everywhere: hrefs resolve against each response's *final*
    /// URL, and credentials drop when a redirect leaves the origin.
    pub cross_origin_discovery: bool,

    /// Front-ends have answered `.well-known` probes with `200 text/html`
    /// (an SSO login page) where XML belongs.
    /// Defended everywhere: `text/html` is rejected before status handling,
    /// and the base URL is probed before `.well-known`.
    pub html_where_xml_belongs: bool,

    /// Lists sub-collections without a trailing slash, or with the port
    /// spelled differently than the request URL.
    /// Defended everywhere: href comparison normalises both.
    pub sloppy_hrefs: bool,

    /// Password authentication is withdrawn; only OAuth bearer tokens are
    /// accepted. Handled above this crate: the account layer refuses to send
    /// a password where a token is required.
    pub oauth_only: bool,
}

/// The ledger. One line per fact, provenance in the comment beside it.
#[must_use]
pub fn quirks_for(server: Server) -> Quirks {
    let mut quirks = Quirks::default();
    match server {
        Server::Sogo => {
            // Field: multiget answering 500 at the propstat level; the reason
            // dav.rs's response-level status gate exists.
            quirks.error_inside_propstat = true;
        }
        Server::Zimbra => {
            // Field: non-ASCII ETag bytes, and hosted Zimbra redirecting
            // https→http on port 8443 (the downgrade veto's origin story).
            quirks.non_ascii_etags = true;
            quirks.sloppy_hrefs = true;
        }
        Server::Cyrus => {
            // Field: strict RFC 7232 — a weak If-Match 412s every write.
            // Apache mod_dav builds share this.
            quirks.strict_if_match = true;
        }
        Server::ICloud => {
            // Field: per-partition hosts (pXX-caldav.icloud.com); discovery
            // starts at caldav.icloud.com and ends somewhere else.
            quirks.cross_origin_discovery = true;
        }
        Server::Exchange => {
            // Field: enterprise front-ends answering .well-known with an IdP
            // login page as 200 text/html; six-hop redirect chains.
            quirks.html_where_xml_belongs = true;
            quirks.cross_origin_discovery = true;
            // Outlook.com withdrew CalDAV entirely; Microsoft 365 mail is
            // token-only. See the provider manifest.
            quirks.oauth_only = true;
        }
        Server::Google => {
            // Documented and observed: Basic auth withdrawn for CalDAV.
            quirks.oauth_only = true;
        }
        Server::Davical => {
            // Field: sub-collections listed without trailing slashes.
            quirks.sloppy_hrefs = true;
        }
        Server::Radicale => {
            // CI (2026-09-03): under its built-in server it announces
            // `Server: WSGIServer/0.2 CPython/3.14.7` — no product token, so
            // `detect` returns Unknown for a real Radicale. Everything below
            // was learned from the journey, not from detection, and is
            // defended unconditionally, so the blind spot costs nothing yet.
            //
            // CI, first live run (2026-08-25): MKCALENDAR on an existing
            // collection answers 409 + DAV:resource-must-be-null rather than
            // 405, and a PUT into a missing collection is a 409 rather than
            // an implicit create. Both defended everywhere: `mkcalendar`
            // treats that 409 as already-exists, and 409-on-PUT was already
            // classified Reconcile.
        }
        Server::Xandikos => {
            // CI (2026-09-03): announces `Server: Python/3.14 aiohttp/3.14.3`
            // and sends no `DAV:` header on PROPFIND at all, so like Radicale
            // it detects as Unknown. Recorded rather than guessed around: an
            // "aiohttp means Xandikos" heuristic would claim every unrelated
            // aiohttp server in the world.
            //
            // CI, first live run (2026-08-25): MKCALENDAR on an existing
            // collection answers 403 + resource-must-be-null — a third
            // spelling of "already exists". Defended everywhere: `mkcalendar`
            // keys on the precondition element, not the status.
        }
        Server::Baikal => {
            // CI, first live run (2026-09-03, Baïkal 0.10 / sabre-dav 4.7.0
            // behind nginx): announces `Server: nginx/1.29.3` and nothing
            // else — no sabre token, no product name. The only identity it
            // volunteers is `X-Sabre-Version`, which `detect` now reads.
            // Nothing else about the journey differed from the Python
            // servers, which is itself worth recording: the most-deployed
            // sabre stack needed no defence the engine did not already have.
        }
        Server::Nextcloud => {
            // CI, first live run (2026-09-03, Nextcloud 34.0.3 / sabre-dav):
            // announces `Server: Apache/2.4.68 (Debian)` with no product
            // token anywhere in it. Its identity is in the `DAV:` compliance
            // header — `nc-paginate`, `nextcloud-checksum-update`,
            // `nc-calendar-search` — which is where `detect` now looks.
            //
            // a 201 to PUT carries no ETag header at all — the value only
            // appears on a later HEAD or in a PROPFIND listing. Defended
            // everywhere by a rule that predates the finding: `drain`
            // discards the PUT response's etag and lets the next listing be
            // the source of truth, precisely because a response etag is
            // optional (RFC 4918 §8.6 recommends it; nothing requires it) and
            // may describe a body the server transformed. The finding
            // confirmed the rule rather than changing it — and it *did* find
            // a test that had quietly relied on the header.
        }
        // The field has not put anything on record for these yet. That is the
        // healthy state: the engine's unconditional defences have been enough.
        Server::Fastmail => {}
        Server::Unknown => {}
    }
    quirks
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fingerprint carrying only a `Server` header — the shape most of
    /// these assertions want.
    fn from_server(header: &str) -> Fingerprint<'_> {
        Fingerprint {
            server: Some(header),
            ..Fingerprint::default()
        }
    }

    fn from_host(host: &str) -> Fingerprint<'_> {
        Fingerprint {
            host: Some(host),
            ..Fingerprint::default()
        }
    }

    #[test]
    fn a_product_token_in_the_server_header_is_still_read_when_present() {
        // None of these shapes has been observed in CI — every server there
        // announces its web server instead (see the module docs). They are
        // kept because a reverse proxy can be configured to forward a product
        // token, and reading one costs nothing; they are NOT evidence that
        // any particular server sends one.
        assert_eq!(detect(from_server("Radicale/3.1.8")), Server::Radicale);
        assert_eq!(detect(from_server("sabre/dav 4.4.0")), Server::Baikal);
        assert_eq!(detect(from_server("SOGo/5.9.0")), Server::Sogo);
        assert_eq!(detect(from_server("Cyrus-HTTP/3.8")), Server::Cyrus);
    }

    #[test]
    fn the_two_biggest_servers_are_not_in_their_server_header_at_all() {
        // Live-observed in CI, 2026-09-03. Both of these were previously
        // undetectable, and one of them was "covered" by a test asserting a
        // header string no Nextcloud has ever sent. The bytes below are
        // copied from the wire.
        let nextcloud = Fingerprint {
            server: Some("Apache/2.4.68 (Debian)"),
            dav: Some(
                "1, 3, extended-mkcol, access-control, \
                 calendarserver-principal-property-search, nc-paginate, \
                 nextcloud-checksum-update, nc-calendar-search, \
                 nc-enable-birthday-calendar, 2",
            ),
            ..Fingerprint::default()
        };
        assert_eq!(detect(nextcloud), Server::Nextcloud);

        let baikal = Fingerprint {
            server: Some("nginx/1.29.3"),
            sabre_version: Some("4.7.0"),
            dav: Some("1, 3, extended-mkcol, access-control, calendar-access"),
            ..Fingerprint::default()
        };
        assert_eq!(detect(baikal), Server::Baikal);
    }

    #[test]
    fn a_named_product_beats_the_library_underneath_it() {
        // Nextcloud is sabre/dav with additions, so a response carrying both
        // signals must not come back as Baïkal.
        let both = Fingerprint {
            server: Some("Apache/2.4.68 (Debian)"),
            dav: Some("1, 3, nc-paginate"),
            sabre_version: Some("4.7.0"),
            ..Fingerprint::default()
        };
        assert_eq!(detect(both), Server::Nextcloud);
    }

    #[test]
    fn hosted_providers_detect_by_host_when_the_header_is_scrubbed() {
        assert_eq!(detect(from_host("caldav.fastmail.com")), Server::Fastmail);
        assert_eq!(
            detect(from_host("apidata.googleusercontent.com")),
            Server::Google
        );
        assert_eq!(detect(from_host("p42-caldav.icloud.com")), Server::ICloud);
        assert_eq!(detect(from_host("outlook.office365.com")), Server::Exchange);
    }

    #[test]
    fn a_lookalike_host_does_not_pass() {
        // Suffix matching has to be on the registrable domain boundary, or
        // fastmail.com.attacker.example detects as Fastmail.
        assert_eq!(
            detect(from_host("fastmail.com.evil.example")),
            Server::Unknown
        );
        assert_eq!(detect(from_host("evilfastmail.com")), Server::Unknown);
        assert_eq!(detect(from_host("notgoogle.com.example")), Server::Unknown);
    }

    #[test]
    fn an_unknown_server_gets_the_defended_everywhere_defaults() {
        // Misdetection must be cheap: Unknown means "the unconditional
        // defences, nothing special" — which is also what every well-behaved
        // server gets.
        assert_eq!(detect(Fingerprint::default()), Server::Unknown);
        assert_eq!(quirks_for(Server::Unknown), Quirks::default());
        assert_eq!(quirks_for(Server::Radicale), Quirks::default());
        // Nextcloud's finding needed no runtime branch either — the defence
        // was already unconditional. An entry with no field set is the
        // ledger working as intended.
        assert_eq!(quirks_for(Server::Nextcloud), Quirks::default());
        assert_eq!(quirks_for(Server::Baikal), Quirks::default());
    }

    #[test]
    fn the_recorded_facts_match_their_defences() {
        // The ledger's seed entries — each one exists as a comment beside its
        // defence in dav.rs; this pins that the table agrees with the code's
        // own account of itself.
        assert!(quirks_for(Server::Sogo).error_inside_propstat);
        assert!(quirks_for(Server::Zimbra).non_ascii_etags);
        assert!(quirks_for(Server::Cyrus).strict_if_match);
        assert!(quirks_for(Server::ICloud).cross_origin_discovery);
        assert!(quirks_for(Server::Exchange).html_where_xml_belongs);
        assert!(quirks_for(Server::Google).oauth_only);
    }
}

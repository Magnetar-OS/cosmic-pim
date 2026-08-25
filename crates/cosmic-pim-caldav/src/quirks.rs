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
//! (`tests/live_server.rs`, currently Radicale), or a field report with the
//! wire traffic to back it. Not from documentation — the entire reason the
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
//! From the `Server` response header the client captured during discovery,
//! plus the URL's host as a fallback for the hosted providers that hide their
//! software behind proxies. Detection is best-effort by construction: an
//! unrecognised server gets [`Server::Unknown`] and the same defended-
//! everywhere behaviour as everyone else, which is exactly why misdetection
//! is cheap.

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
    Unknown,
}

/// Detects the server from what the wire volunteered.
///
/// `server_header` is the `Server` response header; `host` is the request
/// URL's host, for the hosted providers whose proxies scrub the header.
#[must_use]
pub fn detect(server_header: Option<&str>, host: Option<&str>) -> Server {
    if let Some(header) = server_header {
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
            // CI, first live run (2026-08-25): MKCALENDAR on an existing
            // collection answers 409 + DAV:resource-must-be-null rather than
            // 405, and a PUT into a missing collection is a 409 rather than
            // an implicit create. Both defended everywhere: `mkcalendar`
            // treats that 409 as already-exists, and 409-on-PUT was already
            // classified Reconcile.
        }
        // The field has not put anything on record for these yet. That is the
        // healthy state: the engine's unconditional defences have been enough.
        Server::Nextcloud | Server::Baikal | Server::Fastmail => {}
        Server::Unknown => {}
    }
    quirks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_reads_the_product_through_the_web_server() {
        // Nextcloud answers through Apache; the web-server token must not
        // shadow the product token.
        assert_eq!(
            detect(Some("Apache/2.4.57 (Debian) Nextcloud"), None),
            Server::Nextcloud
        );
        assert_eq!(detect(Some("Radicale/3.1.8"), None), Server::Radicale);
        assert_eq!(detect(Some("sabre/dav 4.4.0"), None), Server::Baikal);
        assert_eq!(detect(Some("SOGo/5.9.0"), None), Server::Sogo);
        assert_eq!(detect(Some("Cyrus-HTTP/3.8"), None), Server::Cyrus);
    }

    #[test]
    fn hosted_providers_detect_by_host_when_the_header_is_scrubbed() {
        assert_eq!(detect(None, Some("caldav.fastmail.com")), Server::Fastmail);
        assert_eq!(
            detect(None, Some("apidata.googleusercontent.com")),
            Server::Google
        );
        assert_eq!(detect(None, Some("p42-caldav.icloud.com")), Server::ICloud);
        assert_eq!(detect(None, Some("outlook.office365.com")), Server::Exchange);
    }

    #[test]
    fn a_lookalike_host_does_not_pass() {
        // Suffix matching has to be on the registrable domain boundary, or
        // fastmail.com.attacker.example detects as Fastmail.
        assert_eq!(detect(None, Some("fastmail.com.evil.example")), Server::Unknown);
        assert_eq!(detect(None, Some("evilfastmail.com")), Server::Unknown);
        assert_eq!(detect(None, Some("notgoogle.com.example")), Server::Unknown);
    }

    #[test]
    fn an_unknown_server_gets_the_defended_everywhere_defaults() {
        // Misdetection must be cheap: Unknown means "the unconditional
        // defences, nothing special" — which is also what every well-behaved
        // server gets.
        assert_eq!(detect(None, None), Server::Unknown);
        assert_eq!(quirks_for(Server::Unknown), Quirks::default());
        assert_eq!(quirks_for(Server::Radicale), Quirks::default());
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

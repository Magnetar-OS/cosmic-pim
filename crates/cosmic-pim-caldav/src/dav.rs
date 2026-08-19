// SPDX-License-Identifier: MPL-2.0
//
// Ported from `src-tauri/src/caldav.rs` in the Meltemi project
// (https://github.com/entro314-labs/meltemi). See NOTICE and LICENSING.md.
//
// The URL resolution, wire-format helpers, multistatus parsers, and HTTP client
// below are carried over essentially verbatim: only the error type changed
// (Meltemi's `CmdResult`/`CommandError` became this crate's `Result`/`Error`).
// Every guard in here was written in response to a real server misbehaving in
// production, and the comments explaining which server and which failure are
// the most valuable thing in the file. Do not "clean them up".

//! The CalDAV protocol layer: URLs, XML, and HTTP. No storage, no state.


use std::time::Duration;

use quick_xml::Reader;
use quick_xml::escape::unescape;
use quick_xml::events::Event;

use crate::error::{Error, Result};

/// Per-request wall-clock ceiling. CalDAV servers behind slow SSO chains can
/// take seconds on the first PROPFIND.
const DAV_TIMEOUT: Duration = Duration::from_secs(30);

/// Manual redirect ceiling. Hosted Zimbra and SSO-fronted Exchange chain six or
/// seven hops through the IdP before landing on the DAV root, so 5 is too tight;
/// this matches reqwest's default of 10.
const MAX_REDIRECT_HOPS: usize = 10;

/// calendar-multiget batches: 50 hrefs per REPORT, so a 5000-event calendar
/// does not become one giant request that servers 413 or time out on.
const MULTIGET_BATCH_SIZE: usize = 50;

/// Body read ceiling. ureq defaults to 10 MB, which a 50-event multiget of
/// attachment-laden invites can exceed; 32 MB is comfortably above anything a
/// batch produces while still bounding a hostile response.
const BODY_LIMIT: u64 = 32 * 1024 * 1024;

/* ------------------------------------------------------------------ */
/* URL resolution (minimal RFC 3986 §5 join — the `url` crate is not  */
/* a declared dependency)                                             */

/// Split an absolute http(s) URL into `(origin, path, query)`. `origin`
/// includes the scheme and authority (`https://host:port`), `path` always
/// starts with `/` (an authority-only URL yields `/`), `query` excludes the
/// `?`. Fragments are dropped (they never go on the wire). Returns `None`
/// for anything that isn't <scheme://authority-shaped>.
fn split_absolute_url(url: &str) -> Option<(&str, &str, Option<&str>)> {
    let scheme_end = url.find("://")?;
    let after_scheme = scheme_end + 3;
    let rest = &url[after_scheme..];
    if rest.is_empty() {
        return None;
    }
    let path_start = rest
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| after_scheme + i);
    let origin = &url[..path_start];
    let tail = &url[path_start..];
    let tail = tail.split('#').next().unwrap_or(tail);
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    let path = if path.is_empty() { "/" } else { path };
    Some((origin, path, query))
}

/// RFC 3986 §5.2.4 `remove_dot_segments`, for the path component only.
fn remove_dot_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let trailing_slash = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut result = String::with_capacity(path.len());
    for seg in &out {
        result.push('/');
        result.push_str(seg);
    }
    if result.is_empty() || (trailing_slash && !result.ends_with('/')) {
        result.push('/');
    }
    result
}

/// Resolve a possibly-relative `href` against `base`, with two `CalDAV`-
/// specific deviations from vanilla RFC 3986 the donor learned the hard way:
///
/// 1. **Trailing-slash-before-join.** §5.2 treats the base path's last
///    segment as a "file" and replaces it for path-relative references. But
///    `CalDAV` collections are directories regardless of any server's
///    trailing-slash discipline — Davical, Bedework, and old Zimbra list a
///    calendar as `.../work` (no slash) and then return `event.ics` relative
///    to it. A vanilla join drops `work`; appending `/` first lands the href
///    underneath the collection, where it belongs.
/// 2. **Query re-attach.** §5.3 drops the base's query when the reference
///    carries none. Shared-hosting front-ends pass routing/session tokens
///    through `?token=...` on the calendar URL; silently dropping the token
///    sends event PROPFINDs/PUTs to a tenant-less route. When the href has
///    no query of its own, the base's is re-attached.
pub fn resolve_url_against(base: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }
    let Some((origin, base_path, base_query)) = split_absolute_url(base) else {
        // Malformed base: last-resort concatenation, matching the donor's
        // fallback so a broken server config degrades the same way.
        return format!("{base}{href}");
    };
    if let Some(rest) = href.strip_prefix("//") {
        // Protocol-relative reference: adopt the base's scheme.
        let scheme = &base[..base.find("://").unwrap_or(0)];
        return format!("{scheme}://{rest}");
    }
    let href = href.split('#').next().unwrap_or(href);
    let (href_path, href_query) = match href.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (href, None),
    };
    let path = if href_path.is_empty() {
        base_path.to_string()
    } else if href_path.starts_with('/') {
        remove_dot_segments(href_path)
    } else {
        // Path-relative: deviation (1) — join under the collection.
        let mut dir = base_path.to_string();
        if !dir.ends_with('/') {
            dir.push('/');
        }
        dir.push_str(href_path);
        remove_dot_segments(&dir)
    };
    // Deviation (2): the href's own query wins; otherwise keep the base's.
    let query = href_query.or(base_query);
    match query {
        Some(q) if !q.is_empty() => format!("{origin}{path}?{q}"),
        _ => format!("{origin}{path}"),
    }
}

/// `(scheme, lowercased host, effective port)` for same-origin comparison.
fn origin_of(url: &str) -> Option<(String, String, u16)> {
    let scheme_end = url.find("://")?;
    let scheme = &url[..scheme_end];
    let (origin, _, _) = split_absolute_url(url)?;
    let authority = &origin[scheme_end + 3..];
    // Strip userinfo if present (rare, but legal).
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
            (h, p.parse().ok()?)
        }
        _ => (
            host_port,
            match scheme {
                "https" => 443,
                "http" => 80,
                _ => return None,
            },
        ),
    };
    Some((scheme.to_string(), host.to_ascii_lowercase(), port))
}

/// Re-relativize an absolute href to path-only form when it shares an origin
/// with the request URL. Older `SOGo` (and a handful of niche servers) 400
/// multiget bodies whose hrefs don't share scheme+host with the REPORT URL;
/// after an http→https or hostname-canonicalizing redirect our stored
/// absolute URIs drift from the live request URL even though they name the
/// same resource. Strict servers get the path form they expect; cross-origin
/// hrefs pass through untouched.
fn relativize_for_multiget(request_url: &str, href: &str) -> String {
    if !(href.starts_with("http://") || href.starts_with("https://")) {
        return href.to_string();
    }
    let (Some(req_origin), Some(href_origin)) = (origin_of(request_url), origin_of(href)) else {
        return href.to_string();
    };
    if req_origin.1 != href_origin.1 || req_origin.2 != href_origin.2 {
        return href.to_string();
    }
    match split_absolute_url(href) {
        Some((_, path, Some(q))) => format!("{path}?{q}"),
        Some((_, path, None)) => path.to_string(),
        None => href.to_string(),
    }
}

/* ------------------------------------------------------------------ */
/* Small wire-format helpers                                          */

/// Escape `&`, `<`, `>` for XML element content. Per RFC 3986 a URI can't
/// contain literal `<`/`>`, but `&` is legal in query strings and Exchange
/// OWA's `CalDAV` bridge really does emit hrefs containing it — splatting one
/// unescaped into a multiget body 400s the entire batch.
fn xml_escape_text(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.bytes().any(|b| matches!(b, b'&' | b'<' | b'>')) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Format a stored `ETag` for `If-Match`. Returns `None` when the value is not
/// in a shape RFC 7232 allows there — the caller then skips the header
/// entirely (last-write-wins for that one request, self-correcting on the
/// next sync round):
///
/// - empty/whitespace → `None`;
/// - weak (`W/...`) → `None`: RFC 7232 §3.1 forbids weak validators in
///   If-Match, and strict servers (Apache `mod_dav` builds, Cyrus) 412 every
///   PUT/DELETE carrying one — the retry sees the same stored value and 412s
///   again, wedging the client until a full re-sync;
/// - already-quoted strong `ETag` → verbatim;
/// - bare token (legacy rows from before verbatim storage) → wrapped in
///   quotes so it conforms before going on the wire.
fn prepare_if_match_etag(stored: &str) -> Option<String> {
    let s = stored.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with("W/") {
        return None;
    }
    if s.starts_with('"') {
        return Some(s.to_string());
    }
    Some(format!("\"{s}\""))
}

/// Normalize a `calendar-color` value to `#RRGGBB`. Apple Calendar emits an
/// `#RRGGBBAA` ARGB form (`#0000FFFF` for opaque blue); folding the alpha at
/// parse time saves every render site from handling both shapes. Values
/// outside the well-known 7- and 9-char hex forms pass through verbatim —
/// vendors have shipped names (`blue`) and odd-length hex, and rewriting
/// those would be worse than leaving them alone.
fn normalize_calendar_color(raw: &str) -> String {
    let s = raw.trim();
    if s.len() == 9 && s.starts_with('#') && s.bytes().skip(1).all(|b| b.is_ascii_hexdigit()) {
        return s[..7].to_string();
    }
    s.to_string()
}

/// Whether a listed resource looks like an iCalendar event resource.
///
/// Content-type matching is case-insensitive (RFC 7231 §3.1.1.1) — servers
/// emit `TEXT/CALENDAR` and a case-sensitive match silently skipped every
/// event on them. `application/calendar+xml` (RFC 6321 xCal) counts too.
/// The extension check strips query/fragment first: `/cal/e.ics?rev=42`
/// ends with neither `.ics` nor `/` otherwise. The final fallback (empty
/// content-type + non-slash path tail) admits entries from servers that
/// omit getcontenttype entirely; testing the query-stripped tail keeps
/// `/cal/folder/?rev=1` from slipping through as an event.
fn is_syncable_resource(href: &str, content_type: &str, flavor: Flavor) -> bool {
    let ct_lower = content_type.to_ascii_lowercase();
    let (types, extension): (&[&str], &str) = match flavor {
        Flavor::CalDav => (&["text/calendar", "application/calendar+xml"], ".ics"),
        Flavor::CardDav => (&["text/vcard", "text/x-vcard", "text/directory"], ".vcf"),
    };

    if types.iter().any(|t| ct_lower.contains(t)) {
        return true;
    }
    let path_tail = href.split(['?', '#']).next().unwrap_or(href);
    if path_tail.to_ascii_lowercase().ends_with(extension) {
        return true;
    }
    // No content type at all and not obviously a collection: servers that omit
    // getcontenttype are common, and refusing everything they list would make
    // them unsyncable.
    content_type.is_empty() && !path_tail.ends_with('/')
}

/// Local name of a possibly-namespaced XML tag (`D:href` → `href`). Any
/// prefix is accepted rather than pinning the four well-known namespace
/// URIs: element scoping (`response`/`prop`/`resourcetype` parents) provides
/// the disambiguation, and bridges remap prefixes freely (Davical's `DAV1`,
/// Apple's `CALDAV` aliases).
fn local_name(raw: &[u8]) -> String {
    let full = String::from_utf8_lossy(raw);
    match full.rfind(':') {
        Some(idx) => full[idx + 1..].to_string(),
        None => full.to_string(),
    }
}

/// Status-line ok-ness for `<status>` elements. Lenient on absence — some
/// servers omit the line when it would be 200 OK (RFC 4918 violation, but
/// real). The code is parsed strictly as exactly three ASCII digits so a
/// crafted `HTTP/1.1 2xx Custom` can't slip past the gate.
fn status_line_is_ok(status: &str) -> bool {
    if status.is_empty() {
        return true;
    }
    let Some(code_token) = status.split_whitespace().nth(1) else {
        return false;
    };
    if code_token.len() != 3 || !code_token.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    code_token
        .parse::<u16>()
        .ok()
        .is_some_and(|n| (200..=299).contains(&n))
}

/* ------------------------------------------------------------------ */
/* Multistatus XML parsing (quick-xml streaming)                      */
/*                                                                     */
/* All parsers share the same discipline: an element stack with       */
/* parent scoping (href only as a direct child of <response>, prop    */
/* values only under <prop> — a <href> nested in a <privilege>        */
/* descriptor must not clobber the resource's own), Text AND CData    */
/* accumulation (servers wrap large values in CDATA), and a per-      */
/* propstat 2xx commit gate so a mixed 200/404 propstat pair doesn't  */
/* leak the 404 block's empty values into the committed state.        */

/// RFC 6638 capability answer (see [`CaldavClient::discover_scheduling`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulingInfo {
    pub supports_scheduling: bool,
    pub default_calendar_url: Option<String>,
}

/// A discovered calendar collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredCalendar {
    pub href: String,
    pub display_name: Option<String>,
    pub color: Option<String>,
    pub ctag: Option<String>,
    /// `None` = the server emitted no `current-user-privilege-set` (older
    /// servers commonly omit it) — treated as editable to preserve behavior
    /// there. `Some(false)` is an explicit read-only grant (iCloud/Fastmail/
    /// `SOGo` shared calendars).
    pub can_edit: Option<bool>,
}

/// One event entry from a Depth:1 PROPFIND listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalDavEventEntry {
    pub uri: String,
    /// Verbatim, quotes/`W/` included (RFC 7232: they're part of the value).
    pub etag: String,
}

/// Result of an event listing: parsed entries plus hrefs the SERVER reported
/// as failing (non-2xx response-level status, or propstat blocks present but
/// none 2xx). Failed hrefs must keep their local copies this round — the
/// server reported an error, not an absence. Hrefs we skipped for our own
/// reasons (collections, non-iCal content types) are NOT failures: they were
/// never event resources, and holding them would pin non-events forever.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PropfindEventsResult {
    pub entries: Vec<CalDavEventEntry>,
    pub failed_uris: Vec<String>,
}

/// Collect `<href>` values that are DIRECT children of the named property.
/// RFC 4791 §6.2.1 places them there; any-ancestor matching picked up
/// Davical's nested `<owner><href>` descriptor first and mis-routed
/// discovery to the admin's principal.
fn collect_hrefs(xml: &str, property_name: &str, limit: usize) -> Vec<String> {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut hrefs: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                stack.push(local_name(e.name().as_ref()));
                buf.clear();
            }
            Ok(Event::Text(ref e)) => {
                if let Ok(raw) = std::str::from_utf8(e.as_ref())
                    && let Ok(text) = unescape(raw)
                {
                    buf.push_str(&text);
                }
            }
            Ok(Event::CData(ref e)) => {
                if let Ok(text) = e.decode() {
                    buf.push_str(&text);
                }
            }
            Ok(Event::End(_)) => {
                let parent_is_property = stack
                    .iter()
                    .rev()
                    .nth(1)
                    .is_some_and(|n| n == property_name);
                let is_href_close = stack.last().is_some_and(|n| n == "href");
                if parent_is_property && is_href_close {
                    let val = buf.trim().to_string();
                    if !val.is_empty() {
                        hrefs.push(val);
                        if hrefs.len() >= limit {
                            return hrefs;
                        }
                    }
                }
                stack.pop();
                buf.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    hrefs
}

fn extract_hrefs_property(xml: &str, property_name: &str) -> Vec<String> {
    collect_hrefs(xml, property_name, usize::MAX)
}

fn extract_first_href_property(xml: &str, property_name: &str) -> Option<String> {
    collect_hrefs(xml, property_name, 1).into_iter().next()
}

/// Parse a Depth:1 PROPFIND response into calendar collections (responses
/// whose `<resourcetype>` carries a `<calendar>` marker — self-closed or
/// open/close). `can_edit` is anchored on `<privilege>` elements, NOT the
/// `<current-user-privilege-set>` wrapper: some servers emit a self-closed
/// empty privilege-set as an "unknown ACL" sentinel, and reading that as
/// "explicit empty → read-only" silently locked editable calendars.
/// `write` / `write-content` / `all` inside a privilege imply write access
/// (RFC 3744 §5.3); no privilege element seen at all → `None` = editable.
fn parse_propfind_calendars(xml: &str, flavor: Flavor) -> Vec<DiscoveredCalendar> {
    let mut reader = Reader::from_str(xml);
    let mut calendars = Vec::new();

    let mut stack: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut resp = CalendarResponse {
        marker: flavor.collection_marker(),
        ..CalendarResponse::default()
    };

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = local_name(e.name().as_ref());
                if name == "response" {
                    resp.start_response();
                }
                if name == "propstat" {
                    resp.reset_propstat();
                }
                resp.note_marker(&name, &stack);
                stack.push(name);
                buf.clear();
            }
            // Self-closing markers (<C:calendar/>, <D:privilege/>…) arrive
            // here, not in Start.
            Ok(Event::Empty(ref e)) => {
                resp.note_marker(&local_name(e.name().as_ref()), &stack);
            }
            Ok(Event::Text(ref e)) => {
                if let Ok(raw) = std::str::from_utf8(e.as_ref())
                    && let Ok(text) = unescape(raw)
                {
                    buf.push_str(&text);
                }
            }
            Ok(Event::CData(ref e)) => match e.decode() {
                Ok(text) => buf.push_str(&text),
                Err(err) => tracing::warn!("caldav: PROPFIND CDATA decode failed: {err}"),
            },
            Ok(Event::End(ref e)) => {
                let name = local_name(e.name().as_ref());
                let parent = stack.iter().rev().nth(1).map(String::as_str);
                resp.record_text(parent, &name, &buf);
                if name == "propstat" {
                    resp.close_propstat();
                }
                if name == "response"
                    && let Some(cal) = resp.close_response()
                {
                    calendars.push(cal);
                }
                stack.pop();
                buf.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    calendars
}

/// Per-`<response>` accumulator for the calendars PROPFIND parse. Propstat-
/// scoped `pending_*` values only commit into the response-level fields when
/// their propstat's status line is OK (the shared 2xx commit gate).
// Each bool is an independent marker-seen flag; a state machine would obscure them.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct CalendarResponse {
    /// The `<resourcetype>` element that marks a syncable collection —
    /// `calendar` or `addressbook`, depending on the client's flavour.
    marker: &'static str,
    href: String,
    status: String,
    is_calendar: bool,
    displayname: String,
    ctag: String,
    color: String,
    can_edit: Option<bool>,

    propstat_status: String,
    pending_is_calendar: bool,
    pending_displayname: Option<String>,
    pending_ctag: Option<String>,
    pending_color: Option<String>,
    pending_privilege_seen: bool,
    pending_write_seen: bool,
}

impl CalendarResponse {
    /// `<response>` opened: clear the response-level fields.
    fn start_response(&mut self) {
        self.href.clear();
        self.status.clear();
        self.is_calendar = false;
        self.displayname.clear();
        self.ctag.clear();
        self.color.clear();
        self.can_edit = None;
    }

    /// `<propstat>` opened (or committed): clear the propstat-scoped fields.
    fn reset_propstat(&mut self) {
        self.propstat_status.clear();
        self.pending_is_calendar = false;
        self.pending_displayname = None;
        self.pending_ctag = None;
        self.pending_color = None;
        self.pending_privilege_seen = false;
        self.pending_write_seen = false;
    }

    /// Marker elements — `<calendar>` under `<resourcetype>`, `<privilege>`,
    /// and the write-implying privileges under it. Called with the element
    /// stack BEFORE the current element is pushed (Start and Empty agree).
    fn note_marker(&mut self, name: &str, stack: &[String]) {
        if name == self.marker && stack.iter().any(|s| s == "resourcetype") {
            self.pending_is_calendar = true;
        }
        if name == "privilege" {
            self.pending_privilege_seen = true;
        }
        if (name == "write" || name == "write-content" || name == "all")
            && stack.iter().any(|s| s == "privilege")
        {
            self.pending_write_seen = true;
        }
    }

    /// A text-bearing element closed: record its value under its parent.
    fn record_text(&mut self, parent: Option<&str>, name: &str, buf: &str) {
        match (parent, name) {
            (Some("response"), "href") => self.href = buf.trim().to_string(),
            (Some("response"), "status") => self.status = buf.trim().to_string(),
            (Some("propstat"), "status") => self.propstat_status = buf.trim().to_string(),
            (Some("prop"), "displayname") => {
                self.pending_displayname = Some(buf.trim().to_string());
            }
            (Some("prop"), "getctag") => self.pending_ctag = Some(buf.trim().to_string()),
            (Some("prop"), "calendar-color") => {
                self.pending_color = Some(normalize_calendar_color(buf.trim()));
            }
            _ => {}
        }
    }

    /// `</propstat>`: commit the pending values iff the status line was OK,
    /// then clear the propstat scope either way.
    fn close_propstat(&mut self) {
        if status_line_is_ok(&self.propstat_status) {
            if self.pending_is_calendar {
                self.is_calendar = true;
            }
            if let Some(v) = self.pending_displayname.take() {
                self.displayname = v;
            }
            if let Some(v) = self.pending_ctag.take() {
                self.ctag = v;
            }
            if let Some(v) = self.pending_color.take() {
                self.color = v;
            }
            if self.pending_privilege_seen {
                self.can_edit = Some(self.pending_write_seen);
            }
        }
        self.reset_propstat();
    }

    /// `</response>`: a calendar collection with an href and a 2xx (or
    /// omitted) response status becomes a `DiscoveredCalendar`.
    fn close_response(&self) -> Option<DiscoveredCalendar> {
        (self.is_calendar && !self.href.is_empty() && status_line_is_ok(&self.status)).then(|| {
            DiscoveredCalendar {
                href: self.href.clone(),
                display_name: (!self.displayname.is_empty()).then(|| self.displayname.clone()),
                color: (!self.color.is_empty()).then(|| self.color.clone()),
                ctag: (!self.ctag.is_empty()).then(|| self.ctag.clone()),
                can_edit: self.can_edit,
            }
        })
    }
}

/// Parse a Depth:1 events PROPFIND into (uri, etag) entries + failed hrefs.
/// `<resourcetype><collection/>` responses are filtered — Davical/Bedework/
/// old Zimbra emit sub-collections without a trailing slash and with a
/// getetag, and the extension fallback would otherwise admit them; the
/// follow-up multiget then 403s on the collection and can fail the batch.
fn parse_propfind_events(xml: &str, flavor: Flavor) -> PropfindEventsResult {
    let mut reader = Reader::from_str(xml);
    let mut out = PropfindEventsResult::default();

    let mut stack: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut resp = EventResponse {
        flavor,
        ..EventResponse::default()
    };

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = local_name(e.name().as_ref());
                if name == "response" {
                    resp.start_response();
                }
                if name == "propstat" {
                    resp.start_propstat();
                }
                resp.note_collection(&name, &stack);
                stack.push(name);
                buf.clear();
            }
            Ok(Event::Empty(ref e)) => {
                // Self-closing <D:collection/> arrives here, not in Start.
                resp.note_collection(&local_name(e.name().as_ref()), &stack);
            }
            Ok(Event::Text(ref e)) => {
                if let Ok(raw) = std::str::from_utf8(e.as_ref())
                    && let Ok(text) = unescape(raw)
                {
                    buf.push_str(&text);
                }
            }
            Ok(Event::CData(ref e)) => match e.decode() {
                Ok(text) => buf.push_str(&text),
                Err(err) => tracing::warn!("caldav: PROPFIND CDATA decode failed: {err}"),
            },
            Ok(Event::End(ref e)) => {
                let name = local_name(e.name().as_ref());
                let parent = stack.iter().rev().nth(1).map(String::as_str);
                resp.record_text(parent, &name, &buf);
                if name == "propstat" {
                    resp.close_propstat();
                }
                if name == "response" {
                    resp.close_response(&mut out);
                }
                stack.pop();
                buf.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

/// Per-`<response>` accumulator for the events PROPFIND parse — same commit
/// discipline as `CalendarResponse`, plus the propstat-presence bookkeeping
/// `close_response` needs to classify server-reported failures.
// Each bool is an independent marker-seen flag; a state machine would obscure them.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct EventResponse {
    flavor: Flavor,
    href: String,
    status: String,
    etag: String,
    content_type: String,
    is_collection: bool,
    any_ok_propstat: bool,
    any_propstat_seen: bool,

    propstat_status: String,
    pending_etag: Option<String>,
    pending_content_type: Option<String>,
    pending_is_collection: bool,
}

impl EventResponse {
    /// `<response>` opened: clear the response-level fields.
    fn start_response(&mut self) {
        self.href.clear();
        self.status.clear();
        self.etag.clear();
        self.content_type.clear();
        self.is_collection = false;
        self.any_ok_propstat = false;
        self.any_propstat_seen = false;
    }

    /// `<propstat>` opened: clear the propstat scope and count the block.
    fn start_propstat(&mut self) {
        self.reset_propstat();
        self.any_propstat_seen = true;
    }

    /// Clear the propstat-scoped fields.
    fn reset_propstat(&mut self) {
        self.propstat_status.clear();
        self.pending_etag = None;
        self.pending_content_type = None;
        self.pending_is_collection = false;
    }

    /// `<collection>` marker under `<resourcetype>` (Start or self-closed;
    /// the element stack does not yet include the current element).
    fn note_collection(&mut self, name: &str, stack: &[String]) {
        if name == "collection" && stack.iter().rev().any(|n| n == "resourcetype") {
            self.pending_is_collection = true;
        }
    }

    /// A text-bearing element closed: record its value under its parent.
    fn record_text(&mut self, parent: Option<&str>, name: &str, buf: &str) {
        match (parent, name) {
            (Some("response"), "href") => self.href = buf.trim().to_string(),
            (Some("response"), "status") => self.status = buf.trim().to_string(),
            (Some("propstat"), "status") => self.propstat_status = buf.trim().to_string(),
            (Some("prop"), "getetag") => self.pending_etag = Some(buf.trim().to_string()),
            (Some("prop"), "getcontenttype") => {
                self.pending_content_type = Some(buf.trim().to_string());
            }
            _ => {}
        }
    }

    /// `</propstat>`: commit the pending values iff the status line was OK,
    /// then clear the propstat scope either way.
    fn close_propstat(&mut self) {
        if status_line_is_ok(&self.propstat_status) {
            self.any_ok_propstat = true;
            if let Some(v) = self.pending_etag.take() {
                self.etag = v;
            }
            if let Some(v) = self.pending_content_type.take() {
                self.content_type = v;
            }
            if self.pending_is_collection {
                self.is_collection = true;
            }
        }
        self.reset_propstat();
    }

    /// `</response>`: an OK non-collection iCalendar resource with an etag
    /// lands in `entries`; otherwise a response-level or all-propstat failure
    /// lands in `failed_uris` (skips for our own reasons are neither).
    fn close_response(&self, out: &mut PropfindEventsResult) {
        let response_ok = status_line_is_ok(&self.status);
        let pushed = response_ok
            && !self.href.is_empty()
            && !self.etag.is_empty()
            && !self.is_collection
            && is_syncable_resource(&self.href, &self.content_type, self.flavor);
        if pushed {
            out.entries.push(CalDavEventEntry {
                uri: self.href.clone(),
                etag: self.etag.clone(),
            });
        } else if !self.href.is_empty() {
            let response_level_failed = !response_ok;
            let propstat_level_failed = self.any_propstat_seen && !self.any_ok_propstat;
            if response_level_failed || propstat_level_failed {
                out.failed_uris.push(self.href.clone());
            }
        }
    }
}

/// Parse the ctag out of a Depth:0 PROPFIND (direct child of `<prop>` only).
fn parse_ctag(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<String> = Vec::new();
    let mut buf = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                stack.push(local_name(e.name().as_ref()));
                buf.clear();
            }
            Ok(Event::Text(ref e)) => {
                if let Ok(raw) = std::str::from_utf8(e.as_ref())
                    && let Ok(text) = unescape(raw)
                {
                    buf.push_str(&text);
                }
            }
            Ok(Event::CData(ref e)) => {
                if let Ok(text) = e.decode() {
                    buf.push_str(&text);
                }
            }
            Ok(Event::End(ref e)) => {
                let name = local_name(e.name().as_ref());
                let parent = stack.iter().rev().nth(1).map(String::as_str);
                if parent == Some("prop") && name == "getctag" {
                    let val = buf.trim().to_string();
                    if !val.is_empty() {
                        return Some(val);
                    }
                }
                stack.pop();
                buf.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    None
}

/// Parse a calendar-multiget REPORT into `(href, ical)` pairs. The response-
/// level status gate matters here: `SOGo`'s failure mode is a 500 at the
/// response level WHILE echoing stale calendar-data inside a 200 propstat —
/// the gate is what keeps that stale payload from landing locally.
fn parse_multiget_report(xml: &str, flavor: Flavor) -> Vec<(String, String)> {
    let mut reader = Reader::from_str(xml);
    let mut results = Vec::new();

    let mut stack: Vec<String> = Vec::new();
    let mut buf = String::new();

    let mut response_href = String::new();
    let mut response_status = String::new();
    let mut response_ical = String::new();

    let mut propstat_status = String::new();
    let mut pending_ical: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = local_name(e.name().as_ref());
                if name == "response" {
                    response_href.clear();
                    response_status.clear();
                    response_ical.clear();
                }
                if name == "propstat" {
                    propstat_status.clear();
                    pending_ical = None;
                }
                stack.push(name);
                buf.clear();
            }
            Ok(Event::Text(ref e)) => {
                if let Ok(raw) = std::str::from_utf8(e.as_ref())
                    && let Ok(text) = unescape(raw)
                {
                    buf.push_str(&text);
                }
            }
            Ok(Event::CData(ref e)) => match e.decode() {
                Ok(text) => buf.push_str(&text),
                Err(err) => tracing::warn!("caldav: multiget CDATA decode failed: {err}"),
            },
            Ok(Event::End(ref e)) => {
                let name = local_name(e.name().as_ref());
                let parent = stack.iter().rev().nth(1).map(String::as_str);
                match (parent, name.as_str()) {
                    (Some("response"), "href") => response_href = buf.trim().to_string(),
                    (Some("response"), "status") => response_status = buf.trim().to_string(),
                    (Some("propstat"), "status") => propstat_status = buf.trim().to_string(),
                    // Trim only outer whitespace: CRLF folding inside the
                    // payload is load-bearing iCal syntax.
                    (Some("prop"), name) if name == flavor.data_element() => {
                        pending_ical = Some(buf.trim().to_string());
                    }
                    _ => {}
                }
                if name == "propstat" {
                    if status_line_is_ok(&propstat_status)
                        && let Some(v) = pending_ical.take()
                    {
                        response_ical = v;
                    }
                    propstat_status.clear();
                    pending_ical = None;
                }
                if name == "response" {
                    if status_line_is_ok(&response_status)
                        && !response_href.is_empty()
                        && !response_ical.is_empty()
                    {
                        results.push((response_href.clone(), response_ical.clone()));
                    } else if !status_line_is_ok(&response_status) && !response_href.is_empty() {
                        tracing::debug!(
                            "caldav: multiget response for {response_href} returned \
                             non-2xx status {response_status}; dropping"
                        );
                    }
                }
                stack.pop();
                buf.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    results
}

/// Count `<response>` children at any depth — disambiguates "207 with zero
/// responses" (server bug / first-login race) from "responses present but
/// none are calendars" when a listing comes back empty.
fn count_response_children(xml: &str) -> usize {
    let mut reader = Reader::from_str(xml);
    let mut count = 0;
    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) if local_name(e.name().as_ref()) == "response" => count += 1,
            Ok(Event::Eof) | Err(_) => return count,
            _ => {}
        }
    }
}

/* ------------------------------------------------------------------ */
/* HTTP client (ureq 3, manual redirects)                             */

const PROPFIND_PRINCIPAL: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:current-user-principal/>
  </D:prop>
</D:propfind>"#;

const PROPFIND_CALENDAR_HOME: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <C:calendar-home-set/>
  </D:prop>
</D:propfind>"#;

const PROPFIND_CALENDARS: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"
            xmlns:CS="http://calendarserver.org/ns/"
            xmlns:IC="http://apple.com/ns/ical/">
  <D:prop>
    <D:resourcetype/>
    <D:displayname/>
    <CS:getctag/>
    <IC:calendar-color/>
    <D:current-user-privilege-set/>
  </D:prop>
</D:propfind>"#;

const PROPFIND_EVENTS: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:getetag/>
    <D:getcontenttype/>
  </D:prop>
</D:propfind>"#;

const PROPFIND_CTAG: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/">
  <D:prop>
    <CS:getctag/>
  </D:prop>
</D:propfind>"#;

const PROPFIND_SCHEDULING: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <C:schedule-outbox-URL/>
    <C:schedule-default-calendar-URL/>
  </D:prop>
</D:propfind>"#;

/// Which DAV flavour a client speaks.
///
/// CalDAV and CardDAV are the same protocol with four substitutions: the
/// home-set property, the collection's resourcetype marker, the multiget report
/// name, and the element the payload arrives in. Everything else in this file —
/// URL resolution, the redirect and credential policy, the multistatus
/// scaffolding, the etag handling — is shared verbatim, which is why this is an
/// enum rather than a second crate.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Flavor {
    #[default]
    CalDav,
    CardDav,
}

impl Flavor {
    /// The PROPFIND body that finds the collection home.
    fn home_body(self) -> &'static str {
        match self {
            Self::CalDav => PROPFIND_CALENDAR_HOME,
            Self::CardDav => PROPFIND_ADDRESSBOOK_HOME,
        }
    }

    /// The property name carrying the home href.
    fn home_property(self) -> &'static str {
        match self {
            Self::CalDav => "calendar-home-set",
            Self::CardDav => "addressbook-home-set",
        }
    }

    /// The `<resourcetype>` marker identifying a collection we can sync.
    fn collection_marker(self) -> &'static str {
        match self {
            Self::CalDav => "calendar",
            Self::CardDav => "addressbook",
        }
    }

    /// The element the payload arrives in inside a multiget response.
    fn data_element(self) -> &'static str {
        match self {
            Self::CalDav => "calendar-data",
            Self::CardDav => "address-data",
        }
    }

    /// The multiget REPORT body, given the pre-rendered `<D:href>` elements.
    fn multiget_body(self, href_elements: &str) -> String {
        match self {
            Self::CalDav => format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag/>
    <C:calendar-data/>
  </D:prop>
{href_elements}</C:calendar-multiget>"#
            ),
            Self::CardDav => format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<C:addressbook-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop>
    <D:getetag/>
    <C:address-data/>
  </D:prop>
{href_elements}</C:addressbook-multiget>"#
            ),
        }
    }

    /// The content type a PUT of this flavour's payload carries.
    fn content_type(self) -> &'static str {
        match self {
            Self::CalDav => "text/calendar; charset=utf-8",
            Self::CardDav => "text/vcard; charset=utf-8",
        }
    }
}

const PROPFIND_ADDRESSBOOK_HOME: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop>
    <C:addressbook-home-set/>
  </D:prop>
</D:propfind>"#;

/// A DAV response after manual redirect following.
struct DavResponse {
    status: u16,
    /// The URL the response actually came from — relative hrefs in the body
    /// MUST resolve against this, not the request URL (iCloud/Exchange
    /// bridges redirect discovery to per-tenant hosts).
    final_url: String,
    /// Lowercased, parameter-stripped media type ("" when absent).
    content_type: String,
    /// `ETag` response header, verbatim (lossy UTF-8 when non-ASCII — Yahoo/
    /// Kerio/Zimbra have shipped non-ASCII `ETag` bytes; the lossy value fails
    /// `If-Match` header validation later, which degrades to skipping the
    /// header rather than losing optimistic concurrency silently).
    etag: Option<String>,
    body: String,
}

/// Minimal `CalDAV` client: PROPFIND discovery/listing, REPORT multiget,
/// PUT/DELETE writeback, HTTP Basic auth (username = account email,
/// password from the secret backend).
pub struct CaldavClient {
    flavor: Flavor,
    agent: reqwest::blocking::Client,
    base_url: String,
    /// Precomputed `Basic ...` header value.
    auth_header: String,
    principal_url: Option<String>,
    calendar_home_url: Option<String>,
}

impl CaldavClient {
    pub fn new(base_url: &str, username: &str, password: &str) -> Self {
        // `redirect::Policy::none()`: the client returns 3xx responses instead
        // of following them, and `request()` below walks the chain manually —
        // the only way to both know the final URL for href resolution and to
        // veto https→http downgrades before credentials go over plaintext.
        //
        // reqwest rather than ureq, and this is not a style preference:
        // ureq 3 (via ureq-proto's `Method::verify_version`) enforces a
        // hardcoded allowlist of HTTP methods and rejects every WebDAV verb —
        // PROPFIND, REPORT, MKCALENDAR — with "not valid for HTTP version
        // HTTP/1.1" before a byte reaches the socket. A CalDAV client cannot
        // be built on it at all. The end-to-end test in tests/live_sync.rs is
        // what surfaced that; every unit test passed regardless because they
        // exercise the parsers rather than the transport.
        let agent = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(DAV_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{username}:{password}"),
        );
        Self {
            flavor: Flavor::CalDav,
            agent,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_header: format!("Basic {credentials}"),
            principal_url: None,
            calendar_home_url: None,
        }
    }

    /// The same client, speaking CardDAV.
    #[must_use]
    pub fn carddav(base_url: &str, username: &str, password: &str) -> Self {
        Self {
            flavor: Flavor::CardDav,
            ..Self::new(base_url, username, password)
        }
    }

    #[must_use]
    pub fn flavor(&self) -> Flavor {
        self.flavor
    }

    /// Seed the principal URL from a persisted value so `discover()` can
    /// skip the current-user-principal PROPFIND.
    pub fn set_principal_url(&mut self, url: &str) {
        self.principal_url = Some(url.to_string());
    }

    /// Seed the calendar-home-set URL from a persisted value.
    pub fn set_calendar_home_url(&mut self, url: &str) {
        self.calendar_home_url = Some(url.to_string());
    }

    pub fn principal_url(&self) -> Option<&str> {
        self.principal_url.as_deref()
    }

    pub fn calendar_home_url(&self) -> Option<&str> {
        self.calendar_home_url.as_deref()
    }

    /// One HTTP exchange with manual redirect following (≤ `MAX_REDIRECT_HOPS`).
    ///
    /// - `https → http` downgrades are refused outright: reqwest/ureq strip
    ///   Authorization on host/port changes but NOT on a same-port scheme
    ///   change, and a 301 from `https://host:8443` to `http://host:8443`
    ///   (real hosted-Zimbra failure mode) would replay Basic credentials in
    ///   plaintext.
    /// - Authorization is dropped for the remainder of the chain the moment
    ///   a hop crosses origins (host or effective-port change) — same policy
    ///   as reqwest's `remove_sensitive_headers`, so credentials never leak
    ///   to a third party a compromised server redirects to.
    /// - The method and body are preserved across ALL redirect codes
    ///   (including 303): converting PROPFIND/REPORT to GET per the letter
    ///   of 303 would break the protocol, and DAV servers that redirect
    ///   expect the method replayed.
    fn request(
        &self,
        method: &str,
        url: &str,
        extra_headers: &[(&str, &str)],
        body: &str,
    ) -> Result<DavResponse> {
        let mut current = url.to_string();
        let mut send_auth = true;

        for _hop in 0..=MAX_REDIRECT_HOPS {
            let http_method = reqwest::Method::from_bytes(method.as_bytes())
                .map_err(|e| Error::internal(format!("caldav: bad method {method}: {e}")))?;
            let mut builder = self.agent.request(http_method, current.as_str());
            for (k, v) in extra_headers {
                builder = builder.header(*k, *v);
            }
            if send_auth {
                builder = builder.header("Authorization", self.auth_header.as_str());
            }
            let resp = builder
                .body(body.to_string())
                .send()
                .map_err(|e| Error::protocol(format!("caldav: {method} {current}: {e}")))?;

            let status = resp.status().as_u16();
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let location = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
                    .ok_or_else(|| {
                        Error::protocol(format!(
                            "caldav: {method} {current} redirected ({status}) without Location"
                        ))
                    })?;
                let next = resolve_url_against(&current, &location);
                if current.starts_with("https://") && next.starts_with("http://") {
                    return Err(Error::protocol(format!(
                        "caldav: refusing https -> http downgrade redirect \
                         ({current} -> {next}); credentials would go over plaintext"
                    )));
                }
                if origin_of(&current) != origin_of(&next) {
                    send_auth = false;
                }
                current = next;
                continue;
            }

            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(';').next())
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_default();
            let etag = resp.headers().get("etag").map(|v| {
                if let Ok(s) = v.to_str() {
                    s.to_string()
                } else {
                    let lossy = String::from_utf8_lossy(v.as_bytes()).into_owned();
                    tracing::warn!(
                        "caldav: ETag has non-ASCII bytes; storing lossy UTF-8 ({lossy:?}). \
                     If-Match will be omitted on the next write."
                    );
                    lossy
                }
            });
            // Bound the read explicitly. reqwest has no built-in ceiling, and
            // an unbounded read of a hostile or merely broken response is how a
            // sync cycle turns into an OOM.
            let body = {
                use std::io::Read as _;
                let mut buf = String::new();
                resp.take(BODY_LIMIT)
                    .read_to_string(&mut buf)
                    .map_err(|e| {
                        Error::protocol(format!("caldav: reading {method} {current} body: {e}"))
                    })?;
                buf
            };
            return Ok(DavResponse {
                status,
                final_url: current,
                content_type,
                etag,
                body,
            });
        }
        Err(Error::protocol(format!(
            "caldav: {method} {url}: redirect chain exceeded {MAX_REDIRECT_HOPS} hops"
        )))
    }

    /// PROPFIND returning `(final_url, body)`.
    ///
    /// `text/html` content is rejected BEFORE status handling: SSO portals
    /// and misconfigured nginx front-ends terminate the request with a
    /// 200 + HTML login page; the multistatus parsers read that as "zero
    /// resources" and the reconciler would wipe the local cache. Failing
    /// loudly here turns a silent wipe into a visible error.
    fn propfind(&self, url: &str, depth: &str, body: &str) -> Result<(String, String)> {
        let resp = self.request(
            "PROPFIND",
            url,
            &[
                ("Content-Type", "application/xml; charset=utf-8"),
                ("Depth", depth),
            ],
            body,
        )?;
        if resp.content_type.starts_with("text/html") {
            return Err(Error::protocol(format!(
                "caldav: PROPFIND {url} returned non-XML content (content-type {}); \
                 refusing to treat as multistatus",
                resp.content_type
            )));
        }
        if (200..300).contains(&resp.status) {
            Ok((resp.final_url, resp.body))
        } else {
            Err(Error::status(
                resp.status,
                format!(
                    "caldav: PROPFIND {url}: {}",
                    resp.body.chars().take(300).collect::<String>()
                ),
            ))
        }
    }

    /// REPORT with the same text/html rejection as `propfind`.
    fn report(&self, url: &str, body: &str) -> Result<String> {
        let resp = self.request(
            "REPORT",
            url,
            &[
                ("Content-Type", "application/xml; charset=utf-8"),
                ("Depth", "1"),
            ],
            body,
        )?;
        if resp.content_type.starts_with("text/html") {
            return Err(Error::protocol(format!(
                "caldav: REPORT {url} returned non-XML content (content-type {}); \
                 refusing to treat as multistatus",
                resp.content_type
            )));
        }
        if (200..300).contains(&resp.status) {
            Ok(resp.body)
        } else {
            Err(Error::status(
                resp.status,
                format!(
                    "caldav: REPORT {url}: {}",
                    resp.body.chars().take(300).collect::<String>()
                ),
            ))
        }
    }

    /// Auto-discover principal and calendar-home-set.
    ///
    /// Base URL is probed FIRST and `.well-known/caldav` only as a fallback:
    /// enterprise Exchange front-ends answer 200 + HTML-404 (or an `IdP`
    /// redirect) for the well-known path, and a well-known-first probe reads
    /// that as "discovery succeeded, no principal" and loops. Relative hrefs
    /// resolve against each response's FINAL URL; the home-set href resolves
    /// against the PRINCIPAL URL (Fastmail-style split-host setups put the
    /// principal and DAV root on different hosts — resolving against
    /// `base_url` rebuilds the home on the wrong origin).
    ///
    /// On a principal that yields no home-set, the in-memory principal is
    /// cleared before erroring so the next `discover()` starts from scratch
    /// instead of re-probing the same dead value; clearing any PERSISTED
    /// principal is the caller's decision.
    pub fn discover(&mut self) -> Result<()> {
        if self.principal_url.is_none() {
            self.principal_url = Some(self.discover_principal()?);
        }
        if self.calendar_home_url.is_none() {
            let principal = self
                .principal_url
                .clone()
                .ok_or_else(|| Error::protocol("caldav: no principal URL"))?;
            match self.propfind(&principal, "0", self.flavor.home_body()) {
                Ok((_final_url, body)) => {
                    let homes = extract_hrefs_property(&body, self.flavor.home_property());
                    if homes.len() > 1 {
                        // Delegation / shared-account setups (Apple Calendar
                        // Server, Kerio) legitimately return multiple homes;
                        // only the first is consumed today.
                        tracing::warn!(
                            "caldav: calendar-home-set returned {} hrefs; using only the first",
                            homes.len()
                        );
                    }
                    if let Some(home) = homes.into_iter().next() {
                        self.calendar_home_url = Some(resolve_url_against(&principal, &home));
                    } else {
                        self.principal_url = None;
                        return Err(Error::protocol(
                            "caldav: could not discover calendar-home-set \
                             (stale principal, or no calendars provisioned)",
                        ));
                    }
                }
                Err(e) => {
                    self.principal_url = None;
                    return Err(Error::protocol(format!(
                        "caldav: PROPFIND for calendar-home-set failed: {e}"
                    )));
                }
            }
        }
        tracing::info!(
            "caldav: discovery complete: principal={:?} home={:?}",
            self.principal_url,
            self.calendar_home_url
        );
        Ok(())
    }

    fn discover_principal(&self) -> Result<String> {
        let mut last_error = match self.propfind(&self.base_url, "0", PROPFIND_PRINCIPAL) {
            Ok((final_url, body)) => {
                if let Some(principal) =
                    extract_first_href_property(&body, "current-user-principal")
                {
                    return Ok(resolve_url_against(&final_url, &principal));
                }
                "PROPFIND on base URL returned no current-user-principal".to_string()
            }
            Err(e) => format!("PROPFIND on base URL failed: {e}"),
        };

        let well_known = format!("{}/.well-known/caldav", self.base_url);
        match self.propfind(&well_known, "0", PROPFIND_PRINCIPAL) {
            Ok((final_url, body)) => {
                if let Some(principal) =
                    extract_first_href_property(&body, "current-user-principal")
                {
                    return Ok(resolve_url_against(&final_url, &principal));
                }
                last_error = format!("{last_error}; .well-known/caldav also returned no principal");
            }
            Err(e) => last_error = format!("{last_error}; .well-known/caldav also failed: {e}"),
        }
        Err(Error::protocol(format!(
            "caldav: could not discover current-user-principal: {last_error}"
        )))
    }

    /// List calendar collections in the home-set, hrefs resolved absolute
    /// against the home-set PROPFIND's final URL (not `base_url` — split-
    /// host setups again).
    pub fn list_calendars(&self) -> Result<Vec<DiscoveredCalendar>> {
        let home = self.calendar_home_url.clone().ok_or_else(|| {
            Error::protocol("caldav: no calendar-home-set URL — call discover() first")
        })?;
        let (final_url, body) = self.propfind(&home, "1", PROPFIND_CALENDARS)?;
        let mut calendars = parse_propfind_calendars(&body, self.flavor);
        for cal in &mut calendars {
            cal.href = resolve_url_against(&final_url, &cal.href);
        }
        if calendars.is_empty() {
            // Distinguish "no calendars provisioned" from "content-free 207"
            // so an operator chasing "where did my calendars go" has a lead.
            let responses = count_response_children(&body);
            if responses == 0 {
                tracing::warn!(
                    "caldav: list_calendars at {final_url} returned a 207 with zero \
                     <response> children ({} bytes); first-login race or server error \
                     misreported as 207",
                    body.len()
                );
            } else {
                tracing::warn!(
                    "caldav: list_calendars at {final_url} parsed {responses} responses \
                     but found 0 calendars"
                );
            }
        }
        Ok(calendars)
    }

    /// List (uri, etag) entries for a calendar; uris resolved absolute
    /// against the listing's final URL so they compare byte-equal with what
    /// `fetch_events` normalizes.
    pub fn list_events(&self, calendar_url: &str) -> Result<PropfindEventsResult> {
        let (final_url, body) = self.propfind(calendar_url, "1", PROPFIND_EVENTS)?;
        let mut result = parse_propfind_events(&body, self.flavor);
        for entry in &mut result.entries {
            entry.uri = resolve_url_against(&final_url, &entry.uri);
        }
        for uri in &mut result.failed_uris {
            *uri = resolve_url_against(&final_url, uri);
        }
        Ok(result)
    }

    /// Depth:0 ctag probe.
    pub fn get_ctag(&self, calendar_url: &str) -> Result<Option<String>> {
        let (_final_url, body) = self.propfind(calendar_url, "0", PROPFIND_CTAG)?;
        Ok(parse_ctag(&body))
    }

    /// RFC 6638 capability probe on the principal (F-CAL-6): a
    /// `schedule-outbox-URL` means the server runs the scheduling engine —
    /// an attendee's PUT delivers the iTIP REPLY itself, so no scheduling
    /// mail is needed. `schedule-default-calendar-URL` names the collection
    /// the server files new scheduling objects on (the preferred landing
    /// spot for mail-borne invitations, F-CAL-12).
    pub fn discover_scheduling(&self) -> Result<SchedulingInfo> {
        let principal = self.principal_url.clone().ok_or_else(|| {
            Error::protocol("caldav: no principal URL — call discover() first")
        })?;
        let (final_url, body) = self.propfind(&principal, "0", PROPFIND_SCHEDULING)?;
        let supports_scheduling = extract_first_href_property(&body, "schedule-outbox-URL")
            .is_some_and(|h| !h.trim().is_empty());
        let default_calendar_url =
            extract_first_href_property(&body, "schedule-default-calendar-URL")
                .map(|h| resolve_url_against(&final_url, &h));
        Ok(SchedulingInfo {
            supports_scheduling,
            default_calendar_url,
        })
    }

    /// Batch-fetch iCal payloads by href via calendar-multiget REPORT, in
    /// batches of [`MULTIGET_BATCH_SIZE`]. Request hrefs are XML-escaped and
    /// same-origin absolute hrefs are re-relativized to path form (strict-
    /// server compatibility); response hrefs are normalized with the SAME
    /// `resolve_url_against` the listing side uses, so the (href, etag) maps
    /// line up byte-for-byte.
    pub fn fetch_events(
        &self,
        calendar_url: &str,
        uris: &[String],
    ) -> Result<Vec<(String, String)>> {
        if uris.is_empty() {
            return Ok(Vec::new());
        }
        let mut all = Vec::new();
        for chunk in uris.chunks(MULTIGET_BATCH_SIZE) {
            let mut href_elements = String::new();
            for uri in chunk {
                let body_href = relativize_for_multiget(calendar_url, uri);
                href_elements.push_str("  <D:href>");
                href_elements.push_str(&xml_escape_text(&body_href));
                href_elements.push_str("</D:href>\n");
            }
            let body = self.flavor.multiget_body(&href_elements);
            let response = self.report(calendar_url, &body)?;
            for (uri, ical) in parse_multiget_report(&response, self.flavor) {
                all.push((resolve_url_against(calendar_url, &uri), ical));
            }
        }
        Ok(all)
    }

    /// Create/update an event resource. `If-Match` is derived from the
    /// stored etag via `prepare_if_match_etag` (skipped when the stored
    /// value isn't RFC 7232-legal there). Returns the new `ETag` when the
    /// server supplies one.
    pub fn put_event(
        &self,
        event_url: &str,
        ical_data: &str,
        etag: Option<&str>,
    ) -> Result<Option<String>> {
        let if_match = etag.and_then(prepare_if_match_etag);
        let mut headers: Vec<(&str, &str)> = vec![("Content-Type", self.flavor.content_type())];
        if let Some(im) = if_match.as_deref() {
            headers.push(("If-Match", im));
        }
        let resp = self.request("PUT", event_url, &headers, ical_data)?;
        if (200..300).contains(&resp.status) {
            Ok(resp.etag)
        } else {
            Err(Error::status(
                resp.status,
                format!(
                    "caldav: PUT {event_url}: {}",
                    resp.body.chars().take(300).collect::<String>()
                ),
            ))
        }
    }

    /// Delete an event resource. 404 counts as success — the goal state
    /// ("resource gone") is already true and treating it as failure wedges
    /// the delete in a retry loop.
    pub fn delete_event(&self, event_url: &str, etag: Option<&str>) -> Result<()> {
        let if_match = etag.and_then(prepare_if_match_etag);
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(im) = if_match.as_deref() {
            headers.push(("If-Match", im));
        }
        let resp = self.request("DELETE", event_url, &headers, "")?;
        if (200..300).contains(&resp.status) || resp.status == 404 {
            Ok(())
        } else {
            Err(Error::status(
                resp.status,
                format!(
                    "caldav: DELETE {event_url}: {}",
                    resp.body.chars().take(300).collect::<String>()
                ),
            ))
        }
    }

    /// CALDAV:free-busy-query REPORT (RFC 4791 §7.10) over `[start_ms,
    /// end_ms)`. Depth is 0 per the RFC's example (the report targets the
    /// collection itself, not its members). Returns `(status, body)` — the
    /// caller decides how to treat non-2xx, because 403/405 carry meaning
    /// ("report unsupported", triggering the local fallback) rather than
    /// being outright failures. The body of a compliant server is a bare
    /// `text/calendar` VFREEBUSY object, so unlike `propfind`/`report` no
    /// XML shape is assumed; `text/html` is still rejected (SSO login page,
    /// same failure mode as everywhere else).
    pub fn free_busy_query(
        &self,
        calendar_url: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<(u16, String)> {
        use chrono::TimeZone;
        let fmt_utc = |ms: i64| -> String {
            chrono::Utc.timestamp_millis_opt(ms).single().map_or_else(
                || "19700101T000000Z".to_string(),
                |dt| dt.format("%Y%m%dT%H%M%SZ").to_string(),
            )
        };
        let body = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">
  <C:time-range start="{}" end="{}"/>
</C:free-busy-query>"#,
            fmt_utc(start_ms),
            fmt_utc(end_ms)
        );
        let resp = self.request(
            "REPORT",
            calendar_url,
            &[
                ("Content-Type", "application/xml; charset=utf-8"),
                ("Depth", "0"),
            ],
            &body,
        )?;
        if resp.content_type.starts_with("text/html") {
            return Err(Error::protocol(format!(
                "caldav: free-busy REPORT {calendar_url} returned non-calendar content \
                 (content-type {}); refusing to parse",
                resp.content_type
            )));
        }
        Ok((resp.status, resp.body))
    }
}


#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /* ---------------- URL resolution ---------------- */

    #[test]
    fn resolve_appends_collection_trailing_slash_before_join() {
        // Davical/Bedework/old Zimbra list collections without a trailing
        // slash; a vanilla RFC 3986 join would drop the last segment.
        assert_eq!(
            resolve_url_against("https://h/cal/user/work", "event.ics"),
            "https://h/cal/user/work/event.ics"
        );
        assert_eq!(
            resolve_url_against("https://h/cal/user/work/", "event.ics"),
            "https://h/cal/user/work/event.ics"
        );
    }

    #[test]
    fn resolve_handles_absolute_path_and_absolute_url() {
        assert_eq!(
            resolve_url_against("https://h/cal/user/work", "/cal/event.ics"),
            "https://h/cal/event.ics"
        );
        assert_eq!(
            resolve_url_against("https://h/cal/", "https://other/x.ics"),
            "https://other/x.ics"
        );
    }

    #[test]
    fn resolve_reattaches_base_query_when_href_has_none() {
        // Shared-hosting front-ends route tenants via ?token=... on the
        // calendar URL; a vanilla join drops it and requests go tenant-less.
        let got = resolve_url_against("https://h/cal/work?token=x", "event.ics");
        assert_eq!(got, "https://h/cal/work/event.ics?token=x");
        // ...but an href with its own query wins.
        let got = resolve_url_against("https://h/cal/work?token=x", "event.ics?rev=2");
        assert_eq!(got, "https://h/cal/work/event.ics?rev=2");
    }

    #[test]
    fn resolve_removes_dot_segments() {
        assert_eq!(
            resolve_url_against("https://h/cal/user/", "../shared/e.ics"),
            "https://h/cal/shared/e.ics"
        );
        assert_eq!(
            resolve_url_against("https://h/cal/", "./e.ics"),
            "https://h/cal/e.ics"
        );
    }

    #[test]
    fn resolve_protocol_relative_adopts_base_scheme() {
        assert_eq!(
            resolve_url_against("https://h/cal/", "//other.example/dav/"),
            "https://other.example/dav/"
        );
    }

    #[test]
    fn relativize_multiget_strips_same_origin_absolute() {
        assert_eq!(
            relativize_for_multiget(
                "https://cal.example/cal/user/work/",
                "https://cal.example/cal/user/work/event.ics"
            ),
            "/cal/user/work/event.ics"
        );
        // Default-port normalization: :443 and bare https compare equal.
        assert_eq!(
            relativize_for_multiget(
                "https://cal.example:443/cal/",
                "https://cal.example/cal/e.ics"
            ),
            "/cal/e.ics"
        );
        assert_eq!(
            relativize_for_multiget(
                "https://cal.example/cal/",
                "https://other.example/cal/e.ics"
            ),
            "https://other.example/cal/e.ics"
        );
        assert_eq!(
            relativize_for_multiget("https://cal.example/cal/", "event.ics"),
            "event.ics"
        );
    }

    /* ---------------- ETag / escaping / color / classification ------ */

    #[test]
    fn prepare_if_match_etag_table() {
        // Quoted strong ETag passes through verbatim.
        assert_eq!(prepare_if_match_etag("\"abc\""), Some("\"abc\"".into()));
        // Weak ETags are forbidden in If-Match (RFC 7232 §3.1): strict
        // servers 412 every write carrying one, wedging the client.
        assert_eq!(prepare_if_match_etag("W/\"abc\""), None);
        // Legacy-corrupted weak form (inner quote lost): unsendable.
        assert_eq!(prepare_if_match_etag("W/abc"), None);
        // Legacy bare strong ETag gets its quotes back.
        assert_eq!(prepare_if_match_etag("abc"), Some("\"abc\"".into()));
        // Whitespace trims; empty skips the header.
        assert_eq!(prepare_if_match_etag("  \"abc\"  "), Some("\"abc\"".into()));
        assert_eq!(prepare_if_match_etag(""), None);
        assert_eq!(prepare_if_match_etag("   "), None);
    }

    #[test]
    fn xml_escape_covers_exchange_ampersand_hrefs() {
        assert_eq!(xml_escape_text("/cal/a&b.ics"), "/cal/a&amp;b.ics");
        assert_eq!(xml_escape_text("/cal/a<b>.ics"), "/cal/a&lt;b&gt;.ics");
        assert!(matches!(
            xml_escape_text("/cal/plain.ics"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn color_normalization_folds_apple_argb() {
        assert_eq!(normalize_calendar_color("#0000FFFF"), "#0000FF");
        assert_eq!(normalize_calendar_color("#00FF00"), "#00FF00");
        // Non-hex and odd lengths pass through verbatim.
        assert_eq!(normalize_calendar_color("blue"), "blue");
        assert_eq!(normalize_calendar_color("#12345"), "#12345");
    }

    #[test]
    fn icalendar_resource_classification() {
        assert!(is_syncable_resource("/cal/e.ics", "text/calendar", Flavor::CalDav));
        // Case-insensitive media types (RFC 7231 §3.1.1.1).
        assert!(is_syncable_resource(
            "/cal/e",
            "TEXT/CALENDAR; charset=utf-8",
            Flavor::CalDav
        ));
        assert!(is_syncable_resource(
            "/cal/e.xml",
            "application/calendar+xml",
            Flavor::CalDav
        ));
        // Extension match survives query strings and case.
        assert!(is_syncable_resource("/cal/e.ICS?rev=42", "", Flavor::CalDav));
        // Empty content-type + non-slash tail is the last-resort accept...
        assert!(is_syncable_resource("/cal/e", "", Flavor::CalDav));
        // ...but a collection (slash tail after query-strip) is not.
        assert!(!is_syncable_resource("/cal/folder/?rev=1", "", Flavor::CalDav));
        assert!(!is_syncable_resource("/cal/e", "text/plain", Flavor::CalDav));
    }

    /* ---------------- multistatus parsing ---------------- */

    #[test]
    fn calendars_parse_gates_mixed_propstat_blocks() {
        // displayname arrives in the 200 propstat, calendar-color in a 404
        // one — the 404 block's value must NOT leak into the result.
        let xml = r#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"
               xmlns:IC="http://apple.com/ns/ical/">
  <D:response>
    <D:href>/cal/alice/work/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/><C:calendar/></D:resourcetype>
        <D:displayname>Work</D:displayname>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
    <D:propstat>
      <D:prop>
        <IC:calendar-color>#FF0000FF</IC:calendar-color>
      </D:prop>
      <D:status>HTTP/1.1 404 Not Found</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        let cals = parse_propfind_calendars(xml, Flavor::CalDav);
        assert_eq!(cals.len(), 1);
        assert_eq!(cals[0].href, "/cal/alice/work/");
        assert_eq!(cals[0].display_name.as_deref(), Some("Work"));
        assert_eq!(cals[0].color, None, "404-propstat color must not commit");
        assert_eq!(cals[0].can_edit, None, "no privilege block seen");
    }

    #[test]
    fn calendars_parse_reads_privileges_and_apple_color() {
        let xml = r#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"
               xmlns:IC="http://apple.com/ns/ical/">
  <D:response>
    <D:href>/cal/a/rw/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><C:calendar/></D:resourcetype>
        <IC:calendar-color>#00FF00FF</IC:calendar-color>
        <D:current-user-privilege-set>
          <D:privilege><D:read/></D:privilege>
          <D:privilege><D:write/></D:privilege>
        </D:current-user-privilege-set>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/cal/a/ro/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><C:calendar/></D:resourcetype>
        <D:current-user-privilege-set>
          <D:privilege><D:read/></D:privilege>
        </D:current-user-privilege-set>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/cal/a/unknown-acl/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><C:calendar/></D:resourcetype>
        <D:current-user-privilege-set/>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        let cals = parse_propfind_calendars(xml, Flavor::CalDav);
        assert_eq!(cals.len(), 3);
        assert_eq!(cals[0].can_edit, Some(true));
        assert_eq!(
            cals[0].color.as_deref(),
            Some("#00FF00"),
            "ARGB alpha folded"
        );
        assert_eq!(cals[1].can_edit, Some(false));
        // Empty self-closed privilege-set = "unknown ACL" sentinel, NOT an
        // explicit read-only grant — must stay None (editable).
        assert_eq!(cals[2].can_edit, None);
    }

    #[test]
    fn events_parse_handles_prefix_variance_and_cdata_href() {
        // Different namespace prefixes than the canonical D:/C: — bridges
        // remap freely — plus a CDATA-wrapped href.
        let xml = r#"<?xml version="1.0"?>
<DAV1:multistatus xmlns:DAV1="DAV:">
  <DAV1:response>
    <DAV1:href><![CDATA[/cal/a/one.ics]]></DAV1:href>
    <DAV1:propstat>
      <DAV1:prop>
        <DAV1:getetag>"e1"</DAV1:getetag>
        <DAV1:getcontenttype>text/calendar</DAV1:getcontenttype>
      </DAV1:prop>
      <DAV1:status>HTTP/1.1 200 OK</DAV1:status>
    </DAV1:propstat>
  </DAV1:response>
</DAV1:multistatus>"#;
        let result = parse_propfind_events(xml, Flavor::CalDav);
        assert_eq!(
            result.entries,
            vec![CalDavEventEntry {
                uri: "/cal/a/one.ics".into(),
                etag: "\"e1\"".into(),
            }]
        );
        assert!(result.failed_uris.is_empty());
    }

    #[test]
    fn events_parse_classifies_failures_and_skips_collections() {
        let xml = r#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/cal/a/ok.ics</D:href>
    <D:propstat>
      <D:prop><D:getetag>"e1"</D:getetag></D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/cal/a/server-error.ics</D:href>
    <D:status>HTTP/1.1 500 Internal Server Error</D:status>
  </D:response>
  <D:response>
    <D:href>/cal/a/all-propstats-failed.ics</D:href>
    <D:propstat>
      <D:prop><D:getetag/></D:prop>
      <D:status>HTTP/1.1 404 Not Found</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/cal/a/subfolder</D:href>
    <D:propstat>
      <D:prop>
        <D:getetag>"e9"</D:getetag>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        let result = parse_propfind_events(xml, Flavor::CalDav);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].uri, "/cal/a/ok.ics");
        // Response-level 500 AND all-propstats-non-2xx are server-reported
        // failures → local copies preserved, not deletions.
        assert_eq!(
            result.failed_uris,
            vec![
                "/cal/a/server-error.ics".to_string(),
                "/cal/a/all-propstats-failed.ics".to_string(),
            ]
        );
        // The collection was skipped for OUR reasons — not a failure.
        assert!(!result.failed_uris.iter().any(|u| u.contains("subfolder")));
    }

    #[test]
    fn multiget_parse_drops_response_level_errors() {
        // SOGo emits a response-level 500 while echoing stale calendar-data
        // in a 200 propstat; the response-level gate blocks the stale data.
        let xml = r#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:response>
    <D:href>/cal/a/good.ics</D:href>
    <D:propstat>
      <D:prop><C:calendar-data><![CDATA[BEGIN:VCALENDAR
END:VCALENDAR]]></C:calendar-data></D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>/cal/a/broken.ics</D:href>
    <D:status>HTTP/1.1 500 Internal Server Error</D:status>
    <D:propstat>
      <D:prop><C:calendar-data>STALE</C:calendar-data></D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        let results = parse_multiget_report(xml, Flavor::CalDav);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "/cal/a/good.ics");
        assert!(results[0].1.starts_with("BEGIN:VCALENDAR"));
    }

    #[test]
    fn href_extraction_is_parent_scoped_and_cdata_aware() {
        // Davical delegation mode nests <owner><href> inside the property;
        // direct-child scoping must filter it.
        let xml = r#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:response>
    <D:href>/principals/users/alice/</D:href>
    <D:propstat>
      <D:prop>
        <C:calendar-home-set>
          <D:owner><D:href>/principals/users/admin/</D:href></D:owner>
          <D:href><![CDATA[/calendars/alice/]]></D:href>
        </C:calendar-home-set>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>"#;
        assert_eq!(
            extract_hrefs_property(xml, "calendar-home-set"),
            vec!["/calendars/alice/".to_string()]
        );
        assert_eq!(
            extract_first_href_property(xml, "calendar-home-set").as_deref(),
            Some("/calendars/alice/")
        );
    }

    #[test]
    fn status_line_parse_is_strict_on_digits_lenient_on_absence() {
        assert!(status_line_is_ok(""));
        assert!(status_line_is_ok("HTTP/1.1 200 OK"));
        assert!(status_line_is_ok("HTTP/1.1 207 Multi-Status"));
        assert!(!status_line_is_ok("HTTP/1.1 404 Not Found"));
        assert!(!status_line_is_ok("HTTP/1.1 2xx Custom"));
        assert!(!status_line_is_ok("garbage"));
    }


    /* ---------------- CardDAV flavour ---------------- */

    #[test]
    fn carddav_recognises_an_addressbook_collection_and_caldav_does_not() {
        let xml = r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">
<d:response><d:href>/dav/contacts/default/</d:href><d:propstat><d:prop>
<d:resourcetype><d:collection/><card:addressbook xmlns:card="urn:ietf:params:xml:ns:carddav"/></d:resourcetype>
<d:displayname>Contacts</d:displayname>
</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
</d:multistatus>"#;

        let books = parse_propfind_calendars(xml, Flavor::CardDav);
        assert_eq!(books.len(), 1);
        assert_eq!(books[0].display_name.as_deref(), Some("Contacts"));

        // The same document must yield nothing to a CalDAV client: an address
        // book is not a calendar, and syncing one as the other would fill a
        // calendar with unparseable resources.
        assert!(parse_propfind_calendars(xml, Flavor::CalDav).is_empty());
    }

    #[test]
    fn carddav_reads_address_data_rather_than_calendar_data() {
        let xml = r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
<d:response><d:href>/dav/contacts/default/a.vcf</d:href><d:propstat><d:prop>
<d:getetag>"1"</d:getetag>
<card:address-data>BEGIN:VCARD
VERSION:4.0
FN:Ada
END:VCARD</card:address-data>
</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
</d:multistatus>"#;

        let results = parse_multiget_report(xml, Flavor::CardDav);
        assert_eq!(results.len(), 1);
        assert!(results[0].1.contains("FN:Ada"));

        // And a CalDAV client sees no payload at all, rather than an empty one
        // it would then store over a real contact.
        assert!(parse_multiget_report(xml, Flavor::CalDav).is_empty());
    }

    #[test]
    fn the_multiget_body_names_the_right_report_for_each_flavour() {
        let cal = Flavor::CalDav.multiget_body("  <D:href>/a.ics</D:href>\n");
        assert!(cal.contains("calendar-multiget") && cal.contains("calendar-data"));
        assert!(cal.contains("urn:ietf:params:xml:ns:caldav"));

        let card = Flavor::CardDav.multiget_body("  <D:href>/a.vcf</D:href>\n");
        assert!(card.contains("addressbook-multiget") && card.contains("address-data"));
        assert!(card.contains("urn:ietf:params:xml:ns:carddav"));
    }

    #[test]
    fn the_resource_gate_distinguishes_vcards_from_icalendar() {
        // The bug this prevents: CardDAV listings were being filtered by a
        // CalDAV-only content-type gate, so every .vcf was silently skipped and
        // an address book synced as empty.
        assert!(is_syncable_resource("/c/a.vcf", "text/vcard", Flavor::CardDav));
        assert!(is_syncable_resource("/c/a", "text/vcard; charset=utf-8", Flavor::CardDav));
        assert!(is_syncable_resource("/c/a.VCF?rev=1", "", Flavor::CardDav));
        // text/directory is what vCard 3.0 servers still send.
        assert!(is_syncable_resource("/c/a", "text/directory", Flavor::CardDav));

        assert!(!is_syncable_resource("/c/a.vcf", "text/vcard", Flavor::CalDav));
        assert!(!is_syncable_resource("/cal/e.ics", "text/calendar", Flavor::CardDav));
        assert!(!is_syncable_resource("/c/folder/", "", Flavor::CardDav));
    }
}

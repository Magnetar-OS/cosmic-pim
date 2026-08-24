// SPDX-License-Identifier: MPL-2.0
//
// The cascade's shape, the SSRF guard, and the autoconfig URL order are ported
// from `src-tauri/src/discovery.rs` in the Meltemi project, reduced to the three
// stages that answer for essentially every real account. See NOTICE and
// LICENSING.md.

//! Working out where an address's mail lives, from the address.
//!
//! Asking somebody for an IMAP hostname is asking them a question they should
//! not have to be able to answer. Three stages, in order, first answer wins:
//!
//! 1. **A built-in table.** Gmail, Outlook, Fastmail, iCloud and the rest, with
//!    their aliases. No network, no waiting, and right for most people.
//! 2. **Mozilla autoconfig.** The de-facto standard: a provider publishes its
//!    own settings at a known URL, and Mozilla's ISPDB holds the rest on file.
//!    This is how a small provider or a university gets answered.
//! 3. **A guess, probed.** `imap.<domain>` and `mail.<domain>` on 993, actually
//!    connected to. Right surprisingly often for self-hosted mail, and it is
//!    checked rather than asserted — a guess offered as fact is worse than no
//!    guess, because the failure surfaces later as "wrong password".
//!
//! What is *not* here, from the donor's six-stage version: MX lookup, RFC 6186
//! SRV records, and the JMAP well-known probe. All three need a DNS resolver as
//! a dependency, and they answer for the domains the first three stages already
//! answer for. When there is a second protocol to discover, SRV becomes worth
//! its dependency.
//!
//! # The guard
//!
//! Everything below builds URLs and opens sockets using a string the user
//! typed. `evil@10.0.0.1`, `evil@localhost`, `evil@host:8080/path` — without a
//! guard, "add an account" becomes a way to make someone's mail client probe
//! their own network and report back. [`domain_of`] admits only shapes that are
//! unambiguously a public hostname, and nothing downstream accepts anything it
//! rejected.

use std::io::Read as _;
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs as _};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::imap::Security;

/// Cap on a whole discovery attempt.
///
/// Long enough for one slow HTTPS fetch behind a slow resolver, short enough
/// that somebody adding an account does not conclude the application has hung.
const STAGE_TIMEOUT: Duration = Duration::from_secs(6);

/// Cap on an autoconfig document. They are a few kilobytes; anything larger is
/// not one, and reading it would be letting a stranger choose how much memory
/// to spend.
const MAX_DOCUMENT: u64 = 256 * 1024;

/// What was found, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    pub display_name: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: Security,
    /// What to log in with. Some providers want the local part rather than the
    /// whole address, and autoconfig says which.
    pub username: String,
    pub source: Source,
}

/// Which stage answered — shown to the user, because "we looked this up" and
/// "we guessed and it accepted a connection" deserve different confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// From the built-in table.
    Known,
    /// From an autoconfig document the provider or Mozilla publishes.
    Autoconfig,
    /// Guessed from the domain and confirmed only by a socket opening.
    Guessed,
}

/// One provider in the built-in table.
struct Known {
    display_name: &'static str,
    domains: &'static [&'static str],
    imap_host: &'static str,
    smtp_host: &'static str,
    /// STARTTLS on 587 rather than implicit TLS on 465, where the provider
    /// wants that.
    smtp_starttls: bool,
}

/// The providers most people actually have.
///
/// Worth keeping small and worth keeping honest: an entry here is a promise
/// that these settings work, and a wrong one is worse than no entry because it
/// fails as "your password is wrong". Anything not here falls to autoconfig,
/// which is where the long tail belongs.
const KNOWN: &[Known] = &[
    Known {
        display_name: "Gmail",
        domains: &["gmail.com", "googlemail.com"],
        imap_host: "imap.gmail.com",
        smtp_host: "smtp.gmail.com",
        smtp_starttls: false,
    },
    Known {
        display_name: "Outlook",
        domains: &[
            "outlook.com",
            "hotmail.com",
            "live.com",
            "msn.com",
            "passport.com",
        ],
        imap_host: "outlook.office365.com",
        smtp_host: "smtp-mail.outlook.com",
        smtp_starttls: true,
    },
    Known {
        display_name: "Fastmail",
        domains: &["fastmail.com", "fastmail.fm", "messagingengine.com"],
        imap_host: "imap.fastmail.com",
        smtp_host: "smtp.fastmail.com",
        smtp_starttls: false,
    },
    Known {
        display_name: "iCloud",
        domains: &["icloud.com", "me.com", "mac.com"],
        imap_host: "imap.mail.me.com",
        smtp_host: "smtp.mail.me.com",
        smtp_starttls: true,
    },
    Known {
        display_name: "Yahoo",
        domains: &["yahoo.com", "yahoo.co.uk", "ymail.com", "rocketmail.com"],
        imap_host: "imap.mail.yahoo.com",
        smtp_host: "smtp.mail.yahoo.com",
        smtp_starttls: false,
    },
    Known {
        display_name: "Proton Mail Bridge",
        domains: &["protonmail.com", "proton.me", "pm.me"],
        // The bridge, on localhost — Proton has no direct IMAP. Listed so the
        // form is filled in with something that can work rather than with
        // settings that cannot.
        imap_host: "127.0.0.1",
        smtp_host: "127.0.0.1",
        smtp_starttls: true,
    },
    Known {
        display_name: "Zoho Mail",
        domains: &["zoho.com", "zohomail.com"],
        imap_host: "imap.zoho.com",
        smtp_host: "smtp.zoho.com",
        smtp_starttls: false,
    },
    Known {
        display_name: "GMX",
        domains: &["gmx.com", "gmx.net", "gmx.de", "gmx.at", "gmx.ch"],
        imap_host: "imap.gmx.net",
        smtp_host: "mail.gmx.net",
        smtp_starttls: false,
    },
    Known {
        display_name: "mail.com",
        domains: &["mail.com", "email.com", "usa.com"],
        imap_host: "imap.mail.com",
        smtp_host: "smtp.mail.com",
        smtp_starttls: false,
    },
    Known {
        display_name: "Posteo",
        domains: &["posteo.de", "posteo.net"],
        imap_host: "posteo.de",
        smtp_host: "posteo.de",
        smtp_starttls: false,
    },
    Known {
        display_name: "mailbox.org",
        domains: &["mailbox.org"],
        imap_host: "imap.mailbox.org",
        smtp_host: "smtp.mailbox.org",
        smtp_starttls: false,
    },
    Known {
        display_name: "Migadu",
        domains: &["migadu.com"],
        imap_host: "imap.migadu.com",
        smtp_host: "smtp.migadu.com",
        smtp_starttls: false,
    },
    Known {
        display_name: "Yandex Mail",
        domains: &["yandex.com", "yandex.ru", "ya.ru"],
        imap_host: "imap.yandex.com",
        smtp_host: "smtp.yandex.com",
        smtp_starttls: false,
    },
    Known {
        display_name: "AOL",
        domains: &["aol.com", "aim.com"],
        imap_host: "imap.aol.com",
        smtp_host: "smtp.aol.com",
        smtp_starttls: false,
    },
];

/// Works out where `email`'s mail lives.
///
/// Blocking — it opens sockets — and meant for a worker thread.
pub fn discover(email: &str) -> Result<Discovered> {
    let domain = domain_of(email)?;

    if let Some(found) = from_table(&domain, email) {
        return Ok(found);
    }
    if let Some(found) = from_autoconfig(&domain, email) {
        return Ok(found);
    }
    if let Some(found) = from_guess(&domain, email) {
        return Ok(found);
    }
    Err(Error::Discovery(format!(
        "nothing at {domain} answered, so its settings have to be entered by hand"
    )))
}

/// The table only, with no network at all.
///
/// Separate because a UI can call it on every keystroke while somebody types
/// their address, and fill the form in as soon as the domain is recognisable.
#[must_use]
pub fn known(email: &str) -> Option<Discovered> {
    let domain = domain_of(email).ok()?;
    from_table(&domain, email)
}

fn from_table(domain: &str, email: &str) -> Option<Discovered> {
    let entry = KNOWN
        .iter()
        .find(|known| known.domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))?;

    Some(Discovered {
        display_name: entry.display_name.to_owned(),
        imap_host: entry.imap_host.to_owned(),
        imap_port: 993,
        imap_security: Security::Tls,
        smtp_host: entry.smtp_host.to_owned(),
        smtp_port: if entry.smtp_starttls { 587 } else { 465 },
        smtp_security: if entry.smtp_starttls {
            Security::StartTls
        } else {
            Security::Tls
        },
        username: email.to_owned(),
        source: Source::Known,
    })
}

/// The canonical autoconfig locations, in Thunderbird's own probe order.
///
/// The provider's own document first — it is authoritative and current — then
/// the well-known path on the domain itself, then Mozilla's ISPDB, which holds
/// providers that never published one and answers when a provider's own host is
/// down.
fn autoconfig_urls(domain: &str, email: &str) -> [String; 3] {
    // The *domain* is validated, but the local part is not and can carry URL
    // metacharacters — `#` truncates to a fragment, `&` injects a parameter.
    let email = percent_encode(email);
    [
        format!("https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={email}"),
        format!(
            "https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress={email}"
        ),
        format!("https://autoconfig.thunderbird.net/v1.1/{domain}"),
    ]
}

fn from_autoconfig(domain: &str, email: &str) -> Option<Discovered> {
    let client = reqwest::blocking::Client::builder()
        .timeout(STAGE_TIMEOUT)
        // No redirects. A redirect is the far end choosing the next URL, which
        // is exactly the thing the guard on the first one exists to prevent.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;

    for url in autoconfig_urls(domain, email) {
        let Ok(response) = client.get(&url).send() else {
            continue;
        };
        if !response.status().is_success() {
            // A 404 is the ordinary answer here, not a failure.
            continue;
        }
        let mut body = String::new();
        if response
            .take(MAX_DOCUMENT)
            .read_to_string(&mut body)
            .is_err()
        {
            continue;
        }
        if let Some(found) = parse_autoconfig(&body, email) {
            return Some(found);
        }
    }
    None
}

/// Reads the parts of a `clientConfig` document that say where to connect.
///
/// Tolerant on purpose: these documents are written by hand by hundreds of
/// providers, and one with an unexpected element in it is still telling us the
/// hostname. Anything not understood is skipped rather than failing the parse.
fn parse_autoconfig(xml: &str, email: &str) -> Option<Discovered> {
    use quick_xml::events::Event;

    #[derive(Default)]
    struct Server {
        host: String,
        port: u16,
        security: Option<Security>,
        username: String,
    }

    let mut reader = quick_xml::Reader::from_str(xml);
    let mut display_name = String::new();
    let mut imap = Server::default();
    let mut smtp = Server::default();
    let mut in_incoming = false;
    let mut in_outgoing = false;
    let mut incoming_is_imap = false;
    let mut element = String::new();
    let mut buffer = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(start)) => {
                element = String::from_utf8_lossy(start.local_name().as_ref()).into_owned();
                match element.as_str() {
                    "incomingServer" => {
                        in_incoming = true;
                        // Only IMAP is usable here. A POP3 block is a real
                        // answer to a different question.
                        incoming_is_imap = start.attributes().flatten().any(|attribute| {
                            attribute.key.local_name().as_ref() == b"type"
                                && attribute.value.as_ref() == b"imap"
                        });
                    }
                    "outgoingServer" => in_outgoing = true,
                    _ => {}
                }
            }
            Ok(Event::End(end)) => {
                match String::from_utf8_lossy(end.local_name().as_ref()).as_ref() {
                    "incomingServer" => in_incoming = false,
                    "outgoingServer" => in_outgoing = false,
                    _ => {}
                }
                element.clear();
            }
            Ok(Event::Text(text)) => {
                let value = text.decode().unwrap_or_default().trim().to_string();
                if value.is_empty() {
                    continue;
                }
                let target = if in_incoming && incoming_is_imap {
                    Some(&mut imap)
                } else if in_outgoing {
                    Some(&mut smtp)
                } else {
                    if element == "displayName" && display_name.is_empty() {
                        display_name = value.clone();
                    }
                    None
                };
                if let Some(server) = target {
                    match element.as_str() {
                        "hostname" => server.host = value,
                        "port" => server.port = value.parse().unwrap_or(0),
                        "socketType" => server.security = socket_security(&value),
                        "username" => server.username = expand_username(&value, email),
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buffer.clear();
    }

    // A document that names neither is not an answer.
    if !is_probe_host(&imap.host) || !is_probe_host(&smtp.host) {
        return None;
    }

    // Ports are defaulted *before* the security is derived from them. The other
    // order reads a port of zero and concludes STARTTLS, which then fails on
    // 993 — for a document that simply omitted the port, which plenty do.
    let imap_port = if imap.port == 0 { 993 } else { imap.port };
    let smtp_port = if smtp.port == 0 { 465 } else { smtp.port };

    Some(Discovered {
        display_name,
        imap_security: imap
            .security
            .unwrap_or_else(|| security_for_port(imap_port)),
        smtp_security: smtp
            .security
            .unwrap_or_else(|| security_for_port(smtp_port)),
        imap_port,
        smtp_port,
        username: if imap.username.is_empty() {
            email.to_owned()
        } else {
            imap.username
        },
        imap_host: imap.host,
        smtp_host: smtp.host,
        source: Source::Autoconfig,
    })
}

fn socket_security(socket_type: &str) -> Option<Security> {
    match socket_type.to_ascii_uppercase().as_str() {
        "SSL" | "TLS" => Some(Security::Tls),
        "STARTTLS" => Some(Security::StartTls),
        // `plain` is a real value in these documents and it is never something
        // to configure silently. Treated as "unspecified" so the port
        // convention decides, which at least gets encryption.
        _ => None,
    }
}

/// The convention when a document does not say: 993 and 465 are wrapped TLS,
/// everything else is STARTTLS.
fn security_for_port(port: u16) -> Security {
    match port {
        993 | 465 => Security::Tls,
        _ => Security::StartTls,
    }
}

/// `%EMAILADDRESS%` and `%EMAILLOCALPART%`, which is how autoconfig says
/// "log in with the whole address" or "just the bit before the @".
fn expand_username(template: &str, email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email);
    template
        .replace("%EMAILADDRESS%", email)
        .replace("%EMAILLOCALPART%", local)
}

/// The last resort: the two hostnames self-hosted mail nearly always uses,
/// confirmed by actually connecting.
///
/// Probed rather than asserted. A guess offered as fact is worse than no guess,
/// because it fails later and looks like a rejected password.
fn from_guess(domain: &str, email: &str) -> Option<Discovered> {
    for prefix in ["imap.", "mail.", ""] {
        let host = format!("{prefix}{domain}");
        if !is_probe_host(&host) || !can_connect(&host, 993) {
            continue;
        }
        // The submission host is *not* probed separately: a provider answering
        // on 993 at `imap.x` answers on 465 at `smtp.x` in nearly every case,
        // and a second round of connects doubles the wait to confirm something
        // the send path will report anyway.
        let smtp_host = match prefix {
            "imap." => format!("smtp.{domain}"),
            other => format!("{other}{domain}"),
        };
        return Some(Discovered {
            display_name: String::new(),
            imap_host: host,
            imap_port: 993,
            imap_security: Security::Tls,
            smtp_host,
            smtp_port: 465,
            smtp_security: Security::Tls,
            username: email.to_owned(),
            source: Source::Guessed,
        });
    }
    None
}

/// Does something accept a TCP connection there?
///
/// Not a TLS handshake and not a greeting: this is deciding whether to *offer*
/// a hostname, and "something is listening on the IMAP port" is the whole
/// question. Anything more would be doing the login's job slower.
fn can_connect(host: &str, port: u16) -> bool {
    let Ok(addresses) = (host, port).to_socket_addrs() else {
        return false;
    };
    addresses
        .filter(|address| is_public(address.ip()))
        .any(|address| TcpStream::connect_timeout(&address, STAGE_TIMEOUT).is_ok())
}

/// The domain part of an address, if it is one we may safely probe.
///
/// This is the guard. Everything downstream builds URLs and opens sockets from
/// what this returns, so it admits only shapes that are unambiguously a public
/// hostname — and rejects the rest rather than sanitising them, because a
/// silently rewritten host is one nobody can debug.
pub fn domain_of(email: &str) -> Result<String> {
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::Discovery("that is not an email address".into()));
    };
    if local.is_empty() || domain.is_empty() {
        return Err(Error::Discovery("that is not an email address".into()));
    }
    // Characters that would let the "domain" smuggle URL syntax — a port, a
    // path, a query, userinfo, an IPv6 literal — into a probe URL.
    if domain.bytes().any(|b| {
        matches!(
            b,
            b':' | b'/' | b'\\' | b'?' | b'#' | b'@' | b'[' | b']' | b' ' | b'\t'
        ) || b.is_ascii_control()
    }) {
        return Err(Error::Discovery("that domain cannot be looked up".into()));
    }
    if !domain.contains('.') {
        return Err(Error::Discovery("that domain cannot be looked up".into()));
    }
    // All-numeric hosts are refused whatever they resolve to. `Ipv4Addr` parses
    // strict dotted-quad, but the system resolver happily expands `127.1` —
    // so shape, not parsing, is what decides. Refusing public literals as
    // collateral is fine: mail-by-IP is not a thing people do.
    if domain.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(Error::Discovery(
            "an address at a bare IP cannot be looked up".into(),
        ));
    }
    Ok(domain.to_ascii_lowercase())
}

/// A host derived during discovery — an autoconfig hostname, a guess — before
/// anything is probed or offered.
///
/// An autoconfig document is only as trustworthy as whoever published it, and
/// one naming `localhost` must not widen the probe surface past what the
/// primary guard would have admitted.
fn is_probe_host(host: &str) -> bool {
    if host.is_empty() || !host.contains('.') {
        return false;
    }
    if host.bytes().any(|b| {
        matches!(
            b,
            b':' | b'/' | b'\\' | b'?' | b'#' | b'@' | b'[' | b']' | b' '
        ) || b.is_ascii_control()
    }) {
        return false;
    }
    // A name is fine; an address literal has to be a public one.
    match host.parse::<Ipv4Addr>() {
        Ok(v4) => is_public_v4(v4),
        Err(_) => true,
    }
}

fn is_public(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_public_v4(v4),
        std::net::IpAddr::V6(v6) => {
            !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast())
                // fc00::/7, unique local — the v6 equivalent of RFC 1918.
                && (v6.segments()[0] & 0xfe00) != 0xfc00
                // fe80::/10, link-local.
                && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

/// Is this address routable on the public internet?
///
/// Rejects loopback, RFC 1918, link-local, multicast, broadcast, the
/// unspecified address, RFC 5737 documentation ranges, and RFC 6598
/// carrier-grade NAT.
fn is_public_v4(v4: Ipv4Addr) -> bool {
    if v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
    {
        return false;
    }
    let octets = v4.octets();
    !(octets[0] == 100 && (octets[1] & 0xC0) == 64)
}

/// Percent-encodes everything a URL query would otherwise read as syntax.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_answers_for_the_providers_most_people_have() {
        let found = known("someone@gmail.com").expect("gmail is in the table");
        assert_eq!(found.imap_host, "imap.gmail.com");
        assert_eq!(found.smtp_host, "smtp.gmail.com");
        assert_eq!(found.imap_port, 993);
        assert_eq!(found.source, Source::Known);
        assert_eq!(found.username, "someone@gmail.com");
    }

    #[test]
    fn provider_aliases_resolve_to_the_same_settings() {
        // Somebody with a hotmail.com address is on Outlook and should not have
        // to know that.
        for address in ["a@hotmail.com", "a@live.com", "a@msn.com", "a@OUTLOOK.COM"] {
            let found = known(address).unwrap_or_else(|| panic!("{address}"));
            assert_eq!(found.imap_host, "outlook.office365.com", "{address}");
        }
        assert_eq!(
            known("a@googlemail.com").unwrap().imap_host,
            "imap.gmail.com"
        );
    }

    #[test]
    fn a_provider_that_wants_starttls_gets_the_submission_port_for_it() {
        let found = known("a@outlook.com").unwrap();
        assert_eq!(found.smtp_port, 587);
        assert_eq!(found.smtp_security, Security::StartTls);

        let found = known("a@fastmail.com").unwrap();
        assert_eq!(found.smtp_port, 465);
        assert_eq!(found.smtp_security, Security::Tls);
    }

    #[test]
    fn an_unknown_domain_is_not_answered_from_the_table() {
        assert!(known("a@example.com").is_none());
    }

    #[test]
    fn the_guard_refuses_everything_that_could_probe_a_private_network() {
        // Without this, "add an account" is a way to make somebody's mail
        // client scan their own network and report back.
        for address in [
            "evil@127.0.0.1",
            "evil@10.0.0.1",
            "evil@192.168.1.1",
            "evil@169.254.1.1",
            "evil@127.1",
            "evil@localhost",
            "evil@host:8080",
            "evil@host/path",
            "evil@host#frag",
            "evil@[::1]",
            "evil@",
            "@example.com",
            "not-an-address",
            "two@at@signs.com",
        ] {
            assert!(
                domain_of(address).is_err(),
                "{address} was accepted for probing"
            );
        }
    }

    #[test]
    fn the_guard_admits_ordinary_domains_and_folds_them() {
        assert_eq!(domain_of("a@Example.COM").unwrap(), "example.com");
        assert_eq!(
            domain_of("first.last+tag@mail.example.co.uk").unwrap(),
            "mail.example.co.uk"
        );
    }

    #[test]
    fn a_derived_host_is_checked_as_strictly_as_the_typed_one() {
        // An autoconfig document is only as trustworthy as whoever published
        // it, and one naming localhost must not widen the probe surface.
        assert!(is_probe_host("imap.example.com"));
        assert!(!is_probe_host("localhost"));
        assert!(!is_probe_host("127.0.0.1"));
        assert!(!is_probe_host("10.0.0.5"));
        assert!(!is_probe_host("host:993"));
        assert!(!is_probe_host(""));
        assert!(
            is_probe_host("8.8.8.8"),
            "a public literal is admissible here"
        );
    }

    #[test]
    fn an_autoconfig_document_is_read_for_what_it_says() {
        let xml = r#"<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.com">
    <displayName>Example Mail</displayName>
    <incomingServer type="pop3">
      <hostname>pop.example.com</hostname><port>995</port><socketType>SSL</socketType>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>imap.example.com</hostname>
      <port>143</port>
      <socketType>STARTTLS</socketType>
      <username>%EMAILLOCALPART%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.example.com</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>"#;

        let found = parse_autoconfig(xml, "ada@example.com").expect("parsed");
        assert_eq!(found.display_name, "Example Mail");
        assert_eq!(found.imap_host, "imap.example.com");
        assert_eq!(found.imap_port, 143);
        assert_eq!(found.imap_security, Security::StartTls);
        assert_eq!(
            found.username, "ada",
            "%EMAILLOCALPART% was not expanded, so the login will be rejected"
        );
        assert_eq!(found.smtp_host, "smtp.example.com");
        assert_eq!(found.smtp_port, 465);
        assert_eq!(found.smtp_security, Security::Tls);
        assert_eq!(found.source, Source::Autoconfig);
    }

    #[test]
    fn a_pop3_only_document_is_not_an_answer() {
        // It is a real answer to a different question.
        let xml = r#"<clientConfig><emailProvider>
            <incomingServer type="pop3"><hostname>pop.example.com</hostname></incomingServer>
            <outgoingServer type="smtp"><hostname>smtp.example.com</hostname></outgoingServer>
        </emailProvider></clientConfig>"#;
        assert!(parse_autoconfig(xml, "a@example.com").is_none());
    }

    #[test]
    fn an_autoconfig_document_naming_a_private_host_is_refused() {
        let xml = r#"<clientConfig><emailProvider>
            <incomingServer type="imap"><hostname>127.0.0.1</hostname><port>993</port></incomingServer>
            <outgoingServer type="smtp"><hostname>127.0.0.1</hostname><port>465</port></outgoingServer>
        </emailProvider></clientConfig>"#;
        assert!(parse_autoconfig(xml, "a@example.com").is_none());
    }

    #[test]
    fn a_document_that_omits_ports_falls_back_to_the_convention() {
        let xml = r#"<clientConfig><emailProvider>
            <incomingServer type="imap"><hostname>imap.example.com</hostname></incomingServer>
            <outgoingServer type="smtp"><hostname>smtp.example.com</hostname></outgoingServer>
        </emailProvider></clientConfig>"#;
        let found = parse_autoconfig(xml, "a@example.com").unwrap();
        assert_eq!(found.imap_port, 993);
        assert_eq!(found.imap_security, Security::Tls);
        assert_eq!(
            found.username, "a@example.com",
            "the whole address by default"
        );
    }

    #[test]
    fn rubbish_does_not_parse_into_a_configuration() {
        assert!(parse_autoconfig("", "a@example.com").is_none());
        assert!(parse_autoconfig("<html><body>404</body></html>", "a@example.com").is_none());
        assert!(parse_autoconfig("<clientConfig", "a@example.com").is_none());
    }

    #[test]
    fn the_local_part_cannot_inject_url_syntax_into_a_probe() {
        // The domain is guarded; the local part is not, and `#` truncates a URL
        // to a fragment while `&` injects a parameter.
        let urls = autoconfig_urls("example.com", "a#b&c=d@example.com");
        for url in &urls {
            assert!(!url.contains('#'), "{url}");
            assert!(
                url.matches('&').count() == 0,
                "an extra parameter was injected: {url}"
            );
        }
    }

    #[test]
    fn the_probe_order_puts_the_provider_first_and_mozilla_last() {
        // The provider's own document is authoritative and current; the ISPDB
        // is the mirror for providers that never published one.
        let urls = autoconfig_urls("example.com", "a@example.com");
        assert!(urls[0].starts_with("https://autoconfig.example.com/"));
        assert!(urls[1].starts_with("https://example.com/.well-known/"));
        assert!(urls[2].starts_with("https://autoconfig.thunderbird.net/"));
        assert!(urls.iter().all(|url| url.starts_with("https://")));
    }
}

// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! A local mail server with a self-signed certificate, reached over STARTTLS.
//!
//! This is the shape Proton Mail Bridge has: IMAP and SMTP on `127.0.0.1`,
//! STARTTLS required, and a certificate no authority could have issued. The
//! scripted servers elsewhere in this directory are plaintext, so none of them
//! would notice if a handshake with such a server stopped working — and it
//! fails as a transport error on an account whose only server is this one.
//!
//! The other half matters as much: the same certificate presented under a
//! *name* must still be refused, or the exemption has quietly become "any
//! certificate is fine".

use std::io::{BufRead as _, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use cosmic_pim_mail::Credentials;
use cosmic_pim_mail::compose::Draft;
use cosmic_pim_mail::imap::{Endpoint, Security, Session, is_loopback};
use cosmic_pim_mail::model::Mailbox;
use cosmic_pim_mail::smtp::{SmtpEndpoint, send};

/// A certificate for `127.0.0.1` signed by nobody but itself, generated per
/// run so that no private key lives in the repository.
fn self_signed() -> native_tls::TlsAcceptor {
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509, X509NameBuilder};

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("curve");
    let key = PKey::from_ec_key(EcKey::generate(&group).expect("key")).expect("pkey");

    let mut name = X509NameBuilder::new().expect("name");
    name.append_entry_by_text("CN", "127.0.0.1").expect("cn");
    let name = name.build();

    let mut cert = X509::builder().expect("builder");
    cert.set_version(2).expect("version");
    cert.set_subject_name(&name).expect("subject");
    cert.set_issuer_name(&name).expect("issuer");
    cert.set_pubkey(&key).expect("pubkey");
    cert.set_not_before(&Asn1Time::days_from_now(0).expect("now"))
        .expect("not before");
    cert.set_not_after(&Asn1Time::days_from_now(1).expect("tomorrow"))
        .expect("not after");
    cert.sign(&key, MessageDigest::sha256()).expect("sign");
    let cert = cert.build();

    let identity = native_tls::Identity::from_pkcs8(
        &cert.to_pem().expect("cert pem"),
        &key.private_key_to_pem_pkcs8().expect("key pem"),
    )
    .expect("identity");
    native_tls::TlsAcceptor::new(identity).expect("acceptor")
}

/// One command line off the wire, without its line ending. `None` at EOF.
fn read_command(stream: &mut impl Read) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => line.push(byte[0]),
            _ if line.is_empty() => return None,
            _ => break,
        }
    }
    Some(String::from_utf8_lossy(&line).trim_end().to_owned())
}

/// A server that has accepted one connection and reports what it was sent
/// once TLS was up.
struct Local {
    port: u16,
    after_tls: mpsc::Receiver<Vec<String>>,
}

impl Local {
    fn start(serve: fn(TcpStream, native_tls::TlsAcceptor) -> Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let acceptor = self_signed();
        let (sender, after_tls) = mpsc::channel();
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = sender.send(serve(stream, acceptor));
            }
        });
        Self { port, after_tls }
    }

    fn commands_inside_tls(&self) -> Vec<String> {
        self.after_tls
            .recv_timeout(Duration::from_secs(10))
            .expect("the server never finished a session")
    }
}

/// IMAP: greeting, CAPABILITY advertising STARTTLS, the upgrade, then
/// whatever the client says inside it.
fn serve_imap(stream: TcpStream, acceptor: native_tls::TlsAcceptor) -> Vec<String> {
    let mut plain = stream;
    let _ = write!(plain, "* OK local server ready\r\n");

    loop {
        let Some(command) = read_command(&mut plain) else {
            return Vec::new();
        };
        let (tag, verb) = command.split_once(' ').unwrap_or((&command, ""));
        if verb.eq_ignore_ascii_case("CAPABILITY") {
            let _ = write!(
                plain,
                "* CAPABILITY IMAP4rev1 STARTTLS\r\n{tag} OK done\r\n"
            );
        } else if verb.eq_ignore_ascii_case("STARTTLS") {
            let _ = write!(plain, "{tag} OK begin TLS\r\n");
            break;
        } else {
            let _ = write!(plain, "{tag} BAD STARTTLS first\r\n");
        }
    }

    let Ok(mut tls) = acceptor.accept(plain) else {
        return Vec::new();
    };
    let mut seen = Vec::new();
    while let Some(command) = read_command(&mut tls) {
        let (tag, verb) = command.split_once(' ').unwrap_or((&command, ""));
        let verb = verb.to_ascii_uppercase();
        seen.push(verb.clone());
        if verb.starts_with("CAPABILITY") {
            let _ = write!(tls, "* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n");
        } else if verb.starts_with("LOGOUT") {
            let _ = write!(tls, "* BYE\r\n{tag} OK done\r\n");
            break;
        } else {
            let _ = write!(tls, "{tag} OK done\r\n");
        }
    }
    seen
}

/// SMTP: the same conversation `live_send.rs` scripts, with the upgrade in
/// the middle.
fn serve_smtp(stream: TcpStream, acceptor: native_tls::TlsAcceptor) -> Vec<String> {
    let mut out = stream.try_clone().expect("clone");
    let mut reader = BufReader::new(stream);
    let _ = write!(out, "220 local ESMTP\r\n");

    let mut line = String::new();
    loop {
        line.clear();
        if !reader.read_line(&mut line).is_ok_and(|n| n > 0) {
            return Vec::new();
        }
        let upper = line.trim_end().to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            let _ = write!(out, "250-local\r\n250 STARTTLS\r\n");
        } else if upper == "STARTTLS" {
            let _ = write!(out, "220 begin TLS\r\n");
            break;
        } else {
            let _ = write!(out, "530 5.7.0 STARTTLS first\r\n");
        }
    }

    // Nothing is buffered past the 220: the client waits for it before it
    // starts the handshake.
    let Ok(mut tls) = acceptor.accept(reader.into_inner()) else {
        return Vec::new();
    };
    let mut seen = Vec::new();
    let mut in_data = false;
    while let Some(command) = read_command(&mut tls) {
        if in_data {
            if command == "." {
                in_data = false;
                let _ = write!(tls, "250 2.0.0 queued\r\n");
            }
            continue;
        }
        let upper = command.to_ascii_uppercase();
        seen.push(upper.split(' ').next().unwrap_or_default().to_owned());
        if upper.starts_with("EHLO") {
            let _ = write!(tls, "250-local\r\n250 AUTH PLAIN LOGIN\r\n");
        } else if upper.starts_with("AUTH") {
            let _ = write!(tls, "235 2.7.0 ok\r\n");
        } else if upper == "DATA" {
            in_data = true;
            let _ = write!(tls, "354 go on\r\n");
        } else if upper == "QUIT" {
            let _ = write!(tls, "221 bye\r\n");
            break;
        } else {
            let _ = write!(tls, "250 ok\r\n");
        }
    }
    seen
}

fn password() -> Credentials {
    Credentials::Password("the-password-bridge-generated".into())
}

#[test]
fn imap_on_loopback_logs_in_through_a_self_signed_certificate() {
    let server = Local::start(serve_imap);
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: server.port,
        security: Security::StartTls,
        username: "ada@proton.me".into(),
    };

    let session = Session::connect(&endpoint, &password());
    assert!(session.is_ok(), "the handshake was refused: {session:?}");
    drop(session);

    let seen = server.commands_inside_tls();
    assert!(
        seen.iter().any(|command| command.starts_with("LOGIN")),
        "the password did not travel inside TLS; the server saw {seen:?}"
    );
}

#[test]
fn smtp_on_loopback_submits_through_a_self_signed_certificate() {
    let server = Local::start(serve_smtp);
    let endpoint = SmtpEndpoint {
        host: "127.0.0.1".into(),
        port: server.port,
        security: Security::StartTls,
        username: "ada@proton.me".into(),
    };
    let mut draft = Draft::new(Mailbox {
        name: Some("Ada".into()),
        address: "ada@proton.me".into(),
    });
    draft.to.push(Mailbox {
        name: None,
        address: "grace@example.com".into(),
    });
    draft.subject = "Through Bridge".into();
    draft.body = "Hello.".into();

    let outcome = send(&endpoint, &password(), &draft);
    assert!(outcome.is_sent(), "not sent: {:?}", outcome.error());

    let seen = server.commands_inside_tls();
    assert!(
        seen.iter().any(|command| command == "AUTH"),
        "the password did not travel inside TLS; the server saw {seen:?}"
    );
}

#[test]
fn the_same_certificate_under_a_name_is_still_refused() {
    // `localhost` reaches the same socket, but it is a name: it goes through
    // a resolver, so the certificate is the only thing vouching for the far
    // end and a self-signed one vouches for nothing.
    let server = Local::start(serve_imap);
    let endpoint = Endpoint {
        host: "localhost".into(),
        port: server.port,
        security: Security::StartTls,
        username: "ada@proton.me".into(),
    };

    let session = Session::connect(&endpoint, &password());

    assert!(
        session.is_err(),
        "a self-signed certificate was accepted for a host that is not a loopback literal"
    );
}

#[test]
fn only_a_literal_loopback_address_counts() {
    assert!(is_loopback("127.0.0.1"));
    assert!(is_loopback("127.0.0.53"));
    assert!(is_loopback("::1"));

    assert!(!is_loopback("localhost"));
    assert!(!is_loopback("192.168.1.10"));
    assert!(!is_loopback("10.0.0.1"));
    assert!(!is_loopback("127.0.0.1.example.com"));
    assert!(!is_loopback("imap.fastmail.com"));
    assert!(!is_loopback(""));
}

#[test]
fn a_string_the_socket_layer_would_resolve_is_not_a_loopback_literal() {
    // Each of these looks like loopback to a person and is a *name* to
    // `connect`, which hands it to the resolver. Treating one as loopback
    // would switch the certificate check off for wherever that name is
    // answered with.
    for host in [
        "[::1]",
        "[127.0.0.1]",
        "[[127.0.0.1]]",
        " 127.0.0.1",
        "127.0.0.1 ",
        "127.0.0.1:1143",
        "127.1",
        "0x7f.0.0.1",
        "2130706433",
        "localhost.",
        "::ffff:127.0.0.1",
    ] {
        assert!(
            !is_loopback(host),
            "{host:?} was taken for a loopback literal"
        );
    }
}

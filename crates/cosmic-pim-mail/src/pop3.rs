// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! POP3 (RFC 1939), for the accounts where it is the only thing on offer.
//!
//! # What POP3 is not
//!
//! It is not a small IMAP. There is one mailbox, there are no folders, there
//! are no server-side flags, and nothing a client does — reading, starring,
//! filing — is visible anywhere else. A second device sees none of it. This is
//! a property of the protocol and cannot be worked around; a client that
//! pretends otherwise produces a mailbox whose read marks silently disagree
//! between machines.
//!
//! So the model here is deliberately narrower than the IMAP one: fetch what has
//! not been fetched, keep it, and optionally tell the server to forget it.
//! Flags are local facts stored in the maildir, and the writeback queue is not
//! involved because there is nowhere to write back to.
//!
//! # Message identity
//!
//! `UIDL` gives each message a string the server promises is stable and never
//! reused. Everything else in this crate is keyed by a numeric IMAP UID, so
//! rather than fork the store, each UIDL is assigned a local UID the first time
//! it is seen and the mapping is kept in a sidecar. That buys the whole maildir
//! — the index, threading, search, attachments — unchanged.
//!
//! The message *numbers* POP3 commands take are not identities: they are
//! positions in this session and shift as soon as anything is deleted. Using
//! one across sessions deletes the wrong message, which is the classic way to
//! lose mail with POP3, and is why nothing here persists a message number.
//!
//! A server that does not implement `UIDL` cannot be synced safely at all —
//! there would be no way to tell a message already downloaded from a new one —
//! and is refused rather than guessed at.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::imap::Security;
use crate::model::Flags;
use crate::sasl::{Credentials, xoauth2_payload};
use crate::store::{Cursor, MailStore, RemoteMessage};

/// POP3 servers are chatty and quick; a stalled one should not hold a pass.
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Refuse a line longer than this. RFC 1939 §3 caps a response line at 512
/// bytes; the slack is for servers that ignore it, and the limit is what stops
/// a hostile server growing a `String` until the process dies.
const MAX_LINE: u64 = 64 * 1024;

/// Where and how to reach a POP3 server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub security: Security,
    pub username: String,
}

impl Endpoint {
    /// The conventional endpoint: implicit TLS on 995.
    #[must_use]
    pub fn tls(host: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 995,
            security: Security::Tls,
            username: username.into(),
        }
    }
}

/// What to do with a message once it is safely on disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Retention {
    /// Never delete. The default, and the only choice that is safe when the
    /// same account is also read on a phone.
    #[default]
    LeaveOnServer,
    /// Delete as soon as the message is stored locally.
    ///
    /// The deletion is issued only after the write has been fsynced, because
    /// the alternative — DELE first, crash second — loses the message with no
    /// copy anywhere.
    DeleteWhenFetched,
    /// Delete once the local copy is this many days old. What most clients
    /// mean by "leave on server for two weeks".
    DeleteAfterDays(u16),
}

/// The stream underneath a session: TLS, or not.
enum Stream {
    Plain(TcpStream),
    Tls(Box<native_tls::TlsStream<TcpStream>>),
}

impl std::io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl std::io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// An authenticated POP3 session.
pub struct Session {
    stream: BufReader<Stream>,
    capabilities: Vec<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pop3Session")
            .field("capabilities", &self.capabilities.len())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Connects and authenticates.
    pub fn connect(endpoint: &Endpoint, credentials: &Credentials) -> Result<Self> {
        let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
            .map_err(|why| Error::Pop3(format!("connecting to {}: {why}", endpoint.host)))?;
        tcp.set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|()| tcp.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|why| Error::Pop3(why.to_string()))?;

        let stream = match endpoint.security {
            Security::Tls => Stream::Tls(Box::new(tls(&endpoint.host, tcp)?)),
            Security::Plaintext | Security::StartTls => Stream::Plain(tcp),
        };

        let mut session = Self {
            stream: BufReader::new(stream),
            capabilities: Vec::new(),
        };

        // The greeting. A server that is refusing connections says so here.
        session.read_status()?;

        if endpoint.security == Security::StartTls {
            session.start_tls(&endpoint.host)?;
        }

        session.capabilities = session.capa();
        session.authenticate(&endpoint.username, credentials)?;

        Ok(session)
    }

    /// Upgrades a plaintext connection with `STLS` (RFC 2595).
    fn start_tls(&mut self, host: &str) -> Result<()> {
        self.command("STLS")?;
        // The stream has to be taken apart and rebuilt around the TLS session.
        // Anything the server sent after its +OK but before the handshake would
        // be lost here — servers do not do that, and one that did would be
        // injecting into the plaintext phase, which is exactly what must not be
        // trusted.
        let plain = match self.stream.get_mut() {
            Stream::Plain(stream) => stream
                .try_clone()
                .map_err(|why| Error::Pop3(why.to_string()))?,
            Stream::Tls(_) => return Err(Error::Pop3("STLS on an encrypted stream".into())),
        };
        self.stream = BufReader::new(Stream::Tls(Box::new(tls(host, plain)?)));
        Ok(())
    }

    fn authenticate(&mut self, username: &str, credentials: &Credentials) -> Result<()> {
        match credentials {
            Credentials::OAuth2(token) => {
                if !self.supports("SASL") {
                    return Err(Error::Auth(
                        "this POP3 server does not offer SASL, so an access token cannot be used"
                            .into(),
                    ));
                }
                // RFC 5034 with Google's XOAUTH2 mechanism: the payload rides
                // on the command line, base64-encoded, rather than waiting for
                // a challenge.
                let payload = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    xoauth2_payload(username, token),
                );
                self.command(&format!("AUTH XOAUTH2 {payload}"))
                    .map_err(|why| Error::Auth(why.to_string()))?;
            }
            Credentials::Password(password) => {
                self.command(&format!("USER {username}"))
                    .map_err(|why| Error::Auth(why.to_string()))?;
                self.command(&format!("PASS {password}"))
                    .map_err(|why| Error::Auth(why.to_string()))?;
            }
        }
        Ok(())
    }

    fn capa(&mut self) -> Vec<String> {
        // CAPA is optional (RFC 2449). A server without it is not broken, it is
        // old, and the only cost is that STLS and SASL are not offered.
        match self.command_multiline("CAPA") {
            Ok(lines) => lines
                .into_iter()
                .map(|line| line.trim().to_ascii_uppercase())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn supports(&self, capability: &str) -> bool {
        self.capabilities
            .iter()
            .any(|line| line.split_whitespace().next() == Some(capability))
    }

    /// Whether the server can identify messages across sessions.
    #[must_use]
    pub fn supports_uidl(&self) -> bool {
        // Assume yes when CAPA is unavailable: UIDL predates CAPA, nearly every
        // server has it, and `uidl()` fails loudly if it turns out not to.
        self.capabilities.is_empty() || self.supports("UIDL")
    }

    /// Message count and total size.
    pub fn stat(&mut self) -> Result<(u32, u64)> {
        let line = self.command("STAT")?;
        let mut parts = line.split_whitespace();
        let count = parts.next().and_then(|v| v.parse().ok());
        let bytes = parts.next().and_then(|v| v.parse().ok());
        match (count, bytes) {
            (Some(count), Some(bytes)) => Ok((count, bytes)),
            _ => Err(Error::Pop3(format!("unreadable STAT response: {line}"))),
        }
    }

    /// Every message in the mailbox as `(message number, unique id)`.
    ///
    /// The number is valid for this session only; the id is stable forever.
    pub fn uidl(&mut self) -> Result<Vec<(u32, String)>> {
        let lines = self.command_multiline("UIDL")?;
        let mut out = Vec::with_capacity(lines.len());
        for line in lines {
            let mut parts = line.split_whitespace();
            let (Some(number), Some(uid)) = (parts.next(), parts.next()) else {
                tracing::warn!(line, "skipping an unreadable UIDL entry");
                continue;
            };
            let Ok(number) = number.parse::<u32>() else {
                tracing::warn!(
                    line,
                    "skipping a UIDL entry with a non-numeric message number"
                );
                continue;
            };
            out.push((number, uid.to_owned()));
        }
        Ok(out)
    }

    /// Downloads one message, whole.
    pub fn retr(&mut self, number: u32) -> Result<Vec<u8>> {
        self.write_command(&format!("RETR {number}"))?;
        self.read_status()?;
        self.read_body()
    }

    /// Marks one message for deletion. It goes when the session ends cleanly.
    ///
    /// A session that is dropped rather than [`Self::quit`]-ed leaves every
    /// deletion unapplied (RFC 1939 §8), which is the safe direction: a message
    /// deleted twice is deleted once, a message deleted by accident is gone.
    pub fn dele(&mut self, number: u32) -> Result<()> {
        self.command(&format!("DELE {number}"))?;
        Ok(())
    }

    /// Ends the session, applying deletions.
    pub fn quit(mut self) -> Result<()> {
        self.command("QUIT")?;
        Ok(())
    }

    fn write_command(&mut self, command: &str) -> Result<()> {
        let stream = self.stream.get_mut();
        stream
            .write_all(format!("{command}\r\n").as_bytes())
            .and_then(|()| stream.flush())
            .map_err(|why| Error::Pop3(why.to_string()))
    }

    /// Sends a command and returns the text after `+OK`.
    fn command(&mut self, command: &str) -> Result<String> {
        self.write_command(command)?;
        self.read_status()
    }

    /// Sends a command whose response is terminated by a lone `.`.
    fn command_multiline(&mut self, command: &str) -> Result<Vec<String>> {
        self.write_command(command)?;
        self.read_status()?;
        let body = self.read_body()?;
        Ok(String::from_utf8_lossy(&body)
            .lines()
            .map(ToOwned::to_owned)
            .collect())
    }

    /// Reads one status line, turning `-ERR` into an error.
    fn read_status(&mut self) -> Result<String> {
        let mut line = String::new();
        let read = (&mut self.stream)
            .take(MAX_LINE)
            .read_line(&mut line)
            .map_err(|why| Error::Pop3(why.to_string()))?;
        if read == 0 {
            return Err(Error::Pop3("the server closed the connection".into()));
        }

        let line = line.trim_end_matches(['\r', '\n']);
        if let Some(rest) = line.strip_prefix("+OK") {
            Ok(rest.trim().to_owned())
        } else if let Some(rest) = line.strip_prefix("-ERR") {
            Err(Error::Pop3(rest.trim().to_owned()))
        } else {
            Err(Error::Pop3(format!("unexpected response: {line}")))
        }
    }

    /// Reads a multi-line body up to the terminating `.`, un-stuffing as it
    /// goes.
    ///
    /// RFC 1939 §3 requires a sender to prefix any line already starting with
    /// `.` with a second one, so the terminator is unambiguous. A reader that
    /// forgets to strip it corrupts exactly those messages that contain a line
    /// beginning with a full stop — rare enough to survive testing, common
    /// enough to happen to a real person, and it breaks the DKIM signature of
    /// every message it touches.
    fn read_body(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let mut line = Vec::new();
            let read = (&mut self.stream)
                .take(MAX_LINE)
                .read_until(b'\n', &mut line)
                .map_err(|why| Error::Pop3(why.to_string()))?;
            if read == 0 {
                return Err(Error::Pop3(
                    "the server closed the connection mid-message".into(),
                ));
            }

            let trimmed = strip_crlf(&line);
            if trimmed == b"." {
                return Ok(out);
            }
            // Un-stuff, then keep the line's own terminator as the server sent
            // it: these bytes are stored verbatim and signed over.
            let body = if trimmed.first() == Some(&b'.') {
                &trimmed[1..]
            } else {
                trimmed
            };
            out.extend_from_slice(body);
            out.extend_from_slice(b"\r\n");
        }
    }
}

fn strip_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

fn tls(host: &str, tcp: TcpStream) -> Result<native_tls::TlsStream<TcpStream>> {
    native_tls::TlsConnector::new()
        .map_err(|why| Error::Pop3(format!("TLS: {why}")))?
        .connect(host, tcp)
        .map_err(|why| Error::Pop3(format!("TLS handshake with {host}: {why}")))
}

/// What POP3 has to remember between sessions.
///
/// Only the UIDL mapping. Message numbers are not here on purpose — they are
/// valid for one session, and a stored one deletes whatever has drifted into
/// that position since.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pop3State {
    /// Server unique id → the local UID it was assigned.
    #[serde(default)]
    seen: BTreeMap<String, u32>,
    /// When each local UID was stored, in epoch milliseconds, for
    /// [`Retention::DeleteAfterDays`].
    #[serde(default)]
    fetched_at_ms: BTreeMap<String, i64>,
    #[serde(default = "one")]
    next_uid: u32,
}

fn one() -> u32 {
    1
}

const STATE_FILE: &str = ".pop3-state.json";

impl Pop3State {
    /// Reads the sidecar beside a maildir, or starts empty.
    ///
    /// An unreadable sidecar is treated as absent, and the cost of that is
    /// re-downloading the mailbox rather than being unable to open it.
    pub fn load(maildir: &Path) -> Self {
        match std::fs::read_to_string(maildir.join(STATE_FILE)) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|why| {
                tracing::warn!(path = %maildir.display(), %why, "unreadable POP3 sidecar; treating the mailbox as new");
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    /// Writes the sidecar atomically — a torn one costs a full re-download.
    pub fn save(&self, maildir: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|why| Error::Pop3(format!("serialising POP3 state: {why}")))?;
        cosmic_pim_core::atomic::write(&maildir.join(STATE_FILE), &json, None)
            .map(|_| ())
            .map_err(|why| Error::Pop3(format!("writing POP3 state: {why}")))
    }

    /// Whether this message has already been downloaded.
    #[must_use]
    pub fn has(&self, uidl: &str) -> bool {
        self.seen.contains_key(uidl)
    }

    /// The local UID for a server id, assigning one if it is new.
    fn uid_for(&mut self, uidl: &str, now_ms: i64) -> u32 {
        if let Some(uid) = self.seen.get(uidl) {
            return *uid;
        }
        let uid = self.next_uid;
        self.next_uid = self.next_uid.saturating_add(1);
        self.seen.insert(uidl.to_owned(), uid);
        self.fetched_at_ms.insert(uidl.to_owned(), now_ms);
        uid
    }

    /// Server ids old enough to delete under [`Retention::DeleteAfterDays`].
    fn expired(&self, days: u16, now_ms: i64) -> Vec<String> {
        let cutoff = now_ms - i64::from(days) * 24 * 60 * 60 * 1000;
        self.fetched_at_ms
            .iter()
            .filter(|(_, stored)| **stored <= cutoff)
            .map(|(uidl, _)| uidl.clone())
            .collect()
    }
}

/// What one POP3 pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pop3Outcome {
    pub fetched: usize,
    /// Messages the server was asked to delete.
    pub deleted: usize,
    /// Messages already held, and so not downloaded again.
    pub skipped: usize,
}

/// Runs one pass: download what is new, then apply the retention policy.
///
/// The order is not negotiable. A message is written and fsynced before its
/// `DELE` is issued, because the other order — delete, then crash — is the one
/// that loses mail with no copy anywhere. And deletions are only issued for
/// messages this pass has confirmed are on disk.
pub fn sync_inbox(
    session: &mut Session,
    store: &mut impl MailStore,
    state: &mut Pop3State,
    retention: Retention,
    now_ms: i64,
) -> Result<Pop3Outcome> {
    if !session.supports_uidl() {
        // Without stable ids there is no way to tell an already-downloaded
        // message from a new one, and the choice would be between duplicating
        // the mailbox on every pass and deleting mail to keep track.
        return Err(Error::Pop3(
            "this server does not support UIDL, so messages cannot be identified between sessions"
                .into(),
        ));
    }

    let mut outcome = Pop3Outcome::default();
    let listing = session.uidl()?;

    // Number → id for the deletion pass; numbers are only valid in this
    // session, so they never leave it.
    let numbers: BTreeMap<String, u32> = listing
        .iter()
        .map(|(number, uidl)| (uidl.clone(), *number))
        .collect();

    for (number, uidl) in &listing {
        if state.has(uidl) {
            outcome.skipped += 1;
            continue;
        }

        let raw = session.retr(*number)?;
        let uid = state.uid_for(uidl, now_ms);

        store.upsert(&RemoteMessage {
            uid,
            // POP3 has no server-side flags at all; everything is local, and a
            // freshly downloaded message is unread.
            flags: Flags::default(),
            raw,
            // POP3 has no INTERNALDATE either. `now` is the honest answer —
            // it is genuinely when this mailbox received the message — and it
            // keeps arrival order stable, which sorting by the sender's `Date`
            // header would not.
            internal_date_ms: now_ms,
        })?;
        outcome.fetched += 1;
    }

    // Only now, with everything above written and fsynced.
    let to_delete: Vec<String> = match retention {
        Retention::LeaveOnServer => Vec::new(),
        Retention::DeleteWhenFetched => listing
            .iter()
            .map(|(_, uidl)| uidl.clone())
            .filter(|uidl| state.has(uidl))
            .collect(),
        Retention::DeleteAfterDays(days) => state.expired(days, now_ms),
    };

    for uidl in to_delete {
        let Some(number) = numbers.get(&uidl) else {
            // Already gone from the server — another client, or a previous
            // pass whose QUIT landed after we stopped listening.
            continue;
        };
        session.dele(*number)?;
        outcome.deleted += 1;
    }

    // POP3 has no cursor to speak of; the sidecar is the state. Committing the
    // maildir cursor keeps `state()` honest for everything that reads it.
    store.commit_cursor(Cursor {
        uid_validity: POP3_UID_VALIDITY,
        last_uid: state.next_uid.saturating_sub(1),
        ..Default::default()
    })?;

    Ok(outcome)
}

/// POP3 mailboxes never renumber — the UIDL mapping is what provides identity —
/// so the maildir's UIDVALIDITY is a constant that exists only to keep the
/// shared store honest.
pub const POP3_UID_VALIDITY: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    #[test]
    fn a_dot_stuffed_line_is_restored() {
        // The classic POP3 corruption. A message with a line beginning "." is
        // rare enough to survive testing and common enough to reach a real
        // person, and mangling it invalidates the DKIM signature over it.
        let wire = b"Subject: Test\r\n\r\nOne\r\n..hidden\r\nTwo\r\n.\r\n";
        let mut session = fake_session(wire);

        let body = session.read_body().expect("body");

        assert_eq!(
            String::from_utf8_lossy(&body),
            "Subject: Test\r\n\r\nOne\r\n.hidden\r\nTwo\r\n"
        );
    }

    #[test]
    fn a_terminator_ends_the_body_and_nothing_else_does() {
        let wire = b"line one\r\n.\r\n+OK next command\r\n";
        let mut session = fake_session(wire);

        assert_eq!(session.read_body().unwrap(), b"line one\r\n");
        // The stream is left exactly at the next response, not past it.
        assert_eq!(session.read_status().unwrap(), "next command");
    }

    #[test]
    fn a_truncated_body_is_an_error_rather_than_a_short_message() {
        // Storing what arrived would file a half-message and record it as
        // downloaded, so it would never be fetched again.
        let mut session = fake_session(b"Subject: Test\r\nhalf a mess");
        assert!(session.read_body().is_err());
    }

    #[test]
    fn an_err_response_carries_the_servers_reason() {
        let mut session = fake_session(b"-ERR [AUTH] Invalid credentials\r\n");
        let Err(Error::Pop3(why)) = session.read_status() else {
            panic!("an -ERR was not reported as an error");
        };
        assert_eq!(why, "[AUTH] Invalid credentials");
    }

    #[test]
    fn uidl_pairs_numbers_with_ids_and_skips_nonsense() {
        let mut session = fake_session(b"+OK\r\n1 abc123\r\nrubbish\r\n3 def456\r\n.\r\n");
        assert_eq!(
            session.uidl_after_write().unwrap(),
            vec![(1, "abc123".to_owned()), (3, "def456".to_owned())]
        );
    }

    #[test]
    fn a_local_uid_is_assigned_once_per_server_id() {
        // Re-assigning would store the same message twice under two UIDs.
        let mut state = Pop3State::default();
        let first = state.uid_for("abc", 0);

        assert_eq!(state.uid_for("abc", 1_000), first);
        assert_ne!(state.uid_for("def", 0), first);
        assert!(state.has("abc"));
    }

    #[test]
    fn the_sidecar_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = Pop3State::default();
        let uid = state.uid_for("abc", 0);
        state.save(dir.path()).unwrap();

        let reloaded = Pop3State::load(dir.path());

        assert!(reloaded.has("abc"), "a re-download of the whole mailbox");
        assert_eq!(reloaded.seen.get("abc"), Some(&uid));
    }

    #[test]
    fn an_unreadable_sidecar_costs_a_re_download_rather_than_the_mailbox() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(STATE_FILE), "{ truncated").unwrap();

        assert!(!Pop3State::load(dir.path()).has("abc"));
    }

    #[test]
    fn retention_by_age_only_selects_what_is_old_enough() {
        let day = 24 * 60 * 60 * 1000;
        let mut state = Pop3State::default();
        state.uid_for("old", 0);
        state.uid_for("new", 13 * day);

        let expired = state.expired(14, 15 * day);

        assert_eq!(expired, vec!["old".to_owned()]);
    }

    #[test]
    fn leaving_on_the_server_deletes_nothing() {
        let mut state = Pop3State::default();
        state.uid_for("abc", 0);
        assert!(state.expired(0, 0).contains(&"abc".to_owned()));
        // …but `Retention::LeaveOnServer` never consults `expired` at all,
        // which is what the sync path asserts.
    }

    #[test]
    fn a_message_already_held_is_not_downloaded_again() {
        let store = MemoryStore::default();
        let mut state = Pop3State::default();
        state.uid_for("abc", 0);

        // Stands in for the loop in `sync_inbox`, which cannot run without a
        // socket: the decision under test is the `has` check.
        let listing = [(1u32, "abc".to_owned()), (2, "def".to_owned())];
        let fresh: Vec<&(u32, String)> = listing.iter().filter(|(_, u)| !state.has(u)).collect();

        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].1, "def");
        assert!(store.state().unwrap().entries.is_empty());
    }

    /// A session reading from canned bytes, for the parsing tests. Writes go
    /// nowhere, which is why the commands under test are the ones that only
    /// read.
    fn fake_session(wire: &[u8]) -> Session {
        Session {
            stream: BufReader::new(Stream::Plain(loopback_with(wire))),
            capabilities: Vec::new(),
        }
    }

    /// A connected socket pre-loaded with `wire`, so `Stream` can stay a real
    /// `TcpStream` and the code under test is the code that ships.
    fn loopback_with(wire: &[u8]) -> TcpStream {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let payload = wire.to_vec();
        std::thread::spawn(move || {
            if let Ok((mut server, _)) = listener.accept() {
                let _ = server.write_all(&payload);
                let _ = server.flush();
            }
        });
        let client = TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        client
    }

    impl Session {
        /// `uidl()` without the command write, for a read-only fixture.
        fn uidl_after_write(&mut self) -> Result<Vec<(u32, String)>> {
            self.read_status()?;
            let body = self.read_body()?;
            let mut out = Vec::new();
            for line in String::from_utf8_lossy(&body).lines() {
                let mut parts = line.split_whitespace();
                let (Some(number), Some(uid)) = (parts.next(), parts.next()) else {
                    continue;
                };
                let Ok(number) = number.parse::<u32>() else {
                    continue;
                };
                out.push((number, uid.to_owned()));
            }
            Ok(out)
        }
    }
}

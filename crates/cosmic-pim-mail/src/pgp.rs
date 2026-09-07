// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0
//
// The PGP/MIME shapes, the detached-signature byte range, and the verdict
// ladder are ported from `src-tauri/src/pgp_mail.rs` in the Meltemi project.
// See NOTICE and LICENSING.md.

//! OpenPGP for reading mail: is this signed, by whom, and can it be opened.
//!
//! # What this does and does not do
//!
//! The read path only — verify a signature, decrypt a body, report a verdict.
//! Signing and encrypting on send are deliberately absent rather than
//! half-present: a composer that produces material this module cannot check
//! is worse than one that does not offer the button.
//!
//! Key *storage* is also absent, and that is a design choice rather than an
//! omission. Every function here takes the keys it needs as an argument, so
//! the module is pure, testable without a filesystem, and does not decide
//! where a secret key lives — a question the suite answers once, in
//! `cosmic-pim-accounts`, for every credential it holds.
//!
//! # Why verbatim storage is the precondition
//!
//! A detached signature covers the *exact bytes* of the MIME part it was
//! computed over: its headers, its transfer encoding, and the CRLFs around
//! it. Reconstructing that from a parsed model reproduces the text and not
//! the bytes, and the signature then fails — indistinguishable, from the
//! inside, from a real forgery.
//!
//! This crate stores the server's bytes untouched, an invariant argued for
//! DKIM long before PGP arrived. It turns out to be exactly what verification
//! needs, and it buys a state a reconstructing client can never honestly
//! report: [`Verdict::Invalid`]. Where the bytes are the originals, a
//! signature that does not match means the message was altered, and saying so
//! is safe. A client that re-serialises must answer "cannot tell" to every
//! failure, because that is all it knows.
//!
//! # The verdict ladder
//!
//! Five states, because collapsing any two of them lies to the reader:
//! *unsigned* is not *unknown signer*, and *unknown signer* is very much not
//! *verified*. The distinction that matters most is between
//! [`Verdict::UnknownSigner`] — a signature this device has no key to check —
//! and [`Verdict::Invalid`], a signature that was checked and failed. The
//! first is ordinary; the second means someone changed the message.

use mail_parser::{MessageParser, MimeHeaders as _};
use pgp::composed::{Deserializable as _, DetachedSignature, Message, SignedPublicKey};
use pgp::types::{KeyDetails as _, Password};

/// A public key and the address it was accepted for.
///
/// The binding is the point: a signature proves the holder of *some* key
/// signed the bytes, and only the address this key was imported for turns
/// that into "the sender signed it". Verifying without the binding is how a
/// client shows a green tick for a message signed by someone else entirely.
pub struct Certificate {
    pub email: String,
    pub key: SignedPublicKey,
}

impl Certificate {
    /// Reads an ASCII-armored public key, bound to `email`.
    pub fn from_armored(email: &str, armored: &str) -> Option<Self> {
        let (key, _) = SignedPublicKey::from_string(armored).ok()?;
        Some(Self {
            email: email.trim().to_ascii_lowercase(),
            key,
        })
    }
}

/// What can be said about a message's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No OpenPGP signature. Say nothing.
    Unsigned,
    /// Signed by a key held for the sender's own address.
    Verified { signer: String },
    /// The signature checks out, but against a key bound to someone other
    /// than the `From` address. Not an alarm and not a tick: the message is
    /// authentic and is not from who it appears to be from.
    SignerMismatch { signer: String },
    /// Signed by a key this device does not hold, so nothing can be
    /// concluded. The ordinary state for mail from strangers.
    UnknownSigner,
    /// Checked against the original bytes and failed. The message was
    /// altered after signing — the one state that deserves a loud notice.
    Invalid,
}

/// What one message turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Examined {
    pub verdict: Verdict,
    /// Whether the body is OpenPGP-encrypted. Reported separately from the
    /// verdict because it is not a judgement — and because it changes what a
    /// reply may safely quote, so a reader shows it whatever the verdict.
    pub encrypted: bool,
}

/// Examines a message's OpenPGP state without needing a secret key.
///
/// Takes the raw RFC 5322 bytes rather than a parsed [`crate::model::Message`]
/// on purpose: that model is an extracted view with no MIME structure and no
/// byte offsets, and both are exactly what a detached signature is computed
/// over. `MailStore::raw(uid)` is the intended source, so a reader can
/// examine and display from one read.
#[must_use]
pub fn examine(raw: &[u8], keys: &[Certificate]) -> Examined {
    let Some(parsed) = MessageParser::default().parse(raw) else {
        return Examined {
            verdict: Verdict::Unsigned,
            encrypted: false,
        };
    };

    if is_pgp_encrypted(&parsed) {
        // The signature, if any, is *inside* the ciphertext. Nothing can be
        // said about it until the message is decrypted, and claiming
        // `Unsigned` here would tell the reader something false.
        return Examined {
            verdict: Verdict::UnknownSigner,
            encrypted: true,
        };
    }

    let sender = sender_address(&parsed);
    let verdict = match signed_parts(&parsed) {
        Some((signed_bytes, signature)) => {
            verify_detached(raw, signed_bytes, &signature, keys, &sender)
        }
        None => Verdict::Unsigned,
    };
    Examined {
        verdict,
        encrypted: false,
    }
}

/// Decrypts a PGP/MIME message, returning the inner MIME entity's bytes.
///
/// Bytes in, bytes out, and nothing is written anywhere: the stored file must
/// remain the ciphertext original, or the verbatim-storage invariant breaks
/// and the message can never be verified — or decrypted — again. A caller
/// holds the result in memory for as long as it is being read.
///
/// `None` when the message is not PGP-encrypted, when this key cannot open it,
/// or when the ciphertext is damaged. The three are deliberately not
/// distinguished: telling an attacker which of their guesses was closer is
/// the one thing a decryption oracle must never do.
#[must_use]
pub fn decrypt(
    raw: &[u8],
    secret: &pgp::composed::SignedSecretKey,
    password: &str,
) -> Option<Vec<u8>> {
    let parsed = MessageParser::default().parse(raw)?;
    let armored = encrypted_payload(&parsed)?;
    let (message, _) = Message::from_armor(armored.as_slice()).ok()?;

    let password = if password.is_empty() {
        Password::empty()
    } else {
        Password::from(password.to_owned())
    };
    let mut decrypted = message.decrypt(&password, secret).ok()?;
    if decrypted.is_compressed() {
        decrypted = decrypted.decompress().ok()?;
    }
    decrypted.as_data_vec().ok()
}

/* ---------------- detection ---------------- */

/// The `protocol` parameter of a multipart content type, lowercased.
fn protocol_of(part: &mail_parser::MessagePart<'_>) -> Option<String> {
    part.content_type()?
        .attribute("protocol")
        .map(|value| value.trim().to_ascii_lowercase())
}

/// RFC 3156 §4: `multipart/encrypted` naming the PGP protocol.
///
/// The protocol check is what keeps S/MIME out. Both formats use the same
/// multipart wrappers and differ only here, so a client that matches on the
/// wrapper alone reports every S/MIME message as broken PGP.
fn is_pgp_encrypted(message: &mail_parser::Message<'_>) -> bool {
    message.parts.iter().any(|part| {
        part.content_type()
            .is_some_and(|ct| ct.ctype().eq_ignore_ascii_case("multipart"))
            && part
                .content_type()
                .and_then(|ct| ct.subtype())
                .is_some_and(|sub| sub.eq_ignore_ascii_case("encrypted"))
            && protocol_of(part).as_deref() == Some("application/pgp-encrypted")
    })
}

/// The armored ciphertext of a `multipart/encrypted` message: the second
/// part, per RFC 3156 §4 — the first is the version control part.
fn encrypted_payload(message: &mail_parser::Message<'_>) -> Option<Vec<u8>> {
    if !is_pgp_encrypted(message) {
        return None;
    }
    message
        .parts
        .iter()
        .find(|part| {
            part.content_type().is_some_and(|ct| {
                ct.ctype().eq_ignore_ascii_case("application")
                    && ct
                        .subtype()
                        .is_some_and(|s| s.eq_ignore_ascii_case("octet-stream"))
            })
        })
        .map(|part| part.contents().to_vec())
}

/// The byte range the signature covers, plus the armored signature.
///
/// RFC 3156 §5: `multipart/signed` with `protocol="application/pgp-signature"`,
/// whose first part is the signed entity and whose second is the signature.
/// The signed range runs from the part's *header* offset to its end, because
/// the signature was computed over the transmitted entity — headers included,
/// not merely its decoded body.
fn signed_parts(message: &mail_parser::Message<'_>) -> Option<(std::ops::Range<usize>, String)> {
    let wrapper = message.parts.iter().find(|part| {
        part.content_type()
            .is_some_and(|ct| ct.ctype().eq_ignore_ascii_case("multipart"))
            && part
                .content_type()
                .and_then(|ct| ct.subtype())
                .is_some_and(|sub| sub.eq_ignore_ascii_case("signed"))
            && protocol_of(part).as_deref() == Some("application/pgp-signature")
    })?;

    let mail_parser::PartType::Multipart(children) = &wrapper.body else {
        return None;
    };
    let content = message
        .parts
        .get(usize::try_from(*children.first()?).ok()?)?;
    let signature_part = message
        .parts
        .get(usize::try_from(*children.get(1)?).ok()?)?;

    let armored = String::from_utf8(signature_part.contents().to_vec()).ok()?;
    if !armored.contains("BEGIN PGP SIGNATURE") {
        return None;
    }

    let start = usize::try_from(content.offset_header).ok()?;
    let end = usize::try_from(content.offset_end).ok()?;
    (start < end).then_some((start..end, armored))
}

/* ---------------- verification ---------------- */

fn sender_address(message: &mail_parser::Message<'_>) -> String {
    message
        .from()
        .and_then(mail_parser::Address::first)
        .and_then(|addr| addr.address())
        .map(|a| a.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Verifies a detached signature over the exact transmitted bytes.
///
/// Three candidate ranges are tried, because implementations disagree about
/// the trailing CRLF before the boundary: RFC 3156 says the line ending
/// belongs to the boundary rather than the content, and enough signers get
/// this wrong in each direction that accepting only one reading rejects real,
/// unmodified mail. All three are *narrowings* of the original bytes — none
/// invents content — so a forgery still fails all three.
fn verify_detached(
    raw: &[u8],
    range: std::ops::Range<usize>,
    armored: &str,
    keys: &[Certificate],
    sender: &str,
) -> Verdict {
    let Ok((signature, _)) = DetachedSignature::from_string(armored) else {
        // Not a signature we can parse: nothing was checked, so nothing may
        // be claimed. Emphatically not `Invalid`.
        return Verdict::UnknownSigner;
    };
    let Some(signed) = raw.get(range) else {
        return Verdict::UnknownSigner;
    };

    let trimmed = signed.strip_suffix(b"\r\n").unwrap_or(signed);
    let candidates: [&[u8]; 2] = [signed, trimmed];

    for certificate in keys {
        let verifies = candidates.iter().any(|bytes| {
            signature
                .verify(&certificate.key.primary_key, bytes)
                .is_ok()
                || certificate
                    .key
                    .public_subkeys
                    .iter()
                    .any(|subkey| signature.verify(subkey, bytes).is_ok())
        });
        if verifies {
            return if certificate.email == sender {
                Verdict::Verified {
                    signer: certificate.email.clone(),
                }
            } else {
                Verdict::SignerMismatch {
                    signer: certificate.email.clone(),
                }
            };
        }
    }

    if keys.is_empty() {
        return Verdict::UnknownSigner;
    }

    // We hold keys and none of them verified. That is only evidence of
    // tampering if one of them was the signer's — otherwise it means the
    // signer is simply someone we have no key for, which is the common case.
    if signed_by_any(&signature, keys) {
        Verdict::Invalid
    } else {
        Verdict::UnknownSigner
    }
}

/// Whether the signature claims to come from a key we hold, by key id.
///
/// This is what separates "checked and failed" from "could not check". The
/// issuer is unauthenticated — an attacker may write any key id they like —
/// but that cuts the right way: claiming a key we hold, and then failing
/// against it, is exactly the tampering case.
fn signed_by_any(signature: &DetachedSignature, keys: &[Certificate]) -> bool {
    let packet = &signature.signature;
    keys.iter().any(|certificate| {
        let ids: Vec<pgp::types::KeyId> =
            std::iter::once(certificate.key.primary_key.legacy_key_id())
                .chain(
                    certificate
                        .key
                        .public_subkeys
                        .iter()
                        .map(pgp::types::KeyDetails::legacy_key_id),
                )
                .collect();
        let fingerprints: Vec<pgp::types::Fingerprint> =
            std::iter::once(certificate.key.primary_key.fingerprint())
                .chain(
                    certificate
                        .key
                        .public_subkeys
                        .iter()
                        .map(pgp::types::KeyDetails::fingerprint),
                )
                .collect();
        // Both spellings: a v4 signature names an 8-byte key id, a v6 one a
        // full fingerprint, and a signer may emit either.
        packet.issuer_key_id().iter().any(|id| ids.contains(*id))
            || packet
                .issuer_fingerprint()
                .iter()
                .any(|fp| fingerprints.contains(*fp))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use pgp::composed::{
        ArmorOptions, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey,
        SubkeyParamsBuilder,
    };
    use pgp::crypto::hash::HashAlgorithm;
    use rand_pgp::thread_rng;

    /// A fresh Ed25519 identity. Generated rather than embedded so the tests
    /// exercise real signatures over real bytes — a fixture would prove only
    /// that the fixture still parses.
    fn identity(email: &str) -> (SignedSecretKey, Certificate) {
        let mut signing = SubkeyParamsBuilder::default();
        signing
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None);
        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(format!("Test <{email}>"))
            .subkeys(vec![signing.build().unwrap()]);

        let secret: SignedSecretKey = params.build().unwrap().generate(thread_rng()).unwrap();
        let armored = SignedPublicKey::from(secret.clone())
            .to_armored_string(ArmorOptions::default())
            .unwrap();
        let certificate = Certificate::from_armored(email, &armored).unwrap();
        (secret, certificate)
    }

    /// A `multipart/signed` message: the signature is computed over the exact
    /// transmitted bytes of the first part, headers included, which is the
    /// whole subtlety of RFC 3156.
    fn signed_message(secret: &SignedSecretKey, from: &str, body: &str) -> Vec<u8> {
        let entity = format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n");
        let signing: &dyn pgp::types::SigningKey = secret
            .secret_subkeys
            .iter()
            .find(|sub| sub.key.algorithm().can_sign())
            .map_or(&secret.primary_key as &dyn pgp::types::SigningKey, |sub| {
                &sub.key as &dyn pgp::types::SigningKey
            });
        let signature = DetachedSignature::sign_binary_data(
            thread_rng(),
            &Box::new(signing),
            &Password::empty(),
            HashAlgorithm::Sha256,
            entity.as_bytes(),
        )
        .unwrap()
        .to_armored_string(ArmorOptions::default())
        .unwrap();

        format!(
            "From: {from}\r\nTo: her@example.com\r\nSubject: Signed\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/signed; micalg=pgp-sha256; \
             protocol=\"application/pgp-signature\"; boundary=\"BB\"\r\n\r\n\
             --BB\r\n{entity}\r\n\
             --BB\r\nContent-Type: application/pgp-signature\r\n\r\n{signature}\r\n--BB--\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn a_signature_from_a_key_we_hold_for_the_sender_verifies() {
        let (secret, certificate) = identity("him@example.com");
        let raw = signed_message(&secret, "him@example.com", "the original text");

        let examined = examine(&raw, std::slice::from_ref(&certificate));
        assert_eq!(
            examined.verdict,
            Verdict::Verified {
                signer: "him@example.com".to_owned()
            }
        );
        assert!(!examined.encrypted);
    }

    /// The state that only verbatim storage can earn. One byte of the signed
    /// entity is changed after signing; the verdict must be the loud one.
    #[test]
    fn a_message_altered_after_signing_is_invalid_not_merely_unknown() {
        let (secret, certificate) = identity("him@example.com");
        let raw = signed_message(&secret, "him@example.com", "send me ten pounds");
        let tampered: Vec<u8> = String::from_utf8(raw)
            .unwrap()
            .replace("ten pounds", "ten grand!")
            .into_bytes();

        assert_eq!(
            examine(&tampered, &[certificate]).verdict,
            Verdict::Invalid,
            "a rewritten message read as merely uncheckable"
        );
    }

    /// The common case: mail from a stranger. Not an alarm.
    #[test]
    fn a_signature_from_a_key_we_do_not_hold_is_unknown_not_invalid() {
        let (secret, _) = identity("stranger@example.com");
        let raw = signed_message(&secret, "stranger@example.com", "hello");

        assert_eq!(examine(&raw, &[]).verdict, Verdict::UnknownSigner);
    }

    /// Holding *other* people's keys must not turn a stranger's signature
    /// into evidence of tampering.
    #[test]
    fn an_unrelated_key_in_the_ring_does_not_make_a_stranger_a_forger() {
        let (secret, _) = identity("stranger@example.com");
        let (_, someone_else) = identity("colleague@example.com");
        let raw = signed_message(&secret, "stranger@example.com", "hello");

        assert_eq!(
            examine(&raw, &[someone_else]).verdict,
            Verdict::UnknownSigner
        );
    }

    /// A valid signature by the wrong person. The message is authentic and is
    /// not from who it claims to be — neither a tick nor an alarm.
    #[test]
    fn a_good_signature_bound_to_another_address_is_a_mismatch() {
        let (secret, certificate) = identity("colleague@example.com");
        let raw = signed_message(&secret, "him@example.com", "hello");

        assert_eq!(
            examine(&raw, &[certificate]).verdict,
            Verdict::SignerMismatch {
                signer: "colleague@example.com".to_owned()
            }
        );
    }

    #[test]
    fn ordinary_mail_is_unsigned_and_says_nothing() {
        let raw = b"From: him@example.com\r\nSubject: Hi\r\n\r\njust text\r\n";
        let examined = examine(raw, &[]);
        assert_eq!(examined.verdict, Verdict::Unsigned);
        assert!(!examined.encrypted);
    }

    /// S/MIME uses the same wrapper and a different protocol. Matching the
    /// wrapper alone reports every S/MIME message as broken PGP.
    #[test]
    fn an_smime_signed_message_is_not_treated_as_pgp() {
        let raw = b"From: him@example.com\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"SS\"\r\n\r\n\
--SS\r\nContent-Type: text/plain\r\n\r\nhi\r\n\
--SS\r\nContent-Type: application/pkcs7-signature\r\n\r\nAAAA\r\n--SS--\r\n";

        assert_eq!(examine(raw, &[]).verdict, Verdict::Unsigned);
    }

    #[test]
    fn an_encrypted_message_is_reported_as_such_and_claims_nothing_about_its_signature() {
        let raw = b"From: him@example.com\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"EE\"\r\n\r\n\
--EE\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\
--EE\r\nContent-Type: application/octet-stream\r\n\r\n\
-----BEGIN PGP MESSAGE-----\r\n\r\nAAAA\r\n-----END PGP MESSAGE-----\r\n--EE--\r\n";

        let examined = examine(raw, &[]);
        assert!(examined.encrypted);
        assert_eq!(
            examined.verdict,
            Verdict::UnknownSigner,
            "claimed the message was unsigned while its signature was still sealed"
        );
    }

    #[test]
    fn garbage_never_panics_and_never_claims_a_verdict() {
        for hostile in [
            &b""[..],
            &b"\x00\xff\xfe not a message"[..],
            b"Content-Type: multipart/signed; protocol=\"application/pgp-signature\"\r\n\r\n",
        ] {
            let examined = examine(hostile, &[]);
            assert!(matches!(
                examined.verdict,
                Verdict::Unsigned | Verdict::UnknownSigner
            ));
        }
    }

    #[test]
    fn decrypting_something_that_is_not_encrypted_is_none() {
        let (secret, _) = identity("him@example.com");
        let raw = b"From: him@example.com\r\n\r\nplain text\r\n";
        assert!(decrypt(raw, &secret, "").is_none());
    }
}

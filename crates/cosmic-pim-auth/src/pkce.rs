// SPDX-License-Identifier: MPL-2.0

//! Proof Key for Code Exchange (RFC 7636).
//!
//! # What it is defending against
//!
//! The authorization code comes back to a loopback redirect, and on a desktop
//! any local process can bind a port and any local process can read the
//! `Location` a browser was sent to. Without PKCE, a code intercepted that way
//! is redeemable by whoever holds it, because the token endpoint's only other
//! check — the client secret — is in the application's own package and
//! therefore known to everyone.
//!
//! PKCE makes the code useless on its own: the authorize request commits to
//! `SHA-256(verifier)`, and the token request must produce the verifier that
//! hashes to it. The verifier never leaves this process.
//!
//! `S256` only. RFC 7636 also defines `plain`, which sends the verifier in the
//! authorize URL and therefore defends against nothing; a provider that only
//! accepted `plain` would be better refused than accommodated.

use base64::Engine as _;
use sha2::Digest as _;

/// A verifier and the challenge derived from it.
#[derive(Debug, Clone)]
pub struct Pkce {
    verifier: String,
    challenge: String,
}

/// 32 bytes of entropy, base64url-encoded to 43 characters — the shortest
/// verifier RFC 7636 §4.1 permits, and the length every provider tests with.
const VERIFIER_BYTES: usize = 32;

impl Pkce {
    /// Generates a fresh pair from the OS random source.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; VERIFIER_BYTES];
        rand::fill(&mut bytes);
        Self::from_verifier_bytes(&bytes)
    }

    fn from_verifier_bytes(bytes: &[u8]) -> Self {
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let digest = sha2::Sha256::digest(verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        Self {
            verifier,
            challenge,
        }
    }

    /// The secret half, sent only to the token endpoint.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// The public half, sent in the authorize URL.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// Always `S256`. See the module docs for why `plain` is not offered.
    #[must_use]
    pub fn method(&self) -> &'static str {
        "S256"
    }
}

/// An unguessable value tying a redirect back to the request that started it.
///
/// The loopback listener accepts one connection from anything on the machine,
/// so without this a hostile local process could deliver *its* authorization
/// code and have the account silently bound to its own identity (RFC 6749
/// §10.12). The listener compares and refuses a mismatch.
#[must_use]
pub fn random_state() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_is_the_base64url_sha256_of_the_verifier() {
        // The one vector in RFC 7636 (appendix B). If this is wrong every
        // provider rejects every sign-in with an opaque `invalid_grant`.
        let bytes = [
            116u8, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212,
            37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
        ];
        let pkce = Pkce::from_verifier_bytes(&bytes);

        assert_eq!(
            pkce.verifier(),
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        assert_eq!(
            pkce.challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_verifier_is_long_enough_and_url_safe() {
        let pkce = Pkce::generate();

        // RFC 7636 §4.1: 43..=128 characters from the unreserved set.
        assert_eq!(pkce.verifier().len(), 43);
        assert!(
            pkce.verifier()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)),
            "a verifier carrying a character that needs escaping breaks the token request"
        );
    }

    #[test]
    fn two_sign_ins_never_share_a_verifier_or_a_state() {
        let (a, b) = (Pkce::generate(), Pkce::generate());
        assert_ne!(a.verifier(), b.verifier());
        assert_ne!(random_state(), random_state());
    }

    #[test]
    fn only_s256_is_offered() {
        assert_eq!(Pkce::generate().method(), "S256");
    }
}

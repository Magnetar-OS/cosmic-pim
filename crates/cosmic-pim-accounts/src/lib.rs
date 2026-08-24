// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Accounts and credentials for the COSMIC PIM suite.
//!
//! - [`secret`] — credential storage: the OS keychain, or an encrypted local
//!   envelope when there is no usable keychain.
//! - [`account`] — account metadata, and the binding between a remote calendar
//!   and the local vdir collection that mirrors it.
//!
//! # Relationship to `cosmic-utils/accounts`
//!
//! There is a COSMIC online-accounts daemon (`dev.edfloreshz.Accounts`) that
//! owns OAuth accounts for the whole desktop, and it is the right long-term
//! home for Google and Microsoft sign-in. This crate is not a competitor to it
//! and is not a reimplementation of it.
//!
//! It exists because the daemon does not cover the case that matters most for
//! CalDAV: a server reached with a **URL and an app password** — Fastmail,
//! Nextcloud, Migadu, Radicale, a university, a Synology box. There is no OAuth
//! flow to run and no provider manifest to write, and requiring a running
//! daemon to store one password would make the calendar unusable on any system
//! that does not have one installed.
//!
//! The intended end state is both: this crate for direct credentials, and a
//! D-Bus client to the daemon for OAuth-backed providers, behind the same
//! [`account::Account`] type. [`account::AuthMethod::OAuth`] is the seam where
//! that plugs in.

pub mod account;
pub mod credential;
pub mod error;
pub mod provider;
pub mod secret;

pub use account::{Account, AccountStore, AuthMethod, MailEndpoint, Transport};
pub use credential::{OAuthCredential, Secret};
pub use error::{Error, Result};
pub use provider::{MailProtocol, MailService, OAuth, Provider, Registry};
pub use secret::{Backend, SecretStore};

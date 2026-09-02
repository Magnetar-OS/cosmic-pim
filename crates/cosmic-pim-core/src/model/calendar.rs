// Copyright 2026 Dominikos Pritis
// SPDX-License-Identifier: MPL-2.0

//! Calendar collections.
//!
//! A collection is one directory in the vdir layout. Per the vdir spec it may
//! carry two optional sibling metadata files — `displayname` and `color` — which
//! `vdirsyncer` reads and writes, so honouring them keeps us interoperable.

use std::path::{Path, PathBuf};

/// Fallback colour for a collection with no `color` file.
pub const DEFAULT_CALENDAR_COLOR: Rgb = Rgb(0x2d, 0x7d, 0xd2);

/// Colours offered when creating a calendar. Chosen to stay legible against
/// both light and dark COSMIC themes.
pub const PALETTE: &[Rgb] = &[
    Rgb(0x2d, 0x7d, 0xd2), // blue
    Rgb(0x24, 0x9b, 0x74), // green
    Rgb(0xe4, 0x57, 0x2e), // vermilion
    Rgb(0xc4, 0x4f, 0x9b), // magenta
    Rgb(0x7a, 0x5a, 0xf8), // violet
    Rgb(0xd9, 0x8a, 0x1b), // amber
    Rgb(0x1c, 0x9c, 0xa8), // teal
    Rgb(0x77, 0x7f, 0x8c), // slate
];

/// A plain RGB triple. Deliberately not a libcosmic type — the model layer
/// stays independent of the toolkit so it can be tested without a display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// Parses `#rrggbb`, `rrggbb`, or `#rgb`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('#');
        match s.len() {
            6 => {
                let r = u8::from_str_radix(&s[0..2], 16).ok()?;
                let g = u8::from_str_radix(&s[2..4], 16).ok()?;
                let b = u8::from_str_radix(&s[4..6], 16).ok()?;
                Some(Rgb(r, g, b))
            }
            3 => {
                let f = |i: usize| -> Option<u8> {
                    let v = u8::from_str_radix(&s[i..=i], 16).ok()?;
                    Some(v * 17)
                };
                Some(Rgb(f(0)?, f(1)?, f(2)?))
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.0, self.1, self.2)
    }

    /// Relative luminance, used to pick readable text over a colour chip.
    #[must_use]
    pub fn luminance(self) -> f32 {
        let c = |v: u8| {
            let v = f32::from(v) / 255.0;
            if v <= 0.040_45 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * c(self.0) + 0.7152 * c(self.1) + 0.0722 * c(self.2)
    }

    /// Whether black text reads better than white on this colour.
    #[must_use]
    pub fn prefers_dark_text(self) -> bool {
        self.luminance() > 0.45
    }
}

/// One calendar collection on disk.
#[derive(Clone, Debug)]
pub struct CalendarMeta {
    /// The collection's directory name. Stable, and used as the primary key
    /// everywhere else in the app.
    pub id: String,
    /// Human-readable name from the `displayname` file, falling back to `id`.
    pub name: String,
    pub color: Rgb,
    pub path: PathBuf,
    /// Set when the directory is not writable, so the UI can hide edit affordances
    /// instead of letting a save fail at the last moment.
    pub read_only: bool,
}

impl CalendarMeta {
    /// Reads a collection's metadata from its directory.
    #[must_use]
    pub fn load(path: &Path) -> Option<Self> {
        let id = path.file_name()?.to_str()?.to_owned();

        let read_meta = |name: &str| -> Option<String> {
            let raw = std::fs::read_to_string(path.join(name)).ok()?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        };

        let name = read_meta("displayname").unwrap_or_else(|| id.clone());
        let color = read_meta("color")
            .as_deref()
            .and_then(Rgb::parse)
            .unwrap_or(DEFAULT_CALENDAR_COLOR);

        // An ICS-feed subscription (`cosmic_pim_caldav::feed`, marked by its
        // state sidecar) is read-only by construction: its contents are
        // replaced wholesale on every refresh, so an event written into it
        // would silently vanish. Marking it here makes every write path and
        // every "writable calendar" picker refuse it without each having to
        // know what a feed is.
        let read_only = path.join(".ics-feed.json").exists()
            || std::fs::metadata(path)
                .map(|m| m.permissions().readonly())
                .unwrap_or(true);

        Some(Self {
            id,
            name,
            color,
            path: path.to_path_buf(),
            read_only,
        })
    }

    /// Writes `displayname` and `color` back out, matching what vdirsyncer expects.
    pub fn save_meta(&self) -> std::io::Result<()> {
        std::fs::write(self.path.join("displayname"), &self.name)?;
        std::fs::write(self.path.join("color"), self.color.to_hex())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_colors() {
        assert_eq!(Rgb::parse("#2d7dd2"), Some(Rgb(0x2d, 0x7d, 0xd2)));
        assert_eq!(Rgb::parse("2d7dd2"), Some(Rgb(0x2d, 0x7d, 0xd2)));
        assert_eq!(Rgb::parse("#fff"), Some(Rgb(255, 255, 255)));
        assert_eq!(Rgb::parse("  #2D7DD2  "), Some(Rgb(0x2d, 0x7d, 0xd2)));
        assert_eq!(Rgb::parse("nope"), None);
        assert_eq!(Rgb::parse(""), None);
    }

    #[test]
    fn hex_roundtrips() {
        let c = Rgb(0xe4, 0x57, 0x2e);
        assert_eq!(Rgb::parse(&c.to_hex()), Some(c));
    }

    #[test]
    fn picks_readable_text_color() {
        assert!(Rgb(255, 255, 255).prefers_dark_text());
        assert!(!Rgb(0, 0, 0).prefers_dark_text());
        assert!(!DEFAULT_CALENDAR_COLOR.prefers_dark_text());
    }
}

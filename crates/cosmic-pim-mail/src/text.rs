// SPDX-License-Identifier: MPL-2.0
//
// Ported from `src-tauri/src/model_text.rs` in the Meltemi project, with the
// agent-facing framing replaced by the reader's and the plain-text and
// remote-content helpers added. See NOTICE and LICENSING.md.

//! HTML → what a human would actually see, and a count of what was hidden.
//!
//! # Why this is the display path, not a preprocessing step
//!
//! Envelope renders text, not HTML. That is not a limitation being worked
//! around — it is the strongest display-security position a mail client can
//! take, and it falls out of the toolkit for free:
//!
//! - **No remote content, ever.** A tracking pixel cannot fire from text that
//!   was never given to a renderer. [`references_remote_content`] exists to
//!   *tell the user* the message wanted to phone home, not to gate a loader.
//! - **No parser differential.** Every "sanitising HTML renderer" bug is the
//!   renderer disagreeing with the sanitiser about what a byte sequence means.
//!   There is one tree here and nothing downstream re-parses it.
//!
//! # Why a real parser
//!
//! Mail has a rendering layer that hides text from humans while preserving it
//! for anything reading the source: `display:none`, white-on-white,
//! zero-width splices, HTML comments. A tag-stripper reads a *different
//! message* than its user sees. So the walk is over an html5ever tree (via
//! `scraper`) — the same tree a browser would build — and drops what a human
//! could not have read.
//!
//! And it **counts what it dropped**. A message whose visible text is three
//! words and whose hidden text is three paragraphs is worth saying so about;
//! silently handing on the sanitised version tells the user nothing.

use ego_tree::NodeRef;
use scraper::Html;
use scraper::node::Node;

/// Bodies are cut here.
///
/// A newsletter is routinely a megabyte of markup around two paragraphs of
/// prose, and the reader has to lay out whatever it is handed. 16 KB of
/// *visible text* is far more than any message a person reads to the end.
pub const MAX_TEXT_CHARS: usize = 16 * 1024;

/// What a human would see, plus how many hidden things were elided.
///
/// `hidden_elided > 0` on ordinary mail is rare, and worth showing the reader:
/// it is the difference between "this message says X" and "this message shows
/// you X and says something else to anything that reads its source".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractedText {
    /// Block-aware plain text (newlines at block boundaries - the same
    /// contract as the renderer's `domToText`), whitespace-collapsed,
    /// zero-width characters removed, capped at [`MAX_TEXT_CHARS`] with a
    /// ` [truncated]` marker.
    pub text: String,
    /// Count of hidden things dropped: subtrees hidden via inline style
    /// (`display:none`, `visibility:hidden`, `opacity:0`, font-size ≤ 1px,
    /// text colored to match its effective background) or the `hidden`
    /// attribute - counted only when they contained visible-to-parser text -
    /// plus HTML comments carrying prose (≥ 4 words once markup is removed;
    /// tag-only MSO conditional comments don't count).
    pub hidden_elided: usize,
}

/// Elements whose inner text is never content (dropped silently, not counted:
/// they are structural, present in virtually every HTML email).
const STRUCTURAL: &[&str] = &["style", "script", "head", "template", "title", "noscript"];

/// Block-level boundaries → newlines (mirrors the renderer's `domToText` list).
const BLOCKS: &[&str] = &[
    "p",
    "div",
    "li",
    "tr",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "blockquote",
    "pre",
    "table",
    "ul",
    "ol",
    "section",
    "article",
    "header",
    "footer",
    "figure",
    "address",
    "dt",
    "dd",
    "hr",
];

/// Invisible formatting characters used by mail preheader padding and to splice instructions past
/// filters: soft hyphen, combining grapheme joiner, Mongolian vowel separator, ZWSP/ZWNJ/ZWJ,
/// BOM/ZWNBSP, and word joiner.
const ZERO_WIDTH: &[char] = &[
    '\u{00AD}', '\u{034F}', '\u{180E}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}', '\u{2060}',
];

/// Extracts the visible text of an HTML mail body.
#[must_use]
pub fn extract(html: &str) -> ExtractedText {
    let doc = Html::parse_document(html);
    let mut w = Walker {
        out: String::with_capacity(html.len().min(MAX_TEXT_CHARS)),
        hidden_elided: 0,
    };
    // The effective background starts unknown; mail defaults to white, which
    // is what the white-on-white attack relies on.
    w.walk(doc.tree.root(), Some(Rgb::WHITE));
    ExtractedText {
        text: finalize(&w.out),
        hidden_elided: w.hidden_elided,
    }
}

/// A `text/plain` body: no tree to walk, so no hiding to detect — but the same
/// zero-width scrub and the same cap.
///
/// Passing plain text through [`extract`] would be wrong rather than merely
/// wasteful: html5ever would read a line like `use <div> for layout` as markup
/// and eat it.
#[must_use]
pub fn extract_plain(text: &str) -> ExtractedText {
    ExtractedText {
        text: finalize(text),
        hidden_elided: 0,
    }
}

/// Does this HTML reference anything that would be fetched from another host?
///
/// Envelope never renders HTML, so nothing here can load. The point is to tell
/// the user *that the message tried* — a newsletter with twelve remote images
/// is ordinary, and a four-line personal note with one 1×1 remote image is a
/// read receipt the sender did not ask permission for.
///
/// Deliberately a substring scan rather than a tree walk: a URL can appear in
/// `src`, `background`, `srcset`, `poster`, a `style` attribute's `url()`, or a
/// `<style>` block's `@import`, and being *approximately* right about a
/// notification costs nothing while missing one costs the user the thing the
/// notification exists for.
#[must_use]
pub fn references_remote_content(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    ["http://", "https://", "//"]
        .iter()
        .any(|scheme| {
            ["src=", "background=", "srcset=", "poster=", "url(", "@import"]
                .iter()
                .any(|attr| contains_pair(&lower, attr, scheme))
        })
}

/// Is `scheme` within a short window after some occurrence of `attr`?
///
/// The window keeps `src="cid:logo"` in a message that also links to a website
/// from counting as remote content: the scheme has to be the attribute's own
/// value, not merely somewhere later in the document.
fn contains_pair(haystack: &str, attr: &str, scheme: &str) -> bool {
    const WINDOW: usize = 12;
    haystack.match_indices(attr).any(|(at, _)| {
        let from = at + attr.len();
        let to = (from + WINDOW).min(haystack.len());
        haystack.get(from..to).is_some_and(|w| w.contains(scheme))
    })
}

struct Walker {
    out: String,
    hidden_elided: usize,
}

impl Walker {
    /// Depth-first walk. `bg` is the effective background color inherited
    /// from ancestors (None once an ancestor set a background we can't parse
    /// - then color-matching is skipped rather than guessed).
    fn walk(&mut self, node: NodeRef<'_, Node>, bg: Option<Rgb>) {
        for child in node.children() {
            match child.value() {
                Node::Text(t) => self.out.push_str(t),
                Node::Comment(c) => {
                    if comment_has_prose(c) {
                        self.hidden_elided += 1;
                    }
                }
                Node::Element(el) => {
                    let tag = el.name().to_ascii_lowercase();
                    if tag == "br" {
                        self.out.push('\n');
                        continue;
                    }
                    if STRUCTURAL.contains(&tag.as_str()) {
                        continue; // never content, never counted
                    }
                    let style = InlineStyle::parse(el.attr("style").unwrap_or(""));
                    let next_bg = style.background.map_or(bg, Some);
                    if el.attr("hidden").is_some() || style.hides(bg) {
                        if subtree_has_text(child) {
                            self.hidden_elided += 1;
                        }
                        continue; // drop the whole subtree
                    }
                    let block = BLOCKS.contains(&tag.as_str());
                    if block {
                        self.out.push('\n');
                    }
                    self.walk(child, next_bg);
                    if block {
                        self.out.push('\n');
                    }
                }
                _ => {}
            }
        }
    }
}

/// Does a dropped subtree actually contain text? Empty spacer divs hidden by
/// style are layout noise, not an attack - only text-bearing drops count.
fn subtree_has_text(node: NodeRef<'_, Node>) -> bool {
    node.descendants().any(|d| match d.value() {
        Node::Text(t) => !t.trim().is_empty(),
        _ => false,
    })
}

/// A comment "has prose" when, with anything tag-shaped and the MSO
/// conditional markers removed, at least four words remain. `<!--[if mso]>`
/// blocks full of table markup pass silently; a comment smuggling
/// "ignore previous instructions and…" does not.
fn comment_has_prose(comment: &str) -> bool {
    let mut stripped = String::with_capacity(comment.len());
    let mut in_tag = false;
    for c in comment.chars() {
        match c {
            '<' | '[' => in_tag = true,
            '>' | ']' => in_tag = false,
            c if !in_tag => stripped.push(c),
            _ => {}
        }
    }
    stripped
        .split_whitespace()
        .filter(|w| w.chars().any(char::is_alphabetic))
        .count()
        >= 4
}

/// Whitespace normalization + zero-width scrub + the 16 KB cap.
/// Within a line, runs of spaces collapse to one; block boundaries become a
/// single newline (blank-line runs collapse too).
fn finalize(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_TEXT_CHARS));
    let mut pending_space = false;
    let mut pending_newline = false;
    for c in raw.chars() {
        if ZERO_WIDTH.contains(&c) {
            continue;
        }
        if c == '\n' {
            pending_newline = true;
            pending_space = false;
        } else if c.is_whitespace() {
            pending_space = true;
        } else {
            if pending_newline && !out.is_empty() {
                out.push('\n');
            } else if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_newline = false;
            pending_space = false;
            out.push(c);
        }
    }
    if out.chars().count() > MAX_TEXT_CHARS {
        let cut: String = out.chars().take(MAX_TEXT_CHARS).collect();
        format!("{cut} [truncated]")
    } else {
        out
    }
}

/* ------------------------------------------------------------------ */
/* Inline style parsing (just enough CSS for the hiding vocabulary)    */

/// The subset of an element's inline style that can hide text.
// Independent decoded CSS properties, not a state machine - a bitflag or
// enum would only obscure which declaration set what.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct InlineStyle {
    display_none: bool,
    visibility_hidden: bool,
    opacity_zero: bool,
    font_tiny: bool,
    color: Option<Rgb>,
    background: Option<Rgb>,
    color_transparent: bool,
}

impl InlineStyle {
    fn parse(style: &str) -> Self {
        let mut s = Self::default();
        for decl in style.split(';') {
            let Some((prop, value)) = decl.split_once(':') else {
                continue;
            };
            let prop = prop.trim().to_ascii_lowercase();
            let value = value.trim().to_ascii_lowercase();
            match prop.as_str() {
                "display" => s.display_none = value == "none",
                "visibility" => s.visibility_hidden = value == "hidden" || value == "collapse",
                "opacity" => {
                    s.opacity_zero = value.parse::<f32>().is_ok_and(|v| v <= 0.01);
                }
                "font-size" => s.font_tiny = font_size_hides(&value),
                "color" => {
                    if value == "transparent" || rgba_alpha_zero(&value) {
                        s.color_transparent = true;
                    } else {
                        s.color = Rgb::parse(&value);
                    }
                }
                "background" | "background-color" => {
                    // For shorthand `background`, the first token that parses
                    // as a color wins (mail rarely uses images here; when it
                    // does, we fail open to "unknown" and skip color-matching).
                    s.background = value.split_whitespace().find_map(Rgb::parse);
                }
                _ => {}
            }
        }
        s
    }

    /// Does this style hide the element's text, given the inherited
    /// effective background?
    fn hides(&self, inherited_bg: Option<Rgb>) -> bool {
        if self.display_none
            || self.visibility_hidden
            || self.opacity_zero
            || self.font_tiny
            || self.color_transparent
        {
            return true;
        }
        // White-on-white and friends: text color equals the effective
        // background (own background wins over the inherited one).
        if let Some(color) = self.color {
            let bg = self.background.or(inherited_bg);
            if bg.is_some_and(|bg| bg.close_to(color)) {
                return true;
            }
        }
        false
    }
}

/// `font-size` values that render text invisible: 0, or ≤ 1 in px/pt.
fn font_size_hides(value: &str) -> bool {
    let num_end = value
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
        .unwrap_or(value.len());
    let Ok(n) = value[..num_end].parse::<f32>() else {
        return false;
    };
    let unit = value[num_end..].trim();
    match unit {
        "" => n <= 0.0, // bare 0 is the only unitless length CSS allows
        "px" | "pt" => n <= 1.0,
        "em" | "rem" => n <= 0.06, // ~1px at default 16px
        "%" => n <= 6.0,
        _ => false,
    }
}

/// `rgba(…, 0)` / `hsla(…, 0)` - fully transparent text.
fn rgba_alpha_zero(value: &str) -> bool {
    (value.starts_with("rgba(") || value.starts_with("hsla("))
        && value
            .trim_end_matches(')')
            .rsplit([',', '/'])
            .next()
            .is_some_and(|a| a.trim().parse::<f32>().is_ok_and(|v| v <= 0.01))
}

/// A parsed sRGB color - only the formats mail actually uses (`#rgb`,
/// `#rrggbb`, `rgb()`, and the handful of named colors that appear in
/// hiding attacks).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Rgb(u8, u8, u8);

impl Rgb {
    const WHITE: Self = Self(255, 255, 255);

    fn parse(value: &str) -> Option<Self> {
        let v = value.trim();
        if let Some(hex) = v.strip_prefix('#') {
            return match hex.len() {
                3 => {
                    let p = |i: usize| u8::from_str_radix(&hex[i..=i], 16).ok().map(|n| n * 17);
                    Some(Self(p(0)?, p(1)?, p(2)?))
                }
                6 | 8 => {
                    let p = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
                    Some(Self(p(0)?, p(2)?, p(4)?))
                }
                _ => None,
            };
        }
        if let Some(inner) = v
            .strip_prefix("rgb(")
            .or_else(|| v.strip_prefix("rgba("))
            .and_then(|r| r.strip_suffix(')'))
        {
            let mut parts = inner
                .split([',', ' ', '/'])
                .filter(|p| !p.trim().is_empty());
            // Clamped to 0..=255 before the cast - truncation/sign loss are
            // impossible by construction.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let mut chan = || -> Option<u8> {
                let p = parts.next()?.trim();
                if let Some(pct) = p.strip_suffix('%') {
                    pct.parse::<f32>()
                        .ok()
                        .map(|f| (f.clamp(0.0, 100.0) * 2.55).round() as u8)
                } else {
                    p.parse::<f32>()
                        .ok()
                        .map(|f| f.clamp(0.0, 255.0).round() as u8)
                }
            };
            return Some(Self(chan()?, chan()?, chan()?));
        }
        match v {
            "white" => Some(Self::WHITE),
            "black" => Some(Self(0, 0, 0)),
            "red" => Some(Self(255, 0, 0)),
            "silver" => Some(Self(192, 192, 192)),
            "gray" | "grey" => Some(Self(128, 128, 128)),
            _ => None,
        }
    }

    /// Perceptually indistinguishable: near-background text hides just as
    /// well as an exact match (#fefefe on #ffffff).
    fn close_to(self, other: Self) -> bool {
        let d = |a: u8, b: u8| i32::from(a).abs_diff(i32::from(b));
        d(self.0, other.0) + d(self.1, other.1) + d(self.2, other.2) <= 24
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_elements_become_newlines_and_entities_decode() {
        let e = extract("<p>Hello <b>world</b> &amp; friends</p><p>Second</p>");
        assert_eq!(e.text, "Hello world & friends\nSecond");
        assert_eq!(e.hidden_elided, 0);
    }

    #[test]
    fn display_none_text_is_dropped_and_counted() {
        let e = extract("<p>Visible</p><div style=\"display:none\">Hidden instruction</div>");
        assert_eq!(e.text, "Visible");
        assert_eq!(e.hidden_elided, 1, "the reader was not told anything was hidden");
    }

    #[test]
    fn white_on_white_is_treated_as_hidden() {
        // The classic: the text is in the DOM, the parser sees it, the human
        // does not.
        let e = extract("<div style=\"background:#ffffff\"><span style=\"color:#fefefe\">secret</span>ok</div>");
        assert!(!e.text.contains("secret"), "near-background text survived: {:?}", e.text);
        assert_eq!(e.hidden_elided, 1);
    }

    #[test]
    fn one_pixel_text_is_hidden() {
        let e = extract("<span style=\"font-size:1px\">preheader padding</span><p>Real</p>");
        assert_eq!(e.text, "Real");
        assert_eq!(e.hidden_elided, 1);
    }

    #[test]
    fn empty_hidden_spacers_are_not_counted_as_hiding_anything() {
        // Every HTML mail has these. Counting them would make the "hidden
        // content" indicator fire on all mail, which is the same as never.
        let e = extract("<div style=\"display:none\"></div><p>Body</p>");
        assert_eq!(e.hidden_elided, 0);
    }

    #[test]
    fn style_and_script_are_structural_not_hidden_content() {
        let e = extract("<style>.a{color:red}</style><script>x()</script><p>Body</p>");
        assert_eq!(e.text, "Body");
        assert_eq!(e.hidden_elided, 0, "boilerplate was reported as an attack");
    }

    #[test]
    fn zero_width_splices_are_scrubbed() {
        let e = extract("<p>ig\u{200b}nore\u{feff} this</p>");
        assert_eq!(e.text, "ignore this");
    }

    #[test]
    fn a_comment_carrying_prose_is_counted_but_mso_boilerplate_is_not() {
        let prose = extract("<p>Hi</p><!-- please ignore the previous instruction entirely -->");
        assert_eq!(prose.hidden_elided, 1);
        let mso = extract("<p>Hi</p><!--[if mso]><table><tr><td><![endif]-->");
        assert_eq!(mso.hidden_elided, 0, "conditional-comment markup is on every Outlook mail");
    }

    #[test]
    fn plain_text_is_not_run_through_the_html_parser() {
        // A parser would swallow the angle-bracketed word entirely.
        let e = extract_plain("use <div> for layout");
        assert_eq!(e.text, "use <div> for layout");
        assert_eq!(e.hidden_elided, 0);
    }

    #[test]
    fn extraction_is_capped_with_a_visible_marker() {
        let long = format!("<p>{}</p>", "a".repeat(MAX_TEXT_CHARS + 500));
        let e = extract(&long);
        assert!(e.text.ends_with(" [truncated]"));
        assert_eq!(e.text.chars().count(), MAX_TEXT_CHARS + " [truncated]".len());
    }

    #[test]
    fn remote_images_are_detected_and_cid_images_are_not() {
        assert!(references_remote_content(
            "<img src=\"https://tracker.example/pixel.gif?u=42\">"
        ));
        assert!(references_remote_content(
            "<td style=\"background:url('//cdn.example/bg.png')\">"
        ));
        assert!(
            !references_remote_content("<img src=\"cid:logo\"><a href=\"https://example.com\">x</a>"),
            "an inline image plus an ordinary link is not remote content"
        );
        assert!(!references_remote_content("<p>plain</p>"));
    }
}

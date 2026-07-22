//! Terminal color-depth detection and semantic palettes for the TUI.
//!
//! The TUI keeps a fixed set of named color *roles* (background, text, accent,
//! inbound, outbound, ...). Each role resolves to a concrete [`Color`] through
//! one of three palettes selected by the terminal's color capability, so the
//! same UI stays readable on true-color, 16-color and monochrome terminals.
//!
//! See `docs/adr/0002-tui-palette-by-color-tier.md` for the design.

use ratatui::style::{Color, Modifier, Style};
use std::sync::atomic::{AtomicU8, Ordering};

// --- Tiers ------------------------------------------------------------------

/// Detected terminal color capability, coarse-grained into three tiers.
///
/// The tiers drive which palette resolves the TUI's color roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ColorTier {
    /// No color support: emphasis via [`Modifier`] only.
    Monochrome = 0,
    /// The 8/16 ANSI base colors.
    Sixteen = 1,
    /// 24-bit true color (256-color terminals are treated as true-color too).
    Truecolor = 2,
}

/// User-facing palette selection, exposed in the settings overlay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PaletteChoice {
    /// Follow the detected terminal tier.
    Auto,
    /// Force 24-bit true color.
    Truecolor,
    /// Force the 16 ANSI color palette.
    SixteenColor,
    /// Force the monochrome palette.
    Monochrome,
}

/// Resolve the effective tier from a choice and the detected tier.
pub(crate) fn resolve(choice: PaletteChoice, detected: ColorTier) -> ColorTier {
    match choice {
        PaletteChoice::Auto => detected,
        PaletteChoice::Truecolor => ColorTier::Truecolor,
        PaletteChoice::SixteenColor => ColorTier::Sixteen,
        PaletteChoice::Monochrome => ColorTier::Monochrome,
    }
}

// --- Detection --------------------------------------------------------------

/// Resolve the color tier from the relevant environment-variable values.
///
/// This is the pure, testable core of [`detect_tier`]; it never touches the
/// process environment.
pub(crate) fn tier_from_env(
    colorterm: Option<&str>,
    term: &str,
    no_color: Option<&str>,
) -> ColorTier {
    // no-color.org: a present, non-empty NO_COLOR wins over everything else.
    if no_color.map(|v| !v.is_empty()).unwrap_or(false) {
        return ColorTier::Monochrome;
    }
    if let Some(ct) = colorterm {
        let ct = ct.trim().to_ascii_lowercase();
        if ct == "truecolor" || ct == "24bit" {
            return ColorTier::Truecolor;
        }
    }
    if term.to_ascii_lowercase().contains("256color") {
        return ColorTier::Truecolor;
    }
    // xterm, linux, vt*, screen, dumb and any unrecognized TERM conservatively
    // get the 16-color palette. `dumb` is included by design: it is rare and the
    // 16-color escapes degrade no worse than the alternatives.
    ColorTier::Sixteen
}

/// Read the live environment once and resolve the detected tier.
pub(crate) fn detect_tier() -> ColorTier {
    let term = std::env::var("TERM").unwrap_or_default();
    tier_from_env(
        std::env::var("COLORTERM").ok().as_deref(),
        &term,
        std::env::var("NO_COLOR").ok().as_deref(),
    )
}

// --- Palettes ---------------------------------------------------------------

/// One concrete color per named role for a single tier.
#[derive(Clone, Copy)]
struct Palette {
    bg: Color,
    text: Color,
    strong: Color,
    muted: Color,
    border: Color,
    accent: Color,
    accent_dim: Color,
    inbound: Color,
    outbound: Color,
    violet: Color,
    coral: Color,
    inbound_border: Color,
    outbound_border: Color,
    violet_border: Color,
    overview_highlight: Color,
    warn: Color,
}

/// True-color palette: the original 24-bit RGB theme (unchanged behaviour).
const TRUECOLOR: Palette = Palette {
    bg: Color::Rgb(9, 13, 20),
    text: Color::Rgb(216, 224, 232),
    strong: Color::Rgb(244, 247, 250),
    muted: Color::Rgb(116, 129, 145),
    border: Color::Rgb(37, 53, 68),
    accent: Color::Rgb(255, 183, 3),
    accent_dim: Color::Rgb(154, 111, 8),
    inbound: Color::Rgb(255, 191, 36),
    outbound: Color::Rgb(41, 197, 246),
    violet: Color::Rgb(167, 139, 250),
    coral: Color::Rgb(251, 113, 133),
    inbound_border: Color::Rgb(102, 80, 30),
    outbound_border: Color::Rgb(29, 86, 108),
    violet_border: Color::Rgb(76, 65, 111),
    overview_highlight: Color::Rgb(43, 37, 15),
    warn: Color::Yellow,
};

/// 16-color palette: ANSI base colors mapped by hue, `Reset` background follows
/// the terminal's own palette.
const SIXTEEN: Palette = Palette {
    bg: Color::Reset,
    text: Color::Reset,
    strong: Color::Reset,
    muted: Color::DarkGray,
    border: Color::DarkGray,
    accent: Color::Yellow,
    accent_dim: Color::DarkGray,
    inbound: Color::Yellow,
    outbound: Color::Cyan,
    violet: Color::Magenta,
    coral: Color::Red,
    inbound_border: Color::DarkGray,
    outbound_border: Color::DarkGray,
    violet_border: Color::DarkGray,
    overview_highlight: Color::DarkGray,
    warn: Color::Yellow,
};

/// Monochrome palette: no color at all. Emphasis comes from [`Modifier`]s that
/// the call sites already apply (BOLD on strong/accent); the remaining roles
/// are `Reset`, which is the accepted simplification of the chosen seam.
const MONOCHROME: Palette = Palette {
    bg: Color::Reset,
    text: Color::Reset,
    strong: Color::Reset,
    muted: Color::Reset,
    border: Color::Reset,
    accent: Color::Reset,
    accent_dim: Color::Reset,
    inbound: Color::Reset,
    outbound: Color::Reset,
    violet: Color::Reset,
    coral: Color::Reset,
    inbound_border: Color::Reset,
    outbound_border: Color::Reset,
    violet_border: Color::Reset,
    overview_highlight: Color::Reset,
    warn: Color::Reset,
};

// --- Active palette ---------------------------------------------------------

/// The currently active tier. The TUI runs a single-threaded event loop, so a
/// relaxed atomic is sufficient and avoids threading the palette through every
/// draw function.
static ACTIVE: AtomicU8 = AtomicU8::new(ColorTier::Truecolor as u8);

fn active_tier() -> ColorTier {
    match ACTIVE.load(Ordering::Relaxed) {
        0 => ColorTier::Monochrome,
        1 => ColorTier::Sixteen,
        _ => ColorTier::Truecolor,
    }
}

/// Switch the active palette. Called once at startup and again whenever the
/// user changes the palette in the settings overlay.
pub(crate) fn set_active_tier(tier: ColorTier) {
    ACTIVE.store(tier as u8, Ordering::Relaxed);
}

fn active() -> &'static Palette {
    match active_tier() {
        ColorTier::Monochrome => &MONOCHROME,
        ColorTier::Sixteen => &SIXTEEN,
        ColorTier::Truecolor => &TRUECOLOR,
    }
}

// --- Role accessors ---------------------------------------------------------

pub(crate) fn bg() -> Color {
    active().bg
}
pub(crate) fn text() -> Color {
    active().text
}
pub(crate) fn strong() -> Color {
    active().strong
}
pub(crate) fn muted() -> Color {
    active().muted
}
pub(crate) fn border() -> Color {
    active().border
}
pub(crate) fn accent() -> Color {
    active().accent
}
pub(crate) fn accent_dim() -> Color {
    active().accent_dim
}
pub(crate) fn inbound() -> Color {
    active().inbound
}
pub(crate) fn outbound() -> Color {
    active().outbound
}
pub(crate) fn violet() -> Color {
    active().violet
}
pub(crate) fn coral() -> Color {
    active().coral
}
pub(crate) fn inbound_border() -> Color {
    active().inbound_border
}
pub(crate) fn outbound_border() -> Color {
    active().outbound_border
}
pub(crate) fn violet_border() -> Color {
    active().violet_border
}
pub(crate) fn overview_highlight() -> Color {
    active().overview_highlight
}
pub(crate) fn warn() -> Color {
    active().warn
}

/// Selection highlight style: a dark-blue background on true color, `REVERSED`
/// on 16-color and monochrome, where a background fill would collide with the
/// terminal's own palette.
fn selection_style_for(tier: ColorTier) -> Style {
    match tier {
        ColorTier::Truecolor => Style::default().bg(Color::Rgb(23, 43, 60)),
        ColorTier::Sixteen | ColorTier::Monochrome => {
            Style::default().add_modifier(Modifier::REVERSED)
        }
    }
}

pub(crate) fn selection_style() -> Style {
    selection_style_for(active_tier())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- detection ---

    #[test]
    fn no_color_overrides_everything() {
        // Per no-color.org, NO_COLOR wins over COLORTERM and a 256-color TERM.
        assert_eq!(
            tier_from_env(Some("truecolor"), "xterm-256color", Some("1")),
            ColorTier::Monochrome,
        );
    }

    #[test]
    fn empty_no_color_is_ignored() {
        // An empty NO_COLOR is treated as unset (no-color.org).
        assert_eq!(tier_from_env(None, "xterm", Some("")), ColorTier::Sixteen);
    }

    #[test]
    fn colorterm_truecolor_wins_over_term() {
        assert_eq!(
            tier_from_env(Some("truecolor"), "linux", None),
            ColorTier::Truecolor,
        );
        assert_eq!(
            tier_from_env(Some("24bit"), "linux", None),
            ColorTier::Truecolor,
        );
        // Case-insensitive match.
        assert_eq!(
            tier_from_env(Some("TrueColor"), "xterm", None),
            ColorTier::Truecolor,
        );
    }

    #[test]
    fn unknown_colorterm_value_falls_through() {
        assert_eq!(
            tier_from_env(Some("ansi256"), "xterm", None),
            ColorTier::Sixteen,
        );
    }

    #[test]
    fn term_256color_is_truecolor() {
        assert_eq!(
            tier_from_env(None, "xterm-256color", None),
            ColorTier::Truecolor,
        );
        assert_eq!(
            tier_from_env(None, "screen-256color", None),
            ColorTier::Truecolor,
        );
        assert_eq!(
            tier_from_env(None, "tmux-256color", None),
            ColorTier::Truecolor,
        );
    }

    #[test]
    fn basic_terms_resolve_to_sixteen() {
        assert_eq!(tier_from_env(None, "xterm", None), ColorTier::Sixteen);
        assert_eq!(tier_from_env(None, "linux", None), ColorTier::Sixteen);
        assert_eq!(tier_from_env(None, "vt220", None), ColorTier::Sixteen);
        assert_eq!(tier_from_env(None, "screen", None), ColorTier::Sixteen);
    }

    #[test]
    fn dumb_empty_and_unknown_terms_fallback_to_sixteen() {
        assert_eq!(tier_from_env(None, "dumb", None), ColorTier::Sixteen);
        assert_eq!(tier_from_env(None, "", None), ColorTier::Sixteen);
        assert_eq!(
            tier_from_env(None, "totally-unknown-term", None),
            ColorTier::Sixteen,
        );
    }

    // --- resolve ---

    #[test]
    fn auto_follows_detected_tier() {
        assert_eq!(
            resolve(PaletteChoice::Auto, ColorTier::Monochrome),
            ColorTier::Monochrome,
        );
        assert_eq!(
            resolve(PaletteChoice::Auto, ColorTier::Sixteen),
            ColorTier::Sixteen,
        );
        assert_eq!(
            resolve(PaletteChoice::Auto, ColorTier::Truecolor),
            ColorTier::Truecolor,
        );
    }

    #[test]
    fn explicit_choice_overrides_detected() {
        assert_eq!(
            resolve(PaletteChoice::Truecolor, ColorTier::Monochrome),
            ColorTier::Truecolor,
        );
        assert_eq!(
            resolve(PaletteChoice::SixteenColor, ColorTier::Truecolor),
            ColorTier::Sixteen,
        );
        assert_eq!(
            resolve(PaletteChoice::Monochrome, ColorTier::Truecolor),
            ColorTier::Monochrome,
        );
    }

    // --- palette mappings (regression guard for the approved tables) ---

    #[test]
    fn truecolor_palette_keeps_original_rgb() {
        assert_eq!(TRUECOLOR.bg, Color::Rgb(9, 13, 20));
        assert_eq!(TRUECOLOR.text, Color::Rgb(216, 224, 232));
        assert_eq!(TRUECOLOR.accent, Color::Rgb(255, 183, 3));
        assert_eq!(TRUECOLOR.inbound, Color::Rgb(255, 191, 36));
    }

    #[test]
    fn sixteen_palette_maps_traffic_categories_to_distinct_hues() {
        assert_eq!(SIXTEEN.inbound, Color::Yellow);
        assert_eq!(SIXTEEN.outbound, Color::Cyan);
        assert_eq!(SIXTEEN.violet, Color::Magenta);
        assert_eq!(SIXTEEN.coral, Color::Red);
    }

    #[test]
    fn sixteen_palette_follows_terminal_background() {
        assert_eq!(SIXTEEN.bg, Color::Reset);
        assert_eq!(SIXTEEN.text, Color::Reset);
        assert_eq!(SIXTEEN.muted, Color::DarkGray);
    }

    #[test]
    fn monochrome_palette_is_all_reset() {
        let fields = [
            MONOCHROME.bg,
            MONOCHROME.text,
            MONOCHROME.strong,
            MONOCHROME.muted,
            MONOCHROME.border,
            MONOCHROME.accent,
            MONOCHROME.accent_dim,
            MONOCHROME.inbound,
            MONOCHROME.outbound,
            MONOCHROME.violet,
            MONOCHROME.coral,
            MONOCHROME.inbound_border,
            MONOCHROME.outbound_border,
            MONOCHROME.violet_border,
            MONOCHROME.overview_highlight,
            MONOCHROME.warn,
        ];
        assert!(fields.iter().all(|&c| c == Color::Reset));
    }

    #[test]
    fn selection_style_reverses_below_truecolor() {
        let tc = selection_style_for(ColorTier::Truecolor);
        assert_eq!(tc.bg, Some(Color::Rgb(23, 43, 60)));
        assert_eq!(tc.add_modifier, Modifier::empty());

        let sixteen = selection_style_for(ColorTier::Sixteen);
        assert_eq!(sixteen.add_modifier, Modifier::REVERSED);
        assert_eq!(sixteen.bg, None);

        let mono = selection_style_for(ColorTier::Monochrome);
        assert_eq!(mono.add_modifier, Modifier::REVERSED);
    }
}

use crosswalk::ui::Theme;
use ratatui::style::Color;

fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

#[test]
fn each_name_gives_its_palette() {
    for (name, background, accent) in [
        ("synthwave", 0x1a0b2e, 0xb05cff),
        ("dracula", 0x282a36, 0xbd93f9),
        ("nord", 0x2e3440, 0x81a1c1),
        ("gruvbox", 0x282828, 0x8ec07c),
        ("catppuccin", 0x1e1e2e, 0xcba6f7),
        ("tokyo-night", 0x1a1b26, 0x7aa2f7),
        ("solarized", 0x002b36, 0x268bd2),
        ("monokai", 0x272822, 0xe6db74),
        ("one-dark", 0x282c34, 0x61afef),
        ("everforest", 0x2d353b, 0x83c092),
        ("rose-pine", 0x191724, 0xc4a7e7),
        ("kanagawa", 0x1f1f28, 0x7e9cd8),
        ("ayu", 0x0b0e14, 0x59c2ff),
        ("night-owl", 0x011627, 0x82aaff),
        ("github-dark", 0x0d1117, 0x58a6ff),
        ("palenight", 0x292d3e, 0x82aaff),
    ] {
        let theme = Theme::named(name).unwrap_or_else(|| panic!("{name} should exist"));
        assert_eq!(theme.background, rgb(background), "{name}");
        assert_eq!(theme.accent, rgb(accent), "{name}");
    }
    let terminal = Theme::named("terminal").expect("terminal should exist");
    assert_eq!(terminal.background, Color::Reset);
    assert_eq!(terminal.accent, Color::LightBlue);
}

#[test]
fn an_unknown_name_gives_none() {
    assert_eq!(Theme::named("nope"), None);
}

#[test]
fn the_names_are_listed_in_order() {
    assert_eq!(
        &Theme::NAMES[..],
        &[
            "synthwave",
            "dracula",
            "nord",
            "gruvbox",
            "catppuccin",
            "tokyo-night",
            "solarized",
            "monokai",
            "one-dark",
            "everforest",
            "rose-pine",
            "kanagawa",
            "ayu",
            "night-owl",
            "github-dark",
            "palenight",
            "solarized-light",
            "gruvbox-light",
            "catppuccin-latte",
            "github-light",
            "mono",
            "amber",
            "green",
            "paper",
            "terminal"
        ]
    );
}

#[test]
fn synthwave_is_the_default() {
    assert_eq!(Theme::named("synthwave"), Some(Theme::default()));
}

#[test]
fn inbound_differs_from_outbound_and_text_from_background_in_every_theme() {
    for name in Theme::NAMES {
        let t = Theme::named(name).unwrap();
        assert_ne!(t.inbound, t.outbound, "{name}");
        if name != "terminal" {
            // Both are the terminal's own colours there, so they are equal by design.
            assert_ne!(t.text, t.background, "{name}");
        }
    }
}

#[test]
fn terminal_holds_no_24_bit_colour() {
    let t = Theme::named("terminal").unwrap();
    for color in [
        t.background,
        t.text,
        t.muted,
        t.inbound,
        t.outbound,
        t.accent,
        t.warning,
        t.danger,
        t.ok,
        t.highlight,
    ] {
        assert!(!matches!(color, Color::Rgb(..)), "{color:?}");
    }
}

#[test]
fn each_bright_and_monochrome_name_gives_its_background_and_text() {
    for (name, background, text) in [
        ("solarized-light", 0xfdf6e3, 0x657b83),
        ("gruvbox-light", 0xfbf1c7, 0x3c3836),
        ("catppuccin-latte", 0xeff1f5, 0x4c4f69),
        ("github-light", 0xffffff, 0x24292f),
        ("mono", 0x000000, 0xd0d0d0),
        ("amber", 0x140c00, 0xffb000),
        ("green", 0x020f02, 0x33ff33),
        ("paper", 0xf2f0e9, 0x222222),
    ] {
        let theme = Theme::named(name).unwrap_or_else(|| panic!("{name} should exist"));
        assert_eq!(theme.background, rgb(background), "{name}");
        assert_eq!(theme.text, rgb(text), "{name}");
    }
}

fn channels(color: Color) -> [i32; 3] {
    match color {
        Color::Rgb(r, g, b) => [r as i32, g as i32, b as i32],
        other => panic!("{other:?} is not 24-bit"),
    }
}

fn all_ten(t: &Theme) -> [Color; 10] {
    [
        t.background,
        t.text,
        t.muted,
        t.inbound,
        t.outbound,
        t.accent,
        t.warning,
        t.danger,
        t.ok,
        t.highlight,
    ]
}

/// The hue in degrees, 0 to 360, of a colour with some saturation.
fn hue(color: Color) -> f64 {
    let [r, g, b] = channels(color).map(f64::from);
    let (max, min) = (r.max(g).max(b), r.min(g).min(b));
    let d = max - min;
    assert!(d > 0.0, "{color:?} is a grey");
    let h = if max == r {
        ((g - b) / d).rem_euclid(6.0)
    } else if max == g {
        (b - r) / d + 2.0
    } else {
        (r - g) / d + 4.0
    };
    h * 60.0
}

/// How far a colour is from the background: the sum of the channel differences.
fn distance(from: Color, to: Color) -> i32 {
    let (a, b) = (channels(from), channels(to));
    (0..3).map(|n| (a[n] - b[n]).abs()).sum()
}

#[test]
fn the_greys_have_equal_channels_amber_stays_near_42_degrees_and_green_at_120() {
    for name in ["mono", "paper"] {
        let t = Theme::named(name).unwrap();
        for color in &all_ten(&t)[1..] {
            let [r, g, b] = channels(*color);
            assert!(r == g && g == b, "{name} {color:?}");
        }
        // Paper's off-white background is the one tinted colour: within 16 of grey.
        let [r, g, b] = channels(t.background);
        assert!(r.max(g).max(b) - r.min(g).min(b) <= 16, "{name} background");
    }
    for (name, centre) in [("amber", 42.0), ("green", 120.0)] {
        for color in all_ten(&Theme::named(name).unwrap()) {
            assert!((hue(color) - centre).abs() <= 8.0, "{name} {color:?}");
        }
    }
}

#[test]
fn in_a_monochrome_theme_ok_warning_and_danger_differ_and_danger_is_furthest_from_the_background() {
    for name in ["mono", "amber", "green", "paper"] {
        let t = Theme::named(name).unwrap();
        assert!(
            t.ok != t.warning && t.warning != t.danger && t.ok != t.danger,
            "{name}"
        );
        let (ok, warning, danger) = (
            distance(t.ok, t.background),
            distance(t.warning, t.background),
            distance(t.danger, t.background),
        );
        assert!(
            danger > ok && danger > warning,
            "{name}: {ok} {warning} {danger}"
        );
    }
}

#[test]
fn a_bright_theme_has_a_selection_that_differs_from_its_text_and_a_muted_that_differs_from_the_background()
 {
    for name in [
        "solarized-light",
        "gruvbox-light",
        "catppuccin-latte",
        "github-light",
        "paper",
    ] {
        let t = Theme::named(name).unwrap();
        let selection = t.selection();
        assert_ne!(selection.bg, selection.fg, "{name}");
        assert_ne!(t.muted, t.background, "{name}");
    }
}

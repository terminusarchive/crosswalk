use ratatui::style::{Color, Modifier, Style};

/// One colour per documented name; the panes build their styles from these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    pub background: Color,
    pub text: Color,
    pub muted: Color,
    pub inbound: Color,
    pub outbound: Color,
    pub accent: Color,
    pub warning: Color,
    pub danger: Color,
    pub ok: Color,
    pub highlight: Color,
}

impl Default for Theme {
    /// The synthwave palette: indigo, cyan, hot pink, purple and sunset orange.
    fn default() -> Self {
        palette([
            0x1a0b2e, 0xf0e6ff, 0x8a7aaa, 0x00f0ff, 0xff2a8a, 0xb05cff, 0xff9a3c, 0xff3860,
            0x3cff9a, 0xffe66d,
        ])
    }
}

/// A theme from ten `0xrrggbb` values, in the order of the fields.
fn palette(hex: [u32; 10]) -> Theme {
    let [
        background,
        text,
        muted,
        inbound,
        outbound,
        accent,
        warning,
        danger,
        ok,
        highlight,
    ] = hex.map(|h| Color::Rgb((h >> 16) as u8, (h >> 8) as u8, h as u8));
    Theme {
        background,
        text,
        muted,
        inbound,
        outbound,
        accent,
        warning,
        danger,
        ok,
        highlight,
    }
}

impl Theme {
    /// The built-in themes, in the order `t` cycles them.
    pub const NAMES: [&'static str; 25] = [
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
        "terminal",
    ];

    /// The built-in theme of that name.
    pub fn named(name: &str) -> Option<Self> {
        Some(match name {
            "synthwave" => Self::default(),
            "dracula" => palette([
                0x282a36, 0xf8f8f2, 0x6272a4, 0x8be9fd, 0xff79c6, 0xbd93f9, 0xffb86c, 0xff5555,
                0x50fa7b, 0xf1fa8c,
            ]),
            "nord" => palette([
                0x2e3440, 0xd8dee9, 0x616e88, 0x88c0d0, 0xb48ead, 0x81a1c1, 0xd08770, 0xbf616a,
                0xa3be8c, 0xebcb8b,
            ]),
            "gruvbox" => palette([
                0x282828, 0xebdbb2, 0x928374, 0x83a598, 0xd3869b, 0x8ec07c, 0xfe8019, 0xfb4934,
                0xb8bb26, 0xfabd2f,
            ]),
            "catppuccin" => palette([
                0x1e1e2e, 0xcdd6f4, 0x7f849c, 0x89dceb, 0xf5c2e7, 0xcba6f7, 0xfab387, 0xf38ba8,
                0xa6e3a1, 0xf9e2af,
            ]),
            "tokyo-night" => palette([
                0x1a1b26, 0xc0caf5, 0x565f89, 0x7dcfff, 0xbb9af7, 0x7aa2f7, 0xff9e64, 0xf7768e,
                0x9ece6a, 0xe0af68,
            ]),
            "solarized" => palette([
                0x002b36, 0x93a1a1, 0x586e75, 0x2aa198, 0xd33682, 0x268bd2, 0xcb4b16, 0xdc322f,
                0x859900, 0xb58900,
            ]),
            "monokai" => palette([
                0x272822, 0xf8f8f2, 0x75715e, 0x66d9ef, 0xae81ff, 0xe6db74, 0xfd971f, 0xf92672,
                0xa6e22e, 0xf4bf75,
            ]),
            "one-dark" => palette([
                0x282c34, 0xabb2bf, 0x5c6370, 0x56b6c2, 0xc678dd, 0x61afef, 0xd19a66, 0xe06c75,
                0x98c379, 0xe5c07b,
            ]),
            "everforest" => palette([
                0x2d353b, 0xd3c6aa, 0x859289, 0x7fbbb3, 0xd699b6, 0x83c092, 0xe69875, 0xe67e80,
                0xa7c080, 0xdbbc7f,
            ]),
            "rose-pine" => palette([
                0x191724, 0xe0def4, 0x6e6a86, 0x9ccfd8, 0xebbcba, 0xc4a7e7, 0xea9a97, 0xeb6f92,
                0x31748f, 0xf6c177,
            ]),
            "kanagawa" => palette([
                0x1f1f28, 0xdcd7ba, 0x727169, 0x7fb4ca, 0x957fb8, 0x7e9cd8, 0xffa066, 0xe46876,
                0x98bb6c, 0xe6c384,
            ]),
            "ayu" => palette([
                0x0b0e14, 0xbfbdb6, 0x626a73, 0x39bae6, 0xd2a6ff, 0x59c2ff, 0xff8f40, 0xf07178,
                0xaad94c, 0xe6b450,
            ]),
            "night-owl" => palette([
                0x011627, 0xd6deeb, 0x637777, 0x7fdbca, 0xc792ea, 0x82aaff, 0xf78c6c, 0xef5350,
                0xaddb67, 0xecc48d,
            ]),
            "github-dark" => palette([
                0x0d1117, 0xc9d1d9, 0x8b949e, 0x39c5cf, 0xbc8cff, 0x58a6ff, 0xd29922, 0xf85149,
                0x3fb950, 0xe3b341,
            ]),
            "palenight" => palette([
                0x292d3e, 0xa6accd, 0x676e95, 0x89ddff, 0xc792ea, 0x82aaff, 0xf78c6c, 0xff5370,
                0xc3e88d, 0xffcb6b,
            ]),
            "solarized-light" => palette([
                0xfdf6e3, 0x657b83, 0x93a1a1, 0x2aa198, 0xd33682, 0x268bd2, 0xcb4b16, 0xdc322f,
                0x859900, 0xb58900,
            ]),
            "gruvbox-light" => palette([
                0xfbf1c7, 0x3c3836, 0x928374, 0x076678, 0x8f3f71, 0x427b58, 0xaf3a03, 0x9d0006,
                0x79740e, 0xb57614,
            ]),
            "catppuccin-latte" => palette([
                0xeff1f5, 0x4c4f69, 0x8c8fa1, 0x04a5e5, 0xea76cb, 0x8839ef, 0xfe640b, 0xd20f39,
                0x40a02b, 0xdf8e1d,
            ]),
            "github-light" => palette([
                0xffffff, 0x24292f, 0x6e7781, 0x1b7c83, 0x8250df, 0x0969da, 0xbc4c00, 0xcf222e,
                0x1a7f37, 0x9a6700,
            ]),
            "mono" => palette([
                0x000000, 0xd0d0d0, 0x707070, 0xffffff, 0xa0a0a0, 0xffffff, 0xc0c0c0, 0xffffff,
                0x909090, 0xffffff,
            ]),
            "amber" => palette([
                0x140c00, 0xffb000, 0x8a5f00, 0xffcc4d, 0xc88a00, 0xffd166, 0xffc233, 0xfff0c2,
                0xb37c00, 0xffe08a,
            ]),
            "green" => palette([
                0x020f02, 0x33ff33, 0x1f8f1f, 0x66ff66, 0x22bb22, 0x99ff99, 0x55ee55, 0xccffcc,
                0x2aa82a, 0xb3ffb3,
            ]),
            "paper" => palette([
                0xf2f0e9, 0x222222, 0x8a8a8a, 0x000000, 0x555555, 0x000000, 0x444444, 0x000000,
                0x777777, 0x000000,
            ]),
            // The terminal's own background and text, and its named colours.
            "terminal" => Self {
                background: Color::Reset,
                text: Color::Reset,
                muted: Color::DarkGray,
                inbound: Color::Cyan,
                outbound: Color::Magenta,
                accent: Color::LightBlue,
                warning: Color::Yellow,
                danger: Color::Red,
                ok: Color::Green,
                highlight: Color::LightYellow,
            },
            _ => return None,
        })
    }

    /// Sets a colour by its documented name; false when the name is unknown.
    pub fn set(&mut self, name: &str, color: Color) -> bool {
        let slot = match name {
            "background" => &mut self.background,
            "text" => &mut self.text,
            "muted" => &mut self.muted,
            "inbound" => &mut self.inbound,
            "outbound" => &mut self.outbound,
            "accent" => &mut self.accent,
            "warning" => &mut self.warning,
            "danger" => &mut self.danger,
            "ok" => &mut self.ok,
            "highlight" => &mut self.highlight,
            _ => return false,
        };
        *slot = color;
        true
    }

    /// This theme with each named colour replaced.
    pub fn with_overrides(mut self, overrides: &[(&'static str, Color)]) -> Self {
        for (name, color) in overrides {
            self.set(name, *color);
        }
        self
    }

    pub fn background(&self) -> Style {
        Style::default().bg(self.background).fg(self.text)
    }

    pub fn focus(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn heading(&self) -> Style {
        Style::default()
            .fg(self.inbound)
            .add_modifier(Modifier::BOLD)
    }

    /// Plain body text.
    pub fn text(&self) -> Style {
        Style::default().fg(self.text)
    }

    /// Table column titles: quiet, so the data stands out.
    pub fn table_header(&self) -> Style {
        Style::default().fg(self.muted)
    }

    /// Pane border: accent when focused, otherwise muted.
    pub fn border(&self, focused: bool) -> Style {
        if focused { self.focus() } else { self.muted() }
    }

    /// Pane title: accent and bold when focused, otherwise plain text.
    pub fn title(&self, focused: bool) -> Style {
        if focused { self.focus() } else { self.text() }
    }

    /// An exposed listening port: the loudest style on the screen.
    pub fn open(&self) -> Style {
        Style::default()
            .fg(self.danger)
            .add_modifier(Modifier::BOLD)
    }

    /// The interface name in the Bandwidth title; used for nothing else.
    pub fn name_highlight(&self) -> Style {
        Style::default()
            .fg(self.highlight)
            .add_modifier(Modifier::BOLD)
    }

    pub fn observed(&self) -> Style {
        Style::default().fg(self.ok)
    }

    pub fn blocked(&self) -> Style {
        Style::default().fg(self.danger)
    }

    pub fn warning(&self) -> Style {
        Style::default().fg(self.warning)
    }

    pub fn muted(&self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn selection(&self) -> Style {
        Style::default().bg(self.muted).fg(self.text)
    }
}

/// Parses `#rrggbb`.
pub fn parse_hex(value: &str) -> Option<Color> {
    let digits = value.strip_prefix('#')?;
    if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let channel = |i: usize| u8::from_str_radix(&digits[i..i + 2], 16).ok();
    Some(Color::Rgb(channel(0)?, channel(2)?, channel(4)?))
}

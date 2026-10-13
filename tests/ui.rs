use std::{path::PathBuf, time::Duration};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crosswalk::{
    collect::{
        attribution::{
            AttributionHealth, AttributionStatus, ExecutableIdentity, Listener, ProcessIdentity,
        },
        capture::{
            CaptureHealth, CaptureOrigin, CaptureStatus, Direction, Endpoint, Protocol,
            TrafficEvent,
        },
        interfaces::{
            CollectionHealth, InterfaceAddress, InterfaceMeasurement, InterfaceSnapshot,
            InterfaceStatus,
        },
    },
    firewall::{
        Allowed, FirewallEndpoint, FirewallEvent, FirewallHealth, FirewallStatus, Network, Policy,
        Rule, RuleAction, RuleDirection, RuleSnapshot, RuleSource, Zone, Zones,
        firewalld_reply::{ActiveZone, PortRule, Target},
    },
    state::{AppState, Page, Pane, StateLimits},
    ui::{Overview, Theme, draw, terminal_title},
};
use crosswalk::{
    dns::ReverseDns,
    ui::{Interaction, draw_interactive},
};
use ratatui::{Terminal, backend::TestBackend};

fn press(i: &mut Interaction, state: &AppState, code: KeyCode) {
    i.handle_key(KeyEvent::new(code, KeyModifiers::NONE), state);
}

/// The Traffic page, App Traffic focused.
fn draw_at(state: &AppState, width: u16, height: u16) -> Terminal<TestBackend> {
    draw_focused(state, Pane::AppTraffic, width, height)
}

fn draw_focused(state: &AppState, focus: Pane, width: u16, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| draw(frame, state, &Theme::default(), &Overview::new(focus)))
        .unwrap();
    terminal
}

fn screen(
    state: &AppState,
    i: &mut Interaction,
    dns: Option<&ReverseDns>,
    width: u16,
    height: u16,
) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| draw_interactive(frame, state, &Theme::default(), i, dns))
        .unwrap();
    terminal
}

fn lines(terminal: &Terminal<TestBackend>) -> Vec<String> {
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect()
        })
        .collect()
}

fn text_of(terminal: &Terminal<TestBackend>) -> String {
    lines(terminal).join("\n")
}

mod table_renderer {
    use crosswalk::ui::{
        Theme,
        format::{format_bytes, format_rate},
        table::{Align, Cell, Column, Row, Table},
    };
    use ratatui::{Terminal, backend::TestBackend, style::Color};

    fn columns() -> Vec<Column> {
        vec![
            Column::new("App", Align::Left, 6, 9),
            Column::new("Port", Align::Right, 5, 5),
            Column::new("Rate", Align::Right, 8, 7),
            Column::new("Path", Align::Left, 8, 1),
        ]
    }

    fn rows() -> Vec<Row> {
        vec![
            Row::new(["firefox", "443", "1.2 MB/s", "/usr/lib/firefox/firefox"]),
            Row::new(["curl", "80", "3 B/s", "/usr/bin/curl"]),
            Row::new(["sshd", "22", "0 B/s", "/usr/bin/sshd"]),
        ]
    }

    struct Drawn {
        lines: Vec<String>,
        scroll: usize,
        selected: Option<usize>,
        buffer: ratatui::buffer::Buffer,
    }

    fn draw(
        width: u16,
        height: u16,
        rows: Vec<Row>,
        selected: Option<usize>,
        scroll: usize,
    ) -> Drawn {
        let theme = Theme::default();
        let columns = columns();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut out = None;
        terminal
            .draw(|frame| {
                let table = Table::new(&columns, &rows, &theme)
                    .selected(selected)
                    .scroll(scroll);
                let area = frame.area();
                out = Some(table.render(frame.buffer_mut(), area));
            })
            .unwrap();
        let out = out.unwrap();
        let buffer = terminal.backend().buffer().clone();
        let lines = (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect();
        Drawn {
            lines,
            scroll: out.scroll,
            selected: out.selected,
            buffer,
        }
    }

    #[test]
    fn columns_line_up_under_their_headers() {
        let d = draw(60, 5, rows(), None, 0);
        let header = &d.lines[0];
        let port = header.find("Port").unwrap();
        let rate = header.find("Rate").unwrap();
        // Right-aligned columns end where their header ends.
        assert_eq!(d.lines[1].find("443").unwrap() + 3, port + 4);
        assert_eq!(d.lines[2].find("80").unwrap() + 2, port + 4);
        assert_eq!(d.lines[1].find("1.2 MB/s").unwrap() + 8, rate + 4);
        // Left-aligned columns start under their headers.
        assert_eq!(d.lines[1].find("firefox"), header.find("App"));
        assert_eq!(d.lines[3].find("sshd"), header.find("App"));
    }

    #[test]
    fn narrowing_drops_columns_in_priority_order_without_overlap() {
        let wide = draw(60, 4, rows(), None, 0);
        assert!(wide.lines[0].contains("Path"));
        let mut seen = vec![];
        for width in [28u16, 20, 12, 6] {
            let d = draw(width, 4, rows(), None, 0);
            let header = d.lines[0].clone();
            let present: Vec<&str> = ["App", "Port", "Rate", "Path"]
                .into_iter()
                .filter(|t| header.contains(t))
                .collect();
            seen.push(present.len());
            // Never keep a column while dropping a higher-priority one.
            // Drop order is Path (1), Port (5), Rate (7), App (9).
            if header.contains("Path") {
                assert!(header.contains("Port"));
            }
            if header.contains("Port") {
                assert!(header.contains("Rate"));
            }
            if header.contains("Rate") {
                assert!(header.contains("App"));
            }
            assert!(!present.is_empty());
            // Rows never run into the next column: no row text is cut by overlap.
            assert!(d.lines[1].starts_with("firefox") || d.lines[1].starts_with("firef"));
        }
        assert!(seen.windows(2).all(|w| w[0] >= w[1]), "{seen:?}");
        assert!(seen[0] < 4 && *seen.last().unwrap() == 1);
    }

    #[test]
    fn last_column_is_truncated_with_an_ellipsis() {
        let d = draw(40, 3, rows(), None, 0);
        assert!(d.lines[1].contains('…'), "{:?}", d.lines[1]);
        assert!(d.lines[1].trim_end().chars().count() <= 40);
    }

    #[test]
    fn selection_past_the_end_lands_on_the_last_visible_row() {
        let d = draw(60, 3, rows(), Some(99), 0);
        assert_eq!(d.selected, Some(2));
        // Header plus two body rows: the last row (sshd) is scrolled into view.
        assert_eq!(d.scroll, 1);
        assert!(d.lines.join("\n").contains("sshd"));
        let sshd_y = d.lines.iter().position(|l| l.contains("sshd")).unwrap();
        assert_ne!(d.buffer[(0, sshd_y as u16)].bg, Color::Reset);
    }

    #[test]
    fn scrolls_only_to_keep_the_selection_visible() {
        let d = draw(60, 3, rows(), Some(1), 0);
        assert_eq!(d.scroll, 0);
        let d = draw(60, 3, rows(), Some(0), 1);
        assert_eq!(d.scroll, 0);
        let d = draw(60, 3, rows(), Some(2), 1);
        assert_eq!(d.scroll, 1);
    }

    #[test]
    fn rows_are_cut_off_at_the_bottom_and_styles_apply() {
        let theme = Theme::default();
        let mut rows = rows();
        rows[0] = rows[0].clone().style(theme.muted());
        rows[1].cells[1] = Cell::new("80").style(theme.blocked());
        let d = draw(60, 3, rows, None, 0);
        assert!(!d.lines.join("\n").contains("sshd"));
        assert_eq!(d.buffer[(0, 1)].fg, theme.muted);
        let x = d.lines[2].find("80").unwrap() as u16;
        assert_eq!(d.buffer[(x, 2)].fg, theme.danger);
    }

    /// The lines of a table of `columns` and `rows` drawn `width` wide.
    fn lines_of(columns: &[Column], rows: &[Row], width: u16) -> Vec<String> {
        let theme = Theme::default();
        let mut terminal = Terminal::new(TestBackend::new(width, 6)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                Table::new(columns, rows, &theme).render(frame.buffer_mut(), area);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..6)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect()
            })
            .collect()
    }

    /// The same columns as `columns()` with Path taking the rest.
    fn filled() -> Vec<Column> {
        vec![
            Column::new("App", Align::Left, 6, 9),
            Column::new("Port", Align::Right, 5, 5),
            Column::new("Rate", Align::Right, 8, 7),
            Column::new("Path", Align::Left, 8, 1).fill(1),
        ]
    }

    #[test]
    fn fixed_columns_take_their_content_width_and_the_marked_one_the_rest() {
        let lines = lines_of(&filled(), &rows(), 60);
        // App is seven wide (firefox), Port four (its title), Rate eight.
        assert_eq!(&lines[0], &format!("{:<60}", "App     Port     Rate Path"));
        assert_eq!(
            &lines[1],
            &format!("{:<60}", "firefox  443 1.2 MB/s /usr/lib/firefox/firefox")
        );
        assert_eq!(
            &lines[2],
            &format!("{:<60}", "curl      80    3 B/s /usr/bin/curl")
        );
    }

    #[test]
    fn the_last_column_ends_at_the_right_edge_at_every_width() {
        let columns = vec![
            Column::new("App", Align::Left, 6, 9),
            Column::new("Path", Align::Left, 8, 1).fill(1),
            Column::new("Rate", Align::Right, 8, 7),
        ];
        let rows = vec![
            Row::new(["firefox", "/usr/lib/firefox/firefox", "1.2 MB/s"]),
            Row::new(["curl", "/usr/bin/curl", "3 B/s"]),
        ];
        for width in [30u16, 45, 60, 90] {
            let lines = lines_of(&columns, &rows, width);
            assert!(lines[0].ends_with("Rate"), "{width}: {:?}", lines[0]);
            assert!(lines[1].ends_with("1.2 MB/s"), "{width}: {:?}", lines[1]);
            assert!(lines[2].ends_with("   3 B/s"), "{width}: {:?}", lines[2]);
        }
    }

    #[test]
    fn the_marked_column_is_cut_only_when_its_text_exceeds_its_room() {
        let whole = lines_of(&filled(), &rows(), 60);
        assert!(whole[1].contains("/usr/lib/firefox/firefox"));
        assert!(!whole[1].contains('…'));
        // 40 wide leaves 18 cells for Path (7 + 4 + 8 + three gaps are fixed).
        let cut = lines_of(&filled(), &rows(), 40);
        assert_eq!(&cut[1], "firefox  443 1.2 MB/s /usr/lib/firefox/…");
        assert_eq!(
            &cut[2],
            &format!("{:<40}", "curl      80    3 B/s /usr/bin/curl")
        );
    }

    #[test]
    fn two_marked_columns_the_first_gets_what_it_needs_and_the_second_the_rest() {
        let columns = vec![
            Column::new("ADDRESS", Align::Left, 15, 3).fill(2),
            Column::new("NAME", Align::Left, 4, 1).fill(1),
            Column::new("MAC", Align::Left, 17, 2),
        ];
        let v6 = "fe80::a1:b2c3:aaaa:1234";
        let mac = "aa:bb:cc:dd:ee:ff";
        // A short name: ADDRESS gets the rest and is whole.
        let lines = lines_of(&columns, &[Row::new([v6, "gw", mac])], 60);
        assert!(lines[1].starts_with(v6), "{:?}", lines[1]);
        assert_eq!(lines[1].find("gw"), Some(38));
        assert!(lines[1].ends_with(mac));
        // A long name keeps its room and the address is cut.
        let name = "gateway.home.example";
        let lines = lines_of(&columns, &[Row::new([v6, name, mac])], 60);
        assert!(lines[1].contains(name), "{:?}", lines[1]);
        assert!(
            lines[1].starts_with("fe80::a1:b2c3:aaaa:1…"),
            "{:?}",
            lines[1]
        );
        // The second never falls below its minimum: the name is cut instead.
        let name = "a-very-long-name.in.some.domain.example.com";
        let lines = lines_of(&columns, &[Row::new([v6, name, mac])], 60);
        assert!(
            lines[1].starts_with("fe80::a1:b2c3:… a-very-long-name"),
            "{:?}",
            lines[1]
        );
        assert!(lines[1].contains("…"));
        assert!(lines[1].ends_with(mac));
    }

    #[test]
    fn marked_tables_keep_alignment_and_titles_over_cells() {
        let lines = lines_of(&filled(), &rows(), 60);
        let port = lines[0].find("Port").unwrap();
        let rate = lines[0].find("Rate").unwrap();
        assert_eq!(lines[1].find("443").unwrap() + 3, port + 4);
        assert_eq!(lines[2].find("80").unwrap() + 2, port + 4);
        assert_eq!(lines[1].find("1.2 MB/s").unwrap() + 8, rate + 4);
        assert_eq!(lines[1].find("firefox"), lines[0].find("App"));
        assert_eq!(lines[1].find("/usr/lib"), lines[0].find("Path"));
    }

    #[test]
    fn a_marked_column_empty_in_every_row_leaves_the_others_at_the_edge() {
        let columns = vec![
            Column::new("Path", Align::Left, 4, 1).fill(1),
            Column::new("Rate", Align::Right, 8, 2),
        ];
        let rows = vec![Row::new(["", "1.2 MB/s"]), Row::new(["", "3 B/s"])];
        let lines = lines_of(&columns, &rows, 40);
        assert!(lines[0].ends_with("Rate"));
        assert!(lines[1].ends_with("1.2 MB/s"));
        assert!(lines[2].ends_with("   3 B/s"));
        assert_eq!(lines[1].find("1.2 MB/s"), Some(32));
    }

    #[test]
    fn a_table_with_no_marked_column_keeps_its_preset_widths() {
        let lines = lines_of(&columns(), &rows(), 60);
        // App 7, Port 5 (its preset), Rate 8: Path starts at 7 + 1 + 5 + 1 + 8 + 1.
        assert_eq!(lines[0].find("Path"), Some(23));
    }

    #[test]
    fn marking_a_column_does_not_change_which_columns_are_dropped() {
        let long = vec![Row::new([
            "a-long-application-name",
            "443",
            "1.2 MB/s",
            "/a/very/long/path/that/goes/on/and/on/and/on/and/on",
        ])];
        for width in [60u16, 44, 36, 28, 24, 20, 16, 12, 6] {
            let kept = |columns: &[Column], rows: &[Row]| -> Vec<bool> {
                let header = lines_of(columns, rows, width)[0].clone();
                ["App", "Port", "Rate", "Path"]
                    .iter()
                    .map(|t| header.contains(t))
                    .collect()
            };
            // The same before the change and whatever the cells hold.
            assert_eq!(
                kept(&columns(), &rows()),
                kept(&filled(), &rows()),
                "{width}"
            );
            assert_eq!(kept(&filled(), &rows()), kept(&filled(), &long), "{width}");
        }
    }

    #[test]
    fn a_fixed_column_squeezed_below_its_contents_is_cut_with_an_ellipsis_not_overlapped() {
        let columns = vec![
            Column::new("App", Align::Left, 4, 3),
            Column::new("Path", Align::Left, 8, 1).fill(1),
            Column::new("Rate", Align::Right, 4, 2),
        ];
        let rows = vec![Row::new(["firefox-esr-dev", "/usr/bin/x-long", "1.2M"])];
        // The reserved minimums fill the 18 cells exactly: 4 + 8 + 4 + 2 gaps.
        let lines = lines_of(&columns, &rows, 18);
        assert_eq!(&lines[1], "fir… /usr/bi… 1.2M");
        assert_eq!(&lines[0], "App  Path     Rate");
    }

    #[test]
    fn a_bounded_fixed_column_cannot_starve_the_marked_one() {
        let columns = vec![
            Column::new("App", Align::Left, 6, 9).at_most(10),
            Column::new("Path", Align::Left, 8, 1).fill(1),
        ];
        let rows = vec![Row::new(["an-application-with-a-long-name", "/usr/bin/x"])];
        let lines = lines_of(&columns, &rows, 40);
        assert_eq!(&lines[1], &format!("{:<40}", "an-applic… /usr/bin/x"));
    }

    #[test]
    fn unit_formatters_switch_at_their_boundaries() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_000), "1.0 KB");
        assert_eq!(format_bytes(1_200_000), "1.2 MB");
        assert_eq!(format_bytes(1_000_000), "1.0 MB");
        assert_eq!(format_bytes(1_000_000_000), "1.0 GB");
        assert_eq!(format_bytes(999_999), "1.0 MB");
        assert_eq!(format_rate(999.0), "999 B/s");
        assert_eq!(format_rate(1_000.0), "1.0 KB/s");
        assert_eq!(format_rate(1_000_000.0), "1.0 MB/s");
        assert_eq!(format_rate(1_000_000_000.0), "1.0 GB/s");
    }
}

mod mirrored_chart {
    use std::time::Duration;

    use crosswalk::{
        state::{ByteTotals, RateSample},
        ui::{
            Theme,
            chart::{Chart, GUTTER_WIDTH, shade},
        },
    };
    use ratatui::{buffer::Buffer, layout::Rect, style::Color};

    const PLOT: u16 = 10;
    const WIDTH: u16 = GUTTER_WIDTH + PLOT;
    const HEIGHT: u16 = 7; // 3 outbound rows, centre line, 3 inbound rows

    fn sample(second: u64, download: f64, upload: f64) -> RateSample {
        RateSample {
            at: Duration::from_secs(second),
            download,
            upload,
        }
    }

    fn render(samples: &[RateSample], height: u16) -> Buffer {
        render_in(samples, height, &Theme::default())
    }

    fn render_in(samples: &[RateSample], height: u16, theme: &Theme) -> Buffer {
        let area = Rect::new(0, 0, WIDTH, height);
        let mut buffer = Buffer::empty(area);
        Chart::new(samples, ByteTotals::default(), theme).render(&mut buffer, area);
        buffer
    }

    fn symbol(buffer: &Buffer, plot_x: u16, y: u16) -> String {
        buffer[(GUTTER_WIDTH + plot_x, y)].symbol().to_string()
    }

    fn gutter(buffer: &Buffer) -> String {
        (0..buffer.area.height)
            .map(|y| {
                (0..GUTTER_WIDTH)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every built-in theme but `terminal`, which has no RGB colours.
    fn rgb_themes() -> Vec<Theme> {
        Theme::NAMES
            .iter()
            .filter(|name| **name != "terminal")
            .map(|name| Theme::named(name).unwrap())
            .collect()
    }

    fn channels(colour: Color) -> [i32; 3] {
        let Color::Rgb(r, g, b) = colour else {
            panic!("{colour:?} is not RGB")
        };
        [r, g, b].map(i32::from)
    }

    /// How far a colour is from the background, summed over the channels.
    fn distance(colour: Color, background: Color) -> i32 {
        let (a, b) = (channels(colour), channels(background));
        (0..3).map(|n| (a[n] - b[n]).abs()).sum()
    }

    /// The colour of the inbound bar in a column, from its first row: a full
    /// block is drawn in it, a partial one over it as a background.
    fn inbound_tone(buffer: &Buffer, plot_x: u16) -> Color {
        let cell = &buffer[(GUTTER_WIDTH + plot_x, 4)];
        if cell.symbol() == "█" {
            cell.fg
        } else {
            cell.bg
        }
    }

    #[test]
    fn a_bar_at_the_peak_is_the_themes_colour_exactly() {
        for theme in rgb_themes() {
            for colour in [theme.outbound, theme.inbound] {
                assert_eq!(shade(colour, theme.background, 1.0), colour);
            }
        }
    }

    #[test]
    fn the_smallest_bar_is_dimmer_than_the_colour_and_still_distinct_from_the_background() {
        for theme in rgb_themes() {
            for colour in [theme.outbound, theme.inbound] {
                let floor = shade(colour, theme.background, 0.0);
                assert_ne!(floor, theme.background, "{theme:?}");
                assert!(distance(floor, theme.background) < distance(colour, theme.background));
            }
        }
    }

    #[test]
    fn a_taller_bar_is_never_nearer_the_background_than_a_shorter_one() {
        for theme in rgb_themes() {
            for colour in [theme.outbound, theme.inbound] {
                let distances: Vec<i32> = (0..=20)
                    .map(|n| shade(colour, theme.background, f64::from(n) / 20.0))
                    .map(|tone| distance(tone, theme.background))
                    .collect();
                assert!(
                    distances.windows(2).all(|pair| pair[0] <= pair[1]),
                    "{distances:?}"
                );
            }
        }
    }

    #[test]
    fn a_colour_that_is_not_rgb_comes_back_unchanged() {
        let rgb = Color::Rgb(10, 20, 30);
        assert_eq!(shade(Color::Cyan, Color::Reset, 0.5), Color::Cyan);
        assert_eq!(shade(Color::Cyan, rgb, 0.5), Color::Cyan);
        assert_eq!(shade(rgb, Color::Reset, 0.5), rgb);
    }

    #[test]
    fn bars_are_shaded_by_their_value_against_the_peak_of_their_own_side() {
        let theme = Theme::default();
        // Outbound 1000, 500, 10, 0; inbound 10, 500, 1000, 0.
        let buffer = render(
            &[
                sample(0, 10.0, 1000.0),
                sample(1, 500.0, 500.0),
                sample(2, 1000.0, 10.0),
                sample(3, 0.0, 0.0),
            ],
            HEIGHT,
        );
        let up = |x: u16| buffer[(GUTTER_WIDTH + PLOT - 4 + x, 2)].fg;
        let down = |x: u16| inbound_tone(&buffer, PLOT - 4 + x);
        let from_background = |colour| distance(colour, theme.background);
        assert_eq!(up(0), theme.outbound);
        assert!(from_background(up(1)) < from_background(up(0)));
        assert!(from_background(up(2)) < from_background(up(1)));
        assert!(from_background(up(2)) > 0);
        assert!(from_background(down(0)) < from_background(down(1)));
        assert!(from_background(down(1)) < from_background(down(2)));
        assert_eq!(down(2), theme.inbound);
        assert_eq!(symbol(&buffer, PLOT - 1, 2), " ");
        assert_eq!(symbol(&buffer, PLOT - 1, 4), " ");
    }

    #[test]
    fn the_terminal_theme_keeps_flat_bars() {
        let theme = Theme::named("terminal").unwrap();
        let samples = [sample(0, 10.0, 1000.0), sample(1, 1000.0, 10.0)];
        let buffer = render_in(&samples, HEIGHT, &theme);
        assert_eq!(buffer[(GUTTER_WIDTH + PLOT - 2, 2)].fg, theme.outbound);
        assert_eq!(buffer[(GUTTER_WIDTH + PLOT - 1, 2)].fg, theme.outbound);
        assert_eq!(inbound_tone(&buffer, PLOT - 2), theme.inbound);
        assert_eq!(inbound_tone(&buffer, PLOT - 1), theme.inbound);
    }

    #[test]
    fn newest_sample_is_in_the_rightmost_column() {
        let buffer = render(&[sample(0, 0.0, 0.0), sample(1, 100.0, 50.0)], HEIGHT);
        assert_eq!(symbol(&buffer, PLOT - 1, 2), "█");
        assert_eq!(symbol(&buffer, PLOT - 1, 4), "█");
        assert_eq!(symbol(&buffer, PLOT - 2, 2), " ");
        assert_eq!(symbol(&buffer, PLOT - 2, 4), " ");
    }

    #[test]
    fn largest_samples_fill_their_own_half() {
        let theme = Theme::default();
        let buffer = render(&[sample(0, 1000.0, 10.0), sample(1, 10.0, 500.0)], HEIGHT);
        // Outbound peak is the second sample: all three rows above the centre are full.
        for y in 0..3 {
            assert_eq!(symbol(&buffer, PLOT - 1, y), "█");
            assert_eq!(buffer[(GUTTER_WIDTH + PLOT - 1, y)].fg, theme.outbound);
        }
        // Inbound peak is the first sample: all three rows below hang full.
        for y in 4..7 {
            assert_eq!(symbol(&buffer, PLOT - 2, y), "█");
            assert_eq!(buffer[(GUTTER_WIDTH + PLOT - 2, y)].fg, theme.inbound);
        }
        // A small non-zero sample is still at least one eighth.
        assert_eq!(symbol(&buffer, PLOT - 2, 2), "▁");
        assert_eq!(symbol(&buffer, PLOT - 1, 4), "▇");
        // Its partial cell is the background over a dimmer inbound tone.
        assert_ne!(buffer[(GUTTER_WIDTH + PLOT - 1, 4)].bg, theme.inbound);
        assert_eq!(buffer[(GUTTER_WIDTH + PLOT - 1, 4)].fg, theme.background);
    }

    #[test]
    fn empty_history_draws_only_the_centre_line() {
        let buffer = render(&[], HEIGHT);
        for y in 0..HEIGHT {
            for x in 0..PLOT {
                let expected = if y == 3 { "─" } else { " " };
                assert_eq!(symbol(&buffer, x, y), expected, "({x},{y})");
            }
        }
    }

    #[test]
    fn only_the_newest_samples_that_fit_are_drawn() {
        let mut samples = vec![sample(0, 0.0, 9000.0)];
        samples.extend((1..=PLOT as u64).map(|s| sample(s, 0.0, 100.0)));
        let buffer = render(&samples, HEIGHT);
        // The 9000 sample is off the left edge, so it is not the peak either.
        assert_eq!(symbol(&buffer, 0, 2), "█");
        assert!(!gutter(&buffer).contains("9.0 KB"));
    }

    #[test]
    fn gutter_shows_current_rate_and_peak_in_units() {
        let buffer = render(
            &[sample(0, 2_500_000.0, 3000.0), sample(1, 1500.0, 40.0)],
            HEIGHT,
        );
        let gutter = gutter(&buffer);
        let rows: Vec<&str> = gutter.lines().collect();
        assert!(rows[0].contains("↑ out"), "outbound is on top:\n{gutter}");
        assert!(rows[4].contains("↓ in"), "inbound is below:\n{gutter}");
        for expected in [
            "↓ in", "↑ out", "1.5 KB/s", "2.5 MB/s", "40 B/s", "3.0 KB/s",
        ] {
            assert!(
                gutter.contains(expected),
                "missing {expected:?} in\n{gutter}"
            );
        }
    }

    #[test]
    fn gutter_width_does_not_change_with_the_numbers() {
        let small = render(&[sample(0, 1.0, 1.0)], HEIGHT);
        let big = render(&[sample(0, 999_000_000.0, 999_000_000.0)], HEIGHT);
        assert_eq!(symbol(&small, 0, 3), "─");
        assert_eq!(symbol(&big, 0, 3), "─");
        assert_eq!(symbol(&small, 0, 0), symbol(&big, 0, 0));
    }

    #[test]
    fn uneven_split_gives_the_extra_row_to_the_upper_half() {
        // Height 4: 2 outbound rows, the centre line, 1 inbound row.
        let buffer = render(&[sample(0, 100.0, 100.0)], 4);
        assert_eq!(symbol(&buffer, PLOT - 1, 0), "█");
        assert_eq!(symbol(&buffer, PLOT - 1, 1), "█");
        assert_eq!(symbol(&buffer, PLOT - 1, 2), "─");
        assert_eq!(symbol(&buffer, PLOT - 1, 3), "█");
    }
}

mod overview {
    use super::*;

    fn process(path: &str, pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            executable: ExecutableIdentity {
                path: PathBuf::from(path),
            },
            pid,
            start_time: 1,
            network_namespace: 7,
        }
    }

    fn packet(
        state: &mut AppState,
        at: u64,
        app: Option<&ProcessIdentity>,
        remote: &str,
        port: u16,
        direction: Direction,
        bytes: u32,
    ) {
        let local = Endpoint {
            ip: "192.0.2.10".parse().unwrap(),
            port: Some(51_000),
        };
        let remote = Endpoint {
            ip: remote.parse().unwrap(),
            port: Some(port),
        };
        let (source, destination) = match direction {
            Direction::Outbound => (local, remote),
            Direction::Inbound => (remote, local),
        };
        state.record_traffic(
            Duration::from_secs(at),
            TrafficEvent {
                source,
                destination,
                protocol: Protocol::Tcp,
                direction,
                original_ip_bytes: bytes,
                limitation: None,
                tcp_flags: None,
                timing: None,
            },
            app.cloned(),
        );
    }

    fn healthy(state: &mut AppState) {
        state.record_capture_status(CaptureStatus {
            health: CaptureHealth::Available,
            dropped: 0,
            origin: CaptureOrigin::Own,
        });
        state.record_attribution_status(AttributionStatus {
            health: AttributionHealth::Available,
            only_user: None,
        });
        state.record_firewall_status(FirewallStatus {
            name: "ufw",
            health: FirewallHealth::Available,
        });
    }

    fn rule(action: RuleAction, port: u16, source: RuleSource) -> Rule {
        Rule {
            direction: RuleDirection::In,
            action,
            protocol: None,
            ports: std::iter::once(port..=port).collect(),
            destination: None,
            source,
            interface: None,
            ipv6: false,
            text: format!("{port} rule"),
        }
    }

    fn block(source: &str, port: u16, direction: Direction, stamp: Option<&str>) -> FirewallEvent {
        FirewallEvent {
            timestamp: stamp.map(str::to_owned),
            direction: Some(direction),
            interface: Some("eth0".into()),
            protocol: Some(Protocol::Tcp),
            source: FirewallEndpoint {
                ip: Some(source.parse().unwrap()),
                port: Some(40_000),
            },
            destination: FirewallEndpoint {
                ip: Some("192.0.2.10".parse().unwrap()),
                port: Some(port),
            },
        }
    }

    fn listener(port: u16, address: &str, owner: Option<&str>) -> Listener {
        Listener {
            protocol: Protocol::Tcp,
            address: address.parse().unwrap(),
            port,
            owners: owner.map(|o| process(o, 9)).into_iter().collect(),
        }
    }

    /// Several apps (one with five destinations, one unknown), blocks,
    /// five listeners covering every exposure, and two minutes of history.
    fn sample() -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        for second in 0..120u64 {
            state.advance_time(Duration::from_secs(second));
            state.record_interfaces(InterfaceSnapshot {
                health: CollectionHealth::Available,
                interfaces: vec![
                    InterfaceMeasurement {
                        name: "wlan0".into(),
                        addresses: vec![],
                        download_bytes_per_second: 1.0e5 + 9.0e5 * ((second % 17) as f64 / 17.0),
                        upload_bytes_per_second: 2.0e4 + 3.0e5 * ((second % 11) as f64 / 11.0),
                        session_received_bytes: 4_000_000 + second * 1000,
                        session_transmitted_bytes: 900_000 + second * 100,
                        status: InterfaceStatus::Available,
                        is_up: true,
                    },
                    InterfaceMeasurement {
                        name: "lo".into(),
                        addresses: vec![],
                        download_bytes_per_second: 10.0,
                        upload_bytes_per_second: 10.0,
                        session_received_bytes: 10,
                        session_transmitted_bytes: 10,
                        status: InterfaceStatus::Available,
                        is_up: true,
                    },
                ],
                default_route: Some("wlan0".into()),
                gateway: None,
                name_server: None,
                name_servers: vec![],
            });
        }
        let browser = process("/usr/lib/firefox/firefox", 42);
        let sync = process("/usr/bin/syncthing", 77);
        for (n, ip) in [
            "142.250.80.46",
            "151.101.1.69",
            "104.18.32.7",
            "93.184.216.34",
            "2606:4700::6810:84e5",
        ]
        .into_iter()
        .enumerate()
        {
            packet(
                &mut state,
                118,
                Some(&browser),
                ip,
                443,
                Direction::Outbound,
                1_000 * (n as u32 + 1),
            );
            packet(
                &mut state,
                119,
                Some(&browser),
                ip,
                443,
                Direction::Inbound,
                40_000 * (n as u32 + 1),
            );
        }
        packet(
            &mut state,
            119,
            Some(&sync),
            "198.51.100.23",
            22_000,
            Direction::Outbound,
            5_000,
        );
        packet(
            &mut state,
            119,
            None,
            "203.0.113.9",
            8_080,
            Direction::Inbound,
            700,
        );
        state.advance_time(Duration::from_secs(119));
        for (n, (ip, port)) in [
            ("203.0.113.50", 22),
            ("198.51.100.7", 3389),
            ("192.0.2.200", 22),
        ]
        .into_iter()
        .enumerate()
        {
            for _ in 0..(3 - n) * 40 {
                state.record_firewall(
                    Duration::from_secs(119),
                    block(
                        ip,
                        port,
                        Direction::Inbound,
                        Some(&format!("Oct  8 1{n}:2{n}:00")),
                    ),
                );
            }
        }
        state.record_firewall(
            Duration::from_secs(119),
            block("10.0.0.5", 25, Direction::Outbound, None),
        );
        state.record_listeners(
            vec![
                listener(22, "0.0.0.0", Some("/usr/bin/sshd")),
                listener(631, "127.0.0.1", Some("/usr/bin/cupsd")),
                listener(8080, "0.0.0.0", Some("/usr/bin/python3")),
                listener(22_000, "0.0.0.0", Some("/usr/bin/syncthing")),
                listener(5353, "0.0.0.0", None),
            ],
            32_768..=60_999,
        );
        state.record_rules(RuleSnapshot::Active {
            default_incoming: Policy::Deny,
            default_outgoing: Policy::Allow,
            rules: vec![
                rule(RuleAction::Allow, 22, RuleSource::Anywhere),
                rule(
                    RuleAction::Allow,
                    8080,
                    RuleSource::Specific("10.0.0.0/24".into()),
                ),
            ],
        });
        state
    }

    /// The Network & Firewall page, Firewall Blocks focused.
    fn draw_net(state: &AppState, width: u16, height: u16) -> Terminal<TestBackend> {
        draw_focused(state, Pane::FirewallBlocks, width, height)
    }

    /// Both pages' text, one after the other, for checks about what the
    /// dashboard shows anywhere.
    fn all_pages(state: &AppState, width: u16, height: u16) -> String {
        let mut text = lines(&draw_at(state, width, height));
        text.extend(lines(&draw_net(state, width, height)));
        text.join("\n")
    }

    fn at(lines: &[String], needle: &str) -> (usize, usize) {
        lines
            .iter()
            .enumerate()
            .find_map(|(y, l)| l.find(needle).map(|byte| (y, l[..byte].chars().count())))
            .unwrap_or_else(|| panic!("missing {needle:?} in:\n{}", lines.join("\n")))
    }

    const TRAFFIC_TITLES: [&str; 4] = [
        "BANDWIDTH",
        "APP TRAFFIC",
        "LISTENING PORTS",
        "FIREWALL RULES",
    ];
    const NETWORK_TITLES: [&str; 4] = [
        "FIREWALL BLOCKS",
        "NETWORK EVENTS",
        "NEIGHBORS",
        "WI-FI NETWORKS",
    ];

    #[test]
    fn the_traffic_page_shows_its_four_titles_in_place_and_none_of_the_others() {
        for (width, height) in [(110, 24), (160, 50)] {
            let text = lines(&draw_focused(&sample(), Pane::Bandwidth, width, height));
            let bandwidth = at(&text, "BANDWIDTH");
            let apps = at(&text, "APP TRAFFIC");
            let ports = at(&text, "LISTENING PORTS");
            let rules = at(&text, "FIREWALL RULES");
            // Bandwidth over App Traffic over a bottom row: Listening Ports on
            // the left, Firewall Rules on the right from the middle.
            assert!(bandwidth.0 < apps.0 && apps.0 < ports.0, "{width}x{height}");
            assert_eq!(ports.0, rules.0, "{width}x{height}");
            assert!(
                bandwidth.1 == apps.1 && apps.1 == ports.1,
                "{width}x{height}"
            );
            assert_eq!(rules.1, usize::from(width) / 2 + 2, "{width}x{height}");
            for title in NETWORK_TITLES {
                assert!(
                    text.iter().all(|l| !l.contains(title)),
                    "{title} at {width}x{height}"
                );
            }
            assert!(text.iter().all(|l| l.chars().count() == width as usize));
            assert!(
                at(&text, "wlan0").0 <= bandwidth.0,
                "chart names its interface"
            );
        }
    }

    #[test]
    fn the_network_and_firewall_page_shows_its_four_titles_in_place_and_none_of_traffics() {
        // Firewall Blocks over Network Events on the left, Wi-Fi Networks over
        // Neighbors on the right.
        for (width, height) in [(110, 24), (160, 50)] {
            let text = lines(&draw_focused(
                &sample(),
                Pane::FirewallBlocks,
                width,
                height,
            ));
            let blocked = at(&text, "FIREWALL BLOCKS");
            let rules = at(&text, "NETWORK EVENTS");
            let neighbors = at(&text, "NEIGHBORS");
            let wifi = at(&text, "WI-FI NETWORKS");
            assert_eq!(blocked.1, rules.1, "{width}x{height}");
            assert_eq!(wifi.1, neighbors.1, "{width}x{height}");
            assert!(blocked.1 < wifi.1, "{width}x{height}");
            assert!(
                blocked.0 < rules.0 && wifi.0 < neighbors.0,
                "{width}x{height}"
            );
            assert_eq!(blocked.0, wifi.0, "{width}x{height}");
            assert_eq!(rules.0, neighbors.0, "{width}x{height}");
            for title in TRAFFIC_TITLES {
                assert!(
                    text.iter().all(|l| !l.contains(title)),
                    "{title} at {width}x{height}"
                );
            }
            assert!(text.iter().all(|l| l.chars().count() == width as usize));
        }
    }

    #[test]
    fn listening_ports_at_the_minimum_size_keep_port_app_and_firewall_whole() {
        let text = lines(&draw_at(&sample(), 110, 24));
        let (y, x) = at(&text, "LISTENING PORTS");
        let header = &text[y + 1];
        let pane: String = header.chars().skip(x).collect();
        for column in ["PORT", "APP", "FIREWALL"] {
            assert!(
                pane.contains(column),
                "missing {column:?}:\n{}",
                text.join("\n")
            );
        }
        let rows: Vec<&String> = text[y + 2..y + 5].iter().collect();
        for row in &rows {
            let cells: String = row.chars().skip(x).collect();
            assert!(cells.trim_end_matches('│').trim().len() > 2, "{row:?}");
        }
        // The limited port is the fourth row: more room than the minimum shows it.
        let text = lines(&draw_at(&sample(), 110, 32));
        let (y, x) = at(&text, "LISTENING PORTS");
        let joined = text[y + 2..y + 6]
            .iter()
            .map(|r| r.chars().skip(x).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("◐ limited"),
            "{joined}\n{}",
            text.join("\n")
        );
    }

    #[test]
    fn bidi_overrides_and_zero_width_characters_are_stripped_from_app_names() {
        use crosswalk::ui::panes::app_traffic_rows;
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let app = process("/usr/bin/ev\u{202E}il\u{200B}x\u{2066}\u{FEFF}y", 5);
        packet(
            &mut state,
            1,
            Some(&app),
            "203.0.113.9",
            443,
            Direction::Outbound,
            100,
        );
        let rows = app_traffic_rows(&state, &Theme::default(), "", None, None);
        assert_eq!(rows[0].cells[0].text, "/usr/bin/evilxy");
    }

    const HOSTILE: &str = "a\u{1b}[31m\u{7}b\u{202E}c\u{200B}d\u{2066}e\u{FEFF}f";

    fn assert_clean(text: &str, bound: Option<usize>) {
        assert!(
            text.chars().all(|c| !c.is_control()
                && !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')),
            "{text:?}"
        );
        if let Some(bound) = bound {
            assert!(text.chars().count() <= bound, "{text:?}");
        }
    }

    #[test]
    fn executable_names_in_app_and_listening_rows_are_stripped_and_bounded() {
        use crosswalk::ui::panes::{
            app_traffic_rows, app_traffic_zoom_rows, listening_rows, listening_zoom_rows,
        };
        let long = format!("/usr/bin/{HOSTILE}{}", "x".repeat(100));
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let app = process(&long, 5);
        packet(
            &mut state,
            1,
            Some(&app),
            "203.0.113.9",
            443,
            Direction::Outbound,
            100,
        );
        let theme = Theme::default();
        let rows = app_traffic_rows(&state, &theme, "", None, None);
        // The path is cut from the left to App Traffic's 28 cells.
        assert!(rows[0].cells[0].text.starts_with('…'));
        assert!(
            rows[0].cells[0]
                .text
                .ends_with("xxxxxxxxxxxxxxxxxxxxxxxxxxx")
        );
        assert_clean(&rows[0].cells[0].text, Some(28));
        let rows = app_traffic_zoom_rows(&state, &theme, "", None);
        assert_clean(&rows[0].cells[0].text, Some(48));
        state.record_listeners(vec![listener(22, "0.0.0.0", Some(&long))], 32_768..=60_999);
        let rows = listening_rows(&state, &theme, "");
        assert_clean(&rows[0].cells[1].text, Some(48));
        // The zoom path is whole, but never carries hidden characters.
        let rows = listening_zoom_rows(&state, &theme, "");
        assert_clean(&rows[0].cells[6].text, None);
        assert!(rows[0].cells[6].text.contains("a[31mbcdef"));
    }

    #[test]
    fn a_version_numbered_executable_is_named_by_its_folder() {
        use crosswalk::ui::panes::{app_traffic_rows, listening_rows, listening_zoom_rows};
        let claude = "/home/u/.local/share/claude/versions/2.1.296";
        let mut state = AppState::new(StateLimits::default()).unwrap();
        for (n, path) in [
            claude,
            "/usr/bin/emacs-31.1",
            "/usr/bin/python3.12",
            "/opt/tool/bin/7",
            "/1234",
        ]
        .into_iter()
        .enumerate()
        {
            let app = process(path, 5 + n as u32);
            packet(
                &mut state,
                1,
                Some(&app),
                "203.0.113.9",
                443,
                Direction::Outbound,
                100,
            );
        }
        let theme = Theme::default();
        let names: Vec<String> = app_traffic_rows(&state, &theme, "", None, None)
            .iter()
            .map(|r| r.cells[0].text.clone())
            .filter(|t| !t.is_empty())
            .collect();
        // App Traffic shows the path; the short name is for Listening Ports.
        assert_eq!(
            names,
            [
                "…are/claude/versions/2.1.296",
                "/usr/bin/emacs-31.1",
                "/usr/bin/python3.12",
                "/opt/tool/bin/7",
                "/1234"
            ]
        );
        let found = app_traffic_rows(&state, &theme, "claude", None, None);
        assert_eq!(found.len(), 1);
        assert!(found[0].cells[0].text.contains("claude"));

        state.record_listeners(vec![listener(22, "0.0.0.0", Some(claude))], 32_768..=60_999);
        let rows = listening_rows(&state, &theme, "");
        assert_eq!(rows[0].cells[0].text, "claude");
        let rows = listening_zoom_rows(&state, &theme, "");
        assert!(rows[0].cells[6].text.contains("2.1.296"));
    }

    #[test]
    fn firewall_log_fields_in_the_blocked_and_listening_rows_are_stripped_and_bounded() {
        use crosswalk::ui::panes::{blocked_zoom_rows, listening_zoom_rows};
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let mut event = block("203.0.113.5", 22, Direction::Inbound, None);
        event.interface = Some(format!("{HOSTILE}{}", "i".repeat(100)));
        state.record_firewall(Duration::from_secs(1), event);
        let rows = blocked_zoom_rows(&state, &Theme::default(), "", None);
        assert!(rows[0].cells[5].text.starts_with("a[31mbcdef"));
        assert_clean(&rows[0].cells[5].text, Some(48));

        state.record_listeners(vec![listener(22, "0.0.0.0", None)], 32_768..=60_999);
        let mut hostile_rule = rule(RuleAction::Allow, 22, RuleSource::Anywhere);
        hostile_rule.text = format!("{HOSTILE}{}", "r".repeat(100));
        state.record_rules(RuleSnapshot::Active {
            default_incoming: Policy::Deny,
            default_outgoing: Policy::Allow,
            rules: vec![hostile_rule],
        });
        let rows = listening_zoom_rows(&state, &Theme::default(), "");
        assert!(rows[0].cells[5].text.starts_with("a[31mbcdef"));
        assert_clean(&rows[0].cells[5].text, Some(48));
    }

    #[test]
    fn reverse_dns_names_in_app_traffic_rows_are_stripped_and_bounded() {
        use crosswalk::{
            dns::ReverseDns,
            ui::panes::{app_traffic_rows, app_traffic_zoom_rows},
        };
        let hostile = format!("{HOSTILE}.example{}", "n".repeat(100));
        let mut state = AppState::new(StateLimits::default()).unwrap();
        packet(
            &mut state,
            1,
            Some(&process("/usr/bin/curl", 5)),
            "203.0.113.9",
            443,
            Direction::Outbound,
            100,
        );
        let ip: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let mut dns = ReverseDns::new(true, 8, 8, move |_| Some(hostile.clone()));
        dns.schedule_visible([ip]);
        for _ in 0..200 {
            dns.poll();
            if dns.name(ip).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(dns.name(ip).is_some(), "lookup never finished");
        let theme = Theme::default();
        let rows = app_traffic_rows(&state, &theme, "", None, Some(&dns));
        assert!(rows[0].cells[3].text.starts_with("a[31mbcdef"));
        assert_clean(&rows[0].cells[3].text, Some(48));
        let rows = app_traffic_zoom_rows(&state, &theme, "", Some(&dns));
        assert!(rows[0].cells[9].text.starts_with("a[31mbcdef"));
        assert_clean(&rows[0].cells[9].text, Some(48));
    }

    #[test]
    fn blocked_zoom_keeps_the_last_seen_column_however_narrow() {
        use crosswalk::ui::{
            panes::blocked_zoom_columns,
            table::{Row, Table},
        };
        let theme = Theme::default();
        let columns = blocked_zoom_columns();
        let rows: Vec<Row> = Vec::new();
        for width in [10u16, 20, 30] {
            let area = ratatui::layout::Rect::new(0, 0, width, 2);
            let mut buffer = ratatui::buffer::Buffer::empty(area);
            Table::new(&columns, &rows, &theme).render(&mut buffer, area);
            let header: String = (0..width).map(|x| buffer[(x, 0)].symbol()).collect();
            assert!(header.contains("LAST SEEN"), "{width}: {header:?}");
        }
    }

    #[test]
    fn each_list_pane_has_room_for_its_header_and_three_rows_at_110_by_24() {
        for (focus, titles) in [
            (
                Pane::AppTraffic,
                vec!["APP TRAFFIC", "LISTENING PORTS", "FIREWALL RULES"],
            ),
            (
                Pane::FirewallBlocks,
                vec![
                    "FIREWALL BLOCKS",
                    "NETWORK EVENTS",
                    "NEIGHBORS",
                    "WI-FI NETWORKS",
                ],
            ),
        ] {
            let text = lines(&draw_focused(&sample(), focus, 110, 24));
            for title in titles {
                let (top, x) = at(&text, title);
                let bottom = (top..text.len())
                    .find(|&y| text[y].chars().nth(x - 2) == Some('╰'))
                    .unwrap_or_else(|| panic!("{title} has no bottom border"));
                // Border, header and three rows, border.
                assert!(
                    bottom - top + 1 >= 6,
                    "{title} is {} high",
                    bottom - top + 1
                );
            }
        }
    }

    #[test]
    fn tab_walks_the_eight_panes_across_both_pages_and_wraps() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('3'));
        assert_eq!(i.focus(), Pane::ListeningPorts);
        press(&mut i, &state, KeyCode::Tab);
        assert_eq!(i.focus(), Pane::FirewallRules);
        assert_eq!(i.focus().page(), Page::Traffic);
        press(&mut i, &state, KeyCode::Tab);
        assert_eq!(i.focus(), Pane::FirewallBlocks);
        assert_eq!(i.focus().page(), Page::NetworkFirewall);
        press(&mut i, &state, KeyCode::BackTab);
        assert_eq!(i.focus(), Pane::FirewallRules);
        assert_eq!(i.focus().page(), Page::Traffic);
        press(&mut i, &state, KeyCode::Char('1'));
        press(&mut i, &state, KeyCode::BackTab);
        assert_eq!(i.focus(), Pane::Neighbors);
        press(&mut i, &state, KeyCode::Tab);
        assert_eq!(i.focus(), Pane::Bandwidth);
        press(&mut i, &state, KeyCode::Char('6'));
        assert_eq!(i.focus(), Pane::NetworkEvents);
        press(&mut i, &state, KeyCode::Tab);
        assert_eq!(i.focus(), Pane::WifiNetworks);
    }

    #[test]
    fn the_help_popup_lists_both_pages_with_their_panes_and_fits_at_110_by_24() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('?'));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        for visible in [
            "Traffic",
            "1 Bandwidth",
            "2 App Traffic",
            "3 Listening Ports",
            "Network & Firewall",
            "4 Firewall Rules",
            "5 Firewall Blocks",
            "6 Network Events",
            "7 Wi-Fi Networks",
            "8 Neighbors",
            "tab / 1-8",
            "● open",
        ] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
    }

    #[test]
    fn the_help_popup_names_the_movement_keys_and_still_has_every_other_line_within_its_room() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('?'));
        let terminal = screen(&state, &mut i, None, 110, 24);
        let text = text_of(&terminal);
        let moves = text
            .lines()
            .find(|l| l.contains("j/k"))
            .unwrap_or_else(|| panic!("no movement line:\n{text}"));
        for key in ["g/G", "ctrl-d/u", "Home", "End", "PgUp", "PgDn", "↑↓"] {
            assert!(moves.contains(key), "{key} missing from {moves:?}");
        }
        assert!(
            !moves.contains("in zoom"),
            "it works on the overview too: {moves:?}"
        );
        for line in [
            "move focus, and page",
            "show the other page",
            "zoom the focused pane",
            "leave zoom (search kept), close help",
            "on the overview: clear the search",
            "search the focused pane",
            "interface · reverse DNS names · scan Wi-Fi · map",
            "toggle this help / quit",
            "● open",
        ] {
            assert!(text.contains(line), "missing {line:?}:\n{text}");
        }
        let rows: Vec<String> = lines(&terminal);
        let top = rows.iter().position(|l| l.contains("HELP")).unwrap();
        let left = rows[top].chars().position(|c| c == 'H').unwrap() - 2;
        assert_eq!(rows[top].chars().nth(left), Some('╭'));
        let bottom = (top..rows.len())
            .find(|&y| rows[y].chars().nth(left) == Some('╰'))
            .expect("the popup's bottom border is on screen");
        assert!(rows[top..bottom].iter().any(|l| l.contains("● open")));
        assert!(bottom - top < 17, "the popup is {} rows", bottom - top + 1);
    }

    #[test]
    fn keys_one_to_eight_focus_the_panes_in_order_and_each_shows_its_page() {
        let state = sample();
        let mut i = Interaction::default();
        for (key, pane, shown, hidden) in [
            (
                '1',
                Pane::Bandwidth,
                TRAFFIC_TITLES.to_vec(),
                NETWORK_TITLES.to_vec(),
            ),
            (
                '2',
                Pane::AppTraffic,
                TRAFFIC_TITLES.to_vec(),
                NETWORK_TITLES.to_vec(),
            ),
            (
                '3',
                Pane::ListeningPorts,
                TRAFFIC_TITLES.to_vec(),
                NETWORK_TITLES.to_vec(),
            ),
            (
                '4',
                Pane::FirewallRules,
                TRAFFIC_TITLES.to_vec(),
                NETWORK_TITLES.to_vec(),
            ),
            (
                '5',
                Pane::FirewallBlocks,
                NETWORK_TITLES.to_vec(),
                TRAFFIC_TITLES.to_vec(),
            ),
            (
                '6',
                Pane::NetworkEvents,
                NETWORK_TITLES.to_vec(),
                TRAFFIC_TITLES.to_vec(),
            ),
            (
                '7',
                Pane::WifiNetworks,
                NETWORK_TITLES.to_vec(),
                TRAFFIC_TITLES.to_vec(),
            ),
            (
                '8',
                Pane::Neighbors,
                NETWORK_TITLES.to_vec(),
                TRAFFIC_TITLES.to_vec(),
            ),
        ] {
            press(&mut i, &state, KeyCode::Char(key));
            assert_eq!(i.focus(), pane, "key {key}");
            let text = text_of(&screen(&state, &mut i, None, 110, 24));
            for title in shown {
                assert!(text.contains(title), "key {key} lacks {title}");
            }
            for title in hidden {
                assert!(!text.contains(title), "key {key} shows {title}");
            }
        }
    }

    #[test]
    fn the_bottom_row_is_at_least_seven_rows_and_app_traffic_stays_the_larger() {
        let height_of = |text: &[String], title: &str| {
            let (top, x) = at(text, title);
            let bottom = (top..text.len())
                .find(|&y| text[y].chars().nth(x - 2) == Some('╰'))
                .unwrap();
            bottom - top + 1
        };
        for height in [24u16, 26, 32, 40, 50] {
            let text = lines(&draw_at(&sample(), 110, height));
            let apps = height_of(&text, "APP TRAFFIC");
            let ports = height_of(&text, "LISTENING PORTS");
            let rules = height_of(&text, "FIREWALL RULES");
            assert_eq!(ports, rules, "110x{height}");
            assert!(ports >= 7, "110x{height}: bottom row is {ports} high");
            assert!(apps >= ports, "110x{height}: {apps} against {ports}");
            if height == 24 {
                assert_eq!((apps, ports), (8, 7));
            }
        }
    }

    #[test]
    fn listening_ports_in_its_half_shows_four_rows_with_every_column_whole_at_110_by_24() {
        let text = lines(&draw_at(&sample(), 110, 24));
        let (y, x) = at(&text, "LISTENING PORTS");
        let half = |line: &String| -> String { line.chars().skip(x).take(53).collect() };
        let header = half(&text[y + 1]);
        for column in ["PORT", "APP", "BIND", "FIREWALL"] {
            assert!(header.contains(column), "{column}: {header}");
        }
        assert!(!header.contains("DIR"), "{header}");
        let rows: Vec<String> = text[y + 2..y + 6].iter().map(half).collect();
        for (row, port) in rows
            .iter()
            .zip(["22/tcp", "8080/tcp", "5353/tcp", "22000/tcp"])
        {
            assert!(row.contains(port), "{port}: {row}");
        }
        assert!(rows[1].contains("◐ limited"), "{rows:?}");
    }

    #[test]
    fn network_events_is_titled_and_quiet_on_the_overview_and_in_zoom() {
        let text = lines(&draw_net(&sample(), 110, 24));
        let (y, x) = at(&text, "NETWORK EVENTS");
        assert!(
            text[y + 1]
                .chars()
                .skip(x - 2)
                .collect::<String>()
                .contains("no events yet")
        );
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('6'));
        press(&mut i, &state, KeyCode::Enter);
        assert_eq!(i.zoomed(), Some(Pane::NetworkEvents));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            text.contains("NETWORK EVENTS") && text.contains("no events yet"),
            "{text}"
        );
        assert!(!text.contains("FIREWALL BLOCKS"), "{text}");
    }

    #[test]
    fn terminals_below_110_by_24_show_the_size_message() {
        for (width, height) in [(109, 24), (110, 23)] {
            let text = lines(&draw_at(&sample(), width, height)).join("\n");
            assert!(text.contains("110x24"), "{width}x{height}: {text}");
            assert!(!text.contains("APP TRAFFIC"));
        }
    }

    // ---- Firewall Rules ----

    fn out_rule(action: RuleAction, port: u16, remote: &str) -> Rule {
        Rule {
            direction: RuleDirection::Out,
            destination: Some(Network {
                address: remote.parse().unwrap(),
                prefix: 32,
            }),
            ..rule(action, port, RuleSource::Anywhere)
        }
    }

    /// What UFW holds for rules added without a family: the IPv4 file's rules,
    /// then the IPv6 file's copies.
    fn paired(rules: Vec<Rule>) -> Vec<Rule> {
        let v6 = rules.iter().cloned().map(|r| Rule { ipv6: true, ..r });
        rules.iter().cloned().chain(v6).collect()
    }

    fn with_rules(rules: Vec<Rule>) -> AppState {
        let mut state = sample();
        record(&mut state, Policy::Deny, Policy::Allow, rules);
        state
    }

    fn record(state: &mut AppState, incoming: Policy, outgoing: Policy, rules: Vec<Rule>) {
        state.record_rules(RuleSnapshot::Active {
            default_incoming: incoming,
            default_outgoing: outgoing,
            rules,
        });
    }

    /// The Firewall Rules pane's inner lines, spaces collapsed: the pane is
    /// the right half of the bottom row of the Traffic page.
    fn rules_pane(screen: &str, width: usize) -> Vec<String> {
        let rows: Vec<String> = screen
            .lines()
            .map(|l| l.chars().skip(width / 2).collect())
            .collect();
        let start = rows
            .iter()
            .position(|l| l.contains("FIREWALL RULES"))
            .unwrap();
        rows[start + 1..]
            .iter()
            .take_while(|l| !l.contains('└') && !l.contains('╰'))
            .map(|l| {
                l.chars()
                    .filter(|c| !"│┃║".contains(*c))
                    .collect::<String>()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    }

    fn rules_at(state: &AppState, width: u16, height: u16) -> Vec<String> {
        let text = lines(&draw_at(state, width, height)).join("\n");
        rules_pane(&text, width.into())
    }

    #[test]
    fn rules_lists_inbound_and_outbound_rules_in_order_with_each_column() {
        let mut deny = rule(
            RuleAction::Deny,
            5432,
            RuleSource::Specific("10.1.2.0/24".into()),
        );
        deny.protocol = Some(Protocol::Tcp);
        deny.interface = Some("eth0".into());
        let mut allow = rule(RuleAction::Allow, 22, RuleSource::Anywhere);
        allow.protocol = Some(Protocol::Tcp);
        let mut reject = out_rule(RuleAction::Reject, 25, "203.0.113.9");
        reject.protocol = Some(Protocol::Tcp);
        let mut any = out_rule(RuleAction::Limit, 1, "0.0.0.0");
        any.ports.clear();
        any.destination = None;
        let pane = rules_at(&with_rules(paired(vec![allow, deny, reject, any])), 160, 50);
        assert_eq!(pane[1], "IFACE APP DIR ACTION PORT REMOTE", "{pane:?}");
        assert_eq!(
            pane[2..6],
            [
                "all sshd in allow 22/tcp anywhere",
                "eth0 — in deny 5432/tcp 10.1.2.0/24",
                "all out reject 25/tcp 203.0.113.9",
                "all out limit any anywhere",
            ],
            "{pane:?}"
        );
    }

    #[test]
    fn a_v4_and_v6_pair_is_one_row_and_a_one_family_rule_is_marked() {
        let mut v6_22 = rule(RuleAction::Allow, 22, RuleSource::Anywhere);
        v6_22.ipv6 = true;
        v6_22.text = "22 (v6) rule".into();
        let mut v6_only = rule(RuleAction::Allow, 9999, RuleSource::Anywhere);
        v6_only.ipv6 = true;
        let pane = rules_at(
            &with_rules(vec![
                rule(RuleAction::Allow, 22, RuleSource::Anywhere),
                rule(RuleAction::Deny, 8080, RuleSource::Anywhere),
                v6_22,
                v6_only,
            ]),
            160,
            50,
        );
        assert_eq!(
            pane[2..5],
            [
                "all sshd in allow 22 anywhere",
                "all python3 in v4 deny 8080 anywhere",
                "all — in v6 allow 9999 anywhere",
            ],
            "{pane:?}"
        );
        assert!(pane[5..].iter().all(|l| !l.starts_with("all ")), "{pane:?}");
    }

    #[test]
    fn rules_shows_both_default_policies() {
        let mut state = sample();
        let pane = rules_at(&state, 110, 24);
        assert_eq!(pane[0], "default: deny in · allow out", "{pane:?}");
        record(&mut state, Policy::Reject, Policy::Deny, vec![]);
        let pane = rules_at(&state, 110, 24);
        assert_eq!(pane[0], "default: reject in · deny out", "{pane:?}");
    }

    #[test]
    fn at_110_by_24_the_rules_pane_shows_the_header_and_three_rows_with_every_column() {
        let mut deny = rule(
            RuleAction::Deny,
            5432,
            RuleSource::Specific("192.0.2.7".into()),
        );
        deny.protocol = Some(Protocol::Tcp);
        deny.interface = Some("eth0".into());
        let mut reject = out_rule(RuleAction::Reject, 25, "192.0.2.7");
        reject.protocol = Some(Protocol::Tcp);
        let mut allow = rule(RuleAction::Allow, 22, RuleSource::Anywhere);
        allow.protocol = Some(Protocol::Tcp);
        let extra = rule(RuleAction::Allow, 80, RuleSource::Anywhere);
        let pane = rules_at(
            &with_rules(paired(vec![allow, deny, reject, extra])),
            110,
            24,
        );
        assert_eq!(
            pane[..5],
            [
                "default: deny in · allow out",
                "IFACE APP DIR ACTION PORT REMOTE",
                "all sshd in allow 22/tcp anywhere",
                "eth0 — in deny 5432/tcp 192.0.2.7",
                "all out reject 25/tcp 192.0.2.7",
            ]
        );
    }

    #[test]
    fn at_110_by_24_an_ipv4_network_is_whole_in_the_rules_remote_column() {
        let mut deny = rule(
            RuleAction::Deny,
            5432,
            RuleSource::Specific("10.1.2.0/24".into()),
        );
        deny.protocol = Some(Protocol::Tcp);
        deny.interface = Some("eth0".into());
        let pane = rules_at(&with_rules(paired(vec![deny])), 110, 24);
        assert_eq!(pane[2], "eth0 — in deny 5432/tcp 10.1.2.0/24", "{pane:?}");
    }

    #[test]
    fn a_changed_rule_snapshot_changes_the_rows_on_the_next_draw() {
        let mut state = with_rules(paired(vec![rule(
            RuleAction::Allow,
            22,
            RuleSource::Anywhere,
        )]));
        assert_eq!(
            rules_at(&state, 160, 50)[2],
            "all sshd in allow 22 anywhere"
        );
        record(
            &mut state,
            Policy::Deny,
            Policy::Allow,
            paired(vec![rule(RuleAction::Deny, 23, RuleSource::Anywhere)]),
        );
        let pane = rules_at(&state, 160, 50);
        assert_eq!(pane[2], "all — in deny 23 anywhere", "{pane:?}");
        assert!(pane[3..].iter().all(|l| !l.starts_with("all ")), "{pane:?}");
    }

    #[test]
    fn inactive_and_unreadable_rules_each_show_their_line_and_no_rows() {
        for (snapshot, line) in [
            (RuleSnapshot::Inactive, "UFW is off"),
            (
                RuleSnapshot::Unavailable("permission denied".into()),
                "Cannot read firewall rules",
            ),
        ] {
            let mut state = sample();
            state.record_rules(snapshot);
            let pane = rules_at(&state, 110, 24);
            assert!(pane[0].contains(line), "{pane:?}");
            let all = pane.join(" ");
            assert!(
                !all.contains("allow") && !all.contains("default:") && !all.contains("IFACE"),
                "{pane:?}"
            );
        }
    }

    #[test]
    fn active_with_no_rules_shows_the_policies_and_says_there_are_none() {
        let pane = rules_at(&with_rules(vec![]), 110, 24);
        assert_eq!(pane[0], "default: deny in · allow out", "{pane:?}");
        assert!(pane[1].contains("no rules"), "{pane:?}");
    }

    #[test]
    fn rules_zoom_shows_the_rule_text_once_for_a_merged_pair() {
        let mut v4 = rule(RuleAction::Allow, 22, RuleSource::Anywhere);
        v4.text = "22 ALLOW IN Anywhere".into();
        let mut v6 = v4.clone();
        v6.ipv6 = true;
        v6.text = "22 (v6) ALLOW IN Anywhere (v6)".into();
        let state = with_rules(vec![v4, v6]);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('4'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 32));
        assert!(
            text.contains("RULE") && text.contains("22 ALLOW IN Anywhere"),
            "{text}"
        );
        assert!(!text.contains("(v6)"), "{text}");
    }

    #[test]
    fn a_rules_search_keeps_matching_rows_only_and_survives_zoom() {
        let mut deny = rule(RuleAction::Deny, 23, RuleSource::Anywhere);
        deny.text = "23 DENY IN Anywhere".into();
        let state = with_rules(paired(vec![
            rule(RuleAction::Allow, 22, RuleSource::Anywhere),
            deny,
        ]));
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('4'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "deny");
        press(&mut i, &state, KeyCode::Enter);
        let overview = rules_pane(&text_of(&screen(&state, &mut i, None, 110, 32)), 110);
        assert_eq!(overview[2], "all — in deny 23 anywhere", "{overview:?}");
        assert!(!overview[2..].join(" ").contains("allow"), "{overview:?}");
        press(&mut i, &state, KeyCode::Enter);
        let zoom = text_of(&screen(&state, &mut i, None, 110, 32));
        assert!(zoom.contains("23 DENY IN Anywhere"), "{zoom}");
        assert!(!zoom.contains("allow  "), "{zoom}");
        assert_eq!(i.search(Pane::FirewallRules), "deny");
    }

    #[test]
    fn an_app_with_five_destinations_shows_three_and_the_rest_summed() {
        let text = lines(&draw_at(&sample(), 160, 50)).join("\n");
        assert!(text.contains("+2 more"), "{text}");
        assert!(text.contains("142.250.80.46") && text.contains("104.18.32.7"));
        assert!(!text.contains("93.184.216.34"), "fourth destination listed");
        // The app name is printed on its first row only.
        assert_eq!(
            text.matches("/usr/lib/firefox/firefox").count(),
            1,
            "{text}"
        );
        assert!(text.contains("syncthing"));
    }

    #[test]
    fn no_cell_shows_a_raw_byte_count_a_path_or_debug_formatting() {
        for (width, height) in [(110, 24), (160, 50)] {
            // App Traffic shows an app's path; its rows carry a rate.
            let pages = all_pages(&sample(), width, height);
            let text = pages
                .lines()
                .filter(|l| !l.contains("B/s"))
                .collect::<Vec<_>>()
                .join("\n");
            for banned in [
                "/usr/",
                "Some(",
                "Unavailable(",
                "Degraded(",
                "Open(",
                "Limited(",
                "bytes",
            ] {
                assert!(
                    !text.contains(banned),
                    "{banned:?} at {width}x{height}:\n{text}"
                );
            }
            assert!(pages.contains(" KB/s") || pages.contains(" MB/s"));
        }
    }

    #[test]
    fn firewall_blocks_rows_show_clock_time_source_port_and_hits_inbound_only() {
        let text = lines(&draw_net(&sample(), 160, 50)).join("\n");
        for visible in ["10:20", "203.0.113.50", "22/tcp", "×120", "3389/tcp", "×80"] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
        assert!(!text.contains("10.0.0.5"), "outbound block listed");
    }

    #[test]
    fn listening_ports_mark_every_exposure_and_name_the_owner_by_file_name() {
        let text = lines(&draw_at(&sample(), 160, 50)).join("\n");
        for visible in [
            "● open",
            "◐ limited",
            "· blocked",
            "· local",
            "sshd",
            "cupsd",
            "5353/tcp",
        ] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
    }

    #[test]
    fn open_is_the_most_prominent_listening_marker() {
        let terminal = draw_at(&sample(), 160, 50);
        let text = lines(&terminal);
        let (y, x) = at(&text, "● open");
        let cell = &terminal.backend().buffer()[(x as u16, y as u16)];
        assert_eq!(cell.style().fg, Some(Theme::default().danger));
        assert!(
            cell.style()
                .add_modifier
                .contains(ratatui::style::Modifier::BOLD)
        );
    }

    fn marker_style(terminal: &Terminal<TestBackend>, marker: &str) -> ratatui::style::Style {
        let (y, x) = at(&lines(terminal), marker);
        terminal.backend().buffer()[(x as u16, y as u16)].style()
    }

    /// Listening Ports drawn on the overview and in zoom, so each check covers both.
    fn listening_screens(state: &AppState, theme: &Theme) -> Vec<Terminal<TestBackend>> {
        let overview = {
            let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
            terminal
                .draw(|f| draw(f, state, theme, &Overview::new(Pane::AppTraffic)))
                .unwrap();
            terminal
        };
        let zoom = {
            let mut i = Interaction::default();
            press(&mut i, state, KeyCode::Char('3'));
            press(&mut i, state, KeyCode::Enter);
            let mut terminal = Terminal::new(TestBackend::new(160, 32)).unwrap();
            terminal
                .draw(|f| draw_interactive(f, state, theme, &mut i, None))
                .unwrap();
            terminal
        };
        vec![overview, zoom]
    }

    fn bandwidth_screen(focus: Pane, state: &AppState) -> Terminal<TestBackend> {
        bandwidth_screen_in(focus, state, &Theme::default())
    }

    fn bandwidth_screen_in(focus: Pane, state: &AppState, theme: &Theme) -> Terminal<TestBackend> {
        let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
        terminal
            .draw(|f| draw(f, state, theme, &Overview::new(focus)))
            .unwrap();
        terminal
    }

    #[test]
    fn the_interface_name_in_the_bandwidth_title_is_bold_highlight_colour_focused_or_not() {
        let theme = Theme::default();
        for focused in [false, true] {
            let focus = if focused {
                Pane::Bandwidth
            } else {
                Pane::AppTraffic
            };
            let terminal = bandwidth_screen(focus, &sample());
            let text = lines(&terminal);
            let (y, x) = at(&text, "BANDWIDTH · wlan0");
            let buffer = terminal.backend().buffer();
            let name = buffer[((x + "BANDWIDTH · ".chars().count()) as u16, y as u16)].style();
            assert_eq!(name.fg, Some(theme.highlight));
            assert!(name.add_modifier.contains(ratatui::style::Modifier::BOLD));
            assert_ne!(name.fg, Some(theme.inbound));
            assert_ne!(name.fg, Some(theme.outbound));
            let rest = buffer[(x as u16, y as u16)].style();
            assert_ne!(name.fg, rest.fg);
            assert_eq!(rest.fg, theme.title(focused).fg);
            assert_eq!(rest.add_modifier, theme.title(focused).add_modifier);
        }
    }

    #[test]
    fn overriding_highlight_changes_the_interface_name_colour_and_inbound_does_not() {
        let name_colour = |theme: &Theme| {
            let terminal = bandwidth_screen_in(Pane::AppTraffic, &sample(), theme);
            let text = lines(&terminal);
            let (y, x) = at(&text, "BANDWIDTH · wlan0");
            terminal.backend().buffer()[((x + "BANDWIDTH · ".chars().count()) as u16, y as u16)].fg
        };
        let base = Theme::default();
        let highlighted = Theme {
            highlight: ratatui::style::Color::Rgb(1, 2, 3),
            ..base
        };
        assert_eq!(name_colour(&highlighted), highlighted.highlight);
        let inbound = Theme {
            inbound: ratatui::style::Color::Rgb(4, 5, 6),
            ..base
        };
        assert_eq!(name_colour(&inbound), base.highlight);
    }

    #[test]
    fn with_no_interface_data_the_bandwidth_title_is_bandwidth_alone() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        let text = lines(&bandwidth_screen(Pane::AppTraffic, &state));
        let (y, _) = at(&text, " BANDWIDTH ");
        assert!(!text[y].contains("BANDWIDTH ·"), "{}", text[y]);
    }

    #[test]
    fn each_exposure_is_coloured_by_risk_with_blocked_in_the_ok_colour() {
        let theme = Theme::default();
        let bold = ratatui::style::Modifier::BOLD;
        for terminal in listening_screens(&sample(), &theme) {
            assert_eq!(marker_style(&terminal, "· blocked").fg, Some(theme.ok));
            let open = marker_style(&terminal, "● open");
            assert_eq!(open.fg, Some(theme.danger));
            assert!(open.add_modifier.contains(bold));
            assert_eq!(marker_style(&terminal, "◐ limited").fg, Some(theme.warning));
            assert_eq!(marker_style(&terminal, "· local").fg, Some(theme.muted));
        }
        for (rules, marker) in [
            (RuleSnapshot::Inactive, "? ufw off"),
            (RuleSnapshot::Unavailable("denied".into()), "? unreadable"),
        ] {
            let mut state = sample();
            state.record_rules(rules);
            for terminal in listening_screens(&state, &theme) {
                assert_eq!(marker_style(&terminal, marker).fg, Some(theme.muted));
            }
        }
    }

    #[test]
    fn overriding_ok_changes_the_colour_of_blocked_ports() {
        let theme = Theme {
            ok: ratatui::style::Color::Rgb(1, 2, 3),
            ..Theme::default()
        };
        for terminal in listening_screens(&sample(), &theme) {
            assert_eq!(
                marker_style(&terminal, "· blocked").fg,
                Some(ratatui::style::Color::Rgb(1, 2, 3))
            );
        }
    }

    #[test]
    fn idle_rows_are_muted() {
        let mut state = sample();
        state.advance_time(Duration::from_secs(135));
        let terminal = draw_at(&state, 160, 50);
        let text = lines(&terminal);
        let theme = Theme::default();
        let (y, x) = at(&text, "142.250.80.46");
        assert_eq!(
            terminal.backend().buffer()[(x as u16, y as u16)].style().fg,
            Some(theme.muted)
        );
    }

    fn unowned_state(limits: StateLimits) -> AppState {
        let mut state = AppState::new(limits).unwrap();
        healthy(&mut state);
        let browser = process("/usr/lib/firefox/firefox", 42);
        packet(
            &mut state,
            1,
            Some(&browser),
            "142.250.80.46",
            443,
            Direction::Outbound,
            100,
        );
        packet(
            &mut state,
            1,
            None,
            "203.0.113.9",
            53,
            Direction::Outbound,
            40,
        );
        packet(
            &mut state,
            1,
            None,
            "203.0.113.9",
            53,
            Direction::Inbound,
            3_000,
        );
        state
    }

    #[test]
    fn unowned_traffic_shows_no_unknown_app_and_a_footer_total_in_both_views() {
        let state = unowned_state(StateLimits::default());
        let text = lines(&draw_at(&state, 160, 50)).join("\n");
        assert!(!text.contains("unknown"), "{text}");
        assert!(!text.contains("203.0.113.9"), "{text}");
        assert!(
            text.contains("not attributed: 3.0 KB in, 40 B out"),
            "{text}"
        );
        let rows = crosswalk::ui::panes::app_traffic_zoom_rows(&state, &Theme::default(), "", None);
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0]
                .cells
                .iter()
                .all(|c| !c.text.contains("unknown") && !c.text.contains("203.0.113.9"))
        );
    }

    #[test]
    fn with_no_unowned_traffic_there_is_no_footer_line() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        let browser = process("/usr/lib/firefox/firefox", 42);
        packet(
            &mut state,
            1,
            Some(&browser),
            "142.250.80.46",
            443,
            Direction::Outbound,
            100,
        );
        let text = lines(&draw_at(&state, 160, 50)).join("\n");
        assert!(
            !text.contains("not attributed") && !text.contains("list full"),
            "{text}"
        );
    }

    #[test]
    fn a_full_list_adds_its_figure_after_the_unattributed_one_and_fits_110_by_24() {
        let limits = StateLimits {
            detail_capacity: 1,
            ..StateLimits::default()
        };
        let mut state = unowned_state(limits);
        let browser = process("/usr/lib/firefox/firefox", 42);
        packet(
            &mut state,
            1,
            Some(&browser),
            "151.101.1.69",
            443,
            Direction::Outbound,
            70,
        );
        let wide = lines(&draw_at(&state, 160, 50)).join("\n");
        let both = "not attributed: 3.0 KB in, 40 B out · list full: 0 B in, 70 B out not itemised";
        assert!(wide.contains(both), "{wide}");
        // App Traffic is as wide as the screen, so the whole line fits at the
        // minimum and sits inside the pane's border.
        let narrow = lines(&draw_at(&state, 110, 24));
        let row = narrow
            .iter()
            .find(|l| l.contains("not attributed"))
            .unwrap_or_else(|| panic!("no footer in:\n{}", narrow.join("\n")));
        assert!(row.contains(both), "{row}");
        assert!(row.trim_end().ends_with('│'), "{row}");
    }

    #[test]
    fn a_listening_port_with_no_owner_still_reads_a_dash() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        state.record_listeners(vec![listener(4000, "0.0.0.0", None)], 32_768..=60_999);
        let rows = crosswalk::ui::panes::listening_rows(&state, &Theme::default(), "");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cells[1].text, "—");
        assert!(rows[0].cells.iter().all(|c| !c.text.contains("unknown")));
    }

    #[test]
    fn the_focused_pane_is_marked_in_the_accent_colour() {
        let terminal = draw_at(&sample(), 110, 24);
        let text = lines(&terminal);
        let theme = Theme::default();
        let (y, x) = at(&text, "APP TRAFFIC");
        assert_eq!(
            terminal.backend().buffer()[(x as u16, y as u16)].style().fg,
            Some(theme.accent)
        );
        let (y, x) = at(&text, "LISTENING PORTS");
        assert_ne!(
            terminal.backend().buffer()[(x as u16, y as u16)].style().fg,
            Some(theme.accent)
        );
    }

    #[test]
    fn the_header_shows_four_sources_and_the_footer_shows_the_keys() {
        let text = lines(&draw_at(&sample(), 110, 24));
        for visible in ["capture", "firewall", "interfaces", "apps"] {
            assert!(text[0].contains(visible), "{visible}: {}", text[0]);
        }
        let footer = &text[23];
        for visible in [
            "tab focus",
            "enter zoom",
            "/ search",
            "i interface",
            "? help",
            "q quit",
        ] {
            assert!(footer.contains(visible), "{visible}: {footer}");
        }
    }

    fn header_of(terminal: &Terminal<TestBackend>) -> String {
        lines(terminal).remove(0)
    }

    /// The style of the first cell of `needle` in the header line.
    fn header_style(terminal: &Terminal<TestBackend>, needle: &str) -> ratatui::style::Style {
        let header = header_of(terminal);
        let at = header
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not in {header:?}"));
        let x = header[..at].chars().count() as u16;
        terminal.backend().buffer()[(x, 0)].style()
    }

    fn block_n(state: &mut AppState, count: usize) {
        for n in 0..count {
            state.record_firewall(
                Duration::from_secs(n as u64),
                block("203.0.113.5", 22, Direction::Inbound, None),
            );
        }
    }

    /// The header up to the first source indicator.
    fn left_of_indicators(header: &str) -> &str {
        &header[..header.find('●').unwrap()]
    }

    /// Dumpcap capture, ufw, and `user` on the apps indicator, with 100 blocks.
    fn full_indicators(user: &str) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        block_n(&mut state, 100);
        state.record_capture_status(capture_status(
            CaptureHealth::Available,
            CaptureOrigin::Dumpcap,
        ));
        state.record_firewall_status(firewall_status("ufw", FirewallHealth::Available));
        attribution(&mut state, AttributionHealth::Available, Some(user));
        state
    }

    #[test]
    fn the_longest_labels_fit_beside_99_plus_blocks_and_all_four_indicators_at_110() {
        let state = full_indicators("ryan");
        let mut i = Interaction::default();
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            header.starts_with(" Traffic · Network & Firewall 99+ "),
            "{header:?}"
        );
        assert!(
            header
                .trim_end()
                .ends_with("● capture (dumpcap)  ● firewall (ufw)  ● interfaces  ● apps (ryan)"),
            "{header:?}"
        );
    }

    #[test]
    fn neither_the_title_nor_the_theme_name_is_in_the_header_at_any_width() {
        let state = full_indicators("ryan");
        for width in [110, 200] {
            let mut i = Interaction::default();
            let header = header_of(&screen(&state, &mut i, None, width, 24));
            assert!(
                !header.contains("CROSSWALK") && !header.contains("synthwave"),
                "{width}: {header:?}"
            );
        }
    }

    #[test]
    fn a_user_name_too_long_for_the_header_is_cut_with_an_ellipsis_and_the_left_stays_whole() {
        let state = full_indicators(&"a".repeat(32));
        let mut i = Interaction::default();
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            header.starts_with(" Traffic · Network & Firewall 99+ "),
            "{header:?}"
        );
        assert!(header.contains("● apps (a"), "{header:?}");
        assert!(header.trim_end().ends_with("…)"), "{header:?}");
        assert!(!header.contains(&"a".repeat(32)), "{header:?}");
        assert!(header.contains("● capture (dumpcap)  ● firewall (ufw)  ● interfaces  "));
    }

    #[test]
    fn a_user_name_that_fits_is_not_cut() {
        let state = full_indicators("abcdefghijkl");
        let mut i = Interaction::default();
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(header.contains("● apps (abcdefghijkl)"), "{header:?}");
    }

    /// A capture status of `health` and `origin` that dropped `dropped` packets, at 100 s.
    fn dropping(health: CaptureHealth, origin: CaptureOrigin, dropped: u64) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.advance_time(Duration::from_secs(100));
        state.record_capture_status(CaptureStatus {
            dropped,
            ..capture_status(health, origin)
        });
        state
    }

    fn drawn_header(state: &AppState) -> (Terminal<TestBackend>, String) {
        let mut i = Interaction::default();
        let terminal = screen(state, &mut i, None, 110, 24);
        let header = header_of(&terminal);
        (terminal, header)
    }

    #[test]
    fn recent_drops_put_their_count_on_the_capture_indicator_in_the_warning_colour() {
        let state = dropping(CaptureHealth::Available, CaptureOrigin::Own, 340);
        let (terminal, header) = drawn_header(&state);
        assert!(header.contains("● capture (340 dropped)  ● "), "{header:?}");
        assert_eq!(
            header_style(&terminal, "●").fg,
            Theme::default().warning().fg
        );
    }

    #[test]
    fn recent_drops_through_dumpcap_follow_the_source_name() {
        let state = dropping(CaptureHealth::Available, CaptureOrigin::Dumpcap, 340);
        let (_, header) = drawn_header(&state);
        assert!(
            header.contains("● capture (dumpcap, 340 dropped)  ● "),
            "{header:?}"
        );
    }

    #[test]
    fn eleven_seconds_after_the_last_drop_the_capture_indicator_is_as_before() {
        let mut state = dropping(CaptureHealth::Available, CaptureOrigin::Dumpcap, 340);
        let (before, _) = drawn_header(&dropping(
            CaptureHealth::Available,
            CaptureOrigin::Dumpcap,
            0,
        ));
        state.advance_time(Duration::from_secs(111));
        let (terminal, header) = drawn_header(&state);
        assert!(header.contains("● capture (dumpcap)  ● "), "{header:?}");
        assert_eq!(
            header_style(&terminal, "●").fg,
            header_style(&before, "●").fg
        );
    }

    #[test]
    fn a_capture_that_is_degraded_or_stopped_keeps_its_colour_and_gains_the_count() {
        for health in [
            CaptureHealth::Degraded("lost packets".into()),
            CaptureHealth::Cancelled,
        ] {
            let (own, _) = drawn_header(&dropping(health.clone(), CaptureOrigin::Own, 0));
            let (terminal, header) = drawn_header(&dropping(health, CaptureOrigin::Own, 340));
            assert!(header.contains("● capture (340 dropped)  ● "), "{header:?}");
            assert_eq!(header_style(&terminal, "●").fg, header_style(&own, "●").fg);
        }
    }

    #[test]
    fn a_large_drop_count_is_shortened() {
        for (dropped, shown) in [(999, "999"), (1_234, "1.2k"), (2_500_000, "2.5M")] {
            let state = dropping(CaptureHealth::Available, CaptureOrigin::Own, dropped);
            let (_, header) = drawn_header(&state);
            assert!(
                header.contains(&format!("capture ({shown} dropped)")),
                "{header:?}"
            );
        }
    }

    /// Dumpcap capture dropping 1 234 packets, `firewall`, the user and 100 blocks.
    fn tight_header(firewall: &'static str, user: &str, width: u16) -> String {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.advance_time(Duration::from_secs(100));
        block_n(&mut state, 100);
        state.record_capture_status(CaptureStatus {
            dropped: 1_234,
            ..capture_status(CaptureHealth::Available, CaptureOrigin::Dumpcap)
        });
        state.record_firewall_status(firewall_status(firewall, FirewallHealth::Available));
        attribution(&mut state, AttributionHealth::Available, Some(user));
        let mut i = Interaction::default();
        header_of(&screen(&state, &mut i, None, width, 24))
    }

    #[test]
    fn when_the_header_is_tight_dumpcap_gives_way_before_the_user_name() {
        let header = tight_header("ufw", "ryan", 110);
        assert!(
            header.starts_with(" Traffic · Network & Firewall 99+ "),
            "{header:?}"
        );
        assert!(
            header.trim_end().ends_with(
                "● capture (1.2k dropped)  ● firewall (ufw)  ● interfaces  ● apps (ryan)"
            ),
            "{header:?}"
        );
    }

    #[test]
    fn when_dumpcap_alone_does_not_make_room_the_user_name_is_cut_too() {
        let header = tight_header("ufw", &"a".repeat(32), 110);
        assert!(
            header.starts_with(" Traffic · Network & Firewall 99+ "),
            "{header:?}"
        );
        assert!(
            header.contains("● capture (1.2k dropped)  ● "),
            "{header:?}"
        );
        assert!(header.trim_end().ends_with("…)"), "{header:?}");
        assert!(!header.contains(&"a".repeat(32)), "{header:?}");
    }

    #[test]
    fn with_room_dumpcap_stays_beside_the_drop_count() {
        let header = tight_header("ufw", "ryan", 130);
        assert!(
            header.contains("● capture (dumpcap, 1.2k dropped)  ● "),
            "{header:?}"
        );
    }

    #[test]
    fn a_long_firewall_label_at_110_columns_is_not_drawn_over_the_left_side() {
        let header = tight_header("nftables", "ryan", 110);
        assert!(
            header.starts_with(" Traffic · Network & Firewall 99+ ●"),
            "{header:?}"
        );
        assert!(
            header.contains("● firewall (nftables)  ● interfaces  ● apps (r…)"),
            "{header:?}"
        );
    }

    #[test]
    fn the_header_shows_both_page_names_at_110_columns_with_the_indicators_whole() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        block_n(&mut state, 100);
        let mut i = Interaction::default();
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        for visible in [
            "Traffic",
            "Network & Firewall",
            "99+",
            "capture",
            "firewall",
            "interfaces",
            "apps",
        ] {
            assert!(header.contains(visible), "{visible}: {header:?}");
        }
        assert_eq!(header.matches('●').count(), 4, "{header:?}");
        // Each indicator keeps its dot and name together.
        for name in ["● capture", "● firewall", "● interfaces", "● apps"] {
            assert!(header.contains(name), "{name}: {header:?}");
        }
    }

    #[test]
    fn the_page_shown_is_the_focus_colour_in_the_header_and_the_other_is_not() {
        let state = sample();
        let theme = Theme::default();
        let mut i = Interaction::default();
        let terminal = screen(&state, &mut i, None, 110, 24);
        assert_eq!(header_style(&terminal, "Traffic").fg, theme.focus().fg);
        assert_ne!(
            header_style(&terminal, "Network & Firewall").fg,
            theme.focus().fg
        );
        press(&mut i, &state, KeyCode::Char('5'));
        let terminal = screen(&state, &mut i, None, 110, 24);
        assert_ne!(header_style(&terminal, "Traffic").fg, theme.focus().fg);
        assert_eq!(
            header_style(&terminal, "Network & Firewall").fg,
            theme.focus().fg
        );
    }

    #[test]
    fn three_blocks_recorded_on_traffic_show_a_three_in_the_warning_colour() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let mut i = Interaction::default();
        let before = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            !left_of_indicators(&before)
                .chars()
                .any(|c| c.is_ascii_digit()),
            "{before:?}"
        );
        block_n(&mut state, 3);
        let terminal = screen(&state, &mut i, None, 110, 24);
        let header = header_of(&terminal);
        assert!(header.contains("Network & Firewall 3"), "{header:?}");
        let theme = Theme::default();
        assert_eq!(
            header_style(&terminal, "Network & Firewall 3").fg,
            theme.muted().fg
        );
        assert_eq!(header_style(&terminal, "3").fg, theme.warning().fg);
    }

    #[test]
    fn a_hundred_blocks_show_ninety_nine_plus_and_ninety_nine_show_ninety_nine() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let mut i = Interaction::default();
        block_n(&mut state, 99);
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(header.contains("Network & Firewall 99 "), "{header:?}");
        block_n(&mut state, 1);
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(header.contains("Network & Firewall 99+"), "{header:?}");
    }

    #[test]
    fn the_count_goes_when_network_and_firewall_is_shown_and_starts_again_after_leaving() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let mut i = Interaction::default();
        block_n(&mut state, 3);
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(header.contains("Firewall 3"), "{header:?}");
        press(&mut i, &state, KeyCode::Char('5'));
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            !left_of_indicators(&header)
                .chars()
                .any(|c| c.is_ascii_digit()),
            "{header:?}"
        );
        // Blocks that arrive while the page is shown are seen, not counted.
        block_n(&mut state, 2);
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            !left_of_indicators(&header)
                .chars()
                .any(|c| c.is_ascii_digit())
        );
        press(&mut i, &state, KeyCode::Char('1'));
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            !left_of_indicators(&header)
                .chars()
                .any(|c| c.is_ascii_digit()),
            "{header:?}"
        );
        block_n(&mut state, 1);
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(header.contains("Network & Firewall 1"), "{header:?}");
    }

    #[test]
    fn blocks_that_arrive_while_zoomed_on_a_firewall_pane_are_not_counted_on_return() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        press(&mut i, &state, KeyCode::Enter);
        screen(&state, &mut i, None, 110, 24);
        block_n(&mut state, 2);
        screen(&state, &mut i, None, 110, 24);
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('1'));
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            !left_of_indicators(&header)
                .chars()
                .any(|c| c.is_ascii_digit()),
            "{header:?}"
        );
    }

    #[test]
    fn blocks_that_arrive_while_zoomed_on_a_traffic_pane_are_counted() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Enter);
        screen(&state, &mut i, None, 110, 24);
        block_n(&mut state, 2);
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(header.contains("Network & Firewall 2"), "{header:?}");
    }

    #[test]
    fn unreadable_rules_are_explained_in_listening_ports_while_app_traffic_keeps_working() {
        let mut state = sample();
        state.record_rules(RuleSnapshot::Unavailable("permission denied".into()));
        let text = lines(&draw_at(&state, 110, 32)).join("\n");
        assert!(text.contains("Cannot read firewall rules"), "{text}");
        assert!(text.contains("docs/firewall.md"), "{text}");
        assert!(text.contains("? unreadable"), "{text}");
        assert!(text.contains("142.250.80.46"), "App Traffic lost its rows");
    }

    fn firewall_status(name: &'static str, health: FirewallHealth) -> FirewallStatus {
        FirewallStatus { name, health }
    }

    /// The sample dashboard as it is on a machine with no supported firewall.
    fn without_firewall() -> AppState {
        let mut state = sample();
        state.record_firewall_status(firewall_status("none", FirewallHealth::NoFirewall));
        state.record_rules(RuleSnapshot::NoFirewall);
        state
    }

    #[test]
    fn the_header_names_ufw_at_each_level_it_has() {
        let theme = Theme::default();
        for (health, colour) in [
            (FirewallHealth::Available, theme.ok),
            (FirewallHealth::AwaitingEvents, theme.ok),
            (FirewallHealth::Disabled("off".into()), theme.warning),
            (FirewallHealth::Degraded("partly".into()), theme.warning),
            (FirewallHealth::Unavailable("denied".into()), theme.danger),
            (FirewallHealth::Cancelled, theme.danger),
        ] {
            let mut state = sample();
            state.record_firewall_status(firewall_status("ufw", health.clone()));
            let terminal = draw_at(&state, 110, 24);
            let header = header_of(&terminal);
            assert!(header.contains("firewall (ufw)"), "{health:?}: {header:?}");
            let dot = header.find("● firewall (ufw)").expect("dot before name");
            let x = header[..dot].chars().count() as u16;
            assert_eq!(
                terminal.backend().buffer()[(x, 0)].style().fg,
                Some(colour),
                "{health:?}"
            );
        }
    }

    #[test]
    fn firewalld_not_logging_denied_packets_keeps_the_header_healthy_and_the_blocks_pane_says_so() {
        let theme = Theme::default();
        let cases = [
            (
                FirewallHealth::NotLogging,
                "firewalld is not logging denied packets",
                "sudo firewall-cmd --set-log-denied=all",
            ),
            (
                FirewallHealth::DependsOnLogging,
                "Blocks show only if firewalld logs denied packets",
                "sudo firewall-cmd --set-log-denied=all",
            ),
        ];
        for (health, sentence, command) in cases {
            let mut state = sample();
            state.record_firewall_status(firewall_status("fwd", health.clone()));
            let terminal = draw_at(&state, 110, 32);
            let header = header_of(&terminal);
            let dot = header.find("● firewall (fwd)").expect("dot before name");
            let x = header[..dot].chars().count() as u16;
            assert_eq!(
                terminal.backend().buffer()[(x, 0)].style().fg,
                Some(theme.ok),
                "{health:?}"
            );
            let text = all_pages(&state, 200, 50);
            assert!(text.contains(sentence), "{health:?}: {text}");
            assert!(text.contains(command), "{health:?}: {text}");
        }
    }

    #[test]
    fn the_header_names_none_in_the_muted_colour() {
        let theme = Theme::default();
        let terminal = draw_at(&without_firewall(), 110, 24);
        let header = header_of(&terminal);
        assert!(header.contains("● firewall (none)"), "{header:?}");
        let x = header[..header.find("● firewall (none)").unwrap()]
            .chars()
            .count() as u16;
        assert_eq!(
            terminal.backend().buffer()[(x, 0)].style().fg,
            Some(theme.muted)
        );
    }

    #[test]
    fn with_no_firewall_the_three_panes_say_so_and_nothing_says_it_cannot_read() {
        let state = without_firewall();
        let text = all_pages(&state, 250, 50);
        for line in [
            "No supported firewall found, so there are no rules to show. See docs/firewall.md",
            "No supported firewall found, so no blocks are reported. See docs/firewall.md",
            "No supported firewall found, so exposure is unknown. See docs/firewall.md",
        ] {
            assert!(text.contains(line), "missing {line:?}:\n{text}");
        }
        assert!(!text.contains("Cannot read firewall rules"), "{text}");
        let rules = rules_pane(&text, 250);
        assert!(
            rules[0].contains("No supported firewall found"),
            "{rules:?}"
        );
        let all = rules.join(" ");
        assert!(
            !all.contains("allow") && !all.contains("default:"),
            "{rules:?}"
        );
    }

    #[test]
    fn with_no_firewall_ports_are_marked_no_firewall_in_muted_and_loopback_ports_stay_local() {
        let theme = Theme::default();
        let state = without_firewall();
        for terminal in listening_screens(&state, &theme) {
            assert_eq!(
                marker_style(&terminal, "? no firewall").fg,
                Some(theme.muted)
            );
            assert_eq!(marker_style(&terminal, "· local").fg, Some(theme.muted));
            let text = lines(&terminal).join("\n");
            assert!(!text.contains("? unreadable"), "{text}");
        }
    }

    fn port_rule(ports: std::ops::RangeInclusive<u16>, protocol: &str) -> PortRule {
        PortRule {
            ports,
            protocol: protocol.to_owned(),
        }
    }

    fn zone(name: &str, interfaces: &[&str], sources: &[&str], target: Target) -> Zone {
        Zone {
            name: name.to_owned(),
            interfaces: interfaces.iter().map(|s| (*s).to_owned()).collect(),
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
            target,
            allowed: vec![],
            rich_rules: vec![],
        }
    }

    /// The sample dashboard on a machine running firewalld, as `snapshot` reads it.
    fn firewalld_with(snapshot: RuleSnapshot, health: FirewallHealth) -> AppState {
        let mut state = sample();
        state.record_interfaces(InterfaceSnapshot {
            health: CollectionHealth::Available,
            interfaces: vec![InterfaceMeasurement {
                name: "wlan0".into(),
                addresses: vec![InterfaceAddress {
                    ip: "192.168.1.5".parse().unwrap(),
                    prefix: 24,
                }],
                download_bytes_per_second: 0.0,
                upload_bytes_per_second: 0.0,
                session_received_bytes: 0,
                session_transmitted_bytes: 0,
                status: InterfaceStatus::Available,
                is_up: true,
            }],
            default_route: Some("wlan0".into()),
            gateway: None,
            name_server: None,
            name_servers: vec![],
        });
        state.record_firewall_status(firewall_status("fwd", health));
        state.record_rules(snapshot);
        state
    }

    /// `public` on wlan0 (ssh and a port range, one rich rule) and `work` on a source network
    /// (everything allowed), with `lab` bound to nothing.
    fn two_zones() -> RuleSnapshot {
        let mut public = zone("public", &["wlan0"], &[], Target::Default);
        public.allowed = vec![
            Allowed::Service {
                name: "ssh".into(),
                ports: vec![port_rule(22..=22, "tcp")],
            },
            Allowed::Service {
                name: "samba".into(),
                ports: vec![port_rule(139..=139, "tcp"), port_rule(445..=445, "tcp")],
            },
            Allowed::Port(port_rule(8000..=8010, "tcp")),
        ];
        public.rich_rules = vec![r#"rule source address="192.0.2.9" drop"#.into()];
        let mut work = zone("work", &[], &["10.9.0.0/16"], Target::Accept);
        work.allowed = vec![Allowed::Port(port_rule(53..=53, "udp"))];
        RuleSnapshot::Zones(Zones {
            default_zone: "public".into(),
            zones: vec![public, work, zone("lab", &[], &[], Target::Drop)],
        })
    }

    #[test]
    fn the_header_names_fwd_at_each_level_it_has() {
        let theme = Theme::default();
        for (health, colour) in [
            (FirewallHealth::Available, theme.ok),
            (FirewallHealth::AwaitingEvents, theme.ok),
            (FirewallHealth::NotLogging, theme.ok),
            (FirewallHealth::DependsOnLogging, theme.ok),
            (
                FirewallHealth::Disabled("firewalld is not running".into()),
                theme.warning,
            ),
            (FirewallHealth::Unavailable("denied".into()), theme.danger),
        ] {
            let state = firewalld_with(two_zones(), health.clone());
            let terminal = draw_at(&state, 110, 24);
            let header = header_of(&terminal);
            let dot = header.find("● firewall (fwd)").expect("dot before name");
            let x = header[..dot].chars().count() as u16;
            assert_eq!(
                terminal.backend().buffer()[(x, 0)].style().fg,
                Some(colour),
                "{health:?}"
            );
        }
    }

    #[test]
    fn firewall_rules_shows_a_group_for_each_zone_that_applies_to_something() {
        let state = firewalld_with(two_zones(), FirewallHealth::NotLogging);
        let rules = rules_pane(&lines(&draw_at(&state, 110, 50)).join("\n"), 110).join("\n");
        for line in [
            "public · wlan0 · default reject",
            "ssh 22/tcp",
            "samba 139/tcp, 445/tcp",
            "port 8000-8010/tcp",
            r#"rich rule source address="192.0.2.9" drop"#,
            "work · 10.9.0.0/16 · default accept",
            "everything is allowed",
            "port 53/udp",
        ] {
            assert!(rules.contains(line), "missing {line:?}:\n{rules}");
        }
        assert!(!rules.contains("lab"), "a zone bound to nothing:\n{rules}");
    }

    #[test]
    fn a_zone_default_of_drop_reads_drop() {
        let snapshot = RuleSnapshot::Zones(Zones {
            default_zone: "dmz".into(),
            zones: vec![zone("dmz", &["wlan0"], &[], Target::Drop)],
        });
        let state = firewalld_with(snapshot, FirewallHealth::NotLogging);
        let rules = rules_pane(&lines(&draw_at(&state, 110, 30)).join("\n"), 110).join("\n");
        assert!(rules.contains("dmz · wlan0 · default drop"), "{rules}");
    }

    #[test]
    fn a_stopped_firewalld_says_so_in_each_pane_in_the_words_of_the_spec() {
        let theme = Theme::default();
        let state = firewalld_with(
            RuleSnapshot::FirewalldOff,
            FirewallHealth::Disabled("firewalld is not running".into()),
        );
        let text = all_pages(&state, 250, 50);
        for line in [
            "firewalld is not running, so there are no rules to show. See docs/firewall.md",
            "firewalld is not running, so no blocks are reported. See docs/firewall.md",
            "firewalld is not running, so exposure is unknown. See docs/firewall.md",
        ] {
            assert!(text.contains(line), "missing {line:?}:\n{text}");
        }
        assert!(
            !text.contains("UFW") && !text.contains("unreadable"),
            "{text}"
        );
        for terminal in listening_screens(&state, &theme) {
            assert_eq!(marker_style(&terminal, "? fwd off").fg, Some(theme.muted));
            assert_eq!(marker_style(&terminal, "· local").fg, Some(theme.muted));
        }
    }

    fn zones_only() -> RuleSnapshot {
        RuleSnapshot::ZonesOnly(vec![
            ActiveZone {
                name: "FedoraServer".into(),
                interfaces: vec!["wlan0".into()],
                sources: vec![],
            },
            ActiveZone {
                name: "trusted".into(),
                interfaces: vec![],
                sources: vec!["10.1.0.0/16".into()],
            },
        ])
    }

    #[test]
    fn zones_only_names_the_zones_and_explains_in_the_rules_and_ports_panes() {
        let theme = Theme::default();
        let state = firewalld_with(zones_only(), FirewallHealth::DependsOnLogging);
        let text = lines(&draw_at(&state, 250, 50)).join("\n");
        for line in [
            "firewalld shows this user only its zones. Run with sudo to see the rules.",
            "firewalld shows this user only its zones, so exposure is unknown. Run with sudo to see it.",
            "FedoraServer · wlan0",
            "trusted · 10.1.0.0/16",
        ] {
            assert!(text.contains(line), "missing {line:?}:\n{text}");
        }
        assert!(
            !text.contains("UFW") && !text.contains("unreadable"),
            "{text}"
        );
        for terminal in listening_screens(&state, &theme) {
            assert_eq!(
                marker_style(&terminal, "? not readable").fg,
                Some(theme.muted)
            );
            assert_eq!(marker_style(&terminal, "· local").fg, Some(theme.muted));
        }
        let header = header_of(&draw_at(&state, 110, 24));
        assert!(header.contains("● firewall (fwd)"), "{header}");
    }

    #[test]
    fn zones_only_keeps_the_healthy_colour() {
        let theme = Theme::default();
        let state = firewalld_with(zones_only(), FirewallHealth::DependsOnLogging);
        let terminal = draw_at(&state, 110, 24);
        let header = header_of(&terminal);
        let x = header[..header.find("● firewall (fwd)").unwrap()]
            .chars()
            .count() as u16;
        assert_eq!(
            terminal.backend().buffer()[(x, 0)].style().fg,
            Some(theme.ok)
        );
    }

    #[test]
    fn a_port_the_zones_cannot_judge_reads_unknown() {
        let theme = Theme::default();
        let snapshot = RuleSnapshot::Zones(Zones {
            default_zone: "gone".into(),
            zones: vec![zone("public", &["other0"], &[], Target::Default)],
        });
        let state = firewalld_with(snapshot, FirewallHealth::NotLogging);
        for terminal in listening_screens(&state, &theme) {
            assert_eq!(marker_style(&terminal, "? unknown").fg, Some(theme.muted));
            let text = text_of(&terminal);
            assert!(!text.contains("? unreadable"), "{text}");
        }
    }

    #[test]
    fn the_zoom_gives_no_rule_text_for_a_zones_exposure() {
        let state = firewalld_with(two_zones(), FirewallHealth::NotLogging);
        let text = listening_screens(&state, &Theme::default())[1..]
            .iter()
            .map(text_of)
            .collect::<String>();
        assert!(text.contains("◐ limited —"), "{text}");
        assert!(!text.contains("default policy"), "{text}");
    }

    #[test]
    fn what_firewalld_sends_is_cleaned_before_it_is_drawn() {
        let mut hostile = zone(
            "pub\u{1b}[31mlic\u{202e}",
            &["wl\u{1b}[2Jan0"],
            &["10.0.0.0/8\u{200b}"],
            Target::Reject,
        );
        hostile.allowed = vec![Allowed::Service {
            name: "ss\u{7}h\u{202e}".into(),
            ports: vec![port_rule(22..=22, "tcp")],
        }];
        hostile.rich_rules = vec![format!(
            "rule \u{1b}]0;title\u{7}drop\u{202e}{}",
            "x".repeat(5000)
        )];
        let long_name = zone(&"n".repeat(200), &["wlan0"], &[], Target::Drop);
        let snapshot = RuleSnapshot::Zones(Zones {
            default_zone: "public".into(),
            zones: vec![hostile, long_name],
        });
        let state = firewalld_with(snapshot, FirewallHealth::NotLogging);
        let mut zoom = Interaction::default();
        press(&mut zoom, &state, KeyCode::Char('4'));
        press(&mut zoom, &state, KeyCode::Enter);
        for text in [
            text_of(&draw_at(&state, 110, 30)),
            text_of(&screen(&state, &mut zoom, None, 200, 30)),
        ] {
            for disguise in ['\u{1b}', '\u{7}', '\u{202e}', '\u{200b}'] {
                assert!(!text.contains(disguise), "{disguise:?} in:\n{text}");
            }
            assert!(text.contains("pub[31mlic"), "{text}");
            assert!(!text.contains(&"n".repeat(60)), "{text}");
        }
    }

    #[test]
    fn a_long_rich_rule_is_cut_with_a_sign_and_does_not_hide_the_next_zone() {
        let mut first = zone("first", &["wlan0"], &[], Target::Default);
        first.rich_rules = vec![format!(
            "rule family=\"ipv4\" {}reject",
            "source address=\"192.0.2.1\" ".repeat(20)
        )];
        let second = zone("second", &["eth9"], &[], Target::Default);
        let snapshot = RuleSnapshot::Zones(Zones {
            default_zone: "first".into(),
            zones: vec![first, second],
        });
        let state = firewalld_with(snapshot, FirewallHealth::NotLogging);
        let rules = rules_pane(&lines(&draw_at(&state, 110, 30)).join("\n"), 110);
        let rule = rules
            .iter()
            .find(|l| l.starts_with("rich"))
            .expect("the rule");
        assert!(rule.contains('…'), "{rules:?}");
        assert!(rule.starts_with("rich rule family"), "{rules:?}");
        assert!(rule.ends_with("reject"), "the action stays: {rules:?}");
        assert!(rules.iter().any(|l| l.starts_with("second")), "{rules:?}");
    }

    #[test]
    fn zones_below_the_pane_are_counted_in_more() {
        let mut busy = zone("busy", &["wlan0"], &[], Target::Default);
        busy.allowed = (1..=40u16)
            .map(|n| Allowed::Port(port_rule(n..=n, "tcp")))
            .collect();
        let snapshot = RuleSnapshot::Zones(Zones {
            default_zone: "busy".into(),
            zones: vec![busy],
        });
        let state = firewalld_with(snapshot, FirewallHealth::NotLogging);
        let screen = lines(&draw_at(&state, 110, 30));
        let title = screen
            .iter()
            .position(|l| l.contains("FIREWALL RULES"))
            .unwrap();
        let below: String = screen[title..]
            .iter()
            .map(|l| l.chars().skip(55).collect::<String>())
            .collect();
        assert!(below.contains(" more "), "{below}");
    }

    #[test]
    fn each_dependent_pane_names_its_unhealthy_source_in_plain_words() {
        let mut state = sample();
        state.record_capture_status(CaptureStatus {
            health: CaptureHealth::Degraded("lost packets".into()),
            dropped: 0,
            origin: CaptureOrigin::Own,
        });
        state.record_firewall_status(FirewallStatus {
            name: "ufw",
            health: FirewallHealth::Disabled("logging off".into()),
        });
        state.record_interfaces(InterfaceSnapshot {
            health: CollectionHealth::Unavailable("no /proc".into()),
            interfaces: vec![],
            default_route: None,
            gateway: None,
            name_server: None,
            name_servers: vec![],
        });
        let text = all_pages(&state, 160, 50);
        for visible in [
            "Packet capture is degraded",
            "UFW logging is off",
            "Cannot read interface counters",
            "no interface data",
        ] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
        assert!(!text.contains("Degraded(") && !text.contains("Disabled("));
    }

    #[test]
    fn missing_attribution_explains_the_empty_listening_ports_pane() {
        let mut state = sample();
        state.record_attribution_status(AttributionStatus {
            health: AttributionHealth::Unavailable("procfs restricted".into()),
            only_user: None,
        });
        state.record_listeners(vec![], 32_768..=60_999);
        let text = lines(&draw_at(&state, 160, 50)).join("\n");
        assert!(text.contains("No ports listed"), "{text}");
    }

    #[test]
    fn with_attribution_unavailable_app_traffic_gives_its_message_no_rows_and_a_growing_footer_total()
     {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        state.record_attribution_status(AttributionStatus {
            health: AttributionHealth::Unavailable("procfs restricted".into()),
            only_user: None,
        });
        packet(
            &mut state,
            1,
            None,
            "203.0.113.9",
            443,
            Direction::Outbound,
            100,
        );
        let text = lines(&draw_at(&state, 160, 50)).join("\n");
        assert!(text.contains("App names are unavailable"), "{text}");
        assert!(!text.contains("203.0.113.9"), "{text}");
        assert!(text.contains("not attributed: 0 B in, 100 B out"), "{text}");
        packet(
            &mut state,
            2,
            None,
            "203.0.113.9",
            443,
            Direction::Outbound,
            100,
        );
        let text = lines(&draw_at(&state, 160, 50)).join("\n");
        assert!(text.contains("not attributed: 0 B in, 200 B out"), "{text}");
    }

    fn attribution(state: &mut AppState, health: AttributionHealth, only_user: Option<&str>) {
        state.record_attribution_status(AttributionStatus {
            health,
            only_user: only_user.map(str::to_owned),
        });
    }

    /// Three apps with traffic and some traffic no app owns, so the footer shows.
    fn three_apps_and_unowned() -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        for (pid, name, remote) in [
            (42, "firefox", "142.250.80.46"),
            (43, "curl", "151.101.1.69"),
            (44, "git", "140.82.112.3"),
        ] {
            let app = process(&format!("/usr/bin/{name}"), pid);
            packet(
                &mut state,
                1,
                Some(&app),
                remote,
                443,
                Direction::Outbound,
                100,
            );
        }
        packet(
            &mut state,
            1,
            None,
            "203.0.113.9",
            53,
            Direction::Outbound,
            40,
        );
        state
    }

    /// App Traffic's lines at 110x24: from its title line to its bottom border.
    fn app_traffic_pane(state: &AppState) -> Vec<String> {
        let all = lines(&draw_at(state, 110, 24));
        let top = all.iter().position(|l| l.contains("APP TRAFFIC")).unwrap();
        let bottom = all[top..]
            .iter()
            .position(|l| l.starts_with('╰'))
            .map(|n| top + n)
            .unwrap_or_else(|| panic!("no bottom border:\n{}", all.join("\n")));
        let pane = all[top..=bottom].to_vec();
        assert!(
            pane.iter().all(|l| l.chars().count() == 110),
            "{}",
            all.join("\n")
        );
        pane
    }

    fn data_rows_shown(pane: &[String]) -> usize {
        ["firefox", "curl", "git"]
            .iter()
            .filter(|name| pane.iter().any(|l| l.contains(*name)))
            .count()
    }

    #[test]
    fn app_traffic_at_110_by_24_keeps_its_header_and_three_rows_above_the_footer() {
        let mut state = three_apps_and_unowned();
        attribution(&mut state, AttributionHealth::Available, Some("alice"));
        let pane = app_traffic_pane(&state);
        let text = pane.join("\n");
        assert!(!text.contains("Other users' programs"), "{text}");
        assert!(text.contains("DESTINATION"), "{text}");
        assert_eq!(data_rows_shown(&pane), 3, "{text}");
        assert!(text.contains("not attributed: 0 B in, 40 B out"), "{text}");
    }

    #[test]
    fn app_traffic_at_110_by_24_shows_the_capture_unavailable_notice_without_corruption() {
        let mut state = three_apps_and_unowned();
        state.record_capture_status(CaptureStatus {
            health: CaptureHealth::Degraded("lost packets".into()),
            dropped: 0,
            origin: CaptureOrigin::Own,
        });
        let pane = app_traffic_pane(&state);
        let text = pane.join("\n");
        assert!(text.contains("Packet capture is degraded"), "{text}");
        assert!(text.contains("DESTINATION"), "{text}");
        assert_eq!(data_rows_shown(&pane), 3, "{text}");
    }

    fn capture_status(health: CaptureHealth, origin: CaptureOrigin) -> CaptureStatus {
        CaptureStatus {
            health,
            dropped: 0,
            origin,
        }
    }

    #[test]
    fn the_header_names_dumpcap_as_the_capture_source_only_when_it_is() {
        for (origin, shown) in [
            (CaptureOrigin::Dumpcap, "● capture (dumpcap)  ● firewall"),
            (CaptureOrigin::Own, "● capture  ● firewall"),
        ] {
            let mut state = AppState::new(StateLimits::default()).unwrap();
            state.record_capture_status(capture_status(CaptureHealth::Available, origin));
            let mut i = Interaction::default();
            let header = header_of(&screen(&state, &mut i, None, 110, 24));
            assert!(header.contains(shown), "{header:?}");
        }
    }

    #[test]
    fn app_traffic_says_capture_through_dumpcap_has_stopped_with_the_reason_dumpcap_gave() {
        let mut state = three_apps_and_unowned();
        state.record_capture_status(capture_status(
            CaptureHealth::Degraded(
                "capture through dumpcap has stopped: dumpcap: You do not have permission to capture on that device"
                    .into(),
            ),
            CaptureOrigin::Dumpcap,
        ));
        let pane = app_traffic_pane(&state);
        let text = pane.join(" ");
        assert!(
            text.contains("Capture through dumpcap has stopped: dumpcap: You do not"),
            "{text}"
        );
        assert!(text.contains("permission to capture on that"), "{text}");
        assert!(!text.contains("stopped: capture through"), "{text}");
        assert!(!text.contains("Packet capture is degraded"), "{text}");
        assert_eq!(data_rows_shown(&pane), 3, "{text}");
    }

    #[test]
    fn app_traffic_shows_the_dumpcap_line_for_a_dumpcap_stop_without_the_sources_prefix() {
        let message = "capture device must provide Linux cooked v2 headers, not link type 1";
        let mut state = three_apps_and_unowned();
        state.record_capture_status(capture_status(
            CaptureHealth::Degraded(message.into()),
            CaptureOrigin::Dumpcap,
        ));
        let text = app_traffic_pane(&state).join(" ");
        assert!(
            text.contains("Capture through dumpcap has stopped: capture device must provide"),
            "{text}"
        );
        assert!(text.contains("not link type 1"), "{text}");
        assert!(!text.contains("Packet capture is degraded"), "{text}");
    }

    #[test]
    fn app_traffic_keeps_the_generic_line_for_an_own_capture_whatever_its_message_begins_with() {
        let mut state = three_apps_and_unowned();
        state.record_capture_status(capture_status(
            CaptureHealth::Degraded("capture through dumpcap has stopped: odd".into()),
            CaptureOrigin::Own,
        ));
        let text = app_traffic_pane(&state).join(" ");
        assert!(text.contains("Packet capture is degraded"), "{text}");
        assert!(!text.contains("Capture through dumpcap"), "{text}");
    }

    #[test]
    fn app_traffic_keeps_the_signal_dumpcap_ended_with_in_its_line() {
        let mut state = three_apps_and_unowned();
        state.record_capture_status(capture_status(
            CaptureHealth::Degraded(
                "capture through dumpcap has stopped: it was ended by signal 9".into(),
            ),
            CaptureOrigin::Dumpcap,
        ));
        let text = app_traffic_pane(&state).join(" ");
        assert!(
            text.contains("Capture through dumpcap has stopped: it was ended by signal 9"),
            "{text}"
        );
    }

    #[test]
    fn app_traffic_at_110_by_24_shows_the_attribution_unavailable_notice_without_corruption() {
        let mut state = three_apps_and_unowned();
        attribution(
            &mut state,
            AttributionHealth::Unavailable("procfs restricted".into()),
            None,
        );
        let pane = app_traffic_pane(&state);
        let text = pane.join("\n");
        assert!(text.contains("App names are unavailable"), "{text}");
        assert!(text.contains("DESTINATION"), "{text}");
        assert_eq!(data_rows_shown(&pane), 3, "{text}");
    }

    fn apps_dot(terminal: &Terminal<TestBackend>) -> Option<ratatui::style::Color> {
        let (y, x) = at(&lines(terminal), "apps");
        terminal.backend().buffer()[(x as u16 - 2, y as u16)]
            .style()
            .fg
    }

    fn header_line(terminal: &Terminal<TestBackend>) -> String {
        lines(terminal)
            .into_iter()
            .find(|line| line.contains("apps"))
            .unwrap()
    }

    #[test]
    fn a_user_who_is_not_root_sees_their_name_on_a_healthy_apps_indicator_and_no_line_about_others()
    {
        let theme = Theme::default();
        let mut state = sample();
        attribution(&mut state, AttributionHealth::Available, Some("alice"));
        let terminal = draw_at(&state, 110, 32);
        let text = lines(&terminal).join("\n");
        assert!(header_line(&terminal).contains("apps (alice)"), "{text}");
        assert_eq!(apps_dot(&terminal), Some(theme.ok), "{text}");
        assert!(!text.contains("Other users' programs"), "{text}");
        assert!(!text.contains("cap_sys_ptrace"), "{text}");
        assert!(text.contains("142.250.80.46"), "{text}");
    }

    #[test]
    fn root_sees_apps_without_a_name_on_a_healthy_indicator() {
        let theme = Theme::default();
        let mut state = sample();
        attribution(&mut state, AttributionHealth::Available, None);
        let terminal = draw_at(&state, 110, 32);
        let text = lines(&terminal).join("\n");
        assert!(!header_line(&terminal).contains("apps ("), "{text}");
        assert_eq!(apps_dot(&terminal), Some(theme.ok), "{text}");
    }

    #[test]
    fn a_stale_source_keeps_its_warning_and_line_and_the_name() {
        let theme = Theme::default();
        let mut state = sample();
        attribution(
            &mut state,
            AttributionHealth::Stale("procfs slow".into()),
            Some("alice"),
        );
        let terminal = draw_at(&state, 110, 32);
        let text = lines(&terminal).join("\n");
        assert!(header_line(&terminal).contains("apps (alice)"), "{text}");
        assert_eq!(apps_dot(&terminal), Some(theme.warning), "{text}");
        assert!(text.contains("App names are out of date"), "{text}");
    }

    #[test]
    fn an_unavailable_source_keeps_its_danger_and_line_and_the_name() {
        let theme = Theme::default();
        let mut state = sample();
        attribution(
            &mut state,
            AttributionHealth::Unavailable("procfs restricted".into()),
            Some("alice"),
        );
        let terminal = draw_at(&state, 110, 32);
        let text = lines(&terminal).join("\n");
        assert!(header_line(&terminal).contains("apps (alice)"), "{text}");
        assert_eq!(apps_dot(&terminal), Some(theme.danger), "{text}");
        assert!(text.contains("App names are unavailable"), "{text}");
        assert!(!text.contains("cap_sys_ptrace"), "{text}");
    }

    #[test]
    fn empty_panes_say_so_in_muted_text() {
        let state = AppState::new(StateLimits::default()).unwrap();
        let text = all_pages(&state, 110, 24);
        for visible in [
            "no outbound traffic yet",
            "no blocks seen",
            "no listening ports",
        ] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
    }

    #[test]
    fn a_chosen_interface_and_pane_search_can_be_passed_to_the_overview() {
        let state = sample();
        let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
        let view = Overview::new(Pane::ListeningPorts)
            .interface("lo")
            .search(Pane::AppTraffic, "syncthing");
        terminal
            .draw(|frame| draw(frame, &state, &Theme::default(), &view))
            .unwrap();
        let text = lines(&terminal);
        assert!(
            text.iter()
                .any(|l| l.contains("BANDWIDTH") && l.contains("lo"))
        );
        let joined = text.join("\n");
        assert!(joined.contains("198.51.100.23") && !joined.contains("142.250.80.46"));
    }

    // ---- interaction, zoom, search, help ----

    fn type_text(i: &mut Interaction, state: &AppState, text: &str) {
        for c in text.chars() {
            press(i, state, KeyCode::Char(c));
        }
    }

    fn zoomed(pane_key: char, width: u16, height: u16) -> (AppState, Interaction, String) {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char(pane_key));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, width, height));
        (state, i, text)
    }

    #[test]
    fn keys_focus_the_panes_in_visual_order_and_enter_zooms() {
        let state = sample();
        let mut i = Interaction::default();
        assert_eq!(i.focus(), Pane::Bandwidth);
        for (key, pane) in [
            ('2', Pane::AppTraffic),
            ('3', Pane::ListeningPorts),
            ('4', Pane::FirewallRules),
            ('5', Pane::FirewallBlocks),
            ('6', Pane::NetworkEvents),
            ('7', Pane::WifiNetworks),
            ('8', Pane::Neighbors),
            ('1', Pane::Bandwidth),
        ] {
            press(&mut i, &state, KeyCode::Char(key));
            assert_eq!(i.focus(), pane);
        }
        press(&mut i, &state, KeyCode::Tab);
        assert_eq!(i.focus(), Pane::AppTraffic);
        press(&mut i, &state, KeyCode::BackTab);
        press(&mut i, &state, KeyCode::BackTab);
        assert_eq!(i.focus(), Pane::Neighbors);
        press(&mut i, &state, KeyCode::Enter);
        assert_eq!(i.zoomed(), Some(Pane::Neighbors));
        press(&mut i, &state, KeyCode::Esc);
        assert_eq!(i.zoomed(), None);
    }

    #[test]
    fn app_traffic_zoom_lists_every_destination_with_the_extra_columns() {
        let (_, _, text) = zoomed('2', 120, 32);
        for visible in [
            "APP TRAFFIC",
            "PID",
            "↓ IN",
            "↑ OUT",
            "↓ TOTAL",
            "↑ TOTAL",
            "142.250.80.46",
            "93.184.216.34",
            "2606:4700::6810:84e5",
            "198.51.100.23",
            "esc back",
        ] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
        assert!(!text.contains("+2 more"), "zoom lists every destination");
        assert!(text.contains("capture"));
    }

    #[test]
    fn blocked_zoom_adds_first_seen_interface_direction_and_outbound_blocks() {
        let (_, _, text) = zoomed('5', 120, 32);
        for visible in [
            "LAST SEEN",
            "FIRST SEEN",
            "FROM",
            "PORT",
            "HITS",
            "INTERFACE",
            "DIRECTION",
            "eth0",
            "10.0.0.5",
            " in ",
            " out ",
        ] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
    }

    fn forwarded_state() -> AppState {
        forwarded_state_on(Some("eth0"))
    }

    fn forwarded_state_on(interface: Option<&str>) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        for n in 1..=2 {
            let mut event = block(
                "198.51.100.77",
                8080,
                Direction::Inbound,
                Some("May  3 10:20:01"),
            );
            event.direction = None;
            event.interface = interface.map(str::to_owned);
            state.record_firewall(Duration::from_secs(n), event);
        }
        state
    }

    #[test]
    fn a_forwarded_block_is_a_zoom_row_with_a_dash_for_direction_and_not_on_the_overview() {
        let state = forwarded_state();
        let mut i = Interaction::default();
        let traffic = text_of(&screen(&state, &mut i, None, 160, 50));
        assert!(traffic.contains("Network & Firewall 2"), "{traffic}");
        press(&mut i, &state, KeyCode::Char('5'));
        let overview = text_of(&screen(&state, &mut i, None, 160, 50));
        assert!(!overview.contains("198.51.100.77"), "{overview}");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 160, 32));
        let line = text
            .lines()
            .find(|l| l.contains("198.51.100.77"))
            .unwrap_or_else(|| panic!("{text}"));
        for visible in ["8080/tcp", "×2", "10:20", "eth0", "—"] {
            assert!(line.contains(visible), "missing {visible:?}: {line}");
        }
        assert!(!line.contains(" in ") && !line.contains(" out "), "{line}");
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "198.51.100.77");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 160, 32));
        assert!(text.contains("198.51.100.77"), "{text}");
    }

    fn zoomed_blocked(state: &AppState) -> Interaction {
        let mut i = Interaction::default();
        press(&mut i, state, KeyCode::Char('5'));
        press(&mut i, state, KeyCode::Enter);
        i
    }

    #[test]
    fn a_forwarded_block_with_no_interface_shows_a_dash_for_interface_and_direction() {
        let state = forwarded_state_on(None);
        let mut i = zoomed_blocked(&state);
        let text = text_of(&screen(&state, &mut i, None, 160, 32));
        let line = text
            .lines()
            .find(|l| l.contains("198.51.100.77"))
            .unwrap_or_else(|| panic!("{text}"));
        assert!(line.contains("8080/tcp") && line.contains("×2"), "{line}");
        assert!(!line.contains("eth0"), "{line}");
        assert!(!line.contains(" in ") && !line.contains(" out "), "{line}");
        assert_eq!(line.matches('—').count(), 2, "IFACE and DIR: {line}");
    }

    #[test]
    fn a_zoom_search_that_does_not_match_a_forwarded_block_hides_it() {
        let state = forwarded_state();
        let mut i = zoomed_blocked(&state);
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "203.0.113.9");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 160, 32));
        assert!(!text.contains("198.51.100.77"), "{text}");
    }

    #[test]
    fn listening_zoom_shows_a_long_executable_path_whole_on_a_wide_terminal() {
        let path =
            "/opt/some-vendor/applications/deeply/nested/directory/tree/bin/long-running-daemon";
        assert!(path.len() > 70);
        let mut state = sample();
        state.record_listeners(vec![listener(22, "0.0.0.0", Some(path))], 32_768..=60_999);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('3'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 200, 32));
        assert!(text.contains(path), "{text}");
    }

    #[test]
    fn listening_zoom_adds_pid_the_deciding_rule_and_the_full_path() {
        let (_, _, text) = zoomed('3', 120, 32);
        for visible in [
            "PID",
            "RULE",
            "PATH",
            "22 rule",
            "default policy",
            "loopback only",
            "/usr/bin/sshd",
        ] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
    }

    #[test]
    fn bandwidth_zoom_has_a_taller_chart_and_a_table_of_every_interface() {
        let (_, _, text) = zoomed('1', 110, 32);
        for visible in [
            "wlan0",
            "lo",
            "↓ IN",
            "↑ OUT",
            "↓ TOTAL",
            "↑ TOTAL",
            "▶",
            "peak",
        ] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
        let rows = text.lines().collect::<Vec<_>>();
        let chart_rows = rows
            .iter()
            .filter(|l| l.chars().any(|c| "▁▂▃▄▅▆▇█".contains(c)))
            .count();
        assert!(chart_rows >= 6, "chart is about half the screen:\n{text}");
        assert!(rows.iter().any(|l| l.contains('▶') && l.contains("wlan0")));
        assert!(!rows.iter().any(|l| l.contains('▶') && l.contains(" lo ")));
    }

    #[test]
    fn j_at_the_last_row_stays_and_k_then_moves_up_one() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('3'));
        press(&mut i, &state, KeyCode::Enter);
        for _ in 0..12 {
            press(&mut i, &state, KeyCode::Char('j'));
            screen(&state, &mut i, None, 120, 32);
        }
        assert_eq!(i.selected(), 4, "five listening ports");
        press(&mut i, &state, KeyCode::Char('k'));
        assert_eq!(i.selected(), 3);
        press(&mut i, &state, KeyCode::Up);
        press(&mut i, &state, KeyCode::Down);
        assert_eq!(i.selected(), 3);
        for _ in 0..9 {
            press(&mut i, &state, KeyCode::Char('k'));
        }
        assert_eq!(i.selected(), 0);
    }

    #[test]
    fn the_selected_zoom_row_is_marked_and_the_table_scrolls_only_to_keep_it_visible() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Char('j'));
        press(&mut i, &state, KeyCode::Char('j'));
        let terminal = screen(&state, &mut i, None, 120, 32);
        let text = lines(&terminal);
        let (y, x) = at(&text, "104.18.32.7");
        let buffer = terminal.backend().buffer();
        assert_eq!(
            buffer[(x as u16, y as u16)].style().bg,
            Some(Theme::default().muted)
        );
        let (y, x) = at(&text, "151.101.1.69");
        assert_ne!(
            buffer[(x as u16, y as u16)].style().bg,
            Some(Theme::default().muted)
        );
        for _ in 0..4 {
            press(&mut i, &state, KeyCode::Char('j'));
        }
        let text = text_of(&screen(&state, &mut i, None, 120, 32));
        assert!(text.contains("198.51.100.23"), "{text}");
        assert!(
            text.contains("142.250.80.46"),
            "no scroll while visible:\n{text}"
        );
    }

    #[test]
    fn search_narrows_only_its_own_pane_and_survives_zoom_and_esc() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "syncthing");
        press(&mut i, &state, KeyCode::Enter);
        assert!(!i.field_open());
        let text = text_of(&screen(&state, &mut i, None, 120, 40));
        assert!(text.contains("198.51.100.23") && !text.contains("142.250.80.46"));
        assert!(
            text.contains("sshd"),
            "listening ports pane is untouched:\n{text}"
        );
        press(&mut i, &state, KeyCode::Char('5'));
        let text = text_of(&screen(&state, &mut i, None, 120, 40));
        assert!(
            text.contains("203.0.113.50"),
            "blocked pane is untouched:\n{text}"
        );
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Enter);
        let zoom = text_of(&screen(&state, &mut i, None, 120, 32));
        assert!(zoom.contains("198.51.100.23") && !zoom.contains("142.250.80.46"));
        press(&mut i, &state, KeyCode::Esc);
        assert_eq!(i.search(Pane::AppTraffic), "syncthing");
        assert_eq!(i.search(Pane::FirewallBlocks), "");
    }

    #[test]
    fn the_search_field_is_drawn_in_the_title_with_a_cursor_while_open_and_stays_when_closed() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "fire");
        let text = lines(&screen(&state, &mut i, None, 110, 32));
        assert!(
            text.iter()
                .any(|l| l.contains("APP TRAFFIC") && l.contains("/fire▏")),
            "{text:?}"
        );
        press(&mut i, &state, KeyCode::Backspace);
        press(&mut i, &state, KeyCode::Char('e'));
        press(&mut i, &state, KeyCode::Enter);
        let text = lines(&screen(&state, &mut i, None, 110, 32));
        assert!(
            text.iter()
                .any(|l| l.contains("APP TRAFFIC") && l.contains("/fire") && !l.contains('▏')),
            "{text:?}"
        );
    }

    #[test]
    fn esc_in_the_search_field_clears_the_text_and_closes_it() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "203");
        assert_eq!(i.search(Pane::FirewallBlocks), "203");
        press(&mut i, &state, KeyCode::Esc);
        assert_eq!(i.search(Pane::FirewallBlocks), "");
        assert!(!i.field_open());
    }

    #[test]
    fn esc_on_the_overview_clears_the_kept_search_but_esc_in_zoom_keeps_it() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "203");
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Enter);
        assert_eq!(i.zoomed(), Some(Pane::FirewallBlocks));
        press(&mut i, &state, KeyCode::Esc);
        assert_eq!(i.zoomed(), None);
        assert_eq!(i.search(Pane::FirewallBlocks), "203");
        press(&mut i, &state, KeyCode::Esc);
        assert_eq!(i.search(Pane::FirewallBlocks), "");
    }

    #[test]
    fn the_help_says_where_esc_clears_the_search_and_where_it_keeps_it() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('?'));
        let text = text_of(&screen(&state, &mut i, None, 120, 40));
        assert!(
            text.contains("leave zoom (search kept)")
                && text.contains("on the overview: clear the search"),
            "{text}"
        );
    }

    #[test]
    fn q_types_in_an_open_search_field_but_ctrl_c_still_quits() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('/'));
        press(&mut i, &state, KeyCode::Char('q'));
        assert_eq!(i.search(Pane::Bandwidth), "q");
        assert!(!i.should_quit());
        i.handle_key(
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            &state,
        );
        assert!(i.should_quit());
    }

    #[test]
    fn q_quits_outside_the_search_field() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('q'));
        assert!(i.should_quit());
    }

    #[test]
    fn removed_keys_do_nothing() {
        let state = sample();
        let mut i = Interaction::default();
        for key in ['f', 'c', 'l', 'r'] {
            press(&mut i, &state, KeyCode::Char(key));
        }
        assert!(!i.field_open() && !i.help_open() && i.zoomed().is_none());
        assert_eq!(i.focus(), Pane::Bandwidth);
    }

    #[test]
    fn help_is_a_popup_over_the_dashboard_with_the_pane_titles_still_visible() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('?'));
        assert!(i.help_open());
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        for visible in [
            // The popup covers only its own box: the titles outside it stay.
            "Traffic",
            "BANDWIDTH",
            "APP TRAFFIC",
            "HELP",
            "open",
            "limited",
            "blocked",
            "local",
            "1 Bandwidth",
            "j/k",
        ] {
            assert!(text.contains(visible), "missing {visible:?}:\n{text}");
        }
        press(&mut i, &state, KeyCode::Esc);
        assert!(!i.help_open());
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(!text.contains("HELP"));
    }

    #[test]
    fn the_help_popup_is_short_enough_to_leave_the_dashboard_visible_at_110_by_24() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('?'));
        let rows = lines(&screen(&state, &mut i, None, 110, 24));
        let top = rows.iter().position(|l| l.contains("HELP")).unwrap();
        let last = rows
            .iter()
            .enumerate()
            .skip(top)
            .find(|(_, l)| l.contains("● open"))
            .map(|(n, _)| n)
            .unwrap();
        assert!(last - top + 2 <= 17, "popup is {} rows", last - top + 2);
    }

    #[test]
    fn p_swaps_pages_and_returns_to_the_pane_last_focused_on_each() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::FirewallBlocks);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("FIREWALL BLOCKS") && !text.contains("APP TRAFFIC"));
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::Bandwidth);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("APP TRAFFIC") && !text.contains("FIREWALL BLOCKS"));

        press(&mut i, &state, KeyCode::Char('8'));
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::Bandwidth);
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::Neighbors);
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::AppTraffic);
    }

    #[test]
    fn p_remembers_a_pane_reached_by_tab() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('3'));
        press(&mut i, &state, KeyCode::Tab);
        press(&mut i, &state, KeyCode::Tab);
        press(&mut i, &state, KeyCode::Tab);
        assert_eq!(i.focus(), Pane::NetworkEvents);
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::FirewallRules);
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::NetworkEvents);
    }

    #[test]
    fn p_does_nothing_in_zoom() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::AppTraffic);
        assert_eq!(i.zoomed(), Some(Pane::AppTraffic));
    }

    #[test]
    fn p_typed_in_a_search_field_is_search_text() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Char('/'));
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::AppTraffic);
        assert_eq!(i.search(Pane::AppTraffic), "p");
    }

    #[test]
    fn p_with_help_open_changes_nothing() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('?'));
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::Bandwidth);
        assert!(i.help_open());
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('p'));
        assert_eq!(i.focus(), Pane::FirewallBlocks);
    }

    #[test]
    fn p_to_network_and_firewall_clears_the_header_count() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let mut i = Interaction::default();
        screen(&state, &mut i, None, 110, 24);
        block_n(&mut state, 3);
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(header.contains("Network & Firewall 3"), "{header:?}");
        press(&mut i, &state, KeyCode::Char('p'));
        screen(&state, &mut i, None, 110, 24);
        press(&mut i, &state, KeyCode::Char('p'));
        let header = header_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            !left_of_indicators(&header)
                .chars()
                .any(|c| c.is_ascii_digit()),
            "{header:?}"
        );
    }

    #[test]
    fn the_footer_and_help_list_p_and_fit_at_110_by_24() {
        let state = sample();
        let mut i = Interaction::default();
        let rows = lines(&screen(&state, &mut i, None, 110, 24));
        assert!(rows[23].contains("p page"), "{}", rows[23]);
        assert!(rows[23].contains("q quit"), "{}", rows[23]);
        press(&mut i, &state, KeyCode::Char('?'));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("p  ") || text.contains(" p "), "{text}");
        assert!(text.contains("other page"), "{text}");
        assert!(text.contains("● open"), "{text}");
    }

    #[test]
    fn i_cycles_the_interface_and_wraps() {
        let state = sample();
        let mut i = Interaction::default();
        let plotted = |i: &mut Interaction| {
            lines(&screen(&state, i, None, 110, 32))
                .into_iter()
                .find(|l| l.contains("BANDWIDTH"))
                .unwrap()
        };
        assert!(plotted(&mut i).contains("wlan0"));
        press(&mut i, &state, KeyCode::Char('i'));
        assert!(plotted(&mut i).contains(" lo "));
        press(&mut i, &state, KeyCode::Char('i'));
        assert!(plotted(&mut i).contains("wlan0"));
    }

    fn named_dns() -> ReverseDns {
        let target: std::net::IpAddr = "142.250.80.46".parse().unwrap();
        let mut dns = ReverseDns::new(true, 8, 8, move |address| {
            (address == target).then(|| "lhr25s34-in-f14.1e100.net".to_owned())
        });
        dns.schedule_visible([target]);
        for _ in 0..200 {
            dns.poll();
            if dns.name(target).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        dns
    }

    #[test]
    fn a_search_matching_only_reverse_dns_names_leaves_the_selection_movable() {
        let state = sample();
        let targets: [std::net::IpAddr; 2] = [
            "142.250.80.46".parse().unwrap(),
            "151.101.1.69".parse().unwrap(),
        ];
        let mut dns = ReverseDns::new(true, 8, 8, |address| {
            Some(format!("host-{address}.cdn.example"))
        });
        dns.schedule_visible(targets);
        for _ in 0..200 {
            dns.poll();
            if targets.iter().all(|t| dns.name(*t).is_some()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Enter);
        screen(&state, &mut i, Some(&dns), 160, 32);
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "cdn.example");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, Some(&dns), 160, 32));
        assert!(text.contains("host-142.250.80.46"), "{text}");
        press(&mut i, &state, KeyCode::Char('j'));
        screen(&state, &mut i, Some(&dns), 160, 32);
        assert_eq!(i.selected(), 1);
    }

    #[test]
    fn with_reverse_dns_the_overview_shows_the_name_and_zoom_shows_name_and_address() {
        let state = sample();
        let dns = named_dns();
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('2'));
        let overview = text_of(&screen(&state, &mut i, Some(&dns), 160, 50));
        assert!(overview.contains("lhr25s34-in-f14"), "{overview}");
        assert!(!overview.contains("142.250.80.46"), "{overview}");
        assert!(
            overview.contains("151.101.1.69"),
            "unnamed keep the address"
        );
        press(&mut i, &state, KeyCode::Enter);
        let zoom = text_of(&screen(&state, &mut i, Some(&dns), 160, 32));
        assert!(zoom.contains("lhr25s34-in-f14.1e100.net") && zoom.contains("142.250.80.46"));
    }

    fn blocked_dns(names: &[(&str, &str)]) -> ReverseDns {
        let table: Vec<(std::net::IpAddr, String)> = names
            .iter()
            .map(|(ip, name)| (ip.parse().unwrap(), (*name).to_owned()))
            .collect();
        let lookup = table.clone();
        let mut dns = ReverseDns::new(true, 8, 8, move |address| {
            lookup
                .iter()
                .find(|(ip, _)| *ip == address)
                .map(|(_, n)| n.clone())
        });
        dns.schedule_visible(table.iter().map(|(ip, _)| *ip));
        for _ in 0..200 {
            dns.poll();
            if table.iter().all(|(ip, _)| dns.name(*ip).is_some()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        dns
    }

    // ---- refused attempts beside firewall blocks ----

    fn refuse(state: &mut AppState, at: u64, machine: &str) {
        use crosswalk::collect::capture::TcpFlags;
        let flags = |syn, ack, rst| {
            Some(TcpFlags {
                syn,
                ack,
                rst,
                fin: false,
                psh: false,
            })
        };
        let (me, port) = ("192.0.2.10", 24_800);
        let at = Duration::from_secs(at);
        let end = |ip: &str, port| Endpoint {
            ip: ip.parse().unwrap(),
            port: Some(port),
        };
        let event = |direction, from, to, tcp_flags| TrafficEvent {
            source: from,
            destination: to,
            protocol: Protocol::Tcp,
            direction,
            original_ip_bytes: 60,
            limitation: None,
            tcp_flags,
            timing: None,
        };
        state.record_traffic(
            at,
            event(
                Direction::Inbound,
                end(machine, 40_000),
                end(me, port),
                flags(true, false, false),
            ),
            None,
        );
        state.record_traffic(
            at,
            event(
                Direction::Outbound,
                end(me, port),
                end(machine, 40_000),
                flags(false, true, true),
            ),
            None,
        );
    }

    /// A block from 203.0.113.50 at 1s, a refused attempt from 10.0.1.12 at 2s,
    /// and a block from 198.51.100.7 at 3s, with no listeners.
    fn mixed() -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.set_wall_clock(|| Some("09:41".to_owned()));
        state.record_firewall(
            Duration::from_secs(1),
            block("203.0.113.50", 22, Direction::Inbound, Some("10:20")),
        );
        refuse(&mut state, 2, "10.0.1.12");
        state.record_firewall(
            Duration::from_secs(3),
            block("198.51.100.7", 3389, Direction::Inbound, Some("10:21")),
        );
        state
    }

    /// The foreground of the first `word` on the line holding `address`.
    fn kind_colour(
        terminal: &Terminal<TestBackend>,
        address: &str,
        word: &str,
    ) -> Option<ratatui::style::Color> {
        let rows = lines(terminal);
        let (y, _) = at(&rows, address);
        let x = rows[y].find(word).unwrap_or_else(|| {
            panic!("no {word:?} beside {address}:\n{}", rows.join("\n"));
        });
        let x = rows[y][..x].chars().count() as u16;
        terminal.backend().buffer()[(x, y as u16)].style().fg
    }

    fn assert_kinds(terminal: &Terminal<TestBackend>) {
        let theme = Theme::default();
        let blocked = kind_colour(terminal, "203.0.113.50", "blocked");
        let refused = kind_colour(terminal, "10.0.1.12", "refused");
        assert_eq!(blocked, theme.blocked().fg);
        assert_eq!(refused, theme.warning().fg);
        assert_ne!(blocked, refused);
    }

    #[test]
    fn a_block_and_a_refused_attempt_each_show_their_word_and_colour_on_the_overview() {
        let state = mixed();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        assert_kinds(&screen(&state, &mut i, None, 110, 24));
    }

    #[test]
    fn a_block_and_a_refused_attempt_each_show_their_word_and_colour_in_zoom() {
        let state = mixed();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        press(&mut i, &state, KeyCode::Enter);
        assert_kinds(&screen(&state, &mut i, None, 120, 32));
    }

    #[test]
    fn rows_are_ordered_by_time_across_both_kinds() {
        let state = mixed();
        let order = |rows: &[String]| -> Vec<usize> {
            ["198.51.100.7", "10.0.1.12", "203.0.113.50"]
                .map(|a| at(rows, a).0)
                .to_vec()
        };
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        let overview = order(&lines(&screen(&state, &mut i, None, 110, 24)));
        assert!(
            overview[0] < overview[1] && overview[1] < overview[2],
            "{overview:?}"
        );
        press(&mut i, &state, KeyCode::Enter);
        let zoom = order(&lines(&screen(&state, &mut i, None, 120, 32)));
        assert!(zoom[0] < zoom[1] && zoom[1] < zoom[2], "{zoom:?}");
    }

    #[test]
    fn with_names_on_a_refused_row_shows_its_sources_name_as_a_block_does() {
        let state = mixed();
        let dns = blocked_dns(&[
            ("10.0.1.12", "laptop.lan"),
            ("203.0.113.50", "scanner.example.org"),
        ]);
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('5'));
        let overview = text_of(&screen(&state, &mut i, Some(&dns), 160, 50));
        assert!(overview.contains("laptop.lan"), "{overview}");
        assert!(overview.contains("scanner.example.org"), "{overview}");
        assert!(!overview.contains("10.0.1.12"), "{overview}");
        press(&mut i, &state, KeyCode::Enter);
        let zoom = text_of(&screen(&state, &mut i, Some(&dns), 160, 32));
        assert!(
            zoom.contains("laptop.lan") && zoom.contains("10.0.1.12"),
            "{zoom}"
        );
    }

    #[test]
    fn a_search_for_refused_keeps_only_refused_rows() {
        let state = mixed();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "refused");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("10.0.1.12"), "{text}");
        assert!(
            !text.contains("203.0.113.50") && !text.contains("198.51.100.7"),
            "{text}"
        );
    }

    #[test]
    fn firewall_blocks_shows_the_name_on_the_overview_and_name_and_address_in_zoom() {
        let state = sample();
        let dns = blocked_dns(&[("203.0.113.50", "scanner.example.org")]);
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('5'));
        let overview = text_of(&screen(&state, &mut i, Some(&dns), 160, 50));
        assert!(overview.contains("scanner.example.org"), "{overview}");
        assert!(!overview.contains("203.0.113.50"), "{overview}");
        assert!(
            overview.contains("198.51.100.7"),
            "no name keeps the address"
        );
        press(&mut i, &state, KeyCode::Enter);
        let zoom = text_of(&screen(&state, &mut i, Some(&dns), 160, 32));
        assert!(
            zoom.contains("scanner.example.org") && zoom.contains("203.0.113.50"),
            "{zoom}"
        );
    }

    #[test]
    fn firewall_blocks_goes_back_to_addresses_when_n_turns_names_off() {
        let state = sample();
        let dns = blocked_dns(&[("203.0.113.50", "scanner.example.org")]);
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('5'));
        press(&mut i, &state, KeyCode::Char('n'));
        let off = text_of(&screen(&state, &mut i, Some(&dns), 160, 50));
        assert!(
            off.contains("203.0.113.50") && !off.contains("scanner.example.org"),
            "{off}"
        );
    }

    #[test]
    fn a_search_for_part_of_a_blocked_sources_name_keeps_that_row_and_the_selection_moves() {
        let state = sample();
        let dns = blocked_dns(&[
            ("203.0.113.50", "a.scan.example"),
            ("198.51.100.7", "b.scan.example"),
        ]);
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('5'));
        press(&mut i, &state, KeyCode::Enter);
        screen(&state, &mut i, Some(&dns), 160, 32);
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "scan.example");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, Some(&dns), 160, 32));
        assert!(
            text.contains("a.scan.example") && text.contains("b.scan.example"),
            "{text}"
        );
        assert!(!text.contains("192.0.2.200"), "{text}");
        press(&mut i, &state, KeyCode::Char('j'));
        screen(&state, &mut i, Some(&dns), 160, 32);
        assert_eq!(i.selected(), 1);
        // On the overview the address still matches while the name is shown.
        let mut o = Interaction::with_names(true);
        press(&mut o, &state, KeyCode::Char('5'));
        press(&mut o, &state, KeyCode::Char('/'));
        type_text(&mut o, &state, "203.0.113.50");
        press(&mut o, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut o, Some(&dns), 160, 50));
        assert!(
            text.contains("a.scan.example") && !text.contains("b.scan.example"),
            "{text}"
        );
    }

    #[test]
    fn reverse_dns_names_in_blocked_rows_are_stripped_and_bounded() {
        use crosswalk::ui::panes::{blocked_rows, blocked_zoom_rows};
        let hostile = format!("{HOSTILE}.example{}", "n".repeat(100));
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.record_firewall(
            Duration::from_secs(1),
            block("203.0.113.5", 22, Direction::Inbound, None),
        );
        let ip: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let mut dns = ReverseDns::new(true, 8, 8, move |_| Some(hostile.clone()));
        dns.schedule_visible([ip]);
        for _ in 0..200 {
            dns.poll();
            if dns.name(ip).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let rows = blocked_rows(&state, &Theme::default(), "", Some(&dns));
        assert!(rows[0].cells[1].text.starts_with("a[31mbcdef"));
        assert_clean(&rows[0].cells[1].text, Some(48));
        let rows = blocked_zoom_rows(&state, &Theme::default(), "", Some(&dns));
        assert_clean(&rows[0].cells[2].text, Some(48));
        assert_clean(&rows[0].cells[8].text, Some(48));
        assert!(rows[0].cells[8].text.starts_with("a[31mbcdef"));
    }

    #[test]
    fn lookups_are_wanted_only_for_blocked_sources_the_pane_can_show() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        for n in 0..40u8 {
            state.record_firewall(
                Duration::from_secs(u64::from(n)),
                block(&format!("203.0.113.{n}"), 22, Direction::Inbound, None),
            );
        }
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        let overview = i.blocked_sources_to_look_up(&state, 24);
        assert!(
            !overview.is_empty() && overview.len() < 10,
            "{}",
            overview.len()
        );
        let tall = i.blocked_sources_to_look_up(&state, 50).len();
        assert!(tall > overview.len() && tall < 40);
        // The newest rows come first.
        assert_eq!(
            overview[0],
            state.blocked(Direction::Inbound)[0].source.unwrap()
        );
        press(&mut i, &state, KeyCode::Enter);
        let zoom = i.blocked_sources_to_look_up(&state, 24).len();
        assert!(zoom > overview.len() && zoom <= 32);
        // Another pane in zoom shows no Firewall Blocks rows.
        let mut other = Interaction::default();
        press(&mut other, &state, KeyCode::Char('2'));
        press(&mut other, &state, KeyCode::Enter);
        assert!(other.blocked_sources_to_look_up(&state, 32).is_empty());
    }

    #[test]
    fn n_flips_the_names_state_on_the_overview_and_in_zoom() {
        let state = sample();
        let mut i = Interaction::default();
        assert!(!i.names_on());
        press(&mut i, &state, KeyCode::Char('n'));
        assert!(i.names_on());
        press(&mut i, &state, KeyCode::Char('n'));
        assert!(!i.names_on());
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Char('n'));
        assert!(i.names_on());
        press(&mut i, &state, KeyCode::Char('n'));
        assert!(!i.names_on());
    }

    #[test]
    fn started_with_reverse_dns_on_the_names_state_starts_on() {
        assert!(Interaction::with_names(true).names_on());
        assert!(!Interaction::with_names(false).names_on());
    }

    #[test]
    fn n_in_an_open_search_field_is_text_and_with_help_open_does_nothing() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('/'));
        press(&mut i, &state, KeyCode::Char('n'));
        assert_eq!(i.search(Pane::Bandwidth), "n");
        assert!(!i.names_on());
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('?'));
        press(&mut i, &state, KeyCode::Char('n'));
        assert!(!i.names_on());
        assert!(i.help_open());
    }

    #[test]
    fn names_show_while_on_and_addresses_return_when_n_turns_them_off() {
        let state = sample();
        let dns = named_dns();
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('2'));
        let on = text_of(&screen(&state, &mut i, Some(&dns), 160, 50));
        assert!(on.contains("lhr25s34-in-f14") && !on.contains("142.250.80.46"));
        press(&mut i, &state, KeyCode::Char('n'));
        let off = text_of(&screen(&state, &mut i, Some(&dns), 160, 50));
        assert!(off.contains("142.250.80.46") && !off.contains("lhr25s34-in-f14"));
        press(&mut i, &state, KeyCode::Char('n'));
        let again = text_of(&screen(&state, &mut i, Some(&dns), 160, 50));
        assert!(again.contains("lhr25s34-in-f14"));
    }

    #[test]
    fn the_footer_shows_whether_names_are_on_at_110_by_32_on_the_overview_and_in_zoom() {
        let state = sample();
        for zoom in [false, true] {
            let mut i = Interaction::default();
            if zoom {
                press(&mut i, &state, KeyCode::Enter);
            }
            for (expected, other) in [("n names off", "n names on"), ("n names on", "n names off")]
            {
                let rows = lines(&screen(&state, &mut i, None, 110, 32));
                let footer = rows.last().unwrap();
                assert!(
                    footer.contains(expected) && !footer.contains(other),
                    "{footer}"
                );
                assert!(footer.contains("q quit"), "footer cut off: {footer}");
                press(&mut i, &state, KeyCode::Char('n'));
            }
        }
    }

    #[test]
    fn help_lists_the_names_key() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('?'));
        let rows = lines(&screen(&state, &mut i, None, 110, 32));
        assert!(
            rows.iter()
                .any(|l| l.contains(" n ") && l.contains("reverse DNS names")),
            "{}",
            rows.join("\n")
        );
    }

    #[test]
    fn without_reverse_dns_the_overview_shows_addresses() {
        let state = sample();
        let mut i = Interaction::default();
        let text = text_of(&screen(&state, &mut i, None, 160, 50));
        assert!(text.contains("142.250.80.46"));
    }

    #[test]
    fn zoom_uses_the_same_minimum_size_and_message() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 109, 24));
        assert!(text.contains("110x24"), "{text}");
        let text = text_of(&screen(&state, &mut i, None, 110, 23));
        assert!(text.contains("110x24"), "{text}");
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("BANDWIDTH") && !text.contains("110x24"));
    }

    #[test]
    fn tables_keep_one_column_of_padding_inside_the_border() {
        let traffic = lines(&draw_at(&sample(), 110, 24));
        let network = lines(&draw_net(&sample(), 110, 24));
        for header in ["│ APP", "│ IFACE"] {
            assert!(
                traffic.iter().any(|l| l.contains(header)),
                "missing {header:?}:\n{}",
                traffic.join("\n")
            );
        }
        assert!(
            network.iter().any(|l| l.contains("│ LAST SEEN")),
            "missing the LAST SEEN header:\n{}",
            network.join("\n")
        );
        for text in [&traffic, &network] {
            for line in &text[1..23] {
                let chars: Vec<char> = line.chars().collect();
                for (n, c) in chars.iter().enumerate() {
                    if *c == '│' && n > 0 && chars[n - 1].is_alphanumeric() {
                        panic!("content touches a border: {line}");
                    }
                }
            }
        }
    }

    #[test]
    fn at_110_by_24_the_wanted_columns_survive_and_an_ipv4_address_is_whole() {
        let mut state = sample();
        state.record_firewall(
            Duration::from_secs(119),
            block("255.255.255.255", 65535, Direction::Inbound, None),
        );
        let text = lines(&draw_at(&state, 110, 24));
        let network = lines(&draw_net(&state, 110, 24));
        let joined = [text.clone(), network.clone()].concat().join("\n");
        let header = text.iter().find(|l| l.contains("DESTINATION")).unwrap();
        for col in ["APP", "DESTINATION", "PORT", "↓ IN", "↑ OUT"] {
            assert!(header.contains(col), "{col}: {header}");
        }
        let blocked = network.iter().find(|l| l.contains("FROM")).unwrap();
        for col in ["LAST SEEN", "FROM", "PORT", "HITS", "KIND"] {
            assert!(blocked.contains(col), "{col}: {blocked}");
        }
        assert!(joined.contains("255.255.255.255"), "{joined}");
        assert!(joined.contains("65535/tcp"), "{joined}");
        assert!(joined.contains("142.250.80.46"), "{joined}");
    }

    #[test]
    fn at_110_by_24_a_block_and_a_refused_attempt_each_show_every_column_with_a_whole_address() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.set_wall_clock(|| Some("09:41".to_owned()));
        state.record_firewall(
            Duration::from_secs(1),
            block("198.51.100.123", 22, Direction::Inbound, Some("10:20")),
        );
        refuse(&mut state, 2, "203.0.113.200");
        let text = lines(&draw_net(&state, 110, 24));
        let header = text.iter().find(|l| l.contains("FROM")).unwrap();
        for col in ["LAST SEEN", "FROM", "PORT", "HITS", "KIND"] {
            assert!(header.contains(col), "{col}: {header}");
        }
        for (address, kind) in [("198.51.100.123", "blocked"), ("203.0.113.200", "refused")] {
            let row = text
                .iter()
                .find(|l| l.contains(address))
                .unwrap_or_else(|| {
                    panic!("{address} not whole:\n{}", text.join("\n"));
                });
            assert!(row.contains(kind), "{row}");
        }
    }

    #[test]
    fn hidden_rows_are_counted_on_the_bottom_border() {
        let mut state = sample();
        for n in 0..6u64 {
            state.record_firewall(
                Duration::from_secs(120 + n),
                block(&format!("203.0.113.{n}"), 22, Direction::Inbound, None),
            );
        }
        let terminal = draw_net(&state, 110, 24);
        let text = lines(&terminal);
        let line = text
            .iter()
            .find(|l| l.contains("more") && l.trim_end().ends_with('╯'))
            .unwrap_or_else(|| panic!("no +N more on a border:\n{}", text.join("\n")));
        assert!(line.contains("+1 more"), "{line}");
        let (y, x) = at(&text, "+1 more");
        assert_eq!(
            terminal.backend().buffer()[(x as u16, y as u16)].style().fg,
            Some(Theme::default().muted)
        );
    }

    #[test]
    fn before_the_first_rule_snapshot_listening_ports_say_so_in_muted_text() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        state.record_listeners(vec![listener(22, "0.0.0.0", None)], 32_768..=60_999);
        let terminal = draw_at(&state, 110, 32);
        let text = lines(&terminal);
        let joined = text.join("\n");
        assert!(joined.contains("reading firewall rules…"), "{joined}");
        assert!(!joined.contains("Cannot read firewall rules"), "{joined}");
        let (y, x) = at(&text, "reading firewall rules…");
        assert_eq!(
            terminal.backend().buffer()[(x as u16, y as u16)].style().fg,
            Some(Theme::default().muted)
        );
        assert!(!joined.contains("● open") && !joined.contains("· blocked"));
    }

    #[test]
    fn a_rate_of_zero_is_muted_and_a_live_rate_is_not() {
        let mut state = sample();
        state.advance_time(Duration::from_secs(125));
        let terminal = draw_at(&state, 160, 50);
        let text = lines(&terminal);
        let theme = Theme::default();
        let (y, x) = at(&text, "0 B/s");
        assert_eq!(
            terminal.backend().buffer()[(x as u16, y as u16)].style().fg,
            Some(theme.muted)
        );
        let live = draw_at(&sample(), 160, 50);
        let (y, x) = at(&lines(&live), "KB/s");
        assert_ne!(
            live.backend().buffer()[(x as u16, y as u16)].style().fg,
            Some(theme.muted)
        );
    }

    // ---- Neighbors ----

    use crosswalk::collect::neighbors::{Neighbor, NeighborSnapshot};

    fn neighbor(address: &str, mac: Option<&str>, interface: &str, state: &str) -> Neighbor {
        Neighbor {
            address: address.parse().unwrap(),
            mac: mac.map(str::to_owned),
            interface: interface.to_owned(),
            state: state.to_owned(),
        }
    }

    fn with_neighbors(entries: Vec<Neighbor>) -> AppState {
        let mut state = sample();
        state.record_neighbors(NeighborSnapshot::Available(entries));
        state
    }

    fn line_with<'a>(text: &'a str, needle: &str) -> &'a str {
        text.lines()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no line with {needle}: {text}"))
    }

    /// The foreground of the first cell of `needle` on the screen.
    fn fg_of(terminal: &Terminal<TestBackend>, needle: &str) -> Option<ratatui::style::Color> {
        let buffer = terminal.backend().buffer();
        let width = buffer.area.width as usize;
        let flat: Vec<&str> = buffer.content().iter().map(|c| c.symbol()).collect();
        for y in 0..buffer.area.height as usize {
            let row = flat[y * width..(y + 1) * width].concat();
            if let Some(at) = row.find(needle) {
                let x = row[..at].chars().count();
                return buffer[(x as u16, y as u16)].style().fg;
            }
        }
        panic!("no {needle} on the screen")
    }

    // ---- Network Events ----

    const MAC_A: &str = "aa:aa:aa:aa:aa:aa";
    const MAC_B: &str = "bb:bb:bb:bb:bb:bb";

    fn events_state(clock: fn() -> Option<String>) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.set_wall_clock(clock);
        state
    }

    fn at_ten_oh_five() -> Option<String> {
        Some("10:05".to_owned())
    }

    fn neighbours_seen(state: &mut AppState, entries: &[(&str, &str)]) {
        let entries = entries
            .iter()
            .map(|(address, mac)| neighbor(address, Some(mac), "eth0", "reachable"))
            .collect();
        state.record_neighbors(NeighborSnapshot::Available(entries));
    }

    /// A baseline of one neighbour, then a second one and a changed hardware
    /// address for the first.
    fn state_with_events() -> AppState {
        let mut state = events_state(at_ten_oh_five);
        neighbours_seen(&mut state, &[("10.0.1.5", MAC_A)]);
        neighbours_seen(&mut state, &[("10.0.1.5", MAC_A), ("10.0.1.6", MAC_A)]);
        neighbours_seen(&mut state, &[("10.0.1.5", MAC_B), ("10.0.1.6", MAC_A)]);
        assert_eq!(state.events().len(), 2);
        state
    }

    fn events_screen(state: &AppState, width: u16, zoom: bool) -> Terminal<TestBackend> {
        let mut i = Interaction::default();
        press(&mut i, state, KeyCode::Char('6'));
        if zoom {
            press(&mut i, state, KeyCode::Enter);
        }
        screen(state, &mut i, None, width, 24)
    }

    #[test]
    fn events_are_listed_newest_first_with_time_kind_and_text() {
        let state = state_with_events();
        let text = text_of(&events_screen(&state, 110, false));
        let header = line_with(&text, "TIME");
        assert!(
            header.contains("TIME") && header.contains("EVENT"),
            "{header}"
        );
        let changed = line_with(&text, "10.0.1.5 MAC");
        let seen = line_with(&text, "10.0.1.6");
        assert!(
            changed.contains("10:05 neighbour 10.0.1.5 MAC"),
            "{changed}"
        );
        assert!(
            seen.contains("10:05 neighbour new neighbour 10.0.1.6"),
            "{seen}"
        );
        assert!(
            text.find(changed).unwrap() < text.find(seen).unwrap(),
            "{text}"
        );
    }

    #[test]
    fn an_event_without_a_clock_shows_a_dash_for_the_time() {
        let mut state = events_state(|| None);
        neighbours_seen(&mut state, &[("10.0.1.5", MAC_A)]);
        neighbours_seen(&mut state, &[("10.0.1.5", MAC_A), ("10.0.1.6", MAC_A)]);
        let text = text_of(&events_screen(&state, 110, false));
        assert!(
            line_with(&text, "10.0.1.6").contains("—    neighbour new neighbour 10.0.1.6"),
            "{text}"
        );
    }

    #[test]
    fn a_hardware_address_change_is_danger_a_port_opening_warning_and_a_plain_event_neither() {
        let theme = Theme::default();
        let mut state = state_with_events();
        state.record_listeners(
            vec![listener(22, "0.0.0.0", Some("/usr/bin/sshd"))],
            32_768..=60_999,
        );
        let policy = |rules| RuleSnapshot::Active {
            default_incoming: Policy::Deny,
            default_outgoing: Policy::Allow,
            rules,
        };
        state.record_rules(policy(vec![]));
        state.record_rules(policy(vec![rule(
            RuleAction::Allow,
            22,
            RuleSource::Anywhere,
        )]));
        let terminal = events_screen(&state, 110, false);
        let text = text_of(&terminal);
        assert!(text.contains("exposure block"), "{text}");
        assert_eq!(
            fg_of(&terminal, "10.0.1.5 MAC"),
            Some(theme.danger),
            "{text}"
        );
        assert_eq!(
            fg_of(&terminal, "tcp 0.0.0.0:22"),
            Some(theme.warning),
            "{text}"
        );
        for plain in ["10.0.1.6", "rule added"] {
            let fg = fg_of(&terminal, plain);
            assert!(
                fg != Some(theme.danger) && fg != Some(theme.warning),
                "{plain}: {fg:?}"
            );
        }
    }

    #[test]
    fn a_long_text_is_cut_on_the_overview_and_whole_in_zoom() {
        let state = state_with_events();
        let whole = "10.0.1.5 MAC aa:aa:aa:aa:aa:aa -> bb:bb:bb:bb:bb:bb on eth0";
        let text = text_of(&events_screen(&state, 110, false));
        let row = line_with(&text, "10.0.1.5 MAC");
        assert!(!row.contains(whole) && row.contains('…'), "{row}");
        let zoomed = text_of(&events_screen(&state, 110, true));
        assert!(zoomed.contains(whole), "{zoomed}");
    }

    #[test]
    fn a_long_ipv6_hardware_address_change_shows_both_addresses_in_zoom() {
        let v6 = "fd12:3456:789a:bcde:1111:2222:3333:4444";
        let mut state = events_state(at_ten_oh_five);
        let entry = |mac| vec![neighbor(v6, Some(mac), "wlp0s20f3", "reachable")];
        state.record_neighbors(NeighborSnapshot::Available(entry(MAC_A)));
        state.record_neighbors(NeighborSnapshot::Available(entry(MAC_B)));
        let text = text_of(&events_screen(&state, 110, true));
        let whole = format!("{v6} MAC {MAC_A} -> {MAC_B} on");
        assert!(text.contains(&whole), "{text}");
    }

    #[test]
    fn a_search_keeps_the_events_whose_kind_or_text_match() {
        let state = state_with_events();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('6'));
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "MAC");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("10.0.1.5 MAC"), "{text}");
        assert!(!text.contains("10.0.1.6 "), "{text}");
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('6'));
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "neighbour");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            text.contains("10.0.1.5 MAC") && text.contains("10.0.1.6"),
            "{text}"
        );
    }

    /// A Wi-Fi network whose name holds an escape, a zero-width space and a
    /// right-to-left override, logged in an event.
    fn state_with_hostile_event() -> AppState {
        use crosswalk::collect::wifi::{AccessPoint, WifiSnapshot};
        let point = |in_use| AccessPoint {
            ssid: Some("Evil\u{1b}[31m\u{200B}net\u{202E}end".to_owned()),
            bssid: "00:11:22:33:44:55".to_owned(),
            signal: 80,
            channel: 6,
            frequency_mhz: 2437,
            security: "WPA2".to_owned(),
            in_use,
        };
        let mut state = events_state(at_ten_oh_five);
        state.record_wifi(WifiSnapshot::Available(vec![point(false)]));
        state.record_wifi(WifiSnapshot::Available(vec![point(true)]));
        assert_eq!(state.events().len(), 1);
        state
    }

    #[test]
    fn event_text_is_drawn_without_escapes_zero_width_or_overrides() {
        use crosswalk::ui::panes::event_rows;
        let state = state_with_hostile_event();
        let clean = "Wi-Fi connected to Evil[31mnetend (00:11:22:33:44:55)";
        let rows = event_rows(&state, &Theme::default(), "");
        assert_eq!(rows[0].cells[2].text, clean);
        // Searching for the text as drawn finds it.
        assert_eq!(
            event_rows(&state, &Theme::default(), "evil[31mnetend").len(),
            1
        );
        for zoom in [false, true] {
            let text = text_of(&events_screen(&state, 200, zoom));
            assert!(text.contains(clean), "zoom {zoom}: {text}");
        }
    }

    #[test]
    fn j_moves_the_selection_down_the_events() {
        let theme = Theme::default();
        let state = state_with_events();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('6'));
        press(&mut i, &state, KeyCode::Enter);
        let selected = |terminal: &Terminal<TestBackend>, needle: &str| {
            let buffer = terminal.backend().buffer();
            let width = buffer.area.width as usize;
            let flat: Vec<&str> = buffer.content().iter().map(|c| c.symbol()).collect();
            (0..buffer.area.height as usize).any(|y| {
                let row = flat[y * width..(y + 1) * width].concat();
                row.find(needle).is_some_and(|at| {
                    buffer[(row[..at].chars().count() as u16, y as u16)]
                        .style()
                        .bg
                        == Some(theme.muted)
                })
            })
        };
        let first = screen(&state, &mut i, None, 110, 24);
        assert!(selected(&first, "10.0.1.5 MAC") && !selected(&first, "10.0.1.6"));
        press(&mut i, &state, KeyCode::Char('j'));
        let second = screen(&state, &mut i, None, 110, 24);
        assert!(selected(&second, "10.0.1.6") && !selected(&second, "10.0.1.5 MAC"));
    }

    #[test]
    fn events_recorded_while_traffic_is_shown_are_in_the_pane_after_6() {
        let mut state = events_state(at_ten_oh_five);
        neighbours_seen(&mut state, &[("10.0.1.5", MAC_A)]);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        neighbours_seen(&mut state, &[("10.0.1.5", MAC_A), ("10.0.1.7", MAC_B)]);
        screen(&state, &mut i, None, 110, 24);
        press(&mut i, &state, KeyCode::Char('6'));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("neighbour new neighbour 10.0.1.7"), "{text}");
    }

    #[test]
    fn neighbors_overview_has_no_state_column_and_the_name_whole_when_it_fits_else_cut() {
        let state = with_neighbors(vec![neighbor(
            "192.168.100.200",
            Some("aa:bb:cc:dd:ee:01"),
            "eth0",
            "reachable",
        )]);
        let dns = blocked_dns(&[("192.168.100.200", "gateway.home.example.net")]);
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('8'));
        // At the minimum the pane is half the screen: the 24-character name
        // is cut to what is left after the address and the hardware address.
        let narrow = text_of(&screen(&state, &mut i, Some(&dns), 110, 24));
        let row = line_with(&narrow, "192.168.100.200");
        assert!(
            row.contains("192.168.100.200 gateway.home.exa… aa:bb:cc:dd:ee:01"),
            "{row}"
        );
        let text = text_of(&screen(&state, &mut i, Some(&dns), 160, 24));
        let header = line_with(&text, "ADDRESS");
        let at = |word: &str| {
            header
                .find(word)
                .unwrap_or_else(|| panic!("{word}: {header}"))
        };
        assert!(at("ADDRESS") < at("NAME") && at("NAME") < at("MAC"));
        assert!(
            !header.contains("STATE") && !header.contains("INTERFACE"),
            "{header}"
        );
        let row = line_with(&text, "192.168.100.200");
        assert!(
            row.contains("192.168.100.200 ")
                && row.contains(" gateway.home.example.net aa:bb:cc:dd:ee:01")
                && !row.contains("reachable"),
            "{row}"
        );
    }

    #[test]
    fn an_ipv6_neighbor_is_cut_on_the_overview_without_costing_the_name_and_whole_in_zoom() {
        let state = with_neighbors(vec![
            neighbor(
                "192.168.100.200",
                Some("aa:bb:cc:dd:ee:01"),
                "eth0",
                "reachable",
            ),
            neighbor(
                "fe80::a1:b2c3:d4e5:f607",
                Some("aa:bb:cc:dd:ee:02"),
                "enp3s0",
                "stale",
            ),
        ]);
        let dns = blocked_dns(&[("192.168.100.200", "gateway.home.example.net")]);
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('8'));
        let text = text_of(&screen(&state, &mut i, Some(&dns), 160, 24));
        let row = line_with(&text, "192.168.100.200");
        assert!(
            row.contains("192.168.100.200 ")
                && row.contains(" gateway.home.example.net aa:bb:cc:dd:ee:01"),
            "{row}"
        );
        // At 160 wide the names leave the address room: it is whole.
        let v6 = line_with(&text, "fe80::");
        assert!(v6.contains("fe80::a1:b2c3:d4e5:f607 "), "{v6}");
        // At 110 it is cut, and the cut does not move the name or the
        // hardware address: they start where they do on the IPv4 row.
        let text = text_of(&screen(&state, &mut i, Some(&dns), 110, 24));
        let v4 = line_with(&text, "192.168.100.200");
        let v6 = line_with(&text, "fe80::");
        assert!(
            v6.contains("fe80::a1:b2c3:… ") && !v6.contains("f607"),
            "{v6}"
        );
        assert_eq!(v4.find("aa:bb:cc:dd:ee:01"), v6.find("aa:bb:cc:dd:ee:02"));
        press(&mut i, &state, KeyCode::Char('8'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, Some(&dns), 110, 32));
        let header = line_with(&text, "ADDRESS");
        let at = |word: &str| header.find(word).unwrap();
        assert!(
            at("NAME") < at("MAC") && at("MAC") < at("STATE") && at("STATE") < at("INTERFACE"),
            "{header}"
        );
        let v6 = line_with(&text, "fe80::");
        assert!(
            v6.contains("fe80::a1:b2c3:d4e5:f607") && v6.contains("enp3s0") && v6.contains("stale"),
            "{v6}"
        );
    }

    #[test]
    fn a_neighbor_in_trouble_has_its_whole_row_in_the_warning_colour() {
        let theme = Theme::default();
        let state = with_neighbors(vec![
            neighbor("10.0.1.1", Some("aa:bb:cc:dd:ee:01"), "eth0", "failed"),
            neighbor("10.0.1.2", Some("aa:bb:cc:dd:ee:02"), "eth0", "reachable"),
            neighbor("10.0.1.3", Some("aa:bb:cc:dd:ee:03"), "eth0", "incomplete"),
            neighbor("10.0.1.4", Some("aa:bb:cc:dd:ee:04"), "eth0", "stale"),
            neighbor("10.0.1.5", Some("aa:bb:cc:dd:ee:05"), "eth0", "delay"),
            neighbor("10.0.1.6", Some("aa:bb:cc:dd:ee:06"), "eth0", "probe"),
            neighbor("10.0.1.7", Some("aa:bb:cc:dd:ee:07"), "eth0", "permanent"),
        ]);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('8'));
        for zoomed in [false, true] {
            if zoomed {
                press(&mut i, &state, KeyCode::Enter);
            }
            let term = screen(&state, &mut i, None, 110, 24);
            // The overview has room for all seven rows, as zoom does.
            for n in 1..=7 {
                let warned = matches!(n, 1 | 3);
                for cell in [format!("10.0.1.{n} "), format!("aa:bb:cc:dd:ee:0{n}")] {
                    assert_eq!(
                        fg_of(&term, &cell) == Some(theme.warning),
                        warned,
                        "{cell} zoomed={zoomed}"
                    );
                }
            }
            if zoomed {
                for (word, warned) in [
                    ("failed", true),
                    ("incomplete", true),
                    ("reachable", false),
                    ("stale", false),
                    ("delay", false),
                    ("probe", false),
                ] {
                    assert_eq!(fg_of(&term, word) == Some(theme.warning), warned, "{word}");
                }
            }
        }
    }

    #[test]
    fn zoom_shows_the_state_word_of_each_neighbor_and_the_selection_reads_on_a_warning_row() {
        let theme = Theme::default();
        let state = with_neighbors(vec![
            neighbor("10.0.1.1", Some("aa:bb:cc:dd:ee:01"), "eth0", "failed"),
            neighbor("10.0.1.2", Some("aa:bb:cc:dd:ee:02"), "eth0", "reachable"),
        ]);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('8'));
        press(&mut i, &state, KeyCode::Enter);
        let term = screen(&state, &mut i, None, 110, 32);
        let text = text_of(&term);
        assert!(line_with(&text, "10.0.1.1 ").contains("failed"), "{text}");
        assert!(
            line_with(&text, "10.0.1.2 ").contains("reachable"),
            "{text}"
        );
        // The first row is selected: its background is the selection's and
        // its text is still the warning colour.
        let buffer = term.backend().buffer();
        let y = text.lines().position(|l| l.contains("10.0.1.1 ")).unwrap();
        let x = text.lines().nth(y).unwrap().find("10.0.1.1").unwrap();
        let cell = buffer[(x as u16, y as u16)].style();
        assert_eq!(cell.bg, theme.selection().bg);
        assert_eq!(cell.fg, Some(theme.warning));
        assert_ne!(Some(theme.warning), theme.selection().bg);
    }

    #[test]
    fn neighbors_show_a_resolved_name_cut_to_fit_and_n_removes_names() {
        let state = with_neighbors(vec![
            neighbor(
                "192.168.100.200",
                Some("aa:bb:cc:dd:ee:ff"),
                "eth0",
                "incomplete",
            ),
            neighbor(
                "192.168.100.201",
                Some("aa:bb:cc:dd:ee:fe"),
                "eth0",
                "stale",
            ),
        ]);
        let dns = blocked_dns(&[("192.168.100.200", "gateway.home.example.net")]);
        let mut i = Interaction::with_names(true);
        press(&mut i, &state, KeyCode::Char('8'));
        let text = text_of(&screen(&state, &mut i, Some(&dns), 110, 24));
        let row = line_with(&text, "192.168.100.200");
        assert!(
            row.contains("192.168.100.200 gateway.home.exa… aa:bb:cc:dd:ee:ff"),
            "{row}"
        );
        let wide = text_of(&screen(&state, &mut i, Some(&dns), 160, 24));
        let row = line_with(&wide, "192.168.100.200");
        assert!(
            row.contains("192.168.100.200 ")
                && row.contains(" gateway.home.example.net aa:bb:cc:dd:ee:ff"),
            "{row}"
        );
        let other = line_with(&text, "192.168.100.201");
        assert!(
            other.contains("192.168.100.201 ") && !other.contains("gateway"),
            "{other}"
        );
        press(&mut i, &state, KeyCode::Char('n'));
        let text = text_of(&screen(&state, &mut i, Some(&dns), 110, 24));
        assert!(!text.contains("gateway"), "{text}");
    }

    const V6_23: &str = "fe80::a1:b2c3:d4e5:f607";
    const V6_25: &str = "2001:db8:85a3::8a2e:37:73";

    fn two_neighbors(v6: &str) -> AppState {
        with_neighbors(vec![
            neighbor(
                "192.168.100.200",
                Some("aa:bb:cc:dd:ee:01"),
                "eth0",
                "reachable",
            ),
            neighbor(v6, Some("aa:bb:cc:dd:ee:02"), "eth0", "stale"),
        ])
    }

    fn neighbors_text(state: &AppState, names: &[(&str, &str)], w: u16, h: u16) -> String {
        let mut i = Interaction::with_names(!names.is_empty());
        press(&mut i, state, KeyCode::Char('8'));
        let dns = (!names.is_empty()).then(|| blocked_dns(names));
        text_of(&screen(state, &mut i, dns.as_ref(), w, h))
    }

    #[test]
    fn neighbors_with_names_off_show_a_whole_ipv6_address_and_the_hardware_address_at_the_edge() {
        assert_eq!(V6_25.len(), 25);
        let state = two_neighbors(V6_25);
        for (w, h) in [(110, 24), (160, 50)] {
            let text = neighbors_text(&state, &[], w, h);
            let header = line_with(&text, "ADDRESS");
            assert!(
                !header.contains("NAME") && header.contains("MAC"),
                "{header}"
            );
            let v6 = line_with(&text, "2001:db8");
            assert!(
                v6.contains(V6_25) && v6.contains("aa:bb:cc:dd:ee:02 │"),
                "{v6}"
            );
            let v4 = line_with(&text, "192.168.100.200");
            assert!(v4.contains("aa:bb:cc:dd:ee:01 │"), "{v4}");
            assert!(header.contains("MAC               │"), "{header}");
        }
        // 51 cells: the address takes 51 - 17 - 1 = 33, then the hardware address.
        let text = neighbors_text(&state, &[], 110, 24);
        assert!(line_with(&text, "2001:db8").contains(&format!("{V6_25:<33} aa:bb:cc:dd:ee:02")));
    }

    #[test]
    fn a_17_character_name_is_whole_and_the_ipv6_address_is_cut_but_an_ipv4_one_never_is() {
        let state = two_neighbors(V6_23);
        let name = "nas.home.example1";
        assert_eq!(name.len(), 17);
        let text = neighbors_text(&state, &[("192.168.100.200", name), (V6_23, name)], 110, 24);
        let v6 = line_with(&text, "fe80::");
        assert!(
            v6.contains(&format!("fe80::a1:b2c3:… {name} aa:bb:cc:dd:ee:02 │")),
            "{v6}"
        );
        let v4 = line_with(&text, "192.168.100.200");
        assert!(
            v4.contains(&format!("192.168.100.200 {name} aa:bb:cc:dd:ee:01 │")),
            "{v4}"
        );
    }

    #[test]
    fn names_of_eight_characters_leave_the_ipv6_address_whole() {
        let state = two_neighbors(V6_23);
        let names = [("192.168.100.200", "gateway1"), (V6_23, "printer1")];
        let text = neighbors_text(&state, &names, 110, 24);
        let v6 = line_with(&text, "fe80::");
        // ADDRESS is 51 - 17 - 8 - 2 = 24 cells.
        assert!(
            v6.contains(&format!("{V6_23:<24} printer1 aa:bb:cc:dd:ee:02 │")),
            "{v6}"
        );
        let wide = neighbors_text(&state, &names, 160, 50);
        assert!(line_with(&wide, "fe80::").contains(V6_23));
    }

    #[test]
    fn neighbors_zoom_without_names_has_no_name_column_and_ends_at_the_edge() {
        let state = two_neighbors(V6_25);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('8'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let header = line_with(&text, "ADDRESS");
        assert!(
            !header.contains("NAME") && header.contains("INTERFACE │"),
            "{header}"
        );
        let v6 = line_with(&text, "2001:db8");
        assert!(
            v6.contains(V6_25) && v6.contains("stale     eth0      │"),
            "{v6}"
        );
    }

    // ---- Column layout on the other panes ----

    /// The character column of `needle` in `row`.
    fn col(row: &str, needle: &str) -> usize {
        let at = row
            .find(needle)
            .unwrap_or_else(|| panic!("no {needle} in {row}"));
        row[..at].chars().count()
    }

    fn bare() -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        state
    }

    fn names_screen(state: &AppState, dns: &ReverseDns, keys: &[char], w: u16, h: u16) -> String {
        let mut i = Interaction::with_names(true);
        for k in keys {
            press(&mut i, state, KeyCode::Char(*k));
        }
        text_of(&screen(state, &mut i, Some(dns), w, h))
    }

    #[test]
    fn app_traffic_shows_a_42_character_destination_whole_and_the_columns_after_it_at_the_edge() {
        let long = format!("{}.example.com", "d".repeat(30));
        assert_eq!(long.len(), 42);
        let mut state = bare();
        let curl = process("/usr/bin/curl", 5);
        packet(
            &mut state,
            1,
            Some(&curl),
            "203.0.113.9",
            443,
            Direction::Outbound,
            5_000,
        );
        packet(
            &mut state,
            1,
            Some(&curl),
            "203.0.113.10",
            443,
            Direction::Outbound,
            1_000,
        );
        state.advance_time(Duration::from_secs(2));
        let dns = blocked_dns(&[("203.0.113.9", &long), ("203.0.113.10", "short.example")]);
        let text = names_screen(&state, &dns, &['2'], 110, 24);
        let header = line_with(&text, "DESTINATION");
        let long_row = line_with(&text, &long);
        let short_row = line_with(&text, "short.example");
        assert!(header.ends_with("TOTAL │"), "{header}");
        for row in [long_row, short_row] {
            assert!(row.ends_with("B │") && row.contains("443/tcp"), "{row}");
            // PORT and the rates start in the same cells whatever the name.
            assert_eq!(col(row, "443/tcp"), col(header, "PORT"), "{row}");
            assert_eq!(col(row, "B/s"), col(long_row, "B/s"));
        }
        // The gap after a short name is the price of flush-right.
        assert!(short_row.contains("short.example  "), "{short_row}");
    }

    #[test]
    fn listening_ports_cuts_a_40_character_app_and_keeps_the_columns_after_it_whole_at_its_edge() {
        let app = "a".repeat(40);
        let mut state = bare();
        state.record_listeners(
            vec![
                listener(22, "0.0.0.0", Some(&format!("/usr/bin/{app}"))),
                listener(631, "127.0.0.1", Some("/usr/bin/cupsd")),
            ],
            32_768..=60_999,
        );
        let text = text_of(&screen(&state, &mut Interaction::default(), None, 110, 24));
        // Listening Ports is the left half of the bottom row, 55 cells.
        let half = |line: &str| -> String { line.chars().take(55).collect() };
        let header = half(line_with(&text, "BIND"));
        let row = half(line_with(&text, "aaaa"));
        let other = half(line_with(&text, "cupsd"));
        assert!(
            header.contains("PORT") && header.contains("APP"),
            "{header}"
        );
        assert!(header.ends_with("FIREWALL │"), "{header}");
        // The 40 characters do not fit beside the other columns: cut, not wrapped.
        assert!(row.contains('…') && !row.contains(&app), "{row}");
        assert!(row.ends_with(" │") && other.ends_with(" │"));
        assert_eq!(end(&row, "0.0.0.0"), end(&header, "BIND"));
        assert_eq!(end(&other, "127.0.0.1"), end(&header, "BIND"));
    }

    #[test]
    fn firewall_blocks_give_the_source_name_all_the_room_the_other_columns_leave() {
        // 51 cells less LAST SEEN 9, PORT 8, HITS 4, KIND 7 and four gaps is 19.
        let whole = format!("{}.example.org", "b".repeat(7));
        assert_eq!(whole.len(), 19);
        let cut = format!("{}.example.org", "c".repeat(8));
        let mut state = bare();
        for (ip, port) in [("203.0.113.50", 3389), ("198.51.100.7", 22)] {
            for _ in 0..120 {
                state.record_firewall(
                    Duration::from_secs(1),
                    block(ip, port, Direction::Inbound, Some("Oct  8 10:20:00")),
                );
            }
        }
        let dns = blocked_dns(&[("203.0.113.50", &whole), ("198.51.100.7", &cut)]);
        let text = names_screen(&state, &dns, &['5'], 110, 24);
        let header = line_with(&text, "KIND");
        let a = line_with(&text, "3389/tcp");
        let b = line_with(&text, "22/tcp");
        assert!(a.contains(&format!("{whole} 3389/tcp")), "{a}");
        assert!(b.contains("cccccccc.example.o…") || b.contains('…'), "{b}");
        for row in [a, b] {
            assert!(row.contains("×120 blocked │"), "{row}");
            assert_eq!(col(row, "×120") + 4, col(header, "HITS") + 4);
            assert_eq!(col(row, "blocked"), col(header, "KIND"));
        }
    }

    #[test]
    fn firewall_rules_show_whole_networks_and_remotes_at_the_right_edge() {
        let net20 = "2001:db8:1234::/48ab";
        assert_eq!(net20.len(), 20);
        let mut a = rule(
            RuleAction::Deny,
            5432,
            RuleSource::Specific("10.1.2.0/24".into()),
        );
        a.interface = Some("eth0".into());
        let mut b = rule(RuleAction::Allow, 22, RuleSource::Specific(net20.into()));
        b.interface = Some("wlan0".into());
        let state = with_rules(vec![a, b]);
        // At 110 by 24 a 20-cell network has no room even with APP squeezed to
        // its least: it is cut with an ellipsis, still ending at the pane's
        // edge. Whole at 160.
        let narrow = lines(&draw_at(&state, 110, 24)).join("\n");
        let cut = line_with(&narrow, "2001:db8:1234::/4");
        assert!(
            cut.contains("2001:db8:1234::/4") && cut.contains("… │"),
            "{cut}"
        );
        let text = lines(&draw_at(&state, 160, 50)).join("\n");
        let header = line_with(&text, "REMOTE");
        assert!(header.contains("REMOTE │"), "{header}");
        let r1 = line_with(&text, "10.1.2.0/24");
        let r2 = line_with(&text, net20);
        assert!(
            r1.contains("10.1.2.0/24 │") && r2.contains(&format!("{net20} │")),
            "{r1}\n{r2}"
        );
        assert_eq!(col(r1, "eth0"), col(header, "IFACE"));
        assert_eq!(col(r2, "wlan0"), col(header, "IFACE"));
    }

    /// A rule bound to wlan0 and one bound to no interface, with remotes
    /// that name their rows.
    fn two_interface_rules() -> AppState {
        let mut a = rule(
            RuleAction::Deny,
            22,
            RuleSource::Specific("10.0.1.0/24".into()),
        );
        a.protocol = Some(Protocol::Tcp);
        a.interface = Some("wlan0".into());
        a.text = "ZZ first text".into();
        let mut b = rule(
            RuleAction::Limit,
            2001,
            RuleSource::Specific("10.0.2.0/24".into()),
        );
        b.text = "ZZ second text".into();
        with_rules(paired(vec![a, b]))
    }

    /// A screen line from `from` on, in characters.
    fn tail(line: &str, from: usize) -> String {
        line.chars().skip(from).collect()
    }

    fn end(row: &str, needle: &str) -> usize {
        col(row, needle) + needle.chars().count()
    }

    #[test]
    fn rules_overview_orders_and_aligns_the_columns() {
        let text = lines(&draw_at(&two_interface_rules(), 110, 24)).join("\n");
        let header = tail(line_with(&text, "REMOTE"), 55);
        let r1 = tail(line_with(&text, "10.0.1.0/24"), 55);
        let r2 = tail(line_with(&text, "10.0.2.0/24"), 55);
        let order = ["IFACE", "APP", "DIR", "ACTION", "PORT", "REMOTE"];
        for pair in order.windows(2) {
            assert!(col(&header, pair[0]) < col(&header, pair[1]), "{header}");
        }
        assert!(col(&r1, "wlan0") == col(&header, "IFACE"), "{r1}");
        assert!(col(&r2, "all") == col(&header, "IFACE"), "{r2}");
        assert_eq!(col(&r1, " in ") + 1, col(&header, "DIR"), "{r1}");
        assert_eq!(col(&r2, " in ") + 1, col(&header, "DIR"), "{r2}");
        assert_eq!(end(&r1, "deny"), end(&header, "ACTION"), "{r1}");
        assert_eq!(end(&r2, "limit"), end(&header, "ACTION"), "{r2}");
        assert_eq!(end(&r1, "22/tcp"), end(&header, "PORT"), "{r1}");
        assert_eq!(end(&r2, "2001"), end(&header, "PORT"), "{r2}");
        let edge = header.chars().count() - 1;
        for row in [&header, &r1, &r2] {
            assert_eq!(row.chars().last(), Some('│'), "{row}");
        }
        assert_eq!(end(&header, "REMOTE") + 1, edge, "{header}");
        assert_eq!(end(&r1, "10.0.1.0/24") + 1, edge, "{r1}");
        assert_eq!(end(&r2, "10.0.2.0/24") + 1, edge, "{r2}");
    }

    #[test]
    fn rules_leave_three_blank_cells_before_port_and_before_remote() {
        let state = two_interface_rules();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('4'));
        press(&mut i, &state, KeyCode::Enter);
        let zoom = text_of(&screen(&state, &mut i, None, 110, 24));
        let overview = lines(&draw_at(&state, 110, 24)).join("\n");
        for (text, zoomed) in [(overview, false), (zoom, true)] {
            let from = if zoomed { 0 } else { 55 };
            let header = tail(line_with(&text, "REMOTE"), from);
            let r1 = tail(line_with(&text, "10.0.1.0/24"), from);
            let (header, r1) = (header.as_str(), r1.as_str());
            // 22/tcp is PORT's widest value and 10.0.1.0/24 REMOTE's.
            assert!(
                col(r1, "22/tcp") >= end(header, "ACTION") + 3,
                "{zoomed} {r1}"
            );
            assert!(
                col(r1, "10.0.1.0/24") >= end(r1, "22/tcp") + 3,
                "{zoomed} {r1}"
            );
            assert!(
                col(header, "PORT") >= end(header, "ACTION") + 3,
                "{zoomed} {header}"
            );
            assert!(
                col(header, "REMOTE") >= end(header, "PORT") + 3,
                "{zoomed} {header}"
            );
            assert_eq!(
                col(header, "ACTION"),
                end(header, if zoomed { "DIRECTION" } else { "DIR" }) + 1,
                "{zoomed} {header}"
            );
            if !zoomed {
                let edge = header.chars().count() - 1;
                assert_eq!(end(header, "REMOTE") + 1, edge, "{header}");
                assert_eq!(end(r1, "10.0.1.0/24") + 1, edge, "{r1}");
            }
        }
    }

    #[test]
    fn rules_overview_packs_dir_action_port_and_remote_at_the_right() {
        let text = lines(&draw_at(&two_interface_rules(), 110, 24)).join("\n");
        let header = tail(line_with(&text, "REMOTE"), 55);
        let edge = header.chars().count() - 1;
        // One blank cell from DIR to ACTION, three before PORT and REMOTE.
        assert!(
            header.ends_with("DIR ACTION     PORT        REMOTE │"),
            "{header}"
        );
        let r1 = tail(line_with(&text, "10.0.1.0/24"), 55);
        let r2 = tail(line_with(&text, "10.0.2.0/24"), 55);
        assert!(r1.ends_with("in    deny   22/tcp   10.0.1.0/24 │"), "{r1}");
        assert!(r2.ends_with("in   limit     2001   10.0.2.0/24 │"), "{r2}");
        assert_eq!(end(&header, "REMOTE") + 1, edge, "{header}");
        // The spare room lies between APP and DIR.
        assert!(col(&header, "DIR") > end(&header, "APP") + 5, "{header}");
    }

    #[test]
    fn rules_overview_puts_app_one_blank_cell_after_the_iface_column() {
        let text = lines(&draw_at(&two_interface_rules(), 110, 24)).join("\n");
        let header = tail(line_with(&text, "REMOTE"), 55);
        let r1 = tail(line_with(&text, "10.0.1.0/24"), 55);
        // wlan0 is IFACE's widest cell: APP starts one blank cell after it.
        assert_eq!(col(&header, "APP"), end(&r1, "wlan0") + 1, "{header}\n{r1}");
        // The spare room follows APP, and the right-hand columns stay packed.
        assert!(col(&header, "DIR") > end(&header, "APP") + 5, "{header}");
        assert!(
            header.ends_with("DIR ACTION     PORT        REMOTE │"),
            "{header}"
        );
    }

    #[test]
    fn rules_zoom_header_keeps_its_positions() {
        let state = two_interface_rules();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('4'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let header = line_with(&text, "REMOTE");
        let at: Vec<usize> = [
            "INTERFACE",
            "APP",
            "DIRECTION",
            "ACTION",
            "PORT",
            "REMOTE",
            "RULE",
        ]
        .iter()
        .map(|t| col(header, t))
        .collect();
        assert_eq!(at, [2, 12, 17, 27, 38, 50, 57], "{header}");
    }

    #[test]
    fn searching_all_keeps_the_rule_bound_to_no_interface() {
        let state = two_interface_rules();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('4'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "all");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("10.0.2.0/24"), "{text}");
        assert!(!text.contains("10.0.1.0/24"), "{text}");
    }

    // ---- Firewall Rules: the APP column ----

    /// `sample()`'s listeners: sshd on 22/tcp, cupsd on 631, python3 on
    /// 8080, syncthing on 22000 and a process-less 5353; nothing on 2001.
    #[test]
    fn rules_app_shows_the_listener_or_a_dash_under_app_after_iface() {
        let text = lines(&draw_at(&two_interface_rules(), 110, 24)).join("\n");
        let header = tail(line_with(&text, "REMOTE"), 55);
        let r1 = tail(line_with(&text, "10.0.1.0/24"), 55);
        let r2 = tail(line_with(&text, "10.0.2.0/24"), 55);
        let (header, r1, r2) = (header.as_str(), r1.as_str(), r2.as_str());
        let order = ["IFACE", "APP", "DIR", "ACTION", "PORT", "REMOTE"];
        for pair in order.windows(2) {
            assert!(col(header, pair[0]) < col(header, pair[1]), "{header}");
        }
        assert_eq!(col(r1, "sshd"), col(header, "APP"), "{r1}");
        assert_eq!(col(r2, "—"), col(header, "APP"), "{r2}");
        assert!(!r2.contains("sshd"), "{r2}");
    }

    #[test]
    fn rules_app_shows_a_long_name_whole_while_the_room_allows() {
        let state_with = |name: &str, source: RuleSource| {
            let mut state = sample();
            state.record_listeners(
                vec![listener(9000, "0.0.0.0", Some(&format!("/usr/bin/{name}")))],
                32_768..=60_999,
            );
            let mut r = rule(RuleAction::Allow, 9000, source);
            r.text = "ZZ long app".into();
            record(&mut state, Policy::Deny, Policy::Allow, paired(vec![r]));
            state
        };
        let any = state_with("deskflow-core", RuleSource::Anywhere);
        let row = lines(&draw_at(&any, 110, 24)).join("\n");
        assert!(
            line_with(&row, "anywhere").contains("deskflow-core"),
            "{row}"
        );
        let long = "twentycharacterprogr";
        assert_eq!(long.chars().count(), 20);
        let state = state_with(long, RuleSource::Specific("10.0.1.0/24".into()));
        let wide = lines(&draw_at(&state, 160, 24)).join("\n");
        assert!(line_with(&wide, "10.0.1.0/24").contains(long), "{wide}");
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('4'));
        press(&mut i, &state, KeyCode::Enter);
        let zoom = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(line_with(&zoom, "ZZ long app").contains(long), "{zoom}");
    }

    #[test]
    fn rules_app_is_empty_for_outbound_and_any_port_rules_and_dash_for_other_misses() {
        let mut out = out_rule(RuleAction::Allow, 22, "192.0.2.9");
        out.protocol = Some(Protocol::Tcp);
        let mut any = rule(RuleAction::Allow, 22, RuleSource::Anywhere);
        any.ports.clear();
        let mut udp = rule(RuleAction::Deny, 22, RuleSource::Anywhere);
        udp.protocol = Some(Protocol::Udp);
        let mut anon = rule(RuleAction::Deny, 5353, RuleSource::Anywhere);
        anon.protocol = Some(Protocol::Tcp);
        let both = rule(RuleAction::Limit, 631, RuleSource::Anywhere);
        let pane = rules_at(
            &with_rules(paired(vec![out, any, udp, anon, both])),
            160,
            50,
        );
        assert_eq!(
            pane[2..7],
            [
                "all out allow 22/tcp 192.0.2.9",
                "all in allow any anywhere",
                "all — in deny 22/udp anywhere",
                "all — in deny 5353/tcp anywhere",
                "all cupsd in limit 631 anywhere",
            ],
            "{pane:?}"
        );
    }

    #[test]
    fn rules_app_names_the_first_program_on_a_range_and_counts_the_others() {
        let mut state = sample();
        state.record_listeners(
            vec![
                listener(5009, "0.0.0.0", Some("/usr/bin/beta")),
                listener(5001, "0.0.0.0", Some("/usr/bin/alpha")),
                listener(5003, "0.0.0.0", Some("/usr/bin/alpha")),
                listener(5004, "0.0.0.0", Some("/usr/bin/gamma")),
                listener(6000, "0.0.0.0", Some("/usr/bin/delta")),
            ],
            32_768..=60_999,
        );
        let mut range = rule(RuleAction::Allow, 5000, RuleSource::Anywhere);
        range.ports = std::iter::once(5000..=5010).collect();
        let pair = rule(RuleAction::Allow, 5009, RuleSource::Anywhere);
        let mut one = rule(RuleAction::Deny, 6000, RuleSource::Anywhere);
        one.ports = vec![5009..=5009, 6000..=6000];
        record(
            &mut state,
            Policy::Deny,
            Policy::Allow,
            paired(vec![range, pair, one]),
        );
        let pane = rules_at(&state, 160, 50);
        assert_eq!(
            pane[2..5],
            [
                "all alpha +2 in allow 5000-5010 anywhere",
                "all beta in allow 5009 anywhere",
                "all beta +1 in deny 5009,6000 anywhere",
            ],
            "{pane:?}"
        );
    }

    #[test]
    fn searching_a_program_name_keeps_the_rule_it_is_listening_under() {
        let state = two_interface_rules();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('4'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "sshd");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("10.0.1.0/24"), "{text}");
        assert!(!text.contains("10.0.2.0/24"), "{text}");
    }

    #[test]
    fn rules_zoom_puts_app_after_iface_and_before_dir() {
        let state = two_interface_rules();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('4'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let header = line_with(&text, "REMOTE");
        let r1 = line_with(&text, "ZZ first text");
        let order = [
            "INTERFACE",
            "APP",
            "DIRECTION",
            "ACTION",
            "PORT",
            "REMOTE",
            "RULE",
        ];
        for pair in order.windows(2) {
            assert!(col(header, pair[0]) < col(header, pair[1]), "{header}");
        }
        assert_eq!(col(r1, "sshd"), col(header, "APP"), "{r1}");
        assert_eq!(
            text.matches("sshd").count(),
            1,
            "one APP cell for the merged pair: {text}"
        );
    }

    #[test]
    fn narrowing_firewall_rules_drops_app_before_iface() {
        use crosswalk::ui::{
            panes::{rule_columns, rule_rows},
            table::Table,
        };
        let state = two_interface_rules();
        let theme = Theme::default();
        let columns = rule_columns();
        let rows = rule_rows(&state, &theme, "");
        let header_at = |width: u16| -> String {
            let mut terminal = Terminal::new(TestBackend::new(width, 3)).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    Table::new(&columns, &rows, &theme).render(frame.buffer_mut(), area);
                })
                .unwrap();
            lines(&terminal)[0].clone()
        };
        let all = ["IFACE", "APP", "DIR", "ACTION", "PORT", "REMOTE"];
        assert!(all.iter().all(|c| header_at(110).contains(c)));
        let width = (20..110)
            .rev()
            .find(|w| !header_at(*w).contains("APP"))
            .expect("APP goes at some width");
        let header = header_at(width);
        for column in all.into_iter().filter(|c| *c != "APP") {
            assert!(header.contains(column), "{column}: {header}");
        }
        assert!(header_at(width + 1).contains("APP"));
    }

    #[test]
    fn rules_zoom_orders_and_aligns_the_columns_and_ends_with_rule() {
        let state = two_interface_rules();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('4'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let header = line_with(&text, "REMOTE");
        let r1 = line_with(&text, "ZZ first text");
        let r2 = line_with(&text, "ZZ second text");
        let order = [
            "INTERFACE",
            "APP",
            "DIRECTION",
            "ACTION",
            "PORT",
            "REMOTE",
            "RULE",
        ];
        for pair in order.windows(2) {
            assert!(col(header, pair[0]) < col(header, pair[1]), "{header}");
        }
        assert_eq!(col(r1, "wlan0"), col(header, "INTERFACE"), "{r1}");
        assert_eq!(col(r2, "all"), col(header, "INTERFACE"), "{r2}");
        assert_eq!(col(r1, " in ") + 1, col(header, "DIRECTION"), "{r1}");
        assert_eq!(end(r1, "deny"), end(header, "ACTION"), "{r1}");
        assert_eq!(end(r2, "limit"), end(header, "ACTION"), "{r2}");
        assert_eq!(end(r1, "22/tcp"), end(header, "PORT"), "{r1}");
        assert_eq!(end(r2, "2001"), end(header, "PORT"), "{r2}");
        assert_eq!(end(r1, "10.0.1.0/24"), end(header, "REMOTE"), "{r1}");
        assert_eq!(col(r1, "ZZ first text"), col(header, "RULE"), "{r1}");
        assert_eq!(col(r2, "ZZ second text"), col(header, "RULE"), "{r2}");
    }

    #[test]
    fn every_list_pane_keeps_the_columns_it_showed_at_110_by_24() {
        let state = sample();
        let net = lines(&draw_net(&state, 110, 24)).join("\n");
        let traffic = lines(&draw_at(&state, 110, 24)).join("\n");
        let rules = line_with(&traffic, "REMOTE");
        for title in ["IFACE", "APP", "DIR", "ACTION", "PORT", "REMOTE"] {
            assert!(rules.contains(title), "{title}: {rules}");
        }
        let wifi = with_wifi_sample();
        let pane = wifi_pane(&draw_focused(&wifi, Pane::WifiNetworks, 110, 24));
        for title in ["NETWORK", "SIGNAL", "SECURITY", "CHANNEL"] {
            assert!(pane[1].contains(title), "{title}: {pane:?}");
        }
        let blocks = line_with(&net, "KIND");
        for title in ["LAST SEEN", "FROM", "PORT", "HITS", "KIND"] {
            assert!(blocks.contains(title), "{title}: {blocks}");
        }
        // The Bandwidth zoom's interface table.
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('1'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let header = line_with(&text, "INTERFACE");
        for title in ["↓ IN", "↑ OUT", "↓ TOTAL", "↑ TOTAL"] {
            assert!(header.contains(title), "{title}: {header}");
        }
        assert!(header.ends_with("↑ TOTAL │"), "{header}");
    }

    fn with_wifi_sample() -> AppState {
        with_wifi(vec![access_point(
            Some("Den AP"),
            95,
            161,
            5805,
            "WPA2",
            true,
        )])
    }

    #[test]
    fn a_pane_whose_variable_column_is_empty_in_every_row_draws_its_other_columns_cleanly() {
        let mut state = bare();
        state.record_listeners(vec![listener(5353, "0.0.0.0", None)], 32_768..=60_999);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('3'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let header = line_with(&text, "PATH");
        let row = line_with(&text, "5353/tcp");
        assert!(
            col(header, "APP") < col(header, "BIND")
                && col(header, "FIREWALL") < col(header, "PATH")
        );
        assert_eq!(end(row, "0.0.0.0"), end(header, "BIND"));
        // Firewall Blocks zoom with names off leaves NAME empty.
        let mut state = bare();
        state.record_firewall(
            Duration::from_secs(1),
            block(
                "203.0.113.50",
                22,
                Direction::Inbound,
                Some("Oct  8 10:20:00"),
            ),
        );
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let header = line_with(&text, "KIND");
        let row = line_with(&text, "203.0.113.50");
        assert_eq!(col(row, "22/tcp"), col(header, "PORT"), "{row}");
        assert_eq!(col(row, "blocked"), col(header, "KIND"), "{row}");
    }

    #[test]
    fn an_unavailable_neighbor_table_shows_one_line_and_the_other_panes_keep_their_rows() {
        let mut state = sample();
        state.record_neighbors(NeighborSnapshot::Unavailable(
            "ip: command not found".to_owned(),
        ));
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('8'));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            // The half-width pane wraps the reason onto a second line.
            text.contains("Cannot read the neighbor table")
                && text.contains("(ip: command not")
                && text.contains("found)."),
            "{text}"
        );
        assert!(text.contains("203.0.113.50"), "{text}");
    }

    #[test]
    fn neighbors_say_when_they_are_waiting_or_empty() {
        let mut state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('8'));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("reading neighbors…"), "{text}");
        state.record_neighbors(NeighborSnapshot::Available(Vec::new()));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            text.contains("no neighbors") && !text.contains("reading neighbors"),
            "{text}"
        );
    }

    #[test]
    fn a_neighbors_search_matches_the_cells_shown_so_a_state_word_only_in_zoom() {
        let state = with_neighbors(vec![
            neighbor("10.0.1.2", Some("aa:bb:cc:dd:ee:01"), "eth0", "reachable"),
            neighbor("172.16.0.9", Some("aa:bb:cc:dd:ee:02"), "eth0", "stale"),
        ]);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('8'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "172.16");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 32));
        assert!(
            text.contains("172.16.0.9") && !text.contains("10.0.1.2"),
            "{text}"
        );
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('8'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "stale");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 32));
        assert!(
            !text.contains("172.16.0.9") && !text.contains("10.0.1.2"),
            "{text}"
        );
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 32));
        assert!(
            text.contains("172.16.0.9") && !text.contains("10.0.1.2"),
            "{text}"
        );
    }

    #[test]
    fn lookups_are_wanted_only_for_neighbors_the_pane_can_show() {
        let entries: Vec<Neighbor> = (0..40u8)
            .map(|n| {
                neighbor(
                    &format!("10.0.1.{n}"),
                    Some("aa:bb:cc:dd:ee:01"),
                    "eth0",
                    "stale",
                )
            })
            .collect();
        let state = with_neighbors(entries);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('8'));
        let overview = i.neighbors_to_look_up(&state, 24);
        assert!(
            !overview.is_empty() && overview.len() < 10,
            "{}",
            overview.len()
        );
        assert_eq!(overview[0], "10.0.1.0".parse::<std::net::IpAddr>().unwrap());
        assert!(i.neighbors_to_look_up(&state, 50).len() > overview.len());
        press(&mut i, &state, KeyCode::Enter);
        let zoom = i.neighbors_to_look_up(&state, 24).len();
        assert!(zoom > overview.len() && zoom <= 32);
        let mut other = Interaction::default();
        press(&mut other, &state, KeyCode::Char('2'));
        press(&mut other, &state, KeyCode::Enter);
        assert!(other.neighbors_to_look_up(&state, 24).is_empty());
        let mut unavailable = sample();
        unavailable.record_neighbors(NeighborSnapshot::Unavailable("x".to_owned()));
        assert!(
            Interaction::default()
                .neighbors_to_look_up(&unavailable, 24)
                .is_empty()
        );
    }

    use std::net::IpAddr;

    /// A state with rows in App Traffic, Firewall Blocks and Neighbors, each with its own addresses.
    fn lookup_state() -> (AppState, IpAddr, IpAddr, IpAddr) {
        let mut state = with_neighbors(vec![neighbor(
            "10.0.1.7",
            Some("aa:bb:cc:dd:ee:01"),
            "eth0",
            "stale",
        )]);
        state.record_firewall(
            Duration::from_secs(1),
            block("203.0.113.5", 22, Direction::Inbound, None),
        );
        let app: Vec<IpAddr> = state
            .app_traffic()
            .into_iter()
            .flat_map(|a| a.destinations)
            .map(|d| d.remote.ip)
            .collect();
        assert!(!app.is_empty(), "the state needs App Traffic rows");
        (
            state,
            app[0],
            "203.0.113.5".parse().unwrap(),
            "10.0.1.7".parse().unwrap(),
        )
    }

    fn wanted(i: &Interaction, state: &AppState) -> (Vec<IpAddr>, Vec<IpAddr>, Vec<IpAddr>) {
        (
            i.app_destinations_to_look_up(state),
            i.blocked_sources_to_look_up(state, 24),
            i.neighbors_to_look_up(state, 24),
        )
    }

    #[test]
    fn on_traffic_lookups_are_wanted_for_app_traffic_only() {
        let (state, app, _, _) = lookup_state();
        let mut i = Interaction::default();
        for key in ['1', '2', '3', '4'] {
            press(&mut i, &state, KeyCode::Char(key));
            let (apps, blocks, neighbors) = wanted(&i, &state);
            assert!(apps.contains(&app), "{key}");
            assert!(blocks.is_empty() && neighbors.is_empty(), "{key}");
        }
    }

    #[test]
    fn on_network_and_firewall_lookups_are_wanted_for_blocks_and_neighbors_only() {
        let (state, _, block_source, neighbor_address) = lookup_state();
        let mut i = Interaction::default();
        for key in ['5', '6', '7', '8'] {
            press(&mut i, &state, KeyCode::Char(key));
            let (apps, blocks, neighbors) = wanted(&i, &state);
            assert!(apps.is_empty(), "{key}");
            assert!(blocks.contains(&block_source), "{key}");
            assert!(neighbors.contains(&neighbor_address), "{key}");
        }
    }

    #[test]
    fn zoomed_on_neighbors_only_neighbors_are_wanted() {
        let (state, _, _, neighbor_address) = lookup_state();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('8'));
        press(&mut i, &state, KeyCode::Enter);
        let (apps, blocks, neighbors) = wanted(&i, &state);
        assert!(apps.is_empty() && blocks.is_empty());
        assert!(neighbors.contains(&neighbor_address));
    }

    #[test]
    fn zoomed_on_app_traffic_only_app_traffic_is_wanted() {
        let (state, app, _, _) = lookup_state();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Enter);
        let (apps, blocks, neighbors) = wanted(&i, &state);
        assert!(apps.contains(&app));
        assert!(blocks.is_empty() && neighbors.is_empty());
    }

    #[test]
    fn zoomed_on_another_traffic_pane_wants_no_lookups() {
        let (state, _, _, _) = lookup_state();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('3'));
        press(&mut i, &state, KeyCode::Enter);
        let (apps, blocks, neighbors) = wanted(&i, &state);
        assert!(apps.is_empty() && blocks.is_empty() && neighbors.is_empty());
    }

    fn record_second(state: &mut AppState, second: u64) {
        state.advance_time(Duration::from_secs(second));
        state.record_interfaces(InterfaceSnapshot {
            health: CollectionHealth::Available,
            interfaces: vec![InterfaceMeasurement {
                name: "wlan0".into(),
                addresses: vec![],
                download_bytes_per_second: 9.0e5,
                upload_bytes_per_second: 3.0e5,
                session_received_bytes: 4_000_000,
                session_transmitted_bytes: 900_000,
                status: InterfaceStatus::Available,
                is_up: true,
            }],
            default_route: Some("wlan0".into()),
            gateway: None,
            name_server: None,
            name_servers: vec![],
        });
    }

    #[test]
    fn blocks_recorded_while_traffic_is_shown_are_in_firewall_blocks_after_4() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        let mut i = Interaction::default();
        screen(&state, &mut i, None, 110, 24);
        for n in 0..3u64 {
            state.record_firewall(
                Duration::from_secs(n),
                block(
                    &format!("203.0.113.{}", 10 + n),
                    22,
                    Direction::Inbound,
                    None,
                ),
            );
        }
        press(&mut i, &state, KeyCode::Char('5'));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        for n in 10..13 {
            assert!(text.contains(&format!("203.0.113.{n}")), "{text}");
        }
    }

    #[test]
    fn bandwidth_samples_recorded_while_network_and_firewall_is_shown_are_in_the_chart_after_1() {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        healthy(&mut state);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        screen(&state, &mut i, None, 110, 24);
        for second in 0..30 {
            record_second(&mut state, second);
        }
        press(&mut i, &state, KeyCode::Char('1'));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            text.contains("BANDWIDTH") && text.contains("wlan0"),
            "{text}"
        );
        assert!(text.contains('█'), "no samples in the chart:\n{text}");
    }

    #[test]
    fn tab_and_the_number_keys_do_nothing_in_zoom() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('5'));
        press(&mut i, &state, KeyCode::Enter);
        for key in [
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Char('1'),
            KeyCode::Char('8'),
        ] {
            press(&mut i, &state, key);
            assert_eq!(i.focus(), Pane::FirewallBlocks);
            assert_eq!(i.zoomed(), Some(Pane::FirewallBlocks));
        }
    }

    #[test]
    fn every_list_pane_shows_its_header_columns_and_three_rows_at_110_by_24() {
        let state = with_neighbors(vec![
            neighbor(
                "192.168.100.200",
                Some("aa:bb:cc:dd:ee:01"),
                "eth0",
                "reachable",
            ),
            neighbor(
                "192.168.100.201",
                Some("aa:bb:cc:dd:ee:02"),
                "eth0",
                "reachable",
            ),
            neighbor(
                "192.168.100.202",
                Some("aa:bb:cc:dd:ee:03"),
                "eth0",
                "reachable",
            ),
        ]);
        // The pane's lines from its title down, `skip` cells in, cut at `take`.
        let pane = |text: &[String], title: &str, skip: usize, take: usize| -> Vec<String> {
            let (top, _) = at(text, title);
            text[top + 1..]
                .iter()
                .map(|l| l.chars().skip(skip).take(take).collect::<String>())
                .take_while(|l| !l.contains('╰'))
                .collect()
        };
        let traffic = lines(&draw_at(&state, 110, 24));
        let network = lines(&draw_net(&state, 110, 24));
        let data = |rows: &[String]| {
            rows[1..]
                .iter()
                .filter(|r| !r.trim_matches(['│', ' ']).is_empty())
                .count()
        };
        let apps = pane(&traffic, "APP TRAFFIC", 0, 110);
        let ports = pane(&traffic, "LISTENING PORTS", 0, 110);
        let blocks = pane(&network, "FIREWALL BLOCKS", 0, 55);
        let neighbors = pane(&network, "NEIGHBORS", 55, 55);
        for (rows, columns) in [
            (
                &apps,
                vec!["APP", "DESTINATION", "PORT", "↓ IN", "↑ OUT", "TOTAL"],
            ),
            (&ports, vec!["PORT", "APP", "BIND", "FIREWALL"]),
            (&blocks, vec!["LAST SEEN", "FROM", "PORT", "HITS", "KIND"]),
            (&neighbors, vec!["ADDRESS", "MAC"]),
        ] {
            for column in columns {
                assert!(rows[0].contains(column), "{column}: {rows:?}");
            }
            assert!(data(rows) >= 3, "{rows:?}");
        }
        // Names are off here, so there is no NAME column at all.
        assert!(!neighbors[0].contains("NAME"), "{neighbors:?}");
        for row in &neighbors[1..4] {
            assert!(
                row.contains("192.168.100.20") && row.contains("aa:bb:cc:dd:ee:0"),
                "{row}"
            );
        }
        assert!(
            blocks[1..4].iter().all(|r| r.contains("blocked")),
            "{blocks:?}"
        );
    }

    #[test]
    fn a_neighbor_with_no_hardware_address_shows_a_dash() {
        use crosswalk::ui::panes::neighbor_rows;
        let state = with_neighbors(vec![neighbor("10.0.1.2", None, "eth0", "probe")]);
        let rows = neighbor_rows(&state, &Theme::default(), "", None);
        assert_eq!(rows[0].cells[1].text, "—");
    }

    #[test]
    fn neighbor_text_from_outside_is_stripped_and_bounded() {
        use crosswalk::ui::panes::{neighbor_rows, neighbor_zoom_rows, notice};
        let long = format!("{HOSTILE}{}", "x".repeat(100));
        let state = with_neighbors(vec![neighbor("10.0.1.2", Some(&long), &long, &long)]);
        let theme = Theme::default();
        for (rows, width) in [
            (neighbor_rows(&state, &theme, "", None), 2),
            (neighbor_zoom_rows(&state, &theme, "", None), 4),
        ] {
            assert_eq!(rows[0].cells.len(), width);
            for cell in &rows[0].cells {
                assert_clean(&cell.text, Some(48));
            }
            assert!(rows[0].cells[1].text.starts_with("a[31mbcdef"));
        }
        let mut state = sample();
        state.record_neighbors(NeighborSnapshot::Unavailable(long));
        let line = notice(&state, Pane::Neighbors).unwrap();
        assert_clean(&line, Some(80));
    }

    // ---- Wi-Fi Networks ----

    use crosswalk::collect::wifi::{AccessPoint, WifiSnapshot};

    fn access_point(
        ssid: Option<&str>,
        signal: u8,
        channel: u16,
        mhz: u32,
        security: &str,
        in_use: bool,
    ) -> AccessPoint {
        AccessPoint {
            ssid: ssid.map(str::to_owned),
            bssid: format!("00:11:22:33:44:{channel:02X}"),
            signal,
            channel,
            frequency_mhz: mhz,
            security: security.to_owned(),
            in_use,
        }
    }

    fn with_wifi(points: Vec<AccessPoint>) -> AppState {
        let mut state = sample();
        state.record_wifi(WifiSnapshot::Available(points));
        state
    }

    /// A secured network in use, an open one and a hidden one.
    fn three_networks() -> AppState {
        with_wifi(vec![
            access_point(Some("Cafe"), 62, 6, 2437, "", false),
            access_point(None, 31, 197, 6935, "WPA3", false),
            access_point(Some("Den AP"), 95, 161, 5805, "WPA2", true),
        ])
    }

    /// The Wi-Fi Networks pane's eleven lines on the overview at 110×24: the
    /// right-hand 55 columns from the row of its title down.
    fn wifi_pane(terminal: &Terminal<TestBackend>) -> Vec<String> {
        let rows = lines(terminal);
        let top = rows
            .iter()
            .position(|r| r.contains("WI-FI NETWORKS"))
            .unwrap();
        rows[top..top + 11]
            .iter()
            .map(|r| r.chars().skip(55).collect())
            .collect()
    }

    /// The colours of the SIGNAL cell's eight characters for a network of that
    /// signal, on the overview (`zoom` false) or in the zoom.
    fn signal_colours(signal: u8, zoom: bool) -> Vec<Option<ratatui::style::Color>> {
        use ratatui::style::Color;
        let state = with_wifi(vec![access_point(
            Some("Den"),
            signal,
            6,
            2437,
            "WPA2",
            false,
        )]);
        let terminal = if zoom {
            let mut i = Interaction::default();
            press(&mut i, &state, KeyCode::Char('7'));
            press(&mut i, &state, KeyCode::Enter);
            screen(&state, &mut i, None, 110, 24)
        } else {
            draw_focused(&state, Pane::WifiNetworks, 110, 24)
        };
        let buffer = terminal.backend().buffer();
        let (y, row) = lines(&terminal)
            .into_iter()
            .enumerate()
            .find(|(_, l)| l.contains('▂'))
            .unwrap();
        let x = row.chars().take_while(|&c| c != '▂').count();
        (x..x + 8)
            .map(|x| match buffer[(x as u16, y as u16)].fg {
                Color::Reset => None,
                c => Some(c),
            })
            .collect()
    }

    #[test]
    fn signal_bars_take_the_colour_of_their_strength_and_the_number_and_dots_do_not() {
        let theme = Theme::default();
        let (ok, warning, danger) = (theme.ok, theme.warning, theme.danger);
        for zoom in [false, true] {
            for (signal, colour) in [
                (86, ok),
                (80, ok),
                (71, ok),
                (55, ok),
                (54, warning),
                (42, warning),
                (30, warning),
                (29, danger),
                (18, danger),
            ] {
                let lit = match signal {
                    80.. => 4,
                    55..=79 => 3,
                    30..=54 => 2,
                    _ => 1,
                };
                let cells = signal_colours(signal, zoom);
                for (n, cell) in cells.iter().take(4).enumerate() {
                    let want = if n < lit { colour } else { theme.muted };
                    assert_eq!(*cell, Some(want), "signal {signal} cell {n} zoom {zoom}");
                }
                for cell in &cells[4..] {
                    assert_eq!(*cell, Some(theme.text), "signal {signal} zoom {zoom}");
                }
            }
        }
    }

    #[test]
    fn wifi_overview_shows_four_columns_strongest_first_with_the_in_use_mark_on_one_row() {
        let state = three_networks();
        let pane = wifi_pane(&draw_focused(&state, Pane::WifiNetworks, 110, 24));
        for title in ["NETWORK", "SIGNAL", "SECURITY", "CHANNEL"] {
            assert!(pane[1].contains(title), "{pane:?}");
        }
        assert!(pane[2].contains("● Den AP"), "{pane:?}");
        assert!(pane[2].contains("▂▄▆█  95"), "{pane:?}");
        assert!(
            pane[2].contains("161 · 5G") && pane[2].contains("WPA2"),
            "{pane:?}"
        );
        assert!(
            pane[3].contains("  Cafe") && pane[3].contains("▂▄▆· "),
            "{pane:?}"
        );
        assert!(
            pane[3].contains("6 · 2.4G") && pane[3].contains("open"),
            "{pane:?}"
        );
        assert!(
            pane[4].contains("(hidden)") && pane[4].contains("▂▄··"),
            "{pane:?}"
        );
        assert!(
            pane[4].contains("197 · 6G") && pane[4].contains("WPA3"),
            "{pane:?}"
        );
        let marks = pane[1..].iter().filter(|r| r.contains('●')).count();
        assert_eq!(marks, 1, "{pane:?}");
    }

    /// The screen column at which `needle` starts in `row`, in characters.
    fn column_of(row: &str, needle: &str) -> usize {
        let at = row
            .find(needle)
            .unwrap_or_else(|| panic!("{needle}: {row}"));
        row[..at].chars().count()
    }

    #[test]
    fn wifi_headers_read_network_signal_security_channel_and_zoomed_bssid_freq_channel() {
        let state = three_networks();
        let pane = wifi_pane(&draw_focused(&state, Pane::WifiNetworks, 110, 24));
        let titles: Vec<&str> = pane[1].split_whitespace().filter(|t| *t != "│").collect();
        assert_eq!(
            titles,
            ["NETWORK", "SIGNAL", "SECURITY", "CHANNEL"],
            "{pane:?}"
        );
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let header = line_with(&text, "BSSID");
        let titles: Vec<&str> = header
            .trim_matches(|c: char| c == '│' || c.is_whitespace())
            .split_whitespace()
            .collect();
        assert_eq!(
            titles,
            [
                "NETWORK",
                "SIGNAL",
                "SECURITY",
                "BSSID",
                "FREQUENCY",
                "CHANNEL"
            ],
            "{header}"
        );
    }

    #[test]
    fn channel_cells_line_up_their_dots_digits_and_bands_on_the_overview_and_in_zoom() {
        let state = with_wifi(vec![
            access_point(Some("One"), 90, 1, 2412, "WPA2", false),
            access_point(Some("Eleven"), 80, 11, 2462, "WPA2", false),
            access_point(Some("High"), 70, 161, 5805, "WPA2", false),
        ]);
        let pane = wifi_pane(&draw_focused(&state, Pane::WifiNetworks, 110, 24));
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Enter);
        let zoom = text_of(&screen(&state, &mut i, None, 110, 24));
        let rows = [
            [pane[2].clone(), pane[3].clone(), pane[4].clone()],
            [
                line_with(&zoom, "One").to_owned(),
                line_with(&zoom, "Eleven").to_owned(),
                line_with(&zoom, "High").to_owned(),
            ],
        ];
        for [one, eleven, high] in rows {
            // ` · ` with its spaces, as the signal bars have unlit dots too.
            let dot = column_of(&one, " · ");
            assert_eq!(dot, column_of(&eleven, " · "), "{one} / {eleven}");
            assert_eq!(dot, column_of(&high, " · "), "{one} / {high}");
            // The digits end directly before ` ·` and the bands start together.
            assert_eq!(column_of(&one, "  1 · 2.4G"), dot - 3, "{one}");
            assert_eq!(column_of(&eleven, " 11 · 2.4G"), dot - 3, "{eleven}");
            assert_eq!(column_of(&high, "161 · 5G"), dot - 3, "{high}");
            assert_eq!(column_of(&one, "2.4G"), column_of(&high, "5G"));
            assert_eq!(column_of(&eleven, "2.4G"), column_of(&high, "5G"));
        }
    }

    /// The Wi-Fi pane's row for `name` with one network of that name.
    fn wifi_row_of(name: &str, channel: u16, mhz: u32) -> String {
        let state = with_wifi(vec![access_point(
            Some(name),
            95,
            channel,
            mhz,
            "WPA2",
            true,
        )]);
        wifi_pane(&draw_focused(&state, Pane::WifiNetworks, 110, 24))[2].clone()
    }

    #[test]
    fn a_21_or_22_character_network_name_is_whole_and_a_longer_one_is_cut() {
        // 51 - SIGNAL 8 - SECURITY 8 - 3 gaps = 32 less the channel column:
        // `161 · 5G` is 8 (24 cells, 22 letters), ` 11 · 2.4G` is 10 (20 letters).
        let n22 = "ABCDEFGHIJKLMNOPQRSTUV";
        assert!(wifi_row_of(n22, 161, 5805).contains(&format!("● {n22} ")));
        let n20 = &n22[..20];
        assert!(wifi_row_of(n20, 11, 2462).contains(&format!("● {n20} ")));
        let row = wifi_row_of(n22, 11, 2462);
        assert!(row.contains("● ABCDEFGHIJKLMNOPQRS… "), "{row}");
        assert!(row.contains("11 · 2.4G") && row.contains("WPA2"), "{row}");
    }

    #[test]
    fn wifi_at_160_by_50_gives_a_long_name_whole_and_a_remembered_age_lines_up_with_the_bars() {
        let name = "a-network-name-of-forty-characters-xxxxx";
        assert_eq!(name.len(), 40);
        let state = with_wifi(vec![access_point(Some(name), 95, 161, 5805, "WPA2", true)]);
        let text = text_of(&draw_focused(&state, Pane::WifiNetworks, 160, 50));
        assert!(line_with(&text, "a-network").contains(&format!("● {name} ")));
        let state = with_remembered(40);
        let pane = wifi_pane(&draw_focused(&state, Pane::WifiNetworks, 110, 24));
        let x = |row: &String, needle: &str| {
            let at = row.find(needle).unwrap();
            row[..at].chars().count()
        };
        let bars = x(&pane[2], "▂");
        assert_eq!(bars, x(&pane[4], "seen 40s"), "{pane:?}");
        assert_eq!(bars, x(&pane[1], "SIGNAL"), "{pane:?}");
    }

    #[test]
    fn wifi_zoom_writes_the_band_short_and_keeps_mhz_with_the_last_column_at_the_edge() {
        let state = three_networks();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let den_ap = line_with(&text, "Den AP");
        assert!(den_ap.contains("5805 MHz 161 · 5G"), "{den_ap}");
        assert!(line_with(&text, "Cafe").contains("6 · 2.4G"), "{text}");
        assert!(line_with(&text, "(hidden)").contains("197 · 6G"), "{text}");
        assert!(
            line_with(&text, "FREQUENCY")
                .trim_end_matches('│')
                .trim_end()
                .ends_with("CHANNEL"),
            "{text}"
        );
    }

    #[test]
    fn a_frequency_gives_its_band() {
        use crosswalk::ui::panes::wifi_rows;
        let theme = Theme::default();
        for (mhz, channel, text) in [
            (2412, 1, "  1 · 2.4G"),
            (5805, 161, "161 · 5G"),
            (5924, 177, "177 · 5G"),
            (5925, 1, "  1 · 6G"),
            (6935, 197, "197 · 6G"),
            (2462, 11, " 11 · 2.4G"),
        ] {
            let state = with_wifi(vec![access_point(
                Some("n"),
                50,
                channel,
                mhz,
                "WPA2",
                false,
            )]);
            let rows = wifi_rows(&state, &theme, "");
            assert_eq!(rows[0].cells[3].text, text);
        }
    }

    #[test]
    fn only_an_open_networks_security_is_in_the_warning_colour() {
        let theme = Theme::default();
        let terminal = draw_focused(&three_networks(), Pane::WifiNetworks, 110, 24);
        assert_eq!(fg_of(&terminal, "open"), theme.warning().fg);
        assert_ne!(fg_of(&terminal, "WPA2"), theme.warning().fg);
        assert_ne!(fg_of(&terminal, "WPA3"), theme.warning().fg);
        assert_eq!(fg_of(&terminal, "(hidden)"), theme.muted().fg);
    }

    #[test]
    fn a_32_character_name_is_cut_to_its_column_and_the_other_columns_stay_whole() {
        let name = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        let state = with_wifi(vec![access_point(
            Some(name),
            95,
            161,
            5805,
            "WPA1 WPA2",
            false,
        )]);
        let pane = wifi_pane(&draw_focused(&state, Pane::WifiNetworks, 110, 24));
        // NETWORK gets 51 - 8 - 8 - 9 - 3 = 23 cells: two for the mark, 20
        // letters and the ellipsis.
        assert!(pane[2].contains("  ABCDEFGHIJKLMNOPQRST… "), "{pane:?}");
        assert!(pane[2].contains("▂▄▆█  95"), "{pane:?}");
        assert!(pane[2].contains("161 · 5G"), "{pane:?}");
        assert!(pane[2].contains("WPA1 WPA2"), "{pane:?}");
    }

    #[test]
    fn wifi_zoom_adds_the_hardware_address_and_the_frequency() {
        let state = three_networks();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(
            text.contains("BSSID") && text.contains("FREQUENCY"),
            "{text}"
        );
        let den_ap = line_with(&text, "Den AP");
        assert!(
            den_ap.contains("00:11:22:33:44:A1") && den_ap.contains("5805 MHz"),
            "{den_ap}"
        );
        assert!(line_with(&text, "(hidden)").contains("6935 MHz"), "{text}");
        assert!(!text.contains("FIREWALL BLOCKS"), "{text}");
    }

    #[test]
    fn an_unreadable_wifi_list_gives_one_line_and_no_rows_while_other_panes_keep_theirs() {
        let mut state = with_neighbors(vec![neighbor(
            "10.0.1.7",
            Some("aa:bb:cc:dd:ee:01"),
            "eth0",
            "stale",
        )]);
        state.record_firewall(
            Duration::from_secs(1),
            block("203.0.113.5", 22, Direction::Inbound, None),
        );
        state.record_wifi(WifiSnapshot::Unavailable(
            "NetworkManager is not running".to_owned(),
        ));
        let terminal = draw_focused(&state, Pane::WifiNetworks, 110, 24);
        let pane = wifi_pane(&terminal);
        assert!(
            pane[1].contains("Wi-Fi unavailable: NetworkManager is not running"),
            "{pane:?}"
        );
        assert!(!pane.iter().any(|r| r.contains("NETWORK ")), "{pane:?}");
        assert!(
            pane[2..10]
                .iter()
                .all(|r| r.trim_matches(|c| c == '│' || c == ' ').is_empty()),
            "{pane:?}"
        );
        let text = text_of(&terminal);
        assert!(
            text.contains("203.0.113.5") && text.contains("10.0.1.7"),
            "{text}"
        );
    }

    #[test]
    fn wifi_before_any_snapshot_is_a_quiet_line_and_an_empty_list_says_so() {
        let pane = wifi_pane(&draw_focused(&sample(), Pane::WifiNetworks, 110, 24));
        assert!(pane[1].contains("reading Wi-Fi networks…"), "{pane:?}");
        let pane = wifi_pane(&draw_focused(
            &with_wifi(Vec::new()),
            Pane::WifiNetworks,
            110,
            24,
        ));
        assert!(pane[1].contains("no Wi-Fi networks found"), "{pane:?}");
        assert!(!pane[1].contains("reading"), "{pane:?}");
    }

    #[test]
    fn a_search_keeps_only_the_matching_wifi_rows_and_selection_moves_over_them() {
        let state = three_networks();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "wpa");
        press(&mut i, &state, KeyCode::Enter);
        let pane = wifi_pane(&screen(&state, &mut i, None, 110, 24));
        let text = pane.join("\n");
        assert!(
            text.contains("Den AP") && text.contains("(hidden)"),
            "{text}"
        );
        assert!(!text.contains("Cafe"), "{text}");
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Char('j'));
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("/wpa") && !text.contains("Cafe"), "{text}");
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "zzz");
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        assert!(text.contains("no matches"), "{text}");
    }

    #[test]
    fn wifi_text_from_outside_is_stripped_and_bounded() {
        use crosswalk::ui::panes::{notice, wifi_rows, wifi_zoom_rows};
        let long = format!("{HOSTILE}{}", "x".repeat(100));
        let mut point = access_point(Some(&long), 50, 1, 2412, &long, false);
        point.bssid = long.clone();
        let state = with_wifi(vec![point]);
        let theme = Theme::default();
        for (rows, width) in [
            (wifi_rows(&state, &theme, ""), 4),
            (wifi_zoom_rows(&state, &theme, ""), 6),
        ] {
            assert_eq!(rows[0].cells.len(), width);
            for cell in &rows[0].cells {
                assert_clean(&cell.text, Some(50));
            }
            assert!(rows[0].cells[0].text.trim_start().starts_with("a[31mbcdef"));
        }
        assert!(
            wifi_zoom_rows(&state, &theme, "")[0].cells[3]
                .text
                .starts_with("a[31mbcdef")
        );
        let mut state = sample();
        state.record_wifi(WifiSnapshot::Unavailable(long));
        assert_clean(&notice(&state, Pane::WifiNetworks).unwrap(), Some(80));
        let mut state = sample();
        state.record_wifi(WifiSnapshot::Available(vec![access_point(
            Some("\u{7}\u{202E}"),
            50,
            1,
            2412,
            "WPA2",
            false,
        )]));
        assert!(
            wifi_rows(&state, &theme, "")[0].cells[0]
                .text
                .contains("(hidden)")
        );
    }

    // ---- remembered Wi-Fi access points ----

    /// Two listed access points (one in use) and "Old Cafe", an open
    /// network last listed `age` seconds ago.
    fn with_remembered(age: u64) -> AppState {
        let mut state = sample();
        state.advance_time(Duration::from_secs(1000));
        let mut gone = access_point(Some("Old Cafe"), 70, 11, 2462, "", false);
        gone.in_use = true;
        let listed = vec![
            access_point(Some("Den AP"), 95, 161, 5805, "WPA2", true),
            access_point(Some("Cafe"), 20, 6, 2437, "WPA2", false),
        ];
        let mut first = listed.clone();
        first.push(gone);
        state.record_wifi(WifiSnapshot::Available(first));
        state.advance_time(Duration::from_secs(1000 + age));
        state.record_wifi(WifiSnapshot::Available(listed));
        state
    }

    #[test]
    fn a_remembered_access_point_is_below_the_listed_ones_muted_with_its_age_and_no_bars_or_mark() {
        let state = with_remembered(40);
        let terminal = draw_focused(&state, Pane::WifiNetworks, 110, 24);
        let pane = wifi_pane(&terminal);
        assert!(
            pane[2].contains("Den AP") && pane[3].contains("Cafe"),
            "{pane:?}"
        );
        let old = pane
            .iter()
            .position(|r| r.contains("Old Cafe"))
            .unwrap_or_else(|| panic!("{pane:?}"));
        assert_eq!(old, 4, "{pane:?}");
        let row = &pane[old];
        assert!(row.contains("seen 40s"), "{row}");
        assert!(row.contains("11 · 2.4G") && row.contains("open"), "{row}");
        assert!(!row.contains(['●', '▂', '▄', '▆', '█']), "{row}");
        let top = lines(&terminal)
            .iter()
            .position(|r| r.contains("WI-FI NETWORKS"))
            .unwrap();
        let muted = Theme::default().muted;
        let buffer = terminal.backend().buffer();
        for x in 57..108 {
            let cell = &buffer[(x, (top + old) as u16)];
            if cell.symbol() != " " {
                assert_eq!(cell.fg, muted, "x={x} {:?}", cell.symbol());
            }
        }
    }

    #[test]
    fn ages_read_in_seconds_minutes_hours_and_days_and_fit_the_signal_cell() {
        use crosswalk::ui::panes::wifi_rows;
        let theme = Theme::default();
        for (age, text) in [
            (59, "seen 59s"),
            (60, "seen 1m"),
            (3599, "seen 59m"),
            (3600, "seen 1h"),
            (86_399, "seen 23h"),
            (86_400, "seen 1d"),
            (86_400 * 400, "seen 99d"),
        ] {
            let state = with_remembered(age);
            let rows = wifi_rows(&state, &theme, "");
            let cell = &rows[2].cells[1].text;
            assert_eq!(cell.trim_end(), text, "{age}s");
            assert!(cell.chars().count() <= 8, "{cell:?}");
        }
    }

    #[test]
    fn zoom_shows_a_remembered_access_point_with_its_address_and_frequency() {
        let state = with_remembered(125);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Enter);
        let text = text_of(&screen(&state, &mut i, None, 110, 24));
        let old = line_with(&text, "Old Cafe");
        assert!(old.contains("seen 2m"), "{old}");
        assert!(
            old.contains("00:11:22:33:44:0B") && old.contains("2462 MHz"),
            "{old}"
        );
    }

    #[test]
    fn a_search_matches_a_remembered_access_points_name() {
        let state = with_remembered(40);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "old");
        press(&mut i, &state, KeyCode::Enter);
        let text = wifi_pane(&screen(&state, &mut i, None, 110, 24)).join("\n");
        assert!(
            text.contains("Old Cafe") && !text.contains("Den AP"),
            "{text}"
        );
    }

    // ---- the scan key ----

    use crosswalk::collect::wifi::ScanOutcome;

    fn asks_for_a_scan(i: &mut Interaction) -> bool {
        i.take_scan_request()
    }

    #[test]
    fn r_on_wifi_networks_focused_or_zoomed_asks_for_a_scan_once() {
        let state = three_networks();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Char('r'));
        assert!(asks_for_a_scan(&mut i));
        assert!(!asks_for_a_scan(&mut i), "taking the request clears it");
        press(&mut i, &state, KeyCode::Enter);
        assert_eq!(i.zoomed(), Some(Pane::WifiNetworks));
        press(&mut i, &state, KeyCode::Char('r'));
        assert!(asks_for_a_scan(&mut i));
    }

    #[test]
    fn r_does_nothing_on_other_panes_in_a_search_field_or_with_help_open() {
        let state = three_networks();
        for key in '1'..='8' {
            if key == '7' {
                continue;
            }
            let mut i = Interaction::default();
            press(&mut i, &state, KeyCode::Char(key));
            press(&mut i, &state, KeyCode::Char('r'));
            assert!(!asks_for_a_scan(&mut i), "pane {key}");
            press(&mut i, &state, KeyCode::Enter);
            press(&mut i, &state, KeyCode::Char('r'));
            assert!(!asks_for_a_scan(&mut i), "pane {key} zoomed");
        }
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Char('/'));
        press(&mut i, &state, KeyCode::Char('r'));
        assert!(!asks_for_a_scan(&mut i));
        assert_eq!(i.search(Pane::WifiNetworks), "r");
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('?'));
        press(&mut i, &state, KeyCode::Char('r'));
        assert!(!asks_for_a_scan(&mut i));
        assert!(i.help_open());
    }

    #[test]
    fn the_pane_says_a_scan_was_requested_until_the_next_list_arrives() {
        let mut state = three_networks();
        state.record_wifi_scan(ScanOutcome::Accepted);
        let terminal = draw_focused(&state, Pane::WifiNetworks, 110, 24);
        let pane = wifi_pane(&terminal);
        assert!(pane[1].contains("scan requested…"), "{pane:?}");
        let theme = Theme::default();
        let lines = lines(&terminal);
        let y = lines
            .iter()
            .position(|l| l.contains("scan requested"))
            .unwrap();
        let x = lines[y].chars().position(|c| c == 's').unwrap();
        assert_eq!(
            terminal.backend().buffer()[(x as u16, y as u16)].fg,
            theme.muted
        );
        state.record_wifi(WifiSnapshot::Available(vec![]));
        let pane = wifi_pane(&draw_focused(&state, Pane::WifiNetworks, 110, 24));
        assert!(!pane.join("\n").contains("scan requested"), "{pane:?}");
    }

    #[test]
    fn a_refused_scan_gives_one_warning_line_with_its_reason_for_five_seconds() {
        let mut state = three_networks();
        let now = state.wifi().map(|_| Duration::from_secs(119)).unwrap();
        state.advance_time(now);
        state.record_wifi_scan(ScanOutcome::Refused("a scan was just done".to_owned()));
        let terminal = draw_focused(&state, Pane::WifiNetworks, 110, 24);
        let pane = wifi_pane(&terminal);
        assert!(
            pane[1].contains("scan refused: a scan was just done"),
            "{pane:?}"
        );
        assert!(
            pane.join("\n").contains("Den AP"),
            "the list is left as it was"
        );
        let lines = lines(&terminal);
        let y = lines
            .iter()
            .position(|l| l.contains("scan refused"))
            .unwrap();
        let x = lines[y].chars().position(|c| c == 's').unwrap();
        assert_eq!(
            terminal.backend().buffer()[(x as u16, y as u16)].fg,
            Theme::default().warning
        );
        state.advance_time(Duration::from_secs(119 + 4));
        let pane = wifi_pane(&draw_focused(&state, Pane::WifiNetworks, 110, 24));
        assert!(pane.join("\n").contains("scan refused"), "{pane:?}");
        state.advance_time(Duration::from_secs(119 + 5));
        let pane = wifi_pane(&draw_focused(&state, Pane::WifiNetworks, 110, 24));
        assert!(!pane.join("\n").contains("scan refused"), "{pane:?}");
    }

    #[test]
    fn the_footer_shows_the_r_hint_only_while_wifi_networks_is_focused() {
        let state = three_networks();
        let footer =
            |focus: Pane, width| lines(&draw_focused(&state, focus, width, 24))[23].clone();
        assert!(footer(Pane::WifiNetworks, 110).contains("r scan"));
        assert!(!footer(Pane::Neighbors, 110).contains("r scan"));
        assert!(!footer(Pane::Bandwidth, 110).contains("r scan"));
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Enter);
        let rows = lines(&screen(&state, &mut i, None, 110, 24));
        assert!(rows[23].contains("r scan"), "{}", rows[23]);
    }

    #[test]
    fn the_help_lists_r_and_still_fits_at_110_by_24() {
        let state = sample();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('?'));
        let rows = lines(&screen(&state, &mut i, None, 110, 24));
        let top = rows.iter().position(|l| l.contains("HELP")).unwrap();
        let line = rows
            .iter()
            .skip(top)
            .find(|l| l.contains("scan"))
            .unwrap_or_else(|| panic!("{rows:?}"));
        assert!(line.contains(" r"), "{line}");
        assert!(rows.iter().any(|l| l.contains("● open")), "{rows:?}");
    }

    // ---- 019: PID beside the app, and the app's path in App Traffic ----

    const CLAUDE_PATH: &str = "/home/user/.local/share/claude/versions/2.1.296";

    /// Three apps: firefox on one destination (process 4312), a deeply nested
    /// program whose destination three processes share, and an app with enough
    /// destinations for the overview to fold the rest into a `+N more` row.
    fn path_state() -> AppState {
        let mut state = bare();
        let firefox = process("/usr/lib/firefox/firefox", 4312);
        packet(
            &mut state,
            10,
            Some(&firefox),
            "142.250.80.46",
            443,
            Direction::Outbound,
            1_000,
        );
        for pid in [4312, 4390, 4401] {
            packet(
                &mut state,
                11,
                Some(&process(CLAUDE_PATH, pid)),
                "151.101.1.69",
                443,
                Direction::Outbound,
                1_000,
            );
        }
        let many = process("/usr/bin/many", 700);
        for n in 1..=8 {
            packet(
                &mut state,
                12,
                Some(&many),
                &format!("198.51.100.{n}"),
                443,
                Direction::Outbound,
                1_000,
            );
        }
        state
    }

    fn traffic_text(state: &AppState, i: &mut Interaction) -> Vec<String> {
        lines(&screen(state, i, None, 110, 24))
    }

    fn app_row<'a>(rows: &'a [String], needle: &str) -> &'a str {
        rows.iter()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no {needle} in {rows:#?}"))
    }

    #[test]
    fn app_traffic_overview_header_reads_app_pid_destination_port_rates_total() {
        let rows = traffic_text(&path_state(), &mut Interaction::default());
        let header = app_row(&rows, "DESTINATION");
        let order = [
            "APP",
            "PID",
            "DESTINATION",
            "PORT",
            "↓ IN",
            "↑ OUT",
            "TOTAL",
        ];
        let at: Vec<usize> = order.iter().map(|c| col(header, c)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{header}");
    }

    #[test]
    fn app_traffic_overview_shows_the_path_whole_or_cut_from_the_left_to_28_cells() {
        let rows = traffic_text(&path_state(), &mut Interaction::default());
        assert_eq!(CLAUDE_PATH.chars().count(), 47);
        let header = app_row(&rows, "DESTINATION");
        let firefox = app_row(&rows, "142.250.80.46");
        assert!(firefox.contains("/usr/lib/firefox/firefox"), "{firefox}");
        assert_eq!(col(firefox, "/usr"), col(header, "APP"));
        let claude = app_row(&rows, "151.101.1.69");
        let cut = "…are/claude/versions/2.1.296";
        assert_eq!(cut.chars().count(), 28);
        assert_eq!(col(claude, cut), col(header, "APP"));
        // 28 cells of path, a gap, the sparkline's four cells and a gap.
        assert_eq!(col(header, "PID") - col(header, "APP"), 34, "{header}");
    }

    #[test]
    fn app_traffic_overview_shows_the_first_pid_and_how_many_more() {
        let rows = traffic_text(&path_state(), &mut Interaction::default());
        let header = app_row(&rows, "DESTINATION");
        let pid = col(header, "PID");
        let single = app_row(&rows, "142.250.80.46");
        let shared = app_row(&rows, "151.101.1.69");
        assert_eq!(col(single, "4312"), pid, "{single}");
        assert!(!single.contains("+"), "{single}");
        assert_eq!(col(shared, "4312 +2"), pid, "{shared}");
        assert_eq!(col(shared, "151.101.1.69"), col(header, "DESTINATION"));
    }

    #[test]
    fn the_more_row_has_no_pid_and_only_an_apps_first_row_has_its_path() {
        let rows = lines(&screen(
            &path_state(),
            &mut Interaction::default(),
            None,
            110,
            50,
        ));
        let header = app_row(&rows, "DESTINATION");
        let more = app_row(&rows, "+5 more");
        let (pid, dest) = (col(header, "PID"), col(header, "DESTINATION"));
        let between: String = more.chars().skip(pid).take(dest - pid).collect();
        assert_eq!(between.trim_matches([' ', '│']), "", "{more}");
        assert_eq!(
            rows.iter().filter(|l| l.contains("/usr/bin/many")).count(),
            1
        );
    }

    #[test]
    fn searching_app_traffic_matches_the_path() {
        let state = path_state();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "claude");
        let rows = traffic_text(&state, &mut i);
        assert!(rows.iter().any(|l| l.contains("151.101.1.69")), "{rows:#?}");
        assert!(
            !rows.iter().any(|l| l.contains("142.250.80.46")),
            "{rows:#?}"
        );
        // Text only the path holds, not the short name.
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "usr/lib");
        let rows = traffic_text(&state, &mut i);
        assert!(
            rows.iter().any(|l| l.contains("142.250.80.46")),
            "{rows:#?}"
        );
        assert!(
            !rows.iter().any(|l| l.contains("151.101.1.69")),
            "{rows:#?}"
        );
    }

    fn zoomed_paths(width: u16) -> Vec<String> {
        let state = path_state();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Enter);
        lines(&screen(&state, &mut i, None, width, 30))
    }

    #[test]
    fn zoomed_app_traffic_puts_pid_second_after_the_app() {
        let rows = zoomed_paths(170);
        let header = app_row(&rows, "DESTINATION");
        let order = [
            "APP",
            "PID",
            "DESTINATION",
            "PORT",
            "↓ IN",
            "↑ OUT",
            "↓ TOTAL",
            "↑ TOTAL",
        ];
        let at: Vec<usize> = order.iter().map(|c| col(header, c)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{header}");
    }

    #[test]
    fn zoomed_app_traffic_shows_the_47_character_path_whole_and_every_pid() {
        let rows = zoomed_paths(170);
        let header = app_row(&rows, "DESTINATION");
        let claude = app_row(&rows, "151.101.1.69");
        assert_eq!(col(claude, CLAUDE_PATH), col(header, "APP"), "{claude}");
        assert_eq!(
            col(claude, "4312,4390,4401"),
            col(header, "PID"),
            "{claude}"
        );
    }

    #[test]
    fn zoomed_app_traffic_cuts_a_squeezed_path_from_the_left_at_110_columns() {
        let rows = zoomed_paths(110);
        let header = app_row(&rows, "DESTINATION");
        for title in [
            "APP",
            "PID",
            "DESTINATION",
            "PORT",
            "↓ IN",
            "↑ OUT",
            "↓ TOTAL",
            "↑ TOTAL",
            "NAME",
        ] {
            assert!(header.contains(title), "{title} missing: {header}");
        }
        let claude = app_row(&rows, "151.101.1.69");
        let cell: String = claude
            .chars()
            .skip(col(header, "APP"))
            .take(col(header, "PID") - col(header, "APP") - 6)
            .collect();
        let cell = cell.trim_end();
        assert!(cell.starts_with('…'), "{claude}");
        assert!(cell.ends_with("versions/2.1.296"), "{claude}");
    }

    #[test]
    fn zoomed_app_traffic_cuts_a_path_past_48_cells_from_the_left() {
        let long = format!("/opt/{}/bin/program", "d".repeat(60));
        let mut state = bare();
        packet(
            &mut state,
            10,
            Some(&process(&long, 5)),
            "203.0.113.9",
            443,
            Direction::Outbound,
            100,
        );
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Enter);
        let rows = lines(&screen(&state, &mut i, None, 170, 30));
        let row = app_row(&rows, "203.0.113.9");
        let cut: String = std::iter::once('…')
            .chain(long.chars().skip(long.chars().count() - 47))
            .collect();
        assert!(row.contains(&cut), "{row}");
        assert!(!row.contains(&long), "{row}");
    }

    /// Listening Ports at 110x24: the left half of the bottom row.
    fn listening_half() -> Vec<String> {
        let mut state = bare();
        let owned = Listener {
            protocol: Protocol::Tcp,
            address: "0.0.0.0".parse().unwrap(),
            port: 22,
            owners: vec![process("/usr/bin/sshd", 912)],
        };
        state.record_listeners(
            vec![owned, listener(5353, "0.0.0.0", None)],
            32_768..=60_999,
        );
        lines(&screen(&state, &mut Interaction::default(), None, 110, 24))
            .iter()
            .map(|l| l.chars().take(55).collect())
            .collect()
    }

    /// The ports Listening Ports lists, top down: the first cell of each row
    /// under the pane's title, within its first `width` columns.
    fn listed_ports(screen: &[String], width: usize) -> Vec<u16> {
        let top = screen
            .iter()
            .position(|l| l.contains("LISTENING PORTS"))
            .unwrap();
        screen[top + 1..]
            .iter()
            .map(|l| l.chars().take(width).collect::<String>())
            .map_while(|l| {
                let inner = l.trim_start_matches('│').trim().to_owned();
                (!l.starts_with(['╰', '└'])).then_some(inner)
            })
            .filter_map(|l| {
                l.split_whitespace()
                    .find_map(|word| word.strip_suffix("/tcp")?.parse().ok())
            })
            .collect()
    }

    /// A local port 631, a blocked 22, a limited 2222 and two open ones.
    fn ports_of_every_exposure(rules: Option<RuleSnapshot>) -> AppState {
        let mut state = bare();
        state.record_listeners(
            vec![
                listener(631, "127.0.0.1", Some("/usr/bin/cupsd")),
                listener(22, "0.0.0.0", Some("/usr/bin/sshd")),
                listener(2222, "0.0.0.0", Some("/usr/bin/sshd")),
                listener(8765, "0.0.0.0", Some("/usr/bin/app")),
                listener(80, "0.0.0.0", Some("/usr/bin/httpd")),
            ],
            32_768..=60_999,
        );
        state.record_rules(rules.unwrap_or(RuleSnapshot::Active {
            default_incoming: Policy::Deny,
            default_outgoing: Policy::Allow,
            rules: vec![
                rule(RuleAction::Allow, 80, RuleSource::Anywhere),
                rule(RuleAction::Allow, 8765, RuleSource::Anywhere),
                rule(
                    RuleAction::Allow,
                    2222,
                    RuleSource::Specific("10.0.0.0/24".into()),
                ),
            ],
        }));
        state
    }

    fn zoomed_listing(state: &AppState) -> Vec<String> {
        let mut i = Interaction::default();
        press(&mut i, state, KeyCode::Char('3'));
        press(&mut i, state, KeyCode::Enter);
        lines(&screen(state, &mut i, None, 110, 24))
    }

    #[test]
    fn ports_are_listed_open_first_then_limited_blocked_and_local_in_port_order() {
        let state = ports_of_every_exposure(None);
        let overview = lines(&screen(&state, &mut Interaction::default(), None, 110, 50));
        assert_eq!(
            listed_ports(&overview, 55),
            [80, 8765, 2222, 22, 631],
            "{overview:#?}"
        );
        let first_four = lines(&screen(&state, &mut Interaction::default(), None, 110, 24));
        assert_eq!(listed_ports(&first_four, 55), [80, 8765, 2222, 22]);
        let zoom = zoomed_listing(&state);
        assert_eq!(
            listed_ports(&zoom, 110),
            [80, 8765, 2222, 22, 631],
            "{zoom:#?}"
        );
    }

    #[test]
    fn with_ufw_off_the_ports_are_listed_by_number_and_the_local_one_last() {
        let state = ports_of_every_exposure(Some(RuleSnapshot::Inactive));
        // The notice about UFW takes two of the pane's rows at 110x24.
        let small = lines(&screen(&state, &mut Interaction::default(), None, 110, 24));
        assert_eq!(listed_ports(&small, 55), [22, 80]);
        let overview = lines(&screen(&state, &mut Interaction::default(), None, 110, 50));
        assert_eq!(listed_ports(&overview, 55), [22, 80, 2222, 8765, 631]);
        let zoom = zoomed_listing(&state);
        assert_eq!(
            listed_ports(&zoom, 110),
            [22, 80, 2222, 8765, 631],
            "{zoom:#?}"
        );
    }

    #[test]
    fn listening_ports_header_reads_app_pid_bind_port_firewall_with_every_column_shown() {
        let rows = listening_half();
        let header = app_row(&rows, "FIREWALL");
        let order = ["APP", "PID", "BIND", "PORT", "FIREWALL"];
        let at: Vec<usize> = order.iter().map(|c| col(header, c)).collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{header}");
    }

    #[test]
    fn a_listening_port_shows_its_owners_pid_and_an_ownerless_one_a_dash() {
        let rows = listening_half();
        let header = app_row(&rows, "FIREWALL");
        let pid = col(header, "PID");
        let owned = app_row(&rows, "sshd");
        let ownerless = app_row(&rows, "5353/tcp");
        assert_eq!(col(owned, "912"), pid, "{owned}");
        let cell: String = ownerless.chars().skip(pid).take(3).collect();
        assert_eq!(cell.trim_end(), "—", "{ownerless}");
        assert_eq!(end(owned, "0.0.0.0"), end(header, "BIND"), "{owned}");
    }

    #[test]
    fn narrowing_app_traffic_drops_pid_before_any_other_column() {
        use crosswalk::ui::{
            panes::{app_traffic_columns, app_traffic_rows},
            table::Table,
        };
        let state = path_state();
        let theme = Theme::default();
        let columns = app_traffic_columns();
        let rows = app_traffic_rows(&state, &theme, "", None, None);
        let header_at = |width: u16| -> String {
            let mut terminal = Terminal::new(TestBackend::new(width, 3)).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    Table::new(&columns, &rows, &theme).render(frame.buffer_mut(), area);
                })
                .unwrap();
            lines(&terminal)[0].clone()
        };
        let all = [
            "APP",
            "PID",
            "DESTINATION",
            "PORT",
            "↓ IN",
            "↑ OUT",
            "TOTAL",
        ];
        // Wide enough for every column: all are there.
        assert!(all.iter().all(|c| header_at(110).contains(c)));
        // Narrower by one cell than the titled columns need (the sparkline is
        // already gone): only PID goes.
        let need = columns
            .iter()
            .filter(|c| !c.title.is_empty())
            .map(|c| c.min_width)
            .sum::<u16>()
            + 6;
        let header = header_at(need - 1);
        for column in all.into_iter().filter(|c| *c != "PID") {
            assert!(header.contains(column), "{column}: {header}");
        }
        assert!(!header.contains("PID"), "{header}");
    }

    // ---- 026: the sparkline beside APP in App Traffic ----

    /// The four sparkline cells of body row `n` with their colours, from App
    /// Traffic's overview table drawn `width` cells wide, and the header.
    fn spark_cells(
        state: &AppState,
        limit: Option<usize>,
        width: u16,
        n: usize,
    ) -> (String, Vec<(String, ratatui::style::Color)>) {
        use crosswalk::ui::{
            panes::{app_traffic_columns, app_traffic_rows},
            table::Table,
        };
        let theme = Theme::default();
        let columns = app_traffic_columns();
        let rows = app_traffic_rows(state, &theme, "", limit, None);
        let mut terminal = Terminal::new(TestBackend::new(width, 12)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                Table::new(&columns, &rows, &theme).render(frame.buffer_mut(), area);
            })
            .unwrap();
        let text = lines(&terminal);
        let x = col(&text[0], "PID") - 5;
        let buffer = terminal.backend().buffer();
        let cells = (0..4)
            .map(|k| {
                let cell = &buffer[((x + k) as u16, 1 + n as u16)];
                (cell.symbol().to_owned(), cell.fg)
            })
            .collect();
        (text[0].clone(), cells)
    }

    fn spark(cells: &[(String, ratatui::style::Color)]) -> String {
        cells.iter().map(|(g, _)| g.as_str()).collect()
    }

    fn is_braille(c: char) -> bool {
        ('\u{2801}'..='\u{28ff}').contains(&c)
    }

    fn spark_app(bytes_by_second: &[(u64, Direction, u32)]) -> AppState {
        let mut state = bare();
        let app = process("/usr/bin/spark", 9);
        for &(at, direction, bytes) in bytes_by_second {
            packet(
                &mut state,
                at,
                Some(&app),
                "198.51.100.1",
                443,
                direction,
                bytes,
            );
        }
        state
    }

    #[test]
    fn the_header_has_an_empty_title_after_app_and_no_history() {
        let state = spark_app(&[(20, Direction::Inbound, 100)]);
        let (header, _) = spark_cells(&state, None, 110, 0);
        // Left to right, with only the empty sparkline title between APP and PID.
        let titles = [
            "APP",
            "PID",
            "DESTINATION",
            "PORT",
            "↓ IN",
            "↑ OUT",
            "TOTAL",
        ];
        assert!(
            titles
                .windows(2)
                .all(|w| col(&header, w[0]) < col(&header, w[1]))
        );
        assert!(
            header
                .trim_matches(|c| c == '│' || c == ' ')
                .ends_with("TOTAL")
        );
        assert!(!header.contains("HISTORY"));
        assert!(
            header[col(&header, "APP") + 3..col(&header, "PID")]
                .trim()
                .is_empty()
        );
        let zoomed = zoomed_paths(170);
        assert!(!app_row(&zoomed, "DESTINATION").contains("HISTORY"));
    }

    #[test]
    fn four_seconds_of_rising_download_draw_two_empty_cells_then_braille_in_the_inbound_colour() {
        let down = Direction::Inbound;
        let state = spark_app(&[
            (20, down, 100),
            (21, down, 200),
            (22, down, 400),
            (23, down, 800),
        ]);
        let (_, cells) = spark_cells(&state, None, 110, 0);
        assert_eq!(spark(&cells), "  ⣀⣼");
        let inbound = Theme::default().inbound;
        assert!(cells[2..].iter().all(|(_, c)| *c == inbound), "{cells:?}");
    }

    #[test]
    fn two_destinations_in_one_second_are_drawn_as_their_sum() {
        let down = Direction::Inbound;
        let mut state = spark_app(&[(22, down, 100), (23, down, 400)]);
        let app = process("/usr/bin/spark", 9);
        packet(&mut state, 23, Some(&app), "198.51.100.2", 443, down, 400);
        let (_, cells) = spark_cells(&state, None, 110, 0);
        // The older second is one dot of the left column, the newer all four.
        assert_eq!(spark(&cells), "   ⣸");
    }

    #[test]
    fn an_app_that_only_sent_in_the_last_two_seconds_ends_in_the_outbound_colour() {
        let state = spark_app(&[
            (22, Direction::Outbound, 100),
            (23, Direction::Outbound, 100),
        ]);
        let (_, cells) = spark_cells(&state, None, 110, 0);
        assert_eq!(cells[3].1, Theme::default().outbound);
    }

    #[test]
    fn the_busiest_second_is_four_dots_whatever_the_rate() {
        for bytes in [1_000, 100_000_000] {
            let state = spark_app(&[(23, Direction::Inbound, bytes)]);
            let (_, cells) = spark_cells(&state, None, 110, 0);
            let bits = spark(&cells).chars().last().unwrap() as u32 - 0x2800;
            assert_eq!(bits & 0xB8, 0xB8, "{cells:?}");
        }
    }

    #[test]
    fn an_app_idle_for_eight_seconds_shows_four_empty_cells() {
        let mut state = spark_app(&[(20, Direction::Inbound, 100)]);
        state.advance_time(Duration::from_secs(28));
        let (_, cells) = spark_cells(&state, None, 110, 0);
        assert_eq!(spark(&cells), "    ");
    }

    #[test]
    fn later_rows_and_the_more_row_leave_the_sparkline_empty() {
        let mut state = bare();
        let app = process("/usr/bin/many", 700);
        for n in 1..=5 {
            let ip = format!("198.51.100.{n}");
            packet(
                &mut state,
                23,
                Some(&app),
                &ip,
                443,
                Direction::Inbound,
                100,
            );
        }
        let (_, first) = spark_cells(&state, Some(3), 110, 0);
        assert_ne!(spark(&first).trim(), "");
        for n in 1..=3 {
            let (_, cells) = spark_cells(&state, Some(3), 110, n);
            assert_eq!(spark(&cells), "    ", "row {n}");
        }
    }

    #[test]
    fn a_pane_too_narrow_for_every_column_drops_the_sparkline_and_keeps_pid() {
        use crosswalk::ui::{
            panes::{app_traffic_columns, app_traffic_rows},
            table::Table,
        };
        let state = spark_app(&[(23, Direction::Inbound, 100)]);
        let columns = app_traffic_columns();
        let titled: u16 = columns
            .iter()
            .filter(|c| !c.title.is_empty())
            .map(|c| c.min_width)
            .sum();
        let theme = Theme::default();
        let rows = app_traffic_rows(&state, &theme, "", None, None);
        let mut terminal = Terminal::new(TestBackend::new(titled + 6, 4)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                Table::new(&columns, &rows, &theme).render(frame.buffer_mut(), area);
            })
            .unwrap();
        let text = lines(&terminal).join("\n");
        assert!(text.contains("PID"), "{text}");
        assert!(!text.chars().any(is_braille), "{text}");
    }

    #[test]
    fn zoom_draws_the_sparkline_on_an_apps_first_row_only() {
        let zoomed = zoomed_paths(170);
        let rows: Vec<&String> = zoomed
            .iter()
            .filter(|l| l.chars().any(is_braille))
            .collect();
        assert!(!rows.is_empty(), "{zoomed:?}");
        assert!(rows.iter().all(|l| !l.starts_with("│  ")), "{rows:?}");
    }

    // ---- Selection and scrolling on the overview ----

    /// Every list pane holding ten rows: ports 1001-1010, ten outbound
    /// rules, ten blocked sources, ten neighbours 10.0.1.101-110 (nine
    /// events), ten Wi-Fi networks net01-net10, and the sample's apps.
    fn busy() -> AppState {
        let mut state = sample();
        state.set_wall_clock(at_ten_oh_five);
        state.record_listeners(
            (1..=10)
                .map(|n| listener(1000 + n, "0.0.0.0", Some("/usr/bin/sshd")))
                .collect(),
            32_768..=60_999,
        );
        record(
            &mut state,
            Policy::Deny,
            Policy::Allow,
            (1..=10)
                .map(|n| {
                    out_rule(
                        RuleAction::Allow,
                        2000 + n,
                        &format!("198.51.100.{}", 100 + n),
                    )
                })
                .collect(),
        );
        for n in 1..=6u32 {
            for _ in 0..(21 - n) {
                state.record_firewall(
                    Duration::from_secs(119),
                    block(
                        &format!("172.16.0.{}", 100 + n),
                        22,
                        Direction::Inbound,
                        None,
                    ),
                );
            }
        }
        for n in 1..=10 {
            let entries = (1..=n)
                .map(|k| {
                    neighbor(
                        &format!("10.0.1.{}", 100 + k),
                        Some(MAC_A),
                        "eth0",
                        "reachable",
                    )
                })
                .collect();
            state.record_neighbors(NeighborSnapshot::Available(entries));
        }
        state.record_wifi(WifiSnapshot::Available(
            (1..=10u8)
                .map(|n| {
                    access_point(
                        Some(&format!("net{n:02}")),
                        90 - n,
                        n as u16,
                        2412,
                        "WPA2",
                        false,
                    )
                })
                .collect(),
        ));
        state
    }

    const MARK_X_RIGHT_PANE: usize = 55;

    /// (line, first column) of every line that has a highlighted cell.
    fn marked(terminal: &Terminal<TestBackend>) -> Vec<(usize, usize)> {
        let buffer = terminal.backend().buffer();
        let mark = Theme::default().selection().bg;
        (0..buffer.area.height)
            .filter_map(|y| {
                (0..buffer.area.width)
                    .find(|&x| buffer[(x, y)].style().bg == mark)
                    .map(|x| (usize::from(y), usize::from(x)))
            })
            .collect()
    }

    fn line_of(terminal: &Terminal<TestBackend>, y: usize) -> String {
        lines(terminal)[y].clone()
    }

    fn row_of(terminal: &Terminal<TestBackend>, needle: &str) -> usize {
        at(&lines(terminal), needle).0
    }

    fn key(i: &mut Interaction, state: &AppState, code: KeyCode, modifiers: KeyModifiers) {
        i.handle_key(KeyEvent::new(code, modifiers), state);
    }

    fn ctrl(i: &mut Interaction, state: &AppState, c: char) {
        key(i, state, KeyCode::Char(c), KeyModifiers::CONTROL);
    }

    fn view(state: &AppState, i: &mut Interaction) -> Terminal<TestBackend> {
        screen(state, i, None, 110, 24)
    }

    fn on_ports() -> (AppState, Interaction) {
        let state = busy();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('3'));
        (state, i)
    }

    #[test]
    fn the_focused_listening_ports_pane_highlights_a_row_that_j_moves_and_scrolls_with_a_fixed_header()
     {
        let (state, mut i) = on_ports();
        let t = view(&state, &mut i);
        let header = row_of(&t, "BIND     PORT");
        assert_eq!(marked(&t), vec![(header + 1, 2)], "first row selected");
        assert!(line_of(&t, header + 1).contains("1001/tcp"));
        press(&mut i, &state, KeyCode::Char('j'));
        let t = view(&state, &mut i);
        assert_eq!(marked(&t), vec![(header + 2, 2)]);
        assert!(line_of(&t, header + 2).contains("1002/tcp"));
        // Down to the fourth row, the last the pane shows: no scrolling yet.
        press(&mut i, &state, KeyCode::Char('j'));
        press(&mut i, &state, KeyCode::Char('j'));
        let t = view(&state, &mut i);
        assert_eq!(marked(&t), vec![(header + 4, 2)]);
        assert!(
            line_of(&t, header + 1).contains("1001/tcp"),
            "no scroll yet"
        );
        // One more passes the last visible row: the list scrolls by one.
        press(&mut i, &state, KeyCode::Char('j'));
        let t = view(&state, &mut i);
        assert_eq!(marked(&t), vec![(header + 4, 2)]);
        assert!(line_of(&t, header + 4).contains("1005/tcp"));
        assert!(line_of(&t, header + 1).contains("1002/tcp"));
        assert_eq!(row_of(&t, "BIND     PORT"), header, "header stays");
        assert!(
            lines(&t)[header + 5].contains("+5 more"),
            "{}",
            lines(&t)[header + 5]
        );
        // G: the tenth port on the pane's last row; g: back to the first.
        press(&mut i, &state, KeyCode::Char('G'));
        let t = view(&state, &mut i);
        assert_eq!(marked(&t), vec![(header + 4, 2)]);
        assert!(line_of(&t, header + 4).contains("1010/tcp"));
        let left: String = lines(&t)[header + 5]
            .chars()
            .take(MARK_X_RIGHT_PANE)
            .collect();
        assert!(!left.contains("more"), "{left}");
        press(&mut i, &state, KeyCode::Char('g'));
        let t = view(&state, &mut i);
        assert_eq!(marked(&t), vec![(header + 1, 2)]);
        assert!(line_of(&t, header + 1).contains("1001/tcp"));
    }

    #[test]
    fn on_the_overview_half_page_page_and_home_end_keys_move_as_on_the_ports_pane() {
        // The pane shows four rows: half is two.
        let (state, mut i) = on_ports();
        let header = row_of(&view(&state, &mut i), "BIND     PORT");
        let selected_port = |t: &Terminal<TestBackend>| {
            let m = marked(t);
            assert_eq!(m.len(), 1, "{m:?}");
            line_of(t, m[0].0)
        };
        ctrl(&mut i, &state, 'd');
        assert!(selected_port(&view(&state, &mut i)).contains("1003/tcp"));
        ctrl(&mut i, &state, 'u');
        assert!(selected_port(&view(&state, &mut i)).contains("1001/tcp"));
        press(&mut i, &state, KeyCode::PageDown);
        press(&mut i, &state, KeyCode::PageDown);
        assert!(selected_port(&view(&state, &mut i)).contains("1005/tcp"));
        press(&mut i, &state, KeyCode::PageUp);
        assert!(selected_port(&view(&state, &mut i)).contains("1003/tcp"));
        press(&mut i, &state, KeyCode::End);
        let t = view(&state, &mut i);
        assert_eq!(marked(&t), vec![(header + 4, 2)]);
        assert!(selected_port(&t).contains("1010/tcp"));
        ctrl(&mut i, &state, 'd');
        assert!(
            selected_port(&view(&state, &mut i)).contains("1010/tcp"),
            "stops at the end"
        );
        press(&mut i, &state, KeyCode::Home);
        assert!(selected_port(&view(&state, &mut i)).contains("1001/tcp"));
        ctrl(&mut i, &state, 'u');
        assert!(
            selected_port(&view(&state, &mut i)).contains("1001/tcp"),
            "stops at the top"
        );
    }

    #[test]
    fn moving_focus_shows_the_pane_left_behind_from_its_first_rows_and_starts_the_new_one_on_its_first()
     {
        for leave in [
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Char('4'),
            KeyCode::Char('1'),
        ] {
            let (state, mut i) = on_ports();
            press(&mut i, &state, KeyCode::Char('G'));
            let t = view(&state, &mut i);
            assert!(!lines(&t).join("\n").contains("1001/tcp"), "scrolled");
            press(&mut i, &state, leave);
            let t = view(&state, &mut i);
            let all = lines(&t).join("\n");
            assert!(
                all.contains("1001/tcp") && all.contains("1004/tcp"),
                "{leave:?}:\n{all}"
            );
            assert!(!all.contains("1010/tcp"), "{leave:?}");
            let rows = marked(&t);
            if i.focus() == Pane::FirewallRules {
                let header = row_of(&t, "ACTION");
                assert_eq!(rows.len(), 1, "{rows:?}");
                assert_eq!(rows[0].0, header + 1);
                assert!(rows[0].1 >= MARK_X_RIGHT_PANE);
                assert!(line_of(&t, rows[0].0).contains("2001"));
            } else if i.focus() == Pane::Bandwidth {
                assert!(rows.is_empty(), "{rows:?}");
            }
            // Coming back lands on the first row too.
            press(&mut i, &state, KeyCode::Char('3'));
            let t = view(&state, &mut i);
            let header = row_of(&t, "BIND     PORT");
            assert_eq!(marked(&t), vec![(header + 1, 2)], "{leave:?}");
        }
        // `p` leaves the pane, and the page, and the way back is to the first row.
        let (state, mut i) = on_ports();
        press(&mut i, &state, KeyCode::Char('G'));
        press(&mut i, &state, KeyCode::Char('p'));
        view(&state, &mut i);
        press(&mut i, &state, KeyCode::Char('p'));
        let t = view(&state, &mut i);
        assert_eq!(i.focus(), Pane::ListeningPorts);
        let header = row_of(&t, "BIND     PORT");
        assert_eq!(marked(&t), vec![(header + 1, 2)]);
    }

    #[test]
    fn the_same_keys_move_the_selection_in_every_other_list_pane_and_the_fixed_lines_stay() {
        // (focus key, a word of the header, rows above the first row after the header,
        // lines between the last row and the bottom border)
        for (focus, header_word, below) in [
            ('2', "DESTINATION", 1),
            ('4', "ACTION", 0),
            ('5', "FROM", 0),
            ('6', "DETAIL", 0),
            ('7', "SIGNAL", 0),
            ('8', "ADDRESS", 0),
        ] {
            let state = busy();
            let mut i = Interaction::default();
            press(&mut i, &state, KeyCode::Char(focus));
            let t = view(&state, &mut i);
            let header = row_of(&t, header_word);
            let fixed: Vec<(usize, String)> = lines(&t)
                .into_iter()
                .enumerate()
                .filter(|(_, l)| {
                    l.contains("not attributed")
                        || l.contains("default: deny")
                        || l.contains(header_word)
                })
                .collect();
            let bottom = (header..24)
                .find(|&y| line_of(&t, y).starts_with('╰'))
                .unwrap();
            let rows = marked(&t);
            assert_eq!(rows.len(), 1, "{focus}: {rows:?}\n{}", text_of(&t));
            assert_eq!(rows[0].0, header + 1, "{focus}: first row");
            let first = line_of(&t, header + 1);
            press(&mut i, &state, KeyCode::Char('j'));
            let t = view(&state, &mut i);
            assert_eq!(marked(&t).len(), 1);
            assert_eq!(marked(&t)[0].0, header + 2, "{focus}: j");
            press(&mut i, &state, KeyCode::Char('G'));
            let t = view(&state, &mut i);
            assert_eq!(
                marked(&t).iter().map(|m| m.0).collect::<Vec<_>>(),
                vec![bottom - 1 - below],
                "{focus}: G is on the last row\n{}",
                text_of(&t)
            );
            assert_ne!(line_of(&t, header + 1), first, "{focus}: the list scrolled");
            for (y, line) in &fixed {
                assert_eq!(&line_of(&t, *y), line, "{focus}: fixed line {y} moved");
            }
            press(&mut i, &state, KeyCode::Char('g'));
            let t = view(&state, &mut i);
            assert_eq!(
                marked(&t).iter().map(|m| m.0).collect::<Vec<_>>(),
                vec![header + 1]
            );
            assert_eq!(line_of(&t, header + 1), first, "{focus}: g");
            ctrl(&mut i, &state, 'd');
            let t = view(&state, &mut i);
            assert!(
                marked(&t)[0].0 > header + 1 || i.selected() > 0,
                "{focus}: ctrl-d"
            );
        }
    }

    #[test]
    fn app_traffics_plus_n_more_rows_are_selectable_like_any_other() {
        let state = busy();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('2'));
        for _ in 0..3 {
            press(&mut i, &state, KeyCode::Char('j'));
        }
        let t = view(&state, &mut i);
        let m = marked(&t);
        assert_eq!(m.len(), 1);
        assert!(line_of(&t, m[0].0).contains("+2 more"), "{}", text_of(&t));
        press(&mut i, &state, KeyCode::Char('G'));
        let t = view(&state, &mut i);
        assert!(
            line_of(&t, marked(&t)[0].0).contains("syncthing"),
            "{}",
            text_of(&t)
        );
    }

    #[test]
    fn bandwidth_has_no_rows_and_the_keys_change_nothing() {
        let state = busy();
        let mut i = Interaction::default();
        let before = text_of(&view(&state, &mut i));
        for code in [
            KeyCode::Char('j'),
            KeyCode::Char('G'),
            KeyCode::End,
            KeyCode::PageDown,
        ] {
            press(&mut i, &state, code);
            ctrl(&mut i, &state, 'd');
            let t = view(&state, &mut i);
            assert!(marked(&t).is_empty(), "{code:?}");
            assert_eq!(text_of(&t), before);
        }
        assert_eq!(i.selected(), 0);
        press(&mut i, &state, KeyCode::Char('3'));
        let t = view(&state, &mut i);
        let header = row_of(&t, "BIND     PORT");
        assert_eq!(marked(&t), vec![(header + 1, 2)], "nothing carried over");
    }

    #[test]
    fn zoom_opens_on_the_first_row_and_esc_returns_to_the_overview_on_the_first_row() {
        let (state, mut i) = on_ports();
        press(&mut i, &state, KeyCode::Char('G'));
        view(&state, &mut i);
        press(&mut i, &state, KeyCode::Enter);
        let t = view(&state, &mut i);
        assert_eq!(i.selected(), 0);
        assert!(line_of(&t, marked(&t)[0].0).contains("1001/tcp"));
        press(&mut i, &state, KeyCode::Char('j'));
        press(&mut i, &state, KeyCode::Char('j'));
        view(&state, &mut i);
        press(&mut i, &state, KeyCode::Esc);
        let t = view(&state, &mut i);
        let header = row_of(&t, "BIND     PORT");
        assert_eq!(marked(&t), vec![(header + 1, 2)]);
    }

    #[test]
    fn the_search_field_takes_the_movement_keys_and_a_changed_search_returns_to_the_first_row() {
        let (state, mut i) = on_ports();
        for _ in 0..3 {
            press(&mut i, &state, KeyCode::Char('j'));
        }
        view(&state, &mut i);
        assert_eq!(i.selected(), 3);
        press(&mut i, &state, KeyCode::Char('/'));
        type_text(&mut i, &state, "gGjk");
        assert_eq!(i.search(Pane::ListeningPorts), "gGjk", "typed, not moved");
        press(&mut i, &state, KeyCode::Backspace);
        press(&mut i, &state, KeyCode::Backspace);
        press(&mut i, &state, KeyCode::Backspace);
        press(&mut i, &state, KeyCode::Backspace);
        press(&mut i, &state, KeyCode::Char('1'));
        press(&mut i, &state, KeyCode::Enter);
        let t = view(&state, &mut i);
        assert_eq!(i.selected(), 0, "the search changed");
        let header = row_of(&t, "BIND     PORT");
        assert_eq!(marked(&t), vec![(header + 1, 2)]);
        // Move, then clear the search with Esc: back to the first row.
        press(&mut i, &state, KeyCode::Char('j'));
        view(&state, &mut i);
        assert_eq!(i.selected(), 1);
        press(&mut i, &state, KeyCode::Esc);
        view(&state, &mut i);
        assert_eq!(i.search(Pane::ListeningPorts), "");
        assert_eq!(i.selected(), 0);
        // A move with no search to clear leaves the selection where it is.
        press(&mut i, &state, KeyCode::Char('j'));
        press(&mut i, &state, KeyCode::Esc);
        view(&state, &mut i);
        assert_eq!(i.selected(), 1);
    }

    #[test]
    fn a_changed_search_returns_the_selection_to_the_first_row_in_zoom_too() {
        let (state, mut i) = on_ports();
        press(&mut i, &state, KeyCode::Enter);
        for _ in 0..4 {
            press(&mut i, &state, KeyCode::Char('j'));
        }
        view(&state, &mut i);
        assert_eq!(i.selected(), 4);
        press(&mut i, &state, KeyCode::Char('/'));
        press(&mut i, &state, KeyCode::Char('1'));
        view(&state, &mut i);
        assert_eq!(i.selected(), 0);
    }

    #[test]
    fn the_selection_keeps_its_place_by_position_when_rows_are_added_or_removed() {
        let (mut state, mut i) = on_ports();
        for _ in 0..6 {
            press(&mut i, &state, KeyCode::Char('j'));
        }
        view(&state, &mut i);
        assert_eq!(i.selected(), 6);
        // Four ports go: the selection is held within the six that are left.
        state.record_listeners(
            (1..=6)
                .map(|n| listener(1000 + n, "0.0.0.0", None))
                .collect(),
            32_768..=60_999,
        );
        let t = view(&state, &mut i);
        assert_eq!(i.selected(), 5);
        assert!(line_of(&t, marked(&t)[0].0).contains("1006/tcp"));
        // Ports come: the position stays.
        state.record_listeners(
            (1..=10)
                .map(|n| listener(1000 + n, "0.0.0.0", None))
                .collect(),
            32_768..=60_999,
        );
        let t = view(&state, &mut i);
        assert_eq!(i.selected(), 5);
        assert!(line_of(&t, marked(&t)[0].0).contains("1006/tcp"));
    }
}

mod connection_title {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use crosswalk::{
        collect::interfaces::{
            CollectionHealth, InterfaceAddress, InterfaceMeasurement, InterfaceSnapshot,
            InterfaceStatus,
        },
        state::{AppState, Pane, StateLimits},
        ui::{Interaction, Overview, Theme, draw_bandwidth, draw_interactive},
    };
    use ratatui::{Terminal, backend::TestBackend, layout::Rect};

    fn address(text: &str, prefix: u8) -> InterfaceAddress {
        InterfaceAddress {
            ip: text.parse().unwrap(),
            prefix,
        }
    }

    fn state_with(
        interfaces: Vec<(&str, Vec<InterfaceAddress>)>,
        default_route: Option<&str>,
        gateway: Option<&str>,
        name_server: Option<&str>,
    ) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.advance_time(Duration::from_secs(1));
        state.record_interfaces(InterfaceSnapshot {
            health: CollectionHealth::Available,
            interfaces: interfaces
                .into_iter()
                .map(|(name, addresses)| InterfaceMeasurement {
                    name: name.into(),
                    addresses,
                    download_bytes_per_second: 10.0,
                    upload_bytes_per_second: 10.0,
                    session_received_bytes: 10,
                    session_transmitted_bytes: 10,
                    status: InterfaceStatus::Available,
                    is_up: true,
                })
                .collect(),
            default_route: default_route.map(Into::into),
            gateway: gateway.map(|g| g.parse::<Ipv4Addr>().unwrap()),
            name_server: name_server.map(|n| n.parse::<IpAddr>().unwrap()),
            name_servers: vec![],
        });
        state
    }

    fn sample() -> AppState {
        state_with(
            vec![
                (
                    "wlan0",
                    vec![
                        address("10.0.1.13", 24),
                        address("fd6d::8385", 64),
                        address("fe80::268a", 64),
                    ],
                ),
                ("eth0", vec![address("192.168.1.5", 24)]),
            ],
            Some("wlan0"),
            Some("10.0.1.1"),
            Some("10.0.1.6"),
        )
    }

    fn title_row(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .find(|line| line.contains("BANDWIDTH"))
            .unwrap()
    }

    fn title(state: &AppState, width: u16) -> String {
        title_row(&super::draw_at(state, width, 24))
    }

    /// The Bandwidth pane alone, drawn into an area `width` wide.
    fn title_in_pane(state: &AppState, width: u16, search: &str) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, 6)).unwrap();
        terminal
            .draw(|f| {
                let view = Overview::new(Pane::Bandwidth).search(Pane::Bandwidth, search);
                draw_bandwidth(
                    f,
                    Rect::new(0, 0, width, 6),
                    state,
                    &Theme::default(),
                    &view,
                )
            })
            .unwrap();
        title_row(&terminal)
    }

    #[test]
    fn the_title_reads_name_address_gateway_and_name_server() {
        assert!(
            title(&sample(), 110)
                .contains("BANDWIDTH · wlan0 · 10.0.1.13/24 · gw 10.0.1.1 · dns 10.0.1.6 "),
        );
    }

    #[test]
    fn only_the_interface_name_takes_the_highlight_colour() {
        let theme = Theme::default();
        let terminal = super::draw_at(&sample(), 110, 24);
        let row = title_row(&terminal);
        let y = {
            let buffer = terminal.backend().buffer();
            (0..24u16)
                .find(|&y| {
                    (0..110u16)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                        .contains("BANDWIDTH")
                })
                .unwrap()
        };
        let start = |needle: &str| row[..row.find(needle).unwrap()].chars().count() as u16;
        let buffer = terminal.backend().buffer();
        for x in start("wlan0")..start("wlan0") + 5 {
            assert_eq!(buffer[(x, y)].fg, theme.highlight, "name cell {x}");
        }
        for (needle, length) in [
            ("10.0.1.13/24", 12),
            ("gw 10.0.1.1", 11),
            ("dns 10.0.1.6", 12),
        ] {
            for x in start(needle)..start(needle) + length {
                assert_ne!(buffer[(x, y)].fg, theme.highlight, "{needle} cell {x}");
                assert_eq!(
                    buffer[(x, y)].fg,
                    theme.title(false).fg.unwrap(),
                    "{needle} cell {x}"
                );
            }
        }
    }

    #[test]
    fn an_interface_without_the_default_route_shows_its_address_and_no_gateway() {
        let state = sample();
        let mut i = Interaction::default();
        i.handle_key(
            KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE),
            &state,
        );
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal
            .draw(|f| draw_interactive(f, &state, &Theme::default(), &mut i, None))
            .unwrap();
        let row = title_row(&terminal);
        assert!(
            row.contains("BANDWIDTH · eth0 · 192.168.1.5/24 · dns 10.0.1.6 "),
            "{row}"
        );
        assert!(!row.contains("gw"), "{row}");
    }

    #[test]
    fn an_interface_with_only_ipv6_addresses_shows_the_one_that_is_not_link_local() {
        let state = state_with(
            vec![(
                "wlan0",
                vec![address("fe80::1", 64), address("2001:db8::7", 64)],
            )],
            None,
            None,
            None,
        );
        let row = title(&state, 110);
        assert!(row.contains("BANDWIDTH · wlan0 · 2001:db8::7/64 "), "{row}");
        let only_local = state_with(
            vec![("wlan0", vec![address("fe80::1", 64)])],
            None,
            None,
            None,
        );
        assert!(title(&only_local, 110).contains("BANDWIDTH · wlan0 · fe80::1/64 "));
    }

    #[test]
    fn with_nothing_known_the_title_is_as_before() {
        let state = state_with(vec![("wlan0", vec![])], None, None, None);
        let row = title(&state, 110);
        assert!(row.contains("BANDWIDTH · wlan0 ─"), "{row}");
    }

    fn longest() -> AppState {
        state_with(
            vec![("abcdefghijklmno", vec![address("255.255.255.255", 32)])],
            Some("abcdefghijklmno"),
            Some("255.255.255.255"),
            Some("255.255.255.255"),
        )
    }

    #[test]
    fn the_longest_values_fit_at_110_columns() {
        let row = title(&longest(), 110);
        assert!(
            row.contains(
                "BANDWIDTH · abcdefghijklmno · 255.255.255.255/32 · gw 255.255.255.255 · dns 255.255.255.255 "
            ),
            "{row}"
        );
    }

    #[test]
    fn in_a_narrower_pane_parts_drop_from_the_right_whole() {
        // The full title is 93 cells and the border leaves width - 2.
        let state = longest();
        let row = title_in_pane(&state, 90, "");
        assert!(
            row.contains("255.255.255.255/32 · gw 255.255.255.255 "),
            "{row}"
        );
        assert!(!row.contains("dns"), "{row}");
        let row = title_in_pane(&state, 70, "");
        assert!(
            row.contains("abcdefghijklmno · 255.255.255.255/32 "),
            "{row}"
        );
        assert!(!row.contains("gw") && !row.contains("dns"), "{row}");
        let row = title_in_pane(&state, 50, "");
        assert!(row.contains("BANDWIDTH · abcdefghijklmno "), "{row}");
        assert!(!row.contains("255."), "{row}");
    }

    #[test]
    fn the_search_text_keeps_its_place_when_parts_drop() {
        let row = title_in_pane(&longest(), 70, "ab");
        assert!(row.contains("255.255.255.255/32 /ab "), "{row}");
        assert!(!row.contains("gw") && !row.contains("dns"), "{row}");
    }

    #[test]
    fn i_shows_the_next_interfaces_values() {
        let state = sample();
        let mut i = Interaction::default();
        let row = |i: &mut Interaction| {
            let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
            terminal
                .draw(|f| draw_interactive(f, &state, &Theme::default(), i, None))
                .unwrap();
            title_row(&terminal)
        };
        assert!(row(&mut i).contains("wlan0 · 10.0.1.13/24 · gw 10.0.1.1"));
        i.handle_key(
            KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE),
            &state,
        );
        let second = row(&mut i);
        assert!(second.contains("eth0 · 192.168.1.5/24"), "{second}");
        assert!(!second.contains("10.0.1.13"), "{second}");
    }
}

mod bandwidth_totals {
    use std::time::Duration;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use crosswalk::{
        collect::interfaces::{
            CollectionHealth, InterfaceMeasurement, InterfaceSnapshot, InterfaceStatus,
        },
        state::{AppState, Pane, StateLimits},
        ui::{Interaction, Overview, Theme, draw, draw_bandwidth, draw_interactive},
    };
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer, layout::Rect, style::Color};

    /// Each interface is (name, bytes sent, bytes received); the first carries the default route.
    fn state_with(interfaces: &[(&str, u64, u64)]) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        for second in 0..120u64 {
            state.advance_time(Duration::from_secs(second));
            state.record_interfaces(InterfaceSnapshot {
                health: CollectionHealth::Available,
                interfaces: interfaces
                    .iter()
                    .map(|&(name, sent, received)| InterfaceMeasurement {
                        name: name.into(),
                        addresses: vec![],
                        download_bytes_per_second: 1.0e5 + (second % 7) as f64 * 1.0e5,
                        upload_bytes_per_second: 2.0e4 + (second % 5) as f64 * 1.0e4,
                        session_received_bytes: received,
                        session_transmitted_bytes: sent,
                        status: InterfaceStatus::Available,
                        is_up: true,
                    })
                    .collect(),
                default_route: Some(interfaces[0].0.into()),
                gateway: None,
                name_server: None,
                name_servers: vec![],
            });
        }
        state
    }

    fn overview(state: &AppState) -> Terminal<TestBackend> {
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal
            .draw(|f| draw(f, state, &Theme::default(), &Overview::new(Pane::Bandwidth)))
            .unwrap();
        terminal
    }

    fn row_text(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect()
    }

    fn row_of(buffer: &Buffer, needle: &str) -> u16 {
        (0..buffer.area.height)
            .find(|&y| row_text(buffer, y).contains(needle))
            .unwrap_or_else(|| panic!("no {needle:?} in the buffer"))
    }

    /// The pane's right edge: the last padded inner column at 110 columns.
    const LAST: u16 = 107;
    /// The bar's 16 cells.
    const BAR: std::ops::RangeInclusive<u16> = (LAST - 15)..=LAST;

    fn bar_colours(buffer: &Buffer, y: u16) -> Vec<Color> {
        BAR.map(|x| {
            assert_eq!(buffer[(x, y)].symbol(), "█", "bar cell ({x},{y})");
            buffer[(x, y)].fg
        })
        .collect()
    }

    fn split(outbound: usize, inbound: usize) -> Vec<Color> {
        let theme = Theme::default();
        let mut cells = vec![theme.outbound; outbound];
        cells.extend(vec![theme.inbound; inbound]);
        cells
    }

    #[test]
    fn the_first_row_ends_with_the_bytes_sent_and_the_last_with_the_bytes_received() {
        let theme = Theme::default();
        let terminal = overview(&state_with(&[("eth0", 1_200_000_000, 8_400_000_000)]));
        let buffer = terminal.backend().buffer();
        let first = row_of(buffer, "↑ total");
        let last = row_of(buffer, "↓ total");
        assert!(
            row_text(buffer, first - 1).contains("BANDWIDTH"),
            "first inner row"
        );
        assert!(row_text(buffer, last + 1).contains('╰'), "last inner row");
        let up = row_text(buffer, first);
        let down = row_text(buffer, last);
        let tail = |text: &str| text.chars().take(LAST as usize + 1).collect::<String>();
        assert!(tail(&up).ends_with("↑ total   1.2 GB"), "{up}");
        assert!(tail(&down).ends_with("↓ total   8.4 GB"), "{down}");
        for x in (LAST - 15)..=LAST {
            if buffer[(x, first)].symbol() != " " {
                assert_eq!(buffer[(x, first)].fg, theme.outbound, "({x},{first})");
            }
            if buffer[(x, last)].symbol() != " " {
                assert_eq!(buffer[(x, last)].fg, theme.inbound, "({x},{last})");
            }
        }
    }

    #[test]
    fn the_centre_row_ends_with_a_bar_split_by_the_totals() {
        let terminal = overview(&state_with(&[("eth0", 1_200_000_000, 8_400_000_000)]));
        let buffer = terminal.backend().buffer();
        let centre = (row_of(buffer, "↑ total") + row_of(buffer, "↓ total")) / 2;
        assert_eq!(bar_colours(buffer, centre), split(2, 14));
        assert_eq!(buffer[(LAST - 17, centre)].symbol(), " ");
        assert_eq!(buffer[(LAST - 16, centre)].symbol(), " ");
    }

    #[test]
    fn a_side_that_carried_anything_keeps_one_cell() {
        let terminal = overview(&state_with(&[("eth0", 1_000, 8_400_000_000)]));
        let buffer = terminal.backend().buffer();
        let centre = (row_of(buffer, "↑ total") + row_of(buffer, "↓ total")) / 2;
        assert_eq!(bar_colours(buffer, centre), split(1, 15));
        let terminal = overview(&state_with(&[("eth0", 8_400_000_000, 1_000)]));
        let buffer = terminal.backend().buffer();
        let centre = (row_of(buffer, "↑ total") + row_of(buffer, "↓ total")) / 2;
        assert_eq!(bar_colours(buffer, centre), split(15, 1));
    }

    #[test]
    fn with_nothing_carried_the_bar_and_both_totals_are_muted() {
        let theme = Theme::default();
        let terminal = overview(&state_with(&[("eth0", 0, 0)]));
        let buffer = terminal.backend().buffer();
        let (first, last) = (row_of(buffer, "↑ total"), row_of(buffer, "↓ total"));
        let centre = (first + last) / 2;
        assert_eq!(bar_colours(buffer, centre), vec![theme.muted; 16]);
        for y in [first, last] {
            for x in 90..=LAST {
                if buffer[(x, y)].symbol() != " " {
                    assert_eq!(buffer[(x, y)].fg, theme.muted, "({x},{y})");
                }
            }
        }
        assert!(row_text(buffer, first).contains("0 B"));
    }

    #[test]
    fn a_total_of_zero_is_muted_and_the_other_is_not() {
        let theme = Theme::default();
        let terminal = overview(&state_with(&[("eth0", 0, 5_000_000)]));
        let buffer = terminal.backend().buffer();
        let (first, last) = (row_of(buffer, "↑ total"), row_of(buffer, "↓ total"));
        assert_eq!(buffer[(LAST, first)].fg, theme.muted);
        assert_eq!(buffer[(LAST, last)].fg, theme.inbound);
        assert_eq!(bar_colours(buffer, (first + last) / 2), split(0, 16));
    }

    #[test]
    fn the_plot_is_70_columns_and_the_left_gutter_reads_as_before() {
        let terminal = overview(&state_with(&[("eth0", 1_200_000_000, 8_400_000_000)]));
        let buffer = terminal.backend().buffer();
        let centre = row_of(buffer, "↓ in") - 1;
        let line = row_text(buffer, centre);
        assert_eq!(line.chars().filter(|&c| c == '─').count(), 70, "{line}");
        assert_eq!(buffer[(20, centre)].symbol(), "─");
        assert_eq!(buffer[(89, centre)].symbol(), "─");
        assert_eq!(buffer[(90, centre)].symbol(), " ");
        let first = row_text(buffer, row_of(buffer, "↑ out"));
        assert!(first.contains("│ ↑ out"), "{first}");
        assert!(row_text(buffer, row_of(buffer, "↑ out") + 1).contains("peak"));
    }

    #[test]
    fn i_shows_the_next_interfaces_totals_and_bar() {
        let state = state_with(&[
            ("eth0", 1_200_000_000, 8_400_000_000),
            ("wlan0", 4_000_000, 4_000_000),
        ]);
        let mut interaction = Interaction::default();
        let draw_it = |interaction: &mut Interaction| {
            let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
            terminal
                .draw(|f| draw_interactive(f, &state, &Theme::default(), interaction, None))
                .unwrap();
            terminal
        };
        let terminal = draw_it(&mut interaction);
        let buffer = terminal.backend().buffer();
        assert!(row_text(buffer, row_of(buffer, "↑ total")).contains("1.2 GB"));
        interaction.handle_key(
            KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE),
            &state,
        );
        let terminal = draw_it(&mut interaction);
        let buffer = terminal.backend().buffer();
        let (first, last) = (row_of(buffer, "↑ total"), row_of(buffer, "↓ total"));
        assert!(row_text(buffer, first).contains("4.0 MB"));
        assert!(row_text(buffer, last).contains("4.0 MB"));
        assert!(!row_text(buffer, first).contains("1.2 GB"));
        assert_eq!(bar_colours(buffer, (first + last) / 2), split(8, 8));
    }

    #[test]
    fn zoom_draws_the_gutter_and_its_totals_equal_the_plotted_rows_in_the_table() {
        let state = state_with(&[
            ("eth0", 1_200_000_000, 8_400_000_000),
            ("wlan0", 4_000_000, 4_000_000),
        ]);
        let mut interaction = Interaction::default();
        for code in [KeyCode::Char('1'), KeyCode::Enter] {
            interaction.handle_key(KeyEvent::new(code, KeyModifiers::NONE), &state);
        }
        let mut terminal = Terminal::new(TestBackend::new(110, 32)).unwrap();
        terminal
            .draw(|f| draw_interactive(f, &state, &Theme::default(), &mut interaction, None))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let (first, last) = (row_of(buffer, "↑ total"), row_of(buffer, "↓ total"));
        assert!(first < last);
        assert!(row_text(buffer, first).contains("1.2 GB"));
        assert!(row_text(buffer, last).contains("8.4 GB"));
        let table_row = (0..buffer.area.height)
            .map(|y| row_text(buffer, y))
            .find(|l| l.contains('▶'))
            .unwrap();
        assert!(
            table_row.contains("8.4 GB") && table_row.contains("1.2 GB"),
            "{table_row}"
        );
        assert_eq!(
            bar_colours(buffer, row_of(buffer, "↓ in") - 1),
            split(2, 14)
        );
    }

    #[test]
    fn in_a_pane_55_columns_wide_the_right_gutter_is_left_out() {
        let state = state_with(&[("eth0", 1_200_000_000, 8_400_000_000)]);
        let mut terminal = Terminal::new(TestBackend::new(55, 11)).unwrap();
        terminal
            .draw(|f| {
                draw_bandwidth(
                    f,
                    Rect::new(0, 0, 55, 11),
                    &state,
                    &Theme::default(),
                    &Overview::new(Pane::Bandwidth),
                )
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text: String = (0..11).map(|y| row_text(buffer, y)).collect();
        assert!(!text.contains("total"), "{text}");
        let centre = row_of(buffer, "↓ in") - 1;
        // 55 less the border and padding is 51; the gutter takes 18, the plot the rest.
        assert_eq!(
            row_text(buffer, centre)
                .chars()
                .filter(|&c| c == '─')
                .count(),
            33
        );
    }
}

mod steady_columns {
    use std::{path::PathBuf, time::Duration};

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use crosswalk::{
        collect::{
            attribution::{ExecutableIdentity, ProcessIdentity},
            capture::{Direction, Endpoint, Protocol, TrafficEvent},
            interfaces::{
                CollectionHealth, InterfaceMeasurement, InterfaceSnapshot, InterfaceStatus,
            },
        },
        state::{AppState, Pane, StateLimits},
        ui::{Interaction, Overview, Theme, draw, draw_interactive},
    };
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};

    /// One destination: its port and protocol, and the bytes it moved in the
    /// current second (`rate`, down and up) and before it (`earlier`, down).
    struct Destination {
        port: u16,
        protocol: Protocol,
        rate: u32,
        earlier: u64,
    }

    const TOP: Destination = Destination {
        port: 65_535,
        protocol: Protocol::Udp,
        rate: 999_900_000,
        earlier: 997_900_200_000,
    };

    fn tcp(port: u16) -> Destination {
        Destination {
            port,
            protocol: Protocol::Tcp,
            rate: 0,
            earlier: 100,
        }
    }

    fn packet(
        state: &mut AppState,
        at: u64,
        ip: &str,
        d: &Destination,
        bytes: u32,
        dir: Direction,
    ) {
        let local = Endpoint {
            ip: "192.0.2.10".parse().unwrap(),
            port: Some(51_000),
        };
        let remote = Endpoint {
            ip: ip.parse().unwrap(),
            port: Some(d.port),
        };
        let (source, destination) = match dir {
            Direction::Outbound => (local, remote),
            Direction::Inbound => (remote, local),
        };
        let owner = ProcessIdentity {
            executable: ExecutableIdentity {
                path: PathBuf::from("/usr/bin/curl"),
            },
            pid: 4_321,
            start_time: 1,
            network_namespace: 7,
        };
        state.record_traffic(
            Duration::from_secs(at),
            TrafficEvent {
                source,
                destination,
                protocol: d.protocol,
                direction: dir,
                original_ip_bytes: bytes,
                limitation: None,
                tcp_flags: None,
                timing: None,
            },
            Some(owner),
        );
    }

    fn app_state(destinations: &[Destination]) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        for (n, d) in destinations.iter().enumerate() {
            let ip = format!("198.51.100.{}", n + 1);
            let mut left = d.earlier;
            while left > 0 {
                let bytes = left.min(4_000_000_000) as u32;
                packet(&mut state, 1, &ip, d, bytes, Direction::Inbound);
                left -= u64::from(bytes);
            }
            if d.rate > 0 {
                packet(&mut state, 100, &ip, d, d.rate, Direction::Inbound);
                packet(&mut state, 100, &ip, d, d.rate, Direction::Outbound);
            }
        }
        state.advance_time(Duration::from_secs(100));
        state
    }

    fn interface_state(rate: f64, total: u64) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        for second in 0..5u64 {
            state.advance_time(Duration::from_secs(second));
            state.record_interfaces(InterfaceSnapshot {
                health: CollectionHealth::Available,
                interfaces: vec![InterfaceMeasurement {
                    name: "eth0".into(),
                    addresses: vec![],
                    download_bytes_per_second: rate,
                    upload_bytes_per_second: rate,
                    session_received_bytes: total,
                    session_transmitted_bytes: total,
                    status: InterfaceStatus::Available,
                    is_up: true,
                }],
                default_route: Some("eth0".into()),
                gateway: None,
                name_server: None,
                name_servers: vec![],
            });
        }
        state
    }

    fn row_text(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect()
    }

    fn overview(state: &AppState) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal
            .draw(|f| {
                draw(
                    f,
                    state,
                    &Theme::default(),
                    &Overview::new(Pane::AppTraffic),
                )
            })
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn zoom(state: &AppState, key: char) -> Buffer {
        let mut interaction = Interaction::default();
        for code in [KeyCode::Char(key), KeyCode::Enter] {
            interaction.handle_key(KeyEvent::new(code, KeyModifiers::NONE), state);
        }
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal
            .draw(|f| draw_interactive(f, state, &Theme::default(), &mut interaction, None))
            .unwrap();
        terminal.backend().buffer().clone()
    }

    /// The header line holding `marker` and where each title starts in it.
    fn starts(buffer: &Buffer, marker: &str, titles: &[&str]) -> (u16, Vec<usize>) {
        let y = (0..buffer.area.height)
            .find(|&y| row_text(buffer, y).contains(marker))
            .unwrap_or_else(|| panic!("no {marker:?} header"));
        let line = row_text(buffer, y);
        let at = titles
            .iter()
            .map(|t| {
                let byte = line
                    .find(t)
                    .unwrap_or_else(|| panic!("no {t:?} in {line:?}"));
                line[..byte].chars().count()
            })
            .collect();
        (y, at)
    }

    fn assert_same(quiet: &Buffer, busy: &Buffer, marker: &str, titles: &[&str]) {
        let (_, a) = starts(quiet, marker, titles);
        let (_, b) = starts(busy, marker, titles);
        for (n, title) in titles.iter().enumerate() {
            assert_eq!(a[n], b[n], "{title} starts at {} then at {}", a[n], b[n]);
        }
    }

    #[test]
    fn app_traffic_titles_hold_still_as_the_numbers_grow() {
        let quiet = overview(&app_state(&[tcp(443)]));
        let busy = overview(&app_state(&[tcp(443), TOP]));
        assert_same(
            &quiet,
            &busy,
            "DESTINATION",
            &["PORT", "↓ IN", "↑ OUT", "TOTAL"],
        );
    }

    #[test]
    fn zoomed_app_traffic_titles_hold_still_as_the_numbers_grow() {
        let quiet = zoom(&app_state(&[tcp(443)]), '2');
        let busy = zoom(&app_state(&[tcp(443), TOP]), '2');
        assert_same(
            &quiet,
            &busy,
            "DESTINATION",
            &["PORT", "↓ IN", "↑ OUT", "↓ TOTAL", "↑ TOTAL"],
        );
    }

    #[test]
    fn the_interface_tables_titles_hold_still_as_the_numbers_grow() {
        let quiet = zoom(&interface_state(0.0, 0), '1');
        let busy = zoom(&interface_state(999.9e6, 999_900_000_000), '1');
        assert_same(
            &quiet,
            &busy,
            "↓ TOTAL",
            &["↓ IN", "↑ OUT", "↓ TOTAL", "↑ TOTAL"],
        );
    }

    #[test]
    fn app_traffic_port_title_holds_still_when_a_longer_port_appears() {
        let short = overview(&app_state(&[tcp(443), tcp(80)]));
        let long = overview(&app_state(&[
            tcp(443),
            Destination {
                port: 65_535,
                ..tcp(0)
            },
        ]));
        assert_same(&short, &long, "DESTINATION", &["PORT"]);
    }

    #[test]
    fn numbers_stay_right_aligned_and_the_last_column_ends_at_the_pane_edge() {
        for state in [app_state(&[tcp(443)]), app_state(&[tcp(443), TOP])] {
            let buffer = overview(&state);
            let (y, _) = starts(&buffer, "DESTINATION", &["TOTAL"]);
            for row in [y, y + 1] {
                let line = row_text(&buffer, row);
                let cells: Vec<char> = line.chars().collect();
                assert_ne!(cells[107], ' ', "{line:?}");
                assert_eq!(cells[108], ' ', "{line:?}");
            }
        }
    }
}

mod moves {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use crosswalk::ui::{Interaction, draw_interactive};

    /// Ports 1001, 1002, … , each its own row in Listening Ports.
    fn state_with_ports(count: u16) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let listeners = (1..=count)
            .map(|n| Listener {
                protocol: Protocol::Tcp,
                address: "0.0.0.0".parse().unwrap(),
                port: 1000 + n,
                owners: vec![],
            })
            .collect();
        state.record_listeners(listeners, 32_768..=60_999);
        state
    }

    fn press(i: &mut Interaction, state: &AppState, code: KeyCode) {
        i.handle_key(KeyEvent::new(code, KeyModifiers::NONE), state);
        screen(state, i);
    }

    fn press_ctrl(i: &mut Interaction, state: &AppState, c: char) {
        i.handle_key(
            KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL),
            state,
        );
        screen(state, i);
    }

    fn screen(state: &AppState, i: &mut Interaction) -> Terminal<TestBackend> {
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal
            .draw(|frame| draw_interactive(frame, state, &Theme::default(), i, None))
            .unwrap();
        terminal
    }

    /// The text of every line that has a highlighted cell.
    fn highlighted(terminal: &Terminal<TestBackend>) -> Vec<String> {
        let buffer = terminal.backend().buffer();
        let mark = Theme::default().selection().bg;
        (0..buffer.area.height)
            .filter(|&y| (0..buffer.area.width).any(|x| buffer[(x, y)].style().bg == mark))
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect()
            })
            .collect()
    }

    fn zoomed_ports(count: u16) -> (AppState, Interaction) {
        let state = state_with_ports(count);
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('3'));
        press(&mut i, &state, KeyCode::Enter);
        (state, i)
    }

    #[test]
    fn in_zoom_g_and_home_go_to_the_first_row_and_capital_g_and_end_to_the_last() {
        let (state, mut i) = zoomed_ports(40);
        press(&mut i, &state, KeyCode::Char('G'));
        assert_eq!(i.selected(), 39);
        let marked = highlighted(&screen(&state, &mut i));
        assert!(
            marked.len() == 1 && marked[0].contains("1040/tcp"),
            "{marked:?}"
        );
        press(&mut i, &state, KeyCode::Char('g'));
        assert_eq!(i.selected(), 0);
        let marked = highlighted(&screen(&state, &mut i));
        assert!(marked[0].contains("1001/tcp"), "{marked:?}");
        press(&mut i, &state, KeyCode::End);
        assert_eq!(i.selected(), 39);
        press(&mut i, &state, KeyCode::End);
        assert_eq!(i.selected(), 39, "a move past the end stops there");
        press(&mut i, &state, KeyCode::Home);
        assert_eq!(i.selected(), 0);
        press(&mut i, &state, KeyCode::Home);
        assert_eq!(i.selected(), 0);
    }

    #[test]
    fn in_zoom_ctrl_d_and_page_down_move_half_the_rows_shown_and_ctrl_u_and_page_up_move_back() {
        // 110x24 zoom shows 19 table rows, so half is 9.
        let (state, mut i) = zoomed_ports(40);
        press_ctrl(&mut i, &state, 'd');
        assert_eq!(i.selected(), 9);
        press(&mut i, &state, KeyCode::PageDown);
        assert_eq!(i.selected(), 18);
        press_ctrl(&mut i, &state, 'u');
        assert_eq!(i.selected(), 9);
        press(&mut i, &state, KeyCode::PageUp);
        assert_eq!(i.selected(), 0);
        press(&mut i, &state, KeyCode::PageUp);
        assert_eq!(i.selected(), 0, "a move past the top stops there");
        for _ in 0..6 {
            press_ctrl(&mut i, &state, 'd');
        }
        assert_eq!(i.selected(), 39, "a move past the end stops there");
        let marked = highlighted(&screen(&state, &mut i));
        assert!(
            marked.len() == 1 && marked[0].contains("1040/tcp"),
            "{marked:?}"
        );
    }
}

mod map_drawing {
    use crosswalk::ui::{
        Theme,
        map::{Map, MapBox, MapScroll, draw_map},
    };
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer, layout::Rect};

    fn device(first: &str, second: &str, third: &str) -> MapBox {
        MapBox {
            lines: [first.to_owned(), second.to_owned(), third.to_owned()],
            this_host: false,
            absent: false,
        }
    }

    /// This host and `others` more devices at 10.0.1.20 and up.
    fn map_of(others: usize) -> Map {
        let mut devices = vec![MapBox {
            this_host: true,
            ..device("this host", "10.0.1.13", "Intel")
        }];
        devices.extend(
            (0..others)
                .map(|n| device(&format!("host{n}"), &format!("10.0.1.{}", 20 + n), "Vendor")),
        );
        Map {
            interface: "eth0".to_owned(),
            upstream: vec!["1.1.1.1".parse().unwrap()],
            gateway: Some(device("gateway", "10.0.1.1", "Ubiquiti")),
            label: "eth0".to_owned(),
            devices,
        }
    }

    /// The map in the area below a one-line header on a 110×24 screen.
    fn draw_at(map: Option<&Map>, offset: usize) -> (Buffer, MapScroll) {
        draw_wide(map, offset, 110)
    }

    fn draw_wide(map: Option<&Map>, offset: usize, width: u16) -> (Buffer, MapScroll) {
        let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
        let mut scroll = MapScroll::default();
        terminal
            .draw(|frame| {
                scroll = draw_map(
                    frame,
                    Rect::new(0, 1, width, 22),
                    &Theme::default(),
                    map,
                    offset,
                );
            })
            .unwrap();
        (terminal.backend().buffer().clone(), scroll)
    }

    fn lines(buffer: &Buffer) -> Vec<Vec<String>> {
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol().to_owned())
                    .collect()
            })
            .collect()
    }

    fn text(buffer: &Buffer) -> Vec<String> {
        lines(buffer).iter().map(|l| l.concat()).collect()
    }

    /// Row and column (in cells) of the first occurrence of `needle`.
    fn find(buffer: &Buffer, needle: &str) -> (u16, u16) {
        let rows = text(buffer);
        rows.iter()
            .enumerate()
            .find_map(|(y, row)| {
                row.find(needle)
                    .map(|b| (y as u16, row[..b].chars().count() as u16))
            })
            .unwrap_or_else(|| panic!("missing {needle:?} in:\n{}", rows.join("\n")))
    }

    #[test]
    fn the_title_names_the_interface_and_the_count() {
        let (buffer, _) = draw_at(Some(&map_of(2)), 0);
        assert!(text(&buffer)[1].contains("NETWORK MAP · eth0 · 3 devices"));
        let (buffer, _) = draw_at(Some(&map_of(0)), 0);
        assert!(text(&buffer)[1].contains("NETWORK MAP · eth0 · 1 device "));
    }

    #[test]
    fn no_default_route_is_a_quiet_line() {
        let (buffer, _) = draw_at(None, 0);
        let rows = text(&buffer);
        assert!(rows[1].contains("NETWORK MAP"));
        assert!(rows[2].contains("No default route"));
        assert!(!rows.iter().any(|r| r.contains("┌")));
    }

    #[test]
    fn four_boxes_share_a_row_and_two_rows_show_under_the_gateway() {
        let (buffer, _) = draw_at(Some(&map_of(11)), 0);
        let rows = text(&buffer);
        let (gateway_y, _) = find(&buffer, "gateway");
        let (first_y, _) = find(&buffer, "this host");
        let (second_y, _) = find(&buffer, "host3");
        assert!(gateway_y < first_y && first_y < second_y);
        for name in ["this host", "host0", "host1", "host2"] {
            assert_eq!(find(&buffer, name).0, first_y, "{name}");
        }
        for name in ["host3", "host4", "host5", "host6"] {
            assert_eq!(find(&buffer, name).0, second_y, "{name}");
        }
        assert!(
            !rows.iter().any(|r| r.contains("host7")),
            "third row hidden"
        );
    }

    #[test]
    fn every_device_row_is_joined_to_the_segment_line() {
        let mut map = map_of(11);
        map.label = "eth0 · HomeNet · 5G".to_owned();
        let (buffer, _) = draw_at(Some(&map), 0);
        let cells = lines(&buffer);
        for name in ["this host", "host3"] {
            let (y, x) = find(&buffer, name);
            // The name is on the line under the box's top border.
            let top = usize::from(y) - 1;
            let join = top - 1;
            let box_left = usize::from(x) - 2;
            let centre = box_left + 10;
            assert_eq!(cells[top][centre], "┴", "{name}: box joins up");
            assert!(
                ["┬", "┼"].contains(&cells[join][centre].as_str()),
                "{name}: line above {:?}",
                cells[join][centre]
            );
            // An unbroken line from the left spine to the last box's centre.
            let line = &cells[join];
            let spine = box_left - 2;
            assert!(
                (spine..centre + 22 * 3).all(|c| line[c] != " "),
                "{name}: {}",
                line.concat()
            );
        }
        // The first row's line is joined to the gateway above.
        let (label_y, _) = find(&buffer, "HomeNet");
        let (first_y, _) = find(&buffer, "this host");
        assert_eq!(label_y + 1, first_y - 2);
        assert!(text(&buffer)[usize::from(first_y) - 2].contains('┴'));
    }

    /// The empty cells left and right of everything drawn from the first row's
    /// line down, inside the pane's border.
    fn empty_sides(buffer: &Buffer) -> (u16, u16) {
        let width = buffer.area.width;
        let (host_y, _) = find(buffer, "this host");
        let cells = lines(buffer);
        let mut left = width;
        let mut right = width;
        for row in &cells[usize::from(host_y) - 2..22] {
            let inside = &row[1..usize::from(width) - 1];
            if let Some(first) = inside.iter().position(|c| c != " ") {
                let last = inside.iter().rposition(|c| c != " ").unwrap();
                left = left.min(first as u16);
                right = right.min((inside.len() - 1 - last) as u16);
            }
        }
        (left, right)
    }

    fn assert_centred(buffer: &Buffer, what: &str) {
        let (left, right) = empty_sides(buffer);
        assert!(
            left <= right && right - left <= 1,
            "{what}: {left} left, {right} right\n{}",
            text(buffer).join("\n")
        );
    }

    #[test]
    fn several_rows_sit_in_the_middle_of_the_pane_at_every_width() {
        for width in [110, 111, 125, 130, 131, 150] {
            let (buffer, _) = draw_wide(Some(&map_of(11)), 0, width);
            assert_centred(&buffer, &format!("{width} wide"));
        }
    }

    #[test]
    fn a_short_last_row_stays_at_the_left_of_the_block() {
        let (buffer, _) = draw_wide(Some(&map_of(5)), 0, 130);
        assert_eq!(find(&buffer, "host4").1, find(&buffer, "this host").1);
        assert_centred(&buffer, "130 wide");
    }

    #[test]
    fn one_row_of_two_boxes_sits_in_the_middle_under_the_gateway() {
        for width in [110, 111, 130, 131] {
            let (buffer, _) = draw_wide(Some(&map_of(1)), 0, width);
            assert_centred(&buffer, &format!("{width} wide"));
        }
    }

    #[test]
    fn the_first_rows_line_stays_joined_when_the_rows_are_centred() {
        for (others, width) in [(1, 130), (1, 131), (0, 130), (2, 111), (11, 130), (11, 131)] {
            let (buffer, _) = draw_wide(Some(&map_of(others)), 0, width);
            let (y, x) = find(&buffer, "this host");
            let join = &lines(&buffer)[usize::from(y) - 2];
            let reach = join
                .iter()
                .enumerate()
                .filter(|(i, c)| *c != " " && *i > 0 && *i < usize::from(width) - 1)
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            let (first, last) = (reach[0], reach[reach.len() - 1]);
            assert!(
                (first..=last).all(|c| join[c] != " "),
                "{others}/{width}: {}",
                join.concat()
            );
            let centre = 1 + 2 + (usize::from(width) - 6) / 2;
            assert!(
                first <= centre.min(usize::from(x) + 8) && last >= centre,
                "{}",
                join.concat()
            );
        }
    }

    #[test]
    fn a_map_with_no_devices_draws_the_part_above_the_rows_without_a_panic() {
        let mut map = map_of(0);
        map.devices.clear();
        let (buffer, _) = draw_at(Some(&map), 0);
        let rows = text(&buffer);
        assert!(rows.iter().any(|r| r.contains("gateway")));
        assert!(rows.iter().any(|r| r.contains("internet")));
    }

    #[test]
    fn this_hosts_cells_are_highlight_and_an_absent_devices_are_muted() {
        let mut map = map_of(2);
        map.devices[2].absent = true;
        let (buffer, _) = draw_at(Some(&map), 0);
        let theme = Theme::default();
        let (y, x) = find(&buffer, "this host");
        assert_eq!(buffer[(x, y)].fg, theme.highlight);
        assert_eq!(buffer[(x, y + 1)].fg, theme.highlight);
        let (y, x) = find(&buffer, "host1");
        assert_eq!(buffer[(x, y)].fg, theme.muted);
        assert_eq!(buffer[(x, y + 1)].fg, theme.muted);
        let (y, x) = find(&buffer, "host0");
        assert_eq!(buffer[(x, y)].fg, theme.text);
    }

    #[test]
    fn text_longer_than_the_box_is_cut_with_an_ellipsis() {
        let mut map = map_of(1);
        map.devices[1] = device(
            "aa:bb:cc:dd:ee:ff",
            "2001:db8:1234:5678:9abc:def0:1234:5678",
            "Very Long Maker Name Incorporated",
        );
        let (buffer, _) = draw_at(Some(&map), 0);
        let rows = text(&buffer);
        let (y, x) = find(&buffer, "aa:bb:cc:dd:ee:ff");
        let row = |dy: u16| rows[usize::from(y + dy)].chars().collect::<Vec<_>>();
        let (second, third) = (row(1), row(2));
        let from = usize::from(x);
        assert_eq!(
            second[from..from + 17].iter().collect::<String>(),
            "2001:db8:1234:56…"
        );
        assert_eq!(
            third[from..from + 17].iter().collect::<String>(),
            "Very Long Maker …"
        );
        assert_eq!(second[from + 18], '│', "the border stays in place");
    }

    #[test]
    fn rows_scroll_under_a_fixed_top_and_a_note_says_how_many_are_below() {
        let mut map = map_of(16);
        map.label = "lan label".to_owned();
        let (top, scroll) = draw_at(Some(&map), 0);
        let (scrolled, again) = draw_at(Some(&map), 1);
        assert_eq!(
            scroll,
            MapScroll {
                offset: 0,
                max_offset: 3,
                fit_rows: 2
            }
        );
        assert_eq!(again.offset, 1);
        let (before, after) = (text(&top), text(&scrolled));
        let (label_y, _) = find(&top, "lan label");
        let fixed = usize::from(label_y) + 1;
        assert_eq!(
            before[..fixed],
            after[..fixed],
            "the part above the segment"
        );
        assert_ne!(before[fixed..], after[fixed..]);
        assert!(before.iter().any(|r| r.contains("this host")));
        assert!(!after.iter().any(|r| r.contains("this host")));
        assert!(after.iter().any(|r| r.contains("host4")));
        assert!(before.iter().any(|r| r.contains("9 more devices below")));
        assert!(after.iter().any(|r| r.contains("5 more devices below")));
        let (last, _) = draw_at(Some(&map), 99);
        assert!(!text(&last).iter().any(|r| r.contains("more devices below")));
        assert!(text(&last).iter().any(|r| r.contains("host15")));
    }
}

mod map_keys {
    use std::{
        net::IpAddr,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use crosswalk::{
        collect::{
            interfaces::InterfaceAddress,
            neighbors::{Neighbor, NeighborSnapshot},
        },
        dns::ReverseDns,
        ui::Interaction,
    };

    use super::*;

    const HOST_MAC: &str = "10:00:00:00:00:13";

    fn vendor_file(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("crosswalk-map-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn table() -> PathBuf {
        vendor_file(
            "table.txt",
            "10-00-00   (hex)\t\tIntel\n20-00-00   (hex)\t\tRaspberry Pi\n",
        )
    }

    fn host_mac(_: &str) -> Option<String> {
        Some(HOST_MAC.to_owned())
    }

    fn interaction() -> Interaction {
        Interaction::default()
            .with_vendor_table(table())
            .with_host_address(host_mac)
    }

    fn lan(route: &str) -> InterfaceSnapshot {
        let interface = |name: &str, ip: &str| InterfaceMeasurement {
            name: name.to_owned(),
            addresses: vec![InterfaceAddress {
                ip: ip.parse().unwrap(),
                prefix: 24,
            }],
            download_bytes_per_second: 0.0,
            upload_bytes_per_second: 0.0,
            session_received_bytes: 0,
            session_transmitted_bytes: 0,
            status: InterfaceStatus::Available,
            is_up: true,
        };
        InterfaceSnapshot {
            health: CollectionHealth::Available,
            interfaces: vec![
                interface("eth0", "10.0.1.13"),
                interface("eth1", "192.168.5.2"),
            ],
            default_route: Some(route.to_owned()),
            gateway: Some("10.0.1.1".parse().unwrap()),
            name_server: None,
            name_servers: vec![],
        }
    }

    fn state_with_devices(count: u8) -> AppState {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.record_interfaces(lan("eth0"));
        see(&mut state, count);
        state
    }

    /// `count` devices at 10.0.1.40 and up, plus the gateway.
    fn see(state: &mut AppState, count: u8) {
        let mut entries = vec![neighbor("10.0.1.1", "00:11:22:00:00:01")];
        entries.extend((0..count).map(|n| {
            neighbor(
                &format!("10.0.1.{}", 40 + n),
                &format!("20:00:00:00:00:{:02x}", 40 + n),
            )
        }));
        state.record_neighbors(NeighborSnapshot::Available(entries));
    }

    fn neighbor(address: &str, mac: &str) -> Neighbor {
        Neighbor {
            address: address.parse().unwrap(),
            mac: Some(mac.to_owned()),
            interface: "eth0".to_owned(),
            state: "REACHABLE".to_owned(),
        }
    }

    fn key(i: &mut Interaction, state: &AppState, c: char) {
        press(i, state, KeyCode::Char(c));
    }

    fn ctrl(i: &mut Interaction, state: &AppState, c: char) {
        i.handle_key(
            KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL),
            state,
        );
    }

    fn draw_at(
        state: &AppState,
        i: &mut Interaction,
        dns: Option<&ReverseDns>,
        width: u16,
        height: u16,
    ) -> String {
        text_of(&super::screen(state, i, dns, width, height))
    }

    fn screen(state: &AppState, i: &mut Interaction) -> String {
        draw_at(state, i, None, 110, 24)
    }

    /// How many devices the "below" note counts, 0 without one.
    fn below(text: &str) -> usize {
        text.lines()
            .find_map(|l| {
                let at = l.find(" more device")?;
                l[..at].split_whitespace().last()?.parse().ok()
            })
            .unwrap_or(0)
    }

    #[test]
    fn m_shows_the_map_from_either_page_and_esc_returns_to_the_same_pane_and_search() {
        let state = state_with_devices(3);
        for (pane, pane_key, title) in [
            (Pane::AppTraffic, '2', "APP TRAFFIC"),
            (Pane::Neighbors, '8', "NEIGHBORS"),
        ] {
            let mut i = interaction();
            key(&mut i, &state, pane_key);
            key(&mut i, &state, '/');
            for c in "abc".chars() {
                key(&mut i, &state, c);
            }
            press(&mut i, &state, KeyCode::Enter);
            let before = screen(&state, &mut i);
            assert!(before.contains(title), "{before}");
            key(&mut i, &state, 'm');
            assert!(i.map_open());
            let map = screen(&state, &mut i);
            assert!(map.contains("NETWORK MAP · eth0 · 4 devices"), "{map}");
            assert!(!map.contains(title), "{map}");
            assert!(map.contains("10.0.1.41"), "{map}");
            assert_eq!(i.focus(), pane);
            assert_eq!(i.search(pane), "abc");
            press(&mut i, &state, KeyCode::Esc);
            assert!(!i.map_open());
            assert_eq!(i.focus(), pane);
            assert_eq!(i.search(pane), "abc");
            assert_eq!(screen(&state, &mut i), before);
        }
    }

    #[test]
    fn m_closes_the_map_too() {
        let state = state_with_devices(1);
        let mut i = interaction();
        key(&mut i, &state, 'm');
        assert!(i.map_open());
        key(&mut i, &state, 'm');
        assert!(!i.map_open());
    }

    #[test]
    fn m_does_nothing_when_zoomed_or_in_an_open_search_field() {
        let state = state_with_devices(1);
        let mut i = interaction();
        press(&mut i, &state, KeyCode::Enter);
        key(&mut i, &state, 'm');
        assert!(!i.map_open());
        assert_eq!(i.zoomed(), Some(Pane::Bandwidth));

        let mut i = interaction();
        key(&mut i, &state, '/');
        key(&mut i, &state, 'm');
        assert!(!i.map_open());
        assert_eq!(i.search(Pane::Bandwidth), "m");
    }

    #[test]
    fn tab_numbers_p_enter_slash_i_and_r_do_nothing_while_the_map_is_open() {
        let state = state_with_devices(3);
        let mut i = interaction();
        key(&mut i, &state, '7');
        key(&mut i, &state, 'm');
        let before = screen(&state, &mut i);
        for code in [
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Char('1'),
            KeyCode::Char('8'),
            KeyCode::Char('p'),
            KeyCode::Enter,
            KeyCode::Char('/'),
            KeyCode::Char('i'),
            KeyCode::Char('r'),
        ] {
            press(&mut i, &state, code);
            assert!(i.map_open(), "{code:?}");
            assert_eq!(i.focus(), Pane::WifiNetworks, "{code:?}");
            assert_eq!(i.zoomed(), None, "{code:?}");
            assert!(!i.field_open(), "{code:?}");
            assert_eq!(i.interface(), None, "{code:?}");
            assert!(!i.take_scan_request(), "{code:?}");
            assert_eq!(screen(&state, &mut i), before, "{code:?}");
        }
        // And nothing typed leaked into a search for the pane underneath.
        press(&mut i, &state, KeyCode::Esc);
        assert_eq!(i.search(Pane::WifiNetworks), "");
        assert!(!i.field_open());
    }

    #[test]
    fn the_movement_keys_scroll_the_device_rows_and_stop_at_the_ends() {
        let state = state_with_devices(40);
        let mut i = interaction();
        key(&mut i, &state, 'm');
        let top = screen(&state, &mut i);
        let hidden = below(&top);
        assert!(hidden > 8, "{top}");

        press(&mut i, &state, KeyCode::Up);
        key(&mut i, &state, 'k');
        assert_eq!(screen(&state, &mut i), top, "stops at the top");

        key(&mut i, &state, 'j');
        let one = below(&screen(&state, &mut i));
        assert!(one < hidden, "j moves a row of devices down");
        press(&mut i, &state, KeyCode::Down);
        let two = below(&screen(&state, &mut i));
        assert!(two < one);
        press(&mut i, &state, KeyCode::Home);
        assert_eq!(screen(&state, &mut i), top);
        key(&mut i, &state, 'G');
        let bottom = screen(&state, &mut i);
        assert_eq!(below(&bottom), 0, "{bottom}");
        assert!(bottom.contains("10.0.1.79"), "{bottom}");
        key(&mut i, &state, 'j');
        press(&mut i, &state, KeyCode::PageDown);
        ctrl(&mut i, &state, 'd');
        assert_eq!(screen(&state, &mut i), bottom, "stops at the end");
        key(&mut i, &state, 'g');
        assert_eq!(screen(&state, &mut i), top);
        press(&mut i, &state, KeyCode::PageDown);
        let page = below(&screen(&state, &mut i));
        assert!(page < hidden);
        press(&mut i, &state, KeyCode::End);
        assert_eq!(screen(&state, &mut i), bottom);
        // Half of the two rows that fit is one row: four devices, the last row holding one.
        ctrl(&mut i, &state, 'u');
        assert_eq!(below(&screen(&state, &mut i)), 1);
        press(&mut i, &state, KeyCode::PageUp);
        assert_eq!(below(&screen(&state, &mut i)), 5);
        key(&mut i, &state, 'k');
        press(&mut i, &state, KeyCode::Up);
        assert_eq!(below(&screen(&state, &mut i)), 13);
    }

    #[test]
    fn the_page_underneath_keeps_its_selection_while_the_map_scrolls() {
        let state = state_with_devices(40);
        let mut i = interaction();
        key(&mut i, &state, '8');
        key(&mut i, &state, 'j');
        key(&mut i, &state, 'j');
        let selected = i.selected();
        screen(&state, &mut i);
        key(&mut i, &state, 'm');
        screen(&state, &mut i);
        for _ in 0..3 {
            key(&mut i, &state, 'j');
            screen(&state, &mut i);
        }
        press(&mut i, &state, KeyCode::Esc);
        assert_eq!(i.selected(), selected);
    }

    #[test]
    fn a_neighbour_recorded_while_the_map_is_open_appears_at_the_next_draw() {
        let mut state = state_with_devices(1);
        let mut i = interaction();
        key(&mut i, &state, 'm');
        let before = screen(&state, &mut i);
        assert!(!before.contains("10.0.1.99"));
        state.record_neighbors(NeighborSnapshot::Available(vec![
            neighbor("10.0.1.40", "20:00:00:00:00:28"),
            neighbor("10.0.1.99", "20:00:00:00:00:99"),
        ]));
        let after = screen(&state, &mut i);
        assert!(after.contains("10.0.1.99"), "{after}");
        assert!(after.contains("NETWORK MAP · eth0 · 3 devices"), "{after}");
    }

    #[test]
    fn n_turns_a_boxs_name_into_its_hardware_address_and_back() {
        let state = state_with_devices(1);
        let mut dns = ReverseDns::new(true, 8, 8, |address| {
            (address == "10.0.1.40".parse::<IpAddr>().unwrap()).then(|| "printer.lan".to_owned())
        });
        let mut i = interaction();
        key(&mut i, &state, 'm');
        key(&mut i, &state, 'n');
        assert!(i.names_on());
        dns.schedule_visible(i.map_to_look_up(&state));
        for _ in 0..200 {
            dns.poll();
            if dns.name("10.0.1.40".parse().unwrap()).is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let named = draw_at(&state, &mut i, Some(&dns), 110, 24);
        assert!(named.contains("printer.lan"), "{named}");
        assert!(!named.contains("20:00:00:00:00:28"), "{named}");
        key(&mut i, &state, 'n');
        let plain = draw_at(&state, &mut i, Some(&dns), 110, 24);
        assert!(plain.contains("20:00:00:00:00:28"), "{plain}");
        assert!(!plain.contains("printer.lan"), "{plain}");
        key(&mut i, &state, 'n');
        assert!(draw_at(&state, &mut i, Some(&dns), 110, 24).contains("printer.lan"));
    }

    #[test]
    fn lookups_are_wanted_for_the_gateway_and_every_device_address_while_the_map_is_open() {
        let state = state_with_devices(2);
        let mut i = interaction();
        assert!(i.map_to_look_up(&state).is_empty());
        key(&mut i, &state, 'm');
        let wanted = i.map_to_look_up(&state);
        for ip in ["10.0.1.1", "10.0.1.40", "10.0.1.41"] {
            assert!(wanted.contains(&ip.parse().unwrap()), "{ip} in {wanted:?}");
        }
        assert!(!wanted.contains(&"192.168.5.2".parse().unwrap()));
        press(&mut i, &state, KeyCode::Esc);
        assert!(i.map_to_look_up(&state).is_empty());
    }

    #[test]
    fn one_lookup_is_wanted_per_box_for_the_address_the_box_shows() {
        let mut state = state_with_devices(2);
        state.record_neighbors(NeighborSnapshot::Available(vec![
            neighbor("10.0.1.1", "00:11:22:00:00:01"),
            neighbor("10.0.1.40", "20:00:00:00:00:28"),
            neighbor("fe80::28", "20:00:00:00:00:28"),
            neighbor("2001:db8::29", "20:00:00:00:00:29"),
            neighbor("fe80::29", "20:00:00:00:00:29"),
        ]));
        let mut i = interaction();
        key(&mut i, &state, 'm');
        let mut wanted = i.map_to_look_up(&state);
        wanted.sort();
        let expected: Vec<IpAddr> = ["10.0.1.1", "10.0.1.40", "2001:db8::29"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        assert_eq!(wanted, expected);
    }

    fn wireless(_: &str) -> bool {
        true
    }

    fn wired(_: &str) -> bool {
        false
    }

    #[test]
    fn the_label_names_the_network_when_the_route_interface_is_wireless_whatever_its_name() {
        use crosswalk::collect::wifi::{AccessPoint, WifiSnapshot};
        let mut state = state_with_devices(1);
        state.record_wifi(WifiSnapshot::Available(vec![AccessPoint {
            ssid: Some("HomeNet".to_owned()),
            bssid: "00:11:22:33:44:55".to_owned(),
            signal: 70,
            channel: 36,
            frequency_mhz: 5805,
            security: "WPA2".to_owned(),
            in_use: true,
        }]));
        let mut radio = interaction().with_wireless_check(wireless);
        key(&mut radio, &state, 'm');
        assert!(
            screen(&state, &mut radio).contains("eth0 · HomeNet · 5G"),
            "{}",
            screen(&state, &mut radio)
        );
        let mut cable = interaction().with_wireless_check(wired);
        key(&mut cable, &state, 'm');
        assert!(!screen(&state, &mut cable).contains("HomeNet"));
    }

    #[test]
    fn a_system_without_the_vendor_file_draws_the_map_with_empty_maker_lines() {
        let state = state_with_devices(2);
        let missing = std::env::temp_dir().join("crosswalk-map-keys-no-such-file");
        let mut i = Interaction::default()
            .with_vendor_table(missing)
            .with_host_address(host_mac);
        key(&mut i, &state, 'm');
        let text = screen(&state, &mut i);
        assert!(text.contains("NETWORK MAP · eth0 · 3 devices"), "{text}");
        assert!(text.contains("10.0.1.41"), "{text}");
        assert!(
            !text.contains("Intel") && !text.contains("Raspberry"),
            "{text}"
        );
    }

    #[test]
    fn the_vendor_table_names_makers_and_is_read_once() {
        let state = state_with_devices(1);
        let path = vendor_file("once.txt", "20-00-00   (hex)\t\tRaspberry Pi\n");
        let mut i = Interaction::default()
            .with_vendor_table(&path)
            .with_host_address(host_mac);
        key(&mut i, &state, 'm');
        assert!(screen(&state, &mut i).contains("Raspberry Pi"));
        key(&mut i, &state, 'm');
        std::fs::write(&path, "20-00-00   (hex)\t\tChanged Maker\n").unwrap();
        key(&mut i, &state, 'm');
        let text = screen(&state, &mut i);
        assert!(text.contains("Raspberry Pi") && !text.contains("Changed"));
    }

    static READS: AtomicUsize = AtomicUsize::new(0);

    fn counting_host_mac(_: &str) -> Option<String> {
        READS.fetch_add(1, Ordering::SeqCst);
        Some(HOST_MAC.to_owned())
    }

    #[test]
    fn this_hosts_address_is_read_when_the_map_opens_and_when_the_route_changes() {
        let mut state = state_with_devices(1);
        let mut i = Interaction::default()
            .with_vendor_table(table())
            .with_host_address(counting_host_mac);
        screen(&state, &mut i);
        assert_eq!(READS.load(Ordering::SeqCst), 0, "not while closed");
        key(&mut i, &state, 'm');
        let text = screen(&state, &mut i);
        for _ in 0..3 {
            screen(&state, &mut i);
        }
        assert_eq!(READS.load(Ordering::SeqCst), 1, "not on every frame");
        assert!(
            text.contains("Intel"),
            "the host's maker comes from it: {text}"
        );
        state.record_interfaces(lan("eth1"));
        screen(&state, &mut i);
        screen(&state, &mut i);
        assert_eq!(READS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn blocks_arriving_while_the_map_covers_network_and_firewall_are_counted_on_traffic_until_the_page_is_shown()
     {
        let mut state = state_with_devices(1);
        let mut i = interaction();
        key(&mut i, &state, '5');
        screen(&state, &mut i);
        key(&mut i, &state, 'm');
        for n in 0..2 {
            state.record_firewall(
                Duration::from_secs(n),
                FirewallEvent {
                    timestamp: None,
                    direction: Some(Direction::Inbound),
                    interface: Some("eth0".into()),
                    protocol: Some(Protocol::Tcp),
                    source: FirewallEndpoint {
                        ip: Some("203.0.113.5".parse().unwrap()),
                        port: Some(40_000),
                    },
                    destination: FirewallEndpoint {
                        ip: Some("192.0.2.10".parse().unwrap()),
                        port: Some(22),
                    },
                },
            );
        }
        let header = |text: String| text.lines().next().unwrap().to_owned();
        screen(&state, &mut i);
        key(&mut i, &state, 'm');
        key(&mut i, &state, '1');
        let counted = header(screen(&state, &mut i));
        assert!(counted.contains("Network & Firewall 2"), "{counted}");
        key(&mut i, &state, '5');
        screen(&state, &mut i);
        key(&mut i, &state, '1');
        let cleared = header(screen(&state, &mut i));
        assert!(!cleared.contains("Network & Firewall 2"), "{cleared}");
    }

    #[test]
    fn help_opened_over_the_map_closes_back_to_the_map() {
        let state = state_with_devices(1);
        let mut i = interaction();
        key(&mut i, &state, 'm');
        key(&mut i, &state, '?');
        assert!(i.help_open() && i.map_open());
        let text = screen(&state, &mut i);
        assert!(
            text.contains("HELP") && text.contains("NETWORK MAP"),
            "{text}"
        );
        key(&mut i, &state, '?');
        assert!(!i.help_open() && i.map_open());
        key(&mut i, &state, '?');
        press(&mut i, &state, KeyCode::Esc);
        assert!(!i.help_open() && i.map_open());
        assert!(!i.should_quit());
    }

    #[test]
    fn q_and_ctrl_c_quit_from_the_map() {
        let state = state_with_devices(1);
        for quit in [false, true] {
            let mut i = interaction();
            key(&mut i, &state, 'm');
            if quit {
                ctrl(&mut i, &state, 'c');
            } else {
                key(&mut i, &state, 'q');
            }
            assert!(i.should_quit());
        }
    }

    #[test]
    fn a_terminal_below_the_minimum_says_so_instead_of_the_map() {
        let state = state_with_devices(1);
        let mut i = interaction();
        key(&mut i, &state, 'm');
        let text = draw_at(&state, &mut i, None, 100, 20);
        assert!(text.contains("Terminal too small"), "{text}");
        assert!(!text.contains("NETWORK MAP"), "{text}");
    }

    fn footer_of(state: &AppState, i: &mut Interaction) -> String {
        screen(state, i).lines().nth(23).unwrap().to_owned()
    }

    #[test]
    fn the_footer_names_m_on_both_pages_and_wi_fi_still_fits() {
        let state = state_with_devices(1);
        let mut i = interaction();
        let footer = footer_of(&state, &mut i);
        assert!(
            footer.contains("m map") && footer.contains("q quit"),
            "{footer}"
        );
        key(&mut i, &state, 'p');
        let footer = footer_of(&state, &mut i);
        assert!(
            footer.contains("m map") && footer.contains("q quit"),
            "{footer}"
        );
        key(&mut i, &state, '7');
        let footer = footer_of(&state, &mut i);
        for hint in ["m map", "r scan", "? help", "q quit"] {
            assert!(footer.contains(hint), "{hint} missing from {footer:?}");
        }
    }

    #[test]
    fn the_footer_has_no_m_in_zoom_or_while_typing() {
        let state = state_with_devices(1);
        let mut i = interaction();
        key(&mut i, &state, '/');
        assert!(!footer_of(&state, &mut i).contains("m map"));
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Enter);
        assert!(!footer_of(&state, &mut i).contains("m map"));
    }

    #[test]
    fn with_the_map_open_the_footer_names_the_keys_that_work() {
        let state = state_with_devices(1);
        let mut i = interaction();
        key(&mut i, &state, 'm');
        let footer = footer_of(&state, &mut i);
        for hint in ["esc back", "j/k scroll", "n names off", "? help", "q quit"] {
            assert!(footer.contains(hint), "{hint} missing from {footer:?}");
        }
        for gone in ["tab", "enter", "search", "interface", "page"] {
            assert!(!footer.contains(gone), "{gone} in {footer:?}");
        }
    }

    #[test]
    fn the_help_names_m_and_still_fits_at_110_by_24() {
        let state = state_with_devices(1);
        let mut i = interaction();
        key(&mut i, &state, '?');
        let rows: Vec<String> = draw_at(&state, &mut i, None, 110, 24)
            .lines()
            .map(str::to_owned)
            .collect();
        let top = rows.iter().position(|l| l.contains("HELP")).unwrap();
        let line = rows
            .iter()
            .skip(top)
            .find(|l| l.contains("i / n / r / m") && l.contains("map"))
            .unwrap_or_else(|| panic!("{rows:#?}"));
        assert!(
            line.contains("reverse DNS names") && line.contains("scan Wi-Fi"),
            "{line}"
        );
        let left = rows[top].chars().position(|c| c == 'H').unwrap() - 2;
        let bottom = (top..rows.len())
            .find(|&y| rows[y].chars().nth(left) == Some('╰'))
            .expect("the popup's bottom border is on screen");
        assert!(bottom - top < 17, "the popup is {} rows", bottom - top + 1);
        for kept in [
            "tab / 1-8",
            "j/k g/G ctrl-d/u",
            "toggle this help / quit",
            "● open",
        ] {
            assert!(rows.iter().any(|l| l.contains(kept)), "{kept} missing");
        }
        // Opened over the map, the help is the same popup.
        key(&mut i, &state, '?');
        key(&mut i, &state, 'm');
        key(&mut i, &state, '?');
        let text = draw_at(&state, &mut i, None, 110, 24);
        assert!(
            text.contains("HELP") && text.contains("NETWORK MAP"),
            "{text}"
        );
    }
}

mod theme_cycling {
    use super::*;
    use ratatui::{buffer::Buffer, style::Color};

    fn state() -> AppState {
        AppState::new(StateLimits::default()).unwrap()
    }

    fn draw_with(i: &mut Interaction, state: &AppState, base: &Theme) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal
            .draw(|f| draw_interactive(f, state, base, i, None))
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn named(name: &str) -> Theme {
        Theme::named(name).unwrap()
    }

    /// The screen's background and the focused pane's border, on Traffic.
    fn look(i: &mut Interaction, state: &AppState, base: &Theme) -> (Color, Color) {
        let buffer = draw_with(i, state, base);
        (buffer[(0, 0)].bg, buffer[(0, 1)].fg)
    }

    fn started(name: &str, overrides: &[(&'static str, Color)]) -> (Interaction, Theme) {
        let base = named(name).with_overrides(overrides);
        (Interaction::default().with_theme(name, overrides), base)
    }

    #[test]
    fn t_twenty_five_times_shows_each_theme_once_in_order_and_returns_to_the_first() {
        let state = state();
        let (mut i, base) = started("synthwave", &[]);
        let mut seen = vec![look(&mut i, &state, &base)];
        for _ in 0..25 {
            press(&mut i, &state, KeyCode::Char('t'));
            seen.push(look(&mut i, &state, &base));
        }
        for (n, name) in Theme::NAMES.iter().enumerate() {
            let t = named(name);
            assert_eq!(seen[n], (t.background, t.accent), "{name}");
        }
        assert_eq!(seen[25], seen[0]);
    }

    #[test]
    fn shift_t_shows_the_previous_theme_and_undoes_t() {
        let state = state();
        let (mut i, base) = started("nord", &[]);
        press(&mut i, &state, KeyCode::Char('t'));
        press(&mut i, &state, KeyCode::Char('T'));
        assert_eq!(look(&mut i, &state, &base).0, named("nord").background);
        let (mut i, base) = started("synthwave", &[]);
        press(&mut i, &state, KeyCode::Char('T'));
        assert_eq!(look(&mut i, &state, &base).0, Color::Reset);
        let (mut i, base) = started("synthwave", &[]);
        let first = look(&mut i, &state, &base);
        for _ in 0..25 {
            press(&mut i, &state, KeyCode::Char('T'));
        }
        assert_eq!(look(&mut i, &state, &base), first);
    }

    #[test]
    fn shift_t_works_in_zoom_and_on_the_map_and_is_typed_in_an_open_search() {
        let state = state();
        let (mut i, base) = started("dracula", &[]);
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Char('T'));
        assert_eq!(look(&mut i, &state, &base).0, named("synthwave").background);
        assert_eq!(i.zoomed(), Some(Pane::Bandwidth));
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('m'));
        press(&mut i, &state, KeyCode::Char('T'));
        assert_eq!(look(&mut i, &state, &base).0, Color::Reset);
        assert!(i.map_open());
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('/'));
        press(&mut i, &state, KeyCode::Char('T'));
        assert_eq!(i.search(Pane::Bandwidth), "T");
        assert_eq!(look(&mut i, &state, &base).0, Color::Reset);
    }

    #[test]
    fn cycling_starts_from_the_theme_started_with() {
        let state = state();
        let (mut i, base) = started("nord", &[]);
        press(&mut i, &state, KeyCode::Char('t'));
        assert_eq!(look(&mut i, &state, &base).0, named("gruvbox").background);
    }

    #[test]
    fn the_overrides_stay_on_top_of_every_theme() {
        let state = state();
        let white = Color::Rgb(255, 255, 255);
        let (mut i, base) = started("nord", &[("accent", white)]);
        assert_eq!(
            look(&mut i, &state, &base),
            (named("nord").background, white)
        );
        press(&mut i, &state, KeyCode::Char('t'));
        assert_eq!(
            look(&mut i, &state, &base),
            (named("gruvbox").background, white)
        );
    }

    #[test]
    fn t_works_on_both_pages_in_zoom_and_on_the_map_and_changes_nothing_else() {
        let state = state();
        let (mut i, base) = started("synthwave", &[]);
        press(&mut i, &state, KeyCode::Char('p'));
        press(&mut i, &state, KeyCode::Char('7'));
        press(&mut i, &state, KeyCode::Char('t'));
        assert_eq!(look(&mut i, &state, &base).0, named("dracula").background);
        assert_eq!(i.focus(), Pane::WifiNetworks);
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Char('t'));
        assert_eq!(look(&mut i, &state, &base).0, named("nord").background);
        assert_eq!(i.zoomed(), Some(Pane::WifiNetworks));
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('m'));
        press(&mut i, &state, KeyCode::Char('t'));
        assert_eq!(look(&mut i, &state, &base).0, named("gruvbox").background);
        assert!(i.map_open());
        press(&mut i, &state, KeyCode::Esc);
        assert_eq!(i.focus(), Pane::WifiNetworks);
        assert_eq!(i.zoomed(), None);
    }

    #[test]
    fn t_keeps_the_searches_and_the_selection() {
        let state = state();
        let (mut i, base) = started("synthwave", &[]);
        press(&mut i, &state, KeyCode::Char('2'));
        press(&mut i, &state, KeyCode::Char('/'));
        press(&mut i, &state, KeyCode::Char('x'));
        press(&mut i, &state, KeyCode::Enter);
        press(&mut i, &state, KeyCode::Char('t'));
        look(&mut i, &state, &base);
        assert_eq!(i.search(Pane::AppTraffic), "x");
        assert_eq!(i.focus(), Pane::AppTraffic);
        assert_eq!(i.selected(), 0);
    }

    #[test]
    fn in_an_open_search_field_t_is_typed_and_the_theme_stays() {
        let state = state();
        let (mut i, base) = started("synthwave", &[]);
        press(&mut i, &state, KeyCode::Char('/'));
        press(&mut i, &state, KeyCode::Char('t'));
        assert_eq!(i.search(Pane::Bandwidth), "t");
        assert_eq!(look(&mut i, &state, &base).0, named("synthwave").background);
    }

    #[test]
    fn the_terminal_theme_draws_no_24_bit_colour_and_the_terminals_own_background() {
        let state = state();
        let (mut i, base) = started("paper", &[]);
        press(&mut i, &state, KeyCode::Char('t'));
        let buffer = draw_with(&mut i, &state, &base);
        for cell in buffer.content() {
            assert!(!matches!(cell.fg, Color::Rgb(..)), "{:?}", cell.fg);
            assert!(!matches!(cell.bg, Color::Rgb(..)), "{:?}", cell.bg);
        }
        assert_eq!(buffer[(0, 0)].bg, Color::Reset);
    }

    fn footer_at(i: &mut Interaction, state: &AppState) -> String {
        lines(&screen(state, i, None, 110, 24)).remove(23)
    }

    #[test]
    fn the_footer_names_t_on_the_overview_in_zoom_and_on_the_map_but_not_while_typing() {
        let state = state();
        let mut i = Interaction::default();
        assert!(footer_at(&mut i, &state).contains("t theme"));
        press(&mut i, &state, KeyCode::Char('p'));
        assert!(footer_at(&mut i, &state).contains("t theme"));
        press(&mut i, &state, KeyCode::Enter);
        assert!(footer_at(&mut i, &state).contains("t theme"));
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('m'));
        assert!(footer_at(&mut i, &state).contains("t theme"));
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('/'));
        assert!(!footer_at(&mut i, &state).contains("t theme"));
    }

    fn footer_at_width(i: &mut Interaction, state: &AppState, width: u16) -> String {
        lines(&screen(state, i, None, width, 30)).remove(29)
    }

    #[test]
    fn at_130_columns_the_t_hint_names_the_theme_and_follows_t_on_every_view() {
        let state = state();
        let mut i = Interaction::default();
        let footer = footer_at_width(&mut i, &state, 130);
        assert!(footer.contains("t theme (synthwave)"), "{footer:?}");
        assert!(
            footer
                .trim_end()
                .ends_with("t theme (synthwave) · ? help · q quit"),
            "{footer:?}"
        );
        press(&mut i, &state, KeyCode::Char('t'));
        let footer = footer_at_width(&mut i, &state, 130);
        assert!(footer.contains("t theme (dracula)"), "{footer:?}");
        assert!(!footer.contains("synthwave"), "{footer:?}");
        press(&mut i, &state, KeyCode::Enter);
        let footer = footer_at_width(&mut i, &state, 130);
        assert!(footer.contains("t theme (dracula)"), "zoom: {footer:?}");
        press(&mut i, &state, KeyCode::Esc);
        press(&mut i, &state, KeyCode::Char('m'));
        let footer = footer_at_width(&mut i, &state, 130);
        assert!(footer.contains("t theme (dracula)"), "map: {footer:?}");
    }

    #[test]
    fn at_110_columns_on_the_main_page_the_t_hint_is_plain() {
        let state = state();
        let mut i = Interaction::default();
        let footer = footer_at(&mut i, &state);
        assert!(
            footer.trim_end().ends_with("t theme · ? help · q quit"),
            "{footer:?}"
        );
        assert!(!footer.contains('('), "{footer:?}");
    }

    #[test]
    fn the_footer_keeps_every_other_hint_on_wi_fi_where_t_does_not_fit() {
        let state = state();
        let mut i = Interaction::default();
        press(&mut i, &state, KeyCode::Char('7'));
        let footer = footer_at(&mut i, &state);
        for hint in ["m map", "r scan", "? help", "q quit"] {
            assert!(footer.contains(hint), "{hint} missing from {footer:?}");
        }
    }

    #[test]
    fn the_help_popup_line_for_t_reads_next_theme_and_the_popup_fits_at_110_by_24() {
        let state = state();
        let mut i = Interaction::default().with_theme("nord", &[]);
        press(&mut i, &state, KeyCode::Char('t'));
        press(&mut i, &state, KeyCode::Char('?'));
        let rows = lines(&screen(&state, &mut i, None, 110, 24));
        let row = rows
            .iter()
            .find(|l| l.contains("next theme"))
            .unwrap_or_else(|| panic!("{rows:#?}"));
        assert!(
            row.contains(" t ") && row.contains("next theme · T previous"),
            "{row}"
        );
        assert!(
            !row.contains("gruvbox") && !row.contains("[theme]"),
            "{row}"
        );
        let top = rows.iter().position(|l| l.contains("HELP")).unwrap();
        let bottom = rows
            .iter()
            .rposition(|l| l.contains('╰') && l.contains('╯'))
            .unwrap();
        assert!(top > 0 && bottom < 23 && bottom - top < 20, "{rows:#?}");
        assert!(rows.iter().any(|l| l.contains("● open")));
    }

    fn header(i: &mut Interaction, state: &AppState) -> String {
        lines(&screen(state, i, None, 110, 24)).remove(0)
    }

    #[test]
    fn the_header_never_shows_the_theme_name_whichever_theme_is_in_use() {
        let state = state();
        let mut i = Interaction::default();
        for _ in 0..2 {
            let header = header(&mut i, &state);
            assert!(
                !Theme::NAMES.iter().any(|name| header.contains(name)),
                "{header:?}"
            );
            press(&mut i, &state, KeyCode::Char('t'));
        }
    }
}

#[test]
fn the_terminal_title_names_the_page_or_the_map() {
    assert_eq!(terminal_title(Page::Traffic, false), "Crosswalk: Traffic");
    assert_eq!(
        terminal_title(Page::NetworkFirewall, false),
        "Crosswalk: Network & Firewall"
    );
    assert_eq!(terminal_title(Page::Traffic, true), "Crosswalk: Map");
    assert_eq!(
        terminal_title(Page::NetworkFirewall, true),
        "Crosswalk: Map"
    );
}

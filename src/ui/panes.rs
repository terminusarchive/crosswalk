//! Turns state into what the panes draw: table columns and rows, health
//! sentences and the header indicators.

use std::{net::IpAddr, time::Duration};

use ratatui::style::{Color, Style};

use super::{
    Theme, bound_text,
    format::{format_bytes, format_rate},
    table::{Align, Cell, Column, Row, cut_left, filter_rows},
    whole_text,
};
use crate::{
    collect::{
        attribution::{AttributionHealth, ExecutableIdentity},
        capture::{CaptureHealth, CaptureOrigin, Direction, Protocol},
        dumpcap::stopped_reason,
        interfaces::CollectionHealth,
        neighbors::Neighbor,
    },
    dns::ReverseDns,
    events::{EventKind, EventLevel},
    firewall::{
        Exposure, FirewallHealth, Network, Rule, RuleAction, RuleDirection, RuleSnapshot,
        RuleSource,
    },
    state::{
        AppState, AppTraffic, BlockKind, BlockedRow, ByteRates, ByteTotals, DestinationTraffic,
        HISTORY_SECONDS, ListeningPort, Pane, WifiEntry, WifiScan,
    },
};

/// App Traffic shows this many destinations per app on the overview.
pub const OVERVIEW_DESTINATIONS: usize = 3;

/// The interface the chart plots: the chosen one when it exists, otherwise
/// the default route, otherwise the first interface.
pub fn chart_interface(state: &AppState, chosen: Option<&str>) -> Option<String> {
    let interfaces = state.interfaces();
    [chosen, state.default_route()]
        .into_iter()
        .flatten()
        .find(|name| interfaces.iter().any(|i| i.name == *name))
        .map(str::to_owned)
        .or_else(|| interfaces.first().map(|i| i.name.clone()))
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Other(_) => "ip",
    }
}

fn port_text(port: Option<u16>, protocol: Protocol) -> String {
    let port = port.map_or("—".to_owned(), |p| p.to_string());
    format!("{port}/{}", protocol_name(protocol))
}

/// Folders that only group releases, so they never name an app.
const GENERIC_FOLDERS: [&str; 4] = ["versions", "version", "releases", "bin"];

/// The app's name: its executable's file name, or, when that has no letter
/// (a version number such as `2.1.296`), the nearest folder above it that does
/// and is not a generic release folder.
fn file_name(executable: &ExecutableIdentity) -> String {
    let Some(name) = executable.path.file_name() else {
        return "unknown".to_owned();
    };
    let name = name.to_string_lossy();
    let folder = if name.chars().any(|c| c.is_ascii_alphabetic()) {
        None
    } else {
        executable
            .path
            .ancestors()
            .skip(1)
            .filter_map(|p| p.file_name())
            .map(|f| f.to_string_lossy())
            .find(|f| {
                f.chars().any(|c| c.is_ascii_alphabetic())
                    && !GENERIC_FOLDERS.iter().any(|g| f.eq_ignore_ascii_case(g))
            })
    };
    bound_text(folder.as_deref().unwrap_or(&name))
}

/// The most a fixed column is given where its text comes from outside, so one
/// long value cannot starve the column that takes the rest: an app's name, an
/// interface name, a firewall rule's text, a rule's remote network (zoom).
const APP_MAX: u16 = 24;
const IFACE_MAX: u16 = 16;
const RULE_MAX: u16 = 30;
const REMOTE_MAX: u16 = 43;
/// App Traffic shows an app's full path, up to this many cells on the overview.
const PATH_MAX: u16 = 28;
/// The same on the zoomed list.
const PATH_ZOOM_MAX: u16 = 48;

pub fn app_traffic_columns() -> Vec<Column> {
    vec![
        Column::new("APP", Align::Left, 7, 7)
            .at_most(PATH_MAX)
            .cut_from_left(),
        spark_column(),
        Column::new("PID", Align::Left, 5, 1),
        Column::new("DESTINATION", Align::Left, 13, 6).fill(1),
        Column::new("PORT", Align::Left, 9, 5).at_least(9),
        Column::new("↓ IN", Align::Right, 10, 4).at_least(10),
        Column::new("↑ OUT", Align::Right, 10, 3).at_least(10),
        Column::new("TOTAL", Align::Right, 8, 2).at_least(8),
    ]
}

/// The app's last eight seconds, four braille cells, dropped before any other column.
fn spark_column() -> Column {
    let width = HISTORY_SECONDS as u16 / 2;
    Column::new("", Align::Left, width, 0)
        .at_least(width)
        .at_most(width)
}

/// Four braille cells, two seconds to a cell, oldest at the left: the left
/// dots are the older second, the right the newer. A second's height is its
/// bytes against the busiest of the eight, one to four dots from the bottom
/// and none for no bytes. A cell is blank when both seconds are, else in the
/// colour of the larger direction over the two.
fn spark_cell(theme: &Theme, history: &[ByteTotals; HISTORY_SECONDS]) -> Cell {
    const LEFT: [u32; 4] = [0x40, 0x04, 0x02, 0x01];
    const RIGHT: [u32; 4] = [0x80, 0x20, 0x10, 0x08];
    let sum = |t: &ByteTotals| t.upload.saturating_add(t.download);
    let peak = history.iter().map(sum).max().unwrap_or(0);
    let dots = |t: &ByteTotals, bits: [u32; 4]| -> u32 {
        match sum(t) {
            0 => 0,
            total => {
                let height = (u128::from(total) * 4).div_ceil(u128::from(peak)) as usize;
                bits[..height].iter().sum()
            }
        }
    };
    let (glyphs, styles) = history
        .chunks(2)
        .map(|pair| {
            let bits = dots(&pair[0], LEFT) + dots(&pair[1], RIGHT);
            let download = pair[0].download.saturating_add(pair[1].download);
            let upload = pair[0].upload.saturating_add(pair[1].upload);
            let colour = if download >= upload {
                theme.inbound
            } else {
                theme.outbound
            };
            let glyph = if bits == 0 {
                ' '
            } else {
                char::from_u32(0x2800 + bits).unwrap_or(' ')
            };
            (glyph, Style::default().fg(colour))
        })
        .unzip::<_, _, String, Vec<Style>>();
    Cell::new(glyphs).glyph_styles(styles)
}

/// The app as App Traffic shows it: the executable's full path cut from the
/// left to `width` cells, or its short name when the path names no file.
fn app_name(app: &AppTraffic, width: u16) -> String {
    if app.executable.path.file_name().is_some() {
        cut_left(&whole_text(&app.executable.path.to_string_lossy()), width)
    } else {
        file_name(&app.executable)
    }
}

/// The first process and how many more share the destination, `—` with none.
fn pid_text(pids: &[u32]) -> String {
    match pids {
        [] => "—".to_owned(),
        [only] => only.to_string(),
        [first, more @ ..] => format!("{first} +{}", more.len()),
    }
}

/// The reverse-DNS name of an address, when lookups are on and one is known.
fn name_of(names: Option<&ReverseDns>, ip: IpAddr) -> Option<&str> {
    names.and_then(|dns| dns.name(ip))
}

/// An app's destinations whose app name, address, name or port holds the search.
fn matching<'a>(
    app: &'a AppTraffic,
    name: &str,
    needle: &str,
    names: Option<&ReverseDns>,
) -> Vec<&'a DestinationTraffic> {
    app.destinations
        .iter()
        .filter(|d| {
            needle.is_empty()
                || [
                    name.to_owned(),
                    d.remote.ip.to_string(),
                    name_of(names, d.remote.ip).unwrap_or("").to_owned(),
                    port_text(d.remote.port, d.protocol),
                ]
                .iter()
                .any(|text| text.to_lowercase().contains(needle))
        })
        .collect()
}

/// One row per destination in first-seen order. With `limit`, an app's
/// destinations past it become one `+N more` row carrying their sums.
/// `search` keeps destinations whose app, address, name or port contains it.
/// A destination with a known reverse-DNS name shows the name.
pub fn app_traffic_rows(
    state: &AppState,
    theme: &Theme,
    search: &str,
    limit: Option<usize>,
    names: Option<&ReverseDns>,
) -> Vec<Row> {
    let needle = search.to_lowercase();
    let mut rows = Vec::new();
    for app in state.app_traffic() {
        let name = app_name(&app, PATH_MAX);
        let shown = matching(&app, &name, &needle, names);
        let visible = limit.map_or(shown.len(), |l| l.min(shown.len()));
        for (n, d) in shown.iter().take(visible).enumerate() {
            let label = if n == 0 { name.as_str() } else { "" };
            let destination =
                name_of(names, d.remote.ip).map_or_else(|| d.remote.ip.to_string(), bound_text);
            let mut row = traffic_row(
                theme,
                label,
                &pid_text(&d.pids),
                &destination,
                &port_text(d.remote.port, d.protocol),
                (d.rate, d.bytes),
                d.idle,
            );
            if n == 0 {
                row.cells[1] = spark_cell(theme, &app.history);
            }
            rows.push(row);
        }
        let rest = &shown[visible..];
        if !rest.is_empty() {
            let mut rate = ByteRates::default();
            let mut bytes = ByteTotals::default();
            for d in rest {
                rate.upload += d.rate.upload;
                rate.download += d.rate.download;
                bytes.upload += d.bytes.upload;
                bytes.download += d.bytes.download;
            }
            let idle = rest.iter().all(|d| d.idle);
            let mut row = traffic_row(
                theme,
                "",
                "",
                &format!("+{} more", rest.len()),
                "",
                (rate, bytes),
                idle,
            );
            row.cells[3].style = Some(theme.muted());
            rows.push(row);
        }
    }
    rows
}

pub fn app_traffic_zoom_columns() -> Vec<Column> {
    vec![
        Column::new("APP", Align::Left, 6, 10)
            .at_most(PATH_ZOOM_MAX)
            .cut_from_left(),
        spark_column(),
        Column::new("PID", Align::Left, 5, 4),
        Column::new("DESTINATION", Align::Left, 15, 9),
        Column::new("PORT", Align::Left, 8, 8).at_least(9),
        Column::new("↓ IN", Align::Right, 10, 7).at_least(10),
        Column::new("↑ OUT", Align::Right, 10, 6).at_least(10),
        Column::new("↓ TOTAL", Align::Right, 9, 5).at_least(8),
        Column::new("↑ TOTAL", Align::Right, 9, 3).at_least(8),
        Column::new("NAME", Align::Left, 10, 2).fill(1),
    ]
}

/// Every destination with PID(s), both rates, both totals and the
/// reverse-DNS name next to the address.
pub fn app_traffic_zoom_rows(
    state: &AppState,
    theme: &Theme,
    search: &str,
    names: Option<&ReverseDns>,
) -> Vec<Row> {
    let needle = search.to_lowercase();
    let mut rows = Vec::new();
    for app in state.app_traffic() {
        let name = app_name(&app, PATH_ZOOM_MAX);
        for (n, d) in matching(&app, &name, &needle, names)
            .into_iter()
            .enumerate()
        {
            let pids = d
                .pids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let mut row = Row::new([
                if n == 0 { name.clone() } else { String::new() },
                String::new(),
                if pids.is_empty() {
                    "—".to_owned()
                } else {
                    pids
                },
                d.remote.ip.to_string(),
                port_text(d.remote.port, d.protocol),
                format_rate(d.rate.download),
                format_rate(d.rate.upload),
                format_bytes(d.bytes.download),
                format_bytes(d.bytes.upload),
                name_of(names, d.remote.ip).map_or(String::new(), bound_text),
            ]);
            if n == 0 {
                row.cells[1] = spark_cell(theme, &app.history);
            }
            if d.idle {
                row = row.style(theme.muted());
            } else {
                style_rate_cells(&mut row, theme, 5, d.rate.download, d.rate.upload);
            }
            rows.push(row);
        }
    }
    rows
}

/// A live rate in its direction's colour; zero is muted so live numbers stand out.
pub fn rate_style(theme: &Theme, value: f64, colour: Color) -> Style {
    if value > 0.0 {
        Style::default().fg(colour)
    } else {
        theme.muted()
    }
}

/// Colours the download cell at `first` and the upload cell after it by their rates.
fn style_rate_cells(row: &mut Row, theme: &Theme, first: usize, download: f64, upload: f64) {
    row.cells[first].style = Some(rate_style(theme, download, theme.inbound));
    row.cells[first + 1].style = Some(rate_style(theme, upload, theme.outbound));
}

fn traffic_row(
    theme: &Theme,
    app: &str,
    pid: &str,
    destination: &str,
    port: &str,
    (rate, bytes): (ByteRates, ByteTotals),
    idle: bool,
) -> Row {
    let mut row = Row::new([
        app.to_owned(),
        String::new(),
        pid.to_owned(),
        destination.to_owned(),
        port.to_owned(),
        format_rate(rate.download),
        format_rate(rate.upload),
        format_bytes(bytes.upload.saturating_add(bytes.download)),
    ]);
    if idle {
        return row.style(theme.muted());
    }
    style_rate_cells(&mut row, theme, 5, rate.download, rate.upload);
    row
}

/// App Traffic's footer line: the bytes not attributed to an app, then the
/// bytes the list had no room to itemise, each only when there are any. App
/// Traffic spans the screen, so even the full wording fits the 106 cells
/// inside the pane at the 110-column minimum with every figure up to
/// hundreds of terabytes.
pub fn uncounted_line(state: &AppState) -> Option<String> {
    let total = |t: ByteTotals| t.upload.saturating_add(t.download) > 0;
    let (unattributed, full) = (
        state.app_traffic_unattributed(),
        state.app_traffic_uncounted(),
    );
    let in_out = |t: ByteTotals| {
        format!(
            "{} in, {} out",
            format_bytes(t.download),
            format_bytes(t.upload)
        )
    };
    let alone = format!("not attributed: {}", in_out(unattributed));
    match (total(unattributed), total(full)) {
        (false, false) => None,
        (true, false) => Some(alone),
        (false, true) => Some(format!("list full: {} not itemised", in_out(full))),
        (true, true) => Some(format!(
            "{alone} · list full: {} not itemised",
            in_out(full)
        )),
    }
}

pub fn blocked_columns() -> Vec<Column> {
    vec![
        Column::new("LAST SEEN", Align::Left, 9, 1),
        Column::new("FROM", Align::Left, 15, 4).fill(1),
        Column::new("PORT", Align::Left, 9, 3),
        Column::new("HITS", Align::Right, 4, 2),
        Column::new("KIND", Align::Left, 7, 5),
    ]
}

/// The word for a row's kind, in its own colour.
fn kind_cell(b: &BlockedRow, theme: &Theme) -> Cell {
    match b.kind {
        BlockKind::Firewall => Cell::new("blocked").style(theme.blocked()),
        BlockKind::Refused => Cell::new("refused").style(theme.warning()),
    }
}

/// The cells of a merged block, FROM holding `from`.
fn blocked_cells(b: &BlockedRow, from: String) -> [String; 4] {
    [
        b.last_clock.clone().unwrap_or_else(|| "—".to_owned()),
        from,
        b.protocol.map_or("—".to_owned(), |p| port_text(b.port, p)),
        format!("×{}", b.count),
    ]
}

/// A source's address and, when lookups are on and one is known, its name.
fn source_texts(b: &BlockedRow, names: Option<&ReverseDns>) -> (String, Option<String>) {
    (
        b.source.map_or("—".to_owned(), |ip| ip.to_string()),
        b.source.and_then(|ip| name_of(names, ip)).map(bound_text),
    )
}

/// Inbound blocks as the overview lists them, newest first.
pub fn blocked_overview_order(state: &AppState) -> Vec<BlockedRow> {
    state.blocked(Direction::Inbound)
}

/// A block holds the search in a cell, its address or its name.
fn blocked_matches(row: &Row, address: &str, name: Option<&str>, needle: &str) -> bool {
    row.matches(needle)
        || [Some(address), name]
            .into_iter()
            .flatten()
            .any(|t| t.to_lowercase().contains(needle))
}

/// Inbound blocks; a source with a known name shows the name, and the
/// search also matches the address and the name.
pub fn blocked_rows(
    state: &AppState,
    theme: &Theme,
    search: &str,
    names: Option<&ReverseDns>,
) -> Vec<Row> {
    let needle = search.to_lowercase();
    blocked_overview_order(state)
        .iter()
        .filter_map(|b| {
            let (address, name) = source_texts(b, names);
            let [last, from, port, hits] =
                blocked_cells(b, name.clone().unwrap_or_else(|| address.clone()));
            let row = Row {
                cells: vec![
                    Cell::new(last),
                    Cell::new(from),
                    Cell::new(port),
                    Cell::new(hits),
                    kind_cell(b, theme),
                ],
                ..Row::default()
            };
            blocked_matches(&row, &address, name.as_deref(), &needle).then_some(row)
        })
        .collect()
}

pub fn blocked_zoom_columns() -> Vec<Column> {
    vec![
        Column::new("LAST SEEN", Align::Left, 9, 9),
        Column::new("FIRST SEEN", Align::Left, 10, 4),
        Column::new("FROM", Align::Left, 15, 8),
        Column::new("PORT", Align::Left, 9, 6),
        Column::new("HITS", Align::Right, 4, 5),
        Column::new("INTERFACE", Align::Left, 9, 3).at_most(IFACE_MAX),
        Column::new("DIRECTION", Align::Left, 9, 2),
        Column::new("KIND", Align::Left, 7, 7),
        Column::new("NAME", Align::Left, 10, 1).fill(1),
    ]
}

/// Blocks in every direction, forwarded ones included, newest first.
pub fn blocked_zoom_order(state: &AppState) -> Vec<BlockedRow> {
    let mut blocks = state.blocked_rows();
    blocks.sort_by_key(|b| std::cmp::Reverse(b.first_seen));
    blocks
}

/// Every block with the address in FROM and the name, when known, in NAME.
pub fn blocked_zoom_rows(
    state: &AppState,
    theme: &Theme,
    search: &str,
    names: Option<&ReverseDns>,
) -> Vec<Row> {
    filter_rows(
        blocked_zoom_order(state)
            .iter()
            .map(|b| {
                let (address, name) = source_texts(b, names);
                let [last, from, port, hits] = blocked_cells(b, address);
                let plain = |text: String| Cell::new(text);
                Row {
                    cells: vec![
                        plain(last),
                        plain(b.first_clock.clone().unwrap_or_else(|| "—".to_owned())),
                        plain(from),
                        plain(port),
                        plain(hits),
                        plain(
                            b.interface
                                .clone()
                                .map_or("—".to_owned(), |i| bound_text(&i)),
                        ),
                        plain(
                            match b.direction {
                                Some(Direction::Inbound) => "in",
                                Some(Direction::Outbound) => "out",
                                None => "—",
                            }
                            .to_owned(),
                        ),
                        kind_cell(b, theme),
                        plain(name.unwrap_or_default()),
                    ],
                    ..Row::default()
                }
            })
            .collect(),
        search,
    )
}

/// TIME and EVENT are as wide as their cells; the text takes the rest and is
/// cut at the pane's edge. On a narrow pane TIME goes first, then EVENT.
pub fn events_columns() -> Vec<Column> {
    vec![
        Column::new("TIME", Align::Left, 5, 1),
        Column::new("EVENT", Align::Left, 5, 2),
        Column::new("DETAIL", Align::Left, 8, 3).fill(1),
    ]
}

fn event_kind_word(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Neighbour => "neighbour",
        EventKind::Port => "port",
        EventKind::Firewall => "firewall",
        EventKind::Connection => "connection",
    }
}

/// One row per event, newest first. A danger or warning event's whole row is
/// in that colour; a missing clock is a dash.
pub fn event_rows(state: &AppState, theme: &Theme, search: &str) -> Vec<Row> {
    filter_rows(
        state
            .events()
            .iter()
            .map(|e| Row {
                cells: vec![
                    Cell::new(e.clock.clone().unwrap_or_else(|| "—".to_owned())),
                    Cell::new(event_kind_word(e.kind)),
                    Cell::new(whole_text(&e.text)),
                ],
                style: match e.level {
                    EventLevel::Danger => theme.blocked(),
                    EventLevel::Warning => theme.warning(),
                    EventLevel::Normal => Style::default(),
                },
            })
            .collect(),
        search,
    )
}

pub fn listening_columns() -> Vec<Column> {
    vec![
        Column::new("PORT", Align::Left, 8, 4),
        Column::new("APP", Align::Left, 8, 2).fill(1),
        Column::new("PID", Align::Left, 5, 0),
        Column::new("BIND", Align::Left, 9, 1),
        Column::new("FIREWALL", Align::Left, 12, 3),
    ]
}

/// The ports as Listening Ports draws them: open first, then unknown,
/// limited, blocked and local, each by port, protocol and bind address.
fn by_exposure(mut ports: Vec<ListeningPort>) -> Vec<ListeningPort> {
    let rank = |p: &ListeningPort| match p.exposure {
        Exposure::Open(_) => 0,
        Exposure::Unknown(_) => 1,
        Exposure::Limited(_) => 2,
        Exposure::Blocked(_) => 3,
        Exposure::Local => 4,
    };
    ports.sort_by_key(|p| {
        (
            rank(p),
            p.listener.port,
            protocol_name(p.listener.protocol),
            p.listener.address,
        )
    });
    ports
}

fn first_app(p: &ListeningPort) -> String {
    p.listener
        .owners
        .first()
        .map_or("—".to_owned(), |o| file_name(&o.executable))
}

pub fn listening_rows(state: &AppState, theme: &Theme, search: &str) -> Vec<Row> {
    listening_rows_for(state, theme, search, false)
}

pub fn listening_zoom_columns() -> Vec<Column> {
    vec![
        Column::new("PORT", Align::Left, 8, 7),
        Column::new("APP", Align::Left, 8, 6).at_most(APP_MAX),
        Column::new("PID", Align::Left, 5, 3),
        Column::new("BIND", Align::Left, 9, 5),
        Column::new("FIREWALL", Align::Left, 12, 8),
        Column::new("RULE", Align::Left, 14, 2).at_most(RULE_MAX),
        Column::new("PATH", Align::Left, 10, 1).fill(1),
    ]
}

fn rule_text(exposure: &Exposure) -> String {
    match exposure {
        Exposure::Open(rule) | Exposure::Limited(rule) | Exposure::Blocked(rule) => rule
            .as_deref()
            .map_or("default policy".to_owned(), bound_text),
        Exposure::Local => "loopback only".to_owned(),
        Exposure::Unknown(_) => "—".to_owned(),
    }
}

/// The zoomed rows add the deciding rule and the full executable path.
fn listening_rows_for(state: &AppState, theme: &Theme, search: &str, zoom: bool) -> Vec<Row> {
    let read = state.rule_snapshot().is_some();
    filter_rows(
        by_exposure(state.listening_ports())
            .into_iter()
            .map(|p| {
                let (text, style) = if read {
                    exposure_cell(&p.exposure, theme)
                } else {
                    ("· …", theme.muted())
                };
                let owner = p.listener.owners.first();
                let mut cells = vec![
                    port_text(Some(p.listener.port), p.listener.protocol),
                    first_app(&p),
                    owner.map_or("—".to_owned(), |o| o.pid.to_string()),
                    p.listener.address.to_string(),
                    text.to_owned(),
                ];
                if zoom {
                    cells.push(if read {
                        rule_text(&p.exposure)
                    } else {
                        "—".to_owned()
                    });
                    cells.push(owner.map_or("—".to_owned(), |o| {
                        whole_text(&o.executable.path.to_string_lossy())
                    }));
                }
                let mut row = Row::new(cells);
                row.cells[4].style = Some(style);
                row
            })
            .collect(),
        search,
    )
}

pub fn listening_zoom_rows(state: &AppState, theme: &Theme, search: &str) -> Vec<Row> {
    listening_rows_for(state, theme, search, true)
}

pub fn interface_columns() -> Vec<Column> {
    vec![
        Column::new("", Align::Left, 1, 9),
        Column::new("INTERFACE", Align::Left, 9, 8).fill(1),
        Column::new("↓ IN", Align::Right, 10, 7).at_least(10),
        Column::new("↑ OUT", Align::Right, 10, 6).at_least(10),
        Column::new("↓ TOTAL", Align::Right, 9, 5).at_least(8),
        Column::new("↑ TOTAL", Align::Right, 9, 4).at_least(8),
    ]
}

/// Every interface with rates and session totals; the plotted one is marked.
pub fn interface_rows(
    state: &AppState,
    theme: &Theme,
    search: &str,
    plotted: Option<&str>,
) -> Vec<Row> {
    filter_rows(
        state
            .interfaces()
            .into_iter()
            .map(|i| {
                let mut row = Row::new([
                    if plotted == Some(i.name.as_str()) {
                        "▶"
                    } else {
                        " "
                    }
                    .to_owned(),
                    bound_text(&i.name),
                    format_rate(i.download),
                    format_rate(i.upload),
                    format_bytes(i.session.download),
                    format_bytes(i.session.upload),
                ]);
                style_rate_cells(&mut row, theme, 2, i.download, i.upload);
                row
            })
            .collect(),
        search,
    )
}

/// The zoomed pane's columns and its rows after the pane's search.
pub fn zoom_table(
    state: &AppState,
    theme: &Theme,
    pane: Pane,
    search: &str,
    names: Option<&ReverseDns>,
    plotted: Option<&str>,
) -> (Vec<Column>, Vec<Row>) {
    match pane {
        Pane::AppTraffic => (
            app_traffic_zoom_columns(),
            app_traffic_zoom_rows(state, theme, search, names),
        ),
        Pane::FirewallBlocks => (
            blocked_zoom_columns(),
            blocked_zoom_rows(state, theme, search, names),
        ),
        Pane::ListeningPorts => (
            listening_zoom_columns(),
            listening_zoom_rows(state, theme, search),
        ),
        Pane::Bandwidth => (
            interface_columns(),
            interface_rows(state, theme, search, plotted),
        ),
        Pane::FirewallRules => (rule_zoom_columns(), rule_zoom_rows(state, theme, search)),
        Pane::NetworkEvents => (events_columns(), event_rows(state, theme, search)),
        Pane::Neighbors => (
            neighbor_zoom_columns(names.is_some()),
            neighbor_zoom_rows(state, theme, search, names),
        ),
        Pane::WifiNetworks => (wifi_zoom_columns(), wifi_zoom_rows(state, theme, search)),
    }
}

/// The overview: ADDRESS survives longest, then MAC, then NAME. NAME is as
/// wide as the longest name and ADDRESS takes the rest, never under 15 cells;
/// MAC is as wide as its cells. With names off there is no NAME column.
pub fn neighbor_columns(names: bool) -> Vec<Column> {
    let mut columns = vec![
        Column::new("ADDRESS", Align::Left, NEIGHBOR_ADDRESS_WIDTH, 3).fill(2),
        Column::new("NAME", Align::Left, 4, 1).fill(1),
        Column::new("MAC", Align::Left, 17, 2),
    ];
    if !names {
        columns.remove(1);
    }
    columns
}

/// Zoom adds STATE and INTERFACE; INTERFACE goes first when the pane is
/// narrow, then STATE.
pub fn neighbor_zoom_columns(names: bool) -> Vec<Column> {
    let mut columns = vec![
        Column::new("ADDRESS", Align::Left, NEIGHBOR_ADDRESS_WIDTH, 5).fill(2),
        Column::new("NAME", Align::Left, 4, 3).fill(1),
        Column::new("MAC", Align::Left, 17, 4),
        Column::new("STATE", Align::Left, 10, 2).at_most(10),
        Column::new("INTERFACE", Align::Left, 9, 1).at_most(16),
    ];
    if !names {
        columns.remove(1);
    }
    columns
}

/// The least ADDRESS is given: a whole IPv4 address.
const NEIGHBOR_ADDRESS_WIDTH: u16 = 15;

/// The neighbours, or none before the first snapshot or when it is unavailable.
fn neighbor_entries(state: &AppState) -> &[Neighbor] {
    state.neighbors().and_then(Result::ok).unwrap_or_default()
}

/// The neighbours the pane lists, in address order.
pub fn neighbor_order(state: &AppState) -> Vec<IpAddr> {
    neighbor_entries(state).iter().map(|n| n.address).collect()
}

/// One neighbour's cells: address, the name when names are on, the hardware
/// address, and in zoom the state word and the interface. A neighbour the
/// kernel is failing to reach or still resolving has its whole row in the
/// warning style.
fn neighbor_row(n: &Neighbor, theme: &Theme, names: Option<&ReverseDns>, zoom: bool) -> Row {
    let mut cells = vec![Cell::new(n.address.to_string())];
    if names.is_some() {
        cells.push(Cell::new(
            name_of(names, n.address)
                .map(bound_text)
                .unwrap_or_default(),
        ));
    }
    cells.push(Cell::new(
        n.mac.as_deref().map_or("—".to_owned(), bound_text),
    ));
    if zoom {
        cells.push(Cell::new(bound_text(&n.state)));
        cells.push(Cell::new(bound_text(&n.interface)));
    }
    let in_trouble = matches!(n.state.as_str(), "failed" | "incomplete");
    Row {
        cells,
        style: if in_trouble {
            theme.warning()
        } else {
            Style::default()
        },
    }
}

/// One row per neighbour: address, name (empty when unknown) and hardware
/// address.
pub fn neighbor_rows(
    state: &AppState,
    theme: &Theme,
    search: &str,
    names: Option<&ReverseDns>,
) -> Vec<Row> {
    neighbor_rows_for(state, theme, search, names, false)
}

/// The overview's cells with the address whole, the state and the interface.
pub fn neighbor_zoom_rows(
    state: &AppState,
    theme: &Theme,
    search: &str,
    names: Option<&ReverseDns>,
) -> Vec<Row> {
    neighbor_rows_for(state, theme, search, names, true)
}

fn neighbor_rows_for(
    state: &AppState,
    theme: &Theme,
    search: &str,
    names: Option<&ReverseDns>,
    zoom: bool,
) -> Vec<Row> {
    filter_rows(
        neighbor_entries(state)
            .iter()
            .map(|n| neighbor_row(n, theme, names, zoom))
            .collect(),
        search,
    )
}

/// What Neighbors shows when it has no rows: nothing before the first
/// snapshot or when the table is unreadable.
pub fn neighbors_empty(state: &AppState) -> &'static str {
    match state.neighbors() {
        Some(Ok(_)) => "no neighbors",
        _ => "",
    }
}

pub fn rule_columns() -> Vec<Column> {
    vec![
        // IFACE is as wide as its widest value (up to IFACE_MAX) and APP takes
        // the room that is left. With APP dropped, IFACE takes it.
        Column::new("IFACE", Align::Left, 5, 2)
            .fill(1)
            .at_most(IFACE_MAX),
        Column::new("APP", Align::Left, 3, 1).fill(2),
        Column::new("DIR", Align::Left, 3, 6),
        Column::new("ACTION", Align::Right, 6, 5),
        Column::new("PORT", Align::Right, 7, 4).lead(2),
        Column::new("REMOTE", Align::Right, 8, 3)
            .lead(2)
            .at_most(REMOTE_MAX),
    ]
}

pub fn rule_zoom_columns() -> Vec<Column> {
    let mut columns = rule_columns();
    // IFACE and APP are fixed columns here, as wide as their widest values up
    // to their ceilings; RULE takes the rest.
    columns[0].title = "INTERFACE".into();
    columns[0].min_width = 9;
    columns[2].title = "DIRECTION".into();
    columns[2].min_width = 9;
    columns[0].fill = None;
    columns[1].fill = None;
    columns[1].max_width = Some(APP_MAX);
    columns.push(Column::new("RULE", Align::Left, 14, 0).fill(1));
    columns
}

/// Which address families a row stands for.
#[derive(Clone, Copy, PartialEq)]
enum Families {
    V4,
    V6,
    Both,
}

/// The rules in snapshot order. Two rules alike but for the IPv6 flag (and
/// the text) are one entry at the first one's place, holding the first's text.
fn merged_rules(state: &AppState) -> Vec<(Rule, Families)> {
    let Some(RuleSnapshot::Active { rules, .. }) = state.rule_snapshot() else {
        return Vec::new();
    };
    let mut merged: Vec<(Rule, Families)> = Vec::new();
    for rule in rules {
        let family = if rule.ipv6 {
            Families::V6
        } else {
            Families::V4
        };
        let twin = merged.iter_mut().find(|(other, seen)| {
            *seen != Families::Both
                && *seen != family
                && Rule {
                    ipv6: other.ipv6,
                    text: String::new(),
                    ..rule.clone()
                } == Rule {
                    text: String::new(),
                    ..other.clone()
                }
        });
        match twin {
            Some((_, seen)) => *seen = Families::Both,
            None => merged.push((rule.clone(), family)),
        }
    }
    merged
}

fn network_text(network: &Network) -> String {
    let full = if network.address.is_ipv4() { 32 } else { 128 };
    if network.prefix == full {
        network.address.to_string()
    } else {
        format!("{}/{}", network.address, network.prefix)
    }
}

fn ports_text(rule: &Rule) -> String {
    let ports = rule
        .ports
        .iter()
        .map(|r| {
            if r.start() == r.end() {
                r.start().to_string()
            } else {
                format!("{}-{}", r.start(), r.end())
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    match (ports.is_empty(), rule.protocol) {
        (true, None) => "any".to_owned(),
        (true, Some(p)) => format!("any/{}", protocol_name(p)),
        (false, None) => ports,
        (false, Some(p)) => format!("{ports}/{}", protocol_name(p)),
    }
}

/// The programs listening, in Listening Ports' order, with the port and
/// protocol each listens on. A listener with no owning process is left out.
fn rule_listeners(state: &AppState) -> Vec<(u16, Protocol, String)> {
    state
        .listening_ports()
        .into_iter()
        .filter_map(|p| {
            let owner = p.listener.owners.first()?;
            Some((
                p.listener.port,
                p.listener.protocol,
                file_name(&owner.executable),
            ))
        })
        .collect()
}

/// An inbound rule's APP cell: the first program listening on one of its
/// ports with a matching protocol and how many others; `—` when none is.
/// Empty for an outbound rule and for a rule on any port.
fn rule_app(rule: &Rule, listeners: &[(u16, Protocol, String)]) -> String {
    if rule.direction != RuleDirection::In || rule.ports.is_empty() {
        return String::new();
    }
    // `listeners` is in port order, so each range is a slice of it.
    let mut hits: Vec<usize> = rule
        .ports
        .iter()
        .flat_map(|range| {
            let from = listeners.partition_point(|l| l.0 < *range.start());
            let to = listeners.partition_point(|l| l.0 <= *range.end());
            from..to
        })
        .filter(|&i| rule.protocol.is_none_or(|p| p == listeners[i].1))
        .collect();
    hits.sort_unstable();
    hits.dedup();
    let mut names: Vec<&str> = Vec::new();
    for i in hits {
        if !names.contains(&listeners[i].2.as_str()) {
            names.push(&listeners[i].2);
        }
    }
    match names.as_slice() {
        [] => "—".to_owned(),
        [only] => (*only).to_owned(),
        [first, others @ ..] => format!("{first} +{}", others.len()),
    }
}

fn rule_row(
    theme: &Theme,
    rule: &Rule,
    families: Families,
    listeners: &[(u16, Protocol, String)],
) -> Row {
    let (direction, remote) = match rule.direction {
        RuleDirection::In => (
            "in",
            match &rule.source {
                RuleSource::Anywhere => None,
                RuleSource::Specific(text) => Some(bound_text(text)),
            },
        ),
        RuleDirection::Out => ("out", rule.destination.as_ref().map(network_text)),
    };
    let mark = match families {
        Families::Both => "",
        Families::V4 => " v4",
        Families::V6 => " v6",
    };
    let (action, style) = match rule.action {
        RuleAction::Allow => ("allow", theme.observed()),
        RuleAction::Limit => ("limit", theme.warning()),
        RuleAction::Deny => ("deny", theme.blocked()),
        RuleAction::Reject => ("reject", theme.blocked()),
    };
    let mut row = Row::new([
        rule.interface
            .as_deref()
            .map_or("all".to_owned(), bound_text),
        rule_app(rule, listeners),
        format!("{direction}{mark}"),
        action.to_owned(),
        ports_text(rule),
        remote.unwrap_or_else(|| "anywhere".to_owned()),
    ]);
    row.cells[3].style = Some(style);
    row
}

/// One row per rule, v4 and v6 twins merged and a one-family rule marked.
pub fn rule_rows(state: &AppState, theme: &Theme, search: &str) -> Vec<Row> {
    let listeners = rule_listeners(state);
    filter_rows(
        merged_rules(state)
            .iter()
            .map(|(rule, families)| rule_row(theme, rule, *families, &listeners))
            .collect(),
        search,
    )
}

/// The overview's cells and the rule's text as UFW records it.
pub fn rule_zoom_rows(state: &AppState, theme: &Theme, search: &str) -> Vec<Row> {
    let listeners = rule_listeners(state);
    filter_rows(
        merged_rules(state)
            .iter()
            .map(|(rule, families)| {
                let mut row = rule_row(theme, rule, *families, &listeners);
                row.cells.push(Cell::new(whole_text(&rule.text)));
                row
            })
            .collect(),
        search,
    )
}

/// What Firewall Rules shows when it has no rows: nothing unless UFW is
/// active with no rules.
pub fn rules_empty(state: &AppState) -> &'static str {
    match state.rule_snapshot() {
        Some(RuleSnapshot::Active { .. }) => "no rules",
        _ => "",
    }
}

fn exposure_cell(exposure: &Exposure, theme: &Theme) -> (&'static str, Style) {
    match exposure {
        Exposure::Open(_) => ("● open", theme.open()),
        Exposure::Limited(_) => ("◐ limited", theme.warning()),
        Exposure::Blocked(_) => ("· blocked", theme.observed()),
        Exposure::Local => ("· local", theme.muted()),
        Exposure::Unknown(reason) if reason == "ufw off" => ("? ufw off", theme.muted()),
        Exposure::Unknown(_) => ("? unreadable", theme.muted()),
    }
}

/// How well one data source is doing, for the header dots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Unknown,
    Ok,
    Warn,
    Bad,
}

impl Level {
    pub fn colour(self, theme: &Theme) -> Color {
        match self {
            Level::Unknown => theme.muted,
            Level::Ok => theme.ok,
            Level::Warn => theme.warning,
            Level::Bad => theme.danger,
        }
    }
}

pub fn indicators(state: &AppState) -> [(&'static str, Level); 4] {
    let health = state.source_health();
    let capture_name = match health.capture.as_ref().map(|s| s.origin) {
        Some(CaptureOrigin::Dumpcap) => "capture (dumpcap)",
        Some(CaptureOrigin::Own) | None => "capture",
    };
    let capture = health
        .capture
        .as_ref()
        .map_or(Level::Unknown, |s| match s.health {
            CaptureHealth::Available => Level::Ok,
            CaptureHealth::Degraded(_) => Level::Warn,
            CaptureHealth::Cancelled => Level::Bad,
        });
    let firewall = health
        .firewall
        .as_ref()
        .map_or(Level::Unknown, |s| match s.health {
            FirewallHealth::Available | FirewallHealth::AwaitingEvents => Level::Ok,
            FirewallHealth::Degraded(_) | FirewallHealth::Disabled(_) => Level::Warn,
            FirewallHealth::Unavailable(_) | FirewallHealth::Cancelled => Level::Bad,
        });
    let interfaces = health
        .interfaces
        .as_ref()
        .map_or(Level::Unknown, |h| match h {
            CollectionHealth::Available => Level::Ok,
            CollectionHealth::Stale(_) => Level::Warn,
            CollectionHealth::Unavailable(_) => Level::Bad,
        });
    let apps = health
        .attribution
        .as_ref()
        .map_or(Level::Unknown, |s| match s.health {
            AttributionHealth::Available if s.limited => Level::Warn,
            AttributionHealth::Available => Level::Ok,
            AttributionHealth::Stale(_) => Level::Warn,
            AttributionHealth::Unavailable(_) => Level::Bad,
        });
    [
        (capture_name, capture),
        ("firewall", firewall),
        ("interfaces", interfaces),
        ("apps", apps),
    ]
}

fn unreadable_rules(why: &str) -> String {
    format!(
        "Cannot read firewall rules ({}). See docs/firewall.md",
        reason(why)
    )
}

/// What `dumpcap` gave, whole but for a bound on a runaway line: the pane wraps it over
/// its rows and cuts the end with an ellipsis when it still does not fit.
fn dumpcap_reason(text: &str) -> String {
    whole_text(text).chars().take(200).collect()
}

fn reason(text: &str) -> String {
    bound_text(text).chars().take(30).collect()
}

/// The one plain sentence a pane shows when a source it depends on is not
/// healthy, or `None` when everything it needs is working (or has not
/// reported yet).
pub fn notice(state: &AppState, pane: Pane) -> Option<String> {
    let health = state.source_health();
    let capture = || {
        health.capture.as_ref().and_then(|s| match &s.health {
            CaptureHealth::Available => None,
            CaptureHealth::Degraded(r) => Some(match s.origin {
                CaptureOrigin::Dumpcap => format!(
                    "Capture through dumpcap has stopped: {}",
                    dumpcap_reason(stopped_reason(r).unwrap_or(r))
                ),
                CaptureOrigin::Own => format!(
                    "Packet capture is degraded ({}). See the README.",
                    reason(r)
                ),
            }),
            CaptureHealth::Cancelled => Some("Packet capture has stopped.".to_owned()),
        })
    };
    let attribution = |lead: &str, stale: &str| {
        health.attribution.as_ref().and_then(|s| match &s.health {
            AttributionHealth::Available => None,
            AttributionHealth::Unavailable(r) => {
                Some(format!("{lead} ({}). See the README.", reason(r)))
            }
            AttributionHealth::Stale(r) => {
                Some(format!("{stale} ({}). See the README.", reason(r)))
            }
        })
    };
    match pane {
        Pane::AppTraffic => capture()
            .or_else(|| attribution("App names are unavailable", "App names are out of date"))
            .or_else(|| {
                health.attribution.as_ref().filter(|s| s.limited).map(|_| {
                    "Other users' programs cannot be named: needs cap_sys_ptrace. \
                     See README, Running without sudo."
                        .to_owned()
                })
            }),
        Pane::FirewallBlocks => health.firewall.as_ref().and_then(|s| match &s.health {
            FirewallHealth::Available | FirewallHealth::AwaitingEvents => None,
            FirewallHealth::Disabled(r) => Some(format!(
                "UFW logging is off ({}). See docs/firewall.md",
                reason(r)
            )),
            FirewallHealth::Unavailable(r) => Some(format!(
                "Cannot read the firewall log ({}). See docs/firewall.md",
                reason(r)
            )),
            FirewallHealth::Degraded(r) => Some(format!(
                "Firewall log is partly unreadable ({}). See docs/firewall.md",
                reason(r)
            )),
            FirewallHealth::Cancelled => Some("Firewall log reading has stopped.".to_owned()),
        }),
        Pane::ListeningPorts => attribution(
            "No ports listed: app attribution is unavailable",
            "Ports may be out of date",
        )
        .or_else(|| match state.rule_snapshot() {
            Some(RuleSnapshot::Unavailable(r)) => Some(unreadable_rules(r)),
            Some(RuleSnapshot::Inactive) => {
                Some("UFW is off, so exposure is unknown. See docs/firewall.md".to_owned())
            }
            Some(RuleSnapshot::Active { .. }) | None => None,
        }),
        Pane::FirewallRules => match state.rule_snapshot() {
            Some(RuleSnapshot::Unavailable(r)) => Some(unreadable_rules(r)),
            Some(RuleSnapshot::Inactive) => {
                Some("UFW is off, so there are no rules to show. See docs/firewall.md".to_owned())
            }
            Some(RuleSnapshot::Active { .. }) | None => None,
        },
        Pane::Neighbors => match state.neighbors() {
            Some(Err(why)) => Some(format!("Cannot read the neighbor table ({}).", reason(why))),
            _ => None,
        },
        Pane::WifiNetworks => match (state.wifi_scan(), state.wifi()) {
            (Some(WifiScan::Refused { reason: why, .. }), _) => {
                Some(format!("scan refused: {}", reason(why)))
            }
            (_, Some(Err(why))) => Some(format!("Wi-Fi unavailable: {}.", reason(why))),
            _ => None,
        },
        Pane::NetworkEvents => None,
        Pane::Bandwidth => health.interfaces.as_ref().and_then(|h| match h {
            CollectionHealth::Available => None,
            CollectionHealth::Unavailable(r) => {
                Some(format!("Cannot read interface counters ({}).", reason(r)))
            }
            CollectionHealth::Stale(r) => Some(format!(
                "Interface counters are out of date ({}).",
                reason(r)
            )),
        }),
    }
}

/// A quiet line above a pane's rows: a pane still waiting on its first
/// data says so, as opposed to a failure, and Firewall Rules gives both
/// default policies.
pub fn pending(state: &AppState, pane: Pane) -> Option<String> {
    match (pane, state.rule_snapshot()) {
        (Pane::Neighbors, _) => state
            .neighbors()
            .is_none()
            .then(|| "reading neighbors…".to_owned()),
        (Pane::WifiNetworks, _) => {
            if matches!(state.wifi_scan(), Some(WifiScan::Requested(_))) {
                Some("scan requested…".to_owned())
            } else {
                state
                    .wifi()
                    .is_none()
                    .then(|| "reading Wi-Fi networks…".to_owned())
            }
        }
        (Pane::ListeningPorts | Pane::FirewallRules, None) => {
            Some("reading firewall rules…".to_owned())
        }
        (
            Pane::FirewallRules,
            Some(RuleSnapshot::Active {
                default_incoming,
                default_outgoing,
                ..
            }),
        ) => Some(format!(
            "default: {} in · {} out",
            default_incoming.label(),
            default_outgoing.label()
        )),
        _ => None,
    }
}

/// The most a security string is given, so one long value cannot starve NETWORK.
const WIFI_SECURITY_MAX: u16 = 12;

/// The overview: NETWORK survives longest and takes what the others leave,
/// then SIGNAL, SECURITY and CHANNEL, which is last. The others are as wide as their cells
/// or titles; their `min_width`s (eight for the bars and a number up to 100,
/// twelve for `11 · 2.4G`, nine for `WPA1 WPA2`) only decide what is dropped.
pub fn wifi_columns() -> Vec<Column> {
    vec![
        Column::new("NETWORK", Align::Left, 8, 4).fill(1),
        Column::new("SIGNAL", Align::Left, 8, 3),
        Column::new("SECURITY", Align::Left, 9, 2).at_most(WIFI_SECURITY_MAX),
        Column::new("CHANNEL", Align::Left, 12, 1),
    ]
}

/// Zoom adds BSSID (the hardware address) and FREQUENCY; FREQUENCY goes first when the
/// pane is narrow, then BSSID.
pub fn wifi_zoom_columns() -> Vec<Column> {
    vec![
        Column::new("NETWORK", Align::Left, 8, 6).fill(1),
        Column::new("SIGNAL", Align::Left, 8, 5),
        Column::new("SECURITY", Align::Left, 9, 4).at_most(WIFI_SECURITY_MAX),
        Column::new("BSSID", Align::Left, 17, 2),
        Column::new("FREQUENCY", Align::Right, 9, 1),
        Column::new("CHANNEL", Align::Left, 12, 3),
    ]
}

/// Four bars, lit from the left; an unlit bar is a low dot. 80 and above is
/// four, 55 to 79 three, 30 to 54 two, anything below one.
fn signal_text(signal: u8) -> String {
    let lit = match signal {
        80.. => 4,
        55..=79 => 3,
        30..=54 => 2,
        _ => 1,
    };
    let bars: String = "▂▄▆█"
        .chars()
        .enumerate()
        .map(|(n, bar)| if n < lit { bar } else { '·' })
        .collect();
    format!("{bars} {signal:>3}")
}

/// The channel, right-justified in three cells, and its band, written `2.4G`,
/// `5G` or `6G`: below 3000 MHz is 2.4 GHz, below 5925 is 5 GHz, otherwise
/// 6 GHz. The dots and the bands of a column of them start together.
fn channel_text(channel: u16, frequency_mhz: u32) -> String {
    format!("{channel:>3} · {}", band_text(frequency_mhz))
}

/// The band of a frequency, written `2.4G`, `5G` or `6G`.
pub(super) fn band_text(frequency_mhz: u32) -> &'static str {
    match frequency_mhz {
        ..3000 => "2.4G",
        3000..5925 => "5G",
        _ => "6G",
    }
}

/// How long ago a remembered access point was listed, in at most eight
/// cells: seconds below a minute, minutes below an hour, hours below a day,
/// then days (a day reads `seen 1d`), held at `seen 99d`.
fn seen_text(ago: Duration) -> String {
    let seconds = ago.as_secs();
    let (count, unit) = match seconds {
        ..60 => (seconds, 's'),
        60..3600 => (seconds / 60, 'm'),
        3600..86_400 => (seconds / 3600, 'h'),
        _ => ((seconds / 86_400).min(99), 'd'),
    };
    format!("seen {count}{unit}")
}

fn wifi_row(entry: &WifiEntry, theme: &Theme, zoom: bool) -> Row {
    let point = &entry.point;
    let name = point.ssid.as_deref().map(bound_text).unwrap_or_default();
    let mark = if point.in_use { "● " } else { "  " };
    let network = if name.is_empty() {
        Cell::new(format!("{mark}(hidden)")).style(theme.muted())
    } else {
        Cell::new(format!("{mark}{name}"))
    };
    let security = bound_text(&point.security);
    let security = if security.is_empty() {
        Cell::new("open").style(theme.warning())
    } else {
        Cell::new(security)
    };
    let signal = match entry.seen_ago {
        None => signal_text(point.signal),
        Some(ago) => seen_text(ago),
    };
    let mut cells = vec![network, Cell::new(signal), security];
    if zoom {
        cells.push(Cell::new(bound_text(&point.bssid)));
        cells.push(Cell::new(format!("{} MHz", point.frequency_mhz)));
    }
    cells.push(Cell::new(channel_text(point.channel, point.frequency_mhz)));
    let mut row = Row {
        cells,
        style: Style::default(),
    };
    if entry.seen_ago.is_some() {
        // A cell's own style overrides the row's, so the open and hidden
        // cells are muted by hand too.
        row.style = theme.muted();
        for cell in &mut row.cells {
            cell.style = Some(theme.muted());
        }
    }
    row
}

fn wifi_rows_for(state: &AppState, theme: &Theme, search: &str, zoom: bool) -> Vec<Row> {
    filter_rows(
        state
            .wifi()
            .and_then(Result::ok)
            .unwrap_or_default()
            .iter()
            .map(|entry| wifi_row(entry, theme, zoom))
            .collect(),
        search,
    )
}

/// One row per access point: the listed ones strongest first, then the
/// remembered ones, most recently seen first.
pub fn wifi_rows(state: &AppState, theme: &Theme, search: &str) -> Vec<Row> {
    wifi_rows_for(state, theme, search, false)
}

/// The overview's cells with the hardware address and the frequency.
pub fn wifi_zoom_rows(state: &AppState, theme: &Theme, search: &str) -> Vec<Row> {
    wifi_rows_for(state, theme, search, true)
}

/// What Wi-Fi Networks shows when it has no rows: nothing before the first
/// snapshot or when the list is unreadable.
pub fn wifi_empty(state: &AppState) -> &'static str {
    match state.wifi() {
        Some(Ok(_)) => "no Wi-Fi networks found",
        _ => "",
    }
}

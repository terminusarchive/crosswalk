pub mod chart;
pub mod format;
pub mod input;
pub mod map;
pub mod panes;
pub mod table;
pub mod theme;
mod zone_rows;

pub use input::Interaction;
pub use theme::Theme;

fn page_name(page: Page) -> &'static str {
    match page {
        Page::Traffic => "Traffic",
        Page::NetworkFirewall => "Network & Firewall",
    }
}

/// The terminal title for the view on screen: the open map, else the page.
pub fn terminal_title(page: Page, map_open: bool) -> String {
    let view = if map_open { "Map" } else { page_name(page) };
    format!("Crosswalk: {view}")
}

use chart::Chart;
use table::{Column, Rendered, Row, Table};

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
};

use crate::{
    dns::ReverseDns,
    state::{AppState, Page, Pane},
};

const OVERVIEW_MIN_WIDTH: u16 = 110;
const OVERVIEW_MIN_HEIGHT: u16 = 24;
const BANDWIDTH_HEIGHT: u16 = 7;
/// Firewall Rules' policy line, header and three rules, and the border.
const BOTTOM_ROW_MIN: u16 = 7;

/// What a frame needs besides the state: which pane has focus, which
/// interface the chart plots, each pane's search text, and the zoom and
/// help state.
#[derive(Clone)]
pub struct Overview<'a> {
    focus: Pane,
    interface: Option<&'a str>,
    searches: Vec<(Pane, &'a str)>,
    typing: Option<Pane>,
    help: bool,
    names: Option<&'a ReverseDns>,
    names_on: bool,
    /// The theme now shown, for the header.
    theme_name: &'static str,
    new_blocks: u64,
    zoom: Option<Pane>,
    /// The focused pane's selected row and scroll offset.
    selected: usize,
    scroll: usize,
    /// The network map, if it is shown in place of the page: what to draw
    /// (`None` without a default route) and how far its rows are scrolled.
    map: Option<(Option<map::Map>, usize)>,
}

/// What a frame settled on, for the caller to keep between frames.
enum Drawn {
    Table(Rendered),
    Map(map::MapScroll),
}

impl<'a> Overview<'a> {
    pub fn new(focus: Pane) -> Self {
        Self {
            focus,
            interface: None,
            searches: Vec::new(),
            typing: None,
            help: false,
            names: None,
            names_on: false,
            theme_name: Theme::NAMES[0],
            new_blocks: 0,
            zoom: None,
            selected: 0,
            scroll: 0,
            map: None,
        }
    }

    /// Name the theme now shown, for the header.
    pub fn theme_name(mut self, name: &'static str) -> Self {
        self.theme_name = name;
        self
    }

    /// Show the network map in place of the page, its device rows scrolled by `offset`.
    pub fn map(mut self, map: Option<map::Map>, offset: usize) -> Self {
        self.map = Some((map, offset));
        self
    }

    /// Plot this interface instead of the default route's.
    pub fn interface(mut self, name: &'a str) -> Self {
        self.interface = Some(name);
        self
    }

    pub fn search(mut self, pane: Pane, text: &'a str) -> Self {
        self.searches.retain(|(p, _)| *p != pane);
        self.searches.push((pane, text));
        self
    }

    /// Draw this pane's search field as open for typing.
    pub fn typing(mut self, pane: Pane) -> Self {
        self.typing = Some(pane);
        self
    }

    pub fn help(mut self, open: bool) -> Self {
        self.help = open;
        self
    }

    /// Show reverse-DNS names where known.
    pub fn names(mut self, dns: &'a ReverseDns) -> Self {
        self.names = Some(dns);
        self
    }

    /// Tell the footer whether names are on.
    pub(crate) fn names_on(mut self, on: bool) -> Self {
        self.names_on = on;
        self
    }

    /// Blocks recorded since Network & Firewall was last shown, for the header.
    pub(crate) fn new_blocks(mut self, count: u64) -> Self {
        self.new_blocks = count;
        self
    }

    pub(crate) fn zoom(mut self, pane: Pane) -> Self {
        self.zoom = Some(pane);
        self
    }

    /// The focused pane's selected row and scroll offset.
    pub(crate) fn position(mut self, selected: usize, scroll: usize) -> Self {
        self.selected = selected;
        self.scroll = scroll;
        self
    }

    fn search_for(&self, pane: Pane) -> &'a str {
        self.searches
            .iter()
            .find(|(p, _)| *p == pane)
            .map_or("", |(_, text)| text)
    }
}

/// Everything one list pane draws.
struct ListPane<'a> {
    pane: Pane,
    title: &'a str,
    notice: Option<String>,
    pending: Option<String>,
    columns: Vec<Column>,
    rows: Vec<Row>,
    empty: &'a str,
    footer: Option<String>,
}

/// Traffic: Bandwidth at its fixed height, then App Traffic over a bottom row
/// of Listening Ports beside Firewall Rules in equal widths. The bottom row
/// takes two fifths of the rest but never less than `BOTTOM_ROW_MIN` rows,
/// so App Traffic stays the larger. Returned as bandwidth, apps, ports, rules.
fn traffic_layout(area: Rect) -> [Rect; 4] {
    let [bandwidth, rest] =
        Layout::vertical([Constraint::Length(BANDWIDTH_HEIGHT), Constraint::Min(0)]).areas(area);
    let bottom = (rest.height * 2 / 5).max(BOTTOM_ROW_MIN).min(rest.height);
    let [apps, row] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(bottom)]).areas(rest);
    let [ports, rules] = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).areas(row);
    [bandwidth, apps, ports, rules]
}

/// Network & Firewall: two columns of equal width, each two panes of equal
/// height. Left, Firewall Blocks over Network Events; right, Wi-Fi Networks
/// over Neighbors. Returned in that order: blocks, events, wifi, neighbors.
fn network_firewall_layout(area: Rect) -> [Rect; 4] {
    let [left, right] = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).areas(area);
    let [blocks, events] = Layout::vertical([Constraint::Fill(1), Constraint::Fill(1)]).areas(left);
    let [wifi, neighbors] =
        Layout::vertical([Constraint::Fill(1), Constraint::Fill(1)]).areas(right);
    [blocks, events, wifi, neighbors]
}

/// The overview area of a terminal `height` lines tall, less the header and footer.
fn overview_area(height: u16) -> Rect {
    Rect::new(0, 0, OVERVIEW_MIN_WIDTH, height.saturating_sub(2))
}

/// Rows that fit in the pane at `index` of the Network & Firewall layout (blocks,
/// events, Wi-Fi, neighbors) on the overview of a terminal `height` lines tall:
/// the pane's height, less its border and the header row.
pub(crate) fn overview_fit(index: usize, height: u16) -> usize {
    usize::from(
        network_firewall_layout(overview_area(height))[index]
            .height
            .saturating_sub(3),
    )
}

/// Rows that fit in a zoomed table on a terminal `height` lines tall.
pub(crate) fn zoom_fit(height: u16) -> usize {
    usize::from(height.saturating_sub(2 + 3))
}

pub fn draw(frame: &mut Frame<'_>, state: &AppState, theme: &Theme, view: &Overview<'_>) {
    render(frame, state, theme, view);
}

/// Draws the dashboard for the user's current interaction and keeps the
/// selection and scroll the table settled on.
pub fn draw_interactive(
    frame: &mut Frame<'_>,
    state: &AppState,
    theme: &Theme,
    interaction: &mut Interaction,
    dns: Option<&ReverseDns>,
) {
    let theme = &interaction.theme_to_draw(theme);
    let new_blocks = interaction.blocks_since_shown(state);
    interaction.refresh_map(state);
    let mut view = interaction.view(dns, new_blocks);
    if let Some((map, offset)) = interaction.map_scene(state, dns) {
        view = view.map(map, offset);
    }
    let drawn = render(frame, state, theme, &view);
    interaction.settle(drawn);
}

fn render(
    frame: &mut Frame<'_>,
    state: &AppState,
    theme: &Theme,
    view: &Overview<'_>,
) -> Option<Drawn> {
    let area = frame.area();
    frame.render_widget(Block::new().style(theme.background()), area);
    if area.width < OVERVIEW_MIN_WIDTH || area.height < OVERVIEW_MIN_HEIGHT {
        let message = format!(
            "Terminal too small: crosswalk needs at least {OVERVIEW_MIN_WIDTH}x{OVERVIEW_MIN_HEIGHT}, this is {}x{}.",
            area.width, area.height
        );
        frame.render_widget(
            Paragraph::new(message)
                .style(theme.warning())
                .wrap(Wrap { trim: true }),
            area,
        );
        return None;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);
    draw_header(frame, rows[0], state, theme, view);
    let drawn = match (&view.map, view.zoom) {
        (Some((map, offset)), _) => {
            Drawn::Map(map::draw_map(frame, rows[1], theme, map.as_ref(), *offset))
        }
        (None, Some(pane)) => Drawn::Table(draw_zoom(frame, rows[1], state, theme, view, pane)),
        (None, None) => Drawn::Table(draw_overview(frame, rows[1], state, theme, view)),
    };
    draw_footer(frame, rows[2], theme, view);
    if view.help {
        draw_help(frame, area, theme);
    }
    Some(drawn)
}

/// The page of the focused pane. Returns what the focused pane's table
/// settled on.
fn draw_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &AppState,
    theme: &Theme,
    view: &Overview<'_>,
) -> Rendered {
    let panes: Vec<(Pane, Rect)> = match view.focus.page() {
        Page::Traffic => {
            let [bandwidth, apps, ports, rules] = traffic_layout(area);
            vec![
                (Pane::Bandwidth, bandwidth),
                (Pane::AppTraffic, apps),
                (Pane::ListeningPorts, ports),
                (Pane::FirewallRules, rules),
            ]
        }
        Page::NetworkFirewall => {
            let [blocks, events, wifi, neighbors] = network_firewall_layout(area);
            vec![
                (Pane::FirewallBlocks, blocks),
                (Pane::NetworkEvents, events),
                (Pane::WifiNetworks, wifi),
                (Pane::Neighbors, neighbors),
            ]
        }
    };
    let mut focused = Rendered::EMPTY;
    for (pane, rect) in panes {
        match pane {
            Pane::Bandwidth => draw_bandwidth(frame, rect, state, theme, view),
            _ => {
                let drawn = draw_list(
                    frame,
                    rect,
                    theme,
                    view,
                    list_pane(state, theme, view, pane),
                );
                if pane == view.focus {
                    focused = drawn;
                }
            }
        }
    }
    focused
}

/// What a list pane shows on the overview.
fn list_pane<'a>(state: &AppState, theme: &Theme, view: &Overview<'_>, pane: Pane) -> ListPane<'a> {
    let search = view.search_for(pane);
    let mut list = ListPane {
        pane,
        title: pane_name(pane),
        notice: panes::notice(state, pane),
        pending: panes::pending(state, pane),
        columns: Vec::new(),
        rows: Vec::new(),
        empty: "",
        footer: None,
    };
    match pane {
        Pane::AppTraffic => {
            list.pending = None;
            list.columns = panes::app_traffic_columns();
            list.rows = panes::app_traffic_rows(
                state,
                theme,
                search,
                Some(panes::OVERVIEW_DESTINATIONS),
                view.names,
            );
            list.empty = "no outbound traffic yet";
            list.footer = panes::uncounted_line(state);
        }
        Pane::FirewallBlocks => {
            list.pending = None;
            list.columns = panes::blocked_columns();
            list.rows = panes::blocked_rows(state, theme, search, view.names);
            list.empty = "no blocks seen";
        }
        Pane::NetworkEvents => {
            list.columns = panes::events_columns();
            list.rows = panes::event_rows(state, theme, search);
            list.empty = "no events yet";
        }
        Pane::Neighbors => {
            list.columns = panes::neighbor_columns(view.names.is_some());
            list.rows = panes::neighbor_rows(state, theme, search, view.names);
            list.empty = panes::neighbors_empty(state);
        }
        Pane::FirewallRules => {
            list.columns = panes::rules_columns(state);
            list.rows = panes::rule_rows(state, theme, search);
            list.empty = panes::rules_empty(state);
        }
        Pane::ListeningPorts => {
            list.columns = panes::listening_columns();
            list.rows = panes::listening_rows(state, theme, search);
            list.empty = "no listening ports";
        }
        Pane::WifiNetworks => {
            list.columns = panes::wifi_columns();
            list.rows = panes::wifi_rows(state, theme, search);
            list.empty = panes::wifi_empty(state);
        }
        Pane::Bandwidth => {}
    }
    list
}

fn draw_header(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &AppState,
    theme: &Theme,
    view: &Overview<'_>,
) {
    let page = view.focus.page();
    let shown = |p: Page| {
        if p == page {
            theme.focus()
        } else {
            theme.muted()
        }
    };
    let mut left = vec![
        Span::raw(" "),
        Span::styled(page_name(Page::Traffic), shown(Page::Traffic)),
        Span::styled(" · ", theme.muted()),
        Span::styled(
            page_name(Page::NetworkFirewall),
            shown(Page::NetworkFirewall),
        ),
    ];
    if page == Page::Traffic && view.new_blocks > 0 {
        let count = if view.new_blocks > 99 {
            "99+".to_owned()
        } else {
            view.new_blocks.to_string()
        };
        left.push(Span::raw(" "));
        left.push(Span::styled(count, theme.warning()));
    }
    let room = usize::from(area.width).saturating_sub(Line::from(left.clone()).width() + 1);
    frame.render_widget(Paragraph::new(Line::from(left)), area);
    let mut spans = Vec::new();
    let mut indicators = panes::indicators(state, false);
    if indicators_width(&indicators) > room {
        indicators = panes::indicators(state, true);
    }
    for (name, level) in fit_indicators(indicators, room) {
        spans.push(Span::styled("●", Style::default().fg(level.colour(theme))));
        spans.push(Span::styled(format!(" {name}  "), theme.muted()));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).alignment(Alignment::Right),
        area,
    );
}

/// The indicators as drawn: `●`, a space, the label and two spaces each.
fn indicators_width(indicators: &[(String, panes::Level)]) -> usize {
    indicators
        .iter()
        .map(|(name, _)| name.chars().count() + 4)
        .sum()
}

/// The indicators, with the user name in `apps (<user>)` cut to end in `…` as far as
/// `room` columns need, down to one letter.
fn fit_indicators(
    mut indicators: [(String, panes::Level); 4],
    room: usize,
) -> [(String, panes::Level); 4] {
    let over = indicators_width(&indicators).saturating_sub(room);
    let apps = &mut indicators[3].0;
    let Some(user) = apps
        .strip_prefix("apps (")
        .and_then(|rest| rest.strip_suffix(')'))
    else {
        return indicators;
    };
    let kept = user.chars().count().saturating_sub(over + 1).max(1);
    if kept + 1 < user.chars().count() {
        *apps = format!("apps ({}…)", user.chars().take(kept).collect::<String>());
    }
    indicators
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, theme: &Theme, view: &Overview<'_>) {
    let names = if view.names_on {
        "names on"
    } else {
        "names off"
    };
    let mut hints: Vec<(&str, &str)> = if view.typing.is_some() {
        vec![("type", "to search"), ("enter", "keep"), ("esc", "clear")]
    } else if view.map.is_some() {
        vec![
            ("esc", "back"),
            ("j/k", "scroll"),
            ("n", names),
            ("t", "theme"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else if view.zoom.is_some() {
        vec![
            ("esc", "back"),
            ("j/k", "move"),
            ("/", "search"),
            ("i", "interface"),
            ("n", names),
            ("t", "theme"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        vec![
            ("tab", "focus"),
            ("p", "page"),
            ("enter", "zoom"),
            ("/", "search"),
            ("i", "interface"),
            ("m", "map"),
            ("n", names),
            ("t", "theme"),
            ("?", "help"),
            ("q", "quit"),
        ]
    };
    if view.typing.is_none() && view.focus == Pane::WifiNetworks {
        // Before `?` and `q`, which close the list.
        hints.insert(hints.len() - 2, ("r", "scan"));
    }
    // `t` names the theme while there is room, then is plain, then is the first hint to go.
    let width = |hints: &[(&str, &str)]| {
        1 + hints
            .iter()
            .map(|(key, what)| key.chars().count() + 1 + what.chars().count())
            .sum::<usize>()
            + 3 * hints.len().saturating_sub(1)
    };
    let fits = |hints: &[(&str, &str)]| width(hints) <= usize::from(area.width);
    let theme_hint = format!("theme ({})", view.theme_name);
    if let Some(at) = hints.iter().position(|(key, _)| *key == "t") {
        let plain = hints[at].1;
        hints[at].1 = &theme_hint;
        if !fits(&hints) {
            hints[at].1 = plain;
        }
    }
    if !fits(&hints) {
        hints.retain(|(key, _)| *key != "t");
    }
    let mut spans = vec![Span::raw(" ")];
    for (n, (key, what)) in hints.iter().enumerate() {
        if n > 0 {
            spans.push(Span::styled(" · ", theme.muted()));
        }
        spans.push(Span::styled(*key, theme.text()));
        spans.push(Span::styled(format!(" {what}"), theme.muted()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A pane title, with the pane's search after it while it is open or not empty.
fn title_line(
    theme: &Theme,
    title: &str,
    focused: bool,
    search: &str,
    typing: bool,
) -> Line<'static> {
    let mut spans = vec![Span::styled(format!(" {title} "), theme.title(focused))];
    if typing || !search.is_empty() {
        spans.push(Span::styled(format!("/{search}"), theme.text()));
        if typing {
            spans.push(Span::styled("▏", theme.focus()));
        }
        spans.push(Span::raw(" "));
    }
    Line::from(spans)
}

fn pane_block<'a>(theme: &Theme, title: Line<'a>, focused: bool) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.border(focused))
        .title(title)
        .style(theme.background())
}

/// One column of space between a pane's border and what it draws.
fn pad(inner: Rect) -> Rect {
    Rect {
        x: inner.x + 1.min(inner.width),
        width: inner.width.saturating_sub(2),
        ..inner
    }
}

/// The title of a list pane; the bandwidth pane draws its own.
fn pane_name(pane: Pane) -> &'static str {
    match pane {
        Pane::AppTraffic => "APP TRAFFIC",
        Pane::FirewallBlocks => "FIREWALL BLOCKS",
        Pane::FirewallRules => "FIREWALL RULES",
        Pane::NetworkEvents => "NETWORK EVENTS",
        Pane::Neighbors => "NEIGHBORS",
        Pane::ListeningPorts => "LISTENING PORTS",
        Pane::WifiNetworks => "WI-FI NETWORKS",
        Pane::Bandwidth => "",
    }
}

fn pane_title(view: &Overview<'_>, theme: &Theme, pane: Pane, title: &str) -> Line<'static> {
    title_line(
        theme,
        title,
        view.focus == pane,
        view.search_for(pane),
        view.typing == Some(pane),
    )
}

/// Draw the notice (at most `max` wrapped rows) at the top of `area` and
/// return what is left below it.
fn draw_notice(
    frame: &mut Frame<'_>,
    area: Rect,
    theme: &Theme,
    notice: Option<&str>,
    max: u16,
) -> Rect {
    let Some(text) = notice else { return area };
    let max = max.min(area.height.saturating_sub(1)).max(1);
    let lines = wrap(text, area.width as usize, max as usize);
    let used = lines.len() as u16;
    let lines: Vec<Line> = lines
        .into_iter()
        .map(|l| Line::styled(l, theme.warning()))
        .collect();
    frame.render_widget(
        Paragraph::new(lines),
        Rect {
            height: used,
            ..area
        },
    );
    Rect {
        y: area.y + used,
        height: area.height - used,
        ..area
    }
}

/// Greedy word wrap into at most `max` lines; the last is cut with `…` when
/// the text does not fit.
fn wrap(text: &str, width: usize, max: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for word in text.split_whitespace() {
        match lines.last_mut() {
            Some(line) if line.chars().count() + 1 + word.chars().count() <= width => {
                line.push(' ');
                line.push_str(word);
            }
            _ => lines.push(word.to_owned()),
        }
    }
    if lines.len() > max {
        lines.truncate(max);
        if let Some(last) = lines.last_mut() {
            *last = last
                .chars()
                .take(width.saturating_sub(1))
                .collect::<String>()
                + "…";
        }
    }
    lines.iter_mut().for_each(|l| {
        if l.chars().count() > width {
            *l = l.chars().take(width.saturating_sub(1)).collect::<String>() + "…";
        }
    });
    lines
}

fn notice_rows(inner: Rect) -> u16 {
    if inner.height >= 8 { 3 } else { 2 }
}

/// A muted line at the top of `body`, which then starts below it.
fn draw_quiet_line(frame: &mut Frame<'_>, body: &mut Rect, theme: &Theme, text: String) {
    frame.render_widget(
        Paragraph::new(Span::styled(text, theme.muted())),
        Rect { height: 1, ..*body },
    );
    body.y += 1;
    body.height = body.height.saturating_sub(1);
}

fn draw_list(
    frame: &mut Frame<'_>,
    area: Rect,
    theme: &Theme,
    view: &Overview<'_>,
    pane: ListPane<'_>,
) -> Rendered {
    let block = pane_block(
        theme,
        pane_title(view, theme, pane.pane, pane.title),
        view.focus == pane.pane,
    );
    let inner = pad(block.inner(area));
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return Rendered::EMPTY;
    }
    let mut body = draw_notice(
        frame,
        inner,
        theme,
        pane.notice.as_deref(),
        notice_rows(inner),
    );
    if let (None, Some(text)) = (&pane.notice, pane.pending) {
        draw_quiet_line(frame, &mut body, theme, text);
    }
    if let Some(footer) = pane.footer.filter(|_| body.height >= 4) {
        let line = Rect {
            y: body.y + body.height - 1,
            height: 1,
            ..body
        };
        body.height -= 1;
        let text: String = footer.chars().take(line.width as usize).collect();
        frame.render_widget(Paragraph::new(Span::styled(text, theme.muted())), line);
    }
    if pane.rows.is_empty() {
        let text = if view.search_for(pane.pane).is_empty() {
            pane.empty
        } else {
            "no matches"
        };
        frame.render_widget(Paragraph::new(Span::styled(text, theme.muted())), body);
        return Rendered::EMPTY;
    }
    let mut table = Table::new(&pane.columns, &pane.rows, theme);
    if view.focus == pane.pane {
        table = table.selected(Some(view.selected)).scroll(view.scroll);
    }
    let drawn = table.render(frame.buffer_mut(), body);
    let below = drawn.matched.saturating_sub(drawn.scroll + drawn.visible);
    if below > 0 {
        let text = format!(" +{below} more ");
        let x = area.right().saturating_sub(text.chars().count() as u16 + 2);
        frame.buffer_mut().set_stringn(
            x,
            area.bottom().saturating_sub(1),
            &text,
            text.chars().count(),
            theme.muted().bg(theme.background),
        );
    }
    drawn
}

pub fn draw_bandwidth(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &AppState,
    theme: &Theme,
    view: &Overview<'_>,
) {
    let interface = panes::chart_interface(state, view.interface);
    let block = bandwidth_block(
        theme,
        view,
        state,
        interface.as_deref(),
        view.focus == Pane::Bandwidth,
        area.width,
    );
    let inner = pad(block.inner(area));
    frame.render_widget(block, area);
    let body = draw_notice(
        frame,
        inner,
        theme,
        panes::notice(state, Pane::Bandwidth).as_deref(),
        1,
    );
    draw_chart(frame, body, state, theme, interface.as_deref());
}

/// The Bandwidth pane's border, titled with the plotted interface and what
/// is known of its connection. `width` is the pane's width: the title has
/// the top border less its two corners.
fn bandwidth_block<'a>(
    theme: &Theme,
    view: &Overview<'_>,
    state: &AppState,
    interface: Option<&str>,
    focused: bool,
    width: u16,
) -> Block<'a> {
    let Some(name) = interface else {
        return pane_block(
            theme,
            pane_title(view, theme, Pane::Bandwidth, "BANDWIDTH"),
            focused,
        );
    };
    let mut parts = connection_parts(state, name);
    let room = width.saturating_sub(2) as usize;
    loop {
        let mut title = pane_title(view, theme, Pane::Bandwidth, "BANDWIDTH · ");
        // After " BANDWIDTH · " comes the name, the parts in the title's own
        // style, then the title's closing space.
        title.spans[0].content = " BANDWIDTH · ".into();
        let rest = theme.title(focused);
        title
            .spans
            .insert(1, Span::styled(bound_text(name), theme.name_highlight()));
        let mut next = 2;
        if !parts.is_empty() {
            let text = parts
                .iter()
                .map(|part| format!(" · {part}"))
                .collect::<String>();
            title.spans.insert(next, Span::styled(text, rest));
            next += 1;
        }
        title.spans.insert(next, Span::styled(" ", rest));
        if title.width() <= room || parts.pop().is_none() {
            return pane_block(theme, title, focused);
        }
    }
}

/// The parts that follow the interface name, left to right, which are also
/// the order they are dropped from the right in.
fn connection_parts(state: &AppState, name: &str) -> Vec<String> {
    let Some(snapshot) = state.interface_snapshot() else {
        return Vec::new();
    };
    let mut parts = Vec::new();
    if let Some(interface) = snapshot.interfaces.iter().find(|i| i.name == name) {
        let addresses = &interface.addresses;
        if let Some(address) = map::chosen(addresses, |a| a.ip) {
            parts.push(format!("{}/{}", address.ip, address.prefix));
        }
    }
    if snapshot.default_route.as_deref() == Some(name)
        && let Some(gateway) = snapshot.gateway
    {
        parts.push(format!("gw {gateway}"));
    }
    if let Some(server) = snapshot.name_server {
        parts.push(format!("dns {server}"));
    }
    parts
}

fn is_link_local_v6(ip: std::net::IpAddr) -> bool {
    matches!(ip, std::net::IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
}

fn draw_chart(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &AppState,
    theme: &Theme,
    interface: Option<&str>,
) {
    match interface {
        Some(name) => {
            let totals = state
                .interfaces()
                .into_iter()
                .find(|i| i.name == name)
                .map(|i| i.session)
                .unwrap_or_default();
            Chart::new(&state.rate_history(name), totals, theme).render(frame.buffer_mut(), area)
        }
        None => frame.render_widget(
            Paragraph::new(Span::styled("no interface data", theme.muted())),
            area,
        ),
    }
}

/// The focused pane's table over the whole body area.
fn draw_zoom(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &AppState,
    theme: &Theme,
    view: &Overview<'_>,
    pane: Pane,
) -> Rendered {
    let plotted = panes::chart_interface(state, view.interface);
    let search = view.search_for(pane);
    let (columns, rows) =
        panes::zoom_table(state, theme, pane, search, view.names, plotted.as_deref());
    let block = match pane {
        Pane::Bandwidth => {
            bandwidth_block(theme, view, state, plotted.as_deref(), true, area.width)
        }
        _ => pane_block(theme, pane_title(view, theme, pane, pane_name(pane)), true),
    };
    let inner = pad(block.inner(area));
    frame.render_widget(block, area);
    let mut body = draw_notice(
        frame,
        inner,
        theme,
        panes::notice(state, pane).as_deref(),
        notice_rows(inner),
    );
    if let Some(text) = panes::pending(state, pane).filter(|_| {
        matches!(
            pane,
            Pane::FirewallRules | Pane::Neighbors | Pane::WifiNetworks
        )
    }) {
        draw_quiet_line(frame, &mut body, theme, text);
    }
    if pane == Pane::Bandwidth {
        let chart_height = (body.height / 2).max(3).min(body.height);
        draw_chart(
            frame,
            Rect {
                height: chart_height,
                ..body
            },
            state,
            theme,
            plotted.as_deref(),
        );
        body.y += chart_height;
        body.height -= chart_height;
    }
    if body.width == 0 || body.height == 0 {
        return Rendered::EMPTY;
    }
    if rows.is_empty() {
        let text = if !search.is_empty() {
            "no matches"
        } else if pane == Pane::NetworkEvents {
            "no events yet"
        } else {
            "nothing to show"
        };
        frame.render_widget(Paragraph::new(Span::styled(text, theme.muted())), body);
        return Rendered::EMPTY;
    }
    Table::new(&columns, &rows, theme)
        .selected(Some(view.selected))
        .scroll(view.scroll)
        .render(frame.buffer_mut(), body)
}

fn draw_help(frame: &mut Frame<'_>, area: Rect, theme: &Theme) {
    let key = |keys: &str, what: &str| {
        Line::from(vec![
            Span::styled(format!(" {keys:<17}"), theme.text()),
            Span::styled(what.to_owned(), theme.muted()),
        ])
    };
    let lines = vec![
        Line::styled(
            " Traffic: 1 Bandwidth · 2 App Traffic · 3 Listening Ports",
            theme.heading(),
        ),
        Line::styled("   4 Firewall Rules", theme.heading()),
        Line::styled(
            " Network & Firewall: 5 Firewall Blocks · 6 Network Events",
            theme.heading(),
        ),
        Line::styled("   7 Wi-Fi Networks · 8 Neighbors", theme.heading()),
        key("tab / 1-8", "move focus, and page (shift-tab goes back)"),
        key("p", "show the other page, at its last pane"),
        key("enter", "zoom the focused pane"),
        key("esc", "leave zoom (search kept), close help or map"),
        key("", "on the overview: clear the search"),
        key(
            "j/k g/G ctrl-d/u",
            "move · top/end · half page (↑↓ Home End PgUp PgDn)",
        ),
        key("/", "search the focused pane"),
        key(
            "i / n / r / m",
            "interface · reverse DNS names · scan Wi-Fi · map",
        ),
        key("t", "next theme · T previous"),
        key("? / q / ctrl-c", "toggle this help / quit"),
        Line::from(vec![
            Span::styled(" Ports: ", theme.heading()),
            Span::styled("● open", theme.open()),
            Span::styled("  ◐ limited", theme.warning()),
            Span::styled("  · blocked  · local", theme.muted()),
        ]),
    ];
    let height = (lines.len() as u16 + 2).min(area.height.saturating_sub(2));
    let width = 72.min(area.width.saturating_sub(4));
    let popup = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.focus())
        .title(Span::styled(" HELP ", theme.focus()))
        .style(theme.background());
    frame.render_widget(Paragraph::new(lines).block(block), popup);
}

/// Control characters, bidirectional overrides and isolates, and
/// zero-width characters can reorder or hide what a row says.
fn is_disguising(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}'
        )
}

fn without_controls(value: &str) -> impl Iterator<Item = char> + '_ {
    value.chars().filter(|character| !is_disguising(*character))
}

fn bound_text(value: &str) -> String {
    without_controls(value).take(48).collect()
}

/// Text with control characters stripped and no length bound; the table
/// truncates it to its column.
fn whole_text(value: &str) -> String {
    without_controls(value).collect()
}

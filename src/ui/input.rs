//! Key handling: focus, zoom, per-pane search, selection, interface choice and help.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::PathBuf,
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::Color;

use super::{
    Drawn, Overview,
    map::{Map, build, chosen_address},
    panes::{self, Line},
};
use crate::{
    collect::{
        attribution::ExecutableIdentity,
        interfaces::{hardware_address, is_wireless},
    },
    desktop::DesktopNames,
    dns::ReverseDns,
    state::{AppState, Page, Pane},
    ui::Theme,
    vendors::{SYSTEM_TABLE, Vendors},
};

/// Panes in key order: `1`–`8`, and the order Tab walks.
const VISUAL_ORDER: [Pane; 8] = [
    Pane::Bandwidth,
    Pane::AppTraffic,
    Pane::ListeningPorts,
    Pane::FirewallRules,
    Pane::FirewallBlocks,
    Pane::NetworkEvents,
    Pane::WifiNetworks,
    Pane::Neighbors,
];

/// Where a movement key takes a position `from`, a half page being `half` rows;
/// `None` for a key that does not move.
fn moved(code: KeyCode, control: bool, from: usize, half: usize) -> Option<usize> {
    Some(match code {
        KeyCode::Up | KeyCode::Char('k') => from.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => from.saturating_add(1),
        KeyCode::Home | KeyCode::Char('g') => 0,
        KeyCode::End | KeyCode::Char('G') => usize::MAX,
        KeyCode::PageDown => from.saturating_add(half),
        KeyCode::PageUp => from.saturating_sub(half),
        KeyCode::Char('d') if control => from.saturating_add(half),
        KeyCode::Char('u') if control => from.saturating_sub(half),
        _ => return None,
    })
}

fn slot(pane: Pane) -> usize {
    VISUAL_ORDER.iter().position(|p| *p == pane).unwrap_or(0)
}

/// The digit key that focuses `pane`.
pub fn key_number(pane: Pane) -> usize {
    slot(pane) + 1
}

fn page_slot(page: Page) -> usize {
    match page {
        Page::Traffic => 0,
        Page::NetworkFirewall => 1,
    }
}

/// The network map: whether it is shown, how far its device rows are scrolled,
/// and the two things it keeps between frames.
#[derive(Debug)]
struct MapView {
    open: bool,
    offset: usize,
    /// The greatest offset and the rows that fit, as of the last draw.
    max_offset: usize,
    fit_rows: usize,
    vendor_table: PathBuf,
    /// Read the first time the map opens, then kept.
    vendors: Option<Vendors>,
    host_reader: fn(&str) -> Option<String>,
    wireless_check: fn(&str) -> bool,
    /// The interface this host was read for, its hardware address there and whether it is wireless.
    host: Option<(String, Option<String>, bool)>,
}

impl Default for MapView {
    fn default() -> Self {
        Self {
            open: false,
            offset: 0,
            max_offset: 0,
            fit_rows: 0,
            vendor_table: PathBuf::from(SYSTEM_TABLE),
            vendors: None,
            host_reader: hardware_address,
            wireless_check: is_wireless,
            host: None,
        }
    }
}

impl MapView {
    /// Reads this host's address and whether the interface is wireless again when the default route's interface is not the one it was read for.
    fn refresh_host(&mut self, route: Option<&str>) {
        let Some(route) = route else { return };
        if self.host.as_ref().is_none_or(|(name, ..)| name != route) {
            self.host = Some((
                route.to_owned(),
                (self.host_reader)(route),
                (self.wireless_check)(route),
            ));
        }
    }
}

#[derive(Debug)]
pub struct Interaction {
    map: MapView,
    focus: Pane,
    /// The pane last focused on Traffic and on Network & Firewall, in that order.
    last_focused: [Pane; 2],
    zoom: Option<Pane>,
    searches: [String; 8],
    field_open: bool,
    selected: usize,
    /// Rows the last draw showed in the zoomed table; `None` until the
    /// next draw after the table or its search changed.
    matched: Option<usize>,
    scroll: usize,
    /// Rows the last draw had room for in the table the selection is in.
    visible: usize,
    interface: Option<String>,
    help: bool,
    names: bool,
    /// The apps App Traffic lists the destinations of, by executable.
    expanded: HashSet<ExecutableIdentity>,
    desktop: DesktopNames,
    /// The reverse-DNS names the last draw showed in App Traffic, so a search
    /// by name finds the same lines here.
    known_names: HashMap<IpAddr, String>,
    /// Index in `Theme::NAMES` of the theme started with, then of the one `t` last chose.
    theme: usize,
    /// The `[theme]` colours, kept on top of every theme.
    overrides: Vec<(&'static str, Color)>,
    /// Whether `t` has been pressed; until then the theme drawn is the one the caller passes.
    cycled: bool,
    /// `r` on Wi-Fi Networks, until the main loop takes it.
    scan_requested: bool,
    /// The state's block total as of the last draw of Network & Firewall.
    blocks_seen: u64,
    quit: bool,
}

impl Default for Interaction {
    fn default() -> Self {
        Self {
            map: MapView::default(),
            focus: Pane::Bandwidth,
            last_focused: [Pane::Bandwidth, Pane::FirewallBlocks],
            zoom: None,
            searches: Default::default(),
            field_open: false,
            selected: 0,
            matched: None,
            scroll: 0,
            visible: 0,
            interface: None,
            help: false,
            names: false,
            expanded: HashSet::new(),
            desktop: DesktopNames::default(),
            known_names: HashMap::new(),
            theme: 0,
            overrides: Vec::new(),
            cycled: false,
            scan_requested: false,
            blocks_seen: 0,
            quit: false,
        }
    }
}

impl Interaction {
    /// Starts with reverse-DNS names on or off, as configured.
    pub fn with_names(on: bool) -> Self {
        Self {
            names: on,
            ..Self::default()
        }
    }
    /// Starts on the built-in theme `name`, with `overrides` kept on top of it and of every theme `t` shows next.
    pub fn with_theme(mut self, name: &str, overrides: &[(&'static str, Color)]) -> Self {
        self.theme = Theme::NAMES.iter().position(|n| *n == name).unwrap_or(0);
        self.overrides = overrides.to_vec();
        self
    }
    /// The name of the theme now shown.
    pub fn theme_name(&self) -> &'static str {
        Theme::NAMES[self.theme]
    }
    /// The theme to draw: `configured` until `t` is pressed, then the chosen one with the overrides on top.
    pub(super) fn theme_to_draw(&self, configured: &Theme) -> Theme {
        if !self.cycled {
            return *configured;
        }
        Theme::named(self.theme_name())
            .unwrap_or(*configured)
            .with_overrides(&self.overrides)
    }
    /// Moves `by` places along the names, wrapping; one less than all of them goes back one.
    fn step_theme(&mut self, by: usize) {
        self.theme = (self.theme + by) % Theme::NAMES.len();
        self.cycled = true;
    }
    /// Whether reverse-DNS names are on; `n` flips it for the session.
    pub fn names_on(&self) -> bool {
        self.names
    }
    pub fn focus(&self) -> Pane {
        self.focus
    }
    pub fn zoomed(&self) -> Option<Pane> {
        self.zoom
    }
    pub fn search(&self, pane: Pane) -> &str {
        &self.searches[slot(pane)]
    }
    /// Whether the focused pane's search field is open for typing.
    pub fn field_open(&self) -> bool {
        self.field_open
    }
    /// Whether the network map is shown in place of the page.
    pub fn map_open(&self) -> bool {
        self.map.open
    }
    /// Reads the vendor table from `path` instead of the system's file.
    pub fn with_vendor_table(mut self, path: impl Into<PathBuf>) -> Self {
        self.map.vendor_table = path.into();
        self
    }
    /// Names apps by these desktop entries.
    pub fn with_desktop_names(mut self, names: DesktopNames) -> Self {
        self.desktop = names;
        self
    }
    /// Reads this host's hardware address with `reader` instead of from the system.
    pub fn with_host_address(mut self, reader: fn(&str) -> Option<String>) -> Self {
        self.map.host_reader = reader;
        self
    }
    /// Tells wireless interfaces with `check` instead of from the system.
    pub fn with_wireless_check(mut self, check: fn(&str) -> bool) -> Self {
        self.map.wireless_check = check;
        self
    }
    /// Addresses worth a reverse-DNS lookup for the map: the gateway's and,
    /// for each device on the default route's interface, the one address its
    /// box shows, so as many as there are boxes. The resolver takes what it
    /// has room for and the rest on later frames, as answers come back; none
    /// while the map is closed.
    pub fn map_to_look_up(&self, state: &AppState) -> Vec<IpAddr> {
        let Some(route) = self.map.open.then(|| state.default_route()).flatten() else {
            return Vec::new();
        };
        let gateway = state
            .interface_snapshot()
            .and_then(|s| s.gateway)
            .map(IpAddr::V4);
        let mut seen = HashSet::new();
        gateway
            .into_iter()
            .chain(
                state
                    .devices()
                    .filter(|d| d.interface == route)
                    .filter_map(|d| chosen_address(d.addresses.iter().copied())),
            )
            .filter(|a| seen.insert(*a))
            .collect()
    }
    pub fn help_open(&self) -> bool {
        self.help
    }
    /// Lists the destinations of these apps, by executable, as well.
    pub fn expand(&mut self, apps: impl IntoIterator<Item = ExecutableIdentity>) {
        self.expanded.extend(apps);
    }
    pub fn selected(&self) -> usize {
        self.selected
    }
    /// The interface the user chose; `None` follows the default route.
    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }
    /// Whether `r` asked for a Wi-Fi scan since the last call; asking clears it.
    pub fn take_scan_request(&mut self) -> bool {
        std::mem::take(&mut self.scan_requested)
    }
    pub fn should_quit(&self) -> bool {
        self.quit
    }

    pub fn handle_key(&mut self, key: KeyEvent, state: &AppState) {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if control && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.field_open {
            self.matched = None;
            self.edit_search(key.code, control);
        } else if self.help {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') => self.help = false,
                KeyCode::Char('q') | KeyCode::Char('Q') => self.quit = true,
                _ => {}
            }
        } else if self.map.open {
            self.map_command(key.code, control);
        } else {
            self.command(key.code, control, state);
        }
        self.last_focused[page_slot(self.focus.page())] = self.focus;
        self.clamp_selection();
    }

    fn edit_search(&mut self, code: KeyCode, control: bool) {
        let text = &mut self.searches[slot(self.focus)];
        let before = text.len();
        match code {
            KeyCode::Enter => self.field_open = false,
            KeyCode::Esc => {
                text.clear();
                self.field_open = false;
            }
            KeyCode::Backspace => {
                text.pop();
            }
            KeyCode::Char(c) if !control && !c.is_control() => text.push(c),
            _ => {}
        }
        // Each edit changes the length except replacing nothing, so a
        // different length is a different search.
        if text.len() != before {
            self.reset_position();
        }
    }

    fn command(&mut self, code: KeyCode, control: bool, state: &AppState) {
        let zoomed = self.zoom.is_some();
        if let Some(to) = moved(code, control, self.selected, self.half_page()) {
            self.selected = to;
            return;
        }
        match code {
            KeyCode::Esc if zoomed => {
                self.zoom = None;
                self.reset_position();
            }
            KeyCode::Esc => {
                if !self.searches[slot(self.focus)].is_empty() {
                    self.searches[slot(self.focus)].clear();
                    self.reset_position();
                }
            }
            KeyCode::Enter if !zoomed => self.zoom_in(),
            KeyCode::Tab if !zoomed => self.move_focus(1),
            KeyCode::BackTab if !zoomed => self.move_focus(-1),
            KeyCode::Char(c @ '1'..='8') if !zoomed => {
                self.set_focus(VISUAL_ORDER[c as usize - '1' as usize]);
            }
            KeyCode::Char('p') if !zoomed => {
                let other = match self.focus.page() {
                    Page::Traffic => Page::NetworkFirewall,
                    Page::NetworkFirewall => Page::Traffic,
                };
                self.set_focus(self.last_focused[page_slot(other)]);
            }
            KeyCode::Char('m') if !zoomed => self.open_map(state),
            KeyCode::Char('/') => self.field_open = true,
            KeyCode::Char('i') => self.next_interface(state),
            KeyCode::Char('n') => self.names = !self.names,
            KeyCode::Char('a') if self.focus == Pane::AppTraffic => self.toggle_selected_app(state),
            KeyCode::Char('t') => self.step_theme(1),
            KeyCode::Char('T') => self.step_theme(Theme::NAMES.len() - 1),
            KeyCode::Char('r') if self.focus == Pane::WifiNetworks => self.scan_requested = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('q') | KeyCode::Char('Q') => self.quit = true,
            _ => {}
        }
    }

    fn open_map(&mut self, state: &AppState) {
        self.map.open = true;
        self.map.offset = 0;
        self.map
            .vendors
            .get_or_insert_with(|| Vendors::load(&self.map.vendor_table));
        self.map.refresh_host(state.default_route());
    }

    /// The keys that do something while the map is open; the rest do nothing.
    fn map_command(&mut self, code: KeyCode, control: bool) {
        let half = (self.map.fit_rows / 2).max(1);
        if let Some(to) = moved(code, control, self.map.offset, half) {
            self.map.offset = to.min(self.map.max_offset);
            return;
        }
        match code {
            KeyCode::Esc | KeyCode::Char('m') => self.map.open = false,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('q') | KeyCode::Char('Q') => self.quit = true,
            KeyCode::Char('n') => self.names = !self.names,
            KeyCode::Char('t') => self.step_theme(1),
            KeyCode::Char('T') => self.step_theme(Theme::NAMES.len() - 1),
            _ => {}
        }
        self.map.offset = self.map.offset.min(self.map.max_offset);
    }

    /// Half the rows the table showed in the last draw, at least one.
    fn half_page(&self) -> usize {
        (self.visible / 2).max(1)
    }

    fn zoom_in(&mut self) {
        self.zoom = Some(self.focus);
        self.reset_position();
    }

    /// Puts the selection back on the first row, to be settled by the next draw.
    /// Expands or collapses the app on the selected App Traffic line; on one
    /// of its destinations, collapses its app and selects the app's line.
    fn toggle_selected_app(&mut self, state: &AppState) {
        let apps = state.app_traffic();
        let search = self.search(Pane::AppTraffic);
        let shown = panes::shown_apps(
            &apps,
            search,
            self.zoom.is_some(),
            Some(&self.desktop),
            |ip| self.known_names.get(&ip).map(String::as_str),
        );
        let lines = panes::lines(&shown, &self.expanded);
        let Some(&line) = lines.get(self.selected) else {
            return;
        };
        match line {
            Line::App(n) if shown[n].expandable() => {
                let app = shown[n].app.executable.clone();
                if !self.expanded.remove(&app) {
                    self.expanded.insert(app);
                }
            }
            Line::App(_) => {}
            Line::Destination(n, _) => {
                self.expanded.remove(&shown[n].app.executable);
                self.selected = lines.iter().position(|l| *l == Line::App(n)).unwrap_or(0);
            }
        }
    }

    /// Remembers the names App Traffic shows, for the keys.
    pub(super) fn note_names(&mut self, state: &AppState, dns: Option<&ReverseDns>) {
        self.known_names.clear();
        let Some(dns) = dns.filter(|_| self.names && self.focus == Pane::AppTraffic) else {
            return;
        };
        for d in state.app_traffic().iter().flat_map(|app| &app.destinations) {
            if let Some(name) = dns.name(d.remote.ip) {
                self.known_names.insert(d.remote.ip, name.to_owned());
            }
        }
    }

    fn reset_position(&mut self) {
        self.matched = None;
        self.selected = 0;
        self.scroll = 0;
    }

    /// Focuses `pane`; the pane left behind shows its first rows again and
    /// the new one starts on its first.
    fn set_focus(&mut self, pane: Pane) {
        if pane != self.focus {
            self.focus = pane;
            self.reset_position();
        }
    }

    fn move_focus(&mut self, offset: isize) {
        let next =
            (slot(self.focus) as isize + offset).rem_euclid(VISUAL_ORDER.len() as isize) as usize;
        self.set_focus(VISUAL_ORDER[next]);
    }

    fn next_interface(&mut self, state: &AppState) {
        let names: Vec<String> = state.interfaces().into_iter().map(|i| i.name).collect();
        let current = panes::chart_interface(state, self.interface.as_deref());
        let at = current
            .and_then(|c| names.iter().position(|n| *n == c))
            .unwrap_or(names.len().saturating_sub(1));
        if let Some(next) = names.get((at + 1) % names.len().max(1)) {
            self.interface = Some(next.clone());
        }
    }

    /// Keeps the selection on a row the last draw showed, so the key
    /// handler and the table never disagree about how many rows match.
    fn clamp_selection(&mut self) {
        if let Some(matched) = self.matched {
            self.selected = self.selected.min(matched.saturating_sub(1));
        }
    }

    /// Whether `pane`'s addresses are worth a lookup: the pane is the zoomed
    /// one, or nothing is zoomed and the pane is on the page shown.
    fn wants_lookups(&self, pane: Pane) -> bool {
        match self.zoom {
            Some(zoomed) => zoomed == pane,
            None => self.focus.page() == pane.page(),
        }
    }

    /// How far `pane` is scrolled on the overview: only the focused pane is.
    fn overview_scroll(&self, pane: Pane) -> usize {
        if self.focus == pane { self.scroll } else { 0 }
    }

    /// Every destination in App Traffic, when that pane is on the page shown
    /// or zoomed; otherwise none.
    pub fn app_destinations_to_look_up(&self, state: &AppState) -> Vec<IpAddr> {
        if !self.wants_lookups(Pane::AppTraffic) {
            return Vec::new();
        }
        state
            .app_traffic()
            .into_iter()
            .flat_map(|app| app.destinations)
            .map(|d| d.remote.ip)
            .collect()
    }

    /// Sources worth a reverse-DNS lookup: those of the Firewall Blocks rows
    /// a terminal `height` lines tall can show now, newest first. On the
    /// overview that is the pane's rows that fit; zoomed on Firewall Blocks it is the
    /// rows down to the bottom of the screen at the current scroll; with
    /// another pane zoomed, or with Traffic shown, none. The search is not applied, so a name that
    /// is not yet known can still be searched for once its row is in view.
    pub fn blocked_sources_to_look_up(&self, state: &AppState, height: u16) -> Vec<IpAddr> {
        if !self.wants_lookups(Pane::FirewallBlocks) {
            return Vec::new();
        }
        let (blocks, rows) = match self.zoom {
            None => (
                panes::blocked_overview_order(state),
                self.overview_scroll(Pane::FirewallBlocks) + super::overview_fit(0, height),
            ),
            // `wants_lookups` let only this pane through.
            Some(_) => (
                panes::blocked_zoom_order(state),
                self.scroll + super::zoom_fit(height),
            ),
        };
        blocks.iter().take(rows).filter_map(|b| b.source).collect()
    }

    /// Addresses worth a reverse-DNS lookup: those of the Neighbors rows a
    /// terminal `height` lines tall can show now, in address order. On the
    /// overview that is the pane's rows that fit when Network & Firewall is shown;
    /// zoomed on Neighbors it is the rows down to the bottom of the screen
    /// at the current scroll; with another pane zoomed, or Traffic shown, none. The search is
    /// not applied, as for Firewall Blocks.
    pub fn neighbors_to_look_up(&self, state: &AppState, height: u16) -> Vec<IpAddr> {
        if !self.wants_lookups(Pane::Neighbors) {
            return Vec::new();
        }
        let rows = match self.zoom {
            None => self.overview_scroll(Pane::Neighbors) + super::overview_fit(3, height),
            // `wants_lookups` let only this pane through.
            Some(_) => self.scroll + super::zoom_fit(height),
        };
        panes::neighbor_order(state)
            .into_iter()
            .take(rows)
            .collect()
    }

    /// Notes a draw of the page shown, which is the focused pane's page,
    /// zoomed or not: while it is Network & Firewall the blocks are seen. The
    /// map covers the page, so while it is open nothing is shown and nothing is seen.
    /// Returns the blocks recorded since that page was last shown.
    pub(super) fn blocks_since_shown(&mut self, state: &AppState) -> u64 {
        let total = state.blocked_total();
        if self.focus.page() == Page::NetworkFirewall && !self.map.open {
            self.blocks_seen = total;
        }
        total.saturating_sub(self.blocks_seen)
    }

    /// What the next frame draws.
    pub(super) fn view<'a>(
        &'a self,
        names: Option<&'a ReverseDns>,
        new_blocks: u64,
    ) -> Overview<'a> {
        let mut view = Overview::new(self.focus)
            .position(self.selected, self.scroll)
            .help(self.help)
            .names_on(self.names)
            .expanded(&self.expanded)
            .desktop(&self.desktop)
            .theme_name(self.theme_name())
            .new_blocks(new_blocks);
        if let Some(name) = &self.interface {
            view = view.interface(name);
        }
        if let Some(dns) = names.filter(|_| self.names) {
            view = view.names(dns);
        }
        for pane in VISUAL_ORDER {
            view = view.search(pane, self.search(pane));
        }
        if self.field_open {
            view = view.typing(self.focus);
        }
        if let Some(pane) = self.zoom {
            view = view.zoom(pane);
        }
        view
    }

    /// Reads this host's hardware address if the map is open and the default route moved.
    pub(super) fn refresh_map(&mut self, state: &AppState) {
        if self.map.open {
            self.map.refresh_host(state.default_route());
        }
    }

    /// What the map draws now, built from the state: `None` while it is closed.
    pub(super) fn map_scene(
        &self,
        state: &AppState,
        names: Option<&ReverseDns>,
    ) -> Option<(Option<Map>, usize)> {
        if !self.map.open {
            return None;
        }
        let vendors = self.map.vendors.as_ref()?;
        let host = self.map.host.as_ref();
        let mac = host.and_then(|(_, mac, _)| mac.as_deref());
        let wireless = host.is_some_and(|(.., wireless)| *wireless);
        let names = names.filter(|_| self.names);
        Some((build(state, vendors, names, mac, wireless), self.map.offset))
    }

    /// Keeps what the last draw settled on.
    pub(super) fn settle(&mut self, drawn: Option<Drawn>) {
        match drawn {
            Some(Drawn::Table(drawn)) => {
                self.scroll = drawn.scroll;
                self.selected = drawn.selected.unwrap_or(0);
                self.matched = Some(drawn.matched);
                self.visible = drawn.visible;
            }
            Some(Drawn::Map(drawn)) => {
                self.map.offset = drawn.offset;
                self.map.max_offset = drawn.max_offset;
                self.map.fit_rows = drawn.fit_rows;
            }
            None => {}
        }
    }
}

//! The network map: a model built from the state, and its drawing.

use std::net::IpAddr;

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
};

use super::{Theme, bound_text, is_link_local_v6, pad, pane_block, panes::band_text, table::fit};
use crate::{
    collect::interfaces::InterfaceAddress, dns::ReverseDns, state::AppState, vendors::Vendors,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapBox {
    pub lines: [String; 3],
    pub this_host: bool,
    pub absent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Map {
    pub interface: String,
    pub upstream: Vec<IpAddr>,
    pub gateway: Option<MapBox>,
    pub label: String,
    pub devices: Vec<MapBox>,
}

/// The map of the network that carries the default route; `None` when there
/// is no default route to draw. `host_mac` is this host's hardware address on
/// that interface, if known, and `wireless` whether that interface is a Wi-Fi
/// one. Text from outside is stripped like the panes'.
pub fn build(
    state: &AppState,
    vendors: &Vendors,
    names: Option<&ReverseDns>,
    host_mac: Option<&str>,
    wireless: bool,
) -> Option<Map> {
    let snapshot = state.interface_snapshot()?;
    let route = snapshot.default_route.as_deref()?;
    let own = snapshot.interfaces.iter().find(|i| i.name == route)?;
    let on_link = |ip: &IpAddr| own.addresses.iter().any(|a| in_subnet(*ip, a));
    let (inside, upstream): (Vec<IpAddr>, Vec<IpAddr>) =
        snapshot.name_servers.iter().partition(|ip| on_link(ip));
    let gateway_ip = snapshot.gateway.map(IpAddr::V4);
    let host_mac = host_mac.map(str::to_lowercase);
    let maker = |mac: Option<&str>| {
        mac.and_then(|mac| vendors.maker(mac))
            .map(bound_text)
            .unwrap_or_default()
    };

    let mut gateway = None;
    let mut others = Vec::new();
    let mut host_devices = Vec::new();
    for device in state.devices().filter(|d| d.interface == route) {
        if Some(&device.mac) == host_mac.as_ref() {
            host_devices.push(device);
        } else if gateway.is_none() && gateway_ip.is_some_and(|g| device.addresses.contains(&g)) {
            gateway = Some(device);
        } else {
            others.push(device);
        }
    }

    let roles = |is_gateway: bool, is_host: bool, addresses: &[IpAddr]| {
        let mut roles = Vec::new();
        if is_gateway {
            roles.push("gateway");
        }
        if addresses.iter().any(|a| inside.contains(a)) {
            roles.push("dns");
        }
        if is_host {
            roles.insert(0, "this host");
        }
        roles.join(" · ")
    };
    let make = |role: String, mac: Option<&str>, addresses: Vec<IpAddr>, host, absent| {
        let chosen = chosen_address(addresses.iter().copied());
        let first = if !role.is_empty() {
            role
        } else if let Some(name) = chosen.and_then(|a| names.and_then(|n| n.name(a))) {
            bound_text(name)
        } else {
            mac.map(bound_text).unwrap_or_default()
        };
        MapBox {
            lines: [
                first,
                chosen.map(|a| a.to_string()).unwrap_or_default(),
                maker(mac),
            ],
            this_host: host,
            absent,
        }
    };

    let host_addresses: Vec<IpAddr> = own.addresses.iter().map(|a| a.ip).collect();
    let mut devices = vec![make(
        roles(false, true, &host_addresses),
        host_mac.as_deref(),
        host_addresses.clone(),
        true,
        false,
    )];
    // A name server on the segment with no neighbour entry yet still shows, by its address.
    let unseen = inside.iter().filter(|ip| {
        !host_addresses.contains(ip)
            && Some(**ip) != gateway_ip
            && !others.iter().any(|d| d.addresses.contains(ip))
    });
    let mut segment: Vec<(IpAddr, String, MapBox)> = others
        .iter()
        .map(|d| {
            let addresses: Vec<IpAddr> = d.addresses.iter().copied().collect();
            let first = addresses[0];
            let role = roles(false, false, &addresses);
            (
                first,
                d.mac.clone(),
                make(role, Some(&d.mac), addresses, false, !d.present),
            )
        })
        .chain(unseen.map(|ip| {
            let role = roles(false, false, &[*ip]);
            (
                *ip,
                String::new(),
                make(role, None, vec![*ip], false, false),
            )
        }))
        .collect();
    segment.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    devices.extend(segment.into_iter().map(|(_, _, b)| b));

    let gateway = gateway_ip.map(|ip| {
        let addresses = vec![ip];
        let mac = gateway.map(|d| d.mac.as_str());
        let mut gateway_box = make(roles(true, false, &addresses), mac, addresses, false, false);
        gateway_box.absent = gateway.is_some_and(|d| !d.present);
        gateway_box
    });

    let mut label = vec![bound_text(route)];
    if wireless
        && let Some(Ok(points)) = state.wifi()
        && let Some(entry) = points.iter().find(|e| e.point.in_use)
    {
        if let Some(ssid) = &entry.point.ssid {
            label.push(bound_text(ssid));
        }
        label.push(band_text(entry.point.frequency_mhz).to_owned());
    }

    Some(Map {
        interface: bound_text(route),
        upstream,
        gateway,
        label: label.join(" · "),
        devices,
    })
}

/// The address a box shows: IPv4, else IPv6 that is not link-local, else any.
pub(super) fn chosen_address(addresses: impl IntoIterator<Item = IpAddr>) -> Option<IpAddr> {
    let addresses: Vec<IpAddr> = addresses.into_iter().collect();
    chosen(&addresses, |a| *a).copied()
}

/// The item whose address is the one a box shows, whatever else the item holds.
pub(super) fn chosen<T>(items: &[T], ip: impl Fn(&T) -> IpAddr) -> Option<&T> {
    items
        .iter()
        .find(|a| ip(a).is_ipv4())
        .or_else(|| items.iter().find(|a| !is_link_local_v6(ip(a))))
        .or_else(|| items.first())
}

/// Whether `ip` lies in the network of one of the interface's addresses.
fn in_subnet(ip: IpAddr, own: &InterfaceAddress) -> bool {
    match (ip, own.ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(own.prefix.min(32)))
                .unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(own.prefix.min(128)))
                .unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// Cells of text in a box; a box adds a cell of padding and a border each side.
const TEXT_WIDTH: usize = 17;
const BOX_WIDTH: u16 = TEXT_WIDTH as u16 + 4;
/// A box is its border and three lines; a row of boxes adds the line that joins it to the segment.
const BOX_HEIGHT: u16 = 5;
const ROW_HEIGHT: u16 = BOX_HEIGHT + 1;
/// Cells left of the boxes for the line that carries the segment down to later rows.
const SPINE_GUTTER: u16 = 2;

/// Where a drawing of the map settled: the row offset it used, the
/// greatest offset there is room to scroll to, and the rows that fit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MapScroll {
    pub offset: usize,
    pub max_offset: usize,
    /// How many rows of devices fit under the fixed part.
    pub fit_rows: usize,
}

/// Draws the map in `area`, the device rows scrolled down by `offset` whole
/// rows. `None` is a network with no default route.
pub fn draw_map(
    frame: &mut Frame<'_>,
    area: Rect,
    theme: &Theme,
    map: Option<&Map>,
    offset: usize,
) -> MapScroll {
    let mut title = " NETWORK MAP".to_owned();
    if let Some(map) = map {
        let count = map.devices.len();
        title += &format!(
            " · {} · {count} {} ",
            map.interface,
            if count == 1 { "device" } else { "devices" }
        );
    } else {
        title.push(' ');
    }
    let title = Line::from(Span::styled(title, theme.title(true)));
    let inner = pad(pane_block(theme, title.clone(), true).inner(area));
    frame.render_widget(pane_block(theme, title, true), area);
    let Some(map) = map else {
        let mut canvas = Canvas::new(frame, inner);
        canvas.text(
            inner.x,
            inner.y,
            "No default route: nothing to draw.",
            theme.muted(),
        );
        return MapScroll::default();
    };

    let mut canvas = Canvas::new(frame, inner);
    let line = theme.muted();
    let centre = inner.x + inner.width / 2;
    let mut y = inner.y;

    // What lies beyond the gateway.
    let items: Vec<String> = std::iter::once("internet".to_owned())
        .chain(map.upstream.iter().map(|ip| format!("dns {ip}")))
        .collect();
    let total: usize = items.iter().map(|i| i.chars().count() + 3).sum::<usize>() - 3;
    let mut x = centre.saturating_sub(total as u16 / 2).max(inner.x);
    let mut stems = Vec::new();
    for item in &items {
        let width = item.chars().count() as u16;
        canvas.text(x, y, item, theme.text());
        stems.push(x + width / 2);
        x += width + 3;
    }
    y += 1;
    let (first, last) = (stems[0], stems[stems.len() - 1]);
    for x in first.min(centre)..=last.max(centre) {
        let up = stems.contains(&x);
        let down = x == centre;
        let left = x > first.min(centre);
        let right = x < last.max(centre);
        canvas.text(x, y, junction(up, down, left, right), line);
    }
    y += 1;

    if let Some(gateway) = &map.gateway {
        draw_box(
            &mut canvas,
            centre.saturating_sub(BOX_WIDTH / 2),
            y,
            gateway,
            (true, true),
            theme,
        );
        y += BOX_HEIGHT;
    }
    let label_width = map.label.chars().count() as u16;
    canvas.text(
        centre.saturating_sub(label_width / 2),
        y,
        &map.label,
        theme.text(),
    );
    y += 1;

    // The device rows.
    let count = map.devices.len();
    let single = (usize::from(inner.width) + 1) / usize::from(BOX_WIDTH + 1);
    let spine = count > single.max(1);
    let gutter = if spine { SPINE_GUTTER } else { 0 };
    let columns =
        ((usize::from(inner.width.saturating_sub(gutter)) + 1) / usize::from(BOX_WIDTH + 1)).max(1);
    let rows = count.div_ceil(columns);
    let fit_rows = usize::from(inner.bottom().saturating_sub(y) / ROW_HEIGHT).max(1);
    let max_offset = rows.saturating_sub(fit_rows);
    let offset = offset.min(max_offset);
    let left_edge = inner.x + gutter;
    for (n, row) in (offset..rows.min(offset + fit_rows)).enumerate() {
        let top = y + n as u16 * ROW_HEIGHT;
        let boxes = &map.devices[row * columns..count.min((row + 1) * columns)];
        let stem = |c: usize| left_edge + c as u16 * (BOX_WIDTH + 1) + BOX_WIDTH / 2;
        let ends = (stem(0), stem(boxes.len() - 1));
        let last_row = row + 1 == rows;
        let from = if spine { inner.x } else { ends.0.min(centre) };
        let to = if row == 0 { ends.1.max(centre) } else { ends.1 };
        for x in from..=to {
            let at_spine = spine && x == inner.x;
            let up = (row == 0 && x == centre) || (at_spine && row > 0);
            let down = (x >= left_edge && (0..boxes.len()).any(|c| stem(c) == x))
                || (at_spine && !last_row);
            canvas.text(x, top, junction(up, down, x > from, x < to), line);
        }
        if spine && !last_row {
            for dy in 1..=BOX_HEIGHT {
                canvas.text(inner.x, top + dy, "│", line);
            }
        }
        for (c, device) in boxes.iter().enumerate() {
            let x = left_edge + c as u16 * (BOX_WIDTH + 1);
            draw_box(&mut canvas, x, top + 1, device, (true, false), theme);
        }
    }

    let below = count.saturating_sub(columns * (offset + fit_rows).min(rows));
    if below > 0 {
        let text = format!(
            " {below} more {} below ",
            if below == 1 { "device" } else { "devices" }
        );
        Canvas::new(canvas.frame, area).text(area.x + 2, area.bottom() - 1, &text, theme.muted());
    }
    MapScroll {
        offset,
        max_offset,
        fit_rows,
    }
}

/// One box at `(x, y)`; `joins` says whether its top and bottom borders have a line leaving them.
fn draw_box(
    canvas: &mut Canvas<'_, '_>,
    x: u16,
    y: u16,
    device: &MapBox,
    joins: (bool, bool),
    theme: &Theme,
) {
    let style = if device.this_host {
        theme.name_highlight()
    } else if device.absent {
        theme.muted()
    } else {
        theme.text()
    };
    let border = if device.this_host || device.absent {
        style
    } else {
        theme.muted()
    };
    let middle = BOX_WIDTH / 2;
    let edge = |left: &str, right: &str, join: Option<&str>| {
        let mut cells: Vec<&str> = vec!["─"; usize::from(BOX_WIDTH) - 2];
        if let Some(join) = join {
            cells[usize::from(middle) - 1] = join;
        }
        format!("{left}{}{right}", cells.concat())
    };
    canvas.text(x, y, &edge("┌", "┐", joins.0.then_some("┴")), border);
    for (n, text) in device.lines.iter().enumerate() {
        let dy = 1 + n as u16;
        canvas.text(x, y + dy, "│", border);
        canvas.text(
            x + 1,
            y + dy,
            &format!(" {:<TEXT_WIDTH$} ", fit(text, TEXT_WIDTH)),
            style,
        );
        canvas.text(x + BOX_WIDTH - 1, y + dy, "│", border);
    }
    canvas.text(x, y + 4, &edge("└", "┘", joins.1.then_some("┬")), border);
}

/// The box-drawing character that joins the sides given.
fn junction(up: bool, down: bool, left: bool, right: bool) -> &'static str {
    match (up, down, left, right) {
        (false, true, false, true) => "┌",
        (false, true, true, false) => "┐",
        (false, true, true, true) => "┬",
        (true, false, false, true) => "└",
        (true, false, true, false) => "┘",
        (true, false, true, true) => "┴",
        (true, true, false, true) => "├",
        (true, true, true, false) => "┤",
        (true, true, true, true) => "┼",
        (true, true, false, false) => "│",
        (false, false, _, _) => "─",
        (true, false, false, false) | (false, true, false, false) => "│",
    }
}

/// Text placed by cell, left out where it falls outside the area drawn in.
struct Canvas<'f, 'a> {
    frame: &'f mut Frame<'a>,
    area: Rect,
}

impl<'f, 'a> Canvas<'f, 'a> {
    fn new(frame: &'f mut Frame<'a>, area: Rect) -> Self {
        Self { frame, area }
    }

    fn text(&mut self, x: u16, y: u16, text: &str, style: Style) {
        for (n, character) in text.chars().enumerate() {
            let x = x.saturating_add(n as u16);
            if y >= self.area.y
                && y < self.area.bottom()
                && x >= self.area.x
                && x < self.area.right()
            {
                self.frame.buffer_mut()[(x, y)]
                    .set_char(character)
                    .set_style(style);
            }
        }
    }
}

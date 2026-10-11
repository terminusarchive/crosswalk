use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    net::IpAddr,
    ops::RangeInclusive,
    time::Duration,
};

use crate::{
    collect::{
        attribution::{AttributionStatus, ExecutableIdentity, Listener, ProcessIdentity},
        capture::{CaptureStatus, Direction, Endpoint, Protocol, TrafficEvent},
        interfaces::{CollectionHealth, InterfaceSnapshot},
        neighbors::{Neighbor, NeighborSnapshot},
        wifi::{AccessPoint, ScanOutcome, WifiSnapshot},
    },
    events::{EventKind, EventLevel, EventLog, NetworkEvent},
    firewall::{Exposure, FirewallEvent, FirewallStatus, RuleSnapshot, exposure},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ByteTotals {
    pub upload: u64,
    pub download: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ByteRates {
    pub upload: f64,
    pub download: f64,
}

impl ByteTotals {
    fn add(&mut self, direction: Direction, bytes: u64) {
        match direction {
            Direction::Inbound => self.download = self.download.saturating_add(bytes),
            Direction::Outbound => self.upload = self.upload.saturating_add(bytes),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pane {
    Bandwidth,
    AppTraffic,
    FirewallBlocks,
    ListeningPorts,
    FirewallRules,
    NetworkEvents,
    Neighbors,
    WifiNetworks,
}

/// The two screens of the overview.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Traffic,
    NetworkFirewall,
}

impl Pane {
    /// The page this pane is drawn on.
    pub fn page(self) -> Page {
        match self {
            Pane::Bandwidth | Pane::AppTraffic | Pane::ListeningPorts | Pane::FirewallRules => {
                Page::Traffic
            }
            Pane::FirewallBlocks | Pane::NetworkEvents | Pane::Neighbors | Pane::WifiNetworks => {
                Page::NetworkFirewall
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateLimits {
    pub detail_capacity: usize,
    pub chart_capacity: usize,
}

impl Default for StateLimits {
    fn default() -> Self {
        Self {
            detail_capacity: 4_096,
            chart_capacity: 300,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceHealth {
    pub interfaces: Option<CollectionHealth>,
    pub attribution: Option<AttributionStatus>,
    pub capture: Option<CaptureStatus>,
    pub firewall: Option<FirewallStatus>,
}

/// One second of an interface's download and upload rate, in bytes per second.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RateSample {
    pub at: Duration,
    pub download: f64,
    pub upload: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InterfaceSummary {
    pub name: String,
    pub download: f64,
    pub upload: f64,
    pub session: ByteTotals,
}

/// One remote endpoint an app talked to.
#[derive(Clone, Debug, PartialEq)]
pub struct DestinationTraffic {
    pub remote: Endpoint,
    pub protocol: Protocol,
    pub bytes: ByteTotals,
    pub rate: ByteRates,
    pub idle: bool,
    pub pids: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AppTraffic {
    pub executable: ExecutableIdentity,
    pub destinations: Vec<DestinationTraffic>,
    /// The last eight seconds of all the app's destinations, oldest first, ending with the current second.
    pub history: [ByteTotals; HISTORY_SECONDS],
}

/// Whether a row is a packet the firewall dropped or a connection request the
/// kernel answered with a reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    Firewall,
    Refused,
}

/// One merged block: every event of one kind with the same source address,
/// destination port, protocol and direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedRow {
    pub kind: BlockKind,
    pub source: Option<IpAddr>,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub direction: Option<Direction>,
    pub interface: Option<String>,
    pub count: u64,
    pub first_seen: Duration,
    pub last_seen: Duration,
    /// Local wall-clock `HH:MM` of the latest event that carried a timestamp.
    pub last_clock: Option<String>,
    /// Local wall-clock `HH:MM` of the first event that carried a timestamp.
    pub first_clock: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListeningPort {
    pub listener: Listener,
    pub exposure: Exposure,
}

/// A device on a network: one hardware address seen in the neighbour table
/// on one interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub interface: String,
    pub mac: String,
    /// The addresses the latest snapshot listing it gave it, IPv4 before IPv6.
    pub addresses: BTreeSet<IpAddr>,
    /// Whether the latest readable neighbour snapshot lists it.
    pub present: bool,
}

type PortKey = (Protocol, IpAddr, u16);

/// Most addresses remembered for the neighbour events, and most devices; the kernel's own table is smaller.
const MAX_KNOWN_NEIGHBORS: usize = 4_096;
const MAX_BLOCKED_ROWS: usize = 1_000;
/// A connection request waits this long for the reset that answers it.
const REFUSAL_WINDOW: Duration = Duration::from_secs(2);
const MAX_PENDING_REQUESTS: usize = 64;
pub const DEFAULT_EPHEMERAL_PORTS: RangeInclusive<u16> = 32_768..=60_999;

/// Seconds of per-destination bytes kept for App Traffic's HISTORY column.
pub const HISTORY_SECONDS: usize = 8;

const IDLE_AFTER: Duration = Duration::from_secs(10);
const REMOVE_AFTER: Duration = Duration::from_secs(300);

struct Destination {
    remote: Endpoint,
    protocol: Protocol,
    bytes: ByteTotals,
    second: u64,
    /// Bytes of the last `HISTORY_SECONDS` seconds up to `second`, slot `s % 8` for second `s`.
    recent: [ByteTotals; HISTORY_SECONDS],
    last_seen: Duration,
    pids: Vec<u32>,
}

impl Destination {
    /// The bytes of one second, empty when it is later than `second` or eight or more seconds before it.
    fn bytes_in(&self, s: u64) -> ByteTotals {
        if s <= self.second && self.second - s < HISTORY_SECONDS as u64 {
            self.recent[s as usize % HISTORY_SECONDS]
        } else {
            ByteTotals::default()
        }
    }
}

struct App {
    executable: ExecutableIdentity,
    destinations: Vec<Destination>,
}

/// Most access points remembered; listed ones are never forgotten, so a list
/// longer than this is kept whole.
const WIFI_MEMORY_LIMIT: usize = 200;

/// How long a refused scan stays in the pane.
const WIFI_REFUSAL_SHOWN: Duration = Duration::from_secs(5);

struct Remembered {
    point: AccessPoint,
    last_listed: Duration,
    listed: bool,
}

/// What the user's request for a Wi-Fi scan has come to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WifiScan {
    /// Asked for at this time; cleared when the next list arrives.
    Requested(Duration),
    /// NetworkManager would not scan, for this reason, at this time.
    Refused { reason: String, at: Duration },
}

/// An access point in the Wi-Fi list. `seen_ago` is `None` while
/// NetworkManager lists it, and for one it no longer lists how long ago it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WifiEntry {
    pub point: AccessPoint,
    pub seen_ago: Option<Duration>,
}

pub struct AppState {
    limits: StateLimits,
    interfaces: Option<InterfaceSnapshot>,
    source_health: SourceHealth,
    now: Duration,
    rate_history: HashMap<String, VecDeque<RateSample>>,
    listeners: Vec<Listener>,
    ephemeral_ports: RangeInclusive<u16>,
    /// `None` until the first snapshot arrives.
    rules: Option<RuleSnapshot>,
    /// The last readable rules, the one the next reading is compared with.
    last_readable_rules: Option<RuleSnapshot>,
    /// Whether a listener reading has arrived.
    listeners_read: bool,
    /// App and exposure of each listening port at the last comparison; `None`
    /// until a listener reading and a readable rules reading have both
    /// arrived, which is the baseline.
    known_ports: Option<HashMap<PortKey, (Option<String>, &'static str)>>,
    /// `None` until the first snapshot arrives; entries kept sorted by address.
    neighbors: Option<NeighborSnapshot>,
    /// The hardware address last seen for each address and interface; `None`
    /// until the first available snapshot, which is the baseline. Nothing is
    /// removed when the kernel drops an entry.
    known_neighbors: Option<HashMap<(IpAddr, String), Option<String>>>,
    /// The devices seen on each interface, kept for the rest of the run.
    devices: BTreeMap<(String, String), Device>,
    /// The last readable interface snapshot, which the next one is compared with.
    last_readable_interfaces: Option<InterfaceSnapshot>,
    /// The access point in use at the last readable Wi-Fi list, as hardware
    /// address and network name; `None` before the first, `Some(None)` when
    /// none was in use.
    wifi_connection: Option<Option<(String, Option<String>)>>,
    /// `None` until the first snapshot arrives; then whether the last one was
    /// readable or why not.
    wifi_status: Option<Result<(), String>>,
    /// Every access point seen this session, by hardware address.
    wifi_memory: HashMap<String, Remembered>,
    wifi_scan: Option<WifiScan>,
    blocked: Vec<BlockedRow>,
    /// Block and refused-attempt events ever merged; the row cap does not reduce it.
    blocked_total: u64,
    /// Unowned connection requests to unlistened ports: (remote, local port, when).
    pending_requests: VecDeque<(Endpoint, u16, Duration)>,
    wall_clock: fn() -> Option<String>,
    events: EventLog,
    apps: Vec<App>,
    uncounted: ByteTotals,
    unattributed: ByteTotals,
}

impl AppState {
    pub fn new(limits: StateLimits) -> Result<Self, String> {
        if limits.detail_capacity == 0 || limits.chart_capacity == 0 {
            return Err("state capacities must be greater than zero".to_owned());
        }
        Ok(Self {
            limits,
            interfaces: None,
            source_health: SourceHealth::default(),
            now: Duration::ZERO,
            rate_history: HashMap::new(),
            listeners: Vec::new(),
            ephemeral_ports: DEFAULT_EPHEMERAL_PORTS,
            rules: None,
            last_readable_rules: None,
            listeners_read: false,
            known_ports: None,
            neighbors: None,
            known_neighbors: None,
            devices: BTreeMap::new(),
            last_readable_interfaces: None,
            wifi_connection: None,
            wifi_status: None,
            wifi_memory: HashMap::new(),
            wifi_scan: None,
            blocked: Vec::new(),
            blocked_total: 0,
            pending_requests: VecDeque::new(),
            wall_clock: local_clock_now,
            events: EventLog::default(),
            apps: Vec::new(),
            uncounted: ByteTotals::default(),
            unattributed: ByteTotals::default(),
        })
    }

    pub fn record_traffic(
        &mut self,
        at: Duration,
        traffic: TrafficEvent,
        process: Option<ProcessIdentity>,
    ) {
        self.now = self.now.max(at);
        if process.is_none() {
            self.watch_for_refusal(at, &traffic);
        }
        self.record_app_traffic(at, &traffic, process.as_ref());
    }

    /// Replaces the source of the `HH:MM` stamped on refused attempts.
    pub fn set_wall_clock(&mut self, clock: fn() -> Option<String>) {
        self.wall_clock = clock;
    }

    /// What Crosswalk has noticed changing, newest first.
    pub fn events(&self) -> &EventLog {
        &self.events
    }

    fn log_event(&mut self, kind: EventKind, level: EventLevel, text: String) {
        let clock = (self.wall_clock)();
        self.events.push(NetworkEvent {
            clock,
            kind,
            text,
            level,
        });
    }

    /// Remembers an unowned connection request to a port nothing listens on,
    /// and turns the reset that answers it into a refused-attempt row.
    fn watch_for_refusal(&mut self, at: Duration, traffic: &TrafficEvent) {
        let Some(flags) = traffic.tcp_flags else {
            return;
        };
        if traffic.protocol != Protocol::Tcp {
            return;
        }
        let (local, remote) = traffic.endpoints();
        let Some(port) = local.port else {
            return;
        };
        self.pending_requests
            .retain(|(_, _, seen)| at.saturating_sub(*seen) <= REFUSAL_WINDOW);
        match traffic.direction {
            Direction::Inbound if flags.syn && !flags.ack => {
                if !self.listens_on_tcp(port) {
                    self.pending_requests.push_back((remote, port, at));
                    if self.pending_requests.len() > MAX_PENDING_REQUESTS {
                        self.pending_requests.pop_front();
                    }
                }
            }
            Direction::Outbound if flags.rst => {
                let Some(found) = self
                    .pending_requests
                    .iter()
                    .position(|(r, p, _)| *r == remote && *p == port)
                else {
                    return;
                };
                self.pending_requests.remove(found);
                let clock = (self.wall_clock)();
                let key = (
                    BlockKind::Refused,
                    Some(remote.ip),
                    Some(port),
                    Some(Protocol::Tcp),
                    Some(Direction::Inbound),
                );
                self.merge_row(at, key, None, clock);
            }
            _ => {}
        }
    }

    fn listens_on_tcp(&self, port: u16) -> bool {
        self.listeners
            .iter()
            .any(|l| l.port == port && l.protocol == Protocol::Tcp)
    }

    fn record_app_traffic(
        &mut self,
        at: Duration,
        traffic: &TrafficEvent,
        process: Option<&ProcessIdentity>,
    ) {
        let (_, remote) = traffic.endpoints();
        if left_out_of_app_traffic(traffic, process.is_some(), |port| self.listens_on_tcp(port)) {
            return;
        }
        let bytes = u64::from(traffic.original_ip_bytes);
        let Some(process) = process else {
            self.unattributed.add(traffic.direction, bytes);
            return;
        };
        let executable = process.executable.clone();
        let app_index = self.apps.iter().position(|a| a.executable == executable);
        let existing = app_index.and_then(|i| {
            self.apps[i]
                .destinations
                .iter()
                .position(|d| d.remote == remote && d.protocol == traffic.protocol)
                .map(|j| (i, j))
        });
        let (i, j) = match existing {
            Some(found) => found,
            None => {
                let listed: usize = self.apps.iter().map(|a| a.destinations.len()).sum();
                if listed >= self.limits.detail_capacity {
                    self.uncounted.add(traffic.direction, bytes);
                    return;
                }
                let i = app_index.unwrap_or_else(|| {
                    self.apps.push(App {
                        executable,
                        destinations: Vec::new(),
                    });
                    self.apps.len() - 1
                });
                self.apps[i].destinations.push(Destination {
                    remote,
                    protocol: traffic.protocol,
                    bytes: ByteTotals::default(),
                    second: at.as_secs(),
                    recent: [ByteTotals::default(); HISTORY_SECONDS],
                    last_seen: at,
                    pids: Vec::new(),
                });
                (i, self.apps[i].destinations.len() - 1)
            }
        };
        let destination = &mut self.apps[i].destinations[j];
        destination.bytes.add(traffic.direction, bytes);
        if at.as_secs() > destination.second {
            let first = destination.second + 1;
            for s in (first..=at.as_secs()).take(HISTORY_SECONDS) {
                destination.recent[s as usize % HISTORY_SECONDS] = ByteTotals::default();
            }
            destination.second = at.as_secs();
        }
        destination.recent[destination.second as usize % HISTORY_SECONDS]
            .add(traffic.direction, bytes);
        destination.last_seen = destination.last_seen.max(at);
        if !destination.pids.contains(&process.pid) {
            destination.pids.push(process.pid);
        }
    }

    /// Store the latest listening sockets and the kernel's ephemeral port
    /// range. TCP packets on a listening TCP port are replies to inbound
    /// connections and stay out of App Traffic.
    pub fn record_listeners(&mut self, listeners: Vec<Listener>, ephemeral: RangeInclusive<u16>) {
        self.listeners = listeners;
        self.ephemeral_ports = ephemeral;
        self.listeners_read = true;
        self.log_port_events();
    }

    pub fn record_rules(&mut self, rules: RuleSnapshot) {
        if !matches!(rules, RuleSnapshot::Unavailable(_)) {
            let previous = self.last_readable_rules.replace(rules.clone());
            if let Some(previous) = previous {
                self.log_firewall_events(&previous, &rules);
            }
        }
        self.rules = Some(rules);
        self.log_port_events();
    }

    fn log_firewall_events(&mut self, old: &RuleSnapshot, new: &RuleSnapshot) {
        use RuleSnapshot::{Active, Inactive};
        let mut events = Vec::new();
        match (old, new) {
            (Active { .. }, Inactive) => {
                events.push((EventLevel::Warning, "UFW switched off".to_owned()));
            }
            (Inactive, Active { .. }) => {
                events.push((EventLevel::Normal, "UFW switched on".to_owned()));
            }
            (
                Active {
                    default_incoming: old_in,
                    default_outgoing: old_out,
                    rules: old_rules,
                },
                Active {
                    default_incoming: new_in,
                    default_outgoing: new_out,
                    rules: new_rules,
                },
            ) => {
                let mut gone: Vec<&str> = old_rules.iter().map(|r| r.text.as_str()).collect();
                for rule in new_rules {
                    match gone.iter().position(|text| *text == rule.text) {
                        Some(i) => {
                            gone.remove(i);
                        }
                        None => {
                            events.push((EventLevel::Normal, format!("rule added: {}", rule.text)))
                        }
                    }
                }
                for text in gone {
                    events.push((EventLevel::Normal, format!("rule removed: {text}")));
                }
                for (direction, old, new) in
                    [("incoming", old_in, new_in), ("outgoing", old_out, new_out)]
                {
                    if old != new {
                        events.push((
                            EventLevel::Normal,
                            format!(
                                "default {direction} policy {} -> {}",
                                old.label(),
                                new.label()
                            ),
                        ));
                    }
                }
            }
            _ => {}
        }
        for (level, text) in events {
            self.log_event(EventKind::Firewall, level, text);
        }
    }

    /// Compares the listening ports with those of the last comparison. Waits
    /// for a listener reading and a readable rules reading, so that exposure
    /// settling from "not read yet" is not a change; an exposure that is
    /// unknown (UFW off) is neither a change nor a baseline.
    fn log_port_events(&mut self) {
        if !self.listeners_read || matches!(self.rules, None | Some(RuleSnapshot::Unavailable(_))) {
            return;
        }
        let ports = self.listening_ports();
        let mut known = self.known_ports.take();
        let mut next = HashMap::new();
        let mut events = Vec::new();
        for port in &ports {
            let listener = &port.listener;
            let key = (listener.protocol, listener.address, listener.port);
            let app = listener.owners.first().and_then(|owner| {
                owner
                    .executable
                    .path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            });
            let label = exposure_label(&port.exposure);
            let name = port_name(&key, app.as_deref());
            let stored = match known.as_ref().map(|known| known.get(&key)) {
                None => label,
                Some(None) => {
                    let level = if label == "open" {
                        EventLevel::Warning
                    } else {
                        EventLevel::Normal
                    };
                    events.push((level, format!("{name} started listening, {label}")));
                    label
                }
                Some(Some((_, old))) if *old == label => label,
                Some(Some((_, old))) if *old == "unknown" => label,
                Some(Some((_, old))) if label == "unknown" => old,
                Some(Some((_, old))) => {
                    let level = if label == "open" {
                        EventLevel::Warning
                    } else {
                        EventLevel::Normal
                    };
                    events.push((level, format!("{name} exposure {old} -> {label}")));
                    label
                }
            };
            next.insert(key, (app, stored));
        }
        if let Some(known) = known.as_mut() {
            let mut closed: Vec<_> = known
                .iter()
                .filter(|(k, _)| !next.contains_key(*k))
                .collect();
            closed.sort_by_key(|((_, address, port), _)| (*port, *address));
            for (key, (app, _)) in closed {
                events.push((
                    EventLevel::Normal,
                    format!("{} stopped listening", port_name(key, app.as_deref())),
                ));
            }
        }
        self.known_ports = Some(next);
        for (level, text) in events {
            self.log_event(EventKind::Port, level, text);
        }
    }

    /// The latest firewall rules, or `None` before the first read finishes.
    pub fn rule_snapshot(&self) -> Option<&RuleSnapshot> {
        self.rules.as_ref()
    }

    /// Keep the latest neighbour table, sorted by address (IPv4 before IPv6,
    /// numerically within each), then by interface.
    pub fn record_neighbors(&mut self, mut neighbors: NeighborSnapshot) {
        if let NeighborSnapshot::Available(entries) = &mut neighbors {
            entries.sort_by(|a, b| (a.address, &a.interface).cmp(&(b.address, &b.interface)));
        }
        if let NeighborSnapshot::Available(entries) = &neighbors {
            self.log_neighbor_events(entries);
            self.record_devices(entries);
        }
        self.neighbors = Some(neighbors);
    }

    /// Every device seen since the start, ordered by interface and hardware address.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    fn record_devices(&mut self, entries: &[Neighbor]) {
        for device in self.devices.values_mut() {
            device.present = false;
        }
        let mut listed: BTreeMap<(String, String), BTreeSet<IpAddr>> = BTreeMap::new();
        let mut room = MAX_KNOWN_NEIGHBORS.saturating_sub(self.devices.len());
        for entry in entries {
            let Some(mac) = &entry.mac else { continue };
            let key = (entry.interface.clone(), mac.clone());
            if !listed.contains_key(&key) && !self.devices.contains_key(&key) {
                if room == 0 {
                    continue;
                }
                room -= 1;
            }
            listed.entry(key).or_default().insert(entry.address);
        }
        // A listed device has the addresses the snapshot gives it; an absent one keeps its last.
        for ((interface, mac), addresses) in listed {
            let device = self
                .devices
                .entry((interface.clone(), mac.clone()))
                .or_insert_with(|| Device {
                    interface,
                    mac,
                    addresses: BTreeSet::new(),
                    present: true,
                });
            device.addresses = addresses;
            device.present = true;
        }
    }

    fn log_neighbor_events(&mut self, entries: &[Neighbor]) {
        let baseline = self.known_neighbors.is_none();
        let mut known = self.known_neighbors.take().unwrap_or_default();
        let mut events = Vec::new();
        for entry in entries {
            let key = (entry.address, entry.interface.clone());
            let Some(mac) = &entry.mac else {
                // At the baseline, an address without a hardware address yet
                // is still known, so it is not new when it resolves.
                if baseline {
                    known.insert(key, None);
                }
                continue;
            };
            match known.get(&key) {
                Some(Some(old)) if old == mac => continue,
                Some(Some(old)) => events.push((
                    EventLevel::Danger,
                    format!(
                        "{} MAC {old} -> {mac} on {}",
                        entry.address, entry.interface
                    ),
                )),
                Some(None) => {}
                None if baseline => {}
                None if known.len() >= MAX_KNOWN_NEIGHBORS => continue,
                None => events.push((
                    EventLevel::Normal,
                    format!(
                        "new neighbour {} {mac} on {}",
                        entry.address, entry.interface
                    ),
                )),
            }
            known.insert(key, Some(mac.clone()));
        }
        self.known_neighbors = Some(known);
        for (level, text) in events {
            self.log_event(EventKind::Neighbour, level, text);
        }
    }

    /// Merge an available Wi-Fi list into the memory of access points seen,
    /// keyed by hardware address; the listed ones are stamped with the
    /// current time and the others keep their details and last time. An
    /// unavailable list leaves the memory as it is and is what `wifi()`
    /// reports until the next available one.
    pub fn record_wifi(&mut self, wifi: WifiSnapshot) {
        match wifi {
            WifiSnapshot::Unavailable(reason) => {
                self.wifi_status = Some(Err(reason));
                self.end_wifi_wait();
            }
            WifiSnapshot::Available(access_points) => {
                self.log_wifi_events(&access_points);
                self.wifi_status = Some(Ok(()));
                self.end_wifi_wait();
                for remembered in self.wifi_memory.values_mut() {
                    remembered.listed = false;
                    remembered.point.in_use = false;
                }
                for point in access_points {
                    self.wifi_memory.insert(
                        point.bssid.clone(),
                        Remembered {
                            point,
                            last_listed: self.now,
                            listed: true,
                        },
                    );
                }
                while self.wifi_memory.len() > WIFI_MEMORY_LIMIT {
                    let oldest = self
                        .wifi_memory
                        .iter()
                        .filter(|(_, r)| !r.listed)
                        .min_by_key(|(bssid, r)| (r.last_listed, (*bssid).clone()))
                        .map(|(bssid, _)| bssid.clone());
                    match oldest {
                        Some(bssid) => self.wifi_memory.remove(&bssid),
                        None => break,
                    };
                }
            }
        }
    }

    fn log_wifi_events(&mut self, access_points: &[AccessPoint]) {
        let now = access_points
            .iter()
            .find(|point| point.in_use)
            .map(|point| (point.bssid.clone(), point.ssid.clone()));
        let before = self.wifi_connection.replace(now.clone());
        let Some(before) = before else { return };
        let name =
            |ssid: &Option<String>| ssid.clone().unwrap_or_else(|| "hidden network".to_owned());
        let text = match (before, now) {
            (Some((old, _)), Some((new, _))) if old == new => return,
            (Some((old, old_ssid)), Some((new, new_ssid))) if old_ssid == new_ssid => {
                format!("Wi-Fi roamed on {}: {old} -> {new}", name(&new_ssid))
            }
            (Some((old, old_ssid)), Some((new, new_ssid))) => format!(
                "Wi-Fi moved from {} ({old}) to {} ({new})",
                name(&old_ssid),
                name(&new_ssid)
            ),
            (Some((old, ssid)), None) => format!("Wi-Fi disconnected from {} ({old})", name(&ssid)),
            (None, Some((new, ssid))) => format!("Wi-Fi connected to {} ({new})", name(&ssid)),
            (None, None) => return,
        };
        self.log_event(EventKind::Connection, EventLevel::Normal, text);
    }

    /// A list has arrived, so a scan no longer waits for one.
    fn end_wifi_wait(&mut self) {
        if matches!(self.wifi_scan, Some(WifiScan::Requested(_))) {
            self.wifi_scan = None;
        }
    }

    /// Notes that a scan was asked for now: shown until the next list arrives.
    pub fn record_wifi_scan_requested(&mut self) {
        self.wifi_scan = Some(WifiScan::Requested(self.now));
    }

    /// What NetworkManager answered to a request for a scan.
    pub fn record_wifi_scan(&mut self, outcome: ScanOutcome) {
        match outcome {
            ScanOutcome::Accepted => self.record_wifi_scan_requested(),
            ScanOutcome::Refused(reason) => {
                self.wifi_scan = Some(WifiScan::Refused {
                    reason,
                    at: self.now,
                });
            }
        }
    }

    /// The scan the user asked for: still waiting for its list, or refused
    /// less than `WIFI_REFUSAL_SHOWN` ago. `None` otherwise.
    pub fn wifi_scan(&self) -> Option<&WifiScan> {
        self.wifi_scan.as_ref().filter(|scan| match scan {
            WifiScan::Requested(_) => true,
            WifiScan::Refused { at, .. } => self.now.saturating_sub(*at) < WIFI_REFUSAL_SHOWN,
        })
    }

    /// `None` before the first snapshot; otherwise the access points (possibly
    /// none) or the reason the list could not be read. The ones NetworkManager
    /// lists come first, strongest signal first, then by name (no name last),
    /// then by hardware address; the remembered ones follow, most recently
    /// seen first, each with how long ago it was last listed.
    pub fn wifi(&self) -> Option<Result<Vec<WifiEntry>, &str>> {
        let status = self.wifi_status.as_ref()?;
        if let Err(reason) = status {
            return Some(Err(reason.as_str()));
        }
        let (mut listed, mut remembered): (Vec<_>, Vec<_>) =
            self.wifi_memory.values().partition(|r| r.listed);
        listed.sort_by_key(|r| {
            (
                std::cmp::Reverse(r.point.signal),
                r.point.ssid.is_none(),
                r.point.ssid.clone(),
                r.point.bssid.clone(),
            )
        });
        remembered.sort_by_key(|r| (std::cmp::Reverse(r.last_listed), r.point.bssid.clone()));
        let entries = listed.into_iter().chain(remembered).map(|r| WifiEntry {
            point: r.point.clone(),
            seen_ago: (!r.listed).then(|| self.now.saturating_sub(r.last_listed)),
        });
        Some(Ok(entries.collect()))
    }

    /// `None` before the first snapshot; otherwise the sorted entries (possibly
    /// none) or the reason the table could not be read.
    pub fn neighbors(&self) -> Option<Result<&[Neighbor], &str>> {
        self.neighbors.as_ref().map(|snapshot| match snapshot {
            NeighborSnapshot::Available(entries) => Ok(entries.as_slice()),
            NeighborSnapshot::Unavailable(reason) => Err(reason.as_str()),
        })
    }

    /// Listening ports in port order with their exposure. UDP sockets inside
    /// at or above the ephemeral range start are client sockets and are left out.
    pub fn listening_ports(&self) -> Vec<ListeningPort> {
        let rules = self
            .rules
            .clone()
            .unwrap_or_else(|| RuleSnapshot::Unavailable("rules not read yet".to_owned()));
        let mut ports: Vec<ListeningPort> = self
            .listeners
            .iter()
            .filter(|l| l.protocol != Protocol::Udp || l.port < *self.ephemeral_ports.start())
            .map(|l| ListeningPort {
                exposure: exposure(l, &rules),
                listener: l.clone(),
            })
            .collect();
        ports.sort_by_key(|p| p.listener.port);
        ports
    }

    /// Merged blocks for one direction, newest key first.
    pub fn blocked(&self, direction: Direction) -> Vec<BlockedRow> {
        self.blocked
            .iter()
            .filter(|row| row.direction == Some(direction))
            .cloned()
            .collect()
    }

    /// Every merged block whatever its direction, forwarded ones included, newest key first.
    pub fn blocked_rows(&self) -> Vec<BlockedRow> {
        self.blocked.clone()
    }

    /// Apps in first-seen order, each with destinations in first-seen order.
    pub fn app_traffic(&self) -> Vec<AppTraffic> {
        let now_second = self.now.as_secs();
        self.apps
            .iter()
            .map(|app| AppTraffic {
                executable: app.executable.clone(),
                history: std::array::from_fn(|i| {
                    let second = (now_second + 1 + i as u64).wrapping_sub(HISTORY_SECONDS as u64);
                    let mut sum = ByteTotals::default();
                    for d in &app.destinations {
                        let t = d.bytes_in(second);
                        sum.download = sum.download.saturating_add(t.download);
                        sum.upload = sum.upload.saturating_add(t.upload);
                    }
                    sum
                }),
                destinations: app
                    .destinations
                    .iter()
                    .map(|d| {
                        // The rate shows `d.second` while it is current, else nothing at `now`.
                        let current = now_second.saturating_sub(d.second) <= 1;
                        let second = d.bytes_in(if current { d.second } else { now_second });
                        DestinationTraffic {
                            remote: d.remote,
                            protocol: d.protocol,
                            bytes: d.bytes,
                            rate: ByteRates {
                                upload: second.upload as f64,
                                download: second.download as f64,
                            },
                            idle: self.now.saturating_sub(d.last_seen) >= IDLE_AFTER,
                            pids: d.pids.clone(),
                        }
                    })
                    .collect(),
            })
            .collect()
    }

    /// Bytes of packets that had no owning app and were not left out.
    pub fn app_traffic_unattributed(&self) -> ByteTotals {
        self.unattributed
    }

    /// Bytes that arrived for destinations past the App Traffic capacity.
    pub fn app_traffic_uncounted(&self) -> ByteTotals {
        self.uncounted
    }

    /// The newest `chart_capacity` per-second rate samples for an interface.
    pub fn rate_history(&self, interface: &str) -> Vec<RateSample> {
        self.rate_history
            .get(interface)
            .map(|ring| ring.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Interfaces of the latest snapshot with their current rates and totals.
    pub fn interfaces(&self) -> Vec<InterfaceSummary> {
        self.interfaces
            .iter()
            .flat_map(|snapshot| &snapshot.interfaces)
            .map(|i| InterfaceSummary {
                name: i.name.clone(),
                download: i.download_bytes_per_second,
                upload: i.upload_bytes_per_second,
                session: ByteTotals {
                    upload: i.session_transmitted_bytes,
                    download: i.session_received_bytes,
                },
            })
            .collect()
    }

    /// The latest interface snapshot: addresses, default route, gateway and name server.
    pub fn interface_snapshot(&self) -> Option<&InterfaceSnapshot> {
        self.interfaces.as_ref()
    }

    pub fn default_route(&self) -> Option<&str> {
        self.interfaces.as_ref()?.default_route.as_deref()
    }

    /// Firewall block and refused-attempt events recorded so far, repeats of
    /// a row included; it only grows.
    pub fn blocked_total(&self) -> u64 {
        self.blocked_total
    }

    pub fn record_firewall(&mut self, at: Duration, event: FirewallEvent) {
        self.now = self.now.max(at);
        self.merge_block(at, &event);
    }

    fn merge_block(&mut self, at: Duration, event: &FirewallEvent) {
        let key = (
            BlockKind::Firewall,
            event.source.ip,
            event.destination.port,
            event.protocol,
            event.direction,
        );
        let clock = event.timestamp.as_deref().and_then(clock_time);
        self.merge_row(at, key, event.interface.clone(), clock);
    }

    fn merge_row(
        &mut self,
        at: Duration,
        key: (
            BlockKind,
            Option<IpAddr>,
            Option<u16>,
            Option<Protocol>,
            Option<Direction>,
        ),
        interface: Option<String>,
        clock: Option<String>,
    ) {
        self.blocked_total += 1;
        if let Some(row) = self
            .blocked
            .iter_mut()
            .find(|r| (r.kind, r.source, r.port, r.protocol, r.direction) == key)
        {
            row.count += 1;
            row.last_seen = row.last_seen.max(at);
            row.interface = interface.or(row.interface.take());
            row.first_clock = row.first_clock.take().or_else(|| clock.clone());
            row.last_clock = clock.or(row.last_clock.take());
            return;
        }
        self.blocked.insert(
            0,
            BlockedRow {
                kind: key.0,
                source: key.1,
                port: key.2,
                protocol: key.3,
                direction: key.4,
                interface,
                count: 1,
                first_seen: at,
                last_seen: at,
                first_clock: clock.clone(),
                last_clock: clock,
            },
        );
        self.blocked.truncate(MAX_BLOCKED_ROWS);
    }

    pub fn record_interfaces(&mut self, snapshot: InterfaceSnapshot) {
        self.source_health.interfaces = Some(snapshot.health.clone());
        let at = Duration::from_secs(self.now.as_secs());
        for interface in &snapshot.interfaces {
            let sample = RateSample {
                at,
                download: interface.download_bytes_per_second,
                upload: interface.upload_bytes_per_second,
            };
            let ring = self.rate_history.entry(interface.name.clone()).or_default();
            if ring.back().is_some_and(|last| last.at == at) {
                ring.pop_back();
            }
            ring.push_back(sample);
            while ring.len() > self.limits.chart_capacity {
                ring.pop_front();
            }
        }
        self.rate_history.retain(|name, _| {
            snapshot
                .interfaces
                .iter()
                .any(|interface| &interface.name == name)
        });
        if snapshot.health == CollectionHealth::Available
            && let Some(previous) = self.last_readable_interfaces.replace(snapshot.clone())
        {
            self.log_connection_events(&previous, &snapshot);
        }
        self.interfaces = Some(snapshot);
    }

    fn log_connection_events(&mut self, old: &InterfaceSnapshot, new: &InterfaceSnapshot) {
        let addresses = |snapshot: &InterfaceSnapshot| {
            let mut all: Vec<(String, IpAddr, u8)> = snapshot
                .interfaces
                .iter()
                .flat_map(|i| i.addresses.iter().map(|a| (i.name.clone(), a.ip, a.prefix)))
                .collect();
            all.sort();
            all
        };
        let (before, after) = (addresses(old), addresses(new));
        let mut texts = Vec::new();
        for (name, ip, prefix) in before.iter().filter(|a| !after.contains(a)) {
            texts.push(format!("{name} lost {ip}/{prefix}"));
        }
        for (name, ip, prefix) in after.iter().filter(|a| !before.contains(a)) {
            texts.push(format!("{name} gained {ip}/{prefix}"));
        }
        let route = |snapshot: &InterfaceSnapshot| match &snapshot.default_route {
            None => "none".to_owned(),
            Some(name) => match snapshot.gateway {
                Some(gateway) => format!("{name} via {gateway}"),
                None => name.clone(),
            },
        };
        if (&old.default_route, old.gateway) != (&new.default_route, new.gateway) {
            texts.push(format!("default route {} -> {}", route(old), route(new)));
        }
        if old.name_server != new.name_server {
            let server = |s: Option<IpAddr>| s.map_or("none".to_owned(), |s| s.to_string());
            texts.push(format!(
                "DNS server {} -> {}",
                server(old.name_server),
                server(new.name_server)
            ));
        }
        for text in texts {
            self.log_event(EventKind::Connection, EventLevel::Normal, text);
        }
    }

    pub fn record_attribution_status(&mut self, status: AttributionStatus) {
        self.source_health.attribution = Some(status);
    }

    pub fn record_capture_status(&mut self, status: CaptureStatus) {
        self.source_health.capture = Some(status);
    }

    pub fn record_firewall_status(&mut self, status: FirewallStatus) {
        self.source_health.firewall = Some(status);
    }

    pub fn advance_time(&mut self, now: Duration) {
        self.now = self.now.max(now);
        let now = self.now;
        for app in &mut self.apps {
            app.destinations
                .retain(|d| now.saturating_sub(d.last_seen) < REMOVE_AFTER);
        }
        self.apps.retain(|app| !app.destinations.is_empty());
    }

    pub fn source_health(&self) -> &SourceHealth {
        &self.source_health
    }
}
/// Whether App Traffic leaves the packet out: TCP on a port the machine
/// listens on (mostly replies to inbound connections), and unowned refused
/// inbound attempts, the connection request arriving and the reset the kernel
/// sends back.
pub fn left_out_of_app_traffic(
    traffic: &TrafficEvent,
    owned: bool,
    is_listening_tcp_port: impl Fn(u16) -> bool,
) -> bool {
    if traffic.protocol != Protocol::Tcp {
        return false;
    }
    let (local, _) = traffic.endpoints();
    if local.port.is_some_and(is_listening_tcp_port) {
        return true;
    }
    !owned
        && traffic.tcp_flags.is_some_and(|f| match traffic.direction {
            Direction::Inbound => f.syn && !f.ack,
            Direction::Outbound => f.rst,
        })
}

fn exposure_label(exposure: &Exposure) -> &'static str {
    match exposure {
        Exposure::Open(_) => "open",
        Exposure::Limited(_) => "limited",
        Exposure::Blocked(_) => "blocked",
        Exposure::Local => "local",
        Exposure::Unknown(_) => "unknown",
    }
}

/// `tcp 0.0.0.0:22 sshd`, without the app when none owns the port.
fn port_name(key: &PortKey, app: Option<&str>) -> String {
    let protocol = match key.0 {
        Protocol::Tcp => "tcp".to_owned(),
        Protocol::Udp => "udp".to_owned(),
        Protocol::Other(number) => format!("ip{number}"),
    };
    let address = std::net::SocketAddr::new(key.1, key.2);
    match app {
        Some(app) => format!("{protocol} {address} {app}"),
        None => format!("{protocol} {address}"),
    }
}

fn local_hhmm(seconds: libc::time_t) -> Option<String> {
    let mut local: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call; localtime_r only writes to `local`.
    let converted = unsafe { libc::localtime_r(&seconds, &mut local) };
    (!converted.is_null()).then(|| format!("{:02}:{:02}", local.tm_hour, local.tm_min))
}

/// Local wall-clock `HH:MM` now.
fn local_clock_now() -> Option<String> {
    // SAFETY: time accepts a null pointer and returns the current time.
    local_hhmm(unsafe { libc::time(std::ptr::null_mut()) })
}

/// `HH:MM` from a firewall event's own timestamp: journal microseconds since
/// the epoch (converted to local time), or the wall-clock text of a log line.
fn clock_time(timestamp: &str) -> Option<String> {
    let timestamp = timestamp.trim();
    if !timestamp.is_empty() && timestamp.bytes().all(|b| b.is_ascii_digit()) {
        let seconds: libc::time_t = (timestamp.parse::<u64>().ok()? / 1_000_000)
            .try_into()
            .ok()?;
        return local_hhmm(seconds);
    }
    let time = timestamp
        .split(|c: char| c.is_whitespace() || c == 'T')
        .find(|part| part.as_bytes().get(2) == Some(&b':'))?
        .get(..5)?;
    let digits = |range: std::ops::Range<usize>| time[range].bytes().all(|b| b.is_ascii_digit());
    (digits(0..2) && digits(3..5)).then(|| time.to_owned())
}

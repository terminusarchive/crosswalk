use crossterm::{
    cursor, execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    collections::HashSet,
    net::IpAddr,
    ops::RangeInclusive,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    attribution_log::{self, AttributionLog},
    collect::{
        attribution::{
            AttributionCollector, AttributionHealth, AttributionResult, LinuxProcfsSource, NoOwner,
            NoOwnerCause, OwnerMemory, ProcessIdentity,
        },
        capture::{
            CaptureHealth, CaptureOrigin, CaptureSource, CaptureWorker, PcapSource, Protocol,
            TrafficEvent,
        },
        dumpcap::{DumpcapSource, dumpcap_command},
        interfaces::{
            CollectionHealth, InterfaceCounterCollector, InterfaceSnapshot, InterfaceStatus,
            LinuxInterfaceSource,
        },
        neighbors::{IpCommand, NeighborCollector, NeighborSnapshot},
        wifi::{NmcliCommand, ScanOutcome, WifiCollector, WifiSnapshot},
    },
    config::Config,
    firewall::{self, FirewallEvent, FirewallProvider, FirewallStatus, RuleSnapshot},
    privileges::{
        Capabilities, PrivilegeError, enable_net_raw_if_available, give_up_everything,
        keep_only_sys_ptrace_available, with_sys_ptrace,
    },
    state::{AppState, DEFAULT_EPHEMERAL_PORTS, left_out_of_app_traffic},
};

pub const EVENT_CAPACITY: usize = 1024;
pub const MAX_EVENTS_PER_FRAME: usize = 256;
const LISTENERS_EVERY: Duration = Duration::from_secs(2);
const ADDRESSES_EVERY: Duration = Duration::from_secs(1);
const WIFI_EVERY: Duration = Duration::from_secs(5);
const RULES_EVERY: Duration = Duration::from_secs(5);

/// The kernel's ephemeral port range, or the Linux default when unreadable.
fn ephemeral_port_range() -> RangeInclusive<u16> {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|text| {
            let mut numbers = text.split_whitespace().map(str::parse::<u16>);
            match (numbers.next(), numbers.next()) {
                (Some(Ok(low)), Some(Ok(high))) if low <= high => Some(low..=high),
                _ => None,
            }
        })
        .unwrap_or(DEFAULT_EPHEMERAL_PORTS)
}

#[derive(Debug)]
pub enum DashboardEvent {
    Traffic {
        at: Duration,
        event: TrafficEvent,
        process: Option<crate::collect::attribution::ProcessIdentity>,
    },
    Firewall {
        at: Duration,
        event: FirewallEvent,
    },
    Interfaces(crate::collect::interfaces::InterfaceSnapshot),
    Attribution(crate::collect::attribution::AttributionStatus),
    CaptureStatus(crate::collect::capture::CaptureStatus),
    FirewallStatus(FirewallStatus),
    Listeners {
        listeners: Vec<crate::collect::attribution::Listener>,
        ephemeral: RangeInclusive<u16>,
    },
    FirewallRules(RuleSnapshot),
    Neighbors(NeighborSnapshot),
    Wifi(WifiSnapshot),
    WifiScan(ScanOutcome),
}

pub struct EventPump {
    receiver: Receiver<DashboardEvent>,
}

impl EventPump {
    pub fn new(receiver: Receiver<DashboardEvent>) -> Self {
        Self { receiver }
    }

    pub fn drain(&mut self, state: &mut AppState, limit: usize) -> usize {
        let mut count = 0;
        while count < limit {
            let Ok(event) = self.receiver.try_recv() else {
                break;
            };
            match event {
                DashboardEvent::Traffic { at, event, process } => {
                    state.record_traffic(at, event, process)
                }
                DashboardEvent::Firewall { at, event } => state.record_firewall(at, event),
                DashboardEvent::Interfaces(snapshot) => state.record_interfaces(snapshot),
                DashboardEvent::Attribution(status) => state.record_attribution_status(status),
                DashboardEvent::CaptureStatus(status) => state.record_capture_status(status),
                DashboardEvent::FirewallStatus(status) => state.record_firewall_status(status),
                DashboardEvent::Listeners {
                    listeners,
                    ephemeral,
                } => state.record_listeners(listeners, ephemeral),
                DashboardEvent::FirewallRules(rules) => state.record_rules(rules),
                DashboardEvent::Neighbors(snapshot) => state.record_neighbors(snapshot),
                DashboardEvent::Wifi(snapshot) => state.record_wifi(snapshot),
                DashboardEvent::WifiScan(outcome) => state.record_wifi_scan(outcome),
            }
            count += 1;
        }
        count
    }
}

/// Most packets held for the next snapshot.
pub const HELD_PACKET_LIMIT: usize = 8_192;
/// Age of the last snapshot at which the next is taken while a packet waits.
const SNAPSHOT_WHEN_HELD: Duration = Duration::from_millis(100);
const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);

/// A held packet let go, with how long it waited since it was read (`None`
/// when the read time is not known).
pub struct Released {
    pub at: Duration,
    pub event: TrafficEvent,
    pub process: Option<ProcessIdentity>,
    pub waited: Option<Duration>,
}

/// Packets with no owner when they arrive, kept until the next snapshot so
/// they can be looked up once more, and the time that snapshot is due.
pub struct PacketHold {
    held: Vec<TrafficEvent>,
    limit: usize,
    last_snapshot: Option<Duration>,
}

impl PacketHold {
    pub fn new(limit: usize) -> Self {
        Self {
            held: Vec::new(),
            limit,
            last_snapshot: None,
        }
    }

    /// The packet back when it is to be sent now, `None` when it is held.
    /// Only a packet with no owner under available attribution that App
    /// Traffic would list (`left_out` false) is held, and only while there is
    /// room.
    pub fn admit(
        &mut self,
        event: TrafficEvent,
        result: &AttributionResult,
        left_out: bool,
    ) -> Option<TrafficEvent> {
        let hold = result.owner.is_none()
            && result.health == AttributionHealth::Available
            && !left_out
            && self.held.len() < self.limit;
        if hold {
            self.held.push(event);
            return None;
        }
        Some(event)
    }

    /// Whether a snapshot should be taken now: before the first, a tenth of
    /// a second after the last while a packet is held, else a second after.
    pub fn snapshot_due(&self, now: Duration) -> bool {
        let every = if self.held.is_empty() {
            SNAPSHOT_EVERY
        } else {
            SNAPSHOT_WHEN_HELD
        };
        self.last_snapshot
            .is_none_or(|last| now.saturating_sub(last) >= every)
    }

    pub fn snapshot_taken(&mut self, now: Duration) {
        self.last_snapshot = Some(now);
    }

    /// Every held packet, in arrival order, stamped `at` with the owner
    /// `lookup` finds. Pass `|_| None` when the snapshot could not be taken.
    pub fn release(
        &mut self,
        at: Duration,
        mut lookup: impl FnMut(&TrafficEvent) -> Option<ProcessIdentity>,
    ) -> Vec<Released> {
        self.held
            .drain(..)
            .map(|event| {
                let process = lookup(&event);
                let waited = event.timing.map(|timing| timing.read_at.elapsed());
                Released {
                    at,
                    event,
                    process,
                    waited,
                }
            })
            .collect()
    }
}

pub struct LiveWorkers {
    cancelled: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    /// Set by `request_wifi_scan`, taken by the metrics loop on its next pass.
    scan_requested: Arc<AtomicBool>,
}

impl LiveWorkers {
    pub fn start(
        config: &Config,
        sender: SyncSender<DashboardEvent>,
        attribution_log: Option<AttributionLog>,
        capabilities: Option<Capabilities>,
        origin: CaptureOrigin,
    ) -> Self {
        // Unknown capabilities show nothing; only a known missing one is limited.
        let limited = capabilities.is_some_and(|c| !c.sys_ptrace);
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        let capture_sender = sender.clone();
        let capture_cancelled = cancelled.clone();
        handles.push(
            thread::Builder::new()
                .name("crosswalk-capture".to_owned())
                .spawn(move || {
                    capture_loop(
                        capture_sender,
                        capture_cancelled,
                        attribution_log,
                        limited,
                        origin,
                    )
                })
                .expect("capture worker thread creation failed"),
        );

        let interface_sender = sender.clone();
        let interface_cancelled = cancelled.clone();
        let scan_requested = Arc::new(AtomicBool::new(false));
        let metrics_scan_requested = scan_requested.clone();
        handles.push(
            thread::Builder::new()
                .name("crosswalk-metrics".to_owned())
                .spawn(move || {
                    metrics_loop(
                        interface_sender,
                        interface_cancelled,
                        metrics_scan_requested,
                        limited,
                    )
                })
                .expect("metrics worker thread creation failed"),
        );

        let firewall_cancelled = cancelled.clone();
        let config = config.clone();
        handles.push(
            thread::Builder::new()
                .name("crosswalk-firewall".to_owned())
                .spawn(move || {
                    or_stop(give_up_everything());
                    let mut provider = firewall::create_provider(&config);
                    firewall_loop(provider.as_mut(), sender, firewall_cancelled)
                })
                .expect("firewall worker thread creation failed"),
        );

        Self {
            cancelled,
            handles,
            scan_requested,
        }
    }

    /// Asks the metrics worker to have NetworkManager scan for Wi-Fi networks
    /// on its next pass, about a second at most from now.
    pub fn request_wifi_scan(&self) {
        self.scan_requested.store(true, Ordering::Release);
    }

    pub fn stop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Drop for LiveWorkers {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Why the capture could not be opened. Startup has already checked `cap_net_raw`, so the
/// privilege is not the first suspect; the README leads, because the pane shows only the
/// first 30 characters.
fn capture_open_failed(error: &str) -> String {
    format!("README, Running without sudo: {error}")
}

/// The capture to read packets from. Opening `dumpcap` waits for its stream to begin, so
/// this belongs on the capture thread.
fn open_capture(origin: CaptureOrigin) -> Result<Box<dyn CaptureSource>, String> {
    match origin {
        CaptureOrigin::Own => PcapSource::open_any()
            .map(|source| Box::new(source) as Box<dyn CaptureSource>)
            .map_err(|error| capture_open_failed(&error)),
        CaptureOrigin::Dumpcap => DumpcapSource::new(dumpcap_command())
            .map(|source| Box::new(source) as Box<dyn CaptureSource>),
    }
}

/// The addresses of the interfaces present in an interface reading; nothing when the
/// reading could not be made, so the addresses already in use stay. An interface that
/// has gone keeps its last addresses in the snapshot, but they are no longer ours.
pub fn local_addresses(snapshot: &InterfaceSnapshot) -> Option<HashSet<IpAddr>> {
    (snapshot.health == CollectionHealth::Available).then(|| {
        snapshot
            .interfaces
            .iter()
            .filter(|interface| interface.status == InterfaceStatus::Available)
            .flat_map(|interface| interface.addresses.iter().map(|address| address.ip))
            .collect()
    })
}

fn capture_loop(
    sender: SyncSender<DashboardEvent>,
    cancelled: Arc<AtomicBool>,
    mut log: Option<AttributionLog>,
    limited: bool,
    origin: CaptureOrigin,
) {
    let (traffic_sender, traffic_receiver) = sync_channel(256);
    let mut interface_collector = InterfaceCounterCollector::new(LinuxInterfaceSource::new());
    let initial = interface_collector.sample(Duration::ZERO);
    let addresses = local_addresses(&initial).unwrap_or_default();
    let _ = sender.try_send(DashboardEvent::Interfaces(initial));
    let mut attribution = match AttributionCollector::new(
        LinuxProcfsSource::new("/proc"),
        Duration::from_secs(3),
        65_536,
    ) {
        Ok(collector) => Some(collector),
        Err(error) => {
            let _ = sender.try_send(DashboardEvent::Attribution(
                crate::collect::attribution::AttributionStatus {
                    health: AttributionHealth::Unavailable(error.to_string()),
                    incomplete: true,
                    limited,
                },
            ));
            None
        }
    };
    or_stop(enable_net_raw_if_available());
    let opened = open_capture(origin);
    or_stop(keep_only_sys_ptrace_available());
    let source = match opened {
        Ok(source) => source,
        Err(error) => {
            let _ = sender.try_send(DashboardEvent::CaptureStatus(
                crate::collect::capture::CaptureStatus {
                    health: CaptureHealth::Degraded(error),
                    packets_read: 0,
                    capture_received: 0,
                    capture_dropped: 0,
                    delivery_dropped: 0,
                    origin,
                },
            ));
            return;
        }
    };
    let mut worker = match CaptureWorker::new(source, addresses, 128) {
        Ok(worker) => worker,
        Err(error) => {
            let _ = sender.try_send(DashboardEvent::CaptureStatus(
                crate::collect::capture::CaptureStatus {
                    health: CaptureHealth::Degraded(error),
                    packets_read: 0,
                    capture_received: 0,
                    capture_dropped: 0,
                    delivery_dropped: 0,
                    origin,
                },
            ));
            return;
        }
    };
    let start = Instant::now();
    let mut last_addresses = Duration::ZERO;
    let mut dropped = 0_u64;
    let mut hold = PacketHold::new(HELD_PACKET_LIMIT);
    // TCP ports the latest snapshot shows listening, for the leave-out rule
    // and the log.
    let mut listening_tcp_ports: HashSet<u16> = HashSet::new();
    // Sends a packet to the dashboard, writing it to the log first when it
    // has no owner. False when the dashboard is gone.
    let send = |log: &mut Option<AttributionLog>,
                attribution: Option<&AttributionCollector>,
                listening: &HashSet<u16>,
                at: Duration,
                event: TrafficEvent,
                process: Option<ProcessIdentity>,
                waited: Option<Duration>,
                dropped: &mut u64| {
        let line = match (log.is_some(), &process) {
            (true, None) => unowned_line(attribution, &event, at, listening, waited),
            _ => None,
        };
        match sender.try_send(DashboardEvent::Traffic { at, event, process }) {
            Ok(()) => {
                if let (Some(log), Some(line)) = (log.as_mut(), line) {
                    log.write(&line);
                }
            }
            Err(TrySendError::Full(_)) => *dropped = dropped.saturating_add(1),
            Err(TrySendError::Disconnected(_)) => return false,
        }
        true
    };
    while !cancelled.load(Ordering::Acquire) {
        let now = start.elapsed();
        // Not sent to the dashboard: `metrics_loop` sends its own readings.
        if now.saturating_sub(last_addresses) >= ADDRESSES_EVERY {
            last_addresses = now;
            if let Some(addresses) = local_addresses(&interface_collector.sample(now)) {
                worker.set_local_addresses(addresses);
            }
        }
        if hold.snapshot_due(now) {
            let mut released = Vec::new();
            if let Some(attribution) = attribution.as_mut() {
                let mut status = scan_proc(|| attribution.refresh(now));
                status.limited = limited;
                let available = status.health == AttributionHealth::Available;
                let _ = sender.try_send(DashboardEvent::Attribution(status));
                if let Some(stats) = attribution.snapshot_stats()
                    && let Some(log) = log.as_mut()
                {
                    log.write(&attribution_log::snapshot_line(now, &stats));
                }
                listening_tcp_ports = attribution
                    .listeners()
                    .unwrap_or_default()
                    .iter()
                    .filter(|listener| listener.protocol == Protocol::Tcp)
                    .map(|listener| listener.port)
                    .collect();
                released = if available {
                    hold.release(now, |event| attribution.attribute(event, now).owner)
                } else {
                    hold.release(now, |_| None)
                };
            }
            hold.snapshot_taken(now);
            for released in released {
                if !send(
                    &mut log,
                    attribution.as_ref(),
                    &listening_tcp_ports,
                    released.at,
                    released.event,
                    released.process,
                    released.waited,
                    &mut dropped,
                ) {
                    return;
                }
            }
        }
        let status = worker.poll(&traffic_sender, &cancelled);
        while let Ok(event) = traffic_receiver.try_recv() {
            let (event, process) = match attribution.as_ref() {
                Some(attribution) => {
                    let result = attribution.attribute(&event, now);
                    let left_out = left_out_of_app_traffic(&event, false, |port| {
                        listening_tcp_ports.contains(&port)
                    });
                    match hold.admit(event, &result, left_out) {
                        Some(event) => (event, result.owner),
                        None => continue,
                    }
                }
                None => (event, None),
            };
            if !send(
                &mut log,
                attribution.as_ref(),
                &listening_tcp_ports,
                now,
                event,
                process,
                Some(Duration::ZERO),
                &mut dropped,
            ) {
                return;
            }
        }
        let mut status = status;
        status.delivery_dropped = status.delivery_dropped.saturating_add(dropped);
        let _ = sender.try_send(DashboardEvent::CaptureStatus(status));
        thread::sleep(Duration::from_millis(10));
    }
}

/// The log line for an unowned packet that App Traffic will list. The
/// leave-out rule is `AppState`'s own, but the listening ports come from this
/// loop's snapshot rather than the dashboard's list, which can be up to two
/// seconds different. Packets beyond the table's capacity are not known here.
fn unowned_line(
    attribution: Option<&AttributionCollector>,
    event: &TrafficEvent,
    now: Duration,
    listening_tcp_ports: &HashSet<u16>,
    waited: Option<Duration>,
) -> Option<String> {
    if left_out_of_app_traffic(event, false, |port| listening_tcp_ports.contains(&port)) {
        return None;
    }
    let reason = match attribution {
        Some(attribution) => attribution.explain(event, now)?,
        None => NoOwner {
            cause: NoOwnerCause::Unavailable("attribution collector could not start".to_owned()),
            memory: OwnerMemory::Never,
        },
    };
    Some(attribution_log::packet_line(now, event, &reason, waited))
}

/// Passes after an accepted scan on which the Wi-Fi list is read at once.
const WIFI_READS_AFTER_SCAN: u8 = 5;

fn metrics_loop(
    sender: SyncSender<DashboardEvent>,
    cancelled: Arc<AtomicBool>,
    scan_requested: Arc<AtomicBool>,
    limited: bool,
) {
    or_stop(keep_only_sys_ptrace_available());
    let mut collector = InterfaceCounterCollector::new(LinuxInterfaceSource::new());
    let start = Instant::now();
    let mut attribution = AttributionCollector::new(
        LinuxProcfsSource::new("/proc"),
        Duration::from_secs(3),
        65_536,
    )
    .ok();
    let mut last_listeners: Option<Duration> = None;
    let mut pending_listeners: Option<DashboardEvent> = None;
    let mut neighbors = NeighborCollector::new(IpCommand::new(Arc::clone(&cancelled)));
    let mut last_neighbors: Option<Duration> = None;
    let mut pending_neighbors: Option<DashboardEvent> = None;
    let mut wifi = WifiCollector::new(NmcliCommand::new(Arc::clone(&cancelled)));
    let mut last_wifi: Option<Duration> = None;
    let mut pending_wifi: Option<DashboardEvent> = None;
    let mut pending_scan: Option<DashboardEvent> = None;
    let mut fast_reads = 0_u8;
    while !cancelled.load(Ordering::Acquire) {
        let now = start.elapsed();
        let _ = sender.try_send(DashboardEvent::Interfaces(collector.sample(now)));
        if let Some(collector) = attribution.as_mut() {
            let mut status = scan_proc(|| collector.refresh(now));
            status.limited = limited;
            let _ = sender.try_send(DashboardEvent::Attribution(status));
            if pending_listeners.is_none()
                && last_listeners.is_none_or(|last| now.saturating_sub(last) >= LISTENERS_EVERY)
                && let Some(listeners) = collector.listeners()
            {
                last_listeners = Some(now);
                pending_listeners = Some(DashboardEvent::Listeners {
                    listeners,
                    ephemeral: ephemeral_port_range(),
                });
            }
        }
        if pending_neighbors.is_none()
            && last_neighbors.is_none_or(|last| now.saturating_sub(last) >= LISTENERS_EVERY)
        {
            last_neighbors = Some(now);
            pending_neighbors = Some(DashboardEvent::Neighbors(neighbors.collect()));
        }
        if pending_wifi.is_none()
            && (fast_reads > 0
                || last_wifi.is_none_or(|last| now.saturating_sub(last) >= WIFI_EVERY))
        {
            last_wifi = Some(now);
            fast_reads = fast_reads.saturating_sub(1);
            pending_wifi = Some(DashboardEvent::Wifi(wifi.collect()));
        }
        // The only place Crosswalk asks for a scan; it runs under the same
        // time limit and stop flag as the other `nmcli` calls.
        if pending_scan.is_none() && scan_requested.swap(false, Ordering::AcqRel) {
            let outcome = wifi.request_scan();
            if outcome == ScanOutcome::Accepted {
                fast_reads = WIFI_READS_AFTER_SCAN;
            }
            pending_scan = Some(DashboardEvent::WifiScan(outcome));
        }
        send_pending(&sender, &mut pending_scan);
        send_pending(&sender, &mut pending_listeners);
        send_pending(&sender, &mut pending_neighbors);
        send_pending(&sender, &mut pending_wifi);
        sleep_cancelled(Duration::from_secs(1), &cancelled);
    }
}

/// Sends a held event; a full queue keeps it for the next loop pass.
fn send_pending(sender: &SyncSender<DashboardEvent>, pending: &mut Option<DashboardEvent>) {
    if let Some(event) = pending.take()
        && let Err(TrySendError::Full(event)) = sender.try_send(event)
    {
        *pending = Some(event);
    }
}

fn firewall_loop(
    provider: &mut dyn FirewallProvider,
    sender: SyncSender<DashboardEvent>,
    cancelled: Arc<AtomicBool>,
) {
    let (event_sender, event_receiver) = sync_channel(256);
    let start = Instant::now();
    let mut dropped = 0_u64;
    let mut last_rules: Option<Instant> = None;
    let mut pending_rules: Option<DashboardEvent> = None;
    loop {
        if pending_rules.is_none() && last_rules.is_none_or(|last| last.elapsed() >= RULES_EVERY) {
            last_rules = Some(Instant::now());
            pending_rules = Some(DashboardEvent::FirewallRules(provider.rules()));
        }
        send_pending(&sender, &mut pending_rules);
        if cancelled.load(Ordering::Acquire) {
            let status = provider.poll(&event_sender, &cancelled);
            let _ = sender.try_send(DashboardEvent::FirewallStatus(status));
            break;
        }
        let status = provider.poll(&event_sender, &cancelled);
        while let Ok(event) = event_receiver.try_recv() {
            if sender
                .try_send(DashboardEvent::Firewall {
                    at: start.elapsed(),
                    event,
                })
                .is_err()
            {
                dropped = dropped.saturating_add(1);
            }
        }
        let mut status = status;
        status.delivery_dropped = status.delivery_dropped.saturating_add(dropped);
        let _ = sender.try_send(DashboardEvent::FirewallStatus(status));
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        sleep_cancelled(Duration::from_millis(50), &cancelled);
    }
}

pub struct TerminalSession;

impl TerminalSession {
    pub fn enter() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(std::io::stdout(), EnterAlternateScreen, cursor::Hide) {
            let _ = terminal::disable_raw_mode();
            return Err(error);
        }
        Ok(Self)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let _ = execute!(std::io::stdout(), LeaveAlternateScreen, cursor::Show);
    let _ = terminal::disable_raw_mode();
}

/// Stops Crosswalk from a worker thread, which cannot return the error to `main`:
/// leaves the terminal as it was, says what failed and exits with status 1.
fn stop_for_privilege_failure(error: PrivilegeError) -> ! {
    restore_terminal();
    eprintln!("crosswalk: {error}");
    std::process::exit(1);
}

pub(crate) fn or_stop(result: Result<(), PrivilegeError>) {
    if let Err(error) = result {
        stop_for_privilege_failure(error);
    }
}

/// Runs a scan of `/proc` with `cap_sys_ptrace` in effect for its length only.
fn scan_proc<T>(scan: impl FnOnce() -> T) -> T {
    with_sys_ptrace(scan).unwrap_or_else(|error| stop_for_privilege_failure(error))
}

fn sleep_cancelled(duration: Duration, cancelled: &AtomicBool) {
    let mut remaining = duration;
    while !remaining.is_zero() && !cancelled.load(Ordering::Acquire) {
        let slice = remaining.min(Duration::from_millis(20));
        thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
    }
}

pub fn event_channel() -> (SyncSender<DashboardEvent>, EventPump) {
    let (sender, receiver) = sync_channel(EVENT_CAPACITY);
    (sender, EventPump::new(receiver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{FirewallEvent, FirewallHealth, FirewallStatus, RuleSnapshot};
    use std::sync::mpsc::{RecvTimeoutError, sync_channel};

    #[test]
    fn a_capture_that_cannot_open_points_to_the_readme_within_the_pane_width() {
        let reason = capture_open_failed("could not open libpcap 'any' device: busy");
        assert!(
            reason
                .chars()
                .take(30)
                .collect::<String>()
                .contains("Running without sudo")
        );
        assert!(!reason.contains("packet-capture privileges"));
    }

    struct QuietProvider;

    impl FirewallProvider for QuietProvider {
        fn poll(
            &mut self,
            _sender: &SyncSender<FirewallEvent>,
            _cancelled: &AtomicBool,
        ) -> FirewallStatus {
            self.status()
        }

        fn rules(&mut self) -> RuleSnapshot {
            RuleSnapshot::Inactive
        }

        fn status(&self) -> FirewallStatus {
            FirewallStatus {
                health: FirewallHealth::Available,
                records_read: 0,
                events_emitted: 0,
                malformed_records: 0,
                delivery_dropped: 0,
            }
        }
    }

    #[test]
    fn rules_dropped_by_a_full_queue_are_sent_on_a_later_pass() {
        let (sender, receiver) = sync_channel(1);
        sender
            .send(DashboardEvent::FirewallStatus(QuietProvider.status()))
            .unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let worker = thread::spawn(move || {
            firewall_loop(&mut QuietProvider, sender, worker_cancelled);
        });
        thread::sleep(Duration::from_millis(200));
        let mut seen_rules = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !seen_rules && Instant::now() < deadline {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(DashboardEvent::FirewallRules(_)) => seen_rules = true,
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        cancelled.store(true, Ordering::Release);
        drop(receiver);
        worker.join().unwrap();
        assert!(seen_rules, "rules were not retried after the queue freed");
    }
}

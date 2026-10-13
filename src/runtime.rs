use crossterm::{
    cursor, execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    collections::HashSet,
    net::IpAddr,
    ops::RangeInclusive,
    path::PathBuf,
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
    capture_source::own_user_name,
    collect::{
        attribution::{
            AttributionCollector, AttributionHealth, AttributionResult, LinuxProcfsSource,
            Listener, NoOwner, NoOwnerCause, OwnerMemory, ProcessIdentity,
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
    privileges::{PrivilegeError, enable_net_raw_if_available, give_up_everything, is_root},
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
        origin: CaptureOrigin,
    ) -> Self {
        let only_user = (!is_root()).then(own_user_name);
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
                        only_user,
                        origin,
                        open_capture,
                        "/proc".into(),
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
                    let mut provider =
                        firewall::create_provider(&config, firewall_cancelled.clone());
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

fn degraded_capture_status(
    error: String,
    origin: CaptureOrigin,
) -> crate::collect::capture::CaptureStatus {
    crate::collect::capture::CaptureStatus {
        health: CaptureHealth::Degraded(error),
        dropped: 0,
        origin,
    }
}

fn capture_loop(
    sender: SyncSender<DashboardEvent>,
    cancelled: Arc<AtomicBool>,
    mut log: Option<AttributionLog>,
    only_user: Option<String>,
    origin: CaptureOrigin,
    open: impl FnOnce(CaptureOrigin) -> Result<Box<dyn CaptureSource>, String>,
    scan_root: PathBuf,
) {
    let (traffic_sender, traffic_receiver) = sync_channel(256);
    let mut interface_collector = InterfaceCounterCollector::new(LinuxInterfaceSource::new());
    let initial = interface_collector.sample(Duration::ZERO);
    let addresses = local_addresses(&initial).unwrap_or_default();
    let _ = sender.try_send(DashboardEvent::Interfaces(initial));
    let mut attribution = match AttributionCollector::new(
        LinuxProcfsSource::new(scan_root),
        Duration::from_secs(3),
        65_536,
    ) {
        Ok(collector) => Some(collector),
        Err(error) => {
            let _ = sender.try_send(DashboardEvent::Attribution(
                crate::collect::attribution::AttributionStatus {
                    health: AttributionHealth::Unavailable(error.to_string()),
                    only_user: only_user.clone(),
                },
            ));
            None
        }
    };
    or_stop(enable_net_raw_if_available());
    let opened = open(origin);
    or_stop(give_up_everything());
    // With no worker the loop goes on scanning and there are simply no packets. The one
    // degraded status stays pending until the queue takes it; nothing replaces it.
    let mut pending_status = None;
    let mut worker = match opened.and_then(|source| CaptureWorker::new(source, addresses, 128)) {
        Ok(worker) => Some(worker),
        Err(error) => {
            pending_status = Some(DashboardEvent::CaptureStatus(degraded_capture_status(
                error, origin,
            )));
            None
        }
    };
    let start = Instant::now();
    let mut last_addresses = Duration::ZERO;
    let mut dropped = 0_u64;
    let mut hold = PacketHold::new(HELD_PACKET_LIMIT);
    let mut listeners_queue = ListenersQueue::default();
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
            if let Some(worker) = worker.as_mut()
                && let Some(addresses) = local_addresses(&interface_collector.sample(now))
            {
                worker.set_local_addresses(addresses);
            }
        }
        if hold.snapshot_due(now) {
            let mut released = Vec::new();
            if let Some(attribution) = attribution.as_mut() {
                let mut status = attribution.refresh(now);
                status.only_user = only_user.clone();
                let available = status.health == AttributionHealth::Available;
                let _ = sender.try_send(DashboardEvent::Attribution(status));
                if let Some(stats) = attribution.snapshot_stats()
                    && let Some(log) = log.as_mut()
                {
                    log.write(&attribution_log::snapshot_line(now, &stats));
                }
                let listeners = attribution.listeners();
                listening_tcp_ports = listeners
                    .iter()
                    .flatten()
                    .filter(|listener| listener.protocol == Protocol::Tcp)
                    .map(|listener| listener.port)
                    .collect();
                listeners_queue.build_if_due(now, listeners);
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
        if !send_pending(&sender, &mut listeners_queue.pending)
            || !send_pending(&sender, &mut pending_status)
        {
            return;
        }
        let status = worker
            .as_mut()
            .map(|worker| worker.poll(&traffic_sender, &cancelled));
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
        if let Some(mut status) = status {
            status.dropped = status.dropped.saturating_add(dropped);
            // The loop's own drops stay owed until a status carrying them is taken.
            if sender
                .try_send(DashboardEvent::CaptureStatus(status))
                .is_ok()
            {
                dropped = 0;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// The listeners event on its way to the dashboard: built when `LISTENERS_EVERY` has
/// passed since the last build and none is still waiting, kept until the queue takes it.
#[derive(Default)]
struct ListenersQueue {
    last_built: Option<Duration>,
    pending: Option<DashboardEvent>,
}

impl ListenersQueue {
    /// `listeners` is the scan's reading, absent until a scan has succeeded.
    fn build_if_due(&mut self, now: Duration, listeners: Option<Vec<Listener>>) {
        let due = self
            .last_built
            .is_none_or(|last| now.saturating_sub(last) >= LISTENERS_EVERY);
        if let (true, true, Some(listeners)) = (self.pending.is_none(), due, listeners) {
            self.last_built = Some(now);
            self.pending = Some(DashboardEvent::Listeners {
                listeners,
                ephemeral: ephemeral_port_range(),
            });
        }
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
) {
    or_stop(give_up_everything());
    let mut collector = InterfaceCounterCollector::new(LinuxInterfaceSource::new());
    let start = Instant::now();
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
        send_pending(&sender, &mut pending_neighbors);
        send_pending(&sender, &mut pending_wifi);
        sleep_cancelled(Duration::from_secs(1), &cancelled);
    }
}

/// Sends a held event; a full queue keeps it for the next loop pass. False when the
/// dashboard is gone.
fn send_pending(sender: &SyncSender<DashboardEvent>, pending: &mut Option<DashboardEvent>) -> bool {
    let Some(event) = pending.take() else {
        return true;
    };
    match sender.try_send(event) {
        Err(TrySendError::Full(event)) => {
            *pending = Some(event);
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
        Ok(()) => true,
    }
}

fn firewall_loop(
    provider: &mut dyn FirewallProvider,
    sender: SyncSender<DashboardEvent>,
    cancelled: Arc<AtomicBool>,
) {
    let (event_sender, event_receiver) = sync_channel(256);
    let start = Instant::now();
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
            let _ = sender.try_send(DashboardEvent::Firewall {
                at: start.elapsed(),
                event,
            });
        }
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
    let _ = execute!(
        std::io::stdout(),
        LeaveAlternateScreen,
        cursor::Show,
        terminal::SetTitle("")
    );
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
                name: "ufw",
                health: FirewallHealth::Available,
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

    struct IdleCapture;

    impl CaptureSource for IdleCapture {
        fn link_type(&self) -> i32 {
            276
        }

        fn next_packet(&mut self) -> Result<crate::collect::capture::PacketRead, String> {
            Ok(crate::collect::capture::PacketRead::Idle)
        }

        fn statistics(&mut self) -> Result<crate::collect::capture::CaptureStatistics, String> {
            Ok(crate::collect::capture::CaptureStatistics::default())
        }
    }

    /// A capture that hands over a few packets and then fails, as a stopped `dumpcap` does.
    struct FailingCapture {
        packets_left: u32,
    }

    impl CaptureSource for FailingCapture {
        fn link_type(&self) -> i32 {
            276
        }

        fn next_packet(&mut self) -> Result<crate::collect::capture::PacketRead, String> {
            if self.packets_left == 0 {
                return Err("capture stream ended".to_owned());
            }
            self.packets_left -= 1;
            Ok(crate::collect::capture::PacketRead::Packet {
                data: vec![0; 8],
                captured_at: None,
            })
        }

        fn statistics(&mut self) -> Result<crate::collect::capture::CaptureStatistics, String> {
            Ok(crate::collect::capture::CaptureStatistics::default())
        }
    }

    type Opener = Box<dyn FnOnce(CaptureOrigin) -> Result<Box<dyn CaptureSource>, String> + Send>;

    fn opening(source: impl CaptureSource + Send + 'static) -> Opener {
        Box::new(|_| Ok(Box::new(source) as Box<dyn CaptureSource>))
    }

    /// A directory laid out like `/proc` with one TCP socket listening on port 8080.
    struct ScanRoot(PathBuf);

    impl ScanRoot {
        fn with_a_listener(name: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("crosswalk-runtime-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("self/ns")).unwrap();
            std::os::unix::fs::symlink("net:[7]", root.join("self/ns/net")).unwrap();
            std::fs::create_dir_all(root.join("net")).unwrap();
            for table in ["tcp", "tcp6", "udp", "udp6"] {
                std::fs::write(root.join("net").join(table), "header\n").unwrap();
            }
            std::fs::write(
                root.join("net/tcp"),
                "header\n0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 201",
            )
            .unwrap();
            Self(root)
        }
    }

    impl Drop for ScanRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The real capture loop on a thread, with an idle capture and a scan root
    /// holding one listener, sending into a queue of the given size.
    struct RunningCapture {
        receiver: Receiver<DashboardEvent>,
        cancelled: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
        started: Instant,
        _root: ScanRoot,
    }

    impl RunningCapture {
        fn start(name: &str, queue: usize) -> Self {
            let root = ScanRoot::with_a_listener(name);
            let (sender, receiver) = sync_channel(queue);
            Self::start_with(root, sender, receiver)
        }

        fn start_with(
            root: ScanRoot,
            sender: SyncSender<DashboardEvent>,
            receiver: Receiver<DashboardEvent>,
        ) -> Self {
            Self::start_opening(root, sender, receiver, opening(IdleCapture))
        }

        fn start_opening(
            root: ScanRoot,
            sender: SyncSender<DashboardEvent>,
            receiver: Receiver<DashboardEvent>,
            open: Opener,
        ) -> Self {
            let cancelled = Arc::new(AtomicBool::new(false));
            let worker_cancelled = cancelled.clone();
            let scan_root = root.0.clone();
            let started = Instant::now();
            let worker = thread::spawn(move || {
                capture_loop(
                    sender,
                    worker_cancelled,
                    None,
                    None,
                    CaptureOrigin::Own,
                    open,
                    scan_root,
                );
            });
            Self {
                receiver,
                cancelled,
                worker: Some(worker),
                started,
                _root: root,
            }
        }

        fn start_opening_in_a_queue_of(name: &str, queue: usize, open: Opener) -> Self {
            let (sender, receiver) = sync_channel(queue);
            Self::start_opening(ScanRoot::with_a_listener(name), sender, receiver, open)
        }

        /// Every event that arrives before `until` after the start.
        fn events_by(&self, until: Duration) -> Vec<DashboardEvent> {
            let mut events = Vec::new();
            while let Some(left) = until.checked_sub(self.started.elapsed()) {
                if let Ok(event) = self.receiver.recv_timeout(left) {
                    events.push(event);
                }
            }
            events
        }

        /// The dashboard goes away: the receiver is dropped.
        fn close_the_dashboard(&mut self) {
            self.receiver = sync_channel(1).1;
        }

        /// Whether the loop returns within `limit`.
        fn ends_within(&self, limit: Duration) -> bool {
            let until = Instant::now() + limit;
            let worker = self.worker.as_ref().unwrap();
            while !worker.is_finished() && Instant::now() < until {
                thread::sleep(Duration::from_millis(10));
            }
            worker.is_finished()
        }

        /// The next listeners event that arrives before `until` after the start.
        fn listeners_by(&self, until: Duration) -> Option<(Duration, DashboardEvent)> {
            loop {
                let left = until.checked_sub(self.started.elapsed())?;
                match self.receiver.recv_timeout(left) {
                    Ok(event @ DashboardEvent::Listeners { .. }) => {
                        return Some((self.started.elapsed(), event));
                    }
                    Ok(_) => {}
                    Err(_) => return None,
                }
            }
        }
    }

    impl Drop for RunningCapture {
        fn drop(&mut self) {
            self.cancelled.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                // Keep the queue draining so a send never blocks the join.
                while !worker.is_finished() {
                    let _ = self.receiver.try_recv();
                    thread::sleep(Duration::from_millis(5));
                }
                worker.join().unwrap();
            }
        }
    }

    #[test]
    fn the_capture_thread_publishes_the_listening_ports_at_once() {
        let capture = RunningCapture::start("first", 1024);
        let (_, event) = capture
            .listeners_by(Duration::from_secs(1))
            .expect("no listeners event within a second");
        let DashboardEvent::Listeners {
            listeners,
            ephemeral,
        } = event
        else {
            unreachable!()
        };
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].port, 8080);
        assert_eq!(listeners[0].protocol, Protocol::Tcp);
        assert!(ephemeral.start() <= ephemeral.end());
    }

    #[test]
    fn the_listening_ports_come_again_no_sooner_than_every_two_seconds() {
        let capture = RunningCapture::start("again", 1024);
        let (first, _) = capture
            .listeners_by(Duration::from_secs(1))
            .expect("no first listeners event");
        let (second, _) = capture
            .listeners_by(Duration::from_secs(6))
            .expect("no second listeners event");
        let between = second - first;
        assert!(
            between >= LISTENERS_EVERY,
            "second listeners event only {between:?} after the first"
        );
    }

    #[test]
    fn listening_ports_dropped_by_a_full_queue_are_sent_once_there_is_room() {
        let root = ScanRoot::with_a_listener("full");
        let (sender, receiver) = sync_channel(1);
        sender
            .send(DashboardEvent::WifiScan(ScanOutcome::Accepted))
            .unwrap();
        let capture = RunningCapture::start_with(root, sender, receiver);
        // The first listeners event is built and refused at once; the next
        // would not be built until two seconds in.
        thread::sleep(Duration::from_millis(500));
        assert!(
            capture.listeners_by(Duration::from_millis(1500)).is_some(),
            "the held listeners event was not sent once the queue had room"
        );
    }

    /// What a loop with no working capture sends in `until`: the degraded capture
    /// status once, and the scan's app status and listening ports as they fall due.
    fn assert_scanning_goes_on(name: &str, open: Opener) {
        let capture = RunningCapture::start_opening_in_a_queue_of(name, 1024, open);
        let events = capture.events_by(Duration::from_millis(3500));
        let statuses: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                DashboardEvent::CaptureStatus(status) => Some(status),
                _ => None,
            })
            .collect();
        assert_eq!(statuses.len(), 1, "capture statuses sent");
        assert!(matches!(statuses[0].health, CaptureHealth::Degraded(_)));
        let count =
            |wanted: fn(&DashboardEvent) -> bool| events.iter().filter(|e| wanted(e)).count();
        let app_statuses = count(|event| matches!(event, DashboardEvent::Attribution(_)));
        let listeners = count(|event| matches!(event, DashboardEvent::Listeners { .. }));
        assert!(app_statuses >= 3, "app statuses in 3.5 s: {app_statuses}");
        assert!(listeners >= 2, "listeners events in 3.5 s: {listeners}");
    }

    #[test]
    fn scanning_goes_on_when_the_capture_cannot_be_opened() {
        assert_scanning_goes_on("unopened", Box::new(|_| Err("no dumpcap".to_owned())));
    }

    #[test]
    fn scanning_goes_on_when_the_worker_refuses_the_link_type() {
        struct OtherLink;
        impl CaptureSource for OtherLink {
            fn link_type(&self) -> i32 {
                1
            }

            fn next_packet(&mut self) -> Result<crate::collect::capture::PacketRead, String> {
                Ok(crate::collect::capture::PacketRead::Idle)
            }

            fn statistics(&mut self) -> Result<crate::collect::capture::CaptureStatistics, String> {
                Ok(crate::collect::capture::CaptureStatistics::default())
            }
        }
        assert_scanning_goes_on("refused", opening(OtherLink));
    }

    #[test]
    fn listening_ports_keep_coming_after_the_capture_fails_midway() {
        let capture = RunningCapture::start_opening_in_a_queue_of(
            "midway",
            1024,
            opening(FailingCapture { packets_left: 3 }),
        );
        let listeners = capture
            .events_by(Duration::from_millis(3500))
            .iter()
            .filter(|event| matches!(event, DashboardEvent::Listeners { .. }))
            .count();
        assert!(listeners >= 2, "listeners events in 3.5 s: {listeners}");
    }

    /// `packets` loopback UDP packets, then nothing more to read.
    struct LoopbackPackets {
        packets: usize,
    }

    impl CaptureSource for LoopbackPackets {
        fn link_type(&self) -> i32 {
            276
        }

        fn next_packet(&mut self) -> Result<crate::collect::capture::PacketRead, String> {
            use crate::collect::capture::PacketRead;
            if self.packets == 0 {
                return Ok(PacketRead::Idle);
            }
            self.packets -= 1;
            let mut data = vec![0_u8; 20 + 20 + 8];
            data[0..2].copy_from_slice(&0x0800_u16.to_be_bytes());
            data[10] = 4;
            let ip = &mut data[20..];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&28_u16.to_be_bytes());
            ip[8] = 64;
            ip[9] = 17;
            ip[12..16].copy_from_slice(&[127, 0, 0, 1]);
            ip[16..20].copy_from_slice(&[127, 0, 0, 1]);
            ip[20..22].copy_from_slice(&5000_u16.to_be_bytes());
            ip[22..24].copy_from_slice(&5001_u16.to_be_bytes());
            Ok(PacketRead::Packet {
                data,
                captured_at: None,
            })
        }

        fn statistics(&mut self) -> Result<crate::collect::capture::CaptureStatistics, String> {
            Ok(crate::collect::capture::CaptureStatistics::default())
        }
    }

    #[test]
    fn traffic_dropped_on_a_full_dashboard_queue_is_reported_once_the_queue_has_room() {
        let packets = 5;
        let (sender, receiver) = sync_channel(1);
        let capture = RunningCapture::start_opening(
            ScanRoot::with_a_listener("dashboard-full"),
            sender,
            receiver,
            opening(LoopbackPackets { packets }),
        );
        thread::sleep(Duration::from_millis(1500));
        let reported: u64 = capture
            .events_by(Duration::from_millis(2500))
            .iter()
            .filter_map(|event| match event {
                DashboardEvent::CaptureStatus(status) => Some(status.dropped),
                _ => None,
            })
            .sum();
        assert_eq!(reported, packets as u64);
    }

    #[test]
    fn the_loop_ends_when_the_dashboard_is_gone_with_or_without_a_capture() {
        let failing: Opener = Box::new(|_| Err("no dumpcap".to_owned()));
        for open in [failing, opening(IdleCapture)] {
            let mut capture = RunningCapture::start_opening_in_a_queue_of("gone", 1024, open);
            capture.close_the_dashboard();
            assert!(
                capture.ends_within(Duration::from_secs(3)),
                "the loop kept running with no dashboard"
            );
        }
    }
}

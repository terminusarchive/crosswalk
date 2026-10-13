use std::{path::PathBuf, time::Duration};

mod common;
use common::listener;

use crosswalk::{
    collect::{
        attribution::{
            AttributionHealth, AttributionStatus, ExecutableIdentity, Listener, ProcessIdentity,
        },
        capture::{
            CaptureHealth, CaptureOrigin, CaptureStatus, Direction, Endpoint, Protocol, TcpFlags,
            TrafficEvent,
        },
        interfaces::{CollectionHealth, InterfaceMeasurement, InterfaceSnapshot, InterfaceStatus},
    },
    firewall::{
        Exposure, FirewallEndpoint, FirewallEvent, FirewallHealth, FirewallStatus, Policy, Rule,
        RuleAction, RuleDirection, RuleSnapshot, RuleSource,
    },
    state::{AppState, BlockKind, ByteTotals, StateLimits},
};

fn process(path: &str, pid: u32) -> ProcessIdentity {
    ProcessIdentity {
        executable: ExecutableIdentity {
            path: PathBuf::from(path),
        },
        pid,
        start_time: u64::from(pid),
        network_namespace: 7,
    }
}

fn traffic(
    direction: Direction,
    protocol: Protocol,
    source: (&str, u16),
    destination: (&str, u16),
    bytes: u32,
) -> TrafficEvent {
    TrafficEvent {
        source: Endpoint {
            ip: source.0.parse().unwrap(),
            port: Some(source.1),
        },
        destination: Endpoint {
            ip: destination.0.parse().unwrap(),
            port: Some(destination.1),
        },
        protocol,
        direction,
        original_ip_bytes: bytes,
        limitation: None,
        tcp_flags: None,
        timing: None,
    }
}

fn snapshot(name: &str, download: f64, upload: f64) -> InterfaceSnapshot {
    InterfaceSnapshot {
        health: CollectionHealth::Available,
        interfaces: vec![InterfaceMeasurement {
            name: name.to_owned(),
            addresses: Vec::new(),
            download_bytes_per_second: download,
            upload_bytes_per_second: upload,
            session_received_bytes: 5_000,
            session_transmitted_bytes: 700,
            status: InterfaceStatus::Available,
            is_up: true,
        }],
        default_route: Some(name.to_owned()),
        gateway: None,
        name_server: None,
        name_servers: vec![],
    }
}

fn out(local_port: u16, remote: &str, remote_port: u16, bytes: u32) -> TrafficEvent {
    traffic(
        Direction::Outbound,
        Protocol::Tcp,
        ("192.0.2.10", local_port),
        (remote, remote_port),
        bytes,
    )
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn destinations(state: &AppState) -> Vec<Vec<String>> {
    state
        .app_traffic()
        .iter()
        .map(|app| {
            app.destinations
                .iter()
                .map(|d| format!("{}:{}", d.remote.ip, d.remote.port.unwrap()))
                .collect()
        })
        .collect()
}

#[test]
fn rate_history_keeps_the_newest_300_samples_per_interface_one_per_second() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    for second in 0..305u64 {
        state.advance_time(secs(second));
        state.record_interfaces(snapshot("eth0", second as f64, 1.0));
    }
    // A second snapshot in the same second replaces the sample.
    state.record_interfaces(snapshot("eth0", 999.0, 2.0));
    let history = state.rate_history("eth0");
    assert_eq!(history.len(), 300);
    assert_eq!(history[0].at, secs(5));
    assert_eq!(history[299].at, secs(304));
    assert_eq!(history[299].download, 999.0);
    assert_eq!(history[299].upload, 2.0);
    assert!(state.rate_history("wlan0").is_empty());

    let interfaces = state.interfaces();
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].name, "eth0");
    assert_eq!(interfaces[0].download, 999.0);
    assert_eq!(interfaces[0].session.download, 5_000);
    assert_eq!(state.default_route(), Some("eth0"));
}

#[test]
fn rate_history_of_an_interface_that_is_gone_is_dropped() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.advance_time(secs(1));
    state.record_interfaces(snapshot("veth1", 1.0, 1.0));
    assert_eq!(state.rate_history("veth1").len(), 1);
    state.advance_time(secs(2));
    state.record_interfaces(snapshot("eth0", 1.0, 1.0));
    assert!(state.rate_history("veth1").is_empty());
    assert_eq!(state.rate_history("eth0").len(), 1);
}

#[test]
fn each_sources_health_is_stored_independently_of_the_others() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let none = |state: &AppState| {
        let health = state.source_health();
        [
            health.interfaces.is_some(),
            health.attribution.is_some(),
            health.capture.is_some(),
            health.firewall.is_some(),
        ]
    };
    assert_eq!(none(&state), [false; 4]);

    state.record_capture_status(CaptureStatus {
        health: CaptureHealth::Degraded("no permission".to_owned()),
        dropped: 0,
        origin: CaptureOrigin::Own,
    });
    assert_eq!(none(&state), [false, false, true, false]);

    state.record_firewall_status(FirewallStatus {
        name: "ufw",
        health: FirewallHealth::Unavailable("unreadable".to_owned()),
    });
    state.record_attribution_status(AttributionStatus {
        health: AttributionHealth::Stale("old".to_owned()),
        only_user: None,
    });
    let mut snapshot = snapshot("eth0", 1.0, 1.0);
    snapshot.health = CollectionHealth::Unavailable("no counters".to_owned());
    state.record_interfaces(snapshot);
    assert_eq!(none(&state), [true; 4]);

    let health = state.source_health();
    assert_eq!(
        health.capture.as_ref().unwrap().health,
        CaptureHealth::Degraded("no permission".to_owned())
    );
    assert_eq!(
        health.firewall.as_ref().unwrap().health,
        FirewallHealth::Unavailable("unreadable".to_owned())
    );
    assert_eq!(
        health.attribution.as_ref().unwrap().health,
        AttributionHealth::Stale("old".to_owned())
    );
    assert_eq!(
        health.interfaces,
        Some(CollectionHealth::Unavailable("no counters".to_owned()))
    );

    // A later report from one source leaves the other three as they were.
    state.record_capture_status(CaptureStatus {
        health: CaptureHealth::Available,
        dropped: 0,
        origin: CaptureOrigin::Own,
    });
    let health = state.source_health();
    assert_eq!(
        health.capture.as_ref().unwrap().health,
        CaptureHealth::Available
    );
    assert_eq!(
        health.firewall.as_ref().unwrap().health,
        FirewallHealth::Unavailable("unreadable".to_owned())
    );
    assert_eq!(
        health.interfaces,
        Some(CollectionHealth::Unavailable("no counters".to_owned()))
    );
}

#[test]
fn apps_and_destinations_keep_first_seen_order_when_a_later_one_gets_busier() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let a = process("/opt/a", 1);
    let b = process("/opt/b", 2);
    state.record_traffic(secs(1), out(5000, "198.51.100.1", 443, 10), Some(a.clone()));
    state.record_traffic(secs(1), out(5001, "198.51.100.2", 443, 10), Some(a.clone()));
    state.record_traffic(secs(1), out(5002, "198.51.100.3", 443, 10), Some(b.clone()));
    state.record_traffic(secs(2), out(5003, "198.51.100.2", 443, 9_000), Some(b));
    state.record_traffic(secs(2), out(5004, "198.51.100.2", 443, 9_000), Some(a));
    assert_eq!(
        destinations(&state),
        vec![
            vec!["198.51.100.1:443", "198.51.100.2:443"],
            vec!["198.51.100.3:443", "198.51.100.2:443"],
        ]
    );
}

#[test]
fn upload_and_download_both_count_against_the_remote_endpoint() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let a = process("/opt/a", 1);
    state.record_traffic(
        secs(3),
        out(5000, "198.51.100.1", 443, 100),
        Some(a.clone()),
    );
    state.record_traffic(
        secs(3),
        traffic(
            Direction::Inbound,
            Protocol::Tcp,
            ("198.51.100.1", 443),
            ("192.0.2.10", 5000),
            400,
        ),
        Some(process("/opt/a", 7)),
    );
    let apps = state.app_traffic();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].destinations.len(), 1);
    let d = &apps[0].destinations[0];
    assert_eq!(d.remote.ip.to_string(), "198.51.100.1");
    assert_eq!(
        d.bytes,
        ByteTotals {
            upload: 100,
            download: 400
        }
    );
    assert_eq!(d.rate.upload, 100.0);
    assert_eq!(d.rate.download, 400.0);
    assert_eq!(d.pids, vec![1, 7]);
    assert!(!d.idle);
}

#[test]
fn packets_on_a_listening_local_port_are_left_out() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_listeners(
        vec![Listener {
            protocol: Protocol::Tcp,
            address: "0.0.0.0".parse().unwrap(),
            port: 8080,
            owners: Vec::new(),
        }],
        EPHEMERAL,
    );
    let server = process("/opt/server", 3);
    // Reply to an inbound connection: local port 8080 is listening.
    state.record_traffic(
        secs(1),
        out(8080, "198.51.100.9", 40_000, 500),
        Some(server.clone()),
    );
    // Same port number over UDP is not the listener.
    state.record_traffic(
        secs(1),
        traffic(
            Direction::Outbound,
            Protocol::Udp,
            ("192.0.2.10", 8080),
            ("198.51.100.9", 53),
            20,
        ),
        Some(server),
    );
    assert_eq!(destinations(&state), vec![vec!["198.51.100.9:53"]]);
}

#[test]
fn unowned_traffic_adds_no_row_and_is_totalled_by_direction() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_traffic(secs(1), out(5000, "198.51.100.1", 443, 10), None);
    state.record_traffic(secs(1), out(5001, "198.51.100.2", 443, 15), None);
    state.record_traffic(
        secs(1),
        traffic(
            Direction::Inbound,
            Protocol::Udp,
            ("198.51.100.3", 53),
            ("192.0.2.10", 5002),
            70,
        ),
        None,
    );
    assert!(state.app_traffic().is_empty());
    assert_eq!(
        state.app_traffic_unattributed(),
        ByteTotals {
            upload: 25,
            download: 70
        }
    );
}

#[test]
fn owned_traffic_is_listed_and_adds_nothing_to_the_unattributed_total() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_traffic(
        secs(1),
        out(5000, "198.51.100.1", 443, 10),
        Some(process("/opt/a", 1)),
    );
    assert_eq!(destinations(&state), vec![vec!["198.51.100.1:443"]]);
    assert_eq!(state.app_traffic_unattributed(), ByteTotals::default());
}

#[test]
fn unowned_traffic_at_full_capacity_is_unattributed_not_uncounted() {
    let limits = StateLimits {
        detail_capacity: 1,
        ..StateLimits::default()
    };
    let mut state = AppState::new(limits).unwrap();
    state.record_traffic(
        secs(1),
        out(5000, "198.51.100.1", 443, 10),
        Some(process("/opt/a", 1)),
    );
    state.record_traffic(secs(1), out(5001, "198.51.100.2", 443, 40), None);
    assert_eq!(state.app_traffic_unattributed().upload, 40);
    assert_eq!(state.app_traffic_uncounted(), ByteTotals::default());
}

fn unknown_state() -> AppState {
    AppState::new(StateLimits::default()).unwrap()
}

fn flagged(mut event: TrafficEvent, syn: bool, ack: bool, rst: bool) -> TrafficEvent {
    event.tcp_flags = Some(TcpFlags {
        syn,
        ack,
        rst,
        fin: false,
        psh: false,
    });
    event
}

fn syn_from(port: u16) -> TrafficEvent {
    let mut event = traffic(
        Direction::Inbound,
        Protocol::Tcp,
        ("10.0.1.12", port),
        ("10.0.1.5", 24800),
        60,
    );
    event.tcp_flags = Some(TcpFlags {
        syn: true,
        ack: false,
        rst: false,
        fin: false,
        psh: false,
    });
    event
}

#[test]
fn refused_inbound_attempts_with_no_owner_are_left_out() {
    let mut state = unknown_state();
    for port in 40_000..40_050 {
        state.record_traffic(secs(1), syn_from(port), None);
        let reset = traffic(
            Direction::Outbound,
            Protocol::Tcp,
            ("10.0.1.5", 24800),
            ("10.0.1.12", port),
            40,
        );
        state.record_traffic(secs(1), flagged(reset, false, true, true), None);
    }
    assert!(state.app_traffic().is_empty());
    assert_eq!(state.app_traffic_unattributed(), ByteTotals::default());
    assert_eq!(state.app_traffic_uncounted(), ByteTotals::default());
}

#[test]
fn a_listening_port_reply_with_no_owner_adds_to_neither_total() {
    let mut state = unknown_state();
    state.record_listeners(
        vec![Listener {
            protocol: Protocol::Tcp,
            address: "0.0.0.0".parse().unwrap(),
            port: 8080,
            owners: Vec::new(),
        }],
        EPHEMERAL,
    );
    state.record_traffic(secs(1), out(8080, "198.51.100.9", 40_000, 500), None);
    assert!(state.app_traffic().is_empty());
    assert_eq!(state.app_traffic_unattributed(), ByteTotals::default());
    assert_eq!(state.app_traffic_uncounted(), ByteTotals::default());
}

#[test]
fn an_inbound_syn_ack_or_an_outbound_packet_without_reset_with_no_owner_is_totalled() {
    let mut state = unknown_state();
    state.record_traffic(secs(1), flagged(syn_from(443), true, true, false), None);
    state.record_traffic(
        secs(1),
        flagged(out(5000, "198.51.100.1", 443, 10), false, true, false),
        None,
    );
    assert!(state.app_traffic().is_empty());
    assert_eq!(
        state.app_traffic_unattributed(),
        ByteTotals {
            upload: 10,
            download: 60
        }
    );
}

#[test]
fn an_owned_reset_is_listed_under_its_app() {
    let mut state = unknown_state();
    let reset = flagged(out(5000, "198.51.100.1", 443, 40), false, true, true);
    state.record_traffic(secs(1), reset, Some(process("/opt/a", 1)));
    let apps = state.app_traffic();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].executable.path, std::path::PathBuf::from("/opt/a"));
    assert_eq!(apps[0].destinations[0].bytes.upload, 40);
}

#[test]
fn rows_go_idle_after_10_seconds_and_are_removed_after_5_minutes() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_traffic(
        secs(100),
        out(5000, "198.51.100.1", 443, 10),
        Some(process("/opt/a", 1)),
    );
    state.record_traffic(
        secs(105),
        out(5001, "198.51.100.2", 443, 10),
        Some(process("/opt/a", 1)),
    );
    state.advance_time(secs(109));
    assert!(!state.app_traffic()[0].destinations[0].idle);
    state.advance_time(secs(110));
    let apps = state.app_traffic();
    assert!(apps[0].destinations[0].idle);
    assert!(!apps[0].destinations[1].idle);
    assert_eq!(apps[0].destinations[0].rate, Default::default());
    state.advance_time(secs(399));
    assert_eq!(state.app_traffic()[0].destinations.len(), 2);
    state.advance_time(secs(400));
    assert_eq!(destinations(&state), vec![vec!["198.51.100.2:443"]]);
    state.advance_time(secs(405));
    assert!(state.app_traffic().is_empty());
}

#[test]
fn traffic_past_the_capacity_is_counted_not_listed() {
    let limits = StateLimits {
        detail_capacity: 2,
        ..StateLimits::default()
    };
    let mut state = AppState::new(limits).unwrap();
    let a = process("/opt/a", 1);
    state.record_traffic(secs(1), out(5000, "198.51.100.1", 443, 10), Some(a.clone()));
    state.record_traffic(secs(1), out(5001, "198.51.100.2", 443, 10), Some(a.clone()));
    state.record_traffic(secs(1), out(5002, "198.51.100.3", 443, 70), Some(a.clone()));
    // An already-listed destination still counts.
    state.record_traffic(secs(1), out(5003, "198.51.100.1", 443, 5), Some(a));
    assert_eq!(
        destinations(&state),
        vec![vec!["198.51.100.1:443", "198.51.100.2:443"]]
    );
    assert_eq!(state.app_traffic()[0].destinations[0].bytes.upload, 15);
    assert_eq!(
        state.app_traffic_uncounted(),
        ByteTotals {
            upload: 70,
            download: 0
        }
    );
}

const EPHEMERAL: std::ops::RangeInclusive<u16> = 32_768..=60_999;

#[test]
fn udp_traffic_on_a_bound_udp_port_is_listed() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_listeners(vec![listener(Protocol::Udp, "0.0.0.0", 5353)], EPHEMERAL);
    state.record_traffic(
        secs(1),
        traffic(
            Direction::Outbound,
            Protocol::Udp,
            ("192.0.2.10", 5353),
            ("224.0.0.251", 5353),
            40,
        ),
        Some(process("/opt/mdns", 4)),
    );
    assert_eq!(destinations(&state), vec![vec!["224.0.0.251:5353"]]);
}

fn block(source: &str, port: u16, protocol: Protocol, direction: Direction) -> FirewallEvent {
    FirewallEvent {
        timestamp: None,
        direction: Some(direction),
        interface: Some("eth0".to_owned()),
        protocol: Some(protocol),
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

fn inbound(source: &str, port: u16) -> FirewallEvent {
    block(source, port, Protocol::Tcp, Direction::Inbound)
}

fn forwarded(source: &str, port: u16) -> FirewallEvent {
    FirewallEvent {
        direction: None,
        ..block(source, port, Protocol::Tcp, Direction::Inbound)
    }
}

#[test]
fn forwarded_blocks_with_one_source_port_and_protocol_are_one_row_of_two_hits() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_firewall(Duration::from_secs(1), forwarded("203.0.113.9", 80));
    state.record_firewall(Duration::from_secs(2), forwarded("203.0.113.9", 80));
    let rows = state.blocked_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].direction, rows[0].count), (None, 2));
    assert_eq!(state.blocked_total(), 2);
    assert!(state.blocked(Direction::Inbound).is_empty());
    assert!(state.blocked(Direction::Outbound).is_empty());
}

fn sources(state: &AppState, direction: Direction) -> Vec<String> {
    state
        .blocked(direction)
        .iter()
        .map(|b| format!("{}:{}", b.source.unwrap(), b.port.unwrap()))
        .collect()
}

#[test]
fn a_repeated_block_raises_the_count_and_keeps_its_position() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_firewall(secs(1), inbound("198.51.100.1", 22));
    state.record_firewall(secs(2), inbound("198.51.100.2", 22));
    state.record_firewall(secs(5), inbound("198.51.100.1", 22));
    assert_eq!(
        sources(&state, Direction::Inbound),
        vec!["198.51.100.2:22", "198.51.100.1:22"]
    );
    let rows = state.blocked(Direction::Inbound);
    assert_eq!(rows[1].count, 2);
    assert_eq!(rows[1].first_seen, secs(1));
    assert_eq!(rows[0].count, 1);
}

#[test]
fn a_new_block_key_goes_to_the_front() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_firewall(secs(1), inbound("198.51.100.1", 22));
    state.record_firewall(secs(2), inbound("198.51.100.1", 23));
    state.record_firewall(
        secs(3),
        block("198.51.100.1", 23, Protocol::Udp, Direction::Inbound),
    );
    assert_eq!(
        sources(&state, Direction::Inbound),
        vec!["198.51.100.1:23", "198.51.100.1:23", "198.51.100.1:22"]
    );
    assert_eq!(
        state.blocked(Direction::Inbound)[0].protocol,
        Some(Protocol::Udp)
    );
}

#[test]
fn the_block_cap_drops_the_oldest() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    for port in 1..=1_001_u16 {
        state.record_firewall(secs(1), inbound("198.51.100.1", port));
    }
    let rows = state.blocked(Direction::Inbound);
    assert_eq!(rows.len(), 1_000);
    assert_eq!(rows[0].port, Some(1_001));
    assert_eq!(rows[999].port, Some(2));
}

#[test]
fn inbound_and_outbound_blocks_are_returned_separately() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_firewall(secs(1), inbound("198.51.100.1", 22));
    state.record_firewall(
        secs(1),
        block("198.51.100.1", 22, Protocol::Tcp, Direction::Outbound),
    );
    assert_eq!(sources(&state, Direction::Inbound).len(), 1);
    assert_eq!(sources(&state, Direction::Outbound).len(), 1);
}

fn allow(port: u16) -> Rule {
    Rule {
        direction: RuleDirection::In,
        action: RuleAction::Allow,
        protocol: None,
        ports: std::iter::once(port..=port).collect(),
        destination: None,
        source: RuleSource::Anywhere,
        interface: None,
        ipv6: false,
        text: format!("{port} ALLOW IN Anywhere"),
    }
}

#[test]
fn listening_ports_come_back_in_port_order_with_their_exposure() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_listeners(
        vec![
            listener(Protocol::Tcp, "0.0.0.0", 8080),
            listener(Protocol::Tcp, "0.0.0.0", 22),
            listener(Protocol::Tcp, "127.0.0.1", 631),
        ],
        EPHEMERAL,
    );
    state.record_rules(RuleSnapshot::Active {
        default_incoming: Policy::Deny,
        default_outgoing: Policy::Allow,
        rules: vec![allow(22)],
    });
    let ports = state.listening_ports();
    let seen: Vec<_> = ports
        .iter()
        .map(|p| (p.listener.port, p.exposure.clone()))
        .collect();
    assert_eq!(
        seen,
        vec![
            (22, Exposure::Open(Some("22 ALLOW IN Anywhere".to_owned()))),
            (631, Exposure::Local),
            (8080, Exposure::Blocked(None)),
        ]
    );
}

#[test]
fn ephemeral_udp_listeners_are_left_out_but_tcp_ones_are_kept() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_listeners(
        vec![
            listener(Protocol::Udp, "0.0.0.0", 40_000),
            listener(Protocol::Tcp, "0.0.0.0", 40_001),
            listener(Protocol::Udp, "0.0.0.0", 5353),
        ],
        EPHEMERAL,
    );
    let seen: Vec<_> = state
        .listening_ports()
        .iter()
        .map(|p| (p.listener.protocol, p.listener.port))
        .collect();
    assert_eq!(seen, vec![(Protocol::Udp, 5353), (Protocol::Tcp, 40_001)]);
}

#[test]
fn udp_listeners_above_the_ephemeral_range_are_left_out() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_listeners(
        vec![
            listener(Protocol::Udp, "0.0.0.0", 61_500),
            listener(Protocol::Tcp, "0.0.0.0", 61_501),
            listener(Protocol::Udp, "0.0.0.0", 5353),
        ],
        EPHEMERAL,
    );
    let seen: Vec<_> = state
        .listening_ports()
        .iter()
        .map(|p| (p.listener.protocol, p.listener.port))
        .collect();
    assert_eq!(seen, vec![(Protocol::Udp, 5353), (Protocol::Tcp, 61_501)]);
}

fn stamped(timestamp: &str) -> FirewallEvent {
    FirewallEvent {
        timestamp: Some(timestamp.to_owned()),
        ..inbound("198.51.100.1", 22)
    }
}

#[test]
fn a_block_row_carries_the_clock_time_of_its_latest_stamped_event() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_firewall(secs(1), stamped("Oct  8 12:01:09"));
    assert_eq!(
        state.blocked(Direction::Inbound)[0].last_clock.as_deref(),
        Some("12:01")
    );
    state.record_firewall(secs(2), stamped("2026-10-08T13:45:10.123456+02:00"));
    // An event with no timestamp leaves the last known time alone.
    state.record_firewall(secs(3), inbound("198.51.100.1", 22));
    assert_eq!(
        state.blocked(Direction::Inbound)[0].last_clock.as_deref(),
        Some("13:45")
    );

    // Journal microseconds are converted to local time: HH:MM in the shape.
    state.record_firewall(secs(4), stamped("1791460800000000"));
    let clock = state.blocked(Direction::Inbound)[0]
        .last_clock
        .clone()
        .unwrap();
    assert!(
        clock.len() == 5 && clock.as_bytes()[2] == b':' && clock != "13:45",
        "{clock}"
    );
}

#[test]
fn a_block_without_any_timestamp_has_no_clock_time() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_firewall(secs(1), inbound("198.51.100.1", 22));
    assert_eq!(state.blocked(Direction::Inbound)[0].last_clock, None);
}

fn request(machine: &str, source_port: u16, local_port: u16) -> TrafficEvent {
    let mut event = traffic(
        Direction::Inbound,
        Protocol::Tcp,
        (machine, source_port),
        ("10.0.1.5", local_port),
        60,
    );
    event.tcp_flags = Some(TcpFlags {
        syn: true,
        ack: false,
        rst: false,
        fin: false,
        psh: false,
    });
    event
}

fn reset(machine: &str, source_port: u16, local_port: u16) -> TrafficEvent {
    flagged(
        traffic(
            Direction::Outbound,
            Protocol::Tcp,
            ("10.0.1.5", local_port),
            (machine, source_port),
            40,
        ),
        false,
        true,
        true,
    )
}

fn refusing_state() -> AppState {
    let mut state = unknown_state();
    state.set_wall_clock(|| Some("09:41".to_owned()));
    state
}

fn refuse(state: &mut AppState, at: u64, machine: &str, source_port: u16, local_port: u16) {
    state.record_traffic(secs(at), request(machine, source_port, local_port), None);
    state.record_traffic(secs(at), reset(machine, source_port, local_port), None);
}

#[test]
fn a_request_then_a_reset_gives_one_refused_row() {
    let mut state = refusing_state();
    refuse(&mut state, 3, "10.0.1.12", 40_000, 24_800);
    let rows = state.blocked(Direction::Inbound);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, BlockKind::Refused);
    assert_eq!(rows[0].source, Some("10.0.1.12".parse().unwrap()));
    assert_eq!(rows[0].port, Some(24_800));
    assert_eq!(rows[0].protocol, Some(Protocol::Tcp));
    assert_eq!(rows[0].count, 1);
    assert_eq!(rows[0].first_seen, secs(3));
    assert_eq!(rows[0].last_clock.as_deref(), Some("09:41"));
}

#[test]
fn a_second_attempt_from_another_source_port_raises_the_count_and_keeps_the_place() {
    let mut state = refusing_state();
    refuse(&mut state, 1, "10.0.1.12", 40_000, 24_800);
    refuse(&mut state, 2, "10.0.1.13", 40_000, 24_800);
    refuse(&mut state, 3, "10.0.1.12", 40_001, 24_800);
    let rows = state.blocked(Direction::Inbound);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].source, Some("10.0.1.13".parse().unwrap()));
    assert_eq!(rows[1].source, Some("10.0.1.12".parse().unwrap()));
    assert_eq!(rows[1].count, 2);
}

#[test]
fn a_request_with_no_reset_gives_no_row() {
    let mut state = refusing_state();
    state.record_traffic(secs(1), request("10.0.1.12", 40_000, 24_800), None);
    state.record_traffic(secs(9), request("10.0.1.12", 40_001, 24_800), None);
    assert!(state.blocked(Direction::Inbound).is_empty());
}

#[test]
fn a_reset_with_no_request_before_it_gives_no_row() {
    let mut state = refusing_state();
    state.record_traffic(secs(1), reset("10.0.1.12", 40_000, 24_800), None);
    assert!(state.blocked(Direction::Inbound).is_empty());
}

#[test]
fn a_reset_more_than_two_seconds_after_the_request_gives_no_row() {
    let mut state = refusing_state();
    state.record_traffic(secs(1), request("10.0.1.12", 40_000, 24_800), None);
    state.record_traffic(secs(4), reset("10.0.1.12", 40_000, 24_800), None);
    assert!(state.blocked(Direction::Inbound).is_empty());
    state.record_traffic(secs(10), request("10.0.1.12", 40_001, 24_800), None);
    state.record_traffic(secs(12), reset("10.0.1.12", 40_001, 24_800), None);
    assert_eq!(state.blocked(Direction::Inbound).len(), 1);
}

#[test]
fn a_request_to_a_listening_port_gives_no_row() {
    let mut state = refusing_state();
    state.record_listeners(vec![listener(Protocol::Tcp, "0.0.0.0", 24_800)], EPHEMERAL);
    refuse(&mut state, 1, "10.0.1.12", 40_000, 24_800);
    assert!(state.blocked(Direction::Inbound).is_empty());
}

#[test]
fn a_block_and_a_refused_attempt_for_the_same_source_and_port_are_two_rows() {
    let mut state = refusing_state();
    state.record_firewall(secs(1), inbound("10.0.1.12", 24_800));
    refuse(&mut state, 2, "10.0.1.12", 40_000, 24_800);
    state.record_firewall(secs(3), inbound("10.0.1.12", 24_800));
    let rows = state.blocked(Direction::Inbound);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].kind, BlockKind::Refused);
    assert_eq!(rows[0].count, 1);
    assert_eq!(rows[1].kind, BlockKind::Firewall);
    assert_eq!(rows[1].count, 2);
}

#[test]
fn with_the_cap_reached_the_oldest_row_of_either_kind_is_dropped() {
    let mut state = refusing_state();
    state.record_firewall(secs(1), inbound("198.51.100.1", 1));
    for port in 2..=500_u16 {
        refuse(&mut state, 2, "10.0.1.12", 40_000, port);
    }
    for port in 501..=1_001_u16 {
        state.record_firewall(secs(3), inbound("198.51.100.1", port));
    }
    let rows = state.blocked(Direction::Inbound);
    assert_eq!(rows.len(), 1_000);
    assert_eq!(rows[0].port, Some(1_001));
    assert_eq!(rows[999].port, Some(2));
    assert_eq!(rows[999].kind, BlockKind::Refused);
    refuse(&mut state, 4, "10.0.1.12", 40_000, 2_000);
    let rows = state.blocked(Direction::Inbound);
    assert_eq!(rows.len(), 1_000);
    assert_eq!(rows[0].kind, BlockKind::Refused);
    assert_eq!(rows[999].port, Some(3));
}

#[test]
fn refused_attempts_change_neither_app_traffic_nor_the_unattributed_total() {
    let mut state = refusing_state();
    refuse(&mut state, 1, "10.0.1.12", 40_000, 24_800);
    state.record_traffic(secs(2), request("10.0.1.12", 40_001, 24_800), None);
    state.record_traffic(secs(9), reset("10.0.1.12", 40_005, 24_800), None);
    assert!(state.app_traffic().is_empty());
    assert_eq!(state.app_traffic_unattributed(), ByteTotals::default());
    assert_eq!(state.app_traffic_uncounted(), ByteTotals::default());
}

fn neighbour(address: &str) -> crosswalk::collect::neighbors::Neighbor {
    crosswalk::collect::neighbors::Neighbor {
        address: address.parse().unwrap(),
        mac: Some("aa:bb:cc:dd:ee:ff".to_owned()),
        interface: "eth0".to_owned(),
        state: "reachable".to_owned(),
    }
}

fn neighbour_addresses(state: &AppState) -> Vec<String> {
    state
        .neighbors()
        .expect("a snapshot was recorded")
        .expect("the snapshot is available")
        .iter()
        .map(|n| n.address.to_string())
        .collect()
}

#[test]
fn the_same_address_on_two_interfaces_is_ordered_by_interface() {
    use crosswalk::collect::neighbors::NeighborSnapshot;
    let on = |interface: &str| crosswalk::collect::neighbors::Neighbor {
        interface: interface.to_owned(),
        ..neighbour("fe80::1")
    };
    for dump in [vec![on("wlan0"), on("eth0")], vec![on("eth0"), on("wlan0")]] {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.record_neighbors(NeighborSnapshot::Available(dump));
        let interfaces: Vec<_> = state
            .neighbors()
            .unwrap()
            .unwrap()
            .iter()
            .map(|n| n.interface.clone())
            .collect();
        assert_eq!(interfaces, ["eth0", "wlan0"]);
    }
}

#[test]
fn neighbours_come_back_in_numeric_address_order_with_ipv4_first() {
    use crosswalk::collect::neighbors::NeighborSnapshot;
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_neighbors(NeighborSnapshot::Available(vec![
        neighbour("fe80::2"),
        neighbour("10.0.1.10"),
        neighbour("2001:db8::1"),
        neighbour("10.0.1.2"),
        neighbour("9.9.9.9"),
    ]));
    assert_eq!(
        neighbour_addresses(&state),
        ["9.9.9.9", "10.0.1.2", "10.0.1.10", "2001:db8::1", "fe80::2"]
    );
}

#[test]
fn a_later_neighbour_snapshot_replaces_the_earlier_one() {
    use crosswalk::collect::neighbors::NeighborSnapshot;
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_neighbors(NeighborSnapshot::Available(vec![
        neighbour("10.0.1.2"),
        neighbour("10.0.1.3"),
    ]));
    state.record_neighbors(NeighborSnapshot::Available(vec![neighbour("10.0.1.3")]));
    assert_eq!(neighbour_addresses(&state), ["10.0.1.3"]);
    state.record_neighbors(NeighborSnapshot::Available(Vec::new()));
    assert!(neighbour_addresses(&state).is_empty());
}

#[test]
fn an_unavailable_neighbour_snapshot_is_kept_and_an_available_one_replaces_it() {
    use crosswalk::collect::neighbors::NeighborSnapshot;
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_neighbors(NeighborSnapshot::Unavailable("no ip".to_owned()));
    assert_eq!(state.neighbors().unwrap().unwrap_err(), "no ip");
    state.record_neighbors(NeighborSnapshot::Available(vec![neighbour("10.0.1.2")]));
    assert_eq!(neighbour_addresses(&state), ["10.0.1.2"]);
}

#[test]
fn before_any_neighbour_snapshot_the_state_says_so() {
    let state = AppState::new(StateLimits::default()).unwrap();
    assert!(state.neighbors().is_none());
}

#[test]
fn the_user_an_attribution_status_names_is_kept_until_a_status_without_one_replaces_it() {
    let status = |only_user: Option<&str>| AttributionStatus {
        health: AttributionHealth::Available,
        only_user: only_user.map(str::to_owned),
    };
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_attribution_status(status(Some("alice")));
    let kept = state
        .source_health()
        .attribution
        .as_ref()
        .unwrap()
        .only_user
        .clone();
    assert_eq!(kept.as_deref(), Some("alice"));
    state.record_attribution_status(status(None));
    assert_eq!(
        state
            .source_health()
            .attribution
            .as_ref()
            .unwrap()
            .only_user,
        None
    );
}

#[test]
fn the_block_total_rises_by_one_for_a_new_row_and_for_a_repeat() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    assert_eq!(state.blocked_total(), 0);
    state.record_firewall(secs(1), inbound("203.0.113.5", 22));
    assert_eq!(state.blocked_total(), 1);
    state.record_firewall(secs(2), inbound("203.0.113.5", 22));
    assert_eq!(state.blocked_total(), 2);
    assert_eq!(state.blocked(Direction::Inbound).len(), 1);
}

#[test]
fn the_block_total_rises_by_one_for_a_refused_attempt_and_its_repeat() {
    let mut state = refusing_state();
    state.record_traffic(secs(1), request("10.0.1.12", 40_000, 24_800), None);
    assert_eq!(state.blocked_total(), 0);
    state.record_traffic(secs(1), reset("10.0.1.12", 40_000, 24_800), None);
    assert_eq!(state.blocked_total(), 1);
    refuse(&mut state, 2, "10.0.1.12", 40_001, 24_800);
    assert_eq!(state.blocked_total(), 2);
}

#[test]
fn the_block_total_does_not_rise_for_traffic_that_records_nothing() {
    let mut state = refusing_state();
    state.record_traffic(
        secs(1),
        out(40_000, "198.51.100.7", 443, 900),
        Some(process("/usr/bin/curl", 10)),
    );
    state.record_traffic(secs(1), out(40_001, "198.51.100.7", 443, 900), None);
    state.record_traffic(secs(1), request("10.0.1.12", 40_000, 24_800), None);
    assert_eq!(state.blocked_total(), 0);
}

#[test]
fn the_block_total_keeps_growing_when_the_row_cap_drops_rows() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    for n in 0..300u32 {
        state.record_firewall(
            secs(u64::from(n)),
            inbound(&format!("10.1.{}.{}", n / 250, n % 250), 22),
        );
    }
    assert_eq!(state.blocked_total(), 300);
}

fn access_point(
    ssid: Option<&str>,
    bssid: &str,
    signal: u8,
) -> crosswalk::collect::wifi::AccessPoint {
    crosswalk::collect::wifi::AccessPoint {
        ssid: ssid.map(str::to_owned),
        bssid: bssid.to_owned(),
        signal,
        channel: 36,
        frequency_mhz: 5180,
        security: "WPA2".to_owned(),
        in_use: false,
    }
}

fn wifi_order(state: &AppState) -> Vec<(Option<String>, String)> {
    state
        .wifi()
        .expect("a snapshot was recorded")
        .expect("the snapshot is available")
        .iter()
        .map(|entry| (entry.point.ssid.clone(), entry.point.bssid.clone()))
        .collect()
}

#[test]
fn access_points_come_back_strongest_first() {
    use crosswalk::collect::wifi::WifiSnapshot;
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_wifi(WifiSnapshot::Available(vec![
        access_point(Some("weak"), "00:00:00:00:00:01", 20),
        access_point(Some("strong"), "00:00:00:00:00:02", 90),
        access_point(Some("middle"), "00:00:00:00:00:03", 55),
    ]));
    let names: Vec<_> = wifi_order(&state)
        .into_iter()
        .map(|(n, _)| n.unwrap())
        .collect();
    assert_eq!(names, ["strong", "middle", "weak"]);
}

#[test]
fn equal_signals_are_ordered_by_name_then_address_whichever_order_they_arrive_in() {
    use crosswalk::collect::wifi::WifiSnapshot;
    let list = || {
        vec![
            access_point(None, "00:00:00:00:00:01", 50),
            access_point(Some("b"), "00:00:00:00:00:09", 50),
            access_point(Some("a"), "00:00:00:00:00:05", 50),
            access_point(Some("b"), "00:00:00:00:00:02", 50),
            access_point(None, "00:00:00:00:00:00", 50),
        ]
    };
    let mut reversed = list();
    reversed.reverse();
    let mut orders = Vec::new();
    for dump in [list(), reversed] {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        state.record_wifi(WifiSnapshot::Available(dump));
        orders.push(wifi_order(&state));
    }
    assert_eq!(orders[0], orders[1]);
    let bssids: Vec<_> = orders[0].iter().map(|(_, b)| b.as_str()).collect();
    assert_eq!(
        bssids,
        [
            "00:00:00:00:00:05",
            "00:00:00:00:00:02",
            "00:00:00:00:00:09",
            "00:00:00:00:00:00",
            "00:00:00:00:00:01",
        ]
    );
}

#[test]
fn a_later_wifi_snapshot_replaces_the_earlier_one() {
    use crosswalk::collect::wifi::WifiSnapshot;
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_wifi(WifiSnapshot::Available(vec![
        access_point(Some("gone"), "00:00:00:00:00:01", 80),
        access_point(Some("stays"), "00:00:00:00:00:02", 60),
    ]));
    state.record_wifi(WifiSnapshot::Available(vec![access_point(
        Some("stays"),
        "00:00:00:00:00:02",
        60,
    )]));
    let entries = state.wifi().unwrap().unwrap();
    let listed: Vec<_> = entries.iter().filter(|e| e.seen_ago.is_none()).collect();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].point.ssid.as_deref(), Some("stays"));
}

#[test]
fn an_unavailable_wifi_snapshot_is_kept_and_an_available_one_replaces_it() {
    use crosswalk::collect::wifi::WifiSnapshot;
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_wifi(WifiSnapshot::Unavailable("no Wi-Fi device".to_owned()));
    assert_eq!(state.wifi().unwrap().unwrap_err(), "no Wi-Fi device");
    state.record_wifi(WifiSnapshot::Available(Vec::new()));
    assert!(state.wifi().unwrap().unwrap().is_empty());
}

#[test]
fn before_any_wifi_snapshot_the_state_says_so() {
    let state = AppState::new(StateLimits::default()).unwrap();
    assert!(state.wifi().is_none());
}

mod wifi_memory {
    use super::*;
    use crosswalk::collect::wifi::{AccessPoint, WifiSnapshot};

    fn bssid(n: u32) -> String {
        format!("00:00:00:00:{:02x}:{:02x}", n / 256, n % 256)
    }

    fn ap(n: u32, signal: u8) -> AccessPoint {
        access_point(Some(&format!("net{n}")), &bssid(n), signal)
    }

    fn state() -> AppState {
        AppState::new(StateLimits::default()).unwrap()
    }

    fn listed(state: &mut AppState, at: u64, points: Vec<AccessPoint>) {
        state.advance_time(secs(at));
        state.record_wifi(WifiSnapshot::Available(points));
    }

    /// (name, age in seconds) in the order `wifi()` returns them.
    fn rows(state: &AppState) -> Vec<(String, Option<u64>)> {
        state
            .wifi()
            .unwrap()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e.point.ssid.clone().unwrap(),
                    e.seen_ago.map(|ago| ago.as_secs()),
                )
            })
            .collect()
    }

    #[test]
    fn an_access_point_missing_from_a_later_snapshot_follows_the_listed_ones_with_its_age() {
        let mut state = state();
        listed(&mut state, 10, vec![ap(1, 90), ap(2, 40)]);
        listed(&mut state, 25, vec![ap(2, 40)]);
        state.advance_time(secs(30));
        assert_eq!(
            rows(&state),
            [("net2".to_owned(), None), ("net1".to_owned(), Some(20))]
        );
    }

    #[test]
    fn remembered_access_points_are_most_recently_seen_first() {
        let mut state = state();
        listed(&mut state, 10, vec![ap(1, 50)]);
        listed(&mut state, 20, vec![ap(2, 90)]);
        listed(&mut state, 30, vec![ap(3, 10), ap(4, 60)]);
        listed(&mut state, 40, vec![ap(4, 60)]);
        let names: Vec<_> = rows(&state).into_iter().map(|r| r.0).collect();
        assert_eq!(names, ["net4", "net3", "net2", "net1"]);
    }

    #[test]
    fn an_access_point_listed_again_is_listed_with_its_new_signal_and_no_age() {
        let mut state = state();
        listed(&mut state, 10, vec![ap(1, 30)]);
        listed(&mut state, 20, vec![]);
        listed(&mut state, 30, vec![ap(1, 75)]);
        let entries = state.wifi().unwrap().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seen_ago, None);
        assert_eq!(entries[0].point.signal, 75);
    }

    #[test]
    fn a_remembered_access_point_never_has_the_in_use_mark() {
        let mut state = state();
        let mut current = ap(1, 80);
        current.in_use = true;
        listed(&mut state, 10, vec![current]);
        listed(&mut state, 20, vec![]);
        let entries = state.wifi().unwrap().unwrap();
        assert!(entries[0].seen_ago.is_some());
        assert!(!entries[0].point.in_use);
    }

    #[test]
    fn with_201_seen_the_oldest_remembered_is_forgotten_and_a_listed_one_never_is() {
        let mut state = state();
        for n in 0..200 {
            listed(&mut state, 10 + u64::from(n), vec![ap(n, 50)]);
            // each earlier one stays remembered
        }
        // the 200 so far are all remembered; list a 201st and re-list none else
        listed(&mut state, 300, vec![ap(1000, 5)]);
        let rows = rows(&state);
        assert_eq!(rows.len(), 200);
        assert_eq!(rows[0], ("net1000".to_owned(), None));
        assert!(!rows.iter().any(|r| r.0 == "net0"));
        assert!(rows.iter().any(|r| r.0 == "net1"));

        // 201 listed at once: none of them is dropped
        let mut state2 = self::state();
        listed(&mut state2, 10, vec![ap(5000, 5)]);
        listed(&mut state2, 20, (0..201).map(|n| ap(n, 50)).collect());
        assert_eq!(state2.wifi().unwrap().unwrap().len(), 201);
    }

    #[test]
    fn an_unavailable_snapshot_keeps_what_was_remembered() {
        let mut state = state();
        listed(&mut state, 10, vec![ap(1, 50)]);
        state.record_wifi(WifiSnapshot::Unavailable(
            "Wi-Fi is switched off".to_owned(),
        ));
        assert_eq!(state.wifi().unwrap().unwrap_err(), "Wi-Fi is switched off");
        listed(&mut state, 40, vec![]);
        assert_eq!(rows(&state), [("net1".to_owned(), Some(30))]);
    }
}

fn neighbour_with(address: &str, mac: Option<&str>) -> crosswalk::collect::neighbors::Neighbor {
    crosswalk::collect::neighbors::Neighbor {
        mac: mac.map(str::to_owned),
        ..neighbour(address)
    }
}

fn events_state() -> AppState {
    let mut state = unknown_state();
    state.set_wall_clock(|| Some("10:05".to_owned()));
    state
}

fn seen(state: &mut AppState, neighbours: Vec<crosswalk::collect::neighbors::Neighbor>) {
    state.record_neighbors(crosswalk::collect::neighbors::NeighborSnapshot::Available(
        neighbours,
    ));
}

fn event_texts(state: &AppState) -> Vec<String> {
    state.events().iter().map(|e| e.text.clone()).collect()
}

#[test]
fn the_first_neighbour_snapshot_logs_nothing() {
    let mut state = events_state();
    seen(
        &mut state,
        vec![neighbour("10.0.1.5"), neighbour("10.0.1.6")],
    );
    assert!(state.events().is_empty());
}

#[test]
fn a_new_address_logs_one_event_with_its_hardware_address_and_the_time() {
    use crosswalk::events::{EventKind, EventLevel};
    let mut state = events_state();
    seen(&mut state, vec![neighbour("10.0.1.5")]);
    seen(
        &mut state,
        vec![neighbour("10.0.1.5"), neighbour("10.0.1.9")],
    );
    seen(
        &mut state,
        vec![neighbour("10.0.1.5"), neighbour("10.0.1.9")],
    );
    let events: Vec<_> = state.events().iter().collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::Neighbour);
    assert_eq!(events[0].level, EventLevel::Normal);
    assert_eq!(events[0].clock.as_deref(), Some("10:05"));
    assert_eq!(
        events[0].text,
        "new neighbour 10.0.1.9 aa:bb:cc:dd:ee:ff on eth0"
    );
}

#[test]
fn a_neighbour_that_disappears_and_returns_with_the_same_hardware_address_logs_nothing() {
    let mut state = events_state();
    seen(&mut state, vec![neighbour("10.0.1.5")]);
    seen(&mut state, vec![]);
    seen(&mut state, vec![neighbour("10.0.1.5")]);
    assert!(state.events().is_empty());
}

#[test]
fn a_known_address_with_another_hardware_address_logs_a_danger_event_naming_both() {
    use crosswalk::events::{EventKind, EventLevel};
    let mut state = events_state();
    seen(
        &mut state,
        vec![neighbour_with("10.0.1.5", Some("aa:aa:aa:aa:aa:aa"))],
    );
    seen(
        &mut state,
        vec![neighbour_with("10.0.1.5", Some("bb:bb:bb:bb:bb:bb"))],
    );
    let events: Vec<_> = state.events().iter().collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::Neighbour);
    assert_eq!(events[0].level, EventLevel::Danger);
    assert_eq!(
        events[0].text,
        "10.0.1.5 MAC aa:aa:aa:aa:aa:aa -> bb:bb:bb:bb:bb:bb on eth0"
    );
}

#[test]
fn a_second_change_is_compared_with_the_newest_hardware_address() {
    let mut state = events_state();
    for mac in [
        "aa:aa:aa:aa:aa:aa",
        "bb:bb:bb:bb:bb:bb",
        "bb:bb:bb:bb:bb:bb",
        "cc:cc:cc:cc:cc:cc",
    ] {
        seen(&mut state, vec![neighbour_with("10.0.1.5", Some(mac))]);
    }
    let texts = event_texts(&state);
    assert_eq!(texts.len(), 2);
    assert!(texts[0].ends_with("bb:bb:bb:bb:bb:bb -> cc:cc:cc:cc:cc:cc on eth0"));
    assert!(texts[1].ends_with("aa:aa:aa:aa:aa:aa -> bb:bb:bb:bb:bb:bb on eth0"));
}

#[test]
fn an_unavailable_snapshot_logs_nothing_and_loses_nothing() {
    use crosswalk::collect::neighbors::NeighborSnapshot;
    let mut state = events_state();
    seen(&mut state, vec![neighbour("10.0.1.5")]);
    state.record_neighbors(NeighborSnapshot::Unavailable("ip failed".to_owned()));
    seen(&mut state, vec![neighbour("10.0.1.5")]);
    assert!(state.events().is_empty());
    // A first reading that failed is not the baseline either.
    let mut state = events_state();
    state.record_neighbors(NeighborSnapshot::Unavailable("ip failed".to_owned()));
    seen(&mut state, vec![neighbour("10.0.1.5")]);
    assert!(state.events().is_empty());
}

#[test]
fn an_entry_without_a_hardware_address_is_ignored() {
    let mut state = events_state();
    seen(&mut state, vec![neighbour("10.0.1.5")]);
    seen(
        &mut state,
        vec![neighbour("10.0.1.5"), neighbour_with("10.0.1.8", None)],
    );
    assert!(state.events().is_empty());
}

#[test]
fn a_neighbour_without_a_hardware_address_at_the_baseline_is_known_when_it_resolves() {
    use crosswalk::events::EventLevel;
    let mut state = events_state();
    seen(
        &mut state,
        vec![neighbour_with("10.0.1.8", None), neighbour("10.0.1.5")],
    );
    seen(
        &mut state,
        vec![
            neighbour_with("10.0.1.8", Some("aa:aa:aa:aa:aa:aa")),
            neighbour("10.0.1.5"),
        ],
    );
    assert!(state.events().is_empty());
    seen(
        &mut state,
        vec![
            neighbour_with("10.0.1.8", Some("bb:bb:bb:bb:bb:bb")),
            neighbour("10.0.1.5"),
        ],
    );
    assert_eq!(levels(&state), vec![EventLevel::Danger]);
    assert_eq!(
        event_texts(&state),
        vec!["10.0.1.8 MAC aa:aa:aa:aa:aa:aa -> bb:bb:bb:bb:bb:bb on eth0"]
    );
}

#[test]
fn past_4096_known_addresses_a_new_one_is_not_logged_but_a_known_one_still_is() {
    let address = |n: u32| format!("10.2.{}.{}", n / 250, n % 250 + 1);
    let mut state = events_state();
    let full: Vec<_> = (0..4_096)
        .map(|n| neighbour_with(&address(n), Some("aa:aa:aa:aa:aa:aa")))
        .collect();
    seen(&mut state, full.clone());
    let mut next = full;
    next.push(neighbour(&address(4_096)));
    next[0] = neighbour_with(&address(0), Some("bb:bb:bb:bb:bb:bb"));
    seen(&mut state, next);
    assert_eq!(
        event_texts(&state),
        vec![format!(
            "{} MAC aa:aa:aa:aa:aa:aa -> bb:bb:bb:bb:bb:bb on eth0",
            address(0)
        )]
    );
}

#[test]
fn the_log_keeps_the_newest_500_newest_first() {
    let mut state = events_state();
    seen(&mut state, vec![]);
    for n in 0..600u32 {
        let address = format!("10.1.{}.{}", n / 250, n % 250 + 1);
        seen(&mut state, vec![neighbour(&address)]);
        seen(&mut state, vec![]);
    }
    assert_eq!(state.events().len(), 500);
    let texts = event_texts(&state);
    assert!(texts[0].contains("10.1.2.100 "), "{}", texts[0]);
    assert!(texts[499].contains("10.1.0.101 "), "{}", texts[499]);
}

fn owned_listener(protocol: Protocol, address: &str, port: u16, path: &str) -> Listener {
    Listener {
        owners: vec![process(path, 100)],
        ..listener(protocol, address, port)
    }
}

fn active(incoming: Policy, rules: Vec<Rule>) -> RuleSnapshot {
    RuleSnapshot::Active {
        default_incoming: incoming,
        default_outgoing: Policy::Allow,
        rules,
    }
}

fn levels(state: &AppState) -> Vec<crosswalk::events::EventLevel> {
    state.events().iter().map(|e| e.level).collect()
}

#[test]
fn the_first_listener_and_rules_readings_log_nothing_in_either_order() {
    let ports = vec![owned_listener(
        Protocol::Tcp,
        "0.0.0.0",
        22,
        "/usr/bin/sshd",
    )];
    let mut state = events_state();
    state.record_listeners(ports.clone(), EPHEMERAL);
    state.record_rules(active(Policy::Deny, vec![allow(22)]));
    assert!(state.events().is_empty());
    let mut state = events_state();
    state.record_rules(active(Policy::Deny, vec![allow(22)]));
    state.record_listeners(ports, EPHEMERAL);
    assert!(state.events().is_empty());
}

#[test]
fn a_new_port_logs_once_with_its_app_and_exposure() {
    use crosswalk::events::{EventKind, EventLevel};
    let mut state = events_state();
    state.record_rules(active(Policy::Deny, vec![allow(22)]));
    state.record_listeners(vec![], EPHEMERAL);
    let ports = vec![
        owned_listener(Protocol::Tcp, "0.0.0.0", 22, "/usr/bin/sshd"),
        listener(Protocol::Udp, "0.0.0.0", 5353),
    ];
    state.record_listeners(ports.clone(), EPHEMERAL);
    state.record_listeners(ports, EPHEMERAL);
    let events: Vec<_> = state.events().iter().collect();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.kind == EventKind::Port));
    let texts = event_texts(&state);
    assert!(texts.contains(&"tcp 0.0.0.0:22 sshd started listening, open".to_owned()));
    assert!(texts.contains(&"udp 0.0.0.0:5353 started listening, blocked".to_owned()));
    for event in events {
        let open = event.text.contains("sshd");
        assert_eq!(
            event.level,
            if open {
                EventLevel::Warning
            } else {
                EventLevel::Normal
            }
        );
    }
}

#[test]
fn a_port_that_stops_listening_logs_once() {
    let mut state = events_state();
    state.record_rules(active(Policy::Deny, vec![]));
    state.record_listeners(
        vec![owned_listener(
            Protocol::Tcp,
            "0.0.0.0",
            22,
            "/usr/bin/sshd",
        )],
        EPHEMERAL,
    );
    state.record_listeners(vec![], EPHEMERAL);
    state.record_listeners(vec![], EPHEMERAL);
    assert_eq!(
        event_texts(&state),
        vec!["tcp 0.0.0.0:22 sshd stopped listening"]
    );
}

#[test]
fn a_rule_change_that_opens_a_port_logs_the_rule_and_the_exposure_change() {
    use crosswalk::events::{EventKind, EventLevel};
    let mut state = events_state();
    state.record_listeners(
        vec![owned_listener(
            Protocol::Tcp,
            "0.0.0.0",
            22,
            "/usr/bin/sshd",
        )],
        EPHEMERAL,
    );
    state.record_rules(active(Policy::Deny, vec![]));
    state.record_rules(active(Policy::Deny, vec![allow(22)]));
    let events: Vec<_> = state.events().iter().collect();
    assert_eq!(events.len(), 2);
    let port = events.iter().find(|e| e.kind == EventKind::Port).unwrap();
    assert_eq!(port.text, "tcp 0.0.0.0:22 sshd exposure blocked -> open");
    assert_eq!(port.level, EventLevel::Warning);
    let rule = events
        .iter()
        .find(|e| e.kind == EventKind::Firewall)
        .unwrap();
    assert_eq!(rule.text, "rule added: 22 ALLOW IN Anywhere");
    assert_eq!(rule.level, EventLevel::Normal);
    state.record_rules(active(Policy::Deny, vec![]));
    assert_eq!(state.events().len(), 4);
    let texts = event_texts(&state);
    assert!(texts.contains(&"rule removed: 22 ALLOW IN Anywhere".to_owned()));
    assert!(texts.contains(&"tcp 0.0.0.0:22 sshd exposure open -> blocked".to_owned()));
}

#[test]
fn a_policy_change_logs_the_old_and_new_policy() {
    use crosswalk::events::EventKind;
    let mut state = events_state();
    state.record_rules(active(Policy::Deny, vec![]));
    state.record_rules(active(Policy::Allow, vec![]));
    let events: Vec<_> = state.events().iter().collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::Firewall);
    assert_eq!(events[0].text, "default incoming policy deny -> allow");
    let mut state = events_state();
    state.record_rules(active(Policy::Deny, vec![]));
    state.record_rules(RuleSnapshot::Active {
        default_incoming: Policy::Deny,
        default_outgoing: Policy::Reject,
        rules: vec![],
    });
    assert_eq!(
        event_texts(&state),
        vec!["default outgoing policy allow -> reject"]
    );
}

#[test]
fn ufw_switched_off_is_a_warning_and_back_on_is_plain() {
    use crosswalk::events::EventLevel;
    let mut state = events_state();
    state.record_listeners(
        vec![owned_listener(
            Protocol::Tcp,
            "0.0.0.0",
            22,
            "/usr/bin/sshd",
        )],
        EPHEMERAL,
    );
    state.record_rules(active(Policy::Deny, vec![allow(22)]));
    state.record_rules(RuleSnapshot::Inactive);
    assert_eq!(event_texts(&state), vec!["UFW switched off"]);
    assert_eq!(levels(&state), vec![EventLevel::Warning]);
    state.record_rules(active(Policy::Deny, vec![allow(22)]));
    assert_eq!(
        event_texts(&state),
        vec!["UFW switched on", "UFW switched off"]
    );
    assert_eq!(levels(&state)[0], EventLevel::Normal);
}

#[test]
fn an_unreadable_rules_snapshot_between_two_identical_ones_logs_nothing() {
    let mut state = events_state();
    state.record_listeners(
        vec![owned_listener(
            Protocol::Tcp,
            "0.0.0.0",
            22,
            "/usr/bin/sshd",
        )],
        EPHEMERAL,
    );
    state.record_rules(active(Policy::Deny, vec![allow(22)]));
    state.record_rules(RuleSnapshot::Unavailable("ufw failed".to_owned()));
    state.record_listeners(
        vec![owned_listener(
            Protocol::Tcp,
            "0.0.0.0",
            22,
            "/usr/bin/sshd",
        )],
        EPHEMERAL,
    );
    state.record_rules(active(Policy::Deny, vec![allow(22)]));
    assert!(state.events().is_empty());
}

fn address(ip: &str, prefix: u8) -> crosswalk::collect::interfaces::InterfaceAddress {
    crosswalk::collect::interfaces::InterfaceAddress {
        ip: ip.parse().unwrap(),
        prefix,
    }
}

fn connection(
    addresses: Vec<crosswalk::collect::interfaces::InterfaceAddress>,
    gateway: Option<&str>,
    name_server: Option<&str>,
) -> InterfaceSnapshot {
    let mut snapshot = snapshot("eth0", 0.0, 0.0);
    snapshot.interfaces[0].addresses = addresses;
    snapshot.gateway = gateway.map(|g| g.parse().unwrap());
    snapshot.name_server = name_server.map(|n| n.parse().unwrap());
    snapshot
}

#[test]
fn the_first_interface_reading_logs_nothing() {
    let mut state = events_state();
    state.record_interfaces(connection(
        vec![address("10.0.1.13", 24)],
        Some("10.0.1.1"),
        Some("10.0.1.6"),
    ));
    assert!(state.events().is_empty());
}

#[test]
fn an_added_and_a_removed_address_each_log_once_with_the_interface() {
    use crosswalk::events::{EventKind, EventLevel};
    let mut state = events_state();
    state.record_interfaces(connection(vec![address("10.0.1.13", 24)], None, None));
    state.record_interfaces(connection(
        vec![address("10.0.1.13", 24), address("fd00::5", 64)],
        None,
        None,
    ));
    state.record_interfaces(connection(vec![address("fd00::5", 64)], None, None));
    state.record_interfaces(connection(vec![address("fd00::5", 64)], None, None));
    assert_eq!(
        event_texts(&state),
        vec!["eth0 lost 10.0.1.13/24", "eth0 gained fd00::5/64"]
    );
    assert!(
        state
            .events()
            .iter()
            .all(|e| e.kind == EventKind::Connection && e.level == EventLevel::Normal)
    );
}

#[test]
fn a_gateway_change_and_a_dns_change_each_log_old_and_new() {
    let mut state = events_state();
    state.record_interfaces(connection(vec![], Some("10.0.1.1"), Some("10.0.1.6")));
    state.record_interfaces(connection(vec![], Some("10.0.1.2"), Some("10.0.1.6")));
    assert_eq!(
        event_texts(&state),
        vec!["default route eth0 via 10.0.1.1 -> eth0 via 10.0.1.2"]
    );
    state.record_interfaces(connection(vec![], Some("10.0.1.2"), Some("10.0.1.7")));
    assert_eq!(event_texts(&state)[0], "DNS server 10.0.1.6 -> 10.0.1.7");
    assert_eq!(state.events().len(), 2);
}

#[test]
fn the_default_route_moving_to_another_interface_logs_once() {
    let mut state = events_state();
    state.record_interfaces(connection(vec![], Some("10.0.1.1"), None));
    let mut moved = connection(vec![], Some("192.168.8.1"), None);
    moved.default_route = Some("wlan0".to_owned());
    state.record_interfaces(moved);
    assert_eq!(
        event_texts(&state),
        vec!["default route eth0 via 10.0.1.1 -> wlan0 via 192.168.8.1"]
    );
    let mut gone = connection(vec![], None, None);
    gone.default_route = None;
    state.record_interfaces(gone);
    assert_eq!(
        event_texts(&state)[0],
        "default route wlan0 via 192.168.8.1 -> none"
    );
}

#[test]
fn an_unreadable_interface_reading_between_two_identical_ones_logs_nothing() {
    let mut state = events_state();
    let good = connection(
        vec![address("10.0.1.13", 24)],
        Some("10.0.1.1"),
        Some("10.0.1.6"),
    );
    state.record_interfaces(good.clone());
    for health in [
        CollectionHealth::Stale("read failed".to_owned()),
        CollectionHealth::Unavailable("read failed".to_owned()),
    ] {
        let mut failed = connection(vec![], None, None);
        failed.health = health;
        failed.interfaces.clear();
        state.record_interfaces(failed);
    }
    state.record_interfaces(good);
    assert!(state.events().is_empty());
}

fn connected(ssid: &str, bssid: &str) -> crosswalk::collect::wifi::AccessPoint {
    crosswalk::collect::wifi::AccessPoint {
        in_use: true,
        ..access_point(Some(ssid), bssid, 70)
    }
}

fn wifi_list(state: &mut AppState, points: Vec<crosswalk::collect::wifi::AccessPoint>) {
    state.record_wifi(crosswalk::collect::wifi::WifiSnapshot::Available(points));
}

#[test]
fn the_first_wifi_reading_logs_nothing() {
    let mut state = events_state();
    wifi_list(&mut state, vec![connected("Home", "aa:aa:aa:aa:aa:01")]);
    assert!(state.events().is_empty());
}

#[test]
fn roaming_within_a_network_and_moving_to_another_each_log_once() {
    use crosswalk::events::{EventKind, EventLevel};
    let mut state = events_state();
    wifi_list(&mut state, vec![connected("Home", "aa:aa:aa:aa:aa:01")]);
    wifi_list(&mut state, vec![connected("Home", "aa:aa:aa:aa:aa:02")]);
    wifi_list(&mut state, vec![connected("Home", "aa:aa:aa:aa:aa:02")]);
    assert_eq!(
        event_texts(&state),
        vec!["Wi-Fi roamed on Home: aa:aa:aa:aa:aa:01 -> aa:aa:aa:aa:aa:02"]
    );
    wifi_list(&mut state, vec![connected("Office", "bb:bb:bb:bb:bb:01")]);
    assert_eq!(
        event_texts(&state)[0],
        "Wi-Fi moved from Home (aa:aa:aa:aa:aa:02) to Office (bb:bb:bb:bb:bb:01)"
    );
    assert_eq!(state.events().len(), 2);
    assert!(
        state
            .events()
            .iter()
            .all(|e| e.kind == EventKind::Connection && e.level == EventLevel::Normal)
    );
}

#[test]
fn losing_the_connection_and_regaining_the_same_access_point_logs_twice() {
    let mut state = events_state();
    wifi_list(&mut state, vec![connected("Home", "aa:aa:aa:aa:aa:01")]);
    wifi_list(
        &mut state,
        vec![access_point(Some("Home"), "aa:aa:aa:aa:aa:01", 70)],
    );
    wifi_list(&mut state, vec![connected("Home", "aa:aa:aa:aa:aa:01")]);
    assert_eq!(
        event_texts(&state),
        vec![
            "Wi-Fi connected to Home (aa:aa:aa:aa:aa:01)",
            "Wi-Fi disconnected from Home (aa:aa:aa:aa:aa:01)"
        ]
    );
}

#[test]
fn an_unavailable_wifi_snapshot_between_two_identical_ones_logs_nothing() {
    use crosswalk::collect::wifi::WifiSnapshot;
    let mut state = events_state();
    wifi_list(&mut state, vec![connected("Home", "aa:aa:aa:aa:aa:01")]);
    state.record_wifi(WifiSnapshot::Unavailable("nmcli failed".to_owned()));
    wifi_list(&mut state, vec![connected("Home", "aa:aa:aa:aa:aa:01")]);
    assert!(state.events().is_empty());
    // A failed first reading is not the baseline.
    let mut state = events_state();
    state.record_wifi(WifiSnapshot::Unavailable("nmcli failed".to_owned()));
    wifi_list(&mut state, vec![connected("Home", "aa:aa:aa:aa:aa:01")]);
    assert!(state.events().is_empty());
}

fn on_interface(
    interface: &str,
    address: &str,
    mac: Option<&str>,
) -> crosswalk::collect::neighbors::Neighbor {
    crosswalk::collect::neighbors::Neighbor {
        interface: interface.to_owned(),
        ..neighbour_with(address, mac)
    }
}

fn devices_of(state: &AppState) -> Vec<(String, String, Vec<String>, bool)> {
    state
        .devices()
        .map(|d| {
            (
                d.interface.clone(),
                d.mac.clone(),
                d.addresses.iter().map(|a| a.to_string()).collect(),
                d.present,
            )
        })
        .collect()
}

#[test]
fn an_ipv4_and_an_ipv6_entry_with_one_hardware_address_are_one_device() {
    let mut state = unknown_state();
    seen(
        &mut state,
        vec![
            neighbour_with("fe80::1", Some("aa:aa:aa:aa:aa:aa")),
            neighbour_with("10.0.1.2", Some("aa:aa:aa:aa:aa:aa")),
        ],
    );
    assert_eq!(
        devices_of(&state),
        [(
            "eth0".to_owned(),
            "aa:aa:aa:aa:aa:aa".to_owned(),
            vec!["10.0.1.2".to_owned(), "fe80::1".to_owned()],
            true
        )]
    );
}

#[test]
fn an_entry_without_a_hardware_address_is_no_device() {
    let mut state = unknown_state();
    seen(&mut state, vec![neighbour_with("10.0.1.2", None)]);
    assert!(devices_of(&state).is_empty());
}

#[test]
fn a_device_missing_from_the_next_snapshot_is_kept_absent_and_present_again_when_it_returns() {
    let mut state = unknown_state();
    seen(
        &mut state,
        vec![
            neighbour_with("10.0.1.2", Some("aa:aa:aa:aa:aa:aa")),
            neighbour_with("10.0.1.3", Some("bb:bb:bb:bb:bb:bb")),
        ],
    );
    seen(
        &mut state,
        vec![neighbour_with("10.0.1.3", Some("bb:bb:bb:bb:bb:bb"))],
    );
    let presence = |state: &AppState| -> Vec<(String, bool)> {
        state
            .devices()
            .map(|d| (d.mac.clone(), d.present))
            .collect()
    };
    assert_eq!(
        presence(&state),
        [
            ("aa:aa:aa:aa:aa:aa".to_owned(), false),
            ("bb:bb:bb:bb:bb:bb".to_owned(), true)
        ]
    );
    seen(&mut state, Vec::new());
    assert!(state.devices().all(|d| !d.present));
    seen(
        &mut state,
        vec![neighbour_with("10.0.1.9", Some("aa:aa:aa:aa:aa:aa"))],
    );
    let first = state.devices().next().unwrap();
    assert!(first.present);
    let addresses: Vec<_> = first.addresses.iter().map(|a| a.to_string()).collect();
    assert_eq!(addresses, ["10.0.1.9"]);
}

#[test]
fn a_listed_device_has_the_addresses_of_the_latest_snapshot_and_an_absent_one_its_last() {
    let mut state = unknown_state();
    let mac = Some("aa:aa:aa:aa:aa:aa");
    seen(
        &mut state,
        vec![
            neighbour_with("10.0.1.2", mac),
            neighbour_with("2001:db8::1", mac),
            neighbour_with("2001:db8::2", mac),
        ],
    );
    seen(
        &mut state,
        vec![
            neighbour_with("10.0.1.7", mac),
            neighbour_with("2001:db8::2", mac),
        ],
    );
    let addresses = |state: &AppState| devices_of(state).remove(0).2;
    assert_eq!(addresses(&state), ["10.0.1.7", "2001:db8::2"]);
    seen(&mut state, Vec::new());
    assert_eq!(addresses(&state), ["10.0.1.7", "2001:db8::2"]);
}

#[test]
fn an_unreadable_snapshot_marks_nothing_absent() {
    use crosswalk::collect::neighbors::NeighborSnapshot;
    let mut state = unknown_state();
    seen(
        &mut state,
        vec![neighbour_with("10.0.1.2", Some("aa:aa:aa:aa:aa:aa"))],
    );
    state.record_neighbors(NeighborSnapshot::Unavailable("ip failed".to_owned()));
    assert!(state.devices().all(|d| d.present));
    assert_eq!(state.devices().count(), 1);
}

#[test]
fn devices_are_kept_per_interface() {
    let mut state = unknown_state();
    seen(
        &mut state,
        vec![
            on_interface("wlan0", "10.0.1.2", Some("aa:aa:aa:aa:aa:aa")),
            on_interface("eth0", "192.168.1.2", Some("aa:aa:aa:aa:aa:aa")),
        ],
    );
    seen(
        &mut state,
        vec![on_interface(
            "eth0",
            "192.168.1.2",
            Some("aa:aa:aa:aa:aa:aa"),
        )],
    );
    let found: Vec<_> = state
        .devices()
        .map(|d| (d.interface.as_str(), d.present, d.addresses.len()))
        .collect();
    assert_eq!(found, [("eth0", true, 1), ("wlan0", false, 1)]);
}

#[test]
fn past_4096_devices_a_new_one_is_not_kept_but_a_known_one_still_updates() {
    let mac = |n: u32| format!("02:00:00:00:{:02x}:{:02x}", n / 256, n % 256);
    let address = |n: u32| format!("10.2.{}.{}", n / 250, n % 250 + 1);
    let mut state = unknown_state();
    let full: Vec<_> = (0..4_096)
        .map(|n| neighbour_with(&address(n), Some(&mac(n))))
        .collect();
    seen(&mut state, full.clone());
    let mut next = full;
    next.push(neighbour_with("10.9.9.9", Some(&mac(4_096))));
    next[0] = neighbour_with("10.8.8.8", Some(&mac(0)));
    seen(&mut state, next);
    assert_eq!(state.devices().count(), 4_096);
    assert!(state.devices().all(|d| d.mac != mac(4_096)));
    let first = state.devices().find(|d| d.mac == mac(0)).unwrap();
    assert!(first.addresses.contains(&"10.8.8.8".parse().unwrap()));
}

fn history_of(state: &AppState) -> Vec<(u64, u64)> {
    state.app_traffic()[0]
        .history
        .iter()
        .map(|s| (s.download, s.upload))
        .collect()
}

fn inbound_from(host: &str, bytes: u32) -> TrafficEvent {
    traffic(
        Direction::Inbound,
        Protocol::Tcp,
        (host, 443),
        ("192.0.2.10", 5000),
        bytes,
    )
}

#[test]
fn app_history_sums_its_destinations_in_the_same_second() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let a = process("/opt/a", 1);
    state.record_traffic(secs(13), inbound_from("198.51.100.1", 400), Some(a.clone()));
    state.record_traffic(secs(13), inbound_from("198.51.100.2", 400), Some(a));
    assert_eq!(history_of(&state)[119], (800, 0));
}

#[test]
fn app_history_puts_bytes_from_a_hundred_seconds_ago_at_their_second() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let a = process("/opt/a", 1);
    state.record_traffic(secs(10), inbound_from("198.51.100.1", 5), Some(a.clone()));
    state.record_traffic(secs(110), inbound_from("198.51.100.2", 7), Some(a));
    let history = history_of(&state);
    assert_eq!(history.len(), 120);
    assert_eq!(history[119], (7, 0));
    assert_eq!(history[19], (5, 0));
    assert_eq!(history.iter().filter(|s| **s != (0, 0)).count(), 2);
}

#[test]
fn app_history_drops_bytes_older_than_two_minutes() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let a = process("/opt/a", 1);
    state.record_traffic(secs(10), inbound_from("198.51.100.1", 5), Some(a.clone()));
    state.record_traffic(secs(130), inbound_from("198.51.100.2", 7), Some(a));
    assert_eq!(history_of(&state)[119], (7, 0));
    assert!(history_of(&state)[..119].iter().all(|s| *s == (0, 0)));
}

#[test]
fn app_history_is_empty_after_two_idle_minutes() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_traffic(
        secs(10),
        inbound_from("198.51.100.1", 5),
        Some(process("/opt/a", 1)),
    );
    state.advance_time(secs(130));
    assert_eq!(history_of(&state), vec![(0, 0); 120]);
}

#[test]
fn app_history_keeps_download_and_upload_apart() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let a = process("/opt/a", 1);
    state.record_traffic(
        secs(10),
        out(5000, "198.51.100.1", 443, 30),
        Some(a.clone()),
    );
    state.record_traffic(secs(10), inbound_from("198.51.100.1", 90), Some(a));
    assert_eq!(history_of(&state)[119], (90, 30));
}

#[test]
fn the_capture_status_keeps_which_source_it_came_from() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_capture_status(CaptureStatus {
        health: CaptureHealth::Available,
        dropped: 0,
        origin: CaptureOrigin::Dumpcap,
    });
    let status = state.source_health().capture.clone().unwrap();
    assert_eq!(status.origin, CaptureOrigin::Dumpcap);
}

#[test]
fn with_no_firewall_no_switched_event_and_no_exposure_event_is_recorded() {
    let mut state = events_state();
    state.record_listeners(
        vec![owned_listener(
            Protocol::Tcp,
            "0.0.0.0",
            22,
            "/usr/bin/sshd",
        )],
        EPHEMERAL,
    );
    state.record_rules(RuleSnapshot::NoFirewall);
    state.record_rules(RuleSnapshot::NoFirewall);
    state.record_listeners(
        vec![
            owned_listener(Protocol::Tcp, "0.0.0.0", 22, "/usr/bin/sshd"),
            owned_listener(Protocol::Tcp, "0.0.0.0", 8080, "/usr/bin/app"),
        ],
        EPHEMERAL,
    );
    state.record_listeners(
        vec![owned_listener(
            Protocol::Tcp,
            "127.0.0.1",
            8080,
            "/usr/bin/app",
        )],
        EPHEMERAL,
    );
    state.record_rules(RuleSnapshot::NoFirewall);
    let texts = event_texts(&state);
    assert!(
        texts
            .iter()
            .all(|text| !text.contains("UFW") && !text.contains(" exposure ")),
        "{texts:?}"
    );
    assert!(
        texts.contains(&"tcp 0.0.0.0:8080 app started listening, unknown".to_owned()),
        "{texts:?}"
    );
    assert!(
        levels(&state)
            .iter()
            .all(|l| *l == crosswalk::events::EventLevel::Normal)
    );
}

#[test]
fn recent_drops_are_the_sum_of_those_reported_within_ten_seconds_of_now() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let report = |state: &mut AppState, at: u64, dropped: u64| {
        state.advance_time(Duration::from_secs(at));
        state.record_capture_status(CaptureStatus {
            health: CaptureHealth::Available,
            dropped,
            origin: CaptureOrigin::Own,
        });
    };
    report(&mut state, 10, 3);
    report(&mut state, 15, 4);
    assert_eq!(state.recent_drops(), 7);

    state.advance_time(Duration::from_secs(19));
    assert_eq!(state.recent_drops(), 7);
    state.advance_time(Duration::from_secs(20));
    assert_eq!(state.recent_drops(), 4);
    state.advance_time(Duration::from_secs(25));
    assert_eq!(state.recent_drops(), 0);
}

#[test]
fn listening_ports_follow_the_zones_of_the_interfaces_the_state_holds() {
    use crosswalk::{
        collect::interfaces::InterfaceAddress,
        firewall::{
            Allowed, Zone, Zones,
            firewalld_reply::{PortRule, Target},
        },
    };
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let mut interfaces = snapshot("eth0", 1.0, 1.0);
    interfaces.interfaces[0].addresses = vec![InterfaceAddress {
        ip: "192.168.1.5".parse().unwrap(),
        prefix: 24,
    }];
    state.record_interfaces(interfaces);
    state.record_listeners(
        vec![
            listener(Protocol::Tcp, "0.0.0.0", 22),
            listener(Protocol::Tcp, "192.168.1.5", 23),
            listener(Protocol::Tcp, "10.9.9.9", 24),
        ],
        EPHEMERAL,
    );
    let ssh = |port| {
        Allowed::Port(PortRule {
            ports: port..=port,
            protocol: "tcp".to_owned(),
        })
    };
    state.record_rules(RuleSnapshot::Zones(Zones {
        default_zone: "public".to_owned(),
        zones: vec![Zone {
            name: "public".to_owned(),
            interfaces: vec!["eth0".to_owned()],
            sources: vec![],
            target: Target::Default,
            allowed: vec![ssh(22), ssh(23), ssh(24)],
            rich_rules: vec![],
        }],
    }));
    let seen: Vec<_> = state
        .listening_ports()
        .iter()
        .map(|p| (p.listener.port, p.exposure.clone()))
        .collect();
    assert_eq!(
        seen,
        vec![
            (22, Exposure::Open(None)),
            (23, Exposure::Open(None)),
            // No interface holds 10.9.9.9, so it is judged as listening on every interface.
            (24, Exposure::Open(None)),
        ]
    );
}

fn port_of_zones(state: &mut AppState) -> Exposure {
    use crosswalk::firewall::{Zone, Zones, firewalld_reply::Target};
    state.record_listeners(vec![listener(Protocol::Tcp, "0.0.0.0", 22)], EPHEMERAL);
    state.record_rules(RuleSnapshot::Zones(Zones {
        default_zone: "public".to_owned(),
        zones: vec![Zone {
            name: "public".to_owned(),
            interfaces: vec!["eth0".to_owned()],
            sources: Vec::new(),
            target: Target::Default,
            allowed: Vec::new(),
            rich_rules: Vec::new(),
        }],
    }));
    state.listening_ports().remove(0).exposure
}

#[test]
fn zones_without_an_interface_reading_leave_exposure_unknown_not_blocked() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    assert!(matches!(port_of_zones(&mut state), Exposure::Unknown(_)));
}

#[test]
fn zones_with_an_interface_reading_that_failed_leave_exposure_unknown() {
    for health in [
        CollectionHealth::Unavailable("gone".to_owned()),
        CollectionHealth::Stale("gone".to_owned()),
    ] {
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let mut failed = snapshot("eth0", 0.0, 0.0);
        failed.health = health;
        state.record_interfaces(failed);
        assert!(matches!(port_of_zones(&mut state), Exposure::Unknown(_)));
    }
}

#[test]
fn zones_with_a_readable_interface_reading_judge_the_port() {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let mut reading = snapshot("eth0", 0.0, 0.0);
    reading.interfaces[0].addresses = vec![crosswalk::collect::interfaces::InterfaceAddress {
        ip: "192.168.1.5".parse().unwrap(),
        prefix: 24,
    }];
    state.record_interfaces(reading);
    assert_eq!(port_of_zones(&mut state), Exposure::Blocked(None));
}

/// `eth0` is in a zone that lets port 22 in and `eth1`, with an address, is in one that does not.
fn wildcard_port_with_a_second_interface(second_is_up: bool) -> Exposure {
    use crosswalk::{
        collect::interfaces::InterfaceAddress,
        firewall::{
            Allowed, Zone, Zones,
            firewalld_reply::{PortRule, Target},
        },
    };
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let mut reading = snapshot("eth0", 0.0, 0.0);
    let mut second = reading.interfaces[0].clone();
    second.name = "eth1".to_owned();
    second.is_up = second_is_up;
    for (interface, ip) in reading
        .interfaces
        .iter_mut()
        .chain([&mut second])
        .zip(["10.0.0.5", "10.0.1.5"])
    {
        interface.addresses = vec![InterfaceAddress {
            ip: ip.parse().unwrap(),
            prefix: 24,
        }];
    }
    reading.interfaces.push(second);
    state.record_interfaces(reading);
    state.record_listeners(vec![listener(Protocol::Tcp, "0.0.0.0", 22)], EPHEMERAL);
    let zone = |name: &str, allowed| Zone {
        name: name.to_owned(),
        interfaces: vec![format!("eth{}", usize::from(name == "work"))],
        sources: Vec::new(),
        target: Target::Default,
        allowed,
        rich_rules: Vec::new(),
    };
    let ssh = Allowed::Port(PortRule {
        ports: 22..=22,
        protocol: "tcp".to_owned(),
    });
    state.record_rules(RuleSnapshot::Zones(Zones {
        default_zone: "public".to_owned(),
        zones: vec![zone("public", vec![ssh]), zone("work", Vec::new())],
    }));
    state.listening_ports().remove(0).exposure
}

#[test]
fn an_interface_that_is_administratively_down_is_left_out_of_a_wildcard_ports_judgement() {
    assert_eq!(
        wildcard_port_with_a_second_interface(false),
        Exposure::Open(None)
    );
}

#[test]
fn an_interface_that_is_up_without_carrier_keeps_its_zone_in_the_judgement() {
    // Carrier is not read at all: an unplugged interface that is up is `is_up`.
    assert_eq!(
        wildcard_port_with_a_second_interface(true),
        Exposure::Limited(None)
    );
}

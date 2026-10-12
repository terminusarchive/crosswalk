use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use crosswalk::collect::interfaces::InterfaceAddress;
use crosswalk::collect::interfaces::{
    CollectionHealth, InterfaceCounterCollector, InterfaceCounters, InterfaceSnapshot,
    InterfaceSource, InterfaceStatus, LinuxInterfaceSource,
};

struct SequenceSource {
    snapshots: VecDeque<io::Result<Vec<InterfaceCounters>>>,
}

impl SequenceSource {
    fn new(snapshots: Vec<io::Result<Vec<InterfaceCounters>>>) -> Self {
        Self {
            snapshots: snapshots.into(),
        }
    }
}

impl InterfaceSource for SequenceSource {
    fn read_interfaces(&mut self) -> io::Result<Vec<InterfaceCounters>> {
        self.snapshots
            .pop_front()
            .expect("test should provide a snapshot")
    }
}

fn counters(name: &str, address: [u8; 4], received: u64, transmitted: u64) -> InterfaceCounters {
    InterfaceCounters {
        name: name.to_owned(),
        addresses: vec![InterfaceAddress {
            ip: IpAddr::V4(Ipv4Addr::from(address)),
            prefix: 24,
        }],
        is_up: true,
        received_bytes: received,
        transmitted_bytes: transmitted,
    }
}

#[test]
fn samples_rates_from_elapsed_time_and_accumulates_session_totals() {
    let source = SequenceSource::new(vec![
        Ok(vec![counters("eth0", [192, 0, 2, 10], 1_000, 2_000)]),
        Ok(vec![counters("eth0", [192, 0, 2, 10], 1_600, 2_400)]),
    ]);
    let mut collector = InterfaceCounterCollector::new(source);

    let baseline = collector.sample(Duration::from_secs(4));
    assert_eq!(baseline.health, CollectionHealth::Available);
    assert_eq!(baseline.interfaces[0].download_bytes_per_second, 0.0);
    assert_eq!(baseline.interfaces[0].upload_bytes_per_second, 0.0);
    assert_eq!(baseline.interfaces[0].session_received_bytes, 0);
    assert_eq!(baseline.interfaces[0].session_transmitted_bytes, 0);

    let measured = collector.sample(Duration::from_secs(6));
    assert_eq!(measured.interfaces[0].download_bytes_per_second, 300.0);
    assert_eq!(measured.interfaces[0].upload_bytes_per_second, 200.0);
    assert_eq!(measured.interfaces[0].session_received_bytes, 600);
    assert_eq!(measured.interfaces[0].session_transmitted_bytes, 400);
}

#[test]
fn resets_and_reappearance_preserve_totals_without_synthetic_rates() {
    let source = SequenceSource::new(vec![
        Ok(vec![counters("eth0", [192, 0, 2, 10], 1_000, 2_000)]),
        Ok(vec![counters("eth0", [192, 0, 2, 10], 1_600, 2_400)]),
        Ok(vec![counters("eth0", [192, 0, 2, 10], 100, 50)]),
        Ok(vec![]),
        Ok(vec![counters("eth0", [192, 0, 2, 20], 300, 250)]),
        Ok(vec![counters("eth0", [192, 0, 2, 20], 500, 650)]),
    ]);
    let mut collector = InterfaceCounterCollector::new(source);

    collector.sample(Duration::from_secs(0));
    collector.sample(Duration::from_secs(2));

    let reset = collector.sample(Duration::from_secs(3));
    assert_eq!(reset.interfaces[0].download_bytes_per_second, 0.0);
    assert_eq!(reset.interfaces[0].upload_bytes_per_second, 0.0);
    assert_eq!(reset.interfaces[0].session_received_bytes, 600);
    assert_eq!(reset.interfaces[0].session_transmitted_bytes, 400);

    let missing = collector.sample(Duration::from_secs(4));
    assert_eq!(missing.interfaces[0].status, InterfaceStatus::Missing);
    assert_eq!(missing.interfaces[0].session_received_bytes, 600);
    assert_eq!(missing.interfaces[0].session_transmitted_bytes, 400);

    let reappeared = collector.sample(Duration::from_secs(5));
    assert_eq!(reappeared.interfaces[0].status, InterfaceStatus::Available);
    assert_eq!(
        reappeared.interfaces[0].addresses,
        vec![InterfaceAddress {
            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
            prefix: 24,
        }]
    );
    assert_eq!(reappeared.interfaces[0].download_bytes_per_second, 0.0);
    assert_eq!(reappeared.interfaces[0].upload_bytes_per_second, 0.0);
    assert_eq!(reappeared.interfaces[0].session_received_bytes, 600);
    assert_eq!(reappeared.interfaces[0].session_transmitted_bytes, 400);

    let measured = collector.sample(Duration::from_secs(7));
    assert_eq!(measured.interfaces[0].download_bytes_per_second, 100.0);
    assert_eq!(measured.interfaces[0].upload_bytes_per_second, 200.0);
    assert_eq!(measured.interfaces[0].session_received_bytes, 800);
    assert_eq!(measured.interfaces[0].session_transmitted_bytes, 800);
}

#[test]
fn read_errors_distinguish_unavailable_from_stale_measurements() {
    let source = SequenceSource::new(vec![
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
        Ok(vec![counters("eth0", [192, 0, 2, 10], 100, 200)]),
        Ok(vec![counters("eth0", [192, 0, 2, 10], 300, 500)]),
        Err(io::Error::other("read failed")),
    ]);
    let mut collector = InterfaceCounterCollector::new(source);

    let unavailable = collector.sample(Duration::from_secs(0));
    assert_eq!(
        unavailable.health,
        CollectionHealth::Unavailable("denied".to_owned())
    );
    assert!(unavailable.interfaces.is_empty());

    collector.sample(Duration::from_secs(1));
    let available = collector.sample(Duration::from_secs(3));
    let stale = collector.sample(Duration::from_secs(4));

    assert_eq!(
        stale.health,
        CollectionHealth::Stale("read failed".to_owned())
    );
    assert_eq!(stale.interfaces, available.interfaces);
}

const ROUTE_HEADER: &str =
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";

fn route_row(name: &str, destination: &str, metric: u32) -> String {
    route_row_via(name, destination, "0101000A", metric)
}

fn route_row_via(name: &str, destination: &str, gateway: &str, metric: u32) -> String {
    format!("{name}\t{destination}\t{gateway}\t0003\t0\t0\t{metric}\t00000000\t0\t0\t0\n")
}

fn linux_snapshot(route_table: Option<String>) -> InterfaceSnapshot {
    linux_snapshot_with_resolver(route_table, None)
}

fn linux_snapshot_with_resolver(
    route_table: Option<String>,
    resolver: Option<&str>,
) -> InterfaceSnapshot {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "crosswalk-routes-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let counters = dir.join("dev");
    std::fs::write(
        &counters,
        "Inter-|   Receive\n face |bytes packets\n\
         lo: 10 0 0 0 0 0 0 0 10 0 0 0 0 0 0 0\n\
         eth0: 20 0 0 0 0 0 0 0 30 0 0 0 0 0 0 0\n\
         wlan0: 40 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0\n",
    )
    .unwrap();
    let route = dir.join("route");
    if let Some(table) = route_table {
        std::fs::write(&route, table).unwrap();
    }
    let resolver_path = dir.join("resolv.conf");
    if let Some(contents) = resolver {
        std::fs::write(&resolver_path, contents).unwrap();
    }
    let mut collector = InterfaceCounterCollector::new(
        LinuxInterfaceSource::with_paths(counters, route).with_resolver_path(resolver_path),
    );
    collector.sample(Duration::from_secs(0))
}

#[test]
fn default_route_picks_the_lowest_metric_default_row() {
    let table = format!(
        "{ROUTE_HEADER}{}{}{}",
        route_row("eth0", "00000000", 600),
        route_row("wlan0", "00000000", 100),
        route_row("eth0", "0001000A", 1),
    );
    let snapshot = linux_snapshot(Some(table));
    assert_eq!(snapshot.default_route.as_deref(), Some("wlan0"));
}

#[test]
fn default_route_falls_back_to_the_first_non_loopback_interface() {
    let table = format!("{ROUTE_HEADER}{}", route_row("wlan0", "0001000A", 100));
    let snapshot = linux_snapshot(Some(table));
    assert_eq!(snapshot.default_route.as_deref(), Some("eth0"));
}

#[test]
fn unreadable_route_table_leaves_the_counters_working() {
    let snapshot = linux_snapshot(None);
    assert_eq!(snapshot.health, CollectionHealth::Available);
    assert_eq!(snapshot.interfaces.len(), 3);
    assert_eq!(snapshot.default_route.as_deref(), Some("eth0"));
}

#[test]
fn gateway_is_that_of_the_default_route_the_collector_picks() {
    let table = format!(
        "{ROUTE_HEADER}{}{}{}",
        route_row_via("eth0", "00000000", "0201A8C0", 600),
        route_row_via("wlan0", "00000000", "0101000A", 100),
        route_row_via("eth0", "0001000A", "0301A8C0", 1),
    );
    let snapshot = linux_snapshot(Some(table));
    assert_eq!(snapshot.default_route.as_deref(), Some("wlan0"));
    assert_eq!(snapshot.gateway, Some(Ipv4Addr::new(10, 0, 1, 1)));
}

#[test]
fn a_zero_gateway_means_none() {
    let table = format!(
        "{ROUTE_HEADER}{}",
        route_row_via("wlan0", "00000000", "00000000", 100)
    );
    let snapshot = linux_snapshot(Some(table));
    assert_eq!(snapshot.default_route.as_deref(), Some("wlan0"));
    assert_eq!(snapshot.gateway, None);
}

#[test]
fn no_default_row_means_no_gateway() {
    let table = format!("{ROUTE_HEADER}{}", route_row("wlan0", "0001000A", 100));
    assert_eq!(linux_snapshot(Some(table)).gateway, None);
}

#[test]
fn name_server_is_the_first_nameserver_line() {
    let snapshot = linux_snapshot_with_resolver(
        None,
        Some(
            "# Generated by NetworkManager\n; nameserver 1.1.1.1\n\n# nameserver 9.9.9.9\n\
             search lan\nnameserver\t10.0.1.6\nnameserver 10.0.1.7\n",
        ),
    );
    assert_eq!(
        snapshot.name_server,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 6)))
    );
}

#[test]
fn name_server_skips_values_that_are_not_addresses_and_drops_a_scope_id() {
    let snapshot = linux_snapshot_with_resolver(
        None,
        Some(
            "nameserver\nnameserver example.org\nnameserver   fe80::1%wlan0\nnameserver 10.0.1.6\n",
        ),
    );
    assert_eq!(snapshot.name_server, Some("fe80::1".parse().unwrap()));
}

#[test]
fn no_nameserver_line_means_no_name_server() {
    let snapshot = linux_snapshot_with_resolver(None, Some("# nothing\nsearch lan\n"));
    assert_eq!(snapshot.name_server, None);
}

#[test]
fn unreadable_resolver_file_leaves_the_counters_working() {
    let snapshot = linux_snapshot_with_resolver(None, None);
    assert_eq!(snapshot.health, CollectionHealth::Available);
    assert_eq!(snapshot.interfaces.len(), 3);
    assert_eq!(snapshot.name_server, None);
}

#[test]
fn addresses_from_the_source_come_through_per_interface_with_their_prefixes() {
    let v6 = InterfaceAddress {
        ip: "fe80::1".parse().unwrap(),
        prefix: 64,
    };
    let mut wlan0 = counters("wlan0", [10, 0, 1, 13], 1, 2);
    wlan0.addresses.push(v6);
    let eth0 = counters("eth0", [192, 168, 1, 5], 3, 4);
    let mut collector =
        InterfaceCounterCollector::new(SequenceSource::new(vec![Ok(vec![wlan0, eth0])]));
    let snapshot = collector.sample(Duration::from_secs(0));
    let by_name = |name: &str| {
        snapshot
            .interfaces
            .iter()
            .find(|interface| interface.name == name)
            .unwrap()
            .addresses
            .clone()
    };
    assert_eq!(
        by_name("wlan0"),
        vec![
            InterfaceAddress {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 13)),
                prefix: 24
            },
            v6
        ]
    );
    assert_eq!(by_name("eth0")[0].prefix, 24);
    assert_eq!(by_name("eth0").len(), 1);
}

#[test]
fn an_unreadable_resolver_file_or_route_table_keeps_the_last_known_values() {
    let dir = std::env::temp_dir().join(format!("crosswalk-unreadable-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (counters, route, resolver) = (dir.join("dev"), dir.join("route"), dir.join("resolv"));
    std::fs::write(
        &counters,
        "Inter-|   Receive\n face |bytes packets\n\
         wlan0: 40 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0\n",
    )
    .unwrap();
    std::fs::write(
        &route,
        format!("{ROUTE_HEADER}{}", route_row("wlan0", "00000000", 100)),
    )
    .unwrap();
    std::fs::write(&resolver, "nameserver 10.0.1.6\n").unwrap();
    let mut collector = InterfaceCounterCollector::new(
        LinuxInterfaceSource::with_paths(&counters, &route).with_resolver_path(&resolver),
    );
    let first = collector.sample(Duration::from_secs(0));
    assert_eq!(first.gateway, Some(Ipv4Addr::new(10, 0, 1, 1)));
    assert!(first.name_server.is_some());

    std::fs::remove_file(&route).unwrap();
    std::fs::remove_file(&resolver).unwrap();
    let unreadable = collector.sample(Duration::from_secs(1));
    assert_eq!(unreadable.name_server, first.name_server);
    assert_eq!(unreadable.gateway, first.gateway);
    assert_eq!(unreadable.default_route, first.default_route);

    std::fs::write(&route, ROUTE_HEADER).unwrap();
    std::fs::write(&resolver, "search lan\n").unwrap();
    let empty = collector.sample(Duration::from_secs(2));
    assert_eq!(empty.name_server, None);
    assert_eq!(empty.gateway, None);
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn name_servers_are_every_nameserver_line_in_file_order() {
    let snapshot = linux_snapshot_with_resolver(
        None,
        Some("nameserver 10.0.1.6\nsearch lan\nnameserver 1.1.1.1\nnameserver 2606:4700::1111\n"),
    );
    assert_eq!(
        snapshot.name_servers,
        vec![ip("10.0.1.6"), ip("1.1.1.1"), ip("2606:4700::1111")]
    );
    assert_eq!(snapshot.name_server, Some(ip("10.0.1.6")));
}

#[test]
fn name_servers_skip_comments_and_non_addresses_and_drop_a_scope_id() {
    let snapshot = linux_snapshot_with_resolver(
        None,
        Some(
            "# nameserver 9.9.9.9\n; nameserver 8.8.8.8\nnameserver\nnameserver example.org\n\
             nameserver   fe80::1%wlan0\nnameserver 10.0.1.6\n",
        ),
    );
    assert_eq!(snapshot.name_servers, vec![ip("fe80::1"), ip("10.0.1.6")]);
}

#[test]
fn an_unreadable_resolver_file_keeps_the_last_name_servers_and_an_empty_one_clears_them() {
    let dir = std::env::temp_dir().join(format!("crosswalk-ns-list-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (counters, route, resolver) = (dir.join("dev"), dir.join("route"), dir.join("resolv"));
    std::fs::write(
        &counters,
        "Inter-|   Receive\n face |bytes packets\n\
         wlan0: 40 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0\n",
    )
    .unwrap();
    std::fs::write(&route, ROUTE_HEADER).unwrap();
    std::fs::write(&resolver, "nameserver 10.0.1.6\nnameserver 1.1.1.1\n").unwrap();
    let mut collector = InterfaceCounterCollector::new(
        LinuxInterfaceSource::with_paths(&counters, &route).with_resolver_path(&resolver),
    );
    let first = collector.sample(Duration::from_secs(0));
    assert_eq!(first.name_servers, vec![ip("10.0.1.6"), ip("1.1.1.1")]);

    std::fs::remove_file(&resolver).unwrap();
    let unreadable = collector.sample(Duration::from_secs(1));
    assert_eq!(unreadable.name_servers, first.name_servers);
    assert_eq!(unreadable.name_server, Some(ip("10.0.1.6")));

    std::fs::write(&resolver, "search lan\n").unwrap();
    let empty = collector.sample(Duration::from_secs(2));
    assert!(empty.name_servers.is_empty());
    assert_eq!(empty.name_server, None);
}

#[test]
fn an_interface_the_collector_was_told_is_down_is_carried_as_down_and_back_up() {
    let down = |is_up| InterfaceCounters {
        is_up,
        ..counters("eth0", [192, 0, 2, 10], 1, 1)
    };
    let source = SequenceSource::new(vec![Ok(vec![down(false)]), Ok(vec![down(true)])]);
    let mut collector = InterfaceCounterCollector::new(source);
    let first = collector.sample(Duration::from_secs(0));
    assert!(!first.interfaces[0].is_up);
    let second = collector.sample(Duration::from_secs(1));
    assert!(second.interfaces[0].is_up);
}

#[test]
fn the_system_flags_decide_up_and_an_interface_it_does_not_list_is_not_taken_for_down() {
    let dir = std::env::temp_dir().join(format!("crosswalk-flags-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let counters = dir.join("dev");
    std::fs::write(
        &counters,
        "Inter-|   Receive\n face |bytes packets\n\
         lo: 10 0 0 0 0 0 0 0 10 0 0 0 0 0 0 0\n\
         nosuch9: 20 0 0 0 0 0 0 0 30 0 0 0 0 0 0 0\n",
    )
    .unwrap();
    let mut collector = InterfaceCounterCollector::new(LinuxInterfaceSource::with_paths(
        &counters,
        dir.join("route"),
    ));
    let snapshot = collector.sample(Duration::from_secs(0));
    let is_up = |name: &str| {
        let found = snapshot.interfaces.iter().find(|i| i.name == name);
        found.unwrap().is_up
    };
    assert!(
        is_up("lo"),
        "loopback is administratively up on the test machine"
    );
    assert!(is_up("nosuch9"));
}

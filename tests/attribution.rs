use std::{
    fs, io,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    time::Duration,
};

use crosswalk::collect::{
    attribution::{
        AttributionCollector, AttributionHealth, LinuxProcfsSource, Listener, NoOwner,
        NoOwnerCause, OwnerMemory,
    },
    capture::{DecodeLimitation, Direction, Endpoint, Protocol, TrafficEvent},
};

struct ProcFixture {
    root: PathBuf,
}

impl ProcFixture {
    fn new(namespace: u64) -> Self {
        let root = std::env::temp_dir().join(format!(
            "crosswalk-attribution-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("self/ns")).unwrap();
        symlink(format!("net:[{namespace}]"), root.join("self/ns/net")).unwrap();
        fs::create_dir_all(root.join("net")).unwrap();
        for table in ["tcp", "tcp6", "udp", "udp6"] {
            fs::write(root.join("net").join(table), "header\n").unwrap();
        }
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write_table(&self, table: &str, rows: &[&str]) {
        fs::write(
            self.root.join("net").join(table),
            format!("header\n{}", rows.join("\n")),
        )
        .unwrap();
    }

    fn process(&self, pid: u32, start_time: u64, namespace: u64, executable: &str, inodes: &[u64]) {
        let process = self.root.join(pid.to_string());
        fs::create_dir_all(process.join("fd")).unwrap();
        fs::create_dir_all(process.join("ns")).unwrap();
        fs::write(
            process.join("stat"),
            format!("{pid} (test process) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start_time} 0\n"),
        )
        .unwrap();
        symlink(executable, process.join("exe")).unwrap();
        symlink(format!("net:[{namespace}]"), process.join("ns/net")).unwrap();
        for inode in inodes {
            symlink(
                format!("socket:[{inode}]"),
                process.join("fd").join(inode.to_string()),
            )
            .unwrap();
        }
    }

    fn flatpak_info(&self, pid: u32, text: &str) {
        let root = self.root.join(pid.to_string()).join("root");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".flatpak-info"), text).unwrap();
    }

    fn remove_process(&self, pid: u32) {
        fs::remove_dir_all(self.root.join(pid.to_string())).unwrap();
    }
}

impl Drop for ProcFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn socket_row(local: &str, remote: &str, inode: u64) -> String {
    format!("0: {local} {remote} 01 00000000:00000000 00:00000000 00000000 0 0 {inode}")
}

fn event(source: (&str, u16), destination: (&str, u16), protocol: Protocol) -> TrafficEvent {
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
        direction: Direction::Outbound,
        original_ip_bytes: 64,
        limitation: None::<DecodeLimitation>,
        tcp_flags: None,
        timing: None,
    }
}

#[test]
fn attributes_ipv4_and_ipv6_tcp_udp_without_collapsing_executable_identity() {
    let fixture = ProcFixture::new(77);
    let tcp = socket_row("0A0200C0:C000", "146433C6:01BB", 101);
    let udp = socket_row("0A0200C0:14E9", "357100CB:0035", 102);
    let tcp6 = socket_row(
        "B80D0120000000000000000001000000:C350",
        "B80D0120000000000000000002000000:20FB",
        103,
    );
    let udp6 = socket_row(
        "B80D0120000000000000000001000000:EA60",
        "B80D0120000000000000000003000000:0035",
        104,
    );
    fixture.write_table("tcp", &[&tcp]);
    fixture.write_table("udp", &[&udp]);
    fixture.write_table("tcp6", &[&tcp6]);
    fixture.write_table("udp6", &[&udp6]);
    fixture.process(100, 10, 77, "/opt/tools/client", &[101]);
    fixture.process(101, 11, 77, "/opt/tools/client", &[102]);
    fixture.process(102, 12, 77, "/opt/a/bin/agent", &[103]);
    fixture.process(103, 13, 77, "/srv/b/bin/agent", &[104]);

    let mut collector = AttributionCollector::new(
        LinuxProcfsSource::new(fixture.path()),
        Duration::from_secs(2),
        128,
    )
    .unwrap();
    let status = collector.refresh(Duration::from_secs(1));
    assert_eq!(status.health, AttributionHealth::Available);

    let ipv4_tcp = collector
        .attribute(
            &event(
                ("192.0.2.10", 49_152),
                ("198.51.100.20", 443),
                Protocol::Tcp,
            ),
            Duration::from_secs(1),
        )
        .owner
        .unwrap();
    let ipv4_udp = collector
        .attribute(
            &event(("192.0.2.10", 5353), ("203.0.113.53", 53), Protocol::Udp),
            Duration::from_secs(1),
        )
        .owner
        .unwrap();
    let ipv6_tcp = collector
        .attribute(
            &event(
                ("2001:db8::1", 50_000),
                ("2001:db8::2", 8443),
                Protocol::Tcp,
            ),
            Duration::from_secs(1),
        )
        .owner
        .unwrap();
    let ipv6_udp = collector
        .attribute(
            &event(("2001:db8::1", 60_000), ("2001:db8::3", 53), Protocol::Udp),
            Duration::from_secs(1),
        )
        .owner
        .unwrap();

    assert_eq!(ipv4_tcp.pid, 100);
    assert_eq!(ipv4_tcp.start_time, 10);
    assert_eq!(ipv4_tcp.executable, ipv4_udp.executable);
    assert_eq!(ipv6_tcp.executable.path, PathBuf::from("/opt/a/bin/agent"));
    assert_eq!(ipv6_udp.executable.path, PathBuf::from("/srv/b/bin/agent"));
    assert_ne!(ipv6_tcp.executable, ipv6_udp.executable);
}

#[test]
fn unavailable_ambiguous_exited_wrong_namespace_and_stale_snapshots_stay_unknown() {
    let fixture = ProcFixture::new(77);
    let shared = socket_row("0A0200C0:C001", "146433C6:01BB", 201);
    let exited = socket_row("0A0200C0:C002", "146433C6:01BB", 202);
    let wrong_namespace = socket_row("0A0200C0:C003", "146433C6:01BB", 203);
    let reusable = socket_row("0A0200C0:C004", "146433C6:01BB", 204);
    fixture.write_table("tcp", &[&shared, &exited, &wrong_namespace, &reusable]);
    fixture.process(200, 20, 77, "/opt/one", &[201]);
    fixture.process(201, 21, 77, "/opt/two", &[201]);
    fixture.process(202, 22, 88, "/opt/wrong-namespace", &[203]);
    fixture.process(203, 23, 77, "/opt/old", &[204]);

    let mut collector = AttributionCollector::new(
        LinuxProcfsSource::new(fixture.path()),
        Duration::from_secs(2),
        128,
    )
    .unwrap();
    collector.refresh(Duration::from_secs(1));

    for port in [49_153, 49_154, 49_155] {
        assert!(
            collector
                .attribute(
                    &event(("192.0.2.10", port), ("198.51.100.20", 443), Protocol::Tcp,),
                    Duration::from_secs(1),
                )
                .owner
                .is_none()
        );
    }

    let old = collector
        .attribute(
            &event(
                ("192.0.2.10", 49_156),
                ("198.51.100.20", 443),
                Protocol::Tcp,
            ),
            Duration::from_secs(1),
        )
        .owner
        .unwrap();
    fixture.remove_process(203);
    fixture.process(203, 99, 77, "/opt/new", &[204]);
    collector.refresh(Duration::from_secs(2));
    let reused = collector
        .attribute(
            &event(
                ("192.0.2.10", 49_156),
                ("198.51.100.20", 443),
                Protocol::Tcp,
            ),
            Duration::from_secs(2),
        )
        .owner
        .unwrap();
    assert_eq!(old.start_time, 23);
    assert_eq!(reused.start_time, 99);
    assert_ne!(old, reused);

    fs::remove_file(fixture.path().join("net/tcp")).unwrap();
    let stale = collector.refresh(Duration::from_secs(3));
    assert!(matches!(stale.health, AttributionHealth::Stale(_)));
    let result = collector.attribute(
        &event(
            ("192.0.2.10", 49_156),
            ("198.51.100.20", 443),
            Protocol::Tcp,
        ),
        Duration::from_secs(3),
    );
    assert!(result.owner.is_none());
    assert!(matches!(result.health, AttributionHealth::Stale(_)));

    let missing = fixture.path().join("missing");
    let mut unavailable = AttributionCollector::new(
        LinuxProcfsSource::new(&missing),
        Duration::from_secs(2),
        128,
    )
    .unwrap();
    let status = unavailable.refresh(Duration::ZERO);
    assert!(matches!(status.health, AttributionHealth::Unavailable(_)));
}

#[test]
fn wildcard_matching_requires_one_best_owner_and_snapshot_storage_is_bounded() {
    let fixture = ProcFixture::new(77);
    let wildcard = socket_row("00000000:1F90", "00000000:0000", 301);
    fixture.write_table("tcp", &[&wildcard]);
    fixture.process(300, 30, 77, "/opt/server", &[301]);

    let request = event(
        ("192.0.2.10", 8080),
        ("198.51.100.20", 50_000),
        Protocol::Tcp,
    );
    let mut collector = AttributionCollector::new(
        LinuxProcfsSource::new(fixture.path()),
        Duration::from_secs(2),
        128,
    )
    .unwrap();
    collector.refresh(Duration::ZERO);
    assert_eq!(
        collector
            .attribute(&request, Duration::ZERO)
            .owner
            .unwrap()
            .pid,
        300
    );

    let conflicting = socket_row("00000000:1F90", "00000000:0000", 302);
    fixture.write_table("tcp", &[&wildcard, &conflicting]);
    fixture.process(301, 31, 77, "/opt/other-server", &[302]);
    collector.refresh(Duration::from_secs(1));
    assert!(
        collector
            .attribute(&request, Duration::from_secs(1))
            .owner
            .is_none()
    );

    let exact = socket_row("0A0200C0:1F90", "146433C6:C350", 303);
    fixture.write_table("tcp", &[&wildcard, &exact]);
    fixture.process(302, 32, 77, "/opt/exact-server", &[303]);
    collector.refresh(Duration::from_secs(2));
    assert_eq!(
        collector
            .attribute(&request, Duration::from_secs(2))
            .owner
            .unwrap()
            .pid,
        302
    );
}

#[test]
fn rejects_zero_snapshot_capacity() {
    let fixture = ProcFixture::new(77);
    let error = AttributionCollector::new(
        LinuxProcfsSource::new(fixture.path()),
        Duration::from_secs(2),
        0,
    )
    .err()
    .expect("zero capacity must be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

fn socket_row_in_state(local: &str, remote: &str, state: &str, inode: u64) -> String {
    format!("0: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 0 0 {inode}")
}

fn listeners_of(fixture: &ProcFixture) -> Vec<Listener> {
    let mut collector = AttributionCollector::new(
        LinuxProcfsSource::new(fixture.path()),
        Duration::from_secs(5),
        64,
    )
    .unwrap();
    collector.refresh(Duration::ZERO);
    collector.listeners().expect("a reading succeeded")
}

const NO_PEER4: &str = "00000000:0000";
const NO_PEER6: &str = "00000000000000000000000000000000:0000";

#[test]
fn listeners_tell_listening_tcp_from_connected_tcp() {
    let fixture = ProcFixture::new(81);
    let listening = socket_row_in_state("0100007F:1F90", NO_PEER4, "0A", 201);
    let connected = socket_row_in_state("0A0200C0:C000", "146433C6:01BB", "01", 202);
    fixture.write_table("tcp", &[&listening, &connected]);
    fixture.process(300, 5, 81, "/usr/bin/web", &[201]);
    fixture.process(301, 6, 81, "/usr/bin/client", &[202]);

    let listeners = listeners_of(&fixture);

    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].protocol, Protocol::Tcp);
    assert_eq!(
        listeners[0].address,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(listeners[0].port, 8080);
    assert_eq!(listeners[0].owners.len(), 1);
    assert_eq!(listeners[0].owners[0].pid, 300);
}

#[test]
fn listeners_include_bound_udp_but_not_connected_udp() {
    let fixture = ProcFixture::new(82);
    let bound = socket_row_in_state("00000000:0035", NO_PEER4, "07", 211);
    let connected = socket_row_in_state("0A0200C0:14E9", "357100CB:0035", "01", 212);
    fixture.write_table("udp", &[&bound, &connected]);

    let listeners = listeners_of(&fixture);

    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].protocol, Protocol::Udp);
    assert_eq!(listeners[0].port, 53);
}

#[test]
fn listeners_include_ipv6_sockets() {
    let fixture = ProcFixture::new(83);
    let tcp6 = socket_row_in_state("00000000000000000000000001000000:0016", NO_PEER6, "0A", 221);
    let udp6 = socket_row_in_state("00000000000000000000000000000000:0044", NO_PEER6, "07", 222);
    fixture.write_table("tcp6", &[&tcp6]);
    fixture.write_table("udp6", &[&udp6]);

    let listeners = listeners_of(&fixture);

    assert_eq!(listeners.len(), 2);
    let tcp = listeners
        .iter()
        .find(|l| l.protocol == Protocol::Tcp)
        .unwrap();
    assert_eq!(tcp.address, "::1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(tcp.port, 22);
    let udp = listeners
        .iter()
        .find(|l| l.protocol == Protocol::Udp)
        .unwrap();
    assert_eq!(udp.address, "::".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(udp.port, 68);
}

#[test]
fn listener_without_a_readable_owner_has_no_app() {
    let fixture = ProcFixture::new(84);
    let listening = socket_row_in_state("00000000:0050", NO_PEER4, "0A", 231);
    fixture.write_table("tcp", &[&listening]);

    let listeners = listeners_of(&fixture);

    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].port, 80);
    assert!(listeners[0].owners.is_empty());
}

#[test]
fn identical_listeners_collapse_and_keep_every_owner() {
    let fixture = ProcFixture::new(85);
    let first = socket_row_in_state("00000000:0050", NO_PEER4, "0A", 241);
    let second = socket_row_in_state("00000000:0050", NO_PEER4, "0A", 242);
    fixture.write_table("tcp", &[&first, &second]);
    fixture.process(310, 7, 85, "/usr/bin/web", &[241]);
    fixture.process(311, 8, 85, "/usr/bin/web", &[242]);

    let listeners = listeners_of(&fixture);

    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].owners.len(), 2);
}

const CONN_LOCAL: &str = "0A0200C0:C010";
const CONN_REMOTE: &str = "146433C6:01BB";

fn conn_event() -> TrafficEvent {
    event(
        ("192.0.2.10", 49_168),
        ("198.51.100.20", 443),
        Protocol::Tcp,
    )
}

fn memory_collector(fixture: &ProcFixture, capacity: usize) -> AttributionCollector {
    AttributionCollector::new(
        LinuxProcfsSource::new(fixture.path()),
        Duration::from_secs(1_000),
        capacity,
    )
    .unwrap()
}

fn owner_at(collector: &AttributionCollector, seconds: u64) -> Option<u32> {
    collector
        .attribute(&conn_event(), Duration::from_secs(seconds))
        .owner
        .map(|owner| owner.pid)
}

#[test]
fn a_connection_keeps_its_owner_after_the_socket_loses_it_or_leaves_the_table() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));
    assert_eq!(owner_at(&collector, 1), Some(300));

    // The app closed its fd; the socket is still listed with inode 0.
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 0)]);
    fixture.remove_process(300);
    fixture.process(300, 30, 77, "/opt/app", &[]);
    collector.refresh(Duration::from_secs(2));
    assert_eq!(owner_at(&collector, 2), Some(300));

    // The socket has left the table altogether.
    fixture.write_table("tcp", &[]);
    collector.refresh(Duration::from_secs(3));
    assert_eq!(owner_at(&collector, 3), Some(300));
}

#[test]
fn a_connection_never_seen_owned_has_no_owner() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 0)]);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));
    assert_eq!(owner_at(&collector, 1), None);
    fixture.write_table("tcp", &[]);
    collector.refresh(Duration::from_secs(2));
    assert_eq!(owner_at(&collector, 2), None);
}

#[test]
fn a_new_socket_on_the_same_endpoints_belongs_to_its_own_owner() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));

    fixture.remove_process(300);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 302)]);
    fixture.process(310, 31, 77, "/opt/other", &[302]);
    collector.refresh(Duration::from_secs(2));
    assert_eq!(owner_at(&collector, 2), Some(310));

    // Once that socket is gone too, the newer owner is the remembered one.
    fixture.write_table("tcp", &[]);
    collector.refresh(Duration::from_secs(3));
    assert_eq!(owner_at(&collector, 3), Some(310));
}

#[test]
fn a_remembered_owner_is_forgotten_120_seconds_after_the_socket_was_last_seen_owned() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(10));
    fixture.write_table("tcp", &[]);
    collector.refresh(Duration::from_secs(20));
    assert_eq!(owner_at(&collector, 130), Some(300));
    assert_eq!(owner_at(&collector, 131), None);
}

#[test]
fn a_full_memory_drops_its_oldest_entry() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    let mut collector = memory_collector(&fixture, 1);
    collector.refresh(Duration::from_secs(1));

    fixture.write_table("tcp", &[&socket_row("0A0200C0:C011", CONN_REMOTE, 302)]);
    fixture.process(310, 31, 77, "/opt/other", &[302]);
    collector.refresh(Duration::from_secs(2));
    fixture.write_table("tcp", &[]);
    collector.refresh(Duration::from_secs(3));

    assert_eq!(owner_at(&collector, 3), None);
    let newer = event(
        ("192.0.2.10", 49_169),
        ("198.51.100.20", 443),
        Protocol::Tcp,
    );
    let owner = collector
        .attribute(&newer, Duration::from_secs(3))
        .owner
        .map(|owner| owner.pid);
    assert_eq!(owner, Some(310));
}

#[test]
fn a_remembered_owner_is_not_used_while_attribution_is_stale() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    let mut collector = AttributionCollector::new(
        LinuxProcfsSource::new(fixture.path()),
        Duration::from_secs(2),
        128,
    )
    .unwrap();
    collector.refresh(Duration::from_secs(1));
    fixture.write_table("tcp", &[]);
    collector.refresh(Duration::from_secs(2));
    assert_eq!(owner_at(&collector, 2), Some(300));

    // Too old a snapshot.
    let aged = collector.attribute(&conn_event(), Duration::from_secs(10));
    assert!(matches!(aged.health, AttributionHealth::Stale(_)));
    assert!(aged.owner.is_none());

    // A failed refresh.
    fs::remove_file(fixture.path().join("net/tcp")).unwrap();
    collector.refresh(Duration::from_secs(3));
    let failed = collector.attribute(&conn_event(), Duration::from_secs(3));
    assert!(matches!(failed.health, AttributionHealth::Stale(_)));
    assert!(failed.owner.is_none());
}

fn explain_at(collector: &AttributionCollector, seconds: u64) -> Option<NoOwner> {
    collector.explain(&conn_event(), Duration::from_secs(seconds))
}

fn cause_at(collector: &AttributionCollector, seconds: u64) -> NoOwnerCause {
    explain_at(collector, seconds).expect("unowned").cause
}

#[test]
fn an_owned_packet_has_no_reason() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));
    assert_eq!(explain_at(&collector, 1), None);
}

#[test]
fn reason_no_socket_matches() {
    let fixture = ProcFixture::new(77);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));
    let reason = explain_at(&collector, 1).unwrap();
    assert_eq!(reason.cause, NoOwnerCause::NoSocket);
    assert_eq!(reason.memory, OwnerMemory::Never);
}

#[test]
fn reason_best_socket_has_no_process_gives_its_state_and_inode() {
    let fixture = ProcFixture::new(77);
    // Established (01), no process holds inode 0, and inode 555 has no
    // readable holder.
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 0)]);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));
    assert_eq!(
        cause_at(&collector, 1),
        NoOwnerCause::SocketWithoutProcess {
            protocol: Protocol::Tcp,
            state: 0x01,
            inode: 0,
            sockets: 1
        }
    );
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 555)]);
    collector.refresh(Duration::from_secs(2));
    assert_eq!(
        cause_at(&collector, 2),
        NoOwnerCause::SocketWithoutProcess {
            protocol: Protocol::Tcp,
            state: 0x01,
            inode: 555,
            sockets: 1
        }
    );
}

#[test]
fn reason_best_socket_has_several_owners_gives_how_many() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/a", &[301]);
    fixture.process(310, 31, 77, "/opt/b", &[301]);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));
    assert_eq!(cause_at(&collector, 1), NoOwnerCause::SeveralOwners(2));
}

#[test]
fn reason_not_tcp_udp_or_no_ports() {
    let fixture = ProcFixture::new(77);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));
    let mut icmp = conn_event();
    icmp.protocol = Protocol::Other(1);
    assert_eq!(
        collector
            .explain(&icmp, Duration::from_secs(1))
            .unwrap()
            .cause,
        NoOwnerCause::NotTcpUdp
    );
    let mut portless = conn_event();
    portless.source.port = None;
    assert_eq!(
        collector
            .explain(&portless, Duration::from_secs(1))
            .unwrap()
            .cause,
        NoOwnerCause::NotTcpUdp
    );
}

#[test]
fn reason_attribution_unavailable_or_stale() {
    let fixture = ProcFixture::new(77);
    let mut collector = AttributionCollector::new(
        LinuxProcfsSource::new(fixture.path()),
        Duration::from_secs(2),
        128,
    )
    .unwrap();
    assert!(matches!(
        cause_at(&collector, 1),
        NoOwnerCause::Unavailable(_)
    ));
    collector.refresh(Duration::from_secs(1));
    assert!(matches!(cause_at(&collector, 10), NoOwnerCause::Stale(_)));
}

#[test]
fn an_expired_remembered_owner_is_reported_with_its_age() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(10));
    fixture.write_table("tcp", &[]);
    // Refreshes after the 120 seconds are up must not erase the fact.
    collector.refresh(Duration::from_secs(20));
    collector.refresh(Duration::from_secs(200));
    let reason = explain_at(&collector, 200).unwrap();
    assert_eq!(reason.cause, NoOwnerCause::NoSocket);
    assert_eq!(
        reason.memory,
        OwnerMemory::Expired(Duration::from_secs(190))
    );
}

#[test]
fn snapshot_stats_count_sockets_processes_and_skipped_processes() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    fixture.process(310, 31, 99, "/opt/other-ns", &[]);
    fixture.process(320, 32, 77, "/opt/no-fd", &[]);
    fs::remove_dir_all(fixture.path().join("320/fd")).unwrap();
    let mut collector = memory_collector(&fixture, 128);
    assert!(collector.snapshot_stats().is_none());
    collector.refresh(Duration::from_secs(1));
    let stats = collector.snapshot_stats().unwrap();
    assert_eq!(stats.sockets, 1);
    assert_eq!(stats.processes_read, 1);
    assert_eq!(stats.skipped_other_namespace, 1);
    assert_eq!(stats.skipped_unreadable, 1);
}

#[test]
fn a_process_with_an_unreadable_descriptor_still_owns_its_other_sockets() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    // A descriptor that is not a readable link, as when it closes mid-read.
    fs::write(fixture.path().join("300/fd/9"), "").unwrap();
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));
    assert_eq!(owner_at(&collector, 1), Some(300));
    assert_eq!(collector.snapshot_stats().unwrap().processes_read, 1);
}

#[test]
fn a_process_without_an_executable_is_counted_apart_from_unreadable_ones() {
    let fixture = ProcFixture::new(77);
    fixture.write_table("tcp", &[&socket_row(CONN_LOCAL, CONN_REMOTE, 301)]);
    fixture.process(300, 30, 77, "/opt/app", &[301]);
    fixture.process(320, 32, 77, "/kernel-thread", &[]);
    fs::remove_file(fixture.path().join("320/exe")).unwrap();
    let mut collector = memory_collector(&fixture, 128);
    collector.refresh(Duration::from_secs(1));
    let stats = collector.snapshot_stats().unwrap();
    assert_eq!(stats.processes_read, 1);
    assert_eq!(stats.skipped_no_executable, 1);
    assert_eq!(stats.skipped_unreadable, 0);
}

#[test]
fn listeners_are_none_until_a_reading_has_succeeded() {
    let fixture = ProcFixture::new(82);
    let mut collector = AttributionCollector::new(
        LinuxProcfsSource::new(fixture.path().join("missing")),
        Duration::from_secs(5),
        64,
    )
    .unwrap();
    collector.refresh(Duration::ZERO);
    assert_eq!(collector.listeners(), None);
}

#[test]
fn a_process_in_a_flatpak_sandbox_carries_its_app_id() {
    let fixture = ProcFixture::new(91);
    let listening = socket_row_in_state("0100007F:1F90", NO_PEER4, "0A", 301);
    fixture.write_table("tcp", &[&listening]);
    fixture.process(400, 5, 91, "/app/bin/dropbox", &[301]);
    fixture.flatpak_info(
        400,
        "[Application]\nname=com.dropbox.Client\nruntime=runtime/x\n\n[Instance]\nname=other\n",
    );

    let listeners = listeners_of(&fixture);

    let app = listeners[0].owners[0].executable.flatpak_app.as_deref();
    assert_eq!(app, Some("com.dropbox.Client"));
}

#[test]
fn a_process_outside_a_sandbox_has_no_app_id() {
    let fixture = ProcFixture::new(92);
    let listening = socket_row_in_state("0100007F:1F90", NO_PEER4, "0A", 302);
    fixture.write_table("tcp", &[&listening]);
    fixture.process(401, 5, 92, "/usr/bin/web", &[302]);

    let listeners = listeners_of(&fixture);

    assert_eq!(listeners[0].owners[0].executable.flatpak_app, None);
}

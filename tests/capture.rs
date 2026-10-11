use std::{
    collections::{HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{atomic::AtomicBool, mpsc::sync_channel},
    time::{Duration, Instant, SystemTime},
};

use crosswalk::collect::capture::{
    CaptureHealth, CaptureNormalizer, CaptureSource, CaptureStatistics, CaptureWorker,
    DecodeLimitation, Direction, Endpoint, PacketRead, Protocol, SLL2_LINKTYPE, TcpFlags,
    TrafficEvent,
};

const PACKET_HOST: u8 = 0;
const PACKET_OUTGOING: u8 = 4;

fn sll2(interface_index: u32, packet_type: u8, protocol: u16, packet: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 20];
    frame[0..2].copy_from_slice(&protocol.to_be_bytes());
    frame[4..8].copy_from_slice(&interface_index.to_be_bytes());
    frame[10] = packet_type;
    frame.extend_from_slice(packet);
    frame
}

fn ipv4(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    fragment: u16,
    body: &[u8],
    original_length: u16,
) -> Vec<u8> {
    let mut packet = vec![0; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&original_length.to_be_bytes());
    packet[6..8].copy_from_slice(&fragment.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet.extend_from_slice(body);
    packet
}

fn ipv6(source: Ipv6Addr, destination: Ipv6Addr, next_header: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
    packet[6] = next_header;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet.extend_from_slice(body);
    packet
}

fn ports(source: u16, destination: u16) -> [u8; 8] {
    let mut header = [0; 8];
    header[0..2].copy_from_slice(&source.to_be_bytes());
    header[2..4].copy_from_slice(&destination.to_be_bytes());
    header
}

fn tcp(source: u16, destination: u16) -> [u8; 20] {
    let mut header = [0; 20];
    header[0..2].copy_from_slice(&source.to_be_bytes());
    header[2..4].copy_from_slice(&destination.to_be_bytes());
    header[12] = 5 << 4;
    header
}

fn locals(addresses: impl IntoIterator<Item = IpAddr>) -> HashSet<IpAddr> {
    addresses.into_iter().collect()
}

#[test]
fn normalizes_sll2_ipv4_tcp_and_ipv6_udp_metadata() {
    let local_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let local_v6 = IpAddr::V6("2001:db8::1".parse().unwrap());
    let mut normalizer = CaptureNormalizer::new(locals([local_v4, local_v6]));

    let outbound = sll2(
        7,
        PACKET_OUTGOING,
        0x0800,
        &ipv4(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            6,
            0,
            &tcp(49_152, 443),
            40,
        ),
    );
    let remote_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let incoming = sll2(
        9,
        PACKET_HOST,
        0x86dd,
        &ipv6(
            remote_v6,
            "2001:db8::1".parse().unwrap(),
            17,
            &ports(53, 5353),
        ),
    );

    assert_eq!(
        normalizer.normalize(&outbound),
        Some(TrafficEvent {
            source: Endpoint {
                ip: local_v4,
                port: Some(49_152),
            },
            destination: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
                port: Some(443),
            },
            protocol: Protocol::Tcp,
            direction: Direction::Outbound,
            original_ip_bytes: 40,
            limitation: None,
            tcp_flags: Some(TcpFlags {
                syn: false,
                ack: false,
                rst: false,
                fin: false,
                psh: false,
            }),
            timing: None,
        })
    );
    assert_eq!(
        normalizer.normalize(&incoming),
        Some(TrafficEvent {
            source: Endpoint {
                ip: IpAddr::V6(remote_v6),
                port: Some(53),
            },
            destination: Endpoint {
                ip: local_v6,
                port: Some(5353),
            },
            protocol: Protocol::Udp,
            direction: Direction::Inbound,
            original_ip_bytes: 48,
            limitation: None,
            tcp_flags: None,
            timing: None,
        })
    );
}

#[test]
fn excludes_forwarded_traffic_and_counts_loopback_once() {
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut normalizer = CaptureNormalizer::new(locals([loopback]));
    let forwarded = sll2(
        3,
        PACKET_HOST,
        0x0800,
        &ipv4(
            [198, 51, 100, 1],
            [203, 0, 113, 2],
            17,
            0,
            &ports(1000, 2000),
            28,
        ),
    );
    let loopback_packet = ipv4([127, 0, 0, 1], [127, 0, 0, 1], 6, 0, &tcp(50_000, 8080), 40);

    assert_eq!(normalizer.normalize(&forwarded), None);
    assert!(
        normalizer
            .normalize(&sll2(1, PACKET_OUTGOING, 0x0800, &loopback_packet))
            .is_some()
    );
    assert_eq!(
        normalizer.normalize(&sll2(1, PACKET_HOST, 0x0800, &loopback_packet)),
        None
    );
}

#[test]
fn decodes_tcp_flags_and_leaves_them_out_when_unknown() {
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut normalizer = CaptureNormalizer::new(locals([local]));
    let mut flagged = |flags: u8, packet_type: u8| {
        let mut header = tcp(5000, 80);
        header[13] = flags;
        let frame = sll2(
            2,
            packet_type,
            0x0800,
            &ipv4([10, 0, 0, 3], [10, 0, 0, 2], 6, 0, &header, 40),
        );
        normalizer.normalize(&frame).unwrap().tcp_flags
    };
    let flags = |syn, ack, rst| {
        Some(TcpFlags {
            syn,
            ack,
            rst,
            fin: false,
            psh: false,
        })
    };
    assert_eq!(flagged(0x02, PACKET_HOST), flags(true, false, false));
    assert_eq!(flagged(0x12, PACKET_HOST), flags(true, true, false));
    assert_eq!(flagged(0x14, PACKET_HOST), flags(false, true, true));

    let udp = sll2(
        2,
        PACKET_HOST,
        0x0800,
        &ipv4([10, 0, 0, 3], [10, 0, 0, 2], 17, 0, &ports(1, 2), 28),
    );
    assert_eq!(normalizer.normalize(&udp).unwrap().tcp_flags, None);

    // Header cut short by the capture length: ports but no flags byte.
    let cut = sll2(
        2,
        PACKET_HOST,
        0x0800,
        &ipv4([10, 0, 0, 3], [10, 0, 0, 2], 6, 0, &tcp(5000, 80)[..8], 40),
    );
    assert_eq!(normalizer.normalize(&cut).unwrap().tcp_flags, None);

    // First fragment: flags are not guessed.
    let mut header = tcp(5000, 80);
    header[13] = 0x02;
    let fragment = sll2(
        2,
        PACKET_HOST,
        0x0800,
        &ipv4([10, 0, 0, 3], [10, 0, 0, 2], 6, 0x2000, &header, 40),
    );
    assert_eq!(normalizer.normalize(&fragment).unwrap().tcp_flags, None);
}

#[test]
fn retains_knowable_metadata_for_truncation_fragments_extensions_and_other_protocols() {
    let local_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let local_v6: IpAddr = "fd00::2".parse().unwrap();
    let mut normalizer = CaptureNormalizer::new(locals([local_v4, local_v6]));
    let truncated = sll2(
        2,
        PACKET_OUTGOING,
        0x0800,
        &ipv4([10, 0, 0, 2], [10, 0, 0, 3], 6, 0, &[], 40),
    );
    let fragment = sll2(
        2,
        PACKET_OUTGOING,
        0x0800,
        &ipv4([10, 0, 0, 2], [10, 0, 0, 3], 17, 1, &[0; 8], 28),
    );
    let mut hop_by_hop_udp = vec![17, 0, 0, 0, 0, 0, 0, 0];
    hop_by_hop_udp.extend_from_slice(&ports(1234, 4321));
    let extension = sll2(
        5,
        PACKET_HOST,
        0x86dd,
        &ipv6(
            "fd00::3".parse().unwrap(),
            "fd00::2".parse().unwrap(),
            0,
            &hop_by_hop_udp,
        ),
    );
    let truncated_extension = sll2(
        5,
        PACKET_HOST,
        0x86dd,
        &ipv6(
            "fd00::3".parse().unwrap(),
            "fd00::2".parse().unwrap(),
            0,
            &[17],
        ),
    );
    let other = sll2(
        2,
        PACKET_OUTGOING,
        0x0800,
        &ipv4([10, 0, 0, 2], [10, 0, 0, 3], 1, 0, &[0; 8], 28),
    );

    let truncated = normalizer.normalize(&truncated).unwrap();
    assert_eq!(truncated.protocol, Protocol::Tcp);
    assert_eq!(truncated.source.port, None);
    assert_eq!(truncated.original_ip_bytes, 40);
    assert_eq!(truncated.limitation, Some(DecodeLimitation::Truncated));

    let fragment = normalizer.normalize(&fragment).unwrap();
    assert_eq!(fragment.protocol, Protocol::Udp);
    assert_eq!(fragment.source.port, None);
    assert_eq!(fragment.limitation, Some(DecodeLimitation::Fragment));

    let extension = normalizer.normalize(&extension).unwrap();
    assert_eq!(extension.protocol, Protocol::Udp);
    assert_eq!(extension.source.port, Some(1234));
    assert_eq!(extension.destination.port, Some(4321));
    assert_eq!(extension.limitation, None);

    let truncated_extension = normalizer.normalize(&truncated_extension).unwrap();
    assert_eq!(truncated_extension.protocol, Protocol::Udp);
    assert_eq!(truncated_extension.source.port, None);
    assert_eq!(
        truncated_extension.limitation,
        Some(DecodeLimitation::Truncated)
    );

    let other = normalizer.normalize(&other).unwrap();
    assert_eq!(other.protocol, Protocol::Other(1));
    assert_eq!(other.source.port, None);
    assert_eq!(other.limitation, None);
}

struct ScriptedSource {
    link_type: i32,
    reads: VecDeque<Result<PacketRead, String>>,
    statistics: Result<CaptureStatistics, String>,
}

impl CaptureSource for ScriptedSource {
    fn link_type(&self) -> i32 {
        self.link_type
    }

    fn next_packet(&mut self) -> Result<PacketRead, String> {
        self.reads.pop_front().unwrap_or(Ok(PacketRead::Idle))
    }

    fn statistics(&mut self) -> Result<CaptureStatistics, String> {
        self.statistics.clone()
    }
}

#[test]
fn capture_polling_reports_link_errors_capture_loss_queue_loss_and_cancellation() {
    let unsupported = ScriptedSource {
        link_type: 1,
        reads: VecDeque::new(),
        statistics: Ok(CaptureStatistics::default()),
    };
    let error = CaptureWorker::new(unsupported, HashSet::new(), 8)
        .err()
        .expect("Ethernet capture must be rejected");
    assert!(error.contains("Linux cooked v2 (SLL2)"));

    let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let packet = sll2(
        7,
        PACKET_OUTGOING,
        0x0800,
        &ipv4(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            17,
            0,
            &ports(1000, 2000),
            28,
        ),
    );
    let source = ScriptedSource {
        link_type: SLL2_LINKTYPE,
        reads: VecDeque::from([
            Ok(PacketRead::Packet {
                data: packet,
                captured_at: None,
            }),
            Err("capture read failed".to_owned()),
        ]),
        statistics: Ok(CaptureStatistics {
            received: 10,
            dropped: 3,
            interface_dropped: 2,
        }),
    };
    let mut worker = CaptureWorker::new(source, locals([local]), 8).unwrap();
    let (sender, receiver) = sync_channel(1);
    sender
        .send(TrafficEvent {
            source: Endpoint {
                ip: local,
                port: Some(1),
            },
            destination: Endpoint {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                port: Some(2),
            },
            protocol: Protocol::Udp,
            direction: Direction::Outbound,
            original_ip_bytes: 28,
            limitation: None,
            tcp_flags: None,
            timing: None,
        })
        .unwrap();

    let status = worker.poll(&sender, &AtomicBool::new(false));

    assert_eq!(
        status.health,
        CaptureHealth::Degraded("capture read failed".to_owned())
    );
    assert_eq!(status.capture_dropped, 5);
    assert_eq!(status.delivery_dropped, 1);
    assert_eq!(status.packets_read, 1);
    drop(receiver);

    let idle = ScriptedSource {
        link_type: SLL2_LINKTYPE,
        reads: VecDeque::new(),
        statistics: Ok(CaptureStatistics::default()),
    };
    let mut worker = CaptureWorker::new(idle, HashSet::new(), 8).unwrap();
    let (sender, _receiver) = sync_channel(1);
    let status = worker.poll(&sender, &AtomicBool::new(true));
    assert_eq!(status.health, CaptureHealth::Cancelled);
    assert_eq!(status.packets_read, 0);
}

#[test]
fn a_packet_read_carries_its_capture_lag_and_read_time() {
    let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let frame = sll2(
        7,
        PACKET_OUTGOING,
        0x0800,
        &ipv4(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            17,
            0,
            &ports(1000, 2000),
            28,
        ),
    );
    let captured = SystemTime::now() - Duration::from_millis(500);
    let source = ScriptedSource {
        link_type: SLL2_LINKTYPE,
        reads: VecDeque::from([
            Ok(PacketRead::Packet {
                data: frame.clone(),
                captured_at: Some(captured),
            }),
            Ok(PacketRead::Packet {
                data: frame,
                captured_at: None,
            }),
        ]),
        statistics: Ok(CaptureStatistics::default()),
    };
    let mut worker = CaptureWorker::new(source, locals([local]), 8).unwrap();
    let (sender, receiver) = sync_channel(8);
    let before = Instant::now();
    worker.poll(&sender, &AtomicBool::new(false));

    let stamped = receiver.try_recv().unwrap().timing.unwrap();
    let lag = stamped.lag.unwrap();
    assert!(lag >= Duration::from_millis(500) && lag < Duration::from_secs(5));
    assert!(stamped.read_at >= before);
    let unstamped = receiver.try_recv().unwrap().timing.unwrap();
    assert_eq!(unstamped.lag, None);
}

fn udp_v4(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    sll2(
        2,
        PACKET_HOST,
        0x0800,
        &ipv4(source, destination, 17, 0, &ports(1000, 2000), 28),
    )
}

fn udp_v6(source: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
    sll2(
        2,
        PACKET_HOST,
        0x86dd,
        &ipv6(source, destination, 17, &ports(1000, 2000)),
    )
}

#[test]
fn a_new_ipv4_address_makes_its_packets_this_machines() {
    let old = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let new = Ipv4Addr::new(10, 0, 0, 9);
    let mut normalizer = CaptureNormalizer::new(locals([old]));
    let to_new = udp_v4([198, 51, 100, 1], new.octets());
    let from_new = udp_v4(new.octets(), [198, 51, 100, 1]);

    assert_eq!(normalizer.normalize(&to_new), None);
    normalizer.set_local_addresses(locals([old, IpAddr::V4(new)]));

    assert_eq!(
        normalizer.normalize(&to_new).unwrap().direction,
        Direction::Inbound
    );
    assert_eq!(
        normalizer.normalize(&from_new).unwrap().direction,
        Direction::Outbound
    );
}

#[test]
fn a_new_ipv6_address_makes_its_packets_this_machines() {
    let old = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    let new = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);
    let other = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
    let mut normalizer = CaptureNormalizer::new(locals([old]));
    let to_new = udp_v6(other, new);
    let from_new = udp_v6(new, other);

    assert_eq!(normalizer.normalize(&to_new), None);
    normalizer.set_local_addresses(locals([old, IpAddr::V6(new)]));

    assert_eq!(
        normalizer.normalize(&to_new).unwrap().direction,
        Direction::Inbound
    );
    assert_eq!(
        normalizer.normalize(&from_new).unwrap().direction,
        Direction::Outbound
    );
}

#[test]
fn a_removed_address_no_longer_makes_packets_this_machines() {
    let gone = Ipv4Addr::new(10, 0, 0, 9);
    let mut normalizer = CaptureNormalizer::new(locals([IpAddr::V4(gone)]));
    let between_others = udp_v4([198, 51, 100, 1], gone.octets());

    assert!(normalizer.normalize(&between_others).is_some());
    normalizer.set_local_addresses(locals([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]));

    assert_eq!(normalizer.normalize(&between_others), None);
}

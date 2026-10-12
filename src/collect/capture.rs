use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, TrySendError},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const SLL2_LINKTYPE: i32 = 276;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Other(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeLimitation {
    Truncated,
    Fragment,
    UnsupportedExtension,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
}

/// The TCP flags the leave-out rules and the attribution log read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub rst: bool,
    pub fin: bool,
    pub psh: bool,
}

/// When the capture loop read a packet, and how long after the kernel
/// captured it. Only the attribution log reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadTiming {
    /// Kernel capture timestamp to the read; `None` when the source gave no
    /// timestamp or the clock stepped back.
    pub lag: Option<Duration>,
    pub read_at: Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficEvent {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub protocol: Protocol,
    pub direction: Direction,
    pub original_ip_bytes: u32,
    pub limitation: Option<DecodeLimitation>,
    /// None for other protocols, or when the TCP header is not fully known.
    pub tcp_flags: Option<TcpFlags>,
    /// Set by `CaptureWorker`; `None` from the normalizer alone.
    pub timing: Option<ReadTiming>,
}

impl TrafficEvent {
    /// The (local, remote) endpoints by direction.
    pub fn endpoints(&self) -> (Endpoint, Endpoint) {
        match self.direction {
            Direction::Outbound => (self.source, self.destination),
            Direction::Inbound => (self.destination, self.source),
        }
    }
}

pub struct CaptureNormalizer {
    local_addresses: HashSet<IpAddr>,
}

impl CaptureNormalizer {
    pub fn new(local_addresses: HashSet<IpAddr>) -> Self {
        Self { local_addresses }
    }

    /// Replaces the addresses that count as this machine's.
    pub fn set_local_addresses(&mut self, local_addresses: HashSet<IpAddr>) {
        self.local_addresses = local_addresses;
    }

    pub fn normalize(&mut self, frame: &[u8]) -> Option<TrafficEvent> {
        let header = frame.get(..20)?;
        let network_protocol = u16::from_be_bytes([header[0], header[1]]);
        let packet_type = header[10];
        let decoded = match network_protocol {
            0x0800 => decode_ipv4(&frame[20..])?,
            0x86dd => decode_ipv6(&frame[20..])?,
            _ => return None,
        };
        let source_is_local = self.local_addresses.contains(&decoded.source.ip);
        let destination_is_local = self.local_addresses.contains(&decoded.destination.ip);
        let direction = match (source_is_local, destination_is_local) {
            (true, false) => Direction::Outbound,
            (false, true) => Direction::Inbound,
            (true, true) if packet_type == 4 => Direction::Outbound,
            (true, true) => return None,
            (false, false) => return None,
        };

        Some(TrafficEvent {
            source: decoded.source,
            destination: decoded.destination,
            protocol: decoded.protocol,
            direction,
            original_ip_bytes: decoded.original_ip_bytes,
            limitation: decoded.limitation,
            tcp_flags: decoded.tcp_flags,
            timing: None,
        })
    }
}

struct DecodedIp {
    source: Endpoint,
    destination: Endpoint,
    protocol: Protocol,
    original_ip_bytes: u32,
    limitation: Option<DecodeLimitation>,
    tcp_flags: Option<TcpFlags>,
}

fn decode_ipv4(packet: &[u8]) -> Option<DecodedIp> {
    let fixed = packet.get(..20)?;
    if fixed[0] >> 4 != 4 {
        return None;
    }
    let header_length = usize::from(fixed[0] & 0x0f) * 4;
    if header_length < 20 || packet.len() < header_length {
        return None;
    }
    let original_ip_bytes = u16::from_be_bytes([fixed[2], fixed[3]]) as u32;
    if original_ip_bytes < header_length as u32 {
        return None;
    }
    let source_ip = IpAddr::V4(Ipv4Addr::new(fixed[12], fixed[13], fixed[14], fixed[15]));
    let destination_ip = IpAddr::V4(Ipv4Addr::new(fixed[16], fixed[17], fixed[18], fixed[19]));
    let fragment = u16::from_be_bytes([fixed[6], fixed[7]]);
    let is_fragment = fragment & 0x3fff != 0;
    let is_later_fragment = fragment & 0x1fff != 0;
    let protocol = protocol(fixed[9]);
    let ports = if is_later_fragment {
        None
    } else {
        decode_ports(protocol, packet.get(header_length..).unwrap_or_default())
    };
    let transport = packet.get(header_length..).unwrap_or_default();
    let limitation = if is_fragment {
        Some(DecodeLimitation::Fragment)
    } else if packet.len() < original_ip_bytes as usize
        || matches!(protocol, Protocol::Tcp | Protocol::Udp) && ports.is_none()
    {
        Some(DecodeLimitation::Truncated)
    } else {
        None
    };

    Some(decoded_ip(
        source_ip,
        destination_ip,
        protocol,
        ports,
        original_ip_bytes,
        limitation,
        transport,
    ))
}

fn decode_ipv6(packet: &[u8]) -> Option<DecodedIp> {
    let fixed = packet.get(..40)?;
    if fixed[0] >> 4 != 6 {
        return None;
    }
    let payload_length = u16::from_be_bytes([fixed[4], fixed[5]]) as u32;
    let original_ip_bytes = 40 + payload_length;
    let source_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&fixed[8..24]).ok()?));
    let destination_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&fixed[24..40]).ok()?));
    let mut next_header = fixed[6];
    let mut offset = 40usize;
    let mut fragment = false;
    let mut later_fragment = false;
    let mut unsupported_extension = false;

    let truncated = |next_header: u8| {
        Some(decoded_ip(
            source_ip,
            destination_ip,
            protocol(next_header),
            None,
            original_ip_bytes,
            Some(DecodeLimitation::Truncated),
            &[],
        ))
    };

    loop {
        match next_header {
            0 | 43 | 60 | 51 => {
                let authentication = next_header == 51;
                next_header = *packet.get(offset)?;
                let Some(length) = packet.get(offset + 1) else {
                    return truncated(next_header);
                };
                let length = usize::from(*length);
                let size = if authentication {
                    (length + 2) * 4
                } else {
                    (length + 1) * 8
                };
                offset = offset.checked_add(size)?;
                if offset > packet.len() {
                    return truncated(next_header);
                }
            }
            44 => {
                next_header = *packet.get(offset)?;
                let Some(extension) = packet.get(offset..offset + 8) else {
                    return truncated(next_header);
                };
                let fragment_field = u16::from_be_bytes([extension[2], extension[3]]);
                later_fragment = fragment_field & 0xfff8 != 0;
                fragment = true;
                offset += 8;
            }
            50 => {
                unsupported_extension = true;
                break;
            }
            _ => break,
        }
    }

    let protocol = protocol(next_header);
    let ports = if later_fragment || unsupported_extension {
        None
    } else {
        decode_ports(protocol, packet.get(offset..).unwrap_or_default())
    };
    let transport = packet.get(offset..).unwrap_or_default();
    let limitation = if fragment {
        Some(DecodeLimitation::Fragment)
    } else if unsupported_extension {
        Some(DecodeLimitation::UnsupportedExtension)
    } else if packet.len() < original_ip_bytes as usize
        || matches!(protocol, Protocol::Tcp | Protocol::Udp) && ports.is_none()
    {
        Some(DecodeLimitation::Truncated)
    } else {
        None
    };

    Some(decoded_ip(
        source_ip,
        destination_ip,
        protocol,
        ports,
        original_ip_bytes,
        limitation,
        transport,
    ))
}

fn protocol(number: u8) -> Protocol {
    match number {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        other => Protocol::Other(other),
    }
}

fn decode_ports(protocol: Protocol, bytes: &[u8]) -> Option<(u16, u16)> {
    if !matches!(protocol, Protocol::Tcp | Protocol::Udp) {
        return None;
    }
    let ports = bytes.get(..4)?;
    Some((
        u16::from_be_bytes([ports[0], ports[1]]),
        u16::from_be_bytes([ports[2], ports[3]]),
    ))
}

fn decoded_ip(
    source_ip: IpAddr,
    destination_ip: IpAddr,
    protocol: Protocol,
    ports: Option<(u16, u16)>,
    original_ip_bytes: u32,
    limitation: Option<DecodeLimitation>,
    transport: &[u8],
) -> DecodedIp {
    // Flags are only read from a whole, unfragmented packet; never guessed.
    let tcp_flags = match transport.get(13) {
        Some(&byte) if protocol == Protocol::Tcp && ports.is_some() && limitation.is_none() => {
            Some(TcpFlags {
                syn: byte & 0x02 != 0,
                ack: byte & 0x10 != 0,
                rst: byte & 0x04 != 0,
                fin: byte & 0x01 != 0,
                psh: byte & 0x08 != 0,
            })
        }
        _ => None,
    };
    DecodedIp {
        source: Endpoint {
            ip: source_ip,
            port: ports.map(|value| value.0),
        },
        destination: Endpoint {
            ip: destination_ip,
            port: ports.map(|value| value.1),
        },
        protocol,
        original_ip_bytes,
        limitation,
        tcp_flags,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaptureStatistics {
    pub received: u32,
    pub dropped: u32,
    pub interface_dropped: u32,
}

pub enum PacketRead {
    Packet {
        data: Vec<u8>,
        /// The kernel's capture timestamp, when the source has one.
        captured_at: Option<SystemTime>,
    },
    Idle,
}

pub trait CaptureSource {
    fn link_type(&self) -> i32;
    fn next_packet(&mut self) -> Result<PacketRead, String>;
    fn statistics(&mut self) -> Result<CaptureStatistics, String>;

    fn origin(&self) -> CaptureOrigin {
        CaptureOrigin::Own
    }
}

impl CaptureSource for Box<dyn CaptureSource> {
    fn link_type(&self) -> i32 {
        (**self).link_type()
    }

    fn next_packet(&mut self) -> Result<PacketRead, String> {
        (**self).next_packet()
    }

    fn statistics(&mut self) -> Result<CaptureStatistics, String> {
        (**self).statistics()
    }

    fn origin(&self) -> CaptureOrigin {
        (**self).origin()
    }
}

/// Where the packets come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureOrigin {
    Own,
    Dumpcap,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureHealth {
    Available,
    Degraded(String),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureStatus {
    pub health: CaptureHealth,
    pub packets_read: u64,
    pub capture_received: u32,
    pub capture_dropped: u32,
    pub delivery_dropped: u64,
    pub origin: CaptureOrigin,
}

pub struct CaptureWorker<S> {
    source: S,
    normalizer: CaptureNormalizer,
    batch_limit: usize,
    delivery_dropped: u64,
}

impl<S: CaptureSource> CaptureWorker<S> {
    pub fn new(
        source: S,
        local_addresses: HashSet<IpAddr>,
        batch_limit: usize,
    ) -> Result<Self, String> {
        if source.link_type() != SLL2_LINKTYPE {
            return Err(format!(
                "capture device must provide Linux cooked v2 (SLL2) link type {SLL2_LINKTYPE}; got {}",
                source.link_type()
            ));
        }
        if batch_limit == 0 {
            return Err("capture batch limit must be greater than zero".to_owned());
        }
        Ok(Self {
            source,
            normalizer: CaptureNormalizer::new(local_addresses),
            batch_limit,
            delivery_dropped: 0,
        })
    }

    pub fn set_local_addresses(&mut self, local_addresses: HashSet<IpAddr>) {
        self.normalizer.set_local_addresses(local_addresses);
    }

    pub fn poll(
        &mut self,
        sender: &SyncSender<TrafficEvent>,
        cancelled: &AtomicBool,
    ) -> CaptureStatus {
        if cancelled.load(Ordering::Relaxed) {
            return CaptureStatus {
                health: CaptureHealth::Cancelled,
                packets_read: 0,
                capture_received: 0,
                capture_dropped: 0,
                delivery_dropped: self.delivery_dropped,
                origin: self.source.origin(),
            };
        }

        let mut health = CaptureHealth::Available;
        let mut packets_read = 0;
        for _ in 0..self.batch_limit {
            if cancelled.load(Ordering::Relaxed) {
                health = CaptureHealth::Cancelled;
                break;
            }
            match self.source.next_packet() {
                Ok(PacketRead::Packet { data, captured_at }) => {
                    // The read: the moment `next_packet` returned.
                    let read_at = Instant::now();
                    let read_wall = SystemTime::now();
                    packets_read += 1;
                    if let Some(mut event) = self.normalizer.normalize(&data) {
                        event.timing = Some(ReadTiming {
                            lag: captured_at.and_then(|at| read_wall.duration_since(at).ok()),
                            read_at,
                        });
                        match sender.try_send(event) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                self.delivery_dropped = self.delivery_dropped.saturating_add(1);
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                health = CaptureHealth::Degraded(
                                    "capture event receiver disconnected".to_owned(),
                                );
                                break;
                            }
                        }
                    }
                }
                Ok(PacketRead::Idle) => break,
                Err(error) => {
                    health = CaptureHealth::Degraded(error);
                    break;
                }
            }
        }

        let statistics = match self.source.statistics() {
            Ok(statistics) => statistics,
            Err(error) => {
                if health == CaptureHealth::Available {
                    health = CaptureHealth::Degraded(error);
                }
                CaptureStatistics::default()
            }
        };
        CaptureStatus {
            health,
            packets_read,
            capture_received: statistics.received,
            capture_dropped: statistics
                .dropped
                .saturating_add(statistics.interface_dropped),
            delivery_dropped: self.delivery_dropped,
            origin: self.source.origin(),
        }
    }
}

pub struct PcapSource {
    capture: pcap::Capture<pcap::Active>,
    link_type: i32,
}

impl PcapSource {
    pub fn open_any() -> Result<Self, String> {
        let mut capture = pcap::Capture::from_device("any")
            .map_err(|error| format!("could not select libpcap 'any' device: {error}"))?
            .promisc(false)
            .timeout(100)
            .open()
            .map_err(|error| format!("could not open libpcap 'any' device: {error}"))?;
        capture
            .set_datalink(pcap::Linktype::LINUX_SLL2)
            .map_err(|error| {
                format!("libpcap 'any' does not support Linux cooked v2 (SLL2): {error}")
            })?;
        let capture = capture
            .setnonblock()
            .map_err(|error| format!("could not make libpcap capture nonblocking: {error}"))?;
        let link_type = capture.get_datalink().0;
        if link_type != SLL2_LINKTYPE {
            return Err(format!(
                "libpcap 'any' must provide Linux cooked v2 (SLL2) link type {SLL2_LINKTYPE}; got {link_type}"
            ));
        }
        Ok(Self { capture, link_type })
    }
}

/// Wall-clock time of a libpcap timestamp (microseconds).
fn timeval_time(seconds: i64, micros: i64) -> Option<SystemTime> {
    let seconds = u64::try_from(seconds).ok()?;
    let micros = u32::try_from(micros).ok()?;
    Some(UNIX_EPOCH + Duration::new(seconds, micros.checked_mul(1000)?))
}

impl CaptureSource for PcapSource {
    fn link_type(&self) -> i32 {
        self.link_type
    }

    fn next_packet(&mut self) -> Result<PacketRead, String> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(PacketRead::Packet {
                data: packet.data.to_vec(),
                captured_at: timeval_time(packet.header.ts.tv_sec, packet.header.ts.tv_usec),
            }),
            Err(pcap::Error::NoMorePackets | pcap::Error::TimeoutExpired) => Ok(PacketRead::Idle),
            Err(error) => Err(format!("libpcap capture read failed: {error}")),
        }
    }

    fn statistics(&mut self) -> Result<CaptureStatistics, String> {
        self.capture
            .stats()
            .map(|statistics| CaptureStatistics {
                received: statistics.received,
                dropped: statistics.dropped,
                interface_dropped: statistics.if_dropped,
            })
            .map_err(|error| format!("could not read libpcap capture statistics: {error}"))
    }
}

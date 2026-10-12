use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::CStr,
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    ptr,
    time::Duration,
};

/// An address on an interface with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceCounters {
    pub name: String,
    pub addresses: Vec<InterfaceAddress>,
    /// `IFF_UP` is set: not down by an administrator. Says nothing of carrier.
    pub is_up: bool,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
}

pub trait InterfaceSource {
    fn read_interfaces(&mut self) -> io::Result<Vec<InterfaceCounters>>;

    /// The IPv4 default route: `Ok(None)` when it was read and there is none,
    /// `Err` when it could not be read.
    fn default_route(&mut self) -> io::Result<Option<DefaultRoute>> {
        Ok(None)
    }

    /// The name servers the system is configured with, in order: empty when
    /// the configuration was read and holds none, `Err` when it could not be read.
    fn name_servers(&mut self) -> io::Result<Vec<IpAddr>> {
        Ok(Vec::new())
    }
}

/// The IPv4 default route: its interface and, when it has one, its gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultRoute {
    pub interface: String,
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollectionHealth {
    Available,
    Unavailable(String),
    Stale(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceStatus {
    Available,
    Missing,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InterfaceMeasurement {
    pub name: String,
    pub addresses: Vec<InterfaceAddress>,
    pub download_bytes_per_second: f64,
    pub upload_bytes_per_second: f64,
    pub session_received_bytes: u64,
    pub session_transmitted_bytes: u64,
    pub status: InterfaceStatus,
    pub is_up: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InterfaceSnapshot {
    pub health: CollectionHealth,
    pub interfaces: Vec<InterfaceMeasurement>,
    pub default_route: Option<String>,
    /// The default route's IPv4 gateway; absent when there is none or it cannot be read.
    pub gateway: Option<Ipv4Addr>,
    /// The first name server of the resolver configuration, if one can be read.
    pub name_server: Option<IpAddr>,
    /// Every name server of the resolver configuration, in file order; the
    /// first is `name_server`.
    pub name_servers: Vec<IpAddr>,
}

struct InterfaceState {
    measurement: InterfaceMeasurement,
    last_received_bytes: u64,
    last_transmitted_bytes: u64,
    last_sampled_at: Duration,
}

pub struct InterfaceCounterCollector<S> {
    source: S,
    interfaces: BTreeMap<String, InterfaceState>,
    has_successful_read: bool,
    default_route: Option<String>,
    gateway: Option<Ipv4Addr>,
    name_servers: Vec<IpAddr>,
}

impl<S: InterfaceSource> InterfaceCounterCollector<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            interfaces: BTreeMap::new(),
            has_successful_read: false,
            default_route: None,
            gateway: None,
            name_servers: Vec::new(),
        }
    }

    pub fn sample(&mut self, now: Duration) -> InterfaceSnapshot {
        match self.source.read_interfaces() {
            Ok(counters) => {
                self.record(counters, now);
                self.has_successful_read = true;
                // A route table or resolver file that cannot be read keeps the
                // last known value; one that was read and is empty clears it.
                match self.source.default_route() {
                    Ok(route) => {
                        self.gateway = route.as_ref().and_then(|route| route.gateway);
                        self.default_route = route
                            .map(|route| route.interface)
                            .or_else(|| self.first_interface());
                    }
                    Err(_) if self.default_route.is_none() => {
                        self.default_route = self.first_interface();
                    }
                    Err(_) => {}
                }
                if let Ok(name_servers) = self.source.name_servers() {
                    self.name_servers = name_servers;
                }
                self.snapshot(CollectionHealth::Available)
            }
            Err(error) => {
                let health = if self.has_successful_read {
                    CollectionHealth::Stale(error.to_string())
                } else {
                    CollectionHealth::Unavailable(error.to_string())
                };
                self.snapshot(health)
            }
        }
    }

    fn first_interface(&self) -> Option<String> {
        self.interfaces
            .values()
            .find(|state| {
                state.measurement.name != "lo"
                    && state.measurement.status == InterfaceStatus::Available
            })
            .map(|state| state.measurement.name.clone())
    }

    fn record(&mut self, counters: Vec<InterfaceCounters>, now: Duration) {
        let mut seen = BTreeSet::new();

        for current in counters {
            seen.insert(current.name.clone());
            if let Some(state) = self.interfaces.get_mut(&current.name) {
                let was_missing = state.measurement.status == InterfaceStatus::Missing;
                let elapsed = now
                    .checked_sub(state.last_sampled_at)
                    .unwrap_or_default()
                    .as_secs_f64();
                let received_delta = if was_missing {
                    0
                } else {
                    current
                        .received_bytes
                        .saturating_sub(state.last_received_bytes)
                };
                let transmitted_delta = if was_missing {
                    0
                } else {
                    current
                        .transmitted_bytes
                        .saturating_sub(state.last_transmitted_bytes)
                };

                state.measurement.addresses = current.addresses;
                state.measurement.is_up = current.is_up;
                state.measurement.download_bytes_per_second = rate(received_delta, elapsed);
                state.measurement.upload_bytes_per_second = rate(transmitted_delta, elapsed);
                state.measurement.session_received_bytes = state
                    .measurement
                    .session_received_bytes
                    .saturating_add(received_delta);
                state.measurement.session_transmitted_bytes = state
                    .measurement
                    .session_transmitted_bytes
                    .saturating_add(transmitted_delta);
                state.measurement.status = InterfaceStatus::Available;
                state.last_received_bytes = current.received_bytes;
                state.last_transmitted_bytes = current.transmitted_bytes;
                state.last_sampled_at = now;
            } else {
                self.interfaces.insert(
                    current.name.clone(),
                    InterfaceState {
                        measurement: InterfaceMeasurement {
                            name: current.name,
                            addresses: current.addresses,
                            is_up: current.is_up,
                            download_bytes_per_second: 0.0,
                            upload_bytes_per_second: 0.0,
                            session_received_bytes: 0,
                            session_transmitted_bytes: 0,
                            status: InterfaceStatus::Available,
                        },
                        last_received_bytes: current.received_bytes,
                        last_transmitted_bytes: current.transmitted_bytes,
                        last_sampled_at: now,
                    },
                );
            }
        }

        for (name, state) in &mut self.interfaces {
            if !seen.contains(name) {
                state.measurement.status = InterfaceStatus::Missing;
            }
        }
    }

    fn snapshot(&self, health: CollectionHealth) -> InterfaceSnapshot {
        InterfaceSnapshot {
            health,
            interfaces: self
                .interfaces
                .values()
                .map(|state| state.measurement.clone())
                .collect(),
            default_route: self.default_route.clone(),
            gateway: self.gateway,
            name_server: self.name_servers.first().copied(),
            name_servers: self.name_servers.clone(),
        }
    }
}

fn rate(delta: u64, elapsed_seconds: f64) -> f64 {
    if elapsed_seconds > 0.0 {
        delta as f64 / elapsed_seconds
    } else {
        0.0
    }
}

pub struct LinuxInterfaceSource {
    counters_path: PathBuf,
    route_path: PathBuf,
    resolver_path: PathBuf,
}

impl LinuxInterfaceSource {
    pub fn new() -> Self {
        Self::with_paths("/proc/net/dev", "/proc/net/route")
    }

    pub fn with_paths(counters_path: impl Into<PathBuf>, route_path: impl Into<PathBuf>) -> Self {
        Self {
            counters_path: counters_path.into(),
            route_path: route_path.into(),
            resolver_path: PathBuf::from("/etc/resolv.conf"),
        }
    }

    /// Reads name servers from `path` instead of `/etc/resolv.conf`.
    pub fn with_resolver_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.resolver_path = path.into();
        self
    }
}

impl Default for LinuxInterfaceSource {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceSource for LinuxInterfaceSource {
    fn read_interfaces(&mut self) -> io::Result<Vec<InterfaceCounters>> {
        let contents = fs::read_to_string(&self.counters_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not read interface counters '{}': {error}",
                    self.counters_path.display()
                ),
            )
        })?;
        let live = live_interfaces()?;

        contents
            .lines()
            .skip(2)
            .map(|line| parse_counter_line(line, &live))
            .collect()
    }

    fn default_route(&mut self) -> io::Result<Option<DefaultRoute>> {
        Ok(parse_default_route(&fs::read_to_string(&self.route_path)?))
    }

    fn name_servers(&mut self) -> io::Result<Vec<IpAddr>> {
        Ok(parse_name_servers(&fs::read_to_string(
            &self.resolver_path,
        )?))
    }
}

fn parse_name_servers(resolver: &str) -> Vec<IpAddr> {
    resolver
        .lines()
        .filter(|line| !line.starts_with(['#', ';']))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "nameserver").then_some(())?;
            let value = fields.next()?;
            value.split('%').next()?.parse().ok()
        })
        .collect()
}

/// A `/proc/net/route` address: eight hex digits in host byte order; zero means none.
fn parse_gateway(field: &str) -> Option<Ipv4Addr> {
    let value = u32::from_str_radix(field, 16).ok()?;
    (value != 0).then(|| Ipv4Addr::from(value.to_ne_bytes()))
}

fn parse_default_route(table: &str) -> Option<DefaultRoute> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let destination = fields.next()?;
            let gateway = fields.next()?;
            let metric: u32 = fields.nth(3)?.parse().ok()?;
            (destination == "00000000").then_some((metric, name, gateway))
        })
        .min_by_key(|(metric, _, _)| *metric)
        .map(|(_, name, gateway)| DefaultRoute {
            interface: name.to_owned(),
            gateway: parse_gateway(gateway),
        })
}

fn parse_counter_line(
    line: &str,
    live: &HashMap<String, LiveInterface>,
) -> io::Result<InterfaceCounters> {
    let (name, values) = line.split_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid /proc/net/dev interface line",
        )
    })?;
    let values: Vec<&str> = values.split_whitespace().collect();
    if values.len() < 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete /proc/net/dev interface counters",
        ));
    }

    let name = name.trim().to_owned();
    let found = live.get(&name);
    Ok(InterfaceCounters {
        addresses: found.map(|live| live.addresses.clone()).unwrap_or_default(),
        // An interface the system does not list is not known to be down.
        is_up: found.is_none_or(|live| live.is_up),
        name,
        received_bytes: parse_counter(values[0])?,
        transmitted_bytes: parse_counter(values[8])?,
    })
}

fn parse_counter(value: &str) -> io::Result<u64> {
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid /proc/net/dev counter '{value}': {error}"),
        )
    })
}

/// What `getifaddrs` says of one interface.
struct LiveInterface {
    is_up: bool,
    addresses: Vec<InterfaceAddress>,
}

fn live_interfaces() -> io::Result<HashMap<String, LiveInterface>> {
    let mut head = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let addresses = InterfaceAddressList(head);
    let mut by_interface = HashMap::<String, LiveInterface>::new();
    let mut current = addresses.0;

    while !current.is_null() {
        let address = unsafe { &*current };
        let name = unsafe { CStr::from_ptr(address.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let live = by_interface.entry(name).or_insert_with(|| LiveInterface {
            is_up: address.ifa_flags & libc::IFF_UP as u32 != 0,
            addresses: Vec::new(),
        });
        if !address.ifa_addr.is_null() {
            let family = unsafe { (*address.ifa_addr).sa_family as i32 };
            let netmask = address.ifa_netmask;
            let found = match family {
                libc::AF_INET => {
                    let socket = unsafe { &*(address.ifa_addr.cast::<libc::sockaddr_in>()) };
                    let prefix = if netmask.is_null() {
                        32
                    } else {
                        let mask = unsafe { &*(netmask.cast::<libc::sockaddr_in>()) };
                        prefix_length(&mask.sin_addr.s_addr.to_ne_bytes())
                    };
                    Some(InterfaceAddress {
                        ip: IpAddr::V4(Ipv4Addr::from(socket.sin_addr.s_addr.to_ne_bytes())),
                        prefix,
                    })
                }
                libc::AF_INET6 => {
                    let socket = unsafe { &*(address.ifa_addr.cast::<libc::sockaddr_in6>()) };
                    let prefix = if netmask.is_null() {
                        128
                    } else {
                        let mask = unsafe { &*(netmask.cast::<libc::sockaddr_in6>()) };
                        prefix_length(&mask.sin6_addr.s6_addr)
                    };
                    Some(InterfaceAddress {
                        ip: IpAddr::V6(Ipv6Addr::from(socket.sin6_addr.s6_addr)),
                        prefix,
                    })
                }
                _ => None,
            };
            if let Some(found) = found {
                live.addresses.push(found);
            }
        }
        current = address.ifa_next;
    }

    Ok(by_interface)
}

/// The hardware address of an interface, as the kernel writes it in
/// `/sys/class/net/<name>/address`; `None` when it cannot be read.
pub fn hardware_address(interface: &str) -> Option<String> {
    let text = fs::read_to_string(format!("/sys/class/net/{interface}/address")).ok()?;
    Some(text.trim().to_lowercase()).filter(|mac| mac.len() == 17)
}

/// Whether an interface is a wireless one: the kernel gives it a
/// `/sys/class/net/<name>/wireless` directory.
pub fn is_wireless(interface: &str) -> bool {
    std::path::Path::new("/sys/class/net")
        .join(interface)
        .join("wireless")
        .is_dir()
}

/// The prefix length of a netmask: the number of set bits across its bytes.
fn prefix_length(mask: &[u8]) -> u8 {
    mask.iter().map(|byte| byte.count_ones()).sum::<u32>() as u8
}

struct InterfaceAddressList(*mut libc::ifaddrs);

impl Drop for InterfaceAddressList {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.0) };
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::prefix_length;

    #[test]
    fn counts_prefix_of_ipv4_masks() {
        assert_eq!(prefix_length(&[255, 255, 255, 0]), 24);
        assert_eq!(prefix_length(&[255, 255, 255, 255]), 32);
        assert_eq!(prefix_length(&[0, 0, 0, 0]), 0);
    }

    #[test]
    fn counts_prefix_of_ipv6_masks() {
        let mut mask = [0u8; 16];
        mask[..8].fill(255);
        assert_eq!(prefix_length(&mask), 64);
        assert_eq!(prefix_length(&[255; 16]), 128);
    }
}

use std::{
    collections::{HashMap, HashSet},
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use super::capture::{Endpoint, Protocol, TrafficEvent};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExecutableIdentity {
    pub path: PathBuf,
    /// The app ID of the Flatpak sandbox the process runs in; none outside one.
    pub flatpak_app: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    pub executable: ExecutableIdentity,
    pub pid: u32,
    pub start_time: u64,
    pub network_namespace: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttributionHealth {
    Available,
    Unavailable(String),
    Stale(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributionStatus {
    pub health: AttributionHealth,
    /// Set by the runtime to the name of the user running Crosswalk when it is not
    /// root, because it can then name only that user's programs.
    pub only_user: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributionResult {
    pub owner: Option<ProcessIdentity>,
    pub health: AttributionHealth,
}

/// A TCP socket in the listening state or a UDP socket bound without a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub protocol: Protocol,
    pub address: IpAddr,
    pub port: u16,
    pub owners: Vec<ProcessIdentity>,
}

const TCP_LISTEN: u8 = 0x0A;

/// What one socket snapshot read, for the attribution log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotStats {
    pub took: Duration,
    pub sockets: usize,
    pub processes_read: usize,
    /// Processes in another network namespace: expected.
    pub skipped_other_namespace: usize,
    /// Processes whose files could not be read, or that changed while read.
    pub skipped_unreadable: usize,
    /// Processes with no readable `exe` link, such as kernel threads.
    pub skipped_no_executable: usize,
}

/// Why a packet has no owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoOwnerCause {
    /// No snapshot has been collected, or reading one failed before the first.
    Unavailable(String),
    /// The snapshot is too old, or the latest read failed.
    Stale(String),
    /// Not TCP or UDP, or without ports, or with mixed address families.
    NotTcpUdp,
    NoSocket,
    /// The best-matching sockets are held by no process.
    SocketWithoutProcess {
        protocol: Protocol,
        state: u8,
        inode: u64,
        sockets: usize,
    },
    SeveralOwners(usize),
}

/// Whether the connection's owner was remembered, and how long ago its
/// socket was last seen owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerMemory {
    Never,
    /// Remembered, but past the memory's 120 seconds.
    Expired(Duration),
    /// Remembered and within 120 seconds, yet not used (stale snapshot).
    Live(Duration),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoOwner {
    pub cause: NoOwnerCause,
    pub memory: OwnerMemory,
}

enum Skip {
    OtherNamespace,
    NoExecutable,
    Unreadable,
}

pub struct LinuxProcfsSource {
    root: PathBuf,
}

impl LinuxProcfsSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn read_snapshot(&self, capacity: usize) -> io::Result<Snapshot> {
        let started = Instant::now();
        let network_namespace = namespace_id(&self.root.join("self/ns/net"))?;
        let mut sockets = Vec::new();
        for (name, family, protocol) in [
            ("tcp", AddressFamily::Ipv4, Protocol::Tcp),
            ("tcp6", AddressFamily::Ipv6, Protocol::Tcp),
            ("udp", AddressFamily::Ipv4, Protocol::Udp),
            ("udp6", AddressFamily::Ipv6, Protocol::Udp),
        ] {
            for socket in read_socket_table(&self.root.join("net").join(name), family, protocol)? {
                if sockets.len() == capacity {
                    break;
                }
                sockets.push(socket);
            }
        }

        let wanted_inodes: HashSet<u64> = sockets.iter().map(|socket| socket.inode).collect();
        let mut owners = HashMap::<u64, Vec<ProcessIdentity>>::new();
        let mut owner_count = 0usize;
        let mut stats = SnapshotStats {
            took: Duration::ZERO,
            sockets: sockets.len(),
            processes_read: 0,
            skipped_other_namespace: 0,
            skipped_unreadable: 0,
            skipped_no_executable: 0,
        };
        for entry in fs::read_dir(&self.root)? {
            let Ok(entry) = entry else {
                continue;
            };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let (process, inodes) = match read_process(&entry.path(), pid, network_namespace) {
                Ok(read) => read,
                Err(Skip::OtherNamespace) => {
                    stats.skipped_other_namespace += 1;
                    continue;
                }
                Err(Skip::NoExecutable) => {
                    stats.skipped_no_executable += 1;
                    continue;
                }
                Err(Skip::Unreadable) => {
                    stats.skipped_unreadable += 1;
                    continue;
                }
            };
            stats.processes_read += 1;
            for inode in inodes {
                if !wanted_inodes.contains(&inode) {
                    continue;
                }
                if owner_count == capacity {
                    break;
                }
                owners.entry(inode).or_default().push(process.clone());
                owner_count += 1;
            }
        }

        stats.took = started.elapsed();
        Ok(Snapshot {
            sockets,
            owners,
            stats,
        })
    }
}

/// How long a connection's owner is used after its socket was last seen
/// owned.
const OWNER_MEMORY: Duration = Duration::from_secs(120);

/// How long an entry is kept, so the attribution log can say an owner had
/// expired. Entries older than `OWNER_MEMORY` are never used.
const OWNER_RETAINED: Duration = Duration::from_secs(600);

type ConnectionKey = (AddressFamily, Protocol, Endpoint, Endpoint);

pub struct AttributionCollector {
    source: LinuxProcfsSource,
    max_age: Duration,
    capacity: usize,
    snapshot: Option<Snapshot>,
    sampled_at: Option<Duration>,
    health: AttributionHealth,
    remembered: HashMap<ConnectionKey, (ProcessIdentity, Duration)>,
}

impl AttributionCollector {
    pub fn new(source: LinuxProcfsSource, max_age: Duration, capacity: usize) -> io::Result<Self> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "attribution snapshot capacity must be greater than zero",
            ));
        }
        Ok(Self {
            source,
            max_age,
            capacity,
            snapshot: None,
            sampled_at: None,
            health: AttributionHealth::Unavailable(
                "attribution snapshot has not been collected".to_owned(),
            ),
            remembered: HashMap::new(),
        })
    }

    pub fn refresh(&mut self, now: Duration) -> AttributionStatus {
        match self.source.read_snapshot(self.capacity) {
            Ok(snapshot) => {
                self.remember(&snapshot, now);
                self.snapshot = Some(snapshot);
                self.sampled_at = Some(now);
                self.health = AttributionHealth::Available;
                AttributionStatus {
                    health: self.health.clone(),
                    only_user: None,
                }
            }
            Err(error) => {
                self.health = if self.snapshot.is_some() {
                    AttributionHealth::Stale(error.to_string())
                } else {
                    AttributionHealth::Unavailable(error.to_string())
                };
                AttributionStatus {
                    health: self.health.clone(),
                    only_user: None,
                }
            }
        }
    }

    /// What the latest successful `refresh` read.
    pub fn snapshot_stats(&self) -> Option<SnapshotStats> {
        self.snapshot.as_ref().map(|snapshot| snapshot.stats)
    }

    /// Why `attribute` gives this packet no owner; `None` when it has one.
    pub fn explain(&self, event: &TrafficEvent, now: Duration) -> Option<NoOwner> {
        let memory = event_key(event)
            .and_then(|key| self.remembered.get(&key))
            .map_or(OwnerMemory::Never, |(_, seen)| {
                let age = now.saturating_sub(*seen);
                if age <= OWNER_MEMORY {
                    OwnerMemory::Live(age)
                } else {
                    OwnerMemory::Expired(age)
                }
            });
        let cause = match self.current_health(now) {
            AttributionHealth::Unavailable(reason) => NoOwnerCause::Unavailable(reason),
            AttributionHealth::Stale(reason) => NoOwnerCause::Stale(reason),
            AttributionHealth::Available => match self.snapshot.as_ref() {
                Some(snapshot) => {
                    let cause = snapshot.explain(event)?;
                    if matches!(memory, OwnerMemory::Live(_)) {
                        // `attribute` falls back to the remembered owner.
                        return None;
                    }
                    cause
                }
                None => NoOwnerCause::Unavailable("no snapshot".to_owned()),
            },
        };
        Some(NoOwner { cause, memory })
    }

    pub fn attribute(&self, event: &TrafficEvent, now: Duration) -> AttributionResult {
        let health = self.current_health(now);
        let owner = if health == AttributionHealth::Available {
            self.snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.owner(event))
                .or_else(|| self.remembered_owner(event, now))
        } else {
            None
        };
        AttributionResult { owner, health }
    }

    fn remember(&mut self, snapshot: &Snapshot, now: Duration) {
        for socket in snapshot
            .sockets
            .iter()
            .filter(|socket| !socket.is_listener() && socket.inode != 0)
        {
            if let Some([owner]) = snapshot.owners.get(&socket.inode).map(Vec::as_slice) {
                self.remembered.insert(
                    (socket.family, socket.protocol, socket.local, socket.remote),
                    (owner.clone(), now),
                );
            }
        }
        self.remembered
            .retain(|_, (_, seen)| now.saturating_sub(*seen) <= OWNER_RETAINED);
        while self.remembered.len() > self.capacity {
            let Some(oldest) = self
                .remembered
                .iter()
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.remembered.remove(&oldest);
        }
    }

    fn remembered_owner(&self, event: &TrafficEvent, now: Duration) -> Option<ProcessIdentity> {
        let key = event_key(event)?;
        let (owner, seen) = self.remembered.get(&key)?;
        (now.saturating_sub(*seen) <= OWNER_MEMORY).then(|| owner.clone())
    }

    /// Listening sockets from the current snapshot, sorted by port, with
    /// identical protocol + address + port collapsed into one entry. `None`
    /// until a reading has succeeded; an empty list is a real reading.
    pub fn listeners(&self) -> Option<Vec<Listener>> {
        self.snapshot.as_ref().map(Snapshot::listeners)
    }

    fn current_health(&self, now: Duration) -> AttributionHealth {
        if self.health != AttributionHealth::Available {
            return self.health.clone();
        }
        let Some(sampled_at) = self.sampled_at else {
            return AttributionHealth::Unavailable(
                "attribution snapshot has not been collected".to_owned(),
            );
        };
        if now.saturating_sub(sampled_at) > self.max_age {
            AttributionHealth::Stale("attribution snapshot exceeded its maximum age".to_owned())
        } else {
            AttributionHealth::Available
        }
    }
}

struct Snapshot {
    sockets: Vec<SocketRecord>,
    owners: HashMap<u64, Vec<ProcessIdentity>>,
    stats: SnapshotStats,
}

impl Snapshot {
    fn listeners(&self) -> Vec<Listener> {
        let mut listeners: Vec<Listener> = Vec::new();
        for socket in self.sockets.iter().filter(|socket| socket.is_listener()) {
            let Some(port) = socket.local.port else {
                continue;
            };
            let owners = self.owners.get(&socket.inode).into_iter().flatten();
            match listeners.iter_mut().find(|listener| {
                listener.protocol == socket.protocol
                    && listener.address == socket.local.ip
                    && listener.port == port
            }) {
                Some(existing) => {
                    for owner in owners {
                        if !existing.owners.contains(owner) {
                            existing.owners.push(owner.clone());
                        }
                    }
                }
                None => listeners.push(Listener {
                    protocol: socket.protocol,
                    address: socket.local.ip,
                    port,
                    owners: owners.cloned().collect(),
                }),
            }
        }
        listeners.sort_by_key(|listener| listener.port);
        listeners
    }

    /// The sockets that match the event best, and the processes holding them.
    fn best_matches(
        &self,
        event: &TrafficEvent,
    ) -> Option<(Vec<&SocketRecord>, HashSet<ProcessIdentity>)> {
        let (family, protocol, local, remote) = event_key(event)?;
        let mut best_score = None;
        let mut best = Vec::new();
        let mut candidates = HashSet::new();

        for socket in &self.sockets {
            let Some(score) = socket.match_score(family, protocol, local, remote) else {
                continue;
            };
            match best_score {
                Some(top) if score < top => continue,
                Some(top) if score > top => {
                    best_score = Some(score);
                    best.clear();
                    candidates.clear();
                }
                None => best_score = Some(score),
                _ => {}
            }
            best.push(socket);
            if let Some(owners) = self.owners.get(&socket.inode) {
                candidates.extend(owners.iter().cloned());
            }
        }
        Some((best, candidates))
    }

    fn owner(&self, event: &TrafficEvent) -> Option<ProcessIdentity> {
        let (_, candidates) = self.best_matches(event)?;
        if candidates.len() == 1 {
            candidates.into_iter().next()
        } else {
            None
        }
    }

    /// Why the snapshot gives the event no owner; `None` when it gives one.
    fn explain(&self, event: &TrafficEvent) -> Option<NoOwnerCause> {
        let Some((best, candidates)) = self.best_matches(event) else {
            return Some(NoOwnerCause::NotTcpUdp);
        };
        match (best.first(), candidates.len()) {
            (None, _) => Some(NoOwnerCause::NoSocket),
            (Some(_), 1) => None,
            (Some(_), 0) => {
                let socket = best[0];
                Some(NoOwnerCause::SocketWithoutProcess {
                    protocol: socket.protocol,
                    state: socket.state,
                    inode: socket.inode,
                    sockets: best.len(),
                })
            }
            (Some(_), count) => Some(NoOwnerCause::SeveralOwners(count)),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

struct SocketRecord {
    family: AddressFamily,
    protocol: Protocol,
    local: Endpoint,
    remote: Endpoint,
    state: u8,
    inode: u64,
}

impl SocketRecord {
    fn is_listener(&self) -> bool {
        match self.protocol {
            Protocol::Tcp => self.state == TCP_LISTEN,
            Protocol::Udp => self.remote.ip.is_unspecified() && self.remote.port == Some(0),
            _ => false,
        }
    }

    fn match_score(
        &self,
        family: AddressFamily,
        protocol: Protocol,
        local: Endpoint,
        remote: Endpoint,
    ) -> Option<u8> {
        if self.family != family || self.protocol != protocol || self.local.port != local.port {
            return None;
        }
        let local_score = match_ip(self.local.ip, local.ip)?;
        let remote_score = if self.remote.ip.is_unspecified() && self.remote.port == Some(0) {
            0
        } else if self.remote == remote {
            2
        } else {
            return None;
        };
        Some(local_score + remote_score)
    }
}

fn match_ip(socket: IpAddr, event: IpAddr) -> Option<u8> {
    if socket == event {
        Some(2)
    } else if socket.is_unspecified() {
        Some(0)
    } else {
        None
    }
}

fn event_key(event: &TrafficEvent) -> Option<(AddressFamily, Protocol, Endpoint, Endpoint)> {
    if !matches!(event.protocol, Protocol::Tcp | Protocol::Udp) {
        return None;
    }
    let (local, remote) = event.endpoints();
    if local.port.is_none() || remote.port.is_none() {
        return None;
    }
    let family = match (local.ip, remote.ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => AddressFamily::Ipv4,
        (IpAddr::V6(_), IpAddr::V6(_)) => AddressFamily::Ipv6,
        _ => return None,
    };
    Some((family, event.protocol, local, remote))
}

fn read_socket_table(
    path: &Path,
    family: AddressFamily,
    protocol: Protocol,
) -> io::Result<Vec<SocketRecord>> {
    let contents = fs::read_to_string(path)?;
    contents
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| parse_socket(line, family, protocol))
        .collect()
}

fn parse_socket(line: &str, family: AddressFamily, protocol: Protocol) -> io::Result<SocketRecord> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete procfs socket row",
        ));
    }
    Ok(SocketRecord {
        family,
        protocol,
        local: parse_endpoint(fields[1], family)?,
        remote: parse_endpoint(fields[2], family)?,
        state: u8::from_str_radix(fields[3], 16).map_err(invalid_data)?,
        inode: fields[9].parse().map_err(invalid_data)?,
    })
}

fn parse_endpoint(value: &str, family: AddressFamily) -> io::Result<Endpoint> {
    let (address, port) = value.split_once(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid procfs socket endpoint")
    })?;
    let ip = match family {
        AddressFamily::Ipv4 => {
            let raw = u32::from_str_radix(address, 16).map_err(invalid_data)?;
            IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
        }
        AddressFamily::Ipv6 => {
            if address.len() != 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid procfs IPv6 address",
                ));
            }
            let mut bytes = [0u8; 16];
            for (index, chunk) in address.as_bytes().as_chunks::<8>().0.iter().enumerate() {
                let chunk = std::str::from_utf8(chunk).map_err(invalid_data)?;
                let raw = u32::from_str_radix(chunk, 16).map_err(invalid_data)?;
                bytes[index * 4..index * 4 + 4].copy_from_slice(&raw.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
    };
    Ok(Endpoint {
        ip,
        port: Some(u16::from_str_radix(port, 16).map_err(invalid_data)?),
    })
}

fn read_process(
    path: &Path,
    pid: u32,
    network_namespace: u64,
) -> Result<(ProcessIdentity, Vec<u64>), Skip> {
    fn unreadable<E>(_: E) -> Skip {
        Skip::Unreadable
    }
    let first_start_time = process_start_time(&path.join("stat")).map_err(unreadable)?;
    if namespace_id(&path.join("ns/net")).map_err(unreadable)? != network_namespace {
        return Err(Skip::OtherNamespace);
    }
    let executable = fs::read_link(path.join("exe")).map_err(|_| Skip::NoExecutable)?;
    let mut inodes = Vec::new();
    for entry in fs::read_dir(path.join("fd")).map_err(unreadable)? {
        // A descriptor closed during the read is skipped, not the process.
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        if let Some(inode) = socket_inode(&target) {
            inodes.push(inode);
        }
    }
    if process_start_time(&path.join("stat")).map_err(unreadable)? != first_start_time {
        return Err(Skip::Unreadable);
    }
    Ok((
        ProcessIdentity {
            executable: ExecutableIdentity {
                path: executable,
                flatpak_app: flatpak_app(path),
            },
            pid,
            start_time: first_start_time,
            network_namespace,
        },
        inodes,
    ))
}

/// The app ID in the `[Application]` section of the sandbox's `.flatpak-info`.
fn flatpak_app(process: &Path) -> Option<String> {
    let info = fs::read_to_string(process.join("root/.flatpak-info")).ok()?;
    info.lines()
        .skip_while(|line| line.trim() != "[Application]")
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .find_map(|line| line.strip_prefix("name="))
        .map(|name| name.trim().to_owned())
}

fn process_start_time(path: &Path) -> io::Result<u64> {
    let stat = fs::read_to_string(path)?;
    let end_name = stat
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid procfs process stat"))?;
    stat[end_name + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "procfs process stat is missing start time",
            )
        })?
        .parse()
        .map_err(invalid_data)
}

fn namespace_id(path: &Path) -> io::Result<u64> {
    let target = fs::read_link(path)?;
    let target = target.to_string_lossy();
    target
        .strip_prefix("net:[")
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid network namespace"))?
        .parse()
        .map_err(invalid_data)
}

fn socket_inode(path: &Path) -> Option<u64> {
    let target = path.to_string_lossy();
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

//! The `--attribution-log` diagnostic: one tab-separated line for every
//! packet counted in the unattributed total and one after every socket snapshot.
//!
//! packet:   `packet  secs  dir  proto  local  remote  bytes  flags  reason  detail  memory  lag_ms  waited_ms`
//! snapshot: `snapshot  secs  took_ms=  sockets=  processes=  skipped_other_namespace=  skipped_unreadable=  skipped_no_executable=`

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};

use crate::collect::{
    attribution::{NoOwner, NoOwnerCause, OwnerMemory, SnapshotStats},
    capture::{Direction, Endpoint, Protocol, TrafficEvent},
};

pub struct AttributionLog {
    file: File,
}

impl AttributionLog {
    /// Opens the file for append. When Crosswalk runs as root (effective uid 0) the file is
    /// made readable by everyone, whatever the umask, so the user who ran it with `sudo`
    /// can read it, set on the open file. Otherwise the mode is whatever the user's umask
    /// gives a new file, and an existing file keeps its mode: the log records other users'
    /// connections. A path that is a symbolic link, or that is not a regular file, is an
    /// error: the link is never followed.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_as(path, unsafe { libc::geteuid() } == 0)
    }

    /// `open`, with the root decision given: the suite cannot run as root.
    fn open_as(path: &Path, root: bool) -> io::Result<Self> {
        let open = || -> io::Result<File> {
            let mut options = OpenOptions::new();
            options
                .append(true)
                .create(true)
                .custom_flags(libc::O_NOFOLLOW);
            if root {
                options.mode(0o644);
            }
            let file = options.open(path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a regular file",
                ));
            }
            if root {
                file.set_permissions(fs::Permissions::from_mode(0o644))?;
            }
            Ok(file)
        };
        let file = open().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not open attribution log '{}': {error}",
                    path.display()
                ),
            )
        })?;
        Ok(Self { file })
    }

    /// Appends one line; a failed write is ignored.
    pub fn write(&mut self, line: &str) {
        let _ = self.file.write_all(format!("{line}\n").as_bytes());
    }
}

/// `waited` is how long the packet was held after it was read: zero when it
/// was not held, `None` when not known.
pub fn packet_line(
    at: Duration,
    event: &TrafficEvent,
    reason: &NoOwner,
    waited: Option<Duration>,
) -> String {
    let (local, remote) = event.endpoints();
    let (cause, detail) = cause_fields(&reason.cause);
    [
        "packet".to_owned(),
        format!("{:.3}", at.as_secs_f64()),
        match event.direction {
            Direction::Outbound => "out".to_owned(),
            Direction::Inbound => "in".to_owned(),
        },
        protocol_name(event.protocol),
        endpoint(local),
        endpoint(remote),
        event.original_ip_bytes.to_string(),
        flags(event),
        cause.to_owned(),
        detail,
        match reason.memory {
            OwnerMemory::Never => "none".to_owned(),
            OwnerMemory::Expired(age) => format!("expired:{}s", age.as_secs()),
            OwnerMemory::Live(age) => format!("live:{}s", age.as_secs()),
        },
        milliseconds(event.timing.and_then(|timing| timing.lag)),
        milliseconds(waited),
    ]
    .join("\t")
}

fn milliseconds(duration: Option<Duration>) -> String {
    duration.map_or_else(
        || "-".to_owned(),
        |duration| format!("{:.1}", duration.as_secs_f64() * 1000.0),
    )
}

pub fn snapshot_line(at: Duration, stats: &SnapshotStats) -> String {
    format!(
        "snapshot\t{:.3}\ttook_ms={:.1}\tsockets={}\tprocesses={}\tskipped_other_namespace={}\tskipped_unreadable={}\tskipped_no_executable={}",
        at.as_secs_f64(),
        stats.took.as_secs_f64() * 1000.0,
        stats.sockets,
        stats.processes_read,
        stats.skipped_other_namespace,
        stats.skipped_unreadable,
        stats.skipped_no_executable,
    )
}

fn cause_fields(cause: &NoOwnerCause) -> (&'static str, String) {
    match cause {
        NoOwnerCause::Unavailable(why) => ("attribution-unavailable", one_line(why)),
        NoOwnerCause::Stale(why) => ("attribution-stale", one_line(why)),
        NoOwnerCause::NotTcpUdp => ("not-tcp-udp-or-no-ports", "-".to_owned()),
        NoOwnerCause::NoSocket => ("no-socket-matches", "-".to_owned()),
        NoOwnerCause::SocketWithoutProcess {
            protocol,
            state,
            inode,
            sockets,
        } => (
            "socket-has-no-process",
            format!(
                "state={} inode={inode} sockets={sockets}",
                socket_state(*protocol, *state)
            ),
        ),
        NoOwnerCause::SeveralOwners(count) => {
            ("socket-has-several-owners", format!("owners={count}"))
        }
    }
}

fn socket_state(protocol: Protocol, state: u8) -> String {
    let name = match (protocol, state) {
        (Protocol::Tcp, 0x01) => "ESTABLISHED",
        (Protocol::Tcp, 0x02) => "SYN_SENT",
        (Protocol::Tcp, 0x03) => "SYN_RECV",
        (Protocol::Tcp, 0x04) => "FIN_WAIT1",
        (Protocol::Tcp, 0x05) => "FIN_WAIT2",
        (Protocol::Tcp, 0x06) => "TIME_WAIT",
        (Protocol::Tcp, 0x07) => "CLOSE",
        (Protocol::Tcp, 0x08) => "CLOSE_WAIT",
        (Protocol::Tcp, 0x09) => "LAST_ACK",
        (Protocol::Tcp, 0x0A) => "LISTEN",
        (Protocol::Tcp, 0x0B) => "CLOSING",
        (Protocol::Tcp, 0x0C) => "NEW_SYN_RECV",
        (Protocol::Udp, _) => return format!("udp:{state:02X}"),
        _ => return format!("{state:02X}"),
    };
    name.to_owned()
}

fn protocol_name(protocol: Protocol) -> String {
    match protocol {
        Protocol::Tcp => "tcp".to_owned(),
        Protocol::Udp => "udp".to_owned(),
        Protocol::Other(number) => format!("proto{number}"),
    }
}

fn endpoint(endpoint: Endpoint) -> String {
    match endpoint.port {
        Some(port) => SocketAddr::new(endpoint.ip, port).to_string(),
        None => match endpoint.ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => ip.to_string(),
        },
    }
}

/// `-` when the packet has no known TCP flags, `none` when none are set.
fn flags(event: &TrafficEvent) -> String {
    let Some(f) = event.tcp_flags else {
        return "-".to_owned();
    };
    let set: Vec<&str> = [
        (f.syn, "SYN"),
        (f.ack, "ACK"),
        (f.fin, "FIN"),
        (f.psh, "PSH"),
        (f.rst, "RST"),
    ]
    .into_iter()
    .filter_map(|(on, name)| on.then_some(name))
    .collect();
    if set.is_empty() {
        "none".to_owned()
    } else {
        set.join(",")
    }
}

fn one_line(text: &str) -> String {
    text.replace(['\t', '\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::capture::{ReadTiming, TcpFlags};
    use std::time::Instant;

    fn ep(ip: &str, port: Option<u16>) -> Endpoint {
        Endpoint {
            ip: ip.parse().unwrap(),
            port,
        }
    }

    fn event(
        direction: Direction,
        protocol: Protocol,
        flags: Option<TcpFlags>,
        bytes: u32,
    ) -> TrafficEvent {
        TrafficEvent {
            source: ep("192.0.2.10", Some(49_152)),
            destination: ep("198.51.100.20", Some(443)),
            protocol,
            direction,
            original_ip_bytes: bytes,
            limitation: None,
            tcp_flags: flags,
            timing: None,
        }
    }

    #[test]
    fn a_tcp_packet_gives_its_fields_in_order() {
        let flags = TcpFlags {
            syn: false,
            ack: true,
            rst: false,
            fin: true,
            psh: false,
        };
        let reason = NoOwner {
            cause: NoOwnerCause::SocketWithoutProcess {
                protocol: Protocol::Tcp,
                state: 0x08,
                inode: 0,
                sockets: 1,
            },
            memory: OwnerMemory::Expired(Duration::from_secs(131)),
        };
        // Inbound: the destination is the local endpoint.
        let line = packet_line(
            Duration::from_millis(12_345),
            &event(Direction::Inbound, Protocol::Tcp, Some(flags), 52),
            &reason,
            Some(Duration::ZERO),
        );
        assert_eq!(
            line,
            "packet\t12.345\tin\ttcp\t198.51.100.20:443\t192.0.2.10:49152\t52\tACK,FIN\t\
             socket-has-no-process\tstate=CLOSE_WAIT inode=0 sockets=1\texpired:131s\t-\t0.0"
        );
    }

    #[test]
    fn a_held_packet_shows_its_lag_and_wait_and_an_unheld_one_a_zero_wait() {
        let reason = NoOwner {
            cause: NoOwnerCause::NoSocket,
            memory: OwnerMemory::Never,
        };
        let mut held = event(Direction::Outbound, Protocol::Udp, None, 200);
        held.timing = Some(ReadTiming {
            lag: Some(Duration::from_micros(2_340)),
            read_at: Instant::now(),
        });
        let line = packet_line(
            Duration::from_secs(3),
            &held,
            &reason,
            Some(Duration::from_millis(104)),
        );
        assert!(line.ends_with("\tnone\t2.3\t104.0"), "{line}");
        let line = packet_line(Duration::from_secs(3), &held, &reason, Some(Duration::ZERO));
        assert!(line.ends_with("\tnone\t2.3\t0.0"), "{line}");
    }

    #[test]
    fn a_udp_packet_has_no_flags() {
        let reason = NoOwner {
            cause: NoOwnerCause::NoSocket,
            memory: OwnerMemory::Never,
        };
        let mut udp = event(Direction::Outbound, Protocol::Udp, None, 200);
        udp.destination = ep("239.255.255.250", Some(1900));
        let line = packet_line(Duration::from_secs(3), &udp, &reason, None);
        assert_eq!(
            line,
            "packet\t3.000\tout\tudp\t192.0.2.10:49152\t239.255.255.250:1900\t200\t-\t\
             no-socket-matches\t-\tnone\t-\t-"
        );
    }

    #[test]
    fn a_snapshot_gives_its_counts() {
        let stats = SnapshotStats {
            took: Duration::from_micros(4_250),
            sockets: 90,
            processes_read: 40,
            skipped_other_namespace: 7,
            skipped_unreadable: 2,
            skipped_no_executable: 5,
        };
        assert_eq!(
            snapshot_line(Duration::from_secs(1), &stats),
            "snapshot\t1.000\ttook_ms=4.2\tsockets=90\tprocesses=40\t\
             skipped_other_namespace=7\tskipped_unreadable=2\tskipped_no_executable=5"
        );
    }

    fn mode_after_open(root: bool, before: u32) -> (u32, String) {
        let path = std::env::temp_dir().join(format!(
            "crosswalk-log-mode-{}-{root}-{before:o}",
            std::process::id()
        ));
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(before)).unwrap();
        let mut log = AttributionLog::open_as(&path, root).unwrap();
        log.write("one");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let text = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).unwrap();
        (mode, text)
    }

    // The suite does not run as root, so the root decision is passed in: `open` is `open_as`
    // with `geteuid() == 0`.
    #[test]
    fn run_as_root_the_file_is_made_readable_by_everyone_whatever_its_mode_or_the_umask() {
        assert_eq!(mode_after_open(true, 0o600), (0o644, "one\n".to_owned()));
    }

    #[test]
    fn run_by_another_user_the_mode_of_an_existing_file_is_left_alone() {
        assert_eq!(mode_after_open(false, 0o600), (0o600, "one\n".to_owned()));
        assert_eq!(mode_after_open(false, 0o640), (0o640, "one\n".to_owned()));
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("crosswalk-log-{name}-{}", std::process::id()))
    }

    #[test]
    fn a_path_that_is_a_symbolic_link_is_an_error_and_its_target_is_left_alone() {
        for root in [true, false] {
            let target = scratch(&format!("target-{root}"));
            let link = scratch(&format!("link-{root}"));
            fs::write(&target, "secret").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let error = AttributionLog::open_as(&link, root).err();
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            let text = fs::read_to_string(&target).unwrap();
            fs::remove_file(&link).unwrap();
            fs::remove_file(&target).unwrap();
            let error = error.expect("a link must not be opened").to_string();
            assert!(error.contains(&link.display().to_string()), "{error}");
            assert_eq!((mode, text.as_str()), (0o600, "secret"));
        }
    }

    #[test]
    fn a_directory_is_an_error_naming_the_path() {
        for root in [true, false] {
            let dir = scratch(&format!("dir-{root}"));
            fs::create_dir(&dir).unwrap();
            let error = AttributionLog::open_as(&dir, root).err();
            fs::remove_dir(&dir).unwrap();
            let error = error.expect("a directory must not be opened").to_string();
            assert!(error.contains(&dir.display().to_string()), "{error}");
        }
    }
}

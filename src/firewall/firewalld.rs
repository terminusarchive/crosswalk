use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    time::{Duration, Instant},
};

use crate::command::{run_within, system_command};

use super::{
    Allowed, BlockMarker, BlockReader, FirewallEvent, FirewallHealth, FirewallInput,
    FirewallProvider, FirewallStatus, RuleSnapshot, Zone, Zones,
    firewalld_reply::{
        ActiveZone, BusctlOutput, LogDenied, PortRule, ReplyError, ServiceSettings, ZoneSettings,
        active_zones, default_zone, log_denied, name_has_owner, service_ports, service_settings,
        zone_settings,
    },
    ufw::{DEFAULT_RECORD_BYTES, DEFAULT_RECORD_LIMIT, journal_input},
};

/// The time limit the other helper programs have.
const CALL_TIMEOUT: Duration = Duration::from_secs(1);
/// Longest one pass over firewalld may take: the rules are read again every five seconds.
const PASS_LIMIT: Duration = Duration::from_secs(3);
/// Longest a reason may be: zone and service names come from another program.
const REASON_CHARS: usize = 120;
const FIREWALLD: &str = "org.fedoraproject.FirewallD1";
const FIREWALLD_PATH: &str = "/org/fedoraproject/FirewallD1";
const ZONE_INTERFACE: &str = "org.fedoraproject.FirewallD1.zone";

/// Reads firewalld over the system bus with `busctl`. Every request is a read: a `get…` method,
/// or the bus daemon's `NameHasOwner`.
pub struct FirewalldProvider {
    busctl: PathBuf,
    timeout: Duration,
    pass_limit: Duration,
    block_source: BlockSource,
    cancelled: Arc<AtomicBool>,
    status: FirewallStatus,
    blocks: Option<BlockReader<Box<dyn FirewallInput>>>,
    /// What the last rules pass found, until `poll` has followed it.
    unfollowed: Option<LogReading>,
    /// What `poll` last followed.
    log_reading: Option<LogReading>,
}

/// What the last look at firewalld's logging of denied packets found.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LogReading {
    NotRunning,
    Off,
    On,
    /// firewalld declined to tell this user.
    Refused,
    Failed(String),
}

/// Starts the reader of denied packets; called when the log setting says there may be some.
pub type BlockSource = Box<dyn Fn() -> io::Result<Box<dyn FirewallInput>> + Send>;

/// One request to the bus, and nothing else is ever asked.
enum Call<'a> {
    NameHasOwner,
    ActiveZones,
    DefaultZone,
    ZoneSettings(&'a str),
    ServiceSettings(&'a str),
    LogDenied,
}

/// Why a request gave no usable answer; `refused` is firewalld declining this user.
struct Failure {
    refused: bool,
    reason: String,
}

impl FirewalldProvider {
    pub fn new(cancelled: Arc<AtomicBool>) -> Self {
        let busctl = system_command("busctl").get_program().into();
        Self::with_busctl(busctl, CALL_TIMEOUT, cancelled)
    }

    /// A provider that runs `busctl` from the given path and gives each request `timeout`.
    pub fn with_busctl(busctl: PathBuf, timeout: Duration, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            busctl,
            timeout,
            pass_limit: PASS_LIMIT,
            block_source: Box::new(journal_input),
            cancelled,
            status: FirewallStatus {
                name: "fwd",
                health: FirewallHealth::AwaitingEvents,
            },
            blocks: None,
            unfollowed: None,
            log_reading: None,
        }
    }

    /// Starts the denied-packet reader with `source` instead of `journalctl`.
    pub fn with_block_source(mut self, source: BlockSource) -> Self {
        self.block_source = source;
        self
    }

    /// Gives the whole pass `limit` to read the rules.
    pub fn with_pass_limit(mut self, limit: Duration) -> Self {
        self.pass_limit = limit;
        self
    }

    /// Whether firewalld owns its bus name, asked once with the time limit of a request.
    pub fn is_running(&self) -> Result<bool, String> {
        self.pass()
            .ask(&Call::NameHasOwner, name_has_owner)
            .map_err(|failure| failure.reason)
    }

    fn pass(&self) -> Pass<'_> {
        Pass {
            provider: self,
            deadline: Instant::now() + self.pass_limit,
        }
    }

    /// Starts or stops the reader and sets the health to what `reading` calls for. A reading
    /// like the last one, with the reader as it called for, changes nothing: the health may
    /// have moved on since, to `Available` or to a fault of the reader's. A reading that failed
    /// changes nothing while a reader runs: stopping it would lose the packets denied meanwhile.
    fn follow(&mut self, reading: LogReading) {
        if matches!(reading, LogReading::Failed(_)) && self.blocks.is_some() {
            return;
        }
        let wants_reader = matches!(reading, LogReading::On | LogReading::Refused);
        let unchanged = self.log_reading.as_ref() == Some(&reading);
        if unchanged && wants_reader == self.blocks.is_some() {
            return;
        }
        let stopped = self.stop_reader();
        self.log_reading = Some(reading.clone());
        self.status.health = match (stopped, reading) {
            (Err(error), _) => stop_failed(error),
            (Ok(()), LogReading::NotRunning) => {
                FirewallHealth::Disabled("firewalld is not running".to_owned())
            }
            (Ok(()), LogReading::Off) => FirewallHealth::NotLogging,
            (Ok(()), LogReading::Failed(reason)) => FirewallHealth::Unavailable(reason),
            (Ok(()), LogReading::On) => self.start_reader(FirewallHealth::AwaitingEvents),
            (Ok(()), LogReading::Refused) => self.start_reader(FirewallHealth::DependsOnLogging),
        };
    }

    fn stop_reader(&mut self) -> io::Result<()> {
        self.blocks
            .take()
            .map_or(Ok(()), |mut reader| reader.shutdown())
    }

    /// The health once the reader runs, or the reason it could not be started.
    fn start_reader(&mut self, started: FirewallHealth) -> FirewallHealth {
        match (self.block_source)().and_then(|input| {
            BlockReader::new(
                input,
                BlockMarker::Firewalld,
                DEFAULT_RECORD_LIMIT,
                DEFAULT_RECORD_BYTES,
            )
        }) {
            Ok(reader) => {
                self.blocks = Some(reader);
                started
            }
            Err(error) => FirewallHealth::Unavailable(bounded(format!(
                "could not read the firewalld log: {error}"
            ))),
        }
    }

    fn command(&self, call: &Call) -> Command {
        self.method_call(&call.arguments())
    }

    fn method_call(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.busctl);
        command
            .args([
                "--system",
                "--allow-interactive-authorization=no",
                "--json=short",
                "call",
            ])
            .args(arguments)
            .env("LC_ALL", "C");
        command
    }
}

fn allowed_by(
    settings: &ZoneSettings,
    mut ports_of: impl FnMut(&str) -> Result<Vec<PortRule>, ReplyError>,
) -> Result<Vec<Allowed>, ReplyError> {
    let services = settings.services.iter().map(|name| {
        Ok(Allowed::Service {
            name: name.clone(),
            ports: ports_of(name)?,
        })
    });
    let ports = settings
        .ports
        .iter()
        .cloned()
        .map(|rule| Ok(Allowed::Port(rule)));
    services.chain(ports).collect()
}

/// One reading of firewalld's rules, all of whose requests share one deadline.
struct Pass<'a> {
    provider: &'a FirewalldProvider,
    deadline: Instant,
}

impl Pass<'_> {
    /// What the log setting is, asked last in the pass whose rules were `read`: firewalld not
    /// running is already known, and a pass that failed has no time or no firewalld to ask.
    fn read_log_reading(&self, read: &Result<RuleSnapshot, Failure>) -> LogReading {
        match read {
            Ok(RuleSnapshot::FirewalldOff) => LogReading::NotRunning,
            Err(failure) => LogReading::Failed(failure.reason.clone()),
            Ok(_) => match self.ask(&Call::LogDenied, log_denied) {
                Ok(LogDenied::Off) => LogReading::Off,
                Ok(LogDenied::On) => LogReading::On,
                Err(failure) if failure.refused => LogReading::Refused,
                Err(failure) => LogReading::Failed(failure.reason),
            },
        }
    }

    fn read_rules(&self) -> Result<RuleSnapshot, Failure> {
        if !self.ask(&Call::NameHasOwner, name_has_owner)? {
            return Ok(RuleSnapshot::FirewalldOff);
        }
        let active = self.ask(&Call::ActiveZones, active_zones)?;
        let default = self.ask(&Call::DefaultZone, default_zone)?;
        let mut names: Vec<&str> = active.iter().map(|zone| zone.name.as_str()).collect();
        if !names.contains(&default.as_str()) {
            names.push(&default);
        }
        let Some(settings) = self.read_zone_settings(&names)? else {
            return Ok(RuleSnapshot::ZonesOnly(active));
        };
        let zones = self.build_zones(&names, &active, settings)?;
        Ok(RuleSnapshot::Zones(Zones {
            default_zone: default,
            zones,
        }))
    }

    /// The settings of each zone in order, or `None` as soon as firewalld refuses this user one:
    /// the rest would be refused too, and half the zones would read as the rest being blocked.
    fn read_zone_settings(&self, names: &[&str]) -> Result<Option<Vec<ZoneSettings>>, Failure> {
        let all = names
            .iter()
            .map(|name| self.ask(&Call::ZoneSettings(name), zone_settings))
            .collect::<Result<Vec<_>, Failure>>();
        match all {
            Ok(all) => Ok(Some(all)),
            Err(failure) if failure.refused => Ok(None),
            Err(failure) => Err(failure),
        }
    }

    /// The zones with their services' ports resolved, each distinct service asked for once.
    /// A service that cannot be read, for any reason, fails the pass.
    fn build_zones(
        &self,
        names: &[&str],
        active: &[ActiveZone],
        settings: Vec<ZoneSettings>,
    ) -> Result<Vec<Zone>, Failure> {
        let mut known: HashMap<String, ServiceSettings> = HashMap::new();
        let mut lookup = |name: &str| {
            if let Some(found) = known.get(name) {
                return Ok(found.clone());
            }
            let found = self
                .ask(&Call::ServiceSettings(name), service_settings)
                .map_err(|failure| ReplyError::Failed(failure.reason))?;
            known.insert(name.to_owned(), found.clone());
            Ok(found)
        };
        names
            .iter()
            .zip(settings)
            .map(|(name, settings)| {
                let bound = active.iter().find(|zone| zone.name == *name);
                let allowed = allowed_by(&settings, |service| service_ports(service, &mut lookup))?;
                Ok(Zone {
                    name: (*name).to_owned(),
                    interfaces: bound
                        .map(|zone| zone.interfaces.clone())
                        .unwrap_or_default(),
                    sources: bound.map(|zone| zone.sources.clone()).unwrap_or_default(),
                    target: settings.target,
                    allowed,
                    rich_rules: settings.rich_rules,
                })
            })
            .collect::<Result<_, ReplyError>>()
            .map_err(|error| Failure {
                refused: false,
                reason: bounded(explain(error, None)),
            })
    }

    fn ask<T>(
        &self,
        call: &Call,
        parse: fn(&BusctlOutput) -> Result<T, ReplyError>,
    ) -> Result<T, Failure> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Failure::too_slow());
        }
        let provider = self.provider;
        let limit = provider.timeout.min(left);
        let (status, stdout, stderr) =
            run_within(provider.command(call), limit, &provider.cancelled)
                .map_err(|error| self.failure_of(call, &error))?;
        let output = BusctlOutput {
            success: status.success(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        };
        parse(&output).map_err(|error| Failure::of(call, error))
    }

    /// A call cut off by the pass's deadline, not by its own limit, is firewalld being slow.
    fn failure_of(&self, call: &Call, error: &io::Error) -> Failure {
        match error.kind() {
            io::ErrorKind::TimedOut if Instant::now() >= self.deadline => Failure::too_slow(),
            io::ErrorKind::TimedOut => {
                Failure::said(format!("firewalld timed out on {}", call.describe()))
            }
            io::ErrorKind::Interrupted => Failure::said("cancelled while reading firewalld".into()),
            _ => Failure::said(format!("cannot run busctl: {error}")),
        }
    }
}

impl Call<'_> {
    fn arguments(&self) -> Vec<&str> {
        match self {
            Call::NameHasOwner => vec![
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "NameHasOwner",
                "s",
                FIREWALLD,
            ],
            Call::ActiveZones => vec![FIREWALLD, FIREWALLD_PATH, ZONE_INTERFACE, "getActiveZones"],
            Call::LogDenied => vec![FIREWALLD, FIREWALLD_PATH, FIREWALLD, "getLogDenied"],
            Call::DefaultZone => vec![FIREWALLD, FIREWALLD_PATH, FIREWALLD, "getDefaultZone"],
            Call::ZoneSettings(zone) => vec![
                FIREWALLD,
                FIREWALLD_PATH,
                ZONE_INTERFACE,
                "getZoneSettings2",
                "s",
                zone,
            ],
            Call::ServiceSettings(service) => vec![
                FIREWALLD,
                FIREWALLD_PATH,
                FIREWALLD,
                "getServiceSettings2",
                "s",
                service,
            ],
        }
    }

    /// The method, and the zone or service it was about.
    fn describe(&self) -> String {
        match self {
            Call::NameHasOwner => "NameHasOwner".to_owned(),
            Call::ActiveZones => "getActiveZones".to_owned(),
            Call::DefaultZone => "getDefaultZone".to_owned(),
            Call::LogDenied => "getLogDenied".to_owned(),
            Call::ZoneSettings(zone) => format!("getZoneSettings2 {zone}"),
            Call::ServiceSettings(service) => format!("getServiceSettings2 {service}"),
        }
    }
}

impl Failure {
    fn too_slow() -> Self {
        Self::said("firewalld too slow to answer".to_owned())
    }

    fn said(reason: String) -> Self {
        Self {
            refused: false,
            reason: bounded(reason),
        }
    }

    fn of(call: &Call, error: ReplyError) -> Self {
        Self {
            refused: error == ReplyError::Refused,
            reason: bounded(explain(error, Some(call))),
        }
    }
}

/// What went wrong, first: the panes keep only the start of a reason. A reason from a call
/// already carries its own wording and passes through when there is no call to name.
fn explain(error: ReplyError, call: Option<&Call>) -> String {
    let at = call.map_or_else(String::new, |call| format!(" ({})", call.describe()));
    match (error, call) {
        (ReplyError::Failed(text), None) => text,
        (ReplyError::Refused, _) => format!("firewalld refused{at}"),
        (ReplyError::Empty, _) => format!("firewalld said nothing{at}"),
        (ReplyError::Failed(text), Some(_)) => format!("firewalld error: {text}{at}"),
        (ReplyError::Malformed(text), _) => format!("firewalld answered oddly: {text}{at}"),
    }
}

fn stop_failed(error: io::Error) -> FirewallHealth {
    FirewallHealth::Degraded(bounded(format!(
        "could not stop firewall input cleanly: {error}"
    )))
}

fn bounded(text: String) -> String {
    let line = text.lines().next().unwrap_or_default();
    match line.char_indices().nth(REASON_CHARS) {
        Some((end, _)) => format!("{}…", &line[..end]),
        None => line.to_owned(),
    }
}

impl FirewallProvider for FirewalldProvider {
    fn poll(
        &mut self,
        sender: &SyncSender<FirewallEvent>,
        cancelled: &AtomicBool,
    ) -> FirewallStatus {
        if cancelled.load(Ordering::Relaxed) {
            self.status.health = match self.stop_reader() {
                Ok(()) => FirewallHealth::Cancelled,
                Err(error) => stop_failed(error),
            };
            return self.status();
        }
        if let Some(reading) = self.unfollowed.take() {
            self.follow(reading);
        }
        if let Some(reader) = &mut self.blocks {
            let _ = reader.read_into_health(sender, cancelled, &mut self.status.health);
        }
        self.status()
    }

    fn rules(&mut self) -> RuleSnapshot {
        let pass = self.pass();
        let read = pass.read_rules();
        self.unfollowed = Some(pass.read_log_reading(&read));
        read.unwrap_or_else(|failure| RuleSnapshot::Unavailable(failure.reason))
    }

    fn status(&self) -> FirewallStatus {
        self.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";

    #[test]
    fn the_real_busctl_accepts_the_fixed_options_and_reads_a_name_every_bus_has() {
        let provider = FirewalldProvider::new(Arc::new(AtomicBool::new(false)));
        if !Path::new(&provider.busctl).is_file() || !Path::new(SYSTEM_BUS_SOCKET).exists() {
            eprintln!("skipped: no busctl in the system directories, or no system bus");
            return;
        }
        let command = provider.method_call(&[
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            "s",
            "org.freedesktop.DBus",
        ]);
        let (status, stdout, stderr) =
            run_within(command, CALL_TIMEOUT, &provider.cancelled).unwrap();
        let output = BusctlOutput {
            success: status.success(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        };
        assert_eq!(name_has_owner(&output), Ok(true), "{output:?}");
    }

    #[test]
    fn the_real_command_is_absolute_and_asks_without_a_password_and_never_changes_anything() {
        let provider = FirewalldProvider::new(Arc::new(AtomicBool::new(false)));
        let command = provider.command(&Call::ZoneSettings("public"));
        assert!(Path::new(command.get_program()).is_absolute());
        let arguments: Vec<_> = command.get_args().map(|a| a.to_string_lossy()).collect();
        assert_eq!(
            arguments[..5],
            [
                "--system",
                "--allow-interactive-authorization=no",
                "--json=short",
                "call",
                FIREWALLD
            ]
        );
        let calls = [
            Call::NameHasOwner,
            Call::ActiveZones,
            Call::DefaultZone,
            Call::ZoneSettings("x"),
            Call::ServiceSettings("x"),
            Call::LogDenied,
        ];
        for call in calls {
            let method = call.arguments()[3];
            assert!(
                method == "NameHasOwner" || method.starts_with("get"),
                "{method}"
            );
        }
    }
}

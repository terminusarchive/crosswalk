use std::{
    collections::HashMap,
    fs::{self, File, Metadata},
    io::{self, BufRead, BufReader, Seek, SeekFrom},
    mem,
    net::IpAddr,
    ops::ControlFlow,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{SyncSender, TrySendError},
    },
};

use serde_json::Value;

use super::{
    FirewallEndpoint, FirewallEvent, FirewallHealth, FirewallProvider, FirewallStatus, Network,
    Policy, Rule, RuleAction, RuleDirection, RuleSnapshot, RuleSource, input_for_source,
    unavailable,
};
use crate::{
    collect::capture::{Direction, Protocol},
    command::system_command,
    config::UfwSource,
};

const UFW_MARKER: &str = "[UFW BLOCK]";
pub(super) const DEFAULT_RECORD_LIMIT: usize = 64;
pub(super) const DEFAULT_RECORD_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputRead {
    Record(String),
    Idle,
}

pub trait FirewallInput: Send {
    fn next_record(&mut self) -> io::Result<InputRead>;
    fn shutdown(&mut self) -> io::Result<()>;
}

impl<T: FirewallInput + ?Sized> FirewallInput for Box<T> {
    fn next_record(&mut self) -> io::Result<InputRead> {
        (**self).next_record()
    }

    fn shutdown(&mut self) -> io::Result<()> {
        (**self).shutdown()
    }
}

pub struct UfwProvider<I> {
    reader: BlockReader<I>,
    status: FirewallStatus,
    rule_source: Option<RuleFiles>,
}

/// What marks a denied packet in the kernel's log: each firewall words it differently, and
/// the fields after it (`IN= OUT= SRC= DST= SPT= DPT= PROTO=`) are the kernel's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockMarker {
    /// `[UFW BLOCK]` anywhere in the message.
    Ufw,
    /// firewalld's `filter_IN_<zone>_REJECT: ` or `filter_IN_<zone>_DROP: ` at the start of
    /// the message.
    Firewalld,
}

/// Reads denied packets from a log into events, and says how the reading is going.
pub struct BlockReader<I> {
    input: I,
    marker: BlockMarker,
    record_limit: usize,
    record_bytes: usize,
}

struct RuleFiles {
    ufw_conf: PathBuf,
    ufw_defaults: PathBuf,
    user_rules: PathBuf,
    user6_rules: PathBuf,
}

pub(super) const UFW_CONF: &str = "/etc/ufw/ufw.conf";
const UFW_DEFAULTS: &str = "/etc/default/ufw";
const USER_RULES: &str = "/etc/ufw/user.rules";
const USER6_RULES: &str = "/etc/ufw/user6.rules";

impl<I: FirewallInput> UfwProvider<I> {
    /// Where `rules()` reads UFW's on/off setting, its default policies, and the IPv4 and
    /// IPv6 rule files.
    pub fn with_rule_files(
        mut self,
        ufw_conf: impl Into<PathBuf>,
        ufw_defaults: impl Into<PathBuf>,
        user_rules: impl Into<PathBuf>,
        user6_rules: impl Into<PathBuf>,
    ) -> Self {
        self.rule_source = Some(RuleFiles {
            ufw_conf: ufw_conf.into(),
            ufw_defaults: ufw_defaults.into(),
            user_rules: user_rules.into(),
            user6_rules: user6_rules.into(),
        });
        self
    }

    pub fn new(
        input: I,
        health: FirewallHealth,
        record_limit: usize,
        record_bytes: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            reader: BlockReader::new(input, BlockMarker::Ufw, record_limit, record_bytes)?,
            status: FirewallStatus {
                name: "ufw",
                health,
            },
            rule_source: None,
        })
    }
}

impl<I: FirewallInput> BlockReader<I> {
    pub fn new(
        input: I,
        marker: BlockMarker,
        record_limit: usize,
        record_bytes: usize,
    ) -> io::Result<Self> {
        if record_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "firewall record limit must be greater than zero",
            ));
        }
        if record_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "firewall record byte limit must be greater than zero",
            ));
        }
        Ok(Self {
            input,
            marker,
            record_limit,
            record_bytes,
        })
    }

    /// Reads up to the record limit, sending each block to `sender` and moving `health` as the
    /// reading goes. `Break` when `cancelled` was set before the reading was done.
    pub fn read_into_health(
        &mut self,
        sender: &SyncSender<FirewallEvent>,
        cancelled: &AtomicBool,
        health: &mut FirewallHealth,
    ) -> ControlFlow<()> {
        for _ in 0..self.record_limit {
            if cancelled.load(Ordering::Relaxed) {
                return ControlFlow::Break(());
            }
            if self.read_one(sender, health).is_break() {
                break;
            }
        }
        ControlFlow::Continue(())
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        self.input.shutdown()
    }

    /// Handles the next record. `Break` when there is nothing more to read now, or the reading
    /// went wrong, or the receiver is gone.
    fn read_one(
        &mut self,
        sender: &SyncSender<FirewallEvent>,
        health: &mut FirewallHealth,
    ) -> ControlFlow<()> {
        match self.input.next_record() {
            Ok(InputRead::Idle) => ControlFlow::Break(()),
            Ok(InputRead::Record(record)) => self.take_record(&record, sender, health),
            Err(error) => {
                *health = FirewallHealth::Degraded(format!(
                    "could not read {} input: {error}",
                    self.marker.label()
                ));
                ControlFlow::Break(())
            }
        }
    }

    /// `Break` when the receiver is gone.
    fn take_record(
        &self,
        record: &str,
        sender: &SyncSender<FirewallEvent>,
        health: &mut FirewallHealth,
    ) -> ControlFlow<()> {
        let label = self.marker.label();
        if record.len() > self.record_bytes {
            *health = FirewallHealth::Degraded(format!(
                "{label} record exceeded the configured size limit"
            ));
            return ControlFlow::Continue(());
        }
        match normalize_record(record, self.marker) {
            Ok(Some(event)) => deliver(event, sender, health),
            Ok(None) => ControlFlow::Continue(()),
            Err(error) => {
                *health = FirewallHealth::Degraded(error);
                ControlFlow::Continue(())
            }
        }
    }
}

fn deliver(
    event: FirewallEvent,
    sender: &SyncSender<FirewallEvent>,
    health: &mut FirewallHealth,
) -> ControlFlow<()> {
    match sender.try_send(event) {
        Ok(()) => {
            if matches!(
                health,
                FirewallHealth::AwaitingEvents
                    | FirewallHealth::Available
                    | FirewallHealth::DependsOnLogging
            ) {
                *health = FirewallHealth::Available;
            }
            ControlFlow::Continue(())
        }
        Err(TrySendError::Full(_)) => ControlFlow::Continue(()),
        Err(TrySendError::Disconnected(_)) => {
            *health = FirewallHealth::Degraded("firewall event receiver disconnected".to_owned());
            ControlFlow::Break(())
        }
    }
}

impl<I: FirewallInput> FirewallProvider for UfwProvider<I> {
    fn poll(
        &mut self,
        sender: &SyncSender<FirewallEvent>,
        cancelled: &AtomicBool,
    ) -> FirewallStatus {
        if cancelled.load(Ordering::Relaxed) {
            self.status.health = match self.reader.shutdown() {
                Ok(()) => FirewallHealth::Cancelled,
                Err(error) => FirewallHealth::Degraded(format!(
                    "could not stop firewall input cleanly: {error}"
                )),
            };
            return self.status();
        }

        if matches!(
            self.status.health,
            FirewallHealth::Disabled(_)
                | FirewallHealth::Unavailable(_)
                | FirewallHealth::Cancelled
        ) {
            return self.status();
        }

        if self
            .reader
            .read_into_health(sender, cancelled, &mut self.status.health)
            .is_break()
        {
            return self.poll(sender, cancelled);
        }
        self.status()
    }

    fn rules(&mut self) -> RuleSnapshot {
        match &mut self.rule_source {
            Some(source) => read_rules(source),
            None => RuleSnapshot::Unavailable("no UFW rule source configured".to_owned()),
        }
    }

    fn status(&self) -> FirewallStatus {
        self.status.clone()
    }
}

/// The last file name of a path, which is all a reason has room for.
fn file_name(path: &Path) -> std::path::Display<'_> {
    path.file_name().map_or(path, Path::new).display()
}

/// A short reading of an I/O error: "Not found", or the system's message without its
/// "(os error N)".
fn short_error(error: &io::Error) -> String {
    if error.kind() == io::ErrorKind::NotFound {
        return "Not found".to_owned();
    }
    let text = error.to_string();
    text.split(" (os error").next().unwrap_or(&text).to_owned()
}

/// The last uncommented `KEY=value` in a shell-style settings file, without quotes. The
/// reasons put the setting or error first, and name the file rather than its path, because
/// the pane shows only the first 30 characters of them.
fn setting(path: &Path, key: &str) -> Result<String, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("{}: {}", short_error(&error), file_name(path)))?;
    contents
        .lines()
        .filter_map(|line| line.trim().strip_prefix(key)?.strip_prefix('='))
        .map(|raw| {
            let value = raw.trim_start();
            match value.chars().next() {
                // An unterminated quote is not a value: keep it whole so it reads as unknown.
                Some(quote @ ('"' | '\'')) => value[1..]
                    .split_once(quote)
                    .map_or(value, |(inside, _)| inside),
                // A comment after whitespace ends the line, even before any value.
                Some('#') if value.len() < raw.len() => "",
                _ => value.split_whitespace().next().unwrap_or(""),
            }
        })
        .next_back()
        .map(str::to_owned)
        .ok_or_else(|| format!("{key} missing: {}", file_name(path)))
}

fn default_policy(defaults: &Path, key: &str) -> Result<Policy, String> {
    match setting(defaults, key)?.to_ascii_uppercase().as_str() {
        "ACCEPT" => Ok(Policy::Allow),
        "DROP" => Ok(Policy::Deny),
        "REJECT" => Ok(Policy::Reject),
        other => Err(format!(
            "'{other}' unknown for {key} in {}",
            file_name(defaults)
        )),
    }
}

pub(super) fn enabled(conf: &Path) -> Result<bool, String> {
    match setting(conf, "ENABLED")?.to_ascii_lowercase().as_str() {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => Err(format!(
            "'{other}' unknown for ENABLED in {}",
            file_name(conf)
        )),
    }
}

fn read_rules(source: &mut RuleFiles) -> RuleSnapshot {
    match enabled(&source.ufw_conf) {
        Ok(true) => {}
        Ok(false) => return RuleSnapshot::Inactive,
        Err(reason) => return RuleSnapshot::Unavailable(reason),
    }
    let default_incoming = match default_policy(&source.ufw_defaults, "DEFAULT_INPUT_POLICY") {
        Ok(policy) => policy,
        Err(reason) => return RuleSnapshot::Unavailable(reason),
    };
    let default_outgoing = match default_policy(&source.ufw_defaults, "DEFAULT_OUTPUT_POLICY") {
        Ok(policy) => policy,
        Err(reason) => return RuleSnapshot::Unavailable(reason),
    };

    let mut rules = Vec::new();
    for (path, ipv6) in [(&source.user_rules, false), (&source.user6_rules, true)] {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) => {
                return RuleSnapshot::Unavailable(format!(
                    "could not read '{}': {error}",
                    path.display()
                ));
            }
        };
        for line in contents.lines() {
            let Some(tuple) = line.trim().strip_prefix("### tuple ###") else {
                continue;
            };
            match parse_tuple(tuple.trim(), ipv6) {
                Ok(Some(rule)) => rules.push(rule),
                Ok(None) => {}
                // Outbound rules never affect exposure, so a fault in one is skipped.
                Err(_) if is_out_tuple(tuple) => {}
                Err(reason) => {
                    return RuleSnapshot::Unavailable(format!(
                        "could not parse UFW rule '{}' in '{}': {reason}",
                        line.trim(),
                        path.display()
                    ));
                }
            }
        }
    }
    RuleSnapshot::Active {
        default_incoming,
        default_outgoing,
        rules,
    }
}

/// The tuple's whitespace fields without a trailing `comment=<hex>` field, which
/// ufw appends after the direction.
fn tuple_fields(tuple: &str) -> Vec<&str> {
    let mut fields: Vec<&str> = tuple.split_whitespace().collect();
    if fields
        .last()
        .is_some_and(|field| field.starts_with("comment="))
    {
        fields.pop();
    }
    fields
}

fn is_out_tuple(tuple: &str) -> bool {
    tuple_fields(tuple)
        .last()
        .is_some_and(|direction| *direction == "out" || direction.starts_with("out_"))
}

/// Parses `<action> <proto> <dport> <dst> <sport> <src> [<dapp> <sapp>] <direction>`.
/// Returns `None` for route tuples and any direction other than `in` and `out`.
fn parse_tuple(tuple: &str, ipv6: bool) -> Result<Option<Rule>, String> {
    let fields = tuple_fields(tuple);
    if fields.len() != 7 && fields.len() != 9 {
        return Err(format!("expected 7 or 9 fields, found {}", fields.len()));
    }
    let direction = fields[fields.len() - 1];
    let (direction, interface) = match direction.split_once('_') {
        Some((direction, interface)) => (direction, Some(interface.to_owned())),
        None => (direction, None),
    };
    let direction = match direction {
        "in" if !fields[0].starts_with("route:") => RuleDirection::In,
        "out" if !fields[0].starts_with("route:") => RuleDirection::Out,
        _ => return Ok(None),
    };
    let action = fields[0]
        .strip_suffix("_log-all")
        .or_else(|| fields[0].strip_suffix("_log"))
        .unwrap_or(fields[0]);
    let action = match action {
        "allow" => RuleAction::Allow,
        "limit" => RuleAction::Limit,
        "deny" => RuleAction::Deny,
        "reject" => RuleAction::Reject,
        other => return Err(format!("unknown action '{other}'")),
    };
    let protocol = match fields[1] {
        "any" => None,
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        _ => Some(Protocol::Other(0)),
    };
    let ports = if fields[2] == "any" {
        Vec::new()
    } else {
        fields[2]
            .split(',')
            .map(parse_ports)
            .collect::<Result<_, _>>()?
    };
    let destination = parse_network(fields[3])?;
    let source = match (fields[4], parse_network(fields[5])?) {
        ("any", None) => RuleSource::Anywhere,
        ("any", Some(_)) => RuleSource::Specific(fields[5].to_owned()),
        (port, None) => RuleSource::Specific(format!("source port {port}")),
        (port, Some(_)) => RuleSource::Specific(format!("{} port {port}", fields[5])),
    };
    Ok(Some(Rule {
        direction,
        action,
        protocol,
        ports,
        destination,
        source,
        interface,
        ipv6,
        text: fields.join(" "),
    }))
}

fn parse_ports(text: &str) -> Result<std::ops::RangeInclusive<u16>, String> {
    let port = |value: &str| {
        value
            .parse::<u16>()
            .map_err(|_| format!("invalid port '{text}'"))
    };
    match text.split_once(':') {
        Some((start, end)) => Ok(port(start)?..=port(end)?),
        None => Ok(port(text)?..=port(text)?),
    }
}

/// `None` for anywhere (`/0`).
fn parse_network(text: &str) -> Result<Option<Network>, String> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (text, None),
    };
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("invalid address '{text}'"))?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix
            .parse::<u8>()
            .ok()
            .filter(|prefix| *prefix <= width)
            .ok_or_else(|| format!("invalid prefix in '{text}'"))?,
        None => width,
    };
    Ok((prefix != 0).then_some(Network { address, prefix }))
}

/// `filter_IN_<zone>_REJECT:` or `filter_IN_<zone>_DROP:`, the first word of the message. The
/// action ends the word, so a zone name may hold underscores or any character but whitespace.
fn is_denied_input_prefix(word: &str) -> bool {
    let Some(rest) = word.strip_prefix("filter_IN_") else {
        return false;
    };
    let zone = rest
        .strip_suffix("_REJECT:")
        .or_else(|| rest.strip_suffix("_DROP:"));
    zone.is_some_and(|zone| !zone.is_empty())
}

impl BlockMarker {
    /// Where the marker starts in `message` and where the kernel's fields start after it.
    fn locate(self, message: &str) -> Option<(usize, usize)> {
        match self {
            BlockMarker::Ufw => {
                let start = message.find(UFW_MARKER)?;
                Some((start, start + UFW_MARKER.len()))
            }
            BlockMarker::Firewalld => {
                let end = message.find(char::is_whitespace)?;
                is_denied_input_prefix(&message[..end]).then_some((0, end))
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            BlockMarker::Ufw => "UFW",
            BlockMarker::Firewalld => "firewalld",
        }
    }
}

fn normalize_record(record: &str, marker: BlockMarker) -> Result<Option<FirewallEvent>, String> {
    let (message, timestamp) = journal_fields(record)?;
    let Some((marker_start, fields_start)) = marker.locate(&message) else {
        return Ok(None);
    };
    let fields: HashMap<&str, &str> = message[fields_start..]
        .split_whitespace()
        .filter_map(|field| field.split_once('='))
        .collect();
    if fields.is_empty() {
        return Err(format!(
            "malformed {} block record has no fields",
            marker.label()
        ));
    }

    let incoming = nonempty(fields.get("IN").copied());
    let outgoing = nonempty(fields.get("OUT").copied());
    let (direction, interface) = match (incoming, outgoing) {
        (Some(interface), None) => (Some(Direction::Inbound), Some(interface.to_owned())),
        (None, Some(interface)) => (Some(Direction::Outbound), Some(interface.to_owned())),
        _ => (None, None),
    };

    Ok(Some(FirewallEvent {
        timestamp: timestamp.or_else(|| file_timestamp(&message, marker_start)),
        direction,
        interface,
        protocol: fields.get("PROTO").and_then(|value| protocol(value)),
        source: endpoint(fields.get("SRC"), fields.get("SPT")),
        destination: endpoint(fields.get("DST"), fields.get("DPT")),
    }))
}

fn journal_fields(record: &str) -> Result<(String, Option<String>), String> {
    if !record.trim_start().starts_with('{') {
        return Ok((record.to_owned(), None));
    }
    let value: Value = serde_json::from_str(record)
        .map_err(|error| format!("malformed journal record: {error}"))?;
    let message = value
        .get("MESSAGE")
        .and_then(Value::as_str)
        .ok_or_else(|| "journal record has no MESSAGE field".to_owned())?;
    let timestamp = value
        .get("__REALTIME_TIMESTAMP")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok((message.to_owned(), timestamp))
}

fn file_timestamp(message: &str, marker: usize) -> Option<String> {
    let prefix = message[..marker].trim().trim_end_matches("kernel:").trim();
    (!prefix.is_empty()).then(|| prefix.to_owned())
}

fn endpoint(ip: Option<&&str>, port: Option<&&str>) -> FirewallEndpoint {
    FirewallEndpoint {
        ip: ip.and_then(|value| value.parse::<IpAddr>().ok()),
        port: port.and_then(|value| value.parse::<u16>().ok()),
    }
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

fn protocol(value: &str) -> Option<Protocol> {
    match value.to_ascii_uppercase().as_str() {
        "TCP" => Some(Protocol::Tcp),
        "UDP" => Some(Protocol::Udp),
        "ICMP" => Some(Protocol::Other(1)),
        "IPV6-ICMP" | "ICMPV6" => Some(Protocol::Other(58)),
        _ => None,
    }
}

pub fn checked_ufw_health(conf: &Path) -> FirewallHealth {
    match enabled(conf) {
        Ok(true) => {}
        Ok(false) => {
            return FirewallHealth::Disabled(
                "UFW is inactive; see firewall setup guidance".to_owned(),
            );
        }
        Err(reason) => {
            return FirewallHealth::Unavailable(format!("{reason}; see firewall setup guidance"));
        }
    }
    match setting(conf, "LOGLEVEL") {
        Ok(level) if level.eq_ignore_ascii_case("off") => FirewallHealth::Disabled(
            "UFW logging is disabled; see firewall setup guidance".to_owned(),
        ),
        Ok(_) => FirewallHealth::AwaitingEvents,
        Err(reason) => {
            FirewallHealth::Unavailable(format!("{reason}; see firewall setup guidance"))
        }
    }
}

struct IdleInput;

impl FirewallInput for IdleInput {
    fn next_record(&mut self) -> io::Result<InputRead> {
        Ok(InputRead::Idle)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn with_system_rules<I: FirewallInput>(provider: UfwProvider<I>, conf: &Path) -> UfwProvider<I> {
    provider.with_rule_files(conf, UFW_DEFAULTS, USER_RULES, USER6_RULES)
}

/// Builds the UFW provider, reading UFW's on/off and logging settings from `conf`.
/// A `conf` that cannot be read or lacks a setting does not stop the event input: blocks
/// are still read, and the source waits for events as it would with a healthy `conf`.
/// Only UFW being off and logging being off keep the input from starting.
pub fn create_with_conf(source: &UfwSource, conf: &Path) -> Box<dyn FirewallProvider> {
    let health = match checked_ufw_health(conf) {
        FirewallHealth::Unavailable(_) => FirewallHealth::AwaitingEvents,
        checked => checked,
    };
    let (input, health) = if health == FirewallHealth::AwaitingEvents {
        match input_for_source(source) {
            Ok(input) => (input, health),
            Err(error) => (
                Box::new(IdleInput) as Box<dyn FirewallInput>,
                unavailable(format!(
                    "could not open UFW event source: {error}; see firewall setup guidance"
                )),
            ),
        }
    } else {
        (Box::new(IdleInput) as Box<dyn FirewallInput>, health)
    };
    Box::new(with_system_rules(
        UfwProvider::new(input, health, DEFAULT_RECORD_LIMIT, DEFAULT_RECORD_BYTES)
            .expect("fixed UFW limits are valid"),
        conf,
    ))
}

pub struct FileInput {
    path: PathBuf,
    lines: LineReader<BufReader<File>>,
    identity: FileIdentity,
    /// Where in the file `lines` began reading.
    start: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

impl FileInput {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let mut file = File::open(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("could not open UFW log '{}': {error}", path.display()),
            )
        })?;
        let metadata = file.metadata()?;
        let start = file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path,
            lines: LineReader::new(BufReader::new(file)),
            identity: FileIdentity::from(&metadata),
            start,
        })
    }

    fn reset_if_replaced_or_truncated(&mut self) -> io::Result<bool> {
        let metadata = fs::metadata(&self.path)?;
        let identity = FileIdentity::from(&metadata);
        if identity == self.identity
            && metadata.len() >= self.start.saturating_add(self.lines.bytes_read)
        {
            return Ok(false);
        }
        let mut file = File::open(&self.path)?;
        self.start = file.seek(SeekFrom::End(0))?;
        self.lines = LineReader::new(BufReader::new(file));
        self.identity = identity;
        Ok(true)
    }
}

impl FirewallInput for FileInput {
    fn next_record(&mut self) -> io::Result<InputRead> {
        if self.reset_if_replaced_or_truncated()? {
            return Ok(InputRead::Idle);
        }
        self.lines.next_line()
    }

    fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Gives out a line only once its newline has arrived. A read that finds the line half
/// written has already moved the first half out of the reader, so the half is kept here,
/// as bytes because the half may end inside a character, until the rest comes. Bytes
/// still held when the input ends are not a line and are never given out.
pub struct LineReader<R> {
    reader: R,
    held: Vec<u8>,
    bytes_read: u64,
}

impl<R: BufRead> LineReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            held: Vec::new(),
            bytes_read: 0,
        }
    }

    pub fn next_line(&mut self) -> io::Result<InputRead> {
        let before = self.held.len();
        let read = self.reader.read_until(b'\n', &mut self.held);
        self.bytes_read = self
            .bytes_read
            .saturating_add((self.held.len() - before) as u64);
        match read {
            Ok(_) if self.held.ends_with(b"\n") => {
                let line = String::from_utf8(mem::take(&mut self.held))
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                Ok(InputRead::Record(
                    line.trim_end_matches(['\r', '\n']).to_owned(),
                ))
            }
            Ok(_) => Ok(InputRead::Idle),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(InputRead::Idle),
            Err(error) => Err(error),
        }
    }
}

pub trait JournalProcess: Send {
    fn next_line(&mut self) -> io::Result<InputRead>;
    fn exit_code(&mut self) -> io::Result<Option<i32>>;
    fn terminate_and_wait(&mut self) -> io::Result<()>;
}

pub struct JournalInput<P> {
    process: P,
}

impl<P> JournalInput<P> {
    pub fn new(process: P) -> Self {
        Self { process }
    }
}

impl<P: JournalProcess> FirewallInput for JournalInput<P> {
    fn next_record(&mut self) -> io::Result<InputRead> {
        let read = self.process.next_line()?;
        if read == InputRead::Idle
            && let Some(code) = self.process.exit_code()?
        {
            return Err(io::Error::other(format!(
                "journalctl exited with status {code}"
            )));
        }
        Ok(read)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        self.process.terminate_and_wait()
    }
}

/// The kernel journal, followed from now on.
pub(super) fn journal_input() -> io::Result<Box<dyn FirewallInput>> {
    CommandJournalProcess::spawn()
        .map(JournalInput::new)
        .map(|input| Box::new(input) as Box<dyn FirewallInput>)
}

pub(super) struct CommandJournalProcess {
    child: Child,
    lines: LineReader<BufReader<ChildStdout>>,
}

impl CommandJournalProcess {
    pub(super) fn spawn() -> io::Result<Self> {
        let mut child = system_command("journalctl")
            .args(["--follow", "--lines=0", "--output=json", "--dmesg"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("journalctl stdout was not captured"))?;
        set_nonblocking(stdout.as_raw_fd())?;
        Ok(Self {
            child,
            lines: LineReader::new(BufReader::new(stdout)),
        })
    }
}

impl JournalProcess for CommandJournalProcess {
    fn next_line(&mut self) -> io::Result<InputRead> {
        self.lines.next_line()
    }

    fn exit_code(&mut self) -> io::Result<Option<i32>> {
        Ok(self
            .child
            .try_wait()?
            .map(|status| status.code().unwrap_or(-1)))
    }

    fn terminate_and_wait(&mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        self.child.wait()?;
        Ok(())
    }
}

impl Drop for CommandJournalProcess {
    fn drop(&mut self) {
        let _ = self.terminate_and_wait();
    }
}

fn set_nonblocking(file_descriptor: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(file_descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(file_descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::{self, BufReader, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::AtomicBool, mpsc::sync_channel},
};

use crosswalk::collect::attribution::Listener;
use crosswalk::config::UfwSource;

mod common;
use common::listener;

use crosswalk::{
    collect::capture::{Direction, Protocol},
    firewall::{
        Exposure, FileInput, FirewallEvent, FirewallHealth, FirewallInput, FirewallOutcome,
        FirewallProvider, FirewallStatus, InputRead, JournalInput, JournalProcess, LineReader,
        Network, Policy, Rule, RuleAction, RuleDirection, RuleSnapshot, UfwProvider,
        checked_ufw_health, create_with_conf, exposure,
    },
};

struct ScriptedInput {
    reads: VecDeque<io::Result<InputRead>>,
    stopped: Arc<Mutex<bool>>,
}

impl ScriptedInput {
    fn new(reads: impl IntoIterator<Item = io::Result<InputRead>>) -> (Self, Arc<Mutex<bool>>) {
        let stopped = Arc::new(Mutex::new(false));
        (
            Self {
                reads: reads.into_iter().collect(),
                stopped: Arc::clone(&stopped),
            },
            stopped,
        )
    }
}

impl FirewallInput for ScriptedInput {
    fn next_record(&mut self) -> io::Result<InputRead> {
        self.reads.pop_front().unwrap_or(Ok(InputRead::Idle))
    }

    fn shutdown(&mut self) -> io::Result<()> {
        *self.stopped.lock().unwrap() = true;
        Ok(())
    }
}

fn poll_lines(lines: &[&str]) -> (Vec<FirewallEvent>, FirewallStatus) {
    let reads = lines
        .iter()
        .map(|line| Ok(InputRead::Record((*line).to_owned())))
        .chain([Ok(InputRead::Idle)]);
    let (input, _) = ScriptedInput::new(reads);
    let mut provider = UfwProvider::new(input, FirewallHealth::AwaitingEvents, 32, 4096).unwrap();
    let (sender, receiver) = sync_channel(32);
    let status = provider.poll(&sender, &AtomicBool::new(false));
    (receiver.try_iter().collect(), status)
}

#[test]
fn normalizes_ipv4_ipv6_and_incomplete_ufw_blocks_only() {
    let (events, status) = poll_lines(&[
        r#"{"MESSAGE":"[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.8 DST=192.0.2.10 PROTO=TCP SPT=41234 DPT=22","__REALTIME_TIMESTAMP":"1791460800000000"}"#,
        "Oct  8 12:01:00 host kernel: [UFW BLOCK] IN= OUT=wg0 SRC=2001:db8::1 DST=2001:db8::2 PROTO=UDP SPT=5353 DPT=53",
        "Oct  8 12:02:00 host kernel: [UFW BLOCK] IN=eth1 OUT= PROTO=UDP",
        "Oct  8 12:03:00 host kernel: ordinary kernel message",
    ]);

    assert_eq!(events.len(), 3);
    assert_eq!(events[0].outcome, FirewallOutcome::Blocked);
    assert_eq!(events[0].timestamp.as_deref(), Some("1791460800000000"));
    assert_eq!(events[0].direction, Some(Direction::Inbound));
    assert_eq!(events[0].interface.as_deref(), Some("eth0"));
    assert_eq!(events[0].protocol, Some(Protocol::Tcp));
    assert_eq!(
        events[0].source.ip,
        Some("198.51.100.8".parse::<IpAddr>().unwrap())
    );
    assert_eq!(events[0].source.port, Some(41_234));
    assert_eq!(
        events[0].destination.ip,
        Some("192.0.2.10".parse().unwrap())
    );
    assert_eq!(events[0].destination.port, Some(22));

    assert_eq!(events[1].direction, Some(Direction::Outbound));
    assert_eq!(events[1].interface.as_deref(), Some("wg0"));
    assert_eq!(events[1].protocol, Some(Protocol::Udp));
    assert_eq!(events[1].source.ip, Some("2001:db8::1".parse().unwrap()));
    assert_eq!(
        events[1].destination.ip,
        Some("2001:db8::2".parse().unwrap())
    );

    assert_eq!(events[2].source.ip, None);
    assert_eq!(events[2].source.port, None);
    assert_eq!(events[2].destination.ip, None);
    assert_eq!(events[2].destination.port, None);
    assert_eq!(events[2].process, None);
    assert_eq!(status.health, FirewallHealth::Available);
    assert_eq!(status.records_read, 4);
    assert_eq!(status.events_emitted, 3);
}

#[test]
fn reports_malformed_input_errors_awaiting_state_and_queue_loss() {
    let (events, malformed) = poll_lines(&["kernel: [UFW BLOCK] not-key-values"]);
    assert!(events.is_empty());
    assert!(matches!(malformed.health, FirewallHealth::Degraded(_)));
    assert_eq!(malformed.malformed_records, 1);

    let (input, _) = ScriptedInput::new([Ok(InputRead::Idle)]);
    let mut awaiting = UfwProvider::new(input, FirewallHealth::AwaitingEvents, 1, 128).unwrap();
    let (sender, _) = sync_channel(1);
    assert_eq!(
        awaiting.poll(&sender, &AtomicBool::new(false)).health,
        FirewallHealth::AwaitingEvents
    );

    let (input, _) = ScriptedInput::new([Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "journal is inaccessible",
    ))]);
    let mut failed = UfwProvider::new(input, FirewallHealth::AwaitingEvents, 1, 128).unwrap();
    assert!(matches!(
        failed.poll(&sender, &AtomicBool::new(false)).health,
        FirewallHealth::Degraded(message) if message.contains("inaccessible")
    ));

    let block = "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.8 DST=192.0.2.10 PROTO=TCP";
    let (input, _) = ScriptedInput::new([
        Ok(InputRead::Record(block.to_owned())),
        Ok(InputRead::Record(block.to_owned())),
    ]);
    let mut saturated = UfwProvider::new(input, FirewallHealth::AwaitingEvents, 2, 1024).unwrap();
    let (sender, _receiver) = sync_channel(1);
    let status = saturated.poll(&sender, &AtomicBool::new(false));
    assert_eq!(status.events_emitted, 1);
    assert_eq!(status.delivery_dropped, 1);
}

fn conf_health(conf: &str) -> FirewallHealth {
    checked_ufw_health(TempFile::new(conf).path())
}

#[test]
fn distinguishes_disabled_logging_from_inaccessible_configuration() {
    assert!(matches!(
        conf_health("ENABLED=yes\nLOGLEVEL=off\n"),
        FirewallHealth::Disabled(message) if message.contains("logging")
    ));
    assert!(matches!(
        conf_health("ENABLED=no\nLOGLEVEL=low\n"),
        FirewallHealth::Disabled(message) if message.contains("inactive")
    ));
    assert_eq!(
        conf_health("ENABLED=yes\nLOGLEVEL=low\n"),
        FirewallHealth::AwaitingEvents
    );
    assert!(matches!(
        conf_health("ENABLED=yes\n"),
        FirewallHealth::Unavailable(message) if message.contains("LOGLEVEL")
    ));
    assert!(matches!(
        checked_ufw_health(Path::new("/nonexistent/crosswalk/ufw.conf")),
        FirewallHealth::Unavailable(message)
            if message.starts_with("Not found: ufw.conf")
    ));
}

static TEMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "crosswalk-firewall-{}-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, contents).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn append(&self, line: &str) {
        writeln!(
            OpenOptions::new().append(true).open(&self.path).unwrap(),
            "{line}"
        )
        .unwrap();
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(self.path.with_extension("rotated"));
    }
}

#[test]
fn file_follow_skips_history_and_does_not_replay_after_rotation_or_truncation() {
    let old = "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.1 DST=192.0.2.1 PROTO=TCP";
    let fresh = "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.2 DST=192.0.2.2 PROTO=TCP";
    let file = TempFile::new(&format!("{old}\n"));
    let mut input = FileInput::open(file.path()).unwrap();
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);
    file.append(fresh);
    assert_eq!(
        input.next_record().unwrap(),
        InputRead::Record(fresh.to_owned())
    );

    let rotated = file.path().with_extension("rotated");
    fs::rename(file.path(), &rotated).unwrap();
    fs::write(file.path(), format!("{old}\n")).unwrap();
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);
    file.append(fresh);
    assert_eq!(
        input.next_record().unwrap(),
        InputRead::Record(fresh.to_owned())
    );

    fs::write(file.path(), format!("{old}\n")).unwrap();
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);
    file.append(fresh);
    assert_eq!(
        input.next_record().unwrap(),
        InputRead::Record(fresh.to_owned())
    );
}

/// A pipe that gives what it is told to: a piece of bytes, or nothing readable yet.
struct Pipe(VecDeque<Option<&'static [u8]>>);

impl Read for Pipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.0.pop_front() {
            Some(Some(text)) => {
                buffer[..text.len()].copy_from_slice(text);
                Ok(text.len())
            }
            Some(None) | None => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

fn lines_from(pieces: Vec<Option<&'static [u8]>>) -> LineReader<BufReader<Pipe>> {
    LineReader::new(BufReader::new(Pipe(pieces.into())))
}

fn record(text: &str) -> io::Result<InputRead> {
    Ok(InputRead::Record(text.to_owned()))
}

#[test]
fn a_line_given_in_two_parts_is_one_line_and_the_first_part_alone_gives_nothing() {
    let mut lines = lines_from(vec![
        Some(b"{\"MESSAGE\":\"[UFW BL"),
        None,
        Some(b"OCK]\"}\n"),
    ]);
    assert_eq!(lines.next_line().unwrap(), InputRead::Idle);
    assert_eq!(
        lines.next_line().unwrap(),
        InputRead::Record("{\"MESSAGE\":\"[UFW BLOCK]\"}".to_owned())
    );
}

#[test]
fn a_character_split_across_two_reads_is_read_whole() {
    let mut lines = lines_from(vec![Some(b"ab\xC3"), None, Some(b"\xA9cd\n")]);
    assert_eq!(lines.next_line().unwrap(), InputRead::Idle);
    assert_eq!(lines.next_line().unwrap(), record("ab\u{e9}cd").unwrap());
}

#[test]
fn a_line_given_in_three_parts_is_still_one_line() {
    let mut lines = lines_from(vec![Some(b"ab"), None, Some(b"cd"), None, Some(b"ef\n")]);
    assert_eq!(lines.next_line().unwrap(), InputRead::Idle);
    assert_eq!(lines.next_line().unwrap(), InputRead::Idle);
    assert_eq!(
        lines.next_line().unwrap(),
        InputRead::Record("abcdef".to_owned())
    );
}

#[test]
fn a_complete_line_is_given_at_once_and_two_lines_in_one_read_are_two_lines() {
    let mut lines = lines_from(vec![Some(b"one\r\ntwo\nthree\n")]);
    assert_eq!(lines.next_line().unwrap(), record("one").unwrap());
    assert_eq!(lines.next_line().unwrap(), record("two").unwrap());
    assert_eq!(lines.next_line().unwrap(), record("three").unwrap());
    assert_eq!(lines.next_line().unwrap(), InputRead::Idle);
}

#[test]
fn a_log_file_line_without_its_newline_is_not_a_record_until_it_is_written() {
    let first = "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.1 DST=192.0.2.1 PROTO=TCP";
    let file = TempFile::new("");
    let mut input = FileInput::open(file.path()).unwrap();
    write!(
        OpenOptions::new().append(true).open(file.path()).unwrap(),
        "{}",
        &first[..20]
    )
    .unwrap();
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);
    file.append(&first[20..]);
    assert_eq!(
        input.next_record().unwrap(),
        InputRead::Record(first.to_owned())
    );
}

const HELD_LINE: &str = "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.1 DST=192.0.2.1 PROTO=TCP";
const NEW_LINE: &str = "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.2 DST=192.0.2.2 PROTO=TCP";

fn append_without_newline(file: &TempFile, text: &str) {
    write!(
        OpenOptions::new().append(true).open(file.path()).unwrap(),
        "{text}"
    )
    .unwrap();
}

#[test]
fn a_part_line_held_when_the_log_is_rotated_is_dropped_and_not_joined_to_the_new_file() {
    let file = TempFile::new("");
    let mut input = FileInput::open(file.path()).unwrap();
    append_without_newline(&file, &HELD_LINE[..30]);
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);

    fs::rename(file.path(), file.path().with_extension("rotated")).unwrap();
    fs::write(file.path(), "").unwrap();
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);
    file.append(NEW_LINE);
    assert_eq!(
        input.next_record().unwrap(),
        InputRead::Record(NEW_LINE.to_owned())
    );
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);
}

#[test]
fn a_part_line_held_when_the_log_is_truncated_is_dropped_and_not_joined_to_the_next_line() {
    let file = TempFile::new("");
    let mut input = FileInput::open(file.path()).unwrap();
    append_without_newline(&file, &HELD_LINE[..30]);
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);

    fs::write(file.path(), &HELD_LINE[..10]).unwrap();
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);
    file.append(NEW_LINE);
    assert_eq!(
        input.next_record().unwrap(),
        InputRead::Record(NEW_LINE.to_owned())
    );
    assert_eq!(input.next_record().unwrap(), InputRead::Idle);
}

struct ScriptedProcess {
    reads: VecDeque<io::Result<InputRead>>,
    exit: Option<i32>,
    stopped: Arc<Mutex<bool>>,
}

impl JournalProcess for ScriptedProcess {
    fn next_line(&mut self) -> io::Result<InputRead> {
        self.reads.pop_front().unwrap_or(Ok(InputRead::Idle))
    }

    fn exit_code(&mut self) -> io::Result<Option<i32>> {
        Ok(self.exit)
    }

    fn terminate_and_wait(&mut self) -> io::Result<()> {
        *self.stopped.lock().unwrap() = true;
        Ok(())
    }
}

#[test]
fn journal_exit_and_cancellation_are_reported_without_hanging() {
    let stopped = Arc::new(Mutex::new(false));
    let process = ScriptedProcess {
        reads: VecDeque::from([Ok(InputRead::Idle)]),
        exit: Some(1),
        stopped: Arc::clone(&stopped),
    };
    let (sender, _) = sync_channel(1);
    let mut exited = UfwProvider::new(
        JournalInput::new(process),
        FirewallHealth::AwaitingEvents,
        1,
        128,
    )
    .unwrap();
    assert!(matches!(
        exited.poll(&sender, &AtomicBool::new(false)).health,
        FirewallHealth::Degraded(message) if message.contains("exited")
    ));

    let stopped = Arc::new(Mutex::new(false));
    let process = ScriptedProcess {
        reads: VecDeque::new(),
        exit: None,
        stopped: Arc::clone(&stopped),
    };
    let mut cancelled = UfwProvider::new(
        JournalInput::new(process),
        FirewallHealth::AwaitingEvents,
        1,
        128,
    )
    .unwrap();
    cancelled.poll(&sender, &AtomicBool::new(true));
    assert_eq!(cancelled.status().health, FirewallHealth::Cancelled);
    assert!(*stopped.lock().unwrap());
}

struct OtherProvider {
    event: Option<FirewallEvent>,
}

impl FirewallProvider for OtherProvider {
    fn poll(
        &mut self,
        sender: &std::sync::mpsc::SyncSender<FirewallEvent>,
        _cancelled: &AtomicBool,
    ) -> FirewallStatus {
        if let Some(event) = self.event.take() {
            sender.try_send(event).unwrap();
        }
        self.status()
    }

    fn rules(&mut self) -> RuleSnapshot {
        RuleSnapshot::Inactive
    }

    fn status(&self) -> FirewallStatus {
        FirewallStatus {
            health: FirewallHealth::Available,
            records_read: 1,
            events_emitted: 1,
            malformed_records: 0,
            delivery_dropped: 0,
        }
    }
}

#[test]
fn another_adapter_uses_the_same_normalized_contract() {
    fn collect(provider: &mut dyn FirewallProvider) -> FirewallEvent {
        let (sender, receiver) = sync_channel(1);
        provider.poll(&sender, &AtomicBool::new(false));
        receiver.try_recv().unwrap()
    }

    let expected = FirewallEvent::blocked_unknown();
    let mut provider = OtherProvider {
        event: Some(expected.clone()),
    };
    assert_eq!(collect(&mut provider), expected);
}

const ACTIVE_DENY: &str = "DROP";
const ACTIVE_ALLOW: &str = "ACCEPT";
const ACTIVE_REJECT: &str = "REJECT";
const ENABLED: &str = "ENABLED=yes\n";

fn defaults(incoming: &str) -> String {
    format!("DEFAULT_INPUT_POLICY=\"{incoming}\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n")
}

/// The incoming default is given; UFW is enabled and outgoing is accept.
fn snapshot(incoming: &str, v4: &str, v6: &str) -> RuleSnapshot {
    snapshot_from(ENABLED, &defaults(incoming), v4, v6)
}

fn snapshot_from(conf: &str, defaults: &str, v4: &str, v6: &str) -> RuleSnapshot {
    let conf = TempFile::new(conf);
    let defaults = TempFile::new(defaults);
    let user = TempFile::new(v4);
    let user6 = TempFile::new(v6);
    snapshot_at(conf.path(), defaults.path(), user.path(), user6.path())
}

fn snapshot_at(conf: &Path, defaults: &Path, user: &Path, user6: &Path) -> RuleSnapshot {
    let (input, _) = ScriptedInput::new([]);
    let mut provider = UfwProvider::new(input, FirewallHealth::AwaitingEvents, 1, 128)
        .unwrap()
        .with_rule_files(conf, defaults, user, user6);
    provider.rules()
}

fn tuple(rest: &str) -> String {
    format!("### tuple ### {rest}\n-A ufw-user-input -j ACCEPT\n")
}

fn tcp(port: u16) -> Listener {
    listener(Protocol::Tcp, "0.0.0.0", port)
}

fn exposure_for(incoming: &str, v4: &str, l: &Listener) -> Exposure {
    exposure(l, &snapshot(incoming, v4, ""))
}

fn kind(e: &Exposure) -> &'static str {
    match e {
        Exposure::Open(_) => "open",
        Exposure::Limited(_) => "limited",
        Exposure::Blocked(_) => "blocked",
        Exposure::Local => "local",
        Exposure::Unknown(_) => "unknown",
    }
}

#[test]
fn tuple_lines_parse_into_inbound_rules() {
    let rules = tuple("allow tcp 24800 0.0.0.0/0 any 10.0.1.12 in")
        + &tuple("allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in")
        + &tuple("deny udp 6000:6007 0.0.0.0/0 any 0.0.0.0/0 in")
        + &tuple("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_eth0")
        + &tuple("limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in")
        + &tuple("allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 Nginx%20Full - in")
        + &tuple("allow tcp 53 0.0.0.0/0 any 0.0.0.0/0 out");
    let RuleSnapshot::Active {
        default_incoming,
        rules,
        ..
    } = snapshot(ACTIVE_DENY, &rules, "")
    else {
        panic!("expected an active snapshot");
    };
    assert_eq!(default_incoming, Policy::Deny);
    assert_eq!(rules.len(), 7, "the out tuple is kept");
    assert_eq!(rules[6].direction, RuleDirection::Out);

    use crosswalk::firewall::RuleSource;
    assert_eq!(rules[0].action, RuleAction::Allow);
    assert_eq!(rules[0].protocol, Some(Protocol::Tcp));
    assert_eq!(rules[0].ports, vec![24800..=24800]);
    assert_eq!(
        rules[0].source,
        RuleSource::Specific("10.0.1.12".to_owned())
    );
    assert_eq!(rules[1].ports, vec![80..=80, 443..=443]);
    assert_eq!(rules[1].source, RuleSource::Anywhere);
    assert_eq!(rules[2].action, RuleAction::Deny);
    assert_eq!(rules[2].protocol, Some(Protocol::Udp));
    assert_eq!(rules[2].ports, vec![6000..=6007]);
    assert_eq!(rules[3].interface.as_deref(), Some("eth0"));
    assert_eq!(rules[4].action, RuleAction::Limit);
    assert_eq!(rules[5].ports, vec![80..=80, 443..=443]);
    assert!(rules[0].text.contains("24800"));
}

fn active_rules(incoming: &str, v4: &str, v6: &str) -> Vec<Rule> {
    let RuleSnapshot::Active { rules, .. } = snapshot(incoming, v4, v6) else {
        panic!("expected an active snapshot");
    };
    rules
}

#[test]
fn an_out_tuple_parses_to_an_outbound_rule_with_its_destination_and_port() {
    let rules = active_rules(
        ACTIVE_DENY,
        &tuple("deny tcp 443 10.0.2.0/24 any 0.0.0.0/0 out_eth0"),
        "",
    );
    assert_eq!(rules.len(), 1);
    let rule = &rules[0];
    assert_eq!(rule.direction, RuleDirection::Out);
    assert_eq!(rule.action, RuleAction::Deny);
    assert_eq!(rule.ports, vec![443..=443]);
    assert_eq!(
        rule.destination,
        Some(Network {
            address: "10.0.2.0".parse().unwrap(),
            prefix: 24
        })
    );
    assert_eq!(rule.interface.as_deref(), Some("eth0"));
}

#[test]
fn a_reject_tuple_keeps_its_action() {
    let rules = active_rules(
        ACTIVE_DENY,
        &tuple("reject tcp 25 0.0.0.0/0 any 0.0.0.0/0 in"),
        "",
    );
    assert_eq!(rules[0].action, RuleAction::Reject);
    assert_eq!(rules[0].direction, RuleDirection::In);
}

#[test]
fn a_route_tuple_is_skipped() {
    let rules = active_rules(
        ACTIVE_DENY,
        &tuple("route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in"),
        "",
    );
    assert!(rules.is_empty());
}

#[test]
fn route_deny_limit_and_reject_tuples_are_skipped() {
    for action in ["route:deny", "route:limit", "route:reject"] {
        let rules = active_rules(
            ACTIVE_DENY,
            &tuple(&format!("{action} tcp 80 0.0.0.0/0 any 0.0.0.0/0 in")),
            "",
        );
        assert!(rules.is_empty(), "{action}");
    }
}

#[test]
fn the_configuration_gives_both_default_policies() {
    let RuleSnapshot::Active {
        default_incoming,
        default_outgoing,
        ..
    } = snapshot_from(
        ENABLED,
        "DEFAULT_INPUT_POLICY=REJECT\nDEFAULT_OUTPUT_POLICY=DROP\n",
        "",
        "",
    )
    else {
        panic!("expected an active snapshot");
    };
    assert_eq!(default_incoming, Policy::Reject);
    assert_eq!(default_outgoing, Policy::Deny);
    let RuleSnapshot::Active {
        default_incoming,
        default_outgoing,
        ..
    } = snapshot(ACTIVE_ALLOW, "", "")
    else {
        panic!("expected an active snapshot");
    };
    assert_eq!(default_incoming, Policy::Allow);
    assert_eq!(default_outgoing, Policy::Allow);
}

#[test]
fn rules_keep_file_order_with_the_ipv4_file_first() {
    let v4 = tuple("allow tcp 1 0.0.0.0/0 any 0.0.0.0/0 in")
        + &tuple("allow tcp 2 0.0.0.0/0 any 0.0.0.0/0 out");
    let v6 = tuple("allow tcp 3 ::/0 any ::/0 in");
    let rules = active_rules(ACTIVE_DENY, &v4, &v6);
    let seen: Vec<_> = rules.iter().map(|r| (r.ports[0].clone(), r.ipv6)).collect();
    assert_eq!(seen, vec![(1..=1, false), (2..=2, false), (3..=3, true)]);
}

#[test]
fn an_outbound_rule_never_changes_a_ports_exposure() {
    let inbound = tuple("allow tcp 80 0.0.0.0/0 any 10.0.1.0/24 in");
    let outbound = tuple("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 out")
        + &tuple("deny tcp 80 0.0.0.0/0 any 0.0.0.0/0 out")
        + &tuple("deny tcp 9000 0.0.0.0/0 any 0.0.0.0/0 out")
        + &tuple("allow tcp 9000 0.0.0.0/0 any 0.0.0.0/0 out");
    for (status, rules, port) in [
        (ACTIVE_DENY, "", 80),
        (ACTIVE_DENY, "", 9000),
        (ACTIVE_DENY, inbound.as_str(), 80),
        (ACTIVE_ALLOW, "", 80),
    ] {
        let without = exposure_for(status, rules, &tcp(port));
        let with = exposure_for(status, &(rules.to_owned() + &outbound), &tcp(port));
        assert_eq!(with, without, "port {port}");
    }
}

#[test]
fn a_reject_rule_blocks_like_a_deny_and_a_reject_default_blocks_like_a_deny_default() {
    let reject = tuple("reject tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in");
    let allow = tuple("allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(
        kind(&exposure_for(ACTIVE_ALLOW, &(reject + &allow), &tcp(8080))),
        "blocked"
    );
    assert_eq!(
        kind(&exposure_for(ACTIVE_REJECT, "", &tcp(9000))),
        "blocked"
    );
}

#[test]
fn a_reject_default_limits_a_specific_source_allow_as_a_deny_default_does() {
    let source = tuple("allow tcp 8181 0.0.0.0/0 any 10.0.1.0/24 in");
    assert_eq!(
        kind(&exposure_for(ACTIVE_REJECT, &source, &tcp(8181))),
        "limited"
    );
    assert_eq!(
        kind(&exposure_for(ACTIVE_DENY, &source, &tcp(8181))),
        "limited"
    );
}

#[test]
fn a_reject_rule_scoped_to_a_source_is_passed_over_as_a_scoped_deny_is() {
    let allow = tuple("allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in");
    for action in ["deny", "reject"] {
        let scoped = tuple(&format!("{action} tcp 8080 0.0.0.0/0 any 10.0.1.0/24 in"));
        assert_eq!(
            kind(&exposure_for(ACTIVE_ALLOW, &(scoped + &allow), &tcp(8080))),
            "open",
            "{action}"
        );
    }
}

fn unavailable(snapshot: RuleSnapshot) -> String {
    let RuleSnapshot::Unavailable(reason) = snapshot else {
        panic!("expected unavailable, got {snapshot:?}");
    };
    reason
}

#[test]
fn enabled_with_drop_and_accept_gives_an_active_snapshot_with_the_rules() {
    let v4 = tuple("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in");
    let RuleSnapshot::Active {
        default_incoming,
        default_outgoing,
        rules,
    } = snapshot_from(
        ENABLED,
        "DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n",
        &v4,
        "",
    )
    else {
        panic!("expected an active snapshot");
    };
    assert_eq!(default_incoming, Policy::Deny);
    assert_eq!(default_outgoing, Policy::Allow);
    assert_eq!(rules.len(), 1);
}

#[test]
fn enabled_no_is_inactive_whatever_the_rules_and_policies_are() {
    let v4 = tuple("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(
        snapshot_from("ENABLED=no\n", &defaults("DROP"), &v4, ""),
        RuleSnapshot::Inactive
    );
    assert_eq!(
        snapshot_from("ENABLED=no\n", "", "", ""),
        RuleSnapshot::Inactive
    );
}

#[test]
fn quotes_case_comments_and_other_settings_are_handled() {
    let conf = "# ufw.conf\n\n# ENABLED=no\n  ENABLED=\"Yes\"  # on\nLOGLEVEL=low\n";
    let defaults = "# policy\nIPV6=yes\nDEFAULT_INPUT_POLICY='drop'\n\
                    DEFAULT_OUTPUT_POLICY=accept\nDEFAULT_FORWARD_POLICY=\"DROP\"\n\
                    # DEFAULT_INPUT_POLICY=\"ACCEPT\"\n";
    let RuleSnapshot::Active {
        default_incoming,
        default_outgoing,
        ..
    } = snapshot_from(conf, defaults, "", "")
    else {
        panic!("expected an active snapshot");
    };
    assert_eq!(default_incoming, Policy::Deny);
    assert_eq!(default_outgoing, Policy::Allow);
}

#[test]
fn the_last_assignment_of_a_setting_wins() {
    assert_eq!(
        snapshot_from("ENABLED=yes\nENABLED=no\n", &defaults("DROP"), "", ""),
        RuleSnapshot::Inactive
    );
    let RuleSnapshot::Active {
        default_incoming, ..
    } = snapshot_from(
        ENABLED,
        "DEFAULT_INPUT_POLICY=ACCEPT\nDEFAULT_INPUT_POLICY=DROP\nDEFAULT_OUTPUT_POLICY=ACCEPT\n",
        "",
        "",
    )
    else {
        panic!("expected an active snapshot");
    };
    assert_eq!(default_incoming, Policy::Deny);
}

#[test]
fn a_missing_file_setting_or_unknown_value_is_unavailable_and_says_what() {
    let good = TempFile::new("");
    let conf = TempFile::new(ENABLED);
    let defaults_file = TempFile::new(&defaults("DROP"));
    let missing = Path::new("/nonexistent/crosswalk/ufw.conf");

    let reason = unavailable(snapshot_at(
        missing,
        defaults_file.path(),
        good.path(),
        good.path(),
    ));
    assert_eq!(reason, "Not found: ufw.conf");

    let missing_defaults = Path::new("/nonexistent/crosswalk/ufw-defaults");
    let reason = unavailable(snapshot_at(
        conf.path(),
        missing_defaults,
        good.path(),
        good.path(),
    ));
    assert_eq!(reason, "Not found: ufw-defaults");

    let reason = unavailable(snapshot_from("LOGLEVEL=low\n", &defaults("DROP"), "", ""));
    assert!(reason.starts_with("ENABLED"), "{reason}");
    let reason = unavailable(snapshot_from("ENABLED=maybe\n", &defaults("DROP"), "", ""));
    assert!(
        reason.starts_with("'maybe' unknown for ENABLED"),
        "{reason}"
    );

    let reason = unavailable(snapshot_from(
        ENABLED,
        "DEFAULT_OUTPUT_POLICY=ACCEPT\n",
        "",
        "",
    ));
    assert!(reason.starts_with("DEFAULT_INPUT_POLICY"), "{reason}");
    let reason = unavailable(snapshot_from(
        ENABLED,
        "DEFAULT_INPUT_POLICY=DROP\n",
        "",
        "",
    ));
    assert!(reason.starts_with("DEFAULT_OUTPUT_POLICY"), "{reason}");
    let reason = unavailable(snapshot_from(
        ENABLED,
        "DEFAULT_INPUT_POLICY=DROP\nDEFAULT_OUTPUT_POLICY=SKIP\n",
        "",
        "",
    ));
    assert!(
        reason.starts_with("'SKIP' unknown for DEFAULT_OUTPUT_POLICY"),
        "{reason}"
    );
}

#[test]
fn an_unreadable_rule_file_is_unavailable() {
    let good = TempFile::new("");
    let conf = TempFile::new(ENABLED);
    let defaults_file = TempFile::new(&defaults("DROP"));
    let missing = Path::new("/nonexistent/crosswalk/user.rules");
    assert!(matches!(
        snapshot_at(conf.path(), defaults_file.path(), missing, good.path()),
        RuleSnapshot::Unavailable(_)
    ));
}

#[test]
fn an_unparseable_tuple_line_makes_the_snapshot_unavailable() {
    let bad = tuple("allow tcp notaport 0.0.0.0/0 any 0.0.0.0/0 in");
    let RuleSnapshot::Unavailable(reason) = snapshot(ACTIVE_DENY, &bad, "") else {
        panic!("expected unavailable");
    };
    assert!(reason.contains("notaport"), "{reason}");
}

#[test]
fn a_malformed_out_tuple_is_skipped_and_the_rest_of_the_snapshot_survives() {
    let rules = tuple("allow tcp notaport 0.0.0.0/0 any 0.0.0.0/0 out")
        + &tuple("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in");
    let parsed = active_rules(ACTIVE_DENY, &rules, "");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].ports, vec![80..=80]);
}

#[test]
fn loopback_binds_are_local_whatever_the_rules() {
    let l = listener(Protocol::Tcp, "127.0.0.1", 631);
    let deny = tuple("deny tcp 631 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(exposure_for(ACTIVE_DENY, &deny, &l), Exposure::Local);
    let l6 = listener(Protocol::Tcp, "::1", 631);
    assert_eq!(exposure(&l6, &RuleSnapshot::Inactive), Exposure::Local);
}

#[test]
fn allow_from_anywhere_or_default_allow_is_open() {
    let allow = tuple("allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(kind(&exposure_for(ACTIVE_DENY, &allow, &tcp(443))), "open");
    assert_eq!(kind(&exposure_for(ACTIVE_ALLOW, "", &tcp(9000))), "open");
    let range = tuple("allow any 6000:6007 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(kind(&exposure_for(ACTIVE_DENY, &range, &tcp(6003))), "open");
    assert_eq!(
        kind(&exposure_for(
            ACTIVE_DENY,
            &range,
            &listener(Protocol::Udp, "0.0.0.0", 6007)
        )),
        "open"
    );
}

#[test]
fn a_commented_rule_gives_a_port_the_exposure_its_uncommented_rule_gives() {
    let plain = tuple("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in");
    let commented = tuple("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=737368");
    let expected = exposure_for(ACTIVE_DENY, &plain, &tcp(22));
    assert_eq!(kind(&expected), "open");
    assert_eq!(exposure_for(ACTIVE_DENY, &commented, &tcp(22)), expected);
}

#[test]
fn restricted_allows_and_limit_are_limited() {
    let source = tuple("allow tcp 8181 0.0.0.0/0 any 10.0.1.0/24 in");
    assert_eq!(
        kind(&exposure_for(ACTIVE_DENY, &source, &tcp(8181))),
        "limited"
    );
    let iface = tuple("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_eth0");
    assert_eq!(
        kind(&exposure_for(ACTIVE_DENY, &iface, &tcp(22))),
        "limited"
    );
    let limit = tuple("limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(
        kind(&exposure_for(ACTIVE_DENY, &limit, &tcp(2222))),
        "limited"
    );
    let both = source.clone() + &tuple("allow tcp 8181 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(kind(&exposure_for(ACTIVE_DENY, &both, &tcp(8181))), "open");
    let Exposure::Limited(Some(text)) = exposure_for(ACTIVE_DENY, &source, &tcp(8181)) else {
        panic!("limited carries the deciding rule");
    };
    assert!(text.contains("10.0.1.0/24"));
}

#[test]
fn restricted_rules_under_default_allow_are_open_but_a_deny_still_blocks() {
    let source = tuple("allow tcp 8181 0.0.0.0/0 any 10.0.1.0/24 in");
    assert_eq!(
        kind(&exposure_for(ACTIVE_ALLOW, &source, &tcp(8181))),
        "open"
    );
    let limit = tuple("limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(
        kind(&exposure_for(ACTIVE_ALLOW, &limit, &tcp(2222))),
        "open"
    );
    let deny = tuple("deny tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in") + &limit;
    assert_eq!(
        kind(&exposure_for(ACTIVE_ALLOW, &deny, &tcp(2222))),
        "blocked"
    );
}

#[test]
fn deny_and_default_deny_are_blocked() {
    let deny_first = tuple("deny tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in")
        + &tuple("allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(
        kind(&exposure_for(ACTIVE_ALLOW, &deny_first, &tcp(8080))),
        "blocked"
    );
    assert_eq!(kind(&exposure_for(ACTIVE_DENY, "", &tcp(9000))), "blocked");
    let other = tuple("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(
        kind(&exposure_for(ACTIVE_DENY, &other, &tcp(9000))),
        "blocked"
    );
}

#[test]
fn ipv6_listeners_are_judged_by_the_ipv6_rules() {
    let v6 = tuple("allow tcp 80 ::/0 any ::/0 in");
    let l6 = listener(Protocol::Tcp, "::", 80);
    assert_eq!(
        kind(&exposure(&l6, &snapshot(ACTIVE_DENY, "", &v6))),
        "open"
    );
    assert_eq!(
        kind(&exposure(&tcp(80), &snapshot(ACTIVE_DENY, "", &v6))),
        "blocked"
    );
}

#[test]
fn unavailable_or_inactive_rules_leave_exposure_unknown() {
    assert!(matches!(
        exposure(&tcp(80), &RuleSnapshot::Inactive),
        Exposure::Unknown(_)
    ));
    assert!(matches!(
        exposure(&tcp(80), &RuleSnapshot::Unavailable("no access".to_owned())),
        Exposure::Unknown(reason) if reason == "no access"
    ));
}

fn blocks_through_created_provider(conf: &Path) -> (Vec<FirewallEvent>, FirewallStatus) {
    let log = TempFile::new("");
    let mut provider = create_with_conf(&UfwSource::File(log.path().to_owned()), conf);
    log.append("[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.1 DST=192.0.2.1 PROTO=TCP");
    let (sender, receiver) = sync_channel(32);
    let status = provider.poll(&sender, &AtomicBool::new(false));
    (receiver.try_iter().collect(), status)
}

#[test]
fn blocks_are_read_when_ufw_conf_cannot_be_checked() {
    for conf in [
        TempFile::new("ENABLED=yes\n"),
        TempFile::new("LOGLEVEL=low\n"),
    ] {
        let (events, status) = blocks_through_created_provider(conf.path());
        assert_eq!(events.len(), 1);
        assert_eq!(status.health, FirewallHealth::Available);
    }
    let (events, status) =
        blocks_through_created_provider(Path::new("/nonexistent/crosswalk/ufw.conf"));
    assert_eq!(events.len(), 1);
    assert_eq!(status.health, FirewallHealth::Available);
}

#[test]
fn blocks_are_not_read_when_ufw_is_off_or_logging_is_off() {
    for (conf, word) in [
        ("ENABLED=no\nLOGLEVEL=low\n", "inactive"),
        ("ENABLED=yes\nLOGLEVEL=off\n", "logging"),
    ] {
        let conf = TempFile::new(conf);
        let (events, status) = blocks_through_created_provider(conf.path());
        assert!(events.is_empty());
        assert!(matches!(status.health, FirewallHealth::Disabled(m) if m.contains(word)));
    }
}

fn conf_is_active(conf: &str) -> bool {
    matches!(
        snapshot_from(conf, &defaults("DROP"), "", ""),
        RuleSnapshot::Active { .. }
    )
}

#[test]
fn settings_files_with_crlf_line_endings_are_read() {
    let defaults = "DEFAULT_INPUT_POLICY=\"DROP\"\r\nDEFAULT_OUTPUT_POLICY=ACCEPT\r\n";
    assert!(matches!(
        snapshot_from("ENABLED=yes\r\nLOGLEVEL=low\r\n", defaults, "", ""),
        RuleSnapshot::Active {
            default_incoming: Policy::Deny,
            default_outgoing: Policy::Allow,
            ..
        }
    ));
    assert_eq!(
        snapshot_from("ENABLED=\"no\"\r\n", defaults, "", ""),
        RuleSnapshot::Inactive
    );
}

#[test]
fn an_export_line_is_not_an_assignment_of_the_setting() {
    let reason = unavailable(snapshot_from(
        "export ENABLED=yes\n",
        &defaults("DROP"),
        "",
        "",
    ));
    assert!(reason.starts_with("ENABLED missing"), "{reason}");
}

#[test]
fn a_key_that_begins_another_key_does_not_read_its_value() {
    assert!(conf_is_active("IPV6_ENABLED=no\nENABLED=yes\n"));
    assert!(conf_is_active("ENABLED=yes\nIPV6_ENABLED=no\n"));
    assert!(conf_is_active("ENABLED=yes\nENABLED_X=no\n"));
    let reason = unavailable(snapshot_from(
        "IPV6_ENABLED=yes\n",
        &defaults("DROP"),
        "",
        "",
    ));
    assert!(reason.starts_with("ENABLED missing"), "{reason}");

    let RuleSnapshot::Active {
        default_incoming, ..
    } = snapshot_from(
        ENABLED,
        "DEFAULT_INPUT_POLICY_X=ACCEPT\nDEFAULT_INPUT_POLICY=DROP\n\
         DEFAULT_INPUT_POLICY_Y=ACCEPT\nDEFAULT_OUTPUT_POLICY=ACCEPT\n",
        "",
        "",
    )
    else {
        panic!("expected an active snapshot");
    };
    assert_eq!(default_incoming, Policy::Deny);
}

#[test]
fn a_hash_inside_quotes_is_part_of_the_value() {
    let reason = unavailable(snapshot_from(
        ENABLED,
        "DEFAULT_INPUT_POLICY=\"DR#OP\"\nDEFAULT_OUTPUT_POLICY=ACCEPT\n",
        "",
        "",
    ));
    assert!(reason.contains("'DR#OP'"), "{reason}");
}

#[test]
fn an_unquoted_value_ends_at_a_trailing_comment() {
    assert!(conf_is_active("ENABLED=yes # on\n"));
    assert!(conf_is_active("ENABLED=yes\t# on\n"));
}

#[test]
fn an_empty_value_is_unknown_not_missing() {
    for conf in ["ENABLED=\n", "ENABLED=\"\"\n", "ENABLED=   # nothing\n"] {
        let reason = unavailable(snapshot_from(conf, &defaults("DROP"), "", ""));
        assert!(reason.starts_with("'' unknown for ENABLED"), "{reason}");
    }
}

#[test]
fn an_unterminated_quote_is_not_read_as_a_value() {
    for conf in ["ENABLED=\"yes\n", "ENABLED='yes\n"] {
        let reason = unavailable(snapshot_from(conf, &defaults("DROP"), "", ""));
        assert!(reason.contains("unknown for ENABLED"), "{reason}");
    }
}

#[test]
fn a_commented_seven_field_tuple_gives_the_rule_its_uncommented_line_gives() {
    let plain = active_rules(
        ACTIVE_DENY,
        &tuple("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"),
        "",
    );
    let commented = active_rules(
        ACTIVE_DENY,
        &tuple("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=737368"),
        "",
    );
    assert_eq!(plain.len(), 1);
    assert_eq!(commented, plain);
}

#[test]
fn a_commented_nine_field_tuple_gives_the_rule_its_uncommented_line_gives() {
    let line = "allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 Nginx%20Full - in";
    let plain = active_rules(ACTIVE_DENY, &tuple(line), "");
    let commented = active_rules(
        ACTIVE_DENY,
        &tuple(&format!("{line} comment=4e67696e78")),
        "",
    );
    assert_eq!(plain.len(), 1);
    assert_eq!(commented, plain);
}

#[test]
fn one_commented_rule_among_others_leaves_every_rule_listed() {
    let rules = tuple("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in")
        + &tuple("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=737368")
        + &tuple("deny udp 53 0.0.0.0/0 any 0.0.0.0/0 in");
    assert_eq!(active_rules(ACTIVE_DENY, &rules, "").len(), 3);
}

#[test]
fn a_commented_out_rule_is_left_out_and_the_rest_are_listed() {
    let rules = tuple("allow tcp 53 0.0.0.0/0 any 0.0.0.0/0 out comment=737368")
        + &tuple("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in");
    let parsed = active_rules(ACTIVE_DENY, &rules, "");
    assert_eq!(
        parsed
            .iter()
            .filter(|r| r.direction == RuleDirection::In)
            .count(),
        1
    );
    assert_eq!(
        parsed
            .iter()
            .find(|r| r.direction == RuleDirection::In)
            .unwrap()
            .ports,
        vec![80..=80]
    );
}

#[test]
fn a_commented_tuple_with_one_field_too_few_is_unreadable_with_the_usual_message() {
    let bad = tuple("allow tcp 22 0.0.0.0/0 any in comment=737368");
    let reason = unavailable(snapshot(ACTIVE_DENY, &bad, ""));
    assert!(
        reason.contains("expected 7 or 9 fields, found 6"),
        "{reason}"
    );
}

use std::{
    collections::VecDeque,
    fs, io,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crosswalk::{
    collect::{attribution::Listener, capture::Protocol},
    config::Config,
    firewall::{
        Allowed, Exposure, FirewallEvent, FirewallHealth, FirewallInput, FirewallProvider,
        FirewalldProvider, InputRead, RuleSnapshot, Zone, Zones, create_provider_with, exposure,
        firewalld_reply::{ActiveZone, PortRule, Target},
    },
};

mod common;
use common::listener;

/// Stands in for `busctl`: waits `delay` seconds if that file is there, replays `answers/<method>-<argument>.{out,err,exit}` from the
/// directory it is linked into, logs each call to `calls`, and records anything that is not a
/// read-only call made with the flags the provider must pass in `violations`.
const STAND_IN: &str = r#"#!/bin/sh
dir=$(dirname "$0")
echo "$*" >> "$dir/calls"
if [ "$1 $2 $3 $4" != "--system --allow-interactive-authorization=no --json=short call" ]; then
    echo "flags: $*" >> "$dir/violations"; exit 99
fi
shift 4
method=$4
case "$method" in
    NameHasOwner|getActiveZones|getDefaultZone|getZoneSettings2|getServiceSettings2|getLogDenied) ;;
    *) echo "method: $*" >> "$dir/violations"; exit 99 ;;
esac
key="$method-$6"
if [ -f "$dir/delay" ]; then sleep "$(cat "$dir/delay")"; fi
if [ -f "$dir/answers/$key.hang" ]; then exec sleep 30; fi
if [ ! -f "$dir/answers/$key.out" ]; then
    echo "no answer: $*" >> "$dir/violations"; exit 98
fi
cat "$dir/answers/$key.out"
cat "$dir/answers/$key.err" >&2
exit "$(cat "$dir/answers/$key.exit")"
"#;

/// The stand-in is written once and linked into each machine's directory, and the directory
/// holding it is removed with the last machine. (Writing a copy per machine while other threads
/// start programs fails now and then with "Text file busy".)
static LIVE_MACHINES: Mutex<usize> = Mutex::new(0);

fn stand_in_directory() -> PathBuf {
    std::env::temp_dir().join(format!("crosswalk-busctl-{}", std::process::id()))
}

fn use_stand_in() {
    let mut live = LIVE_MACHINES.lock().unwrap();
    if *live == 0 {
        let directory = stand_in_directory();
        fs::create_dir_all(&directory).unwrap();
        let script = directory.join("script");
        fs::write(&script, STAND_IN).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    }
    *live += 1;
}

fn release_stand_in() {
    let mut live = LIVE_MACHINES.lock().unwrap();
    *live -= 1;
    if *live == 0 {
        let _ = fs::remove_dir_all(stand_in_directory());
    }
}

struct Machine {
    directory: PathBuf,
    cancelled: Arc<AtomicBool>,
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
        release_stand_in();
    }
}

impl Machine {
    fn new(name: &str) -> Self {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let number = COUNT.fetch_add(1, Ordering::Relaxed);
        use_stand_in();
        let directory = stand_in_directory().join(format!("{name}-{number}"));
        fs::create_dir_all(directory.join("answers")).unwrap();
        symlink(
            stand_in_directory().join("script"),
            directory.join("busctl"),
        )
        .unwrap();
        Self {
            directory,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn answer(&self, key: &str, stdout: &str, stderr: &str, exit: i32) {
        let write = |suffix: &str, text: &str| {
            fs::write(self.directory.join(format!("answers/{key}.{suffix}")), text).unwrap()
        };
        write("out", stdout);
        write("err", stderr);
        write("exit", &exit.to_string());
    }

    /// The recorded answer `fixture` as the answer to `key`.
    fn replay(&self, key: &str, fixture: &str) {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/firewalld");
        let read = |suffix: &str| {
            fs::read_to_string(fixtures.join(format!("{fixture}.json{suffix}"))).unwrap()
        };
        self.answer(
            key,
            &read(""),
            &read(".stderr"),
            read(".exit").trim().parse().unwrap(),
        );
    }

    /// Every call waits this long before it answers.
    fn answer_after(&self, seconds: &str) {
        fs::write(self.directory.join("delay"), seconds).unwrap();
    }

    fn hang(&self, key: &str) {
        fs::write(self.directory.join(format!("answers/{key}.hang")), "").unwrap();
    }

    fn running(&self, owned: bool) {
        self.answer(
            "NameHasOwner-org.fedoraproject.FirewallD1",
            &format!("{{\"type\":\"b\",\"data\":[{owned}]}}\n"),
            "",
            0,
        );
    }

    /// A firewalld that answers everything, as the root user would see it.
    fn readable() -> Self {
        let machine = Self::new("readable");
        machine.running(true);
        machine.replay("getActiveZones-", "active-zones");
        machine.replay("getDefaultZone-", "default-zone");
        for zone in ["public", "trusted", "drop", "home"] {
            machine.replay(&format!("getZoneSettings2-{zone}"), &format!("zone-{zone}"));
        }
        machine.replay("getServiceSettings2-ssh", "service-ssh");
        machine.replay("getServiceSettings2-samba", "service-samba");
        machine.replay("getLogDenied-", "log-denied-off");
        // Made up for these tests, in the shape of the recorded ones.
        for (service, ports) in [
            ("http", r#"[["80","tcp"]]"#),
            ("mdns", r#"[["5353","udp"]]"#),
            ("dhcpv6-client", r#"[["546","udp"]]"#),
            ("samba-client", r#"[["137","udp"],["138","udp"]]"#),
        ] {
            let body = format!(
                r#"{{"type":"a{{sv}}","data":[{{"ports":{{"type":"a(ss)","data":{ports}}}}}]}}"#
            );
            machine.answer(&format!("getServiceSettings2-{service}"), &body, "", 0);
        }
        machine
    }

    /// What an ordinary user is told under the server policy.
    fn zones_only() -> Self {
        let machine = Self::new("zones-only");
        machine.running(true);
        machine.replay("getActiveZones-", "plain-server-active-zones");
        machine.replay("getDefaultZone-", "plain-server-default-zone");
        machine.replay("getLogDenied-", "plain-server-log-denied");
        for zone in ["public", "trusted"] {
            machine.replay(
                &format!("getZoneSettings2-{zone}"),
                "plain-server-zone-public",
            );
        }
        machine
    }

    fn provider(&self) -> FirewalldProvider {
        self.provider_within(Duration::from_secs(5))
    }

    fn provider_within(&self, timeout: Duration) -> FirewalldProvider {
        FirewalldProvider::with_busctl(
            self.directory.join("busctl"),
            timeout,
            self.cancelled.clone(),
        )
    }

    /// Each call has `timeout`, and the whole pass `limit`.
    fn provider_limited(&self, timeout: Duration, limit: Duration) -> FirewalldProvider {
        self.provider_within(timeout).with_pass_limit(limit)
    }

    fn calls(&self) -> Vec<String> {
        let calls = fs::read_to_string(self.directory.join("calls")).unwrap_or_default();
        calls.lines().map(str::to_owned).collect()
    }

    fn violations(&self) -> String {
        fs::read_to_string(self.directory.join("violations")).unwrap_or_default()
    }

    fn rules(&self) -> RuleSnapshot {
        let snapshot = self.provider().rules();
        assert_eq!(self.violations(), "", "calls the stand-in refused");
        snapshot
    }
}

fn unavailable_reason(snapshot: &RuleSnapshot) -> &str {
    match snapshot {
        RuleSnapshot::Unavailable(reason) => reason,
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

fn zone_named<'a>(zones: &'a Zones, name: &str) -> &'a Zone {
    zones.zones.iter().find(|zone| zone.name == name).unwrap()
}

fn port(ports: std::ops::RangeInclusive<u16>, protocol: &str) -> PortRule {
    PortRule {
        ports,
        protocol: protocol.to_owned(),
    }
}

fn service(name: &str, ports: Vec<PortRule>) -> Allowed {
    Allowed::Service {
        name: name.to_owned(),
        ports,
    }
}

#[test]
fn everything_readable_gives_the_zones_in_full_with_services_resolved() {
    let RuleSnapshot::Zones(zones) = Machine::readable().rules() else {
        panic!("expected zones");
    };
    assert_eq!(zones.default_zone, "public");
    let mut names: Vec<_> = zones.zones.iter().map(|zone| zone.name.as_str()).collect();
    names.sort();
    assert_eq!(names, ["drop", "home", "public", "trusted"]);
    let public = zone_named(&zones, "public");
    assert_eq!(public.interfaces, ["enp0s2"]);
    assert_eq!(public.target, Target::Default);
    assert_eq!(
        public.allowed,
        vec![
            service("ssh", vec![port(22..=22, "tcp")]),
            service("mdns", vec![port(5353..=5353, "udp")]),
            service("dhcpv6-client", vec![port(546..=546, "udp")]),
            service("http", vec![port(80..=80, "tcp")]),
            Allowed::Port(port(8080..=8080, "tcp")),
            Allowed::Port(port(5000..=5010, "udp")),
        ]
    );
    assert_eq!(public.rich_rules.len(), 3);
    assert_eq!(zone_named(&zones, "trusted").target, Target::Accept);
    assert_eq!(zone_named(&zones, "trusted").sources, ["192.168.50.0/24"]);
    assert_eq!(zone_named(&zones, "drop").target, Target::Drop);
    assert!(zone_named(&zones, "home").allowed.contains(&service(
        "samba-client",
        vec![port(137..=137, "udp"), port(138..=138, "udp")]
    )));
}

#[test]
fn a_pass_runs_busctl_once_per_call_and_looks_each_service_up_once() {
    let machine = Machine::readable();
    machine.rules();
    let calls = machine.calls();
    let looked_up = |method: &str| calls.iter().filter(|call| call.contains(method)).count();
    assert_eq!(
        looked_up("getServiceSettings2"),
        5,
        "ssh, mdns, dhcpv6-client, http, samba-client"
    );
    assert_eq!(looked_up("getZoneSettings2"), 4);
    assert_eq!(calls.len(), 13, "and the log setting, last");
    assert!(calls[12].contains("getLogDenied"));
}

#[test]
fn the_default_zone_is_read_even_when_no_interface_or_source_is_bound_to_it() {
    let machine = Machine::readable();
    machine.answer(
        "getDefaultZone-",
        "{\"type\":\"s\",\"data\":[\"work\"]}",
        "",
        0,
    );
    machine.replay("getZoneSettings2-work", "zone-home");
    let RuleSnapshot::Zones(zones) = machine.rules() else {
        panic!("expected zones");
    };
    let work = zone_named(&zones, "work");
    assert!(work.interfaces.is_empty() && work.sources.is_empty());
    assert_eq!(zones.zones.len(), 5);
}

#[test]
fn settings_refused_to_this_user_give_the_zones_names_and_bindings_only() {
    let machine = Machine::zones_only();
    assert_eq!(
        machine.rules(),
        RuleSnapshot::ZonesOnly(vec![
            ActiveZone {
                name: "public".into(),
                interfaces: vec!["enp0s2".into()],
                sources: vec![]
            },
            ActiveZone {
                name: "trusted".into(),
                interfaces: vec![],
                sources: vec!["192.168.50.0/24".into()]
            },
        ])
    );
}

#[test]
fn a_zone_refused_after_others_were_read_is_zones_only_not_a_partial_picture() {
    let machine = Machine::readable();
    machine.replay("getZoneSettings2-home", "plain-server-zone-public");
    assert!(matches!(machine.rules(), RuleSnapshot::ZonesOnly(zones) if zones.len() == 4));
}

#[test]
fn a_bus_name_nobody_owns_is_off() {
    let machine = Machine::new("off");
    machine.running(false);
    assert_eq!(machine.rules(), RuleSnapshot::FirewalldOff);
    assert_eq!(machine.calls().len(), 1);
}

#[test]
fn the_plain_form_of_the_owner_answer_is_read_too() {
    let machine = Machine::new("plain-owner");
    for (text, expected) in [("b false\n", true), ("b true\n", false)] {
        machine.answer("NameHasOwner-org.fedoraproject.FirewallD1", text, "", 0);
        let off = machine.provider().rules() == RuleSnapshot::FirewalldOff;
        assert_eq!(off, expected, "{text}");
    }
}

#[test]
fn an_owner_answer_that_makes_no_sense_is_unavailable_not_off() {
    let machine = Machine::new("odd-owner");
    for text in ["", "maybe", "{\"data\":[1]}"] {
        machine.answer("NameHasOwner-org.fedoraproject.FirewallD1", text, "", 0);
        assert!(
            matches!(machine.rules(), RuleSnapshot::Unavailable(_)),
            "{text:?}"
        );
    }
}

#[test]
fn a_bus_that_cannot_be_reached_is_unavailable_with_its_reason() {
    let machine = Machine::new("no-bus");
    machine.answer(
        "NameHasOwner-org.fedoraproject.FirewallD1",
        "",
        "Failed to connect to bus: No such file or directory\n",
        1,
    );
    let snapshot = machine.rules();
    assert!(unavailable_reason(&snapshot).contains("Failed to connect to bus"));
}

#[test]
fn a_call_that_never_answers_is_given_up_and_reported_as_unavailable_not_off() {
    let machine = Machine::readable();
    machine.hang("getActiveZones-");
    let started = Instant::now();
    let snapshot = machine.provider_within(Duration::from_millis(300)).rules();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(
        unavailable_reason(&snapshot).contains("timed out"),
        "{snapshot:?}"
    );
}

#[test]
fn a_firewalld_that_answers_every_call_slowly_makes_the_pass_unavailable_as_too_slow() {
    let machine = Machine::readable();
    machine.answer_after("0.3");
    let started = Instant::now();
    let snapshot = machine
        .provider_limited(Duration::from_secs(1), Duration::from_secs(1))
        .rules();
    assert!(started.elapsed() < Duration::from_millis(2500));
    assert!(
        unavailable_reason(&snapshot).contains("too slow"),
        "{snapshot:?}"
    );
}

#[test]
fn a_pass_whose_calls_each_fit_the_limit_is_read_in_full() {
    let machine = Machine::readable();
    machine.answer_after("0.05");
    let mut provider = machine.provider_limited(Duration::from_secs(1), Duration::from_secs(4));
    assert!(matches!(provider.rules(), RuleSnapshot::Zones(_)));
}

#[test]
fn a_cancelled_pass_gives_up_at_once() {
    let machine = Machine::readable();
    machine.hang("NameHasOwner-org.fedoraproject.FirewallD1");
    machine.cancelled.store(true, Ordering::Release);
    let started = Instant::now();
    let snapshot = machine.provider().rules();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(
        unavailable_reason(&snapshot).contains("cancelled"),
        "{snapshot:?}"
    );
}

#[test]
fn a_failure_that_is_not_a_refusal_is_unavailable_never_zones_only_or_an_empty_zone() {
    for (stdout, stderr, exit) in [
        ("", "Call failed: INVALID_ZONE: public\n", 1),
        ("", "", 0),
        ("not json", "", 0),
        ("{\"type\":\"s\",\"data\":[\"x\"]}", "", 0),
    ] {
        let machine = Machine::readable();
        machine.answer("getZoneSettings2-trusted", stdout, stderr, exit);
        let snapshot = machine.rules();
        assert!(
            unavailable_reason(&snapshot).contains("getZoneSettings2 trusted"),
            "{snapshot:?}"
        );
    }
}

#[test]
fn a_failure_of_the_active_zones_or_the_default_zone_is_unavailable() {
    for key in ["getActiveZones-", "getDefaultZone-"] {
        let machine = Machine::readable();
        machine.replay(key, "zone-unknown");
        let snapshot = machine.rules();
        assert!(
            unavailable_reason(&snapshot).contains(key.trim_end_matches('-')),
            "{snapshot:?}"
        );
    }
}

#[test]
fn a_service_whose_settings_cannot_be_read_fails_the_pass_instead_of_having_no_ports() {
    for fixture in ["plain-server-service-ssh", "zone-unknown"] {
        let machine = Machine::readable();
        machine.replay("getServiceSettings2-ssh", fixture);
        let snapshot = machine.rules();
        assert!(
            unavailable_reason(&snapshot).contains("getServiceSettings2 ssh"),
            "{fixture}: {snapshot:?}"
        );
    }
}

#[test]
fn an_include_that_cannot_be_read_fails_the_pass() {
    let machine = Machine::readable();
    machine.replay("getServiceSettings2-samba-client", "zone-unknown");
    let snapshot = machine.rules();
    assert!(unavailable_reason(&snapshot).contains("samba-client"));
}

type Read = fn(&Machine) -> RuleSnapshot;

/// The panes keep the first 30 characters of a reason.
fn first_30(snapshot: &RuleSnapshot) -> String {
    unavailable_reason(snapshot).chars().take(30).collect()
}

#[test]
fn the_first_30_characters_of_a_reason_name_what_went_wrong() {
    let cases: [(&str, Read, &str); 7] = [
        (
            "a call timing out",
            |machine| {
                machine.hang("getActiveZones-");
                machine.provider_within(Duration::from_millis(300)).rules()
            },
            "timed out",
        ),
        (
            "the pass deadline",
            |machine| {
                machine.answer_after("0.3");
                machine
                    .provider_limited(Duration::from_secs(1), Duration::from_secs(1))
                    .rules()
            },
            "too slow",
        ),
        (
            "a failed call",
            |machine| {
                machine.answer("getActiveZones-", "", "Zone busy\n", 1);
                machine.rules()
            },
            "Zone busy",
        ),
        (
            "a refusal",
            |machine| {
                machine.answer("getActiveZones-", "", "Call failed: Not Authorized\n", 1);
                machine.rules()
            },
            "refused",
        ),
        (
            "an empty answer",
            |machine| {
                machine.answer("getActiveZones-", "", "", 0);
                machine.rules()
            },
            "said nothing",
        ),
        (
            "a malformed answer",
            |machine| {
                machine.answer("getActiveZones-", "not json", "", 0);
                machine.rules()
            },
            "answered oddly",
        ),
        (
            "a cancelled pass",
            |machine| {
                machine.cancelled.store(true, Ordering::Release);
                machine.provider().rules()
            },
            "cancelled",
        ),
    ];
    for (name, read, cause) in cases {
        let machine = Machine::readable();
        let snapshot = read(&machine);
        assert!(first_30(&snapshot).contains(cause), "{name}: {snapshot:?}");
    }
}

#[test]
fn text_from_firewalld_is_kept_short_in_a_reason() {
    let machine = Machine::readable();
    let long = "x".repeat(10_000);
    machine.answer("getZoneSettings2-trusted", "", &long, 1);
    let snapshot = machine.rules();
    assert!(unavailable_reason(&snapshot).chars().count() <= 160);
}

#[test]
fn the_exposure_of_a_port_is_unknown_when_firewalld_is_off_or_shows_only_zones() {
    let tcp = |address: &str| listener(Protocol::Tcp, address, 22);
    let wildcard: Listener = tcp("0.0.0.0");
    let off = exposure(&wildcard, &RuleSnapshot::FirewalldOff, None);
    assert_eq!(off, Exposure::Unknown("fwd off".to_owned()));
    let only = exposure(&wildcard, &RuleSnapshot::ZonesOnly(vec![]), None);
    assert_eq!(only, Exposure::Unknown("not readable".to_owned()));
    for snapshot in [RuleSnapshot::FirewalldOff, RuleSnapshot::ZonesOnly(vec![])] {
        assert_eq!(
            exposure(&tcp("127.0.0.1"), &snapshot, None),
            Exposure::Local
        );
    }
}

/// The kernel journal as the provider sees it: counts how often it is started and stopped, and
/// hands out the lines it is given.
#[derive(Clone, Default)]
struct Journal(Arc<Mutex<JournalState>>);

#[derive(Default)]
struct JournalState {
    started: usize,
    stopped: usize,
    cannot_start: bool,
    lines: VecDeque<String>,
}

struct JournalReader(Journal);

impl FirewallInput for JournalReader {
    fn next_record(&mut self) -> io::Result<InputRead> {
        let line = (self.0).0.lock().unwrap().lines.pop_front();
        Ok(line.map_or(InputRead::Idle, InputRead::Record))
    }

    fn shutdown(&mut self) -> io::Result<()> {
        (self.0).0.lock().unwrap().stopped += 1;
        Ok(())
    }
}

impl Journal {
    fn source(&self) -> crosswalk::firewall::BlockSource {
        let journal = self.clone();
        Box::new(move || {
            let mut state = journal.0.lock().unwrap();
            if state.cannot_start {
                return Err(io::Error::other("journalctl will not start"));
            }
            state.started += 1;
            Ok(Box::new(JournalReader(journal.clone())) as Box<dyn FirewallInput>)
        })
    }

    fn say(&self, message: &str) {
        let line = serde_json::json!({"MESSAGE": message, "__REALTIME_TIMESTAMP": "1"});
        self.0.lock().unwrap().lines.push_back(line.to_string());
    }

    fn started(&self) -> usize {
        self.0.lock().unwrap().started
    }

    fn stopped(&self) -> usize {
        self.0.lock().unwrap().stopped
    }
}

const DENIED: &str = "filter_IN_public_REJECT: IN=enp0s2 OUT= SRC=10.0.2.2 DST=10.0.2.15 PROTO=TCP SPT=57930 DPT=8081 ";

impl Machine {
    fn logging(&self, fixture: &str) {
        self.replay("getLogDenied-", fixture);
    }

    /// A provider that starts `journal` for blocks.
    fn blocks_provider(&self, journal: &Journal) -> FirewalldProvider {
        self.provider().with_block_source(journal.source())
    }
}

/// One turn of the loop: a rules pass, which reads the log setting, then a poll.
fn poll(provider: &mut FirewalldProvider) -> (FirewallHealth, Vec<FirewallEvent>) {
    provider.rules();
    poll_alone(provider)
}

fn poll_alone(provider: &mut FirewalldProvider) -> (FirewallHealth, Vec<FirewallEvent>) {
    let (sender, receiver) = std::sync::mpsc::sync_channel(32);
    let status = provider.poll(&sender, &AtomicBool::new(false));
    assert_eq!(status.name, "fwd");
    (status.health, receiver.try_iter().collect())
}

#[test]
fn with_denied_packet_logging_off_the_reader_is_not_started_and_the_health_says_so() {
    let machine = Machine::readable();
    machine.logging("log-denied-off");
    let journal = Journal::default();
    let (health, _) = poll(&mut machine.blocks_provider(&journal));
    assert_eq!(health, FirewallHealth::NotLogging);
    assert_eq!(journal.started(), 0);
    assert_eq!(machine.violations(), "");
}

#[test]
fn with_logging_on_the_reader_is_started_once_and_denied_packets_come_through() {
    let machine = Machine::readable();
    machine.logging("log-denied-all");
    let journal = Journal::default();
    let mut provider = machine.blocks_provider(&journal);
    let (health, events) = poll(&mut provider);
    assert_eq!((health, events.len()), (FirewallHealth::AwaitingEvents, 0));
    journal.say(DENIED);
    journal.say("FINAL_REJECT: IN=enp0s2 OUT= SRC=10.0.2.2 DST=10.0.2.15 PROTO=TCP SPT=1 DPT=2 ");
    let (health, events) = poll(&mut provider);
    assert_eq!(health, FirewallHealth::Available);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].destination.port, Some(8081));
    poll(&mut provider);
    assert_eq!(journal.started(), 1);
}

#[test]
fn with_the_setting_refused_to_this_user_the_reader_is_started_and_blocks_depend_on_logging() {
    let machine = Machine::readable();
    machine.logging("plain-server-log-denied");
    let journal = Journal::default();
    let mut provider = machine.blocks_provider(&journal);
    let (health, _) = poll(&mut provider);
    assert_eq!(health, FirewallHealth::DependsOnLogging);
    assert_eq!(journal.started(), 1);
    journal.say(DENIED);
    let (health, events) = poll(&mut provider);
    assert_eq!((health, events.len()), (FirewallHealth::Available, 1));
    // Reading the setting again does not take back what the blocks showed.
    let (health, _) = poll(&mut provider);
    assert_eq!(health, FirewallHealth::Available);
    assert_eq!(journal.started(), 1);
}

#[test]
fn turning_logging_on_starts_the_reader_and_turning_it_off_stops_it() {
    let machine = Machine::readable();
    machine.logging("log-denied-off");
    let journal = Journal::default();
    let mut provider = machine.blocks_provider(&journal);
    assert_eq!(poll(&mut provider).0, FirewallHealth::NotLogging);
    machine.logging("log-denied-all");
    assert_eq!(poll(&mut provider).0, FirewallHealth::AwaitingEvents);
    assert_eq!((journal.started(), journal.stopped()), (1, 0));
    machine.logging("log-denied-off");
    assert_eq!(poll(&mut provider).0, FirewallHealth::NotLogging);
    assert_eq!((journal.started(), journal.stopped()), (1, 1));
    machine.logging("log-denied-all");
    assert_eq!(poll(&mut provider).0, FirewallHealth::AwaitingEvents);
    assert_eq!(journal.started(), 2);
}

#[test]
fn polling_makes_no_busctl_call_and_follows_the_last_pass() {
    let machine = Machine::readable();
    machine.logging("log-denied-all");
    let journal = Journal::default();
    let mut provider = machine.blocks_provider(&journal);
    provider.rules();
    let asked = machine.calls().len();
    machine.logging("log-denied-off");
    assert_eq!(poll_alone(&mut provider).0, FirewallHealth::AwaitingEvents);
    poll_alone(&mut provider);
    assert_eq!(machine.calls().len(), asked);
    assert_eq!(poll(&mut provider).0, FirewallHealth::NotLogging);
}

#[test]
fn before_any_pass_a_poll_has_nothing_to_follow_asks_nothing_and_starts_no_reader() {
    let machine = Machine::readable();
    machine.logging("log-denied-all");
    let journal = Journal::default();
    let (health, _) = poll_alone(&mut machine.blocks_provider(&journal));
    assert_eq!(health, FirewallHealth::AwaitingEvents);
    assert_eq!((machine.calls().len(), journal.started()), (0, 0));
}

#[test]
fn the_log_setting_and_the_rules_come_from_one_pass_and_one_deadline() {
    let machine = Machine::readable();
    machine.answer_after("0.3");
    let mut provider =
        machine.provider_limited(Duration::from_secs(1), Duration::from_millis(1500));
    let started = Instant::now();
    let snapshot = provider.rules();
    assert!(started.elapsed() < Duration::from_millis(2500));
    assert!(
        unavailable_reason(&snapshot).contains("too slow"),
        "{snapshot:?}"
    );
    let (health, _) = poll_alone(&mut provider);
    assert!(
        matches!(&health, FirewallHealth::Unavailable(why) if why.contains("too slow")),
        "{health:?}"
    );
}

#[test]
fn a_failed_reading_keeps_a_working_reader_and_the_blocks_it_delivers() {
    let machine = Machine::readable();
    machine.logging("log-denied-all");
    let journal = Journal::default();
    let mut provider = machine.blocks_provider(&journal);
    poll(&mut provider);
    machine.answer("getLogDenied-", "", "Call failed: broken\n", 1);
    journal.say(DENIED);
    let (health, events) = poll(&mut provider);
    assert_eq!((health, events.len()), (FirewallHealth::Available, 1));
    machine.logging("log-denied-all");
    let (health, _) = poll(&mut provider);
    assert_eq!(health, FirewallHealth::Available);
    assert_eq!((journal.started(), journal.stopped()), (1, 0));
}

#[test]
fn only_a_reading_of_off_or_a_firewalld_not_running_stops_a_reader() {
    let machine = Machine::readable();
    machine.logging("log-denied-all");
    let journal = Journal::default();
    let mut provider = machine.blocks_provider(&journal);
    poll(&mut provider);
    machine.answer("getLogDenied-", "", "Call failed: broken\n", 1);
    poll(&mut provider);
    assert_eq!(journal.stopped(), 0);
    machine.logging("log-denied-off");
    assert_eq!(poll(&mut provider).0, FirewallHealth::NotLogging);
    assert_eq!(journal.stopped(), 1);
}

#[test]
fn a_firewalld_that_is_not_running_stops_the_reader_and_is_not_an_unhealthy_reading_of_the_log() {
    let machine = Machine::readable();
    machine.logging("log-denied-all");
    let journal = Journal::default();
    let mut provider = machine.blocks_provider(&journal);
    poll(&mut provider);
    machine.running(false);
    let (health, _) = poll(&mut provider);
    assert!(
        matches!(&health, FirewallHealth::Disabled(why) if why.contains("not running")),
        "{health:?}"
    );
    assert_eq!(journal.stopped(), 1);
}

#[test]
fn a_setting_that_cannot_be_read_for_another_reason_is_unavailable_and_starts_nothing() {
    let machine = Machine::readable();
    machine.answer("getLogDenied-", "", "Call failed: broken\n", 1);
    let journal = Journal::default();
    let (health, _) = poll(&mut machine.blocks_provider(&journal));
    assert!(
        matches!(&health, FirewallHealth::Unavailable(why) if why.contains("getLogDenied")),
        "{health:?}"
    );
    assert_eq!(journal.started(), 0);
}

#[test]
fn a_reader_that_cannot_start_is_unavailable_and_tried_again_at_the_next_reading() {
    let machine = Machine::readable();
    machine.logging("log-denied-all");
    let journal = Journal::default();
    journal.0.lock().unwrap().cannot_start = true;
    let mut provider = machine.blocks_provider(&journal);
    let (health, _) = poll(&mut provider);
    assert!(
        matches!(&health, FirewallHealth::Unavailable(why) if why.contains("will not start")),
        "{health:?}"
    );
    journal.0.lock().unwrap().cannot_start = false;
    assert_eq!(poll(&mut provider).0, FirewallHealth::AwaitingEvents);
    assert_eq!(journal.started(), 1);
}

#[test]
fn a_cancelled_poll_stops_the_reader() {
    let machine = Machine::readable();
    machine.logging("log-denied-all");
    let journal = Journal::default();
    let mut provider = machine.blocks_provider(&journal);
    poll(&mut provider);
    let (sender, _receiver) = std::sync::mpsc::sync_channel(1);
    let status = provider.poll(&sender, &AtomicBool::new(true));
    assert_eq!(status.health, FirewallHealth::Cancelled);
    assert_eq!(journal.stopped(), 1);
}

/// What `auto` makes of this machine: its `busctl` is the stand-in, `installed` are the
/// programs in its system directory, and `ufw_conf` is UFW's configuration, if it has one.
fn auto_on(
    machine: &Machine,
    installed: &[&str],
    ufw_conf: Option<&str>,
) -> Box<dyn FirewallProvider> {
    let programs = machine.directory.join("programs");
    let _ = fs::remove_dir_all(&programs);
    fs::create_dir_all(&programs).unwrap();
    for name in installed {
        fs::write(programs.join(name), "").unwrap();
    }
    let conf = machine.directory.join("ufw.conf");
    let _ = fs::remove_file(&conf);
    if let Some(text) = ufw_conf {
        fs::write(&conf, text).unwrap();
    }
    let config =
        Config::load_from(["crosswalk", "--ufw-source", "file:/nonexistent/ufw.log"]).unwrap();
    create_provider_with(&config, &conf, machine.provider(), &[programs.as_path()])
}

#[test]
fn auto_reads_firewalld_when_it_is_running_whatever_ufw_is() {
    let machine = Machine::readable();
    let mut provider = auto_on(&machine, &["firewall-cmd"], Some("ENABLED=yes\n"));
    assert_eq!(provider.status().name, "fwd");
    assert!(matches!(provider.rules(), RuleSnapshot::Zones(_)));
}

#[test]
fn auto_reads_ufw_when_firewalld_is_stopped_and_ufw_is_there() {
    let machine = Machine::new("stopped");
    machine.running(false);
    for conf in ["ENABLED=yes\n", "ENABLED=no\n"] {
        let provider = auto_on(&machine, &["firewalld"], Some(conf));
        assert_eq!(provider.status().name, "ufw", "{conf}");
    }
}

#[test]
fn auto_shows_a_stopped_firewalld_when_it_is_installed_and_ufw_is_not() {
    let machine = Machine::new("stopped-alone");
    machine.running(false);
    let mut provider = auto_on(&machine, &["firewalld"], None);
    assert_eq!(provider.status().name, "fwd");
    assert_eq!(provider.rules(), RuleSnapshot::FirewalldOff);
}

#[test]
fn auto_is_none_when_nothing_is_installed() {
    let machine = Machine::new("nothing");
    machine.running(false);
    assert_eq!(auto_on(&machine, &[], None).status().name, "none");
}

#[test]
fn a_bus_that_does_not_answer_gives_a_working_ufw_and_otherwise_the_failure_where_firewalld_is_installed()
 {
    let machine = Machine::new("silent");
    let working_ufw = auto_on(&machine, &["firewall-cmd"], Some("ENABLED=yes\n"));
    assert_eq!(working_ufw.status().name, "ufw");
    let installed = auto_on(&machine, &["firewall-cmd"], Some("ENABLED=no\n"));
    assert_eq!(installed.status().name, "fwd");
    let alone = auto_on(&machine, &["firewall-cmd"], None);
    assert_eq!(alone.status().name, "fwd");
    let absent = auto_on(&machine, &[], Some("ENABLED=yes\n"));
    assert_eq!(absent.status().name, "ufw");
    let neither = auto_on(&machine, &[], None);
    assert_eq!(neither.status().name, "none");
    assert!(machine.violations().contains("no answer"));
}

#[test]
fn an_explicit_firewalld_is_firewalld_whatever_the_machine_holds() {
    let machine = Machine::new("explicit");
    let config = Config::load_from(["crosswalk", "--firewall-provider", "firewalld"]).unwrap();
    let conf = machine.directory.join("ufw.conf");
    fs::write(&conf, "ENABLED=yes\n").unwrap();
    let provider = create_provider_with(&config, &conf, machine.provider(), &[]);
    assert_eq!(provider.status().name, "fwd");
}

#[test]
fn the_flag_the_runtime_cancels_interrupts_a_pass_of_the_provider_auto_made() {
    let machine = Machine::readable();
    machine.hang("getActiveZones-");
    let mut provider = auto_on(&machine, &["firewalld"], None);
    assert_eq!(provider.status().name, "fwd");
    let started = Instant::now();
    let canceller = machine.cancelled.clone();
    let cancelling = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        canceller.store(true, Ordering::Release);
    });
    let snapshot = provider.rules();
    cancelling.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(2), "{snapshot:?}");
    assert!(
        unavailable_reason(&snapshot).contains("cancelled"),
        "{snapshot:?}"
    );
}

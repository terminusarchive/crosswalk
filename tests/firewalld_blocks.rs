use std::{
    collections::VecDeque,
    io,
    path::Path,
    sync::{atomic::AtomicBool, mpsc::sync_channel},
};

use crosswalk::{
    collect::capture::{Direction, Protocol},
    firewall::{BlockMarker, BlockReader, FirewallEvent, FirewallHealth, FirewallInput, InputRead},
};

struct Lines(VecDeque<String>);

impl FirewallInput for Lines {
    fn next_record(&mut self) -> io::Result<InputRead> {
        Ok(self
            .0
            .pop_front()
            .map_or(InputRead::Idle, InputRead::Record))
    }

    fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The recorded kernel lines: reject (TCP), then drop (TCP, UDP, ICMP, IPv6 TCP).
fn recorded() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/firewalld");
    let text = std::fs::read_to_string(path.join("denied-packets.txt")).unwrap();
    text.lines().map(str::to_owned).collect()
}

/// A line as the journal gives it.
fn in_journal(message: &str) -> String {
    serde_json::json!({"MESSAGE": message, "__REALTIME_TIMESTAMP": "1791827233914663"}).to_string()
}

fn read(marker: BlockMarker, records: &[String]) -> (Vec<FirewallEvent>, FirewallHealth) {
    let input = Lines(records.iter().cloned().collect());
    let mut reader = BlockReader::new(input, marker, 32, 4096).unwrap();
    let (sender, receiver) = sync_channel(32);
    let mut health = FirewallHealth::AwaitingEvents;
    let _ = reader.read_into_health(&sender, &AtomicBool::new(false), &mut health);
    (receiver.try_iter().collect(), health)
}

fn blocks_from(messages: &[&str]) -> Vec<FirewallEvent> {
    let records: Vec<String> = messages.iter().map(|m| in_journal(m)).collect();
    read(BlockMarker::Firewalld, &records).0
}

/// A real line's fields with another prefix in front.
fn with_prefix(prefix: &str) -> String {
    let line = &recorded()[0];
    format!("{prefix}{}", line.split_once(": ").unwrap().1)
}

#[test]
fn the_recorded_reject_and_drop_lines_each_give_a_block_with_what_the_kernel_logged() {
    let records: Vec<String> = recorded().iter().map(|line| in_journal(line)).collect();
    let (events, health) = read(BlockMarker::Firewalld, &records);
    assert_eq!(events.len(), 5);
    assert_eq!(health, FirewallHealth::Available);

    let reject = &events[0];
    assert_eq!(reject.timestamp.as_deref(), Some("1791827233914663"));
    assert_eq!(reject.direction, Some(Direction::Inbound));
    assert_eq!(reject.interface.as_deref(), Some("enp0s2"));
    assert_eq!(reject.protocol, Some(Protocol::Tcp));
    assert_eq!(reject.source.ip, Some("10.0.2.2".parse().unwrap()));
    assert_eq!(reject.source.port, Some(57930));
    assert_eq!(reject.destination.ip, Some("10.0.2.15".parse().unwrap()));
    assert_eq!(reject.destination.port, Some(8081));

    let drop = &events[1];
    assert_eq!(drop.interface.as_deref(), Some("vcw0"));
    assert_eq!(drop.source.ip, Some("10.77.0.2".parse().unwrap()));
    assert_eq!(drop.destination.port, Some(7777));

    assert_eq!(events[2].protocol, Some(Protocol::Udp));
    assert_eq!(events[2].destination.port, Some(5353));

    let ping = &events[3];
    assert_eq!(ping.protocol, Some(Protocol::Other(1)));
    assert_eq!((ping.source.port, ping.destination.port), (None, None));
    assert_eq!(ping.source.ip, Some("10.77.0.2".parse().unwrap()));

    let v6 = &events[4];
    assert_eq!(v6.protocol, Some(Protocol::Tcp));
    assert_eq!(v6.source.ip, Some("fd77::2".parse().unwrap()));
    assert_eq!(v6.destination.ip, Some("fd77::1".parse().unwrap()));
    assert_eq!(v6.destination.port, Some(7778));
}

#[test]
fn prefixes_that_are_not_a_zone_rejecting_or_dropping_input_give_no_block() {
    let others = [
        "FINAL_REJECT: ",
        "STATE_INVALID_DROP: ",
        "filter_FWD_public_REJECT: ",
        "rpfilter_DROP: ",
        "RFC3964_IPv4_REJECT: ",
        "CW-RICH ",
        "filter_IN_public_ACCEPT: ",
        "filter_IN__REJECT: ",
        "filter_OUT_public_REJECT: ",
        "filter_IN_public_REJECT_x: ",
        "filter_IN_public_REJECT ",
        "kernel: filter_IN_public_REJECT: ",
        " filter_IN_public_REJECT: ",
        "[UFW BLOCK] ",
    ];
    for prefix in others {
        let message = with_prefix(prefix);
        assert!(blocks_from(&[&message]).is_empty(), "{prefix:?}");
    }
}

#[test]
fn a_zone_name_may_hold_underscores_and_other_characters_but_not_spaces() {
    for zone in [
        "my_zone", "a_DROP", "a_REJECT", "dmz.1", "wg-0", "x:y", "_", "Zöne",
    ] {
        for action in ["REJECT", "DROP"] {
            let message = with_prefix(&format!("filter_IN_{zone}_{action}: "));
            assert_eq!(blocks_from(&[&message]).len(), 1, "{zone} {action}");
        }
    }
    // The action is the end of the first word whatever the zone looks like.
    let message = with_prefix("filter_IN_a_DROP_REJECT: ");
    assert_eq!(blocks_from(&[&message]).len(), 1);
    let message = with_prefix("filter_IN_a_DROP_deny: ");
    assert!(blocks_from(&[&message]).is_empty());
    let message = with_prefix("filter_IN_two words_DROP: ");
    assert!(blocks_from(&[&message]).is_empty());
}

#[test]
fn ufw_lines_still_give_what_they_gave_and_a_firewalld_line_is_not_one_of_them() {
    let ufw = "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.8 DST=192.0.2.10 PROTO=TCP SPT=41234 DPT=22";
    let (events, _) = read(BlockMarker::Ufw, &[in_journal(ufw)]);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].destination.port, Some(22));
    let (events, _) = read(BlockMarker::Ufw, &[in_journal(&recorded()[0])]);
    assert!(events.is_empty());
    let (events, _) = read(BlockMarker::Firewalld, &[in_journal(ufw)]);
    assert!(events.is_empty());
}

#[test]
fn a_firewalld_prefix_with_no_fields_is_malformed_and_says_firewalld_not_ufw() {
    let (events, health) = read(
        BlockMarker::Firewalld,
        &[in_journal("filter_IN_public_REJECT: nothing here")],
    );
    assert!(events.is_empty());
    assert_eq!(
        health,
        FirewallHealth::Degraded("malformed firewalld block record has no fields".to_owned())
    );
    let long = in_journal(&"x".repeat(5000));
    let (_, health) = read(BlockMarker::Firewalld, &[long]);
    assert!(matches!(health, FirewallHealth::Degraded(m) if m.starts_with("firewalld record")));
}

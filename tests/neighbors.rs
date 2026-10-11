use std::{io, net::IpAddr};

use crosswalk::collect::neighbors::{
    Neighbor, NeighborCollector, NeighborSnapshot, NeighborSource,
};

struct Fixed(Option<io::Result<String>>);

impl NeighborSource for Fixed {
    fn read_table(&mut self) -> io::Result<String> {
        self.0.take().expect("read once")
    }
}

fn collect(result: io::Result<&str>) -> NeighborSnapshot {
    NeighborCollector::new(Fixed(Some(result.map(str::to_owned)))).collect()
}

fn entries(json: &str) -> Vec<Neighbor> {
    match collect(Ok(json)) {
        NeighborSnapshot::Available(entries) => entries,
        other => panic!("expected entries, got {other:?}"),
    }
}

fn reason(result: io::Result<&str>) -> String {
    match collect(result) {
        NeighborSnapshot::Unavailable(reason) => reason,
        other => panic!("expected unavailable, got {other:?}"),
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn ipv4_and_ipv6_entries_carry_address_hardware_interface_and_state() {
    let found = entries(
        r#"[{"dst":"10.0.1.12","dev":"wlan0","lladdr":"a4:00:00:00:00:cd","state":["REACHABLE"]},
            {"dst":"fe80::a1:b2c3:d4e5:f607","dev":"wlan0","lladdr":"1c:b7:2c:00:11:22","router":null,"state":["STALE"]}]"#,
    );
    assert_eq!(
        found,
        vec![
            Neighbor {
                address: ip("10.0.1.12"),
                mac: Some("a4:00:00:00:00:cd".to_owned()),
                interface: "wlan0".to_owned(),
                state: "reachable".to_owned(),
            },
            Neighbor {
                address: ip("fe80::a1:b2c3:d4e5:f607"),
                mac: Some("1c:b7:2c:00:11:22".to_owned()),
                interface: "wlan0".to_owned(),
                state: "stale".to_owned(),
            },
        ]
    );
}

#[test]
fn a_failed_entry_without_hardware_address_is_dropped_and_an_incomplete_one_kept() {
    let found = entries(
        r#"[{"dst":"10.0.1.20","dev":"eth0","state":["FAILED"]},
            {"dst":"10.0.1.21","dev":"eth0","state":["INCOMPLETE"]},
            {"dst":"10.0.1.22","dev":"eth0","lladdr":"aa:bb:cc:dd:ee:ff","state":["FAILED"]}]"#,
    );
    let kept: Vec<_> = found
        .iter()
        .map(|n| (n.address, n.mac.is_some(), n.state.as_str()))
        .collect();
    assert_eq!(
        kept,
        vec![
            (ip("10.0.1.21"), false, "incomplete"),
            (ip("10.0.1.22"), true, "failed"),
        ]
    );
}

#[test]
fn an_entry_with_several_states_keeps_the_first_the_kernel_names() {
    let found = entries(
        r#"[{"dst":"10.0.1.30","dev":"eth0","lladdr":"aa:bb:cc:dd:ee:ff","state":["PERMANENT","NOARP"]}]"#,
    );
    assert_eq!(found[0].state, "permanent");
}

#[test]
fn malformed_json_is_unavailable_and_says_so() {
    assert!(reason(Ok("not json")).contains("not valid JSON"));
}

#[test]
fn a_failed_command_is_unavailable_and_says_so() {
    let error = io::Error::other("ip exited with exit status: 1: boom");
    assert!(reason(Err(error)).contains("exited"));
}

#[test]
fn a_timed_out_command_is_unavailable_and_says_so() {
    let error = io::Error::new(io::ErrorKind::TimedOut, "timed out after 5 s");
    assert!(reason(Err(error)).contains("timed out"));
}

#[test]
fn an_empty_table_is_available_with_no_entries() {
    assert!(entries("[]").is_empty());
    assert!(entries("").is_empty());
}

#[test]
fn an_entry_with_an_unparsable_address_is_skipped_without_failing_the_rest() {
    let found = entries(
        r#"[{"dst":"default","dev":"eth0","lladdr":"aa:bb:cc:dd:ee:ff","state":["REACHABLE"]},
            {"dst":"10.0.1.40","dev":"eth0","lladdr":"aa:bb:cc:dd:ee:ff","state":["REACHABLE"]}]"#,
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].address, ip("10.0.1.40"));
}

#[test]
fn delay_and_probe_entries_without_hardware_addresses_are_kept() {
    let found = entries(
        r#"[{"dst":"10.0.1.5","dev":"eth0","state":["DELAY"]},
            {"dst":"10.0.1.6","dev":"eth0","state":["PROBE"]}]"#,
    );
    let seen: Vec<_> = found
        .iter()
        .map(|n| (n.mac.clone(), n.state.as_str()))
        .collect();
    assert_eq!(seen, vec![(None, "delay"), (None, "probe")]);
}

#[test]
fn a_missing_or_empty_state_reads_as_unknown() {
    let found = entries(
        r#"[{"dst":"10.0.1.5","dev":"eth0","lladdr":"a4:00:00:00:00:cd"},
            {"dst":"10.0.1.6","dev":"eth0","lladdr":"a4:00:00:00:00:ce","state":[]}]"#,
    );
    let states: Vec<_> = found.iter().map(|n| n.state.as_str()).collect();
    assert_eq!(states, vec!["unknown", "unknown"]);
}

#[test]
fn the_same_address_on_two_interfaces_is_kept_twice() {
    let found = entries(
        r#"[{"dst":"fe80::1","dev":"eth0","lladdr":"a4:00:00:00:00:cd","state":["STALE"]},
            {"dst":"fe80::1","dev":"wlan0","lladdr":"a4:00:00:00:00:ce","state":["STALE"]}]"#,
    );
    let interfaces: Vec<_> = found.iter().map(|n| n.interface.as_str()).collect();
    assert_eq!(interfaces, vec!["eth0", "wlan0"]);
}

#[test]
fn valid_json_that_is_not_an_array_is_unavailable() {
    assert!(matches!(
        collect(Ok(r#"{"dst":"10.0.1.5"}"#)),
        NeighborSnapshot::Unavailable(_)
    ));
}

use crosswalk::{
    collect::{attribution::Listener, capture::Protocol},
    firewall::{
        Allowed, Exposure, InterfaceAddresses, RuleSnapshot, Zone, Zones, exposure,
        firewalld_reply::{PortRule, Target},
    },
};

mod common;
use common::listener;

fn port(first: u16, last: u16, protocol: &str) -> PortRule {
    PortRule {
        ports: first..=last,
        protocol: protocol.to_owned(),
    }
}

fn service(name: &str, ports: Vec<PortRule>) -> Allowed {
    Allowed::Service {
        name: name.to_owned(),
        ports,
    }
}

fn zone(name: &str, interfaces: &[&str], sources: &[&str], target: Target) -> Zone {
    Zone {
        name: name.to_owned(),
        interfaces: interfaces.iter().map(|i| i.to_string()).collect(),
        sources: sources.iter().map(|s| s.to_string()).collect(),
        target,
        allowed: Vec::new(),
        rich_rules: Vec::new(),
    }
}

fn allowing(mut zone: Zone, allowed: Allowed) -> Zone {
    zone.allowed.push(allowed);
    zone
}

fn with_rich(mut zone: Zone, rule: &str) -> Zone {
    zone.rich_rules.push(rule.to_owned());
    zone
}

fn interfaces() -> Vec<InterfaceAddresses> {
    let named = |name: &str, address: &str| InterfaceAddresses {
        name: name.to_owned(),
        up: true,
        addresses: vec![address.parse().unwrap()],
    };
    vec![
        named("lo", "127.0.0.1"),
        named("eth0", "192.168.1.5"),
        named("eth1", "10.0.0.5"),
    ]
}

fn snapshot(default_zone: &str, zones: Vec<Zone>) -> RuleSnapshot {
    RuleSnapshot::Zones(Zones {
        default_zone: default_zone.to_owned(),
        zones,
    })
}

fn tcp(address: &str, number: u16) -> Listener {
    listener(Protocol::Tcp, address, number)
}

fn exposure_of(listener: &Listener, zones: Vec<Zone>) -> Exposure {
    exposure_on(listener, zones, &interfaces())
}

fn exposure_on(
    listener: &Listener,
    zones: Vec<Zone>,
    interfaces: &[InterfaceAddresses],
) -> Exposure {
    exposure(listener, &snapshot("public", zones), Some(interfaces))
}

fn both_interfaces(allowed: Allowed) -> Vec<Zone> {
    vec![allowing(
        zone("public", &["eth0", "eth1"], &[], Target::Default),
        allowed,
    )]
}

fn ssh() -> Allowed {
    service("ssh", vec![port(22, 22, "tcp")])
}

#[test]
fn a_loopback_only_port_is_local_whatever_the_zones_say() {
    let zones = both_interfaces(ssh());
    assert_eq!(exposure_of(&tcp("127.0.0.1", 9999), zones), Exposure::Local);
}

#[test]
fn a_service_on_every_interface_is_open() {
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), both_interfaces(ssh())),
        Exposure::Open(None)
    );
}

#[test]
fn a_port_on_every_interface_is_open() {
    let zones = both_interfaces(Allowed::Port(port(8080, 8080, "tcp")));
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 8080), zones),
        Exposure::Open(None)
    );
}

#[test]
fn a_port_range_covers_its_ends() {
    let zones = both_interfaces(Allowed::Port(port(5000, 5010, "tcp")));
    for number in [5000, 5005, 5010] {
        assert_eq!(
            exposure_of(&tcp("0.0.0.0", number), zones.clone()),
            Exposure::Open(None)
        );
    }
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 5011), zones),
        Exposure::Blocked(None)
    );
}

#[test]
fn an_accept_everything_zone_opens_every_port() {
    let zones = vec![zone("trusted", &["eth0", "eth1"], &[], Target::Accept)];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 31337), zones),
        Exposure::Open(None)
    );
}

#[test]
fn a_port_allowed_on_one_of_two_interfaces_is_limited() {
    let zones = vec![
        allowing(zone("public", &["eth0"], &[], Target::Default), ssh()),
        zone("work", &["eth1"], &[], Target::Default),
    ];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Limited(None)
    );
}

#[test]
fn a_port_allowed_only_for_a_source_network_is_limited() {
    let zones = vec![
        zone("public", &["eth0", "eth1"], &[], Target::Default),
        allowing(
            zone("home", &[], &["192.168.70.0/24"], Target::Default),
            ssh(),
        ),
    ];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Limited(None)
    );
}

#[test]
fn a_source_zone_that_accepts_everything_limits_a_port_the_interfaces_do_not_allow() {
    let zones = vec![
        zone("public", &["eth0", "eth1"], &[], Target::Default),
        zone("trusted", &[], &["192.168.50.0/24"], Target::Accept),
    ];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Limited(None)
    );
}

#[test]
fn a_port_allowed_only_by_a_rich_rule_is_limited() {
    let zones = vec![with_rich(
        zone("public", &["eth0", "eth1"], &[], Target::Default),
        r#"rule family="ipv4" source address="203.0.113.0/24" port port="5432" protocol="tcp" accept"#,
    )];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 5432), zones),
        Exposure::Limited(None)
    );
}

#[test]
fn a_rich_rule_that_rejects_or_drops_does_not_let_a_port_in() {
    for action in ["reject", "drop"] {
        let zones = vec![with_rich(
            zone("public", &["eth0", "eth1"], &[], Target::Default),
            &format!(r#"rule family="ipv4" source address="198.51.100.7" {action}"#),
        )];
        assert_eq!(
            exposure_of(&tcp("0.0.0.0", 22), zones),
            Exposure::Blocked(None)
        );
    }
}

#[test]
fn an_allowed_port_in_a_zone_with_a_rejecting_or_dropping_rich_rule_is_limited() {
    for action in ["reject", "drop", r#"reject type="icmp-host-prohibited""#] {
        let zones = vec![with_rich(
            allowing(
                zone("public", &["eth0", "eth1"], &[], Target::Default),
                ssh(),
            ),
            &format!(r#"rule family="ipv4" source address="198.51.100.7" {action}"#),
        )];
        assert_eq!(
            exposure_of(&tcp("0.0.0.0", 22), zones),
            Exposure::Limited(None),
            "{action}"
        );
    }
}

#[test]
fn a_quoted_word_in_a_rich_rule_is_not_its_action() {
    let zones = vec![with_rich(
        allowing(
            zone("public", &["eth0", "eth1"], &[], Target::Default),
            ssh(),
        ),
        r#"rule family="ipv4" log prefix="reject drop " accept"#,
    )];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Open(None)
    );
}

#[test]
fn a_port_no_zone_allows_is_blocked() {
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 25), both_interfaces(ssh())),
        Exposure::Blocked(None)
    );
}

#[test]
fn a_zone_that_rejects_or_drops_by_default_still_lets_in_what_it_lists() {
    for target in [Target::Reject, Target::Drop, Target::Default] {
        let zones = vec![allowing(
            zone("public", &["eth0", "eth1"], &[], target),
            ssh(),
        )];
        assert_eq!(
            exposure_of(&tcp("0.0.0.0", 22), zones.clone()),
            Exposure::Open(None)
        );
        assert_eq!(
            exposure_of(&tcp("0.0.0.0", 25), zones),
            Exposure::Blocked(None)
        );
    }
}

#[test]
fn a_specific_address_bind_follows_the_zone_of_the_interface_holding_it() {
    let zones = vec![
        allowing(zone("public", &["eth0"], &[], Target::Default), ssh()),
        zone("work", &["eth1"], &[], Target::Default),
    ];
    assert_eq!(
        exposure_of(&tcp("192.168.1.5", 22), zones.clone()),
        Exposure::Open(None)
    );
    assert_eq!(
        exposure_of(&tcp("10.0.0.5", 22), zones),
        Exposure::Blocked(None)
    );
}

#[test]
fn an_interface_in_no_listed_zone_is_in_the_default_zone() {
    let zones = vec![
        zone("work", &["eth1"], &[], Target::Default),
        allowing(
            zone("public", &[], &["192.0.2.0/24"], Target::Default),
            ssh(),
        ),
    ];
    // eth0 is in no zone, so in "public"; "public" has no interfaces listed but is the default.
    assert_eq!(
        exposure_of(&tcp("192.168.1.5", 22), zones.clone()),
        Exposure::Open(None)
    );
    assert_eq!(
        exposure_of(&tcp("10.0.0.5", 22), zones.clone()),
        Exposure::Limited(None)
    );
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Limited(None)
    );
}

#[test]
fn a_rule_for_the_other_protocol_lets_nothing_in() {
    let zones = both_interfaces(Allowed::Port(port(53, 53, "tcp")));
    assert_eq!(
        exposure_of(&listener(Protocol::Udp, "0.0.0.0", 53), zones.clone()),
        Exposure::Blocked(None)
    );
    let sctp = both_interfaces(Allowed::Port(port(53, 53, "sctp")));
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 53), sctp),
        Exposure::Blocked(None)
    );
    let udp = both_interfaces(Allowed::Port(port(53, 53, "udp")));
    assert_eq!(
        exposure_of(&listener(Protocol::Udp, "0.0.0.0", 53), udp),
        Exposure::Open(None)
    );
}

#[test]
fn a_zone_that_accepts_everything_lets_in_the_other_protocol_too() {
    let zones = vec![zone("trusted", &["eth0", "eth1"], &[], Target::Accept)];
    assert_eq!(
        exposure_of(&listener(Protocol::Udp, "0.0.0.0", 53), zones),
        Exposure::Open(None)
    );
}

fn interface(name: &str, up: bool, addresses: &[&str]) -> InterfaceAddresses {
    InterfaceAddresses {
        name: name.to_owned(),
        up,
        addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
    }
}

fn unknown(exposure: &Exposure) -> bool {
    matches!(exposure, Exposure::Unknown(_))
}

#[test]
fn a_wildcard_ipv6_bind_reaches_every_interface() {
    let zones = vec![
        allowing(zone("public", &["eth0"], &[], Target::Default), ssh()),
        zone("work", &["eth1"], &[], Target::Default),
    ];
    assert_eq!(
        exposure_of(&tcp("::", 22), zones.clone()),
        Exposure::Limited(None)
    );
    assert_eq!(
        exposure_of(&tcp("::", 22), both_interfaces(ssh())),
        Exposure::Open(None)
    );
    assert_eq!(exposure_of(&tcp("::", 25), zones), Exposure::Blocked(None));
}

#[test]
fn the_low_end_of_a_port_range_is_covered_and_the_port_below_it_is_not() {
    let zones = both_interfaces(Allowed::Port(port(5000, 5010, "tcp")));
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 5000), zones.clone()),
        Exposure::Open(None)
    );
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 4999), zones),
        Exposure::Blocked(None)
    );
}

#[test]
fn sctp_and_dccp_listeners_follow_sctp_and_dccp_rules() {
    for (number, name, other) in [(132, "sctp", "dccp"), (33, "dccp", "sctp")] {
        let sctp_or_dccp = listener(Protocol::Other(number), "0.0.0.0", 7000);
        let matching = both_interfaces(Allowed::Port(port(7000, 7000, name)));
        assert_eq!(
            exposure_of(&sctp_or_dccp, matching),
            Exposure::Open(None),
            "{name}"
        );
        let wrong = both_interfaces(Allowed::Port(port(7000, 7000, other)));
        assert_eq!(
            exposure_of(&sctp_or_dccp, wrong),
            Exposure::Blocked(None),
            "{name} against {other}"
        );
        let tcp_rule = both_interfaces(Allowed::Port(port(7000, 7000, "tcp")));
        assert_eq!(
            exposure_of(&sctp_or_dccp, tcp_rule),
            Exposure::Blocked(None),
            "{name} against tcp"
        );
    }
}

#[test]
fn a_zone_bound_to_interfaces_and_sources_counts_for_both() {
    let both = allowing(
        zone(
            "public",
            &["eth0", "eth1"],
            &["192.0.2.0/24"],
            Target::Default,
        ),
        ssh(),
    );
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), vec![both.clone()]),
        Exposure::Open(None)
    );
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 25), vec![both]),
        Exposure::Blocked(None)
    );
}

#[test]
fn a_port_let_in_on_every_interface_but_refused_by_a_source_zone_is_limited() {
    let zones = vec![
        allowing(
            zone("public", &["eth0", "eth1"], &[], Target::Default),
            ssh(),
        ),
        zone("drop", &[], &["198.51.100.0/24"], Target::Drop),
    ];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Limited(None)
    );
}

#[test]
fn a_port_let_in_on_every_interface_and_by_the_source_zone_too_is_open() {
    let zones = vec![
        allowing(
            zone("public", &["eth0", "eth1"], &[], Target::Default),
            ssh(),
        ),
        allowing(zone("home", &[], &["192.0.2.0/24"], Target::Default), ssh()),
    ];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Open(None)
    );
}

#[test]
fn a_rejecting_rich_rule_in_a_source_zone_that_lets_the_port_in_makes_it_limited() {
    let zones = vec![
        allowing(
            zone("public", &["eth0", "eth1"], &[], Target::Default),
            ssh(),
        ),
        with_rich(
            allowing(zone("home", &[], &["192.0.2.0/24"], Target::Default), ssh()),
            r#"rule family="ipv4" source address="192.0.2.99" reject"#,
        ),
    ];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Limited(None)
    );
}

#[test]
fn a_rejecting_rich_rule_in_a_source_zone_does_not_let_a_port_in() {
    let zones = vec![
        zone("public", &["eth0", "eth1"], &[], Target::Default),
        with_rich(
            zone("home", &[], &["192.0.2.0/24"], Target::Default),
            r#"rule family="ipv4" source address="192.0.2.99" reject"#,
        ),
    ];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Blocked(None)
    );
}

#[test]
fn an_accepting_rich_rule_in_a_source_zone_makes_a_blocked_port_limited() {
    let zones = vec![
        zone("public", &["eth0", "eth1"], &[], Target::Default),
        with_rich(
            zone("home", &[], &["192.0.2.0/24"], Target::Default),
            r#"rule family="ipv4" source address="192.0.2.99" accept"#,
        ),
    ];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Limited(None)
    );
}

#[test]
fn the_three_rich_rules_of_the_recorded_public_zone() {
    let rules = [
        r#"rule family="ipv4" source address="192.0.2.10" accept"#,
        r#"rule family="ipv4" source address="203.0.113.0/24" port port="5432" protocol="tcp" accept"#,
        r#"rule family="ipv4" source address="198.51.100.7" reject"#,
    ];
    let with_rules = |base: Zone| rules.iter().fold(base, |zone, rule| with_rich(zone, rule));
    let bare = with_rules(zone("public", &["eth0", "eth1"], &[], Target::Default));
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 25), vec![bare.clone()]),
        Exposure::Limited(None)
    );
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 5432), vec![bare]),
        Exposure::Limited(None)
    );
    let with_ssh = with_rules(allowing(
        zone("public", &["eth0", "eth1"], &[], Target::Default),
        ssh(),
    ));
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), vec![with_ssh]),
        Exposure::Limited(None)
    );
}

#[test]
fn loopback_interfaces_are_left_out_of_the_interfaces_a_wildcard_reaches() {
    let zones = vec![
        zone("trusted", &["lo"], &[], Target::Accept),
        zone("public", &["eth0", "eth1"], &[], Target::Default),
    ];
    assert_eq!(
        exposure_of(&tcp("0.0.0.0", 22), zones),
        Exposure::Blocked(None)
    );
}

#[test]
fn without_an_interface_reading_the_exposure_is_unknown_not_blocked() {
    let zones = snapshot("public", both_interfaces(ssh()));
    assert_eq!(
        exposure(&tcp("0.0.0.0", 25), &zones, None),
        Exposure::Unknown("interfaces unknown".to_owned())
    );
    assert_eq!(
        exposure(&tcp("192.168.1.5", 25), &zones, None),
        Exposure::Unknown("interfaces unknown".to_owned())
    );
    assert_eq!(
        exposure(&tcp("127.0.0.1", 25), &zones, None),
        Exposure::Local
    );
}

#[test]
fn a_reading_with_nothing_to_reach_is_unknown() {
    let only_lo = [interface("lo", true, &["127.0.0.1"])];
    assert_eq!(
        exposure_on(&tcp("0.0.0.0", 22), both_interfaces(ssh()), &only_lo),
        Exposure::Unknown("no usable interface".to_owned())
    );
    assert_eq!(
        exposure_on(&tcp("0.0.0.0", 22), both_interfaces(ssh()), &[]),
        Exposure::Unknown("no usable interface".to_owned())
    );
}

#[test]
fn an_address_no_interface_holds_is_judged_on_every_interface() {
    let addresses = [
        "224.0.0.251",
        "239.255.255.250",
        "ff02::fb",
        "255.255.255.255",
        "203.0.113.9",
        "::ffff:203.0.113.9",
    ];
    let one_of_two = vec![
        allowing(zone("public", &["eth0"], &[], Target::Default), ssh()),
        zone("work", &["eth1"], &[], Target::Default),
    ];
    for address in addresses {
        assert_eq!(
            exposure_of(&tcp(address, 22), one_of_two.clone()),
            Exposure::Limited(None),
            "{address}"
        );
        assert_eq!(
            exposure_of(&tcp(address, 22), both_interfaces(ssh())),
            Exposure::Open(None),
            "{address}"
        );
        assert_eq!(
            exposure_of(&tcp(address, 25), both_interfaces(ssh())),
            Exposure::Blocked(None),
            "{address}"
        );
    }
}

#[test]
fn an_address_held_only_by_loopback_is_judged_on_every_interface() {
    let held = [
        interface("lo", true, &["127.0.0.1", "10.99.0.1"]),
        interface("eth0", true, &["192.168.1.5"]),
    ];
    assert_eq!(
        exposure_on(&tcp("10.99.0.1", 22), both_interfaces(ssh()), &held),
        Exposure::Open(None)
    );
}

#[test]
fn an_ipv4_mapped_bind_follows_the_interface_holding_the_ipv4_address() {
    let zones = vec![
        allowing(zone("public", &["eth0"], &[], Target::Default), ssh()),
        zone("work", &["eth1"], &[], Target::Default),
    ];
    assert_eq!(
        exposure_of(&tcp("::ffff:192.168.1.5", 22), zones.clone()),
        Exposure::Open(None)
    );
    assert_eq!(
        exposure_of(&tcp("::ffff:10.0.0.5", 22), zones),
        Exposure::Blocked(None)
    );
}

#[test]
fn an_ipv4_mapped_loopback_bind_is_local() {
    assert_eq!(
        exposure_of(&tcp("::ffff:127.0.0.1", 22), both_interfaces(ssh())),
        Exposure::Local
    );
}

#[test]
fn a_missing_default_zone_makes_an_interface_in_no_zone_unknown() {
    let zones = vec![allowing(
        zone("public", &["eth0"], &[], Target::Default),
        ssh(),
    )];
    let two = [
        interface("eth0", true, &["192.168.1.5"]),
        interface("eth1", true, &["10.0.0.5"]),
    ];
    let missing =
        |listener: &Listener| exposure(listener, &snapshot("elsewhere", zones.clone()), Some(&two));
    assert_eq!(
        missing(&tcp("0.0.0.0", 22)),
        Exposure::Unknown("default zone unknown".to_owned())
    );
    assert_eq!(
        missing(&tcp("10.0.0.5", 22)),
        Exposure::Unknown("default zone unknown".to_owned())
    );
    assert_eq!(missing(&tcp("192.168.1.5", 22)), Exposure::Open(None));
}

#[test]
fn interfaces_that_are_down_are_left_out() {
    let zones = vec![
        allowing(zone("public", &["eth0"], &[], Target::Default), ssh()),
        zone("work", &["eth1"], &[], Target::Default),
    ];
    let eth1_down = [
        interface("eth0", true, &["192.168.1.5"]),
        interface("eth1", false, &["10.0.0.5"]),
    ];
    assert_eq!(
        exposure_on(&tcp("0.0.0.0", 22), zones.clone(), &eth1_down),
        Exposure::Open(None)
    );
    // An address held only by a down interface is held by no interface that is up.
    assert_eq!(
        exposure_on(&tcp("10.0.0.5", 22), zones.clone(), &eth1_down),
        Exposure::Open(None)
    );
    let all_down = [
        interface("eth0", false, &["192.168.1.5"]),
        interface("eth1", false, &["10.0.0.5"]),
    ];
    assert!(unknown(&exposure_on(&tcp("0.0.0.0", 22), zones, &all_down)));
}

#[test]
fn an_interface_that_is_up_with_no_address_is_left_out() {
    let zones = vec![
        allowing(zone("public", &["eth0"], &[], Target::Default), ssh()),
        zone("work", &["eth2"], &[], Target::Default),
    ];
    let bridge_port = [
        interface("eth0", true, &["192.168.1.5"]),
        interface("eth2", true, &[]),
    ];
    assert_eq!(
        exposure_on(&tcp("0.0.0.0", 22), zones, &bridge_port),
        Exposure::Open(None)
    );
}

use std::{fs, path::Path};

use crosswalk::firewall::firewalld_reply::{
    ActiveZone, BusctlOutput, LogDenied, PortRule, ReplyError, ServiceSettings, Target,
    ZoneSettings, active_zones, default_zone, log_denied, service_ports, service_settings,
    zone_settings,
};

fn recorded(name: &str) -> BusctlOutput {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/firewalld");
    let read = |suffix: &str| fs::read_to_string(directory.join(format!("{name}.json{suffix}")));
    BusctlOutput {
        success: read(".exit").unwrap().trim() == "0",
        stdout: read("").unwrap(),
        stderr: read(".stderr").unwrap(),
    }
}

fn answered(stdout: &str) -> BusctlOutput {
    BusctlOutput {
        success: true,
        stdout: stdout.to_owned(),
        stderr: String::new(),
    }
}

fn port(ports: std::ops::RangeInclusive<u16>, protocol: &str) -> PortRule {
    PortRule {
        ports,
        protocol: protocol.to_owned(),
    }
}

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn active_zones_give_each_zones_interfaces_and_sources() {
    let zones = active_zones(&recorded("active-zones")).unwrap();
    assert_eq!(
        zones,
        vec![
            ActiveZone {
                name: "drop".into(),
                interfaces: vec![],
                sources: names(&["192.168.60.0/24"])
            },
            ActiveZone {
                name: "home".into(),
                interfaces: vec![],
                sources: names(&["192.168.70.0/24"])
            },
            ActiveZone {
                name: "public".into(),
                interfaces: names(&["enp0s2"]),
                sources: vec![]
            },
            ActiveZone {
                name: "trusted".into(),
                interfaces: vec![],
                sources: names(&["192.168.50.0/24"])
            },
        ]
    );
}

#[test]
fn active_zones_are_readable_by_an_ordinary_user() {
    let zones = active_zones(&recorded("plain-server-active-zones")).unwrap();
    assert_eq!(zones.len(), 2);
}

#[test]
fn default_zone_gives_its_name() {
    assert_eq!(default_zone(&recorded("default-zone")).unwrap(), "public");
}

#[test]
fn public_zone_gives_services_ports_ranges_and_rich_rules() {
    let zone = zone_settings(&recorded("zone-public")).unwrap();
    assert_eq!(
        zone,
        ZoneSettings {
            target: Target::Default,
            services: names(&["ssh", "mdns", "dhcpv6-client", "http"]),
            ports: vec![port(8080..=8080, "tcp"), port(5000..=5010, "udp")],
            rich_rules: names(&[
                r#"rule family="ipv4" source address="192.0.2.10" accept"#,
                r#"rule family="ipv4" source address="203.0.113.0/24" port port="5432" protocol="tcp" accept"#,
                r#"rule family="ipv4" source address="198.51.100.7" reject"#,
            ]),
        }
    );
}

#[test]
fn trusted_zone_accepts_everything() {
    let zone = zone_settings(&recorded("zone-trusted")).unwrap();
    assert_eq!(zone.target, Target::Accept);
    assert!(zone.services.is_empty() && zone.ports.is_empty() && zone.rich_rules.is_empty());
}

#[test]
fn drop_zone_drops() {
    assert_eq!(
        zone_settings(&recorded("zone-drop")).unwrap().target,
        Target::Drop
    );
}

#[test]
fn zone_settings_are_readable_by_an_ordinary_user_under_the_desktop_policy() {
    let zone = zone_settings(&recorded("plain-desktop-zone-public")).unwrap();
    assert_eq!(zone.ports.len(), 2);
}

#[test]
fn a_reject_target_in_either_spelling_is_reject() {
    let settings = |target: &str| {
        answered(&format!(
            r#"{{"type":"a{{sv}}","data":[{{"target":{{"type":"s","data":"{target}"}}}}]}}"#
        ))
    };
    assert_eq!(
        zone_settings(&settings("%%REJECT%%")).unwrap().target,
        Target::Reject
    );
    assert_eq!(
        zone_settings(&settings("REJECT")).unwrap().target,
        Target::Reject
    );
}

#[test]
fn a_target_firewalld_does_not_have_is_malformed() {
    let answer =
        answered(r#"{"type":"a{sv}","data":[{"target":{"type":"s","data":"LET_IT_IN"}}]}"#);
    assert!(matches!(
        zone_settings(&answer),
        Err(ReplyError::Malformed(_))
    ));
}

#[test]
fn samba_gives_its_ports_and_includes() {
    assert_eq!(
        service_settings(&recorded("service-samba")).unwrap(),
        ServiceSettings {
            ports: vec![port(139..=139, "tcp"), port(445..=445, "tcp")],
            includes: names(&["samba-client"]),
        }
    );
}

#[test]
fn ssh_gives_one_port_and_no_includes() {
    assert_eq!(
        service_settings(&recorded("service-ssh")).unwrap(),
        ServiceSettings {
            ports: vec![port(22..=22, "tcp")],
            includes: vec![],
        }
    );
}

#[test]
fn log_setting_is_off_or_on() {
    assert_eq!(
        log_denied(&recorded("log-denied-off")).unwrap(),
        LogDenied::Off
    );
    assert_eq!(
        log_denied(&recorded("log-denied-all")).unwrap(),
        LogDenied::On
    );
    assert_eq!(
        log_denied(&recorded("plain-desktop-log-denied")).unwrap(),
        LogDenied::On
    );
}

#[test]
fn a_refused_call_is_refused_for_every_kind_of_call() {
    assert_eq!(
        zone_settings(&recorded("plain-server-zone-public")),
        Err(ReplyError::Refused)
    );
    assert_eq!(
        service_settings(&recorded("plain-server-service-ssh")),
        Err(ReplyError::Refused)
    );
    assert_eq!(
        log_denied(&recorded("plain-server-log-denied")),
        Err(ReplyError::Refused)
    );
}

#[test]
fn a_failed_call_that_is_not_a_refusal_is_failed_with_its_text() {
    let error = zone_settings(&recorded("zone-unknown")).unwrap_err();
    assert_eq!(
        error,
        ReplyError::Failed("Call failed: INVALID_ZONE: nosuchzone".into())
    );
}

#[test]
fn an_answer_with_no_output_is_empty() {
    assert_eq!(zone_settings(&answered("")), Err(ReplyError::Empty));
    assert_eq!(active_zones(&answered("\n")), Err(ReplyError::Empty));
}

#[test]
fn an_answer_that_is_not_what_was_asked_for_is_malformed() {
    let truncated = answered(r#"{"type":"a{sv}","data":[{"target":"#);
    assert!(matches!(
        zone_settings(&truncated),
        Err(ReplyError::Malformed(_))
    ));
    let wrong_shape = answered(r#"{"type":"s","data":["public"]}"#);
    assert!(matches!(
        zone_settings(&wrong_shape),
        Err(ReplyError::Malformed(_))
    ));
    let bad_port =
        answered(r#"{"type":"a{sv}","data":[{"ports":{"type":"a(ss)","data":[["http","tcp"]]}}]}"#);
    assert!(matches!(
        zone_settings(&bad_port),
        Err(ReplyError::Malformed(_))
    ));
}

fn lookup_in<'a>(
    services: &'a [(&'a str, &'a [&'a str], &'a [PortRule])],
) -> impl FnMut(&str) -> Result<ServiceSettings, ReplyError> + 'a {
    move |name| {
        services
            .iter()
            .find(|(candidate, _, _)| *candidate == name)
            .map(|(_, includes, ports)| ServiceSettings {
                ports: ports.to_vec(),
                includes: names(includes),
            })
            .ok_or_else(|| ReplyError::Failed(format!("no service {name}")))
    }
}

#[test]
fn a_services_includes_are_followed() {
    let services: [(&str, &[&str], &[PortRule]); 2] = [
        ("samba", &["samba-client"], &[port(445..=445, "tcp")]),
        ("samba-client", &[], &[port(137..=137, "udp")]),
    ];
    assert_eq!(
        service_ports("samba", lookup_in(&services)).unwrap(),
        vec![port(445..=445, "tcp"), port(137..=137, "udp")]
    );
}

#[test]
fn a_loop_of_includes_ends() {
    let services: [(&str, &[&str], &[PortRule]); 2] = [
        ("a", &["b"], &[port(1..=1, "tcp")]),
        ("b", &["a"], &[port(2..=2, "tcp")]),
    ];
    assert_eq!(
        service_ports("a", lookup_in(&services)).unwrap(),
        vec![port(1..=1, "tcp"), port(2..=2, "tcp")]
    );
}

#[test]
fn an_include_that_cannot_be_read_fails_the_resolution() {
    let services: [(&str, &[&str], &[PortRule]); 1] = [("a", &["missing"], &[])];
    assert!(service_ports("a", lookup_in(&services)).is_err());
}

#[test]
fn an_answer_of_the_wrong_shape_is_not_a_zone_that_allows_nothing() {
    let active_zones_answer = recorded("active-zones");
    let empty_settings = answered(r#"{"type":"a{sv}","data":[{}]}"#);
    let wrong_type = answered(r#"{"type":"s","data":[{"target":{"type":"s","data":"ACCEPT"}}]}"#);
    for answer in [&active_zones_answer, &empty_settings, &wrong_type] {
        assert!(matches!(
            zone_settings(answer),
            Err(ReplyError::Malformed(_))
        ));
    }
    assert!(matches!(
        service_settings(&wrong_type),
        Err(ReplyError::Malformed(_))
    ));
    assert!(matches!(
        service_settings(&active_zones_answer),
        Err(ReplyError::Malformed(_))
    ));
}

#[test]
fn every_recorded_settings_answer_still_parses() {
    for name in [
        "zone-public",
        "zone-trusted",
        "zone-drop",
        "zone-home",
        "plain-desktop-zone-public",
    ] {
        assert!(zone_settings(&recorded(name)).is_ok(), "{name}");
    }
    for name in [
        "service-samba",
        "service-ssh",
        "plain-desktop-service-samba",
    ] {
        assert!(service_settings(&recorded(name)).is_ok(), "{name}");
    }
}

#[test]
fn a_reversed_port_range_is_malformed() {
    let answer = answered(
        r#"{"type":"a{sv}","data":[{"target":{"type":"s","data":"default"},"ports":{"type":"a(ss)","data":[["10-5","tcp"]]}}]}"#,
    );
    assert!(matches!(
        zone_settings(&answer),
        Err(ReplyError::Malformed(_))
    ));
}

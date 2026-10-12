use std::{net::IpAddr, path::PathBuf, sync::OnceLock};

use crosswalk::{
    collect::{
        interfaces::{
            CollectionHealth, InterfaceAddress, InterfaceMeasurement, InterfaceSnapshot,
            InterfaceStatus,
        },
        neighbors::{Neighbor, NeighborSnapshot},
        wifi::{AccessPoint, WifiSnapshot},
    },
    dns::ReverseDns,
    state::{AppState, StateLimits},
    ui::map::{Map, MapBox, build},
    vendors::Vendors,
};

const HOST_MAC: &str = "10:00:00:00:00:13";

fn address(text: &str, prefix: u8) -> InterfaceAddress {
    InterfaceAddress {
        ip: text.parse().unwrap(),
        prefix,
    }
}

fn interface(name: &str, addresses: Vec<InterfaceAddress>) -> InterfaceMeasurement {
    InterfaceMeasurement {
        name: name.to_owned(),
        addresses,
        download_bytes_per_second: 0.0,
        upload_bytes_per_second: 0.0,
        session_received_bytes: 0,
        session_transmitted_bytes: 0,
        status: InterfaceStatus::Available,
        is_up: true,
    }
}

fn state_with(route: Option<&str>, gateway: Option<&str>, servers: &[&str]) -> AppState {
    let mut state = AppState::new(StateLimits::default()).unwrap();
    state.record_interfaces(InterfaceSnapshot {
        health: CollectionHealth::Available,
        interfaces: vec![
            interface("lo", vec![address("127.0.0.1", 8)]),
            interface(
                "eth0",
                vec![address("fe80::13", 64), address("10.0.1.13", 24)],
            ),
            interface("eth1", vec![address("192.168.5.2", 24)]),
        ],
        default_route: route.map(str::to_owned),
        gateway: gateway.map(|g| g.parse().unwrap()),
        name_server: servers.first().map(|s| s.parse().unwrap()),
        name_servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
    });
    state
}

fn lan() -> AppState {
    state_with(Some("eth0"), Some("10.0.1.1"), &[])
}

fn seen_on(state: &mut AppState, interface: &str, entries: &[(&str, Option<&str>)]) {
    state.record_neighbors(NeighborSnapshot::Available(
        entries
            .iter()
            .map(|(ip, mac)| Neighbor {
                address: ip.parse().unwrap(),
                mac: mac.map(str::to_owned),
                interface: interface.to_owned(),
                state: "REACHABLE".to_owned(),
            })
            .collect(),
    ));
}

fn seen(state: &mut AppState, entries: &[(&str, Option<&str>)]) {
    seen_on(state, "eth0", entries);
}

fn vendors() -> Vendors {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    let path = PATH.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("crosswalk-map-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oui.txt");
        std::fs::write(
            &path,
            "00-11-22   (hex)\t\tUbiquiti\n10-00-00   (hex)\t\tIntel\n20-00-00   (hex)\t\tRaspberry Pi\n",
        )
        .unwrap();
        path
    });
    Vendors::load(path)
}

fn map(state: &AppState) -> Map {
    build(state, &vendors(), None, Some(HOST_MAC), false).expect("a map")
}

fn map_wireless(state: &AppState, wireless: bool) -> Map {
    build(state, &vendors(), None, Some(HOST_MAC), wireless).expect("a map")
}

fn firsts(boxes: &[MapBox]) -> Vec<&str> {
    boxes.iter().map(|b| b.lines[0].as_str()).collect()
}

fn seconds(boxes: &[MapBox]) -> Vec<&str> {
    boxes.iter().map(|b| b.lines[1].as_str()).collect()
}

#[test]
fn no_default_route_gives_no_map() {
    let state = state_with(None, None, &[]);
    assert!(build(&state, &vendors(), None, None, false).is_none());
    let fresh = AppState::new(StateLimits::default()).unwrap();
    assert!(build(&fresh, &vendors(), None, None, false).is_none());
}

#[test]
fn only_the_default_routes_interface_is_taken() {
    let mut state = lan();
    seen(&mut state, &[("10.0.1.40", Some("aa:00:00:00:00:40"))]);
    seen_on(
        &mut state,
        "eth1",
        &[("192.168.5.9", Some("aa:00:00:00:00:99"))],
    );
    let m = map(&state);
    assert_eq!(m.interface, "eth0");
    assert_eq!(seconds(&m.devices), ["10.0.1.13", "10.0.1.40"]);
}

#[test]
fn the_gateway_is_its_own_box_and_not_a_device() {
    let mut state = lan();
    seen(
        &mut state,
        &[
            ("10.0.1.1", Some("00:11:22:00:00:01")),
            ("10.0.1.40", Some("aa:00:00:00:00:40")),
        ],
    );
    let m = map(&state);
    let gateway = m.gateway.unwrap();
    assert_eq!(gateway.lines, ["gateway", "10.0.1.1", "Ubiquiti"]);
    assert_eq!(seconds(&m.devices), ["10.0.1.13", "10.0.1.40"]);
}

#[test]
fn a_gateway_not_in_the_neighbour_table_shows_its_address_alone() {
    let m = map(&lan());
    assert_eq!(m.gateway.unwrap().lines, ["gateway", "10.0.1.1", ""]);
}

#[test]
fn a_name_server_outside_the_subnet_is_upstream_and_one_inside_is_a_dns_device() {
    let mut state = state_with(
        Some("eth0"),
        Some("10.0.1.1"),
        &["1.1.1.1", "10.0.1.6", "9.9.9.9"],
    );
    seen(&mut state, &[("10.0.1.6", Some("20:00:00:00:00:06"))]);
    let m = map(&state);
    let outside: Vec<String> = m.upstream.iter().map(IpAddr::to_string).collect();
    assert_eq!(outside, ["1.1.1.1", "9.9.9.9"]);
    assert_eq!(firsts(&m.devices), ["this host", "dns"]);
    assert_eq!(m.devices[1].lines, ["dns", "10.0.1.6", "Raspberry Pi"]);
}

#[test]
fn a_name_server_inside_the_subnet_with_no_neighbour_entry_is_still_shown() {
    let state = state_with(Some("eth0"), Some("10.0.1.1"), &["10.0.1.6"]);
    let m = map(&state);
    assert!(m.upstream.is_empty());
    assert_eq!(m.devices[1].lines, ["dns", "10.0.1.6", ""]);
}

#[test]
fn the_gateway_that_is_also_a_name_server_reads_gateway_dns() {
    let mut state = state_with(Some("eth0"), Some("10.0.1.1"), &["10.0.1.1"]);
    seen(&mut state, &[("10.0.1.1", Some("00:11:22:00:00:01"))]);
    let m = map(&state);
    assert_eq!(m.gateway.unwrap().lines[0], "gateway · dns");
    assert_eq!(m.devices.len(), 1);
}

#[test]
fn this_host_is_first_with_its_own_address_and_maker_and_the_others_by_address() {
    let mut state = lan();
    seen(
        &mut state,
        &[
            ("10.0.1.40", Some("aa:00:00:00:00:40")),
            ("fe80::2", Some("aa:00:00:00:00:02")),
            ("10.0.1.12", Some("aa:00:00:00:00:12")),
            ("2001:db8::1", Some("aa:00:00:00:00:01")),
            ("10.0.1.9", Some("aa:00:00:00:00:09")),
            ("10.0.1.13", Some(HOST_MAC)),
        ],
    );
    let m = map(&state);
    assert!(m.devices[0].this_host);
    assert!(m.devices.iter().skip(1).all(|b| !b.this_host));
    assert_eq!(m.devices[0].lines, ["this host", "10.0.1.13", "Intel"]);
    assert_eq!(
        seconds(&m.devices),
        [
            "10.0.1.13",
            "10.0.1.9",
            "10.0.1.12",
            "10.0.1.40",
            "2001:db8::1",
            "fe80::2"
        ]
    );
    assert_eq!(m.devices.len(), 6, "this host is not also a neighbour");
}

#[test]
fn a_boxs_first_line_is_role_else_name_when_names_are_on_else_hardware_address() {
    let mut state = lan();
    seen(
        &mut state,
        &[
            ("10.0.1.12", Some("aa:00:00:00:00:12")),
            ("10.0.1.40", Some("aa:00:00:00:00:40")),
        ],
    );
    let ip: IpAddr = "10.0.1.12".parse().unwrap();
    let mut dns = ReverseDns::new(true, 8, 8, |_| Some("desktop\u{1b}[31m".to_owned()));
    dns.schedule_visible([ip]);
    for _ in 0..200 {
        dns.poll();
        if dns.name(ip).is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let with_names = build(&state, &vendors(), Some(&dns), Some(HOST_MAC), false).unwrap();
    assert_eq!(
        firsts(&with_names.devices),
        ["this host", "desktop[31m", "aa:00:00:00:00:40"]
    );
    let without = map(&state);
    assert_eq!(
        firsts(&without.devices),
        ["this host", "aa:00:00:00:00:12", "aa:00:00:00:00:40"]
    );
}

#[test]
fn a_second_line_prefers_ipv4_then_ipv6_that_is_not_link_local_then_any() {
    let mut state = lan();
    seen(
        &mut state,
        &[
            ("fe80::1", Some("aa:00:00:00:00:01")),
            ("10.0.1.50", Some("aa:00:00:00:00:01")),
            ("fe80::2", Some("aa:00:00:00:00:02")),
            ("2001:db8::2", Some("aa:00:00:00:00:02")),
            ("fe80::3", Some("aa:00:00:00:00:03")),
        ],
    );
    let m = map(&state);
    assert_eq!(
        seconds(&m.devices),
        ["10.0.1.13", "10.0.1.50", "2001:db8::2", "fe80::3"]
    );
}

#[test]
fn the_third_line_is_the_maker_private_or_empty() {
    let mut state = lan();
    seen(
        &mut state,
        &[
            ("10.0.1.20", Some("20:00:00:00:00:20")),
            ("10.0.1.21", Some("02:00:00:00:00:21")),
            ("10.0.1.22", Some("cc:00:00:00:00:22")),
        ],
    );
    let m = map(&state);
    let thirds: Vec<&str> = m.devices.iter().map(|b| b.lines[2].as_str()).collect();
    assert_eq!(thirds, ["Intel", "Raspberry Pi", "private", ""]);
}

#[test]
fn the_label_names_the_interface_and_for_the_wifi_in_use_its_network_and_band() {
    let mut state = state_with(Some("eth0"), Some("10.0.1.1"), &[]);
    assert_eq!(map(&state).label, "eth0");
    let point = |ssid: &str, mhz: u32, in_use: bool| AccessPoint {
        ssid: Some(ssid.to_owned()),
        bssid: "00:11:22:33:44:55".to_owned(),
        signal: 70,
        channel: 36,
        frequency_mhz: mhz,
        security: "WPA2".to_owned(),
        in_use,
    };
    state.record_wifi(WifiSnapshot::Available(vec![
        point("Other", 2437, false),
        point("Home\u{1b}Net", 5805, true),
    ]));
    assert_eq!(map(&state).label, "eth0", "not a Wi-Fi interface");

    let mut wireless = state_with(Some("wlan0"), Some("10.0.1.1"), &[]);
    wireless.record_interfaces(InterfaceSnapshot {
        health: CollectionHealth::Available,
        interfaces: vec![interface("wlan0", vec![address("10.0.1.13", 24)])],
        default_route: Some("wlan0".to_owned()),
        gateway: Some("10.0.1.1".parse().unwrap()),
        name_server: None,
        name_servers: vec![],
    });
    wireless.record_wifi(WifiSnapshot::Available(vec![point("HomeNet", 5805, true)]));
    assert_eq!(map_wireless(&wireless, true).label, "wlan0 · HomeNet · 5G");
    wireless.record_wifi(WifiSnapshot::Available(vec![point("HomeNet", 5805, false)]));
    assert_eq!(map_wireless(&wireless, true).label, "wlan0");
    wireless.record_wifi(WifiSnapshot::Available(vec![point("HomeNet", 5805, true)]));
    assert_eq!(
        map_wireless(&wireless, false).label,
        "wlan0",
        "a name starting with wl does not make an interface wireless"
    );
}

#[test]
fn an_absent_device_is_marked_and_this_host_never_is() {
    let mut state = lan();
    seen(
        &mut state,
        &[
            ("10.0.1.12", Some("aa:00:00:00:00:12")),
            ("10.0.1.13", Some(HOST_MAC)),
        ],
    );
    seen(&mut state, &[("10.0.1.40", Some("aa:00:00:00:00:40"))]);
    let m = map(&state);
    let absent: Vec<bool> = m.devices.iter().map(|b| b.absent).collect();
    assert_eq!(seconds(&m.devices), ["10.0.1.13", "10.0.1.12", "10.0.1.40"]);
    assert_eq!(absent, [false, true, false]);
}

#[test]
fn two_devices_with_the_gateways_address_the_first_is_the_gateway_and_the_other_a_device() {
    let mut state = lan();
    seen(
        &mut state,
        &[
            ("10.0.1.1", Some("aa:00:00:00:00:02")),
            ("10.0.1.1", Some("00:11:22:00:00:01")),
        ],
    );
    let m = map(&state);
    assert_eq!(
        m.gateway.unwrap().lines,
        ["gateway", "10.0.1.1", "Ubiquiti"]
    );
    assert_eq!(seconds(&m.devices), ["10.0.1.13", "10.0.1.1"]);
    assert_eq!(m.devices[1].lines[0], "aa:00:00:00:00:02");
}

#[test]
fn a_vendor_name_with_control_and_bidirectional_characters_is_stripped_in_the_box() {
    let dir = std::env::temp_dir().join(format!("crosswalk-map-evil-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("oui.txt");
    std::fs::write(
        &path,
        "20-00-00   (hex)\t\tEvil\u{1b}[31m\u{202e}Corp\u{7}\u{2066}Ltd\u{200f}\n",
    )
    .unwrap();
    let mut state = lan();
    seen(&mut state, &[("10.0.1.40", Some("20:00:00:00:00:40"))]);
    let m = build(&state, &Vendors::load(&path), None, Some(HOST_MAC), false).unwrap();
    let maker = &m.devices[1].lines[2];
    assert_eq!(maker, "Evil[31mCorpLtd");
    assert!(!maker.chars().any(|c| c.is_control()
        || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')));
}

#[test]
fn an_ipv6_name_server_inside_the_subnet_is_a_dns_device_and_one_outside_is_upstream() {
    let mut state = state_with(
        Some("eth0"),
        Some("10.0.1.1"),
        &["fe80::53", "2001:4860:4860::8888"],
    );
    seen(&mut state, &[("fe80::53", Some("20:00:00:00:00:53"))]);
    let m = map(&state);
    let outside: Vec<String> = m.upstream.iter().map(IpAddr::to_string).collect();
    assert_eq!(outside, ["2001:4860:4860::8888"]);
    assert_eq!(m.devices.len(), 2);
    assert_eq!(m.devices[1].lines, ["dns", "fe80::53", "Raspberry Pi"]);

    let bare = state_with(Some("eth0"), Some("10.0.1.1"), &["fe80::54"]);
    let m = map(&bare);
    assert!(m.upstream.is_empty());
    assert_eq!(m.devices[1].lines, ["dns", "fe80::54", ""]);
}

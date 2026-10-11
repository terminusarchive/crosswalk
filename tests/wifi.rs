use std::io;

use crosswalk::collect::wifi::{
    AccessPoint, NmcliOutput, ScanOutcome, WifiCollector, WifiSnapshot, WifiSource,
    nmcli_arguments, nmcli_command, nmcli_scan_arguments,
};

struct Fixed {
    list: Option<io::Result<NmcliOutput>>,
    radio: Option<io::Result<NmcliOutput>>,
    rescan: Option<io::Result<NmcliOutput>>,
}

impl WifiSource for Fixed {
    fn rescan(&mut self) -> io::Result<NmcliOutput> {
        self.rescan.take().expect("no scan was expected")
    }

    fn list(&mut self) -> io::Result<NmcliOutput> {
        self.list.take().expect("read once")
    }

    fn radio(&mut self) -> io::Result<NmcliOutput> {
        self.radio
            .take()
            .expect("the radio was not expected to be asked")
    }
}

fn collect(result: io::Result<NmcliOutput>) -> WifiSnapshot {
    WifiCollector::new(Fixed {
        list: Some(result),
        radio: None,
        rescan: None,
    })
    .collect()
}

/// An empty list, then the radio's answer.
fn collect_empty_with_radio(radio: io::Result<NmcliOutput>) -> WifiSnapshot {
    WifiCollector::new(Fixed {
        list: Some(ok("")),
        radio: Some(radio),
        rescan: None,
    })
    .collect()
}

fn ok(text: &str) -> io::Result<NmcliOutput> {
    failed(0, text, "")
}

fn failed(code: i32, stdout: &str, stderr: &str) -> io::Result<NmcliOutput> {
    Ok(NmcliOutput {
        exit_code: Some(code),
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    })
}

fn points(text: &str) -> Vec<AccessPoint> {
    match collect(ok(text)) {
        WifiSnapshot::Available(points) => points,
        other => panic!("expected access points, got {other:?}"),
    }
}

fn reason(result: io::Result<NmcliOutput>) -> String {
    match collect(result) {
        WifiSnapshot::Unavailable(reason) => reason,
        other => panic!("expected unavailable, got {other:?}"),
    }
}

#[test]
fn a_line_with_an_escaped_hardware_address_parses_to_every_field() {
    let found = points("*:AA\\:BB\\:CC\\:DD\\:EE\\:D4:63:161:5805 MHz:WPA2:Den AP\n");
    assert_eq!(
        found,
        vec![AccessPoint {
            ssid: Some("Den AP".to_owned()),
            bssid: "AA:BB:CC:DD:EE:D4".to_owned(),
            signal: 63,
            channel: 161,
            frequency_mhz: 5805,
            security: "WPA2".to_owned(),
            in_use: true,
        }]
    );
}

#[test]
fn the_in_use_mark_is_read_and_its_absence() {
    let found = points(
        "*:00\\:00\\:00\\:00\\:00\\:01:50:1:2412 MHz:WPA2:A\n :00\\:00\\:00\\:00\\:00\\:02:40:6:2437 MHz:WPA2:B\n:00\\:00\\:00\\:00\\:00\\:03:30:11:2462 MHz:WPA2:\n",
    );
    let marks: Vec<_> = found.iter().map(|p| p.in_use).collect();
    assert_eq!(marks, vec![true, false, false]);
}

#[test]
fn an_empty_name_gives_no_name() {
    let found = points(" :94\\:F7\\:17\\:B3\\:C5\\:10:94:1:2412 MHz:WPA1 WPA2:\n");
    assert_eq!(found[0].ssid, None);
}

#[test]
fn names_with_an_escaped_colon_or_backslash_are_read_whole() {
    let found = points(
        " :00\\:00\\:00\\:00\\:00\\:01:50:1:2412 MHz:WPA2:Cafe\\: Free\n :00\\:00\\:00\\:00\\:00\\:02:40:6:2437 MHz:WPA2:back\\\\slash\n",
    );
    assert_eq!(found[0].ssid.as_deref(), Some("Cafe: Free"));
    assert_eq!(found[1].ssid.as_deref(), Some("back\\slash"));
    assert_eq!(found[1].signal, 40);
}

#[test]
fn a_frequency_of_5805_mhz_gives_5805() {
    let found = points(" :00\\:00\\:00\\:00\\:00\\:01:50:161:5805 MHz:WPA2:A\n");
    assert_eq!(found[0].frequency_mhz, 5805);
    assert_eq!(found[0].channel, 161);
}

#[test]
fn a_security_of_several_words_is_kept_and_an_open_network_is_empty() {
    let found = points(
        " :00\\:00\\:00\\:00\\:00\\:01:50:1:2412 MHz:WPA2 802.1X:A\n :00\\:00\\:00\\:00\\:00\\:02:50:1:2412 MHz::B\n :00\\:00\\:00\\:00\\:00\\:03:50:1:2412 MHz:--:C\n",
    );
    let security: Vec<_> = found.iter().map(|p| p.security.as_str()).collect();
    assert_eq!(security, vec!["WPA2 802.1X", "", ""]);
}

#[test]
fn a_malformed_line_is_skipped_without_failing_the_rest() {
    let found = points(
        " :00\\:00\\:00\\:00\\:00\\:01:50:Short\n :00\\:00\\:00\\:00\\:00\\:02:strong:1:2412 MHz:WPA2:Bad\n :00\\:00\\:00\\:00\\:00\\:03:50:1:2412 MHz:WPA2:Good\n",
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].ssid.as_deref(), Some("Good"));
}

#[test]
fn each_way_of_failing_gives_its_own_reason() {
    let missing = reason(Err(io::Error::from(io::ErrorKind::NotFound)));
    let not_running = reason(failed(8, "", "Error: NetworkManager is not running."));
    let no_device = reason(failed(10, "", "Error: No Wi-Fi device found."));
    let timed_out = reason(Err(io::Error::from(io::ErrorKind::TimedOut)));
    assert_eq!(missing, "nmcli not found");
    assert_eq!(not_running, "NetworkManager is not running");
    assert_eq!(no_device, "no Wi-Fi device");
    assert_eq!(timed_out, "nmcli timed out");
}

#[test]
fn any_other_failure_carries_the_first_line_of_nmcli_error_text() {
    let other = reason(failed(1, "", "Error: something odd.\nsecond line\n"));
    assert_eq!(other, "nmcli: Error: something odd.");
}

#[test]
fn a_network_name_with_a_newline_cannot_forge_a_row_or_the_in_use_mark() {
    // As `nmcli` prints a name of "x\n*:Evil" and of "y\r\n*:Evil2:...": the
    // newline stays, the colons are escaped, and the name is the last field.
    let found = points(
        " :00\\:00\\:00\\:00\\:00\\:01:50:1:2412 MHz:WPA2:x\n*\\:Evil\n :00\\:00\\:00\\:00\\:00\\:02:40:6:2437 MHz:WPA2:y\r\n*\\:Evil2\\:00\\:00\\:00\\:00\\:00\\:09\\:99\\:1\\:2412 MHz\\:WPA2\\:Evil2\n",
    );
    let names: Vec<_> = found.iter().map(|p| p.ssid.as_deref()).collect();
    assert_eq!(names, vec![Some("x"), Some("y")]);
    assert!(found.iter().all(|p| !p.in_use));
}

#[test]
fn the_command_never_asks_for_a_scan_and_names_the_fields_in_order() {
    let arguments = nmcli_arguments();
    let rescan = arguments.iter().position(|a| *a == "--rescan").unwrap();
    assert_eq!(arguments[rescan + 1], "no");
    let fields = arguments.iter().position(|a| *a == "-f").unwrap();
    assert_eq!(
        arguments[fields + 1],
        "IN-USE,BSSID,SIGNAL,CHAN,FREQ,SECURITY,SSID"
    );
}

#[test]
fn the_command_runs_in_the_c_locale_so_its_error_text_is_never_translated() {
    let command = nmcli_command(&nmcli_arguments());
    let locale = command
        .get_envs()
        .find(|(name, _)| *name == "LC_ALL")
        .and_then(|(_, value)| value);
    assert_eq!(locale, Some(std::ffi::OsStr::new("C")));
    assert_eq!(command.get_args().count(), nmcli_arguments().len());
}

#[test]
fn nmcli_is_started_by_absolute_path() {
    let command = nmcli_command(&nmcli_arguments());
    let program = std::path::Path::new(command.get_program());
    assert!(program.is_absolute(), "{program:?}");
    assert_eq!(program.file_name().unwrap(), "nmcli");
}

#[test]
fn a_spawn_error_other_than_not_found_gives_a_short_reason() {
    let denied = reason(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
    assert!(denied.starts_with("nmcli: "), "{denied}");
    assert!(denied.chars().count() <= 40, "{denied}");
}

#[test]
fn a_command_ended_by_a_signal_is_unavailable() {
    let killed = reason(Ok(NmcliOutput {
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
    }));
    assert_eq!(killed, "nmcli: failed");
}

#[test]
fn a_signal_above_100_is_skipped_without_failing_the_rest() {
    let found = points(
        " :00\\:00\\:00\\:00\\:00\\:01:101:1:2412 MHz:WPA2:Loud\n :00\\:00\\:00\\:00\\:00\\:02:100:1:2412 MHz:WPA2:Full\n",
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].ssid.as_deref(), Some("Full"));
}

#[test]
fn an_empty_list_with_the_radio_disabled_says_wifi_is_switched_off() {
    let snapshot = collect_empty_with_radio(ok("disabled\n"));
    assert_eq!(
        snapshot,
        WifiSnapshot::Unavailable("Wi-Fi is switched off".to_owned())
    );
}

#[test]
fn an_empty_list_with_the_radio_enabled_stays_an_empty_available_list() {
    let snapshot = collect_empty_with_radio(ok("enabled\n"));
    assert_eq!(snapshot, WifiSnapshot::Available(Vec::new()));
}

#[test]
fn an_empty_list_whose_radio_query_fails_stays_an_empty_available_list() {
    let failed_exit = collect_empty_with_radio(failed(1, "", "Error: oops"));
    let not_run = collect_empty_with_radio(Err(io::Error::from(io::ErrorKind::TimedOut)));
    assert_eq!(failed_exit, WifiSnapshot::Available(Vec::new()));
    assert_eq!(not_run, WifiSnapshot::Available(Vec::new()));
}

#[test]
fn a_non_empty_list_never_asks_about_the_radio() {
    let mut collector = WifiCollector::new(Fixed {
        list: Some(ok(" :00\\:00\\:00\\:00\\:00\\:01:50:1:2412 MHz:WPA2:A\n")),
        radio: None,
        rescan: None,
    });
    assert!(matches!(collector.collect(), WifiSnapshot::Available(p) if p.len() == 1));
}

fn scan(result: io::Result<NmcliOutput>) -> ScanOutcome {
    WifiCollector::new(Fixed {
        list: None,
        radio: None,
        rescan: Some(result),
    })
    .request_scan()
}

fn refused(outcome: ScanOutcome) -> String {
    match outcome {
        ScanOutcome::Refused(reason) => {
            assert!(reason.chars().count() <= 30, "{reason:?} is too long");
            reason
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_scan_command_is_device_wifi_rescan_and_only_it_asks_for_one() {
    assert_eq!(nmcli_scan_arguments(), ["device", "wifi", "rescan"]);
    let periodic = nmcli_arguments();
    assert!(!periodic.contains(&"rescan"));
    let at = periodic.iter().position(|a| *a == "--rescan").unwrap();
    assert_eq!(periodic[at + 1], "no");
}

#[test]
fn an_accepted_scan_is_accepted() {
    assert_eq!(scan(ok("")), ScanOutcome::Accepted);
}

#[test]
fn each_way_a_scan_can_fail_gives_its_own_short_reason() {
    let too_soon = refused(scan(failed(
        1,
        "",
        "Error: Failed to request scan: Scanning not allowed immediately following previous scan.\n",
    )));
    let unauthorised = refused(scan(failed(
        1,
        "",
        "Error: Failed to request scan: Not authorized to perform this operation\n",
    )));
    let missing = refused(scan(Err(io::Error::from(io::ErrorKind::NotFound))));
    let timed_out = refused(scan(Err(io::Error::from(io::ErrorKind::TimedOut))));
    let not_running = refused(scan(failed(
        8,
        "",
        "Error: NetworkManager is not running.\n",
    )));
    let other = refused(scan(failed(1, "", "Error: something odd happened\n")));
    let mut all = vec![
        too_soon,
        unauthorised,
        missing,
        timed_out,
        not_running,
        other,
    ];
    assert!(all[0].contains("scan"), "{all:?}");
    assert!(all[1].contains("authori"), "{all:?}");
    assert!(all[2].contains("not found"), "{all:?}");
    assert!(all[3].contains("timed out"), "{all:?}");
    assert!(all[4].contains("not running"), "{all:?}");
    assert!(all[5].contains("something odd"), "{all:?}");
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 6);
}

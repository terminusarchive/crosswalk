use std::process::Command;

use crosswalk::privileges::{Capabilities, capabilities_from_status, missing_net_raw_message};

fn caps(mask: &str) -> Option<Capabilities> {
    capabilities_from_status(&format!("Name:\tx\nCapEff:\t{mask}\nCapBnd:\t0\n"))
}

fn both(net_raw: bool, sys_ptrace: bool) -> Option<Capabilities> {
    Some(Capabilities {
        net_raw,
        sys_ptrace,
    })
}

#[test]
fn both_capabilities_are_read_from_the_effective_mask() {
    assert_eq!(caps("0000000000082000"), both(true, true));
}

#[test]
fn only_net_raw_is_read_from_the_effective_mask() {
    assert_eq!(caps("0000000000002000"), both(true, false));
}

#[test]
fn only_sys_ptrace_is_read_from_the_effective_mask() {
    assert_eq!(caps("0000000000080000"), both(false, true));
}

#[test]
fn no_capabilities_is_not_unknown() {
    assert_eq!(caps("0000000000000000"), both(false, false));
}

#[test]
fn a_root_mask_holds_both() {
    assert_eq!(caps("000001ffffffffff"), both(true, true));
}

#[test]
fn a_status_without_capeff_is_unknown() {
    assert_eq!(capabilities_from_status("Name:\tx\nCapBnd:\t2000\n"), None);
}

#[test]
fn an_unparsable_capeff_is_unknown() {
    assert_eq!(caps("not-hex"), None);
}

#[test]
fn the_message_gives_the_command_with_the_path_and_names_sudo_as_the_alternative() {
    let message = missing_net_raw_message("/opt/crosswalk");
    assert!(message.contains("sudo setcap cap_net_raw,cap_sys_ptrace+ep /opt/crosswalk\n"));
    assert!(message.contains("cap_net_raw"));
    assert!(message.contains("run Crosswalk with sudo"));
}

#[test]
fn a_path_with_a_space_is_quoted_so_the_command_can_be_pasted() {
    let message = missing_net_raw_message("/home/a b/crosswalk");
    assert!(message.contains("+ep '/home/a b/crosswalk'\n"));
}

#[test]
fn a_single_quote_in_the_path_is_closed_escaped_and_reopened() {
    let message = missing_net_raw_message("/home/o'neil/crosswalk");
    assert!(message.contains(r"+ep '/home/o'\''neil/crosswalk'"));
}

fn holds_net_raw() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| capabilities_from_status(&status))
        .is_none_or(|c| c.net_raw)
}

const BINARY: &str = env!("CARGO_BIN_EXE_crosswalk");

#[test]
fn without_net_raw_the_binary_exits_1_with_the_command_and_touches_no_terminal() {
    if holds_net_raw() {
        eprintln!("skipped: this process holds cap_net_raw (or its state is unknown)");
        return;
    }
    let output = Command::new(BINARY).output().expect("crosswalk should run");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The path is quoted as the message quotes it, whatever the checkout's path needs.
    assert!(stderr.contains(&missing_net_raw_message(BINARY)));
    assert!(output.stdout.is_empty());
}

#[test]
fn help_succeeds_without_any_capability() {
    let output = Command::new(BINARY)
        .arg("--help")
        .output()
        .expect("crosswalk should run");
    assert!(output.status.success());
}

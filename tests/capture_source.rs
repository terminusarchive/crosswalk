use std::process::Command;

use crosswalk::{
    capture_source::{CaptureChoice, choose_capture_source_in},
    privileges::{Capabilities, missing_net_raw_message},
};

fn net_raw(held: bool) -> Option<Capabilities> {
    Some(Capabilities { net_raw: held })
}

fn scratch_dir_with_dumpcap(name: &str, mode: Option<u32>) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("crosswalk-choice-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    if let Some(mode) = mode {
        std::fs::write(dir.join("dumpcap"), "").unwrap();
        std::fs::set_permissions(dir.join("dumpcap"), std::fs::Permissions::from_mode(mode))
            .unwrap();
    }
    dir
}

fn own_name(flag: &str) -> String {
    let output = Command::new("id").arg(flag).output().unwrap();
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn choice(capabilities: Option<Capabilities>, directory: &std::path::Path) -> CaptureChoice {
    choose_capture_source_in(capabilities, "/opt/crosswalk", &[directory], "ryan")
}

#[test]
fn a_binary_holding_net_raw_captures_by_itself_whatever_dumpcap_is() {
    let runnable = scratch_dir_with_dumpcap("granted-x", Some(0o755));
    let missing = scratch_dir_with_dumpcap("granted-none", None);
    assert_eq!(choice(net_raw(true), &runnable), CaptureChoice::Own);
    assert_eq!(choice(net_raw(true), &missing), CaptureChoice::Own);
}

#[test]
fn unknown_capabilities_capture_by_itself() {
    let runnable = scratch_dir_with_dumpcap("unknown", Some(0o755));
    assert_eq!(choice(None, &runnable), CaptureChoice::Own);
}

#[test]
fn without_net_raw_an_executable_dumpcap_is_chosen() {
    let runnable = scratch_dir_with_dumpcap("runnable", Some(0o755));
    assert_eq!(choice(net_raw(false), &runnable), CaptureChoice::Dumpcap);
}

#[test]
fn a_dumpcap_the_user_cannot_run_gives_both_ways_out_naming_the_group_and_the_user() {
    let locked = scratch_dir_with_dumpcap("locked", Some(0o640));
    let CaptureChoice::Stop(message) = choice(net_raw(false), &locked) else {
        panic!("expected a stop");
    };
    assert!(message.contains(&missing_net_raw_message("/opt/crosswalk")));
    let group = own_name("-gn");
    assert!(
        message.contains(&format!("sudo usermod -aG {group} ryan")),
        "{message}"
    );
    assert!(message.contains("log in again"), "{message}");
}

#[test]
fn no_dumpcap_gives_today_s_text_and_the_line_about_installing_it() {
    let empty = scratch_dir_with_dumpcap("empty", None);
    let CaptureChoice::Stop(message) = choice(net_raw(false), &empty) else {
        panic!("expected a stop");
    };
    assert!(message.contains(&missing_net_raw_message("/opt/crosswalk")));
    assert!(message.contains("install Wireshark's dumpcap"), "{message}");
    assert!(!message.contains("usermod"), "{message}");
}

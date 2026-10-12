//! Which source the packets come from: this process itself, or `dumpcap`.

use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::{
    command::{SYSTEM_DIRECTORIES, find_program_in},
    privileges::{Capabilities, missing_net_raw_message},
};

/// Where packets come from, or why there is no way to get them.
#[derive(Debug, PartialEq, Eq)]
pub enum CaptureChoice {
    Own,
    Dumpcap,
    Stop(String),
}

/// Decides the source from the granted capabilities and the `dumpcap` on this machine.
pub fn choose_capture_source(capabilities: Option<Capabilities>, binary: &str) -> CaptureChoice {
    let directories = SYSTEM_DIRECTORIES.map(Path::new);
    choose_capture_source_in(capabilities, binary, &directories, &own_user_name())
}

/// Capture by itself when the binary holds `cap_net_raw` or its capabilities are unknown;
/// otherwise through the first `dumpcap` found in `directories` if `user` may run it,
/// and otherwise stop with both ways out.
pub fn choose_capture_source_in(
    capabilities: Option<Capabilities>,
    binary: &str,
    directories: &[&Path],
    user: &str,
) -> CaptureChoice {
    if capabilities.is_none_or(|granted| granted.net_raw) {
        return CaptureChoice::Own;
    }
    let Some(dumpcap) = find_program_in("dumpcap", directories) else {
        return CaptureChoice::Stop(format!(
            "{}\nOr install Wireshark's dumpcap, which Crosswalk then captures through.",
            missing_net_raw_message(binary)
        ));
    };
    if can_execute(&dumpcap) {
        return CaptureChoice::Dumpcap;
    }
    let group = group_name_of(&dumpcap).unwrap_or_else(|| "wireshark".to_owned());
    CaptureChoice::Stop(format!(
        "{}\nOr let your user run Wireshark's dumpcap, which Crosswalk then captures through:\n\
         \n    sudo usermod -aG {group} {user}\n\n\
         Then log in again, so that the new group applies.",
        missing_net_raw_message(binary)
    ))
}

fn can_execute(path: &Path) -> bool {
    CString::new(path.as_os_str().as_bytes())
        .is_ok_and(|path| unsafe { libc::access(path.as_ptr(), libc::X_OK) } == 0)
}

fn group_name_of(path: &Path) -> Option<String> {
    let group = unsafe { libc::getgrgid(std::fs::metadata(path).ok()?.gid()) };
    if group.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr((*group).gr_name) };
    Some(name.to_string_lossy().into_owned())
}

fn own_user_name() -> String {
    let user = unsafe { libc::getpwuid(libc::geteuid()) };
    if user.is_null() {
        return "$USER".to_owned();
    }
    let name = unsafe { CStr::from_ptr((*user).pw_name) };
    name.to_string_lossy().into_owned()
}

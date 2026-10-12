//! Builders shared by several test files.
#![allow(dead_code)]

use crosswalk::collect::{attribution::Listener, capture::Protocol};

pub fn listener(protocol: Protocol, address: &str, port: u16) -> Listener {
    Listener {
        protocol,
        address: address.parse().unwrap(),
        port,
        owners: Vec::new(),
    }
}

/// Whether the file at `path` carries file capabilities, which a copy of it would not.
pub fn binary_is_granted_capabilities(path: &str) -> bool {
    let path = std::ffi::CString::new(path).unwrap();
    let name = c"security.capability";
    let size = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    size > 0
}

/// Whether this process may run a `dumpcap` from the system directories.
pub fn dumpcap_is_runnable() -> bool {
    [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/run/current-system/sw/bin",
    ]
    .iter()
    .map(|directory| std::path::Path::new(directory).join("dumpcap"))
    .find(|path| path.is_file())
    .is_some_and(|path| {
        let path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
    })
}

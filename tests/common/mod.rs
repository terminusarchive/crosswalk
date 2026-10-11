//! Builders shared by several test files.

use crosswalk::collect::{attribution::Listener, capture::Protocol};

pub fn listener(protocol: Protocol, address: &str, port: u16) -> Listener {
    Listener {
        protocol,
        address: address.parse().unwrap(),
        port,
        owners: Vec::new(),
    }
}

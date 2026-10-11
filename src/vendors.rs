//! The hardware-vendor table: maker names by the first three bytes of a hardware address.

use std::{collections::HashMap, fs, path::Path};

/// Where the system keeps the IEEE registry.
pub const SYSTEM_TABLE: &str = "/usr/share/hwdata/oui.txt";

/// Bit of the first byte that marks a locally administered address.
const LOCALLY_ADMINISTERED: u8 = 0x02;

#[derive(Debug, Default)]
pub struct Vendors {
    by_prefix: HashMap<[u8; 3], String>,
}

impl Vendors {
    /// Reads the `(hex)` lines of a file in the format of `oui.txt`. A file
    /// that is missing, empty or not that format is an empty table.
    pub fn load(path: impl AsRef<Path>) -> Self {
        let Ok(bytes) = fs::read(path) else {
            return Self::default();
        };
        let mut by_prefix = HashMap::new();
        for line in String::from_utf8_lossy(&bytes).lines() {
            let Some((prefix, name)) = line.split_once("(hex)") else {
                continue;
            };
            let name = name.trim();
            if let (Some(prefix), false) = (parse_octets::<3>(prefix.trim(), '-'), name.is_empty())
            {
                by_prefix.insert(prefix, name.to_owned());
            }
        }
        Self { by_prefix }
    }

    /// How many prefixes the table holds.
    pub fn len(&self) -> usize {
        self.by_prefix.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_prefix.is_empty()
    }

    /// The maker of a hardware address written as `aa:bb:cc:dd:ee:ff`:
    /// `private` for a locally administered one, else the vendor of its prefix;
    /// none for an address of all zeros, which no maker issued.
    pub fn maker(&self, mac: &str) -> Option<&str> {
        if mac.split(':').all(|part| part.bytes().all(|b| b == b'0')) {
            return None;
        }
        let first_three = mac.split(':').take(3).collect::<Vec<_>>().join(":");
        let prefix = parse_octets::<3>(&first_three, ':')?;
        if prefix[0] & LOCALLY_ADMINISTERED != 0 {
            return Some("private");
        }
        self.by_prefix.get(&prefix).map(String::as_str)
    }
}

fn parse_octets<const N: usize>(text: &str, separator: char) -> Option<[u8; N]> {
    let mut octets = [0u8; N];
    let mut parts = text.split(separator);
    for octet in &mut octets {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *octet = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(octets)
}

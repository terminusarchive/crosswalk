//! Which Linux capabilities the process holds, and what to tell the user when one is missing.

const CAP_NET_RAW: u32 = 13;
const CAP_SYS_PTRACE: u32 = 19;

/// The capabilities Crosswalk cares about, from the effective set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub net_raw: bool,
    pub sys_ptrace: bool,
}

/// Reads the effective set from the text of `/proc/self/status`.
/// `None` means unknown: no `CapEff` line, or one that does not parse.
pub fn capabilities_from_status(status: &str) -> Option<Capabilities> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?;
    let mask = u64::from_str_radix(value.trim(), 16).ok()?;
    Some(Capabilities {
        net_raw: mask & (1 << CAP_NET_RAW) != 0,
        sys_ptrace: mask & (1 << CAP_SYS_PTRACE) != 0,
    })
}

/// The message for a process without `cap_net_raw`.
pub fn missing_net_raw_message(binary: &str) -> String {
    format!(
        "crosswalk cannot capture packets: it lacks the cap_net_raw capability.\n\
         Grant it to the binary with:\n\
         \n    sudo setcap cap_net_raw,cap_sys_ptrace+ep {}\n\n\
         Repeat this after each build or install; the capabilities do not survive a new file.\n\
         Or run Crosswalk with sudo instead.",
        shell_quote(binary)
    )
}

fn shell_quote(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+=:,@%".contains(c));
    if plain {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

//! Which Linux capabilities the process holds, what to tell the user when one is missing,
//! and the calls that read and change the calling thread's own capability sets.

use std::fmt;
use std::io;

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

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const NET_RAW_BIT: u64 = 1 << CAP_NET_RAW;
const SYS_PTRACE_BIT: u64 = 1 << CAP_SYS_PTRACE;

/// The sets of one thread, one bit per capability.
/// `effective` is what is in force now; `permitted` is what the thread could switch on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadCapabilities {
    pub effective: u64,
    pub permitted: u64,
    inheritable: u64,
}

/// The kernel refused to read or change a capability set.
/// `capability` names what a failed change was for; a failed read has none.
#[derive(Debug)]
pub struct PrivilegeError {
    capability: Option<&'static str>,
    source: io::Error,
}

impl fmt::Display for PrivilegeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.capability {
            Some(capability) => write!(f, "cannot change {capability}: {}", self.source),
            None => write!(f, "cannot read the capability sets: {}", self.source),
        }
    }
}

impl std::error::Error for PrivilegeError {}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The calling thread's capability sets.
pub fn thread_capabilities() -> io::Result<ThreadCapabilities> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    let result = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let join = |low: u32, high: u32| u64::from(low) | u64::from(high) << 32;
    Ok(ThreadCapabilities {
        effective: join(data[0].effective, data[1].effective),
        permitted: join(data[0].permitted, data[1].permitted),
        inheritable: join(data[0].inheritable, data[1].inheritable),
    })
}

fn set_thread_capabilities(sets: ThreadCapabilities) -> io::Result<()> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let word = |shift: u32| CapData {
        effective: (sets.effective >> shift) as u32,
        permitted: (sets.permitted >> shift) as u32,
        inheritable: (sets.inheritable >> shift) as u32,
    };
    let data = [word(0), word(32)];
    let result = unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Changes the calling thread's sets; names `capability` if the kernel refuses.
/// Does nothing for root, whose sets are left as they are.
fn change(
    capability: &'static str,
    new_sets: impl FnOnce(ThreadCapabilities) -> ThreadCapabilities,
) -> Result<(), PrivilegeError> {
    if is_root() {
        return Ok(());
    }
    let named = |source| PrivilegeError {
        capability: Some(capability),
        source,
    };
    let current = thread_capabilities().map_err(named)?;
    set_thread_capabilities(new_sets(current)).map_err(named)
}

/// Takes every capability out of effect on this thread; they stay available.
pub fn take_everything_out_of_effect() -> Result<(), PrivilegeError> {
    change("cap_net_raw and cap_sys_ptrace", |sets| {
        ThreadCapabilities {
            effective: 0,
            ..sets
        }
    })
}

/// Gives up every capability on this thread for good.
pub fn give_up_everything() -> Result<(), PrivilegeError> {
    change("cap_net_raw and cap_sys_ptrace", |sets| {
        ThreadCapabilities {
            effective: 0,
            permitted: 0,
            ..sets
        }
    })
}

/// Gives up everything on this thread except that `cap_sys_ptrace` stays available.
pub fn keep_only_sys_ptrace_available() -> Result<(), PrivilegeError> {
    change("cap_net_raw", |sets| ThreadCapabilities {
        effective: 0,
        permitted: sets.permitted & SYS_PTRACE_BIT,
        ..sets
    })
}

/// Puts `cap_net_raw` in effect on this thread, which must have it available.
pub fn enable_net_raw() -> Result<(), PrivilegeError> {
    change("cap_net_raw", |sets| ThreadCapabilities {
        effective: sets.effective | NET_RAW_BIT,
        ..sets
    })
}

/// Puts `cap_net_raw` in effect when this thread has it available, and otherwise does
/// nothing, so that opening the capture reports the missing capability itself.
pub fn enable_net_raw_if_available() -> Result<(), PrivilegeError> {
    if read_own_sets()?.permitted & NET_RAW_BIT == 0 {
        return Ok(());
    }
    enable_net_raw()
}

fn read_own_sets() -> Result<ThreadCapabilities, PrivilegeError> {
    thread_capabilities().map_err(|source| PrivilegeError {
        capability: None,
        source,
    })
}

fn set_sys_ptrace_in_effect(in_effect: bool) -> Result<(), PrivilegeError> {
    change("cap_sys_ptrace", |sets| ThreadCapabilities {
        effective: if in_effect {
            sets.effective | SYS_PTRACE_BIT
        } else {
            sets.effective & !SYS_PTRACE_BIT
        },
        ..sets
    })
}

/// Takes `cap_sys_ptrace` out of effect when dropped, including while unwinding.
struct SysPtraceInEffect;

impl SysPtraceInEffect {
    fn end(self) -> Result<(), PrivilegeError> {
        std::mem::forget(self);
        set_sys_ptrace_in_effect(false)
    }
}

impl Drop for SysPtraceInEffect {
    fn drop(&mut self) {
        let _ = set_sys_ptrace_in_effect(false);
    }
}

/// Runs `work` with `cap_sys_ptrace` in effect on this thread, and out of effect after,
/// also if `work` panics. A thread that does not have it available just runs `work`.
pub fn with_sys_ptrace<T>(work: impl FnOnce() -> T) -> Result<T, PrivilegeError> {
    if read_own_sets()?.permitted & SYS_PTRACE_BIT == 0 {
        return Ok(work());
    }
    set_sys_ptrace_in_effect(true)?;
    let guard = SysPtraceInEffect;
    let value = work();
    guard.end()?;
    Ok(value)
}

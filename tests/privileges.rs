use std::process::Command;

mod common;

use crosswalk::privileges::{
    Capabilities, capabilities_from_status, enable_net_raw, enable_net_raw_if_available,
    give_up_everything, missing_net_raw_message, thread_capabilities,
};

fn caps(mask: &str) -> Option<Capabilities> {
    capabilities_from_status(&format!("Name:\tx\nCapEff:\t{mask}\nCapBnd:\t0\n"))
}

fn net_raw(held: bool) -> Option<Capabilities> {
    Some(Capabilities { net_raw: held })
}

#[test]
fn net_raw_is_read_from_the_effective_mask() {
    assert_eq!(caps("0000000000002000"), net_raw(true));
}

#[test]
fn a_mask_without_net_raw_reads_as_not_held() {
    assert_eq!(caps("0000000000080000"), net_raw(false));
}

#[test]
fn no_capabilities_is_not_unknown() {
    assert_eq!(caps("0000000000000000"), net_raw(false));
}

#[test]
fn a_root_mask_holds_net_raw() {
    assert_eq!(caps("000001ffffffffff"), net_raw(true));
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
    assert!(message.contains("sudo setcap cap_net_raw+ep /opt/crosswalk\n"));
    assert!(!message.contains("cap_sys_ptrace"));
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
    if holds_net_raw() || binary_is_granted_capabilities() || common::dumpcap_is_runnable() {
        eprintln!("skipped: the binary would capture (cap_net_raw, state unknown, or dumpcap)");
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

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn status_mask(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .unwrap();
    u64::from_str_radix(value.trim(), 16).unwrap()
}

#[test]
fn the_sets_a_thread_reads_of_itself_match_its_status_file() {
    let sets = thread_capabilities().unwrap();
    assert_eq!(sets.effective, status_mask("CapEff:"));
    assert_eq!(sets.permitted, status_mask("CapPrm:"));
}

#[test]
fn giving_up_everything_empties_both_sets_of_the_thread() {
    if is_root() {
        eprintln!("skipped: root's capability sets are left alone");
        return;
    }
    std::thread::spawn(|| {
        give_up_everything().unwrap();
        assert_eq!(status_mask("CapEff:"), 0);
        assert_eq!(status_mask("CapPrm:"), 0);
    })
    .join()
    .unwrap();
}

#[test]
fn putting_net_raw_in_effect_without_it_available_names_the_capability() {
    if is_root() {
        eprintln!("skipped: root's capability sets are left alone");
        return;
    }
    std::thread::spawn(|| {
        let error = enable_net_raw().unwrap_err();
        assert!(error.to_string().contains("cap_net_raw"), "{error}");
    })
    .join()
    .unwrap();
}

#[test]
fn putting_net_raw_in_effect_where_it_is_not_available_does_nothing() {
    if is_root() {
        eprintln!("skipped: root's capability sets are left alone");
        return;
    }
    std::thread::spawn(|| {
        give_up_everything().unwrap();
        enable_net_raw_if_available().unwrap();
        assert_eq!(status_mask("CapEff:"), 0);
    })
    .join()
    .unwrap();
}

fn binary_is_granted_capabilities() -> bool {
    common::binary_is_granted_capabilities(BINARY) && !is_root()
}

fn runs_with_file_capabilities_that_pid_1_could_refuse() -> bool {
    if !binary_is_granted_capabilities() {
        eprintln!("skipped: the binary holds no file capabilities");
        return false;
    }
    if std::fs::read_dir("/proc/1/root").is_ok() {
        eprintln!("skipped: this process can read /proc/1/root itself");
        return false;
    }
    true
}

fn refused_with_permission_error(output: std::process::Output) {
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Permission denied"), "{stderr}");
}

#[test]
fn a_config_only_cap_sys_ptrace_could_reach_is_refused() {
    if !runs_with_file_capabilities_that_pid_1_could_refuse() {
        return;
    }
    let output = Command::new(BINARY)
        .args(["--config", "/proc/1/root/etc/hostname"])
        .output()
        .expect("crosswalk should run");
    refused_with_permission_error(output);
}

#[test]
fn an_attribution_log_only_cap_sys_ptrace_could_reach_is_refused() {
    if !runs_with_file_capabilities_that_pid_1_could_refuse() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("crosswalk-log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("attribution.log");
    let through_pid_1 = format!("/proc/1/root{}", log.display());
    let output = Command::new(BINARY)
        .args(["--attribution-log", &through_pid_1])
        .output()
        .expect("crosswalk should run");
    let created = log.exists();
    std::fs::remove_dir_all(&dir).unwrap();
    refused_with_permission_error(output);
    assert!(!created, "the log was created");
}

/// One thread's name and sets, as `/proc/<pid>/task/<tid>/status` shows them.
struct ThreadReading {
    name: String,
    effective: u64,
    permitted: u64,
}

fn read_threads(pid: u32) -> Vec<ThreadReading> {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    tasks
        .flatten()
        .filter_map(|task| std::fs::read_to_string(task.path().join("status")).ok())
        .filter_map(|status| {
            let field = |name: &str| status.lines().find_map(|line| line.strip_prefix(name));
            Some(ThreadReading {
                name: field("Name:")?.trim().to_owned(),
                effective: u64::from_str_radix(field("CapEff:")?.trim(), 16).ok()?,
                permitted: u64::from_str_radix(field("CapPrm:")?.trim(), 16).ok()?,
            })
        })
        .collect()
}

/// Runs the dashboard on a pseudo-terminal for `duration`, reading every thread's sets
/// repeatedly, then quits it. Each reading comes with the time since the start.
fn dashboard_thread_readings(
    duration: std::time::Duration,
) -> Vec<(std::time::Duration, Vec<ThreadReading>)> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let (mut master, mut slave) = (-1, -1);
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(opened, 0);
    let slave_file = unsafe { std::fs::File::from_raw_fd(slave) };
    let duplicate = || unsafe { std::fs::File::from_raw_fd(libc::dup(slave_file.as_raw_fd())) };
    let mut child = Command::new(BINARY)
        .stdin(std::process::Stdio::from(duplicate()))
        .stdout(std::process::Stdio::from(duplicate()))
        .stderr(std::process::Stdio::from(duplicate()))
        .spawn()
        .unwrap();
    drop(slave_file);
    let started = std::time::Instant::now();
    let mut readings = Vec::new();
    while started.elapsed() < duration {
        readings.push((started.elapsed(), read_threads(child.id())));
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(unsafe { libc::write(master, b"q\n".as_ptr().cast(), 2) }, 2);
    let _ = child.wait();
    unsafe { libc::close(master) };
    readings
}

/// Every thread reading taken after the dashboard had settled, with the time it was taken.
fn settled_threads(
    readings: &[(std::time::Duration, Vec<ThreadReading>)],
) -> impl Iterator<Item = (std::time::Duration, &ThreadReading)> {
    let settled = std::time::Duration::from_secs(1);
    readings
        .iter()
        .filter(move |(at, _)| *at > settled)
        .flat_map(|(at, threads)| threads.iter().map(move |thread| (*at, thread)))
}

fn judge_thread(thread: &ThreadReading, at: std::time::Duration) {
    assert_eq!(thread.effective, 0, "{} at {at:?}", thread.name);
    assert_eq!(thread.permitted, 0, "{} at {at:?}", thread.name);
}

#[test]
fn no_thread_holds_any_capability_once_the_dashboard_has_settled() {
    if !binary_is_granted_capabilities() {
        eprintln!("skipped: the binary holds no file capabilities");
        return;
    }
    let readings = dashboard_thread_readings(std::time::Duration::from_secs(3));
    let mut seen = 0;
    for (at, thread) in settled_threads(&readings) {
        judge_thread(thread, at);
        seen += 1;
    }
    assert!(seen > 0, "no thread was read after the first second");
}

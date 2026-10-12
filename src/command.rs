use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use crate::{privileges::give_up_everything, runtime::or_stop};

pub(crate) const SYSTEM_DIRECTORIES: [&str; 5] = [
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/run/current-system/sw/bin",
];

/// The command for a helper program, by absolute path from the system directories: `PATH`
/// is never consulted, so a program planted in a directory someone else can write is not run.
/// A helper in none of them gets the `/usr/bin` path, which fails to start as not found.
pub(crate) fn system_command(name: &str) -> Command {
    let directories = SYSTEM_DIRECTORIES.map(Path::new);
    Command::new(program_in(name, &directories))
}

/// The first of `directories` holding a file called `name`. The one lookup both for
/// running a helper and for judging whether it may be run.
pub(crate) fn find_program_in(name: &str, directories: &[&Path]) -> Option<PathBuf> {
    directories
        .iter()
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn program_in(name: &str, directories: &[&Path]) -> PathBuf {
    find_program_in(name, directories).unwrap_or_else(|| Path::new("/usr/bin").join(name))
}

/// Runs a command to completion, killing it if it outlives `timeout` or if
/// `cancelled` is set while it runs.
pub(crate) fn run_within(
    mut command: Command,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = read_in_background(child.stdout.take());
    let stderr = read_in_background(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if cancelled.load(Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out after {} s", timeout.as_secs()),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let read = |handle: thread::JoinHandle<Vec<u8>>| handle.join().unwrap_or_default();
    Ok((status, read(stdout), read(stderr)))
}

fn read_in_background(pipe: Option<impl Read + Send + 'static>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        // The thread that starts this one may still have capabilities available.
        or_stop(give_up_everything());
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        bytes
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("crosswalk-dirs-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_first_directory_holding_the_name_wins() {
        let (first, second, empty) = (scratch_dir("a"), scratch_dir("b"), scratch_dir("c"));
        std::fs::write(second.join("tool"), "").unwrap();
        let dirs = [empty.as_path(), second.as_path(), first.as_path()];
        assert_eq!(program_in("tool", &dirs), second.join("tool"));
        std::fs::write(first.join("tool"), "").unwrap();
        assert_eq!(program_in("tool", &dirs), second.join("tool"));
        let dirs = [first.as_path(), second.as_path()];
        assert_eq!(program_in("tool", &dirs), first.join("tool"));
        for dir in [first, second, empty] {
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn a_name_in_no_directory_gives_usr_bin_and_fails_to_start_as_not_found() {
        let empty = scratch_dir("d");
        let path = program_in("crosswalk-no-such-helper", &[empty.as_path()]);
        assert_eq!(path, Path::new("/usr/bin/crosswalk-no-such-helper"));
        let error = Command::new(path).spawn().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        std::fs::remove_dir_all(empty).unwrap();
    }

    #[test]
    fn the_helpers_are_started_by_absolute_path() {
        for name in ["ip", "nmcli", "journalctl"] {
            let command = system_command(name);
            assert!(Path::new(command.get_program()).is_absolute(), "{name}");
        }
    }

    #[test]
    fn a_command_that_outlives_the_timeout_is_killed_and_reported() {
        let mut command = Command::new("sleep");
        command.arg("30");
        let started = Instant::now();
        let error =
            run_within(command, Duration::from_millis(100), &AtomicBool::new(false)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_command_is_killed_at_once_when_cancelled() {
        let cancelled = AtomicBool::new(false);
        let mut command = Command::new("sleep");
        command.arg("30");
        let started = Instant::now();
        let error = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(100));
                cancelled.store(true, Ordering::Release);
            });
            run_within(command, Duration::from_secs(30), &cancelled).unwrap_err()
        });
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}

use std::{
    io::{BufRead, BufReader},
    os::unix::process::ExitStatusExt,
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    sync::mpsc::{Receiver, SyncSender, TryRecvError, channel, sync_channel},
    thread,
    time::Duration,
};

use crate::{
    collect::{
        capture::{CaptureOrigin, CaptureSource, CaptureStatistics, PacketRead},
        pcap_stream::{PcapStream, StreamPacket},
    },
    command::system_command,
    privileges::give_up_everything,
    runtime::or_stop,
};

/// Packets waiting for the capture loop; when it is full `dumpcap` waits on its pipe.
const QUEUE_LENGTH: usize = 4096;

/// How long a stop waits for `dumpcap`'s last error line; one that has exited has closed
/// its error output, so only a program still running makes the wait run out.
const REASON_WAIT: Duration = Duration::from_millis(200);

/// The command that makes `dumpcap` write every interface's packets to its standard output
/// as a pcap stream with Linux cooked v2 link headers.
pub fn dumpcap_command() -> Command {
    let mut command = system_command("dumpcap");
    command.args([
        "-i",
        "any",
        "-y",
        "LINUX_SLL2",
        "-F",
        "pcap",
        "-p",
        "-q",
        "-w",
        "-",
    ]);
    command
}

/// Packets from a `dumpcap` child, read on a thread of its own so that a quiet network
/// never blocks the capture loop. Dropping the source stops the child.
pub struct DumpcapSource {
    child: Child,
    link_type: i32,
    packets: Receiver<Result<StreamPacket, Option<String>>>,
    stopped: Option<String>,
}

impl DumpcapSource {
    /// Starts `command` and waits for the stream's header, which `dumpcap` writes at once.
    pub fn new(mut command: Command) -> Result<Self, String> {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| stop_message(&format!("it could not be started: {error}")))?;
        let last_line = last_line_in_background(child.stderr.take());
        let header = child
            .stdout
            .take()
            .ok_or_else(|| "dumpcap gave no output pipe".to_owned())
            .and_then(PcapStream::new);
        let stream = match header {
            Ok(stream) => stream,
            Err(error) => {
                let _ = child.kill();
                let exit = child.wait().map(describe_exit).unwrap_or(error);
                return Err(stop_message(
                    &last_line.recv().ok().flatten().unwrap_or(exit),
                ));
            }
        };
        let link_type = stream.link_type();
        let (sender, packets) = sync_channel(QUEUE_LENGTH);
        thread::spawn(move || {
            // The thread that starts this one may have capabilities available.
            or_stop(give_up_everything());
            let Some(outcome) = forward_packets(stream, &sender) else {
                return;
            };
            let reason = last_line
                .recv_timeout(REASON_WAIT)
                .ok()
                .flatten()
                .or(outcome.err());
            let _ = sender.send(Err(reason));
        });
        Ok(Self {
            child,
            link_type,
            packets,
            stopped: None,
        })
    }
}

const STOPPED: &str = "capture through dumpcap has stopped: ";

fn stop_message(reason: &str) -> String {
    format!("{STOPPED}{reason}")
}

/// The reason in a message this module made for a stop, or `None` for any other message.
pub fn stopped_reason(message: &str) -> Option<&str> {
    message.strip_prefix(STOPPED)
}

fn describe_exit(status: ExitStatus) -> String {
    match (status.signal(), status.code()) {
        (Some(signal), _) => format!("it was ended by signal {signal}"),
        (None, Some(code)) => format!("it exited with status {code}"),
        (None, None) => "it ended".to_owned(),
    }
}

/// Sends the stream's packets until it ends. `None` when the receiver has gone, so there
/// is nobody to tell; otherwise `Ok` for a stream that ended cleanly and `Err` with why a
/// broken one could not be read.
fn forward_packets(
    mut stream: PcapStream<ChildStdout>,
    sender: &SyncSender<Result<StreamPacket, Option<String>>>,
) -> Option<Result<(), String>> {
    loop {
        match stream.next_packet() {
            Ok(Some(packet)) => sender.send(Ok(packet)).ok()?,
            Ok(None) => return Some(Ok(())),
            Err(error) => return Some(Err(error)),
        }
    }
}

/// The last line `dumpcap` wrote to its error output that is not one of its status lines,
/// which it writes there even when asked to be quiet.
/// Sent once, when the error output closes.
fn last_line_in_background(
    pipe: Option<impl std::io::Read + Send + 'static>,
) -> Receiver<Option<String>> {
    let (sender, line) = channel();
    thread::spawn(move || {
        // The thread that starts this one may have capabilities available.
        or_stop(give_up_everything());
        let last = pipe.and_then(|pipe| {
            BufReader::new(pipe)
                .lines()
                .map_while(Result::ok)
                .filter(|line| !is_status_line(line))
                .last()
        });
        let _ = sender.send(last);
    });
    line
}

fn is_status_line(line: &str) -> bool {
    let text = line.trim_start_matches(['\r', ' ', '\t']);
    text.trim().is_empty()
        || ["Capturing on", "File:", "Packets "]
            .iter()
            .any(|prefix| text.starts_with(prefix))
}

impl DumpcapSource {
    /// Records and returns the message for a stop: the reason given, or else how `dumpcap`
    /// ended. A stream given up on leaves nothing for the child to do, so it is ended.
    fn remember_stop(&mut self, reason: Option<String>) -> String {
        if reason.is_some() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let reason = reason.unwrap_or_else(|| match self.child.wait() {
            Ok(status) => describe_exit(status),
            Err(error) => format!("its exit could not be read: {error}"),
        });
        self.stopped.insert(stop_message(&reason)).clone()
    }
}

impl CaptureSource for DumpcapSource {
    fn link_type(&self) -> i32 {
        self.link_type
    }

    fn next_packet(&mut self) -> Result<PacketRead, String> {
        if let Some(message) = &self.stopped {
            return Err(message.clone());
        }
        match self.packets.try_recv() {
            Ok(Ok(packet)) => Ok(PacketRead::Packet {
                data: packet.data,
                captured_at: Some(packet.captured_at),
            }),
            Ok(Err(reason)) => Err(self.remember_stop(reason)),
            Err(TryRecvError::Empty) => Ok(PacketRead::Idle),
            Err(TryRecvError::Disconnected) => {
                Err(self.remember_stop(Some("its reader ended".to_owned())))
            }
        }
    }

    fn statistics(&mut self) -> Result<CaptureStatistics, String> {
        Ok(CaptureStatistics::default())
    }

    fn origin(&self) -> CaptureOrigin {
        CaptureOrigin::Dumpcap
    }
}

impl Drop for DumpcapSource {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    fn stream_bytes(packets: &[&[u8]]) -> Vec<u8> {
        let mut bytes = 0xa1b2_3c4du32.to_le_bytes().to_vec();
        bytes.extend([2, 0, 4, 0]);
        bytes.extend([0; 8]);
        bytes.extend(262_144u32.to_le_bytes());
        bytes.extend(276u32.to_le_bytes());
        for (index, packet) in packets.iter().enumerate() {
            bytes.extend((index as u32 + 1).to_le_bytes());
            bytes.extend(0u32.to_le_bytes());
            bytes.extend((packet.len() as u32).to_le_bytes());
            bytes.extend((packet.len() as u32).to_le_bytes());
            bytes.extend(*packet);
        }
        bytes
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("crosswalk-dumpcap-{name}-{}", std::process::id()))
    }

    /// A stand-in that runs `before`, writes `stream` to its output, then runs `after`.
    fn stand_in(name: &str, stream: &[u8], before: &str, after: &str) -> Command {
        let file = scratch(name);
        std::fs::write(&file, stream).unwrap();
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(format!("{before}; cat '{}'; {after}", file.display()));
        command
    }

    fn read_until_not_idle(source: &mut DumpcapSource) -> Result<PacketRead, String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match source.next_packet() {
                Ok(PacketRead::Idle) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5))
                }
                other => return other,
            }
        }
    }

    fn packet_data(read: Result<PacketRead, String>) -> Vec<u8> {
        match read.unwrap() {
            PacketRead::Packet { data, .. } => data,
            PacketRead::Idle => panic!("expected a packet"),
        }
    }

    #[test]
    fn packets_come_out_in_order_with_the_streams_link_type() {
        let stream = stream_bytes(&[b"first", b"second"]);
        let mut source =
            DumpcapSource::new(stand_in("order", &stream, "true", "sleep 30")).unwrap();
        assert_eq!(source.link_type(), 276);
        assert_eq!(packet_data(read_until_not_idle(&mut source)), b"first");
        assert_eq!(packet_data(read_until_not_idle(&mut source)), b"second");
    }

    #[test]
    fn with_nothing_waiting_the_source_is_idle_at_once() {
        let stream = stream_bytes(&[]);
        let mut source = DumpcapSource::new(stand_in("idle", &stream, "true", "sleep 30")).unwrap();
        let started = Instant::now();
        assert!(matches!(source.next_packet(), Ok(PacketRead::Idle)));
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn after_the_program_exits_the_source_errors_with_its_last_error_line_and_stays_so() {
        let stream = stream_bytes(&[b"only"]);
        let mut source = DumpcapSource::new(stand_in(
            "exits",
            &stream,
            "true",
            "echo first complaint >&2; echo no permission >&2",
        ))
        .unwrap();
        assert_eq!(packet_data(read_until_not_idle(&mut source)), b"only");
        let error = read_until_not_idle(&mut source).err().unwrap();
        assert!(
            error.contains("capture through dumpcap has stopped"),
            "{error}"
        );
        assert!(error.contains("no permission"), "{error}");
        assert!(!error.contains("first complaint"), "{error}");
        assert_eq!(source.next_packet().err(), Some(error));
    }

    fn stop_error(after: &str) -> String {
        let stream = stream_bytes(&[]);
        let mut source = DumpcapSource::new(stand_in("stops", &stream, "true", after)).unwrap();
        read_until_not_idle(&mut source).err().unwrap()
    }

    #[test]
    fn a_program_killed_after_only_status_lines_is_reported_as_ended_by_its_signal() {
        let error = stop_error("echo \"Capturing on 'any'\" >&2; echo 'File: -' >&2; kill -9 $$");
        assert!(
            error.starts_with("capture through dumpcap has stopped"),
            "{error}"
        );
        assert!(error.contains("signal 9"), "{error}");
        assert!(!error.contains("File: -"), "{error}");
    }

    #[test]
    fn a_program_that_exits_after_only_status_lines_is_reported_as_exited_with_its_status() {
        let error = stop_error(
            "printf '\\rPackets captured: 0\\n' >&2; \
             echo \"Packets received/dropped on interface 'any': 0/0 (0.0%)\" >&2",
        );
        assert!(
            error.starts_with("capture through dumpcap has stopped"),
            "{error}"
        );
        assert!(error.contains("exited with status 0"), "{error}");
        assert!(!error.contains("Packets"), "{error}");
    }

    #[test]
    fn a_real_error_line_followed_by_status_lines_is_the_reason() {
        let error = stop_error(
            "echo 'dumpcap: no such device' >&2; echo \"Capturing on 'any'\" >&2; \
             printf '\\rPackets captured: 0\\n' >&2; echo 'File: -' >&2",
        );
        assert!(error.contains("dumpcap: no such device"), "{error}");
    }

    #[test]
    fn a_stream_the_parser_rejects_is_reported_at_once_and_the_program_is_ended() {
        let mut stream = stream_bytes(&[]);
        stream.extend([1, 0, 0, 0, 0, 0, 0, 0]);
        stream.extend(u32::MAX.to_le_bytes());
        stream.extend(u32::MAX.to_le_bytes());
        let pid_file = scratch("reject-pid");
        let before = format!("echo $$ > '{}'", pid_file.display());
        let command = stand_in("reject", &stream, &before, "exec sleep 30");
        let mut source = DumpcapSource::new(command).unwrap();
        let pid = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .to_owned();
        let started = Instant::now();
        let error = read_until_not_idle(&mut source).err().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1), "{error}");
        assert!(
            error.contains("capture through dumpcap has stopped"),
            "{error}"
        );
        let gone = Instant::now() + Duration::from_secs(1);
        while Path::new(&format!("/proc/{pid}")).exists() && Instant::now() < gone {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[test]
    fn a_program_that_never_exits_is_gone_once_the_source_is_dropped() {
        let pid_file = scratch("pid");
        let before = format!("echo $$ > '{}'", pid_file.display());
        let command = stand_in("drop", &stream_bytes(&[]), &before, "exec sleep 30");
        let source = DumpcapSource::new(command).unwrap();
        let pid = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .to_owned();
        assert!(Path::new(&format!("/proc/{pid}")).exists());
        drop(source);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[test]
    fn a_program_that_cannot_be_started_is_an_error_from_the_constructor() {
        let error = DumpcapSource::new(Command::new("/nonexistent/crosswalk-dumpcap"))
            .err()
            .unwrap();
        assert!(
            error.contains("capture through dumpcap has stopped"),
            "{error}"
        );
    }

    /// A stand-in that runs `script` and exits without writing anything to its output;
    /// returns the command and the file holding its process id.
    fn fails_before_the_header(name: &str, script: &str) -> (Command, PathBuf) {
        let pid_file = scratch(name);
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(format!("echo $$ > '{}'; {script}", pid_file.display()));
        (command, pid_file)
    }

    fn is_running(pid_file: &Path) -> bool {
        let pid = std::fs::read_to_string(pid_file).unwrap();
        Path::new(&format!("/proc/{}", pid.trim())).exists()
    }

    #[test]
    fn a_program_that_fails_before_its_header_is_an_error_holding_its_error_line() {
        let (command, pid_file) = fails_before_the_header(
            "fails-line",
            "echo \"Capturing on 'any'\" >&2; echo 'File: -' >&2; \
             echo 'dumpcap: You do not have permission to capture' >&2; exit 1",
        );
        let error = DumpcapSource::new(command).err().unwrap();
        assert!(
            error.starts_with("capture through dumpcap has stopped"),
            "{error}"
        );
        assert!(error.contains("You do not have permission"), "{error}");
        assert!(!error.contains("Capturing on"), "{error}");
        assert!(!error.contains("File: -"), "{error}");
        assert!(!is_running(&pid_file));
    }

    #[test]
    fn a_program_that_fails_before_its_header_in_silence_is_reported_as_exited_with_its_status() {
        let (command, pid_file) = fails_before_the_header("fails-silent", "exit 3");
        let error = DumpcapSource::new(command).err().unwrap();
        assert!(
            error.starts_with("capture through dumpcap has stopped"),
            "{error}"
        );
        assert!(error.contains("exited with status 3"), "{error}");
        assert!(!is_running(&pid_file));
    }

    #[test]
    fn the_real_command_is_an_absolute_path_with_the_capture_arguments() {
        let command = dumpcap_command();
        assert!(Path::new(command.get_program()).is_absolute());
        let args: Vec<_> = command.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "-i",
                "any",
                "-y",
                "LINUX_SLL2",
                "-F",
                "pcap",
                "-p",
                "-q",
                "-w",
                "-"
            ]
        );
    }
}

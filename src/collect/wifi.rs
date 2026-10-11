use std::{
    io,
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use crate::command::{run_within, system_command};

/// `nmcli` reads NetworkManager's cache and answers in milliseconds; a hung
/// one holds up the metrics loop.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);

/// `nmcli`'s exit status for "NetworkManager is not running".
const EXIT_NOT_RUNNING: i32 = 8;
/// Its exit status for a device or access point that does not exist; with no
/// Wi-Fi device the message says "Wi-Fi device".
const EXIT_NOT_FOUND: i32 = 10;

/// `ssid`, `bssid` and `security` are external text, kept as `nmcli` reported
/// them apart from the terse-mode escapes; stripping and bounding are left to
/// the row builder. An open network has an empty `security` (`--` is read as
/// empty).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessPoint {
    pub ssid: Option<String>,
    pub bssid: String,
    pub signal: u8,
    pub channel: u16,
    pub frequency_mhz: u32,
    pub security: String,
    pub in_use: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WifiSnapshot {
    Available(Vec<AccessPoint>),
    Unavailable(String),
}

/// What `nmcli` did: its exit status (`None` when a signal ended it) and
/// what it printed.
pub struct NmcliOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// What NetworkManager said to a request for a scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanOutcome {
    Accepted,
    /// A short plain reason, at most 30 characters.
    Refused(String),
}

pub trait WifiSource {
    fn list(&mut self) -> io::Result<NmcliOutput>;
    /// `nmcli device wifi rescan`: the one command that makes the radio transmit.
    fn rescan(&mut self) -> io::Result<NmcliOutput>;
    /// `nmcli -t -f WIFI radio`: `enabled` or `disabled` when it succeeds.
    fn radio(&mut self) -> io::Result<NmcliOutput>;
}

pub struct WifiCollector<S> {
    source: S,
}

impl<S: WifiSource> WifiCollector<S> {
    pub fn new(source: S) -> Self {
        Self { source }
    }

    pub fn collect(&mut self) -> WifiSnapshot {
        match self.source.list() {
            Err(error) => WifiSnapshot::Unavailable(match error.kind() {
                io::ErrorKind::NotFound => "nmcli not found".to_owned(),
                io::ErrorKind::TimedOut => "nmcli timed out".to_owned(),
                _ => format!("nmcli: {error}"),
            }),
            Ok(output) => match output.exit_code {
                Some(0) => {
                    let points: Vec<_> = output.stdout.lines().filter_map(parse_line).collect();
                    // With the radio off `nmcli` lists nothing, which reads as
                    // no networks in range; ask only when the list is empty.
                    if points.is_empty() && self.radio_is_off() {
                        WifiSnapshot::Unavailable("Wi-Fi is switched off".to_owned())
                    } else {
                        WifiSnapshot::Available(points)
                    }
                }
                Some(EXIT_NOT_RUNNING) => {
                    WifiSnapshot::Unavailable("NetworkManager is not running".to_owned())
                }
                Some(EXIT_NOT_FOUND) if output.stderr.contains("Wi-Fi device") => {
                    WifiSnapshot::Unavailable("no Wi-Fi device".to_owned())
                }
                _ => WifiSnapshot::Unavailable(format!(
                    "nmcli: {}",
                    output.stderr.lines().next().unwrap_or("failed").trim()
                )),
            },
        }
    }
}

impl<S: WifiSource> WifiCollector<S> {
    /// Asks NetworkManager for a scan, which makes the radio transmit.
    pub fn request_scan(&mut self) -> ScanOutcome {
        let refused = |reason: &str| ScanOutcome::Refused(reason.to_owned());
        match self.source.rescan() {
            Err(error) => match error.kind() {
                io::ErrorKind::NotFound => refused("nmcli not found"),
                io::ErrorKind::TimedOut => refused("nmcli timed out"),
                _ => refused("nmcli failed"),
            },
            Ok(output) => match output.exit_code {
                Some(0) => ScanOutcome::Accepted,
                Some(EXIT_NOT_RUNNING) => refused("NetworkManager is not running"),
                _ => {
                    let text = output.stderr.to_lowercase();
                    if ["not authorized", "not authorised", "access denied"]
                        .iter()
                        .any(|words| text.contains(words))
                    {
                        refused("not authorised")
                    } else if text.contains("while unavailable") {
                        refused("Wi-Fi is unavailable")
                    } else if text.contains("scanning not allowed") {
                        refused("a scan was just done")
                    } else {
                        // Whatever `nmcli` said first; the pane bounds it.
                        let first = output.stderr.lines().next().unwrap_or("").trim();
                        let first = first.trim_start_matches("Error: ");
                        ScanOutcome::Refused(if first.is_empty() {
                            "nmcli failed".to_owned()
                        } else {
                            first.chars().take(30).collect()
                        })
                    }
                }
            },
        }
    }

    /// A radio query that fails is taken as "not known to be off".
    fn radio_is_off(&mut self) -> bool {
        matches!(
            self.source.radio(),
            Ok(NmcliOutput { exit_code: Some(0), stdout, .. }) if stdout.trim() == "disabled"
        )
    }
}

/// Runs `nmcli`, giving up at once when `cancelled` is set. The periodic read
/// passes `--rescan no`; only `rescan` asks for a scan.
pub struct NmcliCommand {
    cancelled: Arc<AtomicBool>,
}

impl NmcliCommand {
    pub fn new(cancelled: Arc<AtomicBool>) -> Self {
        Self { cancelled }
    }
}

impl NmcliCommand {
    fn run(&self, arguments: &[&str]) -> io::Result<NmcliOutput> {
        let command = nmcli_command(arguments);
        let (status, stdout, stderr) = run_within(command, COMMAND_TIMEOUT, &self.cancelled)?;
        // Lossy, so one odd byte in a network name spoils only its own entry.
        Ok(NmcliOutput {
            exit_code: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

impl WifiSource for NmcliCommand {
    fn list(&mut self) -> io::Result<NmcliOutput> {
        self.run(&nmcli_arguments())
    }

    fn rescan(&mut self) -> io::Result<NmcliOutput> {
        self.run(&nmcli_scan_arguments())
    }

    fn radio(&mut self) -> io::Result<NmcliOutput> {
        self.run(&["-t", "-f", "WIFI", "radio"])
    }
}

/// `nmcli` with `arguments`, in the C locale: its error text is translated
/// otherwise, and the no-device case is recognised by its English words.
pub fn nmcli_command(arguments: &[&str]) -> Command {
    let mut command = system_command("nmcli");
    command.args(arguments).env("LC_ALL", "C");
    command
}

/// The arguments to `nmcli`. `--rescan no` keeps Crosswalk from ever causing a
/// scan. The name is the last field: `nmcli` escapes only `:` and `\\`, so a
/// newline in a name splits the line, and what follows the newline then has
/// no unescaped colon and is dropped as malformed, where a name placed earlier
/// would let that text pose as the start of a row.
pub fn nmcli_arguments() -> [&'static str; 8] {
    [
        "-t",
        "-f",
        "IN-USE,BSSID,SIGNAL,CHAN,FREQ,SECURITY,SSID",
        "device",
        "wifi",
        "list",
        "--rescan",
        "no",
    ]
}

/// The arguments to `nmcli` that ask for a scan.
pub fn nmcli_scan_arguments() -> [&'static str; 3] {
    ["device", "wifi", "rescan"]
}

/// Splits a terse line on colons not escaped by a backslash and removes the
/// escapes. `None` for a line that is not seven fields or has a number that
/// is not one.
fn parse_line(line: &str) -> Option<AccessPoint> {
    let fields = split_terse(line);
    let [in_use, bssid, signal, channel, frequency, security, ssid] = fields.as_slice() else {
        return None;
    };
    let signal: u8 = signal.parse().ok().filter(|signal| *signal <= 100)?;
    Some(AccessPoint {
        ssid: (!ssid.is_empty()).then(|| ssid.clone()),
        bssid: bssid.clone(),
        signal,
        channel: channel.parse().ok()?,
        frequency_mhz: frequency.trim_end_matches("MHz").trim().parse().ok()?,
        security: if security == "--" {
            String::new()
        } else {
            security.clone()
        },
        in_use: in_use.trim() == "*",
    })
}

fn split_terse(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            ':' => fields.push(String::new()),
            '\\' => {
                if let Some(next) = chars.next() {
                    fields.last_mut().unwrap().push(next);
                }
            }
            c => fields.last_mut().unwrap().push(c),
        }
    }
    fields
}

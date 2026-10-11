use std::{
    io,
    net::IpAddr,
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use serde::Deserialize;
use serde_json::Value;

use crate::command::{run_within, system_command};

/// `ip` normally answers in milliseconds; a hung one holds up the metrics loop.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub address: IpAddr,
    pub mac: Option<String>,
    pub interface: String,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NeighborSnapshot {
    Available(Vec<Neighbor>),
    Unavailable(String),
}

pub trait NeighborSource {
    fn read_table(&mut self) -> io::Result<String>;
}

pub struct NeighborCollector<S> {
    source: S,
}

impl<S: NeighborSource> NeighborCollector<S> {
    pub fn new(source: S) -> Self {
        Self { source }
    }

    pub fn collect(&mut self) -> NeighborSnapshot {
        match self.source.read_table() {
            Ok(text) => parse(&text),
            // The pane bounds the reason to 30 characters, so no preamble.
            Err(error) => NeighborSnapshot::Unavailable(error.to_string()),
        }
    }
}

/// Runs `ip -json neigh show` under a short limit, giving up at once when
/// `cancelled` is set.
pub struct IpCommand {
    cancelled: Arc<AtomicBool>,
}

impl IpCommand {
    pub fn new(cancelled: Arc<AtomicBool>) -> Self {
        Self { cancelled }
    }
}

impl NeighborSource for IpCommand {
    fn read_table(&mut self) -> io::Result<String> {
        let mut command = system_command("ip");
        // The error text is shown in the pane; keep it untranslated.
        command.args(["-json", "neigh", "show"]).env("LC_ALL", "C");
        read_output(command, &self.cancelled)
    }
}

fn read_output(command: Command, cancelled: &AtomicBool) -> io::Result<String> {
    let (status, stdout, stderr) = run_within(command, COMMAND_TIMEOUT, cancelled)
        .map_err(|error| io::Error::new(error.kind(), format!("could not run `ip`: {error}")))?;
    if status.success() {
        // Lossy, so one odd byte spoils only the entry it is in.
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    } else {
        Err(io::Error::other(format!(
            "ip exited with {status}: {}",
            String::from_utf8_lossy(&stderr).trim()
        )))
    }
}

fn parse(text: &str) -> NeighborSnapshot {
    if text.trim().is_empty() {
        return NeighborSnapshot::Available(Vec::new());
    }
    match serde_json::from_str::<Vec<Value>>(text) {
        Ok(items) => NeighborSnapshot::Available(
            items
                .into_iter()
                .filter_map(|item| serde_json::from_value::<Entry>(item).ok())
                .filter_map(Entry::into_neighbor)
                .collect(),
        ),
        Err(error) => NeighborSnapshot::Unavailable(format!(
            "the neighbour table was not valid JSON: {error}"
        )),
    }
}

#[derive(Deserialize)]
struct Entry {
    dst: IpAddr,
    dev: String,
    lladdr: Option<String>,
    #[serde(default)]
    state: Vec<String>,
}

impl Entry {
    fn into_neighbor(self) -> Option<Neighbor> {
        let resolving = self
            .state
            .iter()
            .any(|state| matches!(state.as_str(), "INCOMPLETE" | "DELAY" | "PROBE"));
        if self.lladdr.is_none() && !resolving {
            return None;
        }
        // The kernel can name several states for one entry; the first is kept.
        let state = self
            .state
            .first()
            .map_or_else(|| "unknown".to_owned(), |state| state.to_ascii_lowercase());
        Some(Neighbor {
            address: self.dst,
            mac: self.lladdr,
            interface: self.dev,
            state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_that_cannot_start_names_ip() {
        let error = read_output(
            Command::new("crosswalk-no-such-command"),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(
            error.to_string().starts_with("could not run `ip`: "),
            "{error}"
        );
    }

    #[test]
    fn output_with_an_invalid_byte_is_still_read() {
        let mut command = Command::new("printf");
        command.arg(r"[\377]");
        let text = read_output(command, &AtomicBool::new(false)).unwrap();
        assert!(text.starts_with('[') && text.ends_with(']'), "{text}");
    }
}

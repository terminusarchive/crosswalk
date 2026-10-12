use std::{collections::HashSet, ops::RangeInclusive};

use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusctlOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplyError {
    Refused,
    Failed(String),
    Empty,
    Malformed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveZone {
    pub name: String,
    pub interfaces: Vec<String>,
    pub sources: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Default,
    Accept,
    Reject,
    Drop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortRule {
    pub ports: RangeInclusive<u16>,
    pub protocol: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneSettings {
    pub target: Target,
    pub services: Vec<String>,
    pub ports: Vec<PortRule>,
    pub rich_rules: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceSettings {
    pub ports: Vec<PortRule>,
    pub includes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogDenied {
    Off,
    On,
}

/// The zones that have interfaces or sources, by name.
pub fn active_zones(output: &BusctlOutput) -> Result<Vec<ActiveZone>, ReplyError> {
    let zones = read_object(output)?;
    zones
        .iter()
        .map(|(name, bindings)| {
            let bindings = expect_object(bindings)?;
            Ok(ActiveZone {
                name: name.clone(),
                interfaces: plain_strings(bindings.get("interfaces"))?,
                sources: plain_strings(bindings.get("sources"))?,
            })
        })
        .collect()
}

pub fn default_zone(output: &BusctlOutput) -> Result<String, ReplyError> {
    read_string(output)
}

/// The answer of the bus daemon's `NameHasOwner`, as JSON (`{"type":"b","data":[true]}`) or in
/// busctl's plain form (`b true`).
pub fn name_has_owner(output: &BusctlOutput) -> Result<bool, ReplyError> {
    if !output.success {
        return Err(classify_failure(&output.stderr));
    }
    let text = output.stdout.trim();
    if text.is_empty() {
        return Err(ReplyError::Empty);
    }
    let from_json = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|reply| reply["data"][0].as_bool());
    let from_plain = match text.strip_prefix("b ") {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    };
    from_json
        .or(from_plain)
        .ok_or_else(|| ReplyError::Malformed("no true or false in the answer".into()))
}

pub fn zone_settings(output: &BusctlOutput) -> Result<ZoneSettings, ReplyError> {
    let settings = read_settings(output)?;
    Ok(ZoneSettings {
        target: read_target(&settings)?,
        services: variant_strings(&settings, "services")?,
        ports: read_port_rules(&settings)?,
        rich_rules: variant_strings(&settings, "rules_str")?,
    })
}

pub fn service_settings(output: &BusctlOutput) -> Result<ServiceSettings, ReplyError> {
    let settings = read_settings(output)?;
    Ok(ServiceSettings {
        ports: read_port_rules(&settings)?,
        includes: variant_strings(&settings, "includes")?,
    })
}

pub fn log_denied(output: &BusctlOutput) -> Result<LogDenied, ReplyError> {
    match read_string(output)?.as_str() {
        "off" => Ok(LogDenied::Off),
        "all" | "unicast" | "broadcast" | "multicast" => Ok(LogDenied::On),
        other => Err(ReplyError::Malformed(format!(
            "unknown LogDenied value {other:?}"
        ))),
    }
}

/// The ports of a service and of the services it includes, each service once, so a loop of
/// includes ends.
pub fn service_ports(
    name: &str,
    mut lookup: impl FnMut(&str) -> Result<ServiceSettings, ReplyError>,
) -> Result<Vec<PortRule>, ReplyError> {
    let mut seen = HashSet::new();
    let mut ports = Vec::new();
    collect_ports(name, &mut lookup, &mut seen, &mut ports)?;
    Ok(ports)
}

fn collect_ports(
    name: &str,
    lookup: &mut impl FnMut(&str) -> Result<ServiceSettings, ReplyError>,
    seen: &mut HashSet<String>,
    ports: &mut Vec<PortRule>,
) -> Result<(), ReplyError> {
    if !seen.insert(name.to_owned()) {
        return Ok(());
    }
    let settings = lookup(name)?;
    ports.extend(settings.ports);
    settings
        .includes
        .iter()
        .try_for_each(|include| collect_ports(include, lookup, seen, ports))
}

/// The one value a successful call returned, with its D-Bus type, or why there is none.
fn read_payload(output: &BusctlOutput) -> Result<Payload, ReplyError> {
    if !output.success {
        return Err(classify_failure(&output.stderr));
    }
    if output.stdout.trim().is_empty() {
        return Err(ReplyError::Empty);
    }
    let mut reply: Value = serde_json::from_str(&output.stdout)
        .map_err(|error| ReplyError::Malformed(format!("not JSON: {error}")))?;
    let kind = reply["type"].as_str().unwrap_or_default().to_owned();
    match reply.get_mut("data").and_then(Value::as_array_mut) {
        Some(values) if values.len() == 1 => Ok(Payload {
            kind,
            value: values.remove(0),
        }),
        _ => Err(ReplyError::Malformed("no single value in \"data\"".into())),
    }
}

struct Payload {
    kind: String,
    value: Value,
}

fn classify_failure(stderr: &str) -> ReplyError {
    let text = stderr.trim();
    if text.contains("Not Authorized") {
        return ReplyError::Refused;
    }
    ReplyError::Failed(text.to_owned())
}

fn read_string(output: &BusctlOutput) -> Result<String, ReplyError> {
    match read_payload(output)?.value {
        Value::String(text) => Ok(text),
        other => Err(ReplyError::Malformed(format!(
            "expected a string, got {other}"
        ))),
    }
}

fn read_object(output: &BusctlOutput) -> Result<Map<String, Value>, ReplyError> {
    match read_payload(output)?.value {
        Value::Object(map) => Ok(map),
        other => Err(ReplyError::Malformed(format!(
            "expected an object, got {other}"
        ))),
    }
}

/// The settings of a zone or a service: an `a{sv}` map, never another kind of answer.
fn read_settings(output: &BusctlOutput) -> Result<Map<String, Value>, ReplyError> {
    let Payload { kind, value } = read_payload(output)?;
    match value {
        Value::Object(map) if kind == "a{sv}" => Ok(map),
        other => Err(ReplyError::Malformed(format!(
            "expected settings of type a{{sv}}, got {kind} {other}"
        ))),
    }
}

fn expect_object(value: &Value) -> Result<&Map<String, Value>, ReplyError> {
    value
        .as_object()
        .ok_or_else(|| ReplyError::Malformed(format!("expected an object, got {value}")))
}

fn plain_strings(value: Option<&Value>) -> Result<Vec<String>, ReplyError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let list = value
        .as_array()
        .ok_or_else(|| ReplyError::Malformed(format!("expected a list, got {value}")))?;
    list.iter().map(as_text).collect()
}

fn as_text(value: &Value) -> Result<String, ReplyError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ReplyError::Malformed(format!("expected text, got {value}")))
}

/// The list inside a `{"type", "data"}` entry; an entry the answer leaves out is an empty list.
fn variant_list<'a>(
    settings: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], ReplyError> {
    let Some(entry) = settings.get(key) else {
        return Ok(&[]);
    };
    entry
        .get("data")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| ReplyError::Malformed(format!("{key} has no list")))
}

fn variant_strings(settings: &Map<String, Value>, key: &str) -> Result<Vec<String>, ReplyError> {
    variant_list(settings, key)?.iter().map(as_text).collect()
}

fn read_target(settings: &Map<String, Value>) -> Result<Target, ReplyError> {
    let entry = settings
        .get("target")
        .ok_or_else(|| ReplyError::Malformed("settings have no target".into()))?;
    match entry.get("data").and_then(Value::as_str) {
        Some("default") => Ok(Target::Default),
        Some("ACCEPT") => Ok(Target::Accept),
        Some("REJECT" | "%%REJECT%%") => Ok(Target::Reject),
        Some("DROP") => Ok(Target::Drop),
        _ => Err(ReplyError::Malformed(format!("unknown target {entry}"))),
    }
}

fn read_port_rules(settings: &Map<String, Value>) -> Result<Vec<PortRule>, ReplyError> {
    variant_list(settings, "ports")?
        .iter()
        .map(port_rule)
        .collect()
}

fn port_rule(pair: &Value) -> Result<PortRule, ReplyError> {
    let [ports, protocol] = plain_strings(Some(pair))?.try_into().map_err(|_| {
        ReplyError::Malformed(format!("expected a port and a protocol, got {pair}"))
    })?;
    Ok(PortRule {
        ports: port_range(&ports)?,
        protocol,
    })
}

fn port_range(text: &str) -> Result<RangeInclusive<u16>, ReplyError> {
    let (first, last) = text.split_once('-').unwrap_or((text, text));
    let number = |part: &str| part.parse::<u16>().ok();
    match (number(first), number(last)) {
        (Some(first), Some(last)) if first <= last => Ok(first..=last),
        _ => Err(ReplyError::Malformed(format!(
            "{text:?} is not a port or a range of ports"
        ))),
    }
}

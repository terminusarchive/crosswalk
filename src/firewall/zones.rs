use std::net::IpAddr;

use crate::collect::{attribution::Listener, capture::Protocol};

use super::{
    Exposure,
    firewalld_reply::{PortRule, Target},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zones {
    pub default_zone: String,
    pub zones: Vec<Zone>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    pub name: String,
    pub interfaces: Vec<String>,
    pub sources: Vec<String>,
    pub target: Target,
    pub allowed: Vec<Allowed>,
    pub rich_rules: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Allowed {
    Service { name: String, ports: Vec<PortRule> },
    Port(PortRule),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceAddresses {
    pub name: String,
    pub up: bool,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RichAction {
    Accept,
    Reject,
    Drop,
}

/// Why an exposure cannot be judged; the dashboard matches these strings.
pub const NO_INTERFACE_READING: &str = "interfaces unknown";
pub const NO_USABLE_INTERFACE: &str = "no usable interface";
pub const NO_DEFAULT_ZONE: &str = "default zone unknown";

impl Zones {
    /// AC6: what the zones of the interfaces `listener` listens on, and the zones bound to source
    /// networks, let in. A rich rule is never read beyond its action, so it can only limit a port.
    /// `interfaces` is `None` when they have not been read; that is unknown, never blocked.
    pub fn exposure(
        &self,
        listener: &Listener,
        interfaces: Option<&[InterfaceAddresses]>,
    ) -> Exposure {
        let Some(interfaces) = interfaces else {
            return Exposure::Unknown(NO_INTERFACE_READING.to_owned());
        };
        let reached = reached_interfaces(interfaces, listener);
        if reached.is_empty() {
            return Exposure::Unknown(NO_USABLE_INTERFACE.to_owned());
        }
        let Some(reached) = reached
            .iter()
            .map(|interface| self.zone_of(&interface.name))
            .collect::<Option<Vec<&Zone>>>()
        else {
            return Exposure::Unknown(NO_DEFAULT_ZONE.to_owned());
        };
        let sourced: Vec<&Zone> = self
            .zones
            .iter()
            .filter(|zone| !zone.sources.is_empty())
            .collect();
        let letting_in = reached.iter().filter(|zone| zone.lets_in(listener)).count();
        let by_source = sourced.iter().any(|zone| zone.lets_in(listener));
        if letting_in == 0 {
            let by_rich_rule = reached
                .iter()
                .chain(&sourced)
                .any(|zone| zone.has_rich(|action| action == RichAction::Accept));
            return if by_source || by_rich_rule {
                Exposure::Limited(None)
            } else {
                Exposure::Blocked(None)
            };
        }
        let sources_refuse = sourced.iter().any(|zone| !zone.lets_in(listener));
        let rich_refuses = reached
            .iter()
            .chain(&sourced)
            .filter(|zone| zone.lets_in(listener))
            .any(|zone| zone.has_rich(rejects));
        if letting_in == reached.len() && !sources_refuse && !rich_refuses {
            Exposure::Open(None)
        } else {
            Exposure::Limited(None)
        }
    }

    /// The zone an interface is bound to, or the default zone when no listed zone holds it;
    /// `None` when that is the default zone and firewalld did not return it.
    fn zone_of(&self, interface: &str) -> Option<&Zone> {
        self.zones
            .iter()
            .find(|zone| zone.interfaces.iter().any(|bound| bound == interface))
            .or_else(|| {
                self.zones
                    .iter()
                    .find(|zone| zone.name == self.default_zone)
            })
    }
}

fn rejects(action: RichAction) -> bool {
    action != RichAction::Accept
}

/// The interfaces traffic for `listener` can arrive on. Only interfaces that are up, hold an
/// address (a socket is reached through one) and are not loopback count. A bind to an address
/// among them arrives on the interfaces holding it; a wildcard, or an address none of them
/// holds (a multicast group, a broadcast address, one added since the reading), arrives on all.
fn reached_interfaces<'a>(
    interfaces: &'a [InterfaceAddresses],
    listener: &Listener,
) -> Vec<&'a InterfaceAddresses> {
    let candidates: Vec<&InterfaceAddresses> = interfaces
        .iter()
        .filter(|interface| {
            interface.up
                && !interface.addresses.is_empty()
                && !interface.addresses.iter().any(IpAddr::is_loopback)
        })
        .collect();
    let address = listener.address.to_canonical();
    let holders: Vec<&InterfaceAddresses> = candidates
        .iter()
        .copied()
        .filter(|interface| {
            interface
                .addresses
                .iter()
                .any(|held| held.to_canonical() == address)
        })
        .collect();
    if address.is_unspecified() || holders.is_empty() {
        candidates
    } else {
        holders
    }
}

impl Zone {
    fn lets_in(&self, listener: &Listener) -> bool {
        self.target == Target::Accept || self.allowed.iter().any(|allowed| allowed.covers(listener))
    }

    fn has_rich(&self, wanted: impl Fn(RichAction) -> bool) -> bool {
        self.rich_rules
            .iter()
            .filter_map(|rule| rich_action(rule))
            .any(wanted)
    }
}

impl Allowed {
    fn covers(&self, listener: &Listener) -> bool {
        match self {
            Allowed::Service { ports, .. } => ports.iter().any(|rule| rule.covers(listener)),
            Allowed::Port(rule) => rule.covers(listener),
        }
    }
}

impl PortRule {
    fn covers(&self, listener: &Listener) -> bool {
        self.ports.contains(&listener.port) && self.protocol == protocol_name(listener.protocol)
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Other(132) => "sctp",
        Protocol::Other(33) => "dccp",
        Protocol::Other(_) => "",
    }
}

/// The action word of a rich rule, read outside its quoted values.
fn rich_action(rule: &str) -> Option<RichAction> {
    rule.split('"')
        .step_by(2)
        .flat_map(str::split_whitespace)
        .find_map(|word| match word {
            "accept" => Some(RichAction::Accept),
            "reject" => Some(RichAction::Reject),
            "drop" => Some(RichAction::Drop),
            _ => None,
        })
}

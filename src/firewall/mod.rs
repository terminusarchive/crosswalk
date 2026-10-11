use std::{
    io,
    net::IpAddr,
    ops::RangeInclusive,
    sync::{atomic::AtomicBool, mpsc::SyncSender},
};

use crate::{
    collect::{
        attribution::{Listener, ProcessIdentity},
        capture::{Direction, Protocol},
    },
    config::{Config, FirewallProvider as ConfiguredProvider, UfwSource},
};

mod ufw;

pub use ufw::{
    FileInput, FirewallInput, InputRead, JournalInput, JournalProcess, LineReader, UfwProvider,
    checked_ufw_health, create_with_conf,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallOutcome {
    Blocked,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FirewallEndpoint {
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallEvent {
    pub timestamp: Option<String>,
    pub direction: Option<Direction>,
    pub interface: Option<String>,
    pub protocol: Option<Protocol>,
    pub source: FirewallEndpoint,
    pub destination: FirewallEndpoint,
    pub process: Option<ProcessIdentity>,
    pub outcome: FirewallOutcome,
}

impl FirewallEvent {
    pub fn blocked_unknown() -> Self {
        Self {
            timestamp: None,
            direction: None,
            interface: None,
            protocol: None,
            source: FirewallEndpoint::default(),
            destination: FirewallEndpoint::default(),
            process: None,
            outcome: FirewallOutcome::Blocked,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirewallHealth {
    AwaitingEvents,
    Available,
    Disabled(String),
    Unavailable(String),
    Degraded(String),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallStatus {
    pub health: FirewallHealth,
    pub records_read: u64,
    pub events_emitted: u64,
    pub malformed_records: u64,
    pub delivery_dropped: u64,
}

pub trait FirewallProvider: Send {
    fn poll(
        &mut self,
        sender: &SyncSender<FirewallEvent>,
        cancelled: &AtomicBool,
    ) -> FirewallStatus;

    /// The current rules, read fresh on every call.
    fn rules(&mut self) -> RuleSnapshot;

    fn status(&self) -> FirewallStatus;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Limit,
    Deny,
    Reject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleDirection {
    In,
    Out,
}

/// A default policy for a direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Allow,
    Deny,
    Reject,
}

impl Policy {
    pub fn label(self) -> &'static str {
        match self {
            Policy::Allow => "allow",
            Policy::Deny => "deny",
            Policy::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleSource {
    Anywhere,
    /// An address or network, or another restriction, as display text.
    Specific(String),
}

/// An address with a prefix length, as in `10.0.1.0/24`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    pub address: IpAddr,
    pub prefix: u8,
}

impl Network {
    pub fn contains(&self, other: IpAddr) -> bool {
        fn bits(address: IpAddr) -> (u128, u32) {
            match address {
                IpAddr::V4(a) => (u32::from(a) as u128, 32),
                IpAddr::V6(a) => (u128::from(a), 128),
            }
        }
        let (network, width) = bits(self.address);
        let (candidate, other_width) = bits(other);
        if width != other_width || u32::from(self.prefix) > width {
            return false;
        }
        let shift = width - u32::from(self.prefix);
        shift == 128 || network >> shift == candidate >> shift
    }
}

/// One UFW rule in provider-independent form.
///
/// `destination`, `ports` and `source` keep the tuple's meaning in both directions: ports and
/// destination are the rule's destination side. For an `In` rule the remote end is `source`;
/// for an `Out` rule it is `destination`, with `ports` the remote port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub direction: RuleDirection,
    pub action: RuleAction,
    /// `None` means any protocol.
    pub protocol: Option<Protocol>,
    /// Destination ports; empty means any port.
    pub ports: Vec<RangeInclusive<u16>>,
    /// `None` means any destination address.
    pub destination: Option<Network>,
    pub source: RuleSource,
    pub interface: Option<String>,
    /// True for a rule from the IPv6 rule file.
    pub ipv6: bool,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleSnapshot {
    Unavailable(String),
    Inactive,
    Active {
        default_incoming: Policy,
        default_outgoing: Policy,
        rules: Vec<Rule>,
    },
}

/// Each variant that was decided by a rule carries that rule's text, when there is one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exposure {
    Open(Option<String>),
    Limited(Option<String>),
    Blocked(Option<String>),
    Local,
    Unknown(String),
}

impl Rule {
    fn covers(&self, listener: &Listener) -> bool {
        let protocol_matches = match self.protocol {
            None => true,
            Some(protocol) => protocol == listener.protocol,
        };
        protocol_matches
            && self.ipv6 == listener.address.is_ipv6()
            && (self.ports.is_empty() || self.ports.iter().any(|r| r.contains(&listener.port)))
    }

    /// Whether the rule applies to every address the listener receives on.
    fn covers_whole_bind(&self, listener: &Listener) -> bool {
        match self.destination {
            None => true,
            Some(network) => {
                !listener.address.is_unspecified() && network.contains(listener.address)
            }
        }
    }

    fn reaches_bind(&self, listener: &Listener) -> bool {
        match self.destination {
            None => true,
            Some(network) => {
                listener.address.is_unspecified() || network.contains(listener.address)
            }
        }
    }
}

pub fn exposure(listener: &Listener, snapshot: &RuleSnapshot) -> Exposure {
    if listener.address.is_loopback() {
        return Exposure::Local;
    }
    let (default_incoming, rules) = match snapshot {
        RuleSnapshot::Unavailable(reason) => return Exposure::Unknown(reason.clone()),
        RuleSnapshot::Inactive => return Exposure::Unknown("ufw off".to_owned()),
        RuleSnapshot::Active {
            default_incoming,
            rules,
            ..
        } => (*default_incoming, rules),
    };
    let mut limited: Option<String> = None;
    for rule in rules
        .iter()
        .filter(|rule| rule.direction == RuleDirection::In)
        .filter(|rule| rule.covers(listener) && rule.reaches_bind(listener))
    {
        let anywhere = rule.source == RuleSource::Anywhere
            && rule.interface.is_none()
            && rule.covers_whole_bind(listener);
        match rule.action {
            RuleAction::Deny | RuleAction::Reject if anywhere => {
                return Exposure::Blocked(Some(rule.text.clone()));
            }
            RuleAction::Allow if anywhere => return Exposure::Open(Some(rule.text.clone())),
            RuleAction::Deny | RuleAction::Reject => {}
            _ => {
                limited.get_or_insert_with(|| rule.text.clone());
            }
        }
    }
    match limited {
        // Anyone can reach the port when the default allows it.
        _ if default_incoming == Policy::Allow => Exposure::Open(None),
        Some(text) => Exposure::Limited(Some(text)),
        None => Exposure::Blocked(None),
    }
}

pub fn create_provider(config: &Config) -> Box<dyn FirewallProvider> {
    match config.firewall_provider {
        ConfiguredProvider::Ufw => ufw::create(&config.ufw_source),
    }
}

fn unavailable(message: impl Into<String>) -> FirewallHealth {
    FirewallHealth::Unavailable(message.into())
}

fn input_for_source(source: &UfwSource) -> io::Result<Box<dyn FirewallInput>> {
    match source {
        UfwSource::Journal => ufw::CommandJournalProcess::spawn()
            .map(JournalInput::new)
            .map(|input| Box::new(input) as Box<dyn FirewallInput>),
        UfwSource::File(path) => {
            FileInput::open(path).map(|input| Box::new(input) as Box<dyn FirewallInput>)
        }
    }
}

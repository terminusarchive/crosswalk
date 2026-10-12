use std::{
    io,
    net::IpAddr,
    ops::RangeInclusive,
    path::Path,
    sync::{Arc, atomic::AtomicBool, mpsc::SyncSender},
};

use firewalld_reply::ActiveZone;

use crate::{
    collect::{
        attribution::Listener,
        capture::{Direction, Protocol},
    },
    command::{SYSTEM_DIRECTORIES, find_program_in},
    config::{Config, FirewallProvider as ConfiguredProvider, UfwSource},
};

mod firewalld;
pub mod firewalld_reply;
mod none;
mod ufw;
mod zones;

pub use firewalld::{BlockSource, FirewalldProvider};
pub use ufw::{
    BlockMarker, BlockReader, FileInput, FirewallInput, InputRead, JournalInput, JournalProcess,
    LineReader, UfwProvider, checked_ufw_health, create_with_conf,
};
pub use zones::{
    Allowed, InterfaceAddresses, NO_DEFAULT_ZONE, NO_INTERFACE_READING, NO_USABLE_INTERFACE, Zone,
    Zones,
};

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
    /// No supported firewall is in use; nothing is read.
    NoFirewall,
    /// firewalld is not logging denied packets, which is how it is installed: not a fault.
    NotLogging,
    /// firewalld would not say whether it logs denied packets to this user: blocks show if it does.
    DependsOnLogging,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallStatus {
    /// The firewall in use, as the header names it: `ufw` or `none`.
    pub name: &'static str,
    pub health: FirewallHealth,
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
    /// No supported firewall is in use.
    NoFirewall,
    /// firewalld's active zones, with each service's ports resolved.
    Zones(Zones),
    /// firewalld is running but shows this user only its active zones and what they apply to.
    ZonesOnly(Vec<ActiveZone>),
    /// firewalld is not running.
    FirewalldOff,
    Active {
        default_incoming: Policy,
        default_outgoing: Policy,
        rules: Vec<Rule>,
    },
}

/// Each variant that was decided by a rule carries that rule's text, when there is one.
/// Why the exposure of a port is unknown when firewalld is not running, and when it shows this
/// user only its zones; the dashboard matches these strings.
pub const FIREWALLD_OFF: &str = "fwd off";
pub const NOT_READABLE: &str = "not readable";

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

pub fn exposure(
    listener: &Listener,
    snapshot: &RuleSnapshot,
    interfaces: Option<&[InterfaceAddresses]>,
) -> Exposure {
    if listener.address.to_canonical().is_loopback() {
        return Exposure::Local;
    }
    let (default_incoming, rules) = match snapshot {
        RuleSnapshot::Unavailable(reason) => return Exposure::Unknown(reason.clone()),
        RuleSnapshot::Inactive => return Exposure::Unknown("ufw off".to_owned()),
        RuleSnapshot::NoFirewall => return Exposure::Unknown("no firewall".to_owned()),
        RuleSnapshot::FirewalldOff => return Exposure::Unknown(FIREWALLD_OFF.to_owned()),
        RuleSnapshot::ZonesOnly(_) => return Exposure::Unknown(NOT_READABLE.to_owned()),
        RuleSnapshot::Zones(zones) => return zones.exposure(listener, interfaces),
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

/// Whether firewalld is running, as far as the bus could say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Running {
    Yes,
    No,
    /// The question failed or timed out.
    Unknown,
}

/// What `auto` can see of the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub firewalld_running: Running,
    pub firewalld_installed: bool,
    pub ufw_enabled: bool,
    pub ufw_installed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Firewalld,
    Ufw,
    None,
}

/// The firewall `auto` reads: firewalld when it is running; otherwise UFW when it is enabled;
/// otherwise whichever is installed, UFW's if both; otherwise none. When the bus could not say
/// whether firewalld runs, an enabled UFW is chosen; otherwise firewalld where it is installed,
/// so that its failure shows, and else as if it were not running.
pub fn choose(facts: Facts) -> Choice {
    let installed = facts.firewalld_installed;
    match facts.firewalld_running {
        Running::Yes => return Choice::Firewalld,
        Running::Unknown if installed && !facts.ufw_enabled => return Choice::Firewalld,
        Running::Unknown | Running::No => {}
    }
    if facts.ufw_enabled || facts.ufw_installed {
        return Choice::Ufw;
    }
    if installed {
        return Choice::Firewalld;
    }
    Choice::None
}

/// Whether a firewalld program is in one of `directories`. The directory firewalld keeps its
/// files in is not looked at: it can exist without firewalld.
fn firewalld_installed(directories: &[&Path]) -> bool {
    ["firewalld", "firewall-cmd"]
        .iter()
        .any(|name| find_program_in(name, directories).is_some())
}

/// Reads the four facts. A `ufw.conf` that exists and cannot be read is UFW installed, and not
/// enabled: UFW's provider reports the unreadable file itself.
fn read_facts(ufw_conf: &Path, firewalld: &FirewalldProvider, directories: &[&Path]) -> Facts {
    let running = match firewalld.is_running() {
        Ok(true) => Running::Yes,
        Ok(false) => Running::No,
        Err(_) => Running::Unknown,
    };
    Facts {
        firewalld_running: running,
        firewalld_installed: firewalld_installed(directories),
        ufw_enabled: ufw::enabled(ufw_conf).unwrap_or(false),
        ufw_installed: ufw_conf.exists(),
    }
}

/// The provider for the machine, chosen once at startup. A quit sets `cancelled` and ends any
/// call to firewalld at once.
pub fn create_provider(config: &Config, cancelled: Arc<AtomicBool>) -> Box<dyn FirewallProvider> {
    create_provider_with(
        config,
        Path::new(ufw::UFW_CONF),
        FirewalldProvider::new(cancelled),
        &SYSTEM_DIRECTORIES.map(Path::new),
    )
}

/// Builds the provider the configuration asks for, reading UFW's settings from `ufw_conf`,
/// firewalld through `firewalld`, and looking for firewalld's programs in `directories`.
pub fn create_provider_with(
    config: &Config,
    ufw_conf: &Path,
    firewalld: FirewalldProvider,
    directories: &[&Path],
) -> Box<dyn FirewallProvider> {
    let choice = match config.firewall_provider {
        ConfiguredProvider::Ufw => Choice::Ufw,
        ConfiguredProvider::Firewalld => Choice::Firewalld,
        ConfiguredProvider::None => Choice::None,
        ConfiguredProvider::Auto => choose(read_facts(ufw_conf, &firewalld, directories)),
    };
    match choice {
        Choice::Ufw => ufw::create_with_conf(&config.ufw_source, ufw_conf),
        Choice::Firewalld => Box::new(firewalld),
        Choice::None => Box::new(none::NoFirewallProvider),
    }
}

fn unavailable(message: impl Into<String>) -> FirewallHealth {
    FirewallHealth::Unavailable(message.into())
}

fn input_for_source(source: &UfwSource) -> io::Result<Box<dyn FirewallInput>> {
    match source {
        UfwSource::Journal => ufw::journal_input(),
        UfwSource::File(path) => {
            FileInput::open(path).map(|input| Box::new(input) as Box<dyn FirewallInput>)
        }
    }
}

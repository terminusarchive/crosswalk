use std::sync::{atomic::AtomicBool, mpsc::SyncSender};

use super::{FirewallEvent, FirewallHealth, FirewallProvider, FirewallStatus, RuleSnapshot};

/// The provider for a machine with no supported firewall: it reads nothing and sends nothing.
pub(super) struct NoFirewallProvider;

impl FirewallProvider for NoFirewallProvider {
    fn poll(&mut self, _: &SyncSender<FirewallEvent>, _: &AtomicBool) -> FirewallStatus {
        self.status()
    }

    fn rules(&mut self) -> RuleSnapshot {
        RuleSnapshot::NoFirewall
    }

    fn status(&self) -> FirewallStatus {
        FirewallStatus {
            name: "none",
            health: FirewallHealth::NoFirewall,
        }
    }
}

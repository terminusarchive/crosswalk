use super::{
    Theme, bound_text,
    table::{Align, Column, Row, cut_middle},
    whole_text,
};
use crate::firewall::{
    Allowed, RuleSnapshot, Zone,
    firewalld_reply::{PortRule, Target},
};

/// The most of a rich rule that is kept, cut in the middle so its action stays; the table cuts
/// it again to the pane.
const RICH_RULE_MAX: usize = 400;

const INDENT: &str = "  ";

/// Whether Firewall Rules draws groups of zones, not UFW's rules, for this snapshot.
pub fn shows_zones(snapshot: &RuleSnapshot) -> bool {
    matches!(
        snapshot,
        RuleSnapshot::Zones(_) | RuleSnapshot::ZonesOnly(_) | RuleSnapshot::FirewalldOff
    )
}

/// One column, a line of text for each row: a group has no cells to line up. A line too long
/// for the pane is cut in the middle, so a rich rule keeps its start and its action.
pub fn zone_columns() -> Vec<Column> {
    vec![
        Column::new("ZONES", Align::Left, 12, 1)
            .fill(1)
            .cut_from_middle(),
    ]
}

/// A heading for each zone that applies to something, then its rows. With only the active zones
/// to go on, the headings alone.
pub fn zone_rows(snapshot: &RuleSnapshot, theme: &Theme) -> Vec<Row> {
    match snapshot {
        RuleSnapshot::Zones(zones) => zones
            .zones
            .iter()
            .filter(|zone| !zone.interfaces.is_empty() || !zone.sources.is_empty())
            .flat_map(|zone| zone_group(zone, theme))
            .collect(),
        RuleSnapshot::ZonesOnly(active) => active
            .iter()
            .map(|zone| heading(&zone.name, &zone.interfaces, &zone.sources, None, theme))
            .collect(),
        RuleSnapshot::Unavailable(_)
        | RuleSnapshot::Inactive
        | RuleSnapshot::NoFirewall
        | RuleSnapshot::FirewalldOff
        | RuleSnapshot::Active { .. } => Vec::new(),
    }
}

fn zone_group(zone: &Zone, theme: &Theme) -> Vec<Row> {
    let mut rows = vec![heading(
        &zone.name,
        &zone.interfaces,
        &zone.sources,
        Some(zone.target),
        theme,
    )];
    if zone.target == Target::Accept {
        rows.push(Row::new([format!("{INDENT}everything is allowed")]).style(theme.warning()));
    }
    rows.extend(zone.allowed.iter().map(allowed_row));
    rows.extend(
        zone.rich_rules
            .iter()
            .map(|rule| line(format!("rich {}", rich_rule_text(rule)))),
    );
    rows
}

fn heading(
    name: &str,
    interfaces: &[String],
    sources: &[String],
    target: Option<Target>,
    theme: &Theme,
) -> Row {
    let applies_to = interfaces
        .iter()
        .chain(sources)
        .map(|bound| bound_text(bound))
        .collect::<Vec<_>>()
        .join(", ");
    let default = target.map(|target| format!("default {}", target_text(target)));
    let text = [Some(bound_text(name)), Some(applies_to), default]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    Row::new([text]).style(theme.heading())
}

fn target_text(target: Target) -> &'static str {
    match target {
        Target::Default | Target::Reject => "reject",
        Target::Accept => "accept",
        Target::Drop => "drop",
    }
}

fn allowed_row(allowed: &Allowed) -> Row {
    match allowed {
        Allowed::Service { name, ports } => {
            let ports = ports.iter().map(port_text).collect::<Vec<_>>().join(", ");
            line(
                format!("{} {ports}", bound_text(name))
                    .trim_end()
                    .to_owned(),
            )
        }
        Allowed::Port(rule) => line(format!("port {}", port_text(rule))),
    }
}

fn port_text(rule: &PortRule) -> String {
    let range = if rule.ports.start() == rule.ports.end() {
        rule.ports.start().to_string()
    } else {
        format!("{}-{}", rule.ports.start(), rule.ports.end())
    };
    format!("{range}/{}", bound_text(&rule.protocol))
}

fn rich_rule_text(rule: &str) -> String {
    cut_middle(&whole_text(rule), RICH_RULE_MAX)
}

fn line(text: String) -> Row {
    Row::new([format!("{INDENT}{text}")])
}

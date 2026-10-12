# firewalld answers recorded from a real firewalld

Recorded 2026-10-12 from firewalld 2.4.4 on Fedora 44 (Cloud image with firewalld and polkit installed),
in a virtual machine. They hold nothing of any person's: the zones, sources and rules were made up for
the recording. Each `NAME.json` is the exact stdout of the command below; `NAME.json.stderr` is the exact
stderr and `NAME.json.exit` the exit status of the same command.

`B` stands for `busctl --system --json=short call org.fedoraproject.FirewallD1 /org/fedoraproject/FirewallD1`,
`Z` for `B org.fedoraproject.FirewallD1.zone` and `R` for `org.fedoraproject.FirewallD1`.
Run as root (`sudo` in the VM) unless the name starts with `plain-`, which ran as an ordinary user in no groups.

| file | command | state |
| --- | --- | --- |
| `active-zones` | `Z getActiveZones` | root; public on enp0s2, trusted, drop and home each bound to a source network |
| `default-zone` | `B R getDefaultZone` | root |
| `zone-public` | `Z getZoneSettings2 s public` | stock zone plus service http, ports 8080/tcp and 5000-5010/udp, three rich rules |
| `zone-trusted` | `Z getZoneSettings2 s trusted` | target ACCEPT, bound to a source network |
| `zone-drop` | `Z getZoneSettings2 s drop` | target DROP, bound to a source network |
| `zone-home` | `Z getZoneSettings2 s home` | target default, no ports, bound to a source network |
| `service-samba` | `B R getServiceSettings2 s samba` | two ports and an include (`samba-client`) |
| `service-ssh` | `B R getServiceSettings2 s ssh` | one port, no includes |
| `log-denied-all` | `B R getLogDenied` | root; `LogDenied=all` |
| `log-denied-off` | `B R getLogDenied` | root; after `firewall-cmd --set-log-denied=off` |
| `zone-unknown` | `Z getZoneSettings2 s nosuchzone` | root; a failure that is not a refusal (exit 1, `INVALID_ZONE`) |
| `plain-server-*` | `getActiveZones`, `getDefaultZone` (answered), `getZoneSettings2 s public`, `getServiceSettings2 s ssh`, `getLogDenied` (refused) | ordinary user, polkit server policy |
| `plain-desktop-*` | `getZoneSettings2 s public`, `getServiceSettings2 s samba`, `getLogDenied` | ordinary user, polkit desktop policy (symlink `/usr/share/polkit-1/actions/org.fedoraproject.FirewallD1.policy` pointed at `...desktop.policy.choice`, put back afterwards) |

`--set-log-denied` reloads firewalld, so runtime-only changes made before it were lost; the files named
above were each recorded in the state their row describes, and may differ from one another in which source
networks were bound at that moment (`plain-server-active-zones` shows only public and trusted).

`denied-packets.txt` holds the kernel's lines for packets firewalld logged as denied (`LogDenied=all`), one per line, as `journalctl -k` shows them without the date, host and `kernel:`; in the journal's JSON that text is the whole of `MESSAGE`. They were recorded in the same virtual machine (NOTES.md section 4): a rejected TCP packet in zone `public`, then four dropped in zone `drop` (TCP, UDP, ICMP echo, and IPv6 TCP with expanded addresses). The first one's `__REALTIME_TIMESTAMP` was `1791827233914663`.

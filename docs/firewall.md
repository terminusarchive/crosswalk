# UFW events and troubleshooting

Crosswalk's dashboard has two pages (Traffic, and Network & Firewall) with eight panes in all, and needs a terminal of at least 110×24. The [manual](manual.md) describes the pages, the keys (`p`, `Tab` and `1`–`8`), Network Events and the Wi-Fi pane; this guide covers the firewall panes.

Crosswalk reads UFW's configuration files, UFW's rule files, and block-event records; it never changes UFW rules or logging settings, and it never runs the `ufw` command. Three panes use this: Firewall Blocks (key `5`, block events, plus refused attempts seen in captured packets), Firewall Rules (key `4`, the rules themselves) and Listening Ports (key `3`, whether each port is reachable). Listening Ports and Firewall Rules are side by side at the bottom of the Traffic page, which Crosswalk starts on; Firewall Blocks is on the Network & Firewall page, above Network Events. The page shown follows the focused pane, so `3`, `4` and `5` also switch pages, and `p` shows the other page at the pane last focused there. While you are on Traffic, the number beside `Network & Firewall` in the header counts the firewall blocks and refused attempts that have arrived since you last looked at that page (a repeat of a row counts too, and `99+` is the most it shows); that is the way to notice blocks without leaving Traffic. A machine that keeps retrying a refused connection keeps the count high. The default provider is `ufw`, and its default source is the kernel journal. UFW is the only implemented provider. Firewall reporting is independent of packet capture, process attribution, and interface counters.

## Choose an event source

The journal source follows new kernel journal entries with `journalctl --follow --lines=0 --output=json --dmesg`. It does not replay old records. The account running Crosswalk must be able to read the kernel journal, usually through membership of a group such as `systemd-journal`, `adm` or `wheel` (it depends on the distribution), or by running with `sudo`. Granting the capabilities in the README's [Running without sudo](../README.md#running-without-sudo) does not give access to the journal. If the journal cannot be read, the Firewall Blocks pane says so and the other panes keep working.

Whether UFW is on and whether logging is on are read from `/etc/ufw/ufw.conf`. If UFW is off (`ENABLED=no`) or logging is off (`LOGLEVEL=off`), Crosswalk does not start the journal reader, because no block records would come, and the pane says why. If `ufw.conf` cannot be read, has no `ENABLED` or `LOGLEVEL` setting, or has an `ENABLED` value other than `yes` or `no`, Crosswalk cannot tell, so it reads the journal anyway and shows any block records that arrive; the header dot stays green, and the Firewall Rules and Listening Ports panes report the unreadable file themselves.

To select a UFW log file instead, configure its path explicitly. Crosswalk reads new lines from the end of the file and watches for replacement or truncation; it does not ingest existing history.

```sh
sudo ./target/release/crosswalk --ufw-source file:/var/log/ufw.log
```

The equivalent TOML setting is `ufw_source = "file:/var/log/ufw.log"`. Only one source is read per run. The log file must exist and be readable by the running account. File paths can differ by distribution; verify the path and permissions on your host.

The complete example is [../config.example.toml](../config.example.toml). CLI options take precedence over TOML values. `--firewall-provider` currently accepts only `ufw`; `--ufw-source` accepts `journal` or `file:<path>`.

## Logging setup is manual

To compare with what UFW itself reports, run this yourself; Crosswalk never runs it. It changes nothing:

```sh
sudo ufw status verbose
```

If you choose to enable UFW logging, do so deliberately using the level appropriate for your host:

```sh
sudo ufw logging low
```

`low` is UFW's ordinary blocked-packet logging level and uses rate limiting. UFW logging levels and behavior vary by level; higher-volume logging can generate substantial system logs. Logged blocks may be rate-limited, so the dashboard is not an exhaustive block counter. Logging configuration is a user-managed host setting; Crosswalk never runs this command. Consult your distribution's `ufw(8)` documentation before changing the level. [Ubuntu's UFW manual](https://manpages.ubuntu.com/manpages/resolute/man8/ufw.8.html) describes the available levels and logging behavior.

## Listening Ports and Firewall Rules need the rule files

The Listening Ports pane (`3`) and the Firewall Rules pane (`4`), both on the Traffic page, share one reading of UFW's rules. Listening Ports marks each port `open`, `limited`, `blocked` or `local`. To decide, Crosswalk reads four files about every 5 seconds. It does not run `ufw`.

- `/etc/ufw/ufw.conf`, for `ENABLED`: whether UFW is on
- `/etc/default/ufw`, for `DEFAULT_INPUT_POLICY` and `DEFAULT_OUTPUT_POLICY`: the two default policies (`DROP` is shown as deny, `REJECT` as reject, `ACCEPT` as allow)
- `/etc/ufw/user.rules`, for IPv4 rules
- `/etc/ufw/user6.rules`, for IPv6 rules

UFW is reported as on when `ufw.conf` says `ENABLED=yes`, even if UFW failed to load its rules; Crosswalk does not check what the kernel is actually enforcing. On some systems these files are readable only by root (Debian and Ubuntu keep the rule files so). There, run Crosswalk with `sudo`; the capabilities in the README's [Running without sudo](../README.md#running-without-sudo) do not give access to them. Listening Ports uses only inbound rules; Firewall Rules lists inbound and outbound rules.

Exposure is judged from UFW's rules alone. Crosswalk cannot see a router, a cloud firewall or security group, or nftables or iptables rules written outside UFW. Treat `blocked` as "UFW does not allow it", not as proof that nothing can reach the port.

How a state is chosen:

- `local`: the port is bound to loopback only. UFW is not consulted.
- `open`: a rule allows the port from anywhere, or the default incoming policy is allow and no rule denies it from anywhere.
- `limited`: the default incoming policy denies, and the only matching rules allow it from specific sources, on a specific interface or address, or are `ufw limit` rules.
- `blocked`: no rule allows it and the default incoming policy is deny or reject, or a rule denies it from anywhere.

When the pane cannot tell, it says so instead of guessing:

| Column and pane line | Cause | Fix |
| --- | --- | --- |
| `? ufw off`, "UFW is off, so exposure is unknown" (Firewall Rules: "UFW is off, so there are no rules to show") | `ufw.conf` says `ENABLED=no` | Nothing is wrong with Crosswalk. Enable UFW if you want it to filter traffic. Loopback ports still show `local` |
| `? unreadable`, "Cannot read firewall rules (...)" | One of the four files is missing or unreadable by the account running Crosswalk (the line says `cannot read <file>`), `ENABLED`, `DEFAULT_INPUT_POLICY` or `DEFAULT_OUTPUT_POLICY` is missing from its file (`<setting> missing`) or has a value Crosswalk does not know (`<setting> unknown`), or a rule line could not be understood | Run Crosswalk with `sudo` if the files are readable only by root. Check that `/etc/ufw/ufw.conf`, `/etc/default/ufw`, `/etc/ufw/user.rules` and `/etc/ufw/user6.rules` exist and hold those settings. The pane line names the file or problem. Firewall Rules shows the same line |
| `· …`, "reading firewall rules…" (also in Firewall Rules) | The first read has not finished | Wait a few seconds |

UDP ports in the kernel's ephemeral range (from `/proc/sys/net/ipv4/ip_local_port_range`, normally 32768 and up) are not listed, because they are almost always client sockets.

This reading of the rules is separate from the log source above. You can have rules without logging, and logging without readable rules.

## The Firewall Rules pane

Press `4` to focus the pane (Traffic page, bottom right, beside Listening Ports). It lists the UFW rules that filter this machine's own traffic, inbound and outbound, in the order UFW applies them (the first matching rule wins), under a line giving the default incoming and outgoing policies. It shows each rule's interface (`all` when the rule is not limited to one), the app listening on its ports (below), direction, action (`allow`, `limit`, `deny` or `reject`), port and protocol or `any`, and the address or network at the other end or `anywhere`, in that order from the left. The interface, app and direction are left-justified; the action, port and remote are right-justified. The interface is as wide as its widest value and the app column takes the room that is left (when the app column is dropped, the interface takes it), so direction, action, port and remote sit packed together at the pane's right edge and the remote ends there. One blank cell separates direction from action; three separate action from port and port from remote, in zoom too. In zoom the rule text takes the room that is left. Zoom adds the rule's text as UFW records it, without its comment.

- The app column (`APP`, after the interface; the name is cut with `…` only when the pane has no more room, and in zoom at 24 cells) is filled only for an inbound rule that names ports: it shows the program now listening on one of those ports, single ports and ranges, with a matching protocol (a rule with no protocol matches both), by the short name Listening Ports shows. Several programs give the one on the lowest port and a count, `sshd +1`; nothing listening gives `—`, and a listener with no owning process counts as nothing. An outbound rule, and a rule on any port, leave it empty. It matches by port and protocol only, not by the address or interface the program is bound to or the rule's remote, so it says what would answer on that port, not whether the rule applies to it. It is the first column dropped when the pane is narrow, and a search matches it.
- A rule that exists identically for IPv4 and IPv6 (what `ufw allow 22/tcp` writes) is one row. A rule for one family only is marked `v4` or `v6`.
- Forwarding rules (`ufw route ...`) are not listed, because they filter traffic passing through the machine, not its own. Rules written outside UFW (nftables, iptables, a router, a cloud security group) are not listed either, so the pane describes UFW's intent, not everything that filters traffic.
- Rules and the defaults are read from `/etc/ufw/user.rules`, `/etc/ufw/user6.rules`, `/etc/ufw/ufw.conf` and `/etc/default/ufw`, about every 5 seconds, with the same access as above. If UFW is off or the rules cannot be read, the pane shows one line saying so and no rules. With UFW active and no rules it shows the defaults and `no rules`.

## Firewall events in Network Events

Network Events (key `6`, Network & Firewall page, lower left) logs changes in what the Firewall Rules and Listening Ports panes show, as they are read, newest first. The first reading is the baseline and logs nothing. The manual's [Network Events](manual.md#network-events) section lists every kind of event; the firewall ones are:

- `rule added: <text>` and `rule removed: <text>`, where the text is the rule as the Firewall Rules zoom shows it. A rule that changes is a removal and an addition.
- `default incoming policy deny -> allow`, and the same for `outgoing`.
- `UFW switched off` (warning colour) and `UFW switched on`.
- A port's exposure changing because of a rule, such as `tcp 0.0.0.0:22 sshd exposure blocked -> open` (warning colour when it becomes open), and `started listening` and `stopped listening` lines for ports. These wait until both the listening ports and the rules have been read. With UFW off a port's exposure is unknown: a port that starts listening is logged as `started listening, unknown`, and a change of exposure to or from unknown is not logged. With the rules unreadable the port comparison waits, and once they are readable the difference since the last comparison is logged once.
- One rule can log two lines. A rule for both IPv4 and IPv6, such as what `ufw allow 22/tcp` writes, is one row in Firewall Rules but two rules to the log: `rule added: allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in` and `rule added: allow tcp 22 ::/0 any ::/0 in`. A program listening on both `0.0.0.0` and `[::]` likewise logs a line for each address.

A rules reading that cannot be read is skipped; the next readable one is compared with the last readable one, so a file that is briefly unreadable logs nothing. The log is in memory, holds the 500 most recent events, and is not written to disk. Block events from the journal or log file are not repeated there: they stay in Firewall Blocks.

## Interpreting the Firewall Blocks pane

Press `5` to focus the pane (Network & Firewall page, upper left, above Network Events). It holds two kinds of row in one table, newest first, and its KIND column says which each is: `blocked` (UFW dropped a packet) or `refused` (the kernel turned a connection request away). Both kinds share the 1,000-row limit, and the oldest row of either goes first.

- There is one row per kind, source address, port and protocol. A repeat raises the count and last-seen time of that row. Zoom also shows first-seen time, interface, direction, and blocks on outbound traffic.
- Crosswalk reports a block only from records containing a confirmed `[UFW BLOCK]` marker. It does not treat missing records as proof of allowed traffic or no blocks.
- A refused attempt is a connection request (a TCP SYN) to a port nothing listens on that the kernel answered with a reset (RST). It is seen in captured packets, not in UFW's log, so it needs packet capture and does not need UFW logging. Only TCP is covered.
- A request the firewall drops gets no reset, so it is a `blocked` row and never a `refused` one. A request to a port nothing listens on that a UFW `reject` rule turns away gets a reset, and UFW can log it, so it can appear as both a `blocked` row and a `refused` row. The two rows are separate observations; Crosswalk does not merge them.
- A captured packet and a UFW block record are independent evidence. Crosswalk does not correlate them, claim ACCEPT verdicts, or add firewall events to captured or kernel byte totals. Traffic shown in App Traffic is captured traffic, not a statement that the firewall accepted it. Refused attempts are left out of App Traffic.
- UFW records may omit timestamp, direction, interface, protocol, endpoint, or process fields. Missing fields remain unknown; process ownership is not inferred from a port.
- Kernel packet logging can be rate-limited or suppressed by system logging configuration. UFW can also be inactive, logging can be off, and the selected source can be unreadable or unavailable. None of these affects refused attempts, which come from packet capture.

## Troubleshooting

| Dashboard status or symptom | Check |
| --- | --- |
| UFW inactive or logging disabled | Check `ENABLED` and `LOGLEVEL` in `/etc/ufw/ufw.conf`, or compare with `sudo ufw status verbose` run yourself. If you want events, decide whether to enable UFW logging; Crosswalk does not change it. The header `firewall` dot turns orange. |
| Journal unavailable | Check that `journalctl` exists and that your account can read kernel messages (a group such as `systemd-journal`, `adm` or `wheel`) or run with `sudo`. Try the explicit log-file source if your system writes UFW records there. |
| File source unavailable | Confirm the configured file exists and is readable by the run account. Check `ufw_source` spelling and the path used by your distribution. |
| Awaiting events | The source is open but no new block record has arrived since startup. This does not mean that no blocks occurred. |
| Degraded or malformed input | Check source permissions, whether the journal child is still running, and whether the source contains normal UFW kernel records. The displayed health includes the read or parse failure. |
| Listening Ports shows `? ufw off` or `? unreadable`, or Firewall Rules shows one line instead of rules | See [Listening Ports and Firewall Rules need the rule files](#listening-ports-and-firewall-rules-need-the-rule-files). |
| Neighbors shows "Cannot read the neighbor table" | Check that the `ip` command is installed (`ip -json neigh show` should print a list). Neighbors reads the kernel's table and sends nothing, so it lists only machines this computer has recently exchanged packets with |
| No observed packet traffic | Packet capture has separate privileges and SLL2 requirements. Review the capture health in the dashboard; firewall health does not establish capture health. |

No real block during a smoke check is a live-verification limit. Use fixtures and automated tests to verify parsing without altering firewall configuration.

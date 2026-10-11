# Crosswalk manual

Crosswalk is a read-only Linux terminal dashboard for your network. Seven panes on two pages show how much traffic crosses an interface, which apps are sending data out and to where, which local ports are listening and whether UFW lets traffic reach them, which inbound packets your firewall blocked or the kernel refused, which UFW rules are in force, which other machines on your network this computer has recently talked to, and which Wi-Fi networks are in range. It never changes firewall rules and never writes traffic history to disk.

The [README](../README.md) is the short version. This is the reference: the full setup, then the display, the keys, every pane, the network map, the limits, the colours and the smoke checklist.

## Setup in full

### Requirements

- Linux with Rust and Cargo (edition 2024 toolchain).
- libpcap development files and a C toolchain (`libpcap-dev` on Debian/Ubuntu, or the equivalent package for your distribution).
- Packet-capture privileges to observe traffic. There are two ways to get them: run the binary with `sudo`, or grant it two capabilities once and run it as yourself (see [Running without sudo](#running-without-sudo)).
- UFW and `journalctl` for the default firewall source. Crosswalk never runs `ufw`; it reads UFW's configuration and rule files. Where those files are readable only by root, Listening Ports and Firewall Rules need `sudo` (see [Running without sudo](#running-without-sudo)). Firewall reporting is independent of packet capture.
- The `ip` command (from `iproute2`, present on nearly every Linux system) for the Neighbors pane.
- Optional: the `nmcli` command (from NetworkManager) for the Wi-Fi Networks pane. Without it, or without NetworkManager running, that pane says so and the rest of Crosswalk is unaffected. It is also what makes the one key that transmits, `r` (see [Wi-Fi Networks](#wi-fi-networks)), work.

Tested with these versions, which are the ones installed when Crosswalk was tested, not the least that work. Older or newer versions may work but have not been tried. `Cargo.lock` records the Rust libraries.

- Arch Linux, Linux 7.2.9
- Rust 1.98.1
- libpcap 1.11.0
- UFW 0.36.2
- NetworkManager 1.58.1
- iproute2 7.2.0
- systemd 262

Build and inspect the supported options:

```sh
cargo build --release
./target/release/crosswalk --help
```

Run with defaults (UFW provider, kernel journal source, reverse DNS on), either with `sudo`:

```sh
sudo ./target/release/crosswalk
```

or as yourself, once the binary has been granted the capabilities described in [Running without sudo](#running-without-sudo):

```sh
./target/release/crosswalk
```

To use an explicit configuration file:

```sh
./target/release/crosswalk --config config.example.toml
```

(Put `sudo` in front if you run that way.)

Command-line options override values in the TOML file. The terminal must be at least 110 columns by 24 rows; below that, Crosswalk shows a message giving the minimum size. Only `ufw` is currently supported as a firewall provider. For firewall setup, source selection, and diagnostics, see [docs/firewall.md](firewall.md).

### Install

To run `crosswalk` from your `PATH` instead of from `target/release`, install it with Cargo. Run this in the repository:

```sh
cargo install --path .
```

This builds the release binary and puts it in `~/.cargo/bin/crosswalk`, Cargo's own directory. Add that directory to your `PATH` if it is not there already; Cargo prints a warning after the install when it is not.
To remove it:

```sh
cargo uninstall crosswalk
```

To install into `~/.local/bin` instead, for a user who keeps their programs there, give a root:

```sh
cargo install --path . --root ~/.local
cargo uninstall crosswalk --root ~/.local
```

Give `--root` again on each install, and on the uninstall. Cargo also writes `.crates.toml` and `.crates2.json` in the root, which here is `~/.local`.

An installed copy has no capabilities. Run the `setcap` command of [Running without sudo](#running-without-sudo) on the installed path, and again after every install, because a new file does not keep the grant:

```sh
sudo setcap cap_net_raw,cap_sys_ptrace+ep ~/.cargo/bin/crosswalk
```

(Use `~/.local/bin/crosswalk` if you gave `--root ~/.local`.) Without it, run the installed program with `sudo`; started without `cap_net_raw`, Crosswalk prints this command with its own absolute path.

Both directories belong to your account, and anyone who can write to a file with these capabilities can run their own code with them; [What you are granting](#what-you-are-granting) says more. The careful choice is the hardened install there, which copies the binary to a root-owned place before granting anything.

### Running without sudo

Crosswalk needs privilege for two things only: capturing packets, and reading which process owns a socket that belongs to another user. Linux can grant exactly those to one program, so you do not have to run all of Crosswalk as root. Grant them to the binary once:

```sh
sudo setcap cap_net_raw,cap_sys_ptrace+ep <path to the crosswalk binary>
```

Then run `crosswalk` as yourself. Crosswalk does not run `setcap` for you. Whenever it is started without `cap_net_raw`, it prints this command with its own absolute path.

Repeat the command after each build or install: replacing the file clears its capabilities.

- `cap_net_raw` lets Crosswalk capture packets.
- `cap_sys_ptrace` lets Crosswalk read which process owns a socket that belongs to another user. A process holding it can read and control any other process on the machine, root's included, so it is close to root-equivalent. Granting it removes the password prompt and avoids running the whole program as root, but treat it as granting root-level trust to that binary, and grant it only to a binary you trust.

`cap_net_raw` alone is a real option: grant only that (`sudo setcap cap_net_raw+ep <path>`) and Crosswalk runs without naming other users' programs, as described next.

What you see with each missing:

- Without `cap_net_raw`, Crosswalk prints the message with the command and exits without opening the dashboard.
- With `cap_net_raw` but without `cap_sys_ptrace`, Crosswalk runs. It names the programs you own and counts other users' traffic in App Traffic's not-attributed total. App Traffic shows a line saying that other users' programs cannot be named and that `cap_sys_ptrace` is needed, and the `apps` indicator in the header turns orange. In Listening Ports, a port owned by another user's process shows `—` for its app.

The grant has no effect if the binary is on a filesystem mounted `nosuid`, or on one that cannot store capabilities. Crosswalk then prints the same message again. `getcap <path>` shows what a file holds, and `findmnt -no OPTIONS --target <dir>` shows the mount options of the filesystem that holds `<dir>`; look for `nosuid` in the list.

#### What you are granting

`+ep` means the capabilities are permitted to and effective for the program as soon as it starts, with nothing passed on to the commands it runs.

The grant belongs to the file, not to you. Every user who can run the binary gets the capabilities for that process, and anyone who can write to or replace the file can run their own code with them. A binary in a build tree under a home directory can be replaced by that account, so the grant there is only as safe as that account.

For a hardened install, do what Wireshark does for its capture helper: copy the binary to a root-owned place, owned by root, with a dedicated group and no access for others, then grant the capabilities there.

```sh
sudo groupadd crosswalk
sudo usermod -aG crosswalk "$USER"
sudo install -o root -g crosswalk -m 0750 target/release/crosswalk /usr/local/bin/crosswalk
sudo setcap cap_net_raw,cap_sys_ptrace+ep /usr/local/bin/crosswalk
getcap /usr/local/bin/crosswalk
```

Adding your account to the group takes effect at your next login. `getcap` should list `cap_net_raw` and `cap_sys_ptrace` with `ep`. Repeat the `install` and `setcap` commands after each new build, because `install` replaces the file and clears the grant.

To remove the grant, run `sudo setcap -r <path>`.

Two things the capabilities do not cover:

- **The kernel journal.** Firewall Blocks reads the kernel journal, so your account must already be allowed to read it, usually by membership of a group such as `systemd-journal`, `adm` or `wheel`, depending on the distribution. Without that access the pane shows one of three things, depending on how `journalctl` fails: the "Cannot read the firewall log" line when `journalctl` cannot be started, the "Firewall log is partly unreadable" line when it starts and then exits, or nothing at all when it runs but is given no kernel records, in which case an empty pane does not mean there were no blocks. The other panes keep working. Crosswalk cannot grant this access.
- **UFW's files.** Crosswalk reads `/etc/ufw/ufw.conf`, `/etc/default/ufw`, `/etc/ufw/user.rules` and `/etc/ufw/user6.rules`. Some distributions, Debian and Ubuntu among them, keep the rule files readable only by root. Where they do, Firewall Rules and the exposure column in Listening Ports show their "cannot be read" state, and `sudo` is the way to run there. See [docs/firewall.md](firewall.md).

Running with `sudo` is still supported and behaves as before; it prints no message about capabilities.

## The display

Crosswalk has two pages and shows one at a time. It starts on Traffic; press `p` to show the other page, or `Tab` to move through the panes and so to the other page, or `1` to `8` to go straight to a pane.

Traffic:

```
+-- BANDWIDTH · eth0 · 10.0.1.13/24 · gw 10.0.1.1 · dns 10.0.1.6 ------+
| ↑ out   1.2 MB/s  ▂▃▅▇▅▃▂▁▂▃▅▃▂▁▁▂▃▂▃▅▇▅▃▂▁▂▃▅▃▂▁▁  ↑ total   1.2 GB |
| peak    3.4 MB/s  ████████████████████████████████                   |
|                   ────────────────────────────────  ▓▓██████████████ |
| ↓ in    9.8 MB/s  ████████████████████████████████                   |
| peak   12.0 MB/s  ▇▅▃▅▇█▇▅▃▂▃▅▇▅▃▂▁▂▇▅▃▅▇█▇▅▃▂▁▂▃▅  ↓ total   8.4 GB |
+-- APP TRAFFIC -------------------------------------------------------+
|                                                                      |
+-- LISTENING PORTS ----------------+-- FIREWALL RULES ----------------+
|                                   |                                  |
+-----------------------------------+----------------------------------+
```

Network & Firewall:

```
+-- FIREWALL BLOCKS ----------------+-- WI-FI NETWORKS ----------------+
|                                   |                                  |
+-- NETWORK EVENTS -----------------+-- NEIGHBORS ---------------------+
|                                   |                                  |
+-----------------------------------+----------------------------------+
```

On Traffic, Bandwidth is a band across the top and App Traffic is below it, each the full width of the terminal. At the bottom, Listening Ports and Firewall Rules share a row, each half the width; the row is two fifths of the height below Bandwidth and never fewer than seven rows. On Network & Firewall, the left column is Firewall Blocks over Network Events and the right column is Wi-Fi Networks over Neighbors; each pane is half the width and half the height. Which page is shown follows the focused pane, and `p` shows the other page (see [Controls](#controls)).

Everything is collected for both pages all the time; only what is drawn changes. Bandwidth's chart history, Firewall Blocks' rows and the Network Events log keep building while the other page is shown, and are there when you flip to them.

The header shows the name of the program, the names of the two pages with the one shown marked, and four indicators, one for each data source. The footer lists the keys that apply right now.

### The header's page names and count

The header names both pages, `Traffic` and `Network & Firewall`. The page shown is in the accent colour and bold; the other is grey.

While Traffic is shown, a number appears beside `Network & Firewall`. It counts firewall blocks and refused attempts recorded since that page (or a zoomed pane on it) was last shown, or, until Network & Firewall is first shown, since Crosswalk was started, so a repeat of a row you have already seen raises it as much as a new row does. Above 99 it reads `99+`, and when it is zero nothing is shown. It returns to zero as soon as you move to the page. The count is the way to notice blocks while you are looking at Traffic. A machine that keeps retrying a refused connection adds to it every time, so it will stay high until you look at the page.

## Controls

| Key | Action |
| --- | --- |
| `Tab` / `Shift-Tab` | Move focus to the next or previous pane, across both pages |
| `p` | Show the other page. The focus goes to the pane last focused on that page, or to its first pane (Bandwidth, or Firewall Blocks) if none has been. Does nothing in zoom |
| `1`–`8` | Focus a pane, and show its page. Traffic: Bandwidth (`1`), App Traffic (`2`), Listening Ports (`3`), Firewall Rules (`4`). Network & Firewall: Firewall Blocks (`5`), Network Events (`6`), Wi-Fi Networks (`7`), Neighbors (`8`) |
| `Enter` | Zoom the focused pane to the full screen |
| `Esc` | Leave zoom. On the overview, clear the focused pane's search. Closes help, and closes the network map |
| `↓` / `↑` or `j` / `k` | Move the selected row down or up one row, on the overview and in zoom |
| `g` or `Home` / `G` or `End` | Go to the first or the last row |
| `Ctrl-d` or `PgDn` / `Ctrl-u` or `PgUp` | Move down or up half the rows the pane shows, at least one row |
| `/` | Search the focused pane |
| `m` | Show the network map in place of the page; `m` or `Esc` closes it. Does nothing in zoom or while a search field is open (there `m` is a letter to type). See [Network map](#network-map) |
| `t` / `T` | Show the next / previous theme, for this run only; after `terminal` comes `synthwave` again, and `T` from `synthwave` shows `terminal`. Work on both pages, in zoom and on the network map. While a search field is open they are letters to type. The header gives the name of the theme now shown. See [Colours](#colours) |
| `i` | Show the next interface in the Bandwidth pane |
| `n` | Turn reverse-DNS names on or off for this session (App Traffic destinations, Firewall Blocks sources including refused attempts, and Neighbors). Wi-Fi Networks has no addresses, so `n` has nothing to act on there |
| `r` | On Wi-Fi Networks, focused or zoomed: ask NetworkManager for a Wi-Fi scan. This is the one thing in Crosswalk that causes a transmission (see [Wi-Fi Networks](#wi-fi-networks)). On any other pane it does nothing |
| `?` | Show or hide help |
| `q` or `Ctrl-C` | Quit and restore the terminal |

The focused pane has a bright border and title. The page shown is always the page of the focused pane. `Tab` visits the panes in the order of their number keys, `1` to `8`, and `Shift-Tab` goes back; both wrap at the ends, and the page flips as focus crosses from Firewall Rules to Firewall Blocks and from Neighbors back to Bandwidth. `p` flips the page without walking the panes.

### Search

Press `/` to open a search field in the title of the focused pane. Type, and only rows with the text in some column stay in view. Matching ignores case. `Backspace` deletes a character. `Enter` closes the field and keeps the search. `Esc` while typing clears the search and closes the field.

Each pane has its own search. A search is kept when you zoom in and out, and it applies to the zoomed table too. To clear a kept search, press `Esc` on the overview with that pane focused.

### Zoom

`Enter` shows the focused pane as a full-screen table with the columns the overview has no room for:

| Pane | Extra in zoom |
| --- | --- |
| Bandwidth | A taller chart, and a table of every interface with its rates and session totals. The plotted interface is marked |
| App Traffic | Every destination (not just three), every process ID of a destination (`4312,4390,4401`) rather than the first and a count, the app's path up to 48 cells instead of 28, upload and download shown separately, and the reverse-DNS name |
| Firewall Blocks | First-seen time, interface, direction, and the blocks the overview leaves out: those on outbound traffic and those on forwarded traffic, which show `—` for their direction. Refused attempts are listed with the blocks and show their kind |
| Listening Ports | The full executable path and the UFW rule that decided the state (the process ID is on the overview too) |
| Firewall Rules | The text of each rule as UFW records it, without its comment |
| Network Events | The same three columns with each event's text whole when it fits the width, where the overview cuts it at the pane's edge |
| Neighbors | The kernel's state for each neighbour, as a word, and the interface it is on; an IPv6 address shown whole |
| Wi-Fi Networks | Each access point's hardware address (BSSID) and its frequency in MHz |

**How columns are laid out.** In every list, on the overview and in zoom, each column is exactly as wide as its widest cell or its title, except one, which takes all the room that is left: the destination in App Traffic, the app in Listening Ports, the source in Firewall Blocks, the app in Firewall Rules (in zoom the rule text), the event text in Network Events, the network name in Wi-Fi Networks, and the interface in Bandwidth's table (in zoom: the reverse-DNS name, the path, the name, the rule text, the event text, the network name and the interface). The columns after it end flush against the right edge of the pane, so a short value in that column is followed by a gap. The columns whose values change from second to second keep a constant width, that of the widest value they normally hold, so the columns beside them do not move: `PORT` in App Traffic is 9 cells wide (`65535/tcp`), every `↓ IN` and `↑ OUT` in App Traffic and Bandwidth's table is 10 (`999.9 MB/s`), and the totals (`TOTAL`, `↓ TOTAL`, `↑ TOTAL`) are 8 (`999.9 GB`). A value wider than that still widens its column, and the column that takes the room that is left gives up the difference. Text is cut with `…` only when the pane has no room for it. When a pane is too narrow for all its columns, columns are dropped in a fixed order for each pane (given in its section), whatever the cells hold. Text that comes from outside (names, paths) is limited to 48 characters whatever the room, and a few columns that show it have a ceiling too, so one long value cannot squeeze the rest.

**Selecting a row.** The focused pane highlights one row, on the overview and in zoom, starting on the first. The movement keys in the table above move it; a move past either end stops at that end. The table scrolls only when the selection would leave the view, and the pane's header and any notice or footer line (App Traffic's `not attributed` line, Firewall Rules' policy line) stay where they are. A `+N more` at the bottom edge of a pane counts the rows below the ones it shows. In App Traffic the `+N more` rows are rows like any other. Only the focused pane scrolls: when the focus moves to another pane the one left behind shows its first rows again, and the newly focused pane starts on its first row. Zoom opens on the first row, and `Esc` returns to the overview on the first row. Changing a pane's search also returns its selection to the first row; while the search field is open the keys type into it. When rows come or go the selection keeps its place in the list by position and is held within the rows there are. Bandwidth has no rows on the overview, so the keys do nothing there.

In zoom, the selected row stays on screen. `Tab`, `Shift-Tab`, `p` and `1`–`8` do nothing in zoom; press `Esc` first to change the focused pane.

## What the panes show

### Bandwidth

A chart of one network interface over up to the last five minutes. Outbound traffic is drawn above the centre line and inbound traffic below it. Each half is scaled to its own peak, so a quiet direction is not flattened by a busy one. The pane title shows the interface name in the highlight colour, in bold, so it stands out from the rest of the title whether or not the pane is focused. The pane prints the current rate in each direction, and each direction's peak.

On the right, a second gutter as wide as the one on the left shows the plotted interface's totals since Crosswalk started, the same session totals zoom's table shows. The first row carries `↑ total` and the bytes sent, in the outbound colour; the last row carries `↓ total` and the bytes received, in the inbound colour. The centre row carries a bar 16 cells wide, split between the outbound colour on the left and the inbound colour on the right in proportion to the two totals (in the sketch under Traffic, `▓` stands for the outbound colour). A side that has carried anything has at least one cell. Before anything has been carried the bar is drawn in the muted colour, and a total of zero is muted, as a zero rate is on the left. The plot gives up those 18 columns, so at 110 columns it shows 70 seconds of history, and when the pane is so narrow that the plot would have fewer than 20 columns the right gutter is left out. Zoom shows the same gutter beside its taller chart, and `i` shows the next interface's totals with its chart.

After the interface name the title can carry three more parts, each only when it is known: the interface's IPv4 address with its prefix length, or with no IPv4 address an IPv6 address that is not link-local, or else any address (`10.0.1.13/24`); `gw` and the IPv4 default route's gateway, only when the plotted interface carries the default route; and `dns` and the first name server in `/etc/resolv.conf` (`BANDWIDTH · wlan0 · 10.0.1.13/24 · gw 10.0.1.1 · dns 10.0.1.6`). Only the interface name takes the highlight colour. A part that was read and is empty is left out; if the route table or resolver file cannot be read, the last known value stays. When the title is too long for the pane its parts are dropped from the right, `dns` first. The name server is the machine's, not the plotted interface's, so it shows for every interface.

It starts on the interface that carries the default route. Press `i` to move to the next interface; the title shows that interface's address. Rates come from kernel interface counters, so they include traffic Crosswalk cannot decode or attribute to an app.

### App Traffic

Lists apps by the executable's full path, each with the places it is sending data. The columns are `APP`, a narrow one with no title that draws the app's recent rate, `PID`, `DESTINATION`, `PORT`, `↓ IN`, `↑ OUT` and `TOTAL`.

- `APP` is the path, shown on the app's first row only. The column is as wide as the longest path shown, up to 28 cells. A longer path is cut from the left with `…`, so the end of the path, which holds the program's name, always shows: `/home/user/.local/share/claude/versions/2.1.296` reads `…are/claude/versions/2.1.296`. Zoom allows 48 cells, cut the same way; when the zoomed table has less room than the path needs, as at 110 columns, the path is cut from the left with `…` to what it has, so the program's name still shows and no column is dropped for it (the PID list may be cut on the right instead). Control characters are removed from a path. An app whose path names no file is shown as `unknown`.
- `PID` is the process that owns the row's connection. When several processes share the destination it shows the first and how many more (`4312 +2`). The `+N more` line leaves it empty.
- The untitled column after `APP` is four braille cells for the app's last eight seconds: all its destinations added together, ending with the current second, oldest at the left. It is drawn on the app's first row only. Each cell is two seconds, the older in its left column of dots and the newer in its right. A second's height is its download plus upload, one to four dots from the bottom, against the app's own busiest second of the eight: the busiest second is four dots whatever the rate, and any second with traffic has at least one, so it shows the shape and the rate columns give the size. A second with no traffic has no dots, and an app idle for eight seconds shows nothing. A cell is the download colour (the `↓` rate's) when download was at least upload over its two seconds and the upload colour otherwise.
- `DESTINATION` takes the room that is left. When the pane is narrow, the sparkline is dropped first, then `PID`, then `TOTAL`, `↑ OUT`, `↓ IN`, `PORT` and `DESTINATION`; `APP` goes last.
- A search matches the path as shown, so on the overview it does not match the part of a path that was cut off.
- Zoom puts `PID` directly after `APP` and lists every process ID, separated by commas. It puts the sparkline directly after `APP`. When it is narrow, the sparkline is dropped first, then the reverse-DNS `NAME`, then `↑ TOTAL`, `PID`, `↓ TOTAL`, `↑ OUT`, `↓ IN`, `PORT`, `DESTINATION`, and `APP` last.

- Rows stay in the order they were first seen. New apps are added at the bottom, and new destinations go below the app's existing ones. Changing rates never move a row.
- An app shows its first three destinations. A `+N more` line adds up the rest. Zoom shows all of them.
- A row is dimmed after 10 seconds without traffic. It is removed after 5 minutes without traffic.
- Traffic Crosswalk cannot tie to a process is not listed. Its bytes are added to a total, shown in a line under the table as `not attributed: X in, Y out`; the line is not shown while the total is zero. A packet with no owner waits for the next socket snapshot, taken within about a tenth of a second, and is then listed under the app found, so a new connection's traffic reaches its app up to about a tenth of a second late; only a packet still without an owner after that snapshot goes into the total. At most 8,192 packets wait, and none while process ownership is unavailable. Refused inbound connection attempts (a connection request with no owner, and the reset answering it) are left out of App Traffic. A connection's owner is remembered for two minutes after its socket was last seen, so the packets that finish a closed connection stay with its app.
- All UDP traffic is counted. TCP traffic on a port the machine is listening on is left out, because it is mostly replies to inbound connections.
- The list holds up to 4,096 destinations. When it is full, the line under the table also says how many bytes were not listed (`list full: X in, Y out not itemised`), after the not-attributed figure. In a narrow pane the line is shortened to fit.
- With reverse DNS on, the name replaces the address on the overview, and zoom shows both. Firewall Blocks sources and Neighbors get names the same way.

### Firewall Blocks

One table with two kinds of row, newest first. Each row has a KIND column that says which kind it is:

| Kind | Meaning |
| --- | --- |
| `blocked` (red) | A packet UFW blocked, read from UFW log records |
| `refused` (orange) | A refused attempt: another machine sent a connection request (a TCP SYN) to a port nothing on this machine listens on, and the kernel answered with a reset (RST) |

There is one row per kind, source address, port, and protocol. A repeat raises the row's count (shown as `×3`) and updates its last-seen time without moving it. A new source, port, or protocol adds a row at the top. Crosswalk keeps the newest 1,000 rows in all: firewall blocks and refused attempts together, inbound, outbound and forwarded together, and the oldest row of either kind goes first.

The overview lists inbound blocks and refused attempts. A block on traffic passing through this machine (the record names both an inbound and an outbound interface, or neither) is listed in zoom only, with `—` for its direction, one row per source address, port and protocol like any other block; the header's count includes it. A log line is used once it is complete, so a record written in pieces is one block.

A refused attempt is different from a firewall block. A refused attempt means the machine answered: no program was listening, so the kernel said so. A firewall block means UFW dropped the packet and nothing came back. A request that UFW drops therefore never becomes a refused attempt, because no reset is sent. A UFW `reject` rule is the exception: it answers with a reset, so one request to a port nothing listens on can appear as a `blocked` row (from UFW's log) and again as a `refused` row (from the reset).

Refused attempts are seen in captured packets, so they need packet capture to be working, and they are TCP only: Crosswalk does not list refused UDP attempts. Only requests that no program on this machine claims count (a request to a port a program listens on is not refused). Refused attempts are left out of App Traffic and its not-attributed total, and with reverse DNS on their sources show a name as firewall blocks do.

When the pane is narrow, the last-seen time is the first column dropped, then the hit count and the port. Zoom always shows them.

Block rows come from UFW log records. UFW logging has to be on, and logged blocks can be rate-limited, so this pane is not an exact count of blocked packets. Refused attempts do not depend on UFW logging. See [docs/firewall.md](firewall.md).

### Listening Ports

Every TCP port in the listening state, and every bound UDP port below the kernel's ephemeral port range (read from `/proc/sys/net/ipv4/ip_local_port_range`, usually 32768 and up), for IPv4 and IPv6. Each row shows the port and protocol, the app that owns it (its short name: the executable's file name, or, when that is only a version number, as with `.../claude/versions/2.1.296`, the folder it is installed under, `claude`, skipping folders called `versions`, `version`, `releases` or `bin`), the owning process's ID (`—` when no process owns the port), the address it is bound to, and its firewall state. The columns are `PORT`, `APP`, `PID`, `BIND` and `FIREWALL`. The app takes the room that is left; the pane is half the width, so there is no room for a path, and zoom has a `PATH` column. When the pane is narrow, `PID` is dropped first, then `BIND`, `APP` and `FIREWALL`; `PORT` goes last. Zoom is unchanged. Rows are ordered by exposure: `open` first, then the unknown ones (UFW off, or its rules unreadable), then `limited`, `blocked` and `local`; within one state by port number, then protocol, then bind address. This holds on the overview and in zoom, and with UFW off the ports are simply by port number with the local ones last. Network Events logs a port when it starts or stops listening whatever its place in the list. Rows follow changes on the machine within a few seconds. Rules are re-read about every five seconds.

The four states:

| State | Meaning |
| --- | --- |
| `● open` | A UFW rule allows inbound traffic from anywhere, or the default incoming policy is allow and no rule denies it from anywhere. Shown in the loudest style |
| `◐ limited` | With a default incoming policy of deny, allowed only from specific sources, or only on a specific interface or destination address, or the rule is a UFW `limit` rule (rate limiting) |
| `· blocked` | No rule allows it and the default incoming policy denies it, or a rule denies it from anywhere |
| `· local` | Bound to loopback only, so it cannot be reached from another machine |

By default open is red, limited orange, blocked green, and the rest grey.

When a rule that allows from anywhere and a rule that denies from anywhere both match, the one that comes first in UFW's rule file decides.

**Exposure is judged from UFW's rules only.** Crosswalk does not know about your router, a cloud provider's firewall or security group, or nftables or iptables rules written by hand outside UFW. A port marked `blocked` may still be reachable through one of those, and a port marked `open` may be blocked by one.

Crosswalk never runs `ufw`. It reads whether UFW is enabled from `/etc/ufw/ufw.conf`, the default policies from `/etc/default/ufw`, and the rules from `/etc/ufw/user.rules` and `/etc/ufw/user6.rules`. If UFW is off, the column reads `? ufw off`. If the rules cannot be read, it reads `? unreadable`. In both cases no port is marked `open` or `blocked`, and the pane says why. Until the first read finishes, the column shows `· …`. Loopback ports are marked `local` in every case. See [docs/firewall.md](firewall.md) to fix a read problem.

### Firewall Rules

The UFW rules that filter this machine's own traffic, in the order UFW applies them, so the first rule that matches wins. A line above the table gives the defaults, for example `default: deny in · allow out`. The columns:

| Column | Meaning |
| --- | --- |
| `IFACE` | The interface the rule is limited to, or `all` for a rule that applies to every interface |
| `APP` | For an inbound rule that names ports, the program now listening on one of them (see below); empty for an outbound rule and for a rule on any port |
| `DIR` | `in` for inbound traffic, `out` for outbound |
| `ACTION` | `allow` (green), `limit` (orange, UFW's rate limiting), `deny` (red) or `reject` (red) |
| `PORT` | The port and protocol, such as `22/tcp`, a list or range, or `any` |
| `REMOTE` | The address or network at the other end, or `anywhere`: the source of an inbound rule, the destination of an outbound one |

`IFACE`, `APP` and `DIR` are left-justified; `ACTION`, `PORT` and `REMOTE` are right-justified, and `APP` takes the room that is left, so `DIR`, `ACTION`, `PORT` and `REMOTE` sit packed together against the pane's right edge, with a rule's remote ending at the edge. One blank cell separates `DIR` from `ACTION`; three blank cells separate `ACTION` from `PORT` and `PORT` from `REMOTE`, in zoom too. Each of those is as wide as its widest value or its title, `REMOTE` up to 43 cells. `IFACE` is as wide as its widest value (up to 16 cells), so `APP` starts one blank cell after it and the spare room follows `APP`'s text. In zoom `RULE` takes the room that is left instead. When `APP` is dropped, `IFACE` takes the room that is left. When the pane is narrow, `APP` is dropped first, then `IFACE`, `REMOTE`, `PORT` and `ACTION`; `DIR` goes last. Zoom adds `RULE` after `REMOTE`, and titles `IFACE` and `DIR` in full, `INTERFACE` and `DIRECTION`, each at least 9 cells wide. A search matches the cells shown, so `all` matches the rules bound to no interface (and every `allow` rule, whose action contains those letters), and a program's name matches the rules it is listening under.

`APP` is left-justified and follows `IFACE`. On the overview it takes the room that is left, so a program's name is shown whole and is cut with `…` only when the pane has no more room; in zoom it is at most 24 cells wide. It shows the program listening on one of the rule's ports (single ports and ranges) with a matching protocol (a rule with no protocol matches both), by the short name Listening Ports shows. When several programs match, it shows the one on the lowest port and how many more, such as `sshd +1`. It shows `—` when nothing is listening there (a listener with no owning process counts as nothing). It matches by port and protocol only: the address or interface the program is bound to, and the rule's remote, are not looked at, so a program bound to loopback still shows under an inbound rule for its port. With a long remote such as an IPv6 network at 110 columns, `APP` gives up its room down to a few cells and the remote is still cut with `…`; zoom or a wider terminal shows it whole.

A rule that exists identically for IPv4 and IPv6 is one row. A rule for one family only is marked `v4` or `v6` after its direction, such as `in v6`. Forwarding rules (`ufw route`) are not listed, and neither are rules written outside UFW. A rule's comment (`ufw allow 22/tcp comment 'ssh'`) is not shown; the rule is listed as it would be without one. Zoom adds the text of each rule as UFW records it, without its comment.

Rules are re-read about every five seconds. When UFW is off the pane shows one line saying so and no rules; when the rules cannot be read it shows one line saying that and pointing to [docs/firewall.md](firewall.md). With UFW active and no rules it shows the defaults and `no rules`.

### Network Events

A log of changes Crosswalk notices on this machine and its network, newest first, one line each. It is made by comparing each reading with the one before it, so it needs no extra privileges and sends nothing. The columns:

| Column | Meaning |
| --- | --- |
| `TIME` | The local time, `HH:MM`, when Crosswalk noticed the change, or `—` if the clock could not be read |
| `EVENT` | The kind: `neighbour`, `port`, `firewall` or `connection` |
| `DETAIL` | What changed. This column takes the room the others leave and is cut with `…` at the pane's edge; zoom shows it whole when it fits the width |

A warning event's whole row is in the warning colour and a danger event's in the danger colour; every other row is plain. When the pane is narrow, `TIME` is dropped first, then `EVENT`. A search matches the time, the kind and the text. With no events the pane says `no events yet`.

The first reading of each source is the baseline. What exists when Crosswalk starts, such as the neighbours already known, the ports already listening, the rules already set and the current addresses, logs nothing. Only later changes are events.

The kinds of event, with a line of each as it appears in `DETAIL`:

| Kind | Event | Example | Colour |
| --- | --- | --- | --- |
| `neighbour` | An address seen for the first time | `new neighbour 10.0.1.5 aa:bb:cc:dd:ee:01 on eth0` | plain |
| `neighbour` | A known address showing a different hardware address | `10.0.1.5 MAC aa:bb:cc:dd:ee:01 -> aa:bb:cc:dd:ee:02 on eth0` | danger |
| `port` | A port started listening, with its exposure | `tcp 0.0.0.0:22 sshd started listening, open` | warning when open, else plain |
| `port` | A port stopped listening | `tcp 0.0.0.0:22 sshd stopped listening` | plain |
| `port` | A port's exposure changed | `tcp 0.0.0.0:22 sshd exposure blocked -> open` | warning when it becomes open, else plain |
| `firewall` | A rule added or removed, by its text | `rule added: allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in` | plain |
| `firewall` | A default policy changed | `default incoming policy deny -> allow` | plain |
| `firewall` | UFW switched off or on | `UFW switched off` | warning when off, plain when on |
| `connection` | An address gained or lost by an interface | `wlan0 gained 10.0.1.13/24` | plain |
| `connection` | The default route's interface or gateway changed | `default route wlan0 via 10.0.1.1 -> eth0 via 10.0.0.1` | plain |
| `connection` | The name server changed | `DNS server 10.0.1.6 -> 10.0.1.7` | plain |
| `connection` | The Wi-Fi access point in use changed, by hardware address | `Wi-Fi roamed on HomeNet: aa:bb:cc:dd:ee:01 -> aa:bb:cc:dd:ee:02` | plain |

Other Wi-Fi lines are `Wi-Fi moved from Cafe (aa:bb:cc:dd:ee:01) to HomeNet (aa:bb:cc:dd:ee:02)` when the new access point is on another network, `Wi-Fi disconnected from HomeNet (aa:bb:cc:dd:ee:01)` and `Wi-Fi connected to HomeNet (aa:bb:cc:dd:ee:01)`; a network with no name is called `hidden network`.

What is not logged:

- Neighbours are logged at first sighting and on a change of hardware address only. A neighbour the kernel drops and that returns with the same hardware address is not logged, and neither is a neighbour with no hardware address until it has one; one that had none when Crosswalk started is not logged as new when it resolves. The address is remembered per interface, up to 4,096 of them; past that, new addresses are not logged, but a known address that changes still is.
- Port events wait until both the listening ports and the firewall rules have been read, because a port's exposure depends on the rules. With UFW off a port's exposure is unknown: a port that starts listening is logged as `started listening, unknown`, but a change of exposure to or from unknown is not logged, so switching UFW off logs `UFW switched off` and not a change for every port. With the rules unreadable the comparison of ports waits, and once they are readable again the difference since the last comparison is logged once.
- A rules reading that cannot be read is skipped, and the next readable one is compared with the last readable one. The same holds for the interface and Wi-Fi readings. A resolver file or route table that cannot be read keeps the last known name server and default route, and logs nothing; one that is read and holds no name server or no default route logs `none`. Listening ports are compared only once a listener reading has succeeded.
- One rule can log two lines. A rule that exists for both IPv4 and IPv6, such as what `ufw allow 22/tcp` writes, is one row in Firewall Rules but two rules to the log, so adding it logs `rule added: allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in` and `rule added: allow tcp 22 ::/0 any ::/0 in`. Likewise a program listening on both `0.0.0.0` and `[::]` logs a `port` line for each.
- Forwarding rules are not listed, so their changes are not logged. Nothing is logged for traffic. An event's text is shown without control characters, invisible characters and characters that reorder text, so a name that carries them is drawn without them, and a search matches the text as drawn.

The log keeps the 500 most recent events and drops the oldest. It is held in memory for the run and nothing is written to disk. It keeps filling while the other page is shown. Events are not counted in the header: the number beside `Network & Firewall` counts firewall blocks and refused attempts only.

### Neighbors

The machines the kernel currently knows on the local network, read from its neighbour table (the ARP table for IPv4 and the neighbour-discovery table for IPv6). These are the machines this computer has recently exchanged packets with, not every device on the network: a device that has not talked to this computer is not listed. Crosswalk runs `ip -json neigh show` about every two seconds and sends no packets, so it needs the `ip` command and finds nothing on its own.

Neighbors sits under Wi-Fi Networks, so it is half the screen wide. The `NAME` column is as wide as the longest name, and `ADDRESS` takes what is left, never less than a whole IPv4 address (15 cells). So at 110 columns a name of up to 8 characters leaves room for an IPv6 address such as `fe80::a1:b2c3:d4e5:f607`, and a longer name pushes the address toward 15 cells, where an IPv6 address is cut with `…`; a wider terminal gives both more.

Rows are sorted by address, IPv4 and IPv6 together. The overview columns are `ADDRESS`, `NAME` (the reverse-DNS name, blank when none is known; with names off the column is not there and `ADDRESS` takes its room) and `MAC` (the hardware address, against the right edge). An IPv6 address is cut with `…` only when the names leave less than its length. A neighbour that is in trouble (state `failed` or `incomplete`) has its whole row drawn in the warning colour; every other row is plain, including `delay` and `probe`, which a healthy neighbour passes through when idle. Zoom lays out the same way and adds `STATE` as a word and the `INTERFACE` each neighbour is on. When the pane is narrow, `INTERFACE` is dropped first, then `STATE`, then `NAME`, then `MAC`. A search matches the cells shown, so on the overview it does not match a state word, and in zoom it does.

The state, shown in zoom, is the kernel's own word for how sure it is of the entry:

| State | Meaning |
| --- | --- |
| `reachable` | Recently confirmed to answer |
| `stale` | Known, but not confirmed lately; the kernel checks again when it next sends to it |
| `delay` | The kernel is about to check it, after traffic to a stale entry |
| `probe` | The kernel is asking the machine to confirm its address now |
| `incomplete` | The kernel has asked and is waiting for an answer; the `MAC` column shows `—` until it gets one |
| `failed` | The machine stopped answering. Listed only while the kernel still holds its hardware address |

An entry disappears when the kernel drops it; Crosswalk does not keep it. Entries with no hardware address that are not being resolved are not listed. If the table cannot be read, the pane shows one line saying so and the other panes keep working.

### Wi-Fi Networks

The access points NetworkManager lists, one row each, strongest signal first (equal signals: named networks before hidden ones, then by name, then by hardware address), followed by the ones it no longer lists. Crosswalk runs `nmcli -t -f IN-USE,BSSID,SIGNAL,CHAN,FREQ,SECURITY,SSID device wifi list --rescan no` about every five seconds. `--rescan no` makes `nmcli` answer from NetworkManager's cache, so this periodic read does not cause a scan and sends nothing. The list is therefore only as fresh as NetworkManager's own scanning: NetworkManager scans rarely while you are connected and drops networks as they age, so what it lists can swing from a handful of networks to one and back. On a read where the list comes back empty, Crosswalk also runs `nmcli -t -f WIFI radio` to tell "Wi-Fi is switched off" from "no networks in range".

**Remembered access points.** Crosswalk remembers every access point it has seen since it started, by hardware address. One that NetworkManager stops listing stays in the pane, in the muted colour, below every access point currently listed, with `seen` and how long ago it was last listed where the signal bars were: `seen 40s` below a minute, `seen 12m` below an hour, `seen 2h` below a day, then days (`seen 1d`, held at `seen 99d`). Its name, channel, band and security are as last seen, and it never carries the `●` mark. Remembered ones are ordered most recently seen first. If NetworkManager lists one again it goes back among the listed rows with its current signal. Zoom shows remembered access points the same way, with their hardware address and frequency, and search matches them. At most 200 are remembered; when there are more, the one seen longest ago is forgotten, and one NetworkManager currently lists is never forgotten. The memory is kept in memory only: it is gone when Crosswalk exits, and nothing is written to disk.

**Requesting a scan.** Press `r` while Wi-Fi Networks is focused or zoomed to ask NetworkManager for a scan, by running `nmcli device wifi rescan`. This is the one case in which Crosswalk causes a transmission by the Wi-Fi radio itself (reverse DNS lookups, when on, are the only other traffic it sends, and they go to your DNS server): the radio sends probe requests, and a scan briefly takes it off the channel it is connected on, so a call or a download on that connection may stall for a moment. Crosswalk asks at no other time, and never repeats a scan on its own. Within about a second the pane shows `scan requested…`, and for the next few seconds Crosswalk reads the list every second instead of every five, so the networks the scan finds appear without further keys. `r` does nothing on other panes, while help is open, or while a search field is open (there it is search text).

The columns:

| Column | Meaning |
| --- | --- |
| `NETWORK` | The network name, which takes the room the other columns leave. `●` before the name marks the access point this machine is connected to. A network that broadcasts no name shows `(hidden)` in grey |
| `SIGNAL` | Four bars and the strength as a number, 0 to 100. 80 and above lights four bars, 55 to 79 three, 30 to 54 two, and anything lower one |
| `SECURITY` | What NetworkManager reports, such as `WPA2` or `WPA3`. An open network shows `open` in the warning colour |
| `CHANNEL` | The pane's last column, left-justified: the channel number right-justified in three cells, then ` · ` and the band, written `2.4G`, `5G` or `6G`, such as `  1 · 2.4G`, ` 11 · 2.4G` and `161 · 5G`, so the dots and the bands of all rows start in the same column. Below 3000 MHz is 2.4 GHz, below 5925 MHz is 5 GHz, and anything above is 6 GHz |

When the pane is narrow, `CHANNEL` is dropped first, then `SECURITY`, then `SIGNAL`; the name column goes last. The columns read `NETWORK`, `SIGNAL`, `SECURITY`, `CHANNEL` from the left. Zoom reads `NETWORK`, `SIGNAL`, `SECURITY`, `BSSID` (the access point's hardware address), `FREQUENCY` (its frequency in MHz) and `CHANNEL`; in a narrow zoom those two are the first columns dropped.

When there is nothing to list, the pane says why in one line and the other panes keep working:

| The pane shows | When |
| --- | --- |
| `reading Wi-Fi networks…` | The first read has not finished |
| `Wi-Fi unavailable: nmcli not found.` | The `nmcli` command is not installed |
| `Wi-Fi unavailable: NetworkManager is not running.` | NetworkManager is not running |
| `Wi-Fi unavailable: no Wi-Fi device.` | The machine has no Wi-Fi device |
| `Wi-Fi unavailable: nmcli timed out.` | `nmcli` did not answer within a second |
| `Wi-Fi unavailable: Wi-Fi is switched off.` | The list is empty and `nmcli` reports the Wi-Fi radio disabled |
| `scan requested…` | You pressed `r` and the next list has not arrived yet |
| `no Wi-Fi networks found` | `nmcli` worked, NetworkManager's list is empty and the radio is on (or Crosswalk could not tell) |

When NetworkManager will not scan, the pane shows `scan refused: <reason>` in the warning colour for five seconds and leaves the list as it was. The reasons are `a scan was just done` (NetworkManager allows scans only at intervals; wait a few seconds and press `r` again), `not authorised` (your account may not ask NetworkManager to scan), `nmcli not found`, `nmcli timed out`, `NetworkManager is not running`, and `Wi-Fi is unavailable`; any other failure shows the first line of `nmcli`'s error, cut at 30 characters. The text NetworkManager uses for the first of these is matched loosely (on "Scanning not allowed"), because it differs between versions.

Any other `nmcli` failure on the periodic read is shown as `Wi-Fi unavailable: nmcli: <first line of its error>`, cut at 30 characters. Systems that use iwd or wpa_supplicant without NetworkManager get the unavailable line; Crosswalk reads nothing from them.

### Header indicators

Four dots in the header show the state of each data source:

| Indicator | Source |
| --- | --- |
| `capture` | Packet capture, used by App Traffic |
| `firewall` | The UFW log source, used by Firewall Blocks |
| `interfaces` | Kernel interface counters, used by Bandwidth |
| `apps` | Matching sockets to processes, used by App Traffic and Listening Ports |

A green dot means the source is working. An orange dot means it is degraded, out of date, or switched off (for example UFW logging is off). A red dot means it is unavailable or stopped. A grey dot means it has not reported yet.

When a source has a problem, the pane that depends on it shows one plain line saying what is wrong and where to look. The other panes keep working.

### Finding out why traffic is not attributed

`crosswalk --attribution-log <file>` appends to `<file>` a line for every packet counted in the not-attributed total and a line after every socket snapshot (about once a second, and up to ten a second while packets wait for one). Without the option nothing is written. If the file cannot be opened, Crosswalk stops at startup and names it. Run with `sudo`, Crosswalk makes the file readable by everyone, so you can read it without `sudo`; run as an ordinary user, it leaves the mode your umask gives a new file (and an existing file's mode alone), because the log records other users' connections. It grows without limit while the option is set, so use it for a minute or two. It is a command-line option only, not a config-file key. Lines are tab-separated and start with their kind.

A `packet` line has these fields, in order: `packet`, seconds since start, direction (`in` or `out`), protocol (`tcp`, `udp`, `protoN`), local endpoint, remote endpoint, IP bytes, TCP flags (`SYN,ACK,FIN,PSH,RST` as set, `none`, or `-` when not TCP or not known), the reason, a detail for the reason (`-` if none), the owner memory, `lag_ms` and `waited_ms`.

`lag_ms` is the milliseconds from the moment the kernel captured the packet to the moment Crosswalk read it from the capture (`-` if not known). `waited_ms` is the milliseconds from that read to the moment the packet was sent to be listed: `0.0` for a packet that was not held, the time held for one that was (`-` if not known).

Reasons:

| Reason | Meaning |
| --- | --- |
| `no-socket-matches` | No socket in the snapshot matches the packet |
| `socket-has-no-process` | The best-matching socket has no owning process. The detail gives the socket's `state` (a TCP state name, or `udp:NN`), its `inode` (`0` means no process holds it) and how many sockets matched equally |
| `socket-has-several-owners` | The best-matching sockets are held by more than one process. The detail gives `owners=N` |
| `not-tcp-udp-or-no-ports` | The packet is not TCP or UDP, or has no ports |
| `attribution-unavailable`, `attribution-stale` | No usable snapshot; the detail gives why |

The owner memory is `none` when no owner was remembered for the connection, `expired:Ns` when one was but its socket was last seen owned more than 120 seconds ago (N seconds), and `live:Ns` when one was remembered but not used because the snapshot was stale.

A `snapshot` line has the seconds since start, then `took_ms=` (how long reading `/proc` took), `sockets=`, `processes=` (read), `skipped_other_namespace=` (processes in another network namespace, which is expected) and `skipped_unreadable=` (processes whose files could not be read or changed while being read) and `skipped_no_executable=` (processes with no executable, such as kernel threads). A process that closes one file descriptor while it is read is still read; only that descriptor is skipped.

A packet that waited is logged when it is released, with the time of release and the reason from the snapshot that failed to find its owner. Only packets App Traffic lists are logged: refused inbound attempts and TCP on listening ports are left out. The listening ports come from the same snapshot the log uses, which can differ from the Listening Ports pane by up to two seconds.

## Network map

Press `m` for a map of the local network drawn below the header, in place of the page. It draws the interface that carries the default route: the title names the interface and how many devices are drawn. With no default route it says so in one line and draws nothing else. Opening it changes nothing underneath: the focused pane, its selection and every search text are as you left them, and `m` or `Esc` brings the page back.

```
                       internet   dns 1.1.1.1
                           └─────────┬─────────┘
                           ┌─────────┴─────────┐
                           │ gateway           │
                           │ 10.0.1.1          │
                           │ Ubiquiti          │
                           └─────────┬─────────┘
                          wlan0 · HomeNet · 5G
   ┌───────────┬─────────────────────┬─────────────────────┐
   │ this host │ printer.lan         │ aa:bb:cc:dd:ee:ff   │
   │ 10.0.1.13 │ 10.0.1.40           │ 10.0.1.41           │
   │ Intel     │ Raspberry Pi        │ private             │
```

**What it is drawn from.** Only readings Crosswalk already takes, and nothing is sent to find devices: the default route and its gateway, the interface's addresses, the name servers in `/etc/resolv.conf`, the neighbour table (the same `ip -json neigh show` reading as Neighbors), the Wi-Fi network in use, this host's hardware address, and the vendor table. The map redraws from these on every frame: a device that appears, a default route or resolver file that changes, and a name whose lookup returns all show without closing the map.

**Devices.** A device is one hardware address seen in the neighbour table on that interface; its IPv4 and IPv6 addresses are one box. A neighbour entry with no hardware address yet is not a device. This host is the first box, drawn in the `highlight` colour; after it the boxes are in address order, IPv4 lowest first, then devices with only an IPv6 address. Each box has three lines:

1. The device's role: `this host`, `gateway`, `dns`, or two of them such as `gateway · dns`. With no role it is the reverse-DNS name when names are on (`n`) and one is known, and otherwise the hardware address.
2. Its IPv4 address, or with none an IPv6 address that is not link-local, or else any address it has.
3. Its maker, or nothing.

Text too long for the box is cut with `…`.

**Roles.** The gateway is the device with the default route's address; it has its own box above the segment, joined to it by a line, and its box shows only its address until it has appeared in the neighbour table. Above it the map shows `internet` and, beside it, `dns <address>` for each name server in `/etc/resolv.conf` whose address lies outside the interface's subnet. A name server inside the subnet is a device on the segment and is labelled `dns`; if it has not yet appeared as a neighbour, it is drawn on the segment with its address alone. Every name server in the file is drawn one way or the other. Between the gateway and the segment a label gives the interface name and, when the default route's interface is a wireless one (the kernel gives it a `/sys/class/net/<interface>/wireless` directory, read when the map opens and when the route moves) and Wi-Fi Networks has an access point in use, the network's name and band, as `wlan0 · HomeNet · 5G`.

**Makers.** The maker is the vendor registered for the first three bytes of the hardware address, read once from `/usr/share/hwdata/oui.txt` (the `hwdata` package) the first time you open the map. An address with the locally administered bit set, which phones use to hide their hardware, reads `private`. An unknown prefix, or a system without the file, leaves the line empty and changes nothing else.

**Devices stay.** From the start of the run, whether or not the map has been opened, every device seen stays on the map until Crosswalk exits. One that the neighbour table no longer lists is drawn in the muted colour, and in its normal colour again when it returns. This host is never muted.

**Layout and keys.** Boxes are laid out in as many to a row as the width allows, each row joined to the segment line; at 110×24 at least four fit in a row and two rows are visible. When there are more rows than fit, `j`/`k` and the arrows, `g`/`G` or `Home`/`End`, and `Ctrl-d`/`Ctrl-u` or `PgDn`/`PgUp` (half the rows that fit, at least one) scroll the rows of devices by whole rows and stop at the ends. The part above the segment stays in place and a note on the bottom border says how many devices are below. Also working while the map is open: `n` (names), `?`, `q` and `Ctrl-C`. `Tab`, `Shift-Tab`, `1`–`8`, `p`, `Enter`, `/`, `i` and `r` do nothing.

**What it cannot show.** Devices this machine has not exchanged traffic with, and the hops beyond the gateway. Which switch or access point a device is on: it draws one segment. Any network but the default route's interface (no VPNs, bridges or second interface). Traffic: no rates, apps or destinations. There is no selection, search or detail line; Neighbors has a device's full details. Devices are not remembered between runs. Names come only from reverse DNS, not from mDNS or SSDP, and a maker is only as good as the system's vendor table.

## Limits you should know about

- Packet capture is non-promiscuous metadata capture on Linux's `any` device and needs the Linux cooked v2 (SLL2) link type. Packet payloads are discarded.
- Process ownership is best effort. Connections shorter than about a tenth of a second, and DNS lookups, are counted in the not-attributed total, as are restricted `/proc`, shared sockets, traffic from other network namespaces, and replies to an unconnected UDP socket. A connection's owner is remembered for two minutes after its socket was last seen, so the packets that finish a closed connection stay with its app. Crosswalk never guesses an app from a port.
- The minimum terminal size is 110 columns by 24 rows. Each page has room for its panes at that size, but the other page is not visible: the header count is the only sign of new firewall blocks while Traffic is shown, and a machine that keeps retrying a refused connection keeps that count high.
- Wi-Fi Networks is only as fresh as NetworkManager's own scanning, because Crosswalk asks for a scan only when you press `r`; the periodic read never does, and `r` is the one case in which Crosswalk causes a transmission. Access points are remembered only until Crosswalk exits, and at most 200. It needs NetworkManager and the `nmcli` command; iwd or wpa_supplicant alone gives the unavailable line. It lists, and does not connect to or manage, networks, and keeps no signal history.
- The network map keeps up to 4,096 devices, the same limit as the neighbours Network Events remembers, and keeps them only until Crosswalk exits; devices past 4,096 are not added to the map. While it is open, Crosswalk asks the resolver for the name of the gateway and of the one address each device's box shows, so it is asked for about as many addresses as there are boxes; up to 64 wait in its queue at a time and the rest follow as answers come back. The resolver remembers 512 names. With more than 512 devices on the map, the names it has to forget are asked for again as the map is drawn, so the resolver keeps working through the list for as long as the map is open and some boxes show an address or hardware address where a name was a moment before. It reads this host's hardware address from `/sys/class/net` when the map opens and when the default route moves to another interface.
- A captured packet and a UFW block record are separate observations. Crosswalk does not match them up, and silence in Firewall Blocks does not show that nothing was blocked.
- App Traffic uses captured traffic, and Bandwidth uses kernel counters, so their totals can differ. VPNs and bridges can show the same traffic on more than one interface. Packets passing through this machine and other machines' traffic are not described in App Traffic or Bandwidth; the firewall blocks of forwarded packets are listed in zoomed Firewall Blocks only.
- Reverse DNS is on by default: Crosswalk asks the system resolver for the name of each remote address it looks up, which sends those addresses to your configured DNS server. Turn it off with `--reverse-dns false` or `reverse_dns = false`. Press `n` to turn names off or on for the session; it covers Firewall Blocks sources and Neighbors as well as App Traffic destinations, and has nothing to act on in Wi-Fi Networks. The configured value is the starting state and the key does not change the config file. Lookups are made only for panes on the page shown, or for the zoomed pane, so names on the other page can take a moment to appear after you flip to it. Within those panes, Firewall Blocks and Neighbors look up only the rows the screen can show, while App Traffic looks up every destination of every app, including those folded behind `+N more`. A name is the system's reverse (PTR) record for the address. It is not the name the app asked for. A failed lookup leaves the address shown. Lookups run in the background and do not slow the display.
- Everything is kept in memory for the current run and discarded on exit, except what `--attribution-log` writes. The chart keeps 300 one-second samples per interface (five minutes). App Traffic keeps up to 4,096 destinations. Firewall Blocks keeps 1,000 rows: firewall blocks and refused attempts, inbound, outbound and forwarded, together. Network Events keeps 500 events. Nothing about traffic is written to disk.
- The screen redraws every 40 ms, and data is sampled once a second. Listening sockets and the neighbour table are re-read every 2 seconds, and UFW's rules and NetworkManager's Wi-Fi list every 5. A change is logged in Network Events when the read that shows it arrives, so one that comes and goes between two reads is missed. This machine's addresses are read about once a second, and App Traffic follows them: a packet counts as this machine's once the reading that shows its address has been taken, and packets that arrive before that reading are not counted.

## Colours

### Themes

Crosswalk has twenty-five built-in themes, in this order, which is the order `t` cycles them:

- Dark: `synthwave` (the default, a true-colour 1980s palette), `dracula`, `nord`, `gruvbox`, `catppuccin`, `tokyo-night`, `solarized`, `monokai`, `one-dark`, `everforest`, `rose-pine`, `kanagawa`, `ayu`, `night-owl`, `github-dark` and `palenight`.
- Bright background: `solarized-light`, `gruvbox-light`, `catppuccin-latte` and `github-light`.
- Monochrome, shades of one hue: `mono` (grey on black), `amber` and `green` (after the old screens) and `paper` (black on off-white, which is also bright). A monochrome theme cannot tell things apart by hue, so inbound and outbound, and the healthy, degraded and failed states of the header's indicators and of a port's exposure, differ only in brightness; the brightest is the worst.
- `terminal`, last: the terminal's own background and text colour and its named colours, so it follows the terminal's colour scheme and needs no 24-bit colour.

All but `terminal` need 24-bit colour.

Choose one with `name` in the `[theme]` table of the config file (`name = "nord"`) or with `--theme nord` on the command line; the command line wins over the file. A name that is not one of the twenty-five stops startup with an error listing them. Press `t` while running to show the next theme, in the order above, and `T` to show the previous one; they start from the theme Crosswalk was started with. The header shows the name of the theme now shown, in front of the status indicators, on both pages, in zoom and on the map. Nothing is written to the config file, so put that name in `[theme]` to keep a theme.

### Overriding colours

To change single colours, add them to the `[theme]` table and give any of these names a `#rrggbb` value. They are laid over whichever theme is shown, the one named and any reached with `t` or `T`. Names you leave out keep the theme's own colour. The defaults below are synthwave's.

| Name | Default | What it colours |
| --- | --- | --- |
| `background` | `#1a0b2e` | The screen background |
| `text` | `#f0e6ff` | Ordinary text |
| `muted` | `#8a7aaa` | Borders of unfocused panes, column titles, the chart centre line, idle rows, `(hidden)` networks, remembered access points, the page not shown in the header, the network map's lines and the boxes of devices no longer in the neighbour table, secondary text, and the selected row's background |
| `inbound` | `#00f0ff` | Inbound traffic: the lower half of the chart, download rates, and the headings in the help popup |
| `outbound` | `#ff2a8a` | Outbound traffic: the upper half of the chart and upload rates |
| `accent` | `#b05cff` | The focused pane's border and title, the program name, and the page shown in the header |
| `warning` | `#ff9a3c` | `limited` ports, warning events in Network Events, `limit` rules, refused attempts, rows of `failed` and `incomplete` neighbours, `open` networks in Wi-Fi Networks, a refused scan, the header's block count, degraded indicators, and notices |
| `danger` | `#ff3860` | `open` ports, danger events in Network Events (a neighbour's hardware address changing), firewall blocks, `deny` and `reject` rules, and failed indicators |
| `ok` | `#3cff9a` | Healthy indicators, blocked ports in Listening Ports, and `allow` rules |
| `highlight` | `#ffe66d` | The interface name in the Bandwidth title, and this host's box in the network map |

```toml
[theme]
inbound = "#00aaff"
outbound = "#ffaa00"
```

An unknown colour name or a value that is not `#rrggbb` stops startup with an error naming it. [config.example.toml](../config.example.toml) lists every name with its default.

## Smoke checklist

Run this on a Linux machine where you can use packet-capture privileges. Steps 1 to 5 create only local loopback HTTP traffic and do not change firewall rules or UFW logging; step 6 is the exception. Record unavailable privileges or absent block events as limits; do not manufacture firewall events by changing policy.

1. Build with `cargo build --release`, then start `sudo ./target/release/crosswalk`, or grant the capabilities as in [Running without sudo](#running-without-sudo) and start `./target/release/crosswalk` as yourself. Run the check both ways if you can; started without `cap_net_raw`, Crosswalk should print the `setcap` command and exit. Confirm Traffic shows Bandwidth, App Traffic, Listening Ports and Firewall Rules, and that `5` brings up Network & Firewall with its four panes. Check that the Bandwidth title shows the interface's address, and `gw` and `dns` where the machine has them. If capture startup reports a permission or SLL2 error, record it rather than treating empty panes as zero traffic.
2. Record `ip -s link show dev lo`, then in another terminal start a local server: `python3 -m http.server 8765 --bind 127.0.0.1`. Request it repeatedly with `curl --noproxy '*' http://127.0.0.1:8765/` while watching the panes. Compare the loopback kernel counter with Crosswalk's interface rates and look for captured bytes and process attribution (the short-lived client may be unknown). Run `ip -s link show dev lo` again afterward. Kernel counters include both directions and may not equal IP-layer capture lengths.
3. If the host has IPv6 loopback, start a server bound to `::1` on another port and request `http://[::1]:PORT/`. Otherwise record IPv6 live traffic as unavailable. Confirm the numeric IPv6 address remains visible; reverse DNS is optional.
4. Use keys `1`–`8`, `Tab`, `Shift-Tab` and `p`, and check that the page shown follows the focused pane; zoom each pane with `Enter` and return with `Esc`. Resize below and above 110×24. Check search (`/`, type, Enter, then Esc on the overview to clear it) and confirm the terminal is restored after quitting with `q`.
5. Check the `firewall` indicator and the Firewall Blocks pane. Confirm they report available, awaiting events, disabled, or unavailable honestly. Then check that Listening Ports shows `? ufw off` or `? unreadable` instead of guessing when UFW is off or its rules cannot be read. Do not change firewall settings to create a block; if no real block occurs during the check, record block-event behavior as not observed live. Check that Network Events starts empty and that a change after startup, such as a new neighbour appearing, adds a line without making the header count move. Check that Firewall Rules shows the default policies and your UFW rules (or one line saying UFW is off or unreadable), and that Neighbors lists the router or other machines you have recently talked to, with the `ip` command present. Check that Wi-Fi Networks lists the access points `nmcli device wifi list` shows, with your connection marked, or says plainly that `nmcli` is missing, NetworkManager is not running, or there is no Wi-Fi device. Stay on Traffic while something is refused or blocked, and check that the count beside Network & Firewall rises and goes away when you open that page.

6. Optional, and the one step that makes Crosswalk transmit: with Wi-Fi Networks focused press `r`. Check that `scan requested…` appears within about a second and that the list is then refreshed without further keys, and that pressing `r` again straight away shows `scan refused: a scan was just done` for a few seconds. Check that `r` does nothing on another pane. Also check that an access point NetworkManager stops listing stays in the pane, muted, with `seen` and its age.

This checklist is a manual integration check, not a substitute for the automated fixture tests. See [docs/firewall.md](firewall.md) for source troubleshooting.

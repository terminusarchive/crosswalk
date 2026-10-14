# Crosswalk

Crosswalk is a network monitoring TUI that aims to provide useful information about what is happening on your machine, live, in a single terminal window. 

See how much bandwidth you are using, which apps are talking to which hosts, which ports are open and whether your firewall lets traffic reach them, what the firewall has blocked, and which machines and Wi-Fi networks are nearby. Switch between 25 built-in themes with one key.

Crosswalk only watches. It never changes a firewall rule and never writes traffic history to disk.

![The Traffic page: bandwidth, App Traffic, Listening Ports and Firewall Rules](docs/screenshot-traffic.png)

![The Network & Firewall page: Firewall Blocks, Network Events, Wi-Fi Networks and Neighbors](docs/screenshot-network-firewall.png)

![The network map, opened with m](docs/screenshot-map.png)

The screenshots use made-up data, in the synthwave, tokyo-night and catppuccin themes.

## Requirements

- Linux, Rust and Cargo (edition 2024), and a C toolchain.
- libpcap development files (`libpcap-dev` on Debian and Ubuntu).
- Packet-capture privilege: run with `sudo`, grant one capability once, or let Wireshark's `dumpcap` capture (see [Running without sudo](#running-without-sudo)).
- Optional: UFW or firewalld for the firewall panes, and `journalctl` for their blocks. Neither firewall is required. Crosswalk reads UFW's files, and asks firewalld through `busctl` (part of systemd); it never runs `ufw` or `firewall-cmd`.
- `ip` (iproute2) for Neighbors.
- Optional: `nmcli` (NetworkManager) for Wi-Fi Networks.

Tested with Arch Linux (Linux 7.2.9), Rust 1.98.1, libpcap 1.11.0, UFW 0.36.2, NetworkManager 1.58.1, iproute2 7.2.0 and systemd 262. firewalld was tested separately: firewalld 2.4.4 on Fedora 44, in a virtual machine. UFW is the firewall on the development machine. Other versions may work but have not been tried.

## Install

```sh
cargo install crosswalk
sudo ~/.cargo/bin/crosswalk
```

`cargo install` builds the release binary into `~/.cargo/bin/crosswalk`. Run it by its full path, because `sudo` does not search `~/.cargo/bin`. After the `setcap` grant below, plain `crosswalk` works.

Remove it with `cargo uninstall crosswalk`. An installed copy has no capability, so grant it again after every install.

To build from a clone:

```sh
git clone https://github.com/terminusarchive/crosswalk
cd crosswalk
cargo build --release
sudo ./target/release/crosswalk
```

Use `--config config.example.toml` for a configuration file. Command-line options override the file. The terminal must be at least 110 columns by 24 rows.

## Running without sudo

Crosswalk needs privilege to capture packets. Grant just that to the binary once, then run it as yourself:

```sh
sudo setcap cap_net_raw+ep <path to the crosswalk binary>
```

Crosswalk does not run `setcap` for you. Without `cap_net_raw`, and with no `dumpcap` it may run, it prints this command and exits. Replacing the file clears the grant, so repeat the command after each build or install.

`cap_net_raw` lets Crosswalk capture packets, and it is the only capability Crosswalk uses. Crosswalk takes nothing into effect while it reads its configuration, uses `cap_net_raw` once to open the capture, then gives up every capability on every thread.

Without `sudo`, Crosswalk names only your own programs, and the header reads `apps (<user>)`. That is the ordinary state. Other users' traffic is counted as not attributed. With `sudo` the header reads `apps` and every user's programs are named.

The grant belongs to the file. Anyone who can write to the file can run their own code with this capability. For a hardened install, copy the binary to a root-owned place first:

```sh
sudo groupadd crosswalk
sudo usermod -aG crosswalk "$USER"
sudo install -o root -g crosswalk -m 0750 target/release/crosswalk /usr/local/bin/crosswalk
sudo setcap cap_net_raw+ep /usr/local/bin/crosswalk
```

The group takes effect at your next login. Repeat `install` and `setcap` after each build. Remove the grant with `sudo setcap -r <path>`.

The capability does not grant access to the kernel journal, to UFW's rule files or to firewalld's rules. The [manual](docs/manual.md#what-you-are-granting) covers all three, and what you see with and without `sudo`.

### Through Wireshark's dumpcap

If Wireshark's `dumpcap` is installed and your account may run it, a Crosswalk binary without `cap_net_raw` captures through it. Nothing is granted to Crosswalk, and nothing needs repeating after a build.

```sh
sudo usermod -aG wireshark "$USER"
```

Log in again afterwards. `newgrp` is not enough: Crosswalk then cannot name your own programs. The header reads `capture (dumpcap)` when packets come this way.

A binary that holds `cap_net_raw`, or runs under `sudo`, captures by itself. With neither way available, Crosswalk prints both and exits; its message names the group on your system.

## Keys

| Key | Action |
| --- | --- |
| `Tab` / `Shift-Tab` | Next or previous pane |
| `p` | Other page |
| `1`–`8` | Go to a pane |
| `Enter` / `Esc` | Zoom the pane / leave zoom |
| `j` `k` or `↓` `↑` | Move the selection |
| `/` | Search the pane |
| `m` | Network map |
| `i` | Next interface in Bandwidth |
| `n` | Reverse-DNS names on or off |
| `t` / `T` | Next or previous theme |
| `r` | Wi-Fi scan (the one key that transmits) |
| `?` | Help |
| `q` | Quit |

## Panes

Traffic page:

- **Bandwidth** (`1`): download and upload for one interface, as a chart.
- **App Traffic** (`2`): each app's destinations, with rates and totals.
- **Listening Ports** (`3`): local ports, their owners, and whether the firewall lets traffic in.
- **Firewall Rules** (`4`): UFW's default policies and rules, or firewalld's active zones.

Network & Firewall page:

- **Firewall Blocks** (`5`): inbound packets the firewall or the kernel refused.
- **Network Events** (`6`): changes in rules, ports, neighbours and connections.
- **Wi-Fi Networks** (`7`): access points in range.
- **Neighbors** (`8`): machines this computer has recently talked to.

Crosswalk reads UFW or firewalld, chosen once at startup, and the header names the one it reads: `firewall (ufw)`, `firewall (fwd)` for firewalld, or `firewall (none)`. A machine with neither is an ordinary state: the firewall panes say that no supported firewall was found, and the rest of the dashboard is unaffected. On most firewalld installs other than desktop ones an ordinary user may read only the zones' names, and `sudo` shows the rules. `--firewall-provider` (`auto`, `ufw`, `firewalld` or `none`) overrides the choice.

## More

- [docs/manual.md](docs/manual.md): every key and pane in full, the network map, limits, colours and themes, and a smoke checklist.
- [docs/firewall.md](docs/firewall.md): firewall setup, sources and diagnostics.

## Licence

MIT. See [LICENSE](LICENSE).

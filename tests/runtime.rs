use std::{
    collections::HashSet,
    collections::VecDeque,
    fs::File,
    io,
    net::{IpAddr, Ipv4Addr},
    os::fd::{AsRawFd, FromRawFd},
    process::{Command, Stdio},
    sync::{atomic::AtomicBool, mpsc::sync_channel},
    time::Duration,
};

use crosswalk::{
    collect::{
        capture::{CaptureSource, CaptureStatistics, CaptureWorker, PacketRead},
        interfaces::CollectionHealth,
    },
    firewall::{
        FirewallHealth, FirewallInput, FirewallProvider, FirewallStatus, InputRead, UfwProvider,
    },
    runtime::{DashboardEvent, EventPump, TerminalSession, local_addresses},
    state::{AppState, Pane, StateLimits},
    ui::{Overview, Theme, draw},
};
use ratatui::{Terminal, backend::TestBackend};

struct FixtureCapture(Option<Vec<u8>>);

impl CaptureSource for FixtureCapture {
    fn link_type(&self) -> i32 {
        276
    }

    fn next_packet(&mut self) -> Result<PacketRead, String> {
        self.0
            .take()
            .map(|data| PacketRead::Packet {
                data,
                captured_at: None,
            })
            .ok_or_else(|| "fixture capture failure".to_owned())
    }

    fn statistics(&mut self) -> Result<CaptureStatistics, String> {
        Ok(CaptureStatistics::default())
    }
}

struct FixtureFirewall(VecDeque<String>);

impl FirewallInput for FixtureFirewall {
    fn next_record(&mut self) -> io::Result<InputRead> {
        Ok(self
            .0
            .pop_front()
            .map_or(InputRead::Idle, InputRead::Record))
    }

    fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BurstCapture(VecDeque<Vec<u8>>);

impl CaptureSource for BurstCapture {
    fn link_type(&self) -> i32 {
        276
    }
    fn next_packet(&mut self) -> Result<PacketRead, String> {
        Ok(self
            .0
            .pop_front()
            .map_or(PacketRead::Idle, |data| PacketRead::Packet {
                data,
                captured_at: None,
            }))
    }
    fn statistics(&mut self) -> Result<CaptureStatistics, String> {
        Ok(CaptureStatistics::default())
    }
}

#[test]
fn fixture_workers_feed_all_four_real_renderers_and_source_failures_are_independent() {
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (sender, receiver) = sync_channel(4);
    let packet = sll2_tcp_packet();
    let mut capture =
        CaptureWorker::new(FixtureCapture(Some(packet)), HashSet::from([local]), 8).unwrap();
    let status = capture.poll(&sender, &AtomicBool::new(false));
    assert_eq!(status.packets_read, 1);

    let (events_sender, events_receiver) = sync_channel(4);
    events_sender
        .send(DashboardEvent::Traffic {
            at: Duration::from_secs(1),
            event: receiver.try_recv().unwrap(),
            process: None,
        })
        .unwrap();
    let record = r#"{"MESSAGE":"[UFW BLOCK] IN=eth-test OUT= SRC=198.51.100.8 DST=10.0.0.2 PROTO=TCP SPT=443 DPT=52344","__REALTIME_TIMESTAMP":"fixture-time"}"#;
    let mut provider = UfwProvider::new(
        FixtureFirewall(VecDeque::from([record.to_owned()])),
        FirewallHealth::AwaitingEvents,
        8,
        4096,
    )
    .unwrap();
    let (firewall_sender, firewall_receiver) = sync_channel(4);
    let firewall_status = provider.poll(&firewall_sender, &AtomicBool::new(false));
    events_sender
        .send(DashboardEvent::Firewall {
            at: Duration::from_secs(1),
            event: firewall_receiver.try_recv().unwrap(),
        })
        .unwrap();
    events_sender
        .send(DashboardEvent::CaptureStatus(status))
        .unwrap();
    events_sender
        .send(DashboardEvent::FirewallStatus(firewall_status))
        .unwrap();

    let mut state = AppState::new(StateLimits::default()).unwrap();
    let mut pump = EventPump::new(events_receiver);
    assert_eq!(pump.drain(&mut state, 16), 4);
    assert_eq!(
        state
            .blocked(crosswalk::collect::capture::Direction::Inbound)
            .len(),
        1
    );
    assert!(state.app_traffic().is_empty());
    assert!(
        state.app_traffic_unattributed().download + state.app_traffic_unattributed().upload > 0
    );
    assert_eq!(
        state.source_health().firewall.as_ref().unwrap().health,
        FirewallHealth::Available
    );

    // Both pages, so every renderer is drawn once.
    let mut rendered = String::new();
    for focus in [Pane::FirewallBlocks, Pane::Bandwidth] {
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal
            .draw(|frame| draw(frame, &state, &Theme::default(), &Overview::new(focus)))
            .unwrap();
        let buffer = terminal.backend().buffer();
        for y in 0..24 {
            rendered.extend((0..100).map(|x| buffer[(x, y)].symbol()));
            rendered.push('\n');
        }
    }
    for title in [
        "FIREWALL BLOCKS",
        "BANDWIDTH",
        "LISTENING PORTS",
        "APP TRAFFIC",
    ] {
        assert!(
            rendered.contains(title),
            "missing renderer for {title}: {rendered}"
        );
    }
    assert!(rendered.contains("firewall"));
    assert!(matches!(
        state.source_health().capture.as_ref().unwrap().health,
        crosswalk::collect::capture::CaptureHealth::Degraded(_)
    ));
}

#[test]
fn capture_queue_loss_reaches_application_state_and_frame_work_is_bounded() {
    let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut worker = CaptureWorker::new(
        BurstCapture(VecDeque::from([sll2_tcp_packet(), sll2_tcp_packet()])),
        HashSet::from([local]),
        8,
    )
    .unwrap();
    let (traffic_sender, _traffic_receiver) = sync_channel(1);
    let status = worker.poll(&traffic_sender, &AtomicBool::new(false));
    assert_eq!(status.delivery_dropped, 1);

    let (sender, receiver) = sync_channel(8);
    sender.send(DashboardEvent::CaptureStatus(status)).unwrap();
    sender
        .send(DashboardEvent::FirewallStatus(FirewallStatus {
            health: FirewallHealth::Available,
            records_read: 0,
            events_emitted: 0,
            malformed_records: 0,
            delivery_dropped: 0,
        }))
        .unwrap();
    let mut pump = EventPump::new(receiver);
    let mut state = AppState::new(StateLimits::default()).unwrap();
    assert_eq!(pump.drain(&mut state, 1), 1);
    assert_eq!(
        state
            .source_health()
            .capture
            .as_ref()
            .unwrap()
            .delivery_dropped,
        1
    );
    assert_eq!(pump.drain(&mut state, 1), 1);
}

fn sll2_tcp_packet() -> Vec<u8> {
    let mut packet = vec![0_u8; 20 + 40];
    packet[0..2].copy_from_slice(&0x0800_u16.to_be_bytes());
    packet[4..8].copy_from_slice(&2_u32.to_be_bytes());
    packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = &mut packet[20..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&40_u16.to_be_bytes());
    ip[9] = 6;
    ip[12..16].copy_from_slice(&[10, 0, 0, 2]);
    ip[16..20].copy_from_slice(&[198, 51, 100, 8]);
    ip[20..22].copy_from_slice(&52344_u16.to_be_bytes());
    ip[22..24].copy_from_slice(&443_u16.to_be_bytes());
    ip[32] = 0x50;
    packet
}

#[test]
fn terminal_session_subprocess() {
    let Ok(mode) = std::env::var("CROSSWALK_TERMINAL_CHILD") else {
        return;
    };
    if mode == "panic" {
        let _session = TerminalSession::enter().unwrap();
        panic!("controlled terminal panic");
    }
    let result = (|| -> io::Result<()> {
        let _session = TerminalSession::enter()?;
        if mode == "error" {
            return Err(io::Error::other("controlled terminal error"));
        }
        Ok(())
    })();
    if mode == "error" {
        assert!(result.is_err());
    } else {
        result.unwrap();
    }
}

#[test]
fn terminal_modes_and_alternate_screen_are_restored_in_subprocesses() {
    for mode in ["normal", "error", "panic"] {
        let mut master = -1;
        let mut slave = -1;
        let size = libc::winsize {
            ws_row: 28,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &size,
                )
            },
            0
        );
        let slave_file = unsafe { File::from_raw_fd(slave) };
        let duplicate = |fd| unsafe { File::from_raw_fd(libc::dup(fd)) };
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "terminal_session_subprocess", "--nocapture"])
            .env("CROSSWALK_TERMINAL_CHILD", mode)
            .stdin(Stdio::from(duplicate(slave_file.as_raw_fd())))
            .stdout(Stdio::from(duplicate(slave_file.as_raw_fd())))
            .stderr(Stdio::from(duplicate(slave_file.as_raw_fd())))
            .spawn()
            .unwrap();
        drop(slave_file);
        let status = child.wait().unwrap();
        assert_eq!(
            status.success(),
            mode != "panic",
            "unexpected child status for {mode}"
        );

        let mut settings = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(unsafe { libc::tcgetattr(master, &mut settings) }, 0);
        assert_ne!(
            settings.c_lflag & libc::ICANON,
            0,
            "canonical mode not restored for {mode}"
        );
        assert_ne!(
            settings.c_lflag & libc::ECHO,
            0,
            "echo not restored for {mode}"
        );

        let mut output = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = unsafe { libc::read(master, buffer.as_mut_ptr().cast(), buffer.len()) };
            if read <= 0 {
                break;
            }
            output.extend_from_slice(&buffer[..read as usize]);
        }
        let _ = unsafe { libc::close(master) };
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains("\u{1b}[?1049h"),
            "alternate screen not entered for {mode}"
        );
        assert!(
            output.contains("\u{1b}[?1049l"),
            "alternate screen not restored for {mode}"
        );
    }
}

#[test]
fn runnable_dashboard_exits_from_pty_and_restores_terminal() {
    let holds_net_raw = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| crosswalk::privileges::capabilities_from_status(&status))
        .is_none_or(|c| c.net_raw);
    if !holds_net_raw {
        eprintln!("skipped: without cap_net_raw the binary stops at the capability check");
        return;
    }
    let mut master = -1;
    let mut slave = -1;
    let size = libc::winsize {
        ws_row: 28,
        ws_col: 100,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size,
            )
        },
        0
    );
    let slave_file = unsafe { File::from_raw_fd(slave) };
    let duplicate = || unsafe { File::from_raw_fd(libc::dup(slave_file.as_raw_fd())) };
    let mut child = Command::new(env!("CARGO_BIN_EXE_crosswalk"))
        .stdin(Stdio::from(duplicate()))
        .stdout(Stdio::from(duplicate()))
        .stderr(Stdio::from(duplicate()))
        .spawn()
        .unwrap();
    drop(slave_file);
    assert_eq!(unsafe { libc::write(master, b"q\n".as_ptr().cast(), 2) }, 2);
    let mut completed = false;
    for _ in 0..100 {
        if child.try_wait().unwrap().is_some() {
            completed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !completed {
        let _ = child.kill();
        let _ = child.wait();
        panic!("dashboard did not process the quit key");
    }
    let status = child.wait().unwrap();
    assert!(status.success());

    let mut settings = unsafe { std::mem::zeroed::<libc::termios>() };
    assert_eq!(unsafe { libc::tcgetattr(master, &mut settings) }, 0);
    assert_ne!(settings.c_lflag & libc::ICANON, 0);
    assert_ne!(settings.c_lflag & libc::ECHO, 0);
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = unsafe { libc::read(master, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read <= 0 {
            break;
        }
        output.extend_from_slice(&buffer[..read as usize]);
    }
    let _ = unsafe { libc::close(master) };
    let output = String::from_utf8_lossy(&output);
    assert!(
        output.contains("\u{1b}[?1049l"),
        "dashboard did not leave the alternate screen"
    );
}

#[test]
fn the_pump_delivers_listeners_and_firewall_rules_to_the_state() {
    use crosswalk::{
        collect::{attribution::Listener, capture::Protocol},
        firewall::{Exposure, RuleSnapshot},
    };
    let (sender, receiver) = sync_channel(4);
    sender
        .send(DashboardEvent::Listeners {
            listeners: vec![Listener {
                protocol: Protocol::Tcp,
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 22,
                owners: Vec::new(),
            }],
            ephemeral: 32_768..=60_999,
        })
        .unwrap();
    sender
        .send(DashboardEvent::FirewallRules(RuleSnapshot::Inactive))
        .unwrap();
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let mut pump = EventPump::new(receiver);
    assert_eq!(pump.drain(&mut state, 16), 2);
    let ports = state.listening_ports();
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].listener.port, 22);
    assert_eq!(ports[0].exposure, Exposure::Unknown("ufw off".to_owned()));
}

#[test]
fn the_pump_delivers_a_neighbour_snapshot_to_the_state() {
    use crosswalk::collect::neighbors::NeighborSnapshot;
    let (sender, receiver) = sync_channel(4);
    sender
        .send(DashboardEvent::Neighbors(NeighborSnapshot::Unavailable(
            "no ip".to_owned(),
        )))
        .unwrap();
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let mut pump = EventPump::new(receiver);
    assert_eq!(pump.drain(&mut state, 16), 1);
    assert_eq!(state.neighbors().unwrap().unwrap_err(), "no ip");
}

#[test]
fn the_pump_delivers_a_wifi_snapshot_to_the_state() {
    use crosswalk::collect::wifi::WifiSnapshot;
    for snapshot in [
        WifiSnapshot::Unavailable("no nmcli".to_owned()),
        WifiSnapshot::Available(Vec::new()),
    ] {
        let (sender, receiver) = sync_channel(4);
        sender.send(DashboardEvent::Wifi(snapshot.clone())).unwrap();
        let mut state = AppState::new(StateLimits::default()).unwrap();
        let mut pump = EventPump::new(receiver);
        assert_eq!(pump.drain(&mut state, 16), 1);
        match snapshot {
            WifiSnapshot::Unavailable(_) => {
                assert_eq!(state.wifi().unwrap().unwrap_err(), "no nmcli")
            }
            WifiSnapshot::Available(_) => assert!(state.wifi().unwrap().unwrap().is_empty()),
        }
    }
}

mod hold {
    use std::{
        path::PathBuf,
        time::{Duration, Instant},
    };

    use crosswalk::{
        collect::{
            attribution::{
                AttributionHealth, AttributionResult, ExecutableIdentity, ProcessIdentity,
            },
            capture::{Direction, Endpoint, Protocol, ReadTiming, TrafficEvent},
        },
        runtime::{PacketHold, Released},
    };

    fn owner(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            executable: ExecutableIdentity {
                path: PathBuf::from("/opt/a"),
            },
            pid,
            start_time: 1,
            network_namespace: 7,
        }
    }

    fn packet(port: u16) -> TrafficEvent {
        TrafficEvent {
            source: Endpoint {
                ip: "10.0.0.2".parse().unwrap(),
                port: Some(port),
            },
            destination: Endpoint {
                ip: "198.51.100.1".parse().unwrap(),
                port: Some(443),
            },
            protocol: Protocol::Tcp,
            direction: Direction::Outbound,
            original_ip_bytes: 40,
            tcp_flags: None,
            limitation: None,
            timing: None,
        }
    }

    fn result(owner: Option<ProcessIdentity>, health: AttributionHealth) -> AttributionResult {
        AttributionResult {
            owner,
            health,
            incomplete: false,
        }
    }

    fn unowned() -> AttributionResult {
        result(None, AttributionHealth::Available)
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Admits an unowned packet that App Traffic would list.
    fn hold_one(hold: &mut PacketHold, port: u16) -> Option<TrafficEvent> {
        hold.admit(packet(port), &unowned(), false)
    }

    /// (time in ms, source port, owner pid)
    fn summary(events: Vec<Released>) -> Vec<(u128, u16, Option<u32>)> {
        events
            .into_iter()
            .map(|released| {
                (
                    released.at.as_millis(),
                    released.event.source.port.unwrap(),
                    released.process.map(|p| p.pid),
                )
            })
            .collect()
    }

    #[test]
    fn a_packet_owned_after_the_next_snapshot_is_delivered_once_with_that_owner() {
        let mut hold = PacketHold::new(8);
        assert!(hold_one(&mut hold, 5000).is_none());
        let released = hold.release(ms(3_100), |_| Some(owner(9)));
        assert_eq!(summary(released), vec![(3_100, 5000, Some(9))]);
        assert!(hold.release(ms(3_200), |_| Some(owner(9))).is_empty());
    }

    #[test]
    fn a_packet_still_unowned_after_the_next_snapshot_is_delivered_once_without_owner() {
        let mut hold = PacketHold::new(8);
        hold_one(&mut hold, 5000);
        assert_eq!(
            summary(hold.release(ms(3_100), |_| None)),
            vec![(3_100, 5000, None)]
        );
        assert!(hold.release(ms(3_200), |_| None).is_empty());
    }

    #[test]
    fn an_owned_packet_is_delivered_at_once_and_not_held() {
        let mut hold = PacketHold::new(8);
        let owned = result(Some(owner(4)), AttributionHealth::Available);
        assert!(hold.admit(packet(5000), &owned, false).is_some());
        assert!(hold.release(ms(100), |_| Some(owner(9))).is_empty());
    }

    #[test]
    fn a_left_out_packet_is_neither_held_nor_makes_a_snapshot_due() {
        let mut hold = PacketHold::new(8);
        hold.snapshot_taken(ms(1_000));
        assert!(hold.admit(packet(5000), &unowned(), true).is_some());
        assert!(!hold.snapshot_due(ms(1_100)));
        assert!(hold.release(ms(1_100), |_| Some(owner(9))).is_empty());
    }

    #[test]
    fn with_a_packet_held_the_next_snapshot_is_due_a_tenth_of_a_second_after_the_last() {
        let mut hold = PacketHold::new(8);
        hold.snapshot_taken(ms(1_000));
        hold_one(&mut hold, 5000);
        assert!(!hold.snapshot_due(ms(1_099)));
        assert!(hold.snapshot_due(ms(1_100)));
    }

    #[test]
    fn with_nothing_held_the_next_snapshot_is_due_after_a_second() {
        let mut hold = PacketHold::new(8);
        hold.snapshot_taken(ms(1_000));
        assert!(!hold.snapshot_due(ms(1_999)));
        assert!(hold.snapshot_due(ms(2_000)));
    }

    #[test]
    fn a_snapshot_is_due_before_any_has_been_taken() {
        assert!(PacketHold::new(8).snapshot_due(ms(0)));
    }

    #[test]
    fn past_the_limit_the_extra_packet_is_delivered_at_once_and_the_held_ones_are_kept() {
        let mut hold = PacketHold::new(2);
        assert!(hold_one(&mut hold, 5000).is_none());
        assert!(hold_one(&mut hold, 5001).is_none());
        assert!(hold_one(&mut hold, 5002).is_some());
        assert_eq!(
            summary(hold.release(ms(500), |_| Some(owner(9)))),
            vec![(500, 5000, Some(9)), (500, 5001, Some(9))]
        );
    }

    #[test]
    fn nothing_is_held_while_attribution_is_unavailable_or_stale() {
        let mut hold = PacketHold::new(8);
        for health in [
            AttributionHealth::Unavailable("x".into()),
            AttributionHealth::Stale("x".into()),
        ] {
            assert!(
                hold.admit(packet(5000), &result(None, health), false)
                    .is_some()
            );
        }
        assert!(hold.release(ms(100), |_| Some(owner(9))).is_empty());
    }

    #[test]
    fn a_failed_refresh_releases_what_is_held_without_owner() {
        let mut hold = PacketHold::new(8);
        hold_one(&mut hold, 5000);
        hold_one(&mut hold, 5001);
        assert_eq!(
            summary(hold.release(ms(2_000), |_| None)),
            vec![(2_000, 5000, None), (2_000, 5001, None)]
        );
    }

    #[test]
    fn a_released_packet_carries_the_release_time() {
        let mut hold = PacketHold::new(8);
        hold_one(&mut hold, 5000);
        let released = hold.release(ms(2_050), |_| Some(owner(9)));
        assert_eq!(summary(released), vec![(2_050, 5000, Some(9))]);
    }

    #[test]
    fn a_released_packet_reports_the_time_it_waited_since_it_was_read() {
        let mut hold = PacketHold::new(8);
        let mut held = packet(5000);
        held.timing = Some(ReadTiming {
            lag: None,
            read_at: Instant::now() - ms(250),
        });
        assert!(hold.admit(held, &unowned(), false).is_none());
        let released = hold.release(ms(2_050), |_| None);
        let waited = released[0].waited.unwrap();
        assert!(waited >= ms(250) && waited < ms(5_000), "{waited:?}");
    }

    #[test]
    fn a_released_packet_with_no_read_time_reports_no_wait() {
        let mut hold = PacketHold::new(8);
        hold_one(&mut hold, 5000);
        assert_eq!(hold.release(ms(2_050), |_| None)[0].waited, None);
    }
}

#[test]
fn the_pump_delivers_the_limited_attribution_mark_to_the_state() {
    use crosswalk::collect::attribution::{AttributionHealth, AttributionStatus};
    let (sender, receiver) = sync_channel(4);
    sender
        .send(DashboardEvent::Attribution(AttributionStatus {
            health: AttributionHealth::Available,
            incomplete: false,
            limited: true,
        }))
        .unwrap();
    let mut state = AppState::new(StateLimits::default()).unwrap();
    let mut pump = EventPump::new(receiver);
    assert_eq!(pump.drain(&mut state, 16), 1);
    assert!(state.source_health().attribution.as_ref().unwrap().limited);
}

#[test]
fn the_pump_delivers_a_scan_outcome_to_the_state() {
    use crosswalk::{collect::wifi::ScanOutcome, state::WifiScan};
    let (sender, receiver) = sync_channel(4);
    let mut pump = EventPump::new(receiver);
    let mut state = AppState::new(StateLimits::default()).unwrap();
    sender
        .send(DashboardEvent::WifiScan(ScanOutcome::Refused(
            "a scan was just done".to_owned(),
        )))
        .unwrap();
    pump.drain(&mut state, 8);
    assert!(matches!(
        state.wifi_scan(),
        Some(WifiScan::Refused { reason, .. }) if reason == "a scan was just done"
    ));
    sender
        .send(DashboardEvent::WifiScan(ScanOutcome::Accepted))
        .unwrap();
    pump.drain(&mut state, 8);
    assert!(matches!(state.wifi_scan(), Some(WifiScan::Requested(_))));
}

fn interface_snapshot(
    health: CollectionHealth,
    addresses: &[&str],
) -> crosswalk::collect::interfaces::InterfaceSnapshot {
    use crosswalk::collect::interfaces::{
        InterfaceAddress, InterfaceMeasurement, InterfaceSnapshot, InterfaceStatus,
    };
    InterfaceSnapshot {
        health,
        interfaces: vec![InterfaceMeasurement {
            name: "eth0".to_owned(),
            addresses: addresses
                .iter()
                .map(|address| InterfaceAddress {
                    ip: address.parse().unwrap(),
                    prefix: 24,
                })
                .collect(),
            download_bytes_per_second: 0.0,
            upload_bytes_per_second: 0.0,
            session_received_bytes: 0,
            session_transmitted_bytes: 0,
            status: InterfaceStatus::Available,
        }],
        default_route: None,
        gateway: None,
        name_server: None,
        name_servers: Vec::new(),
    }
}

#[test]
fn an_available_interface_reading_gives_its_addresses() {
    let snapshot = interface_snapshot(CollectionHealth::Available, &["10.0.0.9", "fe80::1"]);

    let expected: HashSet<IpAddr> = ["10.0.0.9", "fe80::1"]
        .iter()
        .map(|address| address.parse().unwrap())
        .collect();
    assert_eq!(local_addresses(&snapshot), Some(expected));
}

#[test]
fn an_interface_reading_that_failed_gives_no_addresses() {
    for health in [
        CollectionHealth::Unavailable("gone".to_owned()),
        CollectionHealth::Stale("gone".to_owned()),
    ] {
        assert_eq!(
            local_addresses(&interface_snapshot(health, &["10.0.0.9"])),
            None
        );
    }
}

#[test]
fn a_missing_interface_keeps_none_of_its_addresses() {
    use crosswalk::collect::interfaces::InterfaceStatus;
    let mut snapshot = interface_snapshot(CollectionHealth::Available, &["10.0.0.9"]);
    let mut gone = snapshot.interfaces[0].clone();
    gone.name = "wg0".to_owned();
    gone.status = InterfaceStatus::Missing;
    gone.addresses[0].ip = "10.8.0.2".parse().unwrap();
    snapshot.interfaces.push(gone);

    let expected: HashSet<IpAddr> = ["10.0.0.9".parse().unwrap()].into();
    assert_eq!(local_addresses(&snapshot), Some(expected));
}

use std::{
    io,
    time::{Duration, Instant},
};

use crossterm::event::{self, Event, KeyEventKind};
use crosswalk::{
    attribution_log::AttributionLog,
    capture_source::{CaptureChoice, choose_capture_source},
    collect::capture::CaptureOrigin,
    config::Config,
    dns::ReverseDns,
    privileges::{
        Capabilities, capabilities_from_status, give_up_everything, take_everything_out_of_effect,
    },
    runtime::{LiveWorkers, MAX_EVENTS_PER_FRAME, TerminalSession, event_channel},
    state::{AppState, StateLimits},
    ui::{Interaction, draw_interactive},
};
use ratatui::{Terminal, backend::CrosstermBackend};

fn main() {
    let capabilities = granted_capabilities();
    if let Err(error) = take_everything_out_of_effect() {
        eprintln!("crosswalk: {error}");
        std::process::exit(1);
    }
    let config = match Config::load_from(std::env::args_os()) {
        Ok(config) => config,
        Err(error) => error.exit(),
    };
    let origin = capture_origin(capabilities);
    if let Err(error) = run(config, origin) {
        eprintln!("crosswalk: {error}");
        std::process::exit(1);
    }
}

/// What the process was granted. `None` means the capabilities could not be determined;
/// startup carries on and the capture reports its own failure.
fn granted_capabilities() -> Option<Capabilities> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| capabilities_from_status(&status))
}

/// Where packets will come from, or exits with the fixes when they cannot be captured.
fn capture_origin(capabilities: Option<Capabilities>) -> CaptureOrigin {
    let binary = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "crosswalk".to_owned());
    match choose_capture_source(capabilities, &binary) {
        CaptureChoice::Own => CaptureOrigin::Own,
        CaptureChoice::Dumpcap => CaptureOrigin::Dumpcap,
        CaptureChoice::Stop(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}

fn run(config: Config, origin: CaptureOrigin) -> io::Result<()> {
    let attribution_log = config
        .attribution_log
        .as_deref()
        .map(AttributionLog::open)
        .transpose()?;
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut state = AppState::new(StateLimits::default())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut interaction = Interaction::with_names(config.reverse_dns)
        .with_theme(config.theme_name, &config.theme_overrides);
    let (sender, mut pump) = event_channel();
    let mut workers = LiveWorkers::start(&config, sender, attribution_log, origin);
    give_up_everything().map_err(io::Error::other)?;
    let mut dns = ReverseDns::default();
    dns.set_enabled(config.reverse_dns);
    let mut names_on = config.reverse_dns;
    let started = Instant::now();

    while !interaction.should_quit() {
        pump.drain(&mut state, MAX_EVENTS_PER_FRAME);
        let elapsed = started.elapsed();
        state.advance_time(elapsed);
        if interaction.names_on() != names_on {
            names_on = interaction.names_on();
            dns.set_enabled(names_on);
        }
        dns.poll();
        dns.schedule_visible(interaction.app_destinations_to_look_up(&state));
        let size = terminal.size()?;
        dns.schedule_visible(interaction.blocked_sources_to_look_up(&state, size.height));
        dns.schedule_visible(interaction.neighbors_to_look_up(&state, size.height));
        dns.schedule_visible(interaction.map_to_look_up(&state));
        terminal.draw(|frame| {
            draw_interactive(frame, &state, &config.theme, &mut interaction, Some(&dns))
        })?;

        if event::poll(Duration::from_millis(40))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            interaction.handle_key(key, &state);
            if interaction.take_scan_request() {
                workers.request_wifi_scan();
                state.record_wifi_scan_requested();
            }
        }
    }
    workers.stop();
    Ok(())
}

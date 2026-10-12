use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use crosswalk::{
    config::{Config, FirewallProvider, UfwSource},
    privileges::capabilities_from_status,
    ui::Theme,
};
use ratatui::style::Color;

mod common;

const BINARY: &str = env!("CARGO_BIN_EXE_crosswalk");

static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

fn crosswalk(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("crosswalk should run")
}

fn temporary_config(contents: &str) -> PathBuf {
    let file_id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "crosswalk-config-{}-{file_id}.toml",
        std::process::id()
    ));
    fs::write(&path, contents).expect("temporary configuration should be written");
    path
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn rejects_unknown_firewall_provider() {
    let output = crosswalk(&["--firewall-provider", "nftables"]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("unsupported firewall provider 'nftables'; expected 'ufw'"));
}

#[test]
fn command_line_values_override_file_values() {
    let path = temporary_config(
        "firewall_provider = \"nftables\"\nufw_source = \"invalid\"\nreverse_dns = false\n",
    );

    let cli_log = std::env::temp_dir().join("crosswalk-cli-ufw.log");
    let config = Config::load_from([
        "crosswalk",
        "--config",
        path.to_str().expect("temporary path should be UTF-8"),
        "--firewall-provider",
        "ufw",
        "--ufw-source",
        &format!("file:{}", cli_log.display()),
        "--reverse-dns",
    ])
    .expect("CLI overrides should make the configuration valid");

    fs::remove_file(path).expect("temporary configuration should be removed");
    assert_eq!(config.firewall_provider, FirewallProvider::Ufw);
    assert_eq!(config.ufw_source, UfwSource::File(cli_log));
    assert!(config.reverse_dns);
}

#[test]
fn missing_explicit_configuration_names_the_file() {
    let path = std::env::temp_dir().join("crosswalk-definitely-missing.toml");
    let output = crosswalk(&[
        "--config",
        path.to_str().expect("temporary path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("could not read configuration"));
    assert!(error.contains("crosswalk-definitely-missing.toml"));
}

#[test]
fn malformed_explicit_configuration_names_the_file_and_problem() {
    let path = temporary_config("reverse_dns = sometimes\n");
    let output = crosswalk(&[
        "--config",
        path.to_str().expect("temporary path should be UTF-8"),
    ]);

    fs::remove_file(&path).expect("temporary configuration should be removed");
    assert!(!output.status.success());
    let error = stderr(&output);
    assert!(error.contains("could not parse configuration"));
    assert!(error.contains(path.file_name().unwrap().to_str().unwrap()));
}

#[test]
fn rejects_invalid_ufw_source() {
    let output = crosswalk(&["--ufw-source", "syslog"]);

    assert!(!output.status.success());
    assert!(stderr(&output).contains("UFW source must be 'journal' or 'file:<path>'"));
}

#[test]
fn help_succeeds_without_privileges() {
    let output = crosswalk(&["--help"]);

    assert!(output.status.success(), "{}", stderr(&output));
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--firewall-provider"));
    assert!(help.contains("--ufw-source"));
    assert!(help.contains("--reverse-dns"));
}

fn theme_config(table: &str) -> Result<Config, clap::Error> {
    let path = temporary_config(table);
    let result = Config::load_from([
        "crosswalk",
        "--config",
        path.to_str().expect("temporary path should be UTF-8"),
    ]);
    fs::remove_file(path).expect("temporary configuration should be removed");
    result
}

#[test]
fn theme_entry_overrides_only_that_colour() {
    let config = theme_config("[theme]\ninbound = \"#102030\"\n").expect("theme should load");
    let defaults = Theme::default();

    assert_eq!(config.theme.inbound, Color::Rgb(0x10, 0x20, 0x30));
    assert_eq!(config.theme.outbound, defaults.outbound);
    assert_eq!(config.theme.background, defaults.background);
    assert_eq!(config.theme.danger, defaults.danger);
}

#[test]
fn theme_entry_for_highlight_is_read() {
    let config = theme_config("[theme]\nhighlight = \"#102030\"\n").expect("theme should load");

    assert_eq!(config.theme.highlight, Color::Rgb(0x10, 0x20, 0x30));
}

#[test]
fn unknown_theme_colour_name_is_an_error_naming_it() {
    let error = theme_config("[theme]\nchartreuse = \"#102030\"\n").expect_err("should fail");

    assert!(error.to_string().contains("chartreuse"), "{error}");
}

#[test]
fn invalid_theme_value_is_an_error_naming_key_and_value() {
    for value in ["red", "#12345", "#gg0000", "102030"] {
        let error = theme_config(&format!("[theme]\naccent = \"{value}\"\n"))
            .expect_err("invalid value should fail");
        let message = error.to_string();
        assert!(message.contains("accent"), "{message}");
        assert!(message.contains(value), "{message}");
    }
}

#[test]
fn default_theme_colours_are_all_24_bit() {
    let t = Theme::default();
    for color in [
        t.background,
        t.text,
        t.muted,
        t.inbound,
        t.outbound,
        t.accent,
        t.warning,
        t.danger,
        t.ok,
        t.highlight,
    ] {
        assert!(matches!(color, Color::Rgb(..)), "{color:?}");
    }
}

#[test]
fn example_config_loads_with_the_theme_table_uncommented() {
    let uncommented: String = include_str!("../config.example.toml")
        .lines()
        .map(|line| match line.strip_prefix("# ") {
            Some(rest) if rest == "[theme]" || rest.contains(" = \"#") => rest,
            _ => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(uncommented.contains("\n[theme]\n"), "{uncommented}");
    for name in [
        "background",
        "text",
        "muted",
        "inbound",
        "outbound",
        "accent",
        "warning",
        "danger",
        "ok",
        "highlight",
    ] {
        let prefix = format!("{name} = \"#");
        assert!(
            uncommented.lines().any(|line| line.starts_with(&prefix)),
            "{name} is missing or commented in the example:\n{uncommented}"
        );
    }

    let config = theme_config(&uncommented).expect("example config should load");

    assert_eq!(config.theme, Theme::default());
}

#[test]
fn attribution_log_is_absent_by_default_and_parsed_from_the_command_line() {
    assert_eq!(
        Config::load_from(["crosswalk"]).unwrap().attribution_log,
        None
    );
    let config = Config::load_from(["crosswalk", "--attribution-log", "/tmp/attribution.log"])
        .expect("option should parse");
    assert_eq!(
        config.attribution_log,
        Some(PathBuf::from("/tmp/attribution.log"))
    );
}

fn holds_net_raw() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| capabilities_from_status(&status))
        .is_none_or(|c| c.net_raw)
}

#[test]
fn an_attribution_log_that_cannot_be_opened_stops_startup_naming_the_file() {
    if !holds_net_raw() {
        eprintln!("skipped: without cap_net_raw startup stops at the capability check first");
        return;
    }
    let path = std::env::temp_dir().join("crosswalk-no-such-directory/attribution.log");
    let output = crosswalk(&[
        "--attribution-log",
        path.to_str().expect("temporary path should be UTF-8"),
    ]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains(path.to_str().unwrap()));
}

#[test]
fn without_net_raw_the_capability_check_stops_startup_before_the_attribution_log() {
    if holds_net_raw()
        || common::binary_is_granted_capabilities(BINARY)
        || common::dumpcap_is_runnable()
    {
        eprintln!("skipped: the binary would hold cap_net_raw or capture through dumpcap");
        return;
    }
    let path = std::env::temp_dir().join("crosswalk-no-such-directory/attribution.log");
    let output = crosswalk(&[
        "--attribution-log",
        path.to_str().expect("temporary path should be UTF-8"),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("cap_net_raw"));
    assert!(!stderr(&output).contains(path.to_str().unwrap()));
}

fn reverse_dns_with(file: &str, args: &[&str]) -> bool {
    let path = temporary_config(file);
    let mut argv = vec![
        "crosswalk",
        "--config",
        path.to_str().expect("temporary path should be UTF-8"),
    ];
    argv.extend_from_slice(args);
    let config = Config::load_from(argv).expect("configuration should load");
    fs::remove_file(path).expect("temporary configuration should be removed");
    config.reverse_dns
}

#[test]
fn reverse_dns_is_on_when_neither_command_line_nor_file_sets_it() {
    assert!(reverse_dns_with("", &[]));
}

#[test]
fn reverse_dns_false_on_the_command_line_turns_it_off() {
    assert!(!reverse_dns_with("", &["--reverse-dns", "false"]));
}

#[test]
fn reverse_dns_false_in_the_file_turns_it_off() {
    assert!(!reverse_dns_with("reverse_dns = false\n", &[]));
}

#[test]
fn reverse_dns_on_the_command_line_overrides_a_file_saying_false() {
    assert!(reverse_dns_with(
        "reverse_dns = false\n",
        &["--reverse-dns"]
    ));
}

#[test]
fn reverse_dns_false_on_the_command_line_overrides_a_file_saying_true() {
    assert!(!reverse_dns_with(
        "reverse_dns = true\n",
        &["--reverse-dns", "false"]
    ));
}

fn themed(args: &[&str], table: &str) -> Result<Config, clap::Error> {
    let path = temporary_config(table);
    let mut all = vec!["crosswalk", "--config", path.to_str().unwrap()];
    all.extend_from_slice(args);
    let result = Config::load_from(all);
    fs::remove_file(path).unwrap();
    result
}

#[test]
fn the_theme_is_synthwave_when_none_is_named() {
    let config = themed(&[], "").unwrap();

    assert_eq!(config.theme, Theme::default());
    assert_eq!(config.theme_name, "synthwave");
}

#[test]
fn a_name_in_the_theme_table_chooses_the_theme() {
    let config = themed(&[], "[theme]\nname = \"dracula\"\n").unwrap();

    assert_eq!(config.theme_name, "dracula");
    assert_eq!(config.theme.background, Color::Rgb(0x28, 0x2a, 0x36));
    assert_eq!(config.theme.accent, Color::Rgb(0xbd, 0x93, 0xf9));
}

#[test]
fn the_command_line_theme_wins_over_the_file() {
    let config = themed(&["--theme", "dracula"], "[theme]\nname = \"nord\"\n").unwrap();

    assert_eq!(config.theme_name, "dracula");
    assert_eq!(config.theme, Theme::named("dracula").unwrap());
}

#[test]
fn an_unknown_theme_name_is_an_error_naming_it_and_listing_the_twenty_five() {
    for error in [
        themed(&["--theme", "nope"], "").unwrap_err(),
        themed(&[], "[theme]\nname = \"nope\"\n").unwrap_err(),
    ] {
        let message = error.to_string();
        assert!(message.contains("nope"), "{message}");
        for name in Theme::NAMES {
            assert!(message.contains(name), "{message}");
        }
    }
}

#[test]
fn colour_overrides_sit_on_top_of_the_named_theme_and_of_any_other() {
    let config = themed(&[], "[theme]\nname = \"nord\"\naccent = \"#ffffff\"\n").unwrap();
    let white = Color::Rgb(255, 255, 255);

    assert_eq!(config.theme.accent, white);
    assert_eq!(
        config.theme.background,
        Theme::named("nord").unwrap().background
    );
    let gruvbox = Theme::named("gruvbox")
        .unwrap()
        .with_overrides(&config.theme_overrides);
    assert_eq!(gruvbox.accent, white);
    assert_eq!(
        gruvbox.background,
        Theme::named("gruvbox").unwrap().background
    );
}

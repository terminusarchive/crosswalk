use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::{Parser, error::ErrorKind};
use ratatui::style::Color;
use serde::Deserialize;

use crate::ui::{Theme, theme::parse_hex};

#[derive(Clone, Debug, PartialEq)]
pub enum FirewallProvider {
    Ufw,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UfwSource {
    Journal,
    File(PathBuf),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub firewall_provider: FirewallProvider,
    pub ufw_source: UfwSource,
    pub reverse_dns: bool,
    /// The theme the session starts with: the named one with the overrides on top.
    pub theme: Theme,
    /// The name of the theme the session starts with, the first `t` moves on from.
    pub theme_name: &'static str,
    /// The `[theme]` colours, kept on top of every theme `t` shows.
    pub theme_overrides: Vec<(&'static str, Color)>,
    /// Append a line for every packet listed under `unknown`, and one per
    /// socket snapshot, to this file.
    pub attribution_log: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(name = "crosswalk", about = "Live Linux network dashboard")]
struct Cli {
    /// Read configuration from this TOML file
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Firewall provider to use
    #[arg(long, value_name = "PROVIDER")]
    firewall_provider: Option<String>,

    /// UFW event source: journal or file:<path>
    #[arg(long, value_name = "SOURCE")]
    ufw_source: Option<String>,

    /// Enable or disable reverse-DNS lookups
    #[arg(long, value_name = "BOOL", num_args = 0..=1, default_missing_value = "true")]
    reverse_dns: Option<bool>,

    /// Built-in theme to start with
    #[arg(long, value_name = "NAME")]
    theme: Option<String>,

    /// Diagnostic: log why traffic is listed under unknown to this file
    #[arg(long, value_name = "FILE")]
    attribution_log: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    firewall_provider: Option<String>,
    ufw_source: Option<String>,
    reverse_dns: Option<bool>,
    theme: Option<ThemeFile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThemeFile {
    name: Option<String>,
    background: Option<String>,
    text: Option<String>,
    muted: Option<String>,
    inbound: Option<String>,
    outbound: Option<String>,
    accent: Option<String>,
    warning: Option<String>,
    danger: Option<String>,
    ok: Option<String>,
    highlight: Option<String>,
}

impl Config {
    pub fn load_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = Cli::try_parse_from(args)?;
        let file = match &cli.config {
            Some(path) => load_file(path)?,
            None => FileConfig::default(),
        };

        let provider = cli
            .firewall_provider
            .or(file.firewall_provider)
            .unwrap_or_else(|| "ufw".to_owned());
        let source = cli
            .ufw_source
            .or(file.ufw_source)
            .unwrap_or_else(|| "journal".to_owned());

        let (theme_name, theme_overrides) = build_theme(
            cli.theme.or_else(|| file.theme.as_ref()?.name.clone()),
            file.theme.unwrap_or_default(),
        )?;
        Ok(Self {
            firewall_provider: parse_provider(&provider)?,
            ufw_source: parse_ufw_source(&source)?,
            reverse_dns: cli.reverse_dns.or(file.reverse_dns).unwrap_or(true),
            theme: Theme::named(theme_name)
                .expect("build_theme returns a built-in name")
                .with_overrides(&theme_overrides),
            theme_name,
            theme_overrides,
            attribution_log: cli.attribution_log,
        })
    }
}

fn load_file(path: &Path) -> Result<FileConfig, clap::Error> {
    let contents = fs::read_to_string(path).map_err(|error| {
        validation_error(format!(
            "could not read configuration '{}': {error}",
            path.display()
        ))
    })?;

    toml::from_str(&contents).map_err(|error| {
        validation_error(format!(
            "could not parse configuration '{}': {error}",
            path.display()
        ))
    })
}

/// A built-in theme's name, and the colours the file overrides on top of it.
type ThemeChoice = (&'static str, Vec<(&'static str, Color)>);

/// The chosen built-in theme's name, and the colours the file overrides on top of it.
fn build_theme(chosen: Option<String>, file: ThemeFile) -> Result<ThemeChoice, clap::Error> {
    let chosen = chosen.unwrap_or_else(|| "synthwave".to_owned());
    let name = Theme::NAMES
        .into_iter()
        .find(|name| *name == chosen)
        .ok_or_else(|| {
            validation_error(format!(
                "unknown theme '{chosen}'; expected one of: {}",
                Theme::NAMES.join(", ")
            ))
        })?;
    let entries = [
        ("background", file.background),
        ("text", file.text),
        ("muted", file.muted),
        ("inbound", file.inbound),
        ("outbound", file.outbound),
        ("accent", file.accent),
        ("warning", file.warning),
        ("danger", file.danger),
        ("ok", file.ok),
        ("highlight", file.highlight),
    ];
    let mut overrides = Vec::new();
    for (colour, value) in entries {
        let Some(value) = value else { continue };
        let color = parse_hex(&value).ok_or_else(|| {
            validation_error(format!(
                "invalid theme colour {colour} = '{value}'; expected #rrggbb"
            ))
        })?;
        overrides.push((colour, color));
    }
    Ok((name, overrides))
}

fn parse_provider(value: &str) -> Result<FirewallProvider, clap::Error> {
    match value {
        "ufw" => Ok(FirewallProvider::Ufw),
        other => Err(validation_error(format!(
            "unsupported firewall provider '{other}'; expected 'ufw'"
        ))),
    }
}

fn parse_ufw_source(value: &str) -> Result<UfwSource, clap::Error> {
    if value == "journal" {
        return Ok(UfwSource::Journal);
    }

    if let Some(path) = value.strip_prefix("file:").filter(|path| !path.is_empty()) {
        return Ok(UfwSource::File(PathBuf::from(path)));
    }

    Err(validation_error(
        "UFW source must be 'journal' or 'file:<path>'",
    ))
}

fn validation_error(message: impl Into<String>) -> clap::Error {
    clap::Error::raw(ErrorKind::ValueValidation, message.into())
}

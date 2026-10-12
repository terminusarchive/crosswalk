//! Byte and rate formatting. Units are 1000-based (KB = 1,000 B).

const BYTE_UNITS: [&str; 4] = [" B", " KB", " MB", " GB"];
const COUNT_UNITS: [&str; 4] = ["", "k", "M", "G"];

pub fn format_bytes(bytes: u64) -> String {
    scale(bytes as f64, &BYTE_UNITS)
}

pub fn format_rate(bytes_per_second: f64) -> String {
    format!("{}/s", scale(bytes_per_second, &BYTE_UNITS))
}

/// A plain count the way bytes are written, without the unit: 340, 1.2k, 2.5M.
pub fn format_count(count: u64) -> String {
    scale(count as f64, &COUNT_UNITS)
}

fn scale(value: f64, units: &[&str; 4]) -> String {
    let mut value = value.max(0.0);
    let mut unit = 0;
    // Judge the rounded figure so 999,999 B reads 1.0 MB, not 1000.0 KB.
    while unit + 1 < units.len() && shown(value, unit) >= 1000.0 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{}{}", shown(value, 0), units[0])
    } else {
        format!("{value:.1}{}", units[unit])
    }
}

fn shown(value: f64, unit: usize) -> f64 {
    if unit == 0 {
        value.round()
    } else {
        (value * 10.0).round() / 10.0
    }
}

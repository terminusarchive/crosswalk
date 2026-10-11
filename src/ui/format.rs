//! Byte and rate formatting. Units are 1000-based (KB = 1,000 B).

const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];

pub fn format_bytes(bytes: u64) -> String {
    scale(bytes as f64)
}

pub fn format_rate(bytes_per_second: f64) -> String {
    format!("{}/s", scale(bytes_per_second))
}

fn scale(value: f64) -> String {
    let mut value = value.max(0.0);
    let mut unit = 0;
    // Judge the rounded figure so 999,999 B reads 1.0 MB, not 1000.0 KB.
    while unit + 1 < UNITS.len() && shown(value, unit) >= 1000.0 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} B", shown(value, 0))
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn shown(value: f64, unit: usize) -> f64 {
    if unit == 0 {
        value.round()
    } else {
        (value * 10.0).round() / 10.0
    }
}

//! The mirrored bandwidth chart: outbound rises from a centre line, inbound hangs below it.

use ratatui::{buffer::Buffer, layout::Rect, style::Style};

use super::{
    Theme,
    format::{format_bytes, format_rate},
};
use crate::state::{ByteTotals, RateSample};

/// Columns reserved on the left for labels, current rates and peaks.
pub const GUTTER_WIDTH: u16 = 18;

/// The right gutter, shown only when the plot keeps at least this many columns.
const MIN_PLOT_WITH_TOTALS: u16 = 20;

/// Cells in the totals bar: the gutter less its two blank columns.
const BAR_WIDTH: u16 = GUTTER_WIDTH - 2;

const BLOCKS: [&str; 8] = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

pub struct Chart<'a> {
    samples: &'a [RateSample],
    totals: ByteTotals,
    theme: &'a Theme,
}

impl<'a> Chart<'a> {
    /// `samples` are oldest first, as `AppState::rate_history` returns them.
    pub fn new(samples: &'a [RateSample], totals: ByteTotals, theme: &'a Theme) -> Self {
        Self {
            samples,
            totals,
            theme,
        }
    }

    /// Draws into `area`, which must be at least 3 rows tall to show anything.
    pub fn render(&self, buffer: &mut Buffer, area: Rect) {
        if area.height < 3 || area.width == 0 {
            return;
        }
        let up_rows = area.height / 2; // rows above the centre line (extra row goes here)
        let down_rows = area.height - 1 - up_rows;
        let centre = area.y + up_rows;

        let totals_shown = area.width.saturating_sub(2 * GUTTER_WIDTH) >= MIN_PLOT_WITH_TOTALS;
        let plot_width = area
            .width
            .saturating_sub(GUTTER_WIDTH * if totals_shown { 2 } else { 1 });
        let plot_x = area.x + area.width.min(GUTTER_WIDTH);
        let visible = &self.samples[self.samples.len().saturating_sub(plot_width as usize)..];

        let down_peak = visible.iter().map(|s| s.download).fold(0.0, f64::max);
        let up_peak = visible.iter().map(|s| s.upload).fold(0.0, f64::max);
        let newest = visible.last().copied().unwrap_or_default();

        let centre_style = Style::new().fg(self.theme.muted).bg(self.theme.background);
        for x in 0..plot_width {
            buffer[(plot_x + x, centre)]
                .set_symbol("─")
                .set_style(centre_style);
        }

        let first = plot_width as usize - visible.len();
        for (i, sample) in visible.iter().enumerate() {
            let x = plot_x + (first + i) as u16;
            let outbound = eighths(sample.upload, up_peak, up_rows);
            for row in 0..up_rows {
                let fill = cell_fill(outbound, row);
                if fill > 0 {
                    buffer[(x, centre - 1 - row)]
                        .set_symbol(BLOCKS[fill - 1])
                        .set_style(
                            Style::new()
                                .fg(self.theme.outbound)
                                .bg(self.theme.background),
                        );
                }
            }
            let inbound = eighths(sample.download, down_peak, down_rows);
            for row in 0..down_rows {
                let fill = cell_fill(inbound, row);
                let cell = &mut buffer[(x, centre + 1 + row)];
                match fill {
                    0 => {}
                    8 => {
                        cell.set_symbol("█").set_style(
                            Style::new()
                                .fg(self.theme.inbound)
                                .bg(self.theme.background),
                        );
                    }
                    // Filled from the top by `fill` eighths: the lower block of the
                    // complement, drawn over an inbound-coloured background.
                    _ => {
                        cell.set_symbol(BLOCKS[7 - fill]).set_style(
                            Style::new()
                                .fg(self.theme.background)
                                .bg(self.theme.inbound),
                        );
                    }
                }
            }
        }

        self.gutter(buffer, area, centre, newest, down_peak, up_peak);
        if totals_shown {
            let x = area.x + area.width - BAR_WIDTH;
            self.totals(buffer, x, area, centre);
        }
    }

    /// The right gutter: bytes sent on the first row, the split bar on the
    /// centre row, bytes received on the last. `x` is the bar's first column.
    fn totals(&self, buffer: &mut Buffer, x: u16, area: Rect, centre: u16) {
        let ByteTotals { upload, download } = self.totals;
        let background = self.theme.background;
        let mut line = |y: u16, label: &str, bytes: u64, colour| {
            let colour = if bytes > 0 { colour } else { self.theme.muted };
            let text = format!("{label:<7}{:>9}", format_bytes(bytes));
            buffer.set_string(x, y, text, Style::new().fg(colour).bg(background));
        };
        line(area.y, "↑ total", upload, self.theme.outbound);
        line(
            area.y + area.height - 1,
            "↓ total",
            download,
            self.theme.inbound,
        );
        let sum = upload as u128 + download as u128;
        let outbound = if sum == 0 {
            0
        } else {
            let nearest = (upload as u128 * BAR_WIDTH as u128 * 2 + sum) / (sum * 2);
            let clamped = if upload > 0 && download > 0 {
                nearest.clamp(1, BAR_WIDTH as u128 - 1)
            } else {
                nearest
            };
            clamped as u16
        };
        for cell in 0..BAR_WIDTH {
            let colour = match (sum, cell < outbound) {
                (0, _) => self.theme.muted,
                (_, true) => self.theme.outbound,
                (_, false) => self.theme.inbound,
            };
            buffer[(x + cell, centre)]
                .set_symbol("█")
                .set_style(Style::new().fg(colour).bg(background));
        }
    }

    fn gutter(
        &self,
        buffer: &mut Buffer,
        area: Rect,
        centre: u16,
        newest: RateSample,
        down_peak: f64,
        up_peak: f64,
    ) {
        let width = area.width.min(GUTTER_WIDTH) as usize;
        let mut line = |y: u16, label: &str, rate: f64, colour| {
            // A rate of zero is quiet so live numbers stand out.
            let colour = if rate > 0.0 { colour } else { self.theme.muted };
            let text = format!("{label:<6}{:>10}  ", format_rate(rate));
            buffer.set_stringn(
                area.x,
                y,
                text,
                width,
                Style::new().fg(colour).bg(self.theme.background),
            );
        };
        line(area.y, "↑ out", newest.upload, self.theme.outbound);
        if centre - area.y > 1 {
            line(area.y + 1, "peak", up_peak, self.theme.muted);
        }
        line(centre + 1, "↓ in", newest.download, self.theme.inbound);
        if area.y + area.height - centre - 1 > 1 {
            line(centre + 2, "peak", down_peak, self.theme.muted);
        }
    }
}

/// Bar height in eighths of a cell for a half `rows` tall; any non-zero value gets at least one.
fn eighths(value: f64, peak: f64, rows: u16) -> usize {
    if value <= 0.0 || peak <= 0.0 {
        return 0;
    }
    let total = rows as usize * 8;
    ((value / peak * total as f64).ceil() as usize).clamp(1, total)
}

/// How many eighths of the cell `row` steps from the centre line are filled.
fn cell_fill(eighths: usize, row: u16) -> usize {
    eighths.saturating_sub(row as usize * 8).min(8)
}

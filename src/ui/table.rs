//! The one table renderer shared by the overview panes and zoom.

use ratatui::{buffer::Buffer, layout::Rect, style::Style};

use super::Theme;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

/// A column. When the width is short the columns with the lowest `priority` go first.
#[derive(Clone, Debug)]
pub struct Column {
    pub title: String,
    pub align: Align,
    pub min_width: u16,
    pub priority: u8,
    /// 1 or 2 when the column takes the room the others leave: the first in
    /// line takes what it needs, the second the rest.
    pub fill: Option<u8>,
    /// The most a fixed column is given, for text that comes from outside.
    pub max_width: Option<u16>,
    /// The least a fixed column is given while there is room, so a column of
    /// live numbers does not change width as they do.
    pub least_width: Option<u16>,
    /// When a cell is cut to fit, cut it from the left, so the end shows.
    pub cut_left: bool,
    /// Blank cells before the column, beyond the one every column has.
    pub lead: u16,
}

impl Column {
    pub fn new(title: &str, align: Align, min_width: u16, priority: u8) -> Self {
        Self {
            title: title.into(),
            align,
            min_width,
            priority,
            fill: None,
            max_width: None,
            least_width: None,
            cut_left: false,
            lead: 0,
        }
    }

    /// Marks the column as taking the remaining room, `order` 1 first, 2 second.
    /// Its `min_width` is the least it is given.
    pub fn fill(mut self, order: u8) -> Self {
        self.fill = Some(order);
        self
    }

    /// Cuts a cell that does not fit from the left, `…` first.
    pub fn cut_from_left(mut self) -> Self {
        self.cut_left = true;
        self
    }

    /// Puts `blanks` more blank cells before the column. The room counts when
    /// columns are dropped; the cells' text is not touched.
    pub fn lead(mut self, blanks: u16) -> Self {
        self.lead = blanks;
        self
    }

    /// Keeps a fixed column at least `width` wide while there is room; a wider
    /// cell still widens it. The room reserved for dropping is still `min_width`.
    pub fn at_least(mut self, width: u16) -> Self {
        self.least_width = Some(width);
        self
    }

    /// Bounds a fixed column's width, or what a column that takes the room
    /// that is left asks for before the next such column gets the rest.
    pub fn at_most(mut self, width: u16) -> Self {
        self.max_width = Some(width);
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct Cell {
    pub text: String,
    pub style: Option<Style>,
    /// A style for each character of the text, over the cell's own.
    pub glyph_styles: Vec<Style>,
}

impl Cell {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            style: None,
            glyph_styles: Vec::new(),
        }
    }

    /// Styles each character of a text that is not cut or padded.
    pub fn glyph_styles(mut self, styles: Vec<Style>) -> Self {
        self.glyph_styles = styles;
        self
    }

    /// Overrides the row style for this cell.
    pub fn style(mut self, style: Style) -> Self {
        self.style = Some(style);
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct Row {
    pub cells: Vec<Cell>,
    pub style: Style,
}

impl Row {
    pub fn new<S: Into<String>>(cells: impl IntoIterator<Item = S>) -> Self {
        Self {
            cells: cells.into_iter().map(Cell::new).collect(),
            ..Self::default()
        }
    }

    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    pub fn matches(&self, needle: &str) -> bool {
        needle.is_empty()
            || self
                .cells
                .iter()
                .map(|c| c.text.as_str())
                .any(|t| t.to_lowercase().contains(needle))
    }
}

/// Keeps the rows holding `search` in some cell, ignoring case.
pub fn filter_rows(rows: Vec<Row>, search: &str) -> Vec<Row> {
    let needle = search.to_lowercase();
    rows.into_iter().filter(|r| r.matches(&needle)).collect()
}

/// What a render settled on, for the caller to keep between frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rendered {
    pub scroll: usize,
    /// The selection clamped to the matching rows.
    pub selected: Option<usize>,
    /// Rows left after the search.
    pub matched: usize,
    /// Rows the table has room to show under its header.
    pub visible: usize,
}

impl Rendered {
    /// What a pane with no table to show settles on.
    pub const EMPTY: Self = Self {
        scroll: 0,
        selected: None,
        matched: 0,
        visible: 0,
    };
}

pub struct Table<'a> {
    columns: &'a [Column],
    rows: &'a [Row],
    theme: &'a Theme,
    selected: Option<usize>,
    scroll: usize,
}

impl<'a> Table<'a> {
    pub fn new(columns: &'a [Column], rows: &'a [Row], theme: &'a Theme) -> Self {
        Self {
            columns,
            rows,
            theme,
            selected: None,
            scroll: 0,
        }
    }

    /// Index among the rows that match the search.
    pub fn selected(mut self, selected: Option<usize>) -> Self {
        self.selected = selected;
        self
    }

    pub fn scroll(mut self, scroll: usize) -> Self {
        self.scroll = scroll;
        self
    }

    pub fn render(&self, buf: &mut Buffer, area: Rect) -> Rendered {
        let rows: Vec<&Row> = self.rows.iter().collect();
        let body = (area.height as usize).saturating_sub(1);
        let selected = self.selected.map(|s| s.min(rows.len().saturating_sub(1)));
        let mut scroll = self.scroll.min(rows.len().saturating_sub(body.max(1)));
        if let Some(s) = selected.filter(|_| body > 0) {
            if s < scroll {
                scroll = s;
            } else if s >= scroll + body {
                scroll = s + 1 - body;
            }
        }
        let outcome = Rendered {
            scroll,
            selected,
            matched: rows.len(),
            visible: body,
        };
        if area.width == 0 || area.height == 0 {
            return outcome;
        }

        let (kept, widths) = self.layout(&rows, area.width);
        self.draw_line(
            buf,
            (area.x, area.y),
            (&kept, &widths),
            |i| (self.columns[i].title.as_str(), None, &[]),
            self.theme.table_header(),
        );
        for (n, row) in rows.iter().skip(scroll).take(body).enumerate() {
            let mut style = row.style;
            if selected == Some(scroll + n) {
                style =
                    style.patch(Style::default().bg(self.theme.selection().bg.unwrap_or_default()));
            }
            let y = area.y + 1 + n as u16;
            self.draw_line(
                buf,
                (area.x, y),
                (&kept, &widths),
                |i| {
                    row.cells.get(i).map_or(("", None, &[][..]), |c| {
                        (c.text.as_str(), c.style, c.glyph_styles.as_slice())
                    })
                },
                style,
            );
        }
        outcome
    }

    /// Chooses which columns fit and how wide each is.
    ///
    /// Which columns are kept depends only on the widths and priorities the
    /// columns declare (`min_width` is the room each reserves), never on the
    /// cells, so a column does not come and go as its contents change. The
    /// widths come from all the rows, so they hold still while scrolling.
    fn layout(&self, rows: &[&Row], width: u16) -> (Vec<usize>, Vec<u16>) {
        let mut kept: Vec<usize> = (0..self.columns.len()).collect();
        let need = |kept: &[usize]| -> u16 {
            kept.iter().map(|&i| self.columns[i].min_width).sum::<u16>() + self.gaps(kept)
        };
        while kept.len() > 1 && need(&kept) > width {
            let drop = (0..kept.len())
                .min_by_key(|&k| (self.columns[kept[k]].priority, std::cmp::Reverse(k)))
                .unwrap();
            kept.remove(drop);
        }
        let wanted = |i: usize| -> u16 {
            rows.iter()
                .filter_map(|r| r.cells.get(i))
                .map(|c| c.text.chars().count())
                .chain([self.columns[i].title.chars().count()])
                .chain(self.columns[i].least_width.map(usize::from))
                .max()
                .unwrap_or(0) as u16
        };
        let mut widths: Vec<u16>;
        if kept.len() == 1 {
            widths = vec![width];
        } else if kept.iter().all(|&i| self.columns[i].fill.is_none()) {
            // No column takes the rest: each starts at its minimum and grows
            // toward its contents while there is room.
            widths = kept.iter().map(|&i| self.columns[i].min_width).collect();
            let mut extra = width.saturating_sub(need(&kept));
            for (k, &i) in kept.iter().enumerate() {
                let grow = wanted(i).saturating_sub(widths[k]).min(extra);
                widths[k] += grow;
                extra -= grow;
            }
        } else {
            widths = self.fitted(&kept, width, &wanted);
        }
        (kept, widths)
    }

    /// Widths when some kept column takes the room the others leave: every
    /// other column is as wide as its contents (bounded by its `max_width`),
    /// the first marked column gets what it needs, the second the rest.
    fn fitted(&self, kept: &[usize], width: u16, wanted: &dyn Fn(usize) -> u16) -> Vec<u16> {
        let gaps = self.gaps(kept);
        let marked = |k: usize| self.columns[kept[k]].fill;
        let mut widths: Vec<u16> = kept
            .iter()
            .enumerate()
            .map(|(k, &i)| {
                let column = &self.columns[i];
                if marked(k).is_some() {
                    column.min_width
                } else {
                    wanted(i).min(column.max_width.unwrap_or(u16::MAX))
                }
            })
            .collect();
        // Cells wider than the reserved room give way, last column first,
        // when the minimums do not all fit.
        let mut over = (widths.iter().sum::<u16>() + gaps).saturating_sub(width);
        for k in (0..kept.len()).rev().filter(|&k| marked(k).is_none()) {
            let give = over.min(widths[k].saturating_sub(self.columns[kept[k]].min_width));
            widths[k] -= give;
            over -= give;
        }
        for (k, w) in widths.iter_mut().enumerate() {
            if marked(k).is_some() {
                *w = 0;
            }
        }
        let used: u16 = widths.iter().sum::<u16>() + gaps;
        let mut room = width.saturating_sub(used);
        let mut order: Vec<usize> = (0..kept.len()).filter(|&k| marked(k).is_some()).collect();
        order.sort_by_key(|&k| marked(k));
        let last = order.len().saturating_sub(1);
        for (n, &k) in order.iter().enumerate() {
            let grow = if n == last {
                room
            } else {
                // What it needs, but not so much that the next one falls
                // below its minimum.
                let next: u16 = order[n + 1..]
                    .iter()
                    .map(|&j| self.columns[kept[j]].min_width)
                    .sum();
                let column = &self.columns[kept[k]];
                let needs = wanted(kept[k])
                    .max(column.min_width)
                    .min(column.max_width.unwrap_or(u16::MAX));
                needs.min(room.saturating_sub(next))
            };
            widths[k] += grow;
            room -= grow;
        }
        widths
    }

    /// The blank cells between the kept columns.
    fn gaps(&self, kept: &[usize]) -> u16 {
        kept.iter().skip(1).map(|&i| 1 + self.columns[i].lead).sum()
    }

    fn draw_line<'t>(
        &self,
        buf: &mut Buffer,
        (x0, y): (u16, u16),
        (kept, widths): (&[usize], &[u16]),
        cell: impl Fn(usize) -> (&'t str, Option<Style>, &'t [Style]),
        style: Style,
    ) {
        let mut x = x0;
        for (k, &i) in kept.iter().enumerate() {
            let w = widths[k] as usize;
            let (text, own, glyphs) = cell(i);
            let text = if self.columns[i].cut_left {
                cut_left(text, w as u16)
            } else {
                fit(text, w)
            };
            let pad = w - text.chars().count();
            let text = match self.columns[i].align {
                Align::Left => format!("{text}{}", " ".repeat(pad)),
                Align::Right => format!("{}{text}", " ".repeat(pad)),
            };
            buf.set_stringn(x, y, &text, w, style.patch(own.unwrap_or_default()));
            for (n, glyph) in glyphs.iter().take(w).enumerate() {
                buf.set_style(Rect::new(x + n as u16, y, 1, 1), *glyph);
            }
            let next_lead = kept.get(k + 1).map_or(0, |&n| self.columns[n].lead);
            x += widths[k] + 1 + next_lead;
        }
    }
}

pub(super) fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else if width == 0 {
        String::new()
    } else {
        text.chars().take(width - 1).chain(['…']).collect()
    }
}

/// The text cut from the left to `width` cells, `…` first, so the end of a
/// path, which holds the program's name, stays.
pub fn cut_left(text: &str, width: u16) -> String {
    let (count, width) = (text.chars().count(), usize::from(width));
    if count <= width {
        return text.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let keep = width - 1;
    std::iter::once('…')
        .chain(text.chars().skip(count - keep))
        .collect()
}

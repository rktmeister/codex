use crate::line_truncation::line_width;
use crate::line_truncation::truncate_line_to_width;
use crate::line_truncation::truncate_line_with_ellipsis_if_overflow;
use pulldown_cmark::Alignment;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;

#[derive(Clone, Debug)]
pub(crate) struct MarkdownTableRow {
    pub(crate) cells: Vec<Line<'static>>,
    pub(crate) is_header: bool,
}

pub(crate) fn render_markdown_table(
    alignments: &[Alignment],
    rows: &[MarkdownTableRow],
    max_width: Option<usize>,
    border_style: Style,
    header_style: Style,
) -> Vec<Line<'static>> {
    if rows.is_empty() {
        return Vec::new();
    }

    let column_count = rows
        .iter()
        .map(|row| row.cells.len())
        .max()
        .unwrap_or(0)
        .max(alignments.len());
    if column_count == 0 {
        return Vec::new();
    }

    let mut column_widths = vec![1usize; column_count];
    for row in rows {
        for (idx, cell) in row.cells.iter().enumerate() {
            column_widths[idx] = column_widths[idx].max(line_width(cell));
        }
    }

    if let Some(max_width) = max_width {
        shrink_columns_to_fit(&mut column_widths, max_width);
    }

    let mut out = vec![render_border("┌", "┬", "┐", &column_widths, border_style)];

    for (row_index, row) in rows.iter().enumerate() {
        out.push(render_row(
            row,
            &column_widths,
            alignments,
            border_style,
            if row.is_header {
                Some(header_style)
            } else {
                None
            },
        ));

        if row.is_header && rows.get(row_index + 1).is_some() {
            out.push(render_border("├", "┼", "┤", &column_widths, border_style));
        }
    }

    out.push(render_border("└", "┴", "┘", &column_widths, border_style));
    out
}

fn shrink_columns_to_fit(column_widths: &mut [usize], max_width: usize) {
    while table_width(column_widths) > max_width {
        let Some((idx, width)) = column_widths
            .iter()
            .enumerate()
            .max_by_key(|(_, width)| **width)
        else {
            return;
        };
        if *width <= 1 {
            return;
        }
        column_widths[idx] -= 1;
    }
}

fn table_width(column_widths: &[usize]) -> usize {
    column_widths.iter().sum::<usize>() + column_widths.len() * 3 + 1
}

fn render_border(
    left: &str,
    middle: &str,
    right: &str,
    column_widths: &[usize],
    border_style: Style,
) -> Line<'static> {
    let mut spans = vec![Span::styled(left.to_string(), border_style)];
    for (idx, width) in column_widths.iter().enumerate() {
        spans.push(Span::styled("─".repeat(width + 2), border_style));
        if idx + 1 == column_widths.len() {
            spans.push(Span::styled(right.to_string(), border_style));
        } else {
            spans.push(Span::styled(middle.to_string(), border_style));
        }
    }
    Line::from(spans)
}

fn render_row(
    row: &MarkdownTableRow,
    column_widths: &[usize],
    alignments: &[Alignment],
    border_style: Style,
    cell_style: Option<Style>,
) -> Line<'static> {
    let mut spans = vec![Span::styled("│".to_string(), border_style)];
    for (idx, width) in column_widths.iter().enumerate() {
        spans.push(" ".into());
        spans.extend(padded_cell_spans(
            row.cells.get(idx).cloned().unwrap_or_default(),
            *width,
            alignments.get(idx).copied().unwrap_or(Alignment::None),
            cell_style,
        ));
        spans.push(" ".into());
        spans.push(Span::styled("│".to_string(), border_style));
    }
    Line::from(spans)
}

fn padded_cell_spans(
    line: Line<'static>,
    width: usize,
    alignment: Alignment,
    cell_style: Option<Style>,
) -> Vec<Span<'static>> {
    let mut line = if line_width(&line) > width {
        if width > 1 {
            truncate_line_with_ellipsis_if_overflow(line, width)
        } else {
            truncate_line_to_width(line, width)
        }
    } else {
        line
    };

    if let Some(cell_style) = cell_style {
        for span in &mut line.spans {
            span.style = span.style.patch(cell_style);
        }
    }

    let content_width = line_width(&line);
    let padding = width.saturating_sub(content_width);
    let (left_pad, right_pad) = match alignment {
        Alignment::Right => (padding, 0),
        Alignment::Center => (padding / 2, padding - (padding / 2)),
        Alignment::Left | Alignment::None => (0, padding),
    };

    let mut spans = Vec::new();
    if left_pad > 0 {
        spans.push(Span::from(" ".repeat(left_pad)));
    }
    spans.extend(line.spans);
    if right_pad > 0 {
        spans.push(Span::from(" ".repeat(right_pad)));
    }
    spans
}

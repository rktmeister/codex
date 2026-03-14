use crate::line_truncation::line_width;
use crate::line_truncation::truncate_line_to_width;
use crate::line_truncation::truncate_line_with_ellipsis_if_overflow;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;

pub(crate) fn render_markdown_code_block(
    lines: Vec<Line<'static>>,
    lang: Option<&str>,
    max_width: Option<usize>,
    border_style: Style,
    label_style: Style,
) -> Vec<Line<'static>> {
    let max_total_width = max_width.unwrap_or(usize::MAX);
    if max_total_width < 2 {
        return lines
            .into_iter()
            .map(|line| truncate_line_to_width(line, max_total_width))
            .collect();
    }

    let label = lang.map(|lang| {
        let label_line = Line::from(Span::styled(format!("[{lang}]"), label_style));
        truncate_line_with_ellipsis_if_overflow(label_line, max_total_width.saturating_sub(1))
    });
    let label_width = label.as_ref().map(line_width).unwrap_or(0);
    let max_content_width = max_total_width.saturating_sub(2);
    let widest_line = lines.iter().map(line_width).max().unwrap_or(0);
    let content_width = widest_line
        .max(label_width.saturating_sub(1))
        .min(max_content_width);

    let mut out = Vec::with_capacity(lines.len() + 2);
    out.push(render_top_border(label, border_style));

    for line in lines {
        out.push(render_content_line(line, content_width, border_style));
    }

    out.push(render_bottom_border(content_width, border_style));
    out
}

fn render_top_border(label: Option<Line<'static>>, border_style: Style) -> Line<'static> {
    let mut spans = vec![Span::styled("╭─".to_string(), border_style)];
    if let Some(label) = label {
        spans.extend(label.spans);
    }
    Line::from(spans)
}

fn render_content_line(
    line: Line<'static>,
    content_width: usize,
    border_style: Style,
) -> Line<'static> {
    let line = if line_width(&line) > content_width {
        if content_width > 1 {
            truncate_line_with_ellipsis_if_overflow(line, content_width)
        } else {
            truncate_line_to_width(line, content_width)
        }
    } else {
        line
    };

    let mut spans = vec![Span::styled("│ ".to_string(), border_style)];
    spans.extend(line.spans);
    Line::from(spans)
}

fn render_bottom_border(_content_width: usize, border_style: Style) -> Line<'static> {
    Line::from(Span::styled("╰─".to_string(), border_style))
}

use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;

use super::status_line_setup::StatusLineItem;

#[cfg(test)]
use ratatui::style::Modifier;

const SEGMENT_GAP: &str = "  ";
const REASONING_LEVELS: &[&str] = &["minimal", "low", "medium", "high", "xhigh", "default"];

pub(crate) fn format_status_line<I>(items: I) -> Option<Line<'static>>
where
    I: IntoIterator<Item = (StatusLineItem, String)>,
{
    let mut spans = Vec::new();

    for (idx, (item, value)) in items.into_iter().enumerate() {
        if idx > 0 {
            spans.push(SEGMENT_GAP.into());
        }
        spans.extend(status_line_segment(item, value));
    }

    if spans.is_empty() {
        None
    } else {
        Some(Line::from(spans))
    }
}

fn status_line_segment(item: StatusLineItem, value: String) -> Vec<Span<'static>> {
    match item {
        StatusLineItem::ModelName => vec!["◉ ".cyan(), Span::from(value).cyan().bold()],
        StatusLineItem::ModelWithReasoning => model_segment(value),
        StatusLineItem::CurrentDir => labeled_segment("cwd", value),
        StatusLineItem::ProjectRoot => vec!["⌂ ".dim(), value.into()],
        StatusLineItem::GitBranch => vec![" ".green(), Span::from(value).green()],
        StatusLineItem::BranchLinesAdded => vec![Span::from(format!("+{value}")).green()],
        StatusLineItem::BranchLinesRemoved => vec![Span::from(format!("-{value}")).red()],
        StatusLineItem::ContextUsage => vec![Span::from(value)],
        StatusLineItem::FiveHourLimit => limit_segment("5h", value),
        StatusLineItem::WeeklyLimit => limit_segment("week", value),
        StatusLineItem::CodexVersion => vec!["codex ".magenta(), Span::from(value).dim()],
        StatusLineItem::ContextWindowSize => labeled_segment("ctx", value),
        StatusLineItem::UsedTokens => labeled_segment("tok", value),
        StatusLineItem::TotalInputTokens => directional_segment("↑", value, Color::Green, " in"),
        StatusLineItem::TotalOutputTokens => directional_segment("↓", value, Color::Red, " out"),
        StatusLineItem::SessionId => vec!["# ".dim(), Span::from(value).dim()],
        StatusLineItem::FastMode => fast_mode_segment(value),
    }
}

fn model_segment(value: String) -> Vec<Span<'static>> {
    let mut spans = vec!["◉ ".cyan()];

    if let Some((model, reasoning)) = split_model_reasoning(&value) {
        spans.push(Span::from(model.to_string()).cyan().bold());
        spans.push(" ".into());
        spans.push(Span::from(reasoning.to_string()).cyan());
    } else {
        spans.push(Span::from(value).cyan().bold());
    }

    spans
}

fn labeled_segment(label: &'static str, value: String) -> Vec<Span<'static>> {
    vec![Span::from(format!("{label} ")).dim(), value.into()]
}

fn limit_segment(label: &'static str, value: String) -> Vec<Span<'static>> {
    let style = semantic_percent_style(extract_percent(&value), true);
    let percent = value
        .split_whitespace()
        .find(|part| part.ends_with('%'))
        .unwrap_or(value.as_str());
    vec![
        Span::from(format!("{label} ")).dim(),
        Span::styled(percent.to_string(), style),
    ]
}

fn directional_segment(
    icon: &'static str,
    value: String,
    color: Color,
    suffix: &'static str,
) -> Vec<Span<'static>> {
    let style = Style::default().fg(color);
    if let Some(amount) = value.strip_suffix(suffix) {
        vec![
            Span::styled(format!("{icon} "), style),
            Span::styled(amount.to_string(), style),
            Span::from(suffix.to_string()).dim(),
        ]
    } else {
        vec![
            Span::styled(format!("{icon} "), style),
            Span::styled(value, style),
        ]
    }
}

fn fast_mode_segment(value: String) -> Vec<Span<'static>> {
    let state = if value.eq_ignore_ascii_case("Fast on") {
        Span::from("on").green()
    } else if value.eq_ignore_ascii_case("Fast off") {
        Span::from("off").dim()
    } else {
        Span::from(value)
    };
    vec!["fast ".dim(), state]
}

fn split_model_reasoning(value: &str) -> Option<(&str, &str)> {
    let (model, reasoning) = value.rsplit_once(' ')?;
    REASONING_LEVELS
        .contains(&reasoning)
        .then_some((model, reasoning))
}

fn extract_percent(value: &str) -> Option<i64> {
    value.split_whitespace().find_map(|part| {
        let numeric = part.trim_end_matches('%');
        part.ends_with('%')
            .then(|| numeric.parse::<i64>().ok())
            .flatten()
    })
}

fn semantic_percent_style(percent: Option<i64>, positive_when_high: bool) -> Style {
    match (percent.unwrap_or_default(), positive_when_high) {
        (value, true) if value >= 50 => Style::default().green(),
        (value, true) if value >= 20 => Style::default().cyan(),
        (_, true) => Style::default().red(),
        (value, false) if value >= 80 => Style::default().red(),
        (value, false) if value >= 50 => Style::default().cyan(),
        (_, false) => Style::default().green(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn span_text(line: &Line<'static>) -> Vec<String> {
        line.spans
            .iter()
            .map(|span| span.content.to_string())
            .collect()
    }

    #[test]
    fn format_status_line_styles_reference_segments() {
        let line = format_status_line([
            (
                StatusLineItem::ModelWithReasoning,
                "gpt-5.3-codex xhigh".to_string(),
            ),
            (StatusLineItem::ContextUsage, "Context [█████]".to_string()),
            (StatusLineItem::ProjectRoot, "noumena".to_string()),
            (StatusLineItem::GitBranch, "launch/march6".to_string()),
            (StatusLineItem::BranchLinesAdded, "21770".to_string()),
            (StatusLineItem::BranchLinesRemoved, "2774".to_string()),
        ])
        .expect("line");

        assert_eq!(
            span_text(&line),
            vec![
                "◉ ".to_string(),
                "gpt-5.3-codex".to_string(),
                " ".to_string(),
                "xhigh".to_string(),
                "  ".to_string(),
                "Context [█████]".to_string(),
                "  ".to_string(),
                "⌂ ".to_string(),
                "noumena".to_string(),
                "  ".to_string(),
                " ".to_string(),
                "launch/march6".to_string(),
                "  ".to_string(),
                "+21770".to_string(),
                "  ".to_string(),
                "-2774".to_string(),
            ]
        );
        assert_eq!(line.spans[0].style.fg, Some(Color::Cyan));
        assert_eq!(line.spans[1].style.fg, Some(Color::Cyan));
        assert!(line.spans[1].style.add_modifier.contains(Modifier::BOLD));
        assert_eq!(line.spans[3].style.fg, Some(Color::Cyan));
        assert_eq!(line.spans[10].style.fg, Some(Color::Green));
        assert_eq!(line.spans[13].style.fg, Some(Color::Green));
        assert_eq!(line.spans[15].style.fg, Some(Color::Red));
    }

    #[test]
    fn format_status_line_formats_compact_metrics() {
        let line = format_status_line([
            (StatusLineItem::FiveHourLimit, "5h 72%".to_string()),
            (StatusLineItem::TotalInputTokens, "21.7K in".to_string()),
            (StatusLineItem::TotalOutputTokens, "2.8K out".to_string()),
            (StatusLineItem::FastMode, "Fast on".to_string()),
        ])
        .expect("line");

        assert_eq!(
            span_text(&line),
            vec![
                "5h ".to_string(),
                "72%".to_string(),
                "  ".to_string(),
                "↑ ".to_string(),
                "21.7K".to_string(),
                " in".to_string(),
                "  ".to_string(),
                "↓ ".to_string(),
                "2.8K".to_string(),
                " out".to_string(),
                "  ".to_string(),
                "fast ".to_string(),
                "on".to_string(),
            ]
        );
        assert!(line.spans[0].style.add_modifier.contains(Modifier::DIM));
        assert_eq!(line.spans[1].style.fg, Some(Color::Green));
        assert_eq!(line.spans[3].style.fg, Some(Color::Green));
        assert_eq!(line.spans[7].style.fg, Some(Color::Red));
        assert!(line.spans[11].style.add_modifier.contains(Modifier::DIM));
        assert_eq!(line.spans[12].style.fg, Some(Color::Green));
    }
}

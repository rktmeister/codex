use std::sync::Arc;
use std::sync::RwLock;

use crate::app_event::AppEvent;
use crate::bottom_pane::SelectionItem;
use crate::bottom_pane::SelectionViewParams;
use crate::bottom_pane::SideContentWidth;
use crate::bottom_pane::popup_consts::standard_popup_hint_line;
use crate::render::highlight;
use crate::render::renderable::Renderable;
use crate::text_formatting::truncate_text;
use crate::wrapping::RtOptions;
use crate::wrapping::word_wrap_lines;
use pulldown_cmark::CodeBlockKind;
use pulldown_cmark::Event;
use pulldown_cmark::Parser;
use pulldown_cmark::Tag;
use pulldown_cmark::TagEnd;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Widget;
use textwrap::WordSplitter;

const COPY_CODE_PREVIEW_GRAPHEMES: usize = 72;
const COPY_CODE_PREVIEW_WIDE_MIN_WIDTH: u16 = 32;
const COPY_CODE_PREVIEW_WIDE_WIDTH: u16 = 34;
const COPY_CODE_PREVIEW_NARROW_MAX_SOURCE_LINES: usize = 4;
const COPY_CODE_PREVIEW_WIDE_LEFT_INSET: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CopyableCodeBlock {
    pub(crate) language: Option<String>,
    pub(crate) code: String,
    pub(crate) line_count: usize,
    pub(crate) preview: String,
}

pub(crate) fn parse_fenced_code_blocks(markdown: &str) -> Vec<CopyableCodeBlock> {
    let parser = Parser::new(markdown);
    let mut blocks = Vec::new();
    let mut in_fenced_block = false;
    let mut current_language: Option<String> = None;
    let mut current_code = String::new();

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(info))) => {
                in_fenced_block = true;
                current_language = normalized_fence_language(info.as_ref());
                current_code.clear();
            }
            Event::End(TagEnd::CodeBlock) if in_fenced_block => {
                blocks.push(CopyableCodeBlock::new(
                    current_language.take(),
                    std::mem::take(&mut current_code),
                ));
                in_fenced_block = false;
            }
            Event::Text(text) if in_fenced_block => {
                current_code.push_str(&text);
            }
            _ => {}
        }
    }

    blocks
}

pub(crate) fn build_copy_code_picker_params(
    blocks: Vec<CopyableCodeBlock>,
    copy_hint: Option<String>,
) -> SelectionViewParams {
    let preview_state = CopyCodePreviewState::new(blocks.first().cloned());
    let preview_blocks = blocks.clone();
    let preview_state_for_selection = preview_state.clone();
    let items = blocks
        .into_iter()
        .enumerate()
        .map(|(idx, block)| {
            let line_label = format_line_count(block.line_count);
            let selected_description =
                format!("{line_label}. Press Enter to copy the raw code body.");
            let text = block.code.clone();
            let success_message = format!("Copied code block {} to clipboard.", idx + 1);
            let hint = copy_hint.clone();

            SelectionItem {
                name: block.preview,
                name_prefix_spans: code_block_prefix_spans(block.language.as_deref()),
                description: Some(line_label),
                selected_description: Some(selected_description),
                dismiss_on_select: true,
                actions: vec![Box::new(move |tx| {
                    tx.send(AppEvent::CopyTextToClipboard {
                        text: text.clone(),
                        success_message: success_message.clone(),
                        hint: hint.clone(),
                    });
                })],
                ..Default::default()
            }
        })
        .collect();

    let on_selection_changed = Some(Box::new(move |idx: usize, _tx: &_| {
        if let Some(block) = preview_blocks.get(idx).cloned() {
            preview_state_for_selection.set(block);
        }
    })
        as Box<dyn Fn(usize, &crate::app_event_sender::AppEventSender) + Send + Sync>);

    let footer_note = Line::from(vec![
        "Note: ".dim(),
        "copies the raw code body without surrounding fences or visual wrapping.".dim(),
    ]);

    SelectionViewParams {
        title: Some("Copy Code Block".to_string()),
        subtitle: Some("Select a fenced block from the latest completed output".to_string()),
        footer_note: Some(footer_note),
        footer_hint: Some(standard_popup_hint_line()),
        items,
        side_content: Box::new(CopyCodePreviewWideRenderable::new(preview_state.clone())),
        side_content_width: SideContentWidth::Fixed(COPY_CODE_PREVIEW_WIDE_WIDTH),
        side_content_min_width: COPY_CODE_PREVIEW_WIDE_MIN_WIDTH,
        stacked_side_content: Some(Box::new(CopyCodePreviewNarrowRenderable::new(
            preview_state,
        ))),
        on_selection_changed,
        ..Default::default()
    }
}

#[derive(Clone, Default)]
struct CopyCodePreviewState {
    selected: Arc<RwLock<Option<CopyableCodeBlock>>>,
}

impl CopyCodePreviewState {
    fn new(initial: Option<CopyableCodeBlock>) -> Self {
        Self {
            selected: Arc::new(RwLock::new(initial)),
        }
    }

    fn selected(&self) -> Option<CopyableCodeBlock> {
        self.selected.read().ok().and_then(|guard| guard.clone())
    }

    fn set(&self, block: CopyableCodeBlock) {
        if let Ok(mut selected) = self.selected.write() {
            *selected = Some(block);
        }
    }
}

struct CopyCodePreviewWideRenderable {
    state: CopyCodePreviewState,
}

impl CopyCodePreviewWideRenderable {
    fn new(state: CopyCodePreviewState) -> Self {
        Self { state }
    }
}

impl Renderable for CopyCodePreviewWideRenderable {
    fn render(&self, area: Rect, buf: &mut Buffer) {
        render_copy_code_preview(
            area,
            buf,
            &self.state,
            None,
            COPY_CODE_PREVIEW_WIDE_LEFT_INSET,
        );
    }

    fn desired_height(&self, _width: u16) -> u16 {
        u16::MAX
    }
}

struct CopyCodePreviewNarrowRenderable {
    state: CopyCodePreviewState,
}

impl CopyCodePreviewNarrowRenderable {
    fn new(state: CopyCodePreviewState) -> Self {
        Self { state }
    }
}

impl Renderable for CopyCodePreviewNarrowRenderable {
    fn render(&self, area: Rect, buf: &mut Buffer) {
        render_copy_code_preview(
            area,
            buf,
            &self.state,
            Some(COPY_CODE_PREVIEW_NARROW_MAX_SOURCE_LINES),
            0,
        );
    }

    fn desired_height(&self, width: u16) -> u16 {
        self.state
            .selected()
            .map(|block| {
                build_preview_lines(
                    &block,
                    width,
                    Some(COPY_CODE_PREVIEW_NARROW_MAX_SOURCE_LINES),
                )
                .len()
                .min(u16::MAX as usize) as u16
            })
            .unwrap_or(0)
    }
}

impl CopyableCodeBlock {
    fn new(language: Option<String>, code: String) -> Self {
        let preview_source = code
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("<empty block>");

        Self {
            language,
            line_count: code.lines().count(),
            preview: truncate_text(preview_source, COPY_CODE_PREVIEW_GRAPHEMES),
            code,
        }
    }
}

fn normalized_fence_language(info: &str) -> Option<String> {
    info.split([',', ' ', '\t'])
        .next()
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

fn code_block_prefix_spans(language: Option<&str>) -> Vec<Span<'static>> {
    language
        .map(|language| vec![format!("[{language}] ").dim()])
        .unwrap_or_default()
}

fn render_copy_code_preview(
    area: Rect,
    buf: &mut Buffer,
    state: &CopyCodePreviewState,
    max_source_lines: Option<usize>,
    left_inset: u16,
) {
    if area.height == 0 || area.width == 0 {
        return;
    }

    let Some(block) = state.selected() else {
        return;
    };

    let left_pad = left_inset.min(area.width.saturating_sub(1));
    let render_width = area.width.saturating_sub(left_pad);
    if render_width == 0 {
        return;
    }

    let lines = build_preview_lines(&block, render_width, max_source_lines);
    for (y, line) in (area.y..area.y.saturating_add(area.height)).zip(lines) {
        line.render(
            Rect::new(area.x.saturating_add(left_pad), y, render_width, 1),
            buf,
        );
    }
}

fn build_preview_lines(
    block: &CopyableCodeBlock,
    width: u16,
    max_source_lines: Option<usize>,
) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }

    let mut lines = vec![preview_header_line(block)];
    let rendered_source_lines = rendered_source_lines(block);
    let total_source_lines = rendered_source_lines.len();
    let visible_source_lines = max_source_lines.unwrap_or(total_source_lines);
    let line_number_width = total_source_lines.max(1).to_string().len();
    let continuation_indent = Line::from(" ".repeat(line_number_width + 1).dim());
    let wrap_options = RtOptions::new(width as usize)
        .subsequent_indent(continuation_indent)
        .word_splitter(WordSplitter::NoHyphenation);

    for (idx, code_line) in rendered_source_lines
        .into_iter()
        .take(visible_source_lines)
        .enumerate()
    {
        lines.extend(word_wrap_lines(
            [numbered_preview_line(idx + 1, line_number_width, code_line)],
            wrap_options.clone(),
        ));
    }

    if total_source_lines > visible_source_lines {
        lines.push(Line::from("…".dim()));
    }

    lines
}

fn preview_header_line(block: &CopyableCodeBlock) -> Line<'static> {
    let language = block
        .language
        .as_deref()
        .map(|language| format!("[{language}] "))
        .unwrap_or_else(|| "[code] ".to_string());
    vec![language.dim(), format_line_count(block.line_count).dim()].into()
}

fn rendered_source_lines(block: &CopyableCodeBlock) -> Vec<Line<'static>> {
    if block.code.is_empty() {
        return vec![Line::from("<empty block>".dim())];
    }

    if let Some(language) = block.language.as_deref()
        && let Some(lines) = highlight::highlight_code_to_styled_spans(&block.code, language)
    {
        return lines.into_iter().map(Line::from).collect();
    }

    block
        .code
        .lines()
        .map(|line| Line::from(line.to_string()))
        .collect()
}

fn numbered_preview_line(
    line_number: usize,
    line_number_width: usize,
    code_line: Line<'static>,
) -> Line<'static> {
    let mut spans = vec![format!("{line_number:>line_number_width$} ").dim()];
    spans.extend(code_line.spans);
    Line::from(spans)
}

fn format_line_count(line_count: usize) -> String {
    match line_count {
        1 => "1 line".to_string(),
        _ => format!("{line_count} lines"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_multiple_fenced_blocks() {
        let markdown = concat!(
            "before\n",
            "```bash\n",
            "echo hello\n",
            "```\n",
            "\n",
            "```rust,no_run\n",
            "fn main() {}\n",
            "```\n"
        );

        let blocks = parse_fenced_code_blocks(markdown);

        assert_eq!(
            blocks,
            vec![
                CopyableCodeBlock {
                    language: Some("bash".to_string()),
                    code: "echo hello\n".to_string(),
                    line_count: 1,
                    preview: "echo hello".to_string(),
                },
                CopyableCodeBlock {
                    language: Some("rust".to_string()),
                    code: "fn main() {}\n".to_string(),
                    line_count: 1,
                    preview: "fn main() {}".to_string(),
                },
            ]
        );
    }

    #[test]
    fn preserves_nested_fences_inside_outer_markdown_block() {
        let markdown = concat!(
            "````markdown\n",
            "```bash\n",
            "echo nested\n",
            "```\n",
            "````\n"
        );

        let blocks = parse_fenced_code_blocks(markdown);

        assert_eq!(
            blocks,
            vec![CopyableCodeBlock {
                language: Some("markdown".to_string()),
                code: "```bash\necho nested\n```\n".to_string(),
                line_count: 3,
                preview: "```bash".to_string(),
            }]
        );
    }

    #[test]
    fn empty_block_uses_placeholder_preview() {
        let blocks = parse_fenced_code_blocks("```text\n```\n");

        assert_eq!(
            blocks,
            vec![CopyableCodeBlock {
                language: Some("text".to_string()),
                code: String::new(),
                line_count: 0,
                preview: "<empty block>".to_string(),
            }]
        );
    }
}

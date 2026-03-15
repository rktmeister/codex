use crate::app_event::AppEvent;
use crate::bottom_pane::SelectionItem;
use crate::bottom_pane::SelectionViewParams;
use crate::bottom_pane::popup_consts::standard_popup_hint_line;
use crate::text_formatting::truncate_text;
use pulldown_cmark::CodeBlockKind;
use pulldown_cmark::Event;
use pulldown_cmark::Parser;
use pulldown_cmark::Tag;
use pulldown_cmark::TagEnd;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;

const COPY_CODE_PREVIEW_GRAPHEMES: usize = 72;

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
        ..Default::default()
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

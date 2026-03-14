---
summary: Current markdown rendering coverage in the Codex TUI and the implementation targets needed for richer terminal rendering.
read_when:
  - You are implementing or reviewing markdown rendering in the Codex TUI.
  - You need to know which markdown features already work in chat/history rendering.
  - You want a target list for richer GFM-like terminal markdown support.
---

# Markdown Render Gap Analysis

## Purpose

This document records:

- What markdown rendering already exists in the Codex TUI
- Where it is currently used in chat/history rendering
- Which markdown constructs are intentionally plain-text or unsupported
- A staged implementation target list for richer terminal rendering

This is not a greenfield area. The TUI already has a real markdown renderer and a streaming markdown pipeline.

## Existing Architecture

### Renderer

Core renderer:

- `codex-rs/tui/src/markdown_render.rs`

Current entry points:

- `render_markdown_text(...)`
- `render_markdown_text_with_width(...)`

Implementation notes:

- Uses `pulldown-cmark`
- Produces `ratatui::text::Text`
- Applies terminal styling for headings, emphasis, links, blockquotes, and code
- Supports width-aware wrapping

### Shared wrapper

Shared adapter used by higher-level UI code:

- `codex-rs/tui/src/markdown.rs`

Current helper:

- `append_markdown(markdown_source, width, lines)`

### Streaming path

Streaming markdown support already exists:

- `codex-rs/tui/src/markdown_stream.rs`
- `codex-rs/tui/src/streaming/mod.rs`
- `codex-rs/tui/src/streaming/controller.rs`

This means assistant message deltas are not rendered as raw plain text. They are accumulated and committed as markdown-aware lines.

### Chat/history integration

Markdown rendering is already wired into transcript/history surfaces:

- `codex-rs/tui/src/history_cell.rs`
- `codex-rs/tui/src/chatwidget.rs`

Concrete usage already present:

- Reasoning summary cells use markdown rendering
- Tooltip cells use markdown rendering
- Proposed plan cells use markdown rendering
- Streamed agent messages go through the markdown stream collector and stream controller

### Other current consumers

The transcript path is the main consumer, but it is not the only one.

- `codex-rs/tui/src/model_migration.rs`

Implication:

- Renderer changes can affect non-chat TUI surfaces too, so markdown snapshots should not be treated as transcript-only coverage

## Current Supported Behavior

The current renderer already supports a substantial markdown subset.

### Supported and styled

- Paragraphs
- Headings
- Emphasis
- Strong emphasis
- Combined strong + emphasis
- Strikethrough
- Inline code
- Blockquotes
- Ordered lists
- Unordered lists
- Nested lists
- Task list source remains readable as plain list text
- Links
- Autolinks
- File links with terminal-friendly label behavior
- Fenced code blocks
- Indented code blocks
- Syntax highlighting for known fenced languages
- Horizontal rules
- Hard and soft breaks
- Streaming-safe newline-gated rendering

Evidence in code/tests:

- Renderer styles and event handling in `codex-rs/tui/src/markdown_render.rs`
- Broad coverage in `codex-rs/tui/src/markdown_render_tests.rs`
- Chat-level vt100 snapshot in `codex-rs/tui/src/chatwidget/tests.rs`

## Gap Taxonomy

Not every markdown gap lives at the same layer.

### Parser-enable gaps

Current state:

- `render_markdown_text_with_width_and_cwd(...)` only enables `Options::ENABLE_STRIKETHROUGH`
- GFM-style table, footnote, and task-list-specific events are therefore not fully available to the renderer today

Why this matters:

- Tables are not just a layout problem; the renderer must first receive table structure
- Polished task-list checkboxes require task-list marker events, not just better list bullets
- Footnote rendering requires the parser to emit footnote references and definitions in the first place

### Renderer-richness gaps

Current state:

- Some constructs already reach the renderer but are ignored or rendered conservatively
- Images, HTML blocks, inline HTML, code-block info strings, and callout-like blockquote content fall into this bucket

Why this matters:

- These features can mostly be implemented inside `markdown_render.rs` once the desired terminal treatment is clear
- This is separate work from turning on more parser extensions

## Current Limitations

Several constructs are either unavailable as structured parser events today or are not yet elevated into richer terminal-specific rendering.

### Tables

Current state:

- Table parsing is not enabled in the current parser options
- Table-related tags are ignored structurally in the renderer
- Table source effectively falls through as line text instead of a real aligned table widget

Evidence:

- `render_markdown_text_with_width_and_cwd(...)` only inserts `Options::ENABLE_STRIKETHROUGH`
- `Tag::Table`, `Tag::TableHead`, `Tag::TableRow`, and `Tag::TableCell` are ignored in `codex-rs/tui/src/markdown_render.rs`
- The complex snapshot still shows pipe-table syntax literally

Impact:

- No column alignment
- No header styling
- No width-aware per-column layout

### Footnotes

Current state:

- Footnote parsing is not enabled in the current parser options
- Footnote references are ignored as structured events
- Footnote definitions are not rendered as special note blocks
- Footnote content mostly survives as ordinary text lines

Evidence:

- `render_markdown_text_with_width_and_cwd(...)` only inserts `Options::ENABLE_STRIKETHROUGH`
- `Event::FootnoteReference(_) => {}`
- `Tag::FootnoteDefinition(_) => {}`

Impact:

- No superscript-like markers
- No backreferences
- No visually grouped footnote section

### HTML blocks and inline HTML

Current state:

- Rendered verbatim, not interpreted

Impact:

- `<details>`, `<summary>`, `<kbd>`, `<sup>`, `<sub>`, and other HTML are displayed as literal tags
- Useful as fallback, but not “rich rendering”

### Images

Current state:

- Markdown image tags are ignored by the structural renderer
- In complex snapshots, only alt text survives as ordinary text

Impact:

- No inline image placeholder block
- No dedicated image treatment for markdown-authored images

### Fenced code block presentation

Current state:

- Fenced code blocks render their contents correctly
- Known languages can be syntax-highlighted
- The info string is used for highlighting lookup, but not surfaced as visible block chrome

Evidence:

- `Tag::CodeBlock(...)` extracts the info string language token for highlighting
- Current chat/widget snapshots show code content only, without a visible `[python]`-style language label or code block header

Impact:

- No visible language badge/header for fenced blocks
- No distinct code block container treatment beyond spacing and syntax color
- Screenshot-style markdown with explicit code block chrome is not yet matched

### List marker polish

Current state:

- Unordered lists render with a plain `- ` marker
- Ordered lists render correctly, but list presentation stays utilitarian
- Task list markers are still text-first rather than polished checkbox-like UI
- Task-list-specific parser support is not enabled yet, so checkbox rendering needs both parser and renderer work

Impact:

- The renderer lacks the more polished bullet glyph treatment seen in richer terminal markdown UIs
- Nested lists remain readable, but not especially screenshot-class
- List-heavy prose looks more functional than intentional

### GitHub callouts

Current state:

- No dedicated support for `> [!NOTE]`, `> [!TIP]`, etc.
- They will render as ordinary blockquotes at best

Impact:

- No semantic icons or colored callout treatments

### Mermaid and diagram fences

Current state:

- Mermaid fences are just fenced code blocks

Impact:

- No diagram layout or pseudo-rendering

### Collapsible sections

Current state:

- `<details>` / `<summary>` remain literal HTML

Impact:

- No collapsed/expanded UI semantics

### Terminal table or diff-specialization for markdown fences

Current state:

- Generic fenced code highlighting exists
- No special rendering for fenced `diff`, `mermaid`, or markdown-authored tables inside fenced blocks

### Other literal-source fallbacks visible in the existing snapshot

Observed today:

- Reference-style links and their definitions still show up literally in the complex snapshot
- Definition-list-like syntax remains ordinary text
- Some entity and escape examples remain source-like rather than normalized display text

Implication:

- The current renderer is intentionally conservative beyond the core prose/list/link/code path
- These items are worth tracking, but they are lower-priority than tables, callouts, code-block chrome, and task-list semantics if the goal is screenshot-class terminal markdown

## Practical Reading of Current State

The Codex TUI already has “real markdown rendering,” but it is closer to:

- Common prose markdown
- Lists and quotes
- Links and inline emphasis
- Styled code blocks

It is not yet a full GitHub-flavored terminal renderer for advanced constructs.

If the target is the screenshot-style experience with aligned tables, GitHub callouts, collapsibles, and richer block semantics, that work still needs to be built.

## Streaming Invariants Any Richer Renderer Must Preserve

The streaming pipeline constrains what "richer markdown" can look like.

- `MarkdownStreamCollector` renders the full accumulated buffer and only commits completed logical lines once a newline exists
- The stream snapshots `cwd` once so local file-link shortening stays stable across deltas and finalization
- Finalization appends a temporary trailing newline before the last render pass
- Commit bookkeeping is line-count-based, so already-committed lines should not oscillate as later deltas arrive

Practical consequence:

- Tables, callouts, and fenced blocks need stable intermediate behavior while the block is still incomplete
- A future richer renderer should avoid rewriting earlier committed lines after they have already been emitted to history
- Snapshot coverage must include both direct rendering and newline-gated streaming paths for any new block construct

## Target Tiers

Implementation should be staged. Do not try to ship “full markdown richness” in one pass.

### Tier 1: Tighten high-value terminal markdown

Recommended first target:

- Enable the parser features needed for the Tier 1 constructs
- Rich tables
- Better task list markers and list bullets
- Better fenced code block chrome and visible language labels
- Better markdown image placeholders
- Better file/link presentation where needed
- Preserve streaming behavior and wrapping correctness

Acceptance criteria:

- Required parser options for the tier are enabled deliberately, not implicitly
- Pipe tables render as aligned terminal tables
- Unordered lists and task lists use polished, consistent terminal markers
- Fenced code blocks can show a visible language label/header without regressing copy/paste behavior
- Table headers are visually distinct
- Narrow widths degrade predictably
- Existing chat/history streaming snapshots stay stable or are intentionally updated

### Tier 2: GitHub-ish semantic blocks

Recommended next target:

- GitHub callouts
- Footnote rendering
- Better HTML fallbacks for a small allowlist

Acceptance criteria:

- `> [!NOTE]` and related forms render as styled callout blocks
- Footnote parsing is enabled before renderer-specific footnote polish lands
- Footnote references and definitions have consistent terminal treatment
- Inline safe HTML like `<kbd>` can render more naturally than verbatim tags

### Tier 3: Advanced optional constructs

Only after the basics are solid:

- `<details>` / `<summary>` terminal treatment
- Mermaid fence handling
- Specialized `diff` fence rendering if markdown path should match existing diff UI more closely

Acceptance criteria:

- Advanced constructs degrade safely when a full renderer is not available
- No regressions in streaming or copy/paste behavior

## Recommended Implementation Targets

### Target 1: Tables

This is the clearest gap relative to the desired screenshot.

Approach:

- Enable table parsing in `pulldown-cmark` options before adding renderer table state
- Add explicit table state in `markdown_render.rs`
- Capture header and rows instead of ignoring table tags
- Compute terminal column widths from visible content widths
- Emit aligned `Line` output

Constraints:

- Must work with narrow widths
- Must not explode row height unpredictably
- Must preserve readable fallback on overflow

### Target 2: List marker polish

Approach:

- Replace plain unordered-list hyphen markers with a consistent bullet glyph treatment
- Enable task-list marker parsing if checkbox-like rendering is part of the same milestone
- Improve task list marker rendering in the same pass so bullets and checkboxes feel cohesive
- Keep marker width predictable so nested wrapping and indentation stay stable

Constraints:

- Must preserve alignment for nested and mixed ordered/unordered lists
- Must degrade safely if the chosen glyph is not well-supported by a terminal font
- Should not introduce wrapping regressions in streaming output

### Target 3: Fenced code block chrome

Approach:

- Preserve the current syntax-highlighting path
- Surface the normalized info-string language as an optional visible label/header
- Add lightweight block chrome so fenced code reads as a distinct block even without color

Constraints:

- Must not break copy/paste behavior for code content
- Must behave predictably for unknown or missing languages
- Streaming should not flicker badly while a fence is still incomplete

### Target 4: GitHub callouts

Approach:

- Detect blockquotes whose first line matches `[!TYPE]`
- Map `NOTE`, `TIP`, `IMPORTANT`, `WARNING`, `CAUTION`
- Render as styled prefixed blocks instead of plain blockquotes

Constraints:

- Nested blockquotes should still behave sensibly
- Streaming parser should not flicker badly while the marker is still incomplete

### Target 5: Footnotes

Approach:

- Enable footnote parsing in `pulldown-cmark` before adding renderer state
- Stop dropping footnote reference events
- Track definitions and references
- Render references inline with a compact terminal marker
- Render definitions as a dedicated notes section or inline note blocks

Constraints:

- Keep output deterministic
- Avoid complex cross-link navigation in the first pass

### Target 6: Safe HTML allowlist

Approach:

- Keep generic HTML verbatim by default
- Add a small allowlist for useful inline tags:
  - `kbd`
  - `sup`
  - `sub`

Constraints:

- Do not add an HTML parser that balloons complexity without clear payoff
- Unsupported tags should remain verbatim

### Target 7: Markdown image placeholders

Approach:

- Treat markdown image tags as terminal image placeholders or labeled blocks
- Reuse existing image-oriented UI conventions where possible

Constraints:

- Do not attempt inline terminal image protocols as part of markdown rendering
- Start with textual/image-placeholder rendering

## Suggested Worker Split

If this work is parallelized, use disjoint ownership.

### Worker 1: Renderer core

Owns only:

- `codex-rs/tui/src/markdown_render.rs`

Responsibilities:

- Table state
- List marker polish
- Fenced code block presentation
- Callout recognition
- Footnote state
- Safe HTML allowlist

### Worker 2: Tests and snapshots

Owns only:

- `codex-rs/tui/src/markdown_render_tests.rs`
- `codex-rs/tui/src/snapshots/...markdown...`
- Relevant chatwidget vt100 snapshots if rendering output changes there

Responsibilities:

- Add/update renderer tests
- Add representative complex fixture coverage
- Accept snapshot updates intentionally

### Worker 3: Integration surfaces

Owns only:

- `codex-rs/tui/src/markdown.rs`
- `codex-rs/tui/src/markdown_stream.rs`
- `codex-rs/tui/src/streaming/controller.rs`
- Minimal integration touchpoints if needed

Responsibilities:

- Ensure new rendering constructs behave correctly in streaming
- Prevent regressions in delta/finalize behavior

## Acceptance Criteria for “Screenshot-Class Markdown”

A reasonable target for screenshot-class support is:

- Headings, emphasis, links, inline code, and code blocks remain solid
- Unordered lists and task lists render with polished markers
- Pipe tables render as aligned tables
- Fenced code blocks can show a visible language label/header and distinct block treatment
- Blockquotes and GitHub callouts are visually distinct
- Safe inline HTML such as `kbd` renders acceptably
- Footnotes are not silently dropped as structure
- Advanced constructs like Mermaid degrade predictably when not fully supported

## Recommended First Milestone

Do this first:

- Tables
- Polished list and task markers
- Fenced code block chrome
- Callouts
- Tests + snapshots

That gives the biggest visible improvement with the lowest architectural risk.

## Files to Read Before Implementation

- `codex-rs/tui/src/markdown_render.rs`
- `codex-rs/tui/src/markdown_render_tests.rs`
- `codex-rs/tui/src/markdown.rs`
- `codex-rs/tui/src/markdown_stream.rs`
- `codex-rs/tui/src/streaming/controller.rs`
- `codex-rs/tui/src/history_cell.rs`
- `codex-rs/tui/src/chatwidget/tests.rs`

use crate::FreeformTool;
use crate::FreeformToolFormat;
use crate::JsonSchema;
use crate::ResponsesApiTool;
use crate::ToolSpec;
use std::collections::BTreeMap;

pub fn create_py_repl_tool() -> ToolSpec {
    // Keep Python input freeform while rejecting the most common malformed
    // wrapper shapes before they reach runtime validation.
    const PY_REPL_FREEFORM_GRAMMAR: &str = r#"
start: pragma_source | plain_source

pragma_source: PRAGMA_LINE NEWLINE py_source
plain_source: PLAIN_PY_SOURCE

py_source: PY_SOURCE

PRAGMA_LINE: /[ \t]*#[ \t]*codex-py-repl:[^\r\n]*/
NEWLINE: /\r?\n/
PLAIN_PY_SOURCE: /(?:\s*)(?:[^\s{\"'`]|#[^\r\n])[\s\S]*/
PY_SOURCE: /(?:\s*)(?:[^\s{\"'`]|#[^\r\n])[\s\S]*/
"#;

    ToolSpec::Freeform(FreeformTool {
        name: "py_repl".to_string(),
        description: "Runs Python in a persistent kernel with top-level await. This is a freeform tool: send raw Python source text, optionally with a first-line pragma like `# codex-py-repl: timeout_ms=15000`; do not send JSON/quotes/markdown fences."
            .to_string(),
        format: FreeformToolFormat {
            r#type: "grammar".to_string(),
            syntax: "lark".to_string(),
            definition: PY_REPL_FREEFORM_GRAMMAR.to_string(),
        },
    })
}

pub fn create_py_repl_reset_tool() -> ToolSpec {
    ToolSpec::Function(ResponsesApiTool {
        name: "py_repl_reset".to_string(),
        description:
            "Restarts the py_repl kernel for this run and clears persisted top-level bindings."
                .to_string(),
        strict: false,
        defer_loading: None,
        parameters: JsonSchema::Object {
            properties: BTreeMap::new(),
            required: None,
            additional_properties: Some(false.into()),
        },
        output_schema: None,
    })
}

#[cfg(test)]
#[path = "py_repl_tool_tests.rs"]
mod tests;

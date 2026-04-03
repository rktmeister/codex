use serde_json::Value as JsonValue;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::exec::ExecToolCallOutput;
use crate::exec::StreamOutput;
use crate::function_tool::FunctionCallError;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::events::ToolEmitter;
use crate::tools::events::ToolEventCtx;
use crate::tools::events::ToolEventFailure;
use crate::tools::events::ToolEventStage;
use crate::tools::handlers::parse_arguments;
use crate::tools::py_repl::PY_REPL_PRAGMA_PREFIX;
use crate::tools::py_repl::PyReplArgs;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use codex_features::Feature;
use codex_protocol::models::FunctionCallOutputContentItem;
use codex_protocol::protocol::ExecCommandSource;

pub struct PyReplHandler;
pub struct PyReplResetHandler;

fn join_outputs(stdout: &str, stderr: &str) -> String {
    if stdout.is_empty() {
        stderr.to_string()
    } else if stderr.is_empty() {
        stdout.to_string()
    } else {
        format!("{stdout}\n{stderr}")
    }
}

fn build_py_repl_exec_output(
    output: &str,
    error: Option<&str>,
    duration: Duration,
) -> ExecToolCallOutput {
    let stdout = output.to_string();
    let stderr = error.unwrap_or("").to_string();
    let aggregated_output = join_outputs(&stdout, &stderr);
    ExecToolCallOutput {
        exit_code: if error.is_some() { 1 } else { 0 },
        stdout: StreamOutput::new(stdout),
        stderr: StreamOutput::new(stderr),
        aggregated_output: StreamOutput::new(aggregated_output),
        duration,
        timed_out: false,
    }
}

async fn emit_py_repl_exec_begin(
    session: &crate::codex::Session,
    turn: &crate::codex::TurnContext,
    call_id: &str,
) {
    let emitter = ToolEmitter::shell(
        vec!["py_repl".to_string()],
        turn.cwd.to_path_buf(),
        ExecCommandSource::Agent,
        false,
    );
    let ctx = ToolEventCtx::new(session, turn, call_id, None);
    emitter.emit(ctx, ToolEventStage::Begin).await;
}

async fn emit_py_repl_exec_end(
    session: &crate::codex::Session,
    turn: &crate::codex::TurnContext,
    call_id: &str,
    output: &str,
    error: Option<&str>,
    duration: Duration,
) {
    let exec_output = build_py_repl_exec_output(output, error, duration);
    let emitter = ToolEmitter::shell(
        vec!["py_repl".to_string()],
        turn.cwd.to_path_buf(),
        ExecCommandSource::Agent,
        false,
    );
    let ctx = ToolEventCtx::new(session, turn, call_id, None);
    let stage = if error.is_some() {
        ToolEventStage::Failure(ToolEventFailure::Output(exec_output))
    } else {
        ToolEventStage::Success(exec_output)
    };
    emitter.emit(ctx, stage).await;
}

impl ToolHandler for PyReplHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    fn matches_kind(&self, payload: &ToolPayload) -> bool {
        matches!(
            payload,
            ToolPayload::Function { .. } | ToolPayload::Custom { .. }
        )
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            tracker,
            payload,
            call_id,
            ..
        } = invocation;

        if !session.features().enabled(Feature::PyRepl) {
            return Err(FunctionCallError::RespondToModel(
                "py_repl is disabled by feature flag".to_string(),
            ));
        }

        let args = match payload {
            ToolPayload::Function { arguments } => parse_arguments(&arguments)?,
            ToolPayload::Custom { input } => parse_freeform_args(&input)?,
            _ => {
                return Err(FunctionCallError::RespondToModel(
                    "py_repl expects custom or function payload".to_string(),
                ));
            }
        };

        let manager = turn.py_repl.manager().await?;
        let started_at = Instant::now();
        emit_py_repl_exec_begin(session.as_ref(), turn.as_ref(), &call_id).await;
        let result = manager
            .execute(Arc::clone(&session), Arc::clone(&turn), tracker, args)
            .await;
        let result = match result {
            Ok(result) => result,
            Err(err) => {
                let message = err.to_string();
                emit_py_repl_exec_end(
                    session.as_ref(),
                    turn.as_ref(),
                    &call_id,
                    "",
                    Some(&message),
                    started_at.elapsed(),
                )
                .await;
                return Err(err);
            }
        };

        let content = result.output;
        let mut items = Vec::with_capacity(result.content_items.len() + 1);
        if !content.is_empty() {
            items.push(FunctionCallOutputContentItem::InputText {
                text: content.clone(),
            });
        }
        items.extend(result.content_items);

        emit_py_repl_exec_end(
            session.as_ref(),
            turn.as_ref(),
            &call_id,
            &content,
            None,
            started_at.elapsed(),
        )
        .await;

        if items.is_empty() {
            Ok(FunctionToolOutput::from_text(content, Some(true)))
        } else {
            Ok(FunctionToolOutput::from_content(items, Some(true)))
        }
    }
}

impl ToolHandler for PyReplResetHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        if !invocation.session.features().enabled(Feature::PyRepl) {
            return Err(FunctionCallError::RespondToModel(
                "py_repl is disabled by feature flag".to_string(),
            ));
        }

        let manager = invocation.turn.py_repl.manager().await?;
        manager.reset().await?;
        Ok(FunctionToolOutput::from_text(
            "py_repl kernel reset".to_string(),
            Some(true),
        ))
    }
}

fn parse_freeform_args(input: &str) -> Result<PyReplArgs, FunctionCallError> {
    if input.trim().is_empty() {
        return Err(FunctionCallError::RespondToModel(
            "py_repl expects raw Python tool input (non-empty). Provide Python source text, optionally with first-line `# codex-py-repl: ...`."
                .to_string(),
        ));
    }

    let mut args = PyReplArgs {
        code: input.to_string(),
        timeout_ms: None,
    };

    let mut lines = input.splitn(2, '\n');
    let first_line = lines.next().unwrap_or_default();
    let rest = lines.next().unwrap_or_default();
    let trimmed = first_line.trim_start();
    let Some(pragma) = trimmed.strip_prefix(PY_REPL_PRAGMA_PREFIX) else {
        reject_json_or_quoted_source(&args.code)?;
        return Ok(args);
    };

    let mut timeout_ms: Option<u64> = None;
    let directive = pragma.trim();
    if !directive.is_empty() {
        for token in directive.split_whitespace() {
            let (key, value) = token.split_once('=').ok_or_else(|| {
                FunctionCallError::RespondToModel(format!(
                    "py_repl pragma expects space-separated key=value pairs (supported keys: timeout_ms); got `{token}`"
                ))
            })?;
            match key {
                "timeout_ms" => {
                    if timeout_ms.is_some() {
                        return Err(FunctionCallError::RespondToModel(
                            "py_repl pragma specifies timeout_ms more than once".to_string(),
                        ));
                    }
                    let parsed = value.parse::<u64>().map_err(|_| {
                        FunctionCallError::RespondToModel(format!(
                            "py_repl pragma timeout_ms must be an integer; got `{value}`"
                        ))
                    })?;
                    timeout_ms = Some(parsed);
                }
                _ => {
                    return Err(FunctionCallError::RespondToModel(format!(
                        "py_repl pragma only supports timeout_ms; got `{key}`"
                    )));
                }
            }
        }
    }

    if rest.trim().is_empty() {
        return Err(FunctionCallError::RespondToModel(
            "py_repl pragma must be followed by Python source on subsequent lines".to_string(),
        ));
    }

    reject_json_or_quoted_source(rest)?;
    args.code = rest.to_string();
    args.timeout_ms = timeout_ms;
    Ok(args)
}

fn reject_json_or_quoted_source(code: &str) -> Result<(), FunctionCallError> {
    let trimmed = code.trim();
    if trimmed.starts_with("```") {
        return Err(FunctionCallError::RespondToModel(
            "py_repl expects raw Python source, not markdown code fences. Resend plain Python only (optional first line `# codex-py-repl: ...`)."
                .to_string(),
        ));
    }
    let Ok(value) = serde_json::from_str::<JsonValue>(trimmed) else {
        return Ok(());
    };
    match value {
        JsonValue::Object(_) | JsonValue::String(_) => Err(FunctionCallError::RespondToModel(
            "py_repl is a freeform tool and expects raw Python source. Resend plain Python only (optional first line `# codex-py-repl: ...`); do not send JSON (`{\"code\":...}`), quoted code, or markdown fences."
                .to_string(),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pretty_assertions::assert_eq;

    use super::parse_freeform_args;
    use crate::codex::make_session_and_context_with_rx;
    use codex_protocol::protocol::EventMsg;
    use codex_protocol::protocol::ExecCommandSource;

    #[test]
    fn parse_freeform_args_without_pragma() {
        let args = parse_freeform_args("print('ok')").expect("parse args");
        assert_eq!(args.code, "print('ok')");
        assert_eq!(args.timeout_ms, None);
    }

    #[test]
    fn parse_freeform_args_with_pragma() {
        let input = "# codex-py-repl: timeout_ms=15000\nprint('ok')";
        let args = parse_freeform_args(input).expect("parse args");
        assert_eq!(args.code, "print('ok')");
        assert_eq!(args.timeout_ms, Some(15_000));
    }

    #[test]
    fn parse_freeform_args_rejects_unknown_key() {
        let err = parse_freeform_args("# codex-py-repl: nope=1\nprint('ok')")
            .expect_err("expected error");
        assert_eq!(
            err.to_string(),
            "py_repl pragma only supports timeout_ms; got `nope`"
        );
    }

    #[test]
    fn parse_freeform_args_rejects_json_wrapped_code() {
        let err = parse_freeform_args(r#"{"code":"print('ok')"}"#).expect_err("expected error");
        assert_eq!(
            err.to_string(),
            "py_repl is a freeform tool and expects raw Python source. Resend plain Python only (optional first line `# codex-py-repl: ...`); do not send JSON (`{\"code\":...}`), quoted code, or markdown fences."
        );
    }

    #[tokio::test]
    async fn emit_py_repl_exec_end_sends_event() {
        let (session, turn, rx) = make_session_and_context_with_rx().await;
        super::emit_py_repl_exec_end(
            session.as_ref(),
            turn.as_ref(),
            "call-1",
            "hello",
            None,
            Duration::from_millis(12),
        )
        .await;

        let event = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = rx.recv().await.expect("event");
                if let EventMsg::ExecCommandEnd(end) = event.msg {
                    break end;
                }
            }
        })
        .await
        .expect("timed out waiting for exec end");

        assert_eq!(event.call_id, "call-1");
        assert_eq!(event.turn_id, turn.sub_id);
        assert_eq!(event.command, vec!["py_repl".to_string()]);
        assert_eq!(event.cwd, turn.cwd.to_path_buf());
        assert_eq!(event.source, ExecCommandSource::Agent);
        assert_eq!(event.interaction_input, None);
        assert_eq!(event.stdout, "hello");
        assert_eq!(event.stderr, "");
        assert!(event.aggregated_output.contains("hello"));
    }
}

use super::parse_arguments;
use crate::codex::Session;
use crate::codex::TurnContext;
use crate::exec::ExecToolCallOutput;
use crate::exec::StreamOutput;
use crate::function_tool::FunctionCallError;
use crate::protocol::ExecCommandSource;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolPayload;
use crate::tools::events::ToolEmitter;
use crate::tools::events::ToolEventCtx;
use crate::tools::events::ToolEventFailure;
use crate::tools::events::ToolEventStage;
use codex_protocol::models::FunctionCallOutputContentItem;
use serde::Deserialize;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

pub(super) fn parse_repl_payload<T, F>(
    payload: ToolPayload,
    tool_name: &str,
    parse_freeform_args: F,
) -> Result<T, FunctionCallError>
where
    T: for<'de> Deserialize<'de>,
    F: FnOnce(&str) -> Result<T, FunctionCallError>,
{
    match payload {
        ToolPayload::Function { arguments } => parse_arguments(&arguments),
        ToolPayload::Custom { input } => parse_freeform_args(&input),
        _ => Err(FunctionCallError::RespondToModel(format!(
            "{tool_name} expects custom or function payload"
        ))),
    }
}

pub(super) async fn run_repl_tool_execution<Fut>(
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    call_id: &str,
    tool_name: &'static str,
    execute: Fut,
) -> Result<FunctionToolOutput, FunctionCallError>
where
    Fut: Future<Output = Result<ReplExecutionResult, FunctionCallError>>,
{
    let started_at = Instant::now();
    emit_repl_exec_begin(session.as_ref(), turn.as_ref(), call_id, tool_name).await;

    let result = execute.await;
    let result = match result {
        Ok(result) => result,
        Err(err) => {
            let message = err.to_string();
            emit_repl_exec_end(
                session.as_ref(),
                turn.as_ref(),
                call_id,
                tool_name,
                "",
                Some(&message),
                started_at.elapsed(),
            )
            .await;
            return Err(err);
        }
    };

    emit_repl_exec_end(
        session.as_ref(),
        turn.as_ref(),
        call_id,
        tool_name,
        &result.output,
        /*error*/ None,
        started_at.elapsed(),
    )
    .await;

    Ok(function_tool_output_from_repl_result(
        result.output,
        result.content_items,
    ))
}

pub(super) struct ReplExecutionResult {
    pub(super) output: String,
    pub(super) content_items: Vec<FunctionCallOutputContentItem>,
}

fn function_tool_output_from_repl_result(
    output: String,
    content_items: Vec<FunctionCallOutputContentItem>,
) -> FunctionToolOutput {
    let mut items = Vec::with_capacity(content_items.len() + 1);
    if !output.is_empty() {
        items.push(FunctionCallOutputContentItem::InputText {
            text: output.clone(),
        });
    }
    items.extend(content_items);

    if items.is_empty() {
        FunctionToolOutput::from_text(output, Some(true))
    } else {
        FunctionToolOutput::from_content(items, Some(true))
    }
}

fn join_outputs(stdout: &str, stderr: &str) -> String {
    if stdout.is_empty() {
        stderr.to_string()
    } else if stderr.is_empty() {
        stdout.to_string()
    } else {
        format!("{stdout}\n{stderr}")
    }
}

fn build_repl_exec_output(
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

pub(super) async fn emit_repl_exec_begin(
    session: &Session,
    turn: &TurnContext,
    call_id: &str,
    tool_name: &str,
) {
    let emitter = ToolEmitter::shell(
        vec![tool_name.to_string()],
        turn.cwd.to_path_buf(),
        ExecCommandSource::Agent,
        /*freeform*/ false,
    );
    let ctx = ToolEventCtx::new(session, turn, call_id, /*turn_diff_tracker*/ None);
    emitter.emit(ctx, ToolEventStage::Begin).await;
}

pub(super) async fn emit_repl_exec_end(
    session: &Session,
    turn: &TurnContext,
    call_id: &str,
    tool_name: &str,
    output: &str,
    error: Option<&str>,
    duration: Duration,
) {
    let exec_output = build_repl_exec_output(output, error, duration);
    let emitter = ToolEmitter::shell(
        vec![tool_name.to_string()],
        turn.cwd.to_path_buf(),
        ExecCommandSource::Agent,
        /*freeform*/ false,
    );
    let ctx = ToolEventCtx::new(session, turn, call_id, /*turn_diff_tracker*/ None);
    let stage = if error.is_some() {
        ToolEventStage::Failure(ToolEventFailure::Output(exec_output))
    } else {
        ToolEventStage::Success(exec_output)
    };
    emitter.emit(ctx, stage).await;
}

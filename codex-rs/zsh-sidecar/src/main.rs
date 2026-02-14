use anyhow::Context;
use anyhow::Result;
use base64::Engine as _;
use clap::Parser;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::process::Child;
use tokio::sync::Mutex;

const JSONRPC_VERSION: &str = "2.0";
const METHOD_ZSH_INITIALIZE: &str = "zsh/initialize";
const METHOD_ZSH_EXEC_START: &str = "zsh/execStart";
const METHOD_ZSH_EXEC_STDIN: &str = "zsh/execStdin";
const METHOD_ZSH_EXEC_RESIZE: &str = "zsh/execResize";
const METHOD_ZSH_EXEC_INTERRUPT: &str = "zsh/execInterrupt";
const METHOD_ZSH_SHUTDOWN: &str = "zsh/shutdown";
const METHOD_ZSH_REQUEST_APPROVAL: &str = "zsh/requestApproval";
const METHOD_ZSH_EVENT_EXEC_STARTED: &str = "zsh/event/execStarted";
const METHOD_ZSH_EVENT_EXEC_STDOUT: &str = "zsh/event/execStdout";
const METHOD_ZSH_EVENT_EXEC_STDERR: &str = "zsh/event/execStderr";
const METHOD_ZSH_EVENT_EXEC_EXITED: &str = "zsh/event/execExited";

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    zsh_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
enum JsonRpcId {
    Number(i64),
    String(String),
}

#[derive(Debug, Clone, Serialize)]
struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    id: JsonRpcId,
    method: &'static str,
    params: T,
}

#[derive(Debug, Clone, Serialize)]
struct JsonRpcSuccess<T> {
    jsonrpc: &'static str,
    id: JsonRpcId,
    result: T,
}

#[derive(Debug, Clone, Serialize)]
struct JsonRpcErrorResponse {
    jsonrpc: &'static str,
    id: JsonRpcId,
    error: JsonRpcError,
}

#[derive(Debug, Clone, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct JsonRpcNotification<T> {
    jsonrpc: &'static str,
    method: &'static str,
    params: T,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecStartParams {
    exec_id: String,
    command: Vec<String>,
    cwd: String,
    #[serde(default)]
    env: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecInterruptParams {
    exec_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ApprovalDecision {
    Approved,
    ApprovedForSession,
    ApprovedExecpolicyAmendment,
    Denied,
    Abort,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestApprovalParams {
    approval_id: String,
    exec_id: String,
    command: Vec<String>,
    cwd: String,
    reason: String,
    proposed_execpolicy_amendment: Option<ExecPolicyAmendmentProposal>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestApprovalResult {
    decision: ApprovalDecision,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecPolicyAmendmentProposal {
    command_prefix: Vec<String>,
    rationale: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InitializeResult {
    protocol_version: u32,
    capabilities: Capabilities,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Capabilities {
    interactive_pty: bool,
}

#[derive(Debug, Serialize)]
struct EmptyResult {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecStartedEvent {
    exec_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecChunkEvent {
    exec_id: String,
    chunk_base64: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecExitedEvent {
    exec_id: String,
    exit_code: i32,
    signal: Option<String>,
    timed_out: Option<bool>,
}

#[derive(Default)]
struct SidecarState {
    children: HashMap<String, Arc<Mutex<Child>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let args = Args::parse();
    let state = Arc::new(Mutex::new(SidecarState::default()));
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    loop {
        let Some(line) = lines.next_line().await.context("read stdin")? else {
            break;
        };

        if line.trim().is_empty() {
            continue;
        }

        let value: JsonValue = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!("invalid JSON-RPC input: {err}");
                continue;
            }
        };

        let Some(id_value) = value.get("id") else {
            continue;
        };
        let id: JsonRpcId = match serde_json::from_value(id_value.clone()) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!("invalid request id: {err}");
                continue;
            }
        };

        let method = value
            .get("method")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();

        match method {
            METHOD_ZSH_INITIALIZE => {
                write_json_line(
                    &stdout,
                    &JsonRpcSuccess {
                        jsonrpc: JSONRPC_VERSION,
                        id,
                        result: InitializeResult {
                            protocol_version: 1,
                            capabilities: Capabilities {
                                interactive_pty: false,
                            },
                        },
                    },
                )
                .await?;
            }
            METHOD_ZSH_EXEC_START => {
                let params: ExecStartParams = match parse_params(&value) {
                    Ok(p) => p,
                    Err(message) => {
                        write_json_line(
                            &stdout,
                            &JsonRpcErrorResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id,
                                error: JsonRpcError {
                                    code: -32602,
                                    message,
                                },
                            },
                        )
                        .await?;
                        continue;
                    }
                };

                if params.command.is_empty() {
                    write_json_line(
                        &stdout,
                        &JsonRpcErrorResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id,
                            error: JsonRpcError {
                                code: -32602,
                                message: "execStart.command is empty".to_string(),
                            },
                        },
                    )
                    .await?;
                    continue;
                }

                let approval_callback_id =
                    JsonRpcId::String(format!("approval-{}", params.exec_id));
                let approval_request = JsonRpcRequest {
                    jsonrpc: JSONRPC_VERSION,
                    id: approval_callback_id.clone(),
                    method: METHOD_ZSH_REQUEST_APPROVAL,
                    params: RequestApprovalParams {
                        approval_id: format!("approval-{}", params.exec_id),
                        exec_id: params.exec_id.clone(),
                        command: params.command.clone(),
                        cwd: params.cwd.clone(),
                        reason: "zsh sidecar execStart command approval".to_string(),
                        proposed_execpolicy_amendment: None,
                    },
                };
                write_json_line(&stdout, &approval_request).await?;

                let approval_decision =
                    wait_for_approval_result(&mut lines, approval_callback_id).await?;
                match approval_decision {
                    ApprovalDecision::Approved
                    | ApprovalDecision::ApprovedForSession
                    | ApprovalDecision::ApprovedExecpolicyAmendment => {}
                    ApprovalDecision::Denied => {
                        write_json_line(
                            &stdout,
                            &JsonRpcErrorResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id,
                                error: JsonRpcError {
                                    code: -32003,
                                    message: "command denied by host approval policy".to_string(),
                                },
                            },
                        )
                        .await?;
                        continue;
                    }
                    ApprovalDecision::Abort => {
                        write_json_line(
                            &stdout,
                            &JsonRpcErrorResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id,
                                error: JsonRpcError {
                                    code: -32003,
                                    message: "command aborted by host approval policy".to_string(),
                                },
                            },
                        )
                        .await?;
                        continue;
                    }
                }

                let mut cmd = tokio::process::Command::new(&params.command[0]);
                if params.command.len() > 1 {
                    cmd.args(&params.command[1..]);
                }
                cmd.current_dir(&params.cwd);
                cmd.stdin(Stdio::null());
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
                cmd.kill_on_drop(true);
                cmd.env_clear();
                if let Some(env) = params.env.as_ref() {
                    cmd.envs(env);
                }
                cmd.env("CODEX_ZSH_PATH", &args.zsh_path);

                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(err) => {
                        write_json_line(
                            &stdout,
                            &JsonRpcErrorResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id,
                                error: JsonRpcError {
                                    code: -32000,
                                    message: format!("failed to spawn command: {err}"),
                                },
                            },
                        )
                        .await?;
                        continue;
                    }
                };

                let stdout_handle = child.stdout.take();
                let stderr_handle = child.stderr.take();
                let exec_id = params.exec_id.clone();
                let child = Arc::new(Mutex::new(child));

                {
                    let mut st = state.lock().await;
                    st.children.insert(exec_id.clone(), Arc::clone(&child));
                }

                write_json_line(
                    &stdout,
                    &JsonRpcSuccess {
                        jsonrpc: JSONRPC_VERSION,
                        id,
                        result: EmptyResult {},
                    },
                )
                .await?;
                write_json_line(
                    &stdout,
                    &JsonRpcNotification {
                        jsonrpc: JSONRPC_VERSION,
                        method: METHOD_ZSH_EVENT_EXEC_STARTED,
                        params: ExecStartedEvent {
                            exec_id: exec_id.clone(),
                        },
                    },
                )
                .await?;

                if let Some(out) = stdout_handle {
                    let stdout_writer = Arc::clone(&stdout);
                    let stdout_exec_id = exec_id.clone();
                    tokio::spawn(async move {
                        stream_reader(
                            stdout_exec_id,
                            out,
                            METHOD_ZSH_EVENT_EXEC_STDOUT,
                            stdout_writer,
                        )
                        .await;
                    });
                }

                if let Some(err) = stderr_handle {
                    let stderr_writer = Arc::clone(&stdout);
                    let stderr_exec_id = exec_id.clone();
                    tokio::spawn(async move {
                        stream_reader(
                            stderr_exec_id,
                            err,
                            METHOD_ZSH_EVENT_EXEC_STDERR,
                            stderr_writer,
                        )
                        .await;
                    });
                }

                let wait_writer = Arc::clone(&stdout);
                let wait_state = Arc::clone(&state);
                tokio::spawn(async move {
                    let status = {
                        let mut guard = child.lock().await;
                        guard.wait().await
                    };

                    let (exit_code, signal) = match status {
                        Ok(s) => {
                            let code = s.code().unwrap_or(-1);
                            #[cfg(unix)]
                            {
                                use std::os::unix::process::ExitStatusExt;
                                (code, s.signal().map(|sig| sig.to_string()))
                            }
                            #[cfg(not(unix))]
                            {
                                (code, None)
                            }
                        }
                        Err(err) => {
                            tracing::warn!("wait failed for exec {exec_id}: {err}");
                            (-1, None)
                        }
                    };

                    {
                        let mut st = wait_state.lock().await;
                        st.children.remove(&exec_id);
                    }

                    let _ = write_json_line(
                        &wait_writer,
                        &JsonRpcNotification {
                            jsonrpc: JSONRPC_VERSION,
                            method: METHOD_ZSH_EVENT_EXEC_EXITED,
                            params: ExecExitedEvent {
                                exec_id: exec_id.clone(),
                                exit_code,
                                signal,
                                timed_out: Some(false),
                            },
                        },
                    )
                    .await;
                });
            }
            METHOD_ZSH_EXEC_INTERRUPT => {
                let params: ExecInterruptParams = match parse_params(&value) {
                    Ok(p) => p,
                    Err(message) => {
                        write_json_line(
                            &stdout,
                            &JsonRpcErrorResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id,
                                error: JsonRpcError {
                                    code: -32602,
                                    message,
                                },
                            },
                        )
                        .await?;
                        continue;
                    }
                };

                let child = {
                    let st = state.lock().await;
                    st.children.get(&params.exec_id).cloned()
                };

                match child {
                    Some(child) => {
                        let mut guard = child.lock().await;
                        if let Err(err) = guard.kill().await {
                            tracing::warn!("failed to interrupt {}: {err}", params.exec_id);
                        }
                        write_json_line(
                            &stdout,
                            &JsonRpcSuccess {
                                jsonrpc: JSONRPC_VERSION,
                                id,
                                result: EmptyResult {},
                            },
                        )
                        .await?;
                    }
                    None => {
                        write_json_line(
                            &stdout,
                            &JsonRpcErrorResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id,
                                error: JsonRpcError {
                                    code: -32002,
                                    message: format!("unknown exec id: {}", params.exec_id),
                                },
                            },
                        )
                        .await?;
                    }
                }
            }
            METHOD_ZSH_EXEC_STDIN | METHOD_ZSH_EXEC_RESIZE => {
                write_json_line(
                    &stdout,
                    &JsonRpcErrorResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id,
                        error: JsonRpcError {
                            code: -32004,
                            message: "method not supported in sidecar phase 1".to_string(),
                        },
                    },
                )
                .await?;
            }
            METHOD_ZSH_SHUTDOWN => {
                write_json_line(
                    &stdout,
                    &JsonRpcSuccess {
                        jsonrpc: JSONRPC_VERSION,
                        id,
                        result: EmptyResult {},
                    },
                )
                .await?;
                break;
            }
            _ => {
                write_json_line(
                    &stdout,
                    &JsonRpcErrorResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id,
                        error: JsonRpcError {
                            code: -32601,
                            message: format!("unknown method: {method}"),
                        },
                    },
                )
                .await?;
            }
        }
    }

    Ok(())
}

async fn wait_for_approval_result(
    lines: &mut tokio::io::Lines<BufReader<tokio::io::Stdin>>,
    expected_id: JsonRpcId,
) -> Result<ApprovalDecision> {
    loop {
        let Some(line) = lines.next_line().await.context("read stdin")? else {
            anyhow::bail!("stdin closed while waiting for approval response");
        };
        if line.trim().is_empty() {
            continue;
        }

        let value: JsonValue =
            serde_json::from_str(&line).context("parse approval response JSON-RPC message")?;
        let Some(id_value) = value.get("id") else {
            continue;
        };
        let id: JsonRpcId = serde_json::from_value(id_value.clone())
            .context("parse approval response JSON-RPC id")?;
        if id != expected_id {
            tracing::warn!("ignoring unexpected JSON-RPC message while waiting for approval");
            continue;
        }

        if let Some(error) = value.get("error") {
            let message = error
                .get("message")
                .and_then(JsonValue::as_str)
                .unwrap_or("unknown host approval callback error");
            anyhow::bail!("host rejected approval callback: {message}");
        }

        let result: RequestApprovalResult = serde_json::from_value(
            value
                .get("result")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing approval callback result"))?,
        )
        .context("parse approval callback result")?;
        return Ok(result.decision);
    }
}

async fn stream_reader<R>(
    exec_id: String,
    mut reader: R,
    method: &'static str,
    writer: Arc<Mutex<tokio::io::Stdout>>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = [0_u8; 8192];

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) => {
                tracing::warn!("read stream error for {exec_id}: {err}");
                break;
            }
        };

        let message = JsonRpcNotification {
            jsonrpc: JSONRPC_VERSION,
            method,
            params: ExecChunkEvent {
                exec_id: exec_id.clone(),
                chunk_base64: base64::engine::general_purpose::STANDARD.encode(&buf[..n]),
            },
        };

        if let Err(err) = write_json_line(&writer, &message).await {
            tracing::warn!("failed writing stream event for {exec_id}: {err}");
            break;
        }
    }
}

fn parse_params<T: for<'de> Deserialize<'de>>(value: &JsonValue) -> std::result::Result<T, String> {
    let params = value
        .get("params")
        .cloned()
        .ok_or_else(|| "missing params".to_string())?;
    serde_json::from_value(params).map_err(|err| format!("invalid params: {err}"))
}

async fn write_json_line<T: Serialize>(
    writer: &Arc<Mutex<tokio::io::Stdout>>,
    message: &T,
) -> Result<()> {
    let encoded = serde_json::to_string(message).context("serialize JSON-RPC message")?;
    let mut guard = writer.lock().await;
    guard
        .write_all(encoded.as_bytes())
        .await
        .context("write message")?;
    guard.write_all(b"\n").await.context("write newline")?;
    guard.flush().await.context("flush message")?;
    Ok(())
}

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant as StdInstant;

use codex_exec_server::ExecutorFileSystem;
use codex_features::Feature;
use codex_protocol::ThreadId;
use codex_protocol::models::AdditionalPermissionProfile;
use codex_protocol::models::FunctionCallOutputContentItem;
use codex_protocol::models::ImageDetail;
use codex_utils_output_truncation::approx_token_count;
use codex_utils_path_uri::PathUri;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::process::Child;
use tokio::process::ChildStdin;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;

use crate::agents_md::discover_project_root;
use crate::config::Config;
use crate::exec::ExecCapturePolicy;
use crate::exec::ExecExpiration;
use crate::exec_env::create_env;
use crate::function_tool::FunctionCallError;
use crate::original_image_detail::normalize_output_image_detail;
use crate::sandboxing::ExecOptions;
use crate::sandboxing::SandboxPermissions;
use crate::session::session::Session;
use crate::session::turn_context::TurnContext;
use crate::tools::ToolRouter;
use crate::tools::context::SharedTurnDiffTracker;
use crate::tools::flat_tool_name;
use crate::tools::handlers::apply_granted_turn_permissions;
use crate::tools::handlers::implicit_granted_permissions;
use crate::tools::handlers::normalize_and_validate_additional_permissions;
use crate::tools::handlers::unified_exec::shell_mode_for_environment;
use crate::tools::repl_image::validate_repl_image_data_url;
use crate::tools::router::ToolRouterParams;
use crate::unified_exec::ExecCommandRequest;
use crate::unified_exec::UnifiedExecContext;
use crate::unified_exec::UnifiedExecError;
use crate::unified_exec::WriteStdinRequest;
use codex_sandboxing::SandboxCommand;
use codex_sandboxing::SandboxManager;
use codex_sandboxing::SandboxTransformRequest;
use codex_sandboxing::SandboxablePreference;
use codex_tools::ResponsesApiNamespaceTool;
use codex_tools::ToolName;

pub(crate) const PY_REPL_PRAGMA_PREFIX: &str = "# codex-py-repl:";
const KERNEL_SOURCE: &str = include_str!("kernel.py");
const PY_REPL_STDERR_TAIL_LINE_LIMIT: usize = 20;
const PY_REPL_STDERR_TAIL_LINE_MAX_BYTES: usize = 512;
const PY_REPL_STDERR_TAIL_MAX_BYTES: usize = 4_096;
const PY_REPL_STDERR_TAIL_SEPARATOR: &str = " | ";
const PY_REPL_EXEC_ID_LOG_LIMIT: usize = 8;
const PY_REPL_MODEL_DIAG_STDERR_MAX_BYTES: usize = 1_024;
const PY_REPL_MODEL_DIAG_ERROR_MAX_BYTES: usize = 256;
const PY_REPL_DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Per-task py_repl handle stored on the turn context.
pub(crate) struct PyReplHandle {
    python_path: Option<PathBuf>,
    sys_path: Vec<PathBuf>,
    cell: OnceCell<Arc<PyReplManager>>,
}

impl fmt::Debug for PyReplHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PyReplHandle").finish_non_exhaustive()
    }
}

impl PyReplHandle {
    pub(crate) fn with_python_path(python_path: Option<PathBuf>, sys_path: Vec<PathBuf>) -> Self {
        Self {
            python_path,
            sys_path,
            cell: OnceCell::new(),
        }
    }

    pub(crate) async fn manager(&self) -> Result<Arc<PyReplManager>, FunctionCallError> {
        self.cell
            .get_or_try_init(|| async {
                PyReplManager::new(self.python_path.clone(), self.sys_path.clone()).await
            })
            .await
            .cloned()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PyReplArgs {
    pub code: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub isolated: bool,
}

#[derive(Clone, Debug)]
pub struct PyExecResult {
    pub output: String,
    pub content_items: Vec<FunctionCallOutputContentItem>,
}

struct KernelState {
    child: Arc<Mutex<Child>>,
    recent_stderr: Arc<Mutex<VecDeque<String>>>,
    stdin: Arc<Mutex<ChildStdin>>,
    pending_execs: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<ExecResultMessage>>>>,
    exec_contexts: Arc<Mutex<HashMap<String, ExecContext>>>,
    shutdown: CancellationToken,
}

#[derive(Clone)]
struct ExecContext {
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    cancellation_token: CancellationToken,
    tracker: SharedTurnDiffTracker,
    tmp_dir: PathBuf,
}

type OwnedProcessMap = Arc<Mutex<HashMap<i32, Arc<Session>>>>;

struct ExecToolCalls {
    in_flight: usize,
    content_items: Vec<FunctionCallOutputContentItem>,
    notify: Arc<Notify>,
    cancel: CancellationToken,
}

impl Default for ExecToolCalls {
    fn default() -> Self {
        Self {
            in_flight: 0,
            content_items: Vec::new(),
            notify: Arc::new(Notify::new()),
            cancel: CancellationToken::new(),
        }
    }
}

enum KernelStreamEnd {
    Shutdown,
    StdoutEof,
    StdoutReadError(String),
}

impl KernelStreamEnd {
    fn reason(&self) -> &'static str {
        match self {
            Self::Shutdown => "shutdown",
            Self::StdoutEof => "stdout_eof",
            Self::StdoutReadError(_) => "stdout_read_error",
        }
    }

    fn error(&self) -> Option<&str> {
        match self {
            Self::StdoutReadError(err) => Some(err),
            Self::Shutdown | Self::StdoutEof => None,
        }
    }
}

struct KernelDebugSnapshot {
    pid: Option<u32>,
    status: String,
    stderr_tail: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PythonVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl PythonVersion {
    const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    fn parse(input: &str) -> Result<Self, String> {
        let normalized = input.trim();
        let normalized = normalized
            .strip_prefix("Python ")
            .unwrap_or(normalized)
            .trim();
        let mut parts = normalized.split('.');
        let major = parts
            .next()
            .ok_or_else(|| "missing major version".to_string())?
            .parse::<u32>()
            .map_err(|err| format!("invalid major version: {err}"))?;
        let minor = parts
            .next()
            .ok_or_else(|| "missing minor version".to_string())?
            .parse::<u32>()
            .map_err(|err| format!("invalid minor version: {err}"))?;
        let patch = parts
            .next()
            .unwrap_or("0")
            .parse::<u32>()
            .map_err(|err| format!("invalid patch version: {err}"))?;
        Ok(Self::new(major, minor, patch))
    }
}

impl fmt::Display for PythonVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn required_python_version() -> PythonVersion {
    PythonVersion::new(3, 10, 0)
}

fn format_exit_status(status: std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("code={code}");
    }
    #[cfg(unix)]
    if let Some(signal) = status.signal() {
        return format!("signal={signal}");
    }
    "unknown".to_string()
}

fn format_stderr_tail(lines: &VecDeque<String>) -> String {
    if lines.is_empty() {
        return "<empty>".to_string();
    }
    lines
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(PY_REPL_STDERR_TAIL_SEPARATOR)
}

fn truncate_utf8_prefix_by_bytes(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    if max_bytes == 0 {
        return String::new();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
}

fn stderr_tail_formatted_bytes(lines: &VecDeque<String>) -> usize {
    if lines.is_empty() {
        return 0;
    }
    let payload_bytes: usize = lines.iter().map(String::len).sum();
    let separator_bytes = PY_REPL_STDERR_TAIL_SEPARATOR.len() * (lines.len() - 1);
    payload_bytes + separator_bytes
}

fn stderr_tail_bytes_with_candidate(lines: &VecDeque<String>, line: &str) -> usize {
    if lines.is_empty() {
        return line.len();
    }
    stderr_tail_formatted_bytes(lines) + PY_REPL_STDERR_TAIL_SEPARATOR.len() + line.len()
}

fn push_stderr_tail_line(lines: &mut VecDeque<String>, line: &str) -> String {
    let max_line_bytes = PY_REPL_STDERR_TAIL_LINE_MAX_BYTES.min(PY_REPL_STDERR_TAIL_MAX_BYTES);
    let bounded_line = truncate_utf8_prefix_by_bytes(line, max_line_bytes);
    if bounded_line.is_empty() {
        return bounded_line;
    }

    while !lines.is_empty()
        && (lines.len() >= PY_REPL_STDERR_TAIL_LINE_LIMIT
            || stderr_tail_bytes_with_candidate(lines, &bounded_line)
                > PY_REPL_STDERR_TAIL_MAX_BYTES)
    {
        lines.pop_front();
    }

    lines.push_back(bounded_line.clone());
    bounded_line
}

fn is_kernel_status_exited(status: &str) -> bool {
    status.starts_with("exited(")
}

fn should_include_model_diagnostics_for_write_error(
    err_message: &str,
    snapshot: &KernelDebugSnapshot,
) -> bool {
    is_kernel_status_exited(&snapshot.status)
        || err_message.to_ascii_lowercase().contains("broken pipe")
}

fn format_model_kernel_failure_details(
    reason: &str,
    stream_error: Option<&str>,
    snapshot: &KernelDebugSnapshot,
) -> String {
    let payload = serde_json::json!({
        "reason": reason,
        "stream_error": stream_error
            .map(|err| truncate_utf8_prefix_by_bytes(err, PY_REPL_MODEL_DIAG_ERROR_MAX_BYTES)),
        "kernel_pid": snapshot.pid,
        "kernel_status": snapshot.status,
        "kernel_stderr_tail": truncate_utf8_prefix_by_bytes(
            &snapshot.stderr_tail,
            PY_REPL_MODEL_DIAG_STDERR_MAX_BYTES,
        ),
    });
    let encoded = serde_json::to_string(&payload)
        .unwrap_or_else(|err| format!(r#"{{"reason":"serialization_error","error":"{err}"}}"#));
    format!("py_repl diagnostics: {encoded}")
}

fn with_model_kernel_failure_message(
    base_message: &str,
    reason: &str,
    stream_error: Option<&str>,
    snapshot: &KernelDebugSnapshot,
) -> String {
    format!(
        "{base_message}\n\n{}",
        format_model_kernel_failure_details(reason, stream_error, snapshot)
    )
}

fn format_exec_failure_message(output: String, error: Option<String>) -> String {
    match (output.trim().is_empty(), error) {
        (true, Some(error)) => error,
        (false, Some(error)) => format!("{output}\n{error}"),
        (false, None) => output,
        (true, None) => "py_repl execution failed".to_string(),
    }
}

pub struct PyReplManager {
    python_path: PathBuf,
    sys_path: Vec<PathBuf>,
    tmp_dir: tempfile::TempDir,
    kernel: Arc<Mutex<Option<KernelState>>>,
    exec_lock: Arc<tokio::sync::Semaphore>,
    exec_tool_calls: Arc<Mutex<HashMap<String, ExecToolCalls>>>,
    owned_processes: OwnedProcessMap,
}

impl PyReplManager {
    async fn new(
        python_path: Option<PathBuf>,
        sys_path: Vec<PathBuf>,
    ) -> Result<Arc<Self>, FunctionCallError> {
        let resolved_python_path = resolve_compatible_python(python_path.as_deref())
            .await
            .map_err(FunctionCallError::RespondToModel)?;
        let tmp_dir = tempfile::tempdir().map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to create py_repl temp dir: {err}"))
        })?;

        Ok(Arc::new(Self {
            python_path: resolved_python_path,
            sys_path,
            tmp_dir,
            kernel: Arc::new(Mutex::new(None)),
            exec_lock: Arc::new(tokio::sync::Semaphore::new(1)),
            exec_tool_calls: Arc::new(Mutex::new(HashMap::new())),
            owned_processes: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    pub(crate) async fn execute(
        &self,
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        cancellation_token: CancellationToken,
        tracker: SharedTurnDiffTracker,
        args: PyReplArgs,
    ) -> Result<PyExecResult, FunctionCallError> {
        let _permit = self.exec_lock.clone().acquire_owned().await.map_err(|_| {
            FunctionCallError::RespondToModel("py_repl execution unavailable".to_string())
        })?;
        let isolated = args.isolated;
        if isolated {
            self.reset_kernel().await;
        }

        let (stdin, pending_execs, exec_contexts, child, recent_stderr) = {
            let mut kernel = self.kernel.lock().await;
            if kernel.is_none() {
                let state = self
                    .start_kernel(Arc::clone(&turn), Some(session.thread_id))
                    .await
                    .map_err(FunctionCallError::RespondToModel)?;
                *kernel = Some(state);
            }

            let state = kernel.as_ref().ok_or_else(|| {
                FunctionCallError::RespondToModel("py_repl kernel unavailable".to_string())
            })?;
            (
                Arc::clone(&state.stdin),
                Arc::clone(&state.pending_execs),
                Arc::clone(&state.exec_contexts),
                Arc::clone(&state.child),
                Arc::clone(&state.recent_stderr),
            )
        };

        let (req_id, rx) = {
            let req_id = Uuid::new_v4().to_string();
            let mut pending = pending_execs.lock().await;
            let (tx, rx) = tokio::sync::oneshot::channel();
            pending.insert(req_id.clone(), tx);
            exec_contexts.lock().await.insert(
                req_id.clone(),
                ExecContext {
                    session: Arc::clone(&session),
                    turn: Arc::clone(&turn),
                    cancellation_token,
                    tracker,
                    tmp_dir: self.tmp_dir.path().to_path_buf(),
                },
            );
            self.register_exec_tool_calls(&req_id).await;
            (req_id, rx)
        };

        let payload = HostToKernel::Exec {
            id: req_id.clone(),
            code: args.code,
            timeout_ms: args.timeout_ms,
        };
        if let Err(err) = Self::write_message(&stdin, &payload).await {
            pending_execs.lock().await.remove(&req_id);
            exec_contexts.lock().await.remove(&req_id);
            self.clear_exec_tool_calls(&req_id).await;
            let snapshot = Self::kernel_debug_snapshot(&child, &recent_stderr).await;
            let err_message = err.to_string();
            warn!(
                exec_id = %req_id,
                error = %err_message,
                kernel_pid = ?snapshot.pid,
                kernel_status = %snapshot.status,
                kernel_stderr_tail = %snapshot.stderr_tail,
                "failed to submit py_repl exec request to kernel"
            );
            let message =
                if should_include_model_diagnostics_for_write_error(&err_message, &snapshot) {
                    with_model_kernel_failure_message(
                        &err_message,
                        "write_failed",
                        Some(&err_message),
                        &snapshot,
                    )
                } else {
                    err_message
                };
            return Err(FunctionCallError::RespondToModel(message));
        }

        let timeout_ms = args.timeout_ms.unwrap_or(PY_REPL_DEFAULT_TIMEOUT_MS);
        let response = match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(_)) => {
                pending_execs.lock().await.remove(&req_id);
                exec_contexts.lock().await.remove(&req_id);
                self.wait_for_exec_tool_calls(&req_id).await;
                self.clear_exec_tool_calls(&req_id).await;
                let snapshot = Self::kernel_debug_snapshot(&child, &recent_stderr).await;
                let message = if is_kernel_status_exited(&snapshot.status) {
                    with_model_kernel_failure_message(
                        "py_repl kernel closed unexpectedly",
                        "response_channel_closed",
                        None,
                        &snapshot,
                    )
                } else {
                    "py_repl kernel closed unexpectedly".to_string()
                };
                return Err(FunctionCallError::RespondToModel(message));
            }
            Err(_) => {
                pending_execs.lock().await.remove(&req_id);
                exec_contexts.lock().await.remove(&req_id);
                self.reset_kernel().await;
                self.wait_for_exec_tool_calls(&req_id).await;
                self.clear_exec_tool_calls(&req_id).await;
                return Err(FunctionCallError::RespondToModel(
                    "py_repl execution timed out; kernel reset, rerun your request".to_string(),
                ));
            }
        };

        let (result, restart_after) = match response {
            ExecResultMessage::Ok {
                output,
                content_items,
                restart_after,
            } => (
                Ok(PyExecResult {
                    output,
                    content_items,
                }),
                restart_after,
            ),
            ExecResultMessage::Err {
                message,
                restart_after,
            } => (
                Err(FunctionCallError::RespondToModel(message)),
                restart_after,
            ),
        };
        if isolated || restart_after {
            self.reset_kernel().await;
        }
        result
    }

    pub(crate) async fn reset(&self) -> Result<(), FunctionCallError> {
        let _permit = self.exec_lock.clone().acquire_owned().await.map_err(|_| {
            FunctionCallError::RespondToModel("py_repl execution unavailable".to_string())
        })?;
        self.reset_kernel().await;
        Self::clear_all_exec_tool_calls_map(&self.exec_tool_calls).await;
        Ok(())
    }

    async fn register_exec_tool_calls(&self, exec_id: &str) {
        self.exec_tool_calls
            .lock()
            .await
            .insert(exec_id.to_string(), ExecToolCalls::default());
    }

    async fn clear_exec_tool_calls(&self, exec_id: &str) {
        if let Some(state) = self.exec_tool_calls.lock().await.remove(exec_id) {
            state.cancel.cancel();
            state.notify.notify_waiters();
        }
    }

    async fn wait_for_exec_tool_calls(&self, exec_id: &str) {
        Self::wait_for_exec_tool_calls_map(&self.exec_tool_calls, exec_id).await;
    }

    async fn begin_exec_tool_call(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_id: &str,
    ) -> Option<CancellationToken> {
        let mut calls = exec_tool_calls.lock().await;
        let state = calls.get_mut(exec_id)?;
        state.in_flight += 1;
        Some(state.cancel.clone())
    }

    async fn record_exec_content_item(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_id: &str,
        content_item: FunctionCallOutputContentItem,
    ) {
        let mut calls = exec_tool_calls.lock().await;
        if let Some(state) = calls.get_mut(exec_id) {
            state.content_items.push(content_item);
        }
    }

    async fn finish_exec_tool_call(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_id: &str,
    ) {
        let notify = {
            let mut calls = exec_tool_calls.lock().await;
            let Some(state) = calls.get_mut(exec_id) else {
                return;
            };
            if state.in_flight == 0 {
                return;
            }
            state.in_flight -= 1;
            if state.in_flight == 0 {
                Some(Arc::clone(&state.notify))
            } else {
                None
            }
        };
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }

    async fn wait_for_exec_tool_calls_map(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_id: &str,
    ) {
        loop {
            let notified = {
                let calls = exec_tool_calls.lock().await;
                calls
                    .get(exec_id)
                    .filter(|state| state.in_flight > 0)
                    .map(|state| Arc::clone(&state.notify).notified_owned())
            };
            match notified {
                Some(notified) => notified.await,
                None => return,
            }
        }
    }

    async fn clear_exec_tool_calls_map(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        exec_id: &str,
    ) {
        if let Some(state) = exec_tool_calls.lock().await.remove(exec_id) {
            state.cancel.cancel();
            state.notify.notify_waiters();
        }
    }

    async fn clear_all_exec_tool_calls_map(
        exec_tool_calls: &Arc<Mutex<HashMap<String, ExecToolCalls>>>,
    ) {
        let states = {
            let mut calls = exec_tool_calls.lock().await;
            calls.drain().map(|(_, state)| state).collect::<Vec<_>>()
        };
        for state in states {
            state.cancel.cancel();
            state.notify.notify_waiters();
        }
    }

    async fn reset_kernel(&self) {
        let state = {
            let mut guard = self.kernel.lock().await;
            guard.take()
        };
        if let Some(state) = state {
            state.shutdown.cancel();
            Self::kill_kernel_child(&state.child, "reset").await;
        }
        Self::terminate_owned_processes(&self.owned_processes, "reset").await;
    }

    async fn terminate_owned_processes(owned_processes: &OwnedProcessMap, reason: &str) {
        let processes = {
            let mut owned = owned_processes.lock().await;
            owned.drain().collect::<Vec<_>>()
        };
        for (process_id, session) in processes {
            if !session
                .services
                .unified_exec_manager
                .terminate_process(process_id)
                .await
            {
                warn!(
                    process_id,
                    reason, "py_repl owned process was already unavailable during cleanup"
                );
            }
        }
    }

    async fn record_owned_process(
        owned_processes: &OwnedProcessMap,
        process_id: i32,
        session: &Arc<Session>,
    ) {
        owned_processes
            .lock()
            .await
            .insert(process_id, Arc::clone(session));
    }

    async fn forget_owned_process(owned_processes: &OwnedProcessMap, process_id: i32) {
        owned_processes.lock().await.remove(&process_id);
    }

    async fn start_kernel(
        &self,
        turn: Arc<TurnContext>,
        thread_id: Option<ThreadId>,
    ) -> Result<KernelState, String> {
        let kernel_path = self
            .write_kernel_script()
            .await
            .map_err(|err| err.to_string())?;

        let mut env = create_env(&turn.shell_environment_policy, thread_id);
        env.insert(
            "CODEX_PY_REPL_TMP_DIR".to_string(),
            self.tmp_dir.path().to_string_lossy().to_string(),
        );
        if !self.sys_path.is_empty() {
            let joined = std::env::join_paths(&self.sys_path)
                .map_err(|err| format!("failed to join py_repl_sys_path: {err}"))?;
            env.insert(
                "CODEX_PY_REPL_SYS_PATH".to_string(),
                joined.to_string_lossy().to_string(),
            );
        }
        env.insert("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string());

        let Some(turn_environment) = turn.environments.primary() else {
            return Err("py_repl is unavailable without a selected turn environment".to_string());
        };
        let cwd = turn_environment.cwd().clone();
        let cwd_uri = PathUri::from_abs_path(&cwd);
        let command = SandboxCommand {
            program: self.python_path.clone().into_os_string(),
            args: vec!["-u".to_string(), kernel_path.to_string_lossy().to_string()],
            cwd: cwd_uri.clone(),
            env,
            additional_permissions: None,
        };
        let options = ExecOptions {
            expiration: ExecExpiration::DefaultTimeout,
            capture_policy: ExecCapturePolicy::ShellTool,
        };

        let sandbox = SandboxManager::new();
        let has_managed_network_requirements = turn
            .config
            .config_layer_stack
            .requirements_toml()
            .network
            .is_some();
        let file_system_sandbox_policy = turn.file_system_sandbox_policy();
        let network_sandbox_policy = turn.network_sandbox_policy();
        let sandbox_type = sandbox.select_initial(
            &file_system_sandbox_policy,
            network_sandbox_policy,
            SandboxablePreference::Auto,
            turn.windows_sandbox_level,
            has_managed_network_requirements,
        );
        let windows_sandbox_workspace_roots = {
            let workspace_roots = turn.config.effective_workspace_roots();
            if workspace_roots.is_empty() {
                vec![cwd]
            } else {
                workspace_roots
            }
        };
        let exec_env = sandbox
            .transform(SandboxTransformRequest {
                command,
                permissions: &turn.permission_profile,
                sandbox: sandbox_type,
                enforce_managed_network: has_managed_network_requirements,
                network: None,
                sandbox_policy_cwd: &cwd_uri,
                #[cfg(target_os = "macos")]
                macos_seatbelt_profile_extensions: None,
                codex_linux_sandbox_exe: turn.codex_linux_sandbox_exe.as_deref(),
                use_legacy_landlock: turn.features.use_legacy_landlock(),
                windows_sandbox_level: turn.windows_sandbox_level,
                windows_sandbox_private_desktop: turn
                    .config
                    .permissions
                    .windows_sandbox_private_desktop,
            })
            .map(|request| {
                crate::sandboxing::ExecRequest::from_sandbox_exec_request(
                    request,
                    options,
                    windows_sandbox_workspace_roots,
                )
            })
            .map_err(|err| format!("failed to configure sandbox for py_repl: {err}"))?;

        let mut cmd =
            tokio::process::Command::new(exec_env.command.first().cloned().unwrap_or_default());
        if exec_env.command.len() > 1 {
            cmd.args(&exec_env.command[1..]);
        }
        #[cfg(unix)]
        cmd.arg0(
            exec_env
                .arg0
                .clone()
                .unwrap_or_else(|| exec_env.command.first().cloned().unwrap_or_default()),
        );
        cmd.current_dir(&exec_env.cwd);
        cmd.env_clear();
        cmd.envs(exec_env.env);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|err| format!("failed to start Python runtime: {err}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "py_repl kernel missing stdout".to_string())?;
        let stderr = child.stderr.take();
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "py_repl kernel missing stdin".to_string())?;

        let shutdown = CancellationToken::new();
        let pending_execs: Arc<
            Mutex<HashMap<String, tokio::sync::oneshot::Sender<ExecResultMessage>>>,
        > = Arc::new(Mutex::new(HashMap::new()));
        let exec_contexts: Arc<Mutex<HashMap<String, ExecContext>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let stdin_arc = Arc::new(Mutex::new(stdin));
        let child = Arc::new(Mutex::new(child));
        let recent_stderr = Arc::new(Mutex::new(VecDeque::with_capacity(
            PY_REPL_STDERR_TAIL_LINE_LIMIT,
        )));

        tokio::spawn(Self::read_stdout(
            stdout,
            Arc::clone(&child),
            Arc::clone(&self.kernel),
            Arc::clone(&recent_stderr),
            Arc::clone(&pending_execs),
            Arc::clone(&exec_contexts),
            Arc::clone(&self.exec_tool_calls),
            Arc::clone(&self.owned_processes),
            Arc::clone(&stdin_arc),
            shutdown.clone(),
        ));
        if let Some(stderr) = stderr {
            tokio::spawn(Self::read_stderr(
                stderr,
                Arc::clone(&recent_stderr),
                shutdown.clone(),
            ));
        } else {
            warn!("py_repl kernel missing stderr");
        }

        Ok(KernelState {
            child,
            recent_stderr,
            stdin: stdin_arc,
            pending_execs,
            exec_contexts,
            shutdown,
        })
    }

    async fn write_kernel_script(&self) -> Result<PathBuf, std::io::Error> {
        let dir = self.tmp_dir.path();
        let kernel_path = dir.join("py_repl_kernel.py");
        tokio::fs::write(&kernel_path, KERNEL_SOURCE).await?;
        Ok(kernel_path)
    }

    async fn write_message(
        stdin: &Arc<Mutex<ChildStdin>>,
        msg: &HostToKernel,
    ) -> Result<(), FunctionCallError> {
        let encoded = serde_json::to_string(msg).map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to serialize kernel message: {err}"))
        })?;
        let mut guard = stdin.lock().await;
        guard.write_all(encoded.as_bytes()).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to write to kernel: {err}"))
        })?;
        guard.write_all(b"\n").await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to flush kernel message: {err}"))
        })?;
        Ok(())
    }

    async fn kernel_stderr_tail_snapshot(recent_stderr: &Arc<Mutex<VecDeque<String>>>) -> String {
        let tail = recent_stderr.lock().await;
        format_stderr_tail(&tail)
    }

    async fn kernel_debug_snapshot(
        child: &Arc<Mutex<Child>>,
        recent_stderr: &Arc<Mutex<VecDeque<String>>>,
    ) -> KernelDebugSnapshot {
        let (pid, status) = {
            let mut guard = child.lock().await;
            let pid = guard.id();
            let status = match guard.try_wait() {
                Ok(Some(status)) => format!("exited({})", format_exit_status(status)),
                Ok(None) => "running".to_string(),
                Err(err) => format!("unknown ({err})"),
            };
            (pid, status)
        };
        let stderr_tail = {
            let tail = recent_stderr.lock().await;
            format_stderr_tail(&tail)
        };
        KernelDebugSnapshot {
            pid,
            status,
            stderr_tail,
        }
    }

    async fn kill_kernel_child(child: &Arc<Mutex<Child>>, reason: &'static str) {
        let mut guard = child.lock().await;
        let pid = guard.id();
        match guard.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(err) => {
                warn!(
                    kernel_pid = ?pid,
                    kill_reason = reason,
                    error = %err,
                    "failed to inspect py_repl kernel before kill"
                );
            }
        }

        if let Err(err) = guard.start_kill() {
            warn!(
                kernel_pid = ?pid,
                kill_reason = reason,
                error = %err,
                "failed to send kill signal to py_repl kernel"
            );
            return;
        }

        match tokio::time::timeout(Duration::from_secs(2), guard.wait()).await {
            Ok(Ok(_status)) => {}
            Ok(Err(err)) => {
                warn!(
                    kernel_pid = ?pid,
                    kill_reason = reason,
                    error = %err,
                    "failed while waiting for py_repl kernel exit"
                );
            }
            Err(_) => {
                warn!(
                    kernel_pid = ?pid,
                    kill_reason = reason,
                    "timed out waiting for py_repl kernel to exit after kill"
                );
            }
        }
    }

    fn truncate_id_list(ids: &[String]) -> Vec<String> {
        if ids.len() <= PY_REPL_EXEC_ID_LOG_LIMIT {
            return ids.to_vec();
        }
        let mut output = ids[..PY_REPL_EXEC_ID_LOG_LIMIT].to_vec();
        output.push(format!("...+{}", ids.len() - PY_REPL_EXEC_ID_LOG_LIMIT));
        output
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_stdout(
        stdout: tokio::process::ChildStdout,
        child: Arc<Mutex<Child>>,
        manager_kernel: Arc<Mutex<Option<KernelState>>>,
        recent_stderr: Arc<Mutex<VecDeque<String>>>,
        pending_execs: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<ExecResultMessage>>>>,
        exec_contexts: Arc<Mutex<HashMap<String, ExecContext>>>,
        exec_tool_calls: Arc<Mutex<HashMap<String, ExecToolCalls>>>,
        owned_processes: OwnedProcessMap,
        stdin: Arc<Mutex<ChildStdin>>,
        shutdown: CancellationToken,
    ) {
        let mut reader = BufReader::new(stdout).lines();
        let end_reason = loop {
            let line = tokio::select! {
                _ = shutdown.cancelled() => break KernelStreamEnd::Shutdown,
                res = reader.next_line() => match res {
                    Ok(Some(line)) => line,
                    Ok(None) => break KernelStreamEnd::StdoutEof,
                    Err(err) => break KernelStreamEnd::StdoutReadError(err.to_string()),
                },
            };

            let msg = match serde_json::from_str::<KernelToHost>(&line) {
                Ok(msg) => msg,
                Err(err) => {
                    warn!("py_repl kernel sent invalid json: {err} (line: {line})");
                    continue;
                }
            };

            match msg {
                KernelToHost::ExecResult {
                    id,
                    ok,
                    output,
                    error,
                    restart_after,
                } => {
                    Self::wait_for_exec_tool_calls_map(&exec_tool_calls, &id).await;
                    let content_items = {
                        let calls = exec_tool_calls.lock().await;
                        calls
                            .get(&id)
                            .map(|state| state.content_items.clone())
                            .unwrap_or_default()
                    };
                    let mut pending = pending_execs.lock().await;
                    if let Some(tx) = pending.remove(&id) {
                        let payload = if ok {
                            ExecResultMessage::Ok {
                                output,
                                content_items,
                                restart_after,
                            }
                        } else {
                            ExecResultMessage::Err {
                                message: format_exec_failure_message(output, error),
                                restart_after,
                            }
                        };
                        let _ = tx.send(payload);
                    }
                    exec_contexts.lock().await.remove(&id);
                    Self::clear_exec_tool_calls_map(&exec_tool_calls, &id).await;
                    if restart_after {
                        shutdown.cancel();
                        Self::kill_kernel_child(&child, "restart_after_cell").await;
                        break KernelStreamEnd::Shutdown;
                    }
                }
                KernelToHost::EmitImage(req) => {
                    let exec_id = req.exec_id.clone();
                    let emit_id = req.id.clone();
                    let response =
                        if let Some(ctx) = exec_contexts.lock().await.get(&exec_id).cloned() {
                            match validate_emitted_image_url(&req.image_url) {
                                Ok(()) => {
                                    let content_item = emitted_image_content_item(
                                        ctx.turn.as_ref(),
                                        req.image_url,
                                        req.detail,
                                    );
                                    Self::record_exec_content_item(
                                        &exec_tool_calls,
                                        &exec_id,
                                        content_item,
                                    )
                                    .await;
                                    HostToKernel::EmitImageResult(EmitImageResult {
                                        id: emit_id,
                                        ok: true,
                                        error: None,
                                    })
                                }
                                Err(error) => HostToKernel::EmitImageResult(EmitImageResult {
                                    id: emit_id,
                                    ok: false,
                                    error: Some(error),
                                }),
                            }
                        } else {
                            HostToKernel::EmitImageResult(EmitImageResult {
                                id: emit_id,
                                ok: false,
                                error: Some("py_repl exec context not found".to_string()),
                            })
                        };

                    if let Err(err) = Self::write_message(&stdin, &response).await {
                        let snapshot = Self::kernel_debug_snapshot(&child, &recent_stderr).await;
                        warn!(
                            exec_id = %exec_id,
                            emit_id = %req.id,
                            error = %err,
                            kernel_pid = ?snapshot.pid,
                            kernel_status = %snapshot.status,
                            kernel_stderr_tail = %snapshot.stderr_tail,
                            "failed to reply to kernel emit_image request"
                        );
                    }
                }
                KernelToHost::RunTool(req) => {
                    let Some(reset_cancel) =
                        Self::begin_exec_tool_call(&exec_tool_calls, &req.exec_id).await
                    else {
                        let exec_id = req.exec_id.clone();
                        let tool_call_id = req.id.clone();
                        let payload = HostToKernel::RunToolResult(RunToolResult {
                            id: req.id,
                            ok: false,
                            response: None,
                            error: Some("py_repl exec context not found".to_string()),
                        });
                        if let Err(err) = Self::write_message(&stdin, &payload).await {
                            let snapshot =
                                Self::kernel_debug_snapshot(&child, &recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                tool_call_id = %tool_call_id,
                                error = %err,
                                kernel_pid = ?snapshot.pid,
                                kernel_status = %snapshot.status,
                                kernel_stderr_tail = %snapshot.stderr_tail,
                                "failed to reply to kernel run_tool request"
                            );
                        }
                        continue;
                    };

                    let stdin_clone = Arc::clone(&stdin);
                    let exec_contexts = Arc::clone(&exec_contexts);
                    let exec_tool_calls_for_task = Arc::clone(&exec_tool_calls);
                    let recent_stderr = Arc::clone(&recent_stderr);
                    tokio::spawn(async move {
                        let exec_id = req.exec_id.clone();
                        let tool_call_id = req.id.clone();
                        let tool_name = req.tool_name.clone();
                        let context = { exec_contexts.lock().await.get(&exec_id).cloned() };
                        let result = match context {
                            Some(ctx) => {
                                tokio::select! {
                                    _ = reset_cancel.cancelled() => RunToolResult {
                                        id: tool_call_id.clone(),
                                        ok: false,
                                        response: None,
                                        error: Some("py_repl execution reset".to_string()),
                                    },
                                    result = Self::run_tool_request(ctx, req) => result,
                                }
                            }
                            None => RunToolResult {
                                id: tool_call_id.clone(),
                                ok: false,
                                response: None,
                                error: Some("py_repl exec context not found".to_string()),
                            },
                        };
                        Self::finish_exec_tool_call(&exec_tool_calls_for_task, &exec_id).await;
                        let payload = HostToKernel::RunToolResult(result);
                        if let Err(err) = Self::write_message(&stdin_clone, &payload).await {
                            let stderr_tail =
                                Self::kernel_stderr_tail_snapshot(&recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                tool_call_id = %tool_call_id,
                                tool_name = %tool_name,
                                error = %err,
                                kernel_stderr_tail = %stderr_tail,
                                "failed to reply to kernel run_tool request"
                            );
                        }
                    });
                }
                KernelToHost::RunProcess(req) => {
                    let Some(reset_cancel) =
                        Self::begin_exec_tool_call(&exec_tool_calls, &req.exec_id).await
                    else {
                        let exec_id = req.exec_id.clone();
                        let process_call_id = req.id.clone();
                        let payload = HostToKernel::RunProcessResult(RunProcessResult {
                            id: req.id,
                            ok: false,
                            response: None,
                            error: Some("py_repl exec context not found".to_string()),
                        });
                        if let Err(err) = Self::write_message(&stdin, &payload).await {
                            let snapshot =
                                Self::kernel_debug_snapshot(&child, &recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                process_call_id = %process_call_id,
                                error = %err,
                                kernel_pid = ?snapshot.pid,
                                kernel_status = %snapshot.status,
                                kernel_stderr_tail = %snapshot.stderr_tail,
                                "failed to reply to kernel run_process request"
                            );
                        }
                        continue;
                    };

                    let stdin_clone = Arc::clone(&stdin);
                    let exec_contexts = Arc::clone(&exec_contexts);
                    let exec_tool_calls_for_task = Arc::clone(&exec_tool_calls);
                    let recent_stderr = Arc::clone(&recent_stderr);
                    tokio::spawn(async move {
                        let exec_id = req.exec_id.clone();
                        let process_call_id = req.id.clone();
                        let context = { exec_contexts.lock().await.get(&exec_id).cloned() };
                        let result = match context {
                            Some(ctx) => Self::run_process_request(ctx, req, reset_cancel).await,
                            None => RunProcessResult {
                                id: process_call_id.clone(),
                                ok: false,
                                response: None,
                                error: Some("py_repl exec context not found".to_string()),
                            },
                        };
                        Self::finish_exec_tool_call(&exec_tool_calls_for_task, &exec_id).await;
                        let payload = HostToKernel::RunProcessResult(result);
                        if let Err(err) = Self::write_message(&stdin_clone, &payload).await {
                            let stderr_tail =
                                Self::kernel_stderr_tail_snapshot(&recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                process_call_id = %process_call_id,
                                error = %err,
                                kernel_stderr_tail = %stderr_tail,
                                "failed to reply to kernel run_process request"
                            );
                        }
                    });
                }
                KernelToHost::StartProcess(req) => {
                    let Some(reset_cancel) =
                        Self::begin_exec_tool_call(&exec_tool_calls, &req.exec_id).await
                    else {
                        let exec_id = req.exec_id.clone();
                        let process_call_id = req.id.clone();
                        let payload = HostToKernel::StartProcessResult(RunProcessResult {
                            id: req.id,
                            ok: false,
                            response: None,
                            error: Some("py_repl exec context not found".to_string()),
                        });
                        if let Err(err) = Self::write_message(&stdin, &payload).await {
                            let snapshot =
                                Self::kernel_debug_snapshot(&child, &recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                process_call_id = %process_call_id,
                                error = %err,
                                kernel_pid = ?snapshot.pid,
                                kernel_status = %snapshot.status,
                                kernel_stderr_tail = %snapshot.stderr_tail,
                                "failed to reply to kernel start_process request"
                            );
                        }
                        continue;
                    };

                    let stdin_clone = Arc::clone(&stdin);
                    let exec_contexts = Arc::clone(&exec_contexts);
                    let exec_tool_calls_for_task = Arc::clone(&exec_tool_calls);
                    let owned_processes = Arc::clone(&owned_processes);
                    let recent_stderr = Arc::clone(&recent_stderr);
                    tokio::spawn(async move {
                        let exec_id = req.exec_id.clone();
                        let process_call_id = req.id.clone();
                        let context = { exec_contexts.lock().await.get(&exec_id).cloned() };
                        let result = match context {
                            Some(ctx) => {
                                Self::start_process_request(ctx, req, reset_cancel, owned_processes)
                                    .await
                            }
                            None => RunProcessResult {
                                id: process_call_id.clone(),
                                ok: false,
                                response: None,
                                error: Some("py_repl exec context not found".to_string()),
                            },
                        };
                        Self::finish_exec_tool_call(&exec_tool_calls_for_task, &exec_id).await;
                        let payload = HostToKernel::StartProcessResult(result);
                        if let Err(err) = Self::write_message(&stdin_clone, &payload).await {
                            let stderr_tail =
                                Self::kernel_stderr_tail_snapshot(&recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                process_call_id = %process_call_id,
                                error = %err,
                                kernel_stderr_tail = %stderr_tail,
                                "failed to reply to kernel start_process request"
                            );
                        }
                    });
                }
                KernelToHost::PollProcess(req) => {
                    let Some(reset_cancel) =
                        Self::begin_exec_tool_call(&exec_tool_calls, &req.exec_id).await
                    else {
                        let exec_id = req.exec_id.clone();
                        let process_call_id = req.id.clone();
                        let payload = HostToKernel::PollProcessResult(RunProcessResult {
                            id: req.id,
                            ok: false,
                            response: None,
                            error: Some("py_repl exec context not found".to_string()),
                        });
                        if let Err(err) = Self::write_message(&stdin, &payload).await {
                            let snapshot =
                                Self::kernel_debug_snapshot(&child, &recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                process_call_id = %process_call_id,
                                error = %err,
                                kernel_pid = ?snapshot.pid,
                                kernel_status = %snapshot.status,
                                kernel_stderr_tail = %snapshot.stderr_tail,
                                "failed to reply to kernel poll_process request"
                            );
                        }
                        continue;
                    };

                    let stdin_clone = Arc::clone(&stdin);
                    let exec_contexts = Arc::clone(&exec_contexts);
                    let exec_tool_calls_for_task = Arc::clone(&exec_tool_calls);
                    let owned_processes = Arc::clone(&owned_processes);
                    let recent_stderr = Arc::clone(&recent_stderr);
                    tokio::spawn(async move {
                        let exec_id = req.exec_id.clone();
                        let process_call_id = req.id.clone();
                        let context = { exec_contexts.lock().await.get(&exec_id).cloned() };
                        let result = match context {
                            Some(ctx) => {
                                Self::poll_process_request(ctx, req, reset_cancel, owned_processes)
                                    .await
                            }
                            None => RunProcessResult {
                                id: process_call_id.clone(),
                                ok: false,
                                response: None,
                                error: Some("py_repl exec context not found".to_string()),
                            },
                        };
                        Self::finish_exec_tool_call(&exec_tool_calls_for_task, &exec_id).await;
                        let payload = HostToKernel::PollProcessResult(result);
                        if let Err(err) = Self::write_message(&stdin_clone, &payload).await {
                            let stderr_tail =
                                Self::kernel_stderr_tail_snapshot(&recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                process_call_id = %process_call_id,
                                error = %err,
                                kernel_stderr_tail = %stderr_tail,
                                "failed to reply to kernel poll_process request"
                            );
                        }
                    });
                }
                KernelToHost::KillProcess(req) => {
                    let Some(reset_cancel) =
                        Self::begin_exec_tool_call(&exec_tool_calls, &req.exec_id).await
                    else {
                        let exec_id = req.exec_id.clone();
                        let process_call_id = req.id.clone();
                        let payload = HostToKernel::KillProcessResult(RunProcessResult {
                            id: req.id,
                            ok: false,
                            response: None,
                            error: Some("py_repl exec context not found".to_string()),
                        });
                        if let Err(err) = Self::write_message(&stdin, &payload).await {
                            let snapshot =
                                Self::kernel_debug_snapshot(&child, &recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                process_call_id = %process_call_id,
                                error = %err,
                                kernel_pid = ?snapshot.pid,
                                kernel_status = %snapshot.status,
                                kernel_stderr_tail = %snapshot.stderr_tail,
                                "failed to reply to kernel kill_process request"
                            );
                        }
                        continue;
                    };

                    let stdin_clone = Arc::clone(&stdin);
                    let exec_contexts = Arc::clone(&exec_contexts);
                    let exec_tool_calls_for_task = Arc::clone(&exec_tool_calls);
                    let owned_processes = Arc::clone(&owned_processes);
                    let recent_stderr = Arc::clone(&recent_stderr);
                    tokio::spawn(async move {
                        let exec_id = req.exec_id.clone();
                        let process_call_id = req.id.clone();
                        let context = { exec_contexts.lock().await.get(&exec_id).cloned() };
                        let result = match context {
                            Some(ctx) => {
                                tokio::select! {
                                    _ = reset_cancel.cancelled() => RunProcessResult {
                                        id: process_call_id.clone(),
                                        ok: false,
                                        response: None,
                                        error: Some("py_repl execution reset".to_string()),
                                    },
                                    result = Self::kill_process_request(ctx, req, owned_processes) => result,
                                }
                            }
                            None => RunProcessResult {
                                id: process_call_id.clone(),
                                ok: false,
                                response: None,
                                error: Some("py_repl exec context not found".to_string()),
                            },
                        };
                        Self::finish_exec_tool_call(&exec_tool_calls_for_task, &exec_id).await;
                        let payload = HostToKernel::KillProcessResult(result);
                        if let Err(err) = Self::write_message(&stdin_clone, &payload).await {
                            let stderr_tail =
                                Self::kernel_stderr_tail_snapshot(&recent_stderr).await;
                            warn!(
                                exec_id = %exec_id,
                                process_call_id = %process_call_id,
                                error = %err,
                                kernel_stderr_tail = %stderr_tail,
                                "failed to reply to kernel kill_process request"
                            );
                        }
                    });
                }
            }
        };

        let exec_ids = {
            let mut contexts = exec_contexts.lock().await;
            let ids = contexts.keys().cloned().collect::<Vec<_>>();
            contexts.clear();
            ids
        };
        for exec_id in exec_ids {
            Self::wait_for_exec_tool_calls_map(&exec_tool_calls, &exec_id).await;
            Self::clear_exec_tool_calls_map(&exec_tool_calls, &exec_id).await;
        }
        let unexpected_snapshot = if matches!(end_reason, KernelStreamEnd::Shutdown) {
            None
        } else {
            Some(Self::kernel_debug_snapshot(&child, &recent_stderr).await)
        };
        let kernel_failure_message = unexpected_snapshot.as_ref().map(|snapshot| {
            with_model_kernel_failure_message(
                "py_repl kernel exited unexpectedly",
                end_reason.reason(),
                end_reason.error(),
                snapshot,
            )
        });
        let kernel_exit_message = kernel_failure_message
            .clone()
            .unwrap_or_else(|| "py_repl kernel exited unexpectedly".to_string());

        {
            let mut kernel = manager_kernel.lock().await;
            let should_clear = kernel
                .as_ref()
                .is_some_and(|state| Arc::ptr_eq(&state.child, &child));
            if should_clear {
                kernel.take();
            }
        }

        let mut pending = pending_execs.lock().await;
        let pending_exec_ids = pending.keys().cloned().collect::<Vec<_>>();
        for (_id, tx) in pending.drain() {
            let _ = tx.send(ExecResultMessage::Err {
                message: kernel_exit_message.clone(),
                restart_after: false,
            });
        }
        drop(pending);

        if !matches!(end_reason, KernelStreamEnd::Shutdown) {
            Self::terminate_owned_processes(&owned_processes, end_reason.reason()).await;
            let mut pending_exec_ids = pending_exec_ids;
            pending_exec_ids.sort_unstable();
            let snapshot = Self::kernel_debug_snapshot(&child, &recent_stderr).await;
            warn!(
                reason = %end_reason.reason(),
                stream_error = %end_reason.error().unwrap_or(""),
                kernel_pid = ?snapshot.pid,
                kernel_status = %snapshot.status,
                pending_exec_count = pending_exec_ids.len(),
                pending_exec_ids = ?Self::truncate_id_list(&pending_exec_ids),
                kernel_stderr_tail = %snapshot.stderr_tail,
                "py_repl kernel terminated unexpectedly"
            );
        }
    }

    async fn run_tool_request(exec: ExecContext, req: RunToolRequest) -> RunToolResult {
        if is_py_repl_internal_tool(&req.tool_name) {
            return RunToolResult {
                id: req.id,
                ok: false,
                response: None,
                error: Some("py_repl cannot invoke itself".to_string()),
            };
        }

        let manager = exec.session.services.mcp_connection_manager.load_full();
        let mcp_tools = manager.list_all_tools().await;

        let router = ToolRouter::from_turn_context(
            exec.turn.as_ref(),
            ToolRouterParams {
                deferred_mcp_tools: None,
                mcp_tools: Some(mcp_tools),
                discoverable_tools: None,
                extension_tool_executors: crate::tools::router::extension_tool_executors(
                    exec.session.as_ref(),
                ),
                dynamic_tools: exec.turn.dynamic_tools.as_slice(),
            },
        );

        let specs = router.model_visible_specs();
        let (requested_tool_name, requested_spec_is_freeform) = specs
            .iter()
            .find_map(|spec| match spec {
                codex_tools::ToolSpec::Function(tool) if tool.name == req.tool_name => {
                    Some((ToolName::plain(req.tool_name.clone()), false))
                }
                codex_tools::ToolSpec::Freeform(tool) if tool.name == req.tool_name => {
                    Some((ToolName::plain(req.tool_name.clone()), true))
                }
                codex_tools::ToolSpec::Namespace(namespace) => {
                    namespace.tools.iter().find_map(|tool| match tool {
                        ResponsesApiNamespaceTool::Function(tool) => {
                            let tool_name =
                                ToolName::namespaced(namespace.name.clone(), tool.name.clone());
                            (flat_tool_name(&tool_name) == req.tool_name)
                                .then_some((tool_name, false))
                        }
                    })
                }
                codex_tools::ToolSpec::ImageGeneration { .. }
                | codex_tools::ToolSpec::ToolSearch { .. }
                | codex_tools::ToolSpec::WebSearch { .. }
                | codex_tools::ToolSpec::Function(_)
                | codex_tools::ToolSpec::Freeform(_) => None,
            })
            .unwrap_or_else(|| (ToolName::plain(req.tool_name.clone()), false));

        let payload = if requested_spec_is_freeform {
            crate::tools::context::ToolPayload::Custom {
                input: req.arguments.clone(),
            }
        } else {
            crate::tools::context::ToolPayload::Function {
                arguments: req.arguments.clone(),
            }
        };

        let call = crate::tools::router::ToolCall {
            tool_name: requested_tool_name,
            call_id: req.id.clone(),
            payload,
        };

        match router
            .dispatch_tool_call_with_code_mode_result(
                Arc::clone(&exec.session),
                Arc::clone(&exec.turn),
                exec.cancellation_token.child_token(),
                exec.tracker,
                call,
                crate::tools::router::ToolCallSource::PyRepl,
            )
            .await
        {
            Ok(response) => {
                let response =
                    serde_json::to_value(response.into_response()).unwrap_or_else(|err| {
                        JsonValue::String(format!("failed to serialize tool response: {err}"))
                    });
                RunToolResult {
                    id: req.id,
                    ok: true,
                    response: Some(response),
                    error: None,
                }
            }
            Err(err) => RunToolResult {
                id: req.id,
                ok: false,
                response: None,
                error: Some(err.to_string()),
            },
        }
    }

    async fn run_process_request(
        exec: ExecContext,
        req: RunProcessRequest,
        reset_cancel: CancellationToken,
    ) -> RunProcessResult {
        let started_at = StdInstant::now();
        let timeout_ms = req.timeout_ms.unwrap_or(PY_REPL_DEFAULT_TIMEOUT_MS).max(1);
        let prepared = match Self::prepare_process_exec_request(
            &exec,
            req,
            timeout_ms.min(PY_REPL_DEFAULT_TIMEOUT_MS),
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(result) => return result,
        };
        let request_id = prepared.request_id.clone();
        let process_id = prepared.process_id;
        let max_output_tokens = prepared.max_output_tokens;
        let manager = &exec.session.services.unified_exec_manager;
        let context = UnifiedExecContext::new(
            Arc::clone(&exec.session),
            Arc::clone(&exec.turn),
            request_id.clone(),
        );

        let initial_output = tokio::select! {
            _ = reset_cancel.cancelled() => {
                if !manager.terminate_process(process_id).await {
                    manager.release_process_id(process_id).await;
                }
                return Self::run_process_error(request_id, "py_repl execution reset");
            }
            output = manager.exec_command(prepared.request, &context) => output,
        };
        let mut output = match initial_output {
            Ok(output) => output,
            Err(err) => {
                return Self::run_process_error(request_id, err.to_string());
            }
        };

        let mut output_bytes = std::mem::take(&mut output.raw_output);
        let mut exit_code = output.exit_code;
        let mut session_id = output.process_id;
        let mut timed_out = false;

        while let Some(live_process_id) = session_id {
            let elapsed_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
            if elapsed_ms >= timeout_ms {
                timed_out = true;
                manager.terminate_process(live_process_id).await;
                session_id = None;
                break;
            }

            let poll_request = WriteStdinRequest {
                process_id: live_process_id,
                input: "",
                yield_time_ms: (timeout_ms - elapsed_ms).clamp(1, PY_REPL_DEFAULT_TIMEOUT_MS),
                max_output_tokens,
                truncation_policy: exec.turn.truncation_policy,
            };
            let poll_output = tokio::select! {
                _ = reset_cancel.cancelled() => {
                    manager.terminate_process(live_process_id).await;
                    return Self::run_process_error(request_id, "py_repl execution reset");
                }
                output = manager.write_stdin(poll_request) => output,
            };

            match poll_output {
                Ok(mut next_output) => {
                    output_bytes.append(&mut next_output.raw_output);
                    exit_code = next_output.exit_code;
                    session_id = next_output.process_id;
                }
                Err(UnifiedExecError::UnknownProcessId { .. }) => {
                    session_id = None;
                }
                Err(err) => {
                    return Self::run_process_error(request_id, err.to_string());
                }
            }
        }

        Self::finish_run_process_request(
            &exec,
            RunProcessCompletion {
                request_id,
                started_at,
                output_bytes,
                exit_code,
                timed_out,
                session_id,
            },
        )
        .await
    }

    async fn start_process_request(
        exec: ExecContext,
        req: RunProcessRequest,
        reset_cancel: CancellationToken,
        owned_processes: OwnedProcessMap,
    ) -> RunProcessResult {
        let started_at = StdInstant::now();
        let yield_time_ms = req
            .yield_time_ms
            .or(req.timeout_ms)
            .unwrap_or(1_000)
            .clamp(1, PY_REPL_DEFAULT_TIMEOUT_MS);
        let prepared = match Self::prepare_process_exec_request(&exec, req, yield_time_ms).await {
            Ok(prepared) => prepared,
            Err(result) => return result,
        };
        let request_id = prepared.request_id.clone();
        let process_id = prepared.process_id;
        let manager = &exec.session.services.unified_exec_manager;
        let context = UnifiedExecContext::new(
            Arc::clone(&exec.session),
            Arc::clone(&exec.turn),
            request_id.clone(),
        );
        let initial_output = tokio::select! {
            _ = reset_cancel.cancelled() => {
                if !manager.terminate_process(process_id).await {
                    manager.release_process_id(process_id).await;
                }
                return Self::run_process_error(request_id, "py_repl execution reset");
            }
            output = manager.exec_command(prepared.request, &context) => output,
        };
        let mut output = match initial_output {
            Ok(output) => output,
            Err(err) => {
                return Self::run_process_error(request_id, err.to_string());
            }
        };

        let session_id = output.process_id;
        if let Some(process_id) = session_id {
            Self::record_owned_process(&owned_processes, process_id, &exec.session).await;
        }

        Self::finish_run_process_request(
            &exec,
            RunProcessCompletion {
                request_id,
                started_at,
                output_bytes: std::mem::take(&mut output.raw_output),
                exit_code: output.exit_code,
                timed_out: false,
                session_id,
            },
        )
        .await
    }

    async fn poll_process_request(
        exec: ExecContext,
        req: PollProcessRequest,
        reset_cancel: CancellationToken,
        owned_processes: OwnedProcessMap,
    ) -> RunProcessResult {
        let request_id = req.id;
        let requested_session_id = req.session_id;
        if req.session_id <= 0 {
            return Self::run_process_error(
                request_id,
                "codex.process poll requires a positive session_id",
            );
        }

        let started_at = StdInstant::now();
        let timeout_ms = req
            .timeout_ms
            .unwrap_or(250)
            .clamp(1, PY_REPL_DEFAULT_TIMEOUT_MS);
        let manager = &exec.session.services.unified_exec_manager;
        let poll_request = WriteStdinRequest {
            process_id: req.session_id,
            input: "",
            yield_time_ms: timeout_ms,
            max_output_tokens: req.max_output_tokens,
            truncation_policy: exec.turn.truncation_policy,
        };
        let poll_output = tokio::select! {
            _ = reset_cancel.cancelled() => {
                return Self::run_process_error(request_id, "py_repl execution reset");
            }
            output = manager.write_stdin(poll_request) => output,
        };
        let mut output = match poll_output {
            Ok(output) => output,
            Err(UnifiedExecError::UnknownProcessId { process_id }) => {
                Self::forget_owned_process(&owned_processes, process_id).await;
                return Self::run_process_error(
                    request_id,
                    UnifiedExecError::UnknownProcessId { process_id }.to_string(),
                );
            }
            Err(err) => {
                return Self::run_process_error(request_id, err.to_string());
            }
        };
        let session_id = output.process_id;
        if let Some(process_id) = session_id {
            Self::record_owned_process(&owned_processes, process_id, &exec.session).await;
        } else {
            Self::forget_owned_process(&owned_processes, requested_session_id).await;
        }

        Self::finish_run_process_request(
            &exec,
            RunProcessCompletion {
                request_id,
                started_at,
                output_bytes: std::mem::take(&mut output.raw_output),
                exit_code: output.exit_code,
                timed_out: session_id.is_some(),
                session_id,
            },
        )
        .await
    }

    async fn kill_process_request(
        exec: ExecContext,
        req: KillProcessRequest,
        owned_processes: OwnedProcessMap,
    ) -> RunProcessResult {
        let request_id = req.id;
        if req.session_id <= 0 {
            return Self::run_process_error(
                request_id,
                "codex.process kill requires a positive session_id",
            );
        }

        let started_at = StdInstant::now();
        let manager = &exec.session.services.unified_exec_manager;
        if !manager.terminate_process(req.session_id).await {
            Self::forget_owned_process(&owned_processes, req.session_id).await;
            return Self::run_process_error(
                request_id,
                format!("Unknown process id {}", req.session_id),
            );
        }
        Self::forget_owned_process(&owned_processes, req.session_id).await;

        Self::finish_run_process_request(
            &exec,
            RunProcessCompletion {
                request_id,
                started_at,
                output_bytes: Vec::new(),
                exit_code: None,
                timed_out: false,
                session_id: None,
            },
        )
        .await
    }

    async fn prepare_process_exec_request(
        exec: &ExecContext,
        req: RunProcessRequest,
        yield_time_ms: u64,
    ) -> Result<PreparedProcessExec, RunProcessResult> {
        let request_id = req.id.clone();
        if req.command.is_empty()
            || req
                .command
                .first()
                .is_none_or(std::string::String::is_empty)
        {
            return Err(Self::run_process_error(
                request_id,
                "codex.process.run expects a non-empty command list",
            ));
        }

        let manager = &exec.session.services.unified_exec_manager;
        let Some(turn_environment) = exec.turn.environments.primary() else {
            return Err(Self::run_process_error(
                request_id,
                "unified exec is unavailable in this session",
            ));
        };
        let cwd = req
            .cwd
            .clone()
            .filter(|value| !value.is_empty())
            .map_or_else(
                || turn_environment.cwd().clone(),
                |cwd| turn_environment.cwd().join(cwd),
            );
        let hook_command = codex_shell_command::parse_command::shlex_join(&req.command);
        let process_id = manager.allocate_process_id().await;
        let environment = Arc::clone(&turn_environment.environment);

        let exec_permission_approvals_enabled = exec
            .session
            .features()
            .enabled(Feature::ExecPermissionApprovals);
        let requested_additional_permissions = req.additional_permissions.clone();
        let effective_additional_permissions = apply_granted_turn_permissions(
            exec.session.as_ref(),
            &turn_environment.environment_id,
            cwd.as_path(),
            req.sandbox_permissions,
            req.additional_permissions.clone(),
        )
        .await;
        let additional_permissions_allowed = exec_permission_approvals_enabled
            || (exec
                .session
                .features()
                .enabled(Feature::RequestPermissionsTool)
                && effective_additional_permissions.permissions_preapproved);

        if effective_additional_permissions
            .sandbox_permissions
            .requests_sandbox_override()
            && !effective_additional_permissions.permissions_preapproved
            && !matches!(
                exec.turn.approval_policy.value(),
                codex_protocol::protocol::AskForApproval::OnRequest
            )
        {
            let approval_policy = exec.turn.approval_policy.value();
            manager.release_process_id(process_id).await;
            return Err(Self::run_process_error(
                request_id,
                format!(
                    "approval policy is {approval_policy:?}; reject command - you cannot ask for escalated permissions if the approval policy is {approval_policy:?}"
                ),
            ));
        }

        let normalized_additional_permissions = match implicit_granted_permissions(
            req.sandbox_permissions,
            requested_additional_permissions.as_ref(),
            &effective_additional_permissions,
        )
        .map_or_else(
            || {
                normalize_and_validate_additional_permissions(
                    additional_permissions_allowed,
                    exec.turn.approval_policy.value(),
                    effective_additional_permissions.sandbox_permissions,
                    effective_additional_permissions
                        .additional_permissions
                        .clone(),
                    effective_additional_permissions.permissions_preapproved,
                    cwd.as_path(),
                )
            },
            |permissions| Ok(Some(permissions)),
        ) {
            Ok(normalized) => normalized,
            Err(err) => {
                manager.release_process_id(process_id).await;
                return Err(Self::run_process_error(request_id, err));
            }
        };

        let request = ExecCommandRequest {
            command: req.command,
            shell_type: exec.session.user_shell().shell_type,
            hook_command,
            process_id,
            yield_time_ms,
            max_output_tokens: req.max_output_tokens,
            cwd: cwd.clone(),
            sandbox_cwd: cwd,
            environment,
            env: req.env,
            shell_mode: shell_mode_for_environment(
                &exec.turn.unified_exec_shell_mode,
                turn_environment.environment.as_ref(),
            ),
            network: exec.turn.network.clone(),
            tty: false,
            sandbox_permissions: effective_additional_permissions.sandbox_permissions,
            additional_permissions: normalized_additional_permissions,
            additional_permissions_preapproved: effective_additional_permissions
                .permissions_preapproved,
            justification: req.justification,
            prefix_rule: req.prefix_rule,
        };

        Ok(PreparedProcessExec {
            request_id,
            process_id,
            max_output_tokens: request.max_output_tokens,
            request,
        })
    }

    fn run_process_error(id: String, error: impl Into<String>) -> RunProcessResult {
        RunProcessResult {
            id,
            ok: false,
            response: None,
            error: Some(error.into()),
        }
    }

    async fn finish_run_process_request(
        exec: &ExecContext,
        completion: RunProcessCompletion,
    ) -> RunProcessResult {
        let output = String::from_utf8_lossy(&completion.output_bytes).to_string();
        let original_token_count = Some(approx_token_count(&output));
        let elapsed_ms =
            u64::try_from(completion.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        let output_path =
            Self::write_run_process_log(exec, &completion.request_id, &completion.output_bytes)
                .await;

        RunProcessResult {
            id: completion.request_id,
            ok: true,
            response: Some(RunProcessResponse {
                exit_code: completion.exit_code,
                timed_out: completion.timed_out,
                elapsed_ms,
                stdout: output.clone(),
                stderr: String::new(),
                output,
                stdout_path: output_path.clone(),
                stderr_path: None,
                output_path,
                session_id: completion.session_id,
                original_token_count,
            }),
            error: None,
        }
    }

    async fn write_run_process_log(
        exec: &ExecContext,
        request_id: &str,
        output_bytes: &[u8],
    ) -> Option<String> {
        let safe_id: String = request_id
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        let path = exec.tmp_dir.join(format!("{safe_id}.log"));
        match tokio::fs::write(&path, output_bytes).await {
            Ok(()) => Some(path.to_string_lossy().to_string()),
            Err(err) => {
                warn!(
                    process_call_id = %request_id,
                    path = %path.display(),
                    error = %err,
                    "failed to persist py_repl process output"
                );
                None
            }
        }
    }

    async fn read_stderr(
        stderr: tokio::process::ChildStderr,
        recent_stderr: Arc<Mutex<VecDeque<String>>>,
        shutdown: CancellationToken,
    ) {
        let mut reader = BufReader::new(stderr).lines();

        loop {
            let line = tokio::select! {
                _ = shutdown.cancelled() => break,
                res = reader.next_line() => match res {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(err) => {
                        warn!("py_repl kernel stderr ended: {err}");
                        break;
                    }
                },
            };
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let bounded_line = {
                    let mut tail = recent_stderr.lock().await;
                    push_stderr_tail_line(&mut tail, trimmed)
                };
                if bounded_line.is_empty() {
                    continue;
                }
                warn!("py_repl stderr: {bounded_line}");
            }
        }
    }
}

fn emitted_image_content_item(
    turn: &TurnContext,
    image_url: String,
    detail: Option<ImageDetail>,
) -> FunctionCallOutputContentItem {
    FunctionCallOutputContentItem::InputImage {
        image_url,
        detail: normalize_output_image_detail(&turn.model_info, detail),
    }
}

fn validate_emitted_image_url(image_url: &str) -> Result<(), String> {
    validate_repl_image_data_url(image_url, "codex.emit_image")
}

fn is_py_repl_internal_tool(name: &str) -> bool {
    matches!(name, "py_repl" | "py_repl_reset")
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum KernelToHost {
    ExecResult {
        id: String,
        ok: bool,
        output: String,
        #[serde(default)]
        error: Option<String>,
        #[serde(default)]
        restart_after: bool,
    },
    RunTool(RunToolRequest),
    RunProcess(RunProcessRequest),
    StartProcess(RunProcessRequest),
    PollProcess(PollProcessRequest),
    KillProcess(KillProcessRequest),
    EmitImage(EmitImageRequest),
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HostToKernel {
    Exec {
        id: String,
        code: String,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    RunToolResult(RunToolResult),
    RunProcessResult(RunProcessResult),
    StartProcessResult(RunProcessResult),
    PollProcessResult(RunProcessResult),
    KillProcessResult(RunProcessResult),
    EmitImageResult(EmitImageResult),
}

#[derive(Clone, Debug, Deserialize)]
struct RunToolRequest {
    id: String,
    exec_id: String,
    tool_name: String,
    arguments: String,
}

#[derive(Clone, Debug, Serialize)]
struct RunToolResult {
    id: String,
    ok: bool,
    #[serde(default)]
    response: Option<JsonValue>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RunProcessRequest {
    id: String,
    exec_id: String,
    command: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    yield_time_ms: Option<u64>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    max_output_tokens: Option<usize>,
    #[serde(default)]
    sandbox_permissions: SandboxPermissions,
    #[serde(default)]
    additional_permissions: Option<AdditionalPermissionProfile>,
    #[serde(default)]
    justification: Option<String>,
    #[serde(default)]
    prefix_rule: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
struct PollProcessRequest {
    id: String,
    exec_id: String,
    session_id: i32,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    max_output_tokens: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
struct KillProcessRequest {
    id: String,
    exec_id: String,
    session_id: i32,
}

#[derive(Clone, Debug, Serialize)]
struct RunProcessResult {
    id: String,
    ok: bool,
    #[serde(default)]
    response: Option<RunProcessResponse>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct RunProcessResponse {
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed_ms: u64,
    output: String,
    stdout: String,
    stderr: String,
    output_path: Option<String>,
    stdout_path: Option<String>,
    stderr_path: Option<String>,
    session_id: Option<i32>,
    original_token_count: Option<usize>,
}

struct RunProcessCompletion {
    request_id: String,
    started_at: StdInstant,
    output_bytes: Vec<u8>,
    exit_code: Option<i32>,
    timed_out: bool,
    session_id: Option<i32>,
}

struct PreparedProcessExec {
    request_id: String,
    process_id: i32,
    max_output_tokens: Option<usize>,
    request: ExecCommandRequest,
}

#[derive(Clone, Debug, Deserialize)]
struct EmitImageRequest {
    id: String,
    exec_id: String,
    image_url: String,
    #[serde(default)]
    detail: Option<ImageDetail>,
}

#[derive(Clone, Debug, Serialize)]
struct EmitImageResult {
    id: String,
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug)]
enum ExecResultMessage {
    Ok {
        output: String,
        content_items: Vec<FunctionCallOutputContentItem>,
        restart_after: bool,
    },
    Err {
        message: String,
        restart_after: bool,
    },
}

async fn read_python_version(python_path: &Path) -> Result<PythonVersion, String> {
    let output = tokio::process::Command::new(python_path)
        .arg("-c")
        .arg("import sys; print('.'.join(map(str, sys.version_info[:3])))")
        .output()
        .await
        .map_err(|err| format!("failed to start Python runtime: {err}"))?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let mut details = String::new();
        if !stdout.is_empty() {
            details.push_str("stdout: ");
            details.push_str(&stdout);
        }
        if !stderr.is_empty() {
            if !details.is_empty() {
                details.push_str("; ");
            }
            details.push_str("stderr: ");
            details.push_str(&stderr);
        }
        let details = if details.is_empty() {
            String::new()
        } else {
            format!(" ({details})")
        };
        return Err(format!(
            "failed to read Python version (status {}){details}",
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    PythonVersion::parse(stdout)
        .map_err(|err| format!("failed to parse Python version output `{stdout}`: {err}"))
}

async fn ensure_python_version(python_path: &Path) -> Result<(), String> {
    let required = required_python_version();
    let found = read_python_version(python_path).await?;
    if found < required {
        return Err(format!(
            "Python runtime too old for py_repl (resolved {}): found v{found}, requires >= v{required}. Install/update Python or set CODEX_PY_REPL_PYTHON_PATH to a newer runtime.",
            python_path.display()
        ));
    }
    Ok(())
}

pub(crate) async fn resolve_compatible_python(
    config_path: Option<&Path>,
) -> Result<PathBuf, String> {
    let python_path = resolve_python(config_path).ok_or_else(|| {
        "Python runtime not found; install Python or set CODEX_PY_REPL_PYTHON_PATH".to_string()
    })?;
    ensure_python_version(&python_path).await?;
    Ok(python_path)
}

pub(crate) async fn discover_project_venv_python_path(
    config: &Config,
    fs: &dyn ExecutorFileSystem,
) -> Option<PathBuf> {
    let project_root = discover_project_root(config, fs).await.ok()?;
    let candidates = if cfg!(windows) {
        [".venv/Scripts/python.exe", ".venv/Scripts/python3.exe"]
    } else {
        [".venv/bin/python", ".venv/bin/python3"]
    };

    for relative in candidates {
        let candidate = project_root.join(relative);
        let candidate_uri = PathUri::from_abs_path(&candidate);
        match fs.get_metadata(&candidate_uri, /*sandbox*/ None).await {
            Ok(metadata) if metadata.is_file => return Some(candidate.to_path_buf()),
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                warn!(
                    "failed to inspect py_repl project venv candidate {}: {err}",
                    candidate.display()
                );
                return None;
            }
        }
    }

    None
}

pub(crate) fn resolve_python(config_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CODEX_PY_REPL_PYTHON_PATH")
        && !path.is_empty()
    {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }

    if let Some(path) = config_path
        && path.exists()
    {
        return Some(path.to_path_buf());
    }

    if let Ok(path) = which::which("python3") {
        return Some(path);
    }

    if let Ok(path) = which::which("python") {
        return Some(path);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigBuilder;
    use crate::session::tests::make_session_and_context;
    use codex_exec_server::LOCAL_FS;
    use codex_features::Feature;
    use codex_protocol::models::FunctionCallOutputContentItem;
    use codex_protocol::models::ImageDetail;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use pretty_assertions::assert_eq;
    use std::fs;

    const VALID_PNG_DATA_URL: &str = crate::tools::repl_image::VALID_TEST_PNG_DATA_URL;

    #[test]
    fn python_version_parses_prefix_and_patch() {
        let parsed = PythonVersion::parse("Python 3.10.12").expect("version should parse");
        assert_eq!(parsed, PythonVersion::new(3, 10, 12));
    }

    #[test]
    fn emitted_image_url_requires_data_scheme() {
        assert_eq!(validate_emitted_image_url(VALID_PNG_DATA_URL), Ok(()));
        assert_eq!(
            validate_emitted_image_url("https://example.com/image.png"),
            Err("codex.emit_image only accepts data URLs".to_string())
        );
    }

    #[test]
    fn emitted_image_url_rejects_unsupported_svg_data_url() {
        assert_eq!(
            validate_emitted_image_url("data:image/svg+xml;base64,PHN2Zy8+"),
            Err(
                "codex.emit_image does not support image format `image/svg+xml`; use PNG, JPEG, GIF, or WebP"
                    .to_string()
            )
        );
    }

    #[test]
    fn emitted_image_url_rejects_invalid_image_bytes() {
        assert_eq!(
            validate_emitted_image_url("data:image/png;base64,AAA="),
            Err("codex.emit_image received invalid image data".to_string())
        );
    }

    #[tokio::test]
    async fn discover_project_venv_python_path_uses_project_root() {
        let repo = tempfile::tempdir().expect("tempdir");
        fs::write(repo.path().join(".git"), "gitdir: /tmp/test.git\n").expect("write .git marker");

        let nested = repo.path().join("packages/core");
        fs::create_dir_all(&nested).expect("create nested cwd");

        let python_path = if cfg!(windows) {
            let scripts = repo.path().join(".venv/Scripts");
            fs::create_dir_all(&scripts).expect("create scripts dir");
            scripts.join("python.exe")
        } else {
            let bin = repo.path().join(".venv/bin");
            fs::create_dir_all(&bin).expect("create bin dir");
            bin.join("python")
        };
        fs::write(&python_path, "").expect("create venv interpreter placeholder");

        let codex_home = tempfile::tempdir().expect("codex home");
        let mut config = ConfigBuilder::default()
            .codex_home(codex_home.path().to_path_buf())
            .build()
            .await
            .expect("defaults for test should always succeed");
        config.cwd =
            AbsolutePathBuf::try_from(dunce::canonicalize(&nested).expect("canonical cwd"))
                .expect("absolute cwd");

        let resolved = discover_project_venv_python_path(&config, LOCAL_FS.as_ref()).await;

        assert_eq!(resolved, Some(python_path));
    }

    #[tokio::test]
    async fn emitted_image_content_item_preserves_explicit_non_original_detail() {
        let (_session, turn) = make_session_and_context().await;
        let content_item = emitted_image_content_item(
            &turn,
            "data:image/png;base64,AAA".to_string(),
            Some(ImageDetail::High),
        );
        assert_eq!(
            content_item,
            FunctionCallOutputContentItem::InputImage {
                image_url: "data:image/png;base64,AAA".to_string(),
                detail: Some(ImageDetail::High),
            }
        );
    }

    #[tokio::test]
    async fn emitted_image_content_item_does_not_force_original_when_enabled() {
        let (_session, mut turn) = make_session_and_context().await;
        Arc::make_mut(&mut turn.config)
            .features
            .enable(Feature::ImageDetailOriginal)
            .expect("test config should allow feature update");
        turn.features
            .enable(Feature::ImageDetailOriginal)
            .expect("test turn features should allow feature update");
        turn.model_info.supports_image_detail_original = true;

        let content_item =
            emitted_image_content_item(&turn, "data:image/png;base64,AAA".to_string(), None);

        assert_eq!(
            content_item,
            FunctionCallOutputContentItem::InputImage {
                image_url: "data:image/png;base64,AAA".to_string(),
                detail: None,
            }
        );
    }

    #[tokio::test]
    async fn emitted_image_content_item_allows_explicit_original_detail_when_enabled() {
        let (_session, mut turn) = make_session_and_context().await;
        Arc::make_mut(&mut turn.config)
            .features
            .enable(Feature::ImageDetailOriginal)
            .expect("test config should allow feature update");
        turn.features
            .enable(Feature::ImageDetailOriginal)
            .expect("test turn features should allow feature update");
        turn.model_info.supports_image_detail_original = true;

        let content_item = emitted_image_content_item(
            &turn,
            "data:image/png;base64,AAA".to_string(),
            Some(ImageDetail::Original),
        );

        assert_eq!(
            content_item,
            FunctionCallOutputContentItem::InputImage {
                image_url: "data:image/png;base64,AAA".to_string(),
                detail: Some(ImageDetail::Original),
            }
        );
    }

    #[tokio::test]
    async fn emitted_image_content_item_drops_explicit_original_detail_when_disabled() {
        let (_session, turn) = make_session_and_context().await;

        let content_item = emitted_image_content_item(
            &turn,
            "data:image/png;base64,AAA".to_string(),
            Some(ImageDetail::Original),
        );

        assert_eq!(
            content_item,
            FunctionCallOutputContentItem::InputImage {
                image_url: "data:image/png;base64,AAA".to_string(),
                detail: None,
            }
        );
    }
}

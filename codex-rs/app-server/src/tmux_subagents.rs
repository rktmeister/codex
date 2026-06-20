use crate::transport::AppServerTransport;
use codex_app_server_protocol::ClientTmuxContext;
use codex_arg0::Arg0DispatchPaths;
use codex_protocol::ThreadId;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use std::collections::HashSet;
use std::io;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::info;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum TmuxSubagentPolicy {
    #[default]
    Disabled,
    ParentContext,
    Always,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TmuxSubagentOptions {
    policy: TmuxSubagentPolicy,
}

impl TmuxSubagentOptions {
    pub fn parent_context() -> Self {
        Self {
            policy: TmuxSubagentPolicy::ParentContext,
        }
    }

    pub fn always() -> Self {
        Self {
            policy: TmuxSubagentPolicy::Always,
        }
    }

    pub(crate) fn is_enabled(self) -> bool {
        !matches!(self.policy, TmuxSubagentPolicy::Disabled)
    }

    fn allows_detached_fallback(self) -> bool {
        matches!(self.policy, TmuxSubagentPolicy::Always)
    }
}

#[derive(Clone)]
pub(crate) struct TmuxSubagentLauncher {
    options: TmuxSubagentOptions,
    codex_exe: PathBuf,
    remote_endpoint: String,
    launched_threads: Arc<Mutex<HashSet<ThreadId>>>,
}

pub(crate) struct TmuxSubagentLaunchRequest {
    pub(crate) thread_id: ThreadId,
    pub(crate) cwd: PathBuf,
    pub(crate) session_source: SessionSource,
    pub(crate) parent_tmux: Option<ClientTmuxContext>,
}

impl TmuxSubagentLauncher {
    pub(crate) async fn new(
        options: TmuxSubagentOptions,
        transport: &AppServerTransport,
        arg0_paths: &Arg0DispatchPaths,
    ) -> io::Result<Option<Self>> {
        if !options.is_enabled() {
            return Ok(None);
        }

        if cfg!(windows) {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "--tmux-subagents is not supported on Windows",
            ));
        }

        let remote_endpoint = remote_endpoint_for_transport(transport)?;
        ensure_tmux_available().await?;
        let codex_exe = arg0_paths
            .codex_self_exe
            .clone()
            .or_else(|| std::env::current_exe().ok())
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::NotFound,
                    "failed to resolve Codex executable for tmux subagents",
                )
            })?;

        Ok(Some(Self {
            options,
            codex_exe,
            remote_endpoint,
            launched_threads: Arc::new(Mutex::new(HashSet::new())),
        }))
    }

    pub(crate) async fn launch_subagent(
        &self,
        request: TmuxSubagentLaunchRequest,
    ) -> io::Result<()> {
        {
            let mut launched_threads = self.launched_threads.lock().await;
            if !launched_threads.insert(request.thread_id) {
                return Ok(());
            }
        }

        match self.launch_subagent_once(&request).await {
            Ok(TmuxSubagentLaunchOutcome::Launched) => {}
            Ok(TmuxSubagentLaunchOutcome::SkippedNoParentContext) => {
                self.launched_threads
                    .lock()
                    .await
                    .remove(&request.thread_id);
            }
            Err(err) => {
                self.launched_threads
                    .lock()
                    .await
                    .remove(&request.thread_id);
                return Err(err);
            }
        }
        Ok(())
    }

    async fn launch_subagent_once(
        &self,
        request: &TmuxSubagentLaunchRequest,
    ) -> io::Result<TmuxSubagentLaunchOutcome> {
        let window_name = window_name_for_subagent(&request.session_source, request.thread_id);
        if let Some(parent_tmux) = request.parent_tmux.as_ref() {
            self.launch_subagent_in_parent_tmux(request, parent_tmux, &window_name)
                .await?;
            return Ok(TmuxSubagentLaunchOutcome::Launched);
        }

        if !self.options.allows_detached_fallback() {
            tracing::debug!(
                thread_id = %request.thread_id,
                "skipping tmux subagent observer because no parent tmux context is available"
            );
            return Ok(TmuxSubagentLaunchOutcome::SkippedNoParentContext);
        }

        self.launch_subagent_in_detached_session(request, &window_name)
            .await?;
        Ok(TmuxSubagentLaunchOutcome::Launched)
    }

    async fn launch_subagent_in_parent_tmux(
        &self,
        request: &TmuxSubagentLaunchRequest,
        parent_tmux: &ClientTmuxContext,
        window_name: &str,
    ) -> io::Result<()> {
        let session_target = tmux_parent_session_target(parent_tmux).await?;
        let args = tmux_parent_window_args(
            &session_target,
            window_name,
            &self.codex_exe,
            &self.remote_endpoint,
            &request.cwd,
            request.thread_id,
        );
        let status = tmux_command(Some(parent_tmux))
            .args(&args)
            .stdin(Stdio::null())
            .status()
            .await?;
        ensure_status(status, args.first().map(String::as_str).unwrap_or("tmux"))?;
        info!(
            thread_id = %request.thread_id,
            tmux_target = %session_target,
            tmux_window = %window_name,
            "launched tmux subagent observer in parent tmux session"
        );
        Ok(())
    }

    async fn launch_subagent_in_detached_session(
        &self,
        request: &TmuxSubagentLaunchRequest,
        window_name: &str,
    ) -> io::Result<()> {
        let session_name = session_name_for_cwd(&request.cwd);
        let session_exists = tmux_has_session(&session_name).await?;
        let args = tmux_launch_args(
            &session_name,
            window_name,
            &self.codex_exe,
            &self.remote_endpoint,
            &request.cwd,
            request.thread_id,
            session_exists,
        );
        let status = Command::new("tmux")
            .args(&args)
            .stdin(Stdio::null())
            .status()
            .await?;
        ensure_status(status, args.first().map(String::as_str).unwrap_or("tmux"))?;
        info!(
            thread_id = %request.thread_id,
            tmux_session = %session_name,
            tmux_window = %window_name,
            "launched tmux subagent observer"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TmuxSubagentLaunchOutcome {
    Launched,
    SkippedNoParentContext,
}

pub(crate) fn is_thread_spawn_subagent(session_source: &SessionSource) -> bool {
    matches!(
        session_source,
        SessionSource::SubAgent(SubAgentSource::ThreadSpawn { .. })
    )
}

fn remote_endpoint_for_transport(transport: &AppServerTransport) -> io::Result<String> {
    match transport {
        AppServerTransport::UnixSocket { socket_path } => {
            Ok(format!("unix://{}", socket_path.as_path().display()))
        }
        AppServerTransport::Stdio
        | AppServerTransport::WebSocket { .. }
        | AppServerTransport::Off => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "--tmux-subagents requires --listen unix:// or --listen unix://PATH",
        )),
    }
}

async fn ensure_tmux_available() -> io::Result<()> {
    let status = Command::new("tmux")
        .arg("-V")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(io::Error::new(
            ErrorKind::NotFound,
            format!("tmux is not executable: `tmux -V` exited with {status}"),
        )),
        Err(err) if err.kind() == ErrorKind::NotFound => Err(io::Error::new(
            ErrorKind::NotFound,
            "tmux is not installed; install tmux before using --tmux-subagents",
        )),
        Err(err) => Err(err),
    }
}

async fn tmux_has_session(session_name: &str) -> io::Result<bool> {
    let status = tmux_command(/*parent_tmux*/ None)
        .arg("has-session")
        .arg("-t")
        .arg(session_name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    Ok(status.success())
}

fn ensure_status(status: std::process::ExitStatus, command_name: &str) -> io::Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "`tmux {command_name}` exited with {status}"
        )))
    }
}

fn tmux_command(parent_tmux: Option<&ClientTmuxContext>) -> Command {
    let mut command = Command::new("tmux");
    if let Some(socket_path) = parent_tmux.and_then(|tmux| tmux.socket_path.as_ref()) {
        command.arg("-S").arg(socket_path);
    }
    command
}

async fn tmux_parent_session_target(parent_tmux: &ClientTmuxContext) -> io::Result<String> {
    let output = tmux_command(Some(parent_tmux))
        .args([
            "display-message",
            "-t",
            parent_tmux.pane_id.as_str(),
            "-p",
            "#{session_id}:",
        ])
        .stdin(Stdio::null())
        .output()
        .await?;
    ensure_status(output.status, "display-message")?;
    let target = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if target.is_empty() {
        Err(io::Error::new(
            ErrorKind::InvalidData,
            "tmux did not report a parent session id",
        ))
    } else {
        Ok(target)
    }
}

fn tmux_launch_args(
    session_name: &str,
    window_name: &str,
    codex_exe: &Path,
    remote_endpoint: &str,
    cwd: &Path,
    thread_id: ThreadId,
    session_exists: bool,
) -> Vec<String> {
    let cwd = cwd.to_string_lossy().to_string();
    let codex_exe = codex_exe.to_string_lossy().to_string();
    let thread_id = thread_id.to_string();
    let mut args = if session_exists {
        vec![
            "new-window".to_string(),
            "-t".to_string(),
            session_name.to_string(),
            "-n".to_string(),
            window_name.to_string(),
        ]
    } else {
        vec![
            "new-session".to_string(),
            "-d".to_string(),
            "-s".to_string(),
            session_name.to_string(),
            "-n".to_string(),
            window_name.to_string(),
        ]
    };
    args.extend([
        "-c".to_string(),
        cwd.clone(),
        "--".to_string(),
        codex_exe,
        "--remote".to_string(),
        remote_endpoint.to_string(),
        "-C".to_string(),
        cwd,
        "resume".to_string(),
        thread_id,
    ]);
    args
}

fn tmux_parent_window_args(
    session_target: &str,
    window_name: &str,
    codex_exe: &Path,
    remote_endpoint: &str,
    cwd: &Path,
    thread_id: ThreadId,
) -> Vec<String> {
    let cwd = cwd.to_string_lossy().to_string();
    let codex_exe = codex_exe.to_string_lossy().to_string();
    let thread_id = thread_id.to_string();
    vec![
        "new-window".to_string(),
        "-d".to_string(),
        "-t".to_string(),
        session_target.to_string(),
        "-n".to_string(),
        window_name.to_string(),
        "-c".to_string(),
        cwd.clone(),
        "--".to_string(),
        codex_exe,
        "--remote".to_string(),
        remote_endpoint.to_string(),
        "-C".to_string(),
        cwd,
        "resume".to_string(),
        thread_id,
    ]
}

fn session_name_for_cwd(cwd: &Path) -> String {
    let component = cwd
        .file_name()
        .and_then(|value| value.to_str())
        .map(sanitize_tmux_name_component)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "workspace".to_string());
    let hash = stable_path_hash(cwd) & 0xffff_ffff;
    format!("codex_agents_{component}_{hash:08x}")
}

fn window_name_for_subagent(session_source: &SessionSource, thread_id: ThreadId) -> String {
    let base_name = match session_source {
        SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            agent_path: Some(agent_path),
            ..
        }) => agent_path.name().to_string(),
        SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            agent_nickname: Some(agent_nickname),
            ..
        }) => agent_nickname.clone(),
        SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            agent_role: Some(agent_role),
            ..
        }) => agent_role.clone(),
        _ => format!("agent-{}", short_thread_id(thread_id)),
    };
    sanitize_tmux_name_component(&base_name)
}

fn short_thread_id(thread_id: ThreadId) -> String {
    thread_id.to_string().chars().take(8).collect()
}

fn sanitize_tmux_name_component(component: &str) -> String {
    let mut sanitized = String::new();
    for ch in component.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
        if sanitized.len() == 48 {
            break;
        }
    }

    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        "agent".to_string()
    } else {
        trimmed.to_string()
    }
}

fn stable_path_hash(path: &Path) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

#[cfg(test)]
#[path = "tmux_subagents_tests.rs"]
mod tests;

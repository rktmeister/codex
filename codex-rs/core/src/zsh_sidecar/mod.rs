#![allow(dead_code)]

use crate::error::CodexErr;
use crate::exec::ExecExpiration;
use crate::exec::ExecToolCallOutput;
use crate::exec::StdoutStream;
use crate::sandboxing::CommandSpec;
use crate::sandboxing::SandboxPermissions;
use crate::tools::sandboxing::SandboxAttempt;
use crate::tools::sandboxing::ToolError;
use codex_network_proxy::NetworkProxy;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::Mutex;

pub(crate) mod protocol;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ZshSidecarState {
    pub(crate) initialized_session_id: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ZshSidecarManager {
    zsh_path: Option<PathBuf>,
    codex_home: Option<PathBuf>,
    state: Mutex<ZshSidecarState>,
}

#[derive(Debug, Clone)]
pub(crate) struct ZshSidecarExecRequest {
    pub(crate) command: Vec<String>,
    pub(crate) cwd: PathBuf,
    pub(crate) timeout_ms: Option<u64>,
    pub(crate) env: HashMap<String, String>,
    pub(crate) network: Option<NetworkProxy>,
    pub(crate) sandbox_permissions: SandboxPermissions,
    pub(crate) justification: Option<String>,
}

impl ZshSidecarManager {
    pub(crate) fn new(zsh_path: Option<PathBuf>, codex_home: PathBuf) -> Self {
        Self {
            zsh_path,
            codex_home: Some(codex_home),
            state: Mutex::new(ZshSidecarState::default()),
        }
    }

    pub(crate) async fn initialize_for_session(&self, session_id: &str) {
        let mut state = self.state.lock().await;
        state.initialized_session_id = Some(session_id.to_string());
    }

    pub(crate) async fn shutdown(&self) {
        let mut state = self.state.lock().await;
        state.initialized_session_id = None;
    }

    pub(crate) fn zsh_path(&self) -> Option<&PathBuf> {
        self.zsh_path.as_ref()
    }

    pub(crate) fn codex_home(&self) -> Option<&PathBuf> {
        self.codex_home.as_ref()
    }

    pub(crate) async fn execute_shell_request(
        &self,
        req: &ZshSidecarExecRequest,
        attempt: &SandboxAttempt<'_>,
        stdout_stream: Option<StdoutStream>,
    ) -> Result<ExecToolCallOutput, ToolError> {
        if self.zsh_path.is_none() {
            return Err(ToolError::Rejected(
                "shell_zsh_fork enabled, but zsh_path is not configured".to_string(),
            ));
        }

        let (program, args) = req
            .command
            .split_first()
            .ok_or_else(|| ToolError::Rejected("command args are empty".to_string()))?;
        let spec = CommandSpec {
            program: program.clone(),
            args: args.to_vec(),
            cwd: req.cwd.clone(),
            env: req.env.clone(),
            expiration: ExecExpiration::from(req.timeout_ms),
            sandbox_permissions: req.sandbox_permissions,
            justification: req.justification.clone(),
        };

        let env = attempt
            .env_for(spec, req.network.as_ref())
            .map_err(|err| ToolError::Codex(CodexErr::from(err)))?;
        crate::sandboxing::execute_env(env, attempt.policy, stdout_stream)
            .await
            .map_err(ToolError::Codex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn initialize_and_shutdown_track_session() {
        let manager = ZshSidecarManager::new(
            Some(PathBuf::from("/bin/zsh")),
            PathBuf::from("/tmp/codex-home"),
        );
        manager.initialize_for_session("session-1").await;
        {
            let state = manager.state.lock().await;
            assert_eq!(state.initialized_session_id.as_deref(), Some("session-1"));
        }
        manager.shutdown().await;
        {
            let state = manager.state.lock().await;
            assert_eq!(state.initialized_session_id, None);
        }
    }
}

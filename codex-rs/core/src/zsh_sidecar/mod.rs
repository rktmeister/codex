#![allow(dead_code)]

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

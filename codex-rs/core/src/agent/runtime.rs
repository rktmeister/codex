use serde::Serialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentRuntimeKind {
    #[default]
    InProcess,
    // Constructed by the app-server tmux runtime once process launching is wired.
    #[allow(dead_code)]
    Tmux,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct AgentRuntimeMetadata {
    pub(crate) kind: AgentRuntimeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tmux: Option<TmuxAgentRuntimeMetadata>,
}

impl AgentRuntimeMetadata {
    pub(crate) fn in_process() -> Self {
        Self::default()
    }

    pub(crate) fn is_in_process(&self) -> bool {
        self == &Self::in_process()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TmuxAgentRuntimeMetadata {
    pub(crate) session_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pane_id: Option<String>,
}

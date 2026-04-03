use crate::codex::Session;
use crate::codex::TurnContext;
use crate::function_tool::FunctionCallError;
use crate::sandboxing::SandboxPermissions;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::SharedTurnDiffTracker;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::context::ToolSearchOutput;
use crate::tools::registry::AnyToolResult;
use crate::tools::registry::ToolRegistry;
use crate::tools::spec::build_specs_with_discoverable_tools;
use codex_mcp::mcp_connection_manager::ToolInfo;
use codex_protocol::dynamic_tools::DynamicToolSpec;
use codex_protocol::models::LocalShellAction;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::models::SearchToolCallParams;
use codex_protocol::models::ShellToolCallParams;
use codex_tools::ConfiguredToolSpec;
use codex_tools::DiscoverableTool;
use codex_tools::ToolSpec;
use codex_tools::ToolsConfig;
use rmcp::model::Tool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::instrument;

pub use crate::tools::context::ToolCallSource;

#[derive(Clone, Debug)]
pub struct ToolCall {
    pub tool_name: String,
    pub tool_namespace: Option<String>,
    pub call_id: String,
    pub payload: ToolPayload,
}

pub struct ToolRouter {
    registry: ToolRegistry,
    specs: Vec<ConfiguredToolSpec>,
    model_visible_specs: Vec<ToolSpec>,
}

const SHELL_TOOL_ALIASES: &[&str] = &["shell", "container.exec", "local_shell", "shell_command"];

pub(crate) struct ToolRouterParams<'a> {
    pub(crate) mcp_tools: Option<HashMap<String, Tool>>,
    pub(crate) app_tools: Option<HashMap<String, ToolInfo>>,
    pub(crate) discoverable_tools: Option<Vec<DiscoverableTool>>,
    pub(crate) dynamic_tools: &'a [DynamicToolSpec],
}

impl ToolRouter {
    pub fn from_config(config: &ToolsConfig, params: ToolRouterParams<'_>) -> Self {
        let ToolRouterParams {
            mcp_tools,
            app_tools,
            discoverable_tools,
            dynamic_tools,
        } = params;
        let builder = build_specs_with_discoverable_tools(
            config,
            mcp_tools,
            app_tools,
            discoverable_tools,
            dynamic_tools,
        );
        let (specs, registry) = builder.build();
        let model_visible_specs = if config.code_mode_only_enabled {
            specs
                .iter()
                .filter_map(|configured_tool| {
                    if !codex_code_mode::is_code_mode_nested_tool(configured_tool.name()) {
                        Some(configured_tool.spec.clone())
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            specs
                .iter()
                .map(|configured_tool| configured_tool.spec.clone())
                .collect()
        };

        Self {
            registry,
            specs,
            model_visible_specs,
        }
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.specs
            .iter()
            .map(|config| config.spec.clone())
            .collect()
    }

    pub fn model_visible_specs(&self) -> Vec<ToolSpec> {
        self.model_visible_specs.clone()
    }

    pub fn find_spec(&self, tool_name: &str) -> Option<ToolSpec> {
        self.specs
            .iter()
            .find(|config| config.name() == tool_name)
            .map(|config| config.spec.clone())
    }

    pub fn tool_supports_parallel(&self, tool_name: &str) -> bool {
        let supports_parallel = self
            .specs
            .iter()
            .find(|config| config.name() == tool_name)
            .map(|config| config.supports_parallel_tool_calls);
        if let Some(supports_parallel) = supports_parallel {
            return supports_parallel;
        }

        if SHELL_TOOL_ALIASES.contains(&tool_name) {
            return self
                .specs
                .iter()
                .find(|config| matches!(config.spec.name(), "shell_command" | "exec_command"))
                .map(|config| config.supports_parallel_tool_calls)
                .unwrap_or(false);
        }

        false
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn build_tool_call(
        session: &Session,
        item: ResponseItem,
    ) -> Result<Option<ToolCall>, FunctionCallError> {
        match item {
            ResponseItem::FunctionCall {
                name,
                namespace,
                arguments,
                call_id,
                ..
            } => {
                if let Some((server, tool)) = session.parse_mcp_tool_name(&name, &namespace).await {
                    Ok(Some(ToolCall {
                        tool_name: name,
                        tool_namespace: namespace,
                        call_id,
                        payload: ToolPayload::Mcp {
                            server,
                            tool,
                            raw_arguments: arguments,
                        },
                    }))
                } else {
                    Ok(Some(ToolCall {
                        tool_name: name,
                        tool_namespace: namespace,
                        call_id,
                        payload: ToolPayload::Function { arguments },
                    }))
                }
            }
            ResponseItem::ToolSearchCall {
                call_id: Some(call_id),
                execution,
                arguments,
                ..
            } if execution == "client" => {
                let arguments: SearchToolCallParams =
                    serde_json::from_value(arguments).map_err(|err| {
                        FunctionCallError::RespondToModel(format!(
                            "failed to parse tool_search arguments: {err}"
                        ))
                    })?;
                Ok(Some(ToolCall {
                    tool_name: "tool_search".to_string(),
                    tool_namespace: None,
                    call_id,
                    payload: ToolPayload::ToolSearch { arguments },
                }))
            }
            ResponseItem::ToolSearchCall { .. } => Ok(None),
            ResponseItem::CustomToolCall {
                name,
                input,
                call_id,
                ..
            } => Ok(Some(ToolCall {
                tool_name: name,
                tool_namespace: None,
                call_id,
                payload: ToolPayload::Custom { input },
            })),
            ResponseItem::LocalShellCall {
                id,
                call_id,
                action,
                ..
            } => {
                let call_id = call_id
                    .or(id)
                    .ok_or(FunctionCallError::MissingLocalShellCallId)?;

                match action {
                    LocalShellAction::Exec(exec) => {
                        let params = ShellToolCallParams {
                            command: exec.command,
                            workdir: exec.working_directory,
                            timeout_ms: exec.timeout_ms,
                            sandbox_permissions: Some(SandboxPermissions::UseDefault),
                            additional_permissions: None,
                            prefix_rule: None,
                            justification: None,
                        };
                        Ok(Some(ToolCall {
                            tool_name: "local_shell".to_string(),
                            tool_namespace: None,
                            call_id,
                            payload: ToolPayload::LocalShell { params },
                        }))
                    }
                }
            }
            _ => Ok(None),
        }
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn dispatch_tool_call(
        &self,
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        tracker: SharedTurnDiffTracker,
        call: ToolCall,
        source: ToolCallSource,
    ) -> Result<ResponseInputItem, FunctionCallError> {
        let response_call_id = call.call_id.clone();
        let payload_outputs_custom = matches!(&call.payload, ToolPayload::Custom { .. });
        let payload_outputs_tool_search = matches!(&call.payload, ToolPayload::ToolSearch { .. });

        match self
            .dispatch_tool_call_with_code_mode_result(session, turn, tracker, call, source)
            .await
        {
            Ok(result) => Ok(result.into_response()),
            Err(FunctionCallError::Fatal(message)) => Err(FunctionCallError::Fatal(message)),
            Err(err) => {
                let message = err.to_string();
                let result = if payload_outputs_tool_search {
                    AnyToolResult {
                        call_id: response_call_id,
                        payload: ToolPayload::ToolSearch {
                            arguments: SearchToolCallParams {
                                query: String::new(),
                                limit: None,
                            },
                        },
                        result: Box::new(ToolSearchOutput { tools: Vec::new() }),
                    }
                } else if payload_outputs_custom {
                    AnyToolResult {
                        call_id: response_call_id,
                        payload: ToolPayload::Custom {
                            input: String::new(),
                        },
                        result: Box::new(FunctionToolOutput::from_text(message, Some(false))),
                    }
                } else {
                    AnyToolResult {
                        call_id: response_call_id,
                        payload: ToolPayload::Function {
                            arguments: "{}".to_string(),
                        },
                        result: Box::new(FunctionToolOutput::from_text(message, Some(false))),
                    }
                };
                Ok(result.into_response())
            }
        }
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn dispatch_tool_call_with_code_mode_result(
        &self,
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        tracker: SharedTurnDiffTracker,
        call: ToolCall,
        source: ToolCallSource,
    ) -> Result<AnyToolResult, FunctionCallError> {
        let ToolCall {
            tool_name,
            tool_namespace,
            call_id,
            payload,
        } = call;

        if source == ToolCallSource::Direct {
            let direct_call_error = match (
                turn.tools_config.js_repl_tools_only,
                turn.tools_config.py_repl_tools_only,
            ) {
                (true, true)
                    if !matches!(
                        tool_name.as_str(),
                        "js_repl" | "js_repl_reset" | "py_repl" | "py_repl_reset"
                    ) =>
                {
                    Some(
                        "direct tool calls are disabled; use js_repl / py_repl and codex.tool(...) instead"
                            .to_string(),
                    )
                }
                (true, false) if !matches!(tool_name.as_str(), "js_repl" | "js_repl_reset") => {
                    Some(
                        "direct tool calls are disabled; use js_repl and codex.tool(...) instead"
                            .to_string(),
                    )
                }
                (false, true) if !matches!(tool_name.as_str(), "py_repl" | "py_repl_reset") => {
                    Some(
                        "direct tool calls are disabled; use py_repl and codex.tool(...) instead"
                            .to_string(),
                    )
                }
                _ => None,
            };

            if let Some(message) = direct_call_error {
                return Err(FunctionCallError::RespondToModel(message));
            }
        }

        let invocation = ToolInvocation {
            session,
            turn,
            tracker,
            call_id,
            tool_name,
            tool_namespace,
            payload,
        };

        self.registry.dispatch_any(invocation).await
    }
}
#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;

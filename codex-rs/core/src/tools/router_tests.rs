use std::sync::Arc;

use crate::codex::make_session_and_context;
use crate::tools::context::ToolPayload;
use crate::turn_diff_tracker::TurnDiffTracker;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::openai_models::ConfigShellToolType;

use super::ToolCall;
use super::ToolCallSource;
use super::ToolRouter;
use super::ToolRouterParams;

#[tokio::test]
async fn js_repl_tools_only_blocks_direct_tool_calls() -> anyhow::Result<()> {
    let (session, mut turn) = make_session_and_context().await;
    turn.tools_config.js_repl_tools_only = true;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let mcp_tools = session
        .services
        .mcp_connection_manager
        .read()
        .await
        .list_all_tools()
        .await;
    let app_tools = Some(mcp_tools.clone());
    let router = ToolRouter::from_config(
        &turn.tools_config,
        ToolRouterParams {
            mcp_tools: Some(
                mcp_tools
                    .into_iter()
                    .map(|(name, tool)| (name, tool.tool))
                    .collect(),
            ),
            app_tools,
            discoverable_tools: None,
            dynamic_tools: turn.dynamic_tools.as_slice(),
        },
    );

    let call = ToolCall {
        tool_name: "shell".to_string(),
        tool_namespace: None,
        call_id: "call-1".to_string(),
        payload: ToolPayload::Function {
            arguments: "{}".to_string(),
        },
    };
    let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::new()));
    let response = router
        .dispatch_tool_call(session, turn, tracker, call, ToolCallSource::Direct)
        .await?;

    match response {
        ResponseInputItem::FunctionCallOutput { output, .. } => {
            let content = output.text_content().unwrap_or_default();
            assert!(
                content.contains("direct tool calls are disabled"),
                "unexpected tool call message: {content}",
            );
        }
        other => panic!("expected function call output, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn js_repl_tools_only_allows_js_repl_source_calls() -> anyhow::Result<()> {
    let (session, mut turn) = make_session_and_context().await;
    turn.tools_config.js_repl_tools_only = true;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let mcp_tools = session
        .services
        .mcp_connection_manager
        .read()
        .await
        .list_all_tools()
        .await;
    let app_tools = Some(mcp_tools.clone());
    let router = ToolRouter::from_config(
        &turn.tools_config,
        ToolRouterParams {
            mcp_tools: Some(
                mcp_tools
                    .into_iter()
                    .map(|(name, tool)| (name, tool.tool))
                    .collect(),
            ),
            app_tools,
            discoverable_tools: None,
            dynamic_tools: turn.dynamic_tools.as_slice(),
        },
    );

    let call = ToolCall {
        tool_name: "shell".to_string(),
        tool_namespace: None,
        call_id: "call-2".to_string(),
        payload: ToolPayload::Function {
            arguments: "{}".to_string(),
        },
    };
    let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::new()));
    let response = router
        .dispatch_tool_call(session, turn, tracker, call, ToolCallSource::JsRepl)
        .await?;

    match response {
        ResponseInputItem::FunctionCallOutput { output, .. } => {
            let content = output.text_content().unwrap_or_default();
            assert!(
                !content.contains("direct tool calls are disabled"),
                "js_repl source should bypass direct-call policy gate"
            );
        }
        other => panic!("expected function call output, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn py_repl_tools_only_blocks_direct_tool_calls() -> anyhow::Result<()> {
    let (session, mut turn) = make_session_and_context().await;
    turn.tools_config.py_repl_tools_only = true;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let mcp_tools = session
        .services
        .mcp_connection_manager
        .read()
        .await
        .list_all_tools()
        .await;
    let app_tools = Some(mcp_tools.clone());
    let router = ToolRouter::from_config(
        &turn.tools_config,
        ToolRouterParams {
            mcp_tools: Some(
                mcp_tools
                    .into_iter()
                    .map(|(name, tool)| (name, tool.tool))
                    .collect(),
            ),
            app_tools,
            discoverable_tools: None,
            dynamic_tools: turn.dynamic_tools.as_slice(),
        },
    );

    let call = ToolCall {
        tool_name: "shell".to_string(),
        tool_namespace: None,
        call_id: "call-py-direct".to_string(),
        payload: ToolPayload::Function {
            arguments: "{}".to_string(),
        },
    };
    let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::new()));
    let response = router
        .dispatch_tool_call(session, turn, tracker, call, ToolCallSource::Direct)
        .await?;

    match response {
        ResponseInputItem::FunctionCallOutput { output, .. } => {
            let content = output.text_content().unwrap_or_default();
            assert!(
                content.contains("direct tool calls are disabled"),
                "unexpected tool call message: {content}",
            );
            assert!(content.contains("use py_repl"));
        }
        other => panic!("expected function call output, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn py_repl_tools_only_allows_py_repl_source_calls() -> anyhow::Result<()> {
    let (session, mut turn) = make_session_and_context().await;
    turn.tools_config.py_repl_tools_only = true;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let mcp_tools = session
        .services
        .mcp_connection_manager
        .read()
        .await
        .list_all_tools()
        .await;
    let app_tools = Some(mcp_tools.clone());
    let router = ToolRouter::from_config(
        &turn.tools_config,
        ToolRouterParams {
            mcp_tools: Some(
                mcp_tools
                    .into_iter()
                    .map(|(name, tool)| (name, tool.tool))
                    .collect(),
            ),
            app_tools,
            discoverable_tools: None,
            dynamic_tools: turn.dynamic_tools.as_slice(),
        },
    );

    let call = ToolCall {
        tool_name: "shell".to_string(),
        tool_namespace: None,
        call_id: "call-py-source".to_string(),
        payload: ToolPayload::Function {
            arguments: "{}".to_string(),
        },
    };
    let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::new()));
    let response = router
        .dispatch_tool_call(session, turn, tracker, call, ToolCallSource::PyRepl)
        .await?;

    match response {
        ResponseInputItem::FunctionCallOutput { output, .. } => {
            let content = output.text_content().unwrap_or_default();
            assert!(
                !content.contains("direct tool calls are disabled"),
                "py_repl source should bypass direct-call policy gate"
            );
        }
        other => panic!("expected function call output, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn shell_aliases_inherit_parallel_support_from_active_shell_tool() -> anyhow::Result<()> {
    let (session, mut turn) = make_session_and_context().await;
    turn.tools_config.shell_type = ConfigShellToolType::UnifiedExec;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let mcp_tools = session
        .services
        .mcp_connection_manager
        .read()
        .await
        .list_all_tools()
        .await;
    let app_tools = Some(mcp_tools.clone());
    let router = ToolRouter::from_config(
        &turn.tools_config,
        ToolRouterParams {
            mcp_tools: Some(
                mcp_tools
                    .into_iter()
                    .map(|(name, tool)| (name, tool.tool))
                    .collect(),
            ),
            app_tools,
            discoverable_tools: None,
            dynamic_tools: turn.dynamic_tools.as_slice(),
        },
    );

    assert!(router.tool_supports_parallel("exec_command"));
    assert!(router.tool_supports_parallel("shell_command"));
    assert!(router.tool_supports_parallel("shell"));
    assert!(router.tool_supports_parallel("container.exec"));
    assert!(router.tool_supports_parallel("local_shell"));

    Ok(())
}

#[tokio::test]
async fn combined_repl_tools_only_lists_both_allowed_repls() -> anyhow::Result<()> {
    let (session, mut turn) = make_session_and_context().await;
    turn.tools_config.js_repl_tools_only = true;
    turn.tools_config.py_repl_tools_only = true;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let mcp_tools = session
        .services
        .mcp_connection_manager
        .read()
        .await
        .list_all_tools()
        .await;
    let app_tools = Some(mcp_tools.clone());
    let router = ToolRouter::from_config(
        &turn.tools_config,
        ToolRouterParams {
            mcp_tools: Some(
                mcp_tools
                    .into_iter()
                    .map(|(name, tool)| (name, tool.tool))
                    .collect(),
            ),
            app_tools,
            discoverable_tools: None,
            dynamic_tools: turn.dynamic_tools.as_slice(),
        },
    );

    let call = ToolCall {
        tool_name: "shell".to_string(),
        tool_namespace: None,
        call_id: "call-both-direct".to_string(),
        payload: ToolPayload::Function {
            arguments: "{}".to_string(),
        },
    };
    let tracker = Arc::new(tokio::sync::Mutex::new(TurnDiffTracker::new()));
    let response = router
        .dispatch_tool_call(session, turn, tracker, call, ToolCallSource::Direct)
        .await?;

    match response {
        ResponseInputItem::FunctionCallOutput { output, .. } => {
            let content = output.text_content().unwrap_or_default();
            assert!(content.contains("use js_repl / py_repl"));
        }
        other => panic!("expected function call output, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn build_tool_call_uses_namespace_for_registry_name() -> anyhow::Result<()> {
    let (session, _) = make_session_and_context().await;
    let session = Arc::new(session);
    let tool_name = "create_event".to_string();

    let call = ToolRouter::build_tool_call(
        &session,
        ResponseItem::FunctionCall {
            id: None,
            name: tool_name.clone(),
            namespace: Some("mcp__codex_apps__calendar".to_string()),
            arguments: "{}".to_string(),
            call_id: "call-namespace".to_string(),
        },
    )
    .await?
    .expect("function_call should produce a tool call");

    assert_eq!(call.tool_name, tool_name);
    assert_eq!(
        call.tool_namespace,
        Some("mcp__codex_apps__calendar".to_string())
    );
    assert_eq!(call.call_id, "call-namespace");
    match call.payload {
        ToolPayload::Function { arguments } => {
            assert_eq!(arguments, "{}");
        }
        other => panic!("expected function payload, got {other:?}"),
    }

    Ok(())
}

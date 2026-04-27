#![allow(clippy::expect_used, clippy::unwrap_used)]

use anyhow::Result;
use codex_features::Feature;
use codex_protocol::protocol::EventMsg;
use codex_utils_absolute_path::AbsolutePathBuf;
use core_test_support::responses;
use core_test_support::responses::ResponseMock;
use core_test_support::responses::ResponsesRequest;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_custom_tool_call;
use core_test_support::responses::ev_function_call;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::sse;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event_match;
use pretty_assertions::assert_eq;
use serde_json::Value;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::tempdir;
use toml::toml;
use wiremock::MockServer;

const VALID_PNG_DATA_URL: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";
const VALID_GIF_DATA_URL: &str =
    "data:image/gif;base64,R0lGODdhAQABAIAAAP///////ywAAAAAAQABAAACAkQBADs=";

fn tool_names(body: &Value) -> Vec<String> {
    body["tools"]
        .as_array()
        .expect("tools array should be present")
        .iter()
        .map(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .or_else(|| tool.get("type").and_then(Value::as_str))
                .expect("tool should have a name or type")
                .to_string()
        })
        .collect()
}

fn custom_tool_output_text_and_success(
    req: &ResponsesRequest,
    call_id: &str,
) -> (String, Option<bool>) {
    let (output, success) = req
        .custom_tool_call_output_content_and_success(call_id)
        .expect("custom tool output should be present");
    (output.unwrap_or_default(), success)
}

fn function_tool_output_text_and_success(
    req: &ResponsesRequest,
    call_id: &str,
) -> (String, Option<bool>) {
    let (output, success) = req
        .function_call_output_content_and_success(call_id)
        .expect("function tool output should be present");
    (output.unwrap_or_default(), success)
}

fn assert_py_repl_ok(req: &ResponsesRequest, call_id: &str, expected_output: &str) {
    let (output, success) = custom_tool_output_text_and_success(req, call_id);
    assert_ne!(
        success,
        Some(false),
        "py_repl call failed unexpectedly: {output}"
    );
    assert!(
        output.contains(expected_output),
        "output was `{output}`, expected substring `{expected_output}`"
    );
}

fn assert_py_repl_err(req: &ResponsesRequest, call_id: &str, expected_output: &str) {
    let (output, success) = custom_tool_output_text_and_success(req, call_id);
    assert_ne!(success, Some(true), "py_repl call should fail: {output}");
    assert!(
        output.contains(expected_output),
        "output was `{output}`, expected substring `{expected_output}`"
    );
}

fn set_py_repl_python_path(config: &mut codex_core::config::Config, path: impl AsRef<Path>) {
    let config_path = AbsolutePathBuf::try_from(config.codex_home.join("config.toml"))
        .expect("test config path should be absolute");
    let path = path.as_ref();
    config.py_repl_python_path = Some(path.to_path_buf());
    let path = path.display().to_string();
    config.config_layer_stack = config.config_layer_stack.with_user_config(
        &config_path,
        toml! {
            py_repl_python_path = path
        }
        .into(),
    );
}

fn write_too_old_python_script(dir: &Path) -> Result<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let path = dir.join("old-python.cmd");
        fs::write(
            &path,
            r#"@echo off
if "%1"=="--version" (
  echo Python 3.9.0
  exit /b 0
)
if "%1"=="-c" (
  echo 3.9.0
  exit /b 0
)
echo Python 3.9.0
"#,
        )?;
        Ok(path)
    }

    #[cfg(unix)]
    {
        let path = dir.join("old-python.sh");
        fs::write(
            &path,
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "Python 3.9.0"
  exit 0
fi
if [ "$1" = "-c" ]; then
  echo "3.9.0"
  exit 0
fi
echo "Python 3.9.0"
"#,
        )?;
        let mut permissions = fs::metadata(&path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions)?;
        Ok(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("unsupported platform for py_repl test fixture");
    }
}

async fn run_py_repl_turn(
    test: &TestCodex,
    server: &MockServer,
    prompt: &str,
    call_id: &str,
    py_input: &str,
) -> Result<ResponseMock> {
    let response_id = format!("resp-{call_id}");
    let final_response_id = format!("resp-{call_id}-final");
    responses::mount_sse_once(
        server,
        sse(vec![
            ev_response_created(&response_id),
            ev_custom_tool_call(call_id, "py_repl", py_input),
            ev_completed(&response_id),
        ]),
    )
    .await;

    let final_mock = responses::mount_sse_once(
        server,
        sse(vec![
            ev_assistant_message(&format!("msg-{call_id}"), "done"),
            ev_completed(&final_response_id),
        ]),
    )
    .await;

    test.submit_turn(prompt).await?;
    Ok(final_mock)
}

async fn run_py_repl_reset_turn(
    test: &TestCodex,
    server: &MockServer,
    prompt: &str,
    call_id: &str,
) -> Result<ResponseMock> {
    let response_id = format!("resp-{call_id}");
    let final_response_id = format!("resp-{call_id}-final");
    responses::mount_sse_once(
        server,
        sse(vec![
            ev_response_created(&response_id),
            ev_function_call(call_id, "py_repl_reset", "{}"),
            ev_completed(&response_id),
        ]),
    )
    .await;

    let final_mock = responses::mount_sse_once(
        server,
        sse(vec![
            ev_assistant_message(&format!("msg-{call_id}"), "done"),
            ev_completed(&final_response_id),
        ]),
    )
    .await;

    test.submit_turn(prompt).await?;
    Ok(final_mock)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_is_not_advertised_when_startup_python_is_incompatible() -> Result<()> {
    skip_if_no_network!(Ok(()));
    if std::env::var_os("CODEX_PY_REPL_PYTHON_PATH").is_some() {
        return Ok(());
    }

    let server = responses::start_mock_server().await;
    let temp = tempdir()?;
    let old_python = write_too_old_python_script(temp.path())?;

    let mut builder = test_codex().with_config(move |config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
        set_py_repl_python_path(config, &old_python);
    });
    let test = builder.build(&server).await?;

    let warning = wait_for_event_match(&test.codex, |event| match event {
        EventMsg::Warning(ev) if ev.message.contains("Disabled `py_repl` for this session") => {
            Some(ev.message.clone())
        }
        _ => None,
    })
    .await;
    assert!(
        warning.contains("Python runtime"),
        "warning should explain the Python compatibility issue: {warning}"
    );

    let request_mock = responses::mount_sse_once(
        &server,
        sse(vec![
            ev_assistant_message("msg-1", "done"),
            ev_completed("resp-1"),
        ]),
    )
    .await;

    test.submit_turn("hello").await?;

    let body = request_mock.single_request().body_json();
    let tools = tool_names(&body);
    assert!(
        !tools.iter().any(|tool| tool == "py_repl"),
        "py_repl should be omitted when startup validation fails: {tools:?}"
    );
    assert!(
        !tools.iter().any(|tool| tool == "py_repl_reset"),
        "py_repl_reset should be omitted when startup validation fails: {tools:?}"
    );
    let instructions = body["instructions"].as_str().unwrap_or_default();
    assert!(
        !instructions.contains("## Python REPL"),
        "startup instructions should not mention py_repl when it is disabled: {instructions}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_persists_state_across_turns_and_supports_tla() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let first = run_py_repl_turn(
        &test,
        &server,
        "initialize py_repl state",
        "call-1",
        "import asyncio\nvalue = await asyncio.sleep(0, result=41)\nprint(value)",
    )
    .await?;
    assert_py_repl_ok(&first.single_request(), "call-1", "41");

    let second = run_py_repl_turn(
        &test,
        &server,
        "reuse py_repl state",
        "call-2",
        "print(value + 1)",
    )
    .await?;
    assert_py_repl_ok(&second.single_request(), "call-2", "42");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_can_invoke_builtin_tools() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "use py_repl to call a tool",
        "call-1",
        "tool_out = await codex.tool(\"list_mcp_resources\", {})\nprint(tool_out[\"type\"])",
    )
    .await?;

    let req = mock.single_request();
    assert_py_repl_ok(&req, "call-1", "function_call_output");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_runtime_info_exposes_interpreter_and_paths() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "inspect py_repl runtime info",
        "call-1",
        "info = codex.runtime_info()\nprint(bool(info['python']))\nprint(info['cwd'] == codex.cwd)\nprint(isinstance(info['sys_path'], list))\nprint(info['tmp_dir'] == codex.tmp_dir)",
    )
    .await?;

    let req = mock.single_request();
    assert_py_repl_ok(&req, "call-1", "True\nTrue\nTrue\nTrue");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_process_run_uses_child_env_without_mutating_kernel_env() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "run an isolated child process",
        "call-1",
        "import os, pathlib, sys\nresult = await codex.process.run([sys.executable, '-c', \"import os; print(os.environ.get('PY_REPL_CHILD_ENV', 'missing'))\"], env={'PY_REPL_CHILD_ENV': 'child-value'}, timeout_ms=5000)\nprint(f'exit={result.exit_code}')\nprint(f'stdout={result.stdout.strip()}')\nprint(f'env={os.environ.get(\"PY_REPL_CHILD_ENV\", \"missing\")}')\nprint('path=' + str(bool(result.output_path) and pathlib.Path(result.output_path).exists()))",
    )
    .await?;

    let req = mock.single_request();
    assert_py_repl_ok(&req, "call-1", "exit=0");
    assert_py_repl_ok(&req, "call-1", "stdout=child-value");
    assert_py_repl_ok(&req, "call-1", "env=missing");
    assert_py_repl_ok(&req, "call-1", "path=True");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_process_python_runs_fresh_interpreter_with_args_and_env() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "run a fresh python child process",
        "call-1",
        concat!(
            "import os, sys\n",
            "os.environ['PY_REPL_PARENT_ONLY'] = 'parent'\n",
            "code = \"import os, sys; print(sys.executable); print(sys.argv[1]); print(os.environ.get('PY_REPL_CHILD_ENV', 'missing')); print(os.environ.get('PY_REPL_PARENT_ONLY', 'missing'))\"\n",
            "result = await codex.process.python(code, args=['arg-1'], env={'PY_REPL_CHILD_ENV': 'child-value'}, timeout_ms=5000)\n",
            "explicit = await codex.process.python('import sys; print(sys.executable)', interpreter=sys.executable, timeout_ms=5000)\n",
            "lines = result.stdout.strip().splitlines()\n",
            "print(f'exit={result.exit_code}')\n",
            "print('same=' + str(lines[0] == sys.executable))\n",
            "print('arg=' + lines[1])\n",
            "print('child=' + lines[2])\n",
            "print('parent=' + lines[3])\n",
            "print('explicit=' + str(explicit.stdout.strip() == sys.executable))",
        ),
    )
    .await?;

    let req = mock.single_request();
    assert_py_repl_ok(&req, "call-1", "exit=0");
    assert_py_repl_ok(&req, "call-1", "same=True");
    assert_py_repl_ok(&req, "call-1", "arg=arg-1");
    assert_py_repl_ok(&req, "call-1", "child=child-value");
    assert_py_repl_ok(&req, "call-1", "parent=missing");
    assert_py_repl_ok(&req, "call-1", "explicit=True");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_process_start_waits_and_kills_session() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "manage a long-running child process",
        "call-1",
        concat!(
            "import sys\n",
            "handle = await codex.process.start([sys.executable, '-c', \"import time; print('ready', flush=True); time.sleep(0.8); print('done', flush=True)\"], yield_time_ms=200, timeout_ms=1000)\n",
            "print('started=' + str(handle.session_id is not None))\n",
            "final = await handle.wait(timeout_ms=3000, poll_ms=100)\n",
            "print('running=' + str(handle.running))\n",
            "print('exit=' + str(final.exit_code))\n",
            "print('out=' + handle.stdout.replace('\\n', '|').strip('|'))\n",
            "sleeper = await codex.process.start([sys.executable, '-c', 'import time; time.sleep(5)'], yield_time_ms=100)\n",
            "print('sleeper=' + str(sleeper.session_id is not None))\n",
            "killed = await sleeper.kill()\n",
            "print('killed=' + str(sleeper.running))\n",
            "print('kill_session=' + str(killed.session_id))",
        ),
    )
    .await?;

    let req = mock.single_request();
    assert_py_repl_ok(&req, "call-1", "started=True");
    assert_py_repl_ok(&req, "call-1", "running=False");
    assert_py_repl_ok(&req, "call-1", "exit=0");
    assert_py_repl_ok(&req, "call-1", "out=ready|done");
    assert_py_repl_ok(&req, "call-1", "sleeper=True");
    assert_py_repl_ok(&req, "call-1", "killed=False");
    assert_py_repl_ok(&req, "call-1", "kill_session=None");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_process_list_and_kill_cleanup_surface_tracks_started_processes() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "list and cleanup py_repl processes",
        "call-1",
        concat!(
            "import sys\n",
            "first = await codex.process.start([sys.executable, '-c', 'import time; time.sleep(5)'], yield_time_ms=100)\n",
            "print('listed=' + str([item.session_id for item in codex.process.list()] == [first.session_id]))\n",
            "direct = await codex.process.kill(first.session_id)\n",
            "print('direct_session=' + str(direct.session_id))\n",
            "print('first_running=' + str(first.running))\n",
            "print('after_direct=' + str(codex.process.list()))\n",
            "second = await codex.process.start([sys.executable, '-c', 'import time; time.sleep(5)'], yield_time_ms=100)\n",
            "third = await codex.process.start([sys.executable, '-c', 'import time; time.sleep(5)'], yield_time_ms=100)\n",
            "print('before_all=' + str(len(codex.process.list())))\n",
            "all_killed = await codex.process.kill_all()\n",
            "print('all_killed=' + str(len(all_killed)))\n",
            "print('after_all=' + str(codex.process.list()))\n",
            "print('running=' + str(second.running or third.running))",
        ),
    )
    .await?;

    let req = mock.single_request();
    assert_py_repl_ok(&req, "call-1", "listed=True");
    assert_py_repl_ok(&req, "call-1", "direct_session=None");
    assert_py_repl_ok(&req, "call-1", "first_running=False");
    assert_py_repl_ok(&req, "call-1", "after_direct=[]");
    assert_py_repl_ok(&req, "call-1", "before_all=2");
    assert_py_repl_ok(&req, "call-1", "all_killed=2");
    assert_py_repl_ok(&req, "call-1", "after_all=[]");
    assert_py_repl_ok(&req, "call-1", "running=False");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_process_failure_hooks_can_cleanup_tracked_children() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let failed = run_py_repl_turn(
        &test,
        &server,
        "register a failure cleanup hook",
        "call-1",
        concat!(
            "import sys\n",
            "cleanup_count = 0\n",
            "async def cleanup(_context):\n",
            "    global cleanup_count\n",
            "    cleanup_count += 1\n",
            "    await codex.process.kill_all()\n",
            "hook_id = codex.process.on_failure(cleanup)\n",
            "sleeper = await codex.process.start([sys.executable, '-c', 'import time; time.sleep(5)'], yield_time_ms=100)\n",
            "print('before=' + str(len(codex.process.list())))\n",
            "raise RuntimeError('boom')",
        ),
    )
    .await?;

    let failed_req = failed.single_request();
    assert_py_repl_err(&failed_req, "call-1", "RuntimeError: boom");
    assert_py_repl_err(&failed_req, "call-1", "before=1");

    let inspected = run_py_repl_turn(
        &test,
        &server,
        "inspect failure cleanup state",
        "call-2",
        "print('cleanup_count=' + str(cleanup_count))\nprint('listed=' + str(codex.process.list()))\nprint('running=' + str(sleeper.running))\nprint('removed=' + str(codex.process.remove_failure_hook(hook_id)))",
    )
    .await?;

    let inspected_req = inspected.single_request();
    assert_py_repl_ok(&inspected_req, "call-2", "cleanup_count=1");
    assert_py_repl_ok(&inspected_req, "call-2", "listed=[]");
    assert_py_repl_ok(&inspected_req, "call-2", "running=False");
    assert_py_repl_ok(&inspected_req, "call-2", "removed=True");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_restart_after_cell_resets_kernel_after_result() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let seeded = run_py_repl_turn(
        &test,
        &server,
        "seed py_repl state",
        "call-1",
        "value = 41\nprint(value)",
    )
    .await?;
    assert_py_repl_ok(&seeded.single_request(), "call-1", "41");

    let restart = run_py_repl_turn(
        &test,
        &server,
        "restart after this cell",
        "call-2",
        "print(value)\ncodex.restart_after_cell()",
    )
    .await?;
    assert_py_repl_ok(&restart.single_request(), "call-2", "41");

    let fresh = run_py_repl_turn(
        &test,
        &server,
        "verify restarted kernel",
        "call-3",
        "try:\n    print(value)\nexcept NameError:\n    print('fresh')",
    )
    .await?;
    assert_py_repl_ok(&fresh.single_request(), "call-3", "fresh");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_isolated_pragma_uses_fresh_kernel_and_discards_state() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let seeded = run_py_repl_turn(
        &test,
        &server,
        "seed py_repl state before isolated cell",
        "call-1",
        "value = 41\nprint(value)",
    )
    .await?;
    assert_py_repl_ok(&seeded.single_request(), "call-1", "41");

    let isolated = run_py_repl_turn(
        &test,
        &server,
        "run isolated py_repl cell",
        "call-2",
        "# codex-py-repl: isolated=true\ntry:\n    print(value)\nexcept NameError:\n    print('isolated')\ninner = 1",
    )
    .await?;
    assert_py_repl_ok(&isolated.single_request(), "call-2", "isolated");

    let fresh = run_py_repl_turn(
        &test,
        &server,
        "verify isolated cell reset",
        "call-3",
        "for name in ['value', 'inner']:\n    print(name + '=' + str(name in globals()))",
    )
    .await?;
    let req = fresh.single_request();
    assert_py_repl_ok(&req, "call-3", "value=False");
    assert_py_repl_ok(&req, "call-3", "inner=False");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_warns_when_loaded_native_extension_changes_on_disk() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let loaded = run_py_repl_turn(
        &test,
        &server,
        "register a fake loaded native extension",
        "call-1",
        concat!(
            "import pathlib, sys, types\n",
            "native_path = pathlib.Path(codex.tmp_dir) / 'fake_native.so'\n",
            "native_path.write_bytes(b'one')\n",
            "fake_native = types.ModuleType('fake_native')\n",
            "fake_native.__file__ = str(native_path)\n",
            "sys.modules['fake_native'] = fake_native\n",
            "print('loaded')",
        ),
    )
    .await?;
    assert_py_repl_ok(&loaded.single_request(), "call-1", "loaded");

    let changed = run_py_repl_turn(
        &test,
        &server,
        "change the fake loaded native extension",
        "call-2",
        "native_path.write_bytes(b'two')\nprint('changed')",
    )
    .await?;
    assert_py_repl_ok(&changed.single_request(), "call-2", "changed");

    let warned = run_py_repl_turn(
        &test,
        &server,
        "detect changed native extension",
        "call-3",
        "print('after-change')",
    )
    .await?;
    let req = warned.single_request();
    assert_py_repl_ok(&req, "call-3", "native extension changed on disk");
    assert_py_repl_ok(&req, "call-3", "fake_native.so");
    assert_py_repl_ok(&req, "call-3", "after-change");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_process_run_returns_nonzero_exit_without_failing_cell() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "run a failing child process",
        "call-1",
        "import sys\nresult = await codex.process.run([sys.executable, '-c', 'import sys; sys.exit(7)'], timeout_ms=5000)\nprint(f'exit={result.exit_code}')\nprint(f'timed_out={result.timed_out}')",
    )
    .await?;

    let req = mock.single_request();
    assert_py_repl_ok(&req, "call-1", "exit=7");
    assert_py_repl_ok(&req, "call-1", "timed_out=False");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_process_run_times_out_and_kills_child() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "run a timed out child process",
        "call-1",
        "import sys\nresult = await codex.process.run([sys.executable, '-c', 'import time; time.sleep(2)'], timeout_ms=300)\nprint(f'timed_out={result.timed_out}')\nprint(f'session={result.session_id}')",
    )
    .await?;

    let req = mock.single_request();
    assert_py_repl_ok(&req, "call-1", "timed_out=True");
    assert_py_repl_ok(&req, "call-1", "session=None");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_drains_unawaited_tool_calls_before_cell_completion() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let scheduled = run_py_repl_turn(
        &test,
        &server,
        "schedule nested tool work",
        "call-1",
        "tool_task = codex.tool(\"list_mcp_resources\", {})\nprint(\"scheduled\")",
    )
    .await?;
    assert_py_repl_ok(&scheduled.single_request(), "call-1", "scheduled");

    let observed = run_py_repl_turn(
        &test,
        &server,
        "inspect nested tool task",
        "call-2",
        "print(tool_task.done())\nprint((await tool_task)[\"type\"])",
    )
    .await?;
    let req = observed.single_request();
    assert_py_repl_ok(&req, "call-2", "True");
    assert_py_repl_ok(&req, "call-2", "function_call_output");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_tool_call_rejects_recursive_py_repl_invocation() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "use py_repl recursively",
        "call-1",
        "try:\n    await codex.tool(\"py_repl\", \"print('recursive')\")\n    print(\"unexpected-success\")\nexcept Exception as err:\n    print(str(err))",
    )
    .await?;

    let req = mock.single_request();
    let (output, success) = custom_tool_output_text_and_success(&req, "call-1");
    assert_ne!(
        success,
        Some(false),
        "py_repl call failed unexpectedly: {output}"
    );
    assert!(
        output.contains("py_repl cannot invoke itself"),
        "expected recursion guard message, got output: {output}"
    );
    assert!(
        !output.contains("unexpected-success"),
        "recursive py_repl call unexpectedly succeeded: {output}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_can_emit_images_via_canonical_and_alias_helpers() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "emit images from py_repl",
        "call-1",
        &format!(
            "await codex.emit_image({VALID_PNG_DATA_URL:?})\nawait codex.emitImage({VALID_GIF_DATA_URL:?})\nprint(\"done\")"
        ),
    )
    .await?;

    let req = mock.single_request();
    let custom_output = req.custom_tool_call_output("call-1");
    let output_items = custom_output
        .get("output")
        .and_then(Value::as_array)
        .expect("custom_tool_call_output should be a content item array");
    let emitted_urls = output_items
        .iter()
        .filter_map(|item| {
            (item.get("type").and_then(Value::as_str) == Some("input_image"))
                .then(|| item.get("image_url").and_then(Value::as_str))
                .flatten()
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        emitted_urls,
        vec![
            VALID_PNG_DATA_URL.to_string(),
            VALID_GIF_DATA_URL.to_string(),
        ]
    );
    assert_py_repl_ok(&req, "call-1", "done");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_drains_unawaited_image_emits_before_cell_completion() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let scheduled = run_py_repl_turn(
        &test,
        &server,
        "schedule emitted image work",
        "call-1",
        &format!("emit_task = codex.emit_image({VALID_PNG_DATA_URL:?})\nprint(\"scheduled\")"),
    )
    .await?;
    let scheduled_req = scheduled.single_request();
    let custom_output = scheduled_req.custom_tool_call_output("call-1");
    let output_items = custom_output
        .get("output")
        .and_then(Value::as_array)
        .expect("custom_tool_call_output should be a content item array");
    let emitted_urls = output_items
        .iter()
        .filter_map(|item| {
            (item.get("type").and_then(Value::as_str) == Some("input_image"))
                .then(|| item.get("image_url").and_then(Value::as_str))
                .flatten()
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    assert_eq!(emitted_urls, vec![VALID_PNG_DATA_URL.to_string()]);
    assert_py_repl_ok(&scheduled_req, "call-1", "scheduled");

    let observed = run_py_repl_turn(
        &test,
        &server,
        "inspect emitted image task",
        "call-2",
        "print(emit_task.done())",
    )
    .await?;
    assert_py_repl_ok(&observed.single_request(), "call-2", "True");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_reloads_local_imports_from_cwd() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;
    let module_path = test.workspace_path("repl_probe.py");
    fs::write(&module_path, "value = 41\n")?;

    let first = run_py_repl_turn(
        &test,
        &server,
        "import local module",
        "call-1",
        "import repl_probe\nprint(repl_probe.value)",
    )
    .await?;
    assert_py_repl_ok(&first.single_request(), "call-1", "41");

    fs::write(&module_path, "value = 42\n")?;
    let second = run_py_repl_turn(
        &test,
        &server,
        "reload local module",
        "call-2",
        "import repl_probe\nprint(repl_probe.value)",
    )
    .await?;
    assert_py_repl_ok(&second.single_request(), "call-2", "42");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_recovers_from_timeout_by_resetting_the_kernel() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let seeded = run_py_repl_turn(
        &test,
        &server,
        "seed py_repl state",
        "call-1",
        "value = 41\nprint(value)",
    )
    .await?;
    assert_py_repl_ok(&seeded.single_request(), "call-1", "41");

    let timed_out = run_py_repl_turn(
        &test,
        &server,
        "force a py_repl timeout",
        "call-2",
        "# codex-py-repl: timeout_ms=20\nimport asyncio\nawait asyncio.sleep(0.2)\nprint(\"unexpected-success\")",
    )
    .await?;
    assert_py_repl_err(
        &timed_out.single_request(),
        "call-2",
        "py_repl execution timed out; kernel reset",
    );

    let after_timeout = run_py_repl_turn(
        &test,
        &server,
        "verify timeout reset cleared state",
        "call-3",
        "print(value)",
    )
    .await?;
    assert_py_repl_err(&after_timeout.single_request(), "call-3", "value");

    let fresh = run_py_repl_turn(
        &test,
        &server,
        "verify timeout reset keeps py_repl usable",
        "call-4",
        "print(\"fresh\")",
    )
    .await?;
    assert_py_repl_ok(&fresh.single_request(), "call-4", "fresh");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_reset_clears_persisted_state() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let first = run_py_repl_turn(
        &test,
        &server,
        "store py_repl state",
        "call-1",
        "value = 41\nprint(value)",
    )
    .await?;
    assert_py_repl_ok(&first.single_request(), "call-1", "41");

    let reset = run_py_repl_reset_turn(&test, &server, "reset py_repl", "call-reset").await?;
    let (output, success) =
        function_tool_output_text_and_success(&reset.single_request(), "call-reset");
    assert_ne!(
        success,
        Some(false),
        "py_repl_reset failed unexpectedly: {output}"
    );
    assert!(
        output.contains("py_repl kernel reset"),
        "unexpected reset output: {output}"
    );

    let third = run_py_repl_turn(
        &test,
        &server,
        "verify state is cleared",
        "call-2",
        "print(value)",
    )
    .await?;
    assert_py_repl_err(&third.single_request(), "call-2", "value");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_recovers_from_kernel_crash() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let seeded = run_py_repl_turn(
        &test,
        &server,
        "seed py_repl state before crash",
        "call-1",
        "value = 41\nprint(value)",
    )
    .await?;
    assert_py_repl_ok(&seeded.single_request(), "call-1", "41");

    let crashed = run_py_repl_turn(
        &test,
        &server,
        "crash the py_repl kernel",
        "call-2",
        "import os\nos._exit(7)",
    )
    .await?;
    assert_py_repl_err(
        &crashed.single_request(),
        "call-2",
        "py_repl kernel exited unexpectedly",
    );

    let after_crash = run_py_repl_turn(
        &test,
        &server,
        "verify crash cleared state",
        "call-3",
        "print(value)",
    )
    .await?;
    assert_py_repl_err(&after_crash.single_request(), "call-3", "value");

    let fresh = run_py_repl_turn(
        &test,
        &server,
        "verify py_repl still works after crash",
        "call-4",
        "print(\"after-crash\")",
    )
    .await?;
    assert_py_repl_ok(&fresh.single_request(), "call-4", "after-crash");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_blocks_subprocess_import() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let mock = run_py_repl_turn(
        &test,
        &server,
        "probe subprocess denylist",
        "call-1",
        "try:\n    import subprocess\n    print(\"unexpected-success\")\nexcept Exception as err:\n    print(str(err))",
    )
    .await?;

    let req = mock.single_request();
    let (output, success) = custom_tool_output_text_and_success(&req, "call-1");
    assert_ne!(
        success,
        Some(false),
        "py_repl call failed unexpectedly: {output}"
    );
    assert!(
        output.contains("subprocess"),
        "expected subprocess denylist output, got: {output}"
    );
    assert!(
        !output.contains("unexpected-success"),
        "subprocess import unexpectedly succeeded: {output}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_reloads_local_imports_after_failed_import_then_edit() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;
    let module_path = test.workspace_path("repl_probe_retry.py");
    fs::write(&module_path, "value =\n")?;

    let first = run_py_repl_turn(
        &test,
        &server,
        "import invalid local module",
        "call-1",
        "try:\n    import repl_probe_retry\n    print(\"unexpected-success\")\nexcept Exception as err:\n    print(type(err).__name__)",
    )
    .await?;
    let first_req = first.single_request();
    let (output, success) = custom_tool_output_text_and_success(&first_req, "call-1");
    assert_ne!(
        success,
        Some(false),
        "py_repl call failed unexpectedly: {output}"
    );
    assert!(
        output.contains("SyntaxError"),
        "expected SyntaxError after invalid import, got: {output}"
    );
    assert!(
        !output.contains("unexpected-success"),
        "invalid import unexpectedly succeeded: {output}"
    );

    fs::write(&module_path, "value = 42\n")?;
    let second = run_py_repl_turn(
        &test,
        &server,
        "reload local module after fixing it",
        "call-2",
        "import repl_probe_retry\nprint(repl_probe_retry.value)",
    )
    .await?;
    assert_py_repl_ok(&second.single_request(), "call-2", "42");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_rejects_invalid_image_payloads() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let invalid = run_py_repl_turn(
        &test,
        &server,
        "emit an invalid image payload",
        "call-1",
        "try:\n    await codex.emit_image({\"bytes\": 123, \"mimeType\": \"image/png\"})\n    print(\"unexpected-success\")\nexcept Exception as err:\n    print(str(err))",
    )
    .await?;

    let req = invalid.single_request();
    let (output, success) = custom_tool_output_text_and_success(&req, "call-1");
    assert_ne!(
        success,
        Some(false),
        "py_repl call failed unexpectedly: {output}"
    );
    assert!(
        output.contains("bytes value must be bytes-like"),
        "expected invalid image payload error, got: {output}"
    );
    assert!(
        !output.contains("unexpected-success"),
        "invalid image payload unexpectedly succeeded: {output}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn py_repl_rejects_unsupported_svg_image_data_urls() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        config
            .features
            .enable(Feature::PyRepl)
            .expect("test config should allow feature update");
    });
    let test = builder.build(&server).await?;

    let invalid = run_py_repl_turn(
        &test,
        &server,
        "emit an unsupported svg image payload",
        "call-1",
        "try:\n    await codex.emit_image(\"data:image/svg+xml;base64,PHN2Zy8+\")\n    print(\"unexpected-success\")\nexcept Exception as err:\n    print(str(err))",
    )
    .await?;

    let req = invalid.single_request();
    let (output, success) = custom_tool_output_text_and_success(&req, "call-1");
    assert_ne!(
        success,
        Some(false),
        "py_repl call failed unexpectedly: {output}"
    );
    assert!(
        output.contains("does not support image format `image/svg+xml`"),
        "expected unsupported image format error, got: {output}"
    );
    assert!(
        !output.contains("unexpected-success"),
        "unsupported SVG image unexpectedly succeeded: {output}"
    );

    Ok(())
}

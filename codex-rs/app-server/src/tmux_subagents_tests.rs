use super::*;
use codex_protocol::AgentPath;
use codex_utils_absolute_path::AbsolutePathBuf;
use pretty_assertions::assert_eq;

#[test]
fn remote_endpoint_supports_unix_socket_transport() {
    let socket_path =
        AbsolutePathBuf::from_absolute_path(PathBuf::from("/tmp/codex-app-server.sock"))
            .expect("absolute socket path");
    let endpoint = remote_endpoint_for_transport(&AppServerTransport::UnixSocket { socket_path })
        .expect("unix socket should be supported");

    assert_eq!(endpoint, "unix:///tmp/codex-app-server.sock");
}

#[test]
fn remote_endpoint_rejects_stdio_transport() {
    let err = remote_endpoint_for_transport(&AppServerTransport::Stdio)
        .expect_err("stdio transport should be rejected");

    assert_eq!(
        err.to_string(),
        "--tmux-subagents requires --listen unix:// or --listen unix://PATH"
    );
}

#[test]
fn tmux_subagent_options_default_to_parent_context_when_enabled() {
    assert!(!TmuxSubagentOptions::default().is_enabled());

    let parent_context = TmuxSubagentOptions::parent_context();
    assert!(parent_context.is_enabled());
    assert!(!parent_context.allows_detached_fallback());

    let always = TmuxSubagentOptions::always();
    assert!(always.is_enabled());
    assert!(always.allows_detached_fallback());
}

#[tokio::test]
async fn parent_context_without_parent_tmux_skips_without_marking_thread_launched() {
    let launcher = TmuxSubagentLauncher {
        options: TmuxSubagentOptions::parent_context(),
        codex_exe: PathBuf::from("/usr/local/bin/codex"),
        remote_endpoint: "unix:///tmp/codex.sock".to_string(),
        launched_threads: Arc::new(Mutex::new(HashSet::new())),
    };
    let thread_id =
        ThreadId::from_string("123e4567-e89b-12d3-a456-426614174000").expect("valid thread id");

    launcher
        .launch_subagent(TmuxSubagentLaunchRequest {
            thread_id,
            cwd: PathBuf::from("/work/repo"),
            session_source: SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: ThreadId::new(),
                depth: 1,
                agent_path: None,
                agent_nickname: Some("Pascal".to_string()),
                agent_role: None,
            }),
            parent_tmux: None,
        })
        .await
        .expect("missing parent context should skip cleanly");

    assert!(launcher.launched_threads.lock().await.is_empty());
}

#[test]
fn launch_args_create_session_for_first_subagent_window() {
    let thread_id =
        ThreadId::from_string("123e4567-e89b-12d3-a456-426614174000").expect("valid thread id");
    let args = tmux_launch_args(
        "codex_agents_repo_12345678",
        "task_1",
        Path::new("/usr/local/bin/codex"),
        "unix:///tmp/codex.sock",
        Path::new("/work/repo"),
        thread_id,
        /*session_exists*/ false,
    );

    assert_eq!(
        args,
        vec![
            "new-session",
            "-d",
            "-s",
            "codex_agents_repo_12345678",
            "-n",
            "task_1",
            "-c",
            "/work/repo",
            "--",
            "/usr/local/bin/codex",
            "--remote",
            "unix:///tmp/codex.sock",
            "-C",
            "/work/repo",
            "resume",
            "123e4567-e89b-12d3-a456-426614174000",
        ]
    );
}

#[test]
fn launch_args_add_window_for_existing_session() {
    let thread_id =
        ThreadId::from_string("123e4567-e89b-12d3-a456-426614174000").expect("valid thread id");
    let args = tmux_launch_args(
        "codex_agents_repo_12345678",
        "task_2",
        Path::new("/usr/local/bin/codex"),
        "unix:///tmp/codex.sock",
        Path::new("/work/repo"),
        thread_id,
        /*session_exists*/ true,
    );

    assert_eq!(
        args[..6],
        [
            "new-window",
            "-t",
            "codex_agents_repo_12345678",
            "-n",
            "task_2",
            "-c",
        ]
    );
}

#[test]
fn parent_window_args_create_detached_window_in_parent_session() {
    let thread_id =
        ThreadId::from_string("123e4567-e89b-12d3-a456-426614174000").expect("valid thread id");
    let args = tmux_parent_window_args(
        "$7:",
        "pascal",
        Path::new("/usr/local/bin/codex"),
        "unix:///tmp/codex.sock",
        Path::new("/work/repo"),
        thread_id,
    );

    assert_eq!(
        args,
        vec![
            "new-window",
            "-d",
            "-t",
            "$7:",
            "-n",
            "pascal",
            "-c",
            "/work/repo",
            "--",
            "/usr/local/bin/codex",
            "--remote",
            "unix:///tmp/codex.sock",
            "-C",
            "/work/repo",
            "resume",
            "123e4567-e89b-12d3-a456-426614174000",
        ]
    );
}

#[test]
fn window_name_prefers_agent_path_leaf() {
    let thread_id = ThreadId::new();
    let source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: ThreadId::new(),
        depth: 1,
        agent_path: Some(AgentPath::try_from("/root/implement_diff").expect("valid path")),
        agent_nickname: Some("Plato".to_string()),
        agent_role: Some("developer".to_string()),
    });

    assert_eq!(
        window_name_for_subagent(&source, thread_id),
        "implement_diff"
    );
}

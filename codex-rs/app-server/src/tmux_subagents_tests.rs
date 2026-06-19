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

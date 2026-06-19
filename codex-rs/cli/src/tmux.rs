use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;

use anyhow::Context;
use codex_arg0::Arg0DispatchPaths;

const CODEX_TMUX_SESSION_ENV: &str = "CODEX_TMUX_SESSION";
const CODEX_TMUX_PREFIX_ENV: &str = "CODEX_TMUX_PREFIX";
const CODEX_TMUX_PREFIX_CONFLICTS_ENV: &str = "CODEX_TMUX_PREFIX_CONFLICTS";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum TmuxMode {
    Auto,
    Classic,
}

pub(crate) struct LaunchOptions<'a> {
    pub(crate) mode: TmuxMode,
    pub(crate) raw_args: &'a [OsString],
    pub(crate) arg0_paths: &'a Arg0DispatchPaths,
}

pub(crate) fn rewrite_classic_args<I>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = OsString>,
{
    let mut before_double_dash = true;
    args.into_iter()
        .map(|arg| {
            if before_double_dash && arg.to_str() == Some("--tmux=classic") {
                OsString::from("--tmux-classic")
            } else {
                if arg.to_str() == Some("--") {
                    before_double_dash = false;
                }
                arg
            }
        })
        .collect()
}

pub(crate) fn launch(options: LaunchOptions<'_>) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let _ = options;
        anyhow::bail!("--tmux is not supported on Windows");
    }

    #[cfg(not(windows))]
    launch_impl(options)
}

#[cfg(not(windows))]
fn launch_impl(options: LaunchOptions<'_>) -> anyhow::Result<()> {
    ensure_tmux_available()?;

    let codex_exe = codex_exe(options.arg0_paths)?;
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    let session_name = session_name_for_cwd(&cwd);
    let inner_args = strip_tmux_args(options.raw_args);
    let tmux_prefix = read_tmux_prefix().unwrap_or_else(|| "C-b".to_string());
    let prefix_conflicts = prefix_conflicts_with_codex(&tmux_prefix);
    let session_exists = tmux_has_session(&session_name)?;
    let inside_tmux = running_inside_tmux();

    if inside_tmux {
        if !session_exists {
            let mut command = Command::new("tmux");
            command
                .arg("new-session")
                .arg("-d")
                .arg("-s")
                .arg(&session_name)
                .arg("-c")
                .arg(&cwd)
                .arg("--")
                .arg(&codex_exe)
                .args(&inner_args);
            add_inner_env(&mut command, &session_name, &tmux_prefix, prefix_conflicts);
            ensure_success(
                command
                    .status()
                    .context("failed to run `tmux new-session`")?,
                "tmux new-session",
            )?;
        }

        let status = Command::new("tmux")
            .arg("switch-client")
            .arg("-t")
            .arg(&session_name)
            .status()
            .context("failed to run `tmux switch-client`")?;
        return ensure_success(status, "tmux switch-client");
    }

    let mut command = Command::new("tmux");
    if should_use_control_mode(
        options.mode,
        inside_tmux,
        std::env::var("TERM_PROGRAM").ok().as_deref(),
    ) {
        command.arg("-CC");
    }
    command
        .arg("new-session")
        .arg("-A")
        .arg("-s")
        .arg(&session_name)
        .arg("-c")
        .arg(&cwd)
        .arg("--")
        .arg(&codex_exe)
        .args(&inner_args);
    add_inner_env(&mut command, &session_name, &tmux_prefix, prefix_conflicts);
    let status = command
        .status()
        .context("failed to run `tmux new-session`")?;
    ensure_success(status, "tmux new-session")
}

#[cfg(not(windows))]
fn ensure_tmux_available() -> anyhow::Result<()> {
    let status = Command::new("tmux")
        .arg("-V")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => anyhow::bail!(
            "tmux is not installed or not executable. {}",
            tmux_install_hint()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!("tmux is not installed. {}", tmux_install_hint())
        }
        Err(err) => Err(err).context("failed to run `tmux -V`"),
    }
}

#[cfg(target_os = "macos")]
fn tmux_install_hint() -> &'static str {
    "Install tmux with: brew install tmux"
}

#[cfg(target_os = "linux")]
fn tmux_install_hint() -> &'static str {
    "Install tmux with: sudo apt install tmux"
}

#[cfg(all(not(target_os = "macos"), not(target_os = "linux")))]
fn tmux_install_hint() -> &'static str {
    "Install tmux from your OS package manager."
}

#[cfg(not(windows))]
fn codex_exe(arg0_paths: &Arg0DispatchPaths) -> anyhow::Result<PathBuf> {
    arg0_paths
        .codex_self_exe
        .clone()
        .or_else(|| std::env::current_exe().ok())
        .context("failed to resolve Codex executable for tmux session")
}

#[cfg(not(windows))]
fn running_inside_tmux() -> bool {
    std::env::var_os("TMUX").is_some() || std::env::var_os("TMUX_PANE").is_some()
}

#[cfg(not(windows))]
fn tmux_has_session(session_name: &str) -> anyhow::Result<bool> {
    let status = Command::new("tmux")
        .arg("has-session")
        .arg("-t")
        .arg(session_name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to run `tmux has-session`")?;
    Ok(status.success())
}

#[cfg(not(windows))]
fn read_tmux_prefix() -> Option<String> {
    let output = Command::new("tmux")
        .args(["show-options", "-gv", "prefix"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let prefix = String::from_utf8(output.stdout).ok()?;
    let prefix = prefix.trim();
    if prefix.is_empty() {
        None
    } else {
        Some(prefix.to_string())
    }
}

#[cfg(not(windows))]
fn add_inner_env(
    command: &mut Command,
    session_name: &str,
    tmux_prefix: &str,
    prefix_conflicts: bool,
) {
    command.env(CODEX_TMUX_SESSION_ENV, session_name);
    command.env(CODEX_TMUX_PREFIX_ENV, tmux_prefix);
    if prefix_conflicts {
        command.env(CODEX_TMUX_PREFIX_CONFLICTS_ENV, "1");
    } else {
        command.env_remove(CODEX_TMUX_PREFIX_CONFLICTS_ENV);
    }
}

fn strip_tmux_args(raw_args: &[OsString]) -> Vec<OsString> {
    let mut before_double_dash = true;
    let mut args = Vec::new();
    for arg in raw_args.iter().skip(1) {
        if before_double_dash
            && matches!(
                arg.to_str(),
                Some("--tmux") | Some("--tmux=classic") | Some("--tmux-classic")
            )
        {
            continue;
        }
        if arg.to_str() == Some("--") {
            before_double_dash = false;
        }
        args.push(arg.clone());
    }
    args
}

fn session_name_for_cwd(cwd: &Path) -> String {
    let component = cwd
        .file_name()
        .and_then(|value| value.to_str())
        .map(sanitize_session_component)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "workspace".to_string());
    let hash = stable_path_hash(cwd) & 0xffff_ffff;
    format!("codex_{component}_{hash:08x}")
}

fn sanitize_session_component(component: &str) -> String {
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
        "workspace".to_string()
    } else {
        trimmed.to_string()
    }
}

fn stable_path_hash(path: &Path) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn prefix_conflicts_with_codex(prefix: &str) -> bool {
    matches!(
        prefix,
        "C-b" | "C-c" | "C-d" | "C-g" | "C-j" | "C-l" | "C-o" | "C-r" | "C-t" | "C-v"
    )
}

fn should_use_control_mode(
    mode: TmuxMode,
    running_inside_tmux: bool,
    term_program: Option<&str>,
) -> bool {
    matches!(mode, TmuxMode::Auto)
        && !running_inside_tmux
        && matches!(term_program, Some("iTerm.app"))
}

fn ensure_success(status: ExitStatus, command: &str) -> anyhow::Result<()> {
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("`{command}` exited with status {status}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os_args(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn rewrite_classic_args_supports_code_compatibility_form() {
        assert_eq!(
            rewrite_classic_args(os_args(&["codex", "--tmux=classic", "hello"])),
            os_args(&["codex", "--tmux-classic", "hello"])
        );
    }

    #[test]
    fn rewrite_classic_args_preserves_prompt_after_double_dash() {
        assert_eq!(
            rewrite_classic_args(os_args(&["codex", "--", "--tmux=classic"])),
            os_args(&["codex", "--", "--tmux=classic"])
        );
    }

    #[test]
    fn strip_tmux_args_removes_launcher_flags_before_double_dash() {
        assert_eq!(
            strip_tmux_args(&os_args(&[
                "codex",
                "--tmux",
                "--model",
                "gpt-5",
                "--tmux=classic",
                "--",
                "--tmux",
            ])),
            os_args(&["--model", "gpt-5", "--", "--tmux"])
        );
    }

    #[test]
    fn session_name_sanitizes_component_and_adds_stable_hash() {
        let name = session_name_for_cwd(Path::new("/tmp/repo.name:branch"));
        assert!(name.starts_with("codex_repo_name_branch_"));
        assert_eq!(name.len(), "codex_repo_name_branch_".len() + 8);
    }

    #[test]
    fn session_name_uses_workspace_for_root_path() {
        let name = session_name_for_cwd(Path::new("/"));
        assert!(name.starts_with("codex_workspace_"));
    }

    #[test]
    fn prefix_conflict_matches_codex_control_bindings() {
        assert!(prefix_conflicts_with_codex("C-b"));
        assert!(prefix_conflicts_with_codex("C-t"));
        assert!(!prefix_conflicts_with_codex("C-a"));
    }

    #[test]
    fn control_mode_requires_auto_iterm_and_no_existing_tmux() {
        assert!(should_use_control_mode(
            TmuxMode::Auto,
            /*running_inside_tmux*/ false,
            Some("iTerm.app")
        ));
        assert!(!should_use_control_mode(
            TmuxMode::Classic,
            /*running_inside_tmux*/ false,
            Some("iTerm.app")
        ));
        assert!(!should_use_control_mode(
            TmuxMode::Auto,
            /*running_inside_tmux*/ true,
            Some("iTerm.app")
        ));
        assert!(!should_use_control_mode(
            TmuxMode::Auto,
            /*running_inside_tmux*/ false,
            Some("Apple_Terminal")
        ));
    }
}

---
summary: Public surface and current status for the experimental `py_repl` feature.
read_when:
  - You are enabling or documenting the Python REPL feature.
  - You need the current `py_repl` tool names, config keys, or helper API.
  - You are implementing the `py_repl` runtime or reviewing its surface area.
---

# Python REPL (`py_repl`)

`py_repl` runs Python in a persistent kernel with top-level `await`.

Current status: the runtime is real, but the feature is still experimental and disabled by default.

## Feature gate

`py_repl` is disabled by default and must be enabled explicitly:

```toml
[features]
py_repl = true
```

`py_repl_tools_only` can be enabled to force direct model tool calls through `py_repl`:

```toml
[features]
py_repl = true
py_repl_tools_only = true
```

When enabled, direct model tool calls are restricted to `py_repl` and `py_repl_reset`; other tools remain available via `await codex.tool(...)` inside `py_repl`.

## Python runtime

`py_repl` targets Python `>= 3.10`.

Startup validation disables `py_repl` for the session when the configured runtime is missing or too old.

Runtime resolution order:

1. `CODEX_PY_REPL_PYTHON_PATH`
2. `py_repl_python_path` in config
3. `<project_root>/.venv` when present
4. A compatible Python discovered on `PATH`

`<project_root>` is derived from the session `cwd` using the configured
`project_root_markers`, matching the same root detection Codex uses for
project docs.

You can configure an explicit runtime path:

```toml
py_repl_python_path = "/absolute/path/to/python3"
```

## Import resolution

`py_repl` resolves local imports from:

1. `CODEX_PY_REPL_SYS_PATH` (PATH-delimited list)
2. `py_repl_sys_path` in config (array of absolute paths)
3. The thread working directory (cwd)

Between execs, the kernel invalidates import caches and evicts managed local modules so edited or fixed local files reload on the next import.

Example config:

```toml
py_repl_sys_path = [
  "/absolute/path/to/python/modules",
]
```

## Usage

- `py_repl` is a freeform tool: send raw Python source text.
- Prefer `py_repl` over shelling out to `python - <<'PY'` when you do not need a fresh interpreter or capabilities blocked by the REPL sandbox.
- Optional first-line pragma:
  - `# codex-py-repl: timeout_ms=15000`
  - `# codex-py-repl: timeout_ms=15000 isolated=true`
- Top-level state persists across calls until reset.
- Helper calls start immediately and return task-like objects. Unawaited helper work is still drained before the cell finishes.
- `py_repl_reset` clears the kernel state for the current run and terminates py_repl-tracked child processes.

## Helper APIs inside the kernel

`py_repl` exposes:

- `codex.tmp_dir`
- `codex.cwd`
- `codex.home_dir`
- `codex.runtime_info()`
- `codex.restart_after_cell()`
- `codex.process.run(command, *, cwd=None, env=None, timeout_ms=None, max_output_tokens=None, sandbox_permissions="use_default", additional_permissions=None, justification=None, prefix_rule=None)`
- `codex.process.start(command, *, cwd=None, env=None, yield_time_ms=None, timeout_ms=None, max_output_tokens=None, sandbox_permissions="use_default", additional_permissions=None, justification=None, prefix_rule=None)`
- `codex.process.list()`
- `codex.process.kill(session_id)`
- `codex.process.kill_all()`
- `codex.process.on_failure(callback)`
- `codex.process.remove_failure_hook(hook_id)`
- `codex.process.clear_failure_hooks()`
- `codex.process.use_python(path)`
- `codex.process.use_venv(path)`
- `codex.process.reset_python()`
- `codex.process.python(code, *, args=None, interpreter=None, cwd=None, env=None, timeout_ms=None, max_output_tokens=None, sandbox_permissions="use_default", additional_permissions=None, justification=None, prefix_rule=None)`
- `codex.tool(name, args=None)`
- `codex.emit_image(image_like)`
- `codex.emitImage(image_like)` as a compatibility alias

`codex.emit_image(...)` is the canonical spelling for Python docs and examples.

`codex.runtime_info()` returns the active interpreter, default fresh-process interpreter, Python version, cwd, tmp dir, `sys.path`, and managed import roots.

`codex.restart_after_cell()` asks the host to reset the persistent kernel after the current cell result is returned. Use `isolated=true` in the pragma to run a cell in a fresh kernel and reset it again afterward. Both are intended for imports or native runtime state that should not survive into later cells.

If a loaded native extension (`.so`, `.pyd`, `.dll`, or `.dylib`) changes on disk, `py_repl` emits a warning before the next cell runs because Python cannot safely reload those modules in-place.

`codex.process.run(...)` starts a host-mediated subprocess and returns a task-like object; await it to get a dict-like result with `exit_code`, `timed_out`, `elapsed_ms`, `output`, `stdout`, `stderr`, `output_path`, `stdout_path`, `stderr_path`, `session_id`, and `original_token_count`.

Use an argv list when shell parsing is not needed:

```python
import sys

result = await codex.process.run(
    [sys.executable, "-c", "import os; print(os.environ['PROBE'])"],
    env={"PROBE": "child-only"},
    timeout_ms=5000,
)
print(result.exit_code, result.stdout.strip(), result.output_path)
```

String commands are run through the platform shell (`/bin/sh -lc` on Unix, `cmd /C` on Windows).

The `env` map is an overlay for that subprocess only. It does not mutate `os.environ` in the persistent kernel. Process execution uses the same Codex approval and sandbox pipeline as `exec_command`; request escalated or additional permissions through the `sandbox_permissions`, `additional_permissions`, `justification`, and `prefix_rule` arguments.

The first implementation stores the combined process stream in `output` and `stdout`; `stderr` is currently empty because unified exec exposes an aggregated stream to this helper. Full captured output is also written to a temp log path when possible.

`codex.process.start(...)` keeps the child process alive and returns a handle with `poll(...)`, `wait(...)`, and `kill()` methods. Poll and wait calls append new output to `handle.output` and `handle.stdout` while exposing the latest `exit_code`, `timed_out`, `session_id`, and log paths:

```python
import sys

handle = await codex.process.start(
    [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(5)"],
    yield_time_ms=1000,
)
print(handle.running, handle.stdout)

await handle.poll(timeout_ms=250)
final = await handle.wait(timeout_ms=10_000, poll_ms=1000)
print(final.exit_code, final.output_path)

await handle.kill()
```

Process handles keep a cumulative log at `handle.output_path` and expose `handle.head(lines=40)` / `handle.tail(lines=40)` for quick inspection without reparsing the full output in every cell.

Use `codex.process.list()` to inspect children started by this kernel, `await codex.process.kill(session_id)` to terminate a specific tracked or known child, and `await codex.process.kill_all()` to terminate every tracked child.

Use `codex.process.on_failure(callback)` to register cleanup code that runs when a cell fails. The callback may be sync or async and receives a context dict with `exec_id`, `error`, `output`, and current tracked `processes`. It runs while the cell's helper context is still active, so it can call host-mediated helpers such as `await codex.process.kill_all()`.

`codex.process.python(...)` is a convenience wrapper for fresh interpreter runs. It uses the active py_repl interpreter by default, or an explicit `interpreter` path when provided:

```python
result = await codex.process.python(
    "import os, sys; print(sys.executable); print(sys.argv[1:]); print(os.environ['PROBE'])",
    args=["batch-1"],
    env={"PROBE": "child-only"},
    timeout_ms=5000,
)
```

Use `codex.process.use_python(path)` or `codex.process.use_venv(path)` to set the default interpreter for later `codex.process.python(...)` calls. `codex.process.reset_python()` restores the active py_repl interpreter as that default.

`codex.tool(...)` starts a nested Codex tool call and returns an awaitable task-like object. The awaited value is the raw tool response item dict; nested tool outputs stay inside Python unless you print or emit them.

`codex.emit_image(...)` accepts:

- a base64 `data:` URL for a supported raster image (`image/png`, `image/jpeg`, `image/gif`, or `image/webp`)
- an object like `{ "bytes": ..., "mimeType": ... }`
- a single `input_image` content item
- a raw tool response that contains exactly one image and no text

It rejects mixed text-and-image content.
Unsupported formats such as SVG are rejected.

## Safety model

The current first pass blocks direct process escape paths such as:

- `subprocess`
- `multiprocessing`
- `pty`
- `ctypes`
- `os.system`
- `os.popen`
- `os.spawn*`
- `os.exec*`

Use `codex.process.run(...)` for subprocesses that need Codex sandboxing,
approval, per-call env, timeout, and output capture.

`py_repl` also rejects recursive `py_repl` / `py_repl_reset` tool calls and continues to run inside the normal Codex sandbox pipeline.

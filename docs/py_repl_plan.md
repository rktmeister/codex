---
summary: Implementation plan and remaining hardening work for the parity-level `py_repl` feature.
read_when:
  - You are implementing or reviewing the `py_repl` feature.
  - You need to split `py_repl` work across multiple agents.
  - You need the acceptance criteria and sequencing for Python REPL parity.
---

# py_repl Plan

## Goal

Add a parity-level `py_repl` feature to Codex that matches the practical capabilities of `js_repl`:

- Persistent execution across cells
- Top-level `await`
- Nested `codex.tool(...)` calls
- Explicit image emission
- Reset support
- Startup/runtime validation
- Local import support with reload-friendly behavior
- Optional `*_tools_only` mode

This should be implemented as a sibling feature to `js_repl`, not as a generic multi-language REPL refactor in the first iteration.

## Status Snapshot

The current branch has already landed most of the Phase 0-2 surface:

- feature-gated `py_repl` / `py_repl_reset` tool exposure
- a persistent Python kernel with top-level `await`
- nested `codex.tool(...)`
- `codex.emit_image(...)` plus `codex.emitImage(...)`
- startup Python-version validation
- local import reload support

The remaining work is concentrated in hardening, parity coverage, typed config cleanup, and docs polish. Keep the sequencing below as the source of truth for what is still left to finish.

## Non-Goals

- Exact JS binding semantics such as hoisting behavior
- PTY-driving the stock Python prompt
- A general REPL framework for arbitrary languages
- Full notebook semantics or Jupyter compatibility

## Recommended Public Surface

- Tools:
  - `py_repl`
  - `py_repl_reset`
- Feature flags:
  - `py_repl`
  - `py_repl_tools_only`
- Config:
  - `py_repl_python_path`
  - `py_repl_sys_path`
- Env overrides:
  - `CODEX_PY_REPL_PYTHON_PATH`
  - `CODEX_PY_REPL_SYS_PATH`
- Runtime requirement:
  - Python `>= 3.10`
- Python helper API:
  - `codex.tmp_dir`
  - `codex.tool(name, args=None)`
  - `codex.emit_image(image_like)`
- Compatibility alias:
  - `codex.emitImage(...)` delegates to `codex.emit_image(...)`
- Docs/examples:
  - Use `codex.emit_image(...)` as the canonical spelling

## Architecture

### 1. Host/kernel split

Mirror the `js_repl` model:

- Rust host owns tool registration, sandboxing, kernel lifecycle, timeouts, reset, tool bridging, and content item assembly.
- Python kernel is a dedicated subprocess speaking JSON lines over stdin/stdout.

Do not drive `python -i` via a PTY. Use `python -u <kernel.py>` under the same sandbox pipeline used by `js_repl`.

### 2. Persistent execution model

Use a single long-lived Python process with:

- One persistent globals dict
- One persistent asyncio event loop
- Per-cell compilation/execution

Top-level `await` should be supported by compiling with `ast.PyCF_ALLOW_TOP_LEVEL_AWAIT` and running coroutine results on the persistent loop.

### 3. Output model

Cell output should match `js_repl` behavior at the host boundary:

- Text output returned as the main tool output
- Emitted images appended as content items
- Nested tool results stay internal unless explicitly printed or emitted

### 4. Tool bridge semantics

`codex.tool(...)` and `codex.emit_image(...)` should start work immediately and return awaitable task-like objects. This preserves the useful `js_repl` behavior where unawaited helper calls still run, and the host waits for in-flight helper work before completing the cell.

### 5. Import behavior

Support local imports and configured search roots by:

- Extending `sys.path` with configured roots plus cwd
- Invalidating import caches before each exec
- Evicting locally loaded modules from managed roots before re-import so edited files reload between cells

This should target practical parity with `js_repl` local module reload behavior, not full Python packaging magic.

### 6. Safety model

This is the most sensitive part of the feature.

The kernel must not become a bypass around shell/tool approvals. At minimum:

- Block recursive `py_repl` / `py_repl_reset` self-calls via `codex.tool(...)`
- Block obvious direct process escape paths such as `subprocess`, `multiprocessing`, `pty`, `ctypes`, `os.system`, `os.popen`, `os.spawn*`, and `os.exec*`
- Keep the subprocess under Codex sandboxing exactly like `js_repl`

The first version should prefer explicit denial over incomplete allowlists.

## Implementation Tracks

### Track A: Product contract and surface area

Files:

- `codex-rs/core/src/features.rs`
- `codex-rs/core/src/config/mod.rs`
- `codex-rs/core/src/tools/spec.rs`
- `codex-rs/core/src/tools/router.rs`
- `codex-rs/core/src/project_doc.rs`
- `docs/py_repl.md`

Deliverables:

- New feature flags
- Config/env plumbing
- Freeform tool spec grammar
- Reset tool spec
- `*_tools_only` routing behavior
- User instructions and docs

### Track B: Rust host runtime

Files:

- `codex-rs/core/src/tools/py_repl/mod.rs`
- `codex-rs/core/src/tools/handlers/py_repl.rs`
- `codex-rs/core/src/tools/mod.rs`
- `codex-rs/core/src/tools/handlers/mod.rs`
- `codex-rs/core/src/codex.rs`

Deliverables:

- `PythonReplHandle`
- `PythonReplManager`
- Kernel spawn/reset lifecycle
- Startup validation for Python runtime version/path
- Tool bridge and image bridge
- Timeout behavior
- Model-facing diagnostics

### Track C: Python kernel

Files:

- `codex-rs/core/src/tools/py_repl/kernel.py`

Deliverables:

- JSON-line protocol implementation
- Persistent globals
- Top-level await support
- `codex.tool(...)`
- `codex.emit_image(...)`
- Local import management
- Safety restrictions

### Track D: Tests

Files:

- `codex-rs/core/tests/suite/py_repl.rs`
- `codex-rs/core/src/tools/py_repl/mod.rs` unit tests
- Any config/spec/project-doc test updates required by the new surface

Deliverables:

- Integration coverage matching the important `js_repl` cases
- Unit tests for parsing, reset, helper semantics, and startup validation

## Parallel Work Split

Use this split to avoid merge conflicts.

### Worker 1: Kernel owner

Owns only:

- `codex-rs/core/src/tools/py_repl/kernel.py`

Responsibilities:

- Execution engine
- Async model
- Helper objects
- Import policy
- Safety restrictions inside the kernel

### Worker 2: Host runtime owner

Owns only:

- `codex-rs/core/src/tools/py_repl/mod.rs`
- `codex-rs/core/src/tools/handlers/py_repl.rs`
- Minimal required edits in `codex-rs/core/src/codex.rs`
- Minimal required module exports in `codex-rs/core/src/tools/mod.rs`
- Minimal required handler exports in `codex-rs/core/src/tools/handlers/mod.rs`

Responsibilities:

- Spawn/reset/timeout logic
- JSON-line protocol types
- Bridging kernel requests to Codex tools
- Content item assembly
- Runtime validation

### Worker 3: Surface/docs owner

Owns only:

- `codex-rs/core/src/features.rs`
- `codex-rs/core/src/config/mod.rs`
- `codex-rs/core/src/tools/spec.rs`
- `codex-rs/core/src/tools/router.rs`
- `codex-rs/core/src/project_doc.rs`
- `docs/py_repl.md`

Responsibilities:

- Feature flags
- Config keys and schema-related plumbing
- Tool specs
  - `py_repl_tools_only`
- User-facing docs and prompt text

### Worker 4: Test owner

Owns only:

- `codex-rs/core/tests/suite/py_repl.rs`
- Python-REPL-specific tests in `codex-rs/core/src/tools/py_repl/mod.rs`
- Necessary expected-string updates in existing tests touched by new instructions/specs

Responsibilities:

- Integration scenarios
- Regression coverage
- Fixture helpers

## Sequencing

### Phase 0: Freeze the contract

Status: completed in the current branch.

Before parallel work begins, freeze and publish:

- Final tool names: `py_repl`, `py_repl_reset`
- Final feature/config/env names: `py_repl`, `py_repl_tools_only`, `py_repl_python_path`, `py_repl_sys_path`, `CODEX_PY_REPL_PYTHON_PATH`, `CODEX_PY_REPL_SYS_PATH`
- Minimum supported Python version: `>= 3.10`
- Compatibility alias: `codex.emitImage(...)` delegates to `codex.emit_image(...)`
- Direct-process Python denylist in v1: `subprocess`, `multiprocessing`, `pty`, `ctypes`, `os.system`, `os.popen`, `os.spawn*`, `os.exec*`

This is the only serial blocker.

### Phase 1: Land surface scaffolding and host module skeleton

Status: completed in the current branch.

Goal:

- The repo compiles with placeholder `py_repl` wiring.

Suggested order:

1. Add feature flags and config fields
2. Add tool specs and handlers
3. Add host skeleton module and session wiring
4. Add stub docs

### Phase 2: Build kernel and host bridge in parallel

Status: completed in the current branch.

Goal:

- Real execution path works end-to-end.

Parallelism:

- Worker 1 builds kernel protocol behavior
- Worker 2 builds Rust manager and tool/image bridge
- Worker 3 finishes prompt/docs/spec polish

### Phase 3: Add parity coverage

Status: active follow-up work.

Goal:

- Lock down semantics and close behavior gaps.

Worker 4 focuses on tests while Worker 1 and Worker 2 fix failures.

### Phase 4: Hardening

Status: active follow-up work.

Goal:

- Tighten safety and edge cases after happy-path works.

Focus:

- Timeout/reset during active helper calls
- Kernel crash diagnostics
- Import reload behavior
- Denial paths for unsafe modules

## Acceptance Criteria

The feature is ready for an initial parity merge when all of the following are true:

- `py_repl` and `py_repl_reset` are exposed behind a feature flag
- Session startup disables the feature cleanly when Python is missing or incompatible
- Global variables persist across cells
- Top-level `await` works across cells
- Failed cells preserve prior committed state
- `codex.tool(...)` works from Python
- Unawaited `codex.tool(...)` calls still complete before the cell finishes
- `codex.emit_image(...)` can emit images from supported inputs
- `codex.emitImage(...)` behaves as an alias for `codex.emit_image(...)`
- Unawaited image emission is handled consistently
- Local imports reload after file edits from managed roots
- `py_repl_tools_only` blocks direct tool calls outside the REPL
- Recursive `py_repl` tool invocation is blocked
- Direct-process Python escape paths in the v1 denylist are blocked
- Docs and prompt instructions are updated

## Test Matrix

At minimum, add tests for:

- Feature disabled when Python is absent or too old
- Two-cell persistence
- Top-level await
- Reset clears state
- Failed cell preserves prior committed values
- Nested `codex.tool(...)`
- Unawaited `codex.tool(...)`
- `emit_image(...)` success and rejection cases
- `emitImage(...)` alias behavior
- Import reload after local file edit
- `py_repl_tools_only`
- Recursive REPL-call rejection
- Unsafe module/function denial for the v1 denylist

## Risks

### Safety risk

Python exposes more process and environment escape routes than the JS kernel. This needs explicit hardening early.

### Async semantics risk

If `codex.tool(...)` is implemented as a plain coroutine function, unawaited calls will never start. Use scheduled tasks instead.

### Import semantics risk

Python module caching is easy to get wrong. Module eviction rules must be explicit and limited to managed local roots.

### Scope risk

A premature “generic REPL abstraction” will slow delivery and increase blast radius. Keep `py_repl` parallel to `js_repl` first.

## Recommended First Merge

The first merge should target a narrow but real milestone:

- Feature/config/spec wiring
- End-to-end persistent Python execution
- Top-level await
- Reset
- Basic `codex.tool(...)`
- Basic `codex.emit_image(...)`
- Core integration tests

Deeper hardening can follow immediately after, but the first merge should already be structurally correct and safe by default.

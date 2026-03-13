#!/usr/bin/env python3

from __future__ import annotations

import ast
import asyncio
import base64
import builtins
import contextlib
import importlib
import inspect
import io
import json
import os
import queue
import sys
import threading
import traceback
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any


MINIMUM_VERSION = (3, 10)
BLOCKED_MODULES = frozenset({"subprocess", "multiprocessing", "pty", "ctypes"})
OS_DENYLIST = (
    "system",
    "popen",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "posix_spawn",
    "posix_spawnp",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
)


def debug(message: str) -> None:
    print(f"[py_repl kernel] {message}", file=sys.__stderr__, flush=True)


class PyReplError(RuntimeError):
    pass


class BackgroundTask:
    def __init__(self, task: asyncio.Task[Any]) -> None:
        self._task = task
        self.observed = False

    def __await__(self) -> Any:
        self.observed = True
        return self._task.__await__()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._task, name)


@dataclass
class ExecState:
    exec_id: str
    background_tasks: set[BackgroundTask] = field(default_factory=set)


class CodexProxy:
    def __init__(self, kernel: "PyReplKernel") -> None:
        self._kernel = kernel
        self.tmp_dir = kernel.tmp_dir

    def tool(self, name: str, args: Any = None) -> BackgroundTask:
        return self._kernel.create_background_task(self._kernel.run_tool(name, args))

    def emit_image(self, image_like: Any) -> BackgroundTask:
        return self._kernel.create_background_task(self._kernel.emit_image(image_like))

    def emitImage(self, image_like: Any) -> BackgroundTask:
        return self.emit_image(image_like)


class PyReplKernel:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        self.send_lock = threading.Lock()
        self.exec_queue: "queue.Queue[dict[str, Any] | None]" = queue.Queue()
        self.pending_tool_results: dict[str, asyncio.Future[Any]] = {}
        self.pending_emit_results: dict[str, asyncio.Future[None]] = {}
        self.current_exec: ExecState | None = None
        self.tool_counter = 0
        self.emit_counter = 0
        self.cell_counter = 0
        self.cwd = os.getcwd()
        self.tmp_dir = os.environ.get("CODEX_PY_REPL_TMP_DIR", self.cwd)
        self.original_import = builtins.__import__
        self.original_import_module = importlib.import_module
        self.static_managed_roots = self._resolve_managed_roots_from_env()

        self.globals: dict[str, Any] = {
            "__builtins__": builtins,
            "__name__": "__main__",
            "__package__": None,
        }
        self.codex = CodexProxy(self)
        self.globals["codex"] = self.codex

        self._install_import_guards()
        self._install_os_guards()
        self._evict_blocked_modules()
        self._refresh_sys_path()

    def run(self) -> int:
        stdin_thread = threading.Thread(target=self._stdin_reader, daemon=True)
        stdin_thread.start()

        while True:
            message = self.exec_queue.get()
            if message is None:
                break

            if message.get("type") != "exec":
                debug(f"ignoring non-exec message on exec queue: {message.get('type')!r}")
                continue

            result = self._handle_exec_message(message)
            self._send(result)

        self.loop.call_soon_threadsafe(self._fail_pending_futures, "py_repl kernel stdin closed")
        self.loop.run_until_complete(self._shutdown_async())
        return 0

    def _stdin_reader(self) -> None:
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as err:
                debug(f"failed to parse JSON input: {err}: {line!r}")
                continue

            message_type = message.get("type")
            if message_type == "exec":
                self.exec_queue.put(message)
            elif message_type in {"run_tool_result", "emit_image_result"}:
                self.loop.call_soon_threadsafe(self._resolve_host_message, message)
            else:
                debug(f"ignoring unsupported host message type: {message_type!r}")

        self.exec_queue.put(None)

    def _handle_exec_message(self, message: dict[str, Any]) -> dict[str, Any]:
        exec_id = str(message.get("id") or "")
        code = message.get("code")
        if not exec_id:
            return self._exec_error("", "", "py_repl exec message is missing a non-empty id")
        if not isinstance(code, str):
            return self._exec_error(exec_id, "", "py_repl exec message must include string code")

        return self.loop.run_until_complete(self._execute(exec_id, code))

    async def _execute(self, exec_id: str, code: str) -> dict[str, Any]:
        self._prepare_for_exec()
        exec_state = ExecState(exec_id=exec_id)
        self.current_exec = exec_state
        buffer = io.StringIO()
        error_text: str | None = None

        try:
            filename = os.path.join(self.cwd, f".codex_py_repl_cell_{self.cell_counter}.py")
            self.cell_counter += 1
            compiled = compile(
                code,
                filename,
                "exec",
                flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT,
                dont_inherit=True,
            )

            with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
                result = eval(compiled, self.globals)
                if inspect.isawaitable(result):
                    await result
        except BaseException:
            error_text = traceback.format_exc()

        helper_error = await self._drain_background_tasks(exec_state)
        if error_text is None and helper_error is not None:
            error_text = helper_error

        self.current_exec = None
        output = buffer.getvalue()
        if error_text is not None:
            return self._exec_error(exec_id, output, error_text)
        return {"type": "exec_result", "id": exec_id, "ok": True, "output": output, "error": None}

    async def _drain_background_tasks(self, exec_state: ExecState) -> str | None:
        if not exec_state.background_tasks:
            return None

        tracked = list(exec_state.background_tasks)
        await asyncio.gather(*(task._task for task in tracked), return_exceptions=True)

        first_unobserved_error: BaseException | None = None
        for task in tracked:
            if task._task.cancelled():
                if not task.observed and first_unobserved_error is None:
                    first_unobserved_error = PyReplError("background helper task was cancelled")
                continue

            exc = task._task.exception()
            if exc is not None and not task.observed and first_unobserved_error is None:
                first_unobserved_error = exc

        if first_unobserved_error is None:
            return None

        return "".join(
            traceback.format_exception(
                type(first_unobserved_error),
                first_unobserved_error,
                first_unobserved_error.__traceback__,
            )
        )

    async def _shutdown_async(self) -> None:
        pending = [task for task in asyncio.all_tasks(self.loop) if task is not asyncio.current_task()]
        if not pending:
            return
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    def _prepare_for_exec(self) -> None:
        self._refresh_sys_path()
        importlib.invalidate_caches()
        self._evict_managed_modules()

    def _refresh_sys_path(self) -> None:
        current_roots = self._managed_roots()
        existing = [
            entry
            for entry in sys.path
            if self._canonicalize_path(entry) not in {self._canonicalize_path(root) for root in current_roots}
        ]
        sys.path[:] = current_roots + existing

    def _managed_roots(self) -> list[str]:
        roots: list[str] = []
        seen: set[str] = set()
        for raw_path in [*self.static_managed_roots, os.getcwd()]:
            path = self._canonicalize_path(raw_path)
            if not path or path in seen:
                continue
            seen.add(path)
            roots.append(path)
        return roots

    def _resolve_managed_roots_from_env(self) -> list[str]:
        raw = os.environ.get("CODEX_PY_REPL_SYS_PATH", "")
        roots: list[str] = []
        for entry in raw.split(os.pathsep):
            stripped = entry.strip()
            if not stripped:
                continue
            roots.append(os.path.abspath(stripped))
        return roots

    def _evict_managed_modules(self) -> None:
        managed_roots = tuple(self._managed_roots())
        to_remove: list[str] = []
        for name, module in list(sys.modules.items()):
            if module is None or self._is_blocked_module_name(name):
                continue
            module_path = self._module_path(module)
            if module_path is None:
                continue
            if any(self._path_is_within_root(module_path, root) for root in managed_roots):
                to_remove.append(name)

        for name in to_remove:
            sys.modules.pop(name, None)

    def _module_path(self, module: ModuleType) -> str | None:
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None) if spec is not None else None
        if isinstance(origin, str) and origin not in {"built-in", "frozen"}:
            return self._canonicalize_path(origin)
        file_path = getattr(module, "__file__", None)
        if isinstance(file_path, str):
            return self._canonicalize_path(file_path)
        return None

    def _install_import_guards(self) -> None:
        def guarded_import(
            name: str,
            globals_dict: dict[str, Any] | None = None,
            locals_dict: dict[str, Any] | None = None,
            fromlist: tuple[Any, ...] = (),
            level: int = 0,
        ) -> Any:
            if self._is_blocked_module_name(name):
                raise PyReplError(f"Importing `{name}` is blocked in py_repl")
            return self.original_import(name, globals_dict, locals_dict, fromlist, level)

        def guarded_import_module(name: str, package: str | None = None) -> ModuleType:
            if self._is_blocked_module_name(name):
                raise PyReplError(f"Importing `{name}` is blocked in py_repl")
            return self.original_import_module(name, package)

        builtins.__import__ = guarded_import
        importlib.import_module = guarded_import_module

    def _install_os_guards(self) -> None:
        import os as os_module

        def blocked(name: str):
            def inner(*_args: Any, **_kwargs: Any) -> Any:
                raise PyReplError(f"`os.{name}` is blocked in py_repl")

            return inner

        for name in OS_DENYLIST:
            if hasattr(os_module, name):
                setattr(os_module, name, blocked(name))

    def _evict_blocked_modules(self) -> None:
        for name in list(sys.modules):
            if self._is_blocked_module_name(name):
                sys.modules.pop(name, None)

    def _is_blocked_module_name(self, name: str) -> bool:
        return any(name == blocked or name.startswith(f"{blocked}.") for blocked in BLOCKED_MODULES)

    def _resolve_host_message(self, message: dict[str, Any]) -> None:
        message_type = message.get("type")
        if message_type == "run_tool_result":
            self._finish_future(self.pending_tool_results, message, "tool failed")
        elif message_type == "emit_image_result":
            self._finish_future(self.pending_emit_results, message, "emit_image failed")
        else:
            debug(f"ignoring unexpected async host message type: {message_type!r}")

    def _finish_future(
        self,
        pending: dict[str, asyncio.Future[Any]],
        message: dict[str, Any],
        default_error: str,
    ) -> None:
        request_id = message.get("id")
        if not isinstance(request_id, str):
            debug(f"host result missing string id: {message!r}")
            return

        future = pending.pop(request_id, None)
        if future is None:
            debug(f"host result for unknown request id: {request_id}")
            return
        if future.done():
            return

        if message.get("ok") is True:
            future.set_result(message.get("response"))
        else:
            error = message.get("error")
            future.set_exception(PyReplError(error if isinstance(error, str) and error else default_error))

    def _fail_pending_futures(self, reason: str) -> None:
        for pending in (self.pending_tool_results, self.pending_emit_results):
            for future in pending.values():
                if not future.done():
                    future.set_exception(PyReplError(reason))
            pending.clear()

    def create_background_task(self, coroutine: Any) -> BackgroundTask:
        exec_state = self._require_active_exec()
        task = self.loop.create_task(coroutine)
        tracked = BackgroundTask(task)
        exec_state.background_tasks.add(tracked)
        task.add_done_callback(lambda _task: exec_state.background_tasks.discard(tracked))
        return tracked

    async def run_tool(self, tool_name: str, args: Any = None) -> Any:
        exec_state = self._require_active_exec()
        if not isinstance(tool_name, str) or not tool_name:
            raise PyReplError("codex.tool expects a non-empty tool name string")
        if tool_name in {"py_repl", "py_repl_reset"}:
            raise PyReplError("py_repl cannot invoke itself")

        request_id = f"{exec_state.exec_id}-tool-{self.tool_counter}"
        self.tool_counter += 1
        arguments = self._serialize_tool_args(args)
        future: asyncio.Future[Any] = self.loop.create_future()
        self.pending_tool_results[request_id] = future
        self._send(
            {
                "type": "run_tool",
                "id": request_id,
                "exec_id": exec_state.exec_id,
                "tool_name": tool_name,
                "arguments": arguments,
            }
        )
        return await future

    async def emit_image(self, image_like: Any) -> None:
        exec_state = self._require_active_exec()
        normalized = self._normalize_emit_image_value(await self._maybe_await(image_like))
        request_id = f"{exec_state.exec_id}-emit-image-{self.emit_counter}"
        self.emit_counter += 1
        future: asyncio.Future[None] = self.loop.create_future()
        self.pending_emit_results[request_id] = future
        self._send(
            {
                "type": "emit_image",
                "id": request_id,
                "exec_id": exec_state.exec_id,
                "image_url": normalized["image_url"],
                "detail": normalized.get("detail"),
            }
        )
        await future

    def _serialize_tool_args(self, args: Any) -> str:
        if isinstance(args, str):
            return args
        if args is None:
            return "{}"
        try:
            return json.dumps(args)
        except TypeError as err:
            raise PyReplError(f"codex.tool arguments must be JSON-serializable: {err}") from err

    async def _maybe_await(self, value: Any) -> Any:
        if inspect.isawaitable(value):
            return await value
        return value

    def _normalize_emit_image_value(self, value: Any) -> dict[str, Any]:
        if isinstance(value, str):
            return {"image_url": self._normalize_emit_image_url(value)}

        if isinstance(value, dict):
            direct = self._parse_direct_input_image(value)
            if direct is not None:
                return direct

            byte_image = self._parse_byte_image(value)
            if byte_image is not None:
                return byte_image

            if "output" in value:
                return self._require_single_image(self._parse_content_items(value["output"]))
            if "content" in value:
                return self._require_single_image(self._parse_content_items(value["content"]))
            if value.get("type") == "message":
                return self._require_single_image(self._parse_content_items(value.get("content")))
            if value.get("type") in {"function_call_output", "custom_tool_call_output"}:
                return self._require_single_image(self._parse_content_items(value.get("output")))
            if value.get("type") == "mcp_tool_call_output":
                return self._require_single_image(self._parse_mcp_tool_result(value.get("result")))

        if isinstance(value, list):
            return self._require_single_image(self._parse_content_items(value))

        raise PyReplError("codex.emit_image received an unsupported value")

    def _parse_direct_input_image(self, value: dict[str, Any]) -> dict[str, Any] | None:
        value_type = value.get("type")
        if value_type == "input_image":
            image_url = value.get("image_url")
            if not isinstance(image_url, str):
                raise PyReplError("codex.emit_image expected input_image.image_url to be a string")
            return {
                "image_url": self._normalize_emit_image_url(image_url),
                "detail": value.get("detail"),
            }
        if value_type == "image":
            data = value.get("data")
            mime_type = value.get("mimeType") or value.get("mime_type")
            if not isinstance(data, str) or not isinstance(mime_type, str) or not mime_type:
                raise PyReplError("codex.emit_image expected image data and mime type strings")
            return {
                "image_url": f"data:{mime_type};base64,{data}",
                "detail": value.get("detail"),
            }
        return None

    def _parse_byte_image(self, value: dict[str, Any]) -> dict[str, Any] | None:
        if "bytes" not in value:
            return None
        raw_bytes = value.get("bytes")
        mime_type = value.get("mimeType") or value.get("mime_type")
        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("utf-8")
        if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
            raise PyReplError("codex.emit_image bytes value must be bytes-like")
        if not isinstance(mime_type, str) or not mime_type:
            raise PyReplError("codex.emit_image bytes values require mimeType")
        encoded = base64.b64encode(bytes(raw_bytes)).decode("ascii")
        return {
            "image_url": f"data:{mime_type};base64,{encoded}",
            "detail": value.get("detail"),
        }

    def _parse_content_items(self, value: Any) -> dict[str, Any]:
        if isinstance(value, str):
            return {"images": [], "text_count": 1 if value else 0}
        if not isinstance(value, list):
            raise PyReplError("codex.emit_image received unsupported content items")

        images: list[dict[str, Any]] = []
        text_count = 0
        for item in value:
            if not isinstance(item, dict):
                raise PyReplError("codex.emit_image received malformed content item")
            item_type = item.get("type")
            if item_type == "input_text" or item_type == "text":
                text = item.get("text")
                if isinstance(text, str) and text:
                    text_count += 1
                continue
            if item_type == "input_image":
                image_url = item.get("image_url")
                if not isinstance(image_url, str):
                    raise PyReplError("codex.emit_image expected input_image.image_url to be a string")
                images.append(
                    {
                        "image_url": self._normalize_emit_image_url(image_url),
                        "detail": item.get("detail"),
                    }
                )
                continue
            if item_type == "image":
                data = item.get("data")
                mime_type = item.get("mimeType") or item.get("mime_type")
                if not isinstance(data, str) or not isinstance(mime_type, str) or not mime_type:
                    raise PyReplError("codex.emit_image expected image data and mime type strings")
                images.append(
                    {
                        "image_url": f"data:{mime_type};base64,{data}",
                        "detail": item.get("detail"),
                    }
                )
                continue
            raise PyReplError(f"codex.emit_image does not support content type {item_type!r}")

        return {"images": images, "text_count": text_count}

    def _parse_mcp_tool_result(self, value: Any) -> dict[str, Any]:
        if isinstance(value, str):
            return {"images": [], "text_count": 1 if value else 0}
        if not isinstance(value, dict):
            raise PyReplError("codex.emit_image received an unsupported MCP result")
        if "Err" in value:
            error = value["Err"]
            return {"images": [], "text_count": 1 if isinstance(error, str) and error else 0}
        if "Ok" not in value:
            raise PyReplError("codex.emit_image received an unsupported MCP result")
        ok = value["Ok"]
        if not isinstance(ok, dict):
            raise PyReplError("codex.emit_image received malformed MCP content")
        return self._parse_content_items(ok.get("content"))

    def _require_single_image(self, parsed: dict[str, Any]) -> dict[str, Any]:
        images = parsed.get("images", [])
        text_count = parsed.get("text_count", 0)
        if text_count:
            raise PyReplError("codex.emit_image does not accept mixed text and image content")
        if len(images) != 1:
            raise PyReplError("codex.emit_image expected exactly one image")
        return images[0]

    def _normalize_emit_image_url(self, value: str) -> str:
        if value[:5].lower() != "data:":
            raise PyReplError("codex.emit_image only accepts data URLs")
        return value

    def _require_active_exec(self) -> ExecState:
        if self.current_exec is None:
            raise PyReplError("codex helper calls are only available during active py_repl execution")
        return self.current_exec

    def _send(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False)
        with self.send_lock:
            sys.__stdout__.write(encoded)
            sys.__stdout__.write("\n")
            sys.__stdout__.flush()

    def _exec_error(self, exec_id: str, output: str, error: str) -> dict[str, Any]:
        return {
            "type": "exec_result",
            "id": exec_id,
            "ok": False,
            "output": output,
            "error": error,
        }

    def _canonicalize_path(self, path: str) -> str:
        if not path:
            return ""
        try:
            return os.path.realpath(path)
        except OSError:
            return os.path.abspath(path)

    def _path_is_within_root(self, path: str, root: str) -> bool:
        try:
            common = os.path.commonpath([path, root])
        except ValueError:
            return False
        return common == root


def main() -> int:
    if sys.version_info < MINIMUM_VERSION:
        debug(
            f"py_repl kernel requires Python {MINIMUM_VERSION[0]}.{MINIMUM_VERSION[1]}+, "
            f"got {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )
        return 1

    kernel = PyReplKernel()
    return kernel.run()


if __name__ == "__main__":
    raise SystemExit(main())

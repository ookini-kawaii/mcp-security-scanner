"""Runtime MCP stdio probing for Rug Pull detection."""

import hashlib
import json
import math
import os
import queue
import re
import signal
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from . import VERSION


RUNTIME_RULE_ID = "MCP-RUG-PULL-RUNTIME-001"
RUNTIME_RULE_NAME = "MCP Tool Metadata Changed At Runtime"
DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024
DEFAULT_MAX_MESSAGES = 256
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_MESSAGES = 10_000
ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_ENV_NAMES = {
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC",
    "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
}


class RuntimeProbeError(RuntimeError):
    """The MCP server could not be safely initialized or queried."""


@dataclass
class RuntimeScan:
    command: list[str]
    polls: int
    snapshots: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    policy: dict = field(default_factory=dict)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _public_command(command):
    """Return a useful command label without persisting server arguments."""
    executable = Path(command[0]).name
    return [executable, "<arguments redacted>"] if len(command) > 1 else [executable]


def _validate_limits(max_output_bytes, max_messages):
    if (
        not isinstance(max_output_bytes, int)
        or isinstance(max_output_bytes, bool)
        or not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES
    ):
        raise RuntimeProbeError(
            f"runtime max output 必须在 1 到 {MAX_OUTPUT_BYTES} 字节之间"
        )
    if (
        not isinstance(max_messages, int)
        or isinstance(max_messages, bool)
        or not 1 <= max_messages <= MAX_MESSAGES
    ):
        raise RuntimeProbeError(
            f"runtime max messages 必须在 1 到 {MAX_MESSAGES} 之间"
        )


def _runtime_environment(allow_env, inherit_environment):
    requested = list(allow_env or [])
    invalid = [
        name for name in requested
        if not isinstance(name, str) or not ENV_NAME_PATTERN.fullmatch(name)
    ]
    if invalid:
        raise RuntimeProbeError("runtime allow-env 包含无效环境变量名称")
    if inherit_environment and requested:
        raise RuntimeProbeError("runtime inherit-env 不能与 allow-env 同时使用")
    if inherit_environment:
        return None, {
            "environment_mode": "inherited",
            "environment_variable_count": len(os.environ),
        }

    allowed = DEFAULT_ENV_NAMES | set(requested)
    environment = {
        name: value for name, value in os.environ.items()
        if name in allowed or name.upper() in allowed
    }
    environment.setdefault("PYTHONIOENCODING", "utf-8")
    return environment, {
        "environment_mode": "allowlist",
        "environment_variable_count": len(environment),
        "explicit_environment_count": len(requested),
    }


def _resolve_command_paths(command):
    resolved = []
    for item in command:
        if item.startswith("-"):
            resolved.append(item)
            continue
        try:
            candidate = Path(item)
            if not candidate.is_absolute() and candidate.exists():
                resolved.append(str(candidate.resolve()))
                continue
        except (OSError, ValueError):
            pass
        resolved.append(item)
    return resolved


def _validate_command(command):
    if (
        not isinstance(command, (list, tuple))
        or not command
        or any(not isinstance(item, str) or not item for item in command)
    ):
        raise RuntimeProbeError("runtime command 必须是非空参数列表")
    return list(command)


def _validate_response(message, request_id, method):
    if not isinstance(message, dict):
        raise RuntimeProbeError(f"{method} 响应必须是 JSON 对象")
    if message.get("jsonrpc") != "2.0":
        raise RuntimeProbeError(f"{method} 响应缺少有效的 jsonrpc 2.0 版本")
    if message.get("id") != request_id:
        return False
    has_result = "result" in message
    has_error = "error" in message
    if has_result == has_error:
        raise RuntimeProbeError(f"{method} 响应必须且只能包含 result 或 error")
    if has_error:
        raise RuntimeProbeError(f"{method} 返回 JSON-RPC 错误")
    return True


def _validate_initialize(message):
    result = message.get("result")
    server_info = result.get("serverInfo") if isinstance(result, dict) else None
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("protocolVersion"), str)
        or not result["protocolVersion"]
        or not isinstance(result.get("capabilities"), dict)
        or not isinstance(server_info, dict)
        or not isinstance(server_info.get("name"), str)
        or not server_info["name"]
        or not isinstance(server_info.get("version"), str)
        or not server_info["version"]
    ):
        raise RuntimeProbeError("initialize 响应缺少有效的 protocolVersion、capabilities 或 serverInfo")


def _tool_map(message):
    if not isinstance(message, dict):
        raise RuntimeProbeError("tools/list 响应必须是 JSON 对象")
    if "error" in message:
        raise RuntimeProbeError(f"tools/list 返回错误: {message['error']}")
    result = message.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        raise RuntimeProbeError("tools/list 响应缺少 result.tools 列表")
    tools = {}
    for item in result["tools"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or not isinstance(item.get("inputSchema"), dict)
            or ("description" in item and not isinstance(item["description"], str))
        ):
            raise RuntimeProbeError("tools/list 包含无效工具对象")
        name = item["name"]
        if name in tools:
            raise RuntimeProbeError(f"tools/list 存在重复工具名称: {name}")
        tools[name] = item
    return tools


def _finding(command, poll, name, change, before, after, field=None):
    labels = {
        "added": "运行时新增工具",
        "removed": "运行时删除工具",
        "changed": "运行时工具元数据变化",
    }
    field_path = f"tools.{name}" if field is None else f"tools.{name}.{field}"
    return {
        "rule_id": RUNTIME_RULE_ID,
        "rule_name": RUNTIME_RULE_NAME,
        "severity": "HIGH",
        "severity_rank": 3,
        "category": "supply_chain_poisoning",
        "confidence": 95,
        "matched_pattern": change,
        "matched_text": f"{labels[change]}: {name}" + (f" ({field})" if field else ""),
        "target": "runtime:" + command[0],
        "field_path": field_path,
        "scope": "runtime_tools_list",
        "position": "line:1,column:1",
        "offset": 0,
        "source_file": "runtime_tools_list",
        "decoded_from": None,
        "decoded_depth": 0,
        "runtime_poll": poll,
        "runtime_change": change,
        "before_sha256": _digest(before) if before is not None else None,
        "after_sha256": _digest(after) if after is not None else None,
    }


def _compare(command, poll, previous, current):
    findings = []
    for name in sorted(set(previous) | set(current)):
        if name not in previous:
            findings.append(_finding(command, poll, name, "added", None, current[name]))
            continue
        if name not in current:
            findings.append(_finding(command, poll, name, "removed", previous[name], None))
            continue
        before = previous[name]
        after = current[name]
        for field in ("description", "inputSchema"):
            if before.get(field) != after.get(field):
                findings.append(_finding(command, poll, name, "changed", before.get(field), after.get(field), field))
    return findings


class _StdioSession:
    def __init__(self, command, cwd, environment, max_output_bytes, max_messages):
        self.command = _resolve_command_paths(list(command))
        if not self.command or any(not isinstance(item, str) or not item for item in self.command):
            raise RuntimeProbeError("runtime command 必须是非空参数列表")
        self.max_output_bytes = max_output_bytes
        self.max_messages = max_messages
        self.output_bytes = 0
        self.message_count = 0
        self.state_lock = threading.Lock()
        self.reader_error = None
        creationflags = 0
        start_new_session = os.name != "nt"
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=environment,
                bufsize=0,
                start_new_session=start_new_session,
                creationflags=creationflags,
            )
        except (OSError, ValueError) as exc:
            raise RuntimeProbeError(f"MCP Server 启动失败: {exc}") from exc
        self.messages = queue.Queue(maxsize=max_messages)
        self.reader = threading.Thread(target=self._read_stdout, daemon=True)
        self.error_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self.reader.start()
        self.error_reader.start()

    def _set_reader_error(self, message):
        with self.state_lock:
            if self.reader_error is None:
                self.reader_error = RuntimeProbeError(message)

    def _consume_output(self, size):
        with self.state_lock:
            self.output_bytes += size
            if self.output_bytes > self.max_output_bytes:
                if self.reader_error is None:
                    self.reader_error = RuntimeProbeError(
                        f"MCP Server 输出超过 {self.max_output_bytes} 字节限制"
                    )
                return False
        return True

    def _put_message(self, message):
        with self.state_lock:
            self.message_count += 1
            if self.message_count > self.max_messages:
                if self.reader_error is None:
                    self.reader_error = RuntimeProbeError(
                        f"MCP Server 消息数超过 {self.max_messages} 条限制"
                    )
                return False
        try:
            self.messages.put_nowait(message)
            return True
        except queue.Full:
            self._set_reader_error("MCP Server 消息队列已满")
            return False

    def _read_stdout(self):
        try:
            while True:
                line = self.process.stdout.readline(self.max_output_bytes + 1)
                if not line:
                    return
                if len(line) > self.max_output_bytes:
                    self._set_reader_error("MCP Server 单行输出超过限制")
                    return
                if not self._consume_output(len(line)):
                    return
                if not line.strip():
                    continue
                try:
                    decoded = line.decode("utf-8", errors="strict")
                    message = json.loads(decoded)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    self._set_reader_error(f"MCP Server 输出无效: {exc}")
                    return
                if not self._put_message(message):
                    return
        except (OSError, ValueError) as exc:
            self._set_reader_error(f"MCP Server 输出读取失败: {exc}")

    def _read_stderr(self):
        try:
            while True:
                chunk = self.process.stderr.read(8192)
                if not chunk:
                    return
                if not self._consume_output(len(chunk)):
                    return
        except (OSError, ValueError) as exc:
            self._set_reader_error(f"MCP Server 错误输出读取失败: {exc}")

    def _raise_reader_error(self):
        with self.state_lock:
            error = self.reader_error
        if error is not None:
            raise error

    def request(self, request_id, method, params, timeout):
        if self.process.poll() is not None:
            raise RuntimeProbeError("MCP Server 已提前退出")
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        try:
            payload = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
            self.process.stdin.write(payload)
            self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise RuntimeProbeError(f"MCP Server 请求写入失败: {exc}") from exc
        deadline = time.monotonic() + timeout
        while True:
            self._raise_reader_error()
            if self.process.poll() is not None and self.messages.empty():
                raise RuntimeProbeError("MCP Server 已提前退出")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeProbeError(f"MCP Server 请求超时: {method}")
            try:
                response = self.messages.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if _validate_response(response, request_id, method):
                return response

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        try:
            payload = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
            self.process.stdin.write(payload)
            self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise RuntimeProbeError(f"MCP Server 通知写入失败: {exc}") from exc

    def close(self):
        if self.process.poll() is None:
            try:
                if os.name == "nt":
                    self.process.terminate()
                else:
                    os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    if os.name == "nt":
                        self.process.kill()
                    else:
                        os.killpg(self.process.pid, signal.SIGKILL)
                except OSError:
                    pass
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except (AttributeError, OSError, ValueError):
                pass
        self.reader.join(timeout=0.5)
        self.error_reader.join(timeout=0.5)


def monitor_tools(
    command,
    polls=2,
    timeout=5.0,
    interval=0.0,
    cwd=None,
    allow_env=None,
    inherit_environment=False,
    max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
    max_messages=DEFAULT_MAX_MESSAGES,
):
    command = _validate_command(command)
    if not isinstance(polls, int) or isinstance(polls, bool) or polls < 2:
        raise RuntimeProbeError("runtime polls 至少为 2，才能比较 tools/list 变化")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        raise RuntimeProbeError("runtime timeout 必须大于 0")
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or not math.isfinite(interval) or interval < 0:
        raise RuntimeProbeError("runtime interval 必须大于或等于 0")
    _validate_limits(max_output_bytes, max_messages)
    environment, environment_policy = _runtime_environment(
        allow_env, inherit_environment
    )
    explicit_cwd = cwd is not None
    if explicit_cwd:
        runtime_cwd = Path(cwd)
        if not runtime_cwd.is_dir():
            raise RuntimeProbeError("runtime cwd 不存在或不是目录")
        runtime_cwd = runtime_cwd.resolve()
    public_command = _public_command(command)
    policy = {
        **environment_policy,
        "working_directory_mode": "explicit" if explicit_cwd else "temporary",
        "max_output_bytes": max_output_bytes,
        "max_messages": max_messages,
    }
    scan = RuntimeScan(public_command, polls, policy=policy)
    with ExitStack() as stack:
        if not explicit_cwd:
            runtime_cwd = Path(stack.enter_context(
                tempfile.TemporaryDirectory(prefix="mcp-scanner-runtime-")
            ))
        session = _StdioSession(
            command,
            runtime_cwd,
            environment,
            max_output_bytes,
            max_messages,
        )
        try:
            initialize_response = session.request(
                1,
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-security-scanner", "version": VERSION},
                },
                timeout,
            )
            _validate_initialize(initialize_response)
            session.notify("notifications/initialized")
            previous = None
            for poll in range(1, polls + 1):
                response = session.request(1000 + poll, "tools/list", {}, timeout)
                current = _tool_map(response)
                scan.snapshots.append({
                    "poll": poll,
                    "tool_count": len(current),
                    "sha256": _digest(current),
                })
                if previous is not None:
                    scan.findings.extend(_compare(public_command, poll, previous, current))
                previous = current
                if poll < polls and interval:
                    time.sleep(interval)
        finally:
            session.close()
        session._raise_reader_error()
        return scan

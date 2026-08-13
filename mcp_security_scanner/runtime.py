"""Runtime MCP stdio probing for Rug Pull detection."""

import hashlib
import json
import math
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


RUNTIME_RULE_ID = "MCP-RUG-PULL-RUNTIME-001"
RUNTIME_RULE_NAME = "MCP Tool Metadata Changed At Runtime"


class RuntimeProbeError(RuntimeError):
    """The MCP server could not be safely initialized or queried."""


@dataclass
class RuntimeScan:
    command: list[str]
    polls: int
    snapshots: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _public_command(command):
    """Return a useful command label without persisting server arguments."""
    executable = Path(command[0]).name
    return [executable, "<arguments redacted>"] if len(command) > 1 else [executable]


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
        raise RuntimeProbeError(f"{method} 返回错误: {message['error']}")
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
    def __init__(self, command):
        self.command = list(command)
        if not self.command or any(not isinstance(item, str) or not item for item in self.command):
            raise RuntimeProbeError("runtime command 必须是非空参数列表")
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="strict",
                bufsize=1,
            )
        except (OSError, ValueError) as exc:
            raise RuntimeProbeError(f"MCP Server 启动失败: {exc}") from exc
        self.messages = queue.Queue()
        self.stderr = queue.Queue()
        self.reader = threading.Thread(target=self._read_stdout, daemon=True)
        self.error_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self.reader.start()
        self.error_reader.start()

    def _read_stdout(self):
        try:
            for line in self.process.stdout:
                if line.strip():
                    self.messages.put(json.loads(line))
        except Exception as exc:  # surfaced to the request waiter
            self.messages.put(RuntimeProbeError(f"MCP Server 输出无效: {exc}"))

    def _read_stderr(self):
        try:
            for line in self.process.stderr:
                self.stderr.put(line.rstrip())
        except Exception:
            return

    def request(self, request_id, method, params, timeout):
        if self.process.poll() is not None:
            raise RuntimeProbeError("MCP Server 已提前退出")
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        try:
            self.process.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
            self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise RuntimeProbeError(f"MCP Server 请求写入失败: {exc}") from exc
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeProbeError(f"MCP Server 请求超时: {method}")
            try:
                response = self.messages.get(timeout=remaining)
            except queue.Empty as exc:
                raise RuntimeProbeError(f"MCP Server 请求超时: {method}") from exc
            if isinstance(response, RuntimeProbeError):
                raise response
            if _validate_response(response, request_id, method):
                return response

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        try:
            self.process.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
            self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise RuntimeProbeError(f"MCP Server 通知写入失败: {exc}") from exc

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except (AttributeError, OSError, ValueError):
                pass


def monitor_tools(command, polls=2, timeout=5.0, interval=0.0):
    if not isinstance(polls, int) or isinstance(polls, bool) or polls < 2:
        raise RuntimeProbeError("runtime polls 至少为 2，才能比较 tools/list 变化")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        raise RuntimeProbeError("runtime timeout 必须大于 0")
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or not math.isfinite(interval) or interval < 0:
        raise RuntimeProbeError("runtime interval 必须大于或等于 0")
    session = _StdioSession(command)
    public_command = _public_command(command)
    scan = RuntimeScan(public_command, polls)
    try:
        initialize_response = session.request(
            1,
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "mcp-security-scanner", "version": "1.4.1"},
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
        return scan
    finally:
        session.close()

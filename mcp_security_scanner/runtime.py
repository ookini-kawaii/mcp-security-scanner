"""Runtime MCP stdio monitoring for metadata rug-pull detection."""

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
RUNTIME_RULE_NAME = "MCP Runtime Metadata Changed"
DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024
DEFAULT_MAX_MESSAGES = 256
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_MESSAGES = 10_000
DEFAULT_PROTOCOL_VERSION = "2025-03-26"
SUPPORTED_PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
)
ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_ENV_NAMES = {
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC",
    "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
}


@dataclass(frozen=True)
class _Surface:
    name: str
    method: str
    result_key: str
    identity_key: str
    required: tuple[tuple[str, type], ...]
    optional: tuple[tuple[str, type], ...]
    monitored_fields: tuple[str, ...]


SURFACES = (
    _Surface(
        "tools", "tools/list", "tools", "name",
        (("name", str), ("inputSchema", dict)),
        (("description", str), ("outputSchema", dict), ("annotations", dict)),
        ("description", "inputSchema", "outputSchema", "annotations"),
    ),
    _Surface(
        "resources", "resources/list", "resources", "uri",
        (("name", str), ("uri", str)),
        (("description", str), ("mimeType", str), ("annotations", dict)),
        ("name", "description", "mimeType", "annotations"),
    ),
    _Surface(
        "resource_templates", "resources/templates/list", "resourceTemplates",
        "uriTemplate", (("name", str), ("uriTemplate", str)),
        (("description", str), ("mimeType", str), ("annotations", dict)),
        ("name", "description", "mimeType", "annotations"),
    ),
    _Surface(
        "prompts", "prompts/list", "prompts", "name",
        (("name", str),), (("description", str), ("arguments", list)),
        ("description", "arguments"),
    ),
)
SURFACE_BY_NAME = {surface.name: surface for surface in SURFACES}


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
            f"runtime max output must be between 1 and {MAX_OUTPUT_BYTES} bytes"
        )
    if (
        not isinstance(max_messages, int)
        or isinstance(max_messages, bool)
        or not 1 <= max_messages <= MAX_MESSAGES
    ):
        raise RuntimeProbeError(
            f"runtime max messages must be between 1 and {MAX_MESSAGES}"
        )


def _validate_protocol_version(protocol_version):
    if protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
        supported = ", ".join(SUPPORTED_PROTOCOL_VERSIONS)
        raise RuntimeProbeError(
            f"unsupported runtime protocol version: {protocol_version!r}; "
            f"supported legacy versions: {supported}"
        )


def _runtime_environment(allow_env, inherit_environment):
    requested = list(allow_env or [])
    invalid = [
        name for name in requested
        if not isinstance(name, str) or not ENV_NAME_PATTERN.fullmatch(name)
    ]
    if invalid:
        raise RuntimeProbeError("runtime allow-env contains an invalid variable name")
    if inherit_environment and requested:
        raise RuntimeProbeError("runtime inherit-env cannot be combined with allow-env")
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
        raise RuntimeProbeError("runtime command must be a non-empty argument list")
    return list(command)


def _validate_response(message, request_id, method):
    if not isinstance(message, dict):
        raise RuntimeProbeError(f"{method} response must be a JSON object")
    if message.get("jsonrpc") != "2.0":
        raise RuntimeProbeError(f"{method} response must use JSON-RPC 2.0")
    if message.get("id") != request_id:
        return False
    has_result = "result" in message
    has_error = "error" in message
    if has_result == has_error:
        raise RuntimeProbeError(f"{method} response must contain exactly one of result or error")
    if has_error:
        raise RuntimeProbeError(f"{method} returned a JSON-RPC error")
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
        raise RuntimeProbeError(
            "initialize response requires protocolVersion, capabilities, and serverInfo"
        )
    negotiated = result["protocolVersion"]
    _validate_protocol_version(negotiated)
    capabilities = result["capabilities"]
    for capability in ("tools", "resources", "prompts"):
        if capability in capabilities and not isinstance(capabilities[capability], dict):
            raise RuntimeProbeError(
                f"initialize capability {capability!r} must be a JSON object"
            )
    return negotiated, capabilities


def _selected_surfaces(capabilities, force_tools=False):
    names = []
    if force_tools or "tools" in capabilities or not capabilities:
        names.append("tools")
    if "resources" in capabilities:
        names.extend(("resources", "resource_templates"))
    if "prompts" in capabilities:
        names.append("prompts")
    return tuple(SURFACE_BY_NAME[name] for name in names)


def _validate_prompt_arguments(arguments, method):
    names = set()
    for argument in arguments:
        if (
            not isinstance(argument, dict)
            or not isinstance(argument.get("name"), str)
            or not argument["name"]
            or ("description" in argument and not isinstance(argument["description"], str))
            or ("required" in argument and not isinstance(argument["required"], bool))
        ):
            raise RuntimeProbeError(f"{method} contains an invalid prompt argument")
        if argument["name"] in names:
            raise RuntimeProbeError(f"{method} contains duplicate prompt argument names")
        names.add(argument["name"])


def _surface_page(message, surface):
    result = message.get("result")
    if not isinstance(result, dict) or not isinstance(result.get(surface.result_key), list):
        raise RuntimeProbeError(
            f"{surface.method} response requires result.{surface.result_key}"
        )
    if "nextCursor" in result and (
        not isinstance(result["nextCursor"], str) or not result["nextCursor"]
    ):
        raise RuntimeProbeError(f"{surface.method} returned an invalid nextCursor")

    items = {}
    for item in result[surface.result_key]:
        if not isinstance(item, dict):
            raise RuntimeProbeError(f"{surface.method} contains a non-object item")
        for key, expected_type in surface.required:
            value = item.get(key)
            if not isinstance(value, expected_type) or (
                expected_type is str and not value
            ):
                raise RuntimeProbeError(
                    f"{surface.method} item requires a valid {key}"
                )
        for key, expected_type in surface.optional:
            if key in item and not isinstance(item[key], expected_type):
                raise RuntimeProbeError(
                    f"{surface.method} item has an invalid {key}"
                )
        if surface.name == "prompts" and "arguments" in item:
            _validate_prompt_arguments(item["arguments"], surface.method)
        identity = item[surface.identity_key]
        if identity in items:
            raise RuntimeProbeError(
                f"{surface.method} contains a duplicate {surface.identity_key}"
            )
        items[identity] = {
            surface.identity_key: identity,
            **{key: item.get(key) for key in surface.monitored_fields},
        }
    return items, result.get("nextCursor")


def _identity_label(identity):
    return "sha256:" + _digest(identity)[:16]


def _finding(command, poll, surface, identity, change, before, after, field=None):
    label = _identity_label(identity)
    field_path = f"{surface.name}.{label}"
    if field is not None:
        field_path += f".{field}"
    message = f"Runtime {surface.name} metadata {change}: {label}"
    if field:
        message += f" ({field})"
    return {
        "rule_id": RUNTIME_RULE_ID,
        "rule_name": RUNTIME_RULE_NAME,
        "severity": "HIGH",
        "severity_rank": 3,
        "category": "supply_chain_poisoning",
        "confidence": 95,
        "matched_pattern": change,
        "matched_text": message,
        "target": "runtime:" + command[0],
        "field_path": field_path,
        "scope": "runtime_mcp_metadata",
        "position": "line:1,column:1",
        "offset": 0,
        "source_file": "runtime_mcp_metadata",
        "decoded_from": None,
        "decoded_depth": 0,
        "runtime_poll": poll,
        "runtime_surface": surface.name,
        "runtime_change": change,
        "before_sha256": _digest(before) if before is not None else None,
        "after_sha256": _digest(after) if after is not None else None,
    }


def _compare(command, poll, surface, previous, current):
    findings = []
    for identity in sorted(set(previous) | set(current)):
        if identity not in previous:
            findings.append(
                _finding(command, poll, surface, identity, "added", None, current[identity])
            )
            continue
        if identity not in current:
            findings.append(
                _finding(command, poll, surface, identity, "removed", previous[identity], None)
            )
            continue
        before = previous[identity]
        after = current[identity]
        for field in surface.monitored_fields:
            if before.get(field) != after.get(field):
                findings.append(
                    _finding(
                        command, poll, surface, identity, "changed",
                        before.get(field), after.get(field), field,
                    )
                )
    return findings


class _StdioSession:
    def __init__(self, command, cwd, environment, max_output_bytes, max_messages):
        self.command = _resolve_command_paths(list(command))
        if not self.command or any(not isinstance(item, str) or not item for item in self.command):
            raise RuntimeProbeError("runtime command must be a non-empty argument list")
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
            raise RuntimeProbeError(f"MCP server failed to start: {exc}") from exc
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
            self._set_reader_error("MCP server message queue is full")
            return False

    def _read_stdout(self):
        try:
            while True:
                line = self.process.stdout.readline(self.max_output_bytes + 1)
                if not line:
                    return
                if len(line) > self.max_output_bytes:
                    self._set_reader_error("MCP server line output exceeded the limit")
                    return
                if not self._consume_output(len(line)):
                    return
                if not line.strip():
                    continue
                try:
                    decoded = line.decode("utf-8", errors="strict")
                    message = json.loads(decoded)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    self._set_reader_error(f"MCP server output is invalid: {exc}")
                    return
                if not self._put_message(message):
                    return
        except (OSError, ValueError) as exc:
            self._set_reader_error(f"MCP server output read failed: {exc}")

    def _read_stderr(self):
        try:
            while True:
                chunk = self.process.stderr.read(8192)
                if not chunk:
                    return
                if not self._consume_output(len(chunk)):
                    return
        except (OSError, ValueError) as exc:
            self._set_reader_error(f"MCP server stderr read failed: {exc}")

    def _raise_reader_error(self):
        with self.state_lock:
            error = self.reader_error
        if error is not None:
            raise error

    def request(self, request_id, method, params, timeout):
        if self.process.poll() is not None:
            raise RuntimeProbeError("MCP server exited early")
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        try:
            payload = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
            self.process.stdin.write(payload)
            self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            raise RuntimeProbeError(f"MCP server request write failed: {exc}") from exc
        deadline = time.monotonic() + timeout
        while True:
            self._raise_reader_error()
            if self.process.poll() is not None and self.messages.empty():
                raise RuntimeProbeError("MCP server exited early")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeProbeError(f"MCP server request timed out: {method}")
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
            raise RuntimeProbeError(f"MCP server notification write failed: {exc}") from exc

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


def _query_surface(session, surface, next_request_id, timeout):
    items = {}
    cursor = None
    seen_cursors = set()
    while True:
        params = {} if cursor is None else {"cursor": cursor}
        response = session.request(next_request_id(), surface.method, params, timeout)
        page, next_cursor = _surface_page(response, surface)
        duplicate = set(items) & set(page)
        if duplicate:
            raise RuntimeProbeError(
                f"{surface.method} contains duplicate identities across pages"
            )
        items.update(page)
        if next_cursor is None:
            return items
        if next_cursor in seen_cursors:
            raise RuntimeProbeError(f"{surface.method} returned a cursor loop")
        seen_cursors.add(next_cursor)
        cursor = next_cursor


def _monitor(
    command,
    polls,
    timeout,
    interval,
    cwd,
    allow_env,
    inherit_environment,
    max_output_bytes,
    max_messages,
    protocol_version,
    force_tools,
):
    command = _validate_command(command)
    if not isinstance(polls, int) or isinstance(polls, bool) or polls < 2:
        raise RuntimeProbeError("runtime polls must be at least 2")
    if (
        not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
        or not math.isfinite(timeout) or timeout <= 0
    ):
        raise RuntimeProbeError("runtime timeout must be greater than 0")
    if (
        not isinstance(interval, (int, float)) or isinstance(interval, bool)
        or not math.isfinite(interval) or interval < 0
    ):
        raise RuntimeProbeError("runtime interval must be greater than or equal to 0")
    _validate_protocol_version(protocol_version)
    _validate_limits(max_output_bytes, max_messages)
    environment, environment_policy = _runtime_environment(
        allow_env, inherit_environment
    )
    explicit_cwd = cwd is not None
    if explicit_cwd:
        runtime_cwd = Path(cwd)
        if not runtime_cwd.is_dir():
            raise RuntimeProbeError("runtime cwd does not exist or is not a directory")
        runtime_cwd = runtime_cwd.resolve()
    public_command = _public_command(command)
    policy = {
        **environment_policy,
        "working_directory_mode": "explicit" if explicit_cwd else "temporary",
        "max_output_bytes": max_output_bytes,
        "max_messages": max_messages,
        "requested_protocol_version": protocol_version,
    }
    scan = RuntimeScan(public_command, polls, policy=policy)
    with ExitStack() as stack:
        if not explicit_cwd:
            runtime_cwd = Path(stack.enter_context(
                tempfile.TemporaryDirectory(prefix="mcp-scanner-runtime-")
            ))
        session = _StdioSession(
            command, runtime_cwd, environment, max_output_bytes, max_messages
        )
        request_id = 0

        def next_request_id():
            nonlocal request_id
            request_id += 1
            return request_id

        try:
            initialize_response = session.request(
                next_request_id(),
                "initialize",
                {
                    "protocolVersion": protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-security-scanner", "version": VERSION},
                },
                timeout,
            )
            negotiated, capabilities = _validate_initialize(initialize_response)
            scan.policy["negotiated_protocol_version"] = negotiated
            surfaces = _selected_surfaces(capabilities, force_tools=force_tools)
            scan.policy["monitored_surfaces"] = [surface.name for surface in surfaces]
            session.notify("notifications/initialized")

            previous = None
            for poll in range(1, polls + 1):
                current = {}
                surface_snapshots = {}
                for surface in surfaces:
                    items = _query_surface(
                        session, surface, next_request_id, timeout
                    )
                    current[surface.name] = items
                    surface_snapshots[surface.name] = {
                        "count": len(items),
                        "sha256": _digest(items),
                    }
                scan.snapshots.append({
                    "poll": poll,
                    "capabilities_sha256": _digest(capabilities),
                    "surfaces": surface_snapshots,
                })
                if previous is not None:
                    for surface in surfaces:
                        scan.findings.extend(_compare(
                            public_command,
                            poll,
                            surface,
                            previous[surface.name],
                            current[surface.name],
                        ))
                previous = current
                if poll < polls and interval:
                    time.sleep(interval)
        finally:
            session.close()
        session._raise_reader_error()
    return scan


def monitor_surfaces(
    command,
    polls=2,
    timeout=5.0,
    interval=0.0,
    cwd=None,
    allow_env=None,
    inherit_environment=False,
    max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
    max_messages=DEFAULT_MAX_MESSAGES,
    protocol_version=DEFAULT_PROTOCOL_VERSION,
):
    """Monitor every metadata surface advertised by a legacy MCP stdio server."""
    return _monitor(
        command, polls, timeout, interval, cwd, allow_env, inherit_environment,
        max_output_bytes, max_messages, protocol_version, False,
    )


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
    protocol_version=DEFAULT_PROTOCOL_VERSION,
):
    """Backward-compatible explicit tools/list monitor."""
    return _monitor(
        command, polls, timeout, interval, cwd, allow_env, inherit_environment,
        max_output_bytes, max_messages, protocol_version, True,
    )

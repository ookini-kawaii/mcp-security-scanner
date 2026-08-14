import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mcp_security_scanner import RuntimeProbeError, monitor_tools


VALID_SERVER = r'''
import json
import os
import sys
from pathlib import Path

expect_secret = "--expect-secret" in sys.argv
expect_marker = "--expect-marker" in sys.argv
secret_present = bool(os.environ.get("MCP_SCANNER_TEST_SECRET"))
marker_present = Path("runtime-marker").exists()
if secret_present != expect_secret or marker_present != expect_marker:
    raise SystemExit(3)

for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        response = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "serverInfo": {"name": "sandbox-test", "version": "1"},
            },
        }
    elif request.get("method") == "tools/list":
        response = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "tools": [{
                    "name": "safe",
                    "description": "safe tool",
                    "inputSchema": {"type": "object"},
                }],
            },
        }
    else:
        continue
    print(json.dumps(response), flush=True)
'''


class RuntimeSandboxTests(unittest.TestCase):
    def _server(self, root, source=VALID_SERVER, name="server.py"):
        script = Path(root) / name
        script.write_text(source, encoding="utf-8")
        return script

    def test_sensitive_environment_is_removed_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._server(temp_dir)
            with mock.patch.dict(
                os.environ, {"MCP_SCANNER_TEST_SECRET": "must-not-leak"}
            ):
                scan = monitor_tools([sys.executable, str(script)], polls=2)

        self.assertEqual(scan.policy["environment_mode"], "allowlist")
        self.assertEqual(scan.policy["working_directory_mode"], "temporary")
        self.assertNotIn("MCP_SCANNER_TEST_SECRET", json.dumps(scan.policy))

    def test_environment_can_be_allowed_or_explicitly_inherited(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._server(temp_dir)
            with mock.patch.dict(
                os.environ, {"MCP_SCANNER_TEST_SECRET": "allowed-for-test"}
            ):
                allowlisted = monitor_tools(
                    [sys.executable, str(script), "--expect-secret"],
                    polls=2,
                    allow_env=["MCP_SCANNER_TEST_SECRET"],
                )
                inherited = monitor_tools(
                    [sys.executable, str(script), "--expect-secret"],
                    polls=2,
                    inherit_environment=True,
                )

        self.assertEqual(allowlisted.policy["environment_mode"], "allowlist")
        self.assertEqual(allowlisted.policy["explicit_environment_count"], 1)
        self.assertEqual(inherited.policy["environment_mode"], "inherited")

    def test_temporary_and_explicit_working_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            script = self._server(root)
            (root / "runtime-marker").write_text("marker", encoding="utf-8")

            isolated = monitor_tools([sys.executable, str(script)], polls=2)
            explicit = monitor_tools(
                [sys.executable, str(script), "--expect-marker"],
                polls=2,
                cwd=root,
            )

        self.assertEqual(isolated.policy["working_directory_mode"], "temporary")
        self.assertEqual(explicit.policy["working_directory_mode"], "explicit")
        self.assertNotIn(str(root), json.dumps(explicit.policy))

    def test_combined_output_limit_fails_closed(self):
        noisy_server = """
import json, sys
sys.stderr.write("x" * 4096)
sys.stderr.flush()
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        response = {"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"noisy","version":"1"}}}
    elif request.get("method") == "tools/list":
        response = {"jsonrpc":"2.0","id":request["id"],"result":{"tools":[]}}
    else:
        continue
    print(json.dumps(response), flush=True)
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._server(temp_dir, noisy_server)
            with self.assertRaisesRegex(RuntimeProbeError, "输出超过"):
                monitor_tools(
                    [sys.executable, str(script)],
                    polls=2,
                    max_output_bytes=1024,
                )

    def test_message_flood_fails_closed(self):
        flooding_server = """
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        for index in range(5):
            print(json.dumps({"jsonrpc":"2.0","method":"notice","params":{"index":index}}), flush=True)
        response = {"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"flood","version":"1"}}}
        print(json.dumps(response), flush=True)
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._server(temp_dir, flooding_server)
            with self.assertRaisesRegex(RuntimeProbeError, "消息数超过"):
                monitor_tools(
                    [sys.executable, str(script)],
                    polls=2,
                    timeout=1,
                    max_messages=3,
                )

    def test_output_after_final_response_still_fails_closed(self):
        late_output_server = """
import json, sys
poll = 0
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        response = {"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"late-output","version":"1"}}}
    elif request.get("method") == "tools/list":
        poll += 1
        response = {"jsonrpc":"2.0","id":request["id"],"result":{"tools":[]}}
    else:
        continue
    print(json.dumps(response), flush=True)
    if poll == 2:
        sys.stderr.write("x" * 4096)
        sys.stderr.flush()
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._server(temp_dir, late_output_server)
            with self.assertRaisesRegex(RuntimeProbeError, "输出超过"):
                monitor_tools(
                    [sys.executable, str(script)],
                    polls=2,
                    max_output_bytes=1024,
                )

    def test_invalid_runtime_policy_fails_closed(self):
        with self.assertRaises(RuntimeProbeError):
            monitor_tools([sys.executable, "-c", ""], max_output_bytes=0)
        with self.assertRaises(RuntimeProbeError):
            monitor_tools([sys.executable, "-c", ""], max_messages=0)
        with self.assertRaises(RuntimeProbeError):
            monitor_tools(
                [sys.executable, "-c", ""],
                allow_env=["INVALID-NAME"],
            )
        with self.assertRaises(RuntimeProbeError):
            monitor_tools(
                [sys.executable, "-c", ""],
                allow_env=["PATH"],
                inherit_environment=True,
            )
        with self.assertRaises(RuntimeProbeError):
            monitor_tools([sys.executable, "-c", ""], cwd="missing-directory")

    def test_cli_reports_redacted_runtime_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target"
            target.mkdir()
            (target / "tool.json").write_text("{}", encoding="utf-8")
            script = self._server(root)
            command = [
                sys.executable,
                "-B",
                str(Path(__file__).resolve().parents[1] / "scanner.py"),
                str(target),
                "--format",
                "json",
                "--no-report",
                "--runtime-command",
                sys.executable,
                str(script),
            ]
            environment = dict(os.environ)
            environment["MCP_SCANNER_TEST_SECRET"] = "cli-secret-value"
            completed = subprocess.run(
                command,
                cwd=Path(__file__).resolve().parents[1],
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        policy = payload["runtime"]["policy"]
        self.assertEqual(policy["environment_mode"], "allowlist")
        self.assertEqual(policy["working_directory_mode"], "temporary")
        self.assertNotIn("cli-secret-value", completed.stdout)
        self.assertNotIn("MCP_SCANNER_TEST_SECRET", completed.stdout)


if __name__ == "__main__":
    unittest.main()

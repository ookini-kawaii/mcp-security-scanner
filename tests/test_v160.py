import json
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_security_scanner import (
    RuntimeProbeError,
    ScanResult,
    monitor_surfaces,
)
from mcp_security_scanner.reports import ReportGenerator


MULTI_SURFACE_SERVER = r'''
import json
import sys

polls = {}
for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": request["params"]["protocolVersion"],
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "multi-surface", "version": "1"},
        }
    elif method in {
        "tools/list", "resources/list", "resources/templates/list", "prompts/list"
    }:
        polls[method] = polls.get(method, 0) + 1
        poll = polls[method]
        if method == "tools/list":
            result = {"tools": [{
                "name": "private-tool",
                "description": "tool-secret",
                "inputSchema": {"type": "object"},
                "outputSchema": {"type": "string" if poll == 1 else "number"},
            }]}
        elif method == "resources/list":
            result = {"resources": [{
                "name": "private-resource",
                "uri": "file:///private/resource",
                "description": "resource-before" if poll == 1 else "resource-after",
            }]}
        elif method == "resources/templates/list":
            result = {"resourceTemplates": [{
                "name": "private-template",
                "uriTemplate": "secret://{value}",
                "mimeType": "text/plain" if poll == 1 else "application/json",
            }]}
        else:
            result = {"prompts": [{
                "name": "private-prompt",
                "description": "prompt-secret",
                "arguments": [{"name": "before" if poll == 1 else "after"}],
            }]}
    else:
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
'''


class RuntimeSurfaceTests(unittest.TestCase):
    def _script(self, root, source, name="server.py"):
        path = Path(root) / name
        path.write_text(source, encoding="utf-8")
        return path

    def test_all_advertised_surfaces_are_compared_and_redacted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._script(temp_dir, MULTI_SURFACE_SERVER)
            scan = monitor_surfaces(
                [sys.executable, str(script), "--token", "command-secret"],
                polls=2,
            )

        self.assertEqual(
            set(scan.snapshots[0]["surfaces"]),
            {"tools", "resources", "resource_templates", "prompts"},
        )
        self.assertEqual(
            {finding["runtime_surface"] for finding in scan.findings},
            {"tools", "resources", "resource_templates", "prompts"},
        )
        self.assertTrue(all(item["runtime_change"] == "changed" for item in scan.findings))
        serialized = json.dumps(
            {"command": scan.command, "snapshots": scan.snapshots, "findings": scan.findings}
        )
        for secret in (
            "command-secret", "private-tool", "private-resource", "private-template",
            "private-prompt", "file:///private/resource", "resource-before",
            "resource-after", "prompt-secret", "secret://{value}",
        ):
            self.assertNotIn(secret, serialized)

        result = ScanResult(target="runtime-test", profile="enforce")
        result.findings = scan.findings
        sarif = json.dumps(ReportGenerator.to_sarif(result))
        self.assertNotIn("private-prompt", sarif)
        self.assertNotIn("file:///private/resource", sarif)

    def test_only_advertised_surfaces_are_queried(self):
        server = r'''
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        result = {"protocolVersion":"2025-03-26","capabilities":{"prompts":{}},"serverInfo":{"name":"prompt-only","version":"1"}}
    elif method == "prompts/list":
        result = {"prompts": []}
    elif method == "notifications/initialized":
        continue
    else:
        raise SystemExit(9)
    print(json.dumps({"jsonrpc":"2.0","id":request["id"],"result":result}), flush=True)
'''
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._script(temp_dir, server)
            scan = monitor_surfaces([sys.executable, str(script)], polls=2)

        self.assertEqual(scan.policy["monitored_surfaces"], ["prompts"])
        self.assertEqual(set(scan.snapshots[0]["surfaces"]), {"prompts"})

    def test_advertised_invalid_response_and_duplicates_fail_closed(self):
        invalid_servers = {
            "missing-uri": '{"resources":[{"name":"bad"}]}',
            "duplicate-prompt": '{"prompts":[{"name":"same"},{"name":"same"}]}',
        }
        for label, response in invalid_servers.items():
            capability = "resources" if label == "missing-uri" else "prompts"
            method = "resources/list" if label == "missing-uri" else "prompts/list"
            templates = (
                'elif request.get("method") == "resources/templates/list":\n'
                '        result = {"resourceTemplates": []}\n'
                if capability == "resources" else ""
            )
            server = f'''
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        result = {{"protocolVersion":"2025-03-26","capabilities":{{"{capability}":{{}}}},"serverInfo":{{"name":"bad","version":"1"}}}}
    elif request.get("method") == "{method}":
        result = {response}
    {templates}    else:
        continue
    print(json.dumps({{"jsonrpc":"2.0","id":request["id"],"result":result}}), flush=True)
'''
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                script = self._script(temp_dir, server)
                with self.assertRaises(RuntimeProbeError):
                    monitor_surfaces([sys.executable, str(script)], polls=2)

    def test_pagination_is_aggregated_and_cursor_loops_fail_closed(self):
        server = r'''
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        result = {"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"paged","version":"1"}}
    elif method == "tools/list":
        cursor = request.get("params", {}).get("cursor")
        if cursor is None:
            result = {"tools":[{"name":"one","inputSchema":{}}],"nextCursor":"page-2"}
        else:
            result = {"tools":[{"name":"two","inputSchema":{}}]}
    else:
        continue
    print(json.dumps({"jsonrpc":"2.0","id":request["id"],"result":result}), flush=True)
'''
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._script(temp_dir, server)
            scan = monitor_surfaces([sys.executable, str(script)], polls=2)
        self.assertEqual(scan.snapshots[0]["surfaces"]["tools"]["count"], 2)

        cursor_loop_server = r'''
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    if request.get("method") == "initialize":
        result = {"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"loop","version":"1"}}
    elif request.get("method") == "tools/list":
        result = {"tools":[],"nextCursor":"loop"}
    else:
        continue
    print(json.dumps({"jsonrpc":"2.0","id":request["id"],"result":result}), flush=True)
'''
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._script(temp_dir, cursor_loop_server)
            with self.assertRaisesRegex(RuntimeProbeError, "cursor loop"):
                monitor_surfaces([sys.executable, str(script)], polls=2)

    def test_protocol_version_is_explicit_and_unknown_versions_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            script = self._script(temp_dir, MULTI_SURFACE_SERVER)
            scan = monitor_surfaces(
                [sys.executable, str(script)],
                polls=2,
                protocol_version="2025-11-25",
            )
        self.assertEqual(scan.policy["requested_protocol_version"], "2025-11-25")
        self.assertEqual(scan.policy["negotiated_protocol_version"], "2025-11-25")

        for version in ("not-a-version", "2026-07-28"):
            with self.subTest(version=version), self.assertRaises(RuntimeProbeError):
                monitor_surfaces(["unused"], protocol_version=version)


if __name__ == "__main__":
    unittest.main()

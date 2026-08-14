#!/usr/bin/env python3
"""Command-line entry point for MCP Security Scanner."""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from mcp_security_scanner import (
    IntegrityManifestError,
    MCPSecurityScanner,
    VERSION,
    build_manifest,
    compare_manifest,
    load_manifest,
    save_manifest,
    monitor_tools,
    RuntimeProbeError,
)
from mcp_security_scanner.correlation import correlate
from mcp_security_scanner.reports import ReportGenerator
from mcp_security_scanner.rules import RuleLoader, ScannerConfigurationError
from mcp_security_scanner.runtime import DEFAULT_MAX_MESSAGES, DEFAULT_MAX_OUTPUT_BYTES


EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
BASELINE_KEY_ENV = "MCP_SCANNER_BASELINE_KEY"


def _default_rules_dir():
    local_rules = Path("rules")
    if local_rules.is_dir():
        return local_rules
    source_rules = Path(__file__).resolve().parent / "rules"
    if source_rules.is_dir():
        return source_rules
    installed_rules = Path(sys.prefix) / "share" / "mcp-security-scanner" / "rules"
    return installed_rules


def _inside_target(path: Path, target: Path):
    if not target.is_dir():
        return None
    try:
        return path.resolve().relative_to(target.resolve()).as_posix()
    except ValueError:
        return None


def _save_report(result, target, output_format):
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)
    safe_name = re.sub(r"[^\w]", "_", str(target))
    extension = "sarif" if output_format == "sarif" else "json"
    output_file = output_dir / (
        f"report_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{extension}"
    )
    payload = (
        ReportGenerator.to_sarif(result)
        if output_format == "sarif"
        else ReportGenerator.to_json(result)
    )
    output_file.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[i] 报告已保存: {output_file}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="MCP 工具供应链安全扫描器"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("target", help="目标文件或目录路径")
    parser.add_argument("-r", "--rules", help="ATR 规则目录 (默认: 自动查找内置规则)")
    parser.add_argument(
        "--profile", choices=("hunt", "enforce"), default="hunt",
        help="hunt 保留全部线索，enforce 仅保留高置信结果",
    )
    parser.add_argument("--include-tests", action="store_true", help="包含测试目录和测试文件")
    parser.add_argument(
        "--fail-on", choices=("low", "medium", "high", "critical", "none"),
        default="low", help="达到指定严重级别时返回退出码 1",
    )
    parser.add_argument(
        "--format", choices=("terminal", "json", "sarif"), default="terminal",
        help="标准输出格式",
    )
    baseline_group = parser.add_mutually_exclusive_group()
    baseline_group.add_argument("--baseline", metavar="PATH", help="使用 SHA-256 基线检测文件变化")
    baseline_group.add_argument("--write-baseline", metavar="PATH", help="写出当前目标的 SHA-256 基线")
    parser.add_argument(
        "--integrity-exclude", action="append", default=[], metavar="PATTERN",
        help="基线排除模式，可重复指定",
    )
    parser.add_argument("--no-gitignore", action="store_true", help="基线不读取目标根目录 .gitignore")
    parser.add_argument(
        "--require-signed-baseline", action="store_true",
        help=f"要求 HMAC 签名；密钥从 {BASELINE_KEY_ENV} 读取",
    )
    parser.add_argument("--no-report", action="store_true", help="不保存报告")
    parser.add_argument("--brief", action="store_true", help="精简终端输出")
    parser.add_argument(
        "--runtime-command", nargs="+", metavar="COMMAND",
        help="启动 MCP stdio Server 并监控 tools/list 变化",
    )
    parser.add_argument("--runtime-polls", type=int, default=2, help="tools/list 轮询次数 (默认: 2)")
    parser.add_argument("--runtime-timeout", type=float, default=5.0, help="单次 MCP 请求超时秒数")
    parser.add_argument("--runtime-interval", type=float, default=0.0, help="轮询间隔秒数")
    parser.add_argument(
        "--runtime-cwd", metavar="PATH",
        help="MCP Server 工作目录；默认使用一次性临时目录",
    )
    parser.add_argument(
        "--runtime-allow-env", action="append", default=[], metavar="NAME",
        help="在默认最小环境之外传递指定环境变量，可重复指定",
    )
    parser.add_argument(
        "--runtime-inherit-env", action="store_true",
        help="兼容模式：向 MCP Server 传递当前进程全部环境变量",
    )
    parser.add_argument(
        "--runtime-max-output", type=int, default=DEFAULT_MAX_OUTPUT_BYTES,
        metavar="BYTES", help=f"stdout/stderr 总字节上限 (默认: {DEFAULT_MAX_OUTPUT_BYTES})",
    )
    parser.add_argument(
        "--runtime-max-messages", type=int, default=DEFAULT_MAX_MESSAGES,
        metavar="COUNT", help=f"JSON-RPC 消息数上限 (默认: {DEFAULT_MAX_MESSAGES})",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    target = Path(args.target)
    if not target.exists():
        print(f"[!] 目标不存在: {target}", file=sys.stderr)
        return EXIT_ERROR

    try:
        scanner = MCPSecurityScanner(
            args.rules or _default_rules_dir(),
            profile=args.profile,
            include_tests=args.include_tests,
        )
        result = scanner.scan_path(target)
        signing_key = os.environ.get(BASELINE_KEY_ENV)

        if args.runtime_command:
            runtime_scan = monitor_tools(
                args.runtime_command,
                polls=args.runtime_polls,
                timeout=args.runtime_timeout,
                interval=args.runtime_interval,
                cwd=args.runtime_cwd,
                allow_env=args.runtime_allow_env,
                inherit_environment=args.runtime_inherit_env,
                max_output_bytes=args.runtime_max_output,
                max_messages=args.runtime_max_messages,
            )
            result.runtime = {
                "command": runtime_scan.command,
                "polls": runtime_scan.polls,
                "snapshots": runtime_scan.snapshots,
                "policy": runtime_scan.policy,
            }
            result.findings.extend(runtime_scan.findings)
            result.incidents = correlate(result.findings)

        if args.baseline:
            baseline = load_manifest(
                args.baseline,
                signing_key=signing_key,
                require_signature=args.require_signed_baseline,
            )
            result.findings.extend(compare_manifest(target, baseline))
            result.incidents = correlate(result.findings)

        if args.write_baseline:
            if args.require_signed_baseline and not signing_key:
                raise IntegrityManifestError(
                    f"要求签名基线，但环境变量 {BASELINE_KEY_ENV} 未设置"
                )
            excludes = list(args.integrity_exclude)
            internal_baseline = _inside_target(Path(args.write_baseline), target)
            if internal_baseline and internal_baseline not in excludes:
                excludes.append(internal_baseline)
            manifest = build_manifest(
                target,
                excludes=excludes,
                use_gitignore=not args.no_gitignore,
            )
            save_manifest(manifest, args.write_baseline, signing_key=signing_key)
            print(f"[i] 完整性基线已保存: {args.write_baseline}")

        if args.format == "terminal":
            ReportGenerator.print_terminal(result, brief=args.brief)
        elif args.format == "json":
            print(json.dumps(ReportGenerator.to_json(result), ensure_ascii=False, indent=2))
        else:
            print(json.dumps(ReportGenerator.to_sarif(result), ensure_ascii=False, indent=2))

        if not args.no_report:
            _save_report(result, target, args.format)

        return (
            EXIT_FINDINGS
            if result.reaches_threshold(args.fail_on.upper())
            else EXIT_CLEAN
        )
    except (
        ScannerConfigurationError,
        IntegrityManifestError,
        RuntimeProbeError,
        OSError,
        UnicodeError,
    ) as exc:
        print(f"[!] 扫描失败: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["MCPSecurityScanner", "RuleLoader", "ReportGenerator", "main"]

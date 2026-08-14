"""Terminal, JSON and SARIF report serialization."""

from datetime import datetime, timezone
from pathlib import Path

from . import VERSION


class ReportGenerator:
    @staticmethod
    def print_terminal(result, brief=False):
        print("\n" + "=" * 72)
        print(f"扫描目标: {result.target}")
        print("=" * 72)
        if not result.findings:
            print("[OK] 未检测到达到当前 profile 的风险")
        elif brief:
            print(f"[!] 检测到 {len(result.findings)} 条告警，聚合为 {len(result.incidents)} 个事件")
            print(f"  {'规则 ID':<27}{'级别':<11}{'置信度':<9}目标")
            print("  " + "-" * 68)
            for finding in result.findings:
                target = Path(finding["target"]).name or finding["target"]
                print(
                    f"  {finding['rule_id']:<27}{finding['severity']:<11}"
                    f"{finding['confidence']:<9}{target}"
                )
        else:
            print(f"[!] 检测到 {len(result.findings)} 条告警，聚合为 {len(result.incidents)} 个事件\n")
            for index, finding in enumerate(result.findings, 1):
                print(f"  --- 告警 #{index} ---")
                print(f"  规则:     {finding['rule_id']} / {finding['rule_name']}")
                print(f"  风险:     {finding['severity']} (confidence={finding['confidence']})")
                print(f"  类别:     {finding['category']}")
                print(f"  目标:     {finding['target']}")
                print(f"  位置:     {finding['position']} / {finding['field_path']}")
                print(f"  证据:     {finding['matched_text'][:160]}")
                if finding.get("decoded_from"):
                    print(f"  解码来源: {finding['decoded_from'][:80]}")
                print()
        if result.skipped_files:
            print(f"[i] 已跳过 {len(result.skipped_files)} 个文件")
        if result.runtime:
            policy = result.runtime.get("policy", {})
            print(
                f"[i] 运行时监控: {result.runtime['polls']} 次 tools/list，"
                f"{len(result.runtime['snapshots'])} 个快照"
            )
            if policy:
                print(
                    "[i] 运行时策略: "
                    f"环境={policy.get('environment_mode', 'unknown')}，"
                    f"工作目录={policy.get('working_directory_mode', 'unknown')}，"
                    f"输出上限={policy.get('max_output_bytes', 0)} 字节，"
                    f"消息上限={policy.get('max_messages', 0)}"
                )

    @staticmethod
    def to_json(result):
        return result.to_dict(VERSION)

    @staticmethod
    def to_sarif(result):
        rules = {}
        sarif_results = []
        for finding in result.findings:
            rules.setdefault(finding["rule_id"], {
                "id": finding["rule_id"],
                "name": finding["rule_name"],
                "shortDescription": {"text": finding["rule_name"]},
            })
            line, column = _parse_position(finding.get("position", ""))
            sarif_results.append({
                "ruleId": finding["rule_id"],
                "level": _sarif_level(finding["severity"]),
                "message": {"text": finding["matched_text"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding["target"]},
                        "region": {"startLine": line, "startColumn": column},
                    }
                }],
            })
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "mcp-security-scanner", "version": VERSION, "rules": list(rules.values())}},
                "results": sarif_results,
                "invocations": [{"executionSuccessful": True, "endTimeUtc": datetime.now(timezone.utc).isoformat()}],
            }],
        }


def _sarif_level(severity):
    return "error" if severity in {"CRITICAL", "HIGH"} else "warning"


def _parse_position(position):
    try:
        line_part, column_part = position.split(",", 1)
        return int(line_part.split(":", 1)[1]), int(column_part.split(":", 1)[1])
    except (AttributeError, IndexError, ValueError):
        return 1, 1

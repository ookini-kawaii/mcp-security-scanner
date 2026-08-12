"""Terminal, JSON and SARIF report serialization."""

from datetime import datetime, timezone

from . import VERSION


class ReportGenerator:
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
            sarif_results.append({
                "ruleId": finding["rule_id"],
                "level": _sarif_level(finding["severity"]),
                "message": {"text": finding["matched_text"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding["target"]},
                        "region": {"startLine": int(finding["position"].split(":")[1].split(",")[0])},
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

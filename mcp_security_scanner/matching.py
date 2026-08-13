"""Context-aware rule matching and confidence calibration."""

import re

from .models import SEVERITY_RANK, ScanUnit


ACTION_PATTERN = re.compile(
    r"\b(?:read|open|load|access|send|post|upload|exfil|extract|pass\s+|execute|decode)\w*\b",
    re.IGNORECASE,
)
HIDDEN_DIRECTIVE_PATTERN = re.compile(
    r"\b(?:do not tell|don't tell|keep secret|hidden|before calling|ignore previous)\b",
    re.IGNORECASE,
)
OUTBOUND_PATTERN = re.compile(
    r"\b(?:webhook|callback|send_to_server|external_log|phone_home|exfil)\b",
    re.IGNORECASE,
)
SENSITIVE_PATTERN = re.compile(
    r"(?:~/.ssh|~/.aws|~/.config/gcloud|~/.kube|/etc/(?:shadow|passwd)|\.env|secret|credential|private[_ -]?key|api[_ -]?key)",
    re.IGNORECASE,
)
SAFE_VALIDATION_PATTERN = re.compile(
    r"\b(?:blocked|block|deny|denied|reject|rejected|forbidden|not allowed|disallow|safe list|allowlist|blacklist|blocked_paths|is_blocked)\b|\bpath\s+in\s+[A-Z_]+",
    re.IGNORECASE,
)


def line_column(content: str, offset: int):
    line = content.count("\n", 0, offset) + 1
    newline = content.rfind("\n", 0, offset)
    return line, offset - newline


def match_unit(unit: ScanUnit, rule: dict):
    patterns = rule["patterns"]
    findings = []
    for pattern in patterns["match"]:
        if patterns["type"] == "regex":
            matches = re.finditer(pattern, unit.content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                findings.append(_finding(unit, rule, pattern, match.group(), match.start()))
        else:
            lower_content = unit.content.lower()
            offset = lower_content.find(pattern.lower())
            if offset >= 0:
                findings.append(_finding(unit, rule, pattern, unit.content[:200], offset))
    return findings


def _finding(unit, rule, pattern, matched_text, offset):
    source_offset = (
        unit.source_offsets[offset]
        if unit.source_offsets and offset < len(unit.source_offsets)
        else unit.base_offset + offset
    )
    line, column = line_column(unit.source_content, source_offset)
    confidence, severity = calibrate(unit, rule, matched_text, offset)
    return {
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": severity,
        "severity_rank": SEVERITY_RANK[severity],
        "category": rule["category"],
        "confidence": confidence,
        "matched_pattern": pattern,
        "matched_text": matched_text[:200],
        "target": str(unit.file_path),
        "field_path": unit.field_path,
        "scope": unit.scope,
        "position": f"line:{line},column:{column}",
        "offset": source_offset,
        "source_file": rule.get("_source_file", ""),
        "decoded_from": unit.decoded_from,
        "decoded_depth": unit.decoded_depth,
    }


def calibrate(unit, rule, matched_text, match_offset):
    severity = rule["severity"]
    source_offset = unit.base_offset + match_offset
    context = unit.source_content[
        max(0, source_offset - 240):source_offset + 320
    ]
    has_action = bool(ACTION_PATTERN.search(context))
    has_hidden = bool(HIDDEN_DIRECTIVE_PATTERN.search(context))
    has_outbound = bool(OUTBOUND_PATTERN.search(context))
    has_sensitive = bool(SENSITIVE_PATTERN.search(context))
    has_safe_validation = bool(SAFE_VALIDATION_PATTERN.search(context))

    if rule["category"] == "credential_access" and has_safe_validation and not has_action:
        return 15, "LOW"

    if unit.scope == "source_string" and rule["category"] in {
        "credential_access", "data_exfiltration"
    } and not (has_action or has_hidden):
        return 20, "LOW"
    if rule["category"] == "obfuscation":
        return (90, severity) if has_action or has_hidden or has_outbound else (15, "LOW")
    if rule["category"] == "data_exfiltration":
        if not has_action or not (has_hidden or has_sensitive):
            return 25, "LOW"
        return 95, "CRITICAL"
    if rule["category"] == "credential_access" and not (has_action or has_hidden):
        return 30, "LOW"
    if severity == "CRITICAL" and has_action and (has_hidden or has_outbound):
        return 95, "CRITICAL"
    if severity == "HIGH" and (has_action or has_hidden):
        return 90, "HIGH"
    return 75, severity

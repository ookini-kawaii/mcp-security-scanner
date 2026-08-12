"""Group related rule hits into attack-chain incidents."""

from collections import defaultdict

from .models import SEVERITY_RANK


def correlate(findings):
    groups = defaultdict(list)
    for finding in findings:
        groups[finding["target"]].append(finding)

    incidents = []
    for target, items in groups.items():
        categories = sorted({item["category"] for item in items})
        confidence = max(item["confidence"] for item in items)
        actionable_items = [item for item in items if item["confidence"] >= 70]
        severity_rank = max(
            (item["severity_rank"] for item in actionable_items),
            default=SEVERITY_RANK["LOW"],
        )
        severity = max(
            (item["severity"] for item in actionable_items),
            key=lambda value: SEVERITY_RANK[value],
            default="LOW",
        )
        if confidence < 70:
            severity = "LOW"
            severity_rank = SEVERITY_RANK["LOW"]
        incidents.append({
            "incident_id": f"INC-{len(incidents) + 1:04d}",
            "target": target,
            "severity": severity,
            "severity_rank": severity_rank,
            "confidence": confidence,
            "categories": categories,
            "rule_ids": sorted({item["rule_id"] for item in items}),
            "finding_count": len(items),
            "attack_chain": _attack_chain(categories),
            "findings": items,
        })
    return sorted(incidents, key=lambda item: (-item["severity_rank"], item["target"]))


def _attack_chain(categories):
    chain = []
    if "prompt_injection" in categories:
        chain.append("hidden directive")
    if "credential_access" in categories:
        chain.append("sensitive resource access")
    if "data_exfiltration" in categories:
        chain.append("outbound data channel")
    if "obfuscation" in categories:
        chain.insert(0, "encoded payload")
    return " -> ".join(chain) or "rule match"

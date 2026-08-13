"""Context-aware scanner engine."""

import json
from pathlib import Path

from .correlation import correlate
from .decoders import extract_base64
from .extractors import discover_targets, extract_units, is_test_path
from .matching import line_column, match_unit
from .models import ScanResult, SEVERITY_RANK, ScanUnit
from .rules import RuleLoader


PROFILES = {"hunt", "enforce"}


class MCPSecurityScanner:
    def __init__(self, rules_dir, profile="hunt", include_tests=False):
        if profile not in PROFILES:
            raise ValueError(f"unknown profile: {profile}")
        self.rules = RuleLoader(rules_dir).load()
        self.profile = profile
        self.include_tests = include_tests

    def scan_path(self, target):
        target = Path(target)
        paths, skipped = discover_targets(target, self.include_tests)
        result = ScanResult(str(target), self.profile, skipped_files=skipped)
        for path in paths:
            content = path.read_text(encoding="utf-8")
            result.total_files += 1
            file_findings = self._scan_file(path, content)
            if is_test_path(path):
                for finding in file_findings:
                    finding["severity"] = "LOW"
                    finding["severity_rank"] = SEVERITY_RANK["LOW"]
                    finding["confidence"] = min(finding["confidence"], 45)
                    finding["test_context"] = True
            result.findings.extend(file_findings)
        result.findings = self._deduplicate(result.findings)
        result.incidents = correlate(result.findings)
        if self.profile == "enforce":
            result.findings = [item for item in result.findings if item["confidence"] >= 70]
            result.incidents = [incident for incident in result.incidents if incident["confidence"] >= 70]
        return result

    def _scan_content(self, content, target_name="<memory>"):
        """Compatibility helper for callers of the v1.1 engine API."""
        path = Path(target_name)
        return self._scan_file(path, content)

    def scan_file(self, file_path, save_report=True, brief=False):
        """Compatibility API returning the finding list for one file."""
        result = self.scan_path(file_path)
        return result.findings

    def scan_directory(self, dir_path, save_report=True, brief=False):
        """Compatibility API returning the total finding count."""
        result = self.scan_path(dir_path)
        return len(result.findings)

    def _scan_file(self, path, content):
        findings = []
        units = extract_units(path, content)
        for unit in units:
            for rule in self.rules:
                findings.extend(match_unit(unit, rule))
            findings.extend(self._scan_decoded(unit, content))
        return findings

    def _scan_decoded(self, unit, source_content):
        findings = []
        for decoded in extract_base64(unit.content, unit.decoded_depth):
            source_offset = (
                unit.source_offsets[decoded["position"]]
                if unit.source_offsets
                and decoded["position"] < len(unit.source_offsets)
                else unit.base_offset + decoded["position"]
            )
            decoded_unit = ScanUnit(
                unit.file_path,
                decoded["decoded"],
                unit.field_path,
                unit.scope,
                source_content,
                source_offset,
                decoded["encoded"],
                decoded["depth"],
                [source_offset] * len(decoded["decoded"]),
            )
            decoded_findings = []
            for rule in self.rules:
                if rule["category"] == "obfuscation":
                    continue
                decoded_findings.extend(match_unit(decoded_unit, rule))
            decoded_findings.extend(self._scan_decoded(decoded_unit, source_content))
            findings.extend(decoded_findings)
            if decoded_findings:
                line, column = line_column(source_content, source_offset)
                findings.append({
                    "rule_id": "ATR-ENCODE-OBFUS-001",
                    "rule_name": "Confirmed Encoded Payload",
                    "severity": "MEDIUM",
                    "severity_rank": SEVERITY_RANK["MEDIUM"],
                    "category": "obfuscation",
                    "confidence": 90,
                    "matched_pattern": "base64 payload with malicious decoded content",
                    "matched_text": decoded["encoded"],
                    "target": str(unit.file_path),
                    "field_path": unit.field_path,
                    "scope": unit.scope,
                    "position": f"line:{line},column:{column}",
                    "offset": source_offset,
                    "source_file": "encoding_obfuscation.yaml",
                    "decoded_from": decoded["encoded"],
                    "decoded_depth": decoded["depth"],
                })
        return findings

    @staticmethod
    def _deduplicate(findings):
        unique = []
        seen = set()
        for finding in findings:
            key = (finding["rule_id"], finding["target"], finding["offset"], finding.get("decoded_from"))
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique

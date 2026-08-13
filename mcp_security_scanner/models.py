"""Shared scanner data models."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SEVERITY_RANK = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass
class ScanUnit:
    file_path: Path
    content: str
    field_path: str
    scope: str
    source_content: str
    base_offset: int = 0
    decoded_from: str | None = None
    decoded_depth: int = 0


@dataclass
class ScanResult:
    target: str
    profile: str
    total_files: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    incidents: list[dict[str, Any]] = field(default_factory=list)
    skipped_files: list[dict[str, str]] = field(default_factory=list)
    runtime: dict[str, Any] | None = None

    def to_dict(self, version: str) -> dict[str, Any]:
        return {
            "scanner_version": version,
            "target": self.target,
            "profile": self.profile,
            "total_files": self.total_files,
            "total_findings": len(self.findings),
            "total_incidents": len(self.incidents),
            "findings": self.findings,
            "incidents": self.incidents,
            "skipped_files": self.skipped_files,
            "runtime": self.runtime,
        }

    def reaches_threshold(self, threshold: str) -> bool:
        if threshold == "NONE":
            return False
        minimum = SEVERITY_RANK[threshold]
        return any(
            incident["severity_rank"] >= minimum
            for incident in self.incidents
        )

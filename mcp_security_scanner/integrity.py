"""Hash-pinning manifests for detecting post-install file changes."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .extractors import discover_targets


MANIFEST_VERSION = "1"
INTEGRITY_RULE_ID = "MCP-INTEGRITY-001"


class IntegrityManifestError(ValueError):
    """A baseline manifest is missing, malformed, or unreadable."""


def _relative_path(path: Path, root: Path) -> str:
    if root.is_file():
        return path.name
    return path.relative_to(root).as_posix()


def build_manifest(target, include_tests=False):
    root = Path(target)
    if not root.exists() or not (root.is_file() or root.is_dir()):
        raise IntegrityManifestError(f"基线目标不存在或不是普通文件/目录: {root}")
    paths, skipped = discover_targets(root, include_tests)
    files = {}
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files[_relative_path(path, root)] = digest
    return {
        "manifest_version": MANIFEST_VERSION,
        "algorithm": "sha256",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "include_tests": bool(include_tests),
        "files": dict(sorted(files.items())),
        "skipped_files": skipped,
    }


def save_manifest(manifest, destination):
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_manifest(source):
    path = Path(source)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityManifestError(f"基线清单加载失败 {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise IntegrityManifestError(f"基线清单必须是 JSON 对象: {path}")
    if data.get("manifest_version") != MANIFEST_VERSION:
        raise IntegrityManifestError(f"不支持的基线版本: {path}")
    if data.get("algorithm") != "sha256":
        raise IntegrityManifestError(f"不支持的基线哈希算法: {path}")
    files = data.get("files")
    if not isinstance(files, dict) or any(
        not isinstance(name, str) or not isinstance(value, str)
        or len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower())
        for name, value in files.items()
    ):
        raise IntegrityManifestError(f"基线 files 字段无效: {path}")
    return data


def compare_manifest(target, baseline, include_tests=False):
    current = build_manifest(target, include_tests)
    expected = baseline["files"]
    actual = current["files"]
    findings = []
    for name in sorted(set(expected) | set(actual)):
        if name not in expected:
            kind = "added"
            text = f"新增文件: {name}"
        elif name not in actual:
            kind = "removed"
            text = f"文件已删除: {name}"
        elif expected[name] != actual[name]:
            kind = "changed"
            text = f"文件内容已变化: {name}"
        else:
            continue
        findings.append({
            "rule_id": INTEGRITY_RULE_ID,
            "rule_name": "Pinned File Hash Changed",
            "severity": "HIGH",
            "severity_rank": 3,
            "category": "supply_chain_poisoning",
            "confidence": 95,
            "matched_pattern": kind,
            "matched_text": text,
            "target": str(Path(target)),
            "field_path": f"files.{name}",
            "scope": "integrity_manifest",
            "position": "line:1,column:1",
            "offset": 0,
            "source_file": "integrity_manifest",
            "decoded_from": None,
            "decoded_depth": 0,
            "integrity_change": kind,
            "baseline_sha256": expected.get(name),
            "current_sha256": actual.get(name),
        })
    return findings

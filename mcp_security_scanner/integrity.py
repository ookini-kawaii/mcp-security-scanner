"""Hash-pinning manifests for detecting post-install file changes."""

import fnmatch
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .extractors import discover_targets


MANIFEST_VERSION = "2"
LEGACY_MANIFEST_VERSION = "1"
INTEGRITY_RULE_ID = "MCP-INTEGRITY-001"
DEFAULT_EXCLUDES = (".git/",)


class IntegrityManifestError(ValueError):
    """A baseline manifest is missing, malformed, or unverifiable."""


def _relative_path(path: Path, root: Path) -> str:
    if root.is_file():
        return path.name
    return path.relative_to(root).as_posix()


def _read_ignore_patterns(root: Path) -> list[str]:
    if not root.is_dir():
        return []
    ignore_file = root / ".gitignore"
    if not ignore_file.is_file():
        return []
    try:
        lines = ignore_file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise IntegrityManifestError(f"无法读取忽略规则 {ignore_file}: {exc}") from exc
    patterns = []
    for line in lines:
        pattern = line.strip()
        if not pattern or pattern.startswith("#"):
            continue
        patterns.append(pattern.replace("\\", "/"))
    return patterns


def _pattern_matches(relative_path: str, pattern: str) -> bool:
    negated = pattern.startswith("!")
    if negated:
        pattern = pattern[1:]
    pattern = pattern.lstrip("/")
    directory_pattern = pattern.endswith("/")
    pattern = pattern.rstrip("/")
    if not pattern:
        return False

    path = relative_path.rstrip("/")
    if directory_pattern:
        matched = path == pattern or path.startswith(pattern + "/")
    elif "/" in pattern:
        matched = fnmatch.fnmatchcase(path, pattern)
    else:
        matched = any(fnmatch.fnmatchcase(part, pattern) for part in path.split("/"))
    return matched


def _is_ignored(relative_path: str, patterns: list[str]) -> bool:
    ignored = False
    for pattern in patterns:
        if _pattern_matches(relative_path, pattern):
            ignored = not pattern.startswith("!")
    return ignored


def _integrity_paths(root: Path, patterns: list[str]) -> list[Path]:
    if root.is_file() or root.is_symlink():
        return [] if _is_ignored(root.name, patterns) else [root]
    paths = []
    has_negated_pattern = any(pattern.startswith("!") for pattern in patterns)
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(directory)
        kept_directories = []
        for name in sorted(directory_names):
            path = current / name
            relative = _relative_path(path, root)
            if path.is_symlink():
                if not _is_ignored(relative, patterns):
                    paths.append(path)
            elif not _is_ignored(relative + "/", patterns) or has_negated_pattern:
                kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in sorted(file_names):
            path = current / name
            relative = _relative_path(path, root)
            if not _is_ignored(relative, patterns):
                paths.append(path)
    return sorted(paths, key=lambda path: _relative_path(path, root))


def _file_record(path: Path) -> dict:
    if path.is_symlink():
        target = os.readlink(path)
        payload = target.encode("utf-8", errors="surrogatepass")
        return {
            "type": "symlink",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "link_target": target,
        }
    payload = path.read_bytes()
    return {
        "type": "file",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def _canonical_payload(manifest: dict) -> bytes:
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    return json.dumps(
        unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_manifest(manifest: dict, signing_key) -> dict:
    if not signing_key:
        raise IntegrityManifestError("基线签名密钥不能为空")
    key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
    signed = {key_name: value for key_name, value in manifest.items() if key_name != "signature"}
    signed["signature"] = {
        "algorithm": "hmac-sha256",
        "value": hmac.new(key, _canonical_payload(signed), hashlib.sha256).hexdigest(),
    }
    return signed


def verify_manifest_signature(manifest: dict, signing_key=None, require_signature=False):
    signature = manifest.get("signature")
    if not signature:
        if require_signature or signing_key:
            raise IntegrityManifestError("基线清单缺少签名")
        return
    if not signing_key:
        raise IntegrityManifestError("基线清单已签名，但未提供签名密钥")
    if not isinstance(signature, dict) or signature.get("algorithm") != "hmac-sha256":
        raise IntegrityManifestError("基线签名格式或算法无效")
    value = signature.get("value")
    if not isinstance(value, str) or len(value) != 64:
        raise IntegrityManifestError("基线签名值无效")
    key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
    expected = hmac.new(key, _canonical_payload(manifest), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(value.lower(), expected):
        raise IntegrityManifestError("基线签名校验失败，清单可能已被篡改")


def build_manifest(target, include_tests=False, excludes=None, use_gitignore=True):
    root = Path(target)
    if (
        (not root.exists() and not root.is_symlink())
        or not (root.is_file() or root.is_dir() or root.is_symlink())
    ):
        raise IntegrityManifestError(f"基线目标不存在或不是普通文件/目录: {root}")
    patterns = list(DEFAULT_EXCLUDES)
    if use_gitignore:
        patterns.extend(_read_ignore_patterns(root))
    patterns.extend(str(item).replace("\\", "/") for item in (excludes or []))
    files = {
        _relative_path(path, root): _file_record(path)
        for path in _integrity_paths(root, patterns)
    }
    target_kind = "symlink" if root.is_symlink() else "file" if root.is_file() else "directory"
    return {
        "manifest_version": MANIFEST_VERSION,
        "algorithm": "sha256",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": {"kind": target_kind, "name": root.name},
        "options": {
            "use_gitignore": bool(use_gitignore),
            "exclude": list(excludes or []),
        },
        "file_count": len(files),
        "files": dict(sorted(files.items())),
    }


def save_manifest(manifest, destination, signing_key=None):
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    output = sign_manifest(manifest, signing_key) if signing_key else manifest
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _valid_digest(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdef" for char in value.lower()
    )


def _valid_relative_name(name) -> bool:
    if not isinstance(name, str) or not name or "\\" in name:
        return False
    path = Path(name)
    return not path.is_absolute() and ".." not in path.parts


def _validate_v2(data: dict, path: Path):
    target = data.get("target")
    options = data.get("options")
    files = data.get("files")
    if (
        data.get("algorithm") != "sha256"
        or not isinstance(target, dict)
        or target.get("kind") not in {"file", "directory", "symlink"}
        or not isinstance(target.get("name"), str)
        or not isinstance(options, dict)
        or not isinstance(options.get("use_gitignore"), bool)
        or not isinstance(options.get("exclude"), list)
        or not all(isinstance(item, str) for item in options["exclude"])
        or not isinstance(files, dict)
    ):
        raise IntegrityManifestError(f"基线清单结构无效: {path}")
    for name, record in files.items():
        if (
            not _valid_relative_name(name)
            or not isinstance(record, dict)
            or record.get("type") not in {"file", "symlink"}
            or not _valid_digest(record.get("sha256"))
            or not isinstance(record.get("size"), int)
            or record["size"] < 0
            or (record["type"] == "symlink" and not isinstance(record.get("link_target"), str))
        ):
            raise IntegrityManifestError(f"基线 files 字段无效: {path}")
    if data.get("file_count") != len(files):
        raise IntegrityManifestError(f"基线文件计数不一致: {path}")


def _validate_v1(data: dict, path: Path):
    files = data.get("files")
    if data.get("algorithm") != "sha256" or not isinstance(files, dict) or any(
        not _valid_relative_name(name) or not _valid_digest(value)
        for name, value in files.items()
    ):
        raise IntegrityManifestError(f"旧版基线 files 字段无效: {path}")


def load_manifest(source, signing_key=None, require_signature=False):
    path = Path(source)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityManifestError(f"基线清单加载失败 {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise IntegrityManifestError(f"基线清单必须是 JSON 对象: {path}")
    version = data.get("manifest_version")
    if version == MANIFEST_VERSION:
        _validate_v2(data, path)
        verify_manifest_signature(data, signing_key, require_signature)
    elif version == LEGACY_MANIFEST_VERSION:
        if signing_key or require_signature:
            raise IntegrityManifestError("旧版基线不支持签名，请重新生成 v2 基线")
        _validate_v1(data, path)
    else:
        raise IntegrityManifestError(f"不支持的基线版本: {path}")
    return data


def _change_finding(target, name, kind, expected, actual):
    labels = {"added": "新增文件", "removed": "文件已删除", "changed": "文件内容已变化"}
    return {
        "rule_id": INTEGRITY_RULE_ID,
        "rule_name": "Pinned File Hash Changed",
        "severity": "HIGH",
        "severity_rank": 3,
        "category": "supply_chain_poisoning",
        "confidence": 95,
        "matched_pattern": kind,
        "matched_text": f"{labels[kind]}: {name}",
        "target": str(Path(target) / name) if Path(target).is_dir() else str(Path(target)),
        "field_path": f"files.{name}",
        "scope": "integrity_manifest",
        "position": "line:1,column:1",
        "offset": 0,
        "source_file": "integrity_manifest",
        "decoded_from": None,
        "decoded_depth": 0,
        "integrity_change": kind,
        "baseline_sha256": expected.get("sha256") if isinstance(expected, dict) else expected,
        "current_sha256": actual.get("sha256") if isinstance(actual, dict) else actual,
    }


def compare_manifest(target, baseline, include_tests=False):
    root = Path(target)
    if baseline["manifest_version"] == LEGACY_MANIFEST_VERSION:
        paths, _ = discover_targets(root, bool(baseline.get("include_tests", include_tests)))
        actual = {
            _relative_path(path, root): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths
        }
    else:
        kind = "symlink" if root.is_symlink() else "file" if root.is_file() else "directory"
        if baseline["target"] != {"kind": kind, "name": root.name}:
            raise IntegrityManifestError("基线目标类型或名称与当前目标不匹配")
        options = baseline["options"]
        current = build_manifest(
            root,
            excludes=options["exclude"],
            use_gitignore=options["use_gitignore"],
        )
        actual = current["files"]

    expected = baseline["files"]
    findings = []
    for name in sorted(set(expected) | set(actual)):
        if name not in expected:
            kind = "added"
        elif name not in actual:
            kind = "removed"
        elif expected[name] != actual[name]:
            kind = "changed"
        else:
            continue
        findings.append(_change_finding(root, name, kind, expected.get(name), actual.get(name)))
    return findings

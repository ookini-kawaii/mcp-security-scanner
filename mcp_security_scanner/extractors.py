"""Field-aware metadata and source-string extraction."""

import ast
import json
import re
from pathlib import Path

import yaml

from .models import ScanUnit


SUPPORTED_EXTENSIONS = {
    ".json", ".py", ".yaml", ".yml", ".ts", ".js", ".tsx", ".jsx"
}
TEST_DIRECTORIES = {"test", "tests", "__tests__"}
TEST_FILE_PATTERN = re.compile(r"(?:^|\.)(?:test|spec)\.[^.]+$", re.IGNORECASE)
JS_STRING_PATTERN = re.compile(
    r"(?P<quote>['\"`])(?P<value>(?:\\.|(?!\1).)*)(?P=quote)",
    re.DOTALL,
)


def is_test_path(path: Path) -> bool:
    lowered_parts = {part.lower() for part in path.parts}
    return bool(lowered_parts & TEST_DIRECTORIES) or bool(
        TEST_FILE_PATTERN.search(path.name)
    )


def discover_targets(target: Path, include_tests: bool):
    if target.is_file():
        candidates = [target]
    else:
        candidates = sorted(
            path for path in target.rglob("*")
            if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS
        )

    included = []
    skipped = []
    for path in candidates:
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            skipped.append({"path": str(path), "reason": "unsupported extension"})
        elif not include_tests and is_test_path(path):
            skipped.append({"path": str(path), "reason": "test file excluded"})
        else:
            included.append(path)
    return included, skipped


def extract_units(path: Path, content: str) -> list[ScanUnit]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            return _structured_units(path, content, json.loads(content))
        except json.JSONDecodeError:
            return [_raw_unit(path, content)]
    if suffix in {".yaml", ".yml"}:
        try:
            return _structured_units(path, content, yaml.safe_load(content))
        except yaml.YAMLError:
            return [_raw_unit(path, content)]
    if suffix == ".py":
        return _python_string_units(path, content)
    if suffix in {".ts", ".js", ".tsx", ".jsx"}:
        return _javascript_string_units(path, content)
    return [_raw_unit(path, content)]


def _raw_unit(path: Path, content: str) -> ScanUnit:
    return ScanUnit(path, content, "$raw", "raw", content)


def _structured_units(path: Path, content: str, data) -> list[ScanUnit]:
    units = []
    search_cursor = 0

    def add(value: str, field_path: str, scope: str):
        nonlocal search_cursor
        offset = -1
        source_offsets = None
        source_end = None
        if path.suffix.lower() == ".json":
            located = _find_json_string(
                content,
                value,
                search_cursor,
                key_token=scope in {"parameter_name", "field_name"},
            )
            if located:
                offset, encoded = located
                source_offsets = _json_string_offsets(encoded, offset, value)
                source_end = offset + len(encoded)
        else:
            offset = content.find(value, search_cursor)
        if offset < 0:
            offset = content.find(value)
        if offset < 0:
            offset = 0
        search_cursor = source_end or offset + len(value)
        units.append(
            ScanUnit(path, value, field_path, scope, content, offset, source_offsets=source_offsets)
        )

    def walk(value, field_path="$", parent_key=""):
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = key if field_path == "$" else f"{field_path}.{key}"
                key_lower = str(key).lower()
                if parent_key == "properties":
                    add(str(key), child_path, "parameter_name")
                if key_lower in {
                    "first_call_description", "second_call_description",
                    "description_varies", "dynamic_description",
                    "description_changes",
                }:
                    add(str(key), child_path, "field_name")
                walk(child, child_path, key_lower)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{field_path}[{index}]", parent_key)
        elif isinstance(value, str):
            scope = "description" if "description" in field_path.lower() else "value"
            add(value, field_path, scope)

    walk(data)
    return units or [_raw_unit(path, content)]


def _python_string_units(path: Path, content: str) -> list[ScanUnit]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return [_raw_unit(path, content)]
    units = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node_offset = _line_column_to_offset(
                content, node.lineno, node.col_offset
            )
            segment = ast.get_source_segment(content, node) or ""
            value_offset = segment.find(node.value)
            offset = node_offset + value_offset if value_offset >= 0 else node_offset
            units.append(
                ScanUnit(
                    path, node.value, f"string:{node.lineno}",
                    "source_string", content, offset
                )
            )
    return units


def _javascript_string_units(path: Path, content: str) -> list[ScanUnit]:
    return [
        ScanUnit(
            path, match.group("value"), f"string@{match.start()}",
            "source_string", content, match.start("value")
        )
        for match in JS_STRING_PATTERN.finditer(content)
    ]


def _line_column_to_offset(content: str, line: int, column: int) -> int:
    lines = content.splitlines(keepends=True)
    line_text = lines[line - 1]
    character_column = len(line_text.encode("utf-8")[:column].decode("utf-8"))
    return sum(len(item) for item in lines[:line - 1]) + character_column


def _json_string_offsets(encoded: str, absolute_offset: int, decoded: str):
    offsets = []
    index = 1
    while index < len(encoded) - 1:
        if encoded[index] != "\\":
            offsets.append(absolute_offset + index)
            index += 1
            continue
        escape_length = 2
        if encoded[index + 1] == "u":
            escape_length = 6
            first = int(encoded[index + 2:index + 6], 16)
            if (
                0xD800 <= first <= 0xDBFF
                and encoded[index + 6:index + 8] == "\\u"
            ):
                escape_length = 12
        decoded_escape = json.loads('"' + encoded[index:index + escape_length] + '"')
        offsets.extend([absolute_offset + index] * len(decoded_escape))
        index += escape_length
    return offsets if len(offsets) == len(decoded) else None


def _find_json_string(content: str, value: str, start: int, key_token: bool = False):
    for match in re.finditer(r'"(?:\\.|[^"\\])*"', content[start:]):
        encoded = match.group()
        after = content[start + match.end():].lstrip()
        if after.startswith(":") != key_token:
            continue
        try:
            if json.loads(encoded) == value:
                return start + match.start(), encoded
        except json.JSONDecodeError:
            continue
    return None

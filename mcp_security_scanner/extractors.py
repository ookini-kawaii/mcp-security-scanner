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
        offset = content.find(value, search_cursor)
        if offset < 0:
            offset = content.find(value)
        if offset < 0:
            offset = 0
        search_cursor = offset + len(value)
        units.append(
            ScanUnit(path, value, field_path, scope, content, offset)
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
            offset = _line_column_to_offset(
                content, node.lineno, node.col_offset
            )
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
    return sum(len(item) for item in lines[:line - 1]) + column

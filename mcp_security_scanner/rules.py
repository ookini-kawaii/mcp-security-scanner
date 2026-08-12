"""Rule loading and fail-closed validation."""

import re
from pathlib import Path

import yaml


class ScannerConfigurationError(ValueError):
    """Scanner configuration or rule data is invalid."""


class RuleLoader:
    REQUIRED_FIELDS = {"id", "name", "severity", "category", "patterns"}
    VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    VALID_MATCH_TYPES = {"regex", "keyword"}

    def __init__(self, rules_dir):
        self.rules_dir = Path(rules_dir)

    def load(self):
        if not self.rules_dir.is_dir():
            raise ScannerConfigurationError(
                f"规则目录不存在或不是目录: {self.rules_dir}"
            )

        yaml_files = sorted(
            list(self.rules_dir.rglob("*.yaml"))
            + list(self.rules_dir.rglob("*.yml"))
        )
        if not yaml_files:
            raise ScannerConfigurationError(
                f"规则目录中没有YAML规则: {self.rules_dir}"
            )

        rules = []
        rule_ids = set()
        for yaml_file in yaml_files:
            try:
                rule = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, yaml.YAMLError) as exc:
                raise ScannerConfigurationError(
                    f"规则加载失败 {yaml_file.name}: {exc}"
                ) from exc

            self._validate_rule(rule, yaml_file.name)
            if rule["id"] in rule_ids:
                raise ScannerConfigurationError(
                    f"规则ID重复 {rule['id']}: {yaml_file.name}"
                )
            rule_ids.add(rule["id"])
            rule["_source_file"] = yaml_file.name
            rules.append(rule)
        return rules

    def _validate_rule(self, rule, source_name="<unknown>"):
        if not isinstance(rule, dict):
            raise ScannerConfigurationError(
                f"规则必须是YAML对象: {source_name}"
            )

        missing = sorted(self.REQUIRED_FIELDS - rule.keys())
        if missing:
            raise ScannerConfigurationError(
                f"规则缺少必需字段 {', '.join(missing)}: {source_name}"
            )

        for field_name in ("id", "name", "category"):
            if not isinstance(rule[field_name], str) or not rule[field_name].strip():
                raise ScannerConfigurationError(
                    f"规则字段 {field_name} 必须是非空字符串: {source_name}"
                )

        if rule["severity"] not in self.VALID_SEVERITIES:
            raise ScannerConfigurationError(
                f"规则严重级别无效: {source_name}"
            )

        patterns = rule["patterns"]
        if not isinstance(patterns, dict):
            raise ScannerConfigurationError(
                f"规则字段 patterns 必须是对象: {source_name}"
            )
        match_type = patterns.get("type")
        values = patterns.get("match")
        if match_type not in self.VALID_MATCH_TYPES:
            raise ScannerConfigurationError(
                f"规则匹配类型无效: {source_name}"
            )
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value for value in values
        ):
            raise ScannerConfigurationError(
                f"patterns.match 必须是非空字符串列表: {source_name}"
            )
        if match_type == "regex":
            for pattern in values:
                try:
                    re.compile(pattern, re.IGNORECASE | re.DOTALL)
                except re.error as exc:
                    raise ScannerConfigurationError(
                        f"规则正则表达式无效 {source_name}: {pattern!r}: {exc}"
                    ) from exc

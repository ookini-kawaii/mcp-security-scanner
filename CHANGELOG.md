# Changelog

本项目遵循语义化版本号。

## [1.3.1] - 2026-08-13

### Added

- 完整性基线覆盖全部普通文件和符号链接，而不仅是静态扫描支持的扩展名。
- 支持根目录 `.gitignore`、`--integrity-exclude` 和 `--no-gitignore`。
- 支持通过 `MCP_SCANNER_BASELINE_KEY` 对基线进行 HMAC-SHA256 签名和校验。
- 增加 GitHub Actions 测试矩阵、构建检查和 SARIF 上传。
- 增加 `pyproject.toml`，支持安装后使用 `mcp-security-scanner` 命令。

### Changed

- 完整性清单升级至 v2，绑定目标名称、类型和基线选项，保留 v1 清单兼容。
- `scanner.py` 收敛为 CLI 入口，移除重复的旧版扫描实现。
- SARIF 同时输出准确的起始行和起始列。

## [1.3.0] - 2026-08-12

- 增加 SHA-256 Hash Pinning，检测文件修改、新增和删除。

## [1.2.0] - 2026-08-12

- 增加字段感知、上下文置信度、测试目录策略、攻击事件聚合和 SARIF。
- Base64 改为解码内容命中恶意规则后再确认告警。

## [1.1.1] - 2026-08-11

- 增加 fail-closed 规则校验、稳定退出码、准确位置、去重和目录聚合报告。


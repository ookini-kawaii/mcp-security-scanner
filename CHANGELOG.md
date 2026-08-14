# Changelog

本项目遵循语义化版本号。

## [1.5.0] - 2026-08-14

### Added

- MCP stdio Server 默认在一次性临时工作目录中运行，避免无意依赖扫描器当前目录。
- 默认仅传递跨平台启动所需的最小环境变量，支持显式 `allow-env` 和兼容性继承模式。
- 增加 stdout/stderr 总字节上限、JSON-RPC 消息数上限和有界消息队列。
- JSON 与终端报告增加脱敏的运行时策略摘要，不记录环境值或真实临时路径。

### Changed

- stdio 改为有界二进制读取，严格校验 UTF-8 和逐行 JSON，输出或消息洪泛统一 fail-closed。
- POSIX 平台使用独立进程组关闭 Server，降低遗留子进程风险。
- JSON-RPC 错误不再回显 Server 提供的错误对象，避免敏感信息进入日志。

### Security

- 运行时保护层用于降低环境泄露、工作目录污染和输出资源耗尽风险；它不提供文件系统或网络的操作系统级隔离。

## [1.4.1] - 2026-08-13

### Fixed

- 严格校验 JSON-RPC 与 `initialize` 响应，非法运行时间隔统一 fail-closed 返回退出码 `2`。
- 运行时报告对 Server 命令参数和工具元数据脱敏，仅保留差异摘要与 SHA-256。
- 修复 Python 非 ASCII 字符、JSON 转义及键值同名场景下的告警位置偏移。
- 按既有深度上限递归扫描双层 Base64，避免嵌套编码恶意载荷漏报。

## [1.4.0] - 2026-08-13

### Added

- 增加 MCP stdio JSON-RPC 运行时探针，初始化 Server 并多次调用 `tools/list`。
- 检测工具新增、删除，以及 `description`/`inputSchema` 变化导致的 Rug Pull 风险。
- 运行时快照、哈希和前后元数据进入 JSON/SARIF 结果。
- 运行时协议错误、进程提前退出和请求超时 fail-closed 返回 `2`。

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

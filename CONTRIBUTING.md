# 贡献指南

感谢你帮助改进 MCP Tool Security Scanner。提交变更前，请先搜索现有 Issue，较大的行为变更建议先建立 Issue 说明目标和兼容性影响。

## 本地开发

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
python -m pip install -e .
python -B -m unittest discover -s tests -v
```

提交前还应运行与 CI 一致的检查：

```bash
python -m compileall -q scanner.py mcp_security_scanner tests
python -B scanner.py benchmarks/benign --profile enforce --format json --no-report
```

恶意样本扫描应返回退出码 `1`，表示成功检出达到阈值的风险，而不是程序错误。退出码 `2` 表示扫描结果不可信，必须修复。

## 规则变更

- 规则 ID 必须唯一，并通过 schema 和正则校验。
- 新增或调整规则时，同时补充恶意样本与良性回归样本。
- 不要通过降低全局阈值来掩盖误报；优先完善字段、语法和上下文判断。
- 样本中不得包含真实凭证、个人数据或未经授权的攻击数据。

## Pull Request

PR 应保持单一目的，说明行为变化、测试命令和结果。影响 CLI、退出码、报告 schema 或规则兼容性的变更，应同步更新 README 和 CHANGELOG。

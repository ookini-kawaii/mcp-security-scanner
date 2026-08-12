# 扫描基准

这里放置用于回归测试的良性样本，不代表完整的 MCP 生态样本集。

- `benign/`：来自文章中误报复盘的最小样本，包含环境变量引用、路径校验代码和 PNG Base64 数据。
- `../test_cases/`：五个恶意样本，用于验证规则召回能力没有回退。

v1.3.0 的目标是：恶意样本保持检出；对 `benign/` 使用 `enforce` profile 时不产生高置信告警；基线文件变化必须被报告。运行基准：

```bash
python -B -m unittest discover -s tests -v
python -B scanner.py benchmarks/benign --profile enforce --format json --no-report
```

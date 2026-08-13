## 变更说明

说明本 PR 解决的问题和实现范围。

## 验证

- [ ] `python -B -m unittest discover -s tests -v`
- [ ] `python -B scanner.py benchmarks/benign --profile enforce --format json --no-report`
- [ ] 新增或变更规则时，已补充恶意与良性回归样本
- [ ] 行为或兼容性变化已更新 README/CHANGELOG
- [ ] 不包含真实凭证、敏感数据或生成的扫描报告

## 兼容性影响

说明是否影响 CLI、退出码、规则、报告 schema 或已有基线。

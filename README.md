# MCP Tool Security Scanner

> 面向 MCP 工具描述、配置和源码字符串的静态安全扫描器，将 Agent 供应链威胁检测接入本地开发与 CI。

[![Version](https://img.shields.io/github/v/tag/ookini-kawaii/mcp-security-scanner?label=version&color=orange)](https://github.com/ookini-kawaii/mcp-security-scanner/tags)
[![License](https://img.shields.io/github/license/ookini-kawaii/mcp-security-scanner?label=license&color=brightgreen)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![ATR Rules](https://img.shields.io/badge/ATR%20rules-5-7B61FF)](rules/)
[![Last Commit](https://img.shields.io/github/last-commit/ookini-kawaii/mcp-security-scanner?label=last%20commit)](https://github.com/ookini-kawaii/mcp-security-scanner/commits/main)

当前开发版本为 **v1.3.0**。它延续 v1.2.0 的误报校准能力，并加入 SHA-256 文件基线，用于检测安装后文件被替换、增加或删除。

## 能力概览

- 基于 YAML 的 ATR 规则：正则和关键词匹配，启动时校验 schema、重复 ID 和正则表达式。
- 字段感知：JSON/YAML 显示 `field_path`；Python、TypeScript、JavaScript 扫描字符串字面量，减少函数名和结构文本误报。
- 上下文置信度：识别读取、执行、外发、隐藏指令等动作；安全校验代码中的敏感路径会降级为 LOW。
- Base64 二次匹配：支持标准、URL-safe、无 padding Base64；仅当解码内容命中恶意规则时确认混淆告警，并限制解码深度、大小和数量。
- 测试代码隔离：默认跳过 `test/`、`tests/`、`__tests__/` 以及 `.test.*`/`.spec.*` 文件，可用 `--include-tests` 显式纳入并降级测试上下文告警。
- 结果聚合：按文件关联为攻击事件，告警去重，报告包含字段路径、行列位置、置信度和跳过文件清单。
- 完整性基线：使用 `--write-baseline` 保存基线，使用 `--baseline` 校验当前文件树；哈希变化按高置信供应链事件报告。
- 输出与 CI：terminal、JSON、SARIF；`--fail-on` 控制流水线失败阈值。

## 检测规则

| 规则 ID | 威胁类别 | 默认严重级别 | 说明 |
|---|---|---:|---|
| `ATR-DESC-INJECTION-001` | prompt_injection | HIGH | Description 隐藏指令注入 |
| `ATR-DATA-EXFIL-001` | data_exfiltration | CRITICAL | 参数或描述中的数据外带通道 |
| `ATR-CRED-THEFT-001` | credential_access | CRITICAL | 敏感文件和凭证路径访问 |
| `ATR-RUG-PULL-001` | supply_chain_poisoning | HIGH | `list_tools` 描述变化指示 |
| `ATR-ENCODE-OBFUS-001` | obfuscation | MEDIUM | 解码后确认的编码载荷 |

## 安装

```bash
git clone https://github.com/ookini-kawaii/mcp-security-scanner.git
cd mcp-security-scanner
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 使用

```bash
# 默认 hunt profile：保留低置信线索，适合调查
python scanner.py test_cases/01_description_injection.json -r rules/

# enforce profile：只保留置信度 >= 70 的告警，适合 CI 门禁
python scanner.py . --profile enforce --format terminal --brief --no-report

# 包含测试文件（默认跳过测试目录和测试文件）
python scanner.py . --include-tests --profile hunt

# 输出 JSON 或 SARIF；目录扫描会生成一份聚合报告
python scanner.py test_cases/ --format json --no-report
python scanner.py test_cases/ --format sarif --no-report

# 仅在达到指定严重级别时让 CI 失败
python scanner.py . --profile enforce --fail-on high --format sarif

# 安装后建立 SHA-256 基线，之后校验文件是否被替换/增删
python scanner.py package/ --write-baseline package-baseline.json --no-report
python scanner.py package/ --baseline package-baseline.json --profile enforce --fail-on high

python scanner.py --version
```

### Profile 与退出码

`hunt` 展示所有线索，包括上下文不足、测试文件中的低置信结果；`enforce` 过滤置信度低于 70 的结果。`--fail-on` 可取 `low`、`medium`、`high`、`critical` 或 `none`，默认是 `low`。

| 退出码 | 含义 |
|---:|---|
| `0` | 扫描成功，未达到 `--fail-on` 阈值 |
| `1` | 扫描成功，至少一个攻击事件达到阈值 |
| `2` | 目标、规则 schema、正则或报告写入失败，结果不可信 |

规则目录不存在、没有 YAML 规则、必需字段缺失、规则 ID 重复或正则无效时会 fail-closed，直接返回 `2`。

## 报告结构

JSON 报告包含 `findings`、按文件聚合的 `incidents`、`skipped_files`、`total_files` 和 `profile`。每条 finding 包含：`rule_id`、`severity`、`confidence`、`field_path`、`position`（`line:N,column:M`）、`offset`、`decoded_from` 等字段。SARIF 输出为 2.1.0，可直接导入 GitHub code scanning 等工具。

默认报告写入 `reports/`；该目录已加入 `.gitignore`。

## 项目结构

```
mcp-security-scanner/
├── scanner.py                 # CLI 与兼容入口
├── mcp_security_scanner/      # v1.3 扫描引擎
│   ├── engine.py              # 扫描编排、profile、去重
│   ├── extractors.py          # 字段和源码字符串提取
│   ├── matching.py            # 上下文匹配与置信度校准
│   ├── decoders.py            # Base64 解码与边界控制
│   ├── correlation.py         # 文件级攻击事件聚合
│   ├── integrity.py           # SHA-256 基线与完整性校验
│   ├── reports.py             # JSON/SARIF 序列化
│   └── rules.py               # fail-closed 规则加载
├── rules/                     # 5 条 ATR 示例规则
├── test_cases/                # 恶意召回样本
├── benchmarks/benign/         # 误报回归基准
└── tests/                     # v1.3.0 自动化测试
```

## 验证

```bash
python -B -m unittest discover -s tests -v
```

基准来源于《MCP 供应链安全检测实践》记录的 58 条误报：环境变量 `.env`、安全校验中的 `/etc/passwd`/`/etc/shadow`，以及 PNG、函数名和 URL 被宽 Base64 正则误报。v1.2.0 通过字段感知、上下文窗口、测试目录策略和“解码后再确认”降低这些误报；v1.3.0 增加了本地 Hash Pinning。Rug Pull 运行时差异检测和语义二次确认仍属于后续版本范围。

## 检测边界

这是静态规则扫描器，发现结果代表需要复核的风险信号，不等同于已确认漏洞。当前 Rug Pull 规则只检测静态文件中的描述变化指示字段，尚未连接运行中的 MCP Server 做多次 `tools/list` 差异检测。

## 参考与许可

- [ATR - Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
- 《MCP 供应链安全检测实践》（本次 v1.2.0 精度基准与后续路线的来源）

本项目以 [MIT License](LICENSE) 发布。

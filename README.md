# MCP Tool Security Scanner

> v1.1.1

基于ATR（Agent Threat Rules）的MCP工具安全扫描器，支持静态规则匹配 + Base64自动解码二次匹配。

## 功能

- 📋 基于YAML规则的多模式检测（正则匹配 + 关键词匹配）
- 🔓 Base64编码内容自动解码 + 二次匹配
- 📊 终端彩色输出（详细模式/精简表格模式）
- 📄 单文件报告和目录聚合JSON报告
- 📁 支持单文件/目录批量扫描
- 📎 支持JSON/PY/YAML/TS/JS/TSX/JSX文件格式
- ✅ 启动时校验规则结构和正则表达式，配置错误时拒绝扫描
- 🚦 提供适合CI使用的稳定退出码

## 检测的5类恶意模式

| 规则ID | 威胁类别 | 严重级别 | 说明 |
|--------|---------|---------|------|
| ATR-DESC-INJECTION-001 | prompt_injection | HIGH | Description隐藏指令注入 |
| ATR-DATA-EXFIL-001 | data_exfiltration | CRITICAL | Sidenote参数数据外带 |
| ATR-CRED-THEFT-001 | credential_access | CRITICAL | 敏感文件路径访问 |
| ATR-RUG-PULL-001 | supply_chain_poisoning | HIGH | Rug Pull供应链投毒 |
| ATR-ENCODE-OBFUS-001 | obfuscation | MEDIUM | Base64编码混淆 |

## 安装

```bash
# 克隆仓库
git clone https://github.com/ookini-kawaii/mcp-security-scanner.git
cd mcp-security-scanner

# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

## 使用

```bash
# 扫描单个文件（详细模式）
python scanner.py test_cases/01_description_injection.json -r rules/

# 精简表格模式
python scanner.py test_cases/ -r rules/ --brief

# 不生成JSON报告
python scanner.py test_cases/ -r rules/ --no-report --brief

# 查看版本
python scanner.py --version
```

默认在 `reports/` 下生成报告。扫描单个文件时生成文件报告；扫描目录时生成一份聚合报告，包含每个文件的发现和总计。

### 退出码

| 退出码 | 含义 |
|-------|------|
| `0` | 扫描成功，未发现威胁 |
| `1` | 扫描成功，发现至少一个威胁 |
| `2` | 目标、规则或报告写入错误，扫描结果不可信 |

规则目录不存在、没有YAML规则、规则字段缺失、规则ID重复或正则表达式无效时，扫描器会立即停止并返回退出码 `2`。

## 项目结构

```
mcp-security-scanner/
├── LICENSE                 # MIT许可证
├── scanner.py              # 主扫描器
├── requirements.txt        # Python依赖
├── rules/                  # ATR检测规则
│   ├── description_injection.yaml
│   ├── data_exfiltration.yaml
│   ├── credential_theft.yaml
│   ├── rug_pull.yaml
│   └── encoding_obfuscation.yaml
└── test_cases/             # 测试用例
    ├── 01_description_injection.json
    ├── 02_data_exfiltration.json
    ├── 03_credential_theft.json
    ├── 04_rug_pull.json
    └── 05_encoding_obfuscation.json
```

## 扫描器架构

扫描器分两轮扫描：第一轮静态规则匹配，第二轮Base64自动解码+二次匹配。

```
[1] 规则加载器     →  加载5条YAML规则
[2] 目标文件读取   →  读取JSON/PY/YML/TS/JS/TSX/JSX文件
[3] 第一轮匹配     →  regex正则 + keyword关键词
[4] Base64解码器   →  提取Base64 → 解码 → 二次匹配
[5] 结果处理       →  源文件行列定位 + 告警去重
[6] 报告生成器     →  终端输出 + 单文件/目录聚合JSON报告
```

## 技术亮点

- **Base64自动解码二次匹配**：检测到Base64编码内容后，自动解码并用其他规则进行二次扫描，能够识别编码隐藏的窃密指令
- **多规则交叉检测**：单个恶意样本可触发多条规则，提高检测覆盖率
- **可打印字符比例过滤**：解码后通过可打印字符比例过滤随机二进制数据，降低误报

## 检测边界

当前版本是静态规则扫描器，发现结果代表需要复核的风险信号，不等同于已经确认的漏洞。Rug Pull规则检测静态文件中的描述变化指示字段，尚未连接运行中的MCP Server执行多次 `tools/list` 差异检测。

## 参考

- [ATR - Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
- Black Hat USA 2026 - "Promptware EOD" by Zenity
- Cloud Security Alliance - AI Inference Server Security

## License

[MIT](LICENSE)

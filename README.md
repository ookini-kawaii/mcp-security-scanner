# MCP Tool Security Scanner

基于ATR（Agent Threat Rules）的MCP工具安全扫描器，支持静态规则匹配 + Base64自动解码二次匹配。

## 功能

- 📋 基于YAML规则的多模式检测（正则匹配 + 关键词匹配）
- 🔓 Base64编码内容自动解码 + 二次匹配
- 📊 终端彩色输出（详细模式/精简表格模式）
- 📄 JSON格式检测报告
- 📁 支持单文件/目录批量扫描

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
git clone https://github.com/ookini--kawaii/mcp-security-scanner.git
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
```

## 项目结构

```
mcp-security-scanner/
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
[2] 目标文件读取   →  读取JSON/PY/YML文件
[3] 第一轮匹配     →  regex正则 + keyword关键词
[4] Base64解码器   →  提取Base64 → 解码 → 二次匹配
[5] 报告生成器     →  终端彩色输出 + JSON报告
```

## 技术亮点

- **Base64自动解码二次匹配**：检测到Base64编码内容后，自动解码并用其他规则进行二次扫描，能够识别编码隐藏的窃密指令
- **多规则交叉检测**：单个恶意样本可触发多条规则，提高检测覆盖率
- **可打印字符比例过滤**：解码后通过可打印字符比例过滤随机二进制数据，降低误报

## 参考

- [ATR - Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
- Black Hat USA 2026 - "Promptware EOD" by Zenity
- Cloud Security Alliance - AI Inference Server Security

## License

MIT

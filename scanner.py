#!/usr/bin/env python3
"""
MCP Tool Security Scanner
基于ATR规则的MCP工具安全扫描器
支持Base64自动解码+二次匹配
用法:
    python scanner.py <目标文件或目录> -r <规则目录>
"""

import os
import sys
import json
import re
import yaml
import base64
import argparse
from pathlib import Path
from datetime import datetime


VERSION = "1.1.1"
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = BLUE = WHITE = ""
    class Style:
        BRIGHT = RESET_ALL = NORMAL = ""


class ScannerConfigurationError(ValueError):
    """扫描器配置或规则无效。"""


class RuleLoader:
    """ATR规则加载器：从YAML文件加载检测规则"""

    REQUIRED_FIELDS = {'id', 'name', 'severity', 'category', 'patterns'}
    VALID_SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}
    VALID_MATCH_TYPES = {'regex', 'keyword'}

    def __init__(self, rules_dir):
        self.rules_dir = Path(rules_dir)
        self.rules = []

    def load(self):
        """遍历规则目录，加载所有YAML规则"""
        if not self.rules_dir.is_dir():
            raise ScannerConfigurationError(
                f"规则目录不存在或不是目录: {self.rules_dir}"
            )

        yaml_files = sorted(
            list(self.rules_dir.rglob("*.yaml")) +
            list(self.rules_dir.rglob("*.yml"))
        )
        if not yaml_files:
            raise ScannerConfigurationError(
                f"规则目录中没有YAML规则: {self.rules_dir}"
            )

        self.rules = []
        rule_ids = set()
        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
            except (OSError, UnicodeError, yaml.YAMLError) as exc:
                raise ScannerConfigurationError(
                    f"规则加载失败 {yaml_file.name}: {exc}"
                ) from exc

            self._validate_rule(rule, yaml_file.name)
            if rule['id'] in rule_ids:
                raise ScannerConfigurationError(
                    f"规则ID重复 {rule['id']}: {yaml_file.name}"
                )
            rule_ids.add(rule['id'])
            rule['_source_file'] = str(yaml_file.name)
            self.rules.append(rule)

        print(f"{Fore.GREEN}[+] 已加载 {len(self.rules)} 条规则")
        return self.rules

    def _validate_rule(self, rule, source_name="<unknown>"):
        """校验规则结构，并在扫描前编译正则表达式。"""
        if not isinstance(rule, dict):
            raise ScannerConfigurationError(
                f"规则必须是YAML对象: {source_name}"
            )

        missing = sorted(self.REQUIRED_FIELDS - rule.keys())
        if missing:
            raise ScannerConfigurationError(
                f"规则缺少必需字段 {', '.join(missing)}: {source_name}"
            )

        for field in ('id', 'name', 'category'):
            if not isinstance(rule[field], str) or not rule[field].strip():
                raise ScannerConfigurationError(
                    f"规则字段 {field} 必须是非空字符串: {source_name}"
                )

        if (not isinstance(rule['severity'], str) or
                rule['severity'] not in self.VALID_SEVERITIES):
            allowed = ', '.join(sorted(self.VALID_SEVERITIES))
            raise ScannerConfigurationError(
                f"规则严重级别必须是 {allowed}: {source_name}"
            )

        patterns = rule['patterns']
        if not isinstance(patterns, dict):
            raise ScannerConfigurationError(
                f"规则字段 patterns 必须是对象: {source_name}"
            )

        match_type = patterns.get('type')
        if (not isinstance(match_type, str) or
                match_type not in self.VALID_MATCH_TYPES):
            allowed = ', '.join(sorted(self.VALID_MATCH_TYPES))
            raise ScannerConfigurationError(
                f"规则匹配类型必须是 {allowed}: {source_name}"
            )

        match_patterns = patterns.get('match')
        if (not isinstance(match_patterns, list) or not match_patterns or
                not all(
                    isinstance(item, str) and item
                    for item in match_patterns
                )):
            raise ScannerConfigurationError(
                f"规则字段 patterns.match 必须是非空字符串列表: {source_name}"
            )

        if match_type == 'regex':
            for pattern in match_patterns:
                try:
                    re.compile(pattern, re.IGNORECASE | re.DOTALL)
                except re.error as exc:
                    raise ScannerConfigurationError(
                        f"规则正则表达式无效 {source_name}: {pattern!r}: {exc}"
                    ) from exc


class TargetReader:
    """目标文件读取器：支持JSON/Python/YAML/TS/JS等格式"""

    SUPPORTED_EXTENSIONS = {'.json', '.py', '.yaml', '.yml',
                            '.ts', '.js', '.tsx', '.jsx'}

    @staticmethod
    def read(file_path):
        """读取目标文件内容"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        if path.suffix.lower() not in TargetReader.SUPPORTED_EXTENSIONS:
            print(f"{Fore.YELLOW}[!] 不支持的文件类型: {path.suffix}")
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()

    @staticmethod
    def read_directory(dir_path):
        """递归读取目录下所有支持的目标文件"""
        targets = []
        path = Path(dir_path)
        for ext in sorted(TargetReader.SUPPORTED_EXTENSIONS):
            targets.extend(path.rglob(f"*{ext}"))
        return [
            (str(target), TargetReader.read(target))
            for target in sorted(targets)
        ]


class Base64Decoder:
    """Base64自动解码器：提取Base64内容并解码，用于二次匹配"""

    # 匹配长度>=20的Base64字符串（标准Base64字符集）
    BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

    @staticmethod
    def extract_and_decode(content):
        """
        从内容中提取所有Base64字符串并解码
        返回: [{'encoded': '原始Base64', 'decoded': '解码后文本', 'position': 位置}]
        """
        decoded_results = []
        for match in Base64Decoder.BASE64_PATTERN.finditer(content):
            encoded = match.group()
            try:
                decoded_bytes = base64.b64decode(encoded)
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                # 过滤：只保留有意义的解码结果
                if not decoded_text or len(decoded_text) < 5:
                    continue
                # 计算可打印字符比例，过滤随机二进制数据
                printable_count = sum(1 for c in decoded_text if c.isprintable())
                printable_ratio = printable_count / len(decoded_text)
                if printable_ratio > 0.7:
                    decoded_results.append({
                        'encoded': encoded[:80],
                        'decoded': decoded_text,
                        'position': match.start()
                    })
            except Exception:
                continue
        return decoded_results


class MatchEngine:
    """匹配引擎：根据规则模式匹配目标内容"""

    @staticmethod
    def format_position(content, offset):
        """将字符偏移转换为从1开始的行列位置。"""
        line = content.count('\n', 0, offset) + 1
        last_newline = content.rfind('\n', 0, offset)
        column = offset - last_newline
        return f"line:{line},column:{column}"

    @staticmethod
    def match(content, rule):
        """根据规则类型匹配内容，返回匹配结果列表"""
        findings = []
        patterns = rule.get('patterns', {})
        match_type = patterns.get('type', 'regex')
        match_patterns = patterns.get('match', [])

        for pattern in match_patterns:
            if match_type == 'regex':
                matches = re.finditer(
                    pattern, content, re.IGNORECASE | re.DOTALL
                )
                for match in matches:
                    offset = match.start()
                    findings.append({
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'category': rule['category'],
                        'matched_pattern': pattern,
                        'matched_text': match.group()[:200],
                        'position': MatchEngine.format_position(content, offset),
                        'offset': offset,
                        'source_file': rule.get('_source_file', ''),
                        'decoded_from': None
                    })
            elif match_type == 'keyword':
                content_offset = 0
                for line in content.splitlines(keepends=True):
                    column_offset = line.lower().find(pattern.lower())
                    if column_offset >= 0:
                        offset = content_offset + column_offset
                        findings.append({
                            'rule_id': rule['id'],
                            'rule_name': rule['name'],
                            'severity': rule['severity'],
                            'category': rule['category'],
                            'matched_pattern': pattern,
                            'matched_text': line.strip()[:200],
                            'position': MatchEngine.format_position(content, offset),
                            'offset': offset,
                            'source_file': rule.get('_source_file', ''),
                            'decoded_from': None
                        })
                    content_offset += len(line)
        return findings

    @staticmethod
    def match_decoded(content, rule, decoded_info, source_content):
        """对Base64解码后的内容进行二次匹配"""
        findings = MatchEngine.match(content, rule)
        for f in findings:
            f['matched_text'] = f"[解码内容] {f['matched_text']}"
            f['decoded_from'] = decoded_info['encoded'][:50]
            f['decoded_position'] = f['position']
            f['decoded_offset'] = f['offset']
            f['position'] = MatchEngine.format_position(
                source_content, decoded_info['position']
            )
            f['offset'] = decoded_info['position']
        return findings


class ReportGenerator:
    """报告生成器：终端彩色输出 + JSON报告"""

    SEVERITY_COLORS = {
        'CRITICAL': Fore.RED,
        'HIGH': Fore.RED,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.GREEN
    }

    @staticmethod
    def print_terminal(findings, target_name, brief=False):
        """终端彩色输出检测结果"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}扫描目标: {target_name}")
        print(f"{Fore.CYAN}{'='*60}")

        if not findings:
            print(f"{Fore.GREEN}[OK] 未检测到威胁")
            return

        print(f"{Fore.RED}[!] 检测到 {len(findings)} 个威胁:\n")

        if brief:
            # 精简表格模式
            print(f"  {'#':<4}{'规则ID':<26}{'严重级别':<14}{'威胁类别':<22}{'匹配内容(前50字)'}")
            print(f"  {'-'*110}")
            for i, finding in enumerate(findings, 1):
                color = ReportGenerator.SEVERITY_COLORS.get(
                    finding['severity'], Fore.WHITE
                )
                reset = Fore.WHITE + Style.NORMAL
                text = finding['matched_text'][:50].replace('\n', ' ')
                print(f"  {i:<4}{finding['rule_id']:<26}{color}{finding['severity']:<14}{reset}{finding['category']:<22}{text}")
            print()
            return

        for i, finding in enumerate(findings, 1):
            color = ReportGenerator.SEVERITY_COLORS.get(
                finding['severity'], Fore.WHITE
            )
            print(f"  {color}--- 威胁 #{i} ---")
            print(f"  规则ID:   {finding['rule_id']}")
            print(f"  规则名称: {finding['rule_name']}")
            print(f"  严重级别: {color}{finding['severity']}")
            print(f"  威胁类别: {finding['category']}")
            print(f"  匹配模式: {finding['matched_pattern'][:80]}")
            print(f"  匹配内容: {finding['matched_text'][:100]}...")
            print(f"  位置:     {finding['position']}")
            print(f"  规则文件: {finding['source_file']}")
            if finding.get('decoded_from'):
                print(f"  {Fore.YELLOW}  ⚡ 来自Base64解码: {finding['decoded_from']}...")
                print(f"  解码后位置: {finding['decoded_position']}")
            print()

    @staticmethod
    def save_json(findings, target_name, output_dir="reports"):
        """保存JSON格式报告"""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r'[^\w]', '_', target_name)
        output_file = os.path.join(output_dir, f"report_{safe_name}_{timestamp}.json")

        report = {
            'scanner_version': VERSION,
            'scan_time': datetime.now().isoformat(),
            'target': target_name,
            'total_findings': len(findings),
            'findings': findings
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"{Fore.BLUE}[i] 报告已保存: {output_file}")
        return output_file

    @staticmethod
    def save_directory_json(file_results, target_name, output_dir="reports"):
        """保存目录扫描的单份聚合JSON报告。"""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re.sub(r'[^\w]', '_', target_name)
        output_file = os.path.join(
            output_dir, f"report_{safe_name}_{timestamp}.json"
        )

        report = {
            'scanner_version': VERSION,
            'scan_time': datetime.now().isoformat(),
            'target': target_name,
            'total_files': len(file_results),
            'total_findings': sum(
                result['total_findings'] for result in file_results
            ),
            'files': file_results
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"{Fore.BLUE}[i] 聚合报告已保存: {output_file}")
        return output_file


class MCPSecurityScanner:
    """MCP工具安全扫描器主类"""

    def __init__(self, rules_dir):
        self.loader = RuleLoader(rules_dir)
        self.rules = self.loader.load()

    def scan_file(self, file_path, save_report=True, brief=False):
        """扫描单个文件（含Base64解码二次匹配）"""
        content = TargetReader.read(file_path)
        all_findings = self._scan_content(content)

        ReportGenerator.print_terminal(all_findings, file_path, brief=brief)

        if save_report:
            ReportGenerator.save_json(all_findings, Path(file_path).name)

        return all_findings

    def scan_directory(self, dir_path, save_report=True, brief=False):
        """扫描目录下所有文件"""
        targets = TargetReader.read_directory(dir_path)
        total_findings = 0
        file_results = []

        print(f"\n{Fore.CYAN}[*] 扫描目录: {dir_path}")
        print(f"{Fore.CYAN}[*] 发现 {len(targets)} 个目标文件\n")

        for file_path, content in targets:
            all_findings = self._scan_content(content)
            ReportGenerator.print_terminal(all_findings, file_path, brief=brief)
            total_findings += len(all_findings)
            file_results.append({
                'target': file_path,
                'total_findings': len(all_findings),
                'findings': all_findings
            })

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}扫描完成: 共扫描 {len(targets)} 个文件, "
              f"发现 {total_findings} 个威胁")
        print(f"{Fore.CYAN}{'='*60}")

        if save_report:
            ReportGenerator.save_directory_json(
                file_results, str(Path(dir_path))
            )

        return total_findings

    @staticmethod
    def _deduplicate_findings(findings):
        """按规则、源位置和编码来源去除重复告警。"""
        unique_findings = []
        seen = set()
        for finding in findings:
            key = (
                finding['rule_id'],
                finding['offset'],
                finding.get('decoded_from')
            )
            if key in seen:
                continue
            seen.add(key)
            unique_findings.append(finding)
        return unique_findings

    def _scan_content(self, content):
        """
        核心扫描逻辑：静态规则匹配 + Base64解码二次匹配
        """
        all_findings = []

        # 第一轮：静态规则匹配
        for rule in self.rules:
            findings = MatchEngine.match(content, rule)
            all_findings.extend(findings)

        # 第二轮：Base64自动解码 + 二次匹配
        decoded_items = Base64Decoder.extract_and_decode(content)
        if decoded_items:
            print(f"{Fore.YELLOW}[*] 检测到 {len(decoded_items)} 个Base64编码字符串，正在进行解码二次匹配...")
            for decoded_item in decoded_items:
                for rule in self.rules:
                    # 跳过编码混淆规则本身，避免重复检测
                    if rule['category'] == 'obfuscation':
                        continue
                    findings = MatchEngine.match_decoded(
                        decoded_item['decoded'], rule, decoded_item, content
                    )
                    all_findings.extend(findings)

        return self._deduplicate_findings(all_findings)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='MCP工具安全扫描器 - 基于ATR规则 (支持Base64解码)'
    )
    parser.add_argument(
        '--version', action='version', version=f'%(prog)s {VERSION}'
    )
    parser.add_argument('target', help='目标文件或目录路径')
    parser.add_argument('-r', '--rules', default='rules',
                        help='ATR规则目录路径 (默认: rules)')
    parser.add_argument('--no-report', action='store_true',
                        help='不保存JSON报告')
    parser.add_argument('--brief', action='store_true',
                        help='精简表格输出模式')
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        print(f"{Fore.RED}[!] 目标不存在: {args.target}", file=sys.stderr)
        return EXIT_ERROR

    try:
        scanner = MCPSecurityScanner(args.rules)
        if target.is_dir():
            finding_count = scanner.scan_directory(
                args.target,
                save_report=not args.no_report,
                brief=args.brief
            )
        elif target.is_file():
            findings = scanner.scan_file(
                args.target,
                save_report=not args.no_report,
                brief=args.brief
            )
            finding_count = len(findings)
        else:
            print(
                f"{Fore.RED}[!] 目标不是普通文件或目录: {args.target}",
                file=sys.stderr
            )
            return EXIT_ERROR
    except (ScannerConfigurationError, OSError, UnicodeError) as exc:
        print(f"{Fore.RED}[!] 扫描失败: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_FINDINGS if finding_count else EXIT_CLEAN


if __name__ == '__main__':
    sys.exit(main())

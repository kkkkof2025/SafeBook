# 蜜罐数据分析与威胁情报提取

## 概述

蜜罐的价值不在于"部署"，而在于"分析"——每天都部署蜜罐的组织很多，但能从蜜罐日志中提取可执行的威胁情报的很少。本章教你如何从蜜罐数据中产出真正的 IOC 和 TTPs。

---

## 1. 蜜罐数据管道

```
蜜罐数据流:

  Cowrie (SSH) ─┐
  Dionaea (SMB) ─┤
  Conpot (ICS)  ─┼─→ Elastic Stack ─→ Kibana 仪表盘
  Honeytrap     ─┤     │
  HTTP 蜜罐     ─┘     ├─→ 威胁情报提取
                        │   ├─ IOC 生成 (IP/域名/Hash)
                        │   ├─ TTP 分析 (MITRE ATT&CK 映射)
                        │   └─ 攻击者画像
                        │
                        └─→ 自动响应
                            ├─ 防火墙阻断
                            └─ 通知 CERT
```

---

## 2. IOC 提取

### 2.1 自动化 IOC 提取器

```python
import json
import re
from collections import Counter
from datetime import datetime, timedelta

class HoneypotIOCExtractor:
    """从蜜罐日志中提取 IOC"""

    def __init__(self, log_file):
        self.logs = []
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    self.logs.append(json.loads(line.strip()))
                except:
                    pass

    def extract_ips(self):
        """提取攻击源 IP"""
        ips = Counter()

        for log in self.logs:
            src_ip = log.get('src_ip')
            if src_ip:
                ips[src_ip] += 1

        # 高频攻击 IP
        return [
            {'ip': ip, 'count': count, 'type': 'attacker_ip'}
            for ip, count in ips.most_common(50)
            if count > 5  # 攻击超过 5 次的 IP
        ]

    def extract_malware_hashes(self):
        """提取下载的恶意软件哈希"""
        hashes = []

        for log in self.logs:
            if log.get('eventid') == 'cowrie.session.file_download':
                if 'shasum' in log:
                    hashes.append({
                        'hash': log['shasum'],
                        'filename': log.get('filename', 'unknown'),
                        'url': log.get('url', 'unknown'),
                        'type': 'malware_hash',
                        'confidence': 'high'
                    })

        return hashes

    def extract_domains(self):
        """提取恶意域名"""
        domains = Counter()
        domain_pattern = re.compile(
            r'(?:http[s]?://)?(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|'
            r'(?:%[0-9a-fA-F][0-9a-fA-F]))+\.(?:com|net|org|cn|io|xyz|'
            r'top|tk|ml|ga|cf|pw|info|club|online|site|tech)'
        )

        for log in self.logs:
            if log.get('eventid') == 'cowrie.command.input':
                cmd = log.get('input', '')
                matches = domain_pattern.findall(cmd)
                for match in matches:
                    domains[match] += 1

        return [
            {'domain': d, 'count': c, 'type': 'malicious_domain'}
            for d, c in domains.most_common(30)
        ]

    def extract_attack_commands(self):
        """提取攻击者执行的命令 (TTP 分析)"""
        commands = []
        command_history = {}  # session -> commands

        for log in self.logs:
            session = log.get('session')
            if log.get('eventid') == 'cowrie.command.input':
                cmd = log.get('input', '')
                if session not in command_history:
                    command_history[session] = []
                command_history[session].append(cmd)

        # 分析每个会话的攻击链
        for session, cmds in command_history.items():
            attack_chain = self._classify_attack_chain(cmds)
            if attack_chain:
                commands.append({
                    'session': session,
                    'command_count': len(cmds),
                    'attack_chain': attack_chain
                })

        return commands

    def _classify_attack_chain(self, commands):
        """分类攻击链"""
        chain = []

        # 阶段 1: 侦察
        recon_cmds = ['uname', 'cat /proc/cpuinfo', 'free -m',
                     'df -h', 'ifconfig', 'whoami', 'id']
        for cmd in commands:
            if any(r in cmd.lower() for r in recon_cmds):
                chain.append({
                    'stage': 'reconnaissance',
                    'command': cmd,
                    'mitre': 'T1592 (Gather Victim Host Information)'
                })

        # 阶段 2: 凭据收集
        cred_cmds = ['/etc/shadow', 'cat /etc/passwd', 'lastlog',
                    '/root/.ssh/', 'authorized_keys', '.bash_history']
        for cmd in commands:
            if any(c in cmd.lower() for c in cred_cmds):
                chain.append({
                    'stage': 'credential_access',
                    'command': cmd,
                    'mitre': 'T1003 (OS Credential Dumping)'
                })

        # 阶段 3: 工具下载
        dl_cmds = ['wget ', 'curl ', 'tftp', 'ftp ', 'scp']
        for cmd in commands:
            if any(d in cmd.lower() for d in dl_cmds):
                chain.append({
                    'stage': 'command_and_control',
                    'command': cmd,
                    'mitre': 'T1105 (Ingress Tool Transfer)'
                })

        return chain if chain else None

    def generate_threat_report(self):
        """生成威胁情报报告"""
        ips = self.extract_ips()
        hashes = self.extract_malware_hashes()
        domains = self.extract_domains()
        commands = self.extract_attack_commands()

        return {
            'report_time': datetime.now().isoformat(),
            'time_range': {
                'start': self.logs[0].get('timestamp') if self.logs else None,
                'end': self.logs[-1].get('timestamp') if self.logs else None
            },
            'summary': {
                'total_events': len(self.logs),
                'unique_ips': len(ips),
                'unique_hashes': len(hashes),
                'unique_domains': len(domains),
                'unique_sessions': len(commands),
            },
            'iocs': {
                'ips': ips[:20],
                'domains': domains[:20],
                'hashes': hashes,
            },
            'ttps': commands[:10],
            'top_attack_ip_countries': self._geo_enrich(ips[:10])
        }

    def _geo_enrich(self, ips):
        """GeoIP 富化"""
        # 实际使用 GeoLite2 数据库
        return [{'ip': ip['ip'], 'country': 'unknown', 'count': ip['count']}
                for ip in ips]
```

### 2.2 攻击者画像

```yaml
基于蜜罐数据的攻击者画像:

  脚本小子 (Script Kiddie):
    特征:
      - 使用公开扫描器 (Nmap, Masscan)
      - 尝试默认凭证
      - 命令: whoami, uname -a, cat /proc/cpuinfo
      - 使用已知的公共 Exploit
      置信度: 85%

  僵尸网络节点 (Botnet Node):
    特征:
      - 仅尝试 SSH/Telnet 连接
      - 不执行后续命令
      - 攻击频率高 (每秒多次)
      - 多个蜜罐同时被攻击
      置信度: 70%

  进阶攻击者:
    特征:
      - 少扫描多针对
      - 使用代理/Tor/VPN
      - 下载定制工具而非公开工具
      - 清理日志
      置信度: 60%
```

---

## 3. Kibana 仪表盘

```json
// Kibana 可视化: 攻击者地理位置热力图
{
  "visualization": {
    "title": "攻击者来源热力图",
    "visState": {
      "type": "tile_map",
      "aggs": [
        {
          "id": "1",
          "type": "count",
          "schema": "metric"
        },
        {
          "id": "2",
          "type": "geohash_grid",
          "schema": "segment",
          "params": {
            "field": "geo.coordinates",
            "precision": 3
          }
        }
      ]
    }
  }
}
```

```json
// Kibana 可视化: 攻击命令 Top 10
{
  "visualization": {
    "title": "攻击命令 Top 10",
    "visState": {
      "type": "horizontal_bar",
      "aggs": [
        {
          "id": "1",
          "type": "count",
          "schema": "metric"
        },
        {
          "id": "2",
          "type": "terms",
          "schema": "segment",
          "params": {
            "field": "input.keyword",
            "size": 10,
            "order": "desc",
            "orderBy": "1"
          }
        }
      ]
    }
  }
}
```

---

## 参考资源

- [T-Pot 数据分析](https://github.com/telekom-security/tpotce)
- [Cowrie 日志格式](https://cowrie.readthedocs.io/en/latest/#)
- [MISP 威胁情报共享](https://www.misp-project.org/)

---

*上一篇：[蜜罐网络部署实战](./02-honeynet-deployment.md)*

*下一篇：[蜜罐部署实战](04-honeypot-deployment.md)*

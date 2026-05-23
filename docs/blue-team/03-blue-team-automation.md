# 蓝队自动化防御

## 概述

蓝队的本质是用自动化对抗攻击者的自动化——攻击者用脚本扫描你的 65535 个端口，你用脚本自动阻断每一个可疑连接。本章介绍蓝队从"手动响应"到"自动化防御"的进化路径。

---

## 1. 自动化防御架构

```
自动化防御金字塔:

        ┌──────────────┐
        │  自动响应     │ ← 攻击→阻断 零人工
        ├──────────────┤
        │  行为分析     │ ← ML 检测异常
        ├──────────────┤
        │  规则引擎     │ ← SIEM/YARA/Suricata
        ├──────────────┤
        │  日志聚合     │ ← ELK/Wazuh/Splunk
        ├──────────────┤
        │  资产发现     │ ← Nmap/Shodan/Nessus
        └──────────────┘
```

---

## 2. 开源蓝队工具栈

| 工具 | 功能 | 部署 |
|------|------|------|
| **Wazuh** | HIDS + SIEM | Agent |
| **Suricata** | NIDS/IPS | 网络边界 |
| **Falco** | 容器运行时检测 | K8s DaemonSet |
| **Velociraptor** | 终端取证与响应 | Agent |
| **Sigma Rules** | 通用检测规则 | SIEM |
| **YARA** | 恶意软件特征 | 文件扫描 |
| **OSQuery** | SQL 查询终端 | Agent |
| **TheHive** | 安全事件响应平台 | Server |

---

## 3. Sigma 规则实践

### 3.1 编写 Sigma 规则

```yaml
# Sigma 规则: 可疑 PowerShell 编码命令
title: Suspicious Encoded PowerShell Command
id: 8e3c7bc0-4a9c-4b7e-bc7e-3e3c1a95f1aa
status: experimental
description: 检测 Base64 编码的 PowerShell 命令 (常见于无文件攻击)
author: Blue Team
date: 2024/01/15
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains: '-e'
    ScriptBlockText|re: '[A-Za-z0-9+/]{50,}[=]{0,2}'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - 合法的管理脚本使用编码命令
  - SCCM 包部署
```

### 3.2 多 SIEM 转换

```bash
# Sigma 规则转换为各 SIEM 格式

# Splunk
sigma convert -t splunk rules/windows/powershell_suspicious_encoded.yml

# Elasticsearch
sigma convert -t elastalert rules/windows/powershell_suspicious_encoded.yml

# Wazuh
sigma convert -t wazuh rules/windows/powershell_suspicious_encoded.yml

# Sentinel (KQL)
sigma convert -t sentinel rules/windows/powershell_suspicious_encoded.yml
```

---

## 4. Velociraptor 威胁狩猎

### 4.1 快速狩猎查询

```sql
-- Velociraptor VQL: 检测可疑进程连接

SELECT
    Name, Pid, CreateTime,
    Exe, CommandLine,
    AuthenticationId
FROM pslist()
WHERE
    Name IN ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe')
    AND CommandLine =~ '(?i)-enc|-e(nc)?oded|IEX|Invoke-Expression'
    AND CreateTime > timestamp(epoch=now() - 3600)
    -- 最近 1 小时
```

```sql
-- 检测持久化机制

SELECT
    Key.FullPath AS RegistryKey,
    ValueName, ValueData,
    Mtime AS ModifiedTime
FROM read_reg_key(
    globs='''HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\**'''
)
WHERE
    ValueData =~ '(?i)powershell|cmd|wscript|rundll32|mshta|certutil'
    OR ValueData =~ '(?i)%temp%|%appdata%|AppData|Users\\\\Public'
```

---

## 5. 事件响应自动化

```python
#!/usr/bin/env python3
"""
蓝队自动响应控制器
"""

import requests
import subprocess
import json
import time
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class Alert:
    severity: str
    source_ip: str
    target_host: str
    indicator: str
    technique: str

class BlueTeamAutoResponder:
    """
    蓝队自动响应 - 从检测到抑制的完整链条
    """

    def __init__(self, config_path='blueteam_config.json'):
        with open(config_path) as f:
            self.config = json.load(f)

    def process_alert(self, alert: Alert):
        """根据严重程度自动响应"""

        if alert.severity == 'CRITICAL':
            self._critical_response(alert)
        elif alert.severity == 'HIGH':
            self._high_response(alert)
        elif alert.severity == 'MEDIUM':
            self._medium_response(alert)
        else:
            self._log_only(alert)

    def _critical_response(self, alert: Alert):
        """关键告警 - 立即自动响应"""
        print(f"[CRITICAL] {alert.technique} from {alert.source_ip}")

        # 1. 隔离受影响主机
        self.isolate_host(alert.target_host)

        # 2. 阻断攻击 IP
        self.block_ip(alert.source_ip)

        # 3. 采集取证数据
        self.collect_forensics(alert.target_host)

        # 4. 通知 SOC 团队
        self.notify_soc(alert)

        # 5. 创建事件工单
        self.create_incident(alert)

    def _high_response(self, alert: Alert):
        """高严重性 - 自动响应 + 人工确认"""
        print(f"[HIGH] {alert.technique} from {alert.source_ip}")

        self.block_ip(alert.source_ip, duration_hours=8)
        self.notify_soc(alert)

    def _medium_response(self, alert: Alert):
        """中严重性 - 记录 + 监控"""
        self.add_to_watchlist(alert.source_ip)
        self.enhance_logging(alert.target_host)

    def _log_only(self, alert: Alert):
        """低严重性 - 仅记录"""
        pass

    def isolate_host(self, hostname: str):
        """隔离主机"""
        # Velociraptor 客户端隔离
        subprocess.run([
            'velociraptor', 'client', 'command', hostname,
            '--command', 'isolate'
        ])

    def block_ip(self, ip: str, duration_hours: int = 24):
        """阻断 IP"""
        subprocess.run([
            'iptables', '-I', 'INPUT', '1',
            '-s', ip, '-j', 'DROP',
            '-m', 'comment', '--comment', f'AUTO_BLOCK_{int(time.time())}'
        ])

    def collect_forensics(self, hostname: str):
        """收集取证数据"""
        subprocess.run([
            'velociraptor', 'artifact', 'collect',
            'Windows.Forensics.Prefetch',
            '--client', hostname
        ])

    def notify_soc(self, alert: Alert):
        """通知 SOC"""
        requests.post(self.config['slack_webhook'], json={
            'text': f'🚨 自动响应: {alert.technique}\n'
                   f'IP: {alert.source_ip}\n主机: {alert.target_host}\n'
                   f'指标: {alert.indicator}'
        })

    def create_incident(self, alert: Alert):
        """创建工单"""
        requests.post(f"{self.config['thehive_url']}/api/case", json={
            'title': f'[{alert.severity}] {alert.technique}',
            'description': f'Source: {alert.source_ip}\n'
                          f'Target: {alert.target_host}\n'
                          f'Indicator: {alert.indicator}'
        })
```

---

## 参考资源

- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Velociraptor](https://docs.velociraptor.app/)
- [TheHive](https://thehive-project.org/)

---

*上一篇：[蓝队防御运营](02-blue-team-ops.md)*

*下一篇：[数字取证与事件响应（DFIR）](03-dfir.md)*

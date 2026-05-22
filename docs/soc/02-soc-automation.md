# SOC 自动化响应 (SOAR)

## 概述

SOAR (Security Orchestration, Automation and Response) 将 SOC 从"手动看告警"升级为"机器自动处理"。平均一个 Tier 1 分析师只能处理 8-12 个告警/天，SOAR 可以将 60-80% 的告警自动化处理，让分析师专注于真正的威胁。

---

## 1. SOAR 核心能力

### 1.1 SOAR 三要素

```
SOAR = Orchestration + Automation + Response

    Orchestration (编排):
      连接分散的安全工具
      SIEM ←→ EDR ←→ 威胁情报 ←→ 工单系统
      统一控制平面

    Automation (自动化):
      重复任务无需人工干预
      告警分类 → 富化 → 决策 → 响应
      剧本 (Playbook) 驱动

    Response (响应):
      自动隔离主机/禁用账户/阻断 IP
      自动创建工单并分派
      自动通知相关团队
```

### 1.2 常见 SOAR 平台

| 平台 | 类型 | 优势 | 价格 |
|------|------|------|------|
| **Splunk SOAR (Phantom)** | 商业 | 成熟、社区大 | $$$$ |
| **Palo Alto XSOAR** | 商业 | 剧本丰富 | $$$$ |
| **Microsoft Sentinel** | 商业 | Azure 原生 | $$$ |
| **Shuffle** | 开源 | 纯图形化 | Free |
| **n8n** | 开源 | 通用自动化 | Free |
| **StackStorm** | 开源 | 代码驱动 | Free |

---

## 2. Shuffle SOAR

### 2.1 图形化剧本设计

```yaml
# Shuffle SOAR 剧本: 恶意 IP 自动响应

workflow: "malicious_ip_auto_response"
trigger: "SIEM 告警 (恶意 IP 检测)"

app_version: "1.0.0"

actions:
  # Step 1: 接收 SIEM 告警
  - id: "receive_alert"
    app: "Shuffle Tools"
    name: "receive_webhook"
    parameters:
      webhook: "$webhook"
    # → 解析告警: { "src_ip": "45.XX.XX.XX", "alert_type": "brute_force" }

  # Step 2: 富化 IP (威胁情报)
  - id: "enrich_ip"
    app: "VirusTotal"
    name: "get_ip_report"
    parameters:
      ip: "$receive_alert.src_ip"

  # Step 3: 判断 (条件分支)
  - id: "decision"
    app: "Shuffle Tools"
    name: "conditional"
    parameters:
      conditions:
        - condition: "$enrich_ip.malicious > 0"
          # 恶意 IP → 进入响应流程
          branch: "block_ip"

        - condition: "$enrich_ip.suspicious > 0"
          # 可疑 IP → 创建工单人工审核
          branch: "create_ticket"

        - default:
          # 未知 IP → 记录后关闭
          branch: "close_alert"

  # Step 4: 阻断恶意 IP
  - id: "block_ip"
    app: "Cloudflare"
    name: "add_firewall_rule"
    parameters:
      ip: "$receive_alert.src_ip"
      action: "block"
      reason: "SIEM detected malicious activity"

  # Step 5: EDR 隔离主机
  - id: "isolate_host"
    app: "CrowdStrike"
    name: "contain_host"
    parameters:
      hostname: "$receive_alert.hostname"
      reason: "Connected to known malicious IP"

  # Step 6: 通知 Slack
  - id: "slack_notify"
    app: "Slack"
    name: "send_message"
    parameters:
      channel: "#soc-alerts"
      message: |
        🚨 已自动响应恶意 IP:
        IP: $receive_alert.src_ip
        主机: $receive_alert.hostname
        动作: 阻断 + 隔离
        威胁情报: $enrich_ip.detected_urls

  # Step 7: 创建工单
  - id: "create_ticket"
    app: "Jira"
    name: "create_issue"
    parameters:
      project: "SEC"
      issue_type: "Incident"
      priority: "$enrich_ip.malicious > 5 ? 'Critical' : 'High'"
      summary: "恶意 IP 检测: $receive_alert.src_ip"
      description: |
        IP: $receive_alert.src_ip
        告警类型: $receive_alert.alert_type
        威胁情报报告: $enrich_ip.permalink
        已执行动作:
        - Cloudflare 阻断
        - CrowdStrike 隔离
        - $receive_alert.hostname
```

### 2.2 自动邮件分析剧本

```json
// Shuffle 邮件分析工作流配置

{
  "workflow_name": "email_phishing_analysis",
  "trigger": "用户转发可疑邮件到 soc@company.com",

  "actions": [
    {
      "name": "parse_email",
      "app": "IMAP",
      "action": "get_email",
      "parameters": {
        "folder": "INBOX",
        "from": "soc@company.com",
        "unseen": true
      }
    },

    {
      "name": "extract_artifacts",
      "app": "Shuffle Tools",
      "action": "regex_extract",
      "parameters": {
        "text": "$parse_email.body",
        "extract": {
          "urls": "https?://[^\\s]+",
          "headers": "Received:.*",
          "attachments": "filename=\"([^\"]+)\""
        }
      }
    },

    {
      "name": "check_urls",
      "app": "urlscan.io",
      "action": "scan_url",
      "parameters": {
        "urls": "$extract_artifacts.urls",
        "private": true
      }
    },

    {
      "name": "detonate_attachment",
      "app": "ANY.RUN",
      "action": "submit_file",
      "parameters": {
        "file": "$extract_artifacts.attachments",
        "env_type": "win10_office",
        "timeout": 180
      }
    },

    {
      "name": "decide_action",
      "app": "Shuffle Tools",
      "action": "conditional",
      "parameters": {
        "condition": "$check_urls.malicious > 0 || $detonate_attachment.malicious",
        "true_branch": "alert_and_delete",
        "false_branch": "safe_notify"
      }
    },

    {
      "name": "alert_and_delete",
      "app": "Microsoft Graph",
      "action": "search_and_delete_email",
      "parameters": {
        "subject": "$parse_email.subject",
        "delete_from_all_mailboxes": true,
        "notify_users": true
      }
    }
  ]
}
```

---

## 3. 自定义自动化脚本

### 3.1 Python SOC 自动化

```python
#!/usr/bin/env python3
"""
SOC 自动化响应脚本
集成多个安全工具
"""

import requests
import json
import subprocess
from datetime import datetime
from typing import Optional, Dict

class SOCAutomation:
    """SOC 自动化响应"""

    def __init__(self, config_path='soc_config.json'):
        with open(config_path) as f:
            self.config = json.load(f)

        self.firewall_url = self.config['firewall_api']
        self.edr_url = self.config['edr_api']
        self.ad_url = self.config['ad_ldap']
        self.slack_webhook = self.config['slack_webhook']

    def block_ip(self, ip: str, reason: str, duration_hours: int = 24):
        """阻断 IP — 调用防火墙 API"""

        response = requests.post(
            f'{self.firewall_url}/block/ip',
            headers={'Authorization': f'Bearer {self.config["fw_token"]}'},
            json={
                'ip': ip,
                'reason': reason,
                'expires_in': duration_hours * 3600,
                'source': 'SOC_AUTOMATION',
                'ticket_ref': f'SOC-{datetime.now().strftime("%Y%m%d")}-001'
            }
        )

        if response.ok:
            self._log('BLOCK_IP', f'{ip} 已阻断 ({duration_hours}h): {reason}')
            self.slack_notify(
                f'🚫 IP {ip} 已自动阻断\n原因: {reason}'
            )

    def isolate_host(self, hostname: str, reason: str):
        """隔离主机 — 调用 EDR API"""

        # 1. 查找主机 ID
        devices = requests.get(
            f'{self.edr_url}/devices',
            params={'hostname': hostname},
            headers={'Authorization': f'Bearer {self.config["edr_token"]}'}
        ).json()

        if not devices:
            self._log('ERROR', f'主机 {hostname} 未找到')
            return

        device_id = devices[0]['id']

        # 2. 执行隔离
        response = requests.post(
            f'{self.edr_url}/devices/{device_id}/isolate',
            json={
                'comment': reason,
                'isolation_type': 'full'  # 完全隔离 (断开网络)
            }
        )

        if response.ok:
            self._log('ISOLATE_HOST', f'{hostname} 已隔离: {reason}')
            self.slack_notify(
                f'🔒 主机 {hostname} 已自动隔离\n原因: {reason}'
            )

    def disable_user(self, username: str, reason: str):
        """禁用用户 — AD 操作"""

        result = subprocess.run([
            'powershell',
            '-Command',
            f'Disable-ADAccount -Identity {username} '
            f'-Description "{reason} — SOC Automated Response"'
        ], capture_output=True)

        if result.returncode == 0:
            self._log('DISABLE_USER', f'{username} 已禁用: {reason}')

            # 吊销所有会话
            subprocess.run([
                'powershell',
                '-Command',
                f'Revoke-AzureADUserAllRefreshToken -ObjectId {username}'
            ])

            # 强制断开 RDP 会话
            subprocess.run([
                'powershell',
                '-Command',
                f'Get-WmiObject Win32_Service -ComputerName * | '
                f'Where-Object {{$_.StartName -eq {username}}} | '
                f'ForEach-Object {{$_.StopService()}}'
            ])

            self.slack_notify(
                f'👤 用户 {username} 已禁用\n原因: {reason}'
            )

    def slack_notify(self, message: str):
        """发送 Slack 通知"""

        requests.post(self.slack_webhook, json={
            'text': message,
            'channel': self.config['slack_channel'],
            'username': 'SOC Bot',
            'icon_emoji': ':robot_face:'
        })

    def _log(self, action: str, message: str):
        """记录操作日志"""
        print(f"[{datetime.now().isoformat()}] {action}: {message}")


# 使用示例
soc = SOCAutomation('soc_config.json')

# 场景 1: CrowdStrike 检测到可疑进程 → 自动响应
soc.isolate_host(
    hostname='FINANCE-DESKTOP-025',
    reason='CrowdStrike: 检测到 ransomware_encryption_pattern'
)

# 场景 2: Okta 检测到异常登录 → 自动响应
soc.disable_user(
    username='john.doe',
    reason='Okta: 不可能旅行检测 (北京→纽约 5分钟)'
)

# 场景 3: SIEM 检测到 C2 通信 → 自动响应
soc.block_ip(
    ip='185.130.XX.XX',
    reason='SIEM: Cobalt Strike Beacon 通信 (端口 443, JA3: abc123)'
)
```

---

## 参考资源

- [Shuffle SOAR](https://shuffler.io/)
- [StackStorm](https://stackstorm.com/)
- [n8n 工作流自动化](https://n8n.io/)

---

*上一篇：[安全运营中心建设](./01-soc-building.md)*
*下一篇：[SIEM 规则优化](./03-siem-rules.md)*

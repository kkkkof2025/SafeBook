# SOC 自动化与 SOAR 实战

## 概述

SOC Tier 1 分析师 80% 的时间在做重复性任务——告警分类、误报过滤、富化上下文。SOAR（安全编排自动化与响应）将这些工作自动化，让分析师聚焦真正需要人类判断的事件。

---

## 1. SOAR 核心能力

```
SOAR 五大支柱:

  编排 (Orchestration)
    → 连接安全工具 (SIEM/EDR/防火墙/威胁情报)
    → 统一 API 互通

  自动化 (Automation)
    → 告警分类、误报过滤
    → IOC 富化、上下文补充
    → 自动响应 (隔离主机/禁用账户)

  事件响应 (Incident Response)
    → 应急响应手册 (Playbook)
    → 自动化调查步骤
    → 人工决策点 (Human-in-the-Loop)

  案例管理 (Case Management)
    → 自动创建工单
    → 证据关联
    → 时间线构建

  报告与指标 (Reporting)
    → MTTD/MTTR 跟踪
    → SOC KPI 仪表板
```

---

## 2. SOAR Playbook 设计

### 2.1 钓鱼邮件自动化

```yaml
# 钓鱼邮件 SOAR Playbook

name: Phishing Email Triage
trigger:
  type: email_alert
  conditions:
    - alert_type == "phishing"
    - confidence >= "medium"

steps:
  # Step 1: 提取 IOCs
  - name: extract_iocs
    action: extract_indicators
    source: "{{ alert.email_body }}"
    types: [url, domain, ip, attachment_hash]
    output: iocs

  # Step 2: 提交到沙箱
  - name: sandbox_analysis
    action: submit_to_sandbox
    target: "{{ alert.attachment }}"
    sandbox: "Joe Sandbox"
    timeout: 300
    output: sandbox_result

  # Step 3: 威胁情报富化
  - name: enrich_iocs
    action: threat_intel_lookup
    sources:
      - VirusTotal
      - AlienVault OTX
      - Abuse.ch
    iocs: "{{ steps.extract_iocs.output }}"
    output: enrichment

  # Step 4: 判断
  - name: verdict
    condition: >
      {{ steps.sandbox_result.output.malicious }} or
      {{ steps.enrichment.output.malicious_count }} > 2
    branches:
      true:
        # 自动响应链
        - action: create_case
          title: "Phishing Incident: {{ alert.subject }}"
          severity: "{{ 'critical' if steps.sandbox_result.output.malicious else 'high' }}"

        - action: delete_email
          target: "{{ alert.message_id }}"
          scope: "all_recipients"

        - action: block_iocs
          targets: "{{ steps.enrichment.output.malicious_iocs }}"
          platforms: [firewall, proxy, edr]

        - action: notify_user
          user: "{{ alert.recipient }}"
          template: "phishing_warning"

        - action: assign_analyst
          tier: 2
          reason: "Phishing confirmed, check for lateral movement"

      false:
        - action: close_alert
          reason: "Legitimate email"
```

### 2.2 暴力破解响应

```python
class BruteForcePlaybook:
    """暴力破解自动化响应"""

    def __init__(self, soar_client):
        self.soar = soar_client

    def execute(self, alert):
        """执行暴力破解 Playbook"""

        case = self.soar.create_case(
            title=f"Brute Force: {alert['target']}",
            severity="high",
            source=alert
        )

        # Step 1: 识别来源
        source_ip = alert['source_ip']
        target_account = alert['target_user']

        # 2. 威胁情报查询
        intel = self.soar.threat_intel_lookup(source_ip)
        if intel.get('malicious', False):
            case.add_finding("Source IP is known malicious")

        # 3. 计算失败率
        auth_logs = self.soar.query_logs(
            query=f"EventID=4625 AND IpAddress='{source_ip}'",
            last_hours=1
        )
        failure_count = len(auth_logs)

        # 4. 自动响应 (条件判断)
        if failure_count > 100:
            # 高风险: 自动阻断 + 禁用账户
            self.soar.block_ip(source_ip, duration_hours=24)
            self.soar.disable_account(target_account, reason="Brute force attack")
            case.set_status("contained")

            # 通知 (无需人工批准)
            self.soar.notify_team(
                channel="incident-response",
                message=f"Auto-blocked {source_ip} ({failure_count} failures against {target_account})"
            )
        elif failure_count > 20:
            # 中风险: 自动阻断 + 人工审核
            self.soar.block_ip(source_ip, duration_hours=1)
            case.assign_analyst(tier=2)
            case.add_note("Medium confidence brute force, analyst review required")
        else:
            # 低风险: 仅监控
            case.set_status("monitoring")
            case.add_note("Low confidence brute force, monitoring")

        return case.id
```

---

## 3. SIEM + SOAR 集成

### 3.1 Splunk Phantom 集成

```python
# Splunk ES → Phantom SOAR 集成

import phantom.rules as phantom
import json

def on_poll(action_result, container_id):
    """从 Splunk 拉取告警"""

    # 1. 查询 Splunk 显著事件
    url = phantom.build_phantom_rest_url('splunk', 'query')
    params = {
        'search': 'search index=main sourcetype=WinEventLog EventID=4625 | head 50',
        'earliest_time': '-15m'
    }

    data = phantom.requests.get(url, params=params).json()

    for event in data.get('results', []):
        # 2. 创建 Phantom Container
        container = {
            'name': f"Failed Login — {event.get('Account_Name')}",
            'description': json.dumps(event, indent=2),
            'source_data_identifier': event['_bkt'],
            'label': 'events',
            'severity': 'medium',
            'artifacts': [{
                'name': 'event',
                'container_id': container_id,
                'label': 'event',
                'source_data_identifier': event['_raw'][:100],
                'cef': {
                    'sourceAddress': event.get('IpAddress'),
                    'sourceUserName': event.get('Account_Name'),
                    'deviceCustomString1': event.get('Workstation_Name')
                }
            }]
        }

        phantom.requests.post(
            phantom.build_phantom_rest_url('container'),
            json=container
        )

    return phantom.APP_SUCCESS
```

### 3.2 Shuffle SOAR (开源)

```json
{
  "name": "Brute Force Auto-Response",
  "start": "Webhook",
  "nodes": [
    {
      "id": "webhook",
      "app": "Webhook",
      "label": "SIEM Alert Webhook",
      "parameters": {
        "method": "POST",
        "type": "json"
      }
    },
    {
      "id": "filter_high_severity",
      "app": "Builtin",
      "label": "Filter High Severity",
      "parameters": {
        "condition": "$severity == 'critical' or $failure_count > 50"
      },
      "position": {"x": 300, "y": 100}
    },
    {
      "id": "virustotal_lookup",
      "app": "VirusTotal",
      "label": "IP Reputation Check",
      "parameters": {
        "apikey": "{{ vault_vt_key }}",
        "ip": "{{ $source_ip }}"
      },
      "position": {"x": 600, "y": 100}
    },
    {
      "id": "block_ip_paloalto",
      "app": "Palo Alto Firewall",
      "label": "Block Source IP",
      "parameters": {
        "ip": "{{ $source_ip }}",
        "duration": "3600",
        "tag": "soar-auto-block"
      },
      "position": {"x": 600, "y": 300}
    },
    {
      "id": "disable_user_ad",
      "app": "Active Directory",
      "label": "Disable Account",
      "parameters": {
        "username": "{{ $target_user }}",
        "action": "disable"
      },
      "position": {"x": 600, "y": 500}
    },
    {
      "id": "create_ticket",
      "app": "Jira",
      "label": "Create Incident Ticket",
      "parameters": {
        "project": "SEC",
        "issue_type": "Incident",
        "summary": "Auto-blocked brute force from {{ $source_ip }}"
      },
      "position": {"x": 900, "y": 100}
    }
  ]
}
```

---

## 4. SOC 自动化度量

```python
class SOCMetrics:
    """SOC 自动化效果度量"""

    def __init__(self):
        self.baseline = None

    def set_baseline(self, pre_soar_data):
        """设置自动化前基线"""
        self.baseline = pre_soar_data

    def calculate_roi(self, post_soar_data):
        """计算自动化 ROI"""

        metrics = {}

        # Time to Detect (TTD)
        if self.baseline:
            ttd_before = self.baseline.get('avg_ttd_minutes', 240)
            ttd_after = post_soar_data.get('avg_ttd_minutes', 60)
            metrics['ttd_reduction_pct'] = (
                (ttd_before - ttd_after) / ttd_before * 100
            )

        # Time to Respond (MTTR)
        if self.baseline:
            mttr_before = self.baseline.get('avg_mttr_minutes', 360)
            mttr_after = post_soar_data.get('avg_mttr_minutes', 90)
            metrics['mttr_reduction_pct'] = (
                (mttr_before - mttr_after) / mttr_before * 100
            )

        # 自动化率
        total_alerts = post_soar_data.get('total_alerts', 1000)
        automated = post_soar_data.get('auto_closed', 0)
        metrics['automation_rate_pct'] = (
            automated / total_alerts * 100 if total_alerts else 0
        )

        # 分析师时间节省
        avg_time_per_alert = 15  # minutes
        hours_saved = (
            automated * avg_time_per_alert / 60
        )
        metrics['analyst_hours_saved_per_day'] = hours_saved

        return metrics
```

---

## 参考资源

- [Shuffle SOAR (开源)](https://shuffler.io/)
- [Splunk Phantom](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html)
- [SOC Automation — The DFIR Report](https://thedfirreport.com/)

---

*上一篇：[SIEM 规则引擎](03-siem-rules.md)*

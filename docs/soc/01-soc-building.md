# 安全运营中心建设

## 概述

安全运营中心 (SOC) 是企业安全防御的指挥中枢——7x24 监控、检测、响应安全事件。Ponemon 2024 报告显示，有成熟 SOC 的企业平均 MTTR 从 280 天降至 66 天，数据泄露成本降低 $2.66M。

---

## 1. SOC 成熟度模型

### 1.1 SOC 四阶段

```
Level 1 → Level 2 → Level 3 → Level 4
被动监控  主动检测  威胁狩猎  自适应安全

L1 被动 (0-6月):
  - 收集日志并查看
  - 基于签名的规则告警
  - 人工分类和响应
  - 工具: Splunk/ELK 基础版

L2 主动 (6-24月):
  - SIEM 规则 + 关联分析
  - SOAR 自动化剧本
  - 威胁情报集成
  - 每日威胁狩猎

L3 威胁狩猎 (2-5年):
  - MITRE ATT&CK 覆盖
  - 自定义检测规则
  - 红蓝对抗演练
  - 攻击路径可视化

L4 自适应 (>5年):
  - AI/ML 驱动检测
  - 自动化响应 (零人工干预)
  - 攻击面持续管理
  - 安全数据湖分析
```

### 1.2 团队结构与分工

```yaml
SOC 三层团队模型:
  
  Tier 1 — 安全分析师 (Security Analyst):
    编制: 4-6 人 (每班次 1-2 人)
    职责:
      - 7x24 监控 SIEM 告警
      - 初始分类和验证
      - 低风险事件处理
      - 升级 T2
    技能: Security+, SIEM 基础操作
    工具: SIEM Dashboard, 告警平台

  Tier 2 — 安全事件响应 (Incident Responder):
    编制: 2-4 人
    职责:
      - 深度调查 T1 升级的事故
      - 取证分析 (内存/磁盘/网络)
      - 攻击溯源和影响评估
      - 抑制/根除/恢复
    技能: GCIH, GCFA, 数字取证
    工具: EDR, 取证平台, 威胁情报

  Tier 3 — 安全专家 (Security Expert):
    编制: 1-2 人
    职责:
      - 复杂事件调查
      - 0-day/APT 分析
      - 检测规则开发
      - 威胁狩猎
    技能: OSCP, GREM, 逆向工程
    工具: 沙箱, IDA Pro, Pyramid of Pain

  支持角色:
    - SOC 经理: 管理、KPI、流程优化
    - 威胁情报分析师: CTI 生产、IOC 消费
    - 安全工程师: 工具部署、自动化开发
```

---

## 2. SIEM 选型与部署

### 2.1 主流 SIEM 对比

| 平台 | 类型 | 部署 | 成本 | 适合规模 |
|------|------|------|------|----------|
| **Splunk** | 商业 | 混合/云 | $$$$ | 大型企业 |
| **Elastic (ELK)** | 开源+商业 | 混合/云 | $$ | 中大型 |
| **Wazuh** | 开源 | 本地 | $ | 小型 |
| **Microsoft Sentinel** | 商业 | 云原生 | $$$ | Azure 环境 |
| **QRadar** | 商业 | 混合 | $$$$ | 大型企业 |
| **Graylog** | 开源 | 本地/云 | $ | 中型 |

### 2.2 Wazuh 快速部署

```yaml
# docker-compose.yml - Wazuh 单节点部署

version: '3.7'

services:
  wazuh.manager:
    image: wazuh/wazuh-manager:4.7.4
    hostname: wazuh.manager
    restart: always
    ports:
      - "1514:1514/udp"  # Agent 通信
      - "1515:1515"      # 注册服务
      - "514:514/udp"    # Syslog
    volumes:
      - wazuh_api_configuration:/var/ossec/api/configuration
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
    environment:
      - INDEXER_URL=https://wazuh.indexer:9200
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword

  wazuh.indexer:
    image: wazuh/wazuh-indexer:4.7.4
    hostname: wazuh.indexer
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"

  wazuh.dashboard:
    image: wazuh/wazuh-dashboard:4.7.4
    hostname: wazuh.dashboard
    ports:
      - "443:5601"
    environment:
      - INDEXER_USERNAME=admin
      - INDEXER_PASSWORD=SecretPassword
      - WAZUH_API_URL=https://wazuh.manager
```

### 2.3 关键检测规则

```xml
<!-- Wazuh 检测规则示例 -->
<group name="attack_detection">

  <!-- 暴力破解检测 -->
  <rule id="100001" level="10" frequency="5" timeframe="60">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>暴力破解: 同一 IP 60 秒内 5 次登录失败</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>brute_force,authentication_failed,</group>
  </rule>

  <!-- Mimikatz 检测 (Windows Event 4663) -->
  <rule id="100002" level="12">
    <if_sid>60103</if_sid>
    <field name="win.eventdata.objectName">\Device\VBox</field>
    <description>可能的 Mimikatz LSASS 内存访问</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <!-- PowerShell 编码命令检测 -->
  <rule id="100003" level="10">
    <if_sid>60001</if_sid>
    <field name="win.eventdata.commandLine" negate="yes" type="pcre2">-e(nc|nco)?\s+[A-Za-z0-9+/=]{100,}</field>
    <description>PowerShell 编码命令执行 — 可能是无文件攻击</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- Cobalt Strike Beacon 检测 -->
  <rule id="100004" level="12">
    <if_sid>100210</if_sid>
    <field name="data.win.eventdata.destinationIp" type="pcre2">^(185\.|91\.|45\.).+</field>
    <field name="data.dst_port">^(443|8443|8080|80|53)$</field>
    <description>可能的 Cobalt Strike C2 通信 (活动周期 + 可疑端口)</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>

</group>
```

---

## 3. SOAR 自动化

### 3.1 自动响应剧本

```yaml
# SOAR Playbook: 钓鱼邮件自动响应

playbook: "phishing_auto_response"
trigger: "User reports suspicious email OR EDR detects malicious attachment"

steps:
  1_pull_email:
    action: "graph_api.get_message"
    params:
      user: "{{ event.reporter }}"
      subject: "{{ event.subject }}"

  2_analyze_attachment:
    action: "sandbox.submit_sample"
    params:
      file: "{{ pulled_email.attachments }}"
      profile: "win10_office"
    on_failure: "skip"

  3_check_urls:
    action: "urlscan.io_scan"
    params:
      urls: "{{ pulled_email.extracted_urls }}"

  4_ioc_lookup:
    action: "virustotal.query"
    params:
      hashes: "{{ sandbox_result.hashes }}"
      urls: "{{ urlscan_result.flagged_urls }}"

  5_decision:
    condition:
      - if: "sandbox_result.malicious == true"
        then:
          - action: "email.delete_from_inbox"
            scope: "{{ affected_users }}"
          - action: "edr.isolate_host"
            targets: "{{ affected_endpoints }}"
          - action: "ticket.create"
            priority: "CRITICAL"
            assignee: "SOC T2"
          - action: "slack.notify"
            channel: "#soc-alerts"
            message: "🚨 恶意钓鱼邮件检测 — 已自动隔离 {{ affected_count }} 台主机"

      - if: "virustotal_result.suspicious > 0"
        then:
          - action: "email.move_to_quarantine"
          - action: "ticket.create"
            priority: "HIGH"
          - action: "slack.notify"
            channel: "#soc-alerts"

      - default:
          - action: "ticket.create"
            priority: "LOW"
            assignee: "T1 Queue"

  optional_6_threat_hunt:
    condition: "sandbox_result.malicious == true"
    action: "threat_hunt.search"
    params:
      query: "FindAll{{
        sandbox_result.iocs.domains +
        sandbox_result.iocs.hashes
      }}"
      time_range: "14d"
```

### 3.2 自动化指标

```python
class SOCMetrics:
    """SOC 运营指标计算"""

    def __init__(self):
        self.tickets = []  # 事件工单数据库

    def calculate_mttr(self):
        """平均修复时间 (Mean Time to Remediate)"""
        closed = [t for t in self.tickets if t['status'] == 'closed']
        if not closed:
            return 0

        total_remediation = sum(
            (datetime.fromisoformat(t['closed_at']) -
             datetime.fromisoformat(t['created_at'])).total_seconds() / 3600
            for t in closed
        )
        return total_remediation / len(closed)

    def calculate_mttd(self):
        """平均检测时间 (Mean Time to Detect)

        目标: < 1 小时 (CISA BOD 22-01)
        """
        detected = [t for t in self.tickets
                    if t.get('first_detected') and t.get('incident_start')]

        total_detection = sum(
            (datetime.fromisoformat(t['first_detected']) -
             datetime.fromisoformat(t['incident_start'])).total_seconds() / 3600
            for t in detected
        )
        return total_detection / len(detected)

    def calculate_false_positive_rate(self):
        """误报率 — 目标 < 5%"""
        fp = sum(1 for t in self.tickets if t['resolution'] == 'false_positive')
        total = len(self.tickets)
        return fp / total if total > 0 else 0

    def calculate_automation_rate(self):
        """自动化率 — 目标 > 60%"""
        automated = sum(1 for t in self.tickets if t.get('automated_resolution'))
        return automated / len(self.tickets) if self.tickets else 0

    def soc_health_report(self):
        return {
            'MTTD (hours)': round(self.calculate_mttd(), 1),
            'MTTR (hours)': round(self.calculate_mttr(), 1),
            'False Positive Rate': f"{self.calculate_false_positive_rate()*100:.1f}%",
            'Automation Rate': f"{self.calculate_automation_rate()*100:.1f}%",
            'Open Tickets': sum(1 for t in self.tickets if t['status'] == 'open'),
            'Tickets (Last 30d)': sum(1 for t in self.tickets
                                       if t['created_at'] > thirty_days_ago),
        }
```

---

## 4. 威胁狩猎

```yaml
威胁狩猎流程:

  1. 假设 (Hypothesis):
    - "攻击者可能在利用 Log4Shell 变种在横向移动"
    - "某 APT 组织常用的 PowerShell 混淆模式"
    - "异常的数据外传模式 (DNS/UDP/ICMP)"

  2. 数据收集:
    - EDR 终端日志 (进程树/网络连接/文件活动)
    - 网络流量 (NetFlow/DNS/代理日志)
    - 认证日志 (AD/Domain Controller)
    - 云日志 (AWS CloudTrail/Azure Monitor)

  3. 分析技术:
    - Stack counting (频率异常)
    - Stacking (组合分析)
    - Clustering (聚类发现异常)
    - Frequency analysis (时间序列)

  4. 发现 → 规则:
    - 如果发现新型攻击 → 创建 SIEM 检测规则
    - 更新 MITRE ATT&CK 覆盖矩阵
    - 分享给社区 (ISAC/CERT)
```

---

## 参考资源

- [MITRE ATT&CK SOC 评估](https://attack.mitre.org/resources/soc/)
- [NIST SP 800-61 - 事件响应指南](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)

---

*下一篇：[SOC 自动化响应](./02-soc-automation.md)*

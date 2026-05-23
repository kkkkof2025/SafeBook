# SIEM 与安全监控实战

## SIEM 架构全景

```
日志源         采集层          处理层          存储层         分析层         展示层
┌──────┐     ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌──────┐
│ 服务器 │────→│ Agent   │───→│ Kafka   │───→│  ES/OS  │───→│ 规则引擎 │───→│ 仪表盘│
│ 网络设备│    │ Beats   │    │         │    │         │    │ ML检测  │    │     │
│ 安全设备│    │ Logstash│    │         │    │         │    │ 关联分析 │    │     │
│ 云服务  │    │ Fluentd │    │         │    │         │    │ 威胁情报 │    │     │
└──────┘     └─────────┘    └─────────┘    └─────────┘    └────┬────┘    └──────┘
                                                              ↓
                                                        ┌──────────┐
                                                        │  告警    │──→ 邮件/Slack/
                                                        │  工单    │    PagerDuty/SOAR
                                                        └──────────┘
```

---

## 主要 SIEM 平台对比

| 平台 | 类型 | 许可 | 适用规模 | 中文支持 |
|------|------|------|---------|---------|
| Wazuh | 开源 | 免费 (GPL) | 中小企业 | ✅ |
| Elastic Security | 开源+商业 | 免费(基础)+订阅 | 全规模 | ✅ |
| Splunk Enterprise | 商业 | $/GB/天 | 大企业 | ✅ |
| Microsoft Sentinel | 云原生 | $/GB | Azure 用户 | ✅ |
| QRadar | 商业 | 许可制 | 大企业 | 有限 |
| 奇安信天眼 | 国产 | 许可制 | 中国政企 | ✅ |
| 深信服 SIP | 国产 | 许可制 | 中国企业 | ✅ |

---

## 关键检测规则

### 1. Windows 攻击检测
```xml
<!-- Splunk: Pass-the-Hash 检测 -->
index=windows EventCode=4624 LogonType=3
| stats count by Account_Name, Workstation_Name, Source_Network_Address
| where count > 1
| rename Account_Name as "账户" Workstation_Name as "工作站"

<!-- Wazuh: Mimikatz 检测 -->
<rule id="100002" level="12">
  <if_sid>500</if_sid>
  <match>mimikatz|sekurlsa::logonpasswords|lsadump::sam</match>
  <description>Mimikatz credential dumping detected</description>
</rule>
```

### 2. Linux 攻击检测
```python
# Falco 规则: 容器内 Shell 启动
- rule: Container Shell
  desc: 检测容器内启动 Shell
  condition: >
    container.id != host and
    proc.name in (bash, sh, zsh) and
    proc.args contains "/bin" and
    container.image.repository not in (allowed_images)
  output: "Shell opened in container (user=%user.name)"
  priority: WARNING

# 检测权限提升
- rule: Sudo Privilege Escalation
  condition: >
    evt.type = execve and
    proc.name = sudo and
    user.uid != 0
  output: "Sudo execution by non-root user %user.name"
```

### 3. 数据外泄检测
```python
# DNS 隧道检测 (高熵值长域名)
import math
from collections import Counter

def shannon_entropy(data):
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    return -sum((count/length) * math.log2(count/length)
                for count in counter.values())

def detect_dns_tunnel(dns_query):
    domain = dns_query.split('.')[0]
    if len(domain) > 40 and shannon_entropy(domain) > 4.5:
        return {
            'alert': 'Possible DNS tunneling',
            'query': dns_query,
            'entropy': shannon_entropy(domain),
            'severity': 'HIGH'
        }
    return None

# 流量基线异常检测
class TrafficBaseline:
    def __init__(self, window_hours=24):
        self.history = []  # [(timestamp, bytes_out)]

    def is_anomaly(self, current_bytes):
        if len(self.history) < 24:  # 至少 24 个数据点
            return False
        avg = sum(b for _, b in self.history) / len(self.history)
        std = math.sqrt(sum((b-avg)**2 for _, b in self.history) / len(self.history))
        # 3-sigma 规则
        if current_bytes > avg + 3 * std:
            return True, f"{current_bytes} bytes (baseline avg={avg:.0f} ±{std:.0f})"
        return False, None
```

---

## SOAR 自动化响应

```python
# 告警 → 自动响应 Playbook
class IncidentPlaybook:
    def handle_bruteforce(self, alert):
        """暴力破解自动响应"""
        src_ip = alert['src_ip']

        # 1. 查询威胁情报
        threat_intel = self.lookup_ip(src_ip)
        if threat_intel['malicious']:
            # 2. 自动封禁
            self.block_ip(src_ip, duration_hours=24)
            # 3. 创建工单
            self.create_ticket({
                'title': f'暴力破解 + 恶意IP: {src_ip}',
                'action': '已自动封禁 24 小时',
                'priority': 'P2'
            })
            return

        # 4. 本地检测: 失败次数 > 阈值
        if alert['fail_count'] > 10:
            self.block_ip(src_ip, duration_hours=1)
            self.notify(f'封禁 {src_ip} (暴力破解 {alert["fail_count"]} 次}')
```

---

## 日志源配置清单

```yaml
必备日志源:
  网络:
    - 防火墙日志 (允许/拒绝)
    - IDS/IPS 告警
    - NetFlow/IPFIX
    - DNS 查询日志
    - VPN 连接日志

  端点:
    - Windows Event Log (安全/系统/应用)
    - Linux syslog + auditd
    - EDR/XDR 告警
    - PowerShell 脚本块日志

  应用:
    - Web 服务器访问日志
    - 应用认证日志
    - 数据库审计日志
    - API 网关日志

  云:
    - AWS CloudTrail
    - Azure Activity Log
    - GCP Audit Logs
    - Kubernetes 审计日志
```

---

*下一篇：[蓝队安全运营](02-blue-team-ops.md)*

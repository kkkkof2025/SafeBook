# SIEM 规则工程与威胁检测优化

## 概述

SIEM 不是买来就有效的——它的价值取决于规则的质量。一条好的检测规则应该：高检出率、低误报率、攻击者难以绕过。本章聚焦 SIEM 规则的设计、测试和优化方法论。

---

## 1. 检测规则金字塔

```
检测规则成熟度模型:

  L5 — 行为分析
  │    ML 异常检测 / UEBA
  │    例: 异常时间的批量数据导出
  │
  L4 — 关联规则
  │    多数据源关联
  │    例: VPN 登录 + 5分钟内 → 新建管理员账户
  │
  L3 — 有状态规则
  │    统计/频率/时序
  │    例: 同一用户 1 小时内登录失败 > 10 次
  │
  L2 — 签名规则
  │    基于特征的匹配
  │    例: 检测到 Mimikatz 命令行参数
  │
  L1 — 静态匹配
  │    简单条件过滤
  │    例: EventID=4625 (登录失败)
  │
  L0 — 日志采集 (无规则)
```

---

## 2. 规则设计原则

### 2.1 原子性 (Atomicity)

```yaml
# ❌ 坏规则: 一个规则检测多个不相关的攻击
title: "Everything is bad"
condition: >
  (event_id == 4625 AND user == "Administrator") OR
  (event_id == 4688 AND command_line CONTAINS "mimikatz") OR
  (event_id == 1102 AND service == "Security")
# → 无法区分攻击类型，难以调整阈值

# ✅ 好规则: 一个规则检测一种攻击
title: "Windows - Failed Login Brute Force"
status: production
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    TargetUserName: '*'
  timeframe: 5m
  condition: selection | count() by TargetUserName > 10
level: medium
```

### 2.2 过滤误报

```yaml
# 加入了误报过滤的检测规则

title: "Suspicious Scheduled Task Creation"
status: production
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
    TaskContent|contains:
      - 'powershell'
      - 'cmd.exe /c'
      - 'wscript'
      - 'cscript'
      - 'mshta'
      - 'certutil'

  # 已知的正常活动
  filter_known_good:
    TaskContent|contains:
      - 'Microsoft\Windows\UpdateOrchestrator'       # Windows Update
      - 'Microsoft\Windows\WindowsUpdate'             # Windows Update
      - 'Microsoft\Office\Office ClickToRun Service'  # Office 更新
      - 'OneDrive Standalone Update Task'             # OneDrive

  condition: selection and not filter_known_good
level: high
```

### 2.3 可调参

```yaml
# 使用变量使规则可调参

title: "Suspicious Network Connection"
# 攻击者可以调整参数绕过固定阈值

detection:
  # 定义变量便于调整
  timeframe: 15m
  threshold: 5
  target_ports: [22, 23, 445, 3389, 5985, 5986]

  selection:
    EventID: 5156
    DestPort: target_ports
    Direction: 'Outbound'

  condition: selection | count() by SourceIP > threshold
```

---

## 3. 高级检测规则

### 3.1 横向移动检测

```sql
-- Splunk SPL: 检测横向移动 (PsExec/WMI)
index=windows EventCode=4688
(CommandLine="*psexec*" OR CommandLine="*.exe \\\\*")
| stats values(CommandLine) as Commands,
    dc(ComputerName) as target_count
    by User, _time
| where target_count > 3
| eval risk_score = target_count * 20
| sort - risk_score
```

```sql
-- Elastic KQL: Pass-the-Hash 检测
event.code: "4624"
  AND winlog.event_data.LogonType: "3"
  AND winlog.event_data.AuthenticationPackageName: "NTLM"
  AND NOT winlog.event_data.WorkstationName: "-"
  AND NOT winlog.event_data.IpAddress: "127.0.0.1"
| stats count by winlog.event_data.TargetUserName
| where count > 5
```

### 3.2 数据外泄检测

```sql
-- 检测异常数据量外传

-- 1. 建立基线 (90天平均)
index=firewall action=allowed
| timechart span=1h sum(bytes_out) as hourly_bytes

-- 2. 检测异常 (超过基线 3σ)
index=firewall action=allowed
| bucket _time span=1h
| stats sum(bytes_out) as hourly_bytes by _time, src_ip
| eventstats avg(hourly_bytes) as baseline stdev(hourly_bytes) as stdev
| where hourly_bytes > baseline + 3 * stdev
| table _time, src_ip, hourly_bytes, baseline
```

```yaml
# Sigma 规则: DNS 数据外泄 (DNS Tunneling)
title: "Potential DNS Tunneling"
status: experimental
logsource:
  service: dns
detection:
  selection:
    query|re: '.*\.{50,}\.example\.com'   # 长子域名
    OR query_type: 'TXT'                   # TXT 记录
    OR query_len: '>150'                   # 长查询
  timeframe: 1h
  condition: selection | count() > 100
level: high
tags:
  - attack.exfiltration
  - attack.t1048.003
```

---

## 4. 蜜罐驱动的检测

```yaml
# 检测与蜜罐的交互

title: "Interaction with Honeypot SMB Share"
description: 任何访问蜜罐 SMB 共享的行为都应告警
level: critical
logsource:
  service: smb
detection:
  selection:
    ShareName: '\\\\HONEYPOT-FILESERVER\\Finance'
  condition: selection
# 只有攻击者才会访问蜜罐 → 0 误报
# 这是最高质量的检测规则
```

```python
class HoneypotBasedDetection:
    """
    基于蜜罐的低误报检测
    """

    def __init__(self):
        self.honeypots = {
            'smb_share': r'\\HONEYPOT-FILESERVER\Finance',
            's3_bucket': 'honeypot-backup-xxx',
            'api_endpoint': '/api/internal/admin/',
            'database': 'honeypot_customer_data',
            'ssh_account': 'honeypot_admin',
        }

    def detect(self, event):
        """
        检测蜜罐交互 — 所有交互都是恶意的
        """

        # 访问蜜罐 S3 桶
        if event.get('bucket_name') == self.honeypots['s3_bucket']:
            return {
                'alert': 'HONEYPOT_S3_ACCESS',
                'severity': 'CRITICAL',
                'confidence': '100%',  # 蜜罐交互 = 确认恶意
                'attacker_ip': event.get('source_ip'),
                'mitre_technique': 'T1530 (Data from Cloud Storage)'
            }

        # 访问蜜罐 API
        if self.honeypots['api_endpoint'] in event.get('request_uri', ''):
            return {
                'alert': 'HONEYPOT_API_ACCESS',
                'severity': 'CRITICAL',
                'confidence': '100%',
                'attacker_ip': event.get('source_ip'),
                'mitre_technique': 'T1190 (Exploit Public-Facing Application)'
            }

        return None
```

---

## 5. 规则测试框架

```python
import yaml
import unittest

class SigmaRuleTester:
    """Sigma 规则单元测试"""

    def __init__(self, rule_path):
        with open(rule_path, 'r') as f:
            self.rule = yaml.safe_load(f)

    def test_true_positive(self, test_event):
        """测试真阳性 (规则应该触发)"""
        # 模拟真实攻击事件
        result = self._evaluate(test_event)
        assert result, (
            f"规则 {self.rule['title']}: "
            f"漏检(False Negative)! 应检测到攻击事件"
        )

    def test_false_positive(self, benign_event):
        """测试误报 (规则不应该触发)"""
        result = self._evaluate(benign_event)
        assert not result, (
            f"规则 {self.rule['title']}: "
            f"误报(False Positive)! 正常事件被误判为攻击"
        )

    def _evaluate(self, event):
        """简易规则引擎"""
        detection = self.rule['detection']
        selection = detection.get('selection', {})

        for field, value in selection.items():
            if field not in event:
                return False
            if isinstance(value, list):
                if event[field] not in value:
                    return False
            elif event[field] != value:
                return False

        # 检查过滤器
        filters = detection.get('filter_known_good', {})
        for field, value in filters.items():
            if field in event:
                if isinstance(value, list):
                    if event[field] in value:
                        return False
                elif event[field] == value:
                    return False

        return True


# 示例测试
class TestLateralMovementRule(unittest.TestCase):

    def test_psexec_detected(self):
        tester = SigmaRuleTester('rules/lateral_movement_psexec.yml')
        # 攻击事件
        tester.test_true_positive({
            'EventID': 4688,
            'CommandLine': 'psexec.exe \\\\DC01 cmd.exe'
        })

    def test_normal_remote_management(self):
        tester = SigmaRuleTester('rules/lateral_movement_psexec.yml')
        # 正常远程管理
        tester.test_false_positive({
            'EventID': 4688,
            'CommandLine': 'mmc.exe compmgmt.msc'
        })
```

---

## 参考资源

- [Sigma 规则库](https://github.com/SigmaHQ/sigma)
- [Splunk 安全检测](https://research.splunk.com/)
- [Elastic 检测规则](https://github.com/elastic/detection-rules)

---

*上一篇：[SOC 自动化响应](02-soc-automation.md)*

*下一篇：[SOC 自动化与 SOAR 实战](04-soc-automation.md)*

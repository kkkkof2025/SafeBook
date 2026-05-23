# 威胁狩猎方法论

> 主动威胁狩猎：从假设驱动到数据驱动

---

## 1. 威胁狩猎模型

```
威胁狩猎循环 (Threat Hunting Loop):
  假设形成 → 数据收集 → 分析调查 → 发现确认 → 响应改进
      ↑                                          │
      └──────────────────────────────────────────┘

三种狩猎方法:
  ┌──────────────┬──────────────┬──────────────┐
  │ 假设驱动     │ 指标驱动     │ 数据驱动     │
  ├──────────────┼──────────────┼──────────────┤
  │ 基于 TTP     │ 基于 IOC     │ 异常检测     │
  │ "APT29 可能  │ "这个 IP 已被│ "这个时间段的 │
  │  用 XX 方法" │  标记为恶意" │  活动异常"   │
  └──────────────┴──────────────┴──────────────┘
```

---

## 2. 假设驱动狩猎

```python
class HypothesisDrivenHunt:
    """假设驱动的威胁狩猎"""

    HYPOTHESIS_EXAMPLES = [
        {
            'name': 'PowerShell Download Cradle',
            'hypothesis': '攻击者使用 PowerShell 下载并执行远程 Payload',
            'mitre': 'T1059.001',
            'query': '''
                index=windows EventCode=4104
                ScriptBlockText IN ("*DownloadString*", "*DownloadFile*",
                                    "*Net.WebClient*", "*Invoke-WebRequest*",
                                    "*IEX*", "*Invoke-Expression*")
                | table _time, host, user, ScriptBlockText
            '''
        },
        {
            'name': 'Kerberoasting Activity',
            'hypothesis': '攻击者请求高价值 SPN 的 Kerberos 服务票据',
            'mitre': 'T1558.003',
            'query': '''
                index=windows EventCode=4769
                ServiceName IN ("MSSQLSvc*", "HTTP*", "TERMSRV*", "CIFS*")
                TicketEncryptionType="0x17"  # RC4-HMAC (弱加密)
                | stats count by Account_Name, ServiceName, Client_Address
                | where count > 3
            '''
        },
    ]

    def run_hypothesis(self, hypothesis):
        """执行一次假设驱动的狩猎"""
        results = self.siem.query(hypothesis['query'])

        findings = []
        for result in results:
            finding = {
                'hypothesis': hypothesis['name'],
                'mitre_id': hypothesis['mitre'],
                'host': result.get('host'),
                'user': result.get('user'),
                'timestamp': result.get('_time'),
                'evidence': result,
            }
            findings.append(finding)

        return findings
```

### 高级假设创建
```python
def generate_hypotheses_from_threat_intel(self, apt_group):
    """从威胁情报自动生成假设"""

    # 获取 APT 组已知 TTP
    techniques = self.mitre.get_group_techniques(apt_group)

    hypotheses = []
    for t in techniques:
        # 检查本组织是否存在相关数据源
        if self.has_datasource_for(t['technique_id']):
            hypotheses.append({
                'name': f'{apt_group} — {t["technique_name"]}',
                'mitre': t['technique_id'],
                'rationale': f'{apt_group} 已知使用此技术',
                'priority': 'HIGH' if t.get('used_recently') else 'MEDIUM'
            })

    return sorted(hypotheses, key=lambda h: h['priority'], reverse=True)
```

---

## 3. 异常检测狩猎

```python
class AnomalyDrivenHunt:
    """基于异常的威胁狩猎"""

    def __init__(self):
        self.baselines = self.load_baselines()

    def detect_dns_anomalies(self):
        """DNS 异常检测"""
        # 计算每小时 DNS 查询数基线
        hourly_counts = self.siem.query('''
            index=dns
            | timechart span=1h count by src_ip
            | stats avg(count) as baseline,
                    stdev(count) as stddev by src_ip
        ''')

        # 查找异常 (>3σ)
        for ip in hourly_counts:
            avg = hourly_counts[ip]['baseline']
            std = hourly_counts[ip]['stddev']

            if hourly_counts[ip]['count'] > avg + 3 * std:
                yield {
                    'type': 'DNS_ANOMALY',
                    'src_ip': ip,
                    'count': hourly_counts[ip]['count'],
                    'baseline': avg,
                    'sigma': 3.0,
                    'hypothesis': 'DNS隧道或C2通信'
                }

    def detect_process_anomalies(self):
        """进程行为异常检测"""
        # 检测罕见的父进程关系
        # 例: Excel.exe → powershell.exe (正常不出现!)
        rare_pairs = self.siem.query('''
            index=sysmon EventCode=1
            | eval parent=Image, child=ParentImage
            | stats count by parent, child
            | where count < 5
            | sort count
        ''')

        for pair in rare_pairs:
            if self.is_suspicious_pair(pair['parent'], pair['child']):
                yield {
                    'type': 'RARE_PROCESS_PAIR',
                    'parent': pair['parent'],
                    'child': pair['child'],
                    'count': pair['count'],
                    'hypothesis': '父进程劫持或 DLL 侧加载'
                }
```

---

## 4. 数据收集清单

```yaml
威胁狩猎数据源清单:

  端点:
    - Sysmon Events (1-25, 全量)
    - PowerShell Script Block Logging (4104)
    - EDR Telemetry
    - Windows Event Logs (安全 + 系统)

  网络:
    - DNS 查询日志 (全量)
    - NetFlow/IPFIX
    - HTTP/HTTPS 代理日志
    - IDS/IPS 告警

  身份:
    - AD 认证日志 (4624/4625/4768/4769)
    - VPN 连接日志
    - 云服务审计日志

  存储:
    - 数据湖 (S3/ADLS/HDFS) + Presto/Spark 查询
    - 实时索引 (Elasticsearch) + 历史归档 (S3 Glacier)
```

---

## 5. 狩猎成熟度

| 级别 | 描述 | 频率 |
|------|------|------|
| HMM0 | 无主动狩猎 | N/A |
| HMM1 | 临时/手动查询 | 事件驱动 |
| HMM2 | 例行假设驱动 | 每周 |
| HMM3 | 自动化假设 + 异常检测 | 每日 |
| HMM4 | AI/ML 驱动 | 持续 |
| HMM5 | 预测性狩猎 | 前瞻性 |

---

*上一篇：[安全运营中心 (SOC) 架构](03-soc-architecture.md)*

# 威胁狩猎与攻击溯源

> 从被动响应到主动狩猎——在攻击者造成伤害前发现他们。

---

## 威胁狩猎方法论

### 狩猎假设驱动

```python
# 假设: 攻击者可能使用可疑的 PowerShell 下载
hypothesis = "Attackers are using PowerShell to download C2 payloads"

# 转化为搜索查询
hunting_query = {
    "source": "Windows Event Log (4688)",
    "filter": "powershell.exe",
    "indicator": "contains Invoke-WebRequest OR DownloadFile",
    "timeframe": "last 7 days",
    "exclusions": ["IT admin tools", "SCCM scripts"]
}
```

### 狩猎四步法

```
1. 假设生成
   ├─ 基于最新威胁情报
   ├─ 基于异常行为模式
   ├─ 基于红队演练发现
   └─ 基于合规/行业最佳实践

2. 数据收集
   ├─ EDR 遥测数据
   ├─ 网络流量日志
   ├─ DNS 日志
   ├─ 认证日志
   └─ 云 API 日志

3. 模式匹配
   ├─ 已知 IOC / TTP 匹配
   ├─ 基线行为偏离检测
   └─ 异常时间窗口活动

4. 调查验证
   ├─ 确认误报或真阳性
   ├─ 评估爆炸半径
   └─ 触发 IR 流程（如需要）
```

## 实际狩猎场景

### 场景 1：异常的 DNS 查询

```kql
// KQL (Kusto 查询语言) — Microsoft 365 Defender
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl endswith ".xyz" or RemoteUrl endswith ".top"
| where ActionType == "DnsQueryResponse"
| summarize count() by RemoteUrl, DeviceName
| where count_ > 5
| order by count_ desc

// DGA 域名特征: 高熵、随机字符、短 TLD
// 关注域名: asdflkajsdf.xyz、mno123pqr.top
```

### 场景 2：异常的 LSASS 进程访问

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName == "lsass.exe"
| where ProcessCommandLine contains "procdump" 
    or ProcessCommandLine contains "sekurlsa"
    or ProcessCommandLine contains "minidump"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

### 场景 3：横向移动检测

```kql
// 异常 SMB 连接 + 计划任务创建
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 445
| where InitiatingProcessFileName in~ ("wmiprvse.exe", "svchost.exe", "mmc.exe")
| join kind=inner (
    DeviceProcessEvents
    | where FileName == "schtasks.exe"
    | where ProcessCommandLine contains "/create"
) on DeviceName
| project Timestamp, SourceDevice=DeviceName, 
    RemoteIP, RemotePort,
    LateralCommand=ProcessCommandLine
```

## 日志源清单

| 日志源 | 关键字段 | 保留期 |
|--------|---------|--------|
| Windows Event Log (4688) | 进程创建参数 | 90天 |
| Sysmon (1-25) | 进程/网络/文件变更 | 90天 |
| DNS 日志 | 查询域名 | 30天 |
| 代理日志 (Squid/Zscaler) | URL 访问 | 90天 |
| EDR 遥测 | 进程/网络/注册表 | 180天 |
| CloudTrail | AWS API 调用 | 90天 |
| VPC Flow Logs | 网络流 | 30天 |

## 攻击溯源流程

```mermaid
graph LR
    A[告警触发] --> B[日志提取]
    B --> C[时间线重建]
    C --> D[入口点分析]
    D --> E[横向路径追踪]
    E --> F[数据影响评估]
    F --> G[归因分析]
```

### 溯源实例

```
告警: 域控异常计划任务创建

时间线重建:
T0: [EDR] 用户电脑 A（销售部）收到带宏邮件的 Word 文档
T+1h: [Sysmon] PowerShell 从 IP 1.2.3.4 下载 payload.exe
T+2h: [EDR] payload.exe 进程注入到 explorer.exe
T+3h: [Windows Log] 凭据提取 (sekurlsa::logonpasswords)
T+4h: [AD Audit] 从电脑 A 通过 PsExec 连接到文件服务器
T+5h: [AD] 创建域管理员计划任务（触发告警）
T+6h: [EDR] C2 域名 dga-malicious.xyz DNS 查询

入口点: 钓鱼邮件 → Word 宏 → PowerShell 下载器
攻击者: UNC1234（TTP 匹配 Lazarus 子群组）
影响: 3 台服务器受控，无数据外泄（及时发现遏制）
```

## 自动化狩猎脚本

```python
import requests
from datetime import datetime, timedelta

class ThreatHunter:
    def __init__(self, api_key):
        self.api_key = api_key
        self.ioc_feeds = {
            "abuse_ch": "https://urlhaus.abuse.ch/downloads/text/",
            "tor_exit": "https://check.torproject.org/torbulkexitlist",
            "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        }
    
    def pull_iocs(self):
        """拉取最新 IOC"""
        for name, url in self.ioc_feeds.items():
            resp = requests.get(url)
            self.iocs[name] = resp.text.splitlines()
    
    def cross_reference(self, log_data):
        """将内部日志与 IOC 交叉比对"""
        for log_entry in log_data:
            for feed_name, iocs in self.iocs.items():
                if log_entry["ip"] in iocs:
                    self.alerts.append({
                        "timestamp": datetime.now(),
                        "log": log_entry,
                        "match": f"Found in {feed_name}",
                        "priority": "HIGH"
                    })
```

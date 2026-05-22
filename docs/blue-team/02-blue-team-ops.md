# 蓝队安全运营

## 概述

蓝队运营（Blue Team Operations）是把安全策略转化为日常行动的工程实践。它回答一个核心问题：在 8 小时轮班里，蓝队分析师到底在做什么？

---

## 1. 蓝队日常运营节奏

```
蓝队三班制运营:

  早班 (08:00-16:00): 预防为主
    ├── 08:00 交班 & 了解夜班告警
    ├── 09:00 威胁情报消化 & IOC 导入
    ├── 10:00 新漏洞评估（CVSS/受影响资产）
    ├── 11:00 安全工具维护（SIEM规则/EDR策略）
    ├── 13:00 告警分类 & 误报分析
    ├── 15:00 日报告：今天发现了什么

  中班 (16:00-00:00): 检测为主
    ├── 16:00 交班
    ├── 17:00 实时告警监控（业务高峰期）
    ├── 19:00 异常行为分析
    ├── 21:00 威胁狩猎（主动搜索而不是等告警）
    └── 23:00 日志归档 & 规则调整

  夜班 (00:00-08:00): 应急为主
    ├── 00:00 交班
    ├── 01:00 自动化剧本验证
    ├── 03:00 批处理日志分析
    ├── 05:00 备份验证
    └── 07:00 交班准备
```

---

## 2. 告警分类（Alert Triage）

### 2.1 告警优先级

```python
class AlertTriage:
    """蓝队告警分类引擎"""

    @staticmethod
    def classify(alert):
        """
        告警分类决策树:

        P0 — 正在进行的攻击（需要立即响应）
          → 横向移动、C2通信、数据外泄
          → 响应: <5min 启动 IR

        P1 — 可疑活动（需要深入调查）
          → 异常登录、可疑进程、DNS隧道
          → 响应: <30min 开始分析

        P2 — 低置信度异常（监控 观察）
          → 异常流量峰值、未知用户代理
          → 响应: <2h 分类

        P3 — 已知误报模式（可自动化）
          → 已知的内部扫描、安全工具行为
          → 响应: 自动关闭
        """

        # P0 判定
        p0_patterns = [
            {'event_id': 4624, 'logon_type': 3, 'source_ip': 'external'},
            {'event_id': 4738, 'group': 'Domain Admins'},
            {'c2_indicators': True},
            {'outbound_size_mb': lambda x: x > 100}
        ]

        for pattern in p0_patterns:
            if all(
                alert.get(k) == v if not callable(v) else v(alert.get(k))
                for k, v in pattern.items()
            ):
                return 'P0', 'Critical — 立即启动 IR'

        # P1 判定
        if alert.get('suspicious_process') or \
           alert.get('multiple_failed_logins', 0) > 10:
            return 'P1', 'High — 需要深入调查'

        # P2 判定
        if alert.get('anomaly_score', 0) > 0.7:
            return 'P2', 'Medium — 监控观察'

        return 'P3', 'Low — 自动关闭'
```

### 2.2 误报处理

```yaml
常见误报来源及处理:

  1. 内部安全扫描:
     现象: 大量 4625 + 来自单一内部 IP
     处理: 列入白名单（精确到扫描器 IP + 时间窗口）
     自动化: SIEM rule: if source_ip in ["scanner_ip"] then suppress

  2. 管理工具行为:
     现象: SCCM/SolarWinds 等管理工具扫描
     处理: 识别工具签名（User-Agent/进程名）
     自动化: EDR exclusion for known admin tools

  3. 用户行为异常:
     现象: 晚间登录（夜班员工）
     处理: 确认是否轮班、是否有提前通知
     自动化: 如果用户近期无异常，降权

  误报率目标:
    - Tier 1: < 50% 误报率（好的规则）
    - Tier 2: < 10%（已有分析师过滤）
```

---

## 3. 安全工具日常维护

```python
class SocToolchainHealth:
    """SOC 工具健康检查"""

    def daily_checks(self):
        checks = []

        # 1. SIEM 日志摄入
        checks.append({
            'tool': 'SIEM',
            'check': 'log_ingestion_rate',
            'query': 'index=* earliest=-1h | stats count',
            'expected': '>0',
            'alert_if': 'count == 0'
        })

        # 2. EDR 在线率
        checks.append({
            'tool': 'EDR',
            'check': 'agent_online_rate',
            'query': 'SELECT COUNT(*) FROM agents WHERE status="online"',
            'expected': '>95%',
            'alert_if': '<90%'
        })

        # 3. 日志源活跃度
        checks.append({
            'tool': 'Log Sources',
            'check': 'sources_active',
            'query': '查看最近 1 小时有日志的源',
            'expected': '100% 关键源活跃',
            'alert_if': '防火墙/Mail/DNS 任一离线'
        })

        # 4. 存储空间
        checks.append({
            'tool': 'Storage',
            'check': 'disk_usage',
            'query': 'df -h /var/log /opt/siem',
            'expected': '<80%',
            'alert_if': '>85%'
        })

        return checks
```

---

## 4. 蓝队 KPI

```yaml
蓝队运营 KPI:

  MTTD (Mean Time to Detect):
    目标: < 60 分钟
    测量: 攻击开始 → SIEM 产生第一条告警的时间

  MTTR (Mean Time to Respond):
    目标: < 4 小时 (P0), < 24 小时 (P1)
    测量: 告警产生 → 事件关闭的时间

  误报率 (False Positive Rate):
    目标: < 30% (Tier 1), < 5% (Tier 2)
    测量: 误报数 / 总告警数

  告警覆盖率:
    目标: > 90% MITRE ATT&CK 技术有对应检测规则
    测量: 有 SIEM 规则覆盖的 ATT&CK 技术 / 总 ATT&CK 技术

  自动关闭率:
    目标: > 40% 告警无需人工参与即可关闭
    测量: SOAR 自动关闭量 / 总告警量
```

---

*上一篇：[SIEM 与 SOC](01-siem-soc.md)*

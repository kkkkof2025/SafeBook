# 内部威胁检测与防御

## 概述

内部威胁是最难检测的安全问题——攻击者拥有合法访问权限。Verizon DBIR 2024 报告显示，34% 的数据泄露涉及内部人员，平均损失 $18.4M。本章聚焦从行为分析到技术控制的完整防御体系。

---

## 1. 内部威胁分类

### 1.1 威胁画像

| 类型 | 动机 | 典型行为 | 风险级别 |
|------|------|----------|----------|
| **恶意内部人员** | 报复、经济利益 | 批量下载、删除日志、种植后门 | 极高 |
| **被动内部人员** | 愚昧、被胁迫 | 点击钓鱼、泄露密码 | 高 |
| **疏忽内部人员** | 缺乏安全意识 | 误发邮件、公开配置错误 | 中 |
| **第三方人员** | 承包商/供应商 | 超权限访问、非工作时间操作 | 高 |
| **离职员工** | 带走数据 | 大量下载、U盘拷贝 | 极高 |

### 1.2 离职前 30 天行为模式

```python
class InsiderThreatDetector:
    """内部威胁行为检测"""

    # 离职前异常行为模式
    SUSPICIOUS_PATTERNS = {
        'data_exfiltration': {
            'weight': 10,
            'indicators': [
                'USB 设备首次使用',
                '大量文件下载 (>100MB/day)',
                '访问非业务数据',
                '使用个人邮箱/云存储',
                '异常时段文件访问 (凌晨/周末)',
            ]
        },
        'access_escalation': {
            'weight': 8,
            'indicators': [
                '尝试访问无权限系统',
                '频繁请求权限提升',
                '扫描内部网络',
                '数据库全表查询',
            ]
        },
        'covert_communication': {
            'weight': 5,
            'indicators': [
                '使用加密通信工具',
                '发送大量附件到外部',
                '打印敏感文档',
                '截图/拍照敏感页面',
            ]
        },
        'behavioral_change': {
            'weight': 3,
            'indicators': [
                '工作时间异常 (早到晚退)',
                'VPN 远程连接增加',
                '突然拒绝休假',
                '对工作内容回避',
            ]
        }
    }

    def calculate_risk_score(self, user_id, time_window_days=30):
        """计算用户风险评分"""
        activities = self._get_user_activities(user_id, time_window_days)
        score = 0
        findings = []

        for category, pattern in self.SUSPICIOUS_PATTERNS.items():
            category_score = 0
            for indicator in pattern['indicators']:
                if self._check_indicator(activities, indicator):
                    matches = self._count_indicator_matches(activities, indicator)
                    category_score += matches

            if category_score > 0:
                findings.append({
                    'category': category,
                    'score': category_score * pattern['weight'],
                    'matches': category_score
                })
                score += category_score * pattern['weight']

        return {
            'user_id': user_id,
            'risk_score': score,
            'risk_level': 'CRITICAL' if score > 50 else
                          'HIGH' if score > 30 else
                          'MEDIUM' if score > 15 else 'LOW',
            'findings': findings,
            'period': f'{time_window_days} days'
        }
```

---

## 2. 数据防泄露 (DLP)

### 2.1 DLP 规则引擎

```python
class DLPRuleEngine:
    """数据防泄露规则引擎"""

    def __init__(self):
        # 定义敏感数据模式
        self.sensitive_patterns = {
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'(?i)(api[_-]?key|secret|token|password)[\s:=]+["\']?([A-Za-z0-9+/=_-]{20,})',
            'private_key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            'database_dump': r'(?i)(CREATE TABLE|INSERT INTO|ALTER TABLE)',
            'source_code': r'(?i)(package |import |class |def |function |const )',
            'credentials': r'(?i)(username|password|login|credential)\s*[:=]\s*["\']?\S+',
            'pii_cn_id': r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b',
            'pii_phone': r'\b1[3-9]\d{9}\b',
        }

    def scan_file(self, filepath):
        """扫描文件是否包含敏感数据"""
        findings = []
        filetype = self._detect_filetype(filepath)

        # 检查文件类型限制
        if filetype in ['archive', 'encrypted', 'binary']:
            findings.append({
                'rule': 'file_type_restriction',
                'action': 'BLOCK',
                'reason': f'{filetype} 文件不允许外发'
            })
            return findings

        # 读取文件内容
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            with open(filepath, 'rb') as f:
                content = f.read().decode('latin-1')

        # 扫描敏感数据模式
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = re.finditer(pattern, content)
            match_count = 0
            for match in matches:
                match_count += 1
                if match_count <= 3:  # 只记录前 3 个匹配
                    # 脱敏显示
                    context = content[max(0, match.start()-20):match.end()+20]
                    findings.append({
                        'rule': pattern_name,
                        'match': self._mask_sensitive(match.group()),
                        'context': context[:60],
                        'position': match.start()
                    })

        # 综合判断
        total_matches = len([f for f in findings if f.get('rule')])
        if total_matches > 10:
            findings.append({
                'rule': 'bulk_sensitive_data',
                'action': 'BLOCK_AND_ALERT',
                'reason': f'检测到 {total_matches} 处敏感数据',
                'user_notification': '文件包含大量敏感信息，外发已被阻止'
            })

        return findings

    def check_email_dlp(self, email):
        """检查出站邮件"""
        alerts = []

        # 收件人检测
        recipients = email['to'] + email.get('cc', [])
        for recipient in recipients:
            if self._is_personal_email(recipient):
                alerts.append({
                    'type': 'personal_email',
                    'recipient': self._mask_email(recipient),
                    'action': 'WARN_USER'
                })

        # 附件检测
        for attachment in email.get('attachments', []):
            if attachment['size'] > 10 * 1024 * 1024:  # >10MB
                alerts.append({
                    'type': 'large_attachment',
                    'filename': attachment['name'],
                    'size_mb': attachment['size'] / 1024 / 1024,
                    'action': 'REQUIRE_APPROVAL'
                })

            # 扫描附件内容
            findings = self.scan_file(attachment['temp_path'])
            if findings:
                alerts.append({
                    'type': 'sensitive_attachment',
                    'filename': attachment['name'],
                    'findings': findings,
                    'action': 'BLOCK'
                })

        return alerts
```

---

## 3. UEBA (用户行为分析)

### 3.1 异常检测基线

```python
from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np

class UEBAMonitor:
    """用户实体行为分析"""

    def __init__(self):
        self.baselines = {}   # 用户行为基线
        self.anomaly_model = IsolationForest(contamination=0.05)

    def build_baseline(self, user_id, historical_logs, days=90):
        """构建 90 天行为基线"""
        logs = self._filter_by_period(historical_logs, days)

        baseline = {
            'avg_daily_files_accessed': np.mean([l['files_accessed'] for l in logs]),
            'std_daily_files_accessed': np.std([l['files_accessed'] for l in logs]),
            'avg_daily_data_transfer_mb': np.mean([l['data_transfer_mb'] for l in logs]),
            'typical_login_hours': self._get_typical_hours(logs),
            'typical_locations': self._get_typical_locations(logs),
            'typical_devices': self._get_typical_devices(logs),
            'avg_privileged_actions': np.mean([l['privileged_actions'] for l in logs]),
            'peer_group_average': self._get_peer_group_baseline(user_id),
        }

        self.baselines[user_id] = baseline
        return baseline

    def detect_anomalies(self, user_id, today_logs):
        """检测异常行为"""
        baseline = self.baselines.get(user_id)
        if not baseline:
            return []

        anomalies = []

        # 1. 数据访问异常 (3-sigma)
        today_files = today_logs['files_accessed']
        sigma = baseline['std_daily_files_accessed']
        if sigma > 0:
            deviation = (today_files - baseline['avg_daily_files_accessed']) / sigma
            if deviation > 3:
                anomalies.append({
                    'type': 'MASSIVE_DATA_ACCESS',
                    'value': today_files,
                    'baseline': baseline['avg_daily_files_accessed'],
                    'deviation_sigma': deviation,
                    'severity': 'HIGH'
                })

        # 2. 非工作时间访问
        if not self._is_typical_hours(today_logs, baseline['typical_login_hours']):
            anomalies.append({
                'type': 'OFF_HOURS_ACCESS',
                'time': today_logs['timestamp'],
                'typical_hours': baseline['typical_login_hours'],
                'severity': 'MEDIUM'
            })

        # 3. 异常地点
        if today_logs['location'] not in baseline['typical_locations']:
            anomalies.append({
                'type': 'NEW_LOCATION',
                'location': today_logs['location'],
                'severity': 'MEDIUM'
            })

        # 4. 超过同龄组均值 2 倍
        if today_files > baseline['peer_group_average'] * 2:
            anomalies.append({
                'type': 'EXCEEDS_PEER_GROUP',
                'value': today_files,
                'peer_average': baseline['peer_group_average'],
                'ratio': today_files / baseline['peer_group_average'],
                'severity': 'LOW'
            })

        return anomalies
```

---

## 4. 防御体系

```yaml
内部威胁防御层次:

  预防层 (Preventive):
    - 最小权限原则 (Least Privilege)
    - 职责分离 (Separation of Duties)
    - 定期权限审查 (Access Review)
    - 安全意识培训 (Security Awareness)
    - 背景调查 (Background Check)

  检测层 (Detective):
    - UEBA (用户行为分析)
    - DLP (数据防泄露)
    - SIEM 规则:
      - 大量文件下载/外发
      - 非工作时间访问
      - 权限提升请求
      - USB 设备使用
    - 蜜罐文件 (Honey Tokens)

  响应层 (Responsive):
    - 自动化阻断 (自动禁用账户)
    - 安全团队告警
    - 法律介入流程
    - 证据保全流程

  恢复层 (Recovery):
    - 数据恢复 (备份)
    - 事件复盘 (PIR)
    - 流程改进
    - 心理辅导 (如适用)
```

---

## 参考资源

- [CERT Insider Threat Guide](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=519849)
- [NISTIR 8287 - 内部威胁检测](https://www.nist.gov/publications/)
- [MITRE Insider Threat Framework](https://www.mitre.org/)

---

*上一篇：[高级社工技术](./03-social-advanced.md)*

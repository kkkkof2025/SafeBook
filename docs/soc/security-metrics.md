# 安全指标与 KPI

> 可度量安全：从主观感受到数据驱动

---

## 1. 安全指标体系

```
安全指标金字塔:
        ┌─────────────┐
        │  业务指标    │  ← MTTR, 损失, ROI
        ├─────────────┤
        │  运营指标    │  ← 事件数, 修复率, 响应时间
        ├─────────────┤
        │  技术指标    │  ← 漏洞数, 补丁覆盖率, 扫描结果
        ├─────────────┤
        │  合规指标    │  ← 合规分数, 审计通过率
        └─────────────┘
```

---

## 2. 核心安全 KPI

### 检测与响应
```yaml
MTTD (Mean Time to Detect):
  定义: 从事件发生到检测的平均时间
  目标: < 1 小时 (关键系统 < 15 分钟)
  计算: SUM(检测时间 - 事件时间) / 事件数

MTTR (Mean Time to Respond):
  定义: 从检测到遏制的平均时间
  目标: < 4 小时 (关键系统 < 1 小时)
  计算: SUM(遏制时间 - 检测时间) / 事件数

MTTC (Mean Time to Contain):
  定义: 从检测到完全遏制的平均时间

告警疲劳率:
  定义: 最终判定为误报的告警比例
  目标: < 30%
  计算: 误报告警数 / 总告警数 × 100%
```

### 漏洞管理
```python
class VulnerabilityMetrics:
    """漏洞管理 KPI 仪表盘"""

    def __init__(self):
        self.vuln_data = []

    def mean_time_to_patch(self, severity='critical'):
        """平均修补时间 (按严重度)"""
        target = {
            'critical': timedelta(days=7),
            'high': timedelta(days=14),
            'medium': timedelta(days=30),
            'low': timedelta(days=90),
        }

        patches = [
            (p['patched_date'] - p['discovered_date'])
            for p in self.vuln_data
            if p['severity'] == severity and p['patched_date']
        ]

        avg = sum(patches, timedelta(0)) / len(patches) if patches else None
        compliance = (
            avg <= target[severity] if avg else None
        )
        return {
            'severity': severity,
            'avg_time': avg,
            'target': target[severity],
            'compliant': compliance,
            'sample_size': len(patches)
        }

    def vulnerability_aging(self):
        """漏洞老化分析"""
        now = datetime.utcnow()
        buckets = {
            '0-7 days': 0,
            '8-30 days': 0,
            '31-90 days': 0,
            '91-365 days': 0,
            '365+ days': 0,
        }

        for v in self.vuln_data:
            age = (now - v['discovered_date']).days
            if age <= 7: buckets['0-7 days'] += 1
            elif age <= 30: buckets['8-30 days'] += 1
            elif age <= 90: buckets['31-90 days'] += 1
            elif age <= 365: buckets['91-365 days'] += 1
            else: buckets['365+ days'] += 1

        return buckets

    def patch_coverage(self):
        """补丁覆盖率"""
        total = len(self.vuln_data)
        patched = sum(1 for v in self.vuln_data if v['patched_date'])
        return {'total': total, 'patched': patched,
                'coverage_pct': patched/total*100 if total else 0}
```

---

## 3. 安全姿态评分

```python
class SecurityPostureScore:
    """综合安全姿态评分 (0-100)"""

    WEIGHTS = {
        'vulnerability_management': 25,
        'access_control': 20,
        'network_security': 15,
        'endpoint_security': 15,
        'incident_response': 15,
        'training_awareness': 10,
    }

    def calculate(self):
        scores = {
            'vulnerability_management': self.vuln_score(),
            'access_control': self.iam_score(),
            'network_security': self.network_score(),
            'endpoint_security': self.endpoint_score(),
            'incident_response': self.ir_score(),
            'training_awareness': self.training_score(),
        }

        total = sum(
            scores[k] * self.WEIGHTS[k] / 100
            for k in self.WEIGHTS
        )
        return {
            'overall': total,
            'breakdown': scores,
            'grade': self.to_grade(total)
        }

    def vuln_score(self):
        """漏洞管理评分: CVSS + 修补速度 + 覆盖率"""
        critical_open = self.count_vulns('critical', patched=False)
        mtp = self.mean_time_to_patch('critical')

        score = 100
        if critical_open > 5: score -= 30
        elif critical_open > 0: score -= 15
        if mtp and mtp > timedelta(days=14): score -= 25
        elif mtp and mtp > timedelta(days=7): score -= 10

        return max(0, score)

    def to_grade(self, score):
        if score >= 90: return 'A'
        if score >= 80: return 'B'
        if score >= 70: return 'C'
        if score >= 60: return 'D'
        return 'F'
```

---

## 4. 安全运营仪表盘

| 指标 | 目标 | 当前 | 趋势 |
|------|------|------|------|
| MTTD (Critical) | <15min | 12min | ↓ ✅ |
| MTTR (Critical) | <1h | 38min | ↓ ✅ |
| 告警准确率 | >70% | 72% | ↑ ✅ |
| Critical 漏洞数 | 0 | 2 | ↓ |
| 补丁覆盖率 | >95% | 93% | ↑ |
| MFA 启用率 | 100% | 94% | ↑ ✅ |
| 安全培训完成率 | >90% | 88% | ↑ |
| 外部攻击面 | ↓10% | -8% | → |

---

## 5. 向业务汇报

```yaml
向管理层汇报安全的价值:
  不要报:
    - "我们封堵了 50 万个攻击" (技术指标,无业务意义)
    - "IPS 规则更新了 200 条"
  
  要报:
    - "今年未发生数据泄露" (业务结果)
    - "MTTR 从 4 小时降至 38 分钟" (改进趋势)
    - "安全培训后钓鱼点击率从 12% 降至 3%" (行为改变)
    - "补丁覆盖率从 85% 提升至 93%" (风险降低)
    - "安全自动化为 SOC 节省 40% 工时" (成本节约)

  原则: 安全指标 → 业务影响 → 风险语言
```

---

*上一篇：[SOC 自动化运营](04-soc-soar.md)*

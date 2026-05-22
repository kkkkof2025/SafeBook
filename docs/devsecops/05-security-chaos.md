# 安全混沌工程

## 概述

安全混沌工程（Security Chaos Engineering）将混沌工程理念应用于安全领域——不是在故障中测试系统韧性，而是在安全假设失败时测试系统响应。它是安全防御的最终真实验证。

---

## 1. 安全混沌工程原则

```
混沌工程 → 安全混沌工程:

  混沌工程:
    假设: 分布式系统总会出故障
    方法: 主动注入故障, 验证恢复能力
    目标: 最小化故障影响

  安全混沌工程:
    假设: 攻击者已经在内网
    方法: 主动注入安全事件, 验证检测/响应
    目标: 优化检测能力和响应速度
```

---

## 2. 安全游戏日 (Game Day)

### 2.1 注入场景

```yaml
安全混沌实验目录:

  场景 1: 凭证泄漏模拟
    方法: 在公开仓库放置一个"泄漏的"凭证 honeytoken
    监控: GitHub 扫描告警时间
    检测: 凭证被使用时 → SIEM 告警？
    指标: TTD (Time to Detect) < 24h

  场景 2: C2 信标模拟
    方法: 在隔离主机运行无害的 DNS Beacon 模拟器
    监控: DNS 异常查询告警
    检测: 信标被检测到 → 几天？
    指标: 网络层面的 TTD < 1h

  场景 3: 数据外泄模拟
    方法: 从受监控系统上传标记文件到外部存储
    监控: DLP 告警
    检测: 外泄是否被检测到 → 是否自动阻断？
    指标: TTD < 15min + 自动阻断

  场景 4: 横向移动模拟
    方法: 使用无害脚本通过 WinRM/SSH 遍历多台机器
    监控: EDR 异常行为告警
    检测: 横向移动是否触发告警 → 是否关联？
    指标: 第一次跳转 TTD < 30min

  场景 5: 权限提升模拟
    方法: 创建临时本地管理员 (随即删除)
    监控: 用户组变更告警
    检测: 权限提升是否被检测到 → 是否自动撤销？
    指标: TTD < 5min
```

### 2.2 实验设计模板

```python
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional

@dataclass
class SecurityExperiment:
    """安全混沌实验"""

    name: str
    hypothesis: str
    description: str

    # 实验范围
    target_system: str
    blast_radius: str  # "single_host", "single_vlan", "prod_slice"
    environment: str  # "staging", "production"

    # 注入
    injection_type: str  # "credential_leak", "c2_activity", etc.
    injection_duration: timedelta

    # 预期
    expected_detection_method: str
    expected_response_action: str
    sla_ttd_minutes: int  # Time to Detect

    # 结果
    steady_state: dict = field(default_factory=dict)
    actual_ttd: Optional[float] = None
    actual_response: Optional[str] = None
    findings: List[str] = field(default_factory=list)

    def run(self):
        """执行实验"""

        # 1. 记录稳态
        self.steady_state = self._capture_steady_state()

        # 2. 注入安全事件
        start_time = datetime.now()
        self._inject()

        # 3. 监控检测
        detection_time = self._monitor_for_detection()
        if detection_time:
            self.actual_ttd = (
                detection_time - start_time
            ).total_seconds() / 60
        else:
            self.actual_ttd = None
            self.findings.append("NOT DETECTED within SLA")

        # 4. 记录响应
        self.actual_response = self._capture_response()

        # 5. 对比 SLA
        if self.actual_ttd and self.actual_ttd > self.sla_ttd_minutes:
            self.findings.append(
                f"TTD {self.actual_ttd:.1f}min > SLA {self.sla_ttd_minutes}min"
            )

        # 6. 清理
        self._cleanup()

        return self.generate_report()

    def _monitor_for_detection(self):
        """监控 SIEM 是否有相关的告警"""
        # 实际实现: 轮询 SIEM API 查找实验期间的新告警
        pass

    def generate_report(self):
        return {
            'experiment': self.name,
            'hypothesis': self.hypothesis,
            'detected': self.actual_ttd is not None,
            'ttd_minutes': self.actual_ttd,
            'sla_met': (self.actual_ttd or float('inf')) <= self.sla_ttd_minutes,
            'response': self.actual_response,
            'findings': self.findings
        }
```

---

## 3. 安全注入工具

### 3.1 ChaosMonkey for Security

```python
#!/usr/bin/env python3
"""
Security Chaos Monkey
在 K8s 环境中注入安全事件
"""

import kubernetes
import random
import time

class SecurityChaosMonkey:
    def __init__(self, namespace="chaos-test"):
        self.k8s = kubernetes.client.CoreV1Api()
        self.namespace = namespace

    def inject_privileged_pod(self):
        """注入特权 Pod — 测试 PSP/OPA 策略"""

        pod_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": f"chaos-priv-{random.randint(1000, 9999)}",
                "namespace": self.namespace,
                "labels": {"chaos": "security-test"}
            },
            "spec": {
                "containers": [{
                    "name": "test",
                    "image": "alpine:latest",
                    "command": ["sleep", "300"],
                    "securityContext": {
                        "privileged": True,  # ← 安全注入
                        "allowPrivilegeEscalation": True
                    }
                }],
                "hostPID": True,
                "hostNetwork": True
            }
        }

        try:
            self.k8s.create_namespaced_pod(
                self.namespace, pod_manifest
            )
            print("Privileged pod created — monitor for PSP/OPA denial")

            # 等待检测
            time.sleep(30)

            # 清理
            self.k8s.delete_namespaced_pod(
                pod_manifest["metadata"]["name"],
                self.namespace
            )
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 403:
                print("PSP/OPA blocked privileged pod — WORKING")
            else:
                print(f"Unexpected error: {e}")

    def inject_cve_scenario(self, cve_id):
        """模拟 CVE 攻击场景"""
        scenarios = {
            "CVE-2021-44228": self._inject_log4shell_honeypot,
            "CVE-2023-44487": self._inject_http2_rapid_reset,
        }

        if cve_id in scenarios:
            scenarios[cve_id]()
```

---

## 4. 持续验证

```yaml
安全混沌工程成熟度:

  Level 1 — 手动游戏日:
    - 每季度手动执行预定义场景
    - 在非工作时间进行
    - 人工观察和记录

  Level 2 — 半自动:
    - 自动化注入工具
    - 人工触发，自动监控
    - 自动生成报告

  Level 3 — 持续混沌:
    - CI/CD 集成
    - 每次部署后自动执行安全实验
    - 回归测试 (防止检测倒退)

  Level 4 — 响应式混沌:
    - 基于威胁情报自动生成新场景
    - 自适应注入策略
    - 零人工干预的端到端验证
```

---

## 参考资源

- [Principles of Chaos Engineering](https://principlesofchaos.org/)
- [Security Chaos Engineering (Kelly Shortridge)](https://www.oreilly.com/library/view/security-chaos-engineering/9781098113810/)
- [Chaos Monkey](https://github.com/Netflix/chaosmonkey)

---

*上一篇：[SAST/DAST/SCA](03-sast-dast-secrets.md)*

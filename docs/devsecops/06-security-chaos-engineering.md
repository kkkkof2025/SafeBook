# 安全混沌工程

> 在可控破坏中建立安全韧性

---

## 1. 安全混沌工程原理

```
传统安全测试:                安全混沌工程:
┌────────────┐              ┌────────────────────┐
│ 已知漏洞   │              │ 在系统中注入故障     │
│ 已知攻击面 │              │ 观察安全控制是否失效  │
│ 工具化扫描 │              │ 发现未知弱点        │
│ 频率: 周/月│              │ 持续运行            │
└────────────┘              └────────────────────┘

核心问题: "我们的安全控制在真实攻击下会失效吗?"
```

---

## 2. 安全混沌实验

### 实验设计模板
```yaml
安全混沌实验:
  name: "WAF 绕过混沌实验"
  hypothesis: "当 WAF 规则更新延迟超过 5 分钟时,我们能在 2 分钟内检测到攻击并告警"
  blast_radius: "非生产环境 (Staging)"
  steady_state: "所有 /login 端点的异常请求被 WAF 阻断并触发 SIEM 告警"
  
  experiment:
    - action: "暂停 WAF 规则自动同步"
    - inject: "从攻击节点发送 SQLi payload"
    - verify:
        - "SIEM 在 2 分钟内触发告警"
        - "SOC 收到告警通知"
        - "自动化封禁响应在 5 分钟内生效"
    
    rollback:
      - "恢复 WAF 规则同步"
      - "解封测试 IP"
```

### 自动化实验
```python
class SecurityChaosExperiment:
    """安全混沌实验执行引擎"""

    def __init__(self, kubernetes_client, siem_client):
        self.k8s = kubernetes_client
        self.siem = siem_client

    def run_credential_leak_experiment(self):
        """凭证泄露检测实验"""
        report = []

        # Step 1: 注入假凭证
        fake_aws_key = "AKIA" + secrets.token_hex(16)
        fake_secret = secrets.token_hex(20)

        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(name="test-leaked-secret"),
            string_data={"aws_key": fake_aws_key, "aws_secret": fake_secret}
        )
        self.k8s.create_namespaced_secret("default", secret)

        # Step 2: 等待检测
        time.sleep(120)

        # Step 3: 验证检测
        alerts = self.siem.query_alerts(
            query=f'aws_key:"{fake_aws_key}"',
            time_range='5m'
        )

        result = {
            'experiment': 'credential_leak_detection',
            'injected_at': datetime.utcnow().isoformat(),
            'detected': len(alerts) > 0,
            'detection_time_seconds': (
                alerts[0]['timestamp'] - inject_time if alerts else None
            ),
            'mean_time_to_detect': 'PASS' if len(alerts) > 0 else 'FAIL'
        }
        report.append(result)

        # Step 4: 清理
        self.k8s.delete_namespaced_secret("test-leaked-secret", "default")
        return report

    def run_iam_privilege_escalation_experiment(self):
        """IAM 权限提升检测实验"""

        # 创建低权角色 → 尝试绑定高权策略
        policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': 'iam:*',
                'Resource': '*'
            }]
        }

        # 尝试 AttachRolePolicy (在沙箱环境)
        try:
            iam.attach_role_policy(
                RoleName='chaos-test-role',
                PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
            )
        except:
            pass

        time.sleep(60)

        # 验证 CloudTrail + GuardDuty 检测
        findings = guardduty.list_findings(
            DetectorId=DETECTOR_ID,
            FindingCriteria={
                'Criterion': {
                    'type': {'Equals': ['PrivilegeEscalation:IAMUser/AdministrativePermissions']}
                }
            }
        )

        return {
            'experiment': 'iam_privilege_escalation',
            'detected': len(findings['FindingIds']) > 0,
            'findings': len(findings['FindingIds'])
        }
```

---

## 3. 工具链

| 工具 | 功能 | 场景 |
|------|------|------|
| Chaos Monkey | 随机终止 EC2 实例 | 可用性 |
| Gremlin | 全方位混沌实验 | CPU/内存/网络/安全 |
| Litmus Chaos | K8s 原生混沌工程 | 云原生 |
| Chaos Mesh | K8s 混沌实验平台 | 网络/IO/时间 |
| kube-monkey | K8s Pod 随机删除 | 自愈能力 |

```bash
# Litmus Chaos 安全实验
kubectl apply -f https://litmuschaos.github.io/litmus/litmus-operator.yaml

# WAF 绕过实验
apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: waf-bypass-test
spec:
  experiments:
    - name: waf-rule-disruption
      spec:
        components:
          env:
            - name: WAF_NAMESPACE
              value: security
            - name: DISRUPTION_DURATION
              value: '300'  # 5 分钟
```

---

## 4. 混沌工程成熟度

| 级别 | 描述 | 典型实验 |
|------|------|---------|
| 1 | 手动注入 | 手动关闭 WAF 规则 |
| 2 | 自动化注入 | 定时自动实验 |
| 3 | 持续验证 | 每次部署自动运行 |
| 4 | 自适应 | 根据监控数据自动调整 |
| 5 | 生产验证 | 有限制的生产环境实验 |

---

*上一篇：[蓝队防御进阶](../blue-team/03-advanced-blue-team.md)*

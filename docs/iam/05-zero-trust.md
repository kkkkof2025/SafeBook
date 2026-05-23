# 零信任架构实践

> 从"信任但验证"到"永不信任，始终验证"

---

## 零信任核心原则

```
传统边界安全:            零信任:
┌──────────────┐        ┌──────────────────────┐
│  防火墙       │        │  每个请求独立验证      │
│  ┌────────┐  │        │  ┌─────────────────┐ │
│  │内网=信任│  │   →    │  │身份 + 设备 + 上下文│ │
│  │外网=不信任│ │        │  │   = 动态访问决策  │ │
│  └────────┘  │        │  └─────────────────┘ │
└──────────────┘        └──────────────────────┘
```

---

## 1. 身份驱动的访问控制

### 基于属性的访问控制 (ABAC)
```python
class ZeroTrustPolicyEngine:
    """零信任策略引擎"""

    def evaluate(self, subject, resource, context):
        """
        subject: {user_id, role, clearance_level, auth_method}
        resource: {resource_type, sensitivity, owner}
        context: {device_health, location, time, network}
        """
        policy_checks = [
            # 1. 身份验证
            self.verify_authentication(subject),
            # 2. 设备合规
            self.verify_device_compliance(context.get('device')),
            # 3. 位置合理性
            self.verify_location(context.get('location'),
                                subject.get('usual_locations')),
            # 4. 时间合理性
            self.verify_time_window(context.get('time')),
            # 5. 资源敏感度 vs 认证强度
            self.verify_auth_strength(resource, subject),
            # 6. 最小权限
            self.verify_least_privilege(subject, resource),
        ]

        decision = all(policy_checks)

        if decision:
            return self.grant_access(subject, resource, context)
        else:
            return self.deny_with_reason(policy_checks)

    def verify_device_compliance(self, device):
        """设备合规性检查"""
        if not device:
            return False

        checks = [
            device.get('os_patched', False),
            device.get('antivirus_enabled', False),
            device.get('encryption_enabled', False),
            device.get('jailbroken', False) == False,
            device.get('managed', False),
        ]
        return all(checks)
```

### OAuth 2.0 + 设备认证
```python
# 零信任令牌格式
zero_trust_token = {
    'sub': 'user_12345',           # 用户
    'device_id': 'device_abc',     # 设备
    'auth_method': 'password+mfa', # 认证方式
    'device_health': 'compliant',  # 设备健康
    'access_level': 'standard',    # 动态访问级别
    'session_risk': 'low',         # 会话风险评分
    'exp': now + timedelta(minutes=15),
    'iat': now,
    'jti': unique_id
}
```

---

## 2. 微分段 (Micro-Segmentation)

```yaml
# Kubernetes NetworkPolicy 实现微分段
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: zero-trust-microseg
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # 仅允许来自 API 网关的流量
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - port: 8443
          protocol: TCP
  egress:
    # 仅允许访问数据库
    - to:
        - podSelector:
            matchLabels:
              app: payment-db
      ports:
        - port: 5432
          protocol: TCP
    # 拒绝所有其他出口
```

---

## 3. 持续验证

```python
class ContinuousVerification:
    """持续信任评估"""

    def __init__(self):
        self.sessions = {}  # session_id → trust_score

    def evaluate_behavior(self, session_id, action):
        """每次操作重新评估信任"""
        trust = self.sessions.get(session_id, 100)

        # 降级因子
        risk_factors = {
            'impossible_travel': -30,  # 位置异常跳变
            'unusual_hour': -10,       # 非工作时间
            'sensitive_resource': -15, # 访问敏感资源
            'large_data_transfer': -20,# 大量数据传输
            'new_device': -25,         # 新设备
            'failed_auth_recent': -40, # 最近认证失败
        }

        for factor, score in risk_factors.items():
            if self.check_factor(session_id, action, factor):
                trust += score
                log.warning(f"Trust score decreased: {factor}")

        # 信任阈值
        if trust < 30:
            # 强制重新认证 + 设备验证
            raise ReauthRequired(
                "Trust score too low. MFA + device attestation required."
            )
        elif trust < 50:
            # 限制操作范围
            action.restricted_mode = True

        self.sessions[session_id] = trust
        return trust >= 30
```

---

## 4. 零信任成熟度模型

| 阶段 | 特征 | 实现 |
|------|------|------|
| 传统 | 防火墙+内网信任 | VPN |
| 初级 | 身份认证+MFA | SSO + 2FA |
| 中级 | 设备合规+微分段 | MDM + NetworkPolicy |
| 高级 | 持续验证+动态策略 | 行为分析 + ABAC |
| 最优 | 全自动化+AI驱动 | SOAR + ML 异常检测 |

---

*上一篇：[IAM 高级场景与最佳实践](03-iam-advanced.md)*

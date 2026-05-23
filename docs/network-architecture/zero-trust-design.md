# 零信任网络设计

> 网络边界消亡后的安全架构

---

## 1. 零信任网络架构

```
传统网络:                          零信任网络:
┌─────────────────┐               ┌─────────────────────────┐
│    内网 (信任)   │               │   策略执行点 (PEP)       │
│  ┌──┐ ┌──┐ ┌──┐│               │  ┌───────────────────┐  │
│  │A │ │B │ │C ││               │  │ 策略判定点 (PDP)    │  │
│  └──┘ └──┘ └──┘│               │  │                   │  │
│       ┌──┐      │               │  │ 身份 + 设备 + 上下文│  │
│  外网 │攻击│     │               │  │ = 动态访问决策      │  │
│       └──┘      │               │  └───────────────────┘  │
└─────────────────┘               └─────────────────────────┘
                                           │
                                   ┌───────┴────────┐
                                   │                │
                              ┌────┴────┐    ┌─────┴─────┐
                              │ 工作负载 │    │   用户     │
                              └─────────┘    └───────────┘
```

---

## 2. 零信任核心组件

### 策略引擎
```python
class ZeroTrustPolicyEngine:
    """零信任策略判定引擎"""

    def evaluate_access(self, request):
        """
        评估访问请求: Allow/Deny/MFA Challenge
        """
        decision = {
            'allowed': False,
            'require_mfa': False,
            'require_device_check': False,
            'restrictions': [],
            'session_ttl': timedelta(hours=8)
        }

        # 1. 身份验证
        if not self.verify_identity(request):
            decision['restrictions'].append('AUTHENTICATION_FAILED')
            return decision

        # 2. 设备信任
        device_trust = self.assess_device(request.device_id)
        if device_trust.score < 30:
            decision['restrictions'].append('DEVICE_UNTRUSTED')
            return decision
        elif device_trust.score < 70:
            decision['require_mfa'] = True

        # 3. 上下文评估
        context_risk = self.assess_context(request)
        if context_risk.score > 70:
            decision['restrictions'].append('HIGH_RISK_CONTEXT')
            return decision

        # 4. 资源敏感性
        if request.resource.tier == 'P0':
            decision['require_mfa'] = True
            decision['session_ttl'] = timedelta(hours=1)

        # 5. 策略决策
        decision['allowed'] = len(decision['restrictions']) == 0
        return decision

    def assess_device(self, device_id):
        """设备信任评分"""
        device = self.mdm.get_device(device_id)
        score = 0

        if device.os_patched: score += 20
        if device.encryption_enabled: score += 20
        if device.antivirus_running: score += 15
        if not device.jailbroken: score += 15
        if device.managed: score += 15

        # 减分项
        if (datetime.utcnow() - device.last_checkin).days > 7:
            score -= 30
        if device.os in UNSUPPORTED_OS:
            score -= 50

        return DeviceTrust(score=score, device=device)

    def assess_context(self, request):
        """上下文风险评估"""
        risk = 0

        # 地理位置
        if request.location.country not in request.user.usual_countries:
            risk += 30
            if request.location.is_sanctioned:
                risk += 40

        # 时间
        hour = request.timestamp.hour
        if hour < 6 or hour > 22:
            risk += 15  # 深夜访问

        # 异常行为
        if self.is_impossible_travel(request):
            risk += 50  # 位置异常跳变

        # 网络
        if request.network_type == 'public_wifi':
            risk += 20

        return RiskAssessment(score=min(100, risk))
```

---

## 3. 微隔离实现

```python
class MicroSegmentationController:
    """微隔离策略控制器"""

    def __init__(self):
        self.policies = self.load_policies()

    def allow_connection(self, src, dst, port, protocol):
        """
        检查微隔离策略: 工作负载 A → 工作负载 B:port
        """
        # 1. 查策略
        policy = self.policies.get(f"{src.workload_id}→{dst.workload_id}")
        if not policy:
            return PolicyResult(
                allowed=False,
                reason="No policy defined — default deny"
            )

        # 2. 检查端口/协议
        if (port, protocol) not in policy.allowed_flows:
            return PolicyResult(
                allowed=False,
                reason=f"Port {port}/{protocol} not in allowed flows"
            )

        # 3. 检查身份
        if not self.verify_spiffe_identity(src):
            return PolicyResult(
                allowed=False,
                reason="SPIFFE identity verification failed"
            )

        # 4. 动态策略 (基于当前威胁等级)
        if self.threat_level == 'ELEVATED' and policy.require_quarantine:
            return PolicyResult(
                allowed=False,
                reason="Network in quarantine mode"
            )

        # 5. 记录访问日志
        self.log_access(src, dst, port, protocol, 'ALLOWED')

        return PolicyResult(allowed=True)
```

### Kubernetes 微隔离
```yaml
# Cilium NetworkPolicy (eBPF 微隔离)
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: payment-service-isolation
spec:
  endpointSelector:
    matchLabels:
      app: payment-service
  ingress:
    # 仅允许 API Gateway
    - fromEndpoints:
        - matchLabels:
            app: api-gateway
      toPorts:
        - ports:
            - port: "8443"
              protocol: TCP
  egress:
    # 仅允许数据库 + 密钥服务
    - toEndpoints:
        - matchLabels:
            app: payment-db
      toPorts:
        - ports:
            - port: "5432"
              protocol: TCP
    - toEndpoints:
        - matchLabels:
            app: vault
      toPorts:
        - ports:
            - port: "8200"
              protocol: TCP
  # DNS 白名单
  - toEndpoints:
      - matchLabels:
          io.kubernetes.pod.namespace: kube-system
          k8s-app: coredns
    toPorts:
      - ports:
          - port: "53"
            protocol: UDP
```

---

## 4. 零信任成熟度路线图

| 阶段 | 聚焦 | 里程碑 |
|------|------|--------|
| 第1年 | 身份 | SSO + MFA 100%, 设备清单 |
| 第2年 | 设备 | 设备合规检查 + MDM |
| 第3年 | 网络 | 微隔离上线 + 应用分段 |
| 第4年 | 数据 | 数据分类 + DLP + 加密 |
| 第5年 | 自动化 | AI 驱动自适应策略 |

---

*上一篇：[SDN 安全架构](05-sdn-security.md)*

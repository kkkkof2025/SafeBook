# 微分段与零信任网络

## 概述

微分段（Microsegmentation）是零信任架构的核心技术，通过精细化的网络策略将数据中心东西向流量控制到单个工作负载级别，即使攻击者突破边界也无法横向移动。

---

## 1. 微分段架构

### 1.1 三种实现模型

| 模型 | 实现方式 | 优势 | 劣势 |
|------|----------|------|------|
| 主机代理 | 主机防火墙代理 (Agent-based) | 粒度最细，独立于网络 | 代理管理开销 |
| 网络覆盖 | SDN/VXLAN 策略 | 网络层统一管理 | 依赖网络设备 |
| 云原生 | 安全组 + Kubernetes NetworkPolicy | 云原生集成 | 仅限特定平台 |

### 1.2 微分段 vs 传统分段

```
传统 VLAN 分段:             微分段:
┌─────────────────┐        ┌─────────────────┐
│   VLAN 10       │        │ ┌──┐ ┌──┐ ┌──┐ │
│  ┌──┐ ┌──┐ ┌──┐ │        │ │A │ │B │ │C │ │
│  │A │ │B │ │C │ │        │ └──┘ └──┘ └──┘ │
│  └──┘ └──┘ └──┘ │        │  ↓   ↓   ↓     │
│  A可访问B,C      │        │ A→B ✓  A→C ✗   │
└─────────────────┘        └─────────────────┘
  同VLAN内无限制              工作负载级策略
```

---

## 2. Kubernetes NetworkPolicy

### 2.1 默认拒绝策略

```yaml
# 全局默认拒绝所有 Ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}  # 所有 Pod
  policyTypes:
  - Ingress

---
# 全局默认拒绝所有 Egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
```

### 2.2 精细化策略

```yaml
# API 服务仅允许 Frontend 访问
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow-frontend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-service
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080

---
# 数据库仅允许 API 服务访问
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-allow-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: postgres-db
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-service
    ports:
    - protocol: TCP
      port: 5432

---
# 允许 API 出站到数据库和外部 API
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-egress-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-service
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres-db
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53  # DNS
  - to:
    - ipBlock:
        cidr: 10.0.0.0/8  # 允许访问内部服务
        except:
        - 10.0.1.0/24   # 禁止访问安全区
```

---

## 3. 服务网格微分段

### 3.1 Istio AuthorizationPolicy

```yaml
# 命名空间级别：只允许同命名空间内通信
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-same-namespace
  namespace: production
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        namespaces: ["production"]

---
# 服务级别：payment-service 仅允许 checkout-service 调用
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payment-access-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/checkout-service"]
    to:
    - operation:
        methods: ["POST"]
        paths: ["/api/payment/process"]

---
# JWT 声明级别：仅允许管理员
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: admin-only
  namespace: production
spec:
  selector:
    matchLabels:
      app: admin-panel
  action: ALLOW
  rules:
  - from:
    - source:
        requestPrincipals: ["*"]
    when:
    - key: request.auth.claims[role]
      values: ["admin", "superadmin"]
```

---

## 4. 云原生微分段

### 4.1 AWS Security Groups

```terraform
# Terraform: 精细化安全组策略
resource "aws_security_group" "app_tier" {
  name        = "app-tier"
  description = "Application tier security group"

  # 仅允许来自 ALB 的 HTTP 流量
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "Allow HTTP from ALB"
  }

  # 出站仅到数据库安全组
  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.db.id]
    description     = "Allow PostgreSQL to DB"
  }

  # 出站 HTTPS 到特定 S3 VPC Endpoint
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    prefix_list_ids = [data.aws_vpc_endpoint.s3.prefix_list_id]
    description = "Allow S3 access via VPC Endpoint"
  }
}

resource "aws_security_group" "db" {
  name = "db-tier"

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
  }

  # 拒绝所有出站 (零信任法则)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    # 仅允许通过 VPC Endpoint 的流量
  }
}
```

### 4.2 GCP Firewall Rules

```bash
# GCP 分层防火墙策略
# Tier 1: 全局策略 - 默认拒绝所有入站
gcloud compute firewall-rules create default-deny-ingress \
  --direction=INGRESS \
  --priority=65535 \
  --network=default \
  --action=DENY \
  --rules=all

# Tier 2: 允许健康检查
gcloud compute firewall-rules create allow-health-check \
  --direction=INGRESS \
  --priority=1000 \
  --network=default \
  --action=ALLOW \
  --rules=tcp:8080 \
  --source-ranges=130.211.0.0/22,35.191.0.0/16 \
  --target-tags=web-server

# Tier 3: 服务到服务策略（使用 Service Accounts）
gcloud compute firewall-rules create allow-to-db \
  --direction=INGRESS \
  --priority=1000 \
  --network=default \
  --action=ALLOW \
  --rules=tcp:5432 \
  --source-service-accounts=app-sa@project.iam.gserviceaccount.com \
  --target-service-accounts=db-sa@project.iam.gserviceaccount.com
```

---

## 5. 微分段策略设计

### 5.1 应用依赖映射

```python
"""
应用依赖映射工具
分析流量日志生成微分段策略
"""

def analyze_traffic_flows(flow_logs):
    """
    输入: VPC Flow Logs / NetFlow / sFlow 数据
    输出: 建议的微分段策略规则
    """
    flows = defaultdict(set)

    for log in flow_logs:
        src = f"{log['src_app']}:{log['src_tier']}"
        dst = f"{log['dst_app']}:{log['dst_tier']}"
        port = log['dst_port']
        flows[(src, dst)].add(port)

    # 生成策略
    policies = []
    for (src, dst), ports in flows.items():
        src_app, src_tier = src.split(':')
        dst_app, dst_tier = dst.split(':')

        policy = {
            'source': {'app': src_app, 'tier': src_tier},
            'destination': {'app': dst_app, 'tier': dst_tier},
            'ports': sorted(ports),
            'risk': 'high' if dst_tier == 'db' else 'medium'
        }
        policies.append(policy)

    return policies

# 使用示例
flows = parse_vpc_flow_logs('vpc-flows-2024.json')
policies = analyze_traffic_flows(flows)

print(f"发现 {len(policies)} 条应用依赖")
for p in policies:
    print(f"  {p['source']['app']} → {p['destination']['app']} "
          f"[{','.join(map(str, p['ports']))}]")
```

### 5.2 策略生命周期管理

```yaml
微分段策略生命周期:
  1. Discover (发现):
     - 收集 30 天流量日志
     - 构建应用依赖拓扑图
     - 识别意外/异常流量

  2. Design (设计):
     - 基于最小权限原则设计策略
     - 定义例外清单
     - 编写 Infrastructure-as-Code

  3. Test (测试):
     - 在 staging 环境验证
     - 策略模拟 (dry-run / shadow mode)
     - 性能回归测试

  4. Deploy (部署):
     - 分阶段部署 (先 LOG 再 ENFORCE)
     - 监控拒绝日志
     - 建立快速回滚机制

  5. Maintain (维护):
     - 月度策略审查
     - 自动过期未使用策略 (30天)
     - 策略变更审批流程
```

---

## 6. 零信任参考架构

```
          Internet
              │
    ┌─────────┴──────────┐
    │    WAF / CDN       │
    │  (外部流量清洗)      │
    └─────────┬──────────┘
              │
    ┌─────────┴──────────┐
    │  Identity-Aware    │
    │  Proxy (IAP/BeyondCorp)│
    └─────────┬──────────┘
              │
    ┌─────────┴──────────┐
    │   零信任网关        │
    │  - 持续认证         │
    │  - 设备信任评估      │
    │  - 动态授权         │
    └─────────┬──────────┘
              │
    ┌─────────┴──────────────┐
    │     微分段应用空间       │
    │  ┌──┐  ┌──┐  ┌──┐     │
    │  │A │  │B │  │C │     │
    │  └──┘  └──┘  └──┘     │
    │    ↓     ↓     ↓      │
    │  策略引擎 (PDP)        │
    └────────────────────────┘
```

**核心原则**：
1. 永不信任，始终验证
2. 最小权限访问
3. 假定已受入侵
4. 持续监控与验证

---

## 参考资源

- [NIST SP 800-207: Zero Trust Architecture](https://www.nist.gov/publications/zero-trust-architecture)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Istio Security](https://istio.io/latest/docs/concepts/security/)

---

*上一篇：[企业网络安全架构](./01-network-architecture-security.md)*

*下一篇：[SDN 与网络虚拟化安全](04-sdn-security.md)*

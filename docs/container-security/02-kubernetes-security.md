# Kubernetes 安全

> Pod、RBAC、网络策略——K8s 安全三要素

---

## K8s 安全模型

Kubernetes 是 AI 工作负载的主流编排平台，安全至关重要。

### K8s 的攻击面

```
          ┌──────────────────┐
          │    API Server     │  ← 认证/授权/准入控制
          └────────┬─────────┘
                   │
      ┌────────────┼────────────┐
      ▼            ▼            ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│  etcd     │ │ Controller│ │  Scheduler│
│  (数据)   │ │ Manager   │ │          │
└──────────┘ └──────────┘ └──────────┘
                   │
      ┌────────────┼────────────┐
      ▼            ▼            ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│  Node 1   │ │  Node 2   │ │  Node 3   │
│  Kubelet  │ │  Kubelet  │ │  Kubelet  │
│  ┌────┐   │ │  ┌────┐   │ │  ┌────┐   │
│  │Pod │   │ │  │Pod │   │ │  │Pod │   │
│  └────┘   │ │  └────┘   │ │  └────┘   │
└──────────┘ └──────────┘ └──────────┘
```

---

## RBAC——K8s 安全的核心

### 为什么 RBAC 最重要

> K8s 中的一切操作都是 API 调用。RBAC 决定谁可以调用什么 API。

### 默认 RBAC 配置（危险！）

```bash
# ❌ 许多人在开发环境中这样做

# 给 ServiceAccount 绑定集群管理员权限
kubectl create clusterrolebinding permissive-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default
  
# 结果：该 Namespace 下的所有 Pod 都有集群管理员权限
```

### 最小权限 RBAC

```yaml
# ✅ 正确：AI 训练 Pod 只需要读取数据和写入模型

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: ai-training
  name: model-reader
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: ai-training
  name: model-reader-binding
subjects:
- kind: ServiceAccount
  name: ai-trainer-sa
  namespace: ai-training
roleRef:
  kind: Role
  name: model-reader
  apiGroup: rbac.authorization.k8s.io
```

### RBAC 审计

```bash
# 检查谁有管理员权限
kubectl get clusterrolebindings -o yaml | grep "cluster-admin" -A 10

# 检查特定 ServiceAccount 的权限
kubectl auth can-i --list --as=system:serviceaccount:ai-training:ai-trainer-sa

# 检查谁可以创建 Pod
kubectl describe clusterrolebinding | grep -B 5 "create.*pods"

# 使用 kubeaudit 检查
kubeaudit rbac
```

---

## Pod 安全

### Pod Security Standards（PSS）

K8s 定义了三个 Pod 安全级别：

| 级别 | 说明 | 适用场景 |
|------|------|---------|
| **Privileged** | 无限制 | 系统级组件（不用于普通应用） |
| **Baseline** | 最低限制 | 通用应用 |
| **Restricted** | 严格限制 | 高安全要求的 Pod |

### 正确配置

```yaml
# ✅ AI 推理 Pod 的 Restricted 级别配置

apiVersion: v1
kind: Pod
metadata:
  name: ai-inference
  labels:
    app: ai-inference
spec:
  serviceAccountName: inference-sa
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: inference
    image: ai-model:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
      privileged: false
    resources:
      limits:
        cpu: "2"
        memory: "4Gi"
        nvidia.com/gpu: 1
```

### Pod 安全准入（PSA）

```yaml
# 在 Namespace 级别强制执行 Pod 安全标准

apiVersion: v1
kind: Namespace
metadata:
  name: ai-production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

---

## 网络策略

### 默认：所有 Pod 可以互相通信

> K8s 的默认网络策略是"允许所有"。这不是安全配置。

### 网络策略配置

```yaml
# ✅ 正确的网络隔离

# 1. 默认拒绝所有入站流量（放每个 Namespace）
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
---
# 2. AI 推理 Pod：只允许来自 Ingress 控制器的流量
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ai-inference-policy
spec:
  podSelector:
    matchLabels:
      app: ai-inference
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - port: 8080
      protocol: TCP
---
# 3. 数据库 Pod：只允许 AI 推理 Pod 访问
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-policy
spec:
  podSelector:
    matchLabels:
      app: redis
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: ai-inference
    ports:
    - port: 6379
      protocol: TCP
```

---

## 密钥管理

### 使用 Secret，不用 ConfigMap 存敏感信息

```yaml
# ❌ 错误：API Key 放在 ConfigMap 中（明文）
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  api_key: "sk-xxxxxxxxxxxxxxxx"  # 明文！

# ✅ 正确：使用 Secret
apiVersion: v1
kind: Secret
metadata:
  name: api-credentials
type: Opaque
data:
  api_key: <Base64编码>
  # 注意：Base64 不是加密！需要配合 RBAC 限制谁可以读取

# 更好的做法：使用外部密钥管理（如 AWS Secrets Manager）
# 通过 CSI Driver 挂载到 Pod
```

### 外部密钥管理

```yaml
# 使用 AWS Secrets Manager CSI Driver
# 密钥从 AWS 拉取，不在集群中持久化

apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: aws-secrets
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "prod/ai-api-key"
        objectType: "secretsmanager"
```

---

## AI 场景：推理端点的 K8s 安全

```yaml
# AI 推理服务的完整安全部署

apiVersion: apps/v1
kind: Deployment
metadata:
  name: model-inference
  namespace: inference
spec:
  replicas: 3
  selector:
    matchLabels:
      app: model-inference
  template:
    metadata:
      labels:
        app: model-inference
    spec:
      serviceAccountName: inference-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
      containers:
      - name: model-server
        image: my-model:v2.1.0
        ports:
        - containerPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        resources:
          limits:
            cpu: "4"
            memory: "8Gi"
            nvidia.com/gpu: 1
        env:
        - name: MODEL_PATH
          value: "/models/v2"
        volumeMounts:
        - name: models
          mountPath: /models
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
      volumes:
      - name: models
        persistentVolumeClaim:
          claimName: model-storage
---
apiVersion: v1
kind: Service
metadata:
  name: model-inference
spec:
  selector:
    app: model-inference
  ports:
  - port: 443
    targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: inference-network
spec:
  podSelector:
    matchLabels:
      app: model-inference
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-system
    ports:
    - port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - port: 6379
```

---

## K8s 安全审计

```bash
# kube-bench — CIS Benchmark 检查
kube-bench run --targets master,node

# kube-hunter — 漏洞扫描
kube-hunter

# kubeaudit — 审计容器/集群配置
kubeaudit all --namespace ai-production

# Popeye — 集群健康检查
popeye --namespace ai-production

# Checkov — 扫描 K8s YAML
checkov -d ./k8s-manifests/
```

---

## K8s 安全检查清单

- [ ] RBAC 遵循最小权限原则吗？
- [ ] Pod 不以 root 运行吗？
- [ ] Pod 开启了 seccomp/AppArmor 吗？
- [ ] 网络策略配置了默认拒绝吗？
- [ ] Secret 限制了访问权限吗？
- [ ] 镜像从可信仓库拉取吗？
- [ ] 有资源限制防止 DoS 吗？
- [ ] API Server 开启了审计日志吗？
- [ ] etcd 加密了吗？
- [ ] 定期运行 kube-bench 检查吗？

---

## 延伸阅读

1. [K8s 安全最佳实践](https://kubernetes.io/docs/concepts/security/)
2. [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
3. [OWASP K8s Security](https://owasp.org/www-project-kubernetes-security/)
4. [NSA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
5. [kube-bench](https://github.com/aquasecurity/kube-bench)
6. [K8s AI/ML Workload Security](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/ml-workloads/)

# Kubernetes RBAC 加固

## Kubernetes RBAC 概述

基于角色的访问控制 (RBAC) 是 Kubernetes 的核心安全机制。

### 核心概念

1. **Role/ClusterRole** - 定义权限集合
2. **Subject** - 用户、组或服务账户
3. **RoleBinding/ClusterRoleBinding** - 绑定角色到主体

---

## RBAC 风险控制

### 风险1：过度权限的 ClusterRole

**问题：** 使用 `cluster-admin` 或自定义过于宽松的 ClusterRole

```yaml
# 危险示例：过于宽松的 ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: overly-permissive
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]  # 等同于 cluster-admin
```

**修复：**

```yaml
# 安全示例：最小权限 ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: limited-access
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]  # 仅允许读取 Pod
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"]
```

### 风险2：未使用命名空间隔离

**问题：** 在 `default` 命名空间中运行所有工作负载

**修复：**

```bash
# 创建专用命名空间
kubectl create namespace app-team-a

# 将 RoleBinding 限制在命名空间内
kubectl create rolebinding app-team-a-binding \
  --clusterrole=app-team-a-role \
  --serviceaccount=app-team-a:default \
  --namespace=app-team-a
```

### 风险3：ServiceAccount 未绑定最小权限

**问题：** 默认 ServiceAccount 挂载到每个 Pod，且可能具有过度权限

**修复：**

```yaml
# 禁用自动挂载默认 ServiceAccount
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  automountServiceAccountToken: false  # 禁用自动挂载
  serviceAccountName: custom-sa  # 使用自定义 ServiceAccount
```

---

## RBAC 加固策略

### 1. 实施最小权限原则

**策略：**
- 每个 ServiceAccount 只授予执行其任务所需的最小权限
- 避免使用 `cluster-admin` ClusterRole
- 使用 `kubectl auth reconcile` 验证权限

```bash
# 验证用户的权限
kubectl auth can-i create pods --as=user1
kubectl auth can-i delete pods --as=user1 -n default

# 模拟 Group 权限
kubectl auth can-i "*" "*" --as-group=dev-team
```

### 2. 使用命名空间隔离

**策略：**
- 按团队/项目划分命名空间
- 在命名空间内使用 Role (而非 ClusterRole)
- 跨命名空间共享时使用 ClusterRole + RoleBinding

```yaml
# 跨命名空间共享 ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cross-namespace-access
  namespace: team-b
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: team-a  # 来自 team-a 命名空间
roleRef:
  kind: ClusterRole
  name: shared-cluster-role
  apiGroup: rbac.authorization.k8s.io
```

### 3. 审计 RBAC 配置

**工具：** `kubectl get role,rolebinding,clusterrole,clusterrolebinding`

```bash
# 列出所有 ClusterRoleBinding
kubectl get clusterrolebinding -o json | jq '.items[] | {name: .metadata.name, subjects: .subjects}'

# 检查绑定到 cluster-admin 的主体
kubectl get clusterrolebinding -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.subjects}{"\n"}{end}'
```

### 4. 使用 RBAC Manager 简化管理

**工具：** [RBAC Manager](https://github.com/reactiveopsio/rbac-manager)

```yaml
# RBAC Manager 定义 (简化)
apiVersion: rbac.reactiveops.io/v1beta1
kind: RBACDefinition
metadata:
  name: app-team-a
spec:
  namespaces:
  - app-team-a
  bindings:
  - role: app-team-a-role
    subjects:
    - kind: ServiceAccount
      name: app-sa
      namespace: app-team-a
```

---

## 高级 RBAC 场景

### 场景1：限制节点访问

**需求：** 只允许特定用户访问节点资源

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-admin
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch", "update", "patch"]
- apiGroups: [""]
  resources: ["nodes/status"]
  verbs: ["get", "update", "patch"]
```

### 场景2：限制持久卷 (PV) 访问

**需求：** 只允许特定团队访问其 PV

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pv-access
  namespace: team-a
rules:
- apiGroups: [""]
  resources: ["persistentvolumes"]
  verbs: ["get", "list", "watch"]
  resourceNames: ["pv-team-a-001", "pv-team-a-002"]  # 限制特定 PV
```

### 场景3：实施时间限制访问

**需求：** 临时授予权限，过期自动撤销

**方案：** 使用 `kubectl auth reconcile` + CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: revoke-temp-access
spec:
  schedule: "0 0 * * *"  # 每天午夜执行
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: revoke
            image: bitnami/kubectl
            command:
            - /bin/bash
            - -c
            - |
              kubectl delete rolebinding temp-access --ignore-not-found=true
          restartPolicy: OnFailure
```

---

## RBAC 工具链

### 1. Rakkess

**功能：** 查看集群中所有资源的访问权限

```bash
# 安装
curl -Lo rakkess https://github.com/cornops/rakkess/releases/download/v0.5.2/rakkess-linux-amd64 && chmod +x rakkess && sudo mv rakkess /usr/local/bin/

# 查看所有资源的访问权限
rakkess

# 查看特定资源的访问权限
rakkess --verb=create --resource=pods
```

### 2. kubectl-who-can

**功能：** 快速查找谁可以执行特定操作

```bash
# 安装 kubectl-who-can 插件
kubectl krew install who-can

# 查找谁可以创建 Pod
kubectl who-can create pods

# 查找谁可以删除 Deployment
kubectl who-can delete deployments.apps
```

### 3. K8S-RBAC-Audit

**功能：** 审计 RBAC 配置，检测过度权限

```bash
# 运行审计
docker run -v ~/.kube/config:/root/.kube/config c0ny1/k8s-rbac-audit

# 生成报告
k8s-rbac-audit --output=report.html
```

---

## RBAC 最佳实践清单

### 规划设计

- [ ] 按团队/项目划分命名空间
- [ ] 定义角色层次结构 (基础角色 → 高级角色)
- [ ] 避免使用 `cluster-admin` ClusterRole
- [ ] 使用 `kubectl auth reconcile` 验证权限

### 实施部署

- [ ] 禁用默认 ServiceAccount 自动挂载
- [ ] 为每个工作负载创建专用 ServiceAccount
- [ ] 使用 Role (而非 ClusterRole) 限制命名空间内访问
- [ ] 定期审计 RBAC 配置

### 监控审计

- [ ] 启用 Kubernetes 审计日志 (Audit Log)
- [ ] 监控 `kubectl auth can-i` 异常请求
- [ ] 使用 Rakkess 定期审查权限
- [ ] 实施 RBAC 变更审批流程

---

## 延伸阅读

- [Kubernetes RBAC 官方文档](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [RBAC Manager](https://github.com/reactiveopsio/rbac-manager)
- [Kubernetes Security Book](https://www.oreilly.com/library/view/kubernetes-security/)

---

**下一步：** 学习 [威胁情报](#威胁情报)，掌握威胁情报分析和应用。

# Kubernetes 安全工具链

## 概述

Kubernetes 的安全工具生态已经从零散脚本发展为完整的 CI/CD 安全流水线。从镜像扫描到运行时保护，从策略即代码到合规审计——本章梳理 K8s 安全工具矩阵。

---

## 1. 安全工具全景图

### 1.1 K8s 安全生命周期工具

```
K8s 安全生命周期 & 工具矩阵:

开发阶段:
  Build   → Trivy, Snyk, Grype (镜像扫描)
  Lint    → KubeLinter, Checkov, KICS (IaC 扫描)
  Sign    → Cosign, Notary (镜像签名)

部署阶段:
  Policy  → OPA/Gatekeeper, Kyverno (策略引擎)
  RBAC    → RBAC Tool, kube-rbac-proxy (权限审计)
  Network → Calico, Cilium (网络策略)

运行阶段:
  Runtime → Falco, Tetragon (运行时安全)
  Audit   → kube-bench, kube-hunter (合规扫描)
  Monitor → Prometheus, Grafana, Datadog

事件响应:
  Forensics → kube-forensics, kubesploit
  Recovery  → Velero (备份恢复)
```

### 1.2 工具分类速查

| 工具 | 功能 | 安装 |
|------|------|------|
| **Trivy** | 镜像/CVE/IaC 扫描 | `brew install trivy` |
| **Falco** | 运行时威胁检测 | `helm install falco falcosecurity/falco` |
| **OPA/Gatekeeper** | 策略即代码 | `kubectl apply -f gatekeeper.yaml` |
| **Kyverno** | 策略引擎 (K8s原生) | `helm install kyverno kyverno/kyverno` |
| **kube-bench** | CIS 合规扫描 | `kubectl apply -f job.yaml` |
| **kube-hunter** | 渗透测试 | `pip install kube-hunter` |
| **KubeLinter** | YAML 安全 Lint | `brew install kube-linter` |
| **Cosign** | 镜像签名验证 | `brew install cosign` |
| **Checkov** | IaC 安全扫描 | `pip install checkov` |

---

## 2. 策略即代码 (Policy-as-Code)

### 2.1 OPA/Gatekeeper

```yaml
# OPA Gatekeeper ConstraintTemplate — 禁止 privileged 容器

apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdenyprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sDenyPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdenyprivileged

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged == true
          msg := sprintf("Privileged container is not allowed: %v", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          container.securityContext.privileged == true
          msg := sprintf("Privileged initContainer is not allowed: %v", [container.name])
        }
---
# 应用约束
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDenyPrivileged
metadata:
  name: deny-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]
```

### 2.2 Kyverno

```yaml
# Kyverno ClusterPolicy — 全面安全策略

apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: pod-security-standards
spec:
  validationFailureAction: Enforce  # 强制执行 (默认 Audit)
  rules:
    - name: disallow-host-namespaces
      match:
        any:
        - resources:
            kinds: [Pod]
      validate:
        message: "Host namespaces (hostPID, hostIPC, hostNetwork) 不允许"
        pattern:
          spec:
            =(hostPID): "false"
            =(hostIPC): "false"
            =(hostNetwork): "false"

    - name: disallow-host-ports
      match:
        any:
        - resources:
            kinds: [Pod]
      validate:
        message: "Host Ports 不允许超过 1024"
        pattern:
          spec:
            containers:
              - =(ports):
                  - =(hostPort): ">=0 & <=1024"

    - name: require-run-as-nonroot
      match:
        any:
        - resources:
            kinds: [Pod]
      validate:
        message: "容器必须以非 root 用户运行"
        pattern:
          spec:
            securityContext:
              runAsNonRoot: true
            containers:
              - securityContext:
                  runAsNonRoot: true
    - name: require-resource-limits
      match:
        any:
        - resources:
            kinds: [Pod]
      validate:
        message: "必须设置 CPU 和内存限制"
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    memory: "?*"
                    cpu: "?*"
```

---

## 3. CI/CD 安全流水线

### 3.1 GitHub Actions 完整流水线

```yaml
# .github/workflows/k8s-security-pipeline.yml

name: K8s Security Pipeline

on:
  pull_request:
  push:
    branches: [main]

jobs:
  # 1. 镜像扫描
  image-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Trivy Scan (CVE)
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: sarif
          output: trivy-cve.sarif
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-cve.sarif

      - name: Trivy Scan (配置错误)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          scan-ref: ./k8s/
          severity: CRITICAL,HIGH

  # 2. 签名验证
  sign-image:
    needs: image-scan
    runs-on: ubuntu-latest
    steps:
      - name: Cosign Sign
        uses: sigstore/cosign-installer@v3
      - run: |
          cosign sign --key cosign.key myapp:${{ github.sha }}

  # 3. K8s 清单 Lint
  lint-manifests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: KubeLinter
        uses: stackrox/kube-linter-action@v1
        with:
          directory: k8s/
          config: .kube-linter.yaml

      - name: Checkov (IaC)
        uses: bridgecrewio/checkov-action@master
        with:
          directory: k8s/
          skip_check: CKV_K8S_21  # 跳过只读根文件系统检查

  # 4. 合规审计
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - name: kube-bench (CIS)
        run: |
          kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
```

---

## 4. 运行时安全

### 4.1 Falco 规则

```yaml
# Falco 自定义规则

- rule: Container Drift Detected
  desc: 检测容器运行时文件变更 (不可变基础设施违反)
  condition: >
    evt.type in (open,openat,creat) and
    container.id != host and
    not proc.name in (known_file_modifiers)
  output: >
    容器文件变更检测: %proc.name 在容器 %container.name 中修改了 %fd.name
    (user=%user.name uid=%user.uid container_id=%container.id)
  priority: WARNING
  tags: [filesystem, drift]
  list: known_file_modifiers
  items: [bash]

- rule: Kubernetes ServiceAccount Accessed from Pod
  desc: 检测容器内访问 K8s API (可能是横向移动)
  condition: >
    fd.sport != 443 and
    (fd.sip.name in (kubernetes_service_ips) or
     fd.sip.name = "kubernetes.default.svc.cluster.local")
  output: >
    K8s API 访问: %proc.name 在 Pod %pod.name 中访问了 API server
    (user=%user.name  ip=%fd.cip  cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [k8s, lateral_movement]

- list: kubernetes_service_ips
  items: ['"10.96.0.1"', '"10.100.0.1"']  # 根据集群配置调整

- rule: Privileged Container Started
  desc: 检测启动特权容器
  condition: >
    evt.type = container and
    container.privileged = true and
    not container.image.repository in (trusted_privileged_images)
  output: >
    特权容器启动: %container.name (image=%container.image)
    (user=%user.name pod=%pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  list: trusted_privileged_images
  items: []
```

---

## 参考资源

- [Aqua Trivy](https://github.com/aquasecurity/trivy)
- [Falco 运行时安全](https://falco.org/)
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- [Kyverno 策略引擎](https://kyverno.io/)

---

*上一篇：[Kubernetes RBAC 硬化](./03-kubernetes-rbac-hardening.md)*

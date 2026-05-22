# 容器与 Kubernetes 安全

> 容器化的世界——每一个镜像都是一个攻击面，每一个 Pod 都是一个资产。

---

## 为什么容器安全至关重要

AI、微服务、云原生——生产环境几乎已全面容器化：

```
模型训练 → Docker 容器 (GPU驱动 + PyTorch)
模型推理 → K8s Pod (模型服务 + API网关)
CI/CD    → 容器镜像流式构建推送
```

**一个容器漏洞 = 整个应用管道受影响**。

---

## 容器攻击面全景图

```
                    ┌──────────────────────────────────┐
                    │          容器攻击面全景            │
                    └────────────┬─────────────────────┘
         ┌──────────────────────┼──────────────────────┐
         │                      │                      │
   ┌─────┴─────┐          ┌────┴────┐          ┌──────┴──────┐
   │ 镜像层     │          │ 运行时层 │          │  编排层      │
   │           │          │          │          │            │
   │ 基础镜像  │          │ 容器逃逸 │          │ RBAC 错误  │
   │ 旧组件    │          │ 特权模式 │          │ 网络策略   │
   │ 硬编码密钥│          │ 挂载敏感 │          │ Pod 安全   │
   │ 恶意依赖  │          │ Capability│         │ etcd 暴露 │
   └─────┬─────┘          └────┬────┘          └──────┬──────┘
         │                      │                      │
         ▼                      ▼                      ▼
   trivy/grype          Falco/Tetragon        kube-bench/OPA
```

---

## Top 5 容器安全误区

| # | 误区 | 真相 |
|---|------|------|
| 1 | **"容器就是轻量虚拟机，天然隔离"** | ❌ 容器共享宿主机内核。内核漏洞 → 所有容器受影响。 |
| 2 | **"官方镜像一定安全"** | ❌ `python:3.9` 含 400+ 已知 CVE。用 distroless 或 alpine。 |
| 3 | **"Docker Hub 镜像都是可信的"** | ❌ Docker Hub 已发现多起恶意镜像。始终验证签名。 |
| 4 | **"容器跑完就删，不需要打补丁"** | ❌ 运行期间足够被攻击。更新基础镜像重建。 |
| 5 | **"root 跑容器没问题，反正是隔离的"** | ❌ 容器 root ≈ 宿主机 root (除非有 user namespace)。 |

---

## 本章内容

| 文章 | 核心内容 | 难度 |
|------|----------|------|
| [Docker 安全](01-docker-security.md) | 镜像安全、运行时、最佳实践清单 | ⭐⭐ |
| [Kubernetes 安全](02-kubernetes-security.md) | Pod Security、RBAC、网络策略 | ⭐⭐⭐ |
| [容器供应链安全](03-supply-chain.md) | 镜像签名、漏洞扫描、准入控制 | ⭐⭐⭐ |
| [容器安全工具链](04-container-image-security.md) | Trivy/Syft/Falco/Cosign 工具链 | ⭐⭐⭐ |
| [容器逃逸技术](05-container-escape.md) | CVE-2019-5736/CVE-2022-0492/Capabilities | ⭐⭐⭐⭐ |

---

## 快速检测

```bash
# 1. 镜像漏洞扫描
trivy image python:3.9
# → 列出所有 CVE、严重性、修复版本

# 2. 运行时安全检查
docker run --rm -it \
    --pid=host --userns=host --privileged \
    aquasec/kube-hunter

# 3. K8s 集群合规
kube-bench run --targets master,node

# 4. 镜像配置检查
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy config /
```

---

## 学完本章你能够

- [x] 扫描容器镜像中的已知 CVE
- [x] 配置容器最小权限运行 (非 root、只读文件系统)
- [x] 诊断 K8s RBAC 配置错误
- [x] 检测和防护容器逃逸
- [x] 实施镜像签名和供应链安全
- [x] 部署 Falco 运行时安全监控

---

*下一篇：[Docker 安全](01-docker-security.md)*

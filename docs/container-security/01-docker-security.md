# Docker 安全

> 容器最简单也最容易出安全问题的地方——镜像和运行时

---

## Docker 安全基本原则

```
┌─────────────────────────────────────┐
│         Docker 安全层次             │
├─────────────────────────────────────┤
│ 主机安全 → Docker 守护进程安全       │
│         → 容器运行时安全             │
│              → 镜像安全              │
│                   → 应用代码安全     │
└─────────────────────────────────────┘
```

**最重要的安全原则**：

> 不要以 root 运行容器，不要给不必要的特权，不要信任你从网上下载的镜像。

---

## 镜像安全

### 1. 选择安全的基础镜像

```dockerfile
# ❌ 错误：使用完整基础镜像，包含大量不必要的工具
FROM ubuntu:latest
# 这包含编译工具、网络工具等攻击者可以利用的东西

# ✅ 正确：使用极简基础镜像
FROM python:3.11-slim
# 只包含运行 Python 所需的最小依赖

# 或者使用 distroless 镜像（没有 Shell！）
FROM gcr.io/distroless/python3
# 连 /bin/sh 都没有，容器被入侵也无法执行命令
```

### 2. 不要在镜像中硬编码密钥

```dockerfile
# ❌ 错误：在 Dockerfile 中写密钥
FROM python:3.11-slim
ENV API_KEY=sk-xxxxxxxxxxxxxx
ENV DB_PASSWORD=super_secret
COPY app.py /app/
CMD ["python", "/app/app.py"]

# ✅ 正确：运行时注入
FROM python:3.11-slim
COPY app.py /app/
CMD ["python", "/app/app.py"]

# 运行时通过环境变量注入（不写在镜像里）
# docker run -e API_KEY=$(aws secretsmanager get-secret-value ...) my-app
```

### 3. 最小化镜像层

```dockerfile
# ✅ 推荐：合并 RUN 命令，减少层数
FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && pip install --no-cache-dir \
        torch \
        transformers \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 多阶段构建
FROM python:3.11-slim AS builder
# 编译阶段

FROM python:3.11-slim
# 只复制编译产物的运行阶段
COPY --from=builder /app/wheels /app/wheels
```

### 4. 镜像漏洞扫描

```bash
# Trivy — 免费开源
trivy image my-app:latest

# Docker Scout — 集成在 Docker Desktop
docker scout quickview my-app:latest

# Snyk — 商业版
snyk container test my-app:latest --file=Dockerfile

# 在 CI 中集成
# 扫描到高危漏洞 → 阻止构建
```

---

## 容器运行时安全

### 1. 不以 root 运行

```dockerfile
# ✅ 正确：创建非 root 用户运行

FROM python:3.11-slim

# 创建非 root 用户
RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY app.py /app/

# 切换到非 root 用户
USER appuser

CMD ["python", "/app/app.py"]
```

### 2. 限制容器权限

```bash
# ❌ 错误：不给权限限制
docker run my-app

# ✅ 正确：明确限制权限

# 去掉所有不必要的权限
docker run \
  --read-only \              # 文件系统只读
  --cap-drop ALL \           # 去除所有内核能力
  --cap-add NET_BIND_SERVICE \  # 只加需要的
  --security-opt no-new-privileges:true \  # 禁止提权
  --memory 512m \            # 内存限制
  --cpus 0.5 \               # CPU 限制
  my-app
```

### 3. 资源限制防 DoS

```yaml
# Docker Compose 资源限制
services:
  app:
    image: my-app:latest
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
    security_opt:
      - no-new-privileges:true
```

### 4. 容器逃逸防护

```bash
# 常见容器逃逸途径

# 1. --privileged 模式（最危险）
# ❌ 容器拥有所有主机能力
docker run --privileged ubuntu

# 2. 挂载 Docker Socket
# ❌ 容器可以控制 Docker 守护进程
docker run -v /var/run/docker.sock:/var/run/docker.sock ubuntu

# 3. 挂载宿主机文件系统
# ❌ 容器可以读写宿主机文件
docker run -v /:/host ubuntu

# 4. 使用 --pid=host
# ❌ 容器可以看到所有主机进程
docker run --pid=host ubuntu

# ✅ 检查运行中的容器是否有逃逸风险
docker inspect --format '{{.HostConfig.Privileged}}' container_name
docker inspect --format '{{range .Mounts}}{{.Source}}{{end}}' container_name
```

---

## AI 场景：GPU 容器安全

```dockerfile
# AI 训练镜像安全示例

# 基础镜像使用 NVIDIA 官方 CUDA 镜像（非 root 版本）
FROM nvidia/cuda:12.1.0-runtime-ubuntu22.04

# 创建非 root 用户
RUN groupadd -r mluser && useradd -r -g mluser mluser

# 安装 AI 框架和依赖
RUN pip install --no-cache-dir \
    torch==2.0.1 \
    transformers==4.30.0

COPY --chown=mluser:mluser train.py /app/
COPY --chown=mluser:mluser model/ /app/model/

USER mluser
WORKDIR /app

CMD ["python", "train.py"]
```

```yaml
# Kubernetes GPU Pod 安全配置
apiVersion: v1
kind: Pod
metadata:
  name: ai-training-pod
spec:
  containers:
  - name: trainer
    image: ai-trainer:latest
    resources:
      limits:
        nvidia.com/gpu: 1  # GPU 资源
        memory: "16Gi"
        cpu: "4"
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
```

---

## Docker 安全审计

```bash
# Docker Bench Security — 官方安全审计工具
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc:/host/etc:ro \
  -v /usr/lib/systemd:/host/usr/lib/systemd:ro \
  docker/docker-bench-security

# Dockle — Dockerfile 安全检查
dockle my-app:latest

# 检查容器配置
docker inspect --format '{{json .HostConfig}}' my-container | jq .
```

---

## 安全检查清单

- [ ] 镜像使用最小化基础镜像（slim/distroless）吗？
- [ ] Dockerfile 中没有硬编码密钥吗？
- [ ] 容器不以 root 运行吗？
- [ ] 容器权限被限制了吗（cap-drop）？
- [ ] 镜像在部署前进行了漏洞扫描吗？
- [ ] 不使用 --privileged 模式吗？
- [ ] 不挂载 Docker Socket 吗？
- [ ] 有资源限制防止 DoS 吗？

---

## 延伸阅读

1. [Docker 安全最佳实践](https://docs.docker.com/engine/security/)
2. [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
3. [OWASP Docker Security](https://owasp.org/www-project-docker-security/)
4. [Trivy — 容器漏洞扫描](https://github.com/aquasecurity/trivy)
5. [NVIDIA 容器安全指南](https://docs.nvidia.com/datacenter/cloud-native/container-security/)
6. [Docker Bench Security](https://github.com/docker/docker-bench-security)

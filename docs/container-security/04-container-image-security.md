# 容器镜像安全实践

> 镜像是不安全的默认——FROM alpine 就能挖矿，FROM distroless 才叫安全。

---

## 安全镜像构建

### 从 FROM 到 RUN

```dockerfile
# ❌ 不安全的镜像构建
FROM node:18
COPY . /app
RUN npm install --production
CMD ["node", "app.js"]
# 问题：底层操作系统漏洞多、包含多余工具、root 运行

# ✅ 安全的多阶段构建
# 构建阶段
FROM node:18-alpine AS builder
WORKDIR /build
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force
COPY . .
RUN npm run build

# 运行阶段 （distroless！）
FROM gcr.io/distroless/nodejs18-debian11:nonroot
WORKDIR /app
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/node_modules ./node_modules
USER nonroot:nonroot
EXPOSE 3000
CMD ["dist/server.js"]
```

### Distroless 镜像栈对比

| 镜像 | 大小 | 包含 | 攻击面 |
|------|------|------|--------|
| `node:18` | ~900MB | 完整操作系统 + 包管理器 | 极大 |
| `node:18-alpine` | ~120MB | musl libc + apk | 中等 |
| `node:18-slim` | ~180MB | Debian 最小 | 中等 |
| `distroless` | ~110MB | 只有应用+运行时 | **最小** |
| `scratch` | ~5MB | 什么都没有 | **极最小** |

### 非 root 运行原则

```dockerfile
# ❌ 默认 root
FROM node:18-alpine
RUN npm install
CMD ["node", "app.js"]
# 容器逃逸 → root 权限

# ✅ 显式设置非 root
FROM node:18-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser:appgroup
COPY --chown=appuser:appgroup . /app
WORKDIR /app
CMD ["node", "app.js"]
```

## COSIGN 镜像签名

```bash
# 安装 cosign
# https://github.com/sigstore/cosign

# 生成密钥对
cosign generate-key-pair

# 签名镜像
cosign sign --key cosign.key \
    registry.company.com/app:latest

# 验证签名
cosign verify --key cosign.pub \
    registry.company.com/app:latest

# 在 CI 中验证
cosign verify-attestation --key cosign.pub \
    registry.company.com/app:latest | jq .

# 透明日志（Rekor）
cosign verify --key cosign.pub --rekor-url https://rekor.sigstore.dev \
    registry.company.com/app:latest
```

## SBOM 实战

```bash
# Syft 生成 SBOM
# 从镜像
syft registry.company.com/app:latest -o cyclonedx-json=sbom.cdx.json

# 从 Dockerfile
syft dir:. -o spdx-json=sbom.spdx.json

# Grype 漏洞扫描 + SBOM
grype sbom:sbom.cdx.json -o json > vulns.json

# SBOM 可视化
syft packages ubuntu:latest -o table
```

## CI/CD 镜像安全流水线

```yaml
# GitHub Actions 镜像安全
deploy:
  steps:
    - name: Build
      run: docker build -t app:latest .

    - name: Scan
      run: |
        trivy image --severity CRITICAL app:latest
        grype app:latest --fail-on high
    
    - name: Generate SBOM
      run: syft app:latest -o cyclonedx-json=sbom.json
    
    - name: Sign
      run: cosign sign --key cosign.key app:latest
    
    - name: Push
      run: docker push registry/app:latest
```

## 镜像安全扫描策略

```yaml
扫描频率:
  - 构建时: CI 流水线每次构建
  - 定期: 已部署镜像每周全量扫描
  - 事件驱动: 漏洞 CVE 发布时重新扫描

严重度处理:
  CRITICAL: 阻断发布 + 24小时内修复
  HIGH: 阻断发布（有补丁） / 例外申请（无补丁）
  MEDIUM: 记录 + 30天内修复
  LOW: 记录 + 下一迭代修复

豁免规则:
  - 操作系统基础镜像 CVE（无 POC 的 CRITICAL）
  - 不影响运行时代码的漏洞
  - 已由上游项目标记为"不会修复"
```

## 最小化攻击面

```dockerfile
# 完整安全 Dockerfile
FROM --platform=linux/amd64 gcr.io/distroless/static-debian11:nonroot AS runtime
FROM alpine:3.18 AS builder

# 构建阶段
RUN apk add --no-cache build-base curl
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/server .

# 运行阶段
FROM runtime
COPY --from=builder /app/server /server
USER nonroot:nonroot

# 安全选项
HEALTHCHECK --interval=30s --timeout=3s \
    CMD ["/server", "health"]
STOPSIGNAL SIGTERM
EXPOSE 8080/tcp

ENTRYPOINT ["/server"]
```

## 镜像安全检查清单

```
[ ] 构建
  - [ ] 使用 distroless/scrach 作为运行镜像
  - [ ] 最小化基础镜像（非 slim、非完整 OS）
  - [ ] 不使用 :latest 标签
  - [ ] 固定依赖版本（npm ci 替代 npm install）
  - [ ] 清理构建缓存（npm cache clean --force）

[ ] 运行时
  - [ ] 非 root 用户运行
  - [ ] 只读根文件系统（readOnlyRootFilesystem: true）
  - [ ] 禁用特权提升（allowPrivilegeEscalation: false）
  - [ ] 移除 Linux Capabilities
  - [ ] 限制资源（CPU/Memory limits）

[ ] 供应链
  - [ ] 镜像签名（Cosign）
  - [ ] SBOM 生成（Syft）
  - [ ] 基础镜像漏洞扫描（Trivy/Grype）
  - [ ] 依赖漏洞扫描（npm audit/pip audit）
  - [ ] 定期 re-scan 已部署镜像

[ ] 合规
  - [ ] 镜像来自受信仓库
  - [ ] 镜像不可变（immutable tag）
  - [ ] 删除未使用的镜像
  - [ ] 镜像仓库访问审计
```

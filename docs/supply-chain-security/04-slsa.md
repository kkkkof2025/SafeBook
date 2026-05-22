# SLSA 框架深度实施

## 概述

SLSA（Supply-chain Levels for Software Artifacts，发音 "salsa"）是 Google 开源的供应链安全框架，定义四个递进的安全级别。它不是安全清单——而是对软件构建过程的完整性保证系统。

---

## 1. SLSA 四级详解

```
SLSA 四级对应关系:

  L1 — 基础完整性
    ├── 要求: 有构建脚本 + 源码版本控制
    ├── 防御: 无意的错误
    ├── 投入: 极低（只需 Git + CI 脚本）
    └── 适用: 所有项目

  L2 — 托管构建环境
    ├── 要求: 托管 CI/CD + 构建来源(生成 provenance)
    ├── 防御: 偶然性篡改
    ├── 投入: 低（使用 GitHub Actions/GitLab CI）
    └── 适用: 开源项目/内部工具

  L3 — 加固的构建平台
    ├── 要求: 隔离构建 + 不可抵赖的来源
    ├── 防御: 平台级攻击
    ├── 投入: 中（需要专用的构建基础设施）
    └── 适用: 关键依赖

  L4 — 最高级别
    ├── 要求: 双人审查 + 可复现构建 + 密封性
    ├── 防御: 内部威胁 + 高级持续威胁
    ├── 投入: 高（需要组织级安全工程）
    └── 适用: 安全关键组件（国防/金融核心）
```

---

## 2. SLSA 实施指南

### 2.1 生成 Attestation（SLSA 2+）

```yaml
# .github/workflows/build.yml
# GitHub Actions 中生成 SLSA Provenance

name: SLSA Build
on:
  push:
    branches: [main]

permissions:
  id-token: write  # OIDC token for keyless signing
  contents: read
  actions: read

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.build.outputs.digest }}

    steps:
      - uses: actions/checkout@v4

      # Step 1: 构建镜像
      - name: Build image
        id: build
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/org/app:${{ github.sha }}

      # Step 2: 生成 SLSA provenance (SLSA 3)
      - name: Generate SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/actions/generator_container_slsa3@v2.0.0
        with:
          image: ghcr.io/org/app
          digest: ${{ steps.build.outputs.digest }}

      # Step 3: 验证 provenance
      - name: Verify provenance
        uses: slsa-framework/slsa-verifier/actions/installer@v2.5.0
      - run: |
          slsa-verifier verify-image \
            ghcr.io/org/app@${{ steps.build.outputs.digest }} \
            --source-uri github.com/org/repo \
            --print-provenance
```

### 2.2 验证 SLSA Provenance

```bash
# 消费方验证镜像的 SLSA 级别

# 1. 安装 slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# 2. 验证镜像
slsa-verifier verify-image \
  ghcr.io/org/app@sha256:abc123... \
  --source-uri github.com/org/repo \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0

# 3. 验证结果示例
# PASSED: SLSA Build Level 3
#   - Source: github.com/org/repo
#   - Builder: slsa-github-generator v2.0.0
#   - Materials: complete (all dependencies attested)
```

### 2.3 构建隔离（SLSA 3 要求）

```yaml
# 使用 GitHub self-hosted runner 实现隔离构建
# 每次构建使用新 VM（非复用 runner）

# 方案 1: GitHub Large Runners (临时 VM)
# 方案 2: AWS EC2 + Actions Runner 自动扩缩

# Terraform EC2 runner 示例
resource "aws_autoscaling_group" "build_runner" {
  name = "slsa-isolated-build"
  min_size = 0
  max_size = 10

  launch_template {
    id = aws_launch_template.runner.id
  }

  # 关键: ephemeral storage, 每次构建全新 VM
  tag {
    key   = "Purpose"
    value = "SLSA-Isolated-Build"
    propagate_at_launch = true
  }
}

# Runner 配置: 构建后自动注销
# 保证每次构建都是全新的 runner 实例
```

---

## 3. SLSA 依赖链

```
SLSA 依赖传递:

  如果你的依赖有 SLSA 3 provenance:
    ✅ 你可以证明依赖的构建来源
    ✅ 可以审计依赖的构建日志
    ✅ 可以验证依赖没有在构建中被篡改

  如果你的依赖没有 provenance:
    ❌ 无法证明依赖的安全性
    ❌ 无法审计依赖来源
    ❌ 供应链攻击风险无法量化

  实际例子:
    XZ Utils 后门 (CVE-2024-3094)
    → 如果有 SLSA provenance, 1天内就能追溯到后门注入点
    → 没有 provenance: 安全社区花了 3个月才发现
```

---

## 4. 渐进式实施路线

```yaml
SLSA 实施路线图:

  第 1 周:
    - [ ] 确保构建脚本在 Git 中 → 完成 SLSA 1
    - [ ] 迁移到 GitHub Actions / GitLab CI

  第 1 月:
    - [ ] 启用 SLSA provenance 生成 → 完成 SLSA 2
    - [ ] 验证签名流程
    - [ ] 培训团队 SLSA 意识

  第 3 月:
    - [ ] 配置隔离构建环境 → SLSA 3
    - [ ] 审计所有外部依赖的 SLSA 等级
    - [ ] 对关键依赖要求 SLSA 3+

  第 6-12 月:
    - [ ] 可复现构建 → SLSA 4
    - [ ] 双人审查所有构建配置
    - [ ] 供应链 SLA 集成到采购流程
```

---

## 参考资源

- [SLSA 官方文档](https://slsa.dev/)
- [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)
- [slsa-verifier](https://github.com/slsa-framework/slsa-verifier)
- [Supply-chain Levels for Software Artifacts (论文)](https://slsa.dev/spec/v1.0/about)

---

*上一篇：[SBOM 管理](05-sbom.md)*

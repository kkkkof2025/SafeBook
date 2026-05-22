# 软件签名与验证深度

## 概述

软件签名是供应链安全的基石——它回答一个根本问题："这个软件确实是我信任的那个人/组织构建的吗？" 本章深入 Sigstore、TUF、in-toto 三大签名框架的实现与安全分析。

---

## 1. 攻击场景：为什么签名至关重要

```
无签名的供应链攻击路径:

  攻击者侵入 CI/CD
    → 替换构建产物 (容器镜像/二进制)
    → 注入后门到发行版
    → 用户下载被篡改版本
    → 无签名 = 无法检测

  真实案例:
    - SolarWinds (2020): 攻击者替换了 Orion 构建产物
      如果有签名, 客户安装前就能检测到不一致
    - CodeCov (2021): Bash Uploader 被篡改
      如果有签名验证, 篡改三天内就能被发现
```

---

## 2. Sigstore 深度实现

### 2.1 Keyless 签名原理

```
Sigstore Keyless 签名流程:

  1. 开发者推送镜像: docker push ghcr.io/org/app:v1
  2. Cosign 触发 OIDC 认证:
     → 使用 GitHub/OIDC Provider 验证身份
     → 获取短期证书 (Fulcio, 10min 有效)
  3. 签名写入透明日志: Rekor
     → 永久公开可查
     → 不可篡改
  4. 验证方:
     → 检查 Rekor 日志
     → 验证证书链
     → 确认 OIDC 的身份
```

### 2.2 CI/CD 集成

```yaml
# GitHub Actions: 签名 + 验证

name: Sign and Verify
on:
  push:
    tags: ['v*']

permissions:
  id-token: write
  contents: read
  packages: write

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      # 构建镜像
      - name: Build and push
        run: |
          docker build -t ghcr.io/org/app:${{ github.ref_name }} .
          docker push ghcr.io/org/app:${{ github.ref_name }}

      # Keyless 签名
      - name: Sign image
        run: |
          cosign sign \
            --yes \
            ghcr.io/org/app:${{ github.ref_name }}

      # 验证签名
      - name: Verify signature
        run: |
          cosign verify \
            --certificate-identity "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/${{ github.ref_name }}" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            ghcr.io/org/app:${{ github.ref_name }}

      # 签名 SBOM
      - name: Generate and sign SBOM
        run: |
          syft ghcr.io/org/app:${{ github.ref_name }} -o spdx-json > sbom.json
          cosign attest \
            --predicate sbom.json \
            --type spdxjson \
            ghcr.io/org/app:${{ github.ref_name }}
```

### 2.3 策略引擎集成

```yaml
# Kyverno 策略: 仅允许签名镜像
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-image-signature
      match:
        any:
        - resources:
            kinds: [Pod]
      verifyImages:
      - imageReferences:
        - "ghcr.io/org/*"
        attestors:
        - entries:
          - keys:
              publicKeys: |
                -----BEGIN PUBLIC KEY-----
                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                -----END PUBLIC KEY-----
```

---

## 3. TUF（The Update Framework）

### 3.1 TUF 攻击模型

```yaml
TUF 防御的攻击类型:

  1. 密钥泄露:
     → 使用多层密钥 (root/targets/snapshot/timestamp)
     → 离线 root 密钥 + 在线 targets 密钥

  2. 回滚攻击:
     → 攻击者提供旧版本的文件
     → TUF: 版本号单调递增 + 时间戳验证

  3. 混合攻击:
     → 攻击者混合新旧元数据
     → TUF: 一致性哈希链

  4. 冻结攻击:
     → 攻击者阻止用户获取更新
     → TUF: 客户端缓存未过期则接受

  5. 慢速提取:
     → 攻击者故意缓慢提供更新
     → TUF: 时间戳超时检测
```

### 3.2 TUF 元数据结构

```python
# TUF 元数据示例结构
TUF_METADATA = {
    "root.json": {
        "version": 1,
        "expires": "2026-12-31T00:00:00Z",
        "keys": {
            "root_key": {
                "keytype": "ed25519",
                "scheme": "ed25519",
                "keyval": {"public": "base64..."}
            }
        },
        "roles": {
            "root": {"threshold": 1, "keyids": ["root_key"]},
            "targets": {"threshold": 1, "keyids": []},
            "snapshot": {"threshold": 1, "keyids": []},
            "timestamp": {"threshold": 1, "keyids": []}
        }
    },
    "targets.json": {
        "version": 5,
        "expires": "2026-06-30T00:00:00Z",
        "targets": {
            "app-v1.0.tar.gz": {
                "length": 1048576,
                "hashes": {"sha256": "abc123..."},
                "custom": {"slsa_provenance": "..."}
            }
        }
    },
    "snapshot.json": {
        # 所有元数据文件的哈希列表（防止混合攻击）
        "meta": {
            "targets.json": {"version": 5, "hashes": {"sha256": "def456..."}},
            "root.json": {"version": 1, "hashes": {"sha256": "xyz789..."}}
        }
    },
    "timestamp.json": {
        # 最新的 snapshot 版本号（防止冻结攻击）
        "signed": {
            "meta": {"snapshot.json": {"version": 3, "length": 1024}}
        }
    }
}
```

---

## 4. in-toto 供应链证明

```yaml
# in-toto layout (供应链安全策略)
# 定义整个供应链中每个步骤的期望

layout:
  steps:
    - name: clone
      expected_command: git clone
      expected_materials: []
      expected_products:
        - CREATE: "*"
        - DISALLOW: "*"

    - name: test
      expected_command: pytest
      expected_materials:
        - MATCH: "src/*"
      expected_products:
        - ALLOW: "test-results.xml"

    - name: build
      expected_command: make build
      pubkeys: ["build-team-key"]
      expected_materials:
        - MATCH: "src/*"
        - MATCH: "test-results.xml"
      expected_products:
        - CREATE: "dist/*"

    - name: sign
      expected_command: cosign sign
      pubkeys: ["release-team-key"]
      expected_materials:
        - MATCH: "dist/*"
      expected_products:
        - CREATE: "dist/*.sig"

  inspect:
    - name: untrusted-inspect
      expected_materials:
        - MATCH: "dist/*"
        - MATCH: "dist/*.sig"
      run: cosign verify
```

---

## 5. 部署验证清单

```yaml
签名验证集成位置:

  1. CI/CD 管道:
    - [ ] 构建后签名 (Cosign)
    - [ ] SBOM attestation
    - [ ] PR 合并前验证所有依赖签名

  2. 镜像仓库:
    - [ ] 仓库策略: 仅接受签名镜像
    - [ ] 自动扫描并标注未签名镜像

  3. K8s 准入控制:
    - [ ] Kyverno/OPA Gatekeeper 验证签名
    - [ ] 阻止未签名镜像部署到生产

  4. 运行时验证:
    - [ ] 定期重新验证运行中镜像的签名
    - [ ] 检测签名吊销 (CRL/Fulcio)

  5. 依赖管理:
    - [ ] lock 文件 + 校验和验证
    - [ ] 私有镜像仓库缓存
    - [ ] Dependabot/Renovate 自动更新
```

---

## 参考资源

- [Sigstore](https://sigstore.dev/)
- [The Update Framework (TUF)](https://theupdateframework.io/)
- [in-toto](https://in-toto.io/)
- [SLSA + Sigstore Integration Guide](https://slsa.dev/blog/2023/05/slsa-sigstore)

---

*上一篇：[SLSA 框架](04-slsa.md)*

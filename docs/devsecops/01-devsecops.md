# DevSecOps 安全实践

## 安全左移

DevSecOps 的核心思想：安全不是最后一道门，而是在代码编写那一刻就开始。

### 安全流水线全景
```
设计 → 开发 → 构建 → 测试 → 发布 → 运营
 │       │       │      │      │      │
威胁建模   SAST   SCA    DAST   签名   RASP
 │       │       │      │      │      │
STRIDE  Pre-commit  容器扫描  IAST  镜像签名 运行时
```

---

## SAST（静态安全测试）

### 工具矩阵与集成

| 工具 | 语言 | 速度 | 精确度 | 最佳场景 |
|------|------|------|--------|---------|
| Semgrep | 30+ | ⚡⚡⚡ | ⭐⭐⭐ | CI/CD + IDE |
| CodeQL | Java/JS/Python/C++ | ⚡⚡ | ⭐⭐⭐⭐ | 深度审计 |
| SonarQube | 30+ | ⚡⚡ | ⭐⭐⭐ | 代码质量+安全 |
| Bandit | Python | ⚡⚡⚡ | ⭐⭐ | 快速扫描 |
| Gosec | Go | ⚡⚡⚡ | ⭐⭐ | Go 专项 |

### CI/CD 完整集成示例
```yaml
# .github/workflows/security.yml
name: Security Pipeline
on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Semgrep - 快速 SAST
      - name: Semgrep OWASP Scan
        uses: semgrep/semgrep-action@v1
        with:
          config: p/owasp-top-ten
        continue-on-error: true

      # CodeQL - 深度分析
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: javascript, python
      - name: CodeQL Analysis
        uses: github/codeql-action/analyze@v3

      # TruffleHog - 密钥泄露扫描
      - name: Secret Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.before }}
          head: ${{ github.head_ref }}

  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Dependabot 替代: Dependency Review
      - name: Dependency Review
        uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: critical
          deny-licenses: GPL-3.0, AGPL-3.0

      # Trivy 容器+依赖扫描
      - name: Trivy Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scanners: vuln,secret,misconfig
          severity: CRITICAL,HIGH

  secrets-management:
    runs-on: ubuntu-latest
    steps:
      # 预防性密钥检测 (pre-commit)
      - name: Detect secrets
        run: |
          git diff --cached --name-only | \
          xargs -I {} detect-secrets scan {} --base64-limit 4.5
```

---

## DAST（动态安全测试）

```yaml
# DAST 集成
- name: OWASP ZAP Full Scan
  uses: zaproxy/action-full-scan@v0.10.0
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    target: https://staging.example.com
    rules_file_name: .zap-rules.tsv
    cmd_options: '-a -j -T 60'

# .zap-rules.tsv 示例 (仅启用关键规则)
# 40012  IGNORE  (跨站脚本 - 需人工确认)
# 40018  FAIL    (SQL注入)
# 90022  FAIL    (路径遍历)
```

---

## 基础设施即代码 (IaC) 安全

```yaml
# Terraform 安全扫描
- name: tfsec
  uses: aquasecurity/tfsec-action@v1.0.3
  with:
    soft_fail: false

# Kubernetes 清单扫描
- name: Kubesec
  uses: controlplaneio/kubesec-action@v1
  with:
    file: k8s/deployment.yaml
```

---

## 发布门禁矩阵

| 检查项 | 阻断条件 | 工具 | 豁免流程 |
|--------|---------|------|---------|
| SAST 漏洞 | Critical / High | Semgrep + CodeQL | 安全团队审批 |
| 依赖漏洞 | Critical (CVSS ≥ 9.0) | Dependabot / Trivy | 需评估利用条件 |
| 密钥泄露 | 任何匹配 | TruffleHog | 自动阻断+轮换密钥 |
| 容器高危 | High 以上 | Trivy | 更新基础镜像 |
| IaC 误配置 | Critical | tfsec / Kubesec | 安全团队审批 |
| 许可证合规 | GPL / AGPL | FOSSA | 法务审批 |

---

## DevOps 安全工具链速查

| 阶段 | 工具 | 类别 |
|------|------|------|
| IDE | Semgrep, Snyk Code | SAST |
| Pre-commit | pre-commit hooks, git-secrets | 密钥检测 |
| PR/MR | CodeQL, Dependency Review | 增量分析 |
| Build | Trivy, Grype | 容器扫描 |
| Staging | OWASP ZAP, Burp Suite | DAST |
| Deploy | tfsec, Checkov, Kubesec | IaC 扫描 |
| Runtime | Falco, Tetragon, Tracee | 行为监控 |

---

*上一篇：[代码审计实战](05-code-audit-practice.md)*

*下一篇：[渗透测试方法论实战](02-pentest-methodology.md)*

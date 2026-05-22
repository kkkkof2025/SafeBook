# DevSecOps 安全

> 把安全"左移"到开发最早阶段——不是事后打补丁，而是源头防漏洞

---

## DevSecOps 理念

```
传统安全:   开发 → 测试 → 部署 → [安全检查] ❌ 太晚了
DevSecOps:  [安全] 开发 → [安全] 测试 → [安全] 部署 ✅ 每一环都有安全
```

---

## 本章内容

| 文章 | 核心内容 | 难度 |
|------|----------|------|
| [DevSecOps 入门](01-devsecops.md) | 理念/流水线/工具链选型 | ⭐⭐ |
| [渗透测试方法论](02-pentest-methodology.md) | PTES/OSSTMM 测试框架 | ⭐⭐⭐ |
| [SAST/DAST/SCA](03-sast-dast-secrets.md) | 静态/动态/依赖/密钥扫描 | ⭐⭐⭐ |
| [安全左移](03-devsecops-shift-left.md) | CI/CD 集成/门控/自动化修复 | ⭐⭐⭐⭐ |

---

## 工具链速查

| 阶段 | 工具 |
|------|------|
| SAST | Semgrep, SonarQube, CodeQL |
| SCA | Dependabot, Snyk, Trivy |
| DAST | ZAP, Burp Suite, Nuclei |
| Secret | TruffleHog, GitLeaks |
| IaC | Checkov, tfsec, Terrascan |
| 容器 | Trivy, Anchore, Sysdig |

---

*下一篇：[DevSecOps 入门](01-devsecops.md)*

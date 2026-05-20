# DevSecOps 安全实践

## 安全左移

DevSecOps 的核心思想：安全嵌入开发流程的每个阶段。

### 安全流水线
```
设计 → 开发 → 构建 → 测试 → 发布 → 运营
 │       │       │      │      │      │
威胁建模   SAST   SCA    DAST   签名   RASP
```

## SAST（静态安全测试）

### 工具选型
| 工具 | 支持的扫描语言 | 优势 |
|------|--------------|------|
| Semgrep | 30+ 语言 | 规则可定制、高速 |
| CodeQL | 主要语言 | 深度分析、精确 |
| SonarQube | 30+ 语言 | 代码质量+安全 |
| Bandit | Python | 快速、轻量 |
| Gosec | Go | 原生支持 |
| Brakeman | Ruby | Rails 专项 |

### CI/CD 集成示例
```yaml
# GitHub Actions 集成 Semgrep
- name: Semgrep SAST
  uses: semgrep/semgrep-action@v1
  with:
    config: p/owasp-top-ten
  env:
    SEMGREP_TIMEOUT: 300
```

## DAST（动态安全测试）

### OWASP ZAP 扫描
```yaml
- name: OWASP ZAP DAST
  uses: zaproxy/action-full-scan@v0.10.0
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    target: https://staging.example.com
    rules_file_name: .zap-rules.tsv
```

## SCA（软件组成分析）

```yaml
- name: Dependency Review
  uses: actions/dependency-review-action@v4
  with:
    fail-on-severity: high
    allow-licenses: MIT, Apache-2.0
```

| 工具 | 功能 | 集成 |
|------|------|------|
| Dependabot | 自动依赖更新 | GitHub 原生 |
| Snyk | 漏洞扫描+修复 | CI/CD 插件 |
| Trivy | 容器+依赖扫描 | 多平台支持 |
| OWASP DC | Java/.NET 依赖检查 | Jenkins 插件 |

## IAST（交互式安全测试）
- 运行时插桩，结合 SAST 和 DAST 优势
- Contrast Security / Hdiv / 自研 Agent
- 精确度高、误报率低
- 适合 API 密集型应用

## 安全上线门禁

| 检查项 | 阻断条件 | 对应工具 |
|--------|---------|---------|
| SAST 漏洞 | Critical/High | Semgrep |
| 依赖漏洞 | Critical (CVSS >= 9.0) | Dependabot |
| 密钥泄露 | 任何匹配 | truffleHog |
| 容器扫描 | High 以上 | Trivy |
| 许可证合规 | GPL/AGPL 商用 | FOSSA |

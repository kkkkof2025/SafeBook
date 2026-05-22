# DevSecOps 安全左移实践

## DevSecOps 概述

DevSecOps 将安全集成到 DevOps 流程中。

### 核心原则

1. **安全左移 (Shift Left)** - 在开发早期引入安全
2. **自动化** - 安全测试自动化
3. **持续监控** - 运行时安全监控
4. **协作文化** - 开发、运维、安全团队协作

---

## 安全左移策略

### 阶段1：需求与设计

**活动：**
- 安全需求分析
- 威胁建模 (Threat Modeling)
- 安全架构设计

**工具：**
- **Microsoft Threat Modeling Tool**
- **OWASP Threat Dragon**
- **IriusRisk**

**输出：**
- 威胁模型文档
- 安全需求清单
- 安全架构图

### 阶段2：开发

**活动：**
- 安全编码培训
- 静态应用安全测试 (SAST)
- 依赖项扫描 (SCA)

**工具：**
- **SonarQube** - SAST
- **Checkmarx** - SAST
- **Snyk** - SCA
- **Dependabot** - 依赖更新

**实施：**

```yaml
# GitLab CI 示例
stages:
  - test

sast:
  stage: test
  image: registry.gitlab.com/gitlab-org/security-products/analyzers/semgrep:latest
  script:
    - semgrep --config=auto --json --output=gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### 阶段3：构建

**活动：**
- 容器镜像扫描
- 签名容器镜像
- 生成 SBOM (Software Bill of Materials)

**工具：**
- **Trivy** - 容器扫描
- **Anchore** - 容器策略引擎
- **Syft** - SBOM 生成
- **Grype** - 漏洞扫描

**实施：**

```yaml
# GitHub Actions 示例
name: Build and Scan

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Scan image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
```

### 阶段4：测试

**活动：**
- 动态应用安全测试 (DAST)
- 交互式应用安全测试 (IAST)
- 渗透测试

**工具：**
- **OWASP ZAP** - DAST
- **Burp Suite** - DAST
- **Contrast Security** - IAST

**实施：**

```yaml
# Jenkins Pipeline 示例
pipeline {
    agent any

    stages {
        stage('DAST Scan') {
            steps {
                sh 'docker run -t owasp/zap2docker zap-baseline.py -t http://app:8080'
            }
            post {
                always {
                    publishHTML([reportDir: 'reports', reportFiles: 'zap-report.html', reportName: 'ZAP Report'])
                }
            }
        }
    }
}
```

### 阶段5：部署

**活动：**
- 基础设施即代码 (IaC) 扫描
- 策略即代码 (PaC) 检查
- 密钥扫描

**工具：**
- **Checkov** - IaC 扫描
- **Tfsec** - Terraform 扫描
- **OPA (Open Policy Agent)** - 策略引擎
- **TruffleHog** - 密钥扫描

**实施：**

```bash
# 扫描 Terraform 代码
tfsec --format json --out tfsec-results.json .

# 扫描 Kubernetes 清单
checkov -d k8s/ --output json --output-file checkov-results.json

# 扫描密钥
trufflehog git file://. --json > trufflehog-results.json
```

### 阶段6：运维

**活动：**
- 运行时保护
- 合规性监控
- 事件响应

**工具：**
- **Falco** - 运行时安全
- **Aqua Security** - 云原生安全
- **PagerDuty** - 事件响应

**实施：**

```yaml
# Falco 规则示例
- rule: Unexpected Network Connection
  desc: Detect unexpected network connections
  condition:
    k8s_audit and
    ka.verb != "get" and
    ka.target.uri != "healthz"
  output:
    Network connection detected (user=%ka.user.name verb=%ka.verb uri=%ka.target.uri)
  priority: WARNING
```

---

## DevSecOps 工具链

### 1. SAST (静态应用安全测试)

| 工具 | 语言支持 | 开源/商业 |
|------|----------|------------|
| **SonarQube** | 多语言 | 开源 + 商业 |
| **Checkmarx** | 多语言 | 商业 |
| **Semgrep** | 多语言 | 开源 |
| **Bandit** | Python | 开源 |
| **ESLint** | JavaScript | 开源 |

**SonarQube 配置：**

```properties
# sonar-project.properties
sonar.projectKey=myapp
sonar.projectName=My Application
sonar.projectVersion=1.0
sonar.sources=src/
sonar.language=js,py,java
sonar.sourceEncoding=UTF-8
```

### 2. SCA (软件成分分析)

| 工具 | 功能 | 开源/商业 |
|------|------|------------|
| **Snyk** | 依赖扫描 + 修复 | 开源 + 商业 |
| **Dependabot** | 依赖更新 PR | 开源 |
| **OWASP Dependency-Check** | CVE 检测 | 开源 |
| **Black Duck** | 许可证合规 | 商业 |

**Snyk 使用：**

```bash
# 安装 Snyk
npm install -g snyk

# 认证
snyk auth

# 测试项目
snyk test

# 监控项目 (持续监控)
snyk monitor

# 修复漏洞
snyk wizard
```

### 3. 容器安全

| 工具 | 功能 | 开源/商业 |
|------|------|------------|
| **Trivy** | 镜像扫描 | 开源 |
| **Anchore** | 策略引擎 | 开源 + 商业 |
| **Clair** | 镜像扫描 | 开源 |
| **Sysdig Secure** | 运行时保护 | 商业 |

**Trivy 使用：**

```bash
# 安装 Trivy
brew install aquasecurity/trivy/trivy

# 扫描镜像
trivy image myapp:latest

# 扫描文件系统
trivy fs .

# 扫描 Git 仓库
trivy repo https://github.com/example/myrepo

# 生成 SBOM
trivy image --format sbom --output sbom.spdx myapp:latest
```

### 4. IaC 安全

| 工具 | 支持平台 | 开源/商业 |
|------|------------|------------|
| **Checkov** | Terraform, K8s, CloudFormation | 开源 + 商业 |
| **Tfsec** | Terraform | 开源 |
| **Terrascan** | Terraform, K8s | 开源 |
| **Bridgecrew** | 多平台 | 商业 |

**Checkov 使用：**

```bash
# 安装 Checkov
pip3 install checkov

# 扫描目录
checkov -d .

# 扫描 Terraform 计划
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
checkov -f tfplan.json

# 生成 SARIF 报告
checkov -d . --output sarif --output-file-path results.sarif
```

### 5. 密钥扫描

| 工具 | 功能 | 开源/商业 |
|------|------|------------|
| **TruffleHog** | 高信度密钥扫描 | 开源 |
| **GitLeaks** | 提交历史扫描 | 开源 |
| **GitGuardian** | 实时监控 | 商业 |
| **AWS Git Secrets** | AWS 密钥扫描 | 开源 |

**TruffleHog 使用：**

```bash
# 安装 TruffleHog
pip3 install truffleHog

# 扫描仓库
truffleHog git file://.

# 扫描 S3 桶
truffleHog s3 --bucket my-bucket --aws-access-key-id AKIA...

# 扫描 GCS 桶
truffleHog gcs --bucket my-bucket --gcp-credentials-file creds.json

# 生成 JSON 报告
truffleHog git file://. --json > results.json
```

---

## DevSecOps 最佳实践

### 1. 安全训练

- **培训开发人员** - 安全编码实践
- **建立安全冠军** - 每个团队的安全倡导者
- **定期安全演练** - 红蓝对抗

### 2. 自动化

- **CI/CD 集成** - 每个阶段的安全测试
- **门控策略** - 高危漏洞阻断部署
- **自动修复** - 依赖更新 PR

### 3. 度量

- **MTTD (平均检测时间)** - 缩短漏洞发现时间
- **MTTR (平均修复时间)** - 缩短漏洞修复时间
- **覆盖率** - 安全测试覆盖率

### 4. 协作

- **安全即代码** - 策略即代码
- **共享责任** - 开发、运维、安全团队共同负责
- **持续改进** - 定期回顾和改进

---

## DevSecOps 平台

### 1. GitLab Security

**功能：**
- SAST, DAST, Dependency Scanning
- Container Scanning, Secret Detection
- Compliance Pipeline

**使用：**

```yaml
# .gitlab-ci.yml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
```

### 2. GitHub Advanced Security

**功能：**
- CodeQL (SAST)
- Dependabot (SCA)
- Secret Scanning
- Dependency Review

**使用：**

```yaml
# .github/workflows/security.yml
name: Security

on: [push, pull_request]

jobs:
  codeql:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/init@v2
        with:
          languages: javascript, python
      - uses: github/codeql-action/analyze@v2

  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v2
```

### 3. Azure DevOps Security

**功能：**
- Microsoft Security Code Analysis
- WhiteSource (SCA)
- Azure Security Center

**使用：**

```yaml
# azure-pipelines.yml
steps:
- task: MicrosoftSecurityCodeAnalysis@2
  inputs:
    categories: 'SDL'
    tools: 'Binskim, CredentialScanner'

- task: WhiteSource@21
  inputs:
    cwd: '$(System.DefaultWorkingDirectory)'
```

---

## DevSecOps 度量指标

### 1. 安全债务

- **未修复漏洞数** - 按严重级别分类
- **技术债 vs 安全债** - 平衡修复优先级
- **漏洞老化时间** - 按发现时间排序

### 2. 流程效率

- **安全测试通过率** - CI/CD 中安全测试通过百分比
- **误报率** - 安全工具误报百分比
- **平均修复时间** - 从发现到修复的平均时间

### 3. 风险敞口

- **暴露的 CVE 数** - 生产环境中暴露的 CVE
- **合规违规数** - 等保/SOX/GDPR 违规
- **安全事件数** - 安全事件数量

---

## DevSecOps 清单

### 规划阶段

- [ ] 进行威胁建模
- [ ] 定义安全需求
- [ ] 设计安全架构
- [ ] 选择安全工具链

### 开发阶段

- [ ] 集成 SAST 到 IDE
- [ ] 配置预提交钩子 (pre-commit hooks)
- [ ] 运行 SCA 扫描
- [ ] 代码审查安全检查

### 构建阶段

- [ ] 扫描容器镜像
- [ ] 签名容器镜像
- [ ] 生成 SBOM
- [ ] 扫描密钥

### 测试阶段

- [ ] 运行 DAST 扫描
- [ ] 进行渗透测试
- [ ] 扫描 IaC
- [ ] 检查策略合规性

### 部署阶段

- [ ] 扫描 IaC
- [ ] 检查 PaC
- [ ] 验证密钥未泄露
- [ ] 部署时运行时保护

### 运维阶段

- [ ] 监控运行时安全
- [ ] 定期审计合规性
- [ ] 响应安全事件
- [ ] 持续改进流程

---

## 延伸阅读

- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
- [NIST SSDF (Secure Software Development Framework)](https://www.nist.gov/itl/ssd/software-quality-group/ssdf)
- [Google SLSA (Supply Chain Levels for Software Artifacts)](https://slsa.dev/)
- [CNCF DevSecOps White Paper](https://www.cncf.io/reports/)

---

*上一篇：[DevSecOps 入门](01-devsecops.md)*

# CI/CD 管道安全

> 你的 CI/CD 管道可能是你最脆弱的攻击面——因为它有权限部署到生产环境

---

## 为什么 CI/CD 是高风险目标

```
CI/CD 管道拥有的权限：
  ✅ 读取源码
  ✅ 访问生产密钥
  ✅ 推送镜像到仓库
  ✅ 部署到 K8s 集群
  ✅ 修改生产配置

一个 CI/CD 漏洞 = 攻击者获得上述所有权限
```

---

## 常见 CI/CD 漏洞

### 1. 拉取请求（PR）注入

不安全的 PR 工作流使用 `pull_request_target`，该事件触发的 CI 拥有 GITHUB_TOKEN 的写入权限。攻击者可以通过 PR 中的代码修改工作流、窃取密钥。

**防御**：使用 `pull_request` 替代（只读 Token），且只分析 PR 代码而非执行。

### 2. 密钥泄露到日志

`env` 命令或 `set -x` 会将密钥打印到 CI 日志。使用 `::add-mask::` 隐藏敏感输出：

```bash
echo "::add-mask::${API_KEY}"
```

### 3. 依赖投毒

不加锁的依赖安装可能从恶意源获取包：

```bash
# 安全做法
pip install --require-hashes -r requirements.txt
pip-audit -r requirements.txt
```

### 4. 额外权限

默认 GITHUB_TOKEN 有写入权限。应明确限制：

```yaml
permissions:
  contents: read       # 只读代码
  packages: write      # 推送镜像时启用
  id-token: write      # OIDC 认证
```

---

## 安全 CI/CD 管道模板

```yaml
name: Secure Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  # 扫描阶段：只读权限
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: SAST Scan
        uses: github/codeql-action/analyze@v3
      - name: Dependency Scan
        run: pip-audit -r requirements.txt

  # 构建阶段：需要推包
  build-and-sign:
    needs: security-scan
    permissions:
      contents: read
      packages: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t app:latest .
      - run: cosign sign app:latest
      - run: docker push app:latest

  # 部署阶段：要求人工审批
  deploy:
    needs: build-and-sign
    environment: production
    permissions:
      contents: read
      deployments: write
    steps:
      - run: cosign verify app:latest
      - run: kubectl apply -f k8s/
```

---

## 安全检查清单

- [ ] 使用最小权限 Token（`permissions: read`）
- [ ] PR 构建不执行有写权限的操作
- [ ] 密钥通过 secrets 注入，不在日志暴露
- [ ] 使用 `::add-mask::` 隐藏敏感输出
- [ ] 依赖使用哈希校验安装
- [ ] 有依赖漏洞扫描步骤
- [ ] 生产部署需要人工审批
- [ ] 有超时限制防止异常运行
- [ ] CI 运行环境隔离，不共享持久化存储

---

## Jenkins Pipeline 安全

> Jenkins 是国内企业使用最多的 CI/CD 工具。以下是 Jenkinsfile 安全模板。

```groovy
// Jenkinsfile — 安全管道模板

pipeline {
    agent any

    environment {
        // 密钥通过 Jenkins Credentials 绑定
        DOCKER_REGISTRY = credentials('docker-registry')
        SONAR_TOKEN      = credentials('sonar-token')
        
        // 禁止在日志中暴露密钥
        GIT_COMMIT = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
    }

    stages {
        stage('Security Scan') {
            parallel {
                stage('SAST') {
                    steps {
                        // SonarQube 代码扫描
                        withSonarQubeEnv('SonarQube') {
                            sh 'mvn sonar:sonar -Dsonar.projectKey=myapp'
                        }
                    }
                }
                stage('Dependency Check') {
                    steps {
                        // OWASP Dependency-Check
                        sh '''
                            dependency-check --project myapp \
                                --scan ./target/ --out . --format HTML
                        '''
                    }
                }
                stage('Secret Scan') {
                    steps {
                        // Gitleaks 密钥扫描
                        sh 'gitleaks detect --source . --report-path gitleaks.json'
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                // 等待 SonarQube 质量门
                timeout(time: 1, unit: 'HOURS') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Build & Sign') {
            steps {
                sh 'docker build -t app:latest .'
                // Cosign 镜像签名
                sh 'cosign sign --key jenkins-cosign.key app:latest'
            }
        }

        stage('Deploy to Staging') {
            when {
                branch 'main'
            }
            steps {
                sh 'cosign verify app:latest'
                sh 'kubectl apply -f k8s/staging/'
            }
        }

        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            // 需要人工审批
            input {
                message 'Deploy to production?'
                ok 'Yes, deploy!'
            }
            steps {
                sh 'kubectl apply -f k8s/production/'
            }
        }
    }

    post {
        always {
            // 清理敏感文件
            sh 'rm -f *.key *.pem'
            cleanWs()
        }
        failure {
            // 失败通知
            slackSend(
                channel: '#ci-alerts',
                color: 'danger',
                message: "Pipeline failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
            )
        }
    }
}
```

### GitLab CI 安全要点

```yaml
# .gitlab-ci.yml 安全最佳实践

variables:
  # 不暴露密钥到日志
  DOCKER_AUTH_CONFIG: ${DOCKER_AUTH_CONFIG}

stages:
  - security-scan
  - build
  - deploy

security-scan:
  stage: security-scan
  script:
    - trivy fs --severity HIGH,CRITICAL .
    - secret-detection
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"  # MR 时才扫描

build:
  stage: build
  needs: ["security-scan"]
  script:
    - docker build -t $CI_REGISTRY_IMAGE:latest .
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

---

## 延伸阅读

1. [GitHub Actions 安全加固](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
2. [Jenkins 安全最佳实践](https://www.jenkins.io/doc/book/security/)
3. [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html)

# CSPM 与云安全工具链

> 人管不过来成千上万的云配置——让自动化来做

---

## 什么是 CSPM

**CSPM**（Cloud Security Posture Management，云安全态势管理）是一类自动化工具，用于：

- 持续发现云资源
- 检测配置错误
- 评估合规状态
- 生成修复建议

```
              ┌─────────────────────┐
              │   CSPM 工具          │
              │                      │
  ✉️ API 配置  →  检测配置错误 → 🔴 告警
  🔧 权限变更  →  评估权限风险 → 🟡 建议
  🗄️ 资源列表  →  合规审计     → 🟢 合规报告
              └─────────────────────┘
```

---

## 你在云上需要什么工具

### 按阶段分类

| 阶段 | 工具类型 | 用途 |
|------|---------|------|
| 预防 | IaC 扫描 | 在部署前发现配置问题 |
| 检测 | CSPM | 实时发现运行时配置错误 |
| 响应 | SIEM/SOAR | 告警和自动响应 |
| 审计 | 合规工具 | 持续合规评估 |

---

## IaC 安全扫描（预防）

### 基础设施即代码的安全

```terraform
# ❌ 错误：S3 桶公开可读

resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
  # 没有阻止公开访问的配置
}

# ✅ 正确：使用 checkov 扫描前就写安全的代码

resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### IaC 扫描工具

```bash
# Checkov — 扫描 Terraform/CloudFormation
checkov -d ./terraform/

# tfsec — 扫描 Terraform
tfsec ./terraform/

# Trivy — 扫描 IaC + 容器 + 依赖
trivy config ./terraform/
```

### 在 CI/CD 中集成

```yaml
# GitHub Actions 示例

name: IaC Security Scan

on:
  pull_request:
    paths:
      - 'terraform/**/*.tf'

jobs:
  checkov-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          soft_fail: false  # 失败则阻止合并
```

---

## CSPM 工具

### 云平台原生工具

| 云平台 | CSPM 工具 | 免费版 |
|--------|----------|--------|
| AWS | Security Hub | 30 天试用 |
| Azure | Defender for Cloud | 免费基础版 |
| 阿里云 | 云安全中心 | 免费基础版 |
| 腾讯云 | 安全运营中心 | 免费基础版 |
| GCP | Security Command Center | 免费基础版 |

### AWS Security Hub 配置

```bash
# 启用 Security Hub
aws securityhub enable-security-hub

# 启用合规标准
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
  '{"StandardsArn":"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"}'

# 查看发现结果
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}'

# 查看严重发现
aws securityhub get-findings \
  --query 'Findings[?Severity.Label==`CRITICAL`].[Title,ResourceType]'
```

### 开源 CSPM 工具

```bash
# Prowler — AWS 安全审计标杆
prowler aws

# 检查特定服务
prowler aws --services s3
prowler aws --services iam
prowler aws --services ec2

# 生成 HTML 报告
prowler aws --report-dir ./security-report

# ScoutSuite — 多云支持
scout aws
scout azure
scout gcp
```

---

## 容器和镜像扫描

```bash
# Trivy — 全能扫描器（容器 + IaC + 代码）
# 扫描容器镜像
trivy image nginx:latest

# 扫描文件系统
trivy fs ./my-app/

# 扫描 Git 仓库
trivy repo https://github.com/example/my-app

# 生成 JSON 报告
trivy image --format json --output report.json my-app:latest

# Clair — Red Hat 容器扫描
# Dockle — Dockerfile 安全检查
dockle my-app:latest
```

---

## AI 工作负载的安全监控

### 模型安全监控

```yaml
监控指标:
  数据层面:
    - 训练数据的访问频率和模式（异常访问检测）
    - 模型文件的下载事件（模型窃取检测）
    - 数据集的完整性校验
    
  推理层面:
    - 推理请求量异常（DoS 检测）
    - 异常大的输入（注入检测）
    - 请求来源分析（异常 IP 检测）
    
  配置层面:
    - IAM 角色变更
    - 安全组配置变更
    - 加密配置变更
```

### 告警配置示例

```python
# AWS CloudWatch 告警：检测 S3 异常访问

{
  "AlarmName": "S3-Anomalous-Data-Access",
  "MetricName": "NumberOfObjects",
  "Namespace": "AWS/S3",
  "Statistic": "Sum",
  "Period": 300,
  "EvaluationPeriods": 2,
  "Threshold": 1000,
  "ComparisonOperator": "GreaterThanThreshold",
  "AlarmActions": [
    "arn:aws:sns:us-east-1:123456789:security-team"
  ]
}
```

---

## 安全工具选型指南

| 预算 | 推荐方案 |
|------|---------|
| 💰 免费 | ScoutSuite / Prowler（开源）+ 云平台免费工具 |
| 💵 低预算 | Trivy + Checkov（开源）+ 云平台基础版 |
| 💶 中预算 | Wiz / Lacework（商业 CSPM） |
| 💸 高预算 | Prisma Cloud / Orca Security / CrowdStrike |

---

## 安全检查清单

- [ ] IaC 代码在部署前做了安全扫描吗？
- [ ] 云平台的原生 CSPM 工具启用了吗？
- [ ] 高危配置错误有自动告警吗？
- [ ] 容器镜像在部署前扫描了漏洞吗？
- [ ] IAM 权限定期审计了吗？
- [ ] 存储桶配置定期检查了吗？
- [ ] 安全事件有响应流程吗？

---

## 延伸阅读

1. [CIS Controls v8](https://www.cisecurity.org/controls/v8)
2. [Cloud Security Alliance — CCM](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)
3. [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
4. [Prowler — 开源 AWS 安全审计](https://github.com/prowler-cloud/prowler)
5. [Trivy — 全能漏洞扫描器](https://github.com/aquasecurity/trivy)
6. [Checkov — IaC 安全扫描](https://www.checkov.io/)

*上一篇：[云合规与治理](06-compliance-governance.md)*

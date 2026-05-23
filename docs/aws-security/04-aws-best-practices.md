# AWS 安全最佳实践

> 从 IAM 到 VPC：AWS 安全的全面防护

---

## 1. IAM 安全加固

```json
// IAM Policy: 遵循最小权限原则
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::app-data-bucket",
        "arn:aws:s3:::app-data-bucket/*"
      ],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "10.0.0.0/8"
        },
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
```

### IAM 核心安全推荐
```yaml
IAM 安全清单:
  - [ ] 禁止使用 Root 账号 (仅用于紧急)
  - [ ] Root 账号启用硬件 MFA
  - [ ] IAM 用户使用 MFA 或 SSO (AWS SSO/Okta)
  - [ ] 密码策略: ≥14 位 + 90 天轮换
  - [ ] IAM Role 替代 IAM User (EC2/Lambda/ECS)
  - [ ] 权限边界 (Permission Boundary) 限制最大权限
  - [ ] SCP (Service Control Policy) 组织级强制
  - [ ] IAM Access Analyzer 检测公开资源
  - [ ] Credential Report 定期审计未使用的凭证
```

---

## 2. VPC 网络安全

```terraform
# VPC 安全架构 (Terraform)
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
}

# 私有子网 (数据库)
resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

# NAT Gateway + 公有子网 (出站)
resource "aws_nat_gateway" "nat" {
  subnet_id = aws_subnet.public.id
}
```

### 安全组最小化原则
```yaml
安全组规则设计:
  # Web 层
  - Type: HTTPS, Source: 0.0.0.0/0 (负载均衡)
  - Type: HTTP, Source: 0.0.0.0/0 (重定向到 HTTPS)

  # 应用层
  - Type: 8080, Source: sg-web (仅 Web 层)

  # 数据库层
  - Type: 5432, Source: sg-app (仅应用层)
  - Type: 5432, Source: sg-bastion (跳板机)

  # 拒绝: 绝不开放 SSH/RDP 到 0.0.0.0/0!
```

---

## 3. S3 数据安全

```yaml
S3 安全最佳实践:
  - 默认加密: SSE-S3 或 SSE-KMS
  - Block Public Access: 账户级 + 桶级双重阻止
  - 访问日志: 启用 Server Access Logging
  - 对象版本控制: 防止误删/勒索
  - 生命周期策略: 自动过期/归档

  检测公开 S3 桶:
    aws s3api list-buckets --query "Buckets[].Name"
    aws s3api get-public-access-block --bucket BUCKET_NAME
    # 使用 Trusted Advisor / Security Hub
```

---

## 4. CloudTrail + GuardDuty

```bash
# CloudTrail: 全局审计 (默认仅 90 天)
aws cloudtrail create-trail --name main-trail \
  --s3-bucket-name cloudtrail-logs \
  --is-multi-region-trail \
  --enable-log-file-validation

# GuardDuty: 威胁检测
# 自动检测: 挖矿/数据外泄/未授权访问/IAM 异常
aws guardduty create-detector --enable

# Security Hub: 统一安全视图
# 聚合: GuardDuty + Inspector + Macie + Firewall Manager
aws securityhub enable-security-hub
```

---

## 5. AWS 安全服务全景

| 服务 | 类别 | 功能 |
|------|------|------|
| IAM | 身份 | 用户/角色/策略管理 |
| Cognito | 身份 | 应用用户认证 |
| WAF + Shield | 网络 | 应用层防护 + DDoS |
| GuardDuty | 检测 | 智能威胁检测 |
| Security Hub | 管理 | 安全态势统一视图 |
| Inspector | 漏洞 | 自动漏洞扫描 (ECR/EC2/Lambda) |
| KMS | 加密 | 密钥管理 + HSM |
| Secrets Manager | 秘密 | 凭证轮换存储 |
| Macie | 数据 | 敏感数据发现 (S3) |
| Config | 合规 | 资源配置审计 |

---

*上一篇：[AWS 安全架构设计](02-aws-security-architecture.md)*

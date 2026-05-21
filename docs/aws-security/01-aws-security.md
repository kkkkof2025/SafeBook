# AWS 安全实战

> AWS 是云安全的标杆——掌握 IAM Policy 就掌握了云上权限控制的核心。

---

## AWS IAM 深潜

### IAM Policy 结构

```json
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
                "arn:aws:s3:::company-data",
                "arn:aws:s3:::company-data/*"
            ],
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": "10.0.0.0/8"
                },
                "Bool": {
                    "aws:SecureTransport": "true"
                },
                "StringEquals": {
                    "aws:PrincipalTag/role": "data-analyst"
                }
            }
        }
    ]
}
```

### 最小权限策略模式

```json
// 好：明确 Allow + 隐式 Deny
{
    "Effect": "Allow",
    "Action": ["ec2:Describe*", "ec2:StartInstances"],
    "Resource": "arn:aws:ec2:ap-northeast-1:123456:instance/production-*"
}

// 坏：通配符滥用
{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
}
```

### 权限边界（Permissions Boundary）

```json
// 防止权限提升 — 用户角色可以附加的最大权限范围
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "ec2:RunInstances",
            "s3:PutObject"
        ],
        "Resource": "*"
    }]
}
```

### 信任策略（AssumeRole）

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::123456789012:role/JenkinsBuild"
        },
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {
                "sts:ExternalId": "BUILD-ENV-001"
            }
        }
    }]
}
```

## Key Management Service (KMS)

```bash
# KMS 密钥类型
# AWS Managed Key — AWS 自动管理（免费）
# Customer Managed Key (CMK) — 用户管理（$1/月）
# Custom Key Store — 自管控 HSM（CloudHSM）

# 创建 CMK
aws kms create-key \
    --description "Production Data Encryption" \
    --key-usage ENCRYPT_DECRYPT \
    --customer-master-key-spec SYMMETRIC_DEFAULT

# KMS 密钥策略
aws kms put-key-policy \
    --key-id arn:aws:kms:ap-northeast-1:123456:key/xxx \
    --policy-name default \
    --policy file://kms-policy.json

# KMS 限时授权（Grant）
aws kms create-grant \
    --key-id alias/prod-key \
    --grantee-principal arn:aws:iam::123456:role/BackupRole \
    --operations Decrypt \
    --constraints EncryptionContextEquals={BackupJob=true} \
    --retiring-principal arn:aws:iam::123456:root
```

## 安全服务架构

```yaml
AWS 安全服务栈:

GuardDuty:
  - 威胁检测（DNS异常/API调用/加密货币挖矿）
  - 自动 EBS 快照 + Lambda 响应
  - 定价: $0.01/100万 DNS 请求

Security Hub:
  - 集中安全发现（集成 GuardDuty/Inspector/Macie）
  - CIS AWS 基线检查自动化
  - 生成 SOC/PCI 合规报告

Inspector:
  - EC2 漏洞扫描
  - 无代理扫描（Amazon Inspector Agentless）
  - 每月自动评估

Macie:
  - S3 PII 自动发现
  - AI/ML 驱动敏感数据分类
  - 定价: $0.10/GB

Config:
  - 资源配置合规监控
  - 配置变更历史审计
  - 自定义合规规则（AWS Config Rules）
```

## S3 安全基线

```yaml
# 1. 公开访问阻断
BlockPublicAcls: true
IgnorePublicAcls: true
BlockPublicPolicy: true
RestrictPublicBuckets: true

# 2. 加密配置
DefaultEncryption: SSE-S3 or SSE-KMS
BucketKeyEnabled: true  # 减少 KMS API 调用

# 3. 日志与版本
ServerAccessLogs: enabled
ObjectVersioning: enabled
MFA_Delete: enabled

# 4. 访问控制
BucketPolicy:
  - Condition: aws:SourceIp 限制
  - Condition: aws:SecureTransport（强制 HTTPS）
  - Condition: s3:x-amz-server-side-encryption（强制加密上传）

# 5. 生命周期
Transition: Standard-IA (30d) → Glacier (90d) → Expire (365d)
NoncurrentVersionExpiration: 90d
```

## VPC 安全组 vs NACL

| 特性 | Security Group | NACL |
|------|---------------|------|
| 层级 | 实例级 | 子网级 |
| 状态 | 有状态 | 无状态 |
| 规则 | 仅 Allow | Allow + Deny |
| 评估 | 全部规则合并 | 规则按编号生效 |
| 返回值 | 自动允许返回流量 | 需显式配置出站规则 |
| 适用 | 按应用分组 | 子网级黑白名单 |

## 审计与监控

```bash
# CloudTrail 审计日志
aws cloudtrail create-trail \
    --name SecurityTrail \
    --s3-bucket-name company-cloudtrail-logs \
    --is-multi-region-trail \
    --enable-log-file-validation \
    --cloud-watch-logs-log-group-arn arn:aws:logs:...

# 关键审计事件
# IAM: CreateUser/AttachPolicy/UpdateAssumeRolePolicy
# EC2: RunInstances/CreateSecurityGroup/AuthorizeSecurityGroupIngress
# S3: PutBucketPolicy/PutBucketAcl
# KMS: DisableKey/ScheduleKeyDeletion
# CloudTrail: StopLogging/DeleteTrail
```

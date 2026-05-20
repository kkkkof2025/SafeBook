# 云存储安全

> 配置错误——云上数据泄露的头号原因

---

## 为什么云存储安全如此重要

云存储是最常用的云服务，也是**配置错误最多的地方**。

```
云安全事件中 20-30% 与存储配置错误有关
```

### 经典的数据泄露路径

```
攻击者发现 → S3 桶公开可读 → 下载数据 → 数据泄露 → 公关灾难
```

---

## 云存储安全基础

### 不同云平台的存储服务

| 功能 | AWS | Azure | 阿里云 | 腾讯云 |
|------|-----|-------|-------|-------|
| 对象存储 | S3 | Blob Storage | OSS | COS |
| 文件存储 | EFS | Files | NAS | CFS |
| 块存储 | EBS | Disk | 云盘 | CBS |

**对象存储（S3/OSS/Blob）** 是配置错误的重灾区。

---

## 常见的存储配置错误

### 1. 公开可读（最致命）

```bash
# ❌ 错误：桶公开可读
aws s3 ls s3://company-backup/
# 任何人只要有 AWS CLI 就能列出所有文件

# ✅ 正确：默认阻止公开访问
aws s3api put-public-access-block \
  --bucket company-backup \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,\
  BlockPublicPolicy=true,RestrictPublicBuckets=true
```

**真实案例**：
- 2023 年：某 AI 公司的训练数据桶公开可读（S3 配置错误），包含客户对话记录
- 2022 年：某社交平台（Pegasystems 的 S3 存储配置错误），数十亿条用户数据泄露
- 2021 年：某医疗 AI 公司，7.5TB 患者数据公开

### 2. 缺少服务端加密

```bash
# ❌ 错误：桶未启用加密
aws s3api get-bucket-encryption --bucket my-data
# An error occurred (ServerSideEncryptionConfigurationNotFoundError)

# ✅ 正确：启用默认加密
aws s3api put-bucket-encryption \
  --bucket my-data \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

### 3. 版本控制未开启

```bash
# ❌ 错误：无版本控制
# 误删或勒索软件加密 → 无法恢复

# ✅ 正确：开启版本控制
aws s3api put-bucket-versioning \
  --bucket my-data \
  --versioning-configuration Status=Enabled
```

### 4. 缺少访问日志

```bash
# ❌ 错误：无日志记录
# 数据被读取了你都不知道

# ✅ 正确：开启访问日志
aws s3api put-bucket-logging \
  --bucket my-data \
  --bucket-logging-status \
  '{"LoggingEnabled":{"TargetBucket":"my-logs","TargetPrefix":"s3-access/"}}'
```

---

## AI 场景：训练数据保护

### 训练数据生命周期安全

```
数据收集 → 存储 → 预处理 → 训练 → 模型 → 推理
   │         │        │        │       │       │
   │   加密存储  │ 脱敏处理 │  │  模型加密 │   │
   │         │        │        │       │       │
   ▼         ▼        ▼        ▼       ▼       ▼
```

### 最小权限访问模式

```yaml
# 训练数据桶权限设计

原始数据桶:
  加密: SSE-KMS
  公开访问: 阻止
  生命周期: 30天后转为 Glacier
  
训练数据桶:
  加密: SSE-KMS
  访问: 仅 SageMaker 训练角色
  版本控制: 开启
  
模型输出桶:
  加密: SSE-KMS
  访问: 仅推理端点角色（只读）
  日志: 开启所有访问日志
```

### 数据脱敏（必须做）

```python
import re

def redact_pii(text: str) -> str:
    """训练前脱敏敏感信息"""
    # 替换身份证号
    text = re.sub(r'\d{18}[\dXx]', '[ID_REDACTED]', text)
    # 替换手机号
    text = re.sub(r'1[3-9]\d{9}', '[PHONE_REDACTED]', text)
    # 替换邮箱
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[EMAIL_REDACTED]', text)
    return text
```

---

## AWS S3 安全检查清单

- [ ] 使用 `aws s3api get-public-access-block` 确认所有桶阻止了公开访问
- [ ] 使用 `aws s3api get-bucket-encryption` 确认所有桶启用了加密
- [ ] 使用 `aws s3api get-bucket-versioning` 确认关键桶有版本控制
- [ ] 使用 `aws s3api get-bucket-logging` 确认访问日志已开启
- [ ] 定期使用 `aws s3api get-bucket-policy` 审核桶策略
- [ ] 使用 IAM Access Analyzer 检测意外公开的桶
- [ ] 敏感数据的桶启用对象锁定（防止修改/删除）

---

## 自动化检测工具

```bash
# AWS Config 托管规则
aws configservice describe-compliance-by-config-rule \
  --config-rule-names s3-bucket-public-read-prohibited \
                        s3-bucket-public-write-prohibited \
                        s3-bucket-ssl-requests-only \
                        s3-bucket-server-side-encryption-enabled

# ScoutSuite（开源多云安全审计）
pip install scoutsuite
scout aws --report-dir ./reports

# Prowler（AWS 安全审计）
prowler aws --services s3
```

---

## 延伸阅读

1. [AWS S3 安全最佳实践](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
2. [阿里云 OSS 安全指南](https://help.aliyun.com/document_detail/31884.html)
3. [Azure Blob 存储安全](https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations)
4. [CIS AWS Foundations — S3 部分](https://www.cisecurity.org/benchmark/amazon_web_services)
5. [OWASP Cloud Security — Object Storage](https://owasp.org/www-project-cloud-security/)

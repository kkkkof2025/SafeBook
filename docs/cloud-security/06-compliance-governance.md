# 云合规与治理

> 合规不是安全的目标——安全是合规的结果

---

## 为什么合规对云安全重要

```
没有合规框架 → 凭感觉做安全 → 有遗漏也不知道
有合规框架 → 对照标准检查 → 知道哪里没做好
```

合规框架给了你一个**安全基线**。不是让你"通过认证就完事"，而是"对照标准知道自己差在哪"。

---

## 主流合规框架

### 国际框架

| 框架 | 适用范围 | 对云安全的意义 |
|------|---------|--------------|
| SOC 2 | 云服务商 | 安全可用性保密性隐私 |
| ISO 27001 | 所有组织 | 信息安全管理体系 |
| PCI DSS | 支付行业 | 信用卡数据处理 |
| HIPAA | 医疗行业 | 健康信息保护 |
| FedRAMP | 美国政府云服务 | 政府云安全评估 |

### 国内框架

| 框架 | 适用范围 | 说明 |
|------|---------|------|
| 等保 2.0 | 所有信息系统 | 网络安全等级保护制度 |
| 个保法 | 个人信息处理 | PIPL |
| 数据安全法 | 数据处理活动 | 数据分类分级保护 |
| 关键信息基础设施 | 关键行业 | CII 保护条例 |

---

## 云上的合规挑战

### 挑战 1：数据在哪里？

```
传统数据中心：
  我知道我的数据在机房的哪台服务器上

云上：
  我的数据可能在...
  - 华东区的存储桶
  - 全球分布的 CDN 节点
  - 自动备份到另一个区域
```

**应对**：使用云厂商的数据地图服务（AWS Macie、阿里云敏感数据识别）

### 挑战 2：谁在访问数据？

```
传统环境：
  只有内部人员，容易追踪

云上：
  - IAM 用户
  - 跨账户角色
  - 临时凭证（STS）
  - 服务到服务调用
  - SDK/CLI/Console 多种途径
```

**应对**：启用 CloudTrail/操作审计，持续监控 API 调用

### 挑战 3：合规证据在哪？

```
传统环境：
  人工整理审计证据

云上：
  - 自动化审计（AWS Config / 阿里云 Config）
  - 合规报告（AWS Artifact / 阿里云合规报告）
  - 持续监控（Security Hub / 态势感知）
```

---

## 云合规自动化

### AWS Config 托管规则

```bash
# 自动检查云上配置是否合规

# 检查1：S3 桶是否阻止了公开访问
aws configservice describe-compliance-by-config-rule \
  --config-rule-name s3-bucket-public-read-prohibited

# 检查2：EBS 卷是否加密
aws configservice describe-compliance-by-config-rule \
  --config-rule-name encrypted-volumes

# 检查3：IAM 用户是否有 MFA
aws configservice describe-compliance-by-config-rule \
  --config-rule-name iam-user-mfa-enabled
```

### AI 场景的合规检查

```yaml
# AI 训练数据合规检查清单

数据来源合规:
  - 训练数据是否有明确的使用授权？
  - 是否包含个人身份信息（PII）？
  - 数据是否需要脱敏？
  - 数据跨境存储是否有合规风险？

数据存储合规:
  - 存储桶是否加密？
  - 访问日志是否开启？
  - 数据保留策略是否明确？
  - 数据删除是否有机制保障？

模型输出合规:
  - 推理结果是否包含敏感信息？
  - 是否有内容过滤机制？
  - 推理日志是否记录完整的请求/响应？
  - 是否有数据保留和删除策略？
```

---

## 云治理框架

### 多账户治理

```
大型云部署应该使用多账户策略：

管理账户（Management Account）
├── 安全账户（Security Account）
│   ├── 日志集中存储
│   ├── 安全审计工具
│   └── 合规报告
├── 开发账户（Dev Account）
│   └── 开发环境
├── 测试账户（Staging Account）
│   └── 预发布环境
├── 生产账户（Production Account）
│   └── 生产环境
└── DevOps 账户（Shared Services）
    ├── CI/CD 管道
    └── 镜像仓库
```

### 治理工具

| 工具/服务 | 用途 |
|-----------|------|
| AWS Organizations / 阿里云资源目录 | 多账户管理 |
| AWS Control Tower / 云治理中心 | 自动化治理 |
| AWS Config / 阿里云 Config | 配置合规检查 |
| AWS CloudTrail / 操作审计 | API 调用审计 |
| AWS Security Hub / 安全中心 | 集中安全监控 |
| AWS IAM Access Analyzer | IAM 权限分析 |

---

## AI 合规特有问题

### 训练数据的版权问题

```
案例：2023 年，多名艺术家起诉 AI 公司
      声称他们的作品被未经授权用于训练 AI 模型

合规要点：
  - 训练数据必须有合法的来源授权
  - 公开爬取的数据不等于可以用于训练
  - 需要记录数据来源的版权信息
```

### 模型输出的内容安全

```yaml
AI 内容合规：
  - 输出内容是否合规？（黄/暴/政/恐）
  - 是否包含歧视性内容？
  - 是否泄露了训练数据中的个人信息？
  - 是否有监管要求的内容过滤？
  
技术方案：
  - 推理前：输入内容审核
  - 推理后：输出内容过滤
  - 日志记录：完整的推理审计链
```

---

## 合规工具速查

```bash
# AWS Compliance Tools
# 1. AWS Artifact — 获取 SOC/ISO 报告
aws artifact list-reports

# 2. AWS Audit Manager — 自动化审计
aws auditmanager list-assessment-frameworks

# 3. Prowler — 开源 AWS 安全审计
docker run -e AWS_PROFILE=myprofile toniblyx/prowler:latest

# 4. ScoutSuite — 多云安全审计
scout aws --report-dir ./compliance-report
```

---

## 延伸阅读

1. [AWS 合规中心](https://aws.amazon.com/compliance/)
2. [Azure 合规中心](https://learn.microsoft.com/en-us/azure/compliance/)
3. [阿里云合规](https://www.alibabacloud.com/trust-center)
4. [等保 2.0 云安全扩展要求](https://www.cac.gov.cn/)
5. [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
6. [Cloud Security Alliance — Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)

*上一篇：[Serverless 安全](05-serverless-security.md)*

*下一篇：[CSPM 与云安全工具链](07-cspm-tools.md)*

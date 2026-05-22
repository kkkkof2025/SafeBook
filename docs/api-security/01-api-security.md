# API 安全设计

## 概述

API 是现代应用的神经系统——连接着前端、后端、微服务和第三方。RESTful API、GraphQL、gRPC 各有不同安全模型，但有共同的核心原则：认证、授权、输入验证、速率限制和审计。

---

## 1. API 安全架构

```
API 安全网关架构:

  客户端 → [API Gateway] → 微服务

  API Gateway 负责:
    ├── 认证（JWT/OAuth2/API Key）
    ├── 授权（RBAC/ABAC）
    ├── 速率限制（令牌桶/滑动窗口）
    ├── 输入验证（Schema 验证）
    ├── 请求/响应日志（审计）
    ├── CORS 管理
    ├── 响应缓存
    └── 熔断/降级
```

---

## 2. API 认证方案

### 2.1 JWT vs Session Token

```python
import jwt
import datetime

class JWTAuthManager:
    """JWT 认证（适合微服务/无状态 API）"""

    def __init__(self, secret_key):
        self.secret = secret_key
        self.algorithm = 'HS256'  # 生产环境建议 RS256

    def create_token(self, user_id, role, expiry_minutes=60):
        payload = {
            'sub': user_id,
            'role': role,
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes),
            'jti': os.urandom(16).hex()  # 唯一标识符（用于撤销）
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def verify_token(self, token):
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                options={
                    'require': ['exp', 'sub', 'jti'],
                    'verify_exp': True
                }
            )
            return payload, None
        except jwt.ExpiredSignatureError:
            return None, 'Token expired'
        except jwt.InvalidTokenError as e:
            return None, f'Invalid token: {e}'
```

### 2.2 API Key 最佳实践

```python
class APIKeyManager:
    """
    API Key 安全最佳实践:
    1. 服务端生成 (secrets.token_urlsafe)
    2. 仅存 bcrypt/Argon2 哈希（不存明文）
    3. 前端仅显示前缀 + 后 4 位
    4. 支持多 Key （轮换无中断）
    5. 权限最小化（每个 Key 绑定 Scope）
    """

    def generate_key(self, user_id, scopes):
        """生成 API Key — 仅返回一次明文"""
        prefix = "sk_"  # Stripe 式前缀
        raw = secrets.token_urlsafe(32)
        full_key = prefix + raw

        # 存储: Argon2 哈希
        hash = self.ph.hash(full_key)

        self.db.insert({
            'user_id': user_id,
            'key_hash': hash,
            'key_preview': f"{prefix}{raw[:4]}...{raw[-4:]}",
            'scopes': scopes,
            'created_at': datetime.utcnow(),
            'last_used': None
        })

        # 仅返回一次明文
        return full_key

    def verify_key(self, provided_key):
        """验证 API Key（恒定时间比较）"""
        preview = provided_key[:7]
        keys = self.db.find_keys_by_preview(preview)

        for k in keys:
            if self.ph.verify(k['key_hash'], provided_key):
                self.db.update_last_used(k['id'])
                return k['user_id'], k['scopes']

        return None, None
```

---

## 3. API 输入验证

### 3.1 JSON Schema 验证

```python
from jsonschema import validate, ValidationError

API_SCHEMAS = {
    'create_user': {
        'type': 'object',
        'required': ['email', 'password', 'name'],
        'properties': {
            'email': {
                'type': 'string',
                'format': 'email',
                'maxLength': 254
            },
            'password': {
                'type': 'string',
                'minLength': 8,
                'maxLength': 128,
                'pattern': r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$'
            },
            'name': {
                'type': 'string',
                'minLength': 1,
                'maxLength': 100,
                'pattern': r'^[\w\s\-\']+$'  # 防止注入
            },
            'age': {
                'type': 'integer',
                'minimum': 0,
                'maximum': 150
            }
        },
        'additionalProperties': False  # 拒绝未定义字段
    }
}

class InputValidator:
    @staticmethod
    def validate(endpoint, data):
        schema = API_SCHEMAS.get(endpoint)
        if not schema:
            raise ValueError(f"No schema for endpoint: {endpoint}")

        try:
            validate(instance=data, schema=schema)
            return True, None
        except ValidationError as e:
            return False, str(e)
```

### 3.2 序列化安全

```python
# Mass Assignment 防护（不信任客户端发送的字段）

class UserUpdateSerializer:
    ALLOWED_FIELDS = {'name', 'email', 'avatar_url'}

    @classmethod
    def deserialize(cls, data):
        """仅提取白名单字段，丢弃所有其他字段"""
        safe = {}
        for field in cls.ALLOWED_FIELDS:
            if field in data:
                safe[field] = data[field]
        return safe

# ❌ 危险: User.update(**request.json) → Mass Assignment
# ✅ 安全: User.update(**UserUpdateSerializer.deserialize(request.json))
```

---

## 4. REST API 安全清单

```yaml
API 安全基础检查:

  认证 (Authentication):
    - [ ] 所有端点（除 /health）需要认证
    - [ ] 支持 Token 轮换
    - [ ] 支持 Token 撤销
    - [ ] 失效检测（多 IP 多 User-Agent = 标记）

  授权 (Authorization):
    - [ ] 每个端点有明确的 Scope 要求
    - [ ] 对象级授权（用户只能看自己的数据）
    - [ ] IDOR 测试（尝试 /users/OTHER_USER_ID）

  输入 (Input):
    - [ ] JSON Schema 验证
    - [ ] 拒绝 additionalProperties
    - [ ] 拒绝过大请求（> 10MB = 413）
    - [ ] 拒绝非 JSON Content-Type

  输出 (Output):
    - [ ] 不泄露堆栈跟踪
    - [ ] 标准错误格式: {"error": {"code": "...", "message": "..."}}
    - [ ] Content-Type: application/json
```

---

*下一篇：[API 渗透测试](02-api-pentesting.md)*

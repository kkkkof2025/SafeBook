# SSO 与 OAuth 2.0 安全实战

## 概述

单点登录 (SSO) 是现代企业身份基础设施的核心——但它的安全性是"要么全对，要么全错"。一个 OAuth 配置错误意味着攻击者可以通过一个应用访问所有应用。本章深入 SSO 架构级安全防御。

---

## 1. OAuth 2.0 安全模型

### 1.1 四种授权模式

```
OAuth 2.0 授权模式:

  授权码模式 (Authorization Code) + PKCE:
    适用: Web 应用/SPA/移动端
    安全: ★★★★★ (最安全)
    特点: 前后端分离，Code 换 Token

  隐式模式 (Implicit) — 已废弃:
    适用: 不应再使用
    安全: ★☆☆☆☆
    特点: Token 直接返回 (已不推荐)

  资源所有者密码模式 (Password):
    适用: 高度可信的第一方应用
    安全: ★★☆☆☆
    特点: 直接使用用户名+密码

  客户端凭证模式 (Client Credentials):
    适用: 服务间通信
    安全: ★★★★☆ (需密钥管理)
    特点: 无用户参与
```

### 1.2 PKCE (Proof Key for Code Exchange)

```python
import hashlib
import base64
import secrets
import requests

class OAuthPKCEFlow:
    """OAuth 2.0 + PKCE 安全实现"""

    def __init__(self, client_id, authorization_endpoint, token_endpoint):
        self.client_id = client_id
        self.auth_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint

    def generate_pkce(self):
        """生成 PKCE Code Verifier 和 Challenge"""
        # 随机 43 字符 verifier
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')

        # SHA-256 Challenge
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')

        return code_verifier, code_challenge

    def create_authorization_url(self, redirect_uri, scope, state):
        """创建授权 URL"""
        code_verifier, code_challenge = self.generate_pkce()

        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }

        url = (f"{self.auth_endpoint}?"
               f"{'&'.join(f'{k}={v}' for k, v in params.items())}")

        return url, code_verifier, state

    def exchange_code_for_token(self, code, redirect_uri, code_verifier):
        """用授权码换取 Token"""
        response = requests.post(self.token_endpoint, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.client_id,
            'code_verifier': code_verifier
        })

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Token exchange failed: {response.json()}")
```

---

## 2. SSO 攻击面

### 2.1 常见 SSO 漏洞

```yaml
SSO 攻击面全景:

  1. OAuth State 参数缺失/可预测:
     → CSRF 攻击 → 攻击者将受害者的账号绑定到自己的身份

  2. Redirect URI 验证不严:
     → 开放重定向 → Token 被劫持
     → 不验证子路径 → evil.com/@auth.example.com

  3. Token 泄露:
     → access_token 通过 URL Fragment (#) 传递
     → 被第三方脚本窃取 (postMessage 广播)

  4. JWT 配置错误:
     → alg=none → 无签名验证
     → RS256→HS256 混淆 → 用公钥作为 HMAC 密钥

  5. 混用不同 OAuth 提供商的 Token:
     → Google token 被返回到 Microsoft 端点
     → 错误的 audience 验证

  6. SAML 签名绕过:
     → XML Signature Wrapping (XSW)
     → 签名验证通过但实际身份被篡改
```

### 2.2 SSO 安全检测

```python
import jwt
import requests
import urllib.parse

class SSOSecurityTester:
    """SSO/OAuth 安全测试"""

    def test_state_csrf(self, auth_url, redirect_uri):
        """测试 State 参数 CSRF"""
        # 1. 正常流程获取 state
        response = requests.get(auth_url, allow_redirects=False)

        # 2. 尝试不带 state 参数
        params = {
            'response_type': 'code',
            'client_id': 'test_client',
            'redirect_uri': redirect_uri,
            # 故意不传 state
        }
        test_url = f"{auth_url}?{urllib.parse.urlencode(params)}"
        response = requests.get(test_url, allow_redirects=False)

        if response.status_code == 302:
            print("[VULNERABLE] OAuth 未强制要求 state 参数!")
            return False
        else:
            print("[PASS] 强制要求 state")
            return True

    def test_redirect_uri(self, auth_url, redirect_uri):
        """测试 Redirect URI 验证"""
        # 路径遍历
        malicious_uris = [
            f"https://evil.com",
            f"{redirect_uri}.evil.com",
            f"{redirect_uri}@evil.com",
            f"{redirect_uri}%23@evil.com",
            f"{redirect_uri}/../../evil.com",
            f"javascript://evil.com%0a{alert(1)}",  # XSS in redirect
        ]

        for uri in malicious_uris:
            params = {
                'response_type': 'code',
                'client_id': 'test',
                'redirect_uri': uri,
                'state': 'test'
            }
            test_url = f"{auth_url}?{urllib.parse.urlencode(params)}"
            response = requests.get(test_url, allow_redirects=False)

            if 'Location' in response.headers:
                loc = response.headers['Location']
                if uri in loc or 'evil.com' in loc:
                    print(f"[VULNERABLE] Redirect URI 验证绕过: {uri}")
                    return False

        print("[PASS] Redirect URI 验证有效")
        return True

    def test_jwt_misconfiguration(self, jwt_token):
        """测试 JWT 配置错误"""
        # 1. 测试 alg=none
        header = jwt.get_unverified_header(jwt_token)
        print(f"JWT 算法: {header.get('alg')}")

        if header.get('alg', '').upper() == 'NONE':
            print("[VULNERABLE] JWT 接受 alg=none!")
            return

        # 2. 测试算法混淆
        payload = jwt.decode(jwt_token, options={"verify_signature": False})
        if header.get('alg', '').startswith('RS'):
            # 如果使用 RS256，尝试解析公钥并用 HS256 签名
            print("[INFO] 使用 RS256 — 检查是否存在算法混淆漏洞")

        # 3. 测试过期
        try:
            jwt.decode(jwt_token, options={
                "verify_signature": False,
                "verify_exp": True
            })
        except jwt.ExpiredSignatureError:
            print("[INFO] Token 已过期 (正常)")

    def test_saml_xsw(self, saml_response):
        """测试 SAML XML Signature Wrapping"""
        from lxml import etree

        # 构造 XSW 攻击 Payload:
        # 在签名元素外层包装一个额外的断言
        tree = etree.fromstring(saml_response.encode())

        # 检查是否只有一个断言
        assertions = tree.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
        if len(assertions) > 1:
            print("[VULNERABLE] SAML Response 包含多个断言 (可能的 XSW 目标)")
```

---

## 3. 安全 SSO 架构

### 3.1 零信任 SSO

```yaml
零信任 SSO 设计原则:

  1. 每次请求都验证:
     ❌ 登录一次 → 永远信任
     ✅ 每次 API 调用都验证 Token + Context

  2. 最小权限:
     ❌ 管理员登录 → 所有权限
     ✅ 管理员登录 → 仅当前任务所需权限 (JIT)

  3. 持续验证:
     ✅ 设备健康状态
     ✅ 地理位置 (不可能旅行检测)
     ✅ 行为基线 (异常检测)

  4. Token 生命周期:
     Access Token: 5-15 分钟
     Refresh Token: 1-24 小时
     Refresh Token 轮换: 每次使用换新

  5. Token 撤消:
     单点登出 → 所有应用立即失效
     Token 黑名单 → Redis 缓存
```

### 3.2 安全实现

```python
from datetime import datetime, timedelta
import jwt
import redis

class ZeroTrustSSO:
    """零信任 SSO 实现"""

    def __init__(self):
        self.redis = redis.Redis()
        self.access_token_expiry = timedelta(minutes=5)
        self.refresh_token_expiry = timedelta(hours=6)

    def create_tokens(self, user_id, context):
        """创建 Access + Refresh Token"""

        now = datetime.utcnow()

        # 短期 Access Token (5 分钟)
        access_token = jwt.encode({
            'sub': user_id,
            'iat': now,
            'exp': now + self.access_token_expiry,
            'context': {
                'ip': context['ip'],
                'device_id': context['device_id'],
                'session_id': context['session_id']
            }
        }, self.private_key, algorithm='RS256')

        # Refresh Token 实现轮换
        refresh_token = secrets.token_urlsafe(64)
        refresh_family = secrets.token_urlsafe(32)

        # 存储 Refresh Token
        self.redis.setex(
            f"refresh:{refresh_family}",
            int(self.refresh_token_expiry.total_seconds()),
            refresh_token
        )

        return {
            'access_token': access_token,
            'refresh_token': f"{refresh_family}:{refresh_token}",
            'expires_in': 300
        }

    def validate_access_token(self, token, request_context):
        """验证 Token + 上下文"""
        try:
            payload = jwt.decode(token, self.public_key, algorithms=['RS256'])

            # 上下文验证
            token_ctx = payload.get('context', {})

            # IP 绑定 (可选 — 移动网络 IP 会变化)
            if 'ip' in token_ctx and token_ctx['ip'] != request_context.get('ip'):
                raise Exception("IP mismatch")

            # 检查是否被撤销
            jti = payload.get('jti')
            if self.redis.get(f"revoked:{jti}"):
                raise Exception("Token revoked")

            return payload

        except jwt.ExpiredSignatureError:
            raise Exception("Token expired")
        except jwt.InvalidTokenError:
            raise Exception("Invalid token")

    def rotate_refresh_token(self, refresh_token_str):
        """Refresh Token 轮换 — 检测重放攻击"""
        family_id, token_value = refresh_token_str.split(':')

        stored_token = self.redis.get(f"refresh:{family_id}")

        if not stored_token:
            # 家族不存在 → 已使用过 → 可能是重放攻击!
            # 撤销该用户所有 Token
            self.revoke_all_tokens_for_family(family_id)
            raise Exception("Refresh token replay detected!")

        if stored_token != token_value:
            # Token 不匹配 → 重放 + 原始 Token 已用
            self.revoke_all_tokens_for_family(family_id)
            raise Exception("Refresh token replay detected!")

        # 发放新 Refresh Token (轮换)
        new_token = secrets.token_urlsafe(64)
        self.redis.setex(
            f"refresh:{family_id}",
            int(self.refresh_token_expiry.total_seconds()),
            new_token
        )

        return new_token

    def revoke_all_tokens_for_family(self, family_id):
        """撤销令牌家族"""
        self.redis.delete(f"refresh:{family_id}")
```

---

## 参考资源

- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/draft-ietf-oauth-security-topics/)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [JWT 安全最佳实践](https://tools.ietf.org/html/rfc8725)

---

*上一篇：[零信任架构](01-zero-trust.md)*

*下一篇：[零信任落地实战](03-zero-trust-deep.md)*

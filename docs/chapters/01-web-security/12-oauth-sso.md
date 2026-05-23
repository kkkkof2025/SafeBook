# OAuth 2.0 与 SSO 安全深度

## OAuth 2.0 授权流程

### 四种授权模式
```
模式对比:
  Authorization Code  ← Web 应用（最安全，推荐）
  PKCE                ← 移动端/SPA（无 Client Secret）
  Client Credentials  ← 服务间通信 (M2M)
  Device Code         ← IoT/TV 等输入受限设备

  Implicit (已废弃)   ← OAuth 2.1 中正式移除
  Password (已废弃)   ← OAuth 2.1 中正式移除
```

### PKCE（Proof Key for Code Exchange）
```python
import hashlib, base64, secrets

# 客户端生成
code_verifier = secrets.token_urlsafe(32)  # 43-128 字符
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode()

# 步骤 1: 发起授权请求 (带 code_challenge)
auth_url = f"https://auth.example.com/authorize?" \
    f"response_type=code&" \
    f"client_id={CLIENT_ID}&" \
    f"redirect_uri={REDIRECT_URI}&" \
    f"code_challenge={code_challenge}&" \
    f"code_challenge_method=S256&" \
    f"state={state}&" \
    f"scope=openid profile email"

# 步骤 2: 用 code_verifier 交换 Token
token_resp = requests.post("https://auth.example.com/token", data={
    "grant_type": "authorization_code",
    "code": auth_code,
    "redirect_uri": REDIRECT_URI,
    "client_id": CLIENT_ID,
    "code_verifier": code_verifier
})

# 安全保证: 即使攻击者拦截了 auth_code,
# 没有 code_verifier 也无法交换 Token
```

---

## OAuth 常见攻击

### 1. redirect_uri 不验证
```python
# ❌ 宽松匹配（可被绕过）
# redirect_uri=https://app.example.com@evil.com
# → 被解析为访问 evil.com!

# ❌ 前缀匹配
# redirect_uri=https://app.example.com.evil.com/callback
# → 子域名劫持

# ✅ 精确匹配 + 查询参数一致
def validate_redirect_uri(uri):
    if uri not in ALLOWED_URIS:
        return False
    # 额外的: 不允许额外查询参数
    parsed = urlparse(uri)
    if parsed.fragment:
        return False
    return True
```

### 2. CSRF + OAuth 登录劫持
```python
# 攻击场景: 攻击者发起 OAuth 登录 → 获取自己的 auth_code
# → 诱骗受害者访问 /callback?code=ATTACKER_CODE
# → 受害者登录到攻击者的账号

# ✅ 防御: state 参数
@app.route('/login')
def login():
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session['request_ip'] = request.remote_addr
    return redirect(f"{auth_url}&state={state}")

@app.route('/callback')
def callback():
    # 验证 state
    if request.args.get('state') != session.pop('oauth_state', None):
        return "CSRF Detected", 403
    # 可选的 IP 绑定 (注意 NAT/移动网络)
    if request.remote_addr != session.pop('request_ip', None):
        log.warning(f"IP changed during OAuth: {request.remote_addr}")
```

### 3. Scope 升级
```python
# 攻击: 客户端请求 scope=read → 篡改为 scope=read+write+admin
# 授权服务器必须严格校验

# ✅ 服务端: scope 白名单
class ScopeValidator:
    CLIENT_SCOPES = {
        'app1': {'read:profile', 'read:email'},
        'app2': {'read:profile', 'write:posts'},
    }

    def validate(self, client_id, requested_scopes):
        allowed = self.CLIENT_SCOPES.get(client_id, set())
        requested = set(requested_scopes.split())
        if not requested.issubset(allowed):
            raise ScopeViolationError(
                f"Client {client_id} requested unauthorized scopes: "
                f"{requested - allowed}"
            )
```

---

## SSO 安全

### SAML 安全要点
```xml
<!-- SAML 断言必须验证 -->
<saml:Assertion ID="_abc123">
  <!-- 签名验证 -->
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    ...
  </ds:Signature>
</saml:Assertion>

<!-- ❌ 常见漏洞: 签名验证在断言层而非响应层 -->
<!-- 攻击者可移除整个响应签名，保留断言 → 签名绕过 -->
```

### JWT 配置加固
```python
# ✅ 生产级 JWT 配置
import jwt
from datetime import datetime, timedelta

class SecureJWTManager:
    def __init__(self, private_key, public_key):
        self.private = private_key
        self.public = public_key

    def create(self, user_id, role):
        return jwt.encode({
            'sub': user_id,
            'role': role,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(minutes=15),
            'nbf': datetime.utcnow(),
            'jti': secrets.token_urlsafe(16),
            'iss': 'https://auth.example.com',
            'aud': 'https://api.example.com'
        }, self.private, algorithm='RS256', headers={'kid': 'key-2024'})

    def verify(self, token):
        return jwt.decode(
            token, self.public,
            algorithms=['RS256'],  # ⚠️ 必须是列表，拒绝算法混淆
            options={
                'require': ['exp', 'sub', 'jti', 'iss', 'aud'],
                'verify_exp': True,
                'verify_iss': True,
                'verify_aud': True
            },
            issuer='https://auth.example.com',
            audience='https://api.example.com'
        )
```

---

## 安全清单
- [ ] redirect_uri 精确白名单匹配
- [ ] state 参数防 CSRF
- [ ] PKCE (S256) 用于 SPA/移动端
- [ ] Refresh Token 轮换 (每次刷新发新 Token)
- [ ] Access Token 短期 (15分钟内)
- [ ] 算法固定为白名单 (禁用 "none")
- [ ] Audience 验证
- [ ] Token 绑定 (TLS Token Binding / DPoP)

---

*上一篇：[WebSocket 安全深度](11-websocket-security.md)*

*下一篇：[SSTI（服务端模板注入）深度](13-ssti.md)*

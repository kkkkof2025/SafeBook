# OAuth 2.0 与 SSO 安全

## OAuth 2.0 授权流程

### 授权码模式（推荐）
```
用户 → 客户端 → 授权服务器 → 用户认证
     ← 授权码 ←
     → 授权码 + Client Secret →
     ← Access Token + Refresh Token ←
```

## 常见攻击

### 授权码拦截
```http
# ❌ 危险：授权码在 URL 中可能被泄露
GET /callback?code=AUTH_CODE HTTP/1.1
Referer: https://evil.com/

# ✅ 安全：PKCE 扩展（Proof Key for Code Exchange）
code_verifier = crypto.randomBytes(32).toString('base64url')
code_challenge = crypto.createHash('sha256').update(code_verifier).digest('base64url')
```

### CSRF 攻击
```python
# ❌ 无 state 参数
@app.route('/callback')
def callback():
    code = request.args.get('code')
    # 攻击者可以诱导用户绑定攻击者的账号

# ✅ 使用 state 参数
state = secrets.token_urlsafe(32)
session['oauth_state'] = state
# 回调验证 state == session['oauth_state']
```

### 开放重定向
```python
# ❌ 不验证 redirect_uri
redirect_uri = request.args.get('redirect_uri')
return redirect(redirect_uri)

# ✅ 白名单验证
ALLOWED_URIS = ['https://app.example.com/callback', 'https://app.example.com/login']
if redirect_uri not in ALLOWED_URIS:
    return abort(400)
```

## SSO 安全风险

| 风险 | 描述 | 防护 |
|------|------|------|
| SAML 断言注入 | 伪造签名 XML | 验证签名 + Schema |
| JWT 算法混淆 | 将 RS256 改为 HS256 | 固定算法 + 算法验证 |
| Session 固定 | 预置 Session ID | 登录后重置 Session |
| SSO 劫持 | 窃取 Token | 短期 Token + 绑定 IP |

## JWT 安全最佳实践

```python
import jwt

# ✅ 正确方式
def create_token(user_id):
    payload = {
        'sub': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=1),
        'jti': secrets.token_urlsafe(16)  # 唯一标识
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    try:
        # ❌ 重要：明确指定算法，禁止算法混淆
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
```

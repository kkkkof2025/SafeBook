# 无密码认证迁移指南

## 无密码认证概述

无密码认证 (Passwordless Authentication) 使用生物特征、硬件密钥或魔法链接替代传统密码。

### 主要技术

1. **FIDO2/WebAuthn** - 硬件密钥 (YubiKey) + 平台认证 (Windows Hello)
2. **Magic Link** - 邮件/短信验证码
3. **生物特征** - 指纹、面部识别
4. **OTP** - 一次性密码 (TOTP/HOTP)

---

## FIDO2/WebAuthn 深度解析

### 协议架构

```
+------------+          +------------+          +------------+
| 用户       |          | 浏览器     |          | 服务器     |
| (Platform) | <------> | (Client)  | <------> | (Relying  |
|            |          |            |          |  Party)   |
+------------+          +------------+          +------------+
     |                         |                         |
     v                         v                         v
 (生物特征/               (WebAuthn API)           (验证签名)
  硬件密钥)
```

### 注册流程

```javascript
// 前端：发起注册请求
async function register() {
  // 1. 从服务器获取挑战
  const challenge = await fetch('/register/begin').then(r => r.json());

  // 2. 调用 WebAuthn API
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: base64url.decode(challenge.challenge),
      rp: { name: 'Example App' },
      user: {
        id: base64url.decode(challenge.user.id),
        name: challenge.user.name,
        displayName: challenge.user.displayName
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }]  // ES256
    }
  });

  // 3. 发送凭证到服务器
  await fetch('/register/complete', {
    method: 'POST',
    body: JSON.stringify({ credential })
  });
}
```

```python
# 后端：验证注册
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

rp = PublicKeyCredentialRpEntity('example.com', 'Example App')
server = Fido2Server(rp)

# 验证凭证
auth_data = AttestedCredentialData(credential.response.attestationObject)
credential_id = auth_data.credential_id
public_key = auth_data.public_key

# 存储到数据库
db.store_credential(user_id, credential_id, public_key)
```

### 认证流程

```javascript
// 前端：发起认证请求
async function authenticate() {
  // 1. 从服务器获取挑战
  const challenge = await fetch('/authenticate/begin').then(r => r.json());

  // 2. 调用 WebAuthn API
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: base64url.decode(challenge.challenge),
      allowCredentials: [{ type: 'public-key', id: credential_id }]
    }
  });

  // 3. 发送断言到服务器
  await fetch('/authenticate/complete', {
    method: 'POST',
    body: JSON.stringify({ assertion })
  });
}
```

```python
# 后端：验证签名
from fido2.webauthn import AuthenticatorAssertionResponse

# 获取存储的公钥
public_key = db.get_public_key(user_id, credential_id)

# 验证签名
assertion = AuthenticatorAssertionResponse(response)
assertion.verify(public_key, challenge)
```

---

## Magic Link 认证

### 流程

```
用户 --> 输入邮箱 --> 服务器发送魔法链接 --> 用户点击链接 --> 认证成功
```

### 实现示例

```python
# 后端：发送魔法链接
import secrets
from datetime import datetime, timedelta

def send_magic_link(email):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=15)

    # 存储 token 到数据库
    db.store_magic_token(email, token, expires_at)

    # 发送邮件
    link = f'https://example.com/auth/magic?token={token}'
    send_email(email, 'Login Link', f'Click here: {link}')

# 后端：验证魔法链接
def verify_magic_link(token):
    record = db.get_magic_token(token)

    if not record:
        return False, 'Invalid token'

    if record.expires_at < datetime.utcnow():
        return False, 'Token expired'

    # 认证成功
    user = db.get_user_by_email(record.email)
    db.delete_magic_token(token)
    return True, user
```

### 安全注意事项

1. **Token 有效期** - 15 分钟过期
2. **一次性使用** - 使用后立即删除
3. **HTTPS 强制** - 防止中间人截获
4. **速率限制** - 防止垃圾邮件

---

## 生物特征认证

### 类型

| 类型 | 示例 | 优势 | 风险 |
|------|------|------|------|
| 指纹 | Touch ID | 便捷 | 易受硅胶模具攻击 |
| 面部 | Face ID | 非接触 | 照片/3D 模型攻击 |
| 虹膜 | Windows Hello | 高精度 | 成本高 |
| 声纹 | Siri | 远程 | 录音攻击 |

### Windows Hello 实现

```csharp
// C# UWP 应用
using Windows.Security.Credentials;

public async Task<bool> AuthenticateWithHello()
{
    // 检查设备是否支持
    if (UserConsentVerifier.CheckAvailabilityAsync().GetResults().Status != UserConsentVerifierAvailability.Available)
        return false;

    // 请求认证
    var result = await UserConsentVerifier.RequestVerificationAsync("Authenticate with Windows Hello");

    return result.Status == VerificationStatus.Verified;
}
```

---

## 迁移策略

### 阶段1：并行运行

```
传统密码认证  }---> 同时支持
无密码认证    }---> 用户可选
```

**实施：**
```python
# 后端：支持两种认证方式
def authenticate(request):
    if request.json.get('password'):
        # 传统密码认证
        return authenticate_password(request)
    elif request.json.get('credential'):
        # 无密码认证
        return authenticate_webauthn(request)
    else:
        return error('Missing credentials')
```

### 阶段2：鼓励迁移

**策略：**
1. **登录后提示** - "升级到无密码认证"
2. **奖励机制** - 无密码用户享受额外功能
3. **安全检查** - 检测弱密码并强制迁移

### 阶段3：强制迁移

**策略：**
1. **设定截止日期** - 6 个月后禁用密码
2. **渐进式强制** - 新用户只能使用无密码
3. **遗留支持** - 为无法使用无密码的用户提供备用方案

---

## 安全最佳实践

### 1. 多因素认证 (MFA)

**组合：**
- FIDO2 硬件密钥 + Magic Link
- Windows Hello + OTP

### 2. 回退机制

**场景：** 硬件密钥丢失

**方案：**
1. **备用 OTP** - 预先生成的恢复码
2. **邮件验证** - 发送到注册邮箱
3. **人工审核** - 联系支持团队

### 3. 防钓鱼

**FIDO2 优势：**
- 绑定域名 (RP ID)
- 防止钓鱼网站伪造

```
合法网站: https://example.com --> RP ID: example.com
钓鱼网站: https://examle.com --> RP ID 不匹配 --> 认证失败
```

---

## 部署清单

### 前期准备

- [ ] 选择无密码技术方案 (FIDO2/Magic Link/生物特征)
- [ ] 评估用户设备兼容性
- [ ] 设计回退机制
- [ ] 制定迁移时间表

### 技术实施

- [ ] 前端集成 WebAuthn API
- [ ] 后端实现 FIDO2 服务器逻辑
- [ ] 配置邮件服务 (Magic Link)
- [ ] 实施速率限制和防滥用

### 用户培训

- [ ] 制作使用教程
- [ ] 提供技术支持渠道
- [ ] 解释安全优势和便利性

---

## 延伸阅读

- [WebAuthn Guide](https://webauthn.guide/)
- [FIDO2 Specifications](https://fidoalliance.org/specifications/)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/)

---

*上一篇：[无密码安全概述](01-passwordless-security.md)*

*下一篇：[Passkeys 与 FIDO2 深度解析](04-passkeys-deep-dive.md)*

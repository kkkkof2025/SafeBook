# FIDO2 无密码认证深度

> WebAuthn + CTAP2：终结密码的安全革命

---

## 1. 无密码认证演进

```
认证方式演进:
  知识因子 (Something you know): 密码 → MFA
  拥有因子 (Something you have): OTP → FIDO U2F
  生物因子 (Something you are): 指纹 → FIDO2/WebAuthn

  FIDO2 = WebAuthn (浏览器 API) + CTAP2 (设备协议)
```

---

## 2. WebAuthn 注册流程

```python
from webauthn import (
    generate_registration_options,
    verify_registration_response
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AttestationConveyancePreference
)

class WebAuthnService:
    """WebAuthn 服务端实现"""

    def start_registration(self, user):
        """生成注册挑战"""
        options = generate_registration_options(
            rp_id="example.com",          # RP ID = 域名
            rp_name="Example Corp",
            user_id=user.id.encode(),     # 最多 64 bytes
            user_name=user.email,
            user_display_name=user.name,
            # 认证器要求
            authenticator_selection=AuthenticatorSelectionCriteria(
                # 平台认证器 (Windows Hello/Face ID) 或
                # 跨平台 (USB Key)
                authenticator_attachment="cross-platform",
                user_verification=UserVerificationRequirement.PREFERRED,
                resident_key="required",  # 可发现凭证
            ),
            attestation=AttestationConveyancePreference.DIRECT,
        )

        # 服务器存储挑战 (用于验证)
        session['webauthn_challenge'] = options.challenge
        session['webauthn_user_id'] = user.id

        return options  # → 前端 navigator.credentials.create()

    def verify_registration(self, user, registration_response):
        """验证注册"""
        verification = verify_registration_response(
            credential=registration_response,
            expected_challenge=session['webauthn_challenge'],
            expected_origin="https://example.com",
            expected_rp_id="example.com",
        )

        # 存储凭证
        credential_data = {
            'credential_id': verification.credential_id,
            'public_key': verification.credential_public_key,
            'sign_count': verification.sign_count,
            'transports': registration_response.response.transports,
            'backup_eligible': verification.backup_eligible,
            'backup_state': verification.backup_state,
        }
        self.store_credential(user.id, credential_data)

        return True
```

---

## 3. WebAuthn 认证流程

```python
    def start_authentication(self, user=None):
        """生成认证挑战"""
        options = generate_authentication_options(
            rp_id="example.com",
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        if user:
            # 用户输入了用户名 → 列出该用户的凭证
            credentials = self.get_user_credentials(user.id)
            options.allow_credentials = [
                {'id': c['credential_id'], 'type': 'public-key',
                 'transports': c.get('transports', [])}
                for c in credentials
            ]

        session['webauthn_challenge'] = options.challenge
        return options  # → 前端 navigator.credentials.get()

    def verify_authentication(self, user, auth_response):
        """验证认证"""
        stored_credential = self.get_user_credential(
            user.id, auth_response.id
        )

        verification = verify_authentication_response(
            credential=auth_response,
            expected_challenge=session['webauthn_challenge'],
            expected_origin="https://example.com",
            expected_rp_id="example.com",
            credential_public_key=stored_credential['public_key'],
            credential_current_sign_count=stored_credential['sign_count'],
        )

        # 更新签名计数器 (检测凭证克隆)
        if verification.new_sign_count <= stored_credential['sign_count']:
            raise Exception("Possible credential cloning detected!")

        self.update_sign_count(
            user.id, verification.credential_id,
            verification.new_sign_count
        )

        return True
```

---

## 4. FIDO2 安全特性

### 域名绑定 (Origin Binding)
```
WebAuthn 自动绑定域名 (RP ID):
  - 凭证仅在创建时声明的域名下有效
  - example.com ≠ evil.com
  - 完全免疫钓鱼攻击!
  - 攻击者无法诱使受害者用 example.com 的凭证登录 evil.com
```

### 防重放
```python
# WebAuthn 挑战-应答机制天然防重放
# 1. 每次认证生成随机 Challenge
# 2. Challenge 使用后立即废弃
# 3. 签名计数器递增检测凭证克隆

class ChallengeManager:
    def __init__(self):
        self.active_challenges = {}  # session_id → challenge
        self.expiration = timedelta(minutes=5)

    def create(self, session_id):
        challenge = secrets.token_bytes(32)
        self.active_challenges[session_id] = {
            'challenge': challenge,
            'created': datetime.utcnow(),
            'used': False
        }
        return challenge

    def consume(self, session_id, challenge):
        entry = self.active_challenges.get(session_id)
        if not entry or entry['used']:
            raise Exception("Challenge already used or expired")
        if datetime.utcnow() - entry['created'] > self.expiration:
            raise Exception("Challenge expired")
        if entry['challenge'] != challenge:
            raise Exception("Challenge mismatch")

        entry['used'] = True  # 一次性!
        return True
```

---

## 5. 迁移路线图

```yaml
FIDO2 迁移四阶段:

  Phase 1: 启用 2FA (FIDO U2F)
    - 用户保留密码 + 添加安全密钥
    - 降低钓鱼风险

  Phase 2: WebAuthn 登录选项
    - 添加"使用安全密钥登录"
    - 密码仍然是 fallback

  Phase 3: Passkey 启用
    - 注册时自动创建 Passkey
    - 跨设备同步 (iCloud/Google/第三方)
    - 有条件无密码登录

  Phase 4: 完全无密码
    - 默认使用 Passkey
    - 密码仅作为恢复手段
    - 账户恢复流程 (Passkey 丢失)
```

| 方案 | 钓鱼免疫 | UX | 跨平台 | 推荐 |
|------|---------|-----|--------|------|
| 密码 + SMS OTP | ❌ | ⭐⭐ | ✅ | 淘汰 |
| 密码 + TOTP | ❌ | ⭐⭐⭐ | ✅ | 过渡 |
| 密码 + FIDO U2F | ✅ | ⭐⭐⭐⭐ | ✅ | 推荐 |
| WebAuthn 无密码 | ✅✅ | ⭐⭐⭐⭐⭐ | ✅ (Passkey) | 终极 |

---

*上一篇：[无密码身份验证概述](01-passwordless-overview.md)*

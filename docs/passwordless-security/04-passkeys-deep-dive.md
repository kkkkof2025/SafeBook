# Passkeys 与 FIDO2 深度解析

## 概述

Passkeys (通行密钥) 是 FIDO2/WebAuthn 标准的消费级实现，正在取代密码成为主流认证方式。Apple、Google、Microsoft 2022 年联合宣布支持 Passkeys，2024 年正式大规模推广。

---

## 1. FIDO2 认证架构

### 1.1 公钥认证原理

```
注册流程:
  用户设备                      服务器
    │                             │
    │  1. 请求注册 (username)      │
    │ ←────────────────────────── │
    │  2. challenge + rpInfo      │
    │     (base64url随机值)        │
    │                             │
    │  3. 用户生物识别验证         │
    │  4. 生成密钥对 (P-256)       │
    │  5. 签名(challenge)         │
    │ ──────────────────────────→ │
    │     credential_id + pubkey  │
    │     + signed_challenge      │
    │ ←────────────────────────── │
    │  6. 验证签名, 存储公钥       │

认证流程:
  用户设备                      服务器
    │                             │
    │  1. 请求认证 (credential_id) │
    │ ←────────────────────────── │
    │  2. challenge (新随机值)      │
    │                             │
    │  3. 用户生物识别验证         │
    │  4. 使用私钥签名(challenge)   │
    │ ──────────────────────────→ │
    │     credential_id +         │
    │     signed_challenge        │
    │                             │
    │  5. 使用存储的公钥验证签名   │
    │ ←── 认证成功 ─────────────  │
```

### 1.2 为什么比密码更安全

| 属性 | 密码 | Passkeys |
|------|------|----------|
| 钓鱼抗性 | ❌ 用户可在钓鱼站输入 | ✅ 绑定到域名 (origin) |
| 凭证泄露 | ❌ 服务器数据库泄露 = 全暴露 | ✅ 服务器只存公钥 |
| 密钥强度 | 取决于用户选择 | ✅ P-256 (256-bit ECC) |
| 多设备同步 | ❌ 不安全 (明文/弱加密) | ✅ 端到端加密同步 |
| 用户记忆 | ❌ 难记 → 重用密码 | ✅ 生物识别, 无需记忆 |
| 暴力破解 | ❌ 可离线爆破 | ✅ 不做共享密钥 |

---

## 2. WebAuthn 实现

### 2.1 服务端实现 (Node.js)

```javascript
const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');

class WebAuthnServer {
    constructor() {
        this.challenges = new Map();  // 挑战值存储
        this.credentials = new Map(); // 用户凭证存储
    }

    /**
     * 注册 - 生成挑战
     */
    async generateRegistrationChallenge(userId, username) {
        const challenge = crypto.randomBytes(32);

        // 存储挑战 (关联用户 ID)
        this.challenges.set(userId, {
            challenge: challenge.toString('base64url'),
            timestamp: Date.now(),
            ttl: 300  // 5分钟有效期
        });

        return {
            challenge: base64url(challenge),
            rp: {
                name: "Secure App",
                id: "example.com"  // 域名绑定
            },
            user: {
                id: base64url(Buffer.from(userId)),
                name: username,
                displayName: username
            },
            pubKeyCredParams: [
                { type: "public-key", alg: -7 },   // ES256 (P-256)
                { type: "public-key", alg: -257 }, // RS256
                { type: "public-key", alg: -8 }    // EdDSA (Ed25519)
            ],
            authenticatorSelection: {
                authenticatorAttachment: "platform",  // 内建认证器 (TouchID/FaceID/Windows Hello)
                userVerification: "required",         // 必须用户验证
                residentKey: "required"               // 可发现凭证 (Passkey)
            },
            attestation: "none",  // 不需要认证器证明
            timeout: 60000
        };
    }

    /**
     * 注册 - 验证响应
     */
    async verifyRegistration(userId, credential) {
        const session = this.challenges.get(userId);
        if (!session) throw new Error("Challenge not found");

        // 验证时效
        if (Date.now() - session.timestamp > session.ttl * 1000) {
            throw new Error("Challenge expired");
        }

        // 1. 解码 clientDataJSON
        const clientData = JSON.parse(
            Buffer.from(credential.response.clientDataJSON, 'base64url').toString()
        );

        // 2. 验证 origin (防钓鱼核心)
        const allowedOrigins = ['https://example.com'];
        if (!allowedOrigins.includes(clientData.origin)) {
            throw new Error(`Invalid origin: ${clientData.origin}`);
        }

        // 3. 验证 challenge
        if (clientData.challenge !== session.challenge) {
            throw new Error("Challenge mismatch");
        }

        // 4. 解码 attestationObject (CBOR)
        const attObj = cbor.decode(
            Buffer.from(credential.response.attestationObject, 'base64url')
        );

        // 5. 提取公钥
        const authData = attObj.authData;
        const publicKey = this._extractPublicKey(authData);

        // 6. 存储凭证
        this.credentials.set(credential.id, {
            userId: userId,
            publicKey: publicKey,
            signCount: 0,
            createdAt: new Date()
        });

        // 清理 challenge
        this.challenges.delete(userId);

        return { verified: true, credentialId: credential.id };
    }

    /**
     * 认证 - 生成挑战
     */
    async generateAuthenticationChallenge(credentialId) {
        const challenge = crypto.randomBytes(32);

        // 获取已注册凭证的公钥
        const credential = this.credentials.get(credentialId);
        if (!credential) throw new Error("Credential not found");

        return {
            challenge: base64url(challenge),
            rpId: "example.com",
            allowCredentials: [{
                id: credentialId,
                type: "public-key",
                transports: ["internal"]  // Passkey 内建
            }],
            userVerification: "required",
            timeout: 60000
        };
    }

    /**
     * 认证 - 验证签名
     */
    async verifyAuthentication(credentialId, assertion) {
        const credential = this.credentials.get(credentialId);
        if (!credential) throw new Error("Credential not found");

        // 1. 解码 clientDataJSON
        const clientData = JSON.parse(
            Buffer.from(assertion.response.clientDataJSON, 'base64url').toString()
        );

        // 2. 构建签名数据
        const authenticatorData = Buffer.from(
            assertion.response.authenticatorData, 'base64url'
        );
        const clientDataHash = crypto.createHash('sha256')
            .update(Buffer.from(assertion.response.clientDataJSON, 'base64url'))
            .digest();

        const signatureData = Buffer.concat([
            authenticatorData,
            clientDataHash
        ]);

        // 3. 验证签名
        const signature = Buffer.from(assertion.response.signature, 'base64url');
        const verify = crypto.createVerify('SHA256');
        verify.update(signatureData);

        const isValid = verify.verify(
            { key: credential.publicKey, format: 'pem', type: 'spki' },
            signature
        );

        // 4. 验证签名计数器 (防克隆)
        const newSignCount = authenticatorData.readUInt32BE(33);
        if (newSignCount <= credential.signCount && newSignCount !== 0) {
            throw new Error("Possible credential cloning detected");
        }
        credential.signCount = newSignCount;

        return { verified: isValid };
    }

    _extractPublicKey(authData) {
        // 解析 CBOR 编码的公钥
        // authData offsets: 37(rpIdHash) + 1(flags) + 4(signCount) = 42
        const attestedCredentialData = authData.slice(42);
        const publicKeyCose = cbor.decode(attestedCredentialData.slice(55));

        // COSE Key → JWK → PEM
        const jwk = this._coseToJwk(publicKeyCose);
        return this._jwkToPem(jwk);
    }
}
```

### 2.2 前端实现

```javascript
class PasskeyAuth {
    /**
     * 检测 Passkey 支持
     */
    static isSupported() {
        return !!window.PublicKeyCredential &&
               !!window.PublicKeyCredential.isConditionalMediationAvailable;
    }

    /**
     * 自动填充认证 (Conditional UI)
     */
    static async autofillLogin() {
        try {
            const assertion = await navigator.credentials.get({
                mediation: 'conditional',
                publicKey: {
                    challenge: new Uint8Array(32),  // 将在服务端生成
                    rpId: window.location.hostname,
                    userVerification: 'required'
                }
            });

            // 发送到服务端验证
            const result = await this.verifyWithServer(assertion);
            if (result.verified) {
                window.location.href = '/dashboard';
            }
        } catch (err) {
            console.log('No available passkey', err);
        }
    }

    /**
     * 注册 Passkey
     */
    static async register(username) {
        // 1. 从服务器获取注册挑战
        const options = await fetch('/api/webauthn/register/begin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        }).then(r => r.json());

        // 2. 解码 Base64URL 字段为 ArrayBuffer
        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);

        // 3. 调用 WebAuthn API
        const credential = await navigator.credentials.create({
            publicKey: options
        });

        // 4. 发送凭证到服务器
        const result = await fetch('/api/webauthn/register/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                id: credential.id,
                type: credential.type,
                response: {
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64url(credential.response.attestationObject)
                }
            })
        }).then(r => r.json());

        return result;
    }
}
```

---

## 3. Passkey 平台生态

### 3.1 跨设备同步

```
Apple (iCloud Keychain):
  iPhone ──→ iCloud ──→ MacBook
  (端到端加密同步, Apple 不可见密钥)

Google (Google Password Manager):
  Android ──→ GPM Sync ──→ Chrome Desktop
  (端到端加密, Recovery via Google Account)

Microsoft (Windows Hello):
  Windows Device ──→ Microsoft Account ──→ Other Devices
  (TPM 2.0 保护, Windows 10 22H2+)

跨平台方案:
  - QR Code + Bluetooth: 手机扫描 PC 上的二维码认证
  - FIDO Cross-Device Authentication (Hybrid Transport)
```

### 3.2 Passkey 迁移策略

```yaml
Passkey 渐进迁移:
  阶段 1 (2-4周): 共存模式
    - 注册: 同时支持密码 + Passkey
    - 登录: 密码为主, Passkey 提示
    - 指标: Passkey 注册率

  阶段 2 (4-8周): Passkey 优先
    - 登录: Conditional UI 自动提示
    - 敏感操作: 强制 Passkey 验证
    - 密码降级为恢复方案
    - 指标: Passkey 使用率 > 50%

  阶段 3 (8周+): 无密码
    - 新用户: 仅 Passkey 注册
    - 密码: 引导现有用户移除密码
    - 恢复: 恢复密钥/多设备 Passkey
    - 指标: Passkey 使用率 > 90%
```

---

## 4. 安全考量

### 4.1 威胁模型

```yaml
Passkey 威胁模型:
  防御的威胁:
    - ✅ 凭证填充 (Credential Stuffing)
    - ✅ 钓鱼攻击 (Phishing)
    - ✅ 中间人攻击 (MITM, 对 origin 绑定)
    - ✅ 服务器数据泄露 (只存公钥)
    - ✅ 暴力破解

  未防御的威胁:
    - ⚠️ 设备物理被盗 + 解锁 (生物识别绕过)
    - ⚠️ 会话劫持 (需要附加防护)
    - ⚠️ 供应方 (手机厂商) 的后门风险
    - ⚠️ 同步链攻击 (Apple/Google 帐户被攻破)
    - ⚠️ 恶意浏览器扩展 (可介入 WebAuthn API)
```

### 4.2 安全加固建议

```javascript
// 增强的 WebAuthn 安全配置
const STRICT_WEBAUTHN_CONFIG = {
    // 1. 必须 user verification (生物识别/PIN)
    userVerification: 'required',  // 不是 'preferred'

    // 2. 拒绝不安全的认证器
    authenticatorSelection: {
        authenticatorAttachment: 'platform',  // 拒绝 USB 密钥 (减少社工)
        residentKey: 'required',              // 可发现凭证
        userVerification: 'required'
    },

    // 3. 限制算法
    pubKeyCredParams: [
        { type: 'public-key', alg: -7 }  // 只接受 ES256, 拒绝 RS256
    ],

    // 4. 检查认证器证明 (可选, 需要企业策略)
    attestation: 'direct',  // 或 'none'

    // 5. 短挑战有效期
    timeout: 120000       // 2分钟
};

// 服务端: 注册限流
const rateLimiter = new Map();
function checkRegistrationRate(userId) {
    const key = `register:${userId}`;
    const attempts = rateLimiter.get(key) || [];
    const now = Date.now();

    // 清理过期记录
    const recent = attempts.filter(t => now - t < 3600000); // 1小时

    if (recent.length > 10) {
        throw new Error('Registration rate limit exceeded');
    }

    recent.push(now);
    rateLimiter.set(key, recent);
}
```

---

## 5. 企业部署清单

```yaml
Passkey 企业部署:
  基础设施:
    - [ ] WebAuthn 服务端实现 (RP Server)
    - [ ] 域名验证 (所有子域名覆盖)
    - [ ] 恢复机制 (admin reset / backup passkey)

  客户端:
    - [ ] 浏览器兼容性测试 (Chrome/MacOS/iOS/Windows/Android)
    - [ ] Conditional UI 集成
    - [ ] 错误处理和降级 UI

  策略:
    - [ ] 强制 MFA (Passkey + 短信/邮箱作为后备)
    - [ ] 会话管理 (强制重新认证关键操作)
    - [ ] 审计日志 (Passkey 操作全记录)

  恢复:
    - [ ] 多设备 Passkey 注册 (防止单点故障)
    - [ ] 恢复代码生成 (一次性, 安全存储)
    - [ ] 管理员重置流程 (身份验证 + 审批)
```

---

## 参考资源

- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [FIDO Alliance Passkeys](https://fidoalliance.org/passkeys/)
- [Apple Passkeys 开发者指南](https://developer.apple.com/passkeys/)
- [Google Passwordless 部署指南](https://developers.google.com/identity/fido)

---

*上一篇：[无密码认证迁移策略](./03-passwordless-migration.md)*

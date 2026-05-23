# WebAuthn 实战实现

## 概述

WebAuthn（Web Authentication API）是 FIDO2 标准的核心，让用户通过生物特征或硬件密钥登录——无需记忆密码，也无需担心钓鱼。本章从前端到后端完整实现 WebAuthn 注册与认证。

---

## 1. WebAuthn 协议流程

```
WebAuthn 注册流程:

  用户 → 浏览器 → RP Server → 用户设备

  1. RP Server 生成 challenge (随机 32 字节)
  2. 浏览器调用 navigator.credentials.create()
  3. 用户设备验证用户（指纹/PIN/硬件 Key）
  4. 设备生成公私钥对
  5. 返回公钥+签名 challenge → RP Server
  6. RP Server 验证签名，存储公钥
```

---

## 2. 服务端实现 (Python)

### 2.1 注册 (Registration)

```python
import json
import base64
from dataclasses import dataclass
from typing import Dict, Optional
import secrets
from hashlib import sha256
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

@dataclass
class WebAuthnServer:
    """WebAuthn 服务端实现"""

    rp_id: str = "example.com"  # Relying Party ID
    rp_name: str = "Example Corp"
    origin: str = "https://example.com"

    def generate_registration_options(self, user_id: str,
                                        username: str) -> Dict:
        """生成注册选项"""
        challenge = secrets.token_bytes(32)

        options = {
            "rp": {
                "name": self.rp_name,
                "id": self.rp_id
            },
            "user": {
                "id": base64.urlsafe_b64encode(
                    user_id.encode()
                ).decode().rstrip('='),
                "name": username,
                "displayName": username
            },
            "challenge": base64.urlsafe_b64encode(
                challenge
            ).decode().rstrip('='),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},   # ES256
                {"type": "public-key", "alg": -257},  # RS256
            ],
            "timeout": 60000,
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",  # 或 "cross-platform"
                "residentKey": "preferred",
                "userVerification": "preferred"
            },
            "attestation": "none"
        }

        # 临时存储 challenge（关联到用户 session）
        self._store_challenge(user_id, challenge)

        return options

    def verify_registration(self, user_id: str,
                             credential: Dict) -> bool:
        """验证注册响应"""

        # 1. 验证 challenge
        challenge = self._get_challenge(user_id)

        client_data_json = base64.urlsafe_b64decode(
            credential["response"]["clientDataJSON"] + "==="
        )
        client_data = json.loads(client_data_json)

        # 验证 challenge 匹配
        client_challenge = base64.urlsafe_b64decode(
            client_data["challenge"] + "==="
        )
        if client_challenge != challenge:
            raise ValueError("Challenge mismatch")

        # 2. 验证 origin
        if client_data["origin"] != self.origin:
            raise ValueError(f"Origin mismatch: {client_data['origin']}")

        # 3. 解析 attestationObject
        attestation = self._parse_attestation(
            credential["response"]["attestationObject"]
        )

        # 4. 提取公钥
        public_key = attestation["authData"]["credentialPublicKey"]

        if isinstance(public_key, bytes):
            # COSE 密钥格式: 需要解析
            public_key = self._parse_cose_key(public_key)

        # 5. 存储凭证
        credential_id = credential["rawId"]
        self._store_credential(user_id, {
            "credential_id": credential_id,
            "public_key": public_key,
            "sign_count": attestation["authData"]["signCount"]
        })

        return True

    def _parse_cose_key(self, cose_key: bytes):
        """解析 COSE 格式公钥"""
        # 简化：假设 ES256 (COSE key type: EC2)
        # COSE Key 结构 (RFC 8152):
        #   1: key type (2 = EC2)
        #   3: algorithm (-7 = ES256)
        #  -1: curve (1 = P-256)
        #  -2: x coordinate
        #  -3: y coordinate

        import cbor2
        key_map = cbor2.loads(cose_key)

        if key_map[3] != -7:  # ES256
            raise ValueError("Unsupported algorithm")

        x = key_map[-2]
        y = key_map[-3]

        # 构建 EC 公钥（未压缩格式: 04 || x || y）
        public_numbers = ec.EllipticCurvePublicNumbers.from_encoded_point(
            ec.SECP256R1(),
            b'\x04' + x + y
        )
        return public_numbers
```

### 2.2 认证 (Authentication)

```python
    def generate_authentication_options(self, user_id: str) -> Dict:
        """生成认证选项"""
        challenge = secrets.token_bytes(32)

        # 获取已注册的凭证
        credentials = self._get_credentials(user_id)
        allow_credentials = [{
            "type": "public-key",
            "id": cred["credential_id"]
        } for cred in credentials]

        options = {
            "challenge": base64.urlsafe_b64encode(
                challenge
            ).decode().rstrip('='),
            "timeout": 60000,
            "rpId": self.rp_id,
            "allowCredentials": allow_credentials,
            "userVerification": "preferred"
        }

        self._store_challenge(user_id, challenge)
        return options

    def verify_authentication(self, user_id: str,
                                assertion: Dict) -> bool:
        """验证认证响应"""

        # 1. 验证 challenge
        challenge = self._get_challenge(user_id)
        client_data_json = base64.urlsafe_b64decode(
            assertion["response"]["clientDataJSON"] + "==="
        )
        client_data = json.loads(client_data_json)

        client_challenge = base64.urlsafe_b64decode(
            client_data["challenge"] + "==="
        )
        if client_challenge != challenge:
            raise ValueError("Challenge mismatch")

        # 2. 查找已注册凭证
        credential_id = assertion["rawId"]
        stored = self._get_credential_by_id(credential_id)
        if not stored:
            raise ValueError("Unknown credential")

        # 3. 验证签名
        authenticator_data = base64.urlsafe_b64decode(
            assertion["response"]["authenticatorData"] + "==="
        )
        signature = base64.urlsafe_b64decode(
            assertion["response"]["signature"] + "==="
        )

        # 构建签名数据
        client_data_hash = sha256(client_data_json).digest()
        signed_data = authenticator_data + client_data_hash

        # 验证 ECDSA 签名
        public_key = stored["public_key"].public_key(
            ec.SECP256R1(), default_backend()
        )

        try:
            public_key.verify(
                signature,
                signed_data,
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            raise ValueError("Invalid signature")

        # 4. 验证签名计数器（防克隆）
        auth_data = self._parse_auth_data(authenticator_data)
        if auth_data["signCount"] <= stored["sign_count"]:
            raise ValueError("Possible credential cloning detected")

        # 更新计数器
        stored["sign_count"] = auth_data["signCount"]
        self._update_credential(credential_id, stored)

        return True
```

---

## 3. 前端实现

```javascript
// 注册 WebAuthn 凭证
async function registerWebAuthn() {
    // 1. 从服务端获取注册选项
    const response = await fetch('/webauthn/register/begin', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ username: 'alice' })
    });
    const options = await response.json();

    // 2. 转换 Base64 参数
    options.challenge = Uint8Array.from(
        atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
    );
    options.user.id = Uint8Array.from(
        atob(options.user.id.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
    );

    // 3. 调用 WebAuthn API 创建凭证
    const credential = await navigator.credentials.create({
        publicKey: options
    });

    // 4. 序列化凭证信息
    const attestation = {
        id: credential.id,
        rawId: btoa(String.fromCharCode(
            ...new Uint8Array(credential.rawId)
        )),
        type: credential.type,
        response: {
            clientDataJSON: btoa(String.fromCharCode(
                ...new Uint8Array(credential.response.clientDataJSON)
            )),
            attestationObject: btoa(String.fromCharCode(
                ...new Uint8Array(credential.response.attestationObject)
            ))
        }
    };

    // 5. 发送到服务端验证
    await fetch('/webauthn/register/complete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ credential: attestation })
    });
}

// 认证
async function authenticateWebAuthn() {
    const response = await fetch('/webauthn/auth/begin', { method: 'POST' });
    const options = await response.json();

    options.challenge = Uint8Array.from(
        atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
    );
    if (options.allowCredentials) {
        options.allowCredentials.forEach(cred => {
            cred.id = Uint8Array.from(
                atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')),
                c => c.charCodeAt(0)
            );
        });
    }

    const assertion = await navigator.credentials.get({
        publicKey: options
    });

    await fetch('/webauthn/auth/complete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            assertion: {
                id: assertion.id,
                rawId: btoa(String.fromCharCode(
                    ...new Uint8Array(assertion.rawId)
                )),
                type: assertion.type,
                response: {
                    authenticatorData: btoa(String.fromCharCode(
                        ...new Uint8Array(assertion.response.authenticatorData)
                    )),
                    clientDataJSON: btoa(String.fromCharCode(
                        ...new Uint8Array(assertion.response.clientDataJSON)
                    )),
                    signature: btoa(String.fromCharCode(
                        ...new Uint8Array(assertion.response.signature)
                    )),
                    userHandle: assertion.response.userHandle ?
                        btoa(String.fromCharCode(
                            ...new Uint8Array(assertion.response.userHandle)
                        )) : null
                }
            }
        })
    });
}
```

---

## 参考资源

- [WebAuthn Spec (W3C)](https://www.w3.org/TR/webauthn-2/)
- [WebAuthn.io Demo](https://webauthn.io/)
- [SimpleWebAuthn (Node.js)](https://simplewebauthn.dev/)
- [python-fido2 (Python)](https://github.com/Yubico/python-fido2)

---

*上一篇：[FIDO2/Passkeys 实战](01-passwordless-security.md)*

*下一篇：[无密码认证迁移指南](03-passwordless-migration.md)*

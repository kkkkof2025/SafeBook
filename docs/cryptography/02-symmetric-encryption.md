# 对称加密与非对称加密

## 加密系统分类

```
                    加密算法
                       │
        ┌──────────────┼──────────────┐
        │              │              │
   对称加密        非对称加密       哈希函数
   (一个密钥)      (公钥+私钥)      (不可逆)
   AES, ChaCha    RSA, ECC       SHA-256
        │              │
   数据加密        密钥交换/签名
```

---

## 1. 对称加密

### AES 模式深度对比

| 模式 | 安全性 | 并行 | 需要 IV | 推荐场景 |
|------|--------|------|---------|---------|
| ECB | ❌ 同明文=同密文 | ✅ | ❌ | **绝不使用** |
| CBC | ⚠️ Padding Oracle | ❌ | ✅ | 旧系统兼容 |
| CTR | ✅ | ✅ | ✅ | 高性能场景 |
| GCM | ✅✅ (AEAD) | ✅ | ✅ | **强烈推荐** |
| CCM | ✅✅ (AEAD) | ❌ | ✅ | IoT 设备 |

### AES-GCM 最佳实践
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AESGCMEncryption:
    def __init__(self):
        self.key = AESGCM.generate_key(bit_length=256)  # 256-bit

    def encrypt(self, plaintext, associated_data=b""):
        nonce = os.urandom(12)  # GCM 推荐 96-bit nonce
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext  # nonce || ciphertext || tag

    def decrypt(self, encrypted_data, associated_data=b""):
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
```

### Padding Oracle 攻击（经典案例）
```python
# 攻击原理: 利用服务端不同错误响应推断明文
# 场景: AES-CBC + PKCS#7 填充

# 正常请求 → "Invalid token" 
# 填充错误 → "Padding error" (信息泄露!)
# 攻击者可以逐字节解密任意密文

# 防御: 永远不要泄露填充错误信息
# ✅ 使用 GCM (AEAD, 不依赖填充)
# ✅ 恒定时间错误响应: "Authentication failed"
# ✅ 或使用 encrypt-then-MAC
```

---

## 2. 非对称加密

### RSA vs ECC

| 特性 | RSA-3072 | ECC P-256 (secp256r1) | Ed25519 |
|------|----------|----------------------|---------|
| 安全等级 | 128-bit | 128-bit | 128-bit |
| 公钥大小 | 384B | 64B | 32B |
| 签名速度 | 慢 | 中 | ⚡ 极快 |
| 抗侧信道 | 需特别实现 | 中 | ✅ 天然抗 |
| 推荐度 | 兼容性 | ✅ | ✅✅ 强烈推荐 |

### Ed25519 签名
```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)

# 密钥生成
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# 签名
signature = private_key.sign(b"important message")

# 验证
public_key.verify(signature, b"important message")  # 成功
# public_key.verify(signature, b"modified message")  # InvalidSignature
```

### ECDH 密钥交换
```python
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey
)

# Alice 生成密钥对
alice_private = X25519PrivateKey.generate()
alice_public = alice_private.public_key()

# Bob 生成密钥对
bob_private = X25519PrivateKey.generate()
bob_public = bob_private.public_key()

# 双方计算共享密钥 (结果相同!)
alice_shared = alice_private.exchange(bob_public)
bob_shared = bob_private.exchange(alice_public)
assert alice_shared == bob_shared  # ✅

# 共享密钥 → HKDF 派生 AES 密钥
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"application-specific-context"
).derive(alice_shared)
```

---

## 3. 混合加密 (Hybrid Encryption)

```
发送方                                    接收方
   │                                        │
   ├─ 生成 AES-256 会话密钥 K                │
   ├─ Encrypt(data, K) → C                  │
   ├─ Encrypt(K, recipient_pubkey) → EK     │
   │                                        │
   ├─── 发送 (C, EK) ──────────────────────→│
   │                                        ├─ Decrypt(EK, own_privkey) → K
   │                                        ├─ Decrypt(C, K) → data
```

```python
# Tink (Google) — 推荐的生产级实现
import tink
from tink import aead, hybrid

tink.hybrid.init()

# 接收方生成密钥对
private_keyset_handle = tink.new_keyset_handle(
    hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES256_GCM
)
public_keyset_handle = private_keyset_handle.public_keyset_handle()

# 发送方: 用公钥加密
hybrid_encrypt = public_keyset_handle.primitive(hybrid.HybridEncrypt)
ciphertext = hybrid_encrypt.encrypt(b"secret message", b"context_info")

# 接收方: 用私钥解密
hybrid_decrypt = private_keyset_handle.primitive(hybrid.HybridDecrypt)
plaintext = hybrid_decrypt.decrypt(ciphertext, b"context_info")
```

---

## 4. 密钥管理

| 方案 | 适用场景 | 安全等级 | 密钥轮换 |
|------|---------|---------|---------|
| 环境变量 | 开发/测试 | 低 | 手动 |
| HashiCorp Vault | 生产服务 | 高 | 自动 |
| AWS KMS | AWS 生态 | 极高 | 自动 (CMK) |
| Azure Key Vault | Azure 生态 | 极高 | 自动 |
| GCP Cloud KMS | GCP 生态 | 极高 | 自动 |
| TPM 2.0 | 硬件终端 | 最高 | 硬件绑定 |
| HSM | 金融/CA | 最高 | 硬件模块 |

### 密钥轮换策略
```python
class KeyRotationManager:
    """双密钥平滑轮换"""

    def __init__(self):
        self.current_key = self.generate_key()
        self.previous_key = None
        self.rotation_date = datetime.utcnow()

    def encrypt(self, data):
        """总是用当前密钥加密"""
        return aes_gcm_encrypt(data, self.current_key)

    def decrypt(self, data):
        """先用当前密钥，失败再试旧密钥"""
        try:
            return aes_gcm_decrypt(data, self.current_key)
        except DecryptionError:
            if self.previous_key:
                return aes_gcm_decrypt(data, self.previous_key)
            raise

    def rotate(self):
        """轮换密钥"""
        self.previous_key = self.current_key
        self.current_key = self.generate_key()
        self.rotation_date = datetime.utcnow()

    def retire_old_key(self, grace_period_days=7):
        """宽限期后删除旧密钥"""
        if (datetime.utcnow() - self.rotation_date).days > grace_period_days:
            self.previous_key = None
```

---

*上一篇：[哈希算法与密码安全](01-hash.md)*

*下一篇：[TLS/HTTPS 与 PKI](03-tls-pki.md)*

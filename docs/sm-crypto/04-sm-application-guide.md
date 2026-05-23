# 国密算法应用指南

> SM2/SM3/SM4 企业落地实践

---

## 1. 国密算法体系

```yaml
国密算法全景:

  SM1 (商密1号): 对称加密
    - 算法未公开, 硬件芯片实现
    - 已被 SM4 取代

  SM2: 椭圆曲线公钥密码
    - ECC P-256 等价安全强度
    - 用途: 数字签名 + 密钥交换 + 公钥加密

  SM3: 密码杂凑算法
    - 256-bit 输出
    - SHA-256 等价安全强度
    - 用途: 数字签名 + MAC + 随机数

  SM4: 分组密码算法
    - 128-bit 分组, 128-bit 密钥
    - AES-128 等价安全强度
    - 用途: 数据加密 + 传输加密

  SM9: 基于身份的密码
    - 无需证书的标识密码
    - 用途: 签名 + 密钥封装
```

---

## 2. SM2 椭圆曲线实现

### Python (gmssl)
```python
from gmssl import sm2, func

# SM2 密钥生成
private_key = func.random_hex(32)
sm2_crypt = sm2.CryptSM2(
    private_key=private_key,
    public_key=sm2.default_public_key
)

# SM2 加密 (C1C3C2 模式)
ciphertext = sm2_crypt.encrypt(b"Sensitive data")

# SM2 解密
plaintext = sm2_crypt.decrypt(ciphertext)

# SM2 签名
data = b"contract signature"
signature = sm2_crypt.sign(data, func.random_hex(32))

# SM2 验签
is_valid = sm2_crypt.verify(signature, data)
```

### SM2 + SM3 混合签名
```python
from gmssl import sm2, sm3

# 对哈希签名 (不是对原文直接签名)
message = b"important document"
digest = sm3.sm3_hash(func.bytes_to_list(message))

# 使用 SM3 摘要进行 SM2 签名
sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key=public_key)
signature = sm2_crypt.sign(digest.encode(), func.random_hex(32))
```

---

## 3. SM4 对称加密

```python
from gmssl import sm4, func

class SM4Helper:
    """SM4-CBC 加密/解密"""

    def __init__(self, key=None):
        self.key = key or func.random_hex(16)  # 128-bit

    def encrypt(self, plaintext):
        """SM4-CBC 加密"""
        iv = func.random_hex(16)
        padded = self._pad(plaintext)
        sm4_crypt = sm4.CryptSM4()
        sm4_crypt.set_key(self.key.encode(), sm4.SM4_ENCRYPT)
        ciphertext = sm4_crypt.crypt_cbc(
            iv.encode(),
            padded.encode('utf-8')
        )
        return iv.encode() + ciphertext

    def decrypt(self, encrypted_data):
        """SM4-CBC 解密"""
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        sm4_crypt = sm4.CryptSM4()
        sm4_crypt.set_key(self.key.encode(), sm4.SM4_DECRYPT)
        plaintext = sm4_crypt.crypt_cbc(iv, ciphertext)
        return self._unpad(plaintext.decode('utf-8'))

    def _pad(self, data):
        """PKCS#7 填充"""
        pad_len = 16 - (len(data) % 16)
        return data + chr(pad_len) * pad_len
```

---

## 4. SM3 哈希

```python
from gmssl import sm3

# SM3 哈希
data = b"Hello, SM3!"
hash_value = sm3.sm3_hash(func.bytes_to_list(data))
# 输出: 256-bit (64 hex 字符)

# SM3-HMAC
import hmac
import hashlib

def sm3_hmac(key, message):
    """使用 gmssl 实现 SM3-HMAC"""
    block_size = 64  # SM3 内部块大小
    if len(key) > block_size:
        key = sm3.sm3_hash(func.bytes_to_list(key))
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    o_key_pad = bytes(x ^ 0x5c for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)

    inner = sm3.sm3_hash(func.bytes_to_list(i_key_pad + message))
    return sm3.sm3_hash(func.bytes_to_list(o_key_pad + inner.encode()))
```

---

## 5. 国密 TLS (TLCP)

```yaml
国密 TLS 协议 (GB/T 38636-2020):

  与标准的差异:
    - 使用 ECC-SM2 替代 ECDHE
    - 使用 SM4-GCM 替代 AES-GCM
    - 使用 SM3 替代 SHA-256
    - 使用 SM2 签名替代 RSA/ECDSA

  密码套件:
    ECC-SM2-SM4-GCM-SM3  (密钥交换、加密、哈希)
    ECC-SM2-SM4-CBC-SM3

  实现 (GmSSL):
    # 服务端
    gmssl s_server -cert SM2_cert.pem -key SM2_key.pem

    # 客户端
    gmssl s_client -connect server:443
```

---

## 6. 双证书体系

```python
class SM2CertificateManager:
    """国密 SM2 证书管理"""

    def generate_sm2_keypair(self):
        """生成 SM2 密钥对"""
        from gmssl import sm2, func
        private = func.random_hex(32)
        public = sm2.default_public_key  # 基于私钥推导
        return private, public

    def create_csr(self, common_name, private_key):
        """创建 SM2 证书签名请求"""
        # GmSSL 命令等价:
        # gmssl req -new -sm3 -key SM2_key.pem -subj "/CN=example.com"
        pass

    def verify_certificate_chain(self, cert_chain):
        """验证 SM2 证书链"""
        for i in range(len(cert_chain) - 1):
            cert = cert_chain[i]
            issuer = cert_chain[i+1]
            # 验证发行者的 SM2 签名
            if not self.verify_sm2_signature(
                issuer.public_key,
                cert.signature,
                cert.tbs_certificate
            ):
                return False
        return True
```

---

## 7. 算法选择指南

| 场景 | 推荐国密 | 等效国际 | 原因 |
|------|---------|---------|------|
| HTTPS | SM2 + SM4-GCM | ECDSA + AES-GCM | 国密合规 |
| 存储加密 | SM4-CBC | AES-256-CBC | 数据安全法 |
| 数字签名 | SM2 | ECDSA P-256 | 电子签名法 |
| 哈希 | SM3 | SHA-256 | 完整性校验 |
| 密钥交换 | SM2 ECDH | ECDH P-256 | 密钥协商 |
| 身份认证 | SM9 | 无可直接对照 | 无需证书 |

---

*上一篇：[SM4 实现细节](03-sm4-implementation.md)*

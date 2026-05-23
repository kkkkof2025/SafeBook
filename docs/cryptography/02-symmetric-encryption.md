# 对称加密与非对称加密

## 对称加密

### AES（高级加密标准）

#### 加密模式对比

| 模式 | 安全性 | 性能 | 并行 | 推荐 |
|------|--------|------|------|------|
| ECB | ❌ 相同明文输出相同密文 | 快 | 是 | ❌ |
| CBC | 需要 IV | 慢 | 否 | 旧系统兼容 |
| CTR | 加解密相同 | 快 | 是 | 部分场景 |
| GCM | 认证加密(AEAD) | 快 | 是 | ✅ **强烈推荐** |

```python
from cryptography.fernet import Fernet

# AES-256-GCM 封装
key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"敏感数据")
plain = f.decrypt(token)
```

### ChaCha20-Poly1305
```bash
# OpenSSL 加密
openssl enc -chacha20 -in plain.txt -out encrypted.bin -K KEY -IV NONCE

# age 工具（ChaCha20-Poly1305 封装）
age -r RECIPIENT -o encrypted.age plain.txt
age -d -i key.txt -o decrypted.txt encrypted.age
```

## 非对称加密

### RSA
```bash
# 生成密钥对
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem

# 加密（仅适合小数据）
openssl pkeyutl -encrypt -pubin -inkey public.pem -in plain.txt -out encrypted.bin
openssl pkeyutl -decrypt -inkey private.pem -in encrypted.bin -out decrypted.txt

# 签名
openssl dgst -sha256 -sign private.pem -out signature.bin document.txt
openssl dgst -sha256 -verify public.pem -signature signature.bin document.txt
```

### ECC（椭圆曲线）
```bash
# 生成密钥对（Ed25519）
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem
openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem

# 签名
openssl pkeyutl -sign -inkey ed25519_private.pem -rawin -in message.txt -out sig.bin
openssl pkeyutl -verify -pubin -inkey ed25519_public.pem -rawin -in message.txt -sigfile sig.bin
```

## 混合加密

实际应用中通常结合对称和非对称加密：

```
1. 生成随机会话密钥（AES-256）
2. 用接收方公钥加密会话密钥（RSA/ECC）
3. 用会话密钥加密大块数据（AES-GCM）
4. 传递：加密的会话密钥 + 密文 + GCM Tag
```

## 密钥管理

| 方案 | 用途 | 安全等级 |
|------|------|---------|
| 环境变量 | 开发/测试 | 低 |
| Vault/HashiCorp | 生产 | 高 |
| KMS (AWS/Azure/GCP) | 云端 | 极高 |
| TPM/HSM | 硬件级 | 最高 |

*上一篇：[哈希算法与密码安全](01-hash.md)*

*下一篇：[TLS/HTTPS 与 PKI](03-tls-pki.md)*

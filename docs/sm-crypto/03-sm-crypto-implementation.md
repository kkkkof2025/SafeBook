# 国密算法实现指南

## 国密算法概述

国密算法是中国商用密码算法标准，包含 SM2/SM3/SM4/SM9 等算法。

### 算法体系

| 算法 | 类型 | 用途 | 对应国际标准 |
|------|------|------|------------|
| SM2 | 非对称加密 | 数字签名、密钥交换 | ECDSA P-256 |
| SM3 | 哈希算法 | 数据完整性 | SHA-256 |
| SM4 | 对称加密 | 数据加密 | AES-128 |
| SM9 | 标识密码 | 基于身份的密码 | - |

---

## SM2 椭圆曲线密码

### 算法参数

- **曲线：** `y² = x³ + ax + b` over `GF(p)`
- **参数：**
  - `p` = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
  - `a` = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
  - `b` = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
  - `n` = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
  - `Gx` = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
  - `Gy` = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0

### 密钥生成

```python
# 使用 gmssl 库
from gmssl import sm2

# 生成密钥对
private_key = sm2.CryptSM2(private_key='', public_key='', mode=0)
private_key.generate_keypair()

# 获取密钥
sk = private_key.private_key  # 十六进制字符串
pk = private_key.public_key   # 十六进制字符串 (04 + X + Y)

print(f'私钥: {sk}')
print(f'公钥: {pk}')
```

### 数字签名

```python
from gmssl import sm2
import binascii

# 加载密钥
private_key = sm2.CryptSM2(private_key='YOUR_PRIVATE_KEY', public_key='YOUR_PUBLIC_KEY')

# 签名
data = b'Hello, SM2!'
random_hex = func.random_hex(sm2.CryptSM2.KEY_LEN)  # 随机数
sign = private_key.sign(data, random_hex)

print(f'签名: {binascii.hexlify(sign).decode()}')

# 验签
public_key = sm2.CryptSM2(private_key='', public_key='YOUR_PUBLIC_KEY')
result = public_key.verify(sign, data)
print(f'验签结果: {result}')  # True/False
```

### 加密/解密

```python
from gmssl import sm2

# 加载密钥
private_key = sm2.CryptSM2(private_key='YOUR_PRIVATE_KEY', public_key='YOUR_PUBLIC_KEY')

# 加密 (使用公钥)
data = b'Secret message'
encrypt_data = private_key.encrypt(data)
print(f'密文: {binascii.hexlify(encrypt_data).decode()}')

# 解密 (使用私钥)
decrypt_data = private_key.decrypt(encrypt_data)
print(f'明文: {decrypt_data.decode()}')  # 'Secret message'
```

---

## SM3 哈希算法

### 算法特性

- **输出长度：** 256 位 (32 字节)
- **分组长度：** 512 位 (64 字节)
- **安全性：** 与 SHA-256 相当

### 实现示例

```python
from gmssl import sm3, func

# 计算哈希
data = b'Hello, SM3!'
hash_value = sm3.sm3_hash(func.bytes_to_list(data))

print(f'SM3 哈希: {hash_value}')
print(f'长度: {len(hash_value) * 4} 位')  # 256 位
```

### 与 SHA-256 对比

```python
import hashlib
from gmssl import sm3, func

data = b'Test data'

# SM3
sm3_hash = sm3.sm3_hash(func.bytes_to_list(data))

# SHA-256
sha256_hash = hashlib.sha256(data).hexdigest()

print(f'SM3:  {sm3_hash}')
print(f'SHA-256: {sha256_hash}')
print(f'相同输入，不同输出: {sm3_hash != sha256_hash}')
```

---

## SM4 分组密码

### 算法参数

- **密钥长度：** 128 位
- **分组长度：** 128 位
- **轮数：** 32 轮
- **模式：** ECB、CBC、CFB、OFB、CTR

### ECB 模式加密

```python
from gmssl import sm4
import os

# 生成密钥
key = os.urandom(16)  # 128 位 = 16 字节

# 初始化
crypt_sm4 = sm4.CryptSM4()

# 加密
data = b'Hello, SM4!    '  # 需要填充到 16 字节倍数
crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
encrypt_data = crypt_sm4.crypt_ecb(data)

print(f'密文: {encrypt_data.hex()}')

# 解密
crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
decrypt_data = crypt_sm4.crypt_ecb(encrypt_data)

print(f'明文: {decrypt_data.decode()}')  # 'Hello, SM4!    '
```

### CBC 模式加密

```python
from gmssl import sm4
import os

# 生成密钥和 IV
key = os.urandom(16)
iv = os.urandom(16)

# 加密
crypt_sm4 = sm4.CryptSM4()
crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)

data = b'Hello, SM4 CBC!'
# 填充 (PKCS7)
padding_len = 16 - (len(data) % 16)
data += bytes([padding_len] * padding_len)

encrypt_data = crypt_sm4.crypt_cbc(iv, data)

print(f'密文 (CBC): {encrypt_data.hex()}')

# 解密
crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
decrypt_data = crypt_sm4.crypt_cbc(iv, encrypt_data)

# 去除填充
padding_len = decrypt_data[-1]
decrypt_data = decrypt_data[:-padding_len]

print(f'明文: {decrypt_data.decode()}')
```

---

## SM9 标识密码

### 算法特性

- **基于身份：** 公钥 = 用户标识 (邮箱、手机号等)
- **无需证书：** 减少 PKI 复杂度
- **双线性对：** 使用 Weil/Tate 对

### 密钥生成

```python
from gmssl import sm9

# 初始化 (需要主公钥和主私钥)
master_public_key = '...'  # 主公钥 (KGC 生成)
master_private_key = '...'  # 主私钥 (KGC 保管)

# 用户标识
user_id = 'alice@example.com'

# 生成用户私钥 (KGC 执行)
user_private_key = sm9.generate_private_key(master_private_key, user_id)

print(f'用户标识: {user_id}')
print(f'用户私钥: {user_private_key}')
```

### 签名验证

```python
from gmssl import sm9

# 签名 (使用用户私钥)
user_private_key = '...'
data = b'Hello, SM9!'
signature = sm9.sign(user_private_key, data)

print(f'签名: {signature}')

# 验签 (使用用户标识和主公钥)
user_id = 'alice@example.com'
master_public_key = '...'
result = sm9.verify(master_public_key, user_id, data, signature)

print(f'验签结果: {result}')  # True/False
```

---

## 国密算法应用

### 1. TLS/SSL 国密套件

#### 国密 TLS 流程

```
客户端 --> ClientHello (支持 SM2/SM3/SM4) --> 服务器
客户端 <-- ServerHello (选择国密套件) <-- 服务器
客户端 <-- 证书 (SM2 签名) <-- 服务器
客户端 --> 密钥交换 (SM2 加密) --> 服务器
客户端 --> 完成 (SM4 加密) --> 服务器
```

#### 配置 Nginx 支持国密 TLS

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    # 国密证书
    ssl_certificate /path/to/sm2_cert.pem;
    ssl_certificate_key /path/to/sm2_key.pem;

    # 国密套件
    ssl_ciphers SM2-WITH-SMS4-SM3;
    ssl_prefer_server_ciphers on;

    # 同时支持国际算法 (降级兼容)
    ssl_certificate /path/to/rsa_cert.pem;
    ssl_certificate_key /path/to/rsa_key.pem;
}
```

### 2. IPSec VPN 国密加密

#### 配置 StrongSwan 使用 SM4

```conf
# /etc/ipsec.conf
conn sm4-vpn
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingress=10
    keyexchange=ikev2

    # 国密算法
    ike = sm4-sM3-modp2048
    esp = sm4-sM3

    left = 192.168.1.100
    leftid = @gateway1.example.com
    leftcert = sm2_cert.pem

    right = 192.168.2.100
    rightid = @gateway2.example.com
    rightcert = sm2_cert.pem
```

### 3. 数据库透明加密 (TDE)

#### MySQL 使用 SM4 加密

```sql
-- 创建表空间加密 (MySQL 8.0+)
CREATE TABLE sensitive_data (
    id INT PRIMARY KEY,
    name VARCHAR(100),
    credit_card VARBINARY(256)  -- 加密存储
) ENCRYPTION='Y';

-- 配置 SM4 作为加密算法
-- 需要 MySQL 国密版本或插件
```

---

## 合规性要求

### 等保 2.0 要求

**第三级及以上信息系统：**
- 必须使用国密算法
- SM2/SM3/SM4 替代 RSA/SHA-256/AES
- 获得国密局颁发的商用密码产品型号证书

### 金融行业

**JR/T 0025-2013 (金融 IC 卡):**
- 卡片认证使用 SM2
- 交易数据完整性使用 SM3
- 敏感数据加密使用 SM4

### 电子认证服务

**《电子认证服务密码管理办法》:**
- CA 证书必须使用 SM2 签名
- OCSP 响应必须使用 SM2 签名
- CRL 必须使用 SM2 签名

---

## 开源实现

### 1. GmSSL

**项目地址：** https://github.com/guanzhi/GmSSL

**特性：**
- 支持 SM2/SM3/SM4/SM9
- OpenSSL 兼容 API
- 命令行工具

**安装：**
```bash
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL
./config --prefix=/usr/local/gmssl
make -j4
sudo make install
```

**使用：**
```bash
# 生成 SM2 密钥对
gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2 -out sm2_key.pem

# SM3 哈希
gmssl dgst -sm3 file.txt

# SM4 加密
gmssl enc -sm4 -e -in plain.txt -out cipher.bin -pass pass:123456
```

### 2. Tongsuo (原 BabaSSL)

**项目地址：** https://github.com/Tongsuo-Project/Tongsuo

**特性：**
- 支持国密 TLS (TLCP)
- 支持 SM2/SM3/SM4/SM9
- 兼容 OpenSSL 3.0

**使用：**
```c
// 初始化国密算法
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(NID_sm2, NULL);
EVP_PKEY_sign_init(ctx);
EVP_PKEY_CTX_set_signature_md(ctx, EVP_sm3());

// 签名
EVP_PKEY_sign(ctx, sig, &siglen, data, datalen);
```

---

## 迁移策略

### 阶段1：并行支持

```
国际算法 (RSA/SHA-256/AES) }---> 同时支持
国密算法 (SM2/SM3/SM4)     }---> 逐渐切换
```

**实施：**
- 双证书配置 (RSA + SM2)
- 双算法支持 (TLS 协商选择)
- 灰度发布 (部分用户先切换)

### 阶段2：优先国密

**策略：**
- 检测到国密客户端 → 使用国密算法
- 否则 → 降级到国际算法

### 阶段3：强制国密

**策略：**
- 等保三级及以上系统 → 强制国密
- 金融行业 → 强制国密
- 政府采购 → 强制国密

---

## 安全最佳实践

### 1. 密钥管理

- **SM2 私钥：** HSM 保护，定期轮换
- **SM4 密钥：** 256 位真随机数，安全分发
- **SM9 主私钥：** KGC 严格保管，审计使用

### 2. 随机数生成

```python
# 使用硬件随机数生成器
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# 从 HSM 获取随机数
random_bytes = hsm.generate_random(32)  # 256 位
```

### 3. 侧信道防护

- **SM2 签名：** 使用盲化技术 (Blinding)
- **SM4 加密：** 使用恒定时间实现
- **SM3 哈希：** 避免时序差异

---

## 部署清单

### 前期准备

- [ ] 评估合规性要求 (等保、金融、政府采购)
- [ ] 选择国密算法实现 (GmSSL/Tongsuo)
- [ ] 申请国密证书 (SM2)
- [ ] 测试性能影响 (SM2 签名比 RSA 慢)

### 技术实施

- [ ] 部署 GmSSL/Tongsuo
- [ ] 配置双证书 (RSA + SM2)
- [ ] 配置国密 TLS 套件
- [ ] 实施密钥管理 (HSM)

### 合规审计

- [ ] 委托商用密码检测中心测试
- [ ] 申请商用密码产品型号证书
- [ ] 定期审计密钥使用记录
- [ ] 应急响应计划 (密钥泄露)

---

## 延伸阅读

- [国密局官网](http://www.sca.gov.cn/)
- [GmSSL 文档](https://gmssl.readthedocs.io/)
- [SM2/SM3/SM4/SM9 标准文本](https://www.oscca.gov.cn/)

---

**下一步：** 学习 )，掌握第五代移动通信安全技术。

*上一篇：[国密算法（SM2/SM3/SM4）](01-sm-crypto.md)*

*下一篇：[国密证书与 PKI 体系](04-gm-certificate-pki.md)*

# 密码学攻击向量

> 不要自造加密——你 99% 的概率会出错。

---

## 时序攻击（Timing Attack）

```python
# ❌ 不安全的字符串比较（时序可旁路）
def insecure_compare(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False  # 提前返回！可测量
        time.sleep(0.001)  # 模拟 CPU 耗时
    return True

# 攻击: 逐字节探测
# 测量每次调用耗时
# 第一个字符匹配时耗时增加 → 确认字符
# 以此类推逐个爆破

# ✅ 安全比较（恒定时间）
import hmac

def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
    # Python 3.3+ 的 hmac.compare_digest
    # 保证恒定时间比较，不受内容影响
```

## 填充预言机攻击（Padding Oracle）

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ❌ 不安全的解密（泄露填充错误）
class VulnerableOracle:
    def decrypt(self, ciphertext: bytes) -> str:
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        try:
            plaintext = unpad(cipher.decrypt(ct), 16)
            return plaintext.decode()
        except ValueError as e:
            # ❌ 泄露填充错误！
            # 攻击者可利用此泄露逐字节爆破明文
            if "Padding is incorrect" in str(e):
                return "PADDING_ERROR"
            return "DATA_ERROR"

# 攻击流程:
# 1. 修改密文最后一个字节 → 服务器返回"PADDING_ERROR"
# 2. 逐字节调整 → 直至"OK" → 确认中间值
# 3. 推导明文（明文 = 中间值 XOR IV）
# 4. 重复操作，逐块解密

# ✅ 安全做法：MAC-then-Encrypt 或 GCM
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
# GCM 同时提供加密和认证，无法篡改
```

## 弱 RNG（随机数生成器）

```python
# ❌ Python random 模块——不适用于密码学
import random

def generate_reset_token():
    token_chars = string.ascii_letters + string.digits
    return ''.join(random.choice(token_chars) for _ in range(32))
    # Python random 使用 Mersenne Twister
    # 624 个输出后可预测全部后续随机数！

# 攻击:
# 收集 624 个连续的 token → 用 randcrack 预测后续所有 token

# ✅ 安全的随机数
import secrets

def generate_reset_token():
    return secrets.token_urlsafe(32)  # 43 字符安全随机
    # secrets 使用 os.urandom → 内核熵源

# ✅ 安全验证码
code = str(secrets.randbelow(1000000)).zfill(6)
# 无法预测，不受时序攻击
```

## ROCA 漏洞（CVE-2017-15361）

```yaml
影响: Infineon TPM 芯片生成 RSA 密钥
原理: RSA 质数生成算法有缺陷
  质数 p = k * M + (65537^a mod M)
  其中 M 为前 46 个质数乘积
  
  导致质数符合特定结构
  可被离线分解（约 100 CPU 核心时）

检测:
  # Python
  python roca-detect.py --publickey certificate.der
  
  # Yubikey
  ykman piv info | grep "PIN INVALID"  

修复:
  - 更新 TPM 固件
  - 重新生成所有 RSA 密钥对
  - Infineon TPM v1.2 不受影响（仅 2.0）
```

## 证书伪造（MD5 碰撞）

```yaml
2008 年 MD5 碰撞攻击:
  攻击者: 荷兰密码学家团队
  方法: 利用 MD5 碰撞构造相同哈希的合法证书和恶意证书
  
  合法证书: 由 CA 签名（完全正常）
  恶意证书: 相同签名但不同公钥→伪装为任何网站
  
  耗时: 约 200 台 PS3 运算 3 天（价值 $20k）
  
结果:
  - 成功伪造 RapidSSL 签名的 CA 证书
  - 可拦截所有 HTTPS 流量
  - CA/Browser Forum 宣布 MD5 证书在 2011 年前淘汰
  
教训:
  - 永远不要用 MD5 做签名证书
  - 现在: SHA256 最低要求
  - 中间人拦截依靠 2022 年仍存在未打补丁系统
```

## 常见密码学设计错误

```
1. ECB 模式
   ❌ AES-ECB: 相同明文块→相同密文块（泄露图像轮廓）
   ✅ 必须用 CBC 或 GCM 模式

2. 弱密钥派生
   ❌ password → MD5(password) → 作为 AES 密钥
   ✅ password → PBKDF2(scrypt/argon2) → 派生密钥

3. 无完整性校验
   ❌ AES-CBC 加密但不带 MAC
   ✅ AES-GCM / AES-CBC+HMAC

4. 硬编码密钥
   ❌ key = bytes([0x12, 0x34, 0x56, 0x78, ...])
   ✅ KMS/HSM 托管密钥

5. 短密钥/非对称密钥
   ❌ RSA-512（分钟级分解）
   ❌ RSA-1024（国家级可分解）
   ✅ RSA-2048+ / ECDSA P-256+ / Ed25519
```

## 哈希碰撞表

| 算法 | 碰撞成本 | 安全状态 |
|------|---------|---------|
| MD5 | 秒级 (2^18) | ❌ 完全破解 |
| SHA-1 | ~$45k (2017) | ❌ SHAttered 已演示 |
| SHA-256 | 2^128 理论 | ✅ 当前标准 |
| SHA-3 | 2^128 理论 | ✅ 未来标准 |
| BLAKE2/3 | 2^128 理论 | ✅ 高性能安全 |
| SM3 | 2^128 理论 | ✅ 国密标准 |

*上一篇：[零知识证明与隐私计算](04-zkp-zero-knowledge.md)*

# 哈希算法与密码安全

## 概述

哈希是密码学的基石——但不理解其安全特性就使用哈希，比不使用更危险。MD5 和 SHA-1 在安全场景中已被宣告死亡，而正确选用 Argon2/Bcrypt/Scrypt 可以抵御甚至国家级攻击者。

---

## 1. 哈希安全属性

```
密码学哈希必须满足三个属性:

  1. 抗原像 (Pre-image Resistance):
     已知 h = H(m)，无法找到 m
     → 如果知道哈希值，无法反推原文

  2. 抗第二原像 (Second Pre-image Resistance):
     已知 m1，无法找到 m2 ≠ m1 且 H(m2) = H(m1)
     → 无法制造哈希碰撞

  3. 抗碰撞 (Collision Resistance):
     无法找到任意两个不同的 m1, m2 使得 H(m1) = H(m2)
     → 比第二原像更强的性质

  SHA-1: 2005 年首次理论碰撞，2017 年首次实践碰撞
  MD5:   1996 年发现碰撞，2004 年完全攻破

  SHA-2: 目前安全（SHA-256/384/512）
  SHA-3: 备用方案，基于 Keccak
```

---

## 2. 密码哈希实现

### 2.1 Argon2（2015 密码哈希竞赛冠军）

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

class PasswordManager:
    """使用 Argon2 的密码管理器"""

    def __init__(self):
        # Argon2id 参数:
        #   time_cost: 迭代次数（越大越安全但越慢）
        #   memory_cost: 内存开销（防御 GPU/ASIC，推荐 64MB+）
        #   parallelism: 并行度（防御多核攻击）
        #   hash_len: 输出长度（32 字节推荐）
        self.ph = PasswordHasher(
            time_cost=3,       # OWASP 推荐 ≥2
            memory_cost=65536,  # 64MB（OWASP 推荐 ≥46MB）
            parallelism=4,     # OWASP 推荐 1-4
            hash_len=32,       # 256-bit 输出
            salt_len=16        # 128-bit salt
        )

    def hash_password(self, password):
        """创建密码哈希"""
        try:
            return self.ph.hash(password)
        except Exception as e:
            raise ValueError(f"Password hashing failed: {e}")

    def verify_password(self, hash, password):
        """验证密码"""
        try:
            self.ph.verify(hash, password)

            # 检查是否需要重新哈希（参数升级）
            if self.ph.check_needs_rehash(hash):
                return True, self.ph.hash(password)

            return True, None
        except VerifyMismatchError:
            return False, None

# 使用示例
pm = PasswordManager()
hash = pm.hash_password("correct-horse-battery-staple")
# 输出: $argon2id$v=19$m=65536,t=3,p=4$SALT...$HASH...
```

### 2.2 Bcrypt 与 Scrypt 对比

```python
import bcrypt
import hashlib

# Bcrypt — 简单易用，但无内存硬度
password = b"super_secret"
salt = bcrypt.gensalt(rounds=12)  # 2^12 轮迭代
hashed = bcrypt.hashpw(password, salt)
bcrypt.checkpw(password, hashed)  # True

# Bcrypt 限制:
# - 最大密码长度 72 字节（自动截断！）
# - 无内存硬度（GPU 可并行攻击）
# - rounds 过大导致登录慢

# Scrypt — 内存硬度强于 Bcrypt
import hashlib
scrypt_hash = hashlib.scrypt(
    password,
    salt=os.urandom(16),
    n=2**14,    # CPU/内存成本 (16384)
    r=8,        # 块大小
    p=1,        # 并行度
    dklen=32    # 派生密钥长度
)

# 算法选择建议:
# 新项目: Argon2id（PCM 冠军）
# 兼容性: Bcrypt（广泛支持）
# 内存加密: Scrypt（文件加密/密钥派生）
# 绝不使用: MD5/SHA-1/SHA-256(无盐)/PBKDF2-HMAC-SHA1
```

---

## 3. 哈希攻击与防御

### 3.1 彩虹表攻击

```python
# 彩虹表原理:
# 预计算 H(password) → password 的映射表
# 防御: Salt（随机盐值使每个用户独立）

# ❌ 无盐（彩虹表直接查）
hash = hashlib.sha256(password.encode()).hexdigest()
# rainbow_table[hash] → 瞬间找到原文

# ✅ 有盐（无法使用预计算表）
salt = os.urandom(32)
hash = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode(),
    salt,
    iterations=600000,
    dklen=32
)
# 即使相同密码，不同 salt 产生完全不同的 hash
```

### 3.2 长度扩展攻击

```python
# SHA-256(M) 是可被扩展的 → SHA-256(M || padding || extension)
# 攻击: 已知 H(k || m)，可以计算 H(k || m || padding || evil)
# 即使不知道 k！

# 攻击场景:
# API 签名: token = H(secret_key || user_id || timestamp)
# 攻击者可扩展: token' = H(secret_key || user_id || timestamp || padding || "&admin=true")
# → 伪造管理员 token!

# 防御:
# 1. 使用 HMAC: HMAC-SHA256(key, data) 而不是 SHA256(key || data)
import hmac
secure_token = hmac.new(secret_key, data, hashlib.sha256).hexdigest()

# 2. 或者使用 SHA-3 (天然免疫长度扩展攻击)
import hashlib
sha3_token = hashlib.sha3_256(key + data).hexdigest()
```

---

## 4. 实用场景

```python
import hashlib
import hmac
import secrets

class CryptoToolkit:
    """安全密码学工具集"""

    @staticmethod
    def generate_api_key():
        """生成 API Key"""
        return secrets.token_hex(32)  # 64 字符

    @staticmethod
    def hmac_sign(message, key):
        """HMAC 签名"""
        return hmac.new(
            key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def constant_time_compare(a, b):
        """恒定时间比较（防止时序攻击）"""
        return hmac.compare_digest(a, b)

    @staticmethod
    def file_hash(filepath):
        """文件完整性校验"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
```

---

*下一篇：[对称加密](02-symmetric-crypto.md)*

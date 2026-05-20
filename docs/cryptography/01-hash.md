# 哈希算法与完整性校验

## 常见哈希算法

| 算法 | 输出长度 | 安全状态 | 推荐使用 |
|------|---------|---------|---------|
| MD5 | 128 bits | 已破解（碰撞攻击） | 仅兼容性场景 |
| SHA-1 | 160 bits | 已破解（SHAttered） | ❌ 不应使用 |
| SHA-256 | 256 bits | 安全 | ✅ 通用推荐 |
| SHA-3 | 可变 | 安全 | ✅ 新一代标准 |
| BLAKE3 | 可变 | 安全 | ✅ 性能最优 |

## 哈希的常见应用

### 密码存储
```python
import hashlib, os

def hash_password(password: str) -> bytes:
    """不要用！仅用于演示错误做法"""
    return hashlib.sha256(password.encode()).hexdigest()
    # ❌ 无盐，彩虹表可破解
```

### 正确做法：bcrypt
```python
import bcrypt

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)
```

### 文件完整性
```bash
# 计算文件哈希
sha256sum important-file.bin > checksum.txt

# 校验完整性
sha256sum -c checksum.txt
```

## 哈希长度扩展攻击

MD5/SHA-1/SHA-2 族存在长度扩展漏洞：
已知 `H(message)` 和 `len(message)` 可以计算 `H(message || padding || extra)`

**防护**：使用 HMAC 而非裸哈希
```python
import hmac
mac = hmac.new(key, message, hashlib.sha256).hexdigest()
```

## 哈希碰撞对安全的影响

- **数字证书伪造**：MD5 碰撞可伪造 CA 证书（2008 年 Flame 恶意软件案例）
- **Git 对象碰撞**：SHA-1 碰撞可创建内容不同但 hash 相同的 Git 提交
- **数字签名绕过**：碰撞两个不同消息使签名相同
- **文件去重绕过**：恶意文件与正常文件 hash 相同

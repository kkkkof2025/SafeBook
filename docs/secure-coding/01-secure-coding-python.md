# 安全编码实践（Python）

> 安全的代码不是写出来的，是设计出来的。

---

## 输入验证

```python
# ❌ 不安全：未验证输入类型和范围
def transfer(from_acc, to_acc, amount):
    account.withdraw(from_acc, amount)
    account.deposit(to_acc, amount)

# ✅ 安全：类型检查 + 边界验证
from decimal import Decimal

def transfer(from_acc: str, to_acc: str, amount: Decimal) -> bool:
    # 输入格式验证
    if not re.match(r'^ACC\d{10}$', from_acc):
        raise ValueError("Invalid source account format")
    if not re.match(r'^ACC\d{10}$', to_acc):
        raise ValueError("Invalid target account format")
    # 金额范围检查
    if not Decimal('0.01') <= amount <= Decimal('999999.99'):
        raise ValueError("Amount out of allowed range")
    # 业务逻辑执行
    if account.get_balance(from_acc) < amount:
        raise ValueError("Insufficient balance")
    account.withdraw(from_acc, amount)
    account.deposit(to_acc, amount)
    return True
```

## SQL 注入防护

```python
# ❌ 不安全：字符串拼接
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# ✅ 安全：参数化查询
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, hashed_password))

# SQLAlchemy 自动参数化（ORM）
user = session.query(User).filter(User.username == username).first()
```

## 命令注入防护

```python
import subprocess
import shlex

# ❌ 不安全：shell=True + 字符串拼接
cmd = f"ping -c 1 {user_input}"
subprocess.run(cmd, shell=True)  # 用户输入 "8.8.8.8; rm -rf /"

# ✅ 安全：参数列表方式
subprocess.run(["ping", "-c", "1", user_input], shell=False)

# ✅ 安全：使用专门的库而非 shell 命令
import ipaddress
def ping_host(ip: str):
    try:
        ipaddress.ip_address(ip)  # 验证 IP 格式
    except ValueError:
        return "Invalid IP"
    # 使用 Python 库实现 ping 而非系统命令
    # ping3.ping(ip)
```

## 路径遍历防护

```python
# ❌ 不安全：直接拼接路径
path = os.path.join(UPLOAD_DIR, filename)
open(path).read()  # filename = "../../etc/passwd"

# ✅ 安全：规范化 + 白名单检查
def safe_read_file(filename: str) -> bytes:
    # 路径规范化
    full_path = os.path.normpath(
        os.path.join(UPLOAD_DIR, filename)
    )
    # 确保在允许目录内
    if not full_path.startswith(os.path.abspath(UPLOAD_DIR)):
        raise PermissionError("Path traversal detected")
    if not os.path.exists(full_path):
        raise FileNotFoundError("File not found")
    with open(full_path, 'rb') as f:
        return f.read()
```

## 密码安全

```python
import secrets
import argon2

class PasswordManager:
    def __init__(self):
        self.hasher = argon2.PasswordHasher(
            time_cost=2,      # 迭代次数
            memory_cost=19456, # 内存消耗 (19 MB)
            parallelism=1,    # 并行度
            hash_len=32,      # 哈希长度
            salt_len=16       # 盐长度
        )
    
    def hash_password(self, password: str) -> str:
        """生成安全的密码哈希"""
        if len(password) < 8:
            raise ValueError("Password too short")
        return self.hasher.hash(password)
    
    def verify_password(self, password: str, hash: str) -> bool:
        """验证密码"""
        try:
            return self.hasher.verify(hash, password)
        except argon2.exceptions.VerifyMismatchError:
            return False
    
    def generate_token(self) -> str:
        """生成安全的随机令牌"""
        return secrets.token_urlsafe(32)
```

## 日志安全

```python
import logging

# ❌ 不安全：日志记录敏感信息
logging.info(f"Login: user={username}, password={password}")
logging.info(f"Payment: user={email}, card={credit_card}")

# ✅ 安全：脱敏处理
def mask_sensitive(data: str, show_last: int = 4) -> str:
    """脱敏函数"""
    if not data:
        return "***"
    if len(data) <= show_last:
        return "*" * len(data)
    return "*" * (len(data) - show_last) + data[-show_last:]

logging.info(f"Login: user={username}, password={mask_sensitive(password)}")
logging.info(f"Payment: user={mask_sensitive(email)}, card={mask_sensitive(credit_card, 4)}")
```

## 依赖安全

```toml
# pyproject.toml
[tool.pip-audit]
# 禁止已知漏洞的依赖
strict = true
require_hashes = true

[tool.poetry.dependencies]
python = "^3.11"
flask = ">=2.3,<3.0"  # 指定版本范围
sqlalchemy = ">=2.0"
```

```bash
# 定期扫描依赖漏洞
pip-audit --strict
safety check

# 锁定依赖版本
pip freeze > requirements.txt
# 使用 poetry.lock 或 pipfile.lock 管理
```

## 安全编码检查表

```
[ ] 所有输入使用白名单验证（而非黑名单）
[ ] SQL 使用参数化查询（从不拼接）
[ ] 文件路径规范化后使用
[ ] 命令执行使用参数列表而非 shell
[ ] 密码使用 argon2/bcrypt/scrypt
[ ] 敏感信息不记录日志
[ ] Session/Tokens 使用 secrets 模块
[ ] 依赖定期更新 + 漏洞扫描
[ ] 异常处理不泄露内部信息
[ ] HTTPS 强制（HSTS + CSP + CORS 配置）
```

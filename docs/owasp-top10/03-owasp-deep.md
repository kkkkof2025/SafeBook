# OWASP Top 10 深潜：访问控制与加密

> 2021 版把 Broken Access Control 从第 5 名推到了第 1 名——这是最该管好的漏洞。

---

## A01: Broken Access Control（越权/未授权）

### 常见模式

```
1. 水平越权
   - 用户 A 访问用户 B 的数据
   - 常见于: 订单查看/用户资料/财务记录
  
2. 垂直越权
   - 普通用户访问管理员功能
   - 常见于: API 端点无角色校验

3. IDOR (Insecure Direct Object Reference)
   - 通过修改 ID 参数访问他人数据
   - /api/user/123 → 改成 124

4. 缺少功能级访问控制
   - 页面隐藏管理入口+按钮
   - 但 API 端点未做权限检查
```

### 修复方案

```javascript
// ❌ 缺少访问控制
app.get('/api/user/:id', async (req, res) => {
    const user = await db.findUser(req.params.id);
    res.json(user);
});

// ✅ 水平越权检查
app.get('/api/user/:id', authenticate, async (req, res) => {
    // 验证当前用户只能是本人或管理员
    if (req.user.id !== req.params.id && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    const user = await db.findUser(req.params.id);
    res.json(user);
});

// ✅ 访问控制中间件
function requireRole(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
}

// 使用
app.delete('/api/users/:id', authenticate, requireRole('admin'), async (req, res) => {
    // 只有管理员可删除用户
});
```

## A02: Cryptographic Failures（加密失败）

### 常见错误

```python
# ❌ 使用 MD5/SHA1 存储密码
password_hash = hashlib.md5(password.encode()).hexdigest()

# ❌ 使用自加密算法
def my_encrypt(data, key):
    return base64.b64encode(bytes([a ^ b for a, b in zip(data.encode(), key.encode())]))

# ❌ HTTP 传输敏感数据（无 TLS）
# 登录页不是 HTTPS

# ❌ 敏感数据明文存储
INSERT INTO users (ssn, credit_card) VALUES ('123-45-6789', '4111111111111111')

# ❌ 不安全的随机数
import random
token = random.randint(100000, 999999)  # 可预测！

# ❌ JWT 弱密钥
jwt.encode({"user": "admin"}, "secret123")  # 可爆破
```

### 修复方案

```python
# ✅ 使用 bcrypt 存储密码
import bcrypt

password = b"correct-horse-battery-staple"
salt = bcrypt.gensalt(rounds=12)  # 12 轮迭代
hashed = bcrypt.hashpw(password, salt)

# 验证
if bcrypt.checkpw(password, hashed):
    print("Password matches")

# ✅ 安全随机数
import secrets
token = secrets.token_hex(16)  # 加密安全随机
mfa_code = secrets.randbelow(1000000)

# ✅ 密文存储（AES-GCM 认证加密）
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)
encrypted_ssn = cipher.encrypt(b"123-45-6789")
decrypted = cipher.decrypt(encrypted_ssn)

# ✅ 传输强制 HTTPS
app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
}))
```

## A03: Injection（注入攻击汇总）

### SQL 注入防御

```python
# ❌ 拼接
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")

# ✅ 参数化
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))

# ✅ ORM 安全使用
User.query.filter_by(id=user_input).first()  # SQLAlchemy 自动参数化

# ✅ 额外的深度防御
import sqlite3
conn = sqlite3.connect('db.sqlite')
conn.execute("PRAGMA trusted_schema = OFF")
conn.execute("PRAGMA cell_size_check = ON")
```

### 命令注入防御

```python
# ❌ 最危险
os.system(f"ping {host}")

# ✅ 参数列表（不通过 shell）
subprocess.run(["ping", "-c", "1", host], shell=False)

# ✅ 白名单
if host not in WHITELIST:
    raise ValueError("Invalid host")
```

## A04: Insecure Design（不安全设计）

### SSRF 典型案例

```javascript
// ❌ 直接使用用户输入的 URL
app.post('/fetch', async (req, res) => {
    const response = await fetch(req.body.url);
    const data = await response.text();
    res.send(data);
    // 攻击者可获取元数据: http://169.254.169.254/
});

// ✅ URL 白名单 + 内网阻断
const ALLOWED_DOMAINS = ['api.weather.com', 'maps.google.com'];
const BLOCKED_IPS = ['10.', '172.16.', '192.168.', '169.254.', '127.'];

app.post('/fetch', async (req, res) => {
    const url = new URL(req.body.url);
    
    // 域名白名单
    if (!ALLOWED_DOMAINS.some(d => url.hostname.endsWith(d))) {
        return res.status(400).json({ error: 'Domain not allowed' });
    }
    
    // DNS 解析后检查 IP
    const ip = await dns.promises.resolve4(url.hostname);
    for (const blocked of BLOCKED_IPS) {
        if (ip[0].startsWith(blocked)) {
            return res.status(400).json({ error: 'IP blocked' });
        }
    }
    
    const response = await fetch(url.toString());
    res.send(await response.text());
});
```

## OWASP Top 10 安全验证清单

```
A01: Broken Access Control
  - 每个 API 端点做授权检查
  - 拒绝默认：无显式 Allow 则 Deny
  - IDOR 自动扫描

A02: Cryptographic Failures
  - 密码使用 bcrypt/argon2
  - 敏感数据存储加密
  - TLS 1.2+ 全站

A03: Injection
  - SQL 参数化查询
  - OS 命令使用参数列表
  - CSP 防止 XSS

A04: Insecure Design
  - 威胁建模（STRIDE/LINDDUN）
  - 速率限制
  - SSRF 防护

A05: Security Misconfiguration
  - 默认账户禁用
  - 安全响应头
  - CORS 白名单
  - 环境分离（dev/staging/prod）
```

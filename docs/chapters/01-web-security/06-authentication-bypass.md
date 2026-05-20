# 认证绕过（Authentication Bypass）

> **一句话定义**：攻击者通过利用认证逻辑中的漏洞，绕过身份验证直接访问受保护的资源。

**危险等级**：🔴 严重
**OWASP Top 10 2021**：A07 — Identification and Authentication Failures（第 7 位）

---

## 原理深度分析

### 为什么发生

认证绕过的本质是**认证逻辑存在缺陷**，常见原因：

1. **不安全的直接对象引用**：跳过登录直接访问其他页面
2. **弱密码策略**：可爆破
3. **会话管理缺陷**：会话 ID 可预测，没有失效机制
4. **记住我功能不安全**：Cookie 直接包含用户名
5. **多因素认证绕过**：使用已过期的验证码或旧令牌
6. **路径遍历绕过**：通过 URL 直接访问受保护文件

### 常见绕过类型

| 类型 | 描述 | 示例 |
|------|------|------|
| 直接 URL 访问 | 未登录用户直接访问内部 URL | `/admin/dashboard` |
| 密码爆破 | 无速率限制 | 暴力枚举密码 |
| 会话固定 | 服务器复用旧的会话 ID | 预设置会话 ID |
| Cookie 伪造 | 修改 Cookie 中的角色信息 | `role=user` → `role=admin` |
| SQL 注入绕过 | 利用 SQL 注入绕过登录 | `' OR 1=1 --` |
| JWT 攻击 | 修改 JWT 中的算法或签名 | alg:none → 算法混淆 |

---

## 真实世界案例

### 案例 1：MongoDB 曝露事件（2017）

大量 MongoDB 由于默认无认证配置被攻击。

- **攻击方式**：攻击者扫描公网上 27017 端口，直接连接未认证的 MongoDB
- **后果**：攻击者删除数据并勒索赎金
- **教训**：数据库默认配置必须要求认证

### 案例 2：GitHub OAuth 令牌泄露（2023）

GitHub 的一些 CI 流程意外泄露了 OAuth 令牌，攻击者通过这些令牌访问私有仓库。

- **攻击方式**：利用泄露的 GitHub OAuth 令牌绕过认证
- **后果**：多个知名组织的私有代码被访问
- **教训**：令牌泄露 = 认证完全失效，需要定期轮换

---

## 简单 POC

### 场景 1：直接 URL 访问

```python
# app.py — 只检查了页面渲染，没检查 API
from flask import Flask, request, session
import functools

app = Flask(__name__)
app.secret_key = 'test-key'

def require_login(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return "请先登录", 401
        return f(*args, **kwargs)
    return wrapper

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['user_id'] = 1
        session['role'] = 'user'
        return "登录成功"
    return '''
    <form method="POST">
        用户名：<input name="username"><br>
        密码：<input name="password"><br>
        <button type="submit">登录</button>
    </form>
    '''

# ✅ 正确：加了 @require_login 保护
@app.route('/dashboard')
@require_login
def dashboard():
    return "用户面板"

# 🔴 漏洞：忘记加 @require_login
@app.route('/admin')
def admin():
    # 只在前端检查，后端完全开放！
    return '''
    <h1>管理员面板</h1>
    <p>用户管理、系统配置、数据库导出</p>
    '''

if __name__ == '__main__':
    app.run(port=5007)
```

```bash
# 直接访问管理员页面，不需要登录！
curl "http://localhost:5007/admin"
# 返回管理员面板内容

# 而用户面板需要登录
curl "http://localhost:5007/dashboard"
# 返回 401
```

### 场景 2：Cookie 角色篡改

```python
# app.py — 使用不可信的 Cookie 存储角色
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/login_cookie')
def login_cookie():
    username = request.args.get('username', '')
    
    resp = make_response(f"登录成功，{username}")
    # 🔴 漏洞：直接在 Cookie 中设置角色（用户可修改）
    resp.set_cookie('role', 'user')
    return resp

@app.route('/admin_panel')
def admin_panel():
    # 🔴 漏洞：信任客户端传过来的角色
    role = request.cookies.get('role', '')
    
    # 攻击者在浏览器开发者工具中将 role 改为 admin
    if role == 'admin':
        return "管理员面板：全部用户数据"
    return "普通用户面板"
```

```bash
# 1. 登录
curl -c cookies.txt "http://localhost:5007/login_cookie?username=test"

# 2. 修改 Cookie，访问管理员面板
curl -b "role=admin" "http://localhost:5007/admin_panel"
# 返回：管理员面板：全部用户数据
```

### 场景 3：JWT 算法混淆攻击

```python
# 使用 PyJWT 演示算法混淆
import jwt

# 🔴 漏洞：服务器没有限制签名算法
def verify_jwt(token):
    try:
        # 不指定算法的 verify（危险的默认行为）
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload
    except:
        return None

# 攻击者构造的 JWT — 使用 none 算法
# 标准格式的 JWT：header.payload.signature
# 攻击者修改 header 中的 alg 为 "none"
malicious_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ."
# 解码后：{"alg":"none","typ":"JWT"}.{"user":"admin","role":"admin"}.

# ✅ 正确做法：指定算法
def verify_jwt_fixed(token):
    try:
        payload = jwt.decode(
            token, 
            app.config['SECRET_KEY'],
            algorithms=['HS256']  # ✅ 只接受一种算法
        )
        return payload
    except jwt.InvalidTokenError:
        return None
```

---

## 修复方案

### 方案 1：统一认证中间件 ⭐⭐⭐⭐⭐

```python
from flask import Flask, request, session, redirect, url_for, g
import functools

app = Flask(__name__)
app.secret_key = 'very-secure-key'

# 白名单：不需要认证的路径
PUBLIC_PATHS = {'/', '/login', '/register', '/public', '/health'}

@app.before_request
def check_authentication():
    """全局认证检查中间件"""
    g.user = None
    
    # 公开路径不需要认证
    if request.path in PUBLIC_PATHS:
        return
    
    # 静态资源不需要认证
    if request.path.startswith('/static/'):
        return
    
    # 检查 session
    if 'user_id' in session:
        g.user = {
            'id': session['user_id'],
            'role': session.get('role', 'user'),
            'username': session.get('username', '')
        }
        return
    
    # API 请求返回 401，页面请求跳转登录
    if request.is_json or request.path.startswith('/api/'):
        return {"error": "请先登录"}, 401
    return redirect(url_for('login'))

# ✅ 所有受保护的路由自动获得认证保护
@app.route('/admin')
def admin():
    # 在到达这里之前，中间件已经做了认证检查
    # 还可以做额外的角色检查
    if g.user and g.user['role'] != 'admin':
        return "无权访问", 403
    return "管理员面板"
```

### 方案 2：服务端会话 ⭐⭐⭐⭐⭐

```python
import secrets

# ✅ 使用服务端 Session + 随机令牌
# Flask 默认使用签名的客户端 Cookie Session
# 但不存储角色等敏感信息，只存储 user_id

# 更好的方案：使用 Redis Session
from flask_session import Session
import redis

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379)
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # 签名保护
Session(app)

@app.route('/login')
def login():
    session['user_id'] = 1
    session['role'] = 'admin'
    session['ip'] = request.remote_addr  # 绑定 IP 防劫持
    session.permanent = False
    return "登录成功"
```

### 方案 3：安全 JWT ⭐⭐⭐⭐

```python
import jwt
from datetime import datetime, timedelta

SECRET_KEY = 'your-256-bit-secret-here'

def create_jwt(user_id, role):
    """创建安全的 JWT"""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.now() + timedelta(hours=1),  # 过期时间
        'iat': datetime.now(),                         # 签发时间
        'nbf': datetime.now(),                         # 开始生效时间
        'jti': secrets.token_hex(16),                  # 唯一 ID（用于吊销）
    }
    # ✅ 明确指定算法
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_jwt(token):
    """验证 JWT"""
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=['HS256'],  # ✅ 只接受 HS256
            options={
                'require': ['exp', 'iat', 'jti'],  # 必须包含这些字段
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None  # 令牌已过期
    except jwt.InvalidTokenError:
        return None  # 无效令牌
```

### 方案 4：速率限制 ⭐⭐⭐⭐

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login')
@limiter.limit("5 per minute")  # 限制登录尝试频率
def login():
    # 登录逻辑
    pass
```

---

## 检测与防御工具

| 工具 | 用途 |
|------|------|
| [Burp Suite Auth Analyzer](https://portswigger.net/bappstore/efbf2a4a1c53421fb0a7c2a9b613f8f4) | 认证逻辑自动分析 |
| [JWT.io](https://jwt.io/) | JWT 调试与安全性检查 |
| [John the Ripper](https://www.openwall.com/john/) | 密码爆破 |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra) | 在线密码爆破 |
| [Hashcat](https://hashcat.net/hashcat/) | 哈希密码破解 |

---

## 延伸阅读

1. [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
2. [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
3. [JWT Algorithm Confusion 详解](https://portswigger.net/web-security/jwt/algorithm-confusion)
4. [PortSwigger Authentication 教程](https://portswigger.net/web-security/authentication)
5. [OWASP Password Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

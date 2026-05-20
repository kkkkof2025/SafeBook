# HTTP 协议详解

> 安全从业者必须吃透的协议——没有之一

---

## 为什么 HTTP 是安全的基石

Web 安全几乎全部发生在 HTTP 层面。无论是 SQL 注入（参数在 URL/请求体中），还是 XSS（输出在响应体中），理解 HTTP 才能理解攻击路径。

---

## 请求方法

| 方法 | 用途 | 安全关注 |
|------|------|---------|
| GET | 获取资源 | 参数在 URL 中，会记录在日志/历史 |
| POST | 提交数据 | 参数在请求体中，相对安全 |
| PUT | 上传/替换 | 可能被滥用来上传文件 |
| DELETE | 删除资源 | 权限校验不严可导致删除 |
| OPTIONS | 查询可用方法 | 如果开放了 PUT/DELETE 就危险了 |

**安全意识**：
```http
# 危险：GET 请求带密码，会记录在服务器日志和浏览器历史中
GET /login?password=admin123 HTTP/1.1

# 推荐：POST 请求密码在请求体中
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

password=admin123
```

---

## 状态码

攻击者经常利用状态码来收集信息：

| 状态码 | 含义 | 攻击者利用 |
|--------|------|-----------|
| 200 OK | 请求成功 | 确认资源存在 |
| 301/302 重定向 | 页面跳转 | 开放重定向漏洞 |
| 401 Unauthorized | 未认证 | 知道有认证但不知道密码 |
| 403 Forbidden | 禁止访问 | 知道资源存在但无权访问 |
| 404 Not Found | 不存在 | 可以探测目录和文件是否存在 |
| 500 服务器错误 | 服务端异常 | 可能暴露堆栈信息 |

---

## 请求头与响应头

### 关键请求头

```
Host: example.com         # ✅ 必须，虚拟主机标识
Cookie: session=abc123    # 🔴 安全核心，会话标识
Referer: https://...       # 🟡 可能泄露来源 URL
User-Agent: Mozilla/5.0   # 🟡 可能被伪造
Authorization: Bearer xxx  # 🔴 API 认证
X-Forwarded-For: 1.2.3.4  # 🟡 客户端真实 IP
```

### 安全相关的响应头

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

# 🔴 安全相关响应头：
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax
X-Frame-Options: DENY                       # 防止点击劫持
X-Content-Type-Options: nosniff             # 防止 MIME 类型嗅探
Content-Security-Policy: script-src 'self'  # 防止 XSS
Strict-Transport-Security: max-age=31536000 # 强制 HTTPS
```

---

## Cookie

Cookie 是 Web 安全的核心战场：

```http
Set-Cookie: session=abc123; 
            Expires=Wed, 21 Oct 2026 07:28:00 GMT;  # 过期时间
            Path=/;                                    # 作用路径
            Domain=.example.com;                       # 作用域
            HttpOnly;                                  # ❗禁止 JS 访问（防 XSS 窃取）
            Secure;                                    # ❗仅 HTTPS 发送
            SameSite=Lax                               # ❗防 CSRF
```

---

## HTTPS / TLS

```
HTTP  →  明文传输  → 中间人可以查看和修改内容
HTTPS →  加密传输  → 中间人无法查看内容，但可能做 SSL 剥离
```

HTTPS 并不保证安全——它只保证传输过程中的加密。服务器端如果有漏洞，HTTPS 也无济于事。

> **安全名言**：HTTPS 是公路上的装甲车，不是金库的保险箱。

---

## 实战：用 curl 观察 HTTP

```bash
# 查看 HTTP 请求和响应头
curl -v https://example.com

# 只查看响应头
curl -I https://example.com

# 发送 POST 请求
curl -X POST -d "username=admin&password=123" https://example.com/login

# 携带 Cookie
curl -b "session=abc123" https://example.com/profile

# 设置 User-Agent
curl -A "Mozilla/5.0" https://example.com

# 跟随重定向
curl -L https://example.com
```

---

## 小结

- HTTP 是 Web 安全的底层语言，每一个 Web 漏洞最终都体现在 HTTP 层面
- 熟练使用 curl、Burp Suite 的 Repeater 观察和修改 HTTP 请求是必备技能
- 安全响应头是最简单有效的防御手段之一

[上一章：计算机网络基础](01-networking.md) | [下一章：Web 应用架构 →](03-web-architecture.md)

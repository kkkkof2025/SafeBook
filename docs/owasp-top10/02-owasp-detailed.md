# OWASP Top 10 完整条目解析

## A03: 注入（Injections）

### SQL 注入进阶
```sql
-- 时间盲注
AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(5), 0)

-- 报错注入
AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))

-- 联合查询注入
' UNION SELECT NULL, NULL, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--

-- 堆叠查询（需PHP+MySQL多语句支持）
'; DROP TABLE users; --
```

### NoSQL 注入（MongoDB）
```javascript
// ❌ 漏洞代码
db.users.find({ username: req.body.username, password: req.body.password });

// 利用
POST /login
{"username": {"$gt": ""}, "password": {"$gt": ""}}

// ✅ 修复
db.users.find({ username: String(req.body.username),
                password: hash(req.body.password) });
```

---

## A02: 密码学失效

```python
# ❌ ECB 模式 — 相同明文 = 相同密文（企鹅图效应）
cipher = AES.new(key, AES.MODE_ECB)

# ❌ 固定 IV — 多次加密可恢复明文
iv = b"1234567890123456"  # 绝不复用!

# ✅ GCM 模式 + 随机 IV
from Crypto.Cipher import AES
iv = os.urandom(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
return iv + ciphertext + tag  # 无需额外 MAC
```

---

## A04: 不安全的设计

```python
# 威胁建模 (STRIDE)
threats = {
    'Spoofing': 'OAuth + 2FA + 证书验证',
    'Tampering': 'HMAC 签名 + TLS + 完整性校验',
    'Repudiation': '审计日志 + 数字签名 + 不可篡改',
    'Information Disclosure': '加密 + 脱敏 + 最小权限',
    'Denial of Service': '限流 + CDN + WAF',
    'Elevation of Privilege': 'RBAC + 审批流 + 最小权限'
}

# 安全设计原则
# 1. 默认安全: 新功能默认最小权限
# 2. 纵深防御: 不依赖单一安全层
# 3. 失效安全: 安全控制故障时 ≤ 原始风险
```

---

## A06: 易受攻击和过时的组件

### 依赖扫描最佳实践

| 扫描时机 | 工具 | 频率 |
|---------|------|------|
| Pull Request | Dependabot | 每次提交 |
| 构建阶段 | Trivy/Snyk | 每次构建 |
| 定时扫描 | OWASP DC/Grype | 每日 |
| 容器镜像 | Trivy | 每次推送 |

```yaml
# GitHub Dependabot 配置
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    labels:
      - "security"
      - "dependencies"
```

---

## A07: 认证失效

```python
# ❌ 错误 1: 弱密码策略
MIN_PASSWORD_LENGTH = 6  # 太短!
# ✅ 强密码: ≥12 位 + 大小写 + 数字 + 特殊字符

# ❌ 错误 2: 无登录限速
# ✅ 速率限制
key = f"login:{ip}:{username}"
attempts = redis.get(key) or 0
if int(attempts) > 5:
    raise RateLimitExceeded(block_duration=300)
redis.incr(key); redis.expire(key, 60)

# ❌ 错误 3: "用户名不存在" vs "密码错误"
# ✅ 统一信息: "用户名或密码错误"
```

---

## A08: 软件和数据完整性失效

```yaml
# CI/CD 管道完整性检查
- name: Verify integrity
  run: |
    # SBOM 验证
    sbom-tool verify --sbom sbom.spdx.json
    # 容器镜像签名验证
    cosign verify --key cosign.pub myimage:latest
    # 依赖来源校验
    npm audit --audit-level=critical
```

---

## A10: SSRF 服务端请求伪造

```python
import ipaddress, socket
from urllib.parse import urlparse

def is_safe_url(url):
    """防御 SSRF: 阻止内网/回环/链接本地地址"""
    parsed = urlparse(url)
    hostname = parsed.hostname

    # 直接 IP 检查
    try:
        ip = ipaddress.ip_address(hostname)
        return not (
            ip.is_private or ip.is_loopback or
            ip.is_link_local or ip.is_multicast
        )
    except ValueError:
        pass

    # DNS 解析后检查
    try:
        resolved = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(resolved)
        return not (
            ip.is_private or ip.is_loopback
        )
    except socket.gaierror:
        return False
```

---

*上一篇：[OWASP Top 10 (2021) 深度解析](01-owasp-top10.md)*

*下一篇：[OWASP Top 10 深潜：访问控制与加密](03-owasp-deep.md)*

# OWASP Top 10 (2021) 深度解析

## 概述

OWASP Top 10 是全球最权威的 Web 应用安全风险清单，每 3-4 年更新一次。2021 版引入三个新类别，重新排名了旧类别。本章逐项展开每个风险的攻击原理、真实案例、检测方法和修复方案。

---

## OWASP Top 10 (2021) 全览

| 排名 | 风险 | 变化 | CVSS 平均 | 本书详细章节 |
|------|------|------|-----------|-------------|
| A01 | 失效的访问控制 | ↑5 | 7.5 | [SSTI 攻击与防御](01-owasp-top10.md) |
| A02 | 加密机制失效 | ↓1 | 8.2 | [密码学基础 ↗](../cryptography/01-hash.md) |
| A03 | 注入 | ↓2 | 7.8 | [SSTI 攻击与防御](01-owasp-top10.md) · [命令注入](#a03-injection) |
| A04 | 不安全设计 | 新增 | 7.0 | [威胁建模](#a04-insecure-design) |
| A05 | 安全配置错误 | ↑1 | 6.5 | [安全基线](#a05-security-misconfiguration) |
| A06 | 易受攻击和过时的组件 | ↑3 | 7.2 | [供应链安全 ↗](../supply-chain-security/) · [SBOM ↗](../supply-chain-security/05-sbom.md) |
| A07 | 身份认证失效 | ↓5 | 8.8 | [SSTI 攻击与防御](01-owasp-top10.md) · [IAM ↗](../iam/) |
| A08 | 软件和数据完整性失效 | 新增 | 8.5 | [CI/CD 安全 ↗](../supply-chain-security/01-cicd-security.md) |
| A09 | 安全日志记录和监控失败 | ↑1 | 4.7 | [SOC 安全运营 ↗](../soc/01-soc-building.md) |
| A10 | 服务端请求伪造 (SSRF) | 新增 | 6.8 | [SSTI 攻击与防御](01-owasp-top10.md) |

---

## A01: 失效的访问控制 (Broken Access Control)

**风险级别：最高的 A01** ——从 2017 版第 5 位跃升至第 1 位，94% 的应用至少有一个访问控制缺陷。

### 攻击场景

```http
# 水平越权：用户 A 可查看用户 B 的敏感数据
GET /api/orders/1002 HTTP/1.1
Cookie: session=user_a_token
# → 返回 200 + 用户 B 的订单详情（应 403）

# 垂直越权：普通用户访问管理接口
GET /admin/users HTTP/1.1
Cookie: session=regular_user_token
# → 返回所有用户列表（应拦截）

# 直接对象引用 (IDOR)
# 修改 URL 中的 ID 参数即可访问其他资源
GET /api/invoices/INV-2024-0001 → 自己的发票 ✓
GET /api/invoices/INV-2024-0002 → 别人的发票 ✗ (应拒绝)
```

### 检测方法

```python
# 自动化访问控制测试
import requests

def test_authorization():
    """检查：用户 A 的 session 能否访问用户 B 的资源"""
    session_a = requests.Session()
    session_a.cookies.set('session', 'USER_A_TOKEN')

    # 用户 A 访问自己的资源 → 应该成功
    r1 = session_a.get('https://target.com/api/orders/1001')
    assert r1.status_code == 200, f"Expected 200, got {r1.status_code}"

    # 用户 A 访问用户 B 的资源 → 应该被拒绝
    r2 = session_a.get('https://target.com/api/orders/1002')
    assert r2.status_code in [403, 401, 404], \
        f"IDOR! User A accessed Order 1002: {r2.status_code}"

    # 普通用户访问管理功能 → 应该被拒绝
    r3 = session_a.get('https://target.com/admin/users')
    assert r3.status_code in [403, 401], \
        f"Privilege escalation! {r3.status_code}"
```

### 修复方案

```python
# Flask 修复：验证资源归属 + 角色检查
from functools import wraps

def require_resource_owner(model_class):
    """装饰器：验证当前用户是资源的所有者或管理员"""
    def decorator(f):
        @wraps(f)
        def decorated(resource_id, *args, **kwargs):
            resource = model_class.query.get_or_404(resource_id)
            if resource.user_id != current_user.id and not current_user.is_admin:
                abort(403, description="Access denied")
            return f(resource, *args, **kwargs)
        return decorated
    return decorator

@app.route('/api/orders/<int:order_id>')
@login_required
@require_resource_owner(Order)
def get_order(order):
    return jsonify(order.to_dict())
```

```java
// Spring Boot 修复
@GetMapping("/api/orders/{orderId}")
@PreAuthorize("@orderSecurity.isOwner(#orderId) or hasRole('ADMIN')")
public Order getOrder(@PathVariable Long orderId) {
    return orderService.findById(orderId);
}

@Component
public class OrderSecurity {
    public boolean isOwner(Long orderId) {
        Order order = orderRepository.findById(orderId).orElse(null);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return order != null && order.getUserId().equals(getCurrentUserId(auth));
    }
}
```

**→ 详细分析见：[SSTI 攻击与防御](01-owasp-top10.md)**

---

## A02: 加密机制失效 (Cryptographic Failures)

**风险**：从 2017 的 A03（敏感数据泄露）升级为 A02，覆盖范围更广——不限于传输层和数据存储，也包括密码学误用。

### 常见误用清单

| 误用 | 后果 | 修复 |
|------|------|------|
| 用 MD5/SHA1 存密码 | 彩虹表秒破 | bcrypt/argon2 |
| 自建加密算法 | 极大概率存在致命缺陷 | AES-256-GCM |
| 硬编码密钥 | 源码泄露即密钥泄露 | KMS/Vault |
| 不验证 TLS 证书 | 中间人攻击 | Certificate Pinning |
| 用 ECB 模式加密 | 相同明文→相同密文 | CBC/GCM |
| 弱随机数 (Math.random) | 可预测的 token | SecureRandom |
| 将密钥与密文一起存储 | 等于不加密 | 密钥管理服务 |

### 修复示范

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ✅ 正确：AES-256-GCM + 随机 Nonce
def encrypt_sensitive(data: bytes, key: bytes) -> tuple:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext   # nonce 与密文一起安全存储

# ❌ 错误：ECB 模式
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)  # ← 永远不要用 ECB！
```

**→ 详细分析见：[密码学基础](../cryptography/)**

---

## A03: 注入 (Injection)

**风险**：94% 的应用测试过某种形式的注入，CVSS 平均 7.8。2021 版将跨站脚本 (XSS) 合并到注入类别。

### 注入类型矩阵

| 注入类型 | 影响 | 检测难度 | 本书章节 |
|----------|------|----------|----------|
| **SQL 注入** | 数据库完全控制 | ⭐⭐ | [SSTI 攻击与防御](01-owasp-top10.md) |
| **命令注入** | 服务器 RCE | ⭐⭐ | [SSTI 攻击与防御](01-owasp-top10.md) |
| **LDAP 注入** | 认证绕过 | ⭐⭐⭐ | 本节 |
| **NoSQL 注入** | MongoDB/CouchDB 控制 | ⭐⭐ | 本节 |
| **XSS (跨站脚本)** | Cookie 窃取/会话劫持 | ⭐ | [SSTI 攻击与防御](01-owasp-top10.md) |
| **SSTI (模板注入)** | RCE, 信息泄露 | ⭐⭐⭐ | [SSTI 攻击与防御](01-owasp-top10.md) |
| **XXE (XML 外部实体)** | SSRF/DoS/文件读取 | ⭐⭐⭐ | [SSTI 攻击与防御](01-owasp-top10.md) |

### LDAP 注入

```python
# ❌ 危险：直接拼接 LDAP 查询
ldap_filter = f"(&(uid={username})(userPassword={password}))"
conn.search('dc=example,dc=com', ldap.SCOPE_SUBTREE, ldap_filter)
# 攻击输入: username = *)(uid=*))(|(uid=*
# → 绕过认证

# ✅ 修复：LDAP 转义
def ldap_escape(value):
    chars = {'\\': '\\5c', '*': '\\2a', '(': '\\28', ')': '\\29',
             '\0': '\\00', '/': '\\2f'}
    return ''.join(chars.get(c, c) for c in value)

safe_username = ldap_escape(username)
ldap_filter = f"(&(uid={safe_username})(userPassword=...))"
```

### NoSQL 注入

```javascript
// ❌ 危险：MongoDB $ne 操作符注入
app.post('/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,  // {"$ne": ""} → 绕过
        password: req.body.password   // {"$ne": ""} → 绕过
    });
});

// ✅ 修复：类型校验
if (typeof req.body.username !== 'string' || typeof req.body.password !== 'string') {
    return res.status(400).json({error: 'Invalid input'});
}
```

**→ 详细分析见：[SSTI 攻击与防御](01-owasp-top10.md) · [SSTI 攻击与防御](01-owasp-top10.md) · [SSTI 攻击与防御](01-owasp-top10.md)**

---

## A04: 不安全设计 (Insecure Design)

**风险**：2021 版新增类别——与"实现缺陷"不同，"不安全设计"在架构层面就埋下了安全漏洞。无法通过完美的编码来弥补不安全的设计。

### 典型不安全设计模式

| 模式 | 问题 | 真实案例 |
|------|------|----------|
| 密码重置不验证身份 | 任何人都能重置他人密码 | Facebook 2016 密码重置绕过 |
| 无限次登录尝试 | 暴力破解可行 | 2018 WannaCry 目标 |
| 一次性 token 不失效 | Token 重放攻击 | JWT 无状态过期问题 |
| 缺少速率限制 | API 滥用 | 2021 Twitch 数据泄露 |
| 过于复杂的权限模型 | RBAC 矩阵永远配不对 | 多数企业 SaaS |

### 修复：威胁建模

```python
# 密码重置的安全设计

class SecurePasswordReset:
    """安全密码重置流程"""

    def request_reset(self, email):
        user = User.query.filter_by(email=email).first()
        if not user:
            # ✅ 无论用户是否存在，统一返回
            return {"message": "If the email exists, a reset link has been sent"}

        # ✅ 生成密码学安全的随机 Token
        token = secrets.token_urlsafe(32)
        hashed_token = hashlib.sha256(token.encode()).hexdigest()

        # ✅ 设置有效期 (15 分钟)
        ResetToken.create(
            user_id=user.id,
            token_hash=hashed_token,
            expires_at=datetime.utcnow() + timedelta(minutes=15),
            used=False
        )

        send_email(user.email, f"Reset link: /reset?token={token}")
        return {"message": "If the email exists, a reset link has been sent"}

    def perform_reset(self, token_str, new_password):
        hashed = hashlib.sha256(token_str.encode()).hexdigest()
        reset = ResetToken.query.filter_by(
            token_hash=hashed, used=False
        ).filter(ResetToken.expires_at > datetime.utcnow()).first()

        if not reset:
            abort(400, "Invalid or expired token")

        reset.used = True  # ✅ Token 一次性使用
        reset.user.set_password(new_password)

        # ✅ 吊销所有现有会话 (强制重新登录)
        Session.query.filter_by(user_id=reset.user.id).delete()
        db.session.commit()

        log_security_event('PASSWORD_RESET', user_id=reset.user.id)
        return {"message": "Password reset successful"}
```

### 核心设计原则

1. **最小权限原则**：每个组件只拥有完成职责所需的最小权限
2. **纵深防御**：不依赖单一安全控制，多层防护
3. **默认安全**：出厂的默认配置是最安全的配置
4. **故障安全**：系统故障时进入安全状态，而非暴露数据
5. **不信任用户输入**：所有边界上的数据都是不可信的

---

## A05: 安全配置错误 (Security Misconfiguration)

**风险**：90% 的应用测试过某种形式的配置错误。从云存储桶到错误页面的信息泄露，这是最常见的 Web 安全缺陷。

### 配置错误速查

| 错误 | 攻击方式 | 危害 |
|------|----------|------|
| 默认凭据 (admin/admin) | Shodan 搜索→一键登录 | 完全控制 |
| 目录列表开启 (Directory Listing) | 浏览器访问 /uploads/ | 敏感文件暴露 |
| 详细错误页面 (DEBUG=True) | 故意触发错误→查看堆栈 | 源码/路径/数据库泄露 |
| S3 存储桶公开 | 直接 URL 访问 | 数据泄露 |
| CORS 配置过宽 (Access-Control-Allow-Origin: *) | CSRF+XSS | 跨域攻击 |
| HTTP 方法未限制 (PUT/DELETE 开放) | PUT /config → 修改配置 | 服务器篡改 |
| 未关闭不必要的 HTTP 头 | Server: Apache/2.4.1 | 版本信息泄露 |

### 自动化检测

```bash
# Nuclei 模板扫描安全配置
nuclei -u https://target.com -t exposures/configs/

# 检查常见配置错误
curl -I https://target.com | grep -i "server:\|x-powered-by"
curl https://target.com/.git/config       # Git 泄露
curl https://target.com/.env              # 环境变量泄露
curl https://target.com/robots.txt        # 敏感路径
curl https://target.com/sitemap.xml       # 站点结构

# S3 存储桶检查
aws s3 ls s3://company-backup --no-sign-request 2>/dev/null
curl https://company-backup.s3.amazonaws.com/
```

### 修复清单

```yaml
安全配置加固清单:
  Web 服务器:
    - 移除 Server / X-Powered-By 头
    - 禁用目录列表 (Options -Indexes)
    - 限制 HTTP 方法 (只允许 GET/POST/HEAD)
    - 启用 HSTS (Strict-Transport-Security)
    - 禁用 TRACE/TRACK 方法
    - 设置安全 Cookie 属性 (HttpOnly, Secure, SameSite)

  云服务:
    - S3 存储桶默认私有
    - IAM 最小权限策略
    - CloudTrail 日志审计
    - 安全组规则最小集

  应用:
    - DEBUG=False (生产环境)
    - 自定义错误页面 (不暴露堆栈)
    - CSRF 保护启用
    - CORS 精确配置 (指定具体域名)
    - CSP (Content-Security-Policy) 头配置
```

---

## A06: 易受攻击和过时的组件 (Vulnerable and Outdated Components)

**风险**：Log4Shell (CVE-2021-44228, CVSS 10.0) 就是这个风险的最佳注脚——一个亿级安装量的日志库在 8 年内未被发现漏洞。

### 检测方法

```bash
# 使用 OWASP Dependency-Check
dependency-check --project myapp --scan ./target/

# 使用 Syft 生成 SBOM，然后用 Grype 扫描
syft dir:. -o spdx-json | grype
grype sbom:app.cyclonedx.json --fail-on high

# npm audit
npm audit --json | grep -E '"severity":"(high|critical)"'

# pip-audit (Python)
pip-audit -r requirements.txt --fix

# OWASP Dependency-Track (持续监控)
docker run -d -p 8081:8080 dependencytrack/apiserver
```

### 修复策略

```yaml
组件安全策略:
  1. 盘点 (SBOM):
    - 为每个项目生成 SBOM
    - 记录直接依赖和传递依赖
    - 标注许可证和版本

  2. 监控:
    - 自动扫描 CVE (GitHub Dependabot / Snyk / OWASP DC)
    - 关注供应商安全公告
    - 加入 OSV (Open Source Vulnerabilities) 数据库

  3. 升级:
    - Critical: 24 小时内修复
    - High: 7 天内修复
    - Medium: 30 天内修复
    - Low: 下一版本修复

  4. 淘汰:
    - 移除未维护的组件
    - 减少依赖数量
    - 优先选择活跃维护的库
```

**→ 详细分析见：[SBOM 软件物料清单](../supply-chain-security/05-sbom.md) · [供应链安全](../supply-chain-security/)**

---

## A07: 身份认证失效 (Identification and Authentication Failures)

**风险**：从 2017 的 A02 降至 A07，但 CVSS 平均仍是所有类别中最高的 (8.8)。一旦认证被绕过，后续所有访问控制都形同虚设。

### 认证缺陷清单

| 缺陷 | 示例 | 修复 |
|------|------|------|
| 弱密码策略 | 允许 "password" | 最少 12 字符 + 复杂度 + 密码泄露检测 |
| 暴力破解无防护 | 无限次尝试 | 速率限制 + 账户锁定 + CAPTCHA |
| 凭证填充 (Credential Stuffing) | 撞库攻击 | MFA + 异常登录检测 |
| 会话固定 (Session Fixation) | 登录后 session 不变 | 登录后重新生成 session ID |
| 会话未过期 | 长期有效的 token | 15 分钟空闲超时 |
| 缺少 MFA | 单因素认证 | TOTP/WebAuthn/FIDO2 |

### 修复：安全登录系统

```python
from datetime import datetime, timedelta
import bcrypt, secrets, hashlib

class SecureAuthentication:
    """安全认证实现"""

    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)

    def login(self, username, password, ip_address, user_agent):
        user = User.query.filter_by(username=username).first()

        # 1. 检查账户锁定
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            log_security_event('LOGIN_BLOCKED_LOCKED', username=username)
            return {"error": "Account temporarily locked"}, 429

        # 2. 验证密码
        if not user or not bcrypt.checkpw(
            password.encode(), user.password_hash.encode()
        ):
            self._record_failed_attempt(user, ip_address)
            return {"error": "Invalid credentials"}, 401

        # 3. MFA 检查
        if user.mfa_enabled:
            # 返回 MFA 质询而非直接登录
            return {"mfa_required": True, "session_token": self._create_mfa_session(user)}

        # 4. 创建安全会话
        session = self._create_session(user, ip_address, user_agent)

        # 5. 记录安全事件
        log_security_event('LOGIN_SUCCESS', user_id=user.id, ip=ip_address)
        return {"token": session.token}

    def _record_failed_attempt(self, user, ip_address):
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= self.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.utcnow() + self.LOCKOUT_DURATION
                log_security_event('ACCOUNT_LOCKED', user_id=user.id)
            db.session.commit()

        # 记录 IP 级别失败尝试 (检测分布式暴力破解)
        cache.incr(f"failed_auth:{ip_address}")
        if cache.get(f"failed_auth:{ip_address}") > 20:
            log_security_event('BRUTE_FORCE_DETECTED', ip=ip_address)
```

**→ 详细分析见：[SSTI 攻击与防御](01-owasp-top10.md) · [IAM 高级场景](../iam/03-iam-advanced-scenarios.md)**

---

## A08: 软件和数据完整性失效 (Software and Data Integrity Failures)

**风险**：2021 版新增——覆盖不安全的 CI/CD 管道、未签名的更新、不安全的反序列化。

### 典型攻击

```
CI/CD 攻击链:
  开发者提交代码 → GitHub Actions 触发
  → 拉取依赖 (未验证完整性) → 恶意依赖注入
  → 构建产物 (未签名) → 部署到生产环境
  → 攻击者获得生产服务器控制权

SolarWinds (2020):
  攻击者注入恶意代码到 Orion 构建系统
  → 带签名的合法更新包含后门
  → 18000+ 客户受影响
```

### 修复

```yaml
CI/CD 完整性保护:
  1. 依赖完整性:
    - 锁定依赖版本 (package-lock.json / Pipfile.lock)
    - 验证依赖哈希
    - 使用私有镜像代理 (Nexus/Artifactory)
  
  2. 构建产物签名:
    - Cosign 镜像签名
    - Sigstore 无密钥签名
    - SBOM 随产物一同发布

  3. 管道安全:
    - GitHub Actions: 限制 Actions 权限
    - 审核第三方 Action
    - 环境隔离
```

```bash
# Cosign 镜像签名
cosign sign --key cosign.key myapp:v1.0.0

# 验证签名
cosign verify --key cosign.pub myapp:v1.0.0
```

**→ 详细分析见：[CI/CD 安全加固](../supply-chain-security/01-cicd-security.md)**

---

## A09: 安全日志记录和监控失败 (Security Logging and Monitoring Failures)

**风险**：平均 287 天才能发现一个安全漏洞 (IBM 2023)。没有日志和监控，攻击者可以长期潜伏不被发现。

### 关键指标

| 指标 | 目标值 |
|------|--------|
| MTTD (平均检测时间) | < 1 小时 (CISA BOD 22-01) |
| MTTR (平均响应时间) | < 4 小时 |
| IR 演练频率 | 每季度至少 1 次 |
| 日志保留期 | ≥ 90 天 (PCI DSS: 1 年) |

### 修复

```python
import logging
import json
from datetime import datetime

class SecurityLogger:
    """安全审计日志"""

    def __init__(self):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)

    def log_auth_event(self, event_type, username, ip, success):
        """认证事件日志"""
        self.logger.warning(json.dumps({
            'event': event_type,
            'username': username,
            'ip': ip,
            'success': success,
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'AUTH'
        }))

    def log_data_access(self, user_id, resource, action):
        """数据访问审计"""
        self.logger.info(json.dumps({
            'user_id': user_id,
            'resource': resource,
            'action': action,       # READ / WRITE / DELETE / EXPORT
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'DATA_ACCESS'
        }))

    def log_privilege_change(self, admin_id, target_user, change):
        """权限变更日志 (关键!)"""
        self.logger.critical(json.dumps({
            'admin_id': admin_id,
            'target_user': target_user,
            'change': change,        # GRANT_ADMIN / REVOKE_ACCESS
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'PRIVILEGE_CHANGE'
        }))
```

**→ 详细分析见：[SOC 安全运营](../soc/01-soc-building.md)**

---

## A10: 服务端请求伪造 (SSRF)

**风险**：2021 版新增——随着微服务和云架构的普及，SSRF 成为云环境中的顶级威胁。AWS IMDSv1 (169.254.169.254) 是 SSRF 的黄金目标。

### 攻击场景

```python
# ❌ 危险：URL 提取功能
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    return requests.get(url).text

# 攻击 1: 读取内部服务
# /fetch?url=http://admin.internal:8080/config

# 攻击 2: 窃取云凭证 (AWS)
# /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 攻击 3: 端口扫描内网
# /fetch?url=http://10.0.0.1:22  → Connection Refused → 端口开
# /fetch?url=http://10.0.0.1:23  → Timeout → 端口关
```

### 修复

```python
import ipaddress
import socket
from urllib.parse import urlparse

def is_safe_url(url):
    """SSRF 防护：验证 URL 安全性"""
    parsed = urlparse(url)

    # 1. 禁止非 HTTP 协议
    if parsed.scheme not in ('http', 'https'):
        return False, "Only HTTP/HTTPS allowed"

    # 2. 解析目标 IP
    hostname = parsed.hostname
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
    except:
        return False, "Cannot resolve hostname"

    # 3. 禁止内网/私有 IP
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False, "Internal IP blocked"

    # 4. 禁止 169.254.169.254 (云 metadata)
    if str(ip) == '169.254.169.254':
        return False, "Cloud metadata blocked"

    # 5. DNS 重绑定防护：两次解析，验证一致
    ip2 = ipaddress.ip_address(socket.gethostbyname(hostname))
    if ip != ip2:
        return False, "DNS rebinding detected"

    return True, "OK"
```

**→ 详细分析见：[SSTI 攻击与防御](01-owasp-top10.md)**

---

## 2021 版 vs 2017 版变化

| 2017 排名 | 2021 排名 | 风险 | 变化原因 |
|-----------|-----------|------|----------|
| A1: 注入 | A3: 注入 | 排名下降 | 框架自动防注入普及 |
| A2: 失效认证 | A7: 失效认证 | 大幅下降 | MFA 普及，标准库改进 |
| A3: 敏感数据泄露 | → A2: 加密失效 | 重命名扩展 | 不止数据泄露，覆盖密码学误用 |
| A4: XXE | 移出 Top 10 | 合并 | XML 使用率大幅下降 |
| A5: 访问控制失效 | A1: 访问控制失效 | 跃升第 1 | 云+API 时代手动授权模式大量出现 |
| A7: XSS | → A3: 注入 | 合并 | 与注入类别合并 |
| A8: 不安全反序列化 | → A8: 完整性失效 | 扩展 | 与 CI/CD、更新签名合并 |
| A10: 日志监控不足 | A9: 日志监控失败 | 位次不变 | 仍然严重 |
| 新增 | A4: 不安全设计 | 新增 | 架构级安全需求 |
| 新增 | A10: SSRF | 新增 | 云时代顶级威胁 |

---

## 各行业受 OWASP Top 10 影响热度

| 行业 | #1 风险 | 主要原因 |
|------|---------|----------|
| 金融 | A01 访问控制 | 复杂权限模型 + 多租户 |
| 医疗 | A02 加密失效 | 患者数据保护 (HIPAA) |
| 电商 | A03 注入 | 大量动态查询 |
| SaaS | A07 认证失效 | 多租户 + SSO 集成 |
| 云原生 | A10 SSRF | 微服务 + metadata 服务 |
| IoT | A06 过时组件 | 固件更新困难 |

---

## 检测工具

| 工具 | 覆盖范围 | 类型 |
|------|----------|------|
| **OWASP ZAP** | 全 10 类的自动化扫描 | DAST (免费) |
| **Burp Suite Scanner** | 商业级自动化扫描 | DAST (商业) |
| **SQLMap** | A03 注入专项 | 专项工具 |
| **Nuclei** | A05/A06 配置和组件 | 模板扫描 |
| **Dependency-Check** | A06 组件漏洞 | SCA |

---

*下一篇：[OWASP ASVS 标准解析](./04-owasp-asvs.md)*

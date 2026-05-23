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

### LDAP 注入
```ldap
# 利用：通过注入关闭现有过滤器
user*)(uid=*))(|(uid=*
# 实际构造的查询
(&(uid=user*)(uid=*))(|(uid=*)(password=test))
```

## A06: 易受攻击和过时的组件

### 依赖扫描最佳实践

| 扫描时机 | 工具 | 频率 |
|---------|------|------|
| 拉取请求 | Dependabot | 每次提交 |
| 构建阶段 | Trivy/Snyk | 每次构建 |
| 定时扫描 | OWASP DC | 每天 |
| 夜间扫描 | Grype | 每天 |

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

## A08: 软件和数据完整性失效

### CI/CD 管道安全
```yaml
# 检查依赖完整性
- name: Verify SBOM
  run: |
    sbom-tool verify --sbom sbom.spdx.json
    cosign verify-blob --signature image.sig attestation.json
```

## A09: 安全日志记录和监控失败

### 日志设计清单
- 所有认证事件（成功/失败）
- 权限变更操作
- 敏感数据访问
- 管理员操作
- 异常错误和异常
- 日志禁止包含：密码、Token、PII

## A10: SSRF 服务端请求伪造

```python
import ipaddress

# ❌ 简单域名单不抵
BLOCKED_HOSTS = ['169.254.169.254', 'localhost']

# ✅ 使用 IP 范围校验
def is_safe_url(url):
    parsed = urlparse(url)
    host = parsed.hostname
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        # 域名需 DNS 解析后再次检查
        resolved = socket.gethostbyname(host)
        ip = ipaddress.ip_address(resolved)
        return not (ip.is_private or ip.is_loopback)
```

*上一篇：[OWASP Top 10 (2021) 深度解析](01-owasp-top10.md)*

*下一篇：[OWASP Top 10 深潜：访问控制与加密](03-owasp-deep.md)*

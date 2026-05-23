# 安全代码审查实战

## 概述

代码审查是性价比最高的安全活动之一——在代码合入前发现漏洞，比生产环境修复便宜 30 倍。本章提供系统化安全代码审查方法论和检查清单。

---

## 1. 审查流程

### 1.1 分层审查法

```
安全代码审查分层:

  L1 架构层 (Architecture)
    → 数据流是否加密？
    → 认证授权机制是否一致？
    → 信任边界在哪？

  L2 组件层 (Component)
    → 第三方依赖有已知漏洞？
    → 使用的库函数是否安全？
    → 错误处理是否泄漏信息？

  L3 代码层 (Code)
    → 输入验证
    → 注入防御
    → 敏感数据处理

  L4 配置层 (Configuration)
    → 硬编码密钥？
    → 调试模式开启？
    → 不安全的默认值？
```

### 1.2 审查优先级

```python
class SecurityReviewPrioritizer:
    """根据变更风险评分确定审查优先级"""

    def calculate_risk(self, change):
        score = 0

        # 1. 认证/授权代码 → 最高优先级
        auth_patterns = ['login', 'auth', 'token', 'session', 'password',
                        'jwt', 'oauth', 'cookie', 'csrf', 'cors']
        for pattern in auth_patterns:
            if pattern in change.get('files', '').lower():
                score += 30
                break

        # 2. 数据访问代码 → 高优先级
        data_patterns = ['sql', 'database', 'query', 'orm', 'mongo',
                        'redis', 'elasticsearch', 'cursor']
        for pattern in data_patterns:
            if pattern in change.get('files', '').lower():
                score += 20
                break

        # 3. 用户输入处理 → 高优先级
        input_patterns = ['input', 'request', 'upload', 'file', 'import',
                         'parse', 'serialize', 'deserialize', 'xml']
        for pattern in input_patterns:
            if pattern in change.get('files', '').lower():
                score += 25
                break

        # 4. 加密/签名代码 → 高优先级
        crypto_patterns = ['crypto', 'encrypt', 'decrypt', 'hash',
                          'sign', 'cert', 'key', 'rsa', 'aes']
        for pattern in crypto_patterns:
            if pattern in change.get('files', '').lower():
                score += 25
                break

        # 5. 配置变更 → 中优先级
        config_patterns = ['.env', '.conf', '.config', '.yaml', '.yml',
                          'settings', 'properties', 'Dockerfile']
        for pattern in config_patterns:
            if pattern in change.get('files', '').lower():
                score += 15
                break

        # 6. 变更规模 → 大规模变更风险更高
        lines_changed = change.get('lines', 0)
        if lines_changed > 500:
            score += 15
        elif lines_changed > 100:
            score += 5

        return min(score, 100)

    def priority(self, score):
        if score >= 60:
            return 'CRITICAL — 必须安全审查'
        elif score >= 30:
            return 'HIGH — 建议安全审查'
        else:
            return 'LOW — 常规审查即可'
```

---

## 2. 常见漏洞检测

### 2.1 SQL 注入检测

```python
# ❌ 危险代码
def get_user_vulnerable(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

# ✅ 修复
def get_user_safe(username):
    query = "SELECT * FROM users WHERE username = %s"
    return db.execute(query, (username,))
```

```bash
# Grep 检测 SQL 注入风险
grep -rn "execute(f"\|execute(\".*%\|\execute('.*%" --include="*.py" .
grep -rn "executeQuery\|createQuery\|createNativeQuery" --include="*.java" .
grep -rn ".query(.*+" --include="*.js" --include="*.ts" .
```

### 2.2 命令注入检测

```python
# ❌ 危险代码
import os, subprocess

# Python: os.system / os.popen / subprocess with shell=True
os.system(f"ping -c 1 {user_input}")
subprocess.run(f"ls {user_input}", shell=True)

# ✅ 修复: 使用参数列表
subprocess.run(["ping", "-c", "1", user_input])
subprocess.run(["ls", user_input])
```

```bash
# Grep 检测命令注入风险
grep -rn "os.system(\|os.popen(\|subprocess.*shell=True\|exec(\|eval(" --include="*.py" .
grep -rn "Runtime.exec(\|ProcessBuilder" --include="*.java" .
grep -rn "child_process.exec(\|child_process.spawn(" --include="*.js" .
```

### 2.3 路径遍历检测

```python
# ❌ 危险代码
def read_file(filename):
    path = f"/var/www/uploads/{filename}"
    return open(path).read()
# 攻击: filename = "../../etc/passwd"

# ✅ 修复
import os

def read_file_safe(filename):
    # 1. 规范化路径
    safe_path = os.path.normpath(os.path.join('/var/www/uploads', filename))

    # 2. 验证路径在允许的目录内
    if not safe_path.startswith('/var/www/uploads/'):
        raise ValueError("Invalid path")

    # 3. 验证文件类型
    allowed_extensions = ['.txt', '.pdf', '.png']
    ext = os.path.splitext(filename)[1].lower()
    if ext not in allowed_extensions:
        raise ValueError("Invalid file type")

    return open(safe_path).read()
```

---

## 3. 供应链安全审查

```yaml
依赖审查检查清单:

  1. 版本检查:
    - 是否使用最新稳定版？
    - 是否有已知 CVE (CVE/CVSS >= 7)？
    - npm audit / pip-audit / OWASP Dependency Check

  2. 许可证检查:
    - 是否存在 GPL 传染性许可？
    - 许可证与项目兼容？

  3. 维护状态:
    - 最后更新时间 > 6 个月？ (风险信号)
    - 是否有多个贡献者？ (Bus Factor)
    - Issue/PR 响应速度？

  4. 供应链完整性:
    - 是否使用签名包？ (npm signature / PyPI sig)
    - 是否验证校验和？
    - 来源是否可信？ (typosquatting)
```

```bash
# 依赖安全审查工具链
# Node.js
npm audit --audit-level=high
npx snyk test

# Python
pip-audit
safety check

# Java (Maven)
mvn dependency-check:check -DfailBuildOnCVSS=7

# 通用
trivy fs --scanners vuln .
```

---

## 4. 审查检查清单

```yaml
安全代码审查检查清单 (OWASP Code Review Guide):

  认证 (Authentication):
    - [ ] 密码使用安全哈希存储 (bcrypt/argon2)
    - [ ] 登录失败限制 (防暴力破解)
    - [ ] 会话管理安全 (HttpOnly/Secure/SameSite)
    - [ ] 多因素认证支持

  授权 (Authorization):
    - [ ] 每个端点检查权限
    - [ ] 无直接对象引用 (IDOR)
    - [ ] 角色分离 (RBAC/ABAC)

  输入验证 (Input Validation):
    - [ ] 所有用户输入均验证/净化
    - [ ] 使用白名单而非黑名单
    - [ ] 类型检查 (int/float/string)
    - [ ] 长度限制

  输出编码 (Output Encoding):
    - [ ] HTML 输出上下文编码
    - [ ] JavaScript 上下文编码
    - [ ] SQL 参数化查询
    - [ ] URL 编码

  加密 (Cryptography):
    - [ ] 不使用自研加密算法
    - [ ] 使用强随机数生成器
    - [ ] 密钥不在代码中硬编码
    - [ ] TLS 1.2+ 强制

  日志与监控:
    - [ ] 审计日志包含用户操作
    - [ ] 日志不记录敏感数据 (密码/Token)
    - [ ] 异常告警推送安全团队
```

---

## 参考资源

- [OWASP Code Review Guide v2](https://owasp.org/www-project-code-review-guide/)
- [Google's Code Review Best Practices](https://google.github.io/eng-practices/review/)
- [Secure Code Review Checklist](https://github.com/softwaresecured/secure-code-review-checklist)

---

*上一篇：[Web/JS 安全编码](02-secure-coding-web.md)*

*下一篇：[安全编码清单与检查项](04-secure-coding-checklist.md)*

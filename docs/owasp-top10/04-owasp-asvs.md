# OWASP ASVS 标准深度解析

## 概述

OWASP ASVS (Application Security Verification Standard) 是 Web 应用安全验证的"工业标准"。它定义了三个安全验证级别，提供可量化的安全检查项，被 PCI DSS、NIST 等合规框架引用。

---

## 1. ASVS 三级验证体系

| 级别 | 描述 | 检查项数 | 适用场景 |
|------|------|----------|----------|
| **L1** | 基础安全 | 60+ | 所有应用最低要求 |
| **L2** | 标准安全 | 160+ | 处理敏感数据的应用 |
| **L3** | 高级安全 | 260+ | 金融/医疗/军事等关键应用 |

### 1.1 级别选择决策树

```
应用是否处理用户数据？
├── NO  → L1 基础验证
└── YES → 是否处理敏感数据 (PII/支付/医疗)？
    ├── NO  → L2 标准验证
    └── YES → 是否关键基础设施或高安全需求？
        ├── NO  → L2
        └── YES → L3 高级验证
```

---

## 2. ASVS V4.0 核心章节

### 2.1 V1 - 架构与设计 (3.5% 加权)

```yaml
V1 关键检查项:
  V1.1 (L1):
    - 验证所有应用组件和 API 已识别和文档化
    - 验证威胁建模已执行
  V1.2 (L2):
    - 验证认证/授权/输入验证在各层实现而非仅前端
  V1.4 (L2):
    - 验证正向安全模型 (白名单) 而非负向模型 (黑名单)
  V1.14 (L3):
    - 验证"永不信任第三方系统"原则 (零信任架构)
    - 所有上游数据视为不可信
```

### 2.2 V2 - 认证 (6.5% 加权)

```yaml
V2 关键检查项:
  V2.1 (L1):
    - 验证所有页面和 API 需要认证 (除非公开)
    - 验证密码最小长度 8 位

  V2.2 (L2):
    - 验证密码强度检查
    - 验证防暴力破解 (账户锁定/速率限制/CAPTCHA)
    - 验证防凭证填充 (检测 breached passwords)

  V2.5 (L2):
    - 验证凭据使用安全传输存储
    - 验证无硬编码凭据
    - 验证密码使用强自适应哈希 (bcrypt/argon2)

  V2.8 (L2):
    - 验证弱认证器 (SMS/邮件) 不作为唯一因素
    - 验证抗网络钓鱼的认证机制 (FIDO2/WebAuthn)

  V2.9 (L3):
    - 验证 MFA 的加密模块符合 FIPS 140-2 L2+
```

### 2.3 V4 - 访问控制 (6.5% 加权)

```yaml
V4 关键检查项:
  V4.1 (L1):
    - 验证应用强制访问控制规则在可信服务端

  V4.2 (L2):
    - 验证最小权限原则应用于所有用户/服务
    - 验证对象级授权 (非引用安全)
    - 验证功能级访问控制 (用户不能调用未授权功能)

  V4.3 (L3):
    - 验证访问控制决策基于用户会话和上下文
    - 验证管理员界面访问被严格限制
    - 验证 API 速率限制基于方法/客户端/地址
```

---

## 3. ASVS 集成实施

### 3.1 自动化验证管道

```yaml
# .github/workflows/asvs-compliance.yml
name: ASVS Compliance Check

on: [pull_request]

jobs:
  asvs-l1:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # V5: 输入验证
      - name: SAST - 注入检测
        run: |
          semgrep --config=p/sql-injection --error .
          semgrep --config=p/xss --error .

      # V2: 认证
      - name: 凭据扫描
        run: gitleaks detect --source . --verbose

      # V9: 通信安全
      - name: TLS 配置检查
        run: |
          sslscan api.example.com --no-failed

      # V14: 依赖安全
      - name: 依赖审计
        run: |
          npm audit --audit-level=high
          pip-audit --strict

      # 生成 ASVS 合规报告
      - name: ASVS Report
        run: |
          python scripts/asvs_report.py --level L1
```

### 3.2 ASVS 检查表生成器

```python
import yaml
from typing import Dict, List

class ASVSChecklist:
    """ASVS V4.0.3 自动化检查表"""

    def __init__(self, target_level='L2'):
        self.level = target_level
        self.requirements = self._load_requirements()
        self.checklist = []

    def _load_requirements(self):
        """加载 ASVS 要求定义"""
        return {
            'V2.1.1': {
                'level': 'L1',
                'description': '密码最小长度 8 位',
                'automated': True,
                'tool': 'password_policy_check.py'
            },
            'V2.1.2': {
                'level': 'L1',
                'description': '密码最大长度 >= 64 位',
                'automated': True,
                'tool': 'password_policy_check.py'
            },
            'V2.2.1': {
                'level': 'L2',
                'description': '抗凭证填充检查',
                'automated': True,
                'tool': 'hibp_check.py'
            },
            'V2.5.1': {
                'level': 'L2',
                'description': 'Argon2id 密码哈希',
                'automated': True,
                'tool': 'hash_algorithm_check.py'
            },
            'V4.1.1': {
                'level': 'L1',
                'description': '服务端强制访问控制',
                'automated': False,  # 需要人工审查
                'tool': None
            },
            'V4.1.3': {
                'level': 'L2',
                'description': '最小权限强制',
                'automated': False,
                'tool': None
            },
            'V5.1.1': {
                'level': 'L1',
                'description': '输出编码防 XSS',
                'automated': True,
                'tool': 'csp_header_check.py'
            }
        }

    def generate_checklist(self):
        """生成验证检查表"""

        for req_id, req in self.requirements.items():
            level_rank = {'L1': 1, 'L2': 2, 'L3': 3}
            target_rank = level_rank[self.level]
            req_rank = level_rank[req['level']]

            if req_rank <= target_rank:
                item = {
                    'id': req_id,
                    'description': req['description'],
                    'level': req['level'],
                    'status': 'PENDING',
                    'automated': req['automated'],
                    'tool': req['tool'],
                    'evidence': None,
                    'reviewer': None
                }
                self.checklist.append(item)

        return self.checklist

    def generate_markdown_report(self):
        """生成 Markdown 报告"""
        report = f"# ASVS {self.level} 验证报告\n\n"
        report += f"检查时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        report += f"总检查项: {len(self.checklist)}\n\n"

        # 按结果分组
        passed = [c for c in self.checklist if c['status'] == 'PASSED']
        failed = [c for c in self.checklist if c['status'] == 'FAILED']
        pending = [c for c in self.checklist if c['status'] == 'PENDING']

        report += f"## 摘要\n"
        report += f"- ✅ 通过: {len(passed)}\n"
        report += f"- ❌ 未通过: {len(failed)}\n"
        report += f"- ⏳ 待验证: {len(pending)}\n\n"

        return report
```

---

## 4. ASVS 与合规映射

| ASVS 版本 | PCI DSS 4.0 | NIST 800-63 | ISO 27001 | OWASP Top 10 |
|-----------|-------------|-------------|-----------|--------------|
| V1 架构 | 6.5 | - | A.14.2 | A05 Security Misconfig |
| V2 认证 | 8.2-8.3 | 5.1.1 | A.9.4 | A07 Identification Failures |
| V4 访问控制 | 7.1-7.2 | 6.1 | A.9.1 | A01 Broken Access Control |
| V5 验证与编码 | 6.5.1 | - | A.14.2 | A03 Injection / XSS |
| V7 日志 | 10.2 | - | A.12.4 | A09 Logging Failures |

---

## 参考资源

- [OWASP ASVS v4.0.3](https://owasp.org/www-project-application-security-verification-standard/)
- [ASVS 合规工具集](https://github.com/OWASP/ASVS)
- [PCI DSS 与 ASVS 映射](https://www.pcisecuritystandards.org/)

---

*上一篇：[OWASP 深度解析](./03-owasp-deep.md)*

*下一篇：[OWASP Mobile Top 10 实战](05-owasp-mobile-top10.md)*

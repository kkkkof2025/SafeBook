# SOC 2 审计实战指南

> 从准备到通过 SOC 2 Type II 的完整流程

---

## SOC 2 概述

SOC 2 (Service Organization Control 2) 是由 AICPA 制定的服务组织内部控制审计标准。Type I 评估某个时间点的控制设计，Type II 评估控制在一段时间（通常 6-12 个月）内的运行有效性。

### 五大信任服务标准 (TSC)

| 标准 | 含义 | 示例控制 |
|------|------|---------|
| **Security** | 防止未授权访问 | IAM、防火墙、加密 |
| **Availability** | 系统持续可用 | SLA、DR、冗余 |
| **Confidentiality** | 机密信息保护 | 加密、NDA、访问控制 |
| **Processing Integrity** | 处理准确完整 | 输入验证、QA、变更管理 |
| **Privacy** | 个人信息处理合规 | 隐私政策、数据最小化、DSR |

---

## 1. 审计准备阶段

### 时间线
```
Phase 1: 范围确定 (1-2 个月)
├── 选择审计范围 (Security 必选，其他可选)
├── 选择审计机构 (AICPA CPA Firm)
└── 选择审计周期 (6 or 12 months)

Phase 2: 控制设计 (2-3 个月)
├── 差距分析 (当前状态 vs SOC 2 要求)
├── 设计/修改控制措施
└── 实施 + 文档

Phase 3: 控制运行 (3-6 个月)
├── 控制稳定运行
├── 收集证据 (每个控制的操作证据)
└── 内部审计测试

Phase 4: 外部审计 (2-3 个月)
├── 审计入场
├── 证据呈递
└── 审计报告
```

---

## 2. 关键控制领域

### 访问控制
```yaml
SOC 2 访问控制清单:
  - [ ] 入职/离职流程: 账号创建+权限分配/及时禁用
  - [ ] 季度访问审查: 所有系统账号每 90 天重新审核
  - [ ] MFA 强制: 所有生产系统访问需 MFA
  - [ ] 密码策略: ≥12 位 + 90 天轮换 + 历史不可复用
  - [ ] 权限最小化: 仅授予岗位所需的权限
  - [ ] 特权账号管理: PAM 解决方案 + 审计录像
```

### 变更管理
```yaml
变更管理流程:
  1. 变更请求 (Change Request)
     - 描述 + 风险评估 + 回滚方案
  2. 代码审查 (至少一人审批)
  3. 自动化测试 (单元+集成+安全)
  4. 变更审批 (Change Advisory Board)
  5. 部署 (灰度 → 全量)
  6. 部署后验证 (监控 + 人工确认)
```

### 事件响应
```
事件响应流程 (SOC 2 要求):
  ┌──────────┐   ┌──────────┐   ┌──────────┐
  │  检测    │ → │  分级    │ → │  响应    │
  └──────────┘   └──────────┘   └──────────┘
        ↓              ↓              ↓
  告警/报告       P1-P4 分级   遏制/清除/恢复
                                      ↓
                               ┌──────────┐
                               │事后复盘  │
                               └──────────┘
```

---

## 3. 证据收集

```python
class SOCTwoEvidenceCollector:
    """自动化 SOC 2 证据收集"""

    def collect_access_review_evidence(self):
        """季度访问审查证据"""
        evidence = {
            'control_id': 'AC-03',
            'period': 'Q3-2024',
            'review_date': datetime.utcnow(),
            'reviewer': 'security-team@company.com',
            'systems_reviewed': [
                {'name': 'AWS IAM', 'users_reviewed': 347, 'revoked': 12},
                {'name': 'GitHub', 'users_reviewed': 89, 'revoked': 3},
                {'name': 'Jira', 'users_reviewed': 186, 'revoked': 7},
            ],
            'attachments': ['aws-iam-report.csv', 'github-audit-log.pdf']
        }
        return evidence

    def collect_change_management_evidence(self, change_id):
        """变更管理证据"""
        return {
            'control_id': 'CM-01',
            'change_id': change_id,
            'request_date': '2024-09-15',
            'risk_assessment': 'Low - Standard dependency update',
            'code_review_by': ['alice', 'bob'],
            'deploy_date': '2024-09-17',
            'post_deploy_verification': 'Passed - All metrics green'
        }
```

---

## 4. 常见审计发现

| 发现 | 严重程度 | 修复建议 |
|------|---------|---------|
| 没有离职流程文档 | High | 建立正式 offboarding checklist |
| 季度访问审查未执行 | High | 自动化 IAM 审计 + 提醒 |
| 缺少安全培训记录 | Medium | LMS 自动记录培训完成 |
| 变更无审批记录 | Medium | Jira 工作流强制审批 |
| 备份未定期测试 | Medium | 季度恢复演练 |
| 密码策略不一致 | Low | 统一至 IdP (Okta/Azure AD) |

---

## 5. 自动化合规工具

| 工具 | 功能 | 适用 |
|------|------|------|
| Vanta | 自动化 SOC 2/ISO 27001 监控 | 企业首选 |
| Drata | 自动化合规 + 证据收集 | 企业首选 |
| Secureframe | 合规自动化 | 中小企业 |
| Lacework | 云安全+合规 | 云原生 |
| Wazuh | 开源 SIEM + 合规模块 | 开源选择 |

---

*上一篇：[PCI DSS 合规详解](03-pci-dss.md)*

*下一篇：[等保 2.0 深度](05-dengbao.md)*

# SOC 2 合规实践

## 概述

SOC 2 (Service Organization Control 2) 由 AICPA 制定，是 SaaS 和云服务提供商最重要的安全合规认证。它基于五大信任服务标准（TSC），验证服务组织对客户数据的安全、可用性、处理完整性、机密性和隐私保护能力。

---

## 1. SOC 2 五大信任服务标准

### 1.1 标准详解

| 标准 | 英文 | 控制项数 | 核心理念 |
|------|------|----------|----------|
| 安全 | Security | 9 | 保护系统和数据免受未授权访问 |
| 可用性 | Availability | 3 | 系统按照 SLA 可用 |
| 处理完整性 | Processing Integrity | 5 | 系统处理完整、准确、及时 |
| 机密性 | Confidentiality | 2 | 机密信息受到保护 |
| 隐私 | Privacy | 8 | 个人信息按照隐私声明处理 |

### 1.2 安全标准（CC 系列）通用控制项

SOC 2 2017 版使用 CC (Common Criteria) 系列作为通用标准：

```
CC1: COSO 内部控制框架
CC2: 信息与沟通
CC3: 风险评估
CC4: 监控活动
CC5: 控制活动（逻辑访问、变更管理、物理安全等）
CC6: 逻辑与物理访问控制
CC7: 系统操作
CC8: 变更管理
CC9: 风险缓解
```

---

## 2. 控制措施落地

### 2.1 CC6 - 访问控制

```yaml
访问控制矩阵:
  用户生命周期:
    - 入职: 自动创建账户，基于角色分配权限
    - 转岗: 权限重新评估，72小时内调整
    - 离职: 24小时内禁用，7天内删除
    - 休眠: 90天未登录自动禁用

  认证要求:
    - MFA 强制启用（所有生产环境）
    - 密码策略: 最小12位，复杂度验证
    - 密码轮换: 90天（服务账户60天）
    - 失败锁定: 5次错误锁定30分钟

  权限审查:
    - 季度权限审查（所有生产系统）
    - 特权账户月度审查
    - 自动化权限异常检测

  职责分离:
    developer != deployer
    auditor != auditee
    security_engineer != operator
```

### 2.2 CC8 - 变更管理

```python
class ChangeManagement:
    def validate_change(self, change_request):
        """SOC 2 变更管理控制验证"""

        validations = []

        # 1. 风险分级
        risk_level = self.assess_risk(change_request)
        validations.append(f"风险等级: {risk_level}")

        # 2. 审批要求
        if risk_level == 'HIGH':
            required_approvers = ['CAB', 'Security Lead', 'System Owner']
        elif risk_level == 'MEDIUM':
            required_approvers = ['Team Lead', 'Peer Reviewer']
        else:
            required_approvers = ['Peer Reviewer']

        approvers = self.get_approvals(change_request.id)
        for req in required_approvers:
            assert req in approvers, f"缺少审批: {req}"

        # 3. 测试验证
        if change_request.has_test_plan:
            test_results = self.run_test_plan(change_request.test_plan)
            assert test_results.passed, "测试未通过"

        # 4. 回滚方案
        assert change_request.rollback_plan, "缺少回滚方案"

        # 5. 变更窗口
        if not self.is_within_change_window():
            assert risk_level == 'LOW', "非变更窗口禁止中高风险变更"

        return True
```

### 2.3 CC7 - 系统操作

```bash
# 安全监控要求
monitoring_requirements:
  基础设施:
    - CPU/内存/磁盘利用率 > 85% → 告警
    - 错误率 > 1% → 告警
    - 证书到期 < 30天 → 告警

  安全事件:
    - 暴力破解检测（5分钟内 > 10次失败）
    - 异常登录（新地点/新设备）
    - 特权操作审计
    - 数据导出监控（> 1000 条记录）

  容量管理:
    - 每季度容量规划评审
    - 自动扩缩容策略
    - 数据库连接池监控
```

---

## 3. SOC 2 审核类型

### 3.1 Type I vs Type II

| 维度 | Type I | Type II |
|------|--------|---------|
| 时间点 | 特定日期 | 持续期间（通常 6-12 个月） |
| 评估内容 | 控制措施设计的合理性 | 控制措施运行的有效性 |
| 难度 | 较低 | 较高 |
| 价值 | 证明有控制 | 证明控制有效 |
| 周期 | 一次性的快照 | 需要持续累积证据 |

### 3.2 Type II 证据要求

```markdown
## SSO 访问控制 Type II 证据包

| 控制目标 | 控制活动 | 频率 | 证据类型 |
|----------|----------|------|----------|
| 用户访问审查 | 季度权限审查 | 每季度 | 审查报告 + 审批邮件 |
| 离职账户注销 | 24h 内禁用 | 事件驱动 | 票证记录 + 时间戳 |
| MFA 强制启用 | 100% 覆盖 | 持续 | 系统配置截图 + 日志 |
| 特权会话审计 | 全量记录 | 持续 | 堡垒机日志 |
```

---

## 4. 与其他框架的映射

### 4.1 SOC 2 ↔ ISO 27001 对照

| SOC 2 标准 | ISO 27001 Annex A |
|-----------|-------------------|
| CC6.1 (逻辑访问) | A.9.1, A.9.2, A.9.4 |
| CC8.1 (变更管理) | A.12.1.2, A.14.2 |
| CC7.1 (检测与监控) | A.12.4, A.16 |
| CC7.2 (监控异常) | A.12.4.1 |
| CC7.4 (事件响应) | A.16 |

---

## 5. 自动化合规工具

### 5.1 合规即代码

```python
import boto3
from datetime import datetime, timedelta

class SOC2ComplianceCheck:
    """SOC 2 合规自动化检查"""

    def __init__(self):
        self.iam = boto3.client('iam')
        self.config = boto3.client('config')
        self.findings = []

    def check_mfa(self):
        """CC6.1: MFA 启用检查"""
        users = self.iam.list_users()['Users']
        for user in users:
            mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])
            if not mfa_devices['MFADevices']:
                self.findings.append({
                    'control': 'CC6.1',
                    'severity': 'HIGH',
                    'resource': user['UserName'],
                    'finding': 'MFA 未启用',
                    'remediation': '强制启用 MFA'
                })

    def check_password_rotation(self):
        """CC6.1: 密码轮换检查"""
        users = self.iam.list_users()['Users']
        for user in users:
            if 'PasswordLastUsed' in user:
                last_changed = user.get('PasswordLastChanged', datetime.min)
                if datetime.now(last_changed.tzinfo) - last_changed > timedelta(days=90):
                    self.findings.append({
                        'control': 'CC6.1',
                        'severity': 'MEDIUM',
                        'resource': user['UserName'],
                        'finding': '密码超过 90 天未轮换'
                    })

    def check_cloudtrail(self):
        """CC7.2: 审计日志启用检查"""
        trails = boto3.client('cloudtrail').describe_trails()
        for trail in trails['trailList']:
            if not trail.get('IsMultiRegionTrail'):
                self.findings.append({
                    'control': 'CC7.2',
                    'severity': 'HIGH',
                    'resource': trail['Name'],
                    'finding': 'CloudTrail 未启用多区域'
                })

    def generate_report(self) -> str:
        """生成合规报告"""
        self.check_mfa()
        self.check_password_rotation()
        self.check_cloudtrail()

        report = "# SOC 2 合规检查报告\n\n"
        report += f"检查时间: {datetime.now().isoformat()}\n"
        report += f"发现数量: {len(self.findings)}\n\n"

        high = [f for f in self.findings if f['severity'] == 'HIGH']
        medium = [f for f in self.findings if f['severity'] == 'MEDIUM']

        report += f"高风险: {len(high)}\n"
        report += f"中风险: {len(medium)}\n"
        return report
```

---

## 6. 持续合规运营

### 6.1 合规日历

| 活动 | 频率 | 负责人 |
|------|------|--------|
| 访问权限审查 | 每季度 | IT Security |
| 风险评估更新 | 每半年 | CISO |
| 漏洞扫描 | 每月 | Security Engineering |
| 渗透测试 | 每年 | 外部审计 |
| 安全意识培训 | 每季度 | HR + Security |
| 备份恢复测试 | 每季度 | Infrastructure |
| DR/BCP 演练 | 每年 | Business Continuity |
| 政策评审更新 | 每年 | Compliance |

---

## 参考资源

- [AICPA SOC 2 官方指南](https://www.aicpa.org/soc4so)
- [SOC 2 合规检查清单](https://www.aicpa-cima.com/)
- [Cloud Security Alliance CAIQ](https://cloudsecurityalliance.org/artifacts/consensus-assessments-initiative-questionnaire-v4/)

---

*上一篇：[合规框架与实践](./01-compliance-audit.md)*
*下一篇：[ISO 27001 实施指南](./03-iso27001-implementation.md)*

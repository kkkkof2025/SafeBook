# ISO 27001 信息安全管理体系

## 概述

ISO 27001 是国际上最广泛认可的信息安全管理标准。它不是技术检查清单，而是一个管理体系框架——"你不需要特定的防火墙品牌，但你需要证明你有管理风险的过程"。

---

## 1. ISO 27001 框架

### 1.1 核心结构

```
ISO 27001:2022 结构:

  0. 简介
  1. 范围
  2. 规范性引用文件
  3. 术语和定义
  4. 组织环境 — 理解组织及其环境、利益相关方
  5. 领导力 — 方针、角色、职责
  6. 策划 — 风险评估、风险处置
  7. 支持 — 资源、能力、意识、沟通
  8. 运行 — 风险评估与处置实施
  9. 绩效评价 — 监控、审计、管理评审
  10. 改进 — 不符合项、持续改进

  Annex A — 信息安全控制 (93 项控制，2022 版)
```

### 1.2 Annex A 控制域 (2022)

| 控制域 | 控制项数 | 关键内容 |
|--------|----------|----------|
| A.5 组织控制 | 37 | 策略/角色/供应商/事件管理 |
| A.6 人员控制 | 8 | 筛选/意识/纪律 |
| A.7 物理控制 | 14 | 周界/设备/布线 |
| A.8 技术控制 | 34 | 端点/IAM/加密/网络安全 |

---

## 2. 实施路径

### 2.1 PDCA 循环

```
Plan (策划):
  → 定义 ISMS 范围
  → 制定信息安全方针
  → 风险评估 (识别资产/威胁/脆弱性)
  → 风险处置计划

Do (实施):
  → 实施 Annex A 控制措施
  → 安全意识培训
  → 事件响应流程

Check (检查):
  → 内部审计
  → 管理评审
  → 渗透测试/漏洞评估

Act (改进):
  → 纠正措施
  → 预防措施
  → 持续改进
```

### 2.2 风险评估方法

```python
# ISO 27001 风险评估简化模型

class ISORiskAssessment:
    """ISO 27001 风险评估"""

    def __init__(self):
        self.assets = []
        self.threats = []
        self.vulnerabilities = []

    def calculate_risk(self, asset_value, threat_likelihood, vulnerability_severity):
        """
        风险 = 资产价值 × 威胁可能 × 脆弱性严重度
        """
        risk_score = asset_value * threat_likelihood * vulnerability_severity

        if risk_score >= 12:
            level = 'HIGH'
            action = '必须处置'
        elif risk_score >= 6:
            level = 'MEDIUM'
            action = '应当处置'
        else:
            level = 'LOW'
            action = '可接受'

        return {
            'score': risk_score,
            'level': level,
            'action': action
        }

    def risk_treatment_options(self, risk):
        """风险处置四选项"""
        return {
            'avoid': '停止相关活动',
            'transfer': '购买网络安全保险',
            'mitigate': f'实施控制措施降低风险至 {risk["score"] // 2}',
            'accept': '管理层接受残余风险'
        }
```

---

## 3. 文档体系

```yaml
ISO 27001 文档金字塔:

  L1 - 方针 (Policy):
    - 信息安全方针
    - 适用性声明 (SoA)

  L2 - 流程 (Process):
    - 风险管理流程
    - 事件管理流程
    - 变更管理流程
    - 访问控制流程

  L3 - 规程 (Procedure):
    - 备份与恢复规程
    - 密码管理规程
    - 供应商安全评估规程
    - 安全审计规程

  L4 - 记录 (Record):
    - 风险评估记录
    - 内部审计报告
    - 管理评审会议纪要
    - 安全意识培训记录
```

---

## 4. 认证流程

```
ISO 27001 认证时间线:

  阶段 1 - 文件审查 (1-2 天):
    审核机构审查 ISMS 文件
    确认范围、方针、风险评估

  阶段 2 - 现场审核 (3-5 天):
    验证控制实施情况
    员工访谈
    证据收集

  认证决定:
    通过 → 颁发证书 (有效期 3 年)
    有条件通过 → 整改后颁发
    不通过 → 重新审核

  监督审核 (每年):
    部分控制域抽样审核
    持续合规验证

  再认证 (每 3 年):
    完整重新审核
```

---

## 5. 与其他框架的对比

| 维度 | ISO 27001 | SOC 2 | 等保 2.0 |
|------|-----------|-------|----------|
| 性质 | 管理标准 | 审计报告 | 法律要求 |
| 范围 | ISMS | 服务组织 | 信息系统 |
| 认证 | 是 | 是 (报告) | 是 (测评) |
| 频率 | 3 年 | 1 年 | 2 年 (三级) |
| 国际认可 | ★★★★★ | ★★★★ | ★★ (中国特有) |

---

## 参考资源

- [ISO/IEC 27001:2022 标准](https://www.iso.org/standard/27001)
- [ISO 27001 实施指南](https://www.iso27001security.com/)
- [NIST CSF 与 ISO 27001 映射](https://www.nist.gov/cyberframework)

---

*下一篇：[SOC 2 合规](../compliance-audit/04-soc2-compliance.md)*

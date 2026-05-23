# 全球数据保护法规深度对比

## 全球立法全景

```
                    ┌─────────────────┐
                    │   中国 PIPL      │
                    │  "告知-同意"     │
                    │  数据本地化      │
                    └────────┬────────┘
                             │
  ┌─────────────┐   ┌───────┴───────┐   ┌─────────────┐
  │  EU GDPR    │   │   全球合规     │   │ US CCPA/CPRA│
  │  最严格框架  │   │   交叉辖区     │   │  州级立法    │
  │  域外管辖   │   │   冲突解决     │   │  Opt-out模式 │
  └─────────────┘   └───────────────┘   └─────────────┘
```

---

## 1. 欧盟 GDPR

### 七项核心原则
| 原则 | 要求 | 技术实现 |
|------|------|---------|
| 合法性、公正性、透明性 | 处理必须有法律依据 | Privacy Notice + Cookie 横幅 |
| 目的限制 | 仅用于收集时声明的目的 | 数据库 Schema 级隔离 |
| 数据最小化 | 只收集必需数据 | 字段级权限控制 |
| 准确性 | 数据必须保持最新 | 数据校验 + 用户自助修改 |
| 存储限制 | 到期自动删除 | 定时 TTL 清理任务 |
| 完整性与保密性 | 防止未授权处理 | 加密 + 访问控制 + 审计 |
| 问责制 | 能证明合规 | 数据处理活动记录 (RoPA) |

### 数据主体权利
- **被遗忘权**: 个人可要求删除所有数据（含备份）
- **数据可携带权**: 以机器可读格式（JSON/CSV）导出
- **访问权**: 免费获取数据处理副本
- **纠正权**: 修改不准确数据
- **拒绝权**: 拒绝直接营销和自动化决策

### 处罚力度
- 最高 **2000 万欧元** 或 **全球年营收 4%**（取较高者）
- 数据泄露 **72 小时**内必须通知监管机构
- 处理儿童数据需 **16 岁以下监护人同意**

---

## 2. 中国《个人信息保护法》(PIPL)

### 核心要求
| 要求 | 细节 | 与技术实现 |
|------|------|-----------|
| 告知-同意 | 处理前明确告知 + 取得同意 | Consent Management Platform |
| 最小必要 | 仅收集最小必要信息 | 字段白名单 + 动态脱敏 |
| 单独同意 | 敏感数据/跨境传输需单独弹窗 | 分类分级 + 审批流 |
| 自动化决策 | 需提供拒绝选项 | Opt-out Toggle |
| 数据本地化 | CIIO 数据必须境内存储 | 中国区独立部署 |
| 跨境传输 | 安全评估/认证/标准合同 | 数据出境评估系统 |

### PIPL vs GDPR 关键差异

| 维度 | GDPR | PIPL |
|------|------|------|
| 合法基础 | 6 种法律基础 | 强调告知-同意 + 法定义务 |
| 数据本地化 | 无强制要求 | CIIO 强制本地化 |
| 跨境传输 | 充分性认定/SCC/BCR | 安全评估 + 标准合同 + 认证 |
| 处罚上限 | 2000 万欧元 / 4% | 5000 万人民币 / 5% |
| 执法机构 | 各国 DPA | 网信办 (CAC) |
| 生效日期 | 2018-05-25 | 2021-11-01 |

---

## 3. 美国 CCPA/CPRA

### 适用范围
- 年营收 **> $2500 万**，**OR**
- 购买/出售/共享 **10 万+** 消费者/家庭信息，**OR**
- **50%+** 收入来自出售个人信息

### 消费者权利
```yaml
CCPA 权利:
  - 知情权: 企业必须告知收集的个人信息类别
  - 删除权: 消费者可要求删除
  - 选择退出: 拒绝出售/共享个人信息
  - 纠正权 (CPRA 新增): 纠正不准确信息
  - 限制使用 (CPRA 新增): 限制敏感个人信息使用
  - 非歧视: 行使权利不会导致服务降级

CPRA 新增:
  - 设立加州隐私保护局 (CPPA) 作为独立执法机构
  - 敏感个人信息 (SSPI) 的额外保护
  - 高风险处理需年度网络安全审计
```

---

## 4. 亚太地区法规速览

| 国家/地区 | 法规 | 关键特点 |
|-----------|------|---------|
| 日本 | APPI | 匿名化处理信息可自由使用 |
| 韩国 | PIPA | 亚洲最严，伪名化数据例外 |
| 新加坡 | PDPA | 10 项义务，数据可携带权 |
| 印度 | DPDP 2023 | 新法案，设有数据保护委员会 |
| 澳大利亚 | Privacy Act 1988 | 2022 年修订，大幅提高处罚 |
| 巴西 | LGPD | 受 GDPR 启发，域外管辖 |

---

## 5. 合规实施策略

```python
# 多法规数据分类引擎
class DataComplianceClassifier:
    """根据数据类型和目标法规，自动判定合规要求"""

    REGULATIONS = {
        'GDPR': {
            'personal_data': ['encrypt_at_rest', 'pseudonymize', 'consent_required'],
            'sensitive_data': ['explicit_consent', 'dpia_required', 'encrypt_transit'],
            'child_data': ['parental_consent', 'age_verification'],
        },
        'PIPL': {
            'personal_data': ['consent_required', 'data_localization', 'minimal_collection'],
            'sensitive_data': ['separate_consent', 'necessity_justification', 'impact_assessment'],
            'biometric_data': ['explicit_consent', 'purpose_limitation_only'],
        },
        'CCPA': {
            'personal_data': ['opt_out_mechanism', 'disclosure_required'],
            'sensitive_data': ['opt_in_required', 'limit_use_disclosure'],
        }
    }

    def get_requirements(self, data_type, regulations=['GDPR', 'PIPL']):
        requirements = set()
        for reg in regulations:
            reqs = self.REGULATIONS.get(reg, {}).get(data_type, [])
            requirements.update(reqs)
        return list(requirements)
```

---

## 6. 处罚案例

| 年份 | 企业 | 法规 | 罚金 | 原因 |
|------|------|------|------|------|
| 2021 | Amazon | GDPR | €7.46 亿 | 未经同意使用 Cookie 跟踪 |
| 2023 | Meta | GDPR | €12 亿 | 向美国非法传输用户数据 |
| 2022 | 滴滴 | PIPL | ¥80.26 亿 | 违法收集个人信息 |
| 2022 | Sephora | CCPA | $120 万 | 未披露数据出售 |

---

*上一篇：[数据脱敏与隐私保护技术](01-data-masking.md)*

*下一篇：[数据泄露应急响应](03-data-breach-response.md)*

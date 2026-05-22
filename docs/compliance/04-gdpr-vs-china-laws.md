# GDPR 与中国数据法律对比

## 概述

GDPR（通用数据保护条例）是全球最严格的数据隐私法律。理解 GDPR 与中国《数据安全法》《个人信息保护法》的异同，对于跨国企业的合规团队至关重要。

---

## 1. 法律框架对比

| 维度 | GDPR (欧盟) | 数据安全法 (中) | 个人信息保护法 (中) |
|------|------------|---------------|-------------------|
| 生效日期 | 2018-05-25 | 2021-09-01 | 2021-11-01 |
| 保护对象 | 个人数据 | 数据（广义） | 个人信息 |
| 适用范围 | 域外适用 | 域内 + 损害国家安全 | 域内 + 域外处理中国境内自然人 |
| 罚款上限 | 2000万€ 或 营收 4% | 1000万元 | 5000万元 或 营收 5% |
| 数据主体权利 | 8 项权利 | 无明确定义 | 7 项权利 (类似 GDPR) |
| DPO 要求 | 强制 (特定条件) | 重要数据处理者需指定责任人 | 达到国家规定数量需指定 |
| 跨境传输 | SCC / BCR / 充分性认定 | 安全评估 / SCC / 认证 | 安全评估 / SCC / 认证 |

---

## 2. 关键制度对比

### 2.1 数据处理的合法性基础

```yaml
GDPR (Art. 6): 六项合法性基础
  1. 数据主体同意 (Consent)
  2. 合同履行必要
  3. 法定义务
  4. 保护重大利益 (Vital Interests)
  5. 公共利益/官方授权
  6. 合法利益 (Legitimate Interest) ← 中国法律中无此基础

中国个保法 (第 13 条): 七项合法性基础
  1. 取得个人同意
  2. 合同所必需
  3. 法定职责/义务
  4. 突发公共卫生事件
  5. 公共利益 (新闻报道/舆论监督)
  6. 已合法公开的个人信息
  7. 法律、行政法规规定的其他情形

关键差异:
  - GDPR 有"合法利益"基础 → 中国法无 (更严格)
  - 中国法有"已合法公开"基础 → GDPR 视为特殊类别
```

### 2.2 同意要求

```python
class ConsentValidator:
    """GDPR vs 中国个保法 同意要求对比"""

    def validate_gdpr_consent(self, consent_record):
        """GDPR 有效同意 7 要素"""
        checks = {
            'freely_given': consent_record.get('forced') == False,
            'specific': consent_record.get('purpose') is not None,
            'informed': consent_record.get('notice_given') == True,
            'unambiguous': consent_record.get('passive') == False,
            'explicit': consent_record.get('sensitive_data') == False or
                       consent_record.get('explicit_action') == True,
            'withdrawable': consent_record.get('withdraw_mechanism') is not None,
            'separate': consent_record.get('bundled') == False,
        }
        return all(checks.values()), checks

    def validate_pipl_consent(self, consent_record):
        """中国个保法 有效同意要求"""
        checks = {
            'informed': consent_record.get('notice_given') == True,
            'voluntary': consent_record.get('forced') == False,
            'explicit_for_sensitive': (
                consent_record.get('sensitive_data') == False or
                consent_record.get('separate_consent') == True
            ),
            'specific_purpose': consent_record.get('purpose') is not None,
            'children_under_14': (
                consent_record.get('age') != '<14' or
                consent_record.get('guardian_consent') == True
            ),
        }
        return all(checks.values()), checks

# 关键差异:
# - GDPR 要求"明确同意"处理敏感数据
# - 中国个保法要求处理敏感个人信息需"单独同意"
# - 中国个保法对 <14 岁儿童有监护人同意要求
```

### 2.3 数据跨境传输

```yaml
跨境传输合规路径对比:

  GDPR:
    1. 充分性认定 (Adequacy Decision)
       → 欧盟委员会认定第三国保护水平充分
       → 目前: 日本/韩国/英国/等 14 国 (不含中国)

    2. 标准合同条款 (SCCs)
       → 2021 新版 SCCs
       → 需完成传输影响评估 (TIA)

    3. 约束性公司规则 (BCRs)
       → 跨国公司内部规则
       → DPA 审批 (6-18 个月)

    4. 例外情形
       → 明确同意 / 合同必要 / 公共利益

  中国个保法:
    1. 安全评估 (网信办)
       → 适用: CIIO / 重要数据 / >100万个人信息
       → 审批时间: 45+60 工作日

    2. 标准合同 (SCCs)
       → 2023 版标准合同
       → 备案制 (网信办)

    3. 个人信息保护认证
       → 适用: 跨国公司员工数据等场景

    4. 其他法定条件
       → 法律/行政法规规定
```

---

## 3. 企业合规实践

### 3.1 统一合规框架

```yaml
跨国企业数据合规框架:

  基础层 (适用于所有司法管辖区):
    - 数据分类分级
    - 数据目录 (Data Inventory)
    - 数据流映射 (Data Flow Mapping)
    - 隐私政策 (Privacy Notice)

  GDPR 层:
    - DPO 任命 (如需要)
    - DPIA (数据保护影响评估)
    - RoPA (处理活动记录)
    - 72 小时数据泄露通知

  中国法律层:
    - 数据安全负责人指定
    - 等保测评 + 数据安全风险评估
    - 数据出境安全评估 (如需要)
    - 个人信息保护影响评估 (个性化推送/敏感处理/委托/出境/公开)

  CCPA/CPRA 层 (加州):
    - 隐私通知 + Opt-out 机制
    - 消费者权利 (访问/删除/纠正/可携)
    - 数据共享协议 (服务提供商合同)
```

### 3.2 自动化合规工具

```bash
# 合规检查自动化
# 1. OneTrust / TrustArc — 商业隐私管理平台
# 2. 开源: Data Privacy Toolkit

# 检查 AWS 资源的加密合规性
aws configservice get-compliance-details-by-config-rule \
    --config-rule-name "encrypted-volumes" \
    --compliance-types "NON_COMPLIANT"

# 检查 Azure 存储账户的 TLS 版本
az storage account list \
    --query "[?minimumTlsVersion < 'TLS1_2'].{Name:name, TLS:minimumTlsVersion}"

# 检查 GCP 服务账号密钥年龄
gcloud iam service-accounts keys list \
    --iam-account="sa@project.iam.gserviceaccount.com" \
    --format="table(name, validAfterTime)"
```

---

## 参考资源

- [GDPR 全文](https://gdpr-info.eu/)
- [中国个人信息保护法](http://www.npc.gov.cn/)
- [EDPB Guidelines](https://edpb.europa.eu/our-work-tools/general-guidance/gdpr-guidelines-recommendations-best-practices_en)
- [IAPP 隐私法律比较工具](https://iapp.org/resources/comparison/)

---

*上一篇：[PCI-DSS 实施](03-pci-dss-implementation.md)*

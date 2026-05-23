# 数据安全法深度解读

## 概述

《中华人民共和国数据安全法》（DSL）自 2021 年 9 月 1 日起施行，与《网络安全法》《个人信息保护法》共同构成中国数据治理的"三驾马车"。本章深入解读关键条款对企业的实际影响。

---

## 1. 数据分类分级制度

### 1.1 三级分类框架

```
国家核心数据:
  ├─ 国家安全相关数据
  ├─ 国民经济命脉数据
  ├─ 重大民生数据
  └─ 公共利益数据
  → 严格保护

重要数据:
  ├─ 未公开的政府数据
  ├─ 关键行业数据 (>1000万个人信息)
  ├─ 基因/地理/矿产资源数据
  └─ 关键信息基础设施数据
  → 重点保护

一般数据:
  ├─ 企业经营管理数据
  ├─ 已公开的数据
  └─ 普通业务数据
  → 依法保护
```

### 1.2 重要数据识别指南

```yaml
重要数据识别标准 (GB/T 41479-2022):
  规模维度:
    - 涉及 >= 100 万人的个人信息
    - 涉及 >= 1000 万人的基础信息
    - 基因数据 >= 10 万份

  领域维度:
    - 核心地理信息 (精度优于 1:50000)
    - 关键基础设施运行数据
    - 国家经济数据 (未公开)
    - 国防科研生产数据

  影响维度:
    - 数据泄露可能导致国家安全风险
    - 数据泄露可能造成重大经济损失
    - 影响社会公共利益
```

---

## 2. 数据处理义务

### 2.1 数据处理者安全义务

```python
class DataSecurityComplianceChecker:
    """数据安全法合规检查"""

    def __init__(self):
        self.checks = [
            'data_classification',
            'risk_assessment',
            'access_control',
            'encryption',
            'audit_log',
            'incident_response',
            'cross_border',
            'data_retention',
            'third_party',
            'training'
        ]

    def check_data_classification(self, data_inventory):
        """
        第二十一条: 数据分类分级
        企业必须建立数据分类分级制度
        """
        classification_levels = set()
        for asset in data_inventory:
            classification_levels.add(asset.get('classification', 'unclassified'))

        required_levels = {'general', 'important', 'core'}
        missing = required_levels - classification_levels

        return {
            'check': 'data_classification',
            'compliant': len(missing) == 0,
            'missing_levels': list(missing),
            'evidence': f"已分类 {len(data_inventory)} 项数据资产"
        }

    def check_cross_border_transfer(self, transfer_logs):
        """
        第三十六条: 数据出境安全评估
        - 重要数据出境须经安全评估
        - 个人信息出境须达成标准合同或认证
        """
        violations = []
        for transfer in transfer_logs:
            if transfer['data_type'] == 'important':
                if not transfer.get('cac_assessment_id'):
                    violations.append({
                        'transfer_id': transfer['id'],
                        'issue': '重要数据出境未经网信办安全评估',
                        'severity': 'CRITICAL'
                    })

            if transfer['data_type'] == 'personal_info' and transfer['count'] >= 1_000_000:
                if not transfer.get('cac_assessment_id'):
                    violations.append({
                        'transfer_id': transfer['id'],
                        'issue': '超100万个人信息出境未经评估',
                        'severity': 'CRITICAL'
                    })

        return violations

    def check_risk_monitoring(self, vulnerability_scans):
        """
        第二十二条: 数据安全风险监测
        企业必须建立全流程数据安全管理制度
        """
        last_scan_days = (datetime.now() - vulnerability_scans['last_scan']).days
        return {
            'check': 'risk_monitoring',
            'compliant': last_scan_days <= 90,
            'days_since_last_scan': last_scan_days,
            'action_required': '立即启动安全风险扫描' if last_scan_days > 90 else None
        }
```

### 2.2 数据安全事件响应

```yaml
数据安全事件响应流程 (第四十六条):

  T+0h  发现事件
    - 启动应急响应小组
    - 初步评估影响范围
    - 立即止损措施

  T+2h  事件定级
    - 特别重大: 1亿人以上个人信息泄露
    - 重大: 1000万人以上
    - 较大: 100万人以上
    - 一般: 100万人以下

  T+4h  政府部门报告
    - 特别重大/重大: 8小时内报告网信办
    - 较大/一般: 24小时内报告
    - 涉嫌犯罪: 同时报告公安机关

  T+8h  通知受影响个人
    - 告知事件基本情况
    - 告知可能的影响
    - 告知已采取的补救措施
    - 告知个人可以采取的减轻措施

  T+24h 事件报告提交
    - 事件发生时间/地点
    - 涉及数据类型和数量
    - 可能造成的影响
    - 已采取的处置措施
```

---

## 3. 跨境数据合规

### 3.1 三条出境路径

```yaml
数据出境合规路径 (《数据出境安全评估办法》):
  
  路径一: 安全评估 (CAC评估)
    适用场景:
      - 重要数据出境 (任何数量)
      - 处理 >= 100 万人的个人信息处理者出境个人信息
      - 累计出境 >= 10 万人的个人信息
      - 累计出境 >= 1 万人的敏感个人信息
    有效期: 2 年，可申请延长

  路径二: 标准合同 (SCC)
    适用场景:
      - 非关键信息基础设施运营者
      - 处理 < 100 万人的个人信息
      - 累计出境 < 10 万人的个人信息
      - 累计出境 < 1 万人的敏感个人信息
    生效方式: 签订后向省级网信办备案 (10日内)

  路径三: 认证
    适用场景:
      - 集团内部数据跨境传输
      - 通过认证的专业机构保护
    认证机构: 中国网络安全审查技术与认证中心 (CCRC)
```

### 3.2 安全评估自检清单

```python
class CrossBorderTransferSelfAssessment:
    """数据出境安全自评估"""

    def assess(self, transfer_scenario):
        result = {
            'scenario': transfer_scenario['name'],
            'requires_cac_assessment': False,
            'requirements': []
        }

        # 判断是否需要 CAC 评估
        triggers = []

        # 触发条件 1: 重要数据
        if transfer_scenario['data_type'] == 'important':
            triggers.append('涉及重要数据')

        # 触发条件 2: >= 100 万个人信息
        if (transfer_scenario.get('personal_info_processed', 0) >= 1_000_000
            and transfer_scenario.get('personal_info_exported', 0) > 0):
            triggers.append('处理 >= 100 万人个人信息')

        # 触发条件 3: >= 10 万个人信息出境
        if transfer_scenario.get('personal_info_exported', 0) >= 100_000:
            triggers.append('累计出境 >= 10 万人个人信息')

        # 触发条件 4: >= 1 万敏感个人信息出境
        if transfer_scenario.get('sensitive_info_exported', 0) >= 10_000:
            triggers.append('累计出境 >= 1 万人敏感个人信息')

        result['requires_cac_assessment'] = len(triggers) > 0
        result['triggers'] = triggers
        result['required_documents'] = self._required_documents(result)

        return result

    def _required_documents(self, assessment):
        docs = ['数据出境合同 (Data Transfer Agreement)']
        if assessment['requires_cac_assessment']:
            docs.extend([
                '数据出境风险自评估报告',
                '法律文件 (数据处理协议)',
                '数据安全影响评估 (DPIA)'
            ])
        else:
            docs.append('个人信息出境标准合同 (SCC)')
        return docs
```

---

## 4. 罚则与执法

### 4.1 处罚阶梯

| 违规类型 | 罚款 (组织) | 罚款 (直接负责人) | 附加处罚 |
|----------|-------------|-------------------|----------|
| 一般违规 | 5-50 万元 | 1-10 万元 | 责令改正 |
| 拒不改正 | 5-50 万元 | 1-10 万元 | 暂停业务/吊销执照 |
| 严重违规 | 50-200 万元 | 5-20 万元 | 同上 |
| 造成大量数据泄露 | 200-1000 万元 | 5-20 万元 | 暂停业务/吊销执照 |
| 违反国家核心数据 | 最高 1000 万 + 营业额 5% | 5-20 万元 | 吊销执照 + 刑事责任 |

### 4.2 典型执法案例

```markdown
## 数据安全法执法案例

### 案例 1: 某出行平台 (2022)
- 违规: 未经安全评估，向境外提供重要数据
- 处罚: 罚款 80.26 亿元 (含网络安全法/个人信息保护法)
- 教训: 上市公司境外 IPO 前必须完成数据安全审查

### 案例 2: 某银行 (2023)
- 违规: 数据分类分级制度缺失，客户数据未加密存储
- 处罚: 罚款 200 万元 + 高管警告
- 教训: 金融行业数据分类分级是强制要求

### 案例 3: 某科技公司 (2024)
- 违规: 未及时报告数据泄露事件
- 处罚: 罚款 50 万元 + 暂停 App 新用户注册 30 天
- 教训: 数据泄露后 8 小时内报告是法定义务
```

---

## 5. 数据安全官 (DSO) 职责

```yaml
数据安全负责人 (第四十六条):
  定位:
    - 直接向最高管理层汇报
    - 独立行使数据安全监督权
    - 重要数据处理者必须设立

  核心职责:
    - 制定并实施数据安全管理制度
    - 组织开展数据安全教育培训
    - 定期开展数据安全风险自评估
    - 建立并维护数据安全应急预案
    - 向主管部门报告数据安全事件

  关键能力:
    - 了解数据安全法律法规
    - 具备数据安全技术知识
    - 熟悉行业数据安全标准
    - 有项目管理协调能力
```

---

## 参考资源

- [中华人民共和国数据安全法](http://www.npc.gov.cn/)
- [数据出境安全评估办法](http://www.cac.gov.cn/)
- [GB/T 41479-2022 重要数据识别指南](https://www.tc260.org.cn/)

---

*上一篇：[网络安全法执法实践](./03-cybersecurity-law-enforcement.md)*

*下一篇：[个人信息保护法合规实践](05-personal-information-law.md)*

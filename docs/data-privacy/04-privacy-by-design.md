# Privacy by Design（隐私设计）深度

## 概述

隐私设计不是合规检查项，而是一种工程哲学：将隐私保护作为系统架构的核心约束，而非事后的补丁。GDPR 第 25 条将其写入法律，违反可罚全球营收 4%。

---

## 1. 七大原则的系统实践

```yaml
隐私设计决策矩阵:

  原则 1 — 主动而非被动 (Proactive not Reactive):
    传统: 泄露发生后通知用户、聘请危机公关
    PbD:  加密存储 + 访问审计 + 异常检测
    实现: Vault/HSM 密钥管理 + SIEM 审计

  原则 2 — 默认隐私 (Privacy as Default):
    传统: 用户需要手动关闭数据共享（Opt-out）
    PbD:  用户需要主动开启数据共享（Opt-in）
    实现: 最小权限数据收集 + 自动过期

  原则 3 — 嵌入设计 (Privacy Embedded):
    传统: 产品上线后由安全团队"加隐私层"
    PbD:  架构评审时隐私是验收标准
    实现: Threat Model 包含隐私威胁，架构图标注数据流

  原则 4 — 全功能 (Full Functionality):
    传统: "要实现功能 X 就必须收集所有数据"
    PbD:  零知识证明、联邦学习、同态加密
    实现: 服务端盲化处理

  原则 5 — 全生命周期 (End-to-End Security):
    传统: 只在传输时加密（TLS）
    PbD:  采集→传输→存储→使用→共享→销毁 全程保护
    实现: 传输 TLS + 存储加密 + 使用 Tokenization + 销毁凭证化

  原则 6 — 可见与透明 (Visibility and Transparency):
    传统: 隐私政策是没人读的长文档
    PbD:  仪表盘、实时审计、数据访问通知
    实现: 数据目录 + 用户数据仪表板

  原则 7 — 以用户为中心 (Respect for User):
    传统: "我们为你优化了体验（顺便收集了数据）"
    PbD:  用户控制粒度（数据下载/删除/限制处理）
    实现: DSAR API (Data Subject Access Request)
```

---

## 2. DPIA（数据保护影响评估）

### 2.1 何时需要 DPIA

```python
class DPIATrigger:
    """DPIA 触发条件评估"""

    REQUIRES_DPIA = [
        # GDPR 第 35 条: 高风险处理必须 DPIA
        'systematic_profiling',       # 自动化画像分析
        'large_scale_sensitive',      # 大规模特殊类别数据
        'systematic_monitoring',      # 系统化监控公共场所
        'new_technology',             # 使用新技术可能带来新风险
        'children_data',              # 处理儿童数据
        'biometric_data',             # 生物特征数据
        'cross_border_transfer',      # 跨境传输（高风险地区）
    ]

    def evaluate(self, project):
        triggers = []
        if project.uses_ai_profiling():
            triggers.append('systematic_profiling')
        if project.processes_biometric_data():
            triggers.append('biometric_data')
        if project.target_users_include_children():
            triggers.append('children_data')

        return {
            'dpia_required': len(triggers) > 0,
            'triggers': triggers,
            'risk_level': 'HIGH' if len(triggers) >= 2 else 'MEDIUM'
        }
```

### 2.2 DPIA 模板

```yaml
数据保护影响评估 (DPIA) 模板:

  1. 项目描述:
    名称: [项目名称]
    目的: [业务目的]
    数据控制者: [公司/部门]
    数据处理者: [第三方服务商]

  2. 数据流映射:
    采集点: [Web表单/API/传感器]
    传输: [TLS 1.3, 点对点加密]
    存储: [AES-256-GCM, 1年保留策略]
    访问: [RBAC, 最少10人可访问]
    共享: [仅EU境内, SCC合同]

  3. 风险评估:
    | 风险 | 可能性 | 影响 | 缓解措施 |
    |------|--------|------|----------|
    | 未授权访问 | 中 | 高 | MFA+RBAC+审计 |
    | 数据泄露 | 低 | 极高 | 加密+DLP |
    | 过度收集 | 低 | 中 | 数据最小化评审 |

  4. 签署:
    数据保护官: [签名] 日期:
    CISO: [签名] 日期:
```

---

## 3. 隐私增强技术 (PET)

### 3.1 差分隐私（Differential Privacy）

```python
import numpy as np
from scipy.stats import laplace

class DifferentialPrivacy:
    """
    差分隐私核心实现
    ε (epsilon): 隐私预算（越小越保护隐私，但噪声越大）
    """

    def __init__(self, epsilon=1.0):
        self.epsilon = epsilon

    def laplace_mechanism(self, query_result, sensitivity=1.0):
        """
        拉普拉斯机制
        在查询结果上添加拉普拉斯噪声
        """
        scale = sensitivity / self.epsilon
        noise = np.random.laplace(0, scale)
        return query_result + noise

    def gaussian_mechanism(self, query_result, delta=1e-5, sensitivity=1.0):
        """
        高斯机制 (用于 (ε, δ)-差分隐私)
        """
        sigma = (sensitivity / self.epsilon) * np.sqrt(2 * np.log(1.25 / delta))
        noise = np.random.normal(0, sigma)
        return query_result + noise

    def sparse_vector_technique(self, queries, threshold, budget=1.0):
        """
        稀疏向量技术: 回答"哪些查询超出了阈值？"
        仅消耗超出阈值的查询的隐私预算
        """
        results = []
        remaining_budget = budget

        for query in queries:
            # 添加噪声判断是否超出阈值
            noisy_threshold = threshold + self.laplace_mechanism(
                0, sensitivity=2/budget
            )
            noisy_result = query + self.laplace_mechanism(
                0, sensitivity=2/budget
            )

            if noisy_result > noisy_threshold:
                # 超出阈值 → 消耗预算 + 发布结果
                remaining_budget -= budget / len(queries)
                results.append((query, True))
            else:
                results.append((query, False))

        return results

# 使用示例: 公布公司各部门的薪资统计
dp = DifferentialPrivacy(epsilon=0.5)  # 严格隐私保护
actual_avg_salary = 85000
private_result = dp.laplace_mechanism(actual_avg_salary, sensitivity=10000)
# 输出: ~85234（添加噪声后的近似值，无法推导任何个体薪资）
```

### 3.2 K-匿名性与 L-多样性

```python
class KAnonymity:
    """
    K-匿名: 每个"组合"至少有 K 个个体

    例: 发布医疗数据
    原始: [年龄=35, 邮编=10001, 疾病=HIV]
    K=2 匿名: [年龄=30-39, 邮编=100**, 疾病=HIV]
    """

    def generalize_age(self, age):
        """年龄泛化"""
        if age < 20: return "<20"
        elif age < 40: return "20-39"
        elif age < 60: return "40-59"
        else: return "60+"

    def suppress_zip(self, zipcode):
        """邮编抑制"""
        return zipcode[:3] + "**"

    def check_k_anonymity(self, dataset, quasi_identifiers, k=5):
        """检查是否满足 K-匿名"""
        from collections import Counter

        # 按准标识符分组
        groups = Counter()
        for record in dataset:
            key = tuple(record[qi] for qi in quasi_identifiers)
            groups[key] += 1

        # 所有组是否 >= k
        violations = {key: count for key, count in groups.items()
                     if count < k}

        return {
            'k_anonymous': len(violations) == 0,
            'total_groups': len(groups),
            'violations': len(violations),
            'max_risk': 1 / k  # 重识别最大风险
        }
```

---

## 4. 数据生命周期实践

```yaml
数据生命周期隐私控制:

  采集阶段:
    - [ ] 仅采集必要字段（数据最小化清单）
    - [ ] 用户知情同意记录
    - [ ] 数据分类标签（PII/SPI/内部/公开）

  使用阶段:
    - [ ] 访问控制（最小权限 + JIT）
    - [ ] 用途限制（不允许超出采集时声明的用途）
    - [ ] 自动过期（30天未访问的数据归档）

  共享阶段:
    - [ ] 数据共享评估（DPIA）
    - [ ] 数据脱敏后共享
    - [ ] 共享合同（SCC/DPA）

  销毁阶段:
    - [ ] 保留策略强制执行
    - [ ] 密码学擦除（加密密钥销毁）
    - [ ] 销毁证明（审计日志）
```

---

## 参考资源

- [GDPR 第 25 条: Data protection by design and by default](https://gdpr-info.eu/art-25-gdpr/)
- [Privacy by Design — Ann Cavoukian (7 Foundational Principles)](https://iapp.org/resources/article/privacy-by-design-the-7-foundational-principles/)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)
- [Google Differential Privacy Library](https://github.com/google/differential-privacy)

---

*上一篇：[数据脱敏技术](03-data-masking.md)*

# 个人信息保护法合规实践

## 概述

《个人信息保护法》（PIPL）于 2021 年 11 月 1 日施行，被称为"中国版 GDPR"但某些方面更为严格。对违法行为的处罚可达上一年度营业额的 5%，严重者可吊销营业执照。

---

## 1. PIPL 核心原则

### 1.1 七大原则

```
告知-同意 (Art 13-17)
    ↓
目的限制 (Art 6)
    ↓
最小必要 (Art 6)
    ↓
公开透明 (Art 7)
    ↓
保证质量 (Art 8)
    ↓
安全保护 (Art 9)
    ↓
问责制 (Art 66)
```

### 1.2 合法性基础对照 (PIPL vs GDPR)

| 合法性基础 | PIPL | GDPR |
|-----------|------|------|
| 个人同意 | Art 13(1) | Art 6(1)(a) |
| 合同必需 | Art 13(2) | Art 6(1)(b) |
| 法定义务 | Art 13(3) | Art 6(1)(c) |
| 紧急情况 | Art 13(4) | Art 6(1)(d) |
| 公共利益 | Art 13(5) | Art 6(1)(e) |
| 公开信息 | Art 13(6) | Art 6(1)(f) |
| 法律行政法规规定 | Art 13(7) | — |

---

## 2. 同意管理

### 2.1 同意机制实现

```typescript
// 隐私同意管理 SDK
interface ConsentRecord {
  userId: string;
  purpose: PurposeType;
  grantTime: Date;
  consentVersion: string;
  method: 'explicit' | 'implicit' | 'bundled';
  ipAddress: string;
  userAgent: string;
}

type PurposeType =
  | 'account_service'       // 账号服务
  | 'personalized_content'  // 个性化内容
  | 'marketing'            // 营销
  | 'location'             // 位置服务
  | 'third_party_share'    // 第三方共享
  | 'sensitive_data'       // 敏感个人信息
  | 'cross_border'         // 跨境传输
  | 'automated_decision';  // 自动化决策

class ConsentManager {
  private consents: Map<string, ConsentRecord[]> = new Map();

  /**
   * PIPL 第 14 条: 单独同意
   * - 敏感个人信息处理
   * - 向第三方提供
   * - 跨境传输
   * - 公开个人信息
   * 必须有独立的勾选框，不得捆绑
   */
  async requestSeparateConsent(
    userId: string,
    purposes: PurposeType[]
  ): Promise<ConsentResult> {
    const results: ConsentResult[] = [];

    for (const purpose of purposes) {
      // 每个需要"单独同意"的目的独立弹窗
      const consent = await this.showConsentDialog({
        purpose,
        title: this.getConsentTitle(purpose),
        description: this.getConsentDescription(purpose),
        isSeparate: true,  // 独立勾选框
        isPreChecked: false  // 不得预选
      });

      results.push(consent);
    }

    return results;
  }

  /**
   * PIPL 第 15 条: 撤回同意
   * - 撤回不应影响之前基于同意的处理
   * - 撤回方式不得比授予方式更困难
   */
  async withdrawConsent(userId: string, purpose: PurposeType) {
    const record = this.consents.get(userId)?.find(c => c.purpose === purpose);
    if (!record) return;

    // 标记为撤回
    record.status = 'withdrawn';

    // 停止相关处理
    await this.stopDataProcessing(userId, purpose);

    // 如需删除已收集的数据
    await this.deleteCollectedData(userId, purpose);

    // 通知第三方停止处理
    await this.notifyThirdParties(userId, purpose);
  }

  /**
   * PIPL 第 24 条: 自动化决策
   * - 不得对个人在交易价格上实行不合理差别待遇
   * - 应提供不针对个人特征的选项
   */
  async automatedDecisionOptOut(userId: string) {
    // 为用户提供通用选项（非个性化）
    return {
      genericRecommendations: await this.getNonPersonalizedContent(),
      personalizedOptOut: true,
      differentialPricing: false  // 禁止价格歧视
    };
  }
}
```

### 2.2 隐私政策模板

```markdown
# 个人信息保护政策

## 1. 我们收集哪些信息
### 必要信息 (基本功能)
- 手机号码 (账号注册)
- 设备标识 (安全防护)

### 可选信息 (改善服务)
- 位置信息
- 通讯录
- 相册

## 2. 我们如何使用信息
| 目的 | 信息类型 | 法律基础 |
|------|----------|----------|
| 账号服务 | 手机号码 | 合同必需 |
| 个性化推荐 | 浏览记录 | 同意 |
| 营销推送 | 手机号码 | 同意 |

## 3. 单独同意事项
- [ ] 我同意向第三方提供个人信息
- [ ] 我同意跨境传输个人信息
- [ ] 我同意处理敏感个人信息
- [ ] 我同意进行自动化决策

## 4. 您的权利
- 查阅/复制个人信息
- 更正不准确信息
- 删除个人信息
- 撤回同意
- 注销账户
- 拒绝自动化决策

## 5. 数据安全保护
- 加密存储 (AES-256)
- 访问控制 (最小权限)
- 审计日志 (全流程记录)

## 6. 联系我们
- 个人信息保护负责人: dpo@example.com
- 投诉渠道: 12377 (中国互联网违法和不良信息举报中心)
```

---

## 3. 数据主体权利实现

### 3.1 权利清单

```python
class DataSubjectRights:
    """PIPL 数据主体权利实现"""

    def __init__(self, db_connection):
        self.db = db_connection

    # 第 44 条: 知情权 & 决定权
    def get_processing_info(self, user_id):
        return {
            'collected_categories': self._get_collected_categories(user_id),
            'processing_purposes': self._get_purposes(user_id),
            'retention_period': self._get_retention(user_id),
            'third_party_recipients': self._get_recipients(user_id),
            'cross_border_transfers': self._get_transfers(user_id)
        }

    # 第 45 条: 查阅权 & 复制权 & 转移权
    def export_personal_data(self, user_id, format='json'):
        """个人信息可携带权 - 15 日内响应"""

        data = self.db.query("""
            SELECT * FROM user_data WHERE user_id = %s
        """, (user_id,))

        # 结构化、通用、机器可读格式
        if format == 'json':
            return json.dumps(data, indent=2)
        elif format == 'csv':
            return self._to_csv(data)

    # 第 46 条: 更正权
    def correct_personal_data(self, user_id, corrections):
        """请求更正不准确的信息"""

        for field, value in corrections.items():
            # 验证请求者身份
            self._verify_requester(user_id)

            # 执行更正
            self.db.execute("""
                UPDATE user_data SET {} = %s WHERE user_id = %s
            """.format(field), (value, user_id))

            # 通知接收过该信息的第三方
            recipients = self._get_recipients(user_id)
            for recipient in recipients:
                self._notify_correction(recipient, user_id, field, value)

    # 第 47 条: 删除权
    def delete_personal_data(self, user_id, retention_exceptions=None):
        """删除个人信息"""

        exceptions = retention_exceptions or []
        allowed_exceptions = ['legal_obligation', 'contract_performance', 'public_health']

        # 检查例外
        for exc in exceptions:
            if exc not in allowed_exceptions:
                raise ComplianceViolation(f"非法保留例外: {exc}")

        # 删除或匿名化
        self.db.execute("""
            DELETE FROM user_data WHERE user_id = %s
            AND category NOT IN %s
        """, (user_id, tuple(exceptions)))

        # 通知第三方删除
        self._notify_third_party_deletion(user_id)
```

### 3.2 响应时间要求

| 请求类型 | 法律依据 | 响应时限 | 延期上限 |
|----------|----------|----------|----------|
| 查阅/复制 | 第 45 条 | 15 天 | +15 天 |
| 更正 | 第 46 条 | 15 天 | +15 天 |
| 删除 | 第 47 条 | 15 天 | +15 天 |
| 数据可携带 | 第 45 条 | 15 天 | +15 天 |
| 撤回同意 | 第 15 条 | 即时 | — |

---

## 4. 影响评估 (PIPIA)

### 4.1 触发条件

```python
class PIPIA_Trigger:
    """个人信息保护影响评估触发条件 (PIPL 第 55 条)"""

    triggers = [
        'sensitive_personal_info',   # 处理敏感个人信息
        'automated_decision_making', # 自动化决策
        'third_party_entrust',      # 委托处理
        'third_party_provide',      # 向第三方提供
        'cross_border_transfer',    # 跨境传输
        'public_disclosure',        # 公开个人信息
        'high_risk_processing'      # 其他高风险处理
    ]

    def should_perform_pipia(self, processing_activity):
        """评估是否需要 PIPIA"""

        triggers_matched = []

        # 敏感个人信息
        if any(t in ['biometric', 'health', 'finance', 'location_tracking',
                      'religion', 'political_view', 'minors_under_14']
               for t in processing_activity['data_categories']):
            triggers_matched.append('sensitive_personal_info')

        # 跨境传输
        if processing_activity.get('cross_border'):
            triggers_matched.append('cross_border_transfer')

        # 自动化决策
        if processing_activity.get('automated_decision'):
            triggers_matched.append('automated_decision_making')

        return {
            'pipia_required': len(triggers_matched) > 0,
            'triggers': triggers_matched,
            'deadline': '完成评估后方可开始处理'
        }
```

### 4.2 PIPIA 报告要素

```markdown
# 个人信息保护影响评估报告

## 基础信息
- 评估日期: 2024-XX-XX
- 评估团队: DPO + 技术负责人 + 法务
- 处理活动: [描述]

## 评估内容 (第 56 条)
### 1. 处理目的与方式合法性
- 法律基础: [合同履行/同意/法定义务]
- 必要性分析: [是否最小必要]

### 2. 对个人权益的影响
- 风险等级: [低/中/高/极高]
- 影响个人: [数量]
- 潜在损害: [类型]

### 3. 安全保护措施
- 技术措施: [加密/脱敏/访问控制/审计]
- 管理措施: [制度/培训/应急预案]

### 4. 风险与收益平衡
- 处理必要性: [不可替代性]
- 风险缓解: [措施有效性]
- 结论: [风险可控/需调整/不可接受]
```

---

## 5. 个人权利响应 SOP

```yaml
数据主体请求处理 SOP:
  验证:
    1. 确认请求者身份 (多因素验证)
    2. 确认请求的合法性
    3. 建立请求工单 (Ticket System)

  处理:
    4. 15 日内完成处理
    5. 如需延期，3 日内告知理由
    6. 结果告知请求人

  记录:
    7. 保存请求记录 >= 3 年
    8. 定期审计请求处理情况
    9. 向监管机构报告统计

  拒绝场景:
    - 明显滥用权利: 记录拒绝理由
    - 无合理依据: 告知拒绝 + 申诉路径
```

---

## 参考资源

- [中华人民共和国个人信息保护法](http://www.npc.gov.cn/)
- [App 违法违规收集使用个人信息行为认定方法](http://www.cac.gov.cn/)
- [TC260 个人信息安全规范](https://www.tc260.org.cn/)
- [GDPR 与 PIPL 对比分析](https://iapp.org/)

---

*上一篇：[数据安全法深度解读](./04-data-security-law.md)*

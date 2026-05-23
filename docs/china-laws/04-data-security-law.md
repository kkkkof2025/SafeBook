# 数据安全法实战合规

> 《中华人民共和国数据安全法》企业合规落地指南

---

## 1. 数据分类分级

### 分类框架
```yaml
数据分类:
  公共数据: 政务公开、统计公报
  企业数据: 经营数据、客户信息、商业机密
  个人信息: 姓名/身份证/手机/生物特征
  重要数据: 一旦泄露可能危害国家安全 (行业目录)

数据分级:
  一级 (一般数据): 公开或内部使用
  二级 (重要数据): 泄露导致企业损失
  三级 (核心数据): 泄露危害国家安全/公共利益
```

### 分类引擎实现
```python
class DataClassifier:
    """自动数据分类分级"""

    SENSITIVE_PATTERNS = {
        '身份证': r'[1-9]\d{5}(18|19|20)\d{2}[01]\d[0123]\d{4}[\dXx]',
        '手机号': r'1[3-9]\d{9}',
        '银行卡': r'\d{16,19}',
        '邮箱': r'[\w.-]+@[\w.-]+\.\w+',
    }

    CLASSIFICATION_RULES = {
        '核心数据': ['国家秘密', '军事', '关键基础设施'],
        '重要数据': ['身份证', '银行卡', '生物特征', '健康医疗'],
        '个人信息': ['手机号', '邮箱', '地址'],
        '企业数据': ['财务', '合同', '战略规划'],
        '公共数据': ['公告', '年报'],
    }

    def classify(self, data):
        for level, keywords in self.CLASSIFICATION_RULES.items():
            for keyword in keywords:
                if keyword in str(data).lower():
                    return level
        return '一般数据'
```

---

## 2. 数据处理合规

### 数据全生命周期
```
采集 → 存储 → 使用 → 加工 → 传输 → 提供 → 公开 → 删除
  │      │      │      │      │      │      │      │
  ├─告知   ├─加密   ├─脱敏   ├─匿名化 ├─加密   ├─审批   ├─脱敏   ├─安全擦除
  ├─同意   ├─分级   ├─最小化 ├─不可逆 ├─审计   ├─合同   ├─匿名化 ├─不可恢复
  └─最小化 └─备份   └─审计   └─合规   └─安全评估└─脱敏   └─合规   └─记录
```

### 数据删除实现
```python
class SecureDataDeletion:
    """符合数据安全法的数据删除"""

    def delete_user_data(self, user_id):
        # 1. 主数据库: 软删除 + 定时物理删除
        db.execute("UPDATE users SET deleted_at=NOW() WHERE id=%s", user_id)

        # 2. 备份清理
        for backup in self.list_backups_containing_user(user_id):
            if backup.age_days > 30:
                self.purge_from_backup(backup, user_id)

        # 3. 日志脱敏
        db.execute("UPDATE audit_log SET user_data='[REDACTED]' WHERE user_id=%s", user_id)

        # 4. 第三方数据删除
        for processor in self.get_processors_with_user_data(user_id):
            processor.request_deletion(user_id)
            # 等待删除确认

        # 5. 删除记录 (合规证据)
        self.log_deletion_record({
            'user_id': user_id,
            'deletion_time': datetime.utcnow(),
            'method': 'full_deletion',
            'operator': 'automated'
        })
```

---

## 3. 数据出境安全评估

```yaml
数据出境场景判断:

  需要安全评估:
    - CIIO 向境外提供个人信息或重要数据
    - 处理 100 万人以上个人信息者
    - 累计向境外提供 10 万人以上个人信息
    - 累计向境外提供 1 万人以上敏感个人信息

  可选标准合同:
    - 非 CIIO
    - 处理 <100 万个人信息
    - 年度出境 <10 万个人信息
    - 年度出境 <1 万敏感个人信息

  流程:
    1. 自评估 (数据处理者)
    2. 签订法律文件 (数据出境合同)
    3. 申报安全评估 (网信办)
    4. 评估结果公示
    5. 持续合规监控
```

---

## 4. 处罚案例与合规建议

| 案例 | 违规行为 | 罚金 |
|------|---------|------|
| 滴滴出行 (2022) | 违法收集/处理个人信息 | ¥80.26 亿 |
| 某大数据公司 | 非法获取/出售个人信息 | ¥4000 万 + 刑罚 |
| 某银行 | 数据安全管理缺失 | ¥400 万 |

### 合规路线图
```
Phase 1 (1个月): 数据资产盘点
  - 识别所有数据存储位置
  - 分类分级
  - 绘制数据流图

Phase 2 (2个月): 合规差距分析
  - 对比数据安全法要求
  - 识别技术/流程差距
  - 制定整改计划

Phase 3 (3个月): 整改实施
  - 技术控制 (加密/脱敏/审计)
  - 制度建设 (管理流程/应急预案)
  - 人员培训 (数据安全责任)

Phase 4 (持续): 持续监控
  - 自动化合规检查
  - 半年一次安全审计
  - 年度合规报告
```

---

*上一篇：[个人信息跨境传输合规](03-cross-border-data.md)*

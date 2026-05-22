# 勒索软件应急响应与恢复

## 概述

勒索软件是当前最严重的网络威胁之一。当勒索软件攻击发生时，每一分钟都至关重要。本章提供从检测到恢复的完整应急响应流程，以及防御性备份策略。

---

## 1. 应急响应流程

### 1.1 黄金 60 分钟

```
00:00  确认事件
       ├─ 确认感染范围 (单台 / 多台 / 全公司)
       └─ 立即隔离受影响系统 (断开网络)

00:05  启动 IR 团队
       ├─ 通知 CISO / Legal / PR
       ├─ 启动 War Room (物理 / 虚拟)
       └─ 确定是否需要外部 IR 顾问

00:15  止损
       ├─ 禁用受影响账户 (AD / Cloud IAM)
       ├─ 阻断 C2 通信 (防火墙规则 / DNS sinkhole)
       ├─ 关闭共享文件夹
       └─ 锁死备份系统 (防止被加密)

00:30  取证开始
       ├─ 保存内存转储 (Volatility)
       ├─ 保存磁盘镜像 (FTK Imager / dd)
       ├─ 收集网络流日志
       └─ 识别初始入侵向量

01:00  制定恢复策略
       ├─ 评估备份可用性
       ├─ 通知执法机构 (如适用)
       └─ 启动客户通知流程
```

### 1.2 隔离决策树

```python
def containment_decision(infected_systems):
    """
    隔离决策引擎
    """
    critical_systems = identify_critical(infected_systems)
    encryption_progress = assess_encryption_progress()

    actions = []

    for system in infected_systems:
        if system.is_domain_controller:
            actions.append({
                'action': 'NETWORK_ISOLATE',
                'system': system.name,
                'reason': '域控感染 - 立即隔离网络但保持运行',
                'method': '防火墙规则限制入站/出站'
            })
        elif system.is_critical() and encryption_progress[system] < 50:
            actions.append({
                'action': 'SAFE_SHUTDOWN',
                'system': system.name,
                'reason': '关键系统，加密<50%',
                'method': '正常关机保留数据'
            })
        elif encryption_progress[system] > 50:
            actions.append({
                'action': 'HARD_ISOLATE',
                'system': system.name,
                'reason': '加密>50%, 防止横向移动',
                'method': '交换机端口关闭 + 账户禁用'
            })
        else:
            actions.append({
                'action': 'NETWORK_SEGMENT',
                'system': system.name,
                'reason': '隔离到应急 VLAN',
                'method': 'VLAN 隔离 + 流量镜像'
            })

    return actions
```

---

## 2. 勒索软件识别

### 2.1 早期检测信号

```yaml
勒索软件早期预警:
  文件系统:
    - 短时间内大量文件重命名 (扩展名变更)
    - 磁盘 I/O 异常升高
    - 出现大量 .lock / .encrypt / .crypt 文件
    - 卷影副本 (VSS) 被删除

  进程:
    - vssadmin.exe delete shadows (极强信号)
    - wbadmin.exe delete catalog
    - bcdedit.exe /set {default} recoveryenabled No
    - 大量进程同时进行写操作

  网络:
    - 到已知 C2 域名的 DNS 查询
    - Tor / I2P 网络流量
    - 异常 SMB 流量 (横向移动)
```

### 2.2 自动化检测规则

```yara
rule Ransomware_Behavior_Early {
    meta:
        description = "勒索软件行为早期检测"

    strings:
        $vss_delete = "vssadmin" wide ascii
        $shadow_del = "Delete Shadows" wide ascii
        $bcdedit = "recoveryenabled" wide ascii

    condition:
        uint16(0) == 0x5A4D and
        (all of ($vss_delete, $shadow_del) or $bcdedit)
}
```

---

## 3. 赎金谈判策略

### 3.1 决策框架

```
收到赎金通知
    │
    ├── 备份可用？
    │   ├── YES → 不支付，从备份恢复
    │   └── NO  → 继续评估
    │
    ├── 执法机构建议？
    │   └── 联系当地执法 / CISA / NCSC
    │
    ├── 支付风险？
    │   ├── 不保证恢复 (40% 支付后未完全恢复)
    │   ├── 可能被标记为"愿意支付"的目标
    │   └── 可能违反 OFAC 制裁
    │
    └── 业务影响？
        ├── 生命安全问题 → 紧急评估
        ├── 核心业务停摆 → 考虑保险
        └── 有限影响 → 不支付, 重建
```

### 3.2 与攻击者沟通

```
DO's:
├── 使用专业谈判顾问
├── 请求解密证明 (decrypt 2-3 个样本文件)
├── 尝试协商降低赎金
└── 记录所有通信作为证据

DON'Ts:
├── 不要直接威胁或激怒攻击者
├── 不要暴露恢复进度
├── 不要使用企业邮件系统通信
└── 不要单独决策 - 需要法律/Security/高管协商
```

---

## 4. 备份与恢复策略

### 4.1 3-2-1-1-0 规则

| 规则 | 含义 | 实现 |
|------|------|------|
| 3 | 3 份数据副本 | 生产 + 备份 + 离线 |
| 2 | 2 种不同介质 | 磁盘 + 磁带/云 |
| 1 | 1 份异地保存 | 不同数据中心/区域 |
| 1 | 1 份不可变 | WORM / Object Lock |
| 0 | 0 恢复错误 | 定期恢复测试 |

### 4.2 不可变备份实现

```python
# AWS S3 Object Lock (防删除/防篡改)
import boto3

def setup_immutable_backup():
    s3 = boto3.client('s3')

    # 创建启用 Object Lock 的存储桶
    s3.create_bucket(
        Bucket='immutable-backups',
        ObjectLockEnabledForBucket=True
    )

    # 配置默认保留策略
    s3.put_object_lock_configuration(
        Bucket='immutable-backups',
        ObjectLockConfiguration={
            'ObjectLockEnabled': 'Enabled',
            'Rule': {
                'DefaultRetention': {
                    'Mode': 'GOVERNANCE',  # 或 COMPLIANCE
                    'Days': 90  # 最少保留 90 天
                }
            }
        }
    )

def upload_protected_backup(file_path):
    s3 = boto3.client('s3')
    s3.put_object(
        Bucket='immutable-backups',
        Key=f'backups/{datetime.now().isoformat()}/{file_path}',
        Body=open(file_path, 'rb'),
        ObjectLockMode='COMPLIANCE',  # 连 root 都不能删
        ObjectLockRetainUntilDate=datetime.now() + timedelta(days=365)
    )
```

### 4.3 恢复优先级矩阵

```yaml
恢复优先级:
  P0 (4小时内):
    - Active Directory / 认证系统
    - DNS / DHCP
    - 核心数据库
    - 客户面向应用

  P1 (24小时内):
    - 内部业务系统 (ERP / CRM)
    - 文件服务器
    - 邮件系统
    - 监控与告警

  P2 (72小时内):
    - 开发环境
    - 测试环境
    - 辅助系统
    - 非关键数据仓库
```

---

## 5. 事后分析与加固

### 5.1 根因分析报告模板

```markdown
# 勒索软件事件根因分析

## 事件概要
- **发现时间**: 2024-XX-XX XX:XX
- **感染范围**: X 台服务器, X 台工作站
- **勒索软件家族**: [LockBit / BlackCat / ...]
- **初始入侵向量**: [钓鱼邮件 / RDP 爆破 / VPN 漏洞 / ...]

## 攻击时间线
| 时间 | 事件 |
|------|------|
| T-7d | 钓鱼邮件投递 |
| T-6d | 初始执行 (user clicked) |
| T-5d | 建立 C2 通道 |
| T-2d | 凭证窃取 + 横向移动 |
| T-0h | 数据窃取 (双重勒索) |
| T+1h | 加密开始 |

## 缺失的控制
1. EDR 未检测到初始执行
2. C2 流量未被防火墙阻断
3. 管理员凭证未使用 PAM
4. 备份系统未隔离

## PIR (Post Incident Review) 改进
| 问题 | 改进措施 | 负责人 | 截止日期 |
|------|----------|--------|----------|
| EDR 漏检 | 升级 EDR + 行为分析 | Security | 30d |
| C2 出站 | 默认拒绝出站 + 白名单 | Network | 15d |
| 凭证泄露 | 强制 PAM + JIT 访问 | IAM | 60d |
| 备份被加密 | 实施不可变备份 | Infra | 30d |
```

### 5.2 桌面推演剧本

```yaml
年度桌面推演剧本:
  场景 1 - 钓鱼邮件触发加密:
    - 模拟 HR 收到钓鱼邮件附件
    - 练习: 用户报告 → IR 响应 → 隔离 → 恢复

  场景 2 - RDP 爆破横向移动:
    - 模拟暴露 RDP 的服务器被爆破
    - 练习: SOC 告警 → 账户锁定 → 网络隔离

  场景 3 - 供应链攻击:
    - 模拟 IT 管理软件更新投毒
    - 练习: 大规模感染 → 全局断网 → 离线恢复
```

---

## 参考资源

- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [NIST SP 800-61: Computer Security Incident Handling Guide](https://www.nist.gov/publications/computer-security-incident-handling-guide)

---

*上一篇：[勒索软件防御与恢复](./03-ransomware-defense.md)*

# 数据泄露应急响应

## 应急响应生命周期

```
                      ┌──────────┐
                      │   准备    │
                      └────┬─────┘
                           ↓
  ┌──────────┐   ┌────────┴───────┐   ┌──────────┐
  │   复盘    │ ← │    应急响应    │ → │   检测    │
  └──────────┘   │    生命周期    │   └──────────┘
       ↑         └────────┬───────┘        ↑
       │                  ↓                │
  ┌────┴─────┐    ┌───────────────┐        │
  │   恢复    │ ← │     遏制       │ ←─────┘
  └──────────┘    └───────────────┘
```

---

## 1. 检测与分析（0-4 小时）

### 检测信号
```yaml
数据泄露常见信号:
  - 异常数据库查询量 (SELECT * FROM users WHERE 1=1)
  - 异常出站流量 (>3σ 基线)
  - 深夜/节假日的大量数据导出
  - 新设备/新 IP 访问敏感系统
  - SIEM 告警: 可疑 SQL/文件传输/DNS 隧道
  - DLP 告警: 敏感文件外传
```

### 初始分析命令
```bash
# 1. 确认泄露范围
# 数据库审计日志
grep -i "SELECT\|INSERT\|DUMP" /var/log/mysql/audit.log | \
  awk '{print $1,$2,$NF}' | sort | uniq -c | sort -rn

# 2. 网络流量时间线
tcpdump -r captured.pcap -n 'port 443 or port 22' | \
  awk '{print $1}' | sort | uniq -c

# 3. 账户活动时间线
last -f /var/log/wtmp
lastb -f /var/log/btmp | head -50

# 4. 文件变更时间线
find /var/www -newer /var/log/last-known-good -type f
```

---

## 2. 遏制（4-24 小时）

### 立即行动
```python
class BreachContainment:
    """数据泄露自动遏制脚本"""

    def __init__(self):
        self.affected_systems = []
        self.containment_log = []

    def isolate_system(self, host):
        """网络隔离"""
        # 1. 防火墙规则阻断出站
        subprocess.run(['iptables', '-A', 'OUTPUT', '-j', 'DROP',
                       '-s', host])
        # 2. 保留取证数据
        self.preserve_evidence(host)
        self.containment_log.append(
            f"[{datetime.utcnow()}] Isolated {host}"
        )

    def preserve_evidence(self, host):
        """证据保全"""
        evidence_dir = f"/evidence/{host}_{datetime.utcnow():%Y%m%d_%H%M}"
        os.makedirs(evidence_dir)

        # 内存快照
        subprocess.run(['ssh', host, 'sudo', 'avml', '/tmp/memory.dump'])

        # 磁盘镜像 (dd)
        subprocess.run(['ssh', host,
            f'sudo dd if=/dev/sda1 of=/tmp/disk.img bs=4M'])

        # 关键日志
        logs = ['/var/log/auth.log', '/var/log/syslog',
                '/var/log/nginx/access.log', '/var/log/mysql/*.log']
        for log in logs:
            subprocess.run(['scp', f'{host}:{log}', evidence_dir])

    def revoke_credentials(self):
        """凭证吊销"""
        actions = [
            # 数据库密码轮换
            "aws secretsmanager rotate-secret --secret-id db/master",
            # IAM 密钥禁用
            "aws iam update-access-key --access-key-id AKIAXXX --status Inactive",
            # 应用 Token 全部作废
            "redis-cli FLUSHDB",  # 清空 Token 缓存
            # 密码全局重置
            "echo '密码重置通知已发送至所有用户'"
        ]
        for cmd in actions:
            subprocess.run(cmd, shell=True)
```

---

## 3. 通知（法规要求）

| 法规 | 通知时限 | 通知对象 | 罚款 |
|------|---------|---------|------|
| GDPR | **72 小时** | 监管机构 + 数据主体 | €2000万 / 4% 营收 |
| PIPL | **立即** | 网信办 + 个人 | ¥5000万 / 5% 营收 |
| CCPA | 无固定时限 | 加州总检察长 (非每例) | $7500/次 |
| PCI DSS | 24小时 | 收单行 + 卡组织 | $5千-10万/月 |

### 通知模板
```
主题: [紧急] [公司名称] 数据安全事件通知

尊敬的 [姓名]:

我们于 [日期] [时间] 发现一起涉及您个人信息的安全事件。

事件概述:
  [简述事件性质，如：未经授权的第三方访问了我们的用户数据库]

涉及的信息:
  [明确列出: 姓名/手机号/邮箱/(不)含密码/身份证等]
  ⚠️ 注意: 密码使用 bcrypt 哈希存储，未被直接泄露

已采取的措施:
  1. [第一时间行动: 隔离系统/阻断攻击链]
  2. [已通知执法部门/网信办]
  3. [已聘请第三方安全公司调查]

我们建议您:
  1. 立即修改密码 (如有复用)
  2. 开启双因素认证
  3. 警惕钓鱼邮件 (我们不会通过邮件/电话索要密码)

如有疑问，请联系: security@company.com / 400-XXX-XXXX

[公司名称] 安全团队
[日期]
```

---

## 4. 复盘（事后改进）

```yaml
事后复盘 (Post-Mortem) 模板:

  时间线:
    - 2024-03-15 02:34: 攻击者通过 XX 漏洞获得初始访问
    - 2024-03-15 03:12: 横向移动到数据库服务器
    - 2024-03-15 04:05: 开始批量导出用户数据
    - 2024-03-15 08:30: SIEM 告警触发响应

  根因分析:
    - 直接原因: XX 服务未打补丁 (CVE-2024-XXXX)
    - 根本原因: 补丁管理周期过长 (90天 vs 建议14天)
    - 放大因素: 数据库服务器与Web同网段 (无网络隔离)

  改进措施:
    - [ ] 补丁管理: SLA从90天降至14天
    - [ ] 网络隔离: 数据库服务器独立 VLAN + 微隔离
    - [ ] 监控增强: 大流量数据导出实时告警
    - [ ] 认证增强: 数据库访问强制 MFA
    - [ ] DLP: 部署数据防泄漏系统

  责任人 & 完成时间:
    - 补丁管理自动化: 张三, 2024-04-01
    - 网络改造: 李四, 2024-04-15
    - 监控告警: 王五, 2024-03-30
```

---

*上一篇：[全球数据保护法规对比](02-data-protection-laws.md)*

*下一篇：[Privacy by Design（隐私设计）深度](04-privacy-by-design.md)*

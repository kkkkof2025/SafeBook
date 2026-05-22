# 等保 2.0 三级实战

## 概述

网络安全等级保护 2.0（等保 2.0）是中国网络安全领域的基础性法律要求。三级（安全标记保护级）是大多数企业和政府机构需要达到的级别。本章提供可落地的三级等保实操指南。

---

## 1. 等保 2.0 框架

### 1.1 五级保护体系

| 等级 | 名称 | 适用对象 | 监管 |
|------|------|----------|------|
| 一级 | 自主保护级 | 一般信息系统 | 自主保护 |
| 二级 | 指导保护级 | 一般重要系统 | 指导 |
| **三级** | **监督保护级** | **重要系统** | **监督检查** |
| 四级 | 强制保护级 | 国家重要系统 | 强制监督 |
| 五级 | 专控保护级 | 国家核心系统 | 专门监督 |

### 1.2 等级保护 2.0 十大安全域

```
等保 2.0 (GB/T 22239-2019) 三级要求 = 安全通用要求 + 云计算扩展要求

  ┌─────────────────────────────────────────────┐
  │            等保 2.0 三级安全控制域             │
  ├─────────────────────────────────────────────┤
  │  1. 安全物理环境 (15 项)                      │
  │  2. 安全通信网络 (8 项)                       │
  │  3. 安全区域边界 (20 项)                      │
  │  4. 安全计算环境 (26 项)                      │
  │  5. 安全管理中心 (12 项)                      │
  │  6. 安全管理制度 (5 项)                       │
  │  7. 安全管理机构 (5 项)                       │
  │  8. 安全管理人员 (5 项)                       │
  │  9. 安全建设管理 (11 项)                      │
  │  10. 安全运维管理 (13 项)                     │
  ├─────────────────────────────────────────────┤
  │  + 云计算安全扩展要求 (46 项)                  │
  ├─────────────────────────────────────────────┤
  │  总计: ~211 项控制点                          │
  └─────────────────────────────────────────────┘
```

---

## 2. 关键控制项实操

### 2.1 身份鉴别 (安全计算环境)

```bash
# 身份鉴别 — 三级要求

# 1. 密码策略
# Linux PAM 配置
cat >> /etc/security/pwquality.conf << EOF
minlen = 8              # 最小长度 8
minclass = 3            # 至少包含 3 类字符
maxrepeat = 3           # 最多连续重复 3 次
maxsequence = 3         # 最多连续递增 3 个
EOF

# 2. 密码过期策略
cat >> /etc/login.defs << EOF
PASS_MAX_DAYS   90      # 90天过期
PASS_MIN_DAYS   1       # 修改间隔 ≥1天
PASS_WARN_AGE   7       # 到期前7天提醒
EOF

# 3. 账户锁定策略
cat >> /etc/pam.d/common-auth << EOF
auth required pam_tally2.so deny=5 unlock_time=1800
EOF
# 5 次失败锁定 30 分钟

# 4. 双因素认证 (等保三级建议)
# Google Authenticator PAM
apt-get install libpam-google-authenticator
google-authenticator -t -d -f -r 3 -R 30 -w 3
```

### 2.2 访问控制

```bash
# Linux 访问控制 — 满足等保要求

# 1. 最小权限原则
# 检查特权账户
awk -F: '($3 == 0) {print $1}' /etc/passwd
# → 应该只输出 root

# 2. 审计所有 SUID 文件
find / -perm -4000 -type f 2>/dev/null | while read f; do
    echo "$f: $(ls -l $f | awk '{print $3}')"
done

# 3. 限制 sudo 权限
visudo
# 用户  主机  =  (运行身份)   NOPASSWD:ALL
# admin ALL  =  (ALL)         /usr/bin/systemctl restart nginx
# → 只允许执行特定命令

# 4. 敏感文件权限
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 600 /etc/ssh/sshd_config
chmod 700 /root
```

### 2.3 安全审计

```bash
#!/bin/bash
# 等保三级审计配置

# 1. auditd 配置
cat >> /etc/audit/rules.d/audit.rules << EOF
# 文件完整性监控
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers

# 关键命令审计
-w /usr/bin/chmod -p x -k permission_modify
-w /usr/bin/chown -p x -k permission_modify
-w /usr/bin/passwd -p x -k passwd_change
-w /usr/sbin/useradd -p x -k user_modify
-w /usr/sbin/usermod -p x -k user_modify

# 登录审计
-w /var/log/tallylog -p wa -k login
-w /var/log/faillog -p wa -k login

# 系统配置审计
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/audit/auditd.conf -p wa -k audit_config
EOF

# 2. 日志收集与存储
systemctl restart auditd
auditctl -l

# 3. 日志存储策略 (满足 6 个月存储要求)
cat >> /etc/logrotate.d/audit << EOF
/var/log/audit/audit.log {
    daily
    rotate 180   # 保留 180 天
    compress
    delaycompress
    missingok
    postrotate
        /sbin/service auditd restart 2>/dev/null
    endscript
}
EOF
```

### 2.4 入侵防范

```yaml
# 等保三级 入侵防范 要求对应措施

控制点要求:
  1. 关闭不必要的系统服务:

# systemctl list-units --type=service --state=running
# 禁用不需要的服务
systemctl disable telnet.socket
systemctl disable rsync
systemctl disable rpcbind

  2. 最小安装原则:
# 检查已安装包，移除不必要的软件
rpm -qa --queryformat '%{NAME}\n' | sort

  3. 限制终端接入地址:
# /etc/hosts.allow
sshd: 10.0.0.0/8, 172.16.0.0/12

# /etc/hosts.deny
ALL: ALL

  4. 漏洞扫描:
# 定期使用绿盟/启明星辰扫描器或 Nessus
# 高危漏洞 48 小时内修复
```

---

## 3. 等保测评

### 3.1 测评流程

```
等保三级测评流程:

  1. 定级备案 (1-2周)
     → 确定保护等级 (三级)
     → 编制定级报告
     → 向公安机关备案

  2. 安全整改 (1-3个月)
     → 差距分析
     → 技术整改
     → 管理整改

  3. 等级测评 (1-2周)
     → 测评机构入场
     → 技术测试 + 管理审查
     → 出具测评报告

  4. 监督检查 (持续)
     → 每年至少一次自查
     → 每两年至少一次测评
     → 重大变更后重新测评
```

### 3.2 常见不通过项

| 控制项 | 常见问题 | 修复 |
|--------|----------|------|
| 身份鉴别 | 未启用密码复杂度策略 | PAM pwquality 配置 |
| 访问控制 | 共享账户 (多人用 root) | 个人账户 + sudo |
| 安全审计 | 日志未覆盖所有操作 | auditd 规则完善 |
| 入侵防范 | 未关闭不必要服务 | 服务清单梳理 |
| 数据备份 | 未定期恢复演练 | 每季度一次恢复测试 |
| 剩余信息保护 | 删除文件未彻底擦除 | shred 或加密擦除 |

---

## 4. 密评 (商用密码应用安全性评估)

```yaml
密评 — 等保三级的密码学要求:

  物理和环境安全:
    - 门禁系统使用国密算法 (SM2/SM4)
    - 视频监控数据加密存储

  网络和通信安全:
    - 通信使用国密 TLS (SM2+SM4)
    - VPN 使用国密 IPSec

  设备和计算安全:
    - 身份鉴别使用 SM2/SM3
    - 系统日志使用 SM3 完整性保护

  应用和数据安全:
    - 重要数据传输加密 (SM4)
    - 重要数据存储加密 (SM4)
    - 数据完整性保护 (SM3 HMAC)
```

---

## 参考资源

- [GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求](http://www.gb688.cn/bzgk/gb/newGbInfo?hcno=9B8E7E3C4D0E3E3E3E3E3E3E3E3E3E3E)
- [等保 2.0 测评要求](https://www.djbh.net/)
- [商用密码应用安全性评估](https://www.oscca.gov.cn/)

---

*上一篇：[SOC 2 合规](04-soc2-compliance.md)*

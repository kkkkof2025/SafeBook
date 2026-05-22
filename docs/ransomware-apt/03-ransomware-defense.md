# 勒索软件防御与恢复

## 勒索软件威胁全景

勒索软件（Ransomware）是最具破坏性的网络威胁之一。2024-2025年，勒索软件团伙采用了双重勒索（加密+数据泄露）和三重勒索（加密+泄露+DDoS）策略。

## 主要勒索软件家族

| 家族 | 运营方式 | 加密算法 | 赎金 | 活跃期 |
|------|---------|---------|------|--------|
| LockBit | RaaS (Ransomware-as-a-Service) | AES-256 + RSA-4096 | $5K-$80M+ | 2019-今 |
| BlackCat/ALPHV | RaaS (Rust编写) | ChaCha20 + RSA-OAEP | $400K-$5M | 2021-今 |
| Clop | 定向企业攻击 | AES-256 + RSA-4096 | $500K-$50M+ | 2019-今 |
| REvil/Sodinokibi | RaaS | AES + ECC | $10K-$50M | 2019-2022 |
| Royal/BlackSuit | 封闭运营 | — | 谈判 | 2022-今 |

## 攻击链生命周期

```
初始访问 → 持久化 → 横向移动 → 凭证窃取 → 数据外泄 → 加密
```

### 初始访问向量

```yaml
向量分布 (2024):
  - 钓鱼邮件: 32%
  - RDP 暴力破解: 18%
  - 漏洞利用: 16% (以 VPN/防火墙 CVE 为主)
  - 被盗凭证: 14%
  - 恶意广告: 8%
```

## 预防策略

### 端点防护

1. **EDR 部署**: 确保所有端点部署了启用了防勒索功能的 EDR
2. **ASR 规则**: 重点启用
   - 阻止从 Temp 目录启动进程（GUID: 01443614-cd74-433a-b99e-2ecdc07bfc25）
   - 阻止勒索软件行为（GUID: c1db55ba-c877-4232-8d6f-adec03c1265f）
3. **受控文件夹访问**: 配置关键文件扩展名保护

```powershell
# 启用受控文件夹访问
Set-MpPreference -EnableControlledFolderAccess Enabled

# 添加保护文件夹
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Data"
```

### 备份策略（3-2-1-1-0）

```
3  份副本
2  种不同介质
1  份异地备份
1  份离线（冷存储/不可变存储）
0  次备份验证失败
```

### 不可变备份配置

```bash
# AWS S3 对象锁定配置
aws s3api put-object-lock-configuration \
    --bucket my-backup-bucket \
    --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":90}}}'

# Veeam 不可变备份仓库
# 在 Linux 硬存储库上配置不可变标记
chattr +i /backup/*.vbk  # Linux 级的不可变
```

## 事件响应流程

### 发现阶段

1. **隔离受感染主机**: 立即断网（拔网线 > 软件隔离）
2. **锁定域控**: 禁用域管理员账户、重置 krbtgt 密码
3. **通知法务与高管**: 评估合规报告义务（SEC 要求在 4天内披露）

### 响应与恢复

```powershell
# 1. 识别受影响范围
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | Where-Object {$_.Message -match 'ransom|lockbit|encrypt'}

# 2. 阻止传播
# 在网络设备上阻断 C2 域名/IP
# 更新 DNS 解析，将已知恶意域名解析到本地内网
```

### 解密与赎金谈判

> **⚠️ 不鼓励支付赎金**：研究显示支付赎金的组织中有 32% 遭受第二次攻击，且数据不一定会被完整恢复。

解密可能性评估：
```bash
# ID Ransomware (id-ransomware.malwarehunterteam.com)
# NoMoreRansom (nomoreransom.org) — 免费解密工具库

# 如果勒索信息中没有具体名字，上传样本到 ID Ransomware
```

## 数据泄漏站点监测

勒索软件团伙会部署数据泄漏站点（DLS），用于公布受害组织的数据。

```bash
# 自动化监测工具
# 使用 RansomLook 或 RansomWatch
git clone https://github.com/Ransom-Look/RansomLook
cd RansomLook && docker-compose up -d
```

## 总结

防御勒索软件的最佳策略是预防优于恢复。实施 3-2-1-1-0 备份策略、部署 EDR 并配置 ASR 规则、定期演练恢复流程，可以显著降低勒索软件的影响。

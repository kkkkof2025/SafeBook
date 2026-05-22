# Windows 安全加固实战

## 概述

Windows 是全球最大的企业桌面和服务器操作系统，也是 APT 攻击最重要的目标。本章从 GPO、AppLocker、WDAC 到凭据保护，提供可立即部署的 Windows 安全加固方案。

---

## 1. GPO 安全基线

### 1.1 Windows 安全基线 GPO

```powershell
# 导出/导入安全策略
secedit /export /cfg secpol.inf
secedit /configure /db secedit.sdb /cfg baseline.inf

# 关键 GPO 策略:
# 密码策略
$policy = @{
    # NIST SP 800-63B 建议
    MinimumPasswordLength = 14
    PasswordHistorySize = 24
    MaximumPasswordAge = 90
    MinimumPasswordAge = 1
    PasswordComplexity = $true
    # 不建议强制定期改密（NIST 最新建议）
}

# 账户锁定策略（防暴力破解）
$lockout = @{
    LockoutBadCount = 5
    LockoutDuration = 30  # 分钟
    ResetLockoutCount = 30
}

# 审计策略
$audit = @{
    AuditLogonEvents = "Success,Failure"
    AuditAccountLogon = "Success,Failure"
    AuditAccountManage = "Success,Failure"
    AuditPrivilegeUse = "Success,Failure"
    AuditProcessTracking = "Success"
    AuditPolicyChange = "Success,Failure"
}
```

### 1.2 远程桌面安全

```powershell
# RDP 安全加固
# 1. 网络层认证 (NLA) — 强制
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1

# 2. RDP 非标准端口（通过防火墙规则）
New-NetFirewallRule -DisplayName "RDP-Alt" -Direction Inbound -Protocol TCP -LocalPort 3391 -Action Allow

# 3. 仅允许特定 IP 的 RDP
New-NetFirewallRule -DisplayName "RDP-Restricted" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.0.0/8 -Action Allow

# 4. 禁用 RDP 剪贴板重定向
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fDisableClip" -Value 1
```

---

## 2. AppLocker + WDAC

### 2.1 AppLocker 策略

```powershell
# AppLocker 默认规则（仅允许 Windows + Program Files 中的可执行文件）
$rules = Get-AppLockerPolicy -Effective
New-AppLockerPolicy -Rule $rules -User Everyone -Xml > applocker.xml

# 修改为: DLL 规则（防止 DLL 侧加载）
[xml]$policy = Get-Content applocker.xml
$dllRule = @{
    EnforcementMode = "Enabled"
    RuleCollectionType = "Dll"
}
# 添加 DLL 路径规则...

Set-AppLockerPolicy -XmlPolicy applocker.xml

# AppLocker 审计模式（部署前先审计）
# 查看哪些应用会被阻止
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path C:\Users\*\AppData\*\*.exe
```

### 2.2 WDAC（Windows Defender Application Control）

```powershell
# WDAC 策略（比 AppLocker 更底层，内核级）

# 1. 创建默认 WDAC 基线
$policyPath = "C:\WDAC\DefaultWindows.xml"
New-CIPolicy -FilePath $policyPath -ScanPath "C:\Windows" -UserPEs

# 2. 合并可信发布者规则
Add-SignerRule -FilePath $policyPath -ProductName "Microsoft*"

# 3. 转换为二进制策略
ConvertFrom-CIPolicy -XmlFilePath $policyPath -BinaryFilePath "C:\WDAC\SiPolicy.p7b"

# 4. 部署策略（组策略方式）
Copy-Item "C:\WDAC\SiPolicy.p7b" "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"

# 注意:
# - WDAC 在 Kernel 层，无法被用户态绕过
# - 但配置错误可能导致系统无法启动（备好恢复方案）
```

---

## 3. 凭据保护

### 3.1 Credential Guard

```powershell
# 启用 Credential Guard（Windows 10/11+ Enterprise）
Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard

# 验证 Credential Guard 状态
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# 检查: SecurityServicesRunning 应为 1（运行中）
# 检查: SecurityServicesConfigured 应为 1

# 禁用 NTLM（仅在可能的情况下）
# 路径: 安全设置 > 本地策略 > 安全选项
# 策略: 网络安全: 限制 NTLM
```

### 3.2 LSA 保护

```powershell
# 启用 LSA 保护（防止 Mimikatz 等方式读取 LSASS）
# 方法 1: 组策略
# 计算机配置 > 管理模板 > 系统 > 本地安全机构
# "配置 LSASS 以作为受保护进程运行" → 已启用

# 方法 2: 注册表
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWORD

# 验证（需要重启后）
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"
# 输出: RunAsPPL = 1

# 启用后影响:
# - Mimikatz sekurlsa::logonpasswords → 失败
# - procdump.exe -ma lsass.exe → 拒绝访问
# - Task Manager 创建转储 → 禁止
```

---

## 4. 防御加固清单

```yaml
Windows 安全加固优先级:

  P0 — 立即实施（阻止 >80% 常见攻击）:
    - [ ] Credential Guard (企业版)
    - [ ] LSA Protection (RunAsPPL)
    - [ ] WDAC 默认拒绝模式
    - [ ] Windows Defender + ASR 规则
    - [ ] 关闭 SMBv1 / NetBIOS / LLMNR

  P1 — 1 周内实施:
    - [ ] 安全基线 GPO 部署
    - [ ] LAPS（本地管理员密码方案）
    - [ ] AppLocker 启用
    - [ ] RDP 限制 + NLA
    - [ ] PowerShell 约束语言模式

  P2 — 1 月内实施:
    - [ ] Windows Hello for Business (FIDO2)
    - [ ] Windows Firewall 出站限制
    - [ ] Event Forwarding → SIEM
    - [ ] BitLocker 全盘加密
    - [ ] Secure Boot + Virtualization-Based Security

  P3 — 持续优化:
    - [ ] PAW（特权访问工作站）
    - [ ] Just-in-Time 管理员访问
    - [ ] Windows Sandbox 隔离
```

---

*上一篇：[Linux 持久化](04-linux-persistence.md)*

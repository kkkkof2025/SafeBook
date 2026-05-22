# Windows 安全加固与攻击防御

## 概述

Windows 是企业环境中最广泛部署的操作系统之一，也是攻击者的首要目标。本章涵盖 Windows 安全机制的深度配置、EDR 绕过原理以及企业级加固策略。

## AMSI（反恶意软件扫描接口）

AMSI 是 Windows 10/Server 2016 引入的接口，允许应用程序在内存执行前将内容发送给已注册的反恶意软件提供者扫描。

### AMSI 绕过技术

- **内存补丁**: 修改 amsi.dll!AmsiScanBuffer 的入口字节为 `ret`
- **硬件断点**: 通过设置硬件断点拦截 AmsiScanBuffer
- **CLR 劫持**: 修改 CLR 的加载行为，绕过 .NET 内容扫描

```powershell
# 检测 AMSI 是否正常工作
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### AMSI 加固建议

1. 启用 Windows Defender 应用程序防护（WDAG）
2. 部署 ASR 规则，特别是「阻止 Office 应用程序创建子进程」
3. 启用 PowerShell 约束语言模式（CLM）和日志记录

## ASR（攻击面减少）规则

ASR 规则是 Windows Defender Exploit Guard 的核心组件，用于控制常见恶意行为的执行。

### 关键 ASR 规则

```xml
<!-- 阻止从电子邮件客户端中执行可执行内容 -->
<Rule ID="BE9BA2D6-3E3C-4E8E-8CDA-09852AAD99E9" Action="Enabled" />
<!-- 阻止 Office 通信应用程序创建子进程 -->
<Rule ID="D4F940AB-401B-4EFC-AADC-AD5F3C50688A" Action="Enabled" />
<!-- 阻止从 Windows 本地安全机构子系统 (lsass.exe) 窃取凭据 -->
<Rule ID="9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" Action="Enabled" />
```

## Windows Defender 应用控制（WDAC）

WDAC 取代了旧的 AppLocker，提供基于内核的代码完整性策略。

### 创建 WDAC 策略

```powershell
# 创建默认的允许 Microsoft 签名的策略
New-CIPolicy -FilePath C:\WDAC\Policy.xml -Level Publisher -ScanPath C:\Windows\System32\
# 转换策略为二进制格式
ConvertFrom-CIPolicy -XmlFilePath C:\WDAC\Policy.xml -BinaryFilePath C:\WDAC\Policy.bin
# 部署策略
Copy-Item C:\WDAC\Policy.bin C:\Windows\System32\CodeIntegrity\
```

## 凭据保护技术

### Credential Guard

Credential Guard 使用基于虚拟化的安全（VBS）隔离 NTLM 和 Kerberos 凭据，防止凭据被转储。

```powershell
# 启用 Credential Guard (重启后生效)
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $RegPath -Name "LsaCfgFlags" -Value 1
```

### LSA 保护

```powershell
# 启用 LSA 保护模式
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
```

## PowerShell 安全

### 启用 PowerShell 深度日志记录

```powershell
# 脚本块日志
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
# 模块日志
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
```

## Windows Defender 防火墙高级配置

### 阻止出站连接

```powershell
# 设置默认阻止出站
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
```

## 总结

Windows 加固是纵深防御的关键环节。合理配置 AMSI、ASR、WDAC、Credential Guard 和防火墙，可以大幅减少攻击面并提高检测响应能力。

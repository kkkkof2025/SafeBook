# Windows 安全机制内部

> 从 Ring 0 到 Ring 3——理解 Windows 安全体系才能攻防有道。

---

## Windows 安全架构

```mermaid
graph TB
    subgraph Ring 0 (内核)
        Kernel[Windows Kernel]
        HVCI[Hypervisor-protected Code Integrity]
        VBS[Virtualization-based Security]
        PatchGuard[Kernel Patch Protection]
    end
    subgraph Ring 3 (用户态)
        AppControl[Windows Defender Application Control]
        CredGuard[Windows Defender Credential Guard]
        ASR[Attack Surface Reduction Rules]
        AppLocker[AppLocker]
    end
    subgraph 硬件层
        TPM[TPM 2.0]
        SecureBoot[UEFI Secure Boot]
    end
```

## 核心防御机制

### 1. VBS（基于虚拟化的安全）

```powershell
# 检查 VBS 状态
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# 架构:
# Hyper-V → 创建安全内核（Secure Kernel）
# LSASS 运行在 VSM（虚拟安全模式）隔离环境中
# 即使管理员权限也无法读取 LSASS 内存

# 启用 VBS + Credential Guard
# 组策略:
# 计算机配置 > 管理模板 > 系统 > Device Guard
# "Turn On Virtualization Based Security" → 已启用
# Credential Guard 配置 → "Enabled with UEFI lock"
```

### 2. WDAG（Windows Defender 应用防护）

```powershell
# 应用隔离沙箱
# 浏览器在 Hyper-V 容器中运行
# 即使浏览器被攻破，也无法访问主机

# 启用
Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClient"
```

### 3. 内核保护（PatchGuard + HVCI）

```
PatchGuard（KPP）:
  - 检测内核代码/数据结构篡改
  - 检测驱动签名
  - 检测 SSDT/IDT 修改
  - 不可禁用（BSOD 响应）

HVCI（内存完整性）:
  - DMA 保护（阻止物理内存攻击）
  - 内核模式下只允许签名驱动
  - 保护内核代码页不被修改
```

## 用户态防御

### Attack Surface Reduction (ASR)

```powershell
# 查看当前 ASR 规则
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids

# 启用 ASR 规则（GUID 列表）
Add-MpPreference -AttackSurfaceReductionRules_Ids `
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" `  # 阻止 Office 创建子进程
    -AttackSurfaceReductionRules_Actions Enabled

# 常用规则
# 56a863a9-875e-4185-98a7-b882c64b5ce5 → 阻止 Dropper 活动
# d4f940ab-401b-4efc-aadc-ad5f3c50688a → 阻止 RCE (宏)
# 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 → 阻止 Credential Stealing
# c1db55ab-c21a-463f-bc71-ec12c4b82e73 → 阻止电子邮件执行
```

### Controlled Folder Access

```powershell
# 启用受控文件夹访问（防勒索软件）
Set-MpPreference -EnableControlledFolderAccess Enabled

# 添加保护文件夹
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Users\%USERNAME%\Documents"

# 添加受信任的应用
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\Company\app.exe"
```

## 进程安全

### 进程执行链（Process Trust）

```powershell
# 查看进程信任级别
Get-CimInstance -ClassName Win32_ProcessStartup | 
    Select-Object ProcessId, TrustLabel

# 信任级别:
# Untrusted — 从互联网下载的执行文件（标记为 Zone.Identifier）
# Low — AppContainer（UWP 应用）
# Medium — 普通用户执行
# High — 管理员执行
# System — NT Authority\System

# Windows Defender SmartScreen
# 检查下载文件的 AID 标记
Get-Item .\downloaded.exe -Stream Zone.Identifier
```

## LSA 保护

```powershell
# 开启 LSA 保护（protected process light）
# 注册表设置
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -PropertyType DWORD

# 阻止非微软进程注入 LSASS
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "DisableDomainCreds" -Value 1 -PropertyType DWORD
```

## 安全性基准配置

```yaml
Windows Security Baseline (参考 CIS/微软基准):

账户策略:
  密码长度最小值: 14
  密码历史: 24
  最长密码使用期限: 90
  账户锁定阈值: 5

本地策略:
  审核登录事件: 成功+失败
  审核对象访问: 成功+失败
  审核进程创建: 成功(含命令行)
  审核账户管理: 成功+失败

安全选项:
  网络访问: 不允许 SAM 匿名枚举
  交互登录: 不需要按 Ctrl+Alt+Del(工作站)
  设备: 禁止 CD-ROM 自动运行
  用户账户控制: 管理员批准模式
```

## 攻防验证

```powershell
# 检查防御有效性（使用 PingCastle）
PingCastle.exe --healthcheck --level Full
# 生成报告 → 查看 Score (0~100)
# 检查以下评分项：
# - Maturity Level Index
# - Anomalies
# - High Critical Objects

# 检查 Windows Defender 状态
Get-MpComputerStatus | Select-Object `
    AMServiceEnabled, AntispywareEnabled, AntivirusEnabled,
    BehaviorMonitorEnabled, IoavProtectionEnabled,
    NISEnabled, OnAccessProtectionEnabled,
    RealTimeProtectionEnabled, PUAProtection
```

# Windows 数字取证与事件响应

## Windows 取证概述

数字取证是安全事件响应中不可或缺的一环。Windows 系统保留了大量的数字痕迹，包括注册表、事件日志、Prefetch 文件、USN 日志等。

## 内存取证

### 获取内存镜像

```powershell
# 使用 WinPmem 获取内存（需要管理员权限）
.\winpmem_mini_x64_rc2.exe mem.raw
```

### Volatility 分析

```bash
# 查看镜像信息
volatility3 -f mem.raw windows.info

# 列出进程
volatility3 -f mem.raw windows.pslist
volatility3 -f mem.raw windows.psscan

# 提取 Cobalt Strike beacon 配置
volatility3 -f mem.raw windows.cmdline

# 网络连接
volatility3 -f mem.raw windows.netscan

# 提取 LSASS 内存中的凭据
volatility3 -f mem.raw windows.lsadump
```

## 磁盘取证

### 关键取证工件

| 工件 | 位置 | 价值 |
|------|------|------|
| Prefetch | C:\Windows\Prefetch | 程序执行记录，90天 |
| AmCache | C:\Windows\appcompat\Programs\AmCache.hve | 程序兼容性缓存 |
| ShimCache | SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache | 系统启动的程序记录 |
| USN Journal | $UsnJrnl | 文件变更全记录 |
| Event Logs | C:\Windows\System32\winevt\Logs\ | 安全/系统/应用日志 |

### 使用 KAPE 收集证据

```bash
kape.exe --tsource C:\ --tdest E:\KAPE_Output --target !CUSTOM_Triage --tflush
```

## Windows 事件日志分析

### 关键安全事件 ID

| Event ID | 描述 |
|----------|------|
| 4624 | 登录成功 |
| 4625 | 登录失败 |
| 4672 | 特殊权限分配给新登录 |
| 4688 | 进程创建（含命令行） |
| 4698 | 计划任务创建 |
| 4719 | 审核策略变更 |
| 4720 | 创建用户 |
| 4104 | PowerShell 脚本块日志（启用后） |

### 分析工具

```powershell
# 搜索远程登录（登录类型 10）
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | Where-Object {$_.Properties[8].Value -eq 10} | Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}}

# 搜索计划任务创建
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4698} | Select-Object TimeCreated, Message
```

## USB 设备取证

```powershell
# 查看 USB 设备历史 (以下键下有所有 USB 记录)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" | Select-Object FriendlyName
```

## 浏览器取证

### Chrome 浏览器分析

```powershell
# 查看下载历史
Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" -Encoding Byte -ReadCount 0 | Out-Null
# 实际分析推荐使用 Hindsight 或 BHE 工具
```

## NTFS 时间线分析

```powershell
# MACE（修改/访问/创建/入口更改）时间线
# $MFT 包含文件/目录的完整时间线信息
# 推荐工具: MFTECmd
.\MFTECmd.exe -f "C:\$MFT" --csv "C:\output"
```

## 总结

Windows 取证需要系统化的方法论：内存取证→磁盘取证→日志分析→时间线重建。掌握 Volatility、KAPE 和金相显微镜级的时间戳分析是事件响应成功的关键。

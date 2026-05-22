# Windows 取证深度

## 概述

Windows 是 APT 活动最常见的操作系统。掌握 Windows 取证意味着理解操作系统在每次操作后留下的所有痕迹——从注册表到事件日志到内存。

---

## 1. 关键取证工件

```
Windows 取证工件 (Kroll's 12 Artifacts):

  时间线:
    - $MFT (Master File Table)
    - USN Journal
    - 事件日志 (.evtx)
    - Prefetch (.pf)
    - Shimcache (AppCompatCache)
    - Amcache

  执行:
    - UserAssist (注册表)
    - BAM/DAM (后台活动管理器)
    - SRUM (系统资源使用)
    - Shellbags (资源管理器偏好)
    - Jump Lists
    - LNK 文件

  持久化:
    - Run/RunOnce 注册表键
    - 计划任务 (Scheduled Tasks)
    - 服务 (Services)
    - WMI 事件订阅
    - Startup 文件夹
```

---

## 2. 时间线构建

### 2.1 事件日志解析

```python
import win32evtlog
from datetime import datetime
import json

class WindowsForensicAnalyzer:
    """Windows 取证分析"""

    CRITICAL_EVENT_IDS = {
        4624: "Successful Logon",
        4625: "Failed Logon",
        4672: "Special Privileges Assigned",
        4688: "New Process Created",
        4689: "Process Terminated",
        4697: "Service Installed",
        4698: "Scheduled Task Created",
        4702: "Scheduled Task Updated",
        4720: "User Account Created",
        4722: "User Account Enabled",
        4728: "Member Added to Global Group",
        4732: "Member Added to Local Group",
        5140: "Network Share Accessed",
        7045: "Service Installed (System)"
    }

    def __init__(self):
        pass

    def parse_security_log(self, evtx_path, start_time=None, end_time=None):
        """解析安全事件日志"""
        events = []

        handle = win32evtlog.EvtQuery(
            evtx_path,
            win32evtlog.EvtQueryFilePath,
            "*"
        )

        for event in win32evtlog.EvtNext(handle, 10, timeout=1000):
            rendered = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)

            event_id = self._extract_field(rendered, "EventID")
            event_id = int(event_id) if event_id else 0

            if event_id in self.CRITICAL_EVENT_IDS:
                events.append({
                    'timestamp': self._extract_field(rendered, "TimeCreated"),
                    'event_id': event_id,
                    'description': self.CRITICAL_EVENT_IDS[event_id],
                    'subject_user': self._extract_field(rendered, "SubjectUserName"),
                    'target_user': self._extract_field(rendered, "TargetUserName"),
                    'ip_address': self._extract_field(rendered, "IpAddress"),
                    'workstation': self._extract_field(rendered, "WorkstationName"),
                    'raw': rendered
                })

        return sorted(events, key=lambda e: e['timestamp'])

    def _extract_field(self, xml, field):
        """从事件 XML 中提取字段"""
        import re
        pattern = f'<Data Name="{field}">([^<]*)</Data>'
        match = re.search(pattern, xml)
        return match.group(1) if match else None

    def build_timeline(self, events):
        """构建攻击时间线"""

        timeline = []

        # 关键事件序列模式
        attack_patterns = [
            {
                'name': 'Lateral Movement via RDP',
                'sequence': [4624, 4672, 4688, 5140],
                'criteria': lambda e: (
                    e['event_id'] == 4624 and
                    e.get('logon_type') == '10'
                )
            },
            {
                'name': 'Persistence via Scheduled Task',
                'sequence': [4698, 4702, 4688],
            },
            {
                'name': 'Privilege Escalation',
                'sequence': [4672, 4624],
                'criteria': lambda e: (
                    e['event_id'] == 4672 and
                    'SeDebugPrivilege' in str(e.get('privileges', ''))
                )
            },
            {
                'name': 'Account Creation',
                'sequence': [4720, 4722, 4732],
            }
        ]

        # 检测攻击序列
        for pattern in attack_patterns:
            matched = self._find_sequence(events, pattern['sequence'])
            if matched:
                timeline.append({
                    'pattern': pattern['name'],
                    'first_event': matched[0],
                    'last_event': matched[-1],
                    'confidence': len(matched) / len(pattern['sequence'])
                })

        return timeline

    def _find_sequence(self, events, target_seq):
        """在事件流中查找目标序列"""
        seq_idx = 0
        matched = []

        for event in events:
            if event['event_id'] == target_seq[seq_idx]:
                matched.append(event)
                seq_idx += 1
                if seq_idx == len(target_seq):
                    return matched

        return None
```

### 2.2 MFT 解析

```bash
# MFTEcmd (Zimmerman Tools)
# 解析 MFT 获取所有文件的时间戳
MFTECmd.exe -f \\\\.\\C: --csv c:\forensics\output

# 输出字段:
# - Entry Number
# - Sequence Number
# - Parent Path
# - File Name
# - Extension
# - Created 0x10 ($SI)
# - Last Modified 0x10 ($SI)
# - Last Accessed 0x10 ($SI)
# - Created 0x30 ($FN)
# - Last Modified 0x30 ($FN)
# - File Size
# - In Use (0 = deleted)

# 检测时间篡改 (anti-forensics)
# $SI 时间 != $FN 时间 → 可能被篡改
```

---

## 3. 内存取证

### 3.1 Volatility 3

```python
# Volatility 3 自动化分析
import volatility3
from volatility3.framework import contexts, automagic

class MemoryAnalyzer:
    """内存取证自动化"""

    def __init__(self, memory_dump):
        self.ctx = contexts.Context()
        self.ctx.config['automagic.LayerStacker.single_location'] = memory_dump

    def check_suspicious_processes(self):
        """检测可疑进程"""

        findings = []

        # 1. 列举进程
        processes = self._run_plugin('windows.pslist.PsList')

        # 检测 1: 无关联文件的进程 (进程空洞)
        for proc in processes:
            if not proc.get('ImageFileName'):
                findings.append({
                    'type': 'hollowed_process',
                    'pid': proc['PID'],
                    'name': proc['ImageFileName']
                })

        # 检测 2: PPID 欺骗
        for proc in processes:
            parent = self._get_process_by_pid(proc.get('InheritedFromUniqueProcessId'))
            if parent and proc['CreateTime'] < parent['CreateTime']:
                findings.append({
                    'type': 'ppid_spoofing',
                    'pid': proc['PID'],
                    'ppid': proc['InheritedFromUniqueProcessId']
                })

        # 检测 3: 非标准签名进程 (lsass 被注入)
        for proc in processes:
            if proc['ImageFileName'] == 'lsass.exe':
                # 检查加载的 DLL
                dlls = self._run_plugin(
                    'windows.dlllist.DllList',
                    pid=proc['PID']
                )
                for dll in dlls:
                    if not dll.get('is_signed', False):
                        findings.append({
                            'type': 'unsigned_dll_in_lsass',
                            'pid': proc['PID'],
                            'dll': dll['BaseName']
                        })

        # 检测 4: 网络连接的进程
        netstat = self._run_plugin('windows.netscan.NetScan')
        for conn in netstat:
            if conn.get('State') == 'ESTABLISHED':
                proc_name = self._get_process_name(conn.get('OwningProcess'))
                if proc_name in ['svchost.exe', 'rundll32.exe']:
                    findings.append({
                        'type': 'suspicious_network',
                        'pid': conn['OwningProcess'],
                        'remote': f"{conn['ForeignAddr']}:{conn['ForeignPort']}"
                    })

        return findings

    def _run_plugin(self, plugin_name, **kwargs):
        """运行 Volatility 插件"""
        pass  # 实际实现调用 volatility3 CLI/framework
```

---

## 4. 快速取证检查

```powershell
# 快速取证检查清单 (PowerShell)

# 1. 最近登录事件
Get-WinEvent -LogName Security -MaxEvents 100 |
    Where-Object { $_.Id -in @(4624, 4625, 4672) } |
    Select-Object TimeCreated, Id,
        @{N='User';E={$_.Properties[5].Value}},
        @{N='SourceIP';E={$_.Properties[18].Value}} |
    Format-Table -AutoSize

# 2. 持久化检查
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" }
Get-Service | Where-Object { $_.StartType -eq "Automatic" }

# 3. 新建账户 (最近 7 天)
Get-LocalUser | Where-Object {
    $_.PasswordLastSet -gt (Get-Date).AddDays(-7)
}

# 4. 进程注入检测 (可疑加载路径)
Get-Process | Select-Object Name, Id, Path |
    Where-Object { $_.Path -like "*\Temp\*" -or $_.Path -like "*\AppData\*" }

# 5. 网络连接
Get-NetTCPConnection | Where-Object {
    $_.State -eq "Established" -and
    $_.RemoteAddress -notlike "10.*" -and
    $_.RemoteAddress -notlike "172.1[6-9].*" -and
    $_.RemoteAddress -notlike "192.168.*"
}
```

---

## 参考资源

- [Zimmerman Tools (Eric Zimmerman)](https://ericzimmerman.github.io/)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- [SANS Windows Forensic Analysis Poster](https://www.sans.org/posters/windows-forensic-analysis/)

---

*上一篇：[Windows 防御与 EDR 绕过](04-windows-defense-bypass.md)*

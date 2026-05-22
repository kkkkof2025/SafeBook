# 安全工具与资源大全

> 安全学习、渗透测试、防御运营的权威资源索引

---

## 权威标准与框架

| 资源 | 地址 | 说明 |
|------|------|------|
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ | Web 安全十大风险 |
| OWASP API Top 10 | https://owasp.org/API-Security/ | API 安全风险 |
| OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | LLM 应用十大风险 |
| OWASP Mobile Top 10 | https://owasp.org/www-project-mobile-top-10/ | 移动安全风险 |
| OWASP MASVS | https://mas.owasp.org/MASVS/ | 移动应用安全验证标准 |
| CVE/NVD | https://nvd.nist.gov/ | 美国国家漏洞数据库 |
| MITRE ATT&CK | https://attack.mitre.org/ | 攻击战术知识库 |
| MITRE D3FEND | https://d3fend.mitre.org/ | 防御技术知识库 |
| CAPEC | https://capec.mitre.org/ | 攻击模式枚举 |
| CWE Top 25 | https://cwe.mitre.org/top25/ | 最危险的软件弱点 |
| NIST CSF | https://www.nist.gov/cyberframework | 网络安全框架 |
| ISO 27001 | https://www.iso.org/standard/27001 | 信息安全管理系统 |

---

## 渗透测试工具

### Web 安全
| 工具 | 地址 | 类型 |
|------|------|------|
| Burp Suite | https://portswigger.net/burp | 全栈 Web 测试平台 |
| OWASP ZAP | https://www.zaproxy.org/ | 开源 Web 扫描器 |
| sqlmap | https://sqlmap.org/ | SQL 注入自动化 |
| ffuf | https://github.com/ffuf/ffuf | Web Fuzzer |
| Nuclei | https://github.com/projectdiscovery/nuclei | 漏洞扫描模板引擎 |
| httpx | https://github.com/projectdiscovery/httpx | HTTP 探针 |
| subfinder | https://github.com/projectdiscovery/subfinder | 子域名枚举 |
| dalfox | https://github.com/hahwul/dalfox | XSS 扫描 |
| NoSQLMap | https://github.com/codingo/NoSQLMap | NoSQL 注入 |

### 基础设施
| 工具 | 地址 | 类型 |
|------|------|------|
| Nmap | https://nmap.org/ | 端口扫描与指纹 |
| Masscan | https://github.com/robertdavidgraham/masscan | 互联网扫描 |
| Metasploit | https://www.metasploit.com/ | 渗透测试框架 |
| Impacket | https://github.com/fortra/impacket | Windows 网络协议 |
| CrackMapExec | https://github.com/byt3bl33d3r/CrackMapExec | 域渗透瑞士军刀 |
| BloodHound | https://github.com/BloodHoundAD/BloodHound | AD 攻击路径分析 |
| Mimikatz | https://github.com/gentilkiwi/mimikatz | Windows 凭据提取 |

### 代码安全
| 工具 | 地址 | 类型 |
|------|------|------|
| Semgrep | https://semgrep.dev/ | 多语言 SAST |
| CodeQL | https://codeql.github.com/ | 语义代码分析 |
| SonarQube | https://www.sonarsource.com/ | 代码质量+安全 |
| Trivy | https://github.com/aquasecurity/trivy | 容器+依赖扫描 |
| Snyk | https://snyk.io/ | 开源依赖安全 |
| Dependabot | https://github.com/dependabot | GitHub 原生依赖更新 |

---

## 学习与认证

### 免费学习平台
| 平台 | 地址 | 说明 |
|------|------|------|
| PortSwigger Academy | https://portswigger.net/web-security | 免费 Web 安全课程（最推荐）|
| Hack The Box | https://www.hackthebox.com/ | 渗透测试实验室 |
| TryHackMe | https://tryhackme.com/ | 入门友好 |
| PentesterLab | https://pentesterlab.com/ | Web 渗透练习 |
| PicoCTF | https://picoctf.org/ | CTF 入门（中学生+）|
| OverTheWire | https://overthewire.org/ | Linux 安全 War Game |

### 认证路线
| 认证 | 机构 | 方向 | 难度 |
|------|------|------|------|
| OSCP | OffSec | 渗透测试 | 中高 |
| CISSP | ISC² | 信息安全综合 | 高 |
| CEH | EC-Council | 道德黑客 | 中 |
| GPEN | SANS | 渗透测试 | 高 |
| eJPT | INE | 初级渗透测试 | 低中 |
| AWS Security | AWS | 云安全 | 中 |

### 推荐书籍
| 书名 | 作者 | 领域 |
|------|------|------|
| Web 应用安全权威指南 | 德丸浩 | Web安全入门 |
| The Web Application Hacker's Handbook | Stuttard/Pinto | Web安全经典 |
| Practical Malware Analysis | Sikorski/Honig | 恶意软件分析 |
| The Art of Memory Forensics | Ligh et al. | 内存取证 |
| Security Engineering | Ross Anderson | 安全工程 |
| Threat Modeling: Designing for Security | Adam Shostack | 威胁建模 |

---

## AI 安全资源

| 资源 | 地址 | 说明 |
|------|------|------|
| OWASP LLM Top 10 | https://genai.owasp.org/ | LLM 安全风险 |
| Garak (LLM 安全扫描) | https://github.com/leondz/garak | LLM 漏洞扫描 |
| Lakera Guard | https://www.lakera.ai/ | Prompt 注入检测 |
| Guardrails AI | https://www.guardrailsai.com/ | LLM 输出护栏 |
| NIST AI RMF | https://www.nist.gov/ai-risks | AI 风险管理框架 |
| MITRE ATLAS | https://atlas.mitre.org/ | AI 系统攻击知识库 |
| OWASP ML Top 10 | https://owasp.org/www-project-machine-learning-security-top-10/ | ML 安全风险 |

---

## 安全资讯

| 来源 | 地址 | 频率 |
|------|------|------|
| Krebs on Security | https://krebsonsecurity.com/ | 日报 |
| The Hacker News | https://thehackernews.com/ | 日报 |
| BleepingComputer | https://www.bleepingcomputer.com/ | 日报 |
| /r/netsec (Reddit) | https://reddit.com/r/netsec | 社区 |
| SANS ISC Podcast | https://isc.sans.edu/ | 周播 |
| Risky Business | https://risky.biz/ | 周播 |
| Darknet Diaries | https://darknetdiaries.com/ | 播客 |

---

*下一篇：[安全术语表](glossary.md)*

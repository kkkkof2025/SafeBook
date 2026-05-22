# 学习路径总览

> 安全不是一门可以速成的学科，但有清晰的学习路径可以让你少走弯路。

---

## 安全学习全景图

```
零基础 → 基础夯实(3-6月) → Web安全入门(2-4月) → 实战进阶(6-12月) → 专项深入

第 0 阶段: 计算机基础    第 1 阶段: Web安全    第 2 阶段: 实战      第 3 阶段: 专项
├─ 计算机网络              ├─ OWASP Top 10       ├─ CTF 竞赛           ├─ 云安全
├─ HTTP/HTTPS 协议         ├─ SQL注入/XSS/CSRF   ├─ 漏洞赏金 (SRC)     ├─ AI安全
├─ Linux 基础命令           ├─ Burp Suite/ZAP     ├─ 代码审计           ├─ 移动/工控/IoT
├─ 编程基础 (Python)       ├─ DVWA/WebGoat 靶场 ├─ 红蓝对抗           ├─ 逆向/二进制
└─ Web 应用架构            └─ 安全工具链         └─ CTF 高阶          └─ 威胁情报
```

---

## 详细路线图

### 📅 第 0 阶段：基础夯实 (1-3 个月)

**目标**：建立计算机基础，能看懂网络通信和安全工具输出。

| 周次 | 主题 | 资源 | 本书章节 |
|------|------|------|----------|
| 1-2 | 计算机网络基础 | 《计算机网络：自顶向下》或 B 站视频 | [已读 →](basics/01-networking.md) |
| 3-4 | HTTP 协议深入 | MDN HTTP 文档 + Burp Suite 实战 | [已读 →](basics/02-http.md) |
| 5-6 | Linux 命令行 | ` overthewire.org/bandit` | ... |
| 7-8 | Python 编程基础 | `automatetheboringstuff.com` | ... |
| 9-10 | Web 应用架构 | 前端/后端/数据库交互理解 | [已读 →](basics/03-web-architecture.md) |
| 11-12 | 安全工具入门 | Nmap/Burp/ZAP/Wireshark | [已读 →](basics/04-tools.md) |

**里程碑**：能独立搭建 DVWA 靶场，理解 HTTP 请求/响应结构。

---

### 📅 第 1 阶段：Web 安全核心 (2-4 个月)

**目标**：掌握 OWASP Top 10 每个漏洞的原理和利用。

| 周次 | 主题 | 靶场练习 | 本书章节 |
|------|------|----------|----------|
| 1-2 | SQL 注入 (含二阶/盲注) | SQLi-Labs + DVWA | [详细 →](../chapters/01-web-security/01-sql-injection.md) |
| 3 | XSS (反射/存储/DOM) | XSS Game + DVWA | [详细 →](../chapters/01-web-security/02-xss.md) |
| 4 | CSRF + SSRF | PortSwigger Labs | [CSRF→](../chapters/01-web-security/03-csrf.md) · [SSRF→](../chapters/01-web-security/04-ssrf.md) |
| 5 | 认证与授权漏洞 | WebGoat (Auth 模块) | [认证绕过 →](../chapters/01-web-security/06-authentication-bypass.md) |
| 6 | 文件上传 + RCE | DVWA + Upload Labs | [上传→](../chapters/01-web-security/08-file-upload.md) · [RCE→](../chapters/01-web-security/05-rce.md) |
| 7 | XXE + 反序列化 | WebGoat + 自建靶场 | [XXE→](../chapters/01-web-security/09-xxe.md) · [反序列化→](../chapters/01-web-security/10-deserialization.md) |
| 8 | IDOR + 访问控制 | PortSwigger Labs (Access Ctrl) | [IDOR →](../chapters/01-web-security/07-idor.md) |

**里程碑**：能在 DVWA 和 WebGoat 中独立完成所有漏洞利用。

---

### 📅 第 2 阶段：实战进阶 (6-12 个月)

**目标**：从靶场走向真实场景——CTF、SRC、HVV。

| 月份 | 主题 | 活动 | 本书参考 |
|------|------|------|----------|
| 1-2 | CTF 入门 (Web+Misc) | CTFtime.org 找比赛 | [CTF 章节 →](../ctf/) |
| 3-4 | 漏洞赏金 (SRC) | 补天/漏洞盒子/HackerOne | [CVE/POC →](../cve-poc/) |
| 5-7 | 代码审计 | PHP/Java/Python 开源项目审计 | [安全编码 →](../secure-coding/) |
| 8-9 | 内网渗透 | 红蓝对抗演练 | [HVV 章节 →](../hvv/) |
| 10-12 | 云安全 + 容器 | AWS/Azure/K8s 攻防 | [云安全 →](../cloud-security/) |

---

### 📅 第 3 阶段：专项深入 (持续)

**目标**：选择方向深入，形成核心竞争力。

| 方向 | 技能栈 | 本书章节 |
|------|--------|----------|
| **Web 安全专家** | WAF 绕过、逻辑漏洞挖掘、API 安全 | [Web 安全章](../chapters/01-web-security/) · [API](../api-security/) |
| **云安全工程师** | AWS/Azure/GCP 安全、K8s 安全 | [云安全](../cloud-security/) · [容器](../container-security/) |
| **红队/渗透测试** | C2框架、免杀、横向移动、域渗透 | [HVV](../hvv/) · [红队](../red-team/) · [社工](../social-engineering/) |
| **威胁情报分析师** | APT 跟踪、IOC 生产、ATT&CK 映射 | [威胁情报](../threat-intel/) · [APT](../ransomware-apt/) |
| **二进制/逆向** | IDA Pro/Ghidra、Fuzzing、Exploit 开发 | [逆向](../reverse-engineering/) · [系统安全](../system-security/) |
| **AI 安全** | LLM 攻击面、Agent 安全、模型红队 | [AI 安全](../ai-security/) · [AI 进阶](../advanced-ai-security/) |

---

## 推荐学习资源

- **免费靶场**: [DVWA](https://github.com/digininja/DVWA) · [WebGoat](https://github.com/WebGoat/WebGoat) · [PortSwigger Labs](https://portswigger.net/web-security)
- **CTF 平台**: [CTFtime](https://ctftime.org/) · [BUUCTF](https://buuoj.cn/) · [攻防世界](https://adworld.xctf.org.cn/)
- **SRC 平台**: 补天 · 漏洞盒子 · HackerOne · Bugcrowd
- **书籍推荐**: 《白帽子讲Web安全》《Web安全开发指南》《Web Hacking 101》
- **YouTube/B站**: LiveOverflow · IppSec · The Cyber Mentor

---

## 📚 推荐阅读顺序

| 你的背景 | 本书推荐阅读顺序 |
|----------|-----------------|
| 零基础 | [入门基础 →](../basics/00-intro.md) [Web 安全 →](../chapters/01-web-security/index.md) [云安全 →](../cloud-security/) [学习路径](#) [AI 安全 →](../ai-security/) |
| 有 Web 基础 | [Web 安全 →](../chapters/01-web-security/) [云安全 →](../cloud-security/) [容器 →](../container-security/) [AI →](../ai-security/) [CVE/POC →](../cve-poc/) |
| 安全从业者 | 按需阅读，重点 [AI 安全](../ai-security/) / [云安全](../cloud-security/) / [供应链](../supply-chain-security/) / [HVV](../hvv/) |
| CTF 选手 | [Web 安全](../chapters/01-web-security/) + [系统安全](../system-security/) + [CTF](../ctf/) + [漏洞数据库](../vulnerability-databases/) |
| 开发者 | [Web 安全](../chapters/01-web-security/) + [容器安全](../container-security/) + [安全编码](../secure-coding/) + [供应链](../supply-chain-security/) |

---

## 学习建议

1. **不要追求一步到位**——安全是积累型技能。今天看懂一个漏洞，明天多跑一个 POC，后天修复一个 Bug。
2. **动手 > 阅读**——每看完一篇文章，打开靶场实操至少 30 分钟。
3. **记录学习笔记**——学完一个漏洞后用自己的话写一份"如果是我怎么修复"的方案。
4. **加入社区**——关注安全公众号、加入微信群、参加线下 Meetup。
5. **保持好奇**——安全的核心能力不是技术栈的广度，而是"为什么能绕过"的好奇心。

---

*下一篇：[安全学习路线图](01-learning-path.md)*

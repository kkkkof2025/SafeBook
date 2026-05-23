# 安全工具入门

> 工欲善其事，必先利其器 — 安全从业者的工具箱

---

## 工具图谱

```
信息收集          漏洞扫描          漏洞利用          报告
───────          ───────          ───────          ──────
nmap              OWASP ZAP        Burp Suite       Markdown
subfinder         Nuclei           sqlmap           Dradis
httpx             Nikto            Metasploit
WhatWeb           WPScan
```

---

## 核心工具详解

### 1. Burp Suite — 安全从业者的瑞士军刀

**用途**：Web 安全测试的核心工具，拦截和修改 HTTP 请求/响应。

```text
Burp Suite Community Edition（免费）
├── Proxy      ← 抓包、修改请求
├── Repeater   ← 重复发送修改后的请求
├── Intruder   ← 自动化枚举和暴力破解
├── Decoder    ← 编解码（Base64/URL/Hex）
└── Sequencer  ← 随机性分析（Cookie/Token）

Burp Suite Professional（付费）
├── Scanner    ← 自动化漏洞扫描
└── Extensions ← 插件（Auth Analyzer、Turbo Intruder）
```

**入门操作**：

```
1. 启动 Burp Suite
2. Proxy → Intercept → 开启拦截
3. 浏览器设置代理到 127.0.0.1:8080
4. 访问目标网站 → Burp 抓到请求
5. 修改请求内容 → Forward
6. 对感兴趣的请求右键 → Send to Repeater
7. 在 Repeater 中反复修改和发送
```

### 2. Nmap — 网络扫描器

**用途**：扫描目标开放端口、运行服务、操作系统识别。

```bash
# 基础扫描
nmap 192.168.1.1

# 端口范围扫描
nmap -p 1-1000 192.168.1.1

# 服务版本检测
nmap -sV 192.168.1.1

# 操作系统检测
nmap -O 192.168.1.1

# 全面扫描
nmap -sC -sV -O 192.168.1.1

# 扫描整个网段
nmap 192.168.1.0/24
```

### 3. SQLmap — SQL 注入自动化

**用途**：检测和利用 SQL 注入漏洞。

```bash
# 基础用法
sqlmap -u "http://target.com/page?id=1"

# 带 Cookie
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc"

# 获取数据库列表
sqlmap -u "http://target.com/page?id=1" --dbs

# 获取表
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# 获取数据
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump
```

### 4. OWASP ZAP — 免费开源扫描器

**用途**：Burp Suite 的免费替代品，内置自动扫描功能。

```text
功能：
├── 自动爬虫 ← 自动发现页面
├── 被动扫描 ← 浏览时自动检测
├── 主动扫描 ← 模拟攻击检测漏洞
├── HUD      ← 在浏览器中直接操作
└── API      ← 可集成到 CI/CD
```

---

## 工具推荐路径

| 阶段 | 工具 | 说明 |
|------|------|------|
| 入门 | Burp Suite + 浏览器 | 最基础配置 |
| 进阶 | 加 Nmap + SQLmap | 扩大测试范围 |
| 专业 | 加 Nuclei + 自定义脚本 | 自动化 |

---

## 搭建自己的实验环境

```bash
# DVWA（Damn Vulnerable Web Application）
docker run -d -p 80:80 vulnerables/web-dvwa

# PortSwigger Labs（在线，无需搭建）
https://portswigger.net/web-security/all-labs

# VulHub（多种漏洞环境）
git clone https://github.com/vulhub/vulhub.git
cd vulhub/xxx
docker compose up -d
```

---

## 小结

- Burp Suite 是必修课，每天都要用
- Nmap 让你了解目标的网络暴露面
- SQLmap 是 SQL 注入的利器，但要理解原理再使用
- 不用记所有命令和参数，知道"用什么工具做什么事"就够了

[上一章：Web 应用架构](03-web-architecture.md) | [下一章：信息收集与侦察 →](05-reconnaissance.md)

*上一篇：[Web 应用架构](03-web-architecture.md)*

*下一篇：[信息收集与侦察](05-reconnaissance.md)*

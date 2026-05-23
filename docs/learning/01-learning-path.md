# 安全学习路线图

> **从哪里开始，走向哪里** — 从零基础到专业安全工程师的路线图

---

## 四个阶段

### 第一阶段：基础奠基（0-6 个月）

**目标**：理解 Web 工作原理，掌握基本安全概念。

**必备技能**：
- HTTP/HTTPS 协议（请求、响应、Cookie、Session、CORS）
- HTML/CSS/JavaScript 基础
- 一种后端语言（Python/Java/PHP）
- 数据库基础（SQL）
- Linux 基础命令

**推荐实践**：
1. 搭建自己的靶场：DVWA、WebGoat
2. 学会使用 Burp Suite 抓包改包
3. 理解 OWASP Top 10 各个漏洞的基本概念
4. 完成 PortSwigger Web Security Academy 的免费课程

### 第二阶段：深入理解（6-12 个月）

**目标**：能够独立发现和利用常见漏洞，理解防御措施。

**必备技能**：
- 精通 OWASP Top 10 每个漏洞的原理和利用
- 能够编写简单的 POC 脚本（Python）
- 理解 WAF 和常见安全防御机制
- 学会绕过常见防护（编码、大小写、双写等）
- 掌握 SQLMap、XSSer、Nmap 等工具

**推荐实践**：
1. 参加 CTF 比赛（BugKu、CTFHub、XCTF）
2. 在 HackerOne/Bugcrowd 上寻找低难度漏洞
3. 写博客记录自己学到的知识
4. 搭建自己的测试环境（Vulhub、Vulfocus）

### 第三阶段：专业化（1-2 年）

**目标**：选择一个方向深入，成为该领域的专家。

**可选方向**：

| 方向 | 工作内容 | 需要学习 |
|------|----------|----------|
| Web 安全工程师 | 渗透测试、代码审计 | 代码审计、框架漏洞、APISec |
| 安全研发 | 安全工具、WAF、RASP | 开发能力 + 安全知识 |
| 安全运维 | 安全监控、应急响应 | SIEM、EDR、威胁情报 |
| 移动安全 | App 安全测试 | Android/iOS 逆向、Hook |
| 云安全 | 云架构安全 | AWS/Azure/GCP、容器、K8s |
| AI 安全 | LLM 安全、对抗攻击 | ML 基础、Prompt 攻防 |

**推荐实践**：
1. 考取认证：OSCP、CISSP、CEH
2. 在博客/公众号建立技术影响力
3. 参与开源安全项目
4. 在漏洞赏金平台实战

### 第四阶段：进阶（2-5 年）

**目标**：成为安全架构师或安全团队负责人。

**技能**：
- 安全架构设计
- 安全体系规划
- 团队管理与培训
- 安全合规与审计
- 高级威胁分析与狩猎

---

## 学习资源优先级

```
★★★★★ 必读/必学
★★★★  强烈推荐
★★★   值得了解
★★    可选择性了解
★     参考

第一阶段：
★★★★★ OWASP Top 10
★★★★★ PortSwigger Web Security Academy
★★★★★ HTTP: The Definitive Guide
★★★★   WebGoat / DVWA
★★★★   Burp Suite 官方教程

第二阶段：
★★★★★ The Web Application Hacker's Handbook
★★★★★ 代码审计：企业级 Web 代码安全架构
★★★★   CTF 竞赛入门
★★★★   SQLMap 文档
★★★    Metasploit Unleashed

第三阶段：
★★★★★ OWASP Testing Guide
★★★★★ Red Team Field Manual
★★★★   OSCP 备考指南
★★★★   Bug Bounty: Hacking for Profit
★★★    Attacking Network Protocols

第四阶段：
★★★★★ Threat Modeling: Designing for Security
★★★★   Security Engineering (Ross Anderson)
★★★★   CISSP 备考
★★★    The Art of Invisibility
```

---

## 关键里程碑

```mermaid
gantt
    title 安全学习路线（2 年规划）
    dateFormat  YYYY-MM-DD
    section 基础
    HTTP/Web 基础           :a1, 0, 90d
    OWASP Top 10 理解       :a2, 30d, 120d
    Burp Suite 熟练使用     :a3, 60d, 90d
    
    section 进阶
    CTF 竞赛                :b1, 120d, 180d
    漏洞挖掘实战           :b2, 180d, 240d
    代码审计学习            :b3, 200d, 300d
    
    section 专业化
    方向选择                :c1, 365d, 30d
    OSCP 备考               :c2, 400d, 180d
    漏洞赏金                :c3, 400d, 365d
    
    section 持续发展
    技术博客                :d1, 180d, 730d
    开源贡献                :d2, 365d, 730d
    安全社区参与            :d3, 180d, 730d
```

---

## 最重要的三条建议

1. **动手 > 读书**：安全是实践学科。读十遍不如自己跑一次 POC
2. **持续学习**：安全行业变化极快，新技术/新漏洞每天都在出现
3. **合法测试**：永远在授权范围内测试，不要触碰法律红线

*下一篇：[推荐学习平台](02-platforms.md)*

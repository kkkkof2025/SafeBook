<div align="center">

# 🛡️ 安全漏洞实战手册

### 从 Web 安全到 AI 安全 — 每个漏洞的原理、案例、POC 与修复

[![GitHub Pages](https://img.shields.io/github/deployments/kkkkof2025/SafeBook/github-pages?label=Pages&logo=github&style=flat-square)](https://kkkkof2025.github.io/SafeBook/)
[![GitHub last commit](https://img.shields.io/github/last-commit/kkkkof2025/SafeBook?style=flat-square&logo=git)](#)
[![GitHub repo size](https://img.shields.io/github/repo-size/kkkkof2025/SafeBook?style=flat-square&logo=github)](#)
[![GitHub license](https://img.shields.io/github/license/kkkkof2025/SafeBook?style=flat-square)](#)
[![GitHub stars](https://img.shields.io/github/stars/kkkkof2025/SafeBook?style=flat-square&logo=github)](#)
[![Visitors](https://visitor-badge.laobi.icu/badge?page_id=kkkkof2025.SafeBook&left_text=Visitors&right_color=red)](#)

🔗 **在线阅读**: [kkkkof2025.github.io/SafeBook](https://kkkkof2025.github.io/SafeBook/)

</div>

---

## 📖 关于本书

一本系统性安全漏洞实战手册，从 Web 经典漏洞到 AI 安全前沿，**每个漏洞都包含**：

- **原理剖析** — 漏洞为什么存在，攻击者怎么利用
- **实战案例** — 真实世界中的漏洞案例
- **POC 示例** — 可复现的概念验证代码
- **修复方案** — 防御方的加固指南

目标：让认真读完的人，真正具备安全防御和漏洞分析能力。

---

## 📚 章节

全书共 **50+ 章，250+ 篇文章**。

| 章 | 分类 | 文章数 | 内容 |
|----|------|--------|------|
| 01 | 入门基础 | 6 | 白帽黑客之路/网络/HTTP/Web/工具/信息收集 |
| 02 | Web 安全 | 14 | SQL/XSS/CSRF/SSRF/RCE/认证/IDOR/文件上传/XXE/反序列化/WebSocket/OAuth/SSTI |
| 03 | 云安全 | 7 | 共享责任/IAM/存储/网络/Serverless/合规/CSPM |
| 04 | 容器/K8s 安全 | 3 | Docker/K8s/供应链 |
| 05 | 供应链安全 | 5 | CI/CD/依赖/SBOM/SLSA/签名 |
| 06 | 系统安全 | 7 | 缓冲区溢出/提权/持久化/Windows/AD |
| 07 | 移动安全 | 4 | Android/iOS/加固 |
| 08 | 数据隐私 | 5 | 脱敏/法规/应急/Design/DLP |
| 09 | AI 安全(LLM) | 5 | Prompt注入/Agent/钓鱼/污染 |
| 10 | AI 安全进阶 | 5 | 红队/模型评估/投毒/Agent逃逸 |
| 11 | 密码学 | 4 | 哈希/对称/TLS/签名 |
| 12 | OWASP Top 10 | 2 | 深度解析 |
| 13 | API 安全 | 4 | 测试/渗透/认证/GraphQL |
| 14 | IoT 安全 | 2 | 固件分析 |
| 15 | CVE/POC | 4 | 中间件/框架/重大CVE |
| 16 | HVV/CTF | 10 | 红蓝对抗/CTF全题型 |
| 17 | 社会工程 | 3 | 钓鱼/高级社工 |
| 18 | 区块链/Web3 | 2 | 智能合约/DeFi安全 |
| 19 | 威胁情报 | 2 | ATT&CK/威胁狩猎 |
| 20 | 零信任/IAM | 1 | 零信任架构 |
| 21 | 云原生安全 | 2 | 云原生/Istio Service Mesh |
| 22 | 浏览器安全 | 1 | SOP/V8/沙箱 |
| 23 | 勒索软件/APT | 1 | 攻击链/案例分析 |
| 24 | 电子邮件安全 | 1 | SPF/DKIM/DMARC |
| 25 | 安全编码 | 2 | Python/Web |
| 26 | Windows 内部 | 1 | VBS/HVCI/ASR |
| 27 | 合规审计 | 1 | ISO27001/等保/SOC2 |
| 28+ | 逆向/工控/无线 | 各1 | 基础概述 |

---

## 🚀 快速开始

```bash
# 本地预览
git clone git@github.com:kkkkof2025/SafeBook.git
cd SafeBook
pip install -r requirements-docs.txt
mkdocs serve

# 打开浏览器访问 http://localhost:8000
```

---

### 在线阅读

直接访问 [kkkkof2025.github.io/SafeBook](https://kkkkof2025.github.io/SafeBook/) 即可在线阅读，支持搜索、导航折叠、代码高亮。

---

## 🚧 待补充计划

### ✅ 已完成（2026-05-22 审查修复）

- [x] OWASP Top 10 深度解析（18000 字全面重写）
- [x] 密码学概述页（时间线+三大支柱+误区表）
- [x] 学习路径总览（4阶段路线图+周计划+里程碑）
- [x] OpenClaw→Agent 平台安全实战
- [x] CI/CD 新增 Jenkins Pipeline + GitLab CI
- [x] 统计数据统一（50+章/250+篇）
- [x] SUMMARY.md 完整同步
- [x] SBOM 去重

### 待办 — 内容深度

- [ ] **CVE/POC 实战分析** — Log4Shell 完整走一遍：公告→分析→POC→验证→修复
- [ ] **容器安全概述充實** — 补充攻击面图、top 5 误区
- [ ] **漏洞数据库章节正文** — CNVD/CNNVD 深度、NVD/CVE/MITRE 使用
- [ ] **云安全深潜** — AWS GuardDuty/SecurityHub + Azure Defender + GCP SCC
- [ ] **SOC 扩展** — SIEM 规则优化、威胁狩猎进阶
- [ ] **欺骗防御扩展** — 蜜罐数据分析、自动化欺骗响应
- [ ] **量子安全扩展** — 后量子迁移案例研究
- [ ] **硬件安全扩展** — 芯片安全攻击（故障注入/侧信道进阶）

### 待办 — 章节补齐

- [ ] **蓝队防御扩展** — 日志分析/事件响应/SOAR 进阶
- [ ] **OSINT 扩展** — 社交媒体情报高级技巧
- [ ] **合规审计扩展** — 等保 2.0 三级/密评

### 待办 — 网站质量

- [ ] 修复缺失导航页（container-image-security, osint-advanced-tools 等）
- [ ] 修复锚点链接警告（_03 系列文件的"上一篇/下一篇"中文链接）
- [ ] 所有章节添加 index.md 概述页

---

## 🔗 相关链接

- [在线阅读](https://kkkkof2025.github.io/SafeBook/)
- [GitHub 仓库](https://github.com/kkkkof2025/SafeBook)
- [prompts — AI 学习方法全景书](https://kkkkof2025.github.io/prompts/)（姊妹项目）

---

## 📄 许可

本项目采用 **MIT License** — 可自由使用、修改、分发。

---

<div align="center">
  
**如果这个项目对你有帮助，欢迎 ⭐ Star ✨**

</div>

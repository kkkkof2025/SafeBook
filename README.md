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

> 📌 **面向读者**：安全从业者、渗透测试工程师、安全开发、CTF 选手、对安全感兴趣的学生

---

## 🗺️ 内容结构

| # | 章节 | 文章数 | 状态 |
|---|------|--------|------|
| 1 | **入门基础** — 白帽黑客之路、网络基础、HTTP、工具入门 | 6 | ✅ 完成 |
| 2 | **Web 安全** — SQL 注入、XSS、CSRF、SSRF、RCE、认证绕过、IDOR、文件上传、XXE、反序列化 | 11 | ✅ 完成 |
| 3 | **学习路径** — 学习路线图、推荐平台、职业发展 | 4 | ✅ 完成 |
| 4 | **云安全** — 共享责任、IAM、存储、网络、Serverless、合规、CSPM | 8 | ✅ 完成 |
| 5 | **容器与 K8s 安全** — Docker/K8s/供应链 | 4 | ✅ 完成 |
| 6 | **供应链安全** — CI/CD 安全、依赖投毒防御 | 3 | ✅ 完成 |
| 7 | **系统安全** — 缓冲区溢出、Linux 提权 | 3 | ✅ 完成 |
| 8 | **移动安全** — Android/iOS 安全测试 | 3 | ✅ 完成 |
| 9 | **数据隐私与合规** — 脱敏与隐私保护 | 2 | ✅ 完成 |
| 10 | **AI 安全** — LLM 漏洞、提示注入、OpenClaw 安全、AI 钓鱼、内容污染 | 6 | ✅ 完成 |
| 11 | **AI 安全进阶** — AI 红队、Agent 多步攻击 | 3 | ✅ 完成 |
| 12 | **CVE 漏洞库与 POC** — Awesome-POC 实战、中间件/框架 CVE | 4 | ✅ 完成 |
| 13 | **HVV 护网行动** — 发展史、红蓝对抗全流程、实战攻击链 | 2 | ✅ 完成 |
| 14 | **安全学习平台与 CTF** — 20+ 国际/国内平台、CTF 策略、社区资源 | 3 | ✅ 完成 |
| 15 | **漏洞数据库平台** — CNVD/CNNVD/NVD/CVE/CWE/CVSS | 4 | ✅ 完成 |
| 16 | **附录** — 资源引用、术语表、安全检查清单 | 3 | ✅ 完成 |

> 📊 **总计**: 16 个章节 · **70+ 篇文章** · 持续扩展中

---

## 🌟 核心特色

### 覆盖面广

```
Web 安全 → 云安全 → 容器安全 → 供应链安全 → 
系统安全 → 移动安全 → 数据隐私 → AI 安全 →
CVE/POC → HVV → CTF 平台 → 漏洞数据库
```

从经典 SQL 注入到 AI 红队测试，一个项目覆盖全链路。

### 每个漏洞都有实操 POC

```python
# SQL 注入 — POC 示例
sqli_payload = "' UNION SELECT username, password FROM users--"
```

```bash
# Shiro 反序列化 — 利用命令
java -jar ShiroAttack2.jar -u http://target/login.jsp
```

### AI 安全是核心亮点

不仅涵盖传统的 OWASP Top 10，还深入 AI 安全：

- **Prompt 注入攻击与防御**
- **OpenClaw Agent 安全架构**
- **AI 辅助钓鱼的检测代码**
- **RAG 内容污染鉴别技术**

### 国产安全专属

针对国内安全从业者：

- CNVD/CNNVD 详解与对比
- HVV 护网行动攻防指南
- 国内 SRC/社区/公众号资源
- 国内 CTF 赛事与平台

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

### 在线阅读

直接访问 [kkkkof2025.github.io/SafeBook](https://kkkkof2025.github.io/SafeBook/) 即可在线阅读，支持搜索、导航折叠、代码高亮。

---

## 🎯 路线图

### ✅ 已完成

- [x] 全书骨架搭建（红色 Material 主题）
- [x] 16 章全部内容撰写
- [x] GitHub Actions 自动部署
- [x] 导航折叠（JS 实现）
- [x] 代码块中文字体修复
- [x] CVE/CNVD/CNNVD 官方数据库详解

### 🔄 待补充

- [ ] **密码学专题** — 常见加密漏洞、TLS 安全
- [ ] **内网渗透** — 横向移动、域渗透
- [ ] **IoT 安全** — 固件分析、硬件安全
- [ ] **API 安全** — REST/GraphQL 安全测试
- [ ] **云原生深度** — Service Mesh、eBPF 安全
- [ ] **零信任架构** — ZTA 原理与落地
- [ ] **安全开发流程** — SDL/S-SDLC、DevSecOps

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

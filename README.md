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

全书共 **54 章，286 篇文章**（2026-05-22 实时统计）。

| 章 | 分类 | 文章数 | 内容 |
|----|------|--------|------|
| 入门基础 | 7 | 白帽黑客之路/网络/HTTP/Web架构/安全工具/信息收集 |
| Web 安全 | 14 | SQL/XSS/CSRF/SSRF/RCE/认证/IDOR/文件上传/XXE/反序列化/WebSocket/OAuth/SSTI |
| 云安全 | 8 | 共享责任/IAM/存储/网络/Serverless/合规/CSPM |
| AWS 云安全 | 4 | AWS安全服务/Azure对照/Threat Detection |
| 容器安全 | 6 | Docker/K8s/供应链/攻击面/漏洞管理/容器逃逸 |
| 云原生安全 | 7 | K8s RBAC/Service Mesh/Falco/eBPF/K8s安全工具 |
| 供应链安全 | 6 | CI/CD/依赖/SBOM/SLSA/签名/SBOM管理 |
| 系统安全 | 8 | 缓冲区溢出/Linux提权/Windows/AD CS/Linux持久化 |
| 移动安全 | 5 | Android/iOS/API/加固/移动TOP10 |
| 数据隐私 | 6 | 脱敏/法规/隐私设计/DLP/泄漏/数据分类 |
| AI 安全(LLM) | 6 | Prompt注入/Agent平台安全/AI钓鱼/内容污染/RAG防御 |
| AI 安全进阶 | 6 | 红队/模型评估/投毒/对抗性/模型窃取 |
| 密码学 | 7 | 哈希/对称/TLS/签名/密码分析/实用密码学/ZKP |
| OWASP Top 10 | 6 | 深度解析(18000字)/Web漏洞扫描/OWASP ASVS |
| API 安全 | 7 | 设计与测试/渗透/认证深度/GraphQL/OAuth2/速率限制 |
| IoT 安全 | 6 | 固件分析/通信协议/云平台安全/测试/开发/逆向 |
| CVE/POC | 6 | 中间件/框架/Log4Shell全生命周期/漏洞分析/挖掘 |
| HVV 实战 | 4 | 攻击技术/防御策略/实战复盘 |
| CTF 竞赛 | 8 | 各题型详解+靶场平台 |
| 社会工程 | 5 | 钓鱼/身份冒充/高级社工/内部威胁 |
| 区块链/Web3 | 6 | 智能合约审计/DeFi/钱包/MEV/链分析 |
| 威胁情报 | 8 | ATT&CK/平台自动化/生命周期/分析/TIP |
| 身份管理(IAM) | 9 | 联合身份/JIT/PAM/零信任/SSO-OAuth/云IAM |
| 浏览器安全 | 5 | 攻击面/扩展/浏览器指纹/同源策略 |
| 勒索软件/APT | 5 | 攻击链/案例/防御/应急/威胁组织 |
| 电子邮件安全 | 5 | SPF/DKIM/DMARC/邮件钓鱼分析/安全测试 |
| 安全编码 | 5 | Python/Web/代码审查/清单 |
| Windows 内部 | 6 | VBS/HVCI/ASR/EDR/AD CS/取证 |
| 合规审计 | 5 | ISO27001/SOC2/等保2.0/PCI-DSS/GDPR对比 |
| 逆向工程 | 5 | x86/x64/ARM/Ghidra/IDA Pro |
| 工控安全 | 5 | SCADA/PLC/Modbus/DNP3/威胁狩猎 |
| 无线安全 | 5 | WiFi/WPA3/Bluetooth/渗透测试 |
| 无密码认证 | 5 | Passkeys/WebAuthn/FIDO2/迁移 |
| 国密算法 | 4 | SM2/SM3/SM4/PKI |
| 5G 安全 | 4 | 核心网/网络切片 |
| 网络安全架构 | 5 | 零信任/微分段/安全网关/SDN |
| OSINT | 5 | 工具链/社交媒体/暗网/进阶 |
| DevSecOps | 6 | SAST/DAST/SCA/Shift-Left/混沌工程 |
| 蓝队防御 | 6 | 蓝图/操作/自动化/威胁狩猎/SOC |
| 欺骗防御 | 4 | 蜜罐/蜜网/数据分析 |
| SOC 运营 | 5 | 概述/SIEM规则/自动化SOAR |
| 红队技术 | 4 | 战术/行动安全 |
| 红队基础设施 | 4 | C2框架/域前置/反检测 |
| 恶意软件分析 | 7 | 静态/动态/YARA/内存取证/沙箱/实战 |
| 车联网安全 | 5 | 车辆入侵/V2X/取证 |
| 漏洞数据库 | 6 | CNVD/CNNVD/NVD/CVE/MITRE |
| 量子安全 | 4 | PQC算法/QKD/迁移 |
| 硬件安全 | 4 | 固件逆向/芯片安全/侧信道 |
| 中国法律 | 4 | 数据安全法/个保法/跨境传输 |
| 安全平台工具 | 8 | 工具和平台速查 |
| 学习路径 | 4 | 4阶段路线图/资源/职业发展 |

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

## 🚧 待办计划（v2.9）

### ✅ 已完成

- [x] Nav 全部修复（286页 100% 在导航中）
- [x] 锚点/跨文件链接 ~100 处修复
- [x] 构建警告从 35 降至 0
- [x] 54 章全部 >=4 篇文章
- [x] 16 章缺失 index.md 全部补齐
- [x] OWASP Top 10 深度解析（18000字重写）
- [x] Log4Shell 全生命周期实战
- [x] CNVD/CNNVD 深度
- [x] 等保 2.0 + GDPR 对比
- [x] WebAuthn 前后端完整实现
- [x] MEV 三明治攻击深潜
- [x] 安全混沌工程
- [x] 芯片安全（侧信道/故障注入）
- [x] C2 反检测（域前置/JA3伪装）
- [x] 云原生威胁检测（Falco/eBPF）
- [x] SOC 自动化/SOAR 实战
- [x] Windows 取证深度
- [x] 恶意软件分析实战

### ✅ 全部完成（2026-05-23 凌晨）

- [x] 21 篇短文全部扩展至 3-8KB 技术深度
- [x] SLSA 框架（672B → 4096B）
- [x] 签名验证（811B → 6054B）
- [x] 隐私设计（1155B → 6310B）
- [x] HVV 攻击技术（1315B → 4744B）
- [x] HVV 防御策略（1151B → 3569B）
- [x] 系统安全 3 篇扩展（ROP/持久化/Windows加固）
- [x] 渗透测试方法论（1334B → 3318B）
- [x] IoT 安全概述（1458B → 2914B）
- [x] iOS 安全（1767B → 4546B）
- [x] Android 加固（1930B → 7660B）
- [x] API 安全设计+渗透（~3600B → 各 5KB+）
- [x] 蓝队操作（1911B → 4029B）
- [x] 模型安全评估（1586B → 5758B）
- [x] WebSocket 安全（1717B → 5070B）
- [x] SSTI 深度（1942B → 4745B）
- [x] 密码学哈希（1849B → 4469B）
- [x] TLS/PKI（1733B → 5043B）
- [x] 安全资源（1802B → 4295B）
- [x] 构建警告 0（全部交叉引用已修复）
- [x] 版本号统一为 v3.0

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

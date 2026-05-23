# 安全术语表

> 本书涵盖的安全术语速查，按领域分类

---

## Web 安全

| 术语 | 英文 | 定义 |
|------|------|------|
| SQL 注入 | SQL Injection | 攻击者将恶意 SQL 代码注入查询，操控数据库 |
| XSS | Cross-Site Scripting | 恶意脚本注入网页，在用户浏览器执行 |
| CSRF | Cross-Site Request Forgery | 利用用户已登录状态，伪造请求执行操作 |
| SSRF | Server-Side Request Forgery | 利用服务端发起内网请求，穿透网络边界 |
| RCE | Remote Code Execution | 远程代码执行，攻击者完全控制服务器 |
| IDOR | Insecure Direct Object Reference | 越权访问其他用户的数据资源 |
| XXE | XML External Entity | 利用 XML 外部实体读取文件或发起 SSRF |
| SSTI | Server-Side Template Injection | 服务端模板注入，可在服务器执行任意代码 |
| LFI/RFI | Local/Remote File Inclusion | 本地/远程文件包含漏洞 |
| WebSocket | WebSocket Protocol | 全双工通信协议，可能绕过传统 HTTP 安全控制 |

## 认证与授权

| 术语 | 英文 | 定义 |
|------|------|------|
| 2FA/MFA | Two-Factor/Multi-Factor Authentication | 双因素/多因素认证 |
| JWT | JSON Web Token | 无状态身份验证令牌 |
| OAuth 2.0 | Open Authorization 2.0 | 第三方授权协议框架 |
| OIDC | OpenID Connect | 基于 OAuth 2.0 的身份验证层 |
| SSO | Single Sign-On | 单点登录，一次认证访问多个系统 |
| RBAC | Role-Based Access Control | 基于角色的访问控制 |
| ABAC | Attribute-Based Access Control | 基于属性的访问控制 |
| PBAC | Policy-Based Access Control | 基于策略的访问控制 |

## 基础设施

| 术语 | 英文 | 定义 |
|------|------|------|
| WAF | Web Application Firewall | Web 应用防火墙 |
| IDS/IPS | Intrusion Detection/Prevention System | 入侵检测/防御系统 |
| EDR | Endpoint Detection and Response | 端点检测与响应 |
| XDR | Extended Detection and Response | 扩展检测与响应 |
| SIEM | Security Information and Event Management | 安全信息与事件管理 |
| SOAR | Security Orchestration Automation and Response | 安全编排自动化与响应 |
| NGFW | Next-Generation Firewall | 下一代防火墙 |
| DLP | Data Loss Prevention | 数据防泄漏 |
| HSM | Hardware Security Module | 硬件安全模块 |
| CASB | Cloud Access Security Broker | 云访问安全代理 |

## 漏洞管理

| 术语 | 英文 | 定义 |
|------|------|------|
| CVE | Common Vulnerabilities and Exposures | 公共漏洞披露编号 |
| CVSS | Common Vulnerability Scoring System | 通用漏洞评分系统（0-10） |
| CWE | Common Weakness Enumeration | 常见弱点枚举分类 |
| CAPEC | Common Attack Pattern Enumeration and Classification | 攻击模式枚举 |
| POC | Proof of Concept | 概念验证，证明漏洞存在的代码 |
| EXP | Exploit | 漏洞利用代码 |
| 0day | Zero-Day | 厂商尚未修补的漏洞 |
| N-Day | N-Day | 已知但未修补的漏洞 |
| EPSS | Exploit Prediction Scoring System | 漏洞利用预测评分系统 |

## AI 安全

| 术语 | 英文 | 定义 |
|------|------|------|
| LLM | Large Language Model | 大语言模型 |
| RAG | Retrieval-Augmented Generation | 检索增强生成 |
| RLHF | Reinforcement Learning from Human Feedback | 基于人类反馈的强化学习 |
| Prompt Injection | Prompt Injection | 提示注入攻击 |
| Jailbreak | Jailbreak | 绕过 LLM 安全限制 |
| Hallucination | Hallucination | 模型生成不实内容 |
| Adversarial Example | Adversarial Example | 对抗样本 |
| Data Poisoning | Data Poisoning | 数据投毒攻击 |

## 攻击与利用

| 术语 | 英文 | 定义 |
|------|------|------|
| 反弹 Shell | Reverse Shell | 受害机器主动连接攻击者的 Shell |
| WebShell | Web Shell | 上传到服务器的远程命令执行脚本 |
| DoS/DDoS | Denial of Service | 拒绝服务/分布式拒绝服务攻击 |
| APT | Advanced Persistent Threat | 高级持续性威胁 |
| C2/C&C | Command and Control | 命令与控制服务器 |
| 横向移动 | Lateral Movement | 攻击者在内网中扩展访问范围 |
| 权限提升 | Privilege Escalation | 从低权限提升至管理员/系统权限 |
| 持久化 | Persistence | 攻击者在系统中维持长期访问 |
| 社工 | Social Engineering | 利用人性弱点获取信息或权限 |

## 防御与运营

| 术语 | 英文 | 定义 |
|------|------|------|
| SOC | Security Operations Center | 安全运营中心 |
| CSIRT | Computer Security Incident Response Team | 安全事件响应团队 |
| SDL | Security Development Lifecycle | 安全开发生命周期 |
| SAST | Static Application Security Testing | 静态应用安全测试 |
| DAST | Dynamic Application Security Testing | 动态应用安全测试 |
| SCA | Software Composition Analysis | 软件组成分析 |
| CSP | Content Security Policy | 浏览器内容安全策略 |
| CORS | Cross-Origin Resource Sharing | 跨源资源共享 |
| Zero Trust | Zero Trust Architecture | 零信任架构 |
| SBOM | Software Bill of Materials | 软件物料清单 |

## 合规与标准

| 术语 | 英文 | 定义 |
|------|------|------|
| ISO 27001 | ISO/IEC 27001 | 信息安全管理体系标准 |
| GDPR | General Data Protection Regulation | 欧盟通用数据保护条例 |
| PCI DSS | Payment Card Industry Data Security Standard | 支付卡行业数据安全标准 |
| HIPAA | Health Insurance Portability and Accountability Act | 美国医疗隐私法 |
| SOC 2 | Service Organization Control 2 | 服务组织安全审计报告 |
| 等保 2.0 | Classified Protection 2.0 | 中国网络安全等级保护制度 |
| NIST CSF | NIST Cybersecurity Framework | NIST 网络安全框架 |

---

*上一篇：[安全工具与资源大全](resources.md)*

*下一篇：[安全检查清单](checklists.md)*

<div class="hero" markdown="1">

# 🛡️ 安全漏洞实战手册

**从认识漏洞到修复漏洞 — 不止于原理，更重于实战**

</div>

<div class="feature-grid" markdown="1">

<div class="feature-card" markdown="1">

### 🏪 入门基础
**从零开始的安全之路**
- 计算机网络与 HTTP 协议
- Web 应用架构解析
- 安全工具与信息收集
- **适合零基础读者入门**

[进入入门基础章节 →](basics/00-intro.md)

</div>

<div class="feature-card" markdown="1">

### 🔴 Web 安全
**OWASP Top 10 深度解析**。每个漏洞都包含原理、案例、POC 与修复。
- SQL 注入、XSS、CSRF、SSRF、RCE
- 认证绕过、IDOR、文件上传、XXE、反序列化

[进入 Web 安全章节 →](chapters/01-web-security/index.md)

</div>

<div class="feature-card" markdown="1">

### 🎯 学习路径
不只是漏洞清单。从零基础到安全工程师的完整路线。
- 零基础怎么开始学安全
- 推荐学习平台和资源
- 安全行业的职业发展

[进入学习路径章节 →](learning/index.md)

</div>

<div class="feature-card" markdown="1">

### ☁️ 云安全
**AI 时代的云基础设施安全**。
- 共享责任模型与 IAM 安全
- 云存储与网络安全
- Serverless 与合规治理

[进入云安全章节 →](cloud-security/index.md)

</div>

<div class="feature-card" markdown="1">

### 🐳 容器与 K8s 安全
**AI 工作负载的运行平台安全**。
- Docker 镜像与运行时安全
- Kubernetes RBAC 与网络策略
- 容器供应链安全

[进入容器安全章节 →](container-security/index.md)

</div>

<div class="feature-card" markdown="1">

### 🔗 供应链安全
**每一行依赖都可能是攻击入口**。
- SolarWinds/xz 后门案例分析
- CI/CD 管道安全与 SLSA 框架
- AI 模型供应链安全

[进入供应链安全章节 →](supply-chain-security/index.md)

</div>

<div class="feature-card" markdown="1">

### 📱 移动安全
**移动端的 AI 应用安全**。
- Android/iOS 安全架构
- 移动 API 安全与证书固定
- AI 移动应用隐私保护

[进入移动安全章节 →](mobile-security/index.md)

</div>

<div class="feature-card" markdown="1">

### 🖥️ 系统安全
**操作系统层面的防御**。
- 缓冲区溢出原理与防御
- Linux/Windows 提权路径
- GPU 与训练服务器加固

[进入系统安全章节 →](system-security/index.md)

</div>

<div class="feature-card" markdown="1">

### 🔒 数据隐私与合规
**AI 时代的数据保护法规**。
- PIPL/GDPR/CCPA 对比
- AI 训练数据合规
- 数据脱敏与差异化隐私

[进入数据隐私章节 →](data-privacy/index.md)

</div>

<div class="feature-card" markdown="1">

### 🧠 AI 安全进阶
**更深层的 AI 安全攻防**。
- 模型安全评估与红队测试
- Agent 工具调用安全
- 多 Agent 协作防御

[进入 AI 安全进阶 →](advanced-ai-security/index.md)

</div>

<div class="feature-card" markdown="1">

### 🤖 AI 安全
**大模型时代的安全新挑战**。
- Prompt 注入与防御
- LLM 特有的安全漏洞
- Agent 平台安全（OpenClaw）
- AI 辅助钓鱼与内容污染

[进入 AI 安全章节 →](ai-security/index.md)

</div>

</div>

---

## 阅读建议

| 你的背景 | 推荐阅读顺序 |
|----------|-------------|
| 零基础 | 入门基础 → Web 安全 → 云安全 → 学习路径 → AI 安全 |
| 有 Web 基础 | Web 安全 → 云安全 → 容器 → AI → 进阶 |
| 安全从业者 | 按需阅读，重点看 AI 安全 / 云安全 / 供应链 |
| 开发者 | Web 安全 + 容器安全 + 数据隐私 |

---

## 更新日志

### 2026-05-20 — 第四阶段：新增 5 个大章（供应链安全、移动安全、系统安全、数据隐私、AI 安全进阶）
- ✅ 供应链安全：覆盖 SolarWinds/xz 后门案例、SLSA 框架、CI/CD 管道安全
- ✅ 移动安全：Android/iOS 架构对比、移动 API 安全、证书固定代码示例
- ✅ 系统安全：缓冲区溢出 POC、提权路径、训练服务器加固
- ✅ 数据隐私与合规：PIPL/GDPR/CCPA 对比、AI 训练合规、数据脱敏
- ✅ AI 安全进阶：模型安全评估、红队测试、Agent 工具调用安全、多 Agent 安全
- ✅ 导航已在 mkdocs build 验证通过
- ✅ 首页显示全部 14 个章节入口

### 2026-05-20 — 第三阶段：新增云安全 + 容器安全
- 云安全 8 篇、容器 K8s 安全 4 篇

### 2026-05-20 — 第二阶段：修复导航 + 新增入门基础
- 修复导航配置、新增 6 篇入门基础

### 2026-05-20 — 第一版发布
- Web 安全 10 篇 + AI 安全 6 篇 + 学习路径 4 篇 + 附录 3 篇

---

> **目标**：认真读完这本书的人，能够进入安全行业。

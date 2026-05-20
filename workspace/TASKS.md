# TASKS.md — 《安全漏洞实战手册》写作工作区

## 写作计划总览

### 📍 项目位置
- **书籍根目录**：`X:\c\ai\Safe`
- **框架参考**：`X:\c\ai\prompts`（mkdocs Material 书籍框架）
- **追踪格式模仿**：飞书 Aily 工作空间

### 📖 书籍结构

```
X:\c\ai\Safe/
├── workspace/              ← 工作区追踪
│   ├── TASKS.md            ← 任务总跟踪 ✅
│   ├── MEMORY.md           ← 长期记忆 ✅
│   ├── AGENTS.md           ← 写作规则 ✅
│   ├── SOUL.md             ← 写作灵魂 ✅
│   └── HEARTBEAT.md        ← 心跳检查 ✅
├── index.md                ← 书籍首页 ✅
├── mkdocs.yml              ← 构建配置 ✅
├── docs/
│   ├── index.md            ← 书稿首页 ✅
│   ├── SUMMARY.md          ← 完整目录 ✅
│   ├── stylesheets/
│   │   └── extra.css       ← 自定义样式 ✅
│   ├── chapters/01-web-security/  ← Web 安全（10 篇）✅
│   ├── learning/           ← 学习路径（4 篇）✅
│   ├── ai-security/        ← AI 安全（6 篇）✅
│   └── appendix/           ← 附录（3 篇）✅
```

### 🎯 内容规范

每篇文章包含 7 个核心部分：漏洞概述 → 原理深度分析 → 真实案例 → POC → 修复方案 → 检测工具 → 延伸阅读

### ✅ 完成清单

#### ✅ 阶段一：项目搭建
- [x] 创建工作区追踪系统（TASKS.md、MEMORY.md、AGENTS.md、SOUL.md、HEARTBEAT.md）
- [x] 创建 mkdocs.yml 配置
- [x] 创建 index.md、docs/index.md、docs/SUMMARY.md
- [x] 创建 docs/stylesheets/extra.css

#### ✅ 阶段二：Web 安全（10 篇）
- [x] index.md — Web 安全总览
- [x] 01-sql-injection.md — SQL 注入（9.4KB）
- [x] 02-xss.md — XSS 跨站脚本（9.4KB）
- [x] 03-csrf.md — CSRF 跨站请求伪造（8.7KB）
- [x] 04-ssrf.md — SSRF 服务端请求伪造（9.2KB）
- [x] 05-rce.md — 远程代码执行（8.2KB）
- [x] 06-authentication-bypass.md — 认证绕过（10.5KB）
- [x] 07-idor.md — IDOR 越权访问（8.3KB）
- [x] 08-file-upload.md — 文件上传漏洞（9.3KB）
- [x] 09-xxe.md — XXE 外部实体注入（8.0KB）
- [x] 10-deserialization.md — 反序列化攻击（9.0KB）

#### ✅ 阶段三：学习路径（4 篇）
- [x] index.md — 学习路径总览
- [x] 01-learning-path.md — 安全学习路线图（4.6KB）
- [x] 02-platforms.md — 推荐学习平台（3.6KB）
- [x] 03-career-development.md — 安全职业发展（4.5KB）

#### ✅ 阶段四：AI 安全（6 篇）
- [x] index.md — AI 安全概述（2.0KB）
- [x] 01-llm-vulns.md — LLM 安全漏洞（3.7KB）
- [x] 02-prompt-injection.md — Prompt 注入攻击（9.3KB）
- [x] 03-openclaw-security.md — OpenClaw 安全（6.8KB）
- [x] 04-phishing-ai.md — AI 辅助钓鱼与防护（8.6KB）
- [x] 05-content-pollution.md — 内容污染鉴别（11.8KB）

#### ✅ 阶段五：附录（3 篇）
- [x] resources.md — 资源与引用
- [x] glossary.md — 术语表
- [x] checklists.md — 安全检查清单

### 📊 项目统计

- **总文件数**：21 篇文章 + 6 个配置文件 + 5 个工作区文件 = **32 个文件**
- **总字数**：Web 安全 ~90KB / 学习路径 ~13KB / AI 安全 ~42KB / 附录 ~6KB
- **书籍框架**：mkdocs Material 主题，中文配置

### 📝 写作进度

| 日期 | 完成内容 | 下一步 |
|------|---------|--------|
| 2026-05-20 | 第一阶段全部完成 + Web 安全 10 篇 + 学习路径 4 篇 + AI 安全 6 篇 + 附录 3 篇 | 可继续扩展更多漏洞类别 |

### 🔮 下一阶段可扩展内容

Web 安全之外，后续可以添加：
- 系统安全（缓冲区溢出、提权）
- 移动安全（Android/iOS）
- 云安全（容器逃逸、K8s 配置）
- 网络安全（协议攻击、中间人）
- 密码学（算法实现缺陷）

### ⚡ 中断恢复指南

下次启动时：
1. 读 workspace/MEMORY.md → 回顾上下文
2. 读 workspace/TASKS.md → 查看完成状态和下一步
3. 从"下一阶段可扩展内容"中选择继续

---

_最后更新：2026-05-20 | 第一阶段初稿全部完成 ✅_

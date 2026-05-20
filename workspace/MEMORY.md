2026-05-20：第二阶段 — 修复导航 + 新增入门基础。

【修复】
- mkdocs.yml 改了 docs_dir 从根目录到 docs/（新版 mkdocs 不允许 docs_dir='.'）
- site_url → https://kkkkof2025.github.io/SafeBook/
- 新增 nav 特性：navigation.instant.progress、toc.follow、content.action.edit 等
- 合并了根 index.md 和 docs/index.md，消除了重复首页

【新增】
- 入门基础章节（6 篇）：入门指引、网络基础、HTTP 协议、Web 架构、安全工具、信息收集
- 阅读建议：零基础读者建议从入门基础开始
- 更新日志放在 docs/index.md 底部

【构建验证】
- mkdocs build 通过，生成 33 HTML 页面
- 所有内部链接验证通过

2026-05-20：第三阶段 — 新增云安全 + 容器/K8s 安全。

【新增】
- 云安全章节（8 篇）：共享责任模型、IAM 与身份安全、云存储安全、云网络安全、Serverless 安全、云合规与治理、CSPM 工具链 + 章节总览
- 容器与 K8s 安全章节（4 篇）：Docker 安全（镜像/运行时/逃逸防护）、Kubernetes 安全（RBAC/Pod 安全/网络策略）、容器供应链安全（签名/SBOM/准入控制）+ 章节总览

【总规模】
- 从 6 个章节扩展到 9 个章节
- 从 29 篇扩展到 41 篇
- 50 个文件

【构建验证】
- mkdocs build 通过，无错误
- 所有章节已在导航中可见

【下一步可扩展】
- 供应链安全（软件供应链、CI/CD Pipeline 安全）

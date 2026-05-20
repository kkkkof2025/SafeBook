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

【下一步】
- 继续扩展基础章节（密码学基础、Linux/Windows 基础）
- 可以考虑扩展更多大类（系统安全、移动安全、云安全）
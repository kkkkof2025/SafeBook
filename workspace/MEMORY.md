# 第六轮更新总结 — CSS修复 + 导航折叠 + CVE/POC章节

## 完成的修改

### 1. CSS 代码块可读性修复（参考 prompts 项目风格）
- 代码块背景改为浅色 `#f5f2f0`，文字 `#333`
- 精确配色: YAML键=蓝、字符串=深蓝、注释=灰斜体、关键字=红粗体
- 行内代码灰底红字 `#f0e8e8/#c62828`
- 表格表头红色主题
- 消除 `.highlight .err` 导致的中文文字不可见问题

### 2. 导航折叠 JS
- `docs/javascripts/extra.js` — 页面加载后自动折叠非当前章节
- 仅展开当前页面所在章节组
- 支持 Material 即时导航（SPA）

### 3. 新增 CVE/POC 章节（3篇文章）
每篇完整的: 原理 + HTTP-POC/Python-脚本 + CVSS评分 + 修复 + NVD/GitHub链接
- **Awesome-POC 实战指南**: Log4Shell/Spring4Shell/Shiro/FastJSON/Nacos 等 CVE 索引
- **中间件 CVE**: Log4j远程执行/Tomcat Ghostcat/WebLogic反序列化/JBoss/Nginx
- **框架漏洞 CVE**: ThinkPHP RCE/Spring Cloud Gateway/Shiro-550/FastJSON

### 4. 所有引用添加真实链接
- 每个 CVE 附 NVD 官方页面链接
- POC 指向 Awesome-POC/POChouse/VulHub/PeiQi-WIKI
- 文章引用: 火山引擎、博客园、知乎、Moonsec、HVV PDF

## 总规模
- **15个章节** → **58篇文章** → **63 HTML页面**
- 红色 Material 主题，完整导航+目录，导航折叠，代码块清晰可读
- 所有文章含: 原理 + 案例 + POC + 修复 + 参考链接

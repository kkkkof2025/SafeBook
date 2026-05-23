# 安全检查清单

> 安全开发、运维、AI 安全、云安全完整检查清单

---

## 开发安全清单

### 输入与输出
- [ ] 所有用户输入在输出前进行 HTML 实体编码
- [ ] 数据库查询使用参数化查询（Prepared Statements / ORM）
- [ ] 文件上传限制 MIME 类型、大小（≤10MB）、重命名存储
- [ ] 不信任 `Content-Type` / `filename`（双重扩展名攻击）
- [ ] XML 解析禁用外部实体（`defusedxml`）
- [ ] 反序列化用 JSON 替代 Pickle，绝不反序列化用户输入
- [ ] JSON Schema 验证所有 API 请求（拒绝 `additionalProperties`）

### 认证与授权
- [ ] 密码哈希: bcrypt (cost≥12) 或 Argon2id（禁止 MD5/SHA1）
- [ ] JWT 明确指定算法白名单 `algorithms=['RS256']`
- [ ] Session Cookie: HttpOnly + Secure + SameSite=Lax/Strict
- [ ] 登录限速: 5 次/分钟/IP，错 10 次锁定 30 分钟
- [ ] 每个 API 端点有明确的 Scope 要求（对象级授权）
- [ ] 2FA 强制用于管理员和敏感操作

### 配置安全
- [ ] 密钥/密码通过环境变量或密钥管理服务（KMS/Vault），禁止硬编码
- [ ] HTTPS + HSTS (`max-age=63072000; includeSubDomains`)
- [ ] CSP 头: `default-src 'self'; script-src 'self'`
- [ ] 错误页面不展示堆栈/路径/版本号
- [ ] 目录列表已禁用（Nginx: `autoindex off`）
- [ ] 依赖项自动更新（Dependabot/Renovate）+ SCA 扫描

### CI/CD 管道
- [ ] SAST: Semgrep/CodeQL 每次 PR 自动扫描
- [ ] 密钥检测: TruffleHog/git-secrets
- [ ] 容器扫描: Trivy (Critical/High = 阻断构建)
- [ ] IaC 扫描: tfsec/Checkov
- [ ] DAST: 预发布环境 OWASP ZAP 自动扫描

---

## API 安全清单

- [ ] 认证: JWT/OAuth2 (PKCE) / API Key (scoped)
- [ ] 速率限制: 令牌桶 (100 req/min/user)
- [ ] CORS: 仅允许必要 Origin（禁止 `*`）
- [ ] GraphQL: 查询深度限制 (max depth ≤ 10)
- [ ] GraphQL: Introspection 生产环境禁用
- [ ] 输出脱敏: 删除 `password`/`secret`/`token` 字段
- [ ] 日志: 记录操作但不记录 Token/密码/PII
- [ ] API 版本管理: 废弃的 v1 及时下线

---

## 云安全清单

### IAM
- [ ] 遵循最小权限原则
- [ ] 禁止使用 Root 账号（启用 MFA）
- [ ] IAM Role 替代长期 Access Key
- [ ] 定期审计未使用的权限、用户、角色
- [ ] S3 存储桶禁止公开访问（Block Public Access）

### 网络
- [ ] VPC 安全组: 默认拒绝、仅开放必要端口
- [ ] WAF 已启用（AWS WAF/Cloud Armor/Azure WAF）
- [ ] CloudTrail/Activity Log/Audit Logs 已启用
- [ ] DDoS 防护: Shield/Azure DDoS/Cloud Armor

### 数据
- [ ] 静态加密: KMS 管理密钥 + 自动轮换
- [ ] 传输加密: TLS 1.2+ (禁用 TLS 1.0/1.1)
- [ ] 数据库: 私有子网、仅允许应用层访问
- [ ] 备份: 启用自动备份 + 跨区域复制

### 容器/K8s
- [ ] 镜像: 基础镜像使用 Distroless/Alpine，定期更新
- [ ] Pod Security: `restricted` 标准（非 root + 只读根文件系统）
- [ ] NetworkPolicy: 默认拒绝 + 白名单
- [ ] 密钥: Kubernetes Secrets + External Secrets Operator（对接到 KMS）
- [ ] 运行时安全: Falco/Tetragon 行为监控

---

## AI 安全清单

### LLM Agent
- [ ] 系统提示词不包含 API Key / 内部 IP / 架构信息
- [ ] Agent 工具调用需参数验证
- [ ] 高风险操作（`rm`/`DROP TABLE`/`sudo`）需人工确认
- [ ] 外部内容（文档、网页、邮件）读取前需注入检测
- [ ] 所有 Agent 工具调用记录到不可篡改日志

### Prompt 安全
- [ ] 输入过滤: 检测 `Ignore previous instructions` 等注入标记
- [ ] 输出过滤: 不泄露系统提示词、内部数据
- [ ] 内容隔离: 用户输入与系统指令明确分隔（使用 ChatML/分隔符）
- [ ] 越狱测试: 定期用 Garak/PyRIT 扫描
- [ ] 速率限制: 防止模型爬取/影子模型攻击

### 数据安全
- [ ] 训练数据来源签名验证
- [ ] 差分隐私训练: ε ≤ 8.0
- [ ] 模型部署前哈希签名 + 完整性校验
- [ ] RAG 检索源白名单
- [ ] 用户输入不进入训练数据（除非明确授权）

---

## 应急响应清单

### 检测到事件
- [ ] 确认漏洞真实存在（排除误报）
- [ ] 评估影响: 哪些系统、哪些数据、多少用户
- [ ] 评估 CVSS 评分 (3.1) + 业务影响
- [ ] 通知: 安全团队 → 法务 → 管理层 → (如法规要求) 监管机构
- [ ] 立即遏制: 隔离系统 + 吊销凭证 + 阻断攻击链

### 取证
- [ ] 内存快照: `avml /tmp/memory.dump`
- [ ] 磁盘镜像: `dd if=/dev/sda of=/evidence/disk.img bs=4M`
- [ ] 日志: `/var/log/*`，`audit.log`，`CloudTrail`
- [ ] 时间线重建: 关联所有主机/网络日志

### 恢复与复盘
- [ ] 重建受影响系统（从干净的备份/镜像）
- [ ] 修补漏洞入口 + 安全加固
- [ ] 验证修复（重新进行渗透测试）
- [ ] 事后复盘文档: 时间线 → 根因 → 改进 → 责任人

---

*上一篇：[安全工具速查手册](04-security-tools-reference.md)*

*下一篇：[术语表](glossary.md)*

# Agent 平台安全实战

> Agent 平台的安全风险 —— 以 OpenClaw 为例，覆盖 LangChain/AutoGPT/CrewAI 等平台

---

## OpenClaw 的安全模型

OpenClaw 是一个 Agent 工作台，它能够：
- 读取和写入文件
- 执行系统命令
- 访问网络资源（HTTP API、浏览器）
- 发送消息和邮件
- 操作云服务

这种能力既是它的价值所在，也是它的攻击面。

### 核心安全挑战

| 挑战 | 描述 | 风险等级 |
|------|------|---------|
| Prompt 注入 | 对话中被诱导执行危险操作 | 🔴 严重 |
| 工具滥用 | Agent 权限过大，执行未授权操作 | 🔴 严重 |
| 数据泄露 | Agent 在对话中泄露敏感信息 | 🟡 高危 |
| 钓鱼访问 | 诱导 Agent 访问恶意网站 | 🟡 高危 |
| 内容污染 | Agent 读取被污染的知识库内容 | 🟡 高危 |

---

## 关键安全场景

### 场景 1：自动访问钓鱼网站

**OpenClaw 的能力**：Agent 可以接收链接并自动访问网页。

**威胁**：攻击者发送一个恶意链接，Agent 自动访问并执行了网页中的恶意内容（JavaScript 攻击、CSRF 触发、Cookie 窃取等）。

**攻击示例**：

```text
攻击者输入：
"帮我看看这个链接里的内容：https://evil.com/fake-login"

如果 Agent 自动访问这个链接：
1. 链接页面包含针对浏览器/Agent 的 CSRF 攻击
2. 页面自动提交表单到用户已登录的银行系统
3. 或者页面包含脚本，试图窃取 Agent 环境中的信息
```

**防护措施**：

```yaml
# ✅ 推荐的安全配置

1. 链接访问权限：
   - 默认不自动访问链接，需要用户明确确认
   - 用户必须说"打开链接"或类似的确认词
   
2. URL 安全检查：
   - 检查域名是否在已知恶意域名数据库中
   - 检查 URL 是否匹配已知钓鱼模式
   - 对短链接进行还原检查

3. 浏览器隔离：
   - 使用沙箱浏览器访问外部链接
   - 禁止执行页面中的 JavaScript
   - 不持久化 Cookie（每次会话新浏览器）
```

### 场景 2：Agent 被诱导执行危险命令

**威胁**：攻击者通过 Prompt 注入让 Agent 执行 `rm -rf /`、`format` 或其他破坏性命令。

**防护措施**：

```python
# OpenClaw Skills 中的命令过滤
DANGEROUS_COMMANDS = [
    'rm -rf', 'format', 'mkfs', 'dd if=',
    'chmod 777', 'chown -R', '> /dev/sda',
    ':(){ :|:& };:',  # Fork bomb
    'wget -O- | sh', 'curl ... | bash',
]

def is_safe_command(command: str) -> bool:
    """检查命令是否安全"""
    lower_cmd = command.lower()
    
    for dangerous in DANGEROUS_COMMANDS:
        if dangerous in lower_cmd:
            return False
    
    return True
```

### 场景 3：API Key 泄露

**威胁**：Agent 的系统提示词或配置中包含 API Key，攻击者通过注入诱导 Agent 泄露。

**防护措施**：

```yaml
敏感信息管理：
  - API Key 存储在环境变量中，不在系统提示词中出现
  - Agent 在输出中自动过滤敏感信息（正则匹配 Key 格式）
  - 使用 OpenClaw 的连接管理功能，避免 Key 暴露在对话中
```

---

## OpenClaw 安全配置指南

### 1. Skill 权限管理

```yaml
# 在 Skill 的 metadata 中明确声明权限
permissions:
  files:
    read: true        # 允许读文件吗？
    write: false      # 允许写文件吗？
    delete: false     # 允许删除文件吗？
  
  network:
    http: true        # 允许 HTTP 请求吗？
    internal: false   # 允许访问内网 IP 吗？
  
  system:
    exec: false       # 允许执行系统命令吗？
    env: false        # 允许读取环境变量吗？
```

### 2. 敏感操作确认

```python
# 高风险操作需要二次确认
HIGH_RISK_PATTERNS = [
    'delete', 'remove', 'truncate',
    'overwrite', 'format',
    '转账', '支付', '发送邮件',
    '修改密码', '重置',
]

def requires_confirmation(action_description: str) -> bool:
    """判断操作是否需要用户确认"""
    for pattern in HIGH_RISK_PATTERNS:
        if pattern in action_description.lower():
            return True
    return False
```

### 3. 数据出口控制

```yaml
# 控制 Agent 可以发送数据到哪些外部服务
data_egress:
  allowed_domains:
    - api.trusted-service.com
    - cdn.trusted-cdn.com
  
  blocked_patterns:
    - "*evil*"
    - "*phish*"
    - "*hack*"
  
  # 发送敏感数据需要审批
  sensitive_data_rules:
    - pattern: "api_key|token|password|secret"
      action: "block_and_alert"
```

### 4. 会话安全

```python
# 会话级别的安全检查

def validate_tool_call(tool_name: str, params: dict, context: dict) -> bool:
    """在执行工具调用前进行安全检查"""
    
    # 1. 检查是否是高风险工具
    if tool_name in HIGH_RISK_TOOLS:
        # 需要用户确认
        return request_user_approval(tool_name, params)
    
    # 2. 检查参数是否包含注入
    for key, value in params.items():
        if isinstance(value, str):
            if detect_injection(value):
                log_security_event('injection_detected', {
                    'tool': tool_name,
                    'param': key,
                    'session': context.get('session_id')
                })
                return False
    
    # 3. 检查上下文一致性
    # 如果用户刚刚要求忽略指令，后续操作需要额外校验
    if context.get('suspicious_context', False):
        return request_user_approval(tool_name, params, reason='可疑上下文')
    
    return True
```

---

## 安全最佳实践清单

### 用户层面

- [ ] 不要在系统提示词中存放敏感信息（密码、Key 等）
- [ ] 连接外部 API 时使用 OpenClaw 的连接管理
- [ ] 定期审查已安装的 Skill
- [ ] 为不同的项目创建独立的会话
- [ ] 高敏感操作需要手动确认

### Agent/Skill 开发者层面

- [ ] Skill 只申请最小必要权限
- [ ] 工具函数参数做类型验证
- [ ] 敏感输出自动脱敏
- [ ] 记录所有工具调用日志
- [ ] 避免使用 shell=True 执行命令

### 平台层面

- [ ] 启用操作审计日志
- [ ] 配置数据出口白名单
- [ ] 定期安全审计
- [ ] 异常行为告警
- [ ] 沙箱隔离

---

## 延伸阅读

1. [OWASP LLM Security](https://genai.owasp.org/)
2. [OpenClaw 官方文档](https://openclaw.ai/)
3. [MCP 安全指南](https://modelcontextprotocol.io/)
4. [Anthropic Agent 安全指南](https://docs.anthropic.com/en/docs/agent-security)
5. [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)

*上一篇：[Prompt 注入攻击](02-prompt-injection.md)*

*下一篇：[AI 辅助钓鱼与防护](04-phishing-ai.md)*

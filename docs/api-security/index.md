# API 安全

> API 是现代应用的命脉——也是攻击者的首要目标

## 为什么 API 安全至关重要

```
                      ┌───────────────────────┐
                      │      现代应用架构       │
                      ├───────────────────────┤
                      │         80%            │
                      │    流量 = API 调用     │
                      │                       │
                      │    REST  ──── 60%      │
                      │    GraphQL ── 20%      │
                      │    gRPC     ── 15%     │
                      │    WebSocket ─ 5%      │
                      └───────────────────────┘
```

---

## 本章内容

| 文章 | 核心内容 | 难度 |
|------|----------|------|
| [API 安全基础](01-api-security.md) | REST 认证/授权/限流 | ⭐⭐ |
| [API 认证鉴权](02-api-auth.md) | JWT/OAuth/API Key | ⭐⭐⭐ |
| [API 渗透测试](02-api-pentesting.md) | 工具链与测试方法 | ⭐⭐⭐ |
| [GraphQL 安全入门](03-graphql-security.md) | 查询安全/权限/注入 | ⭐⭐⭐ |
| [GraphQL 安全进阶](05-graphql-security.md) | 深度/复杂度/持久化查询 | ⭐⭐⭐⭐ |

---

## 快速检测

```bash
# API 安全基线检测
# 1. 认证检查
curl -s -o /dev/null -w "%{http_code}" https://api.example.com/protected

# 2. 速率限制
for i in {1..200}; do
    curl -s -o /dev/null -w "%{http_code} " https://api.example.com/endpoint
done

# 3. 版本检测
curl -s https://api.example.com/v1/ | jq .

# 4. GraphQL 内省
curl -s -X POST https://api.example.com/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name}}}"}'
```

---

*下一篇：[API 安全基础](01-api-security.md)*

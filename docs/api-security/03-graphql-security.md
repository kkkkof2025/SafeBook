# GraphQL API 安全

> GraphQL 的灵活性也带来了独特的安全挑战——批量查询 + 深度嵌套 = 攻击者的 playground。

---

## 攻击面

```
GraphQL 特有攻击:
├── 信息泄露（Introspection 未关闭）
├── 深度查询攻击（递归嵌套耗尽资源）
├── 批量查询攻击（Batch Query / Alias）
├── 认证绕过（缺少授权检查）
├── 字段级授权泄露（隐藏字段被查询）
└── SQL/NoSQL 注入（Resolver 层）
```

## 1. Introspection 信息泄露

```graphql
# ❌ 未关闭 Introspection → 攻击者可获取完整 Schema
query {
    __schema {
        types {
            name
            fields {
                name
                type { name kind }
            }
        }
    }
}

# 可获取：所有类型、字段、参数、枚举值
# 包括隐藏的管理接口（admin/deleteUser/...）

# ✅ 生产环境禁用 Introspection
# Apollo Server
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production'
});
```

## 2. 深度查询攻击

```graphql
# ❌ 深度嵌套查询（资源耗尽）
query {
    user(id:1) {
        posts {
            comments {
                user {
                    posts {
                        comments {
                            user {
                                posts { ... }
}}}}}}}}

# ✅ 限制查询深度
# graphql-depth-limit
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
    validationRules: [depthLimit(5)]  // 最大深度 5 层
});
```

## 3. 批量攻击（Alias 别名）

```graphql
# ❌ 一次请求成千上万次查询
query {
    a1: user(id:1) { email }
    a2: user(id:2) { email }
    a3: user(id:3) { email }
    # ... 9997 个重复查询
}

# ✅ 限制查询复杂度
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
    validationRules: [
        createComplexityLimitRule(1000, {  // 最大复杂度 1000
            onCost: cost => console.log('Query cost:', cost)
        })
    ]
});
```

## 4. 授权检查缺失

```graphql
# ❌ 每个字段缺少授权检查
const resolvers = {
    Query: {
        // 只检查了顶层——但字段级没有！
        user: (_, { id }) => db.users.find(id)
    },
    User: {
        // 任何人都能查别人的 email
        email: (parent) => {
            // ❌ 未检查当前用户是否有权限
            return parent.email;
        },
        // 任何人都能查别人的手机号
        phone: (parent) => parent.phone
    }
};

# ✅ 字段级授权检查
const resolvers = {
    User: {
        email: (parent, args, context) => {
            // 只有本人或管理员可查看
            if (parent.id !== context.user.id && !context.user.isAdmin) {
                return null; // 或抛错
            }
            return parent.email;
        }
    }
};
```

## GraphQL 安全配置清单

```javascript
// Apollo Server 综合安全配置
const server = new ApolloServer({
    typeDefs, resolvers,
    
    // 1. 限深
    validationRules: [
        depthLimit(7),
        createComplexityLimitRule(2000),
    ],
    
    // 2. 禁用 Introspection
    introspection: false,
    
    // 3. 持久化查询（允许 + 禁止的组合策略）
    persistedQueries: {
        ttl: 900,  // 缓存 15 分钟
    },
    
    // 4. 速率限制
    plugins: [
        ApolloServerPluginInlineTraceDisabled(),
        {
            async requestDidStart({ request, context }) {
                // Rate limit per user
                const key = context.user?.id || request.http.headers.get('x-forwarded-for');
                const allowed = await rateLimiter.check(key, 'graphql', 100);
                if (!allowed) throw new GraphQLError('Rate limit exceeded');
            }
        }
    ],
    
    // 5. 自定义格式化错误（不泄露内部信息）
    formatError: (err) => {
        // 生产环境不暴露内部错误详情
        if (err.extensions?.code === 'INTERNAL_SERVER_ERROR') {
            return new GraphQLError('Internal server error');
        }
        return err;
    }
});
```

## WAF 防护

```nginx
# Nginx + GraphQL 防护
location /graphql {
    # 限制请求体大小
    client_max_body_size 10k;
    
    # 限制请求方法
    limit_except POST {
        deny all;
    }
    
    # 速率限制
    limit_req zone=graphql burst=20 nodelay;
    
    # 只允许特定操作名（持久化查询）
    if ($arg_query !~ "^(Me|User|Post|CreatePost)$") {
        # 允许非持久化但限速
        limit_req zone=dynamic burst=5;
    }
    
    proxy_pass http://graphql-server;
}
```

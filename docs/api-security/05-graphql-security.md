# GraphQL API 安全攻防

## 概述

GraphQL 正在快速取代 REST 成为现代 API 标准。但它带来了全新的攻击面：内省查询泄露 schema、递归查询导致 DoS、批量查询绕过速率限制。75% 的 GraphQL 端点暴露了内省接口。

---

## 1. GraphQL 攻击面

### 1.1 REST vs GraphQL 安全对比

| 攻击向量 | REST | GraphQL |
|----------|------|---------|
| 信息泄露 | 需要猜测端点 | 内省查询一览无余 |
| 注入 | SQL/命令注入 | GraphQL 注入 + 底层解析器注入 |
| DoS | 大量请求 | 深度递归查询 (单个请求) |
| 授权 | 端点级授权 | 字段级授权 (每个 resolver) |
| 批量数据窃取 | 需要多次请求 | 单次查询获取全部关联数据 |

### 1.2 GraphQL 信息泄露

```graphql
# 攻击者首先尝试内省查询
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}

# 响应泄露了完整的数据库 schema：
# - User 类型 ← 包含 email, password_hash, credit_card
# - Admin 类型 ← 包含内部管理字段
# - Billing 类型 ← 包含 payment_token
#
# 攻击者现在知道了所有可查询的敏感字段

# 利用 schema 信息构造深度查询
query DataExfiltration {
  users {
    email
    personalInfo {  # ← 获取关联数据
      ssn
      address
      phoneNumber
    }
    orders {
      paymentInfo {
        creditCardNumber
        cvv
        billingAddress
      }
    }
  }
}
```

---

## 2. 深度查询 DoS

### 2.1 递归查询攻击

```graphql
# 经典递归 DoS 攻击
query DeepDoS {
  users {           # Level 1
    posts {         # Level 2
      comments {    # Level 3
        author {    # Level 4
          posts {   # Level 5 → 无限递归
            comments {
              author {
                posts {
                  # ... 继续嵌套 ...
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### 2.2 查询复杂度限制

```javascript
const { createComplexityLimitRule } = require('graphql-validation-complexity');

// 计算查询复杂度
function calculateComplexity(ast, schema) {
    let complexity = 0;

    visit(ast, {
        Field(node) {
            // 基础字段 = 1
            complexity += 1;

            // 连接字段 (列表) = 子字段复杂度 × 10 (预估返回 10 条)
            if (isConnectionField(node, schema)) {
                // 默认页码大小
                const connections = complexity;
                complexity += connections * 10;
            }
        }
    });

    return complexity;
}

// Apollo Server 配置
const server = new ApolloServer({
    schema,
    validationRules: [
        depthLimit(5),  // 最多 5 层嵌套

        createComplexityLimitRule(1000, {
            onCost: (cost) => {
                console.log(`Query cost: ${cost}`);
            },
            formatErrorMessage: (cost) => {
                return `查询过于复杂 (${cost}/1000)。请拆分查询或减少嵌套。`;
            }
        })
    ]
});
```

---

## 3. 授权与数据隔离

### 3.1 字段级授权

```javascript
const { rule, shield, and, or, not } = require('graphql-shield');

// 定义权限规则
const rules = {
    isAuthenticated: rule()(async (parent, args, ctx) => {
        return !!ctx.user;
    }),

    isAdmin: rule()(async (parent, args, ctx) => {
        return ctx.user?.role === 'admin';
    }),

    isOwner: rule()(async (parent, args, ctx) => {
        return parent.createdBy === ctx.user?.id;
    }),

    isUserOrAdmin: rule()(async (parent, args, ctx) => {
        return ctx.user?.id === args.userId || ctx.user?.role === 'admin';
    })
};

// 字段级权限 (shield)
const permissions = shield({
    Query: {
        // 全局查询需要认证
        '*': rules.isAuthenticated,

        // 用户列表仅管理员可查
        users: rules.isAdmin,

        // 订单：用户只能查自己的
        orders: rules.isAuthenticated,
    },
    User: {
        // 敏感字段仅管理员或本人可查
        email: or(rules.isAdmin, rules.isOwner),
        phone: or(rules.isAdmin, rules.isOwner),
        creditCard: rules.isAdmin,
        passwordHash: rules.isAdmin,
    },
    Mutation: {
        '*': rules.isAuthenticated,
        deleteUser: rules.isAdmin,
        updateUser: and(rules.isAuthenticated, rules.isOwner),
    }
});

// 应用到 Schema
const server = new ApolloServer({
    schema: applyMiddleware(schema, permissions),
});
```

### 3.2 防止批量查询绕过授权

```javascript
// GraphQL Resolver - 防止数据泄漏
const resolvers = {
    Query: {
        users: async (parent, args, ctx) => {
            // ❌ 不安全：可能返回所有用户
            // return User.findAll();

            // ✅ 安全：强制过滤
            if (ctx.user.role !== 'admin') {
                // 非管理员只能查自己
                return User.findAll({
                    where: { id: ctx.user.id }
                });
            }

            // 管理员可以查询但有限制
            const { offset = 0, limit = 20 } = args;
            return User.findAll({
                offset: Math.min(offset, 100),
                limit: Math.min(limit, 20)
            });
        }
    },

    User: {
        // 字段解析器也需要安全检查
        orders: async (parent, args, ctx) => {
            // ❌ 不安全：parent.orderIds.forEach(load)
            // ✅ 安全：验证访问权限
            if (ctx.user.id !== parent.id && ctx.user.role !== 'admin') {
                throw new ForbiddenError('无权限查看该用户的订单');
            }

            return Order.findAll({
                where: { userId: parent.id },
                limit: 10
            });
        }
    }
};
```

---

## 4. 注入防御

### 4.1 GraphQL 注入检测

```graphql
# GraphQL Injection 示例

# 攻击者尝试注入
query {
  # 普通的参数
  user(id: 1) { name }

  # SQL 注入尝试 (如果 resolver 未参数化)
  user(id: "1 OR 1=1") { name }

  # NoSQL 注入尝试
  users(filter: "{\"$gt\": \"\"}") { email }

  # 命令行注入尝试
  export(format: "pdf; rm -rf /") { data }

  # 模板注入 (SSTI)
  greeting(template: "{{7*7}}") { message }
}
```

### 4.2 输入验证

```javascript
const { GraphQLScalarType, Kind } = require('graphql');
const { isEmail, isURL, isMobilePhone } = require('validator');

// 自定义标量类型 (强类型验证)
const EmailAddress = new GraphQLScalarType({
    name: 'EmailAddress',
    description: '已验证的电子邮件地址',
    serialize(value) {
        return value;
    },
    parseValue(value) {
        if (!isEmail(value)) {
            throw new GraphQLError('无效的邮箱地址');
        }
        return value.toLowerCase();
    },
    parseLiteral(ast) {
        if (ast.kind !== Kind.STRING) {
            throw new GraphQLError('EmailAddress 必须是字符串');
        }
        if (!isEmail(ast.value)) {
            throw new GraphQLError('无效的邮箱地址');
        }
        return ast.value.toLowerCase();
    }
});

// 安全 ID 类型
const SafeID = new GraphQLScalarType({
    name: 'SafeID',
    serialize: String,
    parseValue(value) {
        // UUID 验证
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(String(value))) {
            throw new GraphQLError('无效的 ID 格式');
        }
        return String(value);
    },
    parseLiteral(ast) {
        if (ast.kind !== Kind.STRING) {
            throw new GraphQLError('ID 必须是字符串');
        }
        return SafeID.parseValue(ast.value);
    }
});

// 使用自定义类型
const typeDefs = gql`
    scalar EmailAddress
    scalar SafeID

    type User {
        id: SafeID!
        email: EmailAddress!
    }
`;
```

---

## 5. 速率限制与防滥用

### 5.1 查询级速率限制

```javascript
const rateLimit = require('graphql-rate-limit');

const rateLimiter = rateLimit.createRateLimiter({
    // 通用限制
    defaultRate: 100,    // 每分钟 100 个查询
    window: '1m',

    // 基于字段的限制
    limits: {
        // 敏感字段额外限制
        'Mutation.login': { rate: 5, window: '1m' },     // 登录
        'Mutation.createUser': { rate: 10, window: '1h' }, // 注册
        'Query.users': { rate: 30, window: '1m' },         // 用户列表

        // 昂贵的查询
        'Query.analytics': { rate: 10, window: '5m' }
    },

    // 基于用户的限制
    keyGenerator: (context) => {
        return context.user?.id || context.ip;
    }
});
```

### 5.2 Persisted Queries

```javascript
// 持久化查询 - 白名单模式
// 客户端只发送查询 ID，服务器从存储中获取查询文本

const persistedQueries = new Map();

// 注册查询时计算哈希
const crypto = require('crypto');

function registerQuery(queryString) {
    const hash = crypto.createHash('sha256')
        .update(queryString)
        .digest('hex');

    persistedQueries.set(hash, queryString);
    return hash;
}

// Apollo Server 持久化查询配置
const server = new ApolloServer({
    schema,
    persistedQueries: {
        cache: new Map(),
        ttl: 900  // 15 分钟
    },
    plugins: [{
        requestDidStart() {
            return {
                async didResolveOperation(context) {
                    // 可选：禁止 ad-hoc 查询 (生产环境推荐)
                    if (process.env.NODE_ENV === 'production') {
                        const isPersisted = context.request.extensions?.persistedQuery;
                        if (!isPersisted) {
                            throw new GraphQLError(
                                'Production only accepts persisted queries'
                            );
                        }
                    }
                }
            };
        }
    }]
});
```

---

## 6. GraphQL 安全清单

```yaml
GraphQL 安全基线:
  信息泄露:
    - [ ] 生产环境禁用内省 (introspection: false)
    - [ ] 禁止 GraphiQL/Playground
    - [ ] 自定义错误消息 (不暴露堆栈)

  查询控制:
    - [ ] 深度限制 (depthLimit <= 5)
    - [ ] 复杂度限制 (complexityLimit)
    - [ ] 查询超时 (5 秒)
    - [ ] Persisted Queries (生产环境)

  授权:
    - [ ] 字段级授权 (graphql-shield)
    - [ ] 每个 resolver 检查权限
    - [ ] 禁止批量数据绕过

  速率限制:
    - [ ] 全局/字段/用户级速率限制
    - [ ] 登录/注册特殊限制
    - [ ] 查询成本计费

  注入防御:
    - [ ] 自定义标量类型验证
    - [ ] 参数化 resolver 查询
    - [ ] 禁止动态字段选择
```

---

## 参考资源

- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [Apollo Server Security](https://www.apollographql.com/docs/apollo-server/security/)
- [GraphQL Armor](https://github.com/Escape-Technologies/graphql-armor)
- [InQL (GraphQL 安全扫描器)](https://github.com/doyensec/inql)

---

*上一篇：[GraphQL 安全入门](./03-graphql-security.md)*

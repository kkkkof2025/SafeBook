# API 安全测试

## 常见 API 漏洞

### 过度数据暴露
```json
// ❌ API 返回太多字段
GET /api/users/123
{
  "id": 123,
  "name": "张三",
  "email": "zhangsan@example.com",
  "phone": "13800138000",
  "internal_id": "EMP-2023-001",
  "ssn_last4": "1234",
  "department": "Finance",
  "salary": 85000,
  "manager_name": "李四"
}

// ✅ 仅返回必要字段
{
  "id": 123,
  "name": "张三",
  "email": "zhangsan@example.com"
}
```

### 批量分配（Mass Assignment）
```python
# ❌ 用户可设置任意字段
@app.route('/api/user/profile', methods=['PUT'])
def update_profile():
    user = User.query.get(session['user_id'])
    user.update(request.json)  # 用户可设置 is_admin=true
    db.session.commit()

# ✅ 白名单字段
ALLOWED_FIELDS = {'name', 'email', 'bio'}
def update_profile():
    user = User.query.get(session['user_id'])
    for field in ALLOWED_FIELDS:
        if field in request.json:
            setattr(user, field, request.json[field])
```

## GraphQL 安全

### 深度查询攻击
```graphql
query DeepQuery {
  user(id: 1) {
    posts { comments { user { posts { comments { user { name } } } } } }
  }
}
```
防御：限制查询深度 max_depth=5

### 批量查询攻击
```graphql
query BatchAttack {
  a1: user(id: 1) { ... }
  a2: user(id: 2) { ... }
  a1000: user(id: 1000) { ... }
}
```
防御：限制查询数量和耗时

## API 安全清单

- [ ] 速率限制（Rate Limiting）
- [ ] 认证鉴权（OAuth 2.0 / JWT）
- [ ] 输入验证（Schema 校验）
- [ ] 输出过滤（仅返回必要数据）
- [ ] 请求大小限制
- [ ] CORS 配置白名单
- [ ] API Key 定期轮换
- [ ] 审计日志记录

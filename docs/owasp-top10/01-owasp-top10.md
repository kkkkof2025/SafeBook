# OWASP Top 10 深度解析

## A01: 失效的访问控制

### 典型场景
```http
# 水平越权：用户A可查看用户B的订单
GET /api/orders/1001  # 用户A的订单
GET /api/orders/1002  # 用户B的订单（无权限校验）

# 垂直越权：普通用户访问管理后台
GET /admin/dashboard  # 返回200（应返回403）
```

### 修复方案
```python
# 水平越权修复：验证资源归属
@app.route('/api/orders/<order_id>')
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id and not current_user.is_admin:
        return abort(403)
    return order.to_dict()
```

## A02: 加密机制失效

### 常见问题
- 明文传输密码
- 使用 MD5/SHA-1 存储密码
- 自建加密算法
- 证书验证不严格

### 修复
```python
# 使用 bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

## A03: 注入

SQL 注入、命令注入、LDAP 注入、NoSQL 注入

## A04: 不安全设计

缺乏威胁建模、未遵循安全设计原则

## A05: 安全配置错误

默认凭据、未禁用目录列表、详细错误信息

## A06: 易受攻击和过时的组件

使用已知漏洞的第三方组件

## A07: 身份认证和会话管理失效

弱密码策略、会话固定、缺乏 MFA

## A08: 软件和数据完整性失效

CI/CD 管道未签名、不安全的反序列化

## A09: 安全日志记录和监控失败

缺乏审计日志、告警配置不当

## A10: 服务端请求伪造（SSRF）

云环境和内部网络的重要攻击面

